require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'socket'
require 'timeout'
require 'logger'
require_relative '../ssh_relay'

class SSHRelayTest < Minitest::Test
  def setup
    @dir = Dir.mktmpdir('ssh-relay-test-')
    @pids = File.join(@dir, 'pids')
    @requests = File.join(@dir, 'requests')
    @child = File.join(@dir, 'npiperelay')
    File.write(@child, <<~RUBY)
      #!/usr/bin/ruby
      exit 2 unless ARGV == ['-p', '-l', '-s', '-ei', '-ep', '//./pipe/openssh-ssh-agent']
      File.open('#{@pids}', 'a') { |f| f.puts Process.pid }
      loop do
        header = STDIN.read(4)
        break unless header && header.bytesize == 4
        length = header.unpack1('N')
        body = STDIN.read(length)
        break unless body && body.bytesize == length
        File.open('#{@requests}', 'a') { |f| f.puts body }
        sleep 0.3 if body == 'slow'
        exit 9 if body == 'exit'
        STDOUT.write(header + body)
        STDOUT.flush
      end
    RUBY
    File.chmod(0o755, @child)
    @relay = SSHRelay.new(Logger.new(File::NULL), idle_timeout: 0.15, command: @child)
    @clients = []
  end

  def teardown
    @relay.close
    @clients.each { |client| client.close rescue nil }
    FileUtils.remove_entry(@dir)
  end

  def connect
    server, client = UNIXSocket.pair
    @relay.accept(server)
    @clients << client
    client
  end

  def send_packet(client, body)
    client.write([body.bytesize].pack('N') + body)
  end

  def response(client)
    Timeout.timeout(3) do
      header = client.read(4)
      return nil unless header && header.bytesize == 4
      client.read(header.unpack1('N'))
    end
  end

  def exchange(client, body)
    send_packet(client, body)
    assert_equal body, response(client)
  end

  def pids
    File.exist?(@pids) ? File.readlines(@pids).map(&:to_i) : []
  end

  def wait_until
    Timeout.timeout(3) do
      loop do
        return if yield
        sleep 0.01
      end
    end
  end

  def test_idle_timeout_reuses_then_restarts_process_without_interrupting_request
    client = connect
    wait_until { pids.length == 1 }
    exchange(client, 'first')
    sleep 0.04
    exchange(client, 'second')
    assert_equal 1, pids.length
    exchange(client, 'slow')
    assert_equal 1, pids.length
    first_pid = pids.first
    wait_until { !File.exist?("/proc/#{first_pid}") }
    exchange(client, 'after idle')
    wait_until { pids.length == 2 }
    refute_equal first_pid, pids.last
  end

  def test_idle_timeout_starts_from_accept_even_without_request
    connect
    wait_until { pids.length == 1 }
    first_pid = pids.first
    wait_until { !File.exist?("/proc/#{first_pid}") }
  end

  def test_exited_process_fails_active_request_without_replay
    client = connect
    send_packet(client, 'exit')
    assert_nil response(client)
    next_client = connect
    exchange(next_client, 'next')
    wait_until { pids.length == 2 }
  end

  def test_disconnected_client_response_is_drained
    first = connect
    send_packet(first, 'slow')
    sleep 0.05
    first.close
    second = connect
    exchange(second, 'second')
    assert_equal 1, pids.length
  end

  def test_concurrent_requests_are_serialized_in_arrival_order
    first = connect
    second = connect
    send_packet(first, 'slow')
    wait_until { File.exist?(@requests) && File.read(@requests).include?('slow') }
    send_packet(second, 'second')
    assert_equal 'slow', response(first)
    assert_equal 'second', response(second)
    assert_equal ["slow\n", "second\n"], File.readlines(@requests)
    assert_equal 1, pids.length
  end

  def test_shutdown_stops_active_process
    client = connect
    send_packet(client, 'slow')
    wait_until { pids.length == 1 }
    pid = pids.first
    @relay.close
    wait_until { !File.exist?("/proc/#{pid}") }
  end
end
