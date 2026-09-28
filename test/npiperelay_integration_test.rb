require 'minitest/autorun'
require 'tmpdir'
require 'fileutils'
require 'socket'
require 'timeout'
require 'digest'

class NpiperelayIntegrationTest < Minitest::Test
  ROOT = File.expand_path('..', __dir__)
  WSL = File.join(ROOT, 'gpg_relay_wsl.rb')
  WIN = File.join(ROOT, 'gpg_relay_win.rb')

  def setup
    @dir = Dir.mktmpdir('gpg-relay-test-')
    @bin = File.join(@dir, 'bin')
    Dir.mkdir(@bin)
    executable('ruby.exe', "#!/bin/sh\nexit 0\n")
    executable('gpg-agent.exe', "#!/bin/sh\nexit 0\n")
    executable('gpg-connect-agent.exe', "#!/bin/sh\nexit 0\n")
    executable('gpgconf.exe', "#!/bin/sh\nprintf '%s\\n' \"$TEST_ASSUAN_PATH\"\n")
    executable('gpgconf', "#!/bin/sh\nprintf '%s/%s\\n' \"$TEST_SOCK_DIR\" \"$2\"\n")
    executable('wslpath', "#!/bin/sh\nprintf '%s\\n' \"$2\"\n")
    executable('ip', "#!/bin/sh\nprintf 'default via 127.0.0.1 dev eth0\\n'\n")
    executable('npiperelay', <<~RUBY)
      #!/usr/bin/ruby
      exit 7 unless ARGV == ['-ei', '-s', '//./pipe/openssh-ssh-agent']
      File.open(ENV.fetch('TEST_CHILD_PIDS'), 'a') { |f| f.puts Process.pid }
      begin
        loop do
          data = STDIN.readpartial(4096)
          STDOUT.write(data)
          STDOUT.flush
        end
      rescue EOFError
      end
    RUBY
    @env = {
      'PATH' => "#{@bin}:/usr/bin:/bin",
      'TEST_SOCK_DIR' => @dir,
      'TEST_CHILD_PIDS' => File.join(@dir, 'pids'),
      'TEST_ASSUAN_PATH' => File.join(@dir, 'assuan')
    }
    @relay_pid = nil
    @listen_socket = nil
  end

  def teardown
    stop_relay
  rescue Errno::ESRCH
  ensure
    @listen_socket&.close
    FileUtils.remove_entry(@dir)
  end

  def test_ordinary_listener_handles_concurrent_clients_and_closes_children
    start_relay
    path = File.join(@dir, 'agent-ssh-socket')
    wait_for_socket(path)
    payloads = [("first" * 100), ("second" * 100)]
    workers = payloads.map do |payload|
      Thread.new do
        UNIXSocket.open(path) do |client|
          client.write(payload)
          client.shutdown(Socket::SHUT_WR)
          assert_equal payload, client.read
        end
      end
    end
    Timeout.timeout(5) { workers.each(&:value) }
    assert_children_exit(2)
  end

  def test_systemd_activated_listener_forwards_ssh
    path = File.join(@dir, 'activated.sock')
    @listen_socket = UNIXServer.new(path)
    start_relay(true)
    UNIXSocket.open(path) do |client|
      client.write('hello through fd')
      client.shutdown(Socket::SHUT_WR)
      assert_equal 'hello through fd', Timeout.timeout(5) { client.read }
    end
    assert_children_exit(1)
  end

  def test_gpg_uses_direct_assuan_in_wsl1_and_mirrored_modes
    %w[wsl1 wsl2_mirrored].each do |mode|
      server = TCPServer.new('127.0.0.1', 0)
      nonce = 'a' * 16
      File.binwrite(@env['TEST_ASSUAN_PATH'], "#{server.addr[1]}\n#{nonce}")
      start_relay(false, mode)
      wait_for_socket(File.join(@dir, 'agent-socket'))
      exchange_gpg(server, nonce)
      stop_relay
      server.close
    end
  end

  def test_gpg_uses_windows_relay_in_nat_mode
    server = TCPServer.new('127.0.0.1', 0)
    nonce = 'b' * 16
    File.binwrite(File.join(@dir, 'nonce'), nonce)
    start_relay(false, 'wsl2_nat', server.addr[1])
    wait_for_socket(File.join(@dir, 'agent-socket'))
    exchange_gpg(server, nonce)
  ensure
    server&.close
  end

  def test_abrupt_gpg_client_disconnect_in_direct_mode
    server = TCPServer.new('127.0.0.1', 0)
    nonce = 'c' * 16
    File.binwrite(@env['TEST_ASSUAN_PATH'], "#{server.addr[1]}\n#{nonce}")
    start_relay(false, 'wsl2_mirrored')
    wait_for_socket(File.join(@dir, 'agent-socket'))
    disconnect_gpg_client(server, nonce)
  ensure
    server&.close
  end

  def test_abrupt_gpg_client_disconnect_in_nat_mode
    server = TCPServer.new('127.0.0.1', 0)
    nonce = 'd' * 16
    File.binwrite(File.join(@dir, 'nonce'), nonce)
    start_relay(false, 'wsl2_nat', server.addr[1])
    wait_for_socket(File.join(@dir, 'agent-socket'))
    disconnect_gpg_client(server, nonce)
  ensure
    server&.close
  end

  def test_windows_relay_opens_only_three_gpg_ports
    probe = TCPServer.new('127.0.0.1', 0)
    first_port = probe.addr[1]
    probe.close
    @relay_pid = Process.spawn(@env, '/usr/bin/ruby', WIN,
                               '--noncefile', File.join(@dir, 'win-nonce'),
                               '--port', first_port.to_s,
                               '--windows-address', '127.0.0.1',
                               chdir: @dir, out: File::NULL,
                               err: File.join(@dir, 'win-relay.log'))
    (0..2).each do |offset|
      Timeout.timeout(5) do
        loop do
          begin
            socket = TCPSocket.new('127.0.0.1', first_port + offset)
            socket.close
            break
          rescue Errno::ECONNREFUSED
            sleep 0.02
          end
        end
      end
    end
    assert_raises(Errno::ECONNREFUSED) { TCPSocket.new('127.0.0.1', first_port + 3) }
  rescue Timeout::Error
    warn File.read(File.join(@dir, 'win-relay.log')) if File.exist?(File.join(@dir, 'win-relay.log'))
    raise
  end

  def test_missing_npiperelay_reports_error
    File.unlink(File.join(@bin, 'npiperelay'))
    output = IO.popen(@env, ['/usr/bin/ruby', WSL, '--enable-ssh-support', '--noncefile', File.join(@dir, 'nonce')], err: [:child, :out], &:read)
    refute $?.success?
    assert_includes output, 'cannot find npiperelay in PATH'
  end

  private

  def executable(name, body)
    path = File.join(@bin, name)
    File.write(path, body)
    File.chmod(0o755, path)
  end

  def start_relay(systemd = false, mode = 'wsl2_mirrored', port = nil)
    env = @env.dup
    args = ['/usr/bin/ruby', WSL, '--enable-ssh-support', '--noncefile', File.join(@dir, 'nonce'), '--wsl-mode', mode]
    args.concat(['--port', port.to_s]) if port
    if systemd
      env['LISTEN_FDNAMES'] = 'agent-ssh-socket'
      env['LISTEN_FDS'] = '1'
      args << '--systemd'
      @relay_pid = Process.spawn(env, *args, 3 => @listen_socket, out: File::NULL, err: File.join(@dir, 'relay.log'))
    else
      @relay_pid = Process.spawn(env, *args, out: File::NULL, err: File.join(@dir, 'relay.log'))
    end
  end

  def stop_relay
    return unless @relay_pid

    Process.kill('TERM', @relay_pid)
    Process.wait(@relay_pid)
    @relay_pid = nil
  rescue Errno::ESRCH, Errno::ECHILD
    @relay_pid = nil
  end

  def exchange_gpg(server, nonce)
    request = 'request' * 4096
    response = 'response' * 4096
    responder = Thread.new do
      peer = server.accept
      assert_equal nonce, peer.read(16)
      assert_equal Digest::SHA256.hexdigest(request), Digest::SHA256.hexdigest(Timeout.timeout(5) { peer.read })
      peer.write(response)
      peer.shutdown(Socket::SHUT_WR)
      peer.close
    end
    UNIXSocket.open(File.join(@dir, 'agent-socket')) do |client|
      client.write(request)
      client.shutdown(Socket::SHUT_WR)
      assert_equal Digest::SHA256.hexdigest(response), Digest::SHA256.hexdigest(Timeout.timeout(5) { client.read })
    end
    Timeout.timeout(5) { responder.value }
  end

  def disconnect_gpg_client(server, nonce)
    responder = Thread.new do
      peer = server.accept
      assert_equal nonce, peer.read(16)
      assert_equal 'ping', peer.read(4)
      peer.write('ready')
      assert_equal '', Timeout.timeout(5) { peer.read }
      peer.close
    end
    client = UNIXSocket.new(File.join(@dir, 'agent-socket'))
    client.write('ping')
    assert_equal 'ready', Timeout.timeout(5) { client.read(5) }
    client.close
    Timeout.timeout(5) { responder.value }
  ensure
    client&.close unless client&.closed?
  end

  def wait_for_socket(path)
    Timeout.timeout(5) do
      sleep 0.02 until File.socket?(path)
    end
  rescue Timeout::Error
    raise
  end

  def assert_children_exit(count)
    pids = nil
    Timeout.timeout(5) do
      loop do
        pids = File.exist?(@env['TEST_CHILD_PIDS']) ? File.readlines(@env['TEST_CHILD_PIDS']).map(&:to_i) : []
        break if pids.length == count && pids.all? { |pid| !File.exist?("/proc/#{pid}") }
        sleep 0.02
      end
    end
    assert_equal count, pids.length
  end
end
