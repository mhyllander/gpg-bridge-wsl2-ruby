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
    executable('gpgconf.exe', <<~SH)
      #!/bin/sh
      printf '%s\n' "$2" >> "$TEST_GPGCONF_CALLS"
      if [ -n "$TEST_GPG_SOCKET_PATHS" ]; then
        printf '%s/%s\n' "$TEST_ASSUAN_PATH" "$2"
      else
        printf '%s\n' "$TEST_ASSUAN_PATH"
      fi
    SH
    executable('gpgconf', "#!/bin/sh\nprintf '%s/%s\\n' \"$TEST_SOCK_DIR\" \"$2\"\n")
    executable('wslpath', "#!/bin/sh\nprintf '%s\\n' \"$2\"\n")
    executable('ip', "#!/bin/sh\nprintf 'default via 127.0.0.1 dev eth0\\n'\n")
    executable('npiperelay', <<~RUBY)
      #!/usr/bin/ruby
      valid_ssh = ARGV == ['-p', '-l', '-s', '-ep', '//./pipe/openssh-ssh-agent']
      gpg_sockets = %w[agent-socket agent-extra-socket agent-browser-socket]
      valid_gpg = ARGV.length == 4 && ARGV[0..2] == ['-a', '-ei', '-ep'] &&
                  ARGV[3].start_with?(ENV.fetch('TEST_ASSUAN_PATH') + '/') &&
                  gpg_sockets.include?(File.basename(ARGV[3]))
      exit 7 unless valid_ssh || valid_gpg
      File.open(ENV.fetch('TEST_CHILD_PIDS'), 'a') { |f| f.puts Process.pid }
      File.open(ENV.fetch('TEST_CHILD_ARGS'), 'a') { |f| f.puts ARGV.join(' ') }
      begin
        if valid_ssh
          loop do
            header = STDIN.read(4)
            break unless header && header.bytesize == 4
            length = header.unpack1('N')
            body = STDIN.read(length)
            break unless body && body.bytesize == length
            STDOUT.write(header + body)
            STDOUT.flush
          end
        else
          loop do
            data = STDIN.readpartial(4096)
            STDOUT.write(data)
            STDOUT.flush
          end
        end
      rescue EOFError
      end
    RUBY
    @env = {
      'PATH'               => "#{@bin}:/usr/bin:/bin",
      'TEST_SOCK_DIR'      => @dir,
      'TEST_CHILD_PIDS'    => File.join(@dir, 'pids'),
      'TEST_CHILD_ARGS'    => File.join(@dir, 'args'),
      'TEST_GPGCONF_CALLS' => File.join(@dir, 'gpgconf-calls'),
      'TEST_ASSUAN_PATH'   => File.join(@dir, 'assuan'),
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

  def test_ordinary_listener_reuses_one_ssh_child_for_concurrent_and_persistent_clients
    start_relay
    path = File.join(@dir, 'agent-ssh-socket')
    wait_for_socket(path)
    workers = %w[first second third fourth].map do |payload|
      Thread.new do
        UNIXSocket.open(path) do |client|
          assert_equal payload, ssh_exchange(client, payload)
          assert_equal payload + ' again', ssh_exchange(client, payload + ' again')
        end
      end
    end
    Timeout.timeout(5) { workers.each(&:value) }
    assert_equal 1, File.readlines(@env['TEST_CHILD_PIDS']).length
    stop_relay
    assert_children_exit(1)
  end

  def test_systemd_activated_listener_forwards_ssh
    path = File.join(@dir, 'activated.sock')
    @listen_socket = UNIXServer.new(path)
    start_relay(true)
    UNIXSocket.open(path) do |client|
      assert_equal 'hello through fd', ssh_exchange(client, 'hello through fd')
    end
    stop_relay
    assert_children_exit(1)
  end

  def test_gpg_uses_direct_assuan_in_mirrored_mode
    server = TCPServer.new('127.0.0.1', 0)
    nonce = 'a' * 16
    File.binwrite(@env['TEST_ASSUAN_PATH'], "#{server.addr[1]}\n#{nonce}")
    start_relay(false, 'mirrored')
    wait_for_socket(File.join(@dir, 'agent-socket'))
    exchange_gpg(server, nonce)
    stop_relay
  ensure
    server&.close
  end

  def test_gpg_uses_windows_relay_in_nat_mode
    server = TCPServer.new('127.0.0.1', 0)
    nonce = 'b' * 16
    File.binwrite(File.join(@dir, 'nonce'), nonce)
    start_relay(false, 'nat', server.addr[1])
    wait_for_socket(File.join(@dir, 'agent-socket'))
    exchange_gpg(server, nonce)
  ensure
    server&.close
  end

  def test_abrupt_gpg_client_disconnect_in_direct_mode
    server = TCPServer.new('127.0.0.1', 0)
    nonce = 'c' * 16
    File.binwrite(@env['TEST_ASSUAN_PATH'], "#{server.addr[1]}\n#{nonce}")
    start_relay(false, 'mirrored')
    wait_for_socket(File.join(@dir, 'agent-socket'))
    disconnect_gpg_client(server, nonce)
  ensure
    server&.close
  end

  def test_abrupt_gpg_client_disconnect_in_nat_mode
    server = TCPServer.new('127.0.0.1', 0)
    nonce = 'd' * 16
    File.binwrite(File.join(@dir, 'nonce'), nonce)
    start_relay(false, 'nat', server.addr[1])
    wait_for_socket(File.join(@dir, 'agent-socket'))
    disconnect_gpg_client(server, nonce)
  ensure
    server&.close
  end

  def test_npiperelay_gpg_forwards_concurrent_clients_and_closes_children
    start_relay(false, 'npiperelay')
    path = File.join(@dir, 'agent-socket')
    wait_for_socket(path)
    payloads = ['first' * 100, 'second' * 100]
    workers = payloads.map do |payload|
      Thread.new do
        UNIXSocket.open(path) do |client|
          client.write(payload)
          client.shutdown(Socket::SHUT_WR)
          assert_equal payload, Timeout.timeout(5) {client.read}
        end
      end
    end
    Timeout.timeout(5) {workers.each(&:value)}
    assert_children_exit(2)
    assert_equal(2, File.readlines(@env['TEST_CHILD_ARGS']).count {|line| line.include?('-a -ei -ep ' + @env['TEST_ASSUAN_PATH'] + '/agent-socket')})
    assert_equal(1, File.readlines(@env['TEST_GPGCONF_CALLS']).count {|line| line.chomp == 'agent-socket'})
  end

  def test_npiperelay_gpg_works_without_ssh_support
    start_relay(false, 'npiperelay', nil, false)
    path = File.join(@dir, 'agent-extra-socket')
    wait_for_socket(path)
    UNIXSocket.open(path) do |client|
      client.write('gpg request')
      client.shutdown(Socket::SHUT_WR)
      assert_equal 'gpg request', Timeout.timeout(5) {client.read}
    end
    assert_children_exit(1)
    assert_includes File.read(@env['TEST_CHILD_ARGS']), '-a -ei -ep ' + @env['TEST_ASSUAN_PATH'] + '/agent-extra-socket'
  end

  def test_systemd_activated_listener_forwards_gpg_with_npiperelay
    path = File.join(@dir, 'activated-gpg.sock')
    @listen_socket = UNIXServer.new(path)
    start_relay(true, 'npiperelay', nil, false, 'agent-browser-socket')
    UNIXSocket.open(path) do |client|
      client.write('activated gpg')
      client.shutdown(Socket::SHUT_WR)
      assert_equal 'activated gpg', Timeout.timeout(5) {client.read}
    end
    assert_children_exit(1)
    assert_includes File.read(@env['TEST_CHILD_ARGS']), '-a -ei -ep ' + @env['TEST_ASSUAN_PATH'] + '/agent-browser-socket'
  end

  def test_missing_npiperelay_in_gpg_mode_reports_error
    File.unlink(File.join(@bin, 'npiperelay'))
    output = IO.popen(@env, ['/usr/bin/ruby', WSL, '--mode', 'npiperelay', '--noncefile', File.join(@dir, 'nonce')], err: %i[child out], &:read)
    refute $?.success?
    assert_includes output, 'cannot find npiperelay in PATH'
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
          socket = TCPSocket.new('127.0.0.1', first_port + offset)
          socket.close
          break
        rescue Errno::ECONNREFUSED
          sleep 0.02
        end
      end
    end
    assert_raises(Errno::ECONNREFUSED) {TCPSocket.new('127.0.0.1', first_port + 3)}
  rescue Timeout::Error
    warn File.read(File.join(@dir, 'win-relay.log')) if File.exist?(File.join(@dir, 'win-relay.log'))
    raise
  end

  def test_missing_npiperelay_reports_error
    File.unlink(File.join(@bin, 'npiperelay'))
    output = IO.popen(@env, ['/usr/bin/ruby', WSL, '--enable-ssh-support', '--noncefile', File.join(@dir, 'nonce')], err: %i[child out], &:read)
    refute $?.success?
    assert_includes output, 'cannot find npiperelay in PATH'
  end

  private

  def ssh_exchange(client, payload)
    client.write([payload.bytesize].pack('N') + payload)
    header = Timeout.timeout(5) { client.read(4) }
    raise 'missing SSH response header' unless header && header.bytesize == 4

    length = header.unpack1('N')
    response = Timeout.timeout(5) { client.read(length) }
    raise 'incomplete SSH response' unless response && response.bytesize == length

    response
  end

  def executable(name, body)
    path = File.join(@bin, name)
    File.write(path, body)
    File.chmod(0o755, path)
  end

  def start_relay(systemd = false, mode = 'mirrored', port = nil, ssh = true, listen_name = 'agent-ssh-socket')
    env = @env.dup
    env['TEST_GPG_SOCKET_PATHS'] = '1' if mode == 'npiperelay'
    args = ['/usr/bin/ruby', WSL, '--noncefile', File.join(@dir, 'nonce'), '--mode', mode]
    args << '--enable-ssh-support' if ssh
    args.concat(['--port', port.to_s]) if port
    if systemd
      env['LISTEN_FDNAMES'] = listen_name
      env['LISTEN_FDS'] = '1'
      args << '--systemd'
      @relay_pid = Process.spawn(env, *args, 3 => @listen_socket, :out => File::NULL, :err => File.join(@dir, 'relay.log'))
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
      assert_equal Digest::SHA256.hexdigest(request), Digest::SHA256.hexdigest(Timeout.timeout(5) {peer.read})
      peer.write(response)
      peer.shutdown(Socket::SHUT_WR)
      peer.close
    end
    UNIXSocket.open(File.join(@dir, 'agent-socket')) do |client|
      client.write(request)
      client.shutdown(Socket::SHUT_WR)
      assert_equal Digest::SHA256.hexdigest(response), Digest::SHA256.hexdigest(Timeout.timeout(5) {client.read})
    end
    Timeout.timeout(5) {responder.value}
  end

  def disconnect_gpg_client(server, nonce)
    responder = Thread.new do
      peer = server.accept
      assert_equal nonce, peer.read(16)
      assert_equal 'ping', peer.read(4)
      peer.write('ready')
      assert_equal '', Timeout.timeout(5) {peer.read}
      peer.close
    end
    client = UNIXSocket.new(File.join(@dir, 'agent-socket'))
    client.write('ping')
    assert_equal 'ready', Timeout.timeout(5) {client.read(5)}
    client.close
    Timeout.timeout(5) {responder.value}
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
        break if pids.length == count && pids.all? {|pid| !File.exist?("/proc/#{pid}")}

        sleep 0.02
      end
    end
    assert_equal count, pids.length
  end
end
