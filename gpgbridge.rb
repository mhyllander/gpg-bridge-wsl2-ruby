#!/usr/bin/env ruby
# gpgbridge.rb forwards requests from gpg clients in WSL1 and WSL2 to
# Gpg4win's gpg-agent.exe in Windows. It can also forward ssh requests to
# gpg-agent.exe, when using a PGP key for ssh authentication.

require 'optparse'
require 'socket'
require 'date'
require 'sys/proctable'
require 'logger'

FIRST_PORT = 6910
BUFSIZ = 4096

class Relay
  def initialize(options, logger)
    @options = options
    @logger = logger
  end

  def dial_assuan(socket_path)
    # the assuan "socket" file contains a port number (ascii characters), followed by a new line character (10), then a
    # nonce (16 bytes)
    bytes = []
    File.open(socket_path, 'rb') do |f|
      f.each_byte do |b|
        bytes << b
      end
    end
    sep = bytes.index(10)
    port = bytes.slice(0, sep).pack('C*').to_i
    nonce = bytes.slice(sep + 1, bytes.length)
    @logger.debug {"assuan socket #{socket_path} -> TCP 127.0.0.1:#{port}"}
    if nonce.length != 16
      @logger.error {"#{socket_path} nonce length is #{nonce.length} != 16"}
      exit 1
    end
    gpg_agent = TCPSocket.new '127.0.0.1', port
    gpg_agent.write nonce.pack('C16') # send the nonce to "authenticate"
    gpg_agent
  end

  def relay(client, server)
    Thread.new do
      loop = true
      while loop
        ready = IO.select([client, server])
        readable = ready[0]
        if readable.include?(client)
          @logger.debug 'msg from client'
          begin
            msg = client.recv BUFSIZ
            @logger.debug "msg from client: (len=#{msg&.length})"
            if msg.nil? # || msg.empty?
              loop = false
            else
              server.send msg, 0
            end
          rescue Errno::ECONNRESET => e
            @logger.error "Exception while receiving msg from client: #{e.inspect}"
            Thread.exit
          rescue StandardError => e
            @logger.error "StandardError while receiving msg from client: #{e.inspect}"
            Thread.exit
          end
        end

        next unless readable.include?(server)

        @logger.debug 'msg from server'
        begin
          msg = server.recv BUFSIZ
          @logger.debug "msg from gpg_agent: (len=#{msg&.length})"
          if msg.nil? # || msg.empty?
            loop = false
          else
            client.send msg, 0
          end
        rescue Errno::ECONNRESET => e
          @logger.error "Exception while receiving msg from gpg_agent: #{e.inspect}"
          Thread.exit
        rescue StandardError => e
          @logger.error "StandardError while receiving msg from gpg_agent: #{e.inspect}"
          Thread.exit
        end
      end
    ensure
      @logger.debug 'closing sockets'
      client.close
      server.close
    end
  end
end

# WslBridge runs in WSL. It receives requests from WSL clients through local sockets and either connects directly with
# gpg_agent.exe using its Assuan sockets (in Windows), or relays them to WindowsBridge (in Windows).
class WslBridge < Relay
  def initialize(options, logger)
    super options, logger

    @pidfile = options[:pidfile]

    # setup cleanup handlers
    at_exit {cleanup}

    # stop gpg-agent if running in WSL
    @logger.info 'stop gpg-agent'
    # %x[gpg-connect-agent killagent /bye]
    %x[pkill gpg-agent]

    remote_address = options[:remote_address]
    socket_names = options[:socket_names]
    noncefile = options[:noncefile]

    # start WindowsBridge if needed for relaying
    start_windows_bridge options if socket_names.detect {|k, v| v[:type] == :relay}

    # start socket listeners
    @threads = if systemd_enabled?
                 # Use systemd socket activation - listen fds are passed by systemd
                 socket_names.collect do |socket_name, config|
                   fd = fd_for_socket_name(socket_name)
                   if fd.nil?
                     @logger.error "No listen fd found for socket #{socket_name}"
                     next nil
                   end
                   Thread.start(socket_name, remote_address, config, noncefile, fd) do |s, r, c, n, f|
                     start_socket_listener_fd s, r, c, n, f
                   end
                 end.compact
               else
                 # Use traditional socket creation
                 socket_names.collect do |socket_name, config|
                   Thread.start(socket_name, remote_address, config, noncefile) do |s, r, c, n|
                     start_socket_listener s, r, c, n
                   end
                 end
               end
  end

  def cleanup
    # stop_windows_bridge
    File.unlink @pidfile if @pidfile
    # Close listen fds when using systemd socket activation
    if systemd_enabled?
      listen_names.each do |name|
        fd = fd_for_socket_name(name)
        begin
          IO.new(fd).close if fd
        rescue StandardError => e
          @logger.error "Failed to close listen fd for #{name}: #{e.inspect}"
        end
      end
    end
    @logger.info 'exiting'
  end

  def start_windows_bridge(options)
    @logger.info 'start windows bridge'

    opts = ['--windows-bridge']

    noncedir = File.dirname options[:noncefile]
    file = File.basename options[:noncefile]
    noncefile = "#{%x[wslpath -w '#{noncedir}'].chomp}\\#{file}"
    opts += ['--noncefile', noncefile]

    opts += ['--wsl-mode', options[:wsl_mode]] if options[:wsl_mode]
    opts += ['--enable-ssh-support'] if options[:enable_ssh_support]
    opts += ['--remote-address', options[:windows_address]] if options[:windows_address]
    opts += ['--port', options[:port].to_s] if options[:port]
    opts += ['--logfile', options[:windows_logfile]] if options[:windows_logfile]
    opts += ['--pidfile', options[:windows_pidfile]] if options[:windows_pidfile]
    opts += ['--log-level', options[:log_level]] if options[:log_level]

    winpath = %x[wslpath -w '#{__FILE__}'].chomp

    @winbridge = Process.fork do
      Process.setsid
      exit 0 unless Process.fork.nil?
      Process.exec 'ruby.exe', winpath, *opts
    end
    Process.detach @winbridge
  end

  def stop_windows_bridge
    p = Sys::ProcTable.ps(pid: @winbridge)
    if p && p.cmdline =~ /ruby.*gpgbridge\.rb/
      @logger.debug {"stop_windows_bridge #{@winbridge}"}
      Process.kill 'TERM', @winbridge
    end
  rescue StandardError => e
    @logger.error 'stop_windows_bridge exception'
    @logger.error e
  end

  def start_socket_listener(socket_name, remote_address, config, noncefile)
    socket_path = %x[gpgconf --list-dirs #{socket_name}].chomp
    assuan_socket_path = %x[gpgconf.exe --list-dirs #{socket_name}].chomp
    assuan_socket_path = %x[wslpath -u '#{assuan_socket_path}'].chomp
    @logger.info {"start listener on WSL socket #{socket_name} = #{socket_path}"}
    File.unlink(socket_path) if File.exist?(socket_path) && File.socket?(socket_path)
    Socket.unix_server_loop(socket_path) do |client, _client_addrinfo|
      @logger.debug {"got connect request on WSL socket #{socket_name} = #{socket_path}"}
      server = if config[:type] == :relay
                 dial_winbridge remote_address, config[:port], noncefile
               else
                 dial_assuan assuan_socket_path
               end
      if server.nil?
        sock.close
      else
        @logger.debug 'connected'
        relay client, server
      end
    end
  end

  def start_socket_listener_fd(socket_name, remote_address, config, noncefile, fd)
    @logger.info {"start listener on systemd fd #{fd} for #{socket_name}"}
    assuan_socket_path = %x[gpgconf.exe --list-dirs #{socket_name}].chomp
    assuan_socket_path = %x[wslpath -u '#{assuan_socket_path}'].chomp
    unix_server = UNIXServer.new(fd)
    unix_server.listen 5
    loop do
      client = unix_server.accept
      @logger.debug {"got connect request on WSL socket #{socket_name} via fd #{fd}"}
      server = if config[:type] == :relay
                 dial_winbridge remote_address, config[:port], noncefile
               else
                 dial_assuan assuan_socket_path
               end
      if server.nil?
        client.close
      else
        @logger.debug 'connected'
        relay client, server
      end
    end
  end

  def dial_winbridge(remote_address, port, noncefile)
    # get WindowsBridge nonce
    nonce = get_nonce noncefile
    winbridge = nil
    begin
      @logger.debug 'connect with winbridge'
      winbridge = TCPSocket.new remote_address, port
      # send the nonce to authenticate, if the nonce is wrong the connection will be closed immediately
      winbridge.send nonce, 0
    rescue Errno::ETIMEDOUT => e
      @logger.error "Exception while connecting with winbridge: #{e.inspect}"
    end
    winbridge
  end

  def get_nonce(noncefile)
    unless File.exist? noncefile
      @logger.error {"missing noncefile #{noncefile}"}
      return ''
    end
    nonce = []
    File.open(noncefile, 'rb') do |f|
      f.each_byte do |b|
        nonce << b
        break if nonce.length == 16 # break when 16 bytes have been read
      end
    end
    nonce.pack('C16')
  end

  def systemd_enabled?
    options[:systemd] == true
  end

  def listen_fds
    ENV['LISTEN_FDS'].to_i
  end

  def listen_names
    names_env = ENV['LISTEN_NAMES']
    return [] if names_env.nil? || names_env.empty?

    names_env.split(':')
  end

  def fd_for_socket_name(socket_name)
    names = listen_names
    idx = names.index(socket_name)
    return nil if idx.nil?

    3 + idx # LISTEN_FDS starts at fd 3
  end

  def trap_signals
    Signal.trap('HUP') do
      exit 0
    end
    Signal.trap('INT') do
      exit 0
    end
    Signal.trap('TERM') do
      exit 0
    end
  end

  def run
    trap_signals
    @threads.each(&:join)
  end
end

# WindowsBridge runs in Windows. It receives requests over the network from
# WslBridge and forwards them through the assuan sockets to gpg-agent.exe
# from Gpg4Win. It can forward both gpg and SSH Pageant requests.
class WindowsBridge < Relay
  def initialize(options, logger)
    super options, logger

    @noncefile = options[:noncefile]
    @pidfile = options[:pidfile]

    # make sure gpg-agent.exe is running
    system 'gpg-connect-agent.exe /bye 2>nul'

    # create nonce
    nonce = create_nonce @noncefile

    # setup cleanup handlers
    at_exit {cleanup}

    @logger.debug 'start proxies'
    remote_address = options[:remote_address]
    # select the sockets to relay, which depends on the WSL mode
    socket_names = options[:socket_names].select {|_, v| v[:type] == :relay}
    @threads = socket_names.collect do |socket_name, config|
      Thread.start(socket_name, remote_address, config, nonce) do |s, r, c, n|
        if s == 'agent-ssh-socket'
          start_pageant_proxy s, r, c, n
        else
          start_assuan_proxy s, r, c, n
        end
      end
    end
  end

  def cleanup
    File.unlink @noncefile if @noncefile
    File.unlink @pidfile if @pidfile
    @logger.info 'exiting'
  end

  def create_nonce(noncefile)
    nonce = Random.new.bytes(16)
    File.write(noncefile, nonce)
    @logger.debug {"created nonce in noncefile #{noncefile}: #{nonce.unpack('C*')}"}
    nonce
  end

  def start_assuan_proxy(socket_name, remote_address, config, nonce)
    port = config[:port]
    socket_path = %x[gpgconf.exe --list-dirs #{socket_name}].chomp
    @logger.info {"start assuan socket proxy for #{socket_name} = #{socket_path} on port #{port}"}
    Socket.tcp_server_loop(remote_address, port) do |sock, _client_addrinfo|
      @logger.debug {"got bridge connect request on port #{port} for #{socket_name}"}
      wsl_bridge_nonce = sock.recv 16
      if wsl_bridge_nonce != nonce
        @logger.error {"received wrong nonce from WSL bridge on port #{port} for #{socket_name}: #{wsl_bridge_nonce.unpack('C*')}"}
        sock.close
      else
        @logger.info {"got correct nonce on port #{port} for #{socket_name}"}
        gpg_agent = dial_assuan socket_path
        relay sock, gpg_agent
      end
    end
  end

  def start_pageant_proxy(socket_name, remote_address, config, nonce)
    port = config[:port]
    @logger.info {"start Pageant proxy for #{socket_name} on port #{port}"}
    Socket.tcp_server_loop(remote_address, port) do |sock, _client_addrinfo|
      @logger.debug {"got bridge connect request on port #{port} for #{socket_name}"}
      wsl_bridge_nonce = sock.recv 16
      if wsl_bridge_nonce != nonce
        @logger.error {"received wrong nonce from WSL bridge on port #{port} for #{socket_name}: #{wsl_bridge_nonce.unpack('C*')}"}
        sock.close
      else
        @logger.info {"got correct nonce on port #{port} for #{socket_name}"}
        relay_pageant sock
      end
    end
  end

  def relay_pageant(client)
    Thread.new do
      # the pageant "socket" isn't a real socket (not an IO), can't be used in IO.select.
      pageant = Net::SSH::Authentication::Pageant::SocketWithTimeout.open
      loop do
        ready = IO.select([client])
        readable = ready[0]

        next unless readable.include?(client)

        @logger.debug 'msg from client'
        begin
          msg = client.recv BUFSIZ
          @logger.debug "msg from client: (len=#{msg&.length})"
          if msg.nil? # || msg.empty?
            Thread.exit
          else
            pageant = send_pageant_response pageant, client, msg
          end
        rescue Errno::ECONNRESET => e
          @logger.error "Exception while receiving msg from client: #{e.inspect}"
          Thread.exit
        rescue StandardError => e
          @logger.error "StandardError while receiving msg from client: #{e.inspect}"
          Thread.exit
        end
      end
    ensure
      @logger.debug 'closing sockets'
      client.close
      pageant.close
    end
  end

  def send_pageant_response(pageant, client, msg)
    tries = 3
    begin
      pageant.send msg, 0
    rescue Net::SSH::Exception => e
      if tries > 0
        if e.message == 'Message failed with error: 1460'
          # ERROR_TIMEOUT
          @logger.warn 'send to pageant timeout, retrying'
          tries -= 1
          retry
        elsif e.message == 'Message failed with error: 1400'
          # ERROR_INVALID_WINDOW_HANDLE
          @logger.warn 'lost connection with pageant, reconnecting'
          pageant = Net::SSH::Authentication::Pageant::SocketWithTimeout.open
          tries -= 1
          retry
        end
      end

      @logger.error 'send to pageant exception'
      @logger.error e
      raise
    end

    begin
      msg = pageant.read BUFSIZ
      @logger.debug "msg from pageant: (len=#{msg&.length})"
      if msg.nil? # || msg.empty?
        Thread.exit
      else
        client.send msg, 0
      end
    rescue Errno::ECONNRESET => e
      @logger.error "Exception while receiving msg from pageant: #{e.inspect}"
      Thread.exit
    rescue StandardError => e
      @logger.error "StandardError while receiving msg from pageant: #{e.inspect}"
      Thread.exit
    end

    pageant # return in case it was reconnected
  end

  def trap_signals
    Signal.trap('INT', 'SIG_IGN')
  end

  def run
    trap_signals
    @threads.each(&:join)
  end
end

def suppress_std_in_out
  # redirect stdin to /dev/null to avoid reading from tty
  $stdin.reopen('/dev/null', 'r')
  # redirect stdout and stderr to /dev/null
  $stderr.reopen('/dev/null', 'a')
  $stdout.reopen($stderr)
end

def redirect_std_in_out(logfile)
  # redirect stdin to /dev/null to avoid reading from tty
  $stdin.reopen('/dev/null', 'r')
  # redirect stdout and stderr to logfile
  f = File.open(logfile, mode: 'a', perm: 0o644, flags: File::LOCK_UN)
  $stderr.reopen(f)
  $stdout.reopen($stderr)
  $stdout.sync = $stderr.sync = true
end

def daemonize
  exit 0 unless Process.fork.nil?
  Process.setsid
  exit 0 unless Process.fork.nil?
end

def get_logger(level, windows_bridge)
  Logger.new($stderr,
             'weekly',
             level:    level,
             progname: "#{windows_bridge ? 'Win' : 'WSL'}-bridge")
end

LEVELS = %w[DEBUG INFO WARN ERROR FATAL UNKNOWN].freeze

# Windows bridge
#
# gpg_agent.exe is listening on port 127.0.0.1 in the Windows VM.
#
# 1. WSL2 in NAT networking mode can connect to the Windows VM via the default gateway. The WinBridge must listen on
#    0.0.0.0, and all gpg-agent.exe ports must be proxied.
# 2. WSL2 in mirrored networking mode, and WSL1, can connect to gpg_agent.exe on 127.0.0.1 directly. The WinBridge is
#    would ideally not be needed in this case, but there is an issue with the SSH socket.
#
# gpg_agent.exe is unfortunately not responding on the SSH socket. The workaround is to use the PuTTY Pageant protocol.
# This means that when SSH support is enabled, the WinBridge must always be started to proxy the ssh port.
#
# Summary: The WinBridge must be deployed, to proxy either all sockets when WSL2 is in NAT networking mode, or proxy the
# SSH socket in all other cases.

options = {
  wsl_mode:           'wsl2_mirrored',
  remote_address:     '127.0.0.1',
  windows_address:    '127.0.0.1',
  enable_ssh_support: false,
  daemon:             false,
  port:               FIRST_PORT,
  noncefile:          nil,
  logfile:            nil,
  pidfile:            nil,
  log_level:          'WARN',
  windows_bridge:     false,
  windows_logfile:    nil,
  windows_pidfile:    nil,
  systemd:            false,
}

OptionParser.new do |opts|
  opts.banner = 'Usage: gpgbridge.rb [options]'

  opts.on('-m', '--wsl-mode MODE', String, "The WSL networking mode (wsl1, wsl2_nat, wsl2_mirrored) [#{options[:wsl_mode]}]") do |v|
    options[:wsl_mode] = v
    case v
    when 'wsl2_nat'
      options[:remote_address] = Regexp.last_match(1) if %x[ip route].split("\n").grep(/^default via /).first =~ /^default via ([0-9.]+)/
      options[:windows_address] = '0.0.0.0'
    when 'wsl1', 'wsl2_mirrored'
      options[:remote_address] = '127.0.0.1'
      options[:windows_address] = '127.0.0.1'
    else
      warn "Unknown WSL mode: #{v}"
      exit 1
    end
  end
  opts.on('-s', '--[no-]enable-ssh-support', 'Enable proxying of gpg-agent SSH sockets') do |v|
    options[:enable_ssh_support] = v
  end
  opts.on('-r', '--remote-address IPADDR', String, "The remote address of the Windows bridge component [#{options[:remote_address]}]") do |v|
    options[:remote_address] = v
  end
  opts.on('-p', '--port PORT', Integer, 'The first port (of three or four) to use for proxying sockets') do |v|
    options[:port] = v
  end
  opts.on('-n', '--noncefile PATH', String, 'The nonce file path (defaults to file in Windows gpg homedir)') do |v|
    options[:noncefile] = v
  end
  opts.on('-l', '--logfile PATH', String, 'The log file path') do |v|
    options[:logfile] = v
  end
  opts.on('-i', '--pidfile PATH', String, 'The PID file path') do |v|
    options[:pidfile] = v
  end

  opts.on('-d', '--[no-]daemon', 'Run as a daemon in the background') do |v|
    options[:daemon] = v
  end
  opts.on('-v', '--log-level LEVEL', LEVELS, "Logging level (#{LEVELS.join(', ')}) [#{options[:log_level]}]") do |v|
    options[:log_level] = v
  end

  opts.on('-W', '--[no-]windows-bridge', 'Start the Windows bridge (used by the WSL bridge)') do |v|
    options[:windows_bridge] = v
  end
  opts.on('--systemd', 'Use systemd socket activation (listen fds passed by systemd)') do
    options[:systemd] = true
  end
  opts.on('-R', '--windows-address IPADDR', String, "The IP listening address of the Windows bridge [#{options[:windows_address]}]") do |v|
    options[:windows_address] = v
  end
  opts.on('-L', '--windows-logfile PATH', String, 'The log file path of the Windows bridge') do |v|
    options[:windows_logfile] = v
  end
  opts.on('-I', '--windows-pidfile PATH', String, 'The PID file path of the Windows bridge') do |v|
    options[:windows_pidfile] = v
  end
  opts.on('-h', '--help', 'Prints this help') do
    puts opts
    exit
  end
end.parse!

windows_bridge = options[:windows_bridge]

logger = get_logger options[:log_level], options[:windows_bridge]

unless windows_bridge
  require 'ptools'
  unless File.which('ruby.exe')
    logger.error {"cannot find ruby.exe in the PATH: #{ENV['PATH']}"}
    exit 2
  end
  unless File.which('gpgconf.exe')
    logger.error {"cannot find gpgconf.exe in the PATH: #{ENV['PATH']}"}
    exit 2
  end
  unless File.which('gpg-agent.exe')
    logger.error {"cannot find gpg-agent.exe in the PATH: #{ENV['PATH']}"}
    exit 2
  end
end

if options[:noncefile].nil?
  begin
    win_gpghome = %x[gpgconf.exe --list-dirs homedir].chomp
    noncefile = 'gpgbridge.nonce'
    options[:noncefile] = if windows_bridge
                            "#{win_gpghome}\\#{noncefile}"
                          else
                            "#{%x[wslpath -u '#{win_gpghome}'].chomp}/#{noncefile}"
                          end
  rescue StandardError => e
    logger.error 'constructing path to noncefile'
    logger.error e
    exit 1
  end
end

if options[:pidfile] && !options[:systemd] && File.exist?(options[:pidfile])
  pid = File.read(options[:pidfile]).chomp.to_i
  p = Sys::ProcTable.ps(pid: pid)
  if p && p.cmdline =~ /ruby.*gpgbridge\.rb/
    logger.debug {"detected gpgbridge.rb running as pid #{pid}, exiting"}
    exit 0
  end
end

if options[:daemon] && !options[:systemd]
  if options[:pidfile].nil?
    logger.error 'Missing pidfile argument'
    exit 1
  end
  daemonize
  if options[:logfile]
    redirect_std_in_out options[:logfile]
  else
    suppress_std_in_out
  end
elsif options[:logfile] && !options[:systemd]
  redirect_std_in_out(options[:logfile])
end

# re-open the logger on the current stderr, after possibly daemonizing
logger = get_logger options[:log_level], options[:windows_bridge]

# write process id to file (skip for socket activation - systemd tracks the process)
File.open(options[:pidfile], mode: 'w', perm: 0o644) {|f| f.puts Process.pid.to_s} if options[:pidfile] && !options[:systemd]

logger.info 'starting gpgbridge'
logger.debug {"using noncefile #{options[:noncefile]}"}

# Create the map of gpg sockets and corresponding bridge ports
first_port = options[:port]
access_mode = options[:wsl_mode] == 'wsl2_nat' ? :relay : :assuan
# For socket activation, the socket names are mapped from LISTEN_NAMES env var
if options[:systemd]
  listen_names = ENV['LISTEN_NAMES']&.split(':') || []
  socket_names = {}
  listen_names.each_with_index do |name, idx|
    # SSH socket is special - needs relay mode
    socket_names[name] = { port: first_port + idx, type: (name == 'agent-ssh-socket' ? :relay : access_mode) }
  end
  logger.warn 'SSH support enabled but no SSH listen fd found' if options[:enable_ssh_support] && !listen_names.include?('agent-ssh-socket')
else
  socket_names = {
    'agent-socket'         => { port: first_port, type: access_mode },
    'agent-extra-socket'   => { port: first_port + 1, type: access_mode },
    'agent-browser-socket' => { port: first_port + 2, type: access_mode },
  }
  # SSH is always :relay for the Pageant workaround
  socket_names['agent-ssh-socket'] = { port: first_port + 3, type: :relay } if options[:enable_ssh_support]
end
options[:socket_names] = socket_names
logger.debug {"ssh support #{options[:enable_ssh_support]}"}
logger.debug {"socket_names #{options[:socket_names]}"}

if windows_bridge
  require 'net/ssh'

  module Net
    module SSH
      module Authentication
        module Pageant
          class SocketWithTimeout < Net::SSH::Authentication::Pageant::Socket
            # default timeout 30s
            def self.open(timeout = 30000)
              new timeout
            end

            def initialize(timeout)
              @timeout = timeout
              super()
            end

            # override to enable setting the SendMessageTimeout timeout
            def send_query(query)
              filemap = 0
              ptr = nil
              id = Win.malloc_ptr(Win::SIZEOF_DWORD)

              mapname = format('PageantRequest%08x', Win.GetCurrentThreadId())
              security_attributes = Win.get_ptr Win.get_security_attributes_for_user

              filemap = Win.CreateFileMapping(Win::INVALID_HANDLE_VALUE,
                                              security_attributes,
                                              Win::PAGE_READWRITE, 0,
                                              AGENT_MAX_MSGLEN, mapname)

              if [0, Win::INVALID_HANDLE_VALUE].include?(filemap)
                raise Net::SSH::Exception,
                      "Creation of file mapping failed with error: #{Win.GetLastError}"
              end

              ptr = Win.MapViewOfFile(filemap, Win::FILE_MAP_WRITE, 0, 0,
                                      0)

              raise Net::SSH::Exception, 'Mapping of file failed' if ptr.nil? || ptr.null?

              Win.set_ptr_data(ptr, query)

              # using struct to achieve proper alignment and field size on 64-bit platform
              cds = Win::COPYDATASTRUCT.new(Win.malloc_ptr(Win::COPYDATASTRUCT.size))
              cds.dwData = AGENT_COPYDATA_ID
              cds.cbData = mapname.size + 1
              cds.lpData = Win.get_cstr(mapname)
              succ = Win.SendMessageTimeout(@win, Win::WM_COPYDATA, Win::NULL,
                                            cds.to_ptr, Win::SMTO_NORMAL, @timeout, id)

              raise Net::SSH::Exception, "Message failed with error: #{Win.GetLastError}" unless succ > 0

              retlen = 4 + ptr.to_s(4).unpack1('N')
              res = ptr.to_s(retlen)

              res
            ensure
              Win.UnmapViewOfFile(ptr) unless ptr.nil? || ptr.null?
              Win.CloseHandle(filemap) if filemap != 0
            end
          end
        end
      end
    end
  end
end

if windows_bridge
  Dir.chdir File.dirname(__FILE__)
  WindowsBridge.new(options, logger).run
else
  Dir.chdir ENV['HOME']
  WslBridge.new(options, logger).run
end
