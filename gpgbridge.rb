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

# WslBridge runs in WSL. It receives requests from WSL clients through
# local sockets and forwards them to WindowsBridge in Windows.
class WslBridge
  def initialize(options, logger)
    @pidfile = options[:pidfile]
    @logger = logger

    # start WindowsBridge
    start_windows_bridge options

    # setup cleaup handlers
    at_exit {cleanup}

    # stop gpg-agent if running in WSL
    @logger.info 'stop gpg-agent'
    # %x[gpg-connect-agent killagent /bye]
    %x[pkill gpg-agent]

    @logger.debug 'start listeners for WSL sockets'
    remote_address = options[:remote_address]
    socket_names = options[:socket_names]
    noncefile = options[:noncefile]
    @threads = socket_names.collect do |socket_name, port|
      Thread.start(socket_name, remote_address, port, noncefile) do |s, r, p, n|
        start_listener s, r, p, n
      end
    end
  end

  def cleanup
    # stop_windows_bridge
    File.unlink @pidfile if @pidfile
    @logger.info 'exiting'
  end

  def start_windows_bridge(options)
    @logger.info 'start windows bridge'

    opts = ['--windows-bridge']

    noncedir = File.dirname options[:noncefile]
    file = File.basename options[:noncefile]
    noncefile = "#{%x[wslpath -w '#{noncedir}'].chomp}\\#{file}"
    opts += ['--noncefile', noncefile]

    opts += ['--remote-address', options[:windows_address]] if options[:windows_address]
    opts += ['--port', options[:port].to_s] if options[:port]
    opts += ['--logfile', options[:windows_logfile]] if options[:windows_logfile]
    opts += ['--pidfile', options[:windows_pidfile]] if options[:windows_pidfile]
    opts += ['--enable-ssh-support'] if options[:enable_ssh_support]
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

  def start_listener(socket_name, remote_address, port, noncefile)
    socket_path = %x[gpgconf --list-dirs #{socket_name}].chomp
    @logger.info {"start listener on WSL socket #{socket_name} = #{socket_path}"}
    File.unlink(socket_path) if File.exist?(socket_path) && File.socket?(socket_path)
    Socket.unix_server_loop(socket_path) do |sock, _client_addrinfo|
      @logger.debug {"got connect request on WSL socket #{socket_name} = #{socket_path}"}
      Thread.new do
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
          Thread.exit
        end
        @logger.debug 'connected'
        begin
          loop = true
          while loop
            ready = IO.select([sock, winbridge])
            readable = ready[0]
            if readable.include?(sock)
              @logger.debug 'msg from client'
              begin
                msg = sock.recv BUFSIZ
                if msg&.empty?
                  loop = false
                else
                  winbridge.send msg, 0
                end
              rescue Errno::ECONNRESET => e
                @logger.error "Exception while receiving msg from client: #{e.inspect}"
                Thread.exit
              end
            end
            next unless readable.include?(winbridge)

            @logger.debug 'msg from winbridge'
            begin
              msg = winbridge.recv BUFSIZ
              if msg&.empty?
                loop = false
              else
                sock.send msg, 0
              end
            rescue Errno::ECONNRESET => e
              @logger.error "Exception while receiving msg from winbridge: #{e.inspect}"
              Thread.exit
            end
          end
        ensure
          @logger.debug 'closing sockets'
          winbridge.close
          sock.close
        end
      end
    end
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
# from Gpg4Win. It can forward both gpg and SSH Pagent requests.
class WindowsBridge
  def initialize(options, logger)
    @noncefile = options[:noncefile]
    @pidfile = options[:pidfile]
    @logger = logger

    # make sure gpg-agent.exe is running
    system 'gpg-connect-agent.exe /bye 2>nul'

    # create nonce
    nonce = create_nonce @noncefile

    # setup cleaup handlers
    at_exit {cleanup}

    @logger.debug 'start proxies'
    remote_address = options[:remote_address]
    socket_names = options[:socket_names]
    @threads = socket_names.collect do |socket_name, port|
      Thread.start(socket_name, remote_address, port, nonce) do |s, r, p, n|
        if s == 'agent-ssh-socket'
          start_pageant_proxy s, r, p, n
        else
          start_assuan_proxy s, r, p, n
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
    @logger.debug {"creating nonce in noncefile #{noncefile}"}
    nonce = Random.new.bytes(16)
    File.write(noncefile, nonce)
    nonce
  end

  def start_assuan_proxy(socket_name, remote_address, port, nonce)
    socket_path = %x[gpgconf.exe --list-dirs #{socket_name}].chomp
    @logger.info {"start assuan socket proxy for #{socket_name} = #{socket_path} on port #{port}"}
    Socket.tcp_server_loop(remote_address, port) do |sock, _client_addrinfo|
      @logger.debug {"got bridge connect request on port #{port} for #{socket_name}"}
      Thread.new do
        wsl_bridge_nonce = sock.recv 16
        if wsl_bridge_nonce != nonce
          @logger.error {"received wrong nonce from WSL bridge on port #{port} for #{socket_name}: #{wsl_bridge_nonce.unpack('C*')}"}
          Thread.exit
        else
          @logger.info {"got correct nonce on port #{port} for #{socket_name}"}
        end
        gpg_agent = connect_to_agent_assuan_socket socket_path
        loop = true
        while loop
          ready = IO.select([sock, gpg_agent])
          readable = ready[0]
          if readable.include?(sock)
            @logger.debug 'msg from bridge'
            msg = sock.recv BUFSIZ
            if msg&.empty?
              loop = false
            else
              gpg_agent.send msg, 0
            end
          end
          next unless readable.include?(gpg_agent)

          @logger.debug 'msg from gpg_agent'
          msg = gpg_agent.recv BUFSIZ
          if msg&.empty?
            loop = false
          else
            sock.send msg, 0
          end
        end
      ensure
        @logger.debug 'closing sockets'
        gpg_agent&.close
        sock.close
      end
    end
  end

  def start_pageant_proxy(socket_name, remote_address, port, nonce)
    @logger.info {"start Pageant proxy for #{socket_name} on port #{port}"}
    pageant = Net::SSH::Authentication::Pageant::SocketWithTimeout.open
    server = TCPServer.new remote_address, port
    connections = []
    loop do
      ready = IO.select([server] + connections)
      readable = ready[0]

      if readable.include?(server)
        @logger.debug {"got bridge connect request on port #{port} for #{socket_name}"}
        sock = server.accept
        wsl_bridge_nonce = sock.recv 16
        if wsl_bridge_nonce != nonce
          @logger.error {"received wrong nonce from WSL bridge on port #{port} for #{socket_name}"}
          sock.close
          next
        else
          @logger.debug {"got correct nonce on port #{port} for #{socket_name}"}
        end
        connections << sock
        readable.delete server
      end

      readable.each do |s|
        @logger.debug 'msg from bridge'
        msg = s.recv BUFSIZ

        if msg&.empty?
          @logger.debug 'closing socket'
          connections.delete s
          s.close
          next
        end

        tries = 3
        begin
          pageant.send msg, 0
        rescue Net::SSH::Exception => e
          if e.message == 'Message failed with error: 1460' && tries > 0
            # ERROR_TIMEOUT
            @logger.warn 'send to pageant timeout, retrying'
            tries -= 1
            retry
          elsif e.message == 'Message failed with error: 1400' && tries > 0
            # ERROR_INVALID_WINDOW_HANDLE
            @logger.warn 'lost connection with pageant, reconnecting'
            pageant = Net::SSH::Authentication::Pageant::SocketWithTimeout.open
            tries -= 1
            retry
          end

          @logger.error 'send to pageant exception'
          @logger.error e
          raise
        end

        resp = pageant.read BUFSIZ
        s.send resp, 0
        @logger.warn 'no resp from gpg-agent pageant' if resp.empty?
      rescue StandardError => e
        @logger.error 'exception while communicating with pageant'
        @logger.error e
        @logger.debug 'closing socket'
        connections.delete s
        s.close
      end
    end
  end

  def connect_to_agent_assuan_socket(socket_path)
    port = []
    nonce = []
    File.open(socket_path, 'rb') do |f|
      f.each_byte do |b|
        break if b == 10 # break on newline char

        port << b
      end
      f.each_byte do |b|
        nonce << b
      end
    end
    port = port.pack('C*').to_i
    @logger.debug {"redirect assuan socket #{socket_path} to TCP 127.0.0.1:#{port}"}
    if nonce.length != 16
      @logger.error {"#{socket_path} nonce length is #{nonce.length} != 16"}
      exit 1
    end
    gpg_agent = TCPSocket.new '127.0.0.1', port
    gpg_agent.write nonce.pack('C16') # send the nonce to "authenticate"
    gpg_agent
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

# Windows bridge:
# Binding to 0.0.0.0 (instead of options[:remote_address]) supports both WSL1 and WSL2
# WSL1 connects to 127.0.0.1
# WSL2 connects to Windows VM via default gateway (using a private IP range)

options = {
  enable_ssh_support: false,
  daemon:             false,
  remote_address:     '127.0.0.1',
  port:               FIRST_PORT,
  noncefile:          nil,
  logfile:            nil,
  pidfile:            nil,
  log_level:          'WARN',
  windows_bridge:     false,
  windows_address:    '0.0.0.0',
  windows_logfile:    nil,
  windows_pidfile:    nil,
}

OptionParser.new do |opts|
  opts.banner = 'Usage: gpgbridge.rb [options]'

  opts.on('-s', '--[no-]enable-ssh-support', 'Enable proxying of gpg-agent SSH sockets') do |v|
    options[:enable_ssh_support] = v
  end
  opts.on('-d', '--[no-]daemon', 'Run as a daemon in the background') do |v|
    options[:daemon] = v
  end
  opts.on('-r', '--remote-address IPADDR', String, 'The remote address of the Windows bridge component. Needed for WSL2. [127.0.0.1]') do |v|
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

  opts.on('-v', '--log-level LEVEL', LEVELS, "Logging level (#{LEVELS.join(', ')}) [#{options[:log_level]}]") do |v|
    options[:log_level] = v
  end

  opts.on('-W', '--[no-]windows-bridge', 'Start the Windows bridge (used by the WSL bridge)') do |v|
    options[:windows_bridge] = v
  end
  opts.on('-R', '--windows-address IPADDR', String, 'The IP address of the Windows bridge. [0.0.0.0]') do |v|
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

@windows_bridge = options[:windows_bridge]

logger = get_logger options[:log_level], options[:windows_bridge]

unless @windows_bridge
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
    options[:noncefile] = if @windows_bridge
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

if options[:pidfile] && File.exist?(options[:pidfile])
  pid = File.read(options[:pidfile]).chomp.to_i
  p = Sys::ProcTable.ps(pid: pid)
  if p && p.cmdline =~ /ruby.*gpgbridge\.rb/
    logger.debug {"detected gpgbridge.rb running as pid #{pid}, exiting"}
    exit 0
  end
end

if options[:daemon]
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
elsif options[:logfile]
  redirect_std_in_out(options[:logfile])
end

# re-open the logger on the current stderr, after possibly daemonizing
logger = get_logger options[:log_level], options[:windows_bridge]

# write process id to file
File.open(options[:pidfile], mode: 'w', perm: 0o644) {|f| f.puts Process.pid.to_s} if options[:pidfile]

logger.info 'starting gpgbridge'
logger.debug {"using noncefile #{options[:noncefile]}"}

# Create the list of gpg sockets and corresponding bridge ports
first_port = options[:port]
socket_names = [['agent-socket', first_port],
                ['agent-extra-socket', first_port + 1],
                ['agent-browser-socket', first_port + 2]]
socket_names << ['agent-ssh-socket', first_port + 3] if options[:enable_ssh_support]
options[:socket_names] = socket_names

if @windows_bridge
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

if @windows_bridge
  Dir.chdir File.dirname(__FILE__)
  WindowsBridge.new(options, logger).run
else
  Dir.chdir ENV['HOME']
  WslBridge.new(options, logger).run
end
