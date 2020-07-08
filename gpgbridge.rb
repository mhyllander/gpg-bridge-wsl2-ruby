#!/usr/bin/env ruby
# gpgbridge.rb replaces the separate solutions provided by npiperelay,
# weasel_pageant and gpgbridge.py. It can also forward ssh-agent requests
# to gpg-agent, when using PGP keys for ssh authentication. It will also
# work with WSL2.

# Install gpgbridge.rb in a location reachable by Windows.
# Install Ruby for Windows. https://rubyinstaller.org/downloads/
#  Ensure that the GPG and Ruby executables are in the PATH.
# In WSL, run "sudo gem install sys-proctable ptools".
# In Windows, start a Ruby command window, run "gem install sys-proctable net-ssh".

# For WSL2, add an inbound rule to Windows Firewall, allowing access from
# [172.16.0.0/12, 192.168.0.0/16] to TCP ports 6910-6913.

require 'optparse'
require 'socket'
require 'date'
require 'sys/proctable'

FIRST_PORT = 6910
BUFSIZ = 4096

# WslBridge runs in WSL. It receives requests through local sockets
# requests from WSL clients and forwards them to WindowsBridge in Windows.
class WslBridge
  def initialize(options)
    @verbose = options[:verbose]

    # start WindowsBridge
    start_windows_bridge options

    # setup cleaup handlers
    at_exit { log 'exiting' }
    #at_exit { stop_windows_bridge }

    # stop gpg-agent if running in WSL
    log 'stop gpg-agent' if @verbose
    #%x[gpg-connect-agent killagent /bye]
    %x[pkill gpg-agent]

    log 'start listeners for WSL sockets' if @verbose
    remote_address = options[:remote_address]
    socket_names = options[:socket_names]
    @threads = socket_names.collect do |socket_name, port|
      Thread.start(socket_name, remote_address, port) do |s, r, p|
        start_listener s, r, p
      end
    end
  end

  def log(msg)
    puts "#{DateTime.now.iso8601} [WSL/#{Process.pid}] #{msg}"
  end

  def start_windows_bridge(options)
    log 'start windows bridge' if @verbose

    require 'ptools'
    unless File.which('ruby.exe')
      log "Error: cannot find ruby.exe in the PATH: #{ENV['PATH']}"
      exit 2
    end

    opts = ['--windows-bridge']
    opts += ['--remote-address', options[:windows_address]] if options[:windows_address]
    opts += ['--port', options[:port].to_s] if options[:port]
    opts += ['--logfile', options[:windows_logfile]] if options[:windows_logfile]
    opts += ['--pidfile', options[:windows_pidfile]] if options[:windows_pidfile]
    opts += ['--enable-ssh-support'] if options[:enable_ssh_support]
    opts += ['--verbose'] if options[:verbose]
    
    winpath = %x[wslpath -w '#{__FILE__}'].chomp

    @winbridge = Process.fork do
      Process.setsid
      exit 0 unless Process.fork.nil?
      Process.exec 'ruby.exe', winpath, *opts
    end
    Process.detach @winbridge
  end

  def stop_windows_bridge
    begin
      p = Sys::ProcTable.ps(pid: @winbridge)
      if p && p.cmdline =~ /ruby.*gpgbridge\.rb/
        log "stop_windows_bridge #{@winbridge}" if @verbose
        Process.kill 'TERM', @winbridge
      end
    rescue StandardError => e
      log "stop_windows_bridge exception: #{e.inspect}"
    end
  end

  def start_listener(socket_name, remote_address, port)
    socket_path = %x[gpgconf --list-dirs #{socket_name}].chomp
    log "start listener on WSL socket #{socket_name} = #{socket_path}" if @verbose
    File.unlink(socket_path) if File.exist?(socket_path) && File.socket?(socket_path)
    Socket.unix_server_loop(socket_path) do |sock, client_addrinfo|
      log 'got connect request' if @verbose
      Thread.new do
        #log 'connect with remote'
        winbridge = TCPSocket.new remote_address, port
        #log 'connected'
        begin
          loop = true
          while loop
            ready = IO.select([sock, winbridge])
            readable = ready[0]
            if readable.include?(sock)
              #log 'msg from client' if @verbose
              msg = sock.recv BUFSIZ
              if msg.length > 0
                winbridge.send msg, 0
              else
                loop = false
              end
            end
            if readable.include?(winbridge)
              #log 'msg from bridge' if @verbose
              msg = winbridge.recv BUFSIZ
              if msg.length > 0
                sock.send msg, 0
              else
                loop = false
              end
            end
          end
        ensure
          log 'closing sockets' if @verbose
          winbridge.close
          sock.close
        end
      end
    end
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
    @threads.each {|t| t.join}
  end

end

# WindowsBridge runs in Windows. It receives requests over the network from
# WslBridge and forwards them through the Assuan sockets to gpg-agent.exe
# from Gpg4Win. It can forward both gpg and SSH Pagent requests.
class WindowsBridge
  def initialize(options)
    at_exit { log 'exiting' }
    @verbose = options[:verbose]

    # make sure gpg-agent.exe is running
    system 'gpg-connect-agent.exe /bye 2>nul'

    log 'start listeners for Assuan sockets' if @verbose
    remote_address = options[:remote_address]
    socket_names = options[:socket_names]
    @threads = socket_names.collect do |socket_name, port|
      Thread.start(socket_name, remote_address, port) do |s, r, p|
        if socket_name == 'agent-ssh-socket'
          start_pageant s, r, p
        else
          start_handler s, r, p
        end
      end
    end
  end

  def log(msg)
    puts "#{DateTime.now.iso8601} [Win/#{Process.pid}] #{msg}"
  end

  def start_handler(socket_name, remote_address, port)
    socket_path = %x[gpgconf.exe --list-dirs #{socket_name}].chomp
    log "start handler for Assuan socket #{socket_name} = #{socket_path} on port #{port}" if @verbose
    Socket.tcp_server_loop(remote_address, port) do |sock, client_addrinfo|
      log 'got bridge connect request' if @verbose
      Thread.new do
        gpg_agent = connect_to_agent_assuan_socket socket_path
        begin
          loop = true
          while loop
            ready = IO.select([sock, gpg_agent])
            readable = ready[0]
            if readable.include?(sock)
              #log 'msg from bridge' if @verbose
              msg = sock.recv BUFSIZ
              if msg.length > 0
                gpg_agent.send msg, 0
              else
                loop = false
              end
            end
            if readable.include?(gpg_agent)
              #log 'msg from gpg_agent' if @verbose
              msg = gpg_agent.recv BUFSIZ
              if msg.length > 0
                sock.send msg, 0
              else
                loop = false
              end
            end
          end
        ensure
          log 'closing sockets' if @verbose
          gpg_agent.close
          sock.close
        end
      end
    end
  end

  def start_pageant(socket_name, remote_address, port)
    require 'net/ssh'
    log "start Pageant agent on port #{port}" if @verbose
    pageant = Net::SSH::Authentication::Pageant::Socket.open
    server = TCPServer.new remote_address, port
    connections = []
    while true
      ready = IO.select([server] + connections)
      readable = ready[0]
      if readable.include?(server)
        log 'got bridge connect request' if @verbose
        sock = server.accept
        connections << sock
        readable.delete server
      end
      readable.each do |sock|
        begin
          #log 'msg from bridge' if @verbose
          msg = sock.recv BUFSIZ
          #log 'sock ->'
          if msg.length > 0
            tries = 10
            begin
              pageant.send msg, 0
              #log '-> agent'
            rescue Net::SSH::Exception => se
              if se.message == 'Message failed with error: 1460' # 1460 = ERROR_TIMEOUT
                log "send to pageant timeout: #{se.inspect}"
                tries -= 1
                retry if tries > 0
              end
              log "send to pageant exception: #{se.inspect}"              
            end
            
            tries = 10
            resp = ''
            begin
              resp = pageant.read BUFSIZ
              #log '<- agent'
            rescue Net::SSH::Exception => se
              if se.message == 'Message failed with error: 1460' # 1460 = ERROR_TIMEOUT
                log "read from pageant timeout: #{se.inspect}"
                tries -= 1
                retry if tries > 0
              end
              log "read from pageant exception: #{se.inspect}"              
            end
            
            if resp.length > 0
              #log 'got resp from agent' if @verbose
              sock.send resp, 0
              #log 'sock <-'
            else
              #log 'no resp from agent' if @verbose
              sock.send '', 0
            end
          else
            log 'closing socket' if @verbose
            connections.delete sock
            sock.close
          end
        rescue StandardError => e
          log "Exception while communicating with Pageant: #{e.inspect}"
        end
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
    log "assuan redirect #{socket_path} => 127.0.0.1:#{port}" if @verbose
    if nonce.length != 16
      log "Error: #{socket_path} nonce length is #{nonce.length} != 16"
      exit 1
    end
    gpg_agent = TCPSocket.new '127.0.0.1', port
    gpg_agent.write nonce.pack('C16') # send the nonce to "authenticate"
    gpg_agent
  end

  def trap_signals
    Signal.trap('INT','SIG_IGN')
  end

  def run
    trap_signals
    @threads.each {|t| t.join}
  end
end

def suppress_std_in_out
  $stdin.reopen('/dev/null', 'r')
  $stderr.reopen('/dev/null', 'a')
  $stdout.reopen($stderr)
end

def redirect_std_in_out(logfile)
  $stdin.reopen('/dev/null', 'r')
  $stderr.reopen(logfile, 'a+')
  $stdout.reopen($stderr)
  $stdout.sync = $stderr.sync = true
end

def daemonize
  exit 0 unless Process.fork.nil?
  Process.setsid
  exit 0 unless Process.fork.nil?
end

# Windows bridge:
# Binding to 0.0.0.0 (instead of options[:remote_address]) supports both WSL1 and WSL2
# WSL1 connects to 127.0.0.1
# WSL2 connects to Windows VM via default gateway (using a private IP range)

options = {
  enable_ssh_support: false,
  remote_address: '127.0.0.1',
  port: FIRST_PORT,
  logfile: nil,
  pidfile: nil,
  daemon: false,
  verbose: false,
  windows_bridge: false,
  windows_address: '0.0.0.0',
  windows_logfile: nil,
  windows_pidfile: nil,
}

OptionParser.new do |opts|
  opts.banner = 'Usage: gpgbridge.rb [options]'

  opts.on('-s', '--[no-]enable-ssh-support', 'Enable proxying of gpg-agent SSH sockets') do |v|
    options[:enable_ssh_support] = v
  end
  opts.on('-r', '--remote-address IPADDR', String, 'The remote address of the Windows bridge component. Needed for WSL2. [127.0.0.1]') do |v|
    options[:remote_address] = v
  end
  opts.on('-p', '--port PORT', Integer, 'The first port (of three or four) to use for proxying sockets') do |v|
    options[:port] = v
  end
  opts.on('-l', '--logfile PATH', String, 'The log file path') do |v|
    options[:logfile] = v
  end
  opts.on('-d', '--[no-]daemon', 'Run as a daemon in the background') do |v|
    options[:daemon] = v
  end
  opts.on('-p', '--pidfile PATH', String, 'The PID file path') do |v|
    options[:pidfile] = v
  end
  opts.on('-v', '--[no-]verbose', 'Verbose logging') do |v|
    options[:verbose] = v
  end
  opts.on('-W', '--[no-]windows-bridge', 'Start the Windows bridge (used by the WSL bridge))') do |v|
    options[:windows_bridge] = v
  end
  opts.on('-R', '--windows-address IPADDR', String, 'The IP address of the Windows bridge. [0.0.0.0]') do |v|
    options[:windows_address] = v
  end
  opts.on('-L', '--windows-logfile PATH', String, 'The log file path of the Windows bridge') do |v|
    options[:windows_logfile] = v
  end
  opts.on('-P', '--windows-pidfile PATH', String, 'The PID file path of the Windows bridge') do |v|
    options[:windows_pidfile] = v
  end
  opts.on('-h', '--help', 'Prints this help') do
    puts opts
    exit
  end
end.parse!

if options[:pidfile] && File.exist?(options[:pidfile])
  pid = File.read(options[:pidfile]).chomp.to_i
  p = Sys::ProcTable.ps(pid: pid)
  if p && p.cmdline =~ /ruby.*gpgbridge\.rb/
    puts "#{DateTime.now.iso8601} [#{options[:windows_bridge] ? 'Win' : 'WSL'}/#{Process.pid}] detected gpgbridge.rb running as pid #{pid}, exiting" if options[:verbose]
    exit 0
  end
end

if options[:daemon]
  if options[:pidfile].nil?
    puts 'Missing pidfile argument'
    exit 1
  end
  daemonize
  if options[:logfile]
    redirect_std_in_out options[:logfile]
  else
    suppress_std_in_out
    options[:verbose] = false
  end
else
  redirect_std_in_out(options[:logfile]) if options[:logfile]
end

File.write(options[:pidfile], Process.pid.to_s) if options[:pidfile]

puts "#{DateTime.now.iso8601} [#{options[:windows_bridge] ? 'Win' : 'WSL'}/#{Process.pid}] starting gpgbridge" if options[:verbose]

# Create the list of gpg sockets and corresponding bridge ports
first_port = options[:port]
socket_names = [['agent-socket', first_port],
                ['agent-extra-socket', first_port+1],
                ['agent-browser-socket', first_port+2]]
socket_names << ['agent-ssh-socket', first_port+3] if options[:enable_ssh_support]
options[:socket_names] = socket_names

if options[:windows_bridge]
  Dir.chdir File.dirname(__FILE__)
  WindowsBridge.new(options).run
else
  Dir.chdir ENV['HOME']
  WslBridge.new(options).run
end
