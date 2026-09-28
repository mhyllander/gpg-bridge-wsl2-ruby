#!/usr/bin/env ruby
# gpgbridge.rb forwards requests from gpg clients in WSL1 and WSL2 to
# Gpg4win's gpg-agent.exe in Windows. It can also forward ssh requests to
# gpg-agent.exe, when using a PGP key for ssh authentication.

require 'optparse'
require 'socket'
require 'date'
require 'sys/proctable'
require 'logger'
require 'ptools'

require_relative 'relay'

FIRST_PORT = 6910

# WslBridge runs in WSL. It receives requests from WSL clients through local sockets and either connects directly with
# gpg_agent.exe using its Assuan sockets (in Windows), or relays them to WindowsBridge (in Windows).
class WslBridge < Relay
  def initialize(options, logger)
    super options, logger

    @pidfile = options[:pidfile]

    # setup cleanup handlers
    at_exit {cleanup}

    remote_address = options[:remote_address]
    socket_names = options[:socket_names]
    noncefile = options[:noncefile]

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
                 end
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

  def start_socket_listener(socket_name, remote_address, config, noncefile)
    socket_path = %x[gpgconf --list-dirs #{socket_name}].chomp
    assuan_socket_path = %x[gpgconf.exe --list-dirs #{socket_name}].chomp
    assuan_socket_path = %x[wslpath -u '#{assuan_socket_path}'].chomp
    @logger.info {"start listener on WSL socket #{socket_name} = #{socket_path}"}
    # File.unlink(socket_path) if File.exist?(socket_path) && File.socket?(socket_path)
    Socket.unix_server_loop(socket_path) do |client, _client_addrinfo|
      @logger.debug {"got connect request on WSL socket #{socket_name} = #{socket_path}"}
      server = if config[:type] == :relay
                 dial_win_relay remote_address, config[:port], noncefile
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
    unix_server = UNIXServer.for_fd(fd)
    unix_server.listen 5
    loop do
      client = unix_server.accept
      @logger.debug {"got connect request on WSL socket #{socket_name} via fd #{fd}"}
      server = if config[:type] == :relay
                 dial_win_relay remote_address, config[:port], noncefile
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

  def dial_win_relay(remote_address, port, noncefile)
    # get WindowsBridge nonce
    nonce = get_nonce noncefile
    sock = nil
    begin
      @logger.debug 'connect with gpg_relay_win'
      sock = TCPSocket.new remote_address, port
      # send the nonce to authenticate, if the nonce is wrong the connection will be closed immediately
      sock.send nonce, 0
    rescue Errno::ETIMEDOUT => e
      @logger.error "Exception while connecting with gpg_relay_win: #{e.inspect}"
    end
    sock
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
    @options[:systemd] == true
  end

  def listen_names
    names_env = ENV['LISTEN_FDNAMES']
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

def get_logger(level)
  Logger.new($stderr,
             'weekly',
             level:    level,
             progname: 'gpg_relay_wsl')
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
  enable_ssh_support: false,
  systemd:            false,
  port:               FIRST_PORT,
  noncefile:          nil,
  logfile:            nil,
  pidfile:            nil,
  log_level:          'WARN',
}

OptionParser.new do |opts|
  opts.banner = 'Usage: gpgbridge.rb [options]'

  opts.on('-m', '--wsl-mode MODE', String, "The WSL networking mode (wsl1, wsl2_nat, wsl2_mirrored) [#{options[:wsl_mode]}]") do |v|
    options[:wsl_mode] = v
    unless %w[wsl1 wsl2_nat wsl2_mirrored].include?(v)
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

  opts.on('--systemd', 'Use systemd socket activation (listen fds passed by systemd)') do
    options[:systemd] = true
  end
  opts.on('-v', '--log-level LEVEL', LEVELS, "Logging level (#{LEVELS.join(', ')}) [#{options[:log_level]}]") do |v|
    options[:log_level] = v
  end

  opts.on('-h', '--help', 'Prints this help') do
    puts opts
    exit
  end
end.parse!

logger = get_logger options[:log_level]

unless File.which('gpgconf.exe')
  logger.error {"cannot find gpgconf.exe in the PATH: #{ENV['PATH']}"}
  exit 2
end

case options[:wsl_mode]
when 'wsl2_nat'
  options[:remote_address] = Regexp.last_match(1) if %x[ip route].split("\n").grep(/^default via /).first =~ /^default via ([0-9.]+)/
when 'wsl1', 'wsl2_mirrored'
  options[:remote_address] = '127.0.0.1'
end

if options[:noncefile].nil?
  begin
    win_gpghome = %x[gpgconf.exe --list-dirs homedir].chomp
    noncefile = 'gpgbridge.nonce'
    options[:noncefile] = "#{%x[wslpath -u '#{win_gpghome}'].chomp}/#{noncefile}"
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

redirect_std_in_out(options[:logfile]) if options[:logfile] && !options[:systemd]

# open the logger on the current stderr
logger = get_logger options[:log_level]

# write process id to file (skip for socket activation - systemd tracks the process)
File.open(options[:pidfile], mode: 'w', perm: 0o644) {|f| f.puts Process.pid.to_s} if options[:pidfile] && !options[:systemd]

logger.info 'starting gpg_relay_wsl'
logger.debug {"using noncefile #{options[:noncefile]}"}

# Create the map of gpg sockets and corresponding bridge ports
first_port = options[:port]
access_mode = options[:wsl_mode] == 'wsl2_nat' ? :relay : :assuan
socket_names = {
  'agent-socket'         => { port: first_port, type: access_mode },
  'agent-extra-socket'   => { port: first_port + 1, type: access_mode },
  'agent-browser-socket' => { port: first_port + 2, type: access_mode },
}
# SSH is always :relay for the Pageant workaround
socket_names['agent-ssh-socket'] = { port: first_port + 3, type: :relay } if options[:enable_ssh_support]
options[:socket_names] = socket_names

logger.debug {"ssh support #{options[:enable_ssh_support]}"}
logger.debug {"socket_names #{options[:socket_names]}"}
if options[:systemd]
  logger.debug {"LISTEN_FDS #{ENV['LISTEN_FDS']}"}
  logger.debug {"LISTEN_FDNAMES #{ENV['LISTEN_FDNAMES']}"}
end

Dir.chdir ENV['HOME']
WslBridge.new(options, logger).run
