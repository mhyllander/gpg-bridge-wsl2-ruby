#!/usr/bin/env ruby
# gpg_relay_wsl.rb forwards requests from gpg clients in WSL1 and WSL2 to
# Gpg4win's gpg-agent.exe in Windows. It can also forward ssh requests to
# gpg-agent.exe, when using a PGP key for ssh authentication.

require 'optparse'
require 'socket'
require 'date'
require 'sys/proctable'
require 'logger'
require 'open3'

require_relative 'relay'

FIRST_PORT = 6910

# WslRelay runs in WSL. It receives requests from WSL clients through local sockets and either connects directly with
# gpg_agent.exe using its Assuan sockets (in Windows), or relays them to WindowsRelay (in Windows).
class WslRelay < Relay
  def initialize(options, logger)
    super options, logger

    @pidfile = options[:pidfile]
    @windows_gpg_socket_paths = {}
    @windows_assuan_socket_paths = {}
    @windows_gpg_socket_paths_mutex = Mutex.new
    @windows_assuan_socket_paths_mutex = Mutex.new

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
    assuan_socket_path = windows_assuan_socket_path(socket_name) if config[:type] == :assuan
    @logger.info {"start listener on WSL socket #{socket_name} = #{socket_path}"}
    # File.unlink(socket_path) if File.exist?(socket_path) && File.socket?(socket_path)
    Socket.unix_server_loop(socket_path) do |client, _client_addrinfo|
      @logger.debug {"got connect request on WSL socket #{socket_name} = #{socket_path}"}
      handle_client client, remote_address, config, noncefile, assuan_socket_path, socket_name
    end
  end

  def start_socket_listener_fd(socket_name, remote_address, config, noncefile, fd)
    @logger.info {"start listener on systemd fd #{fd} for #{socket_name}"}
    assuan_socket_path = windows_assuan_socket_path(socket_name) if config[:type] == :assuan
    unix_server = UNIXServer.for_fd(fd)
    unix_server.listen 5
    loop do
      client = unix_server.accept
      @logger.debug {"got connect request on WSL socket #{socket_name} via fd #{fd}"}
      handle_client client, remote_address, config, noncefile, assuan_socket_path, socket_name
    end
  end

  def windows_assuan_socket_path(socket_name)
    @windows_assuan_socket_paths_mutex.synchronize do
      @windows_assuan_socket_paths[socket_name] ||= begin
        path = windows_gpg_socket_path(socket_name)
        %x[wslpath -u '#{path}'].chomp
      end
    end
  end

  def windows_gpg_socket_path(socket_name)
    @windows_gpg_socket_paths_mutex.synchronize do
      @windows_gpg_socket_paths[socket_name] ||= %x[gpgconf.exe --list-dirs #{socket_name}].chomp
    end
  end

  def handle_client(client, remote_address, config, noncefile, assuan_socket_path, socket_name)
    if config[:type] == :ssh
      relay_npiperelay(client, '-s', '//./pipe/openssh-ssh-agent', 'SSH pipe')
      return
    end
    if config[:type] == :npiperelay
      relay_npiperelay(client, '-a', windows_gpg_socket_path(socket_name), 'GPG socket')
      return
    end

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

  def relay_npiperelay(client, target_flag, target_path, target_name)
    Thread.new do
      input = output = process = writer = nil
      begin
        input, output, process = Open3.popen2('npiperelay', '-ei', target_flag, target_path)
        writer = Thread.new do
          copied = IO.copy_stream(client, input)
          @logger.debug {"#{target_name} client input ended after #{copied} bytes"}
        rescue IOError, SystemCallError => e
          @logger.debug {"#{target_name} client input closed: #{e.inspect}"}
        ensure
          input.close unless input.closed?
        end
        copied = IO.copy_stream(output, client)
        @logger.debug {"#{target_name} output ended after #{copied} bytes"}
      rescue IOError, SystemCallError => e
        @logger.error "#{target_name} relay failed: #{e.inspect}"
      ensure
        client.close unless client.closed?
        output.close if output && !output.closed?
        writer.join if writer
        input.close if input && !input.closed?
        if process
          begin
            Process.kill('TERM', process.pid) if process.alive?
          rescue Errno::ESRCH
            # The relay exited between the liveness check and the signal.
          end
          process.join
        end
      end
    end
  end

  def dial_win_relay(remote_address, port, noncefile)
    # get WindowsRelay nonce
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
# 1. WSL2 in NAT networking mode can connect to the Windows VM via the default gateway. The WinRelay must listen on
#    0.0.0.0, and all gpg-agent.exe ports must be proxied.
# 2. WSL2 in mirrored networking mode, and WSL1, can connect to gpg_agent.exe on 127.0.0.1 directly.
# SSH uses npiperelay to reach Gpg4win's named pipe in every networking mode.

options = {
  mode:               'wsl2_mirrored',
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
  opts.banner = 'Usage: gpg_relay_wsl.rb [options]'

  opts.on('-m', '--mode MODE', String, "The GPG access mode (wsl1, wsl2_nat, wsl2_mirrored, npiperelay) [#{options[:mode]}]") do |v|
    options[:mode] = v
    unless %w[wsl1 wsl2_nat wsl2_mirrored npiperelay].include?(v)
      warn "Unknown mode: #{v}"
      exit 1
    end
  end
  opts.on('-s', '--[no-]enable-ssh-support', 'Relay SSH through the Gpg4win named pipe using npiperelay') do |v|
    options[:enable_ssh_support] = v
  end
  opts.on('-r', '--remote-address IPADDR', String, "The remote address of the Windows relay component [#{options[:remote_address]}]") do |v|
    options[:remote_address] = v
  end
  opts.on('-p', '--port PORT', Integer, 'The first of three ports used for GPG sockets') do |v|
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

def executable_on_path?(name)
  ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? do |directory|
    path = File.join(directory, name)
    File.file?(path) && File.executable?(path)
  end
end

unless executable_on_path?('gpgconf.exe')
  logger.error {"cannot find gpgconf.exe in the PATH: #{ENV['PATH']}"}
  exit 2
end

if (options[:enable_ssh_support] || options[:mode] == 'npiperelay') && !executable_on_path?('npiperelay')
  logger.error 'cannot find npiperelay in PATH; add the /usr/local/bin/npiperelay symlink'
  exit 2
end

case options[:mode]
when 'wsl2_nat'
  options[:remote_address] = Regexp.last_match(1) if %x[ip route].split("\n").grep(/^default via /).first =~ /^default via ([0-9.]+)/
when 'wsl1', 'wsl2_mirrored'
  options[:remote_address] = '127.0.0.1'
end

if options[:noncefile].nil?
  begin
    win_gpghome = %x[gpgconf.exe --list-dirs homedir].chomp
    noncefile = 'gpg_relay.nonce'
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
  if p && p.cmdline =~ /ruby.*gpg_relay_wsl\.rb/
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
access_mode = case options[:mode]
              when 'wsl2_nat' then :relay
              when 'npiperelay' then :npiperelay
              else :assuan
              end
socket_names = {
  'agent-socket'         => { port: first_port, type: access_mode },
  'agent-extra-socket'   => { port: first_port + 1, type: access_mode },
  'agent-browser-socket' => { port: first_port + 2, type: access_mode },
}
socket_names['agent-ssh-socket'] = { type: :ssh } if options[:enable_ssh_support]
options[:socket_names] = socket_names

logger.debug {"ssh support #{options[:enable_ssh_support]}"}
logger.debug {"socket_names #{options[:socket_names]}"}
if options[:systemd]
  logger.debug {"LISTEN_FDS #{ENV['LISTEN_FDS']}"}
  logger.debug {"LISTEN_FDNAMES #{ENV['LISTEN_FDNAMES']}"}
end

Dir.chdir ENV['HOME']
WslRelay.new(options, logger).run
