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

    # setup cleanup handlers
    at_exit {cleanup}

    # stop gpg-agent if running in WSL
    @logger.info 'stop gpg-agent'
    # %x[gpg-connect-agent killagent /bye]
    %x[pkill gpg-agent]

    @logger.debug 'start listeners for WSL sockets'
    socket_names = options[:socket_names]
    @threads = socket_names.collect do |socket_name|
      Thread.start(socket_name) do |s|
        start_listener s
      end
    end
  end

  def cleanup
    File.unlink @pidfile if @pidfile
    @logger.info 'exiting'
  end

  def start_listener(socket_name)
    socket_path = %x[gpgconf --list-dirs #{socket_name}].chomp
    assuan_socket_path = %x[gpgconf.exe --list-dirs #{socket_name}].chomp
    assuan_socket_path = %x[wslpath -u '#{assuan_socket_path}'].chomp
    @logger.info {"start listener on WSL socket #{socket_name}: #{socket_path} -> #{assuan_socket_path}"}

    File.unlink(socket_path) if File.exist?(socket_path)
    Socket.unix_server_loop(socket_path) do |sock, _client_addrinfo|
      @logger.debug {"got connect request on WSL socket #{socket_name} = #{socket_path}"}
      gpg_agent = connect_to_agent_assuan_socket assuan_socket_path
      Thread.new do
        loop = true
        while loop
          ready = IO.select([sock, gpg_agent])
          readable = ready[0]
          if readable.include?(sock)
            @logger.debug 'msg from client'
            begin
              msg = sock.recv BUFSIZ
              @logger.debug "msg from client: (len=#{msg&.length}) #{msg}"
              if msg.nil? # || msg.empty?
                loop = false
              else
                gpg_agent.send msg, 0
              end
            rescue Errno::ECONNRESET => e
              @logger.error "Exception while receiving msg from client: #{e.inspect}"
              Thread.exit
            rescue StandardError => e
              @logger.error "StandardError while receiving msg from client: #{e.inspect}"
              Thread.exit
            end
          end
          next unless readable.include?(gpg_agent)

          @logger.debug 'msg from gpg_agent'
          begin
            msg = gpg_agent.recv BUFSIZ
            @logger.debug "msg from gpg_agent: (len=#{msg&.length}) #{msg}"
            if msg.nil? # || msg.empty?
              loop = false
            else
              sock.send msg, 0
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
        sock.close
        gpg_agent&.close
      end
    end
  end

  def connect_to_agent_assuan_socket(socket_path)
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

def get_logger(level)
  Logger.new($stderr,
             'weekly',
             level:    level,
             progname: 'WSL-bridge')
end

LEVELS = %w[DEBUG INFO WARN ERROR FATAL UNKNOWN].freeze

options = {
  enable_ssh_support: false,
  daemon:             false,
  port:               FIRST_PORT,
  logfile:            nil,
  pidfile:            nil,
  log_level:          'WARN',
}

OptionParser.new do |opts|
  opts.banner = 'Usage: gpgbridge.rb [options]'

  opts.on('-s', '--[no-]enable-ssh-support', 'Enable proxying of gpg-agent SSH sockets') do |v|
    options[:enable_ssh_support] = v
  end
  opts.on('-d', '--[no-]daemon', 'Run as a daemon in the background') do |v|
    options[:daemon] = v
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

  opts.on('-h', '--help', 'Prints this help') do
    puts opts
    exit
  end
end.parse!

logger = get_logger options[:log_level]

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
logger = get_logger options[:log_level]

# write process id to file
File.open(options[:pidfile], mode: 'w', perm: 0o644) {|f| f.puts Process.pid.to_s} if options[:pidfile]

logger.info 'starting gpgbridge'

# Create the list of gpg sockets to monitor
socket_names = %w[agent-socket agent-extra-socket agent-browser-socket]
socket_names << 'agent-ssh-socket' if options[:enable_ssh_support]
options[:socket_names] = socket_names

Dir.chdir ENV['HOME']
WslBridge.new(options, logger).run
