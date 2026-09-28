#!/usr/bin/env ruby
# gpg_relay_win.rb forwards requests from gpg clients in WSL1 and WSL2 to
# Gpg4win's gpg-agent.exe in Windows for WSL2 NAT mode.

require 'optparse'
require 'socket'
require 'date'
require 'sys/proctable'
require 'logger'

require_relative 'relay'

FIRST_PORT = 6910

# WindowsRelay runs in Windows. It receives requests over the network from
# WslRelay and forwards them through the assuan sockets to gpg-agent.exe
# from Gpg4Win. It forwards GPG traffic for WSL2 NAT mode.
class WindowsRelay < Relay
  def initialize(options, logger)
    super options, logger

    @noncefile = options[:noncefile]
    @pidfile = options[:pidfile]

    # make sure gpg-agent.exe is running
    system('gpg-connect-agent.exe', '/bye', out: File::NULL, err: File::NULL)

    # create nonce
    nonce = create_nonce @noncefile

    # setup cleanup handlers
    at_exit {cleanup}

    @logger.debug 'start proxies'
    remote_address = options[:windows_address]
    # All three GPG sockets are relayed in WSL2 NAT mode
    socket_names = options[:socket_names].select {|_, v| v[:type] == :relay}
    @threads = socket_names.collect do |socket_name, config|
      Thread.start(socket_name, remote_address, config, nonce) do |s, r, c, n|
        start_assuan_proxy s, r, c, n
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

  def trap_signals
    Signal.trap('INT', 'SIG_IGN')
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
             progname: 'gpg_relay_win')
end

LEVELS = %w[DEBUG INFO WARN ERROR FATAL UNKNOWN].freeze

options = {
  port:               FIRST_PORT,
  noncefile:          nil,
  log_level:          'WARN',
  windows_address:    '127.0.0.1',
  windows_logfile:    nil,
  windows_pidfile:    nil,
}

OptionParser.new do |opts|
  opts.banner = 'Usage: gpg_relay_win.rb [options]'

  opts.on('-p', '--port PORT', Integer, 'The first of three ports used for GPG sockets') do |v|
    options[:port] = v
  end
  opts.on('-n', '--noncefile PATH', String, 'The nonce file path (defaults to file in Windows gpg homedir)') do |v|
    options[:noncefile] = v
  end

  opts.on('-v', '--log-level LEVEL', LEVELS, "Logging level (#{LEVELS.join(', ')}) [#{options[:log_level]}]") do |v|
    options[:log_level] = v
  end

  opts.on('-R', '--windows-address IPADDR', String, "The IP listening address [#{options[:windows_address]}]") do |v|
    options[:windows_address] = v
  end
  opts.on('-L', '--windows-logfile PATH', String, 'The log file path') do |v|
    options[:windows_logfile] = v
  end
  opts.on('-I', '--windows-pidfile PATH', String, 'The PID file path') do |v|
    options[:windows_pidfile] = v
  end
  opts.on('-h', '--help', 'Prints this help') do
    puts opts
    exit
  end
end.parse!

logger = get_logger options[:log_level]

if options[:noncefile].nil?
  begin
    win_gpghome = %x[gpgconf.exe --list-dirs homedir].chomp
    noncefile = 'gpg_relay.nonce'
    options[:noncefile] = "#{win_gpghome}\\#{noncefile}"
  rescue StandardError => e
    logger.error 'constructing path to noncefile'
    logger.error e
    exit 1
  end
end

logger = get_logger options[:log_level]

def executable_on_path?(name)
  ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).any? do |directory|
    File.executable?(File.join(directory, name))
  end
end

unless executable_on_path?('ruby.exe')
  logger.error {"cannot find ruby.exe in the PATH: #{ENV['PATH']}"}
  exit 2
end
unless executable_on_path?('gpgconf.exe')
  logger.error {"cannot find gpgconf.exe in the PATH: #{ENV['PATH']}"}
  exit 2
end
unless executable_on_path?('gpg-agent.exe')
  logger.error {"cannot find gpg-agent.exe in the PATH: #{ENV['PATH']}"}
  exit 2
end

# write process id to file (skip for socket activation - systemd tracks the process)
File.open(options[:pidfile], mode: 'w', perm: 0o644) {|f| f.puts Process.pid.to_s} if options[:pidfile] && !options[:systemd]

logger.info 'starting gpg_relay_win'
logger.debug {"using noncefile #{options[:noncefile]}"}

# Create the map of gpg sockets and corresponding bridge ports
first_port = options[:port]
socket_names = {
  'agent-socket'         => { port: first_port, type: :relay },
  'agent-extra-socket'   => { port: first_port + 1, type: :relay },
  'agent-browser-socket' => { port: first_port + 2, type: :relay },
}
options[:socket_names] = socket_names

logger.debug {"socket_names #{options[:socket_names]}"}

Dir.chdir File.dirname(__FILE__)
WindowsRelay.new(options, logger).run
