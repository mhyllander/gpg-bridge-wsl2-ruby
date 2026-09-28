#!/usr/bin/env ruby
# gpgbridge.rb forwards requests from gpg clients in WSL1 and WSL2 to
# Gpg4win's gpg-agent.exe in Windows. It can also forward ssh requests to
# gpg-agent.exe, when using a PGP key for ssh authentication.

require 'optparse'
require 'socket'
require 'date'
require 'sys/proctable'
require 'logger'
require 'net/ssh'

require_relative 'relay'

FIRST_PORT = 6910

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
    # the pageant "socket" isn't a real socket (not an IO), can't be used in IO.select.
    @pageant = Net::SSH::Authentication::Pageant::SocketWithTimeout.open
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
  ensure
    @logger.debug 'closing pageant socket'
    @pageant.close
  end

  def relay_pageant(client)
    Thread.new do
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
            send_pageant_response client, msg
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
      @logger.debug 'closing client socket'
      client.close
    end
  end

  def send_pageant_response(client, msg)
    tries = 3
    begin
      @pageant.send msg, 0
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
          @pageant = Net::SSH::Authentication::Pageant::SocketWithTimeout.open
          tries -= 1
          retry
        end
      end

      @logger.error 'send to pageant exception'
      @logger.error e
      raise
    end

    begin
      msg = @pageant.read BUFSIZ
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

def get_logger(level)
  Logger.new($stderr,
             'weekly',
             level:    level,
             progname: 'gpg_relay_win')
end

LEVELS = %w[DEBUG INFO WARN ERROR FATAL UNKNOWN].freeze

options = {
  enable_ssh_support: false,
  port:               FIRST_PORT,
  noncefile:          nil,
  log_level:          'WARN',
  windows_address:    '127.0.0.1',
  windows_logfile:    nil,
  windows_pidfile:    nil,
}

OptionParser.new do |opts|
  opts.banner = 'Usage: gpgbridge.rb [options]'

  opts.on('-s', '--[no-]enable-ssh-support', 'Enable proxying of gpg-agent SSH sockets') do |v|
    options[:enable_ssh_support] = v
  end
  opts.on('-p', '--port PORT', Integer, 'The first port (of three or four) to use for proxying sockets') do |v|
    options[:port] = v
  end
  opts.on('-n', '--noncefile PATH', String, 'The nonce file path (defaults to file in Windows gpg homedir)') do |v|
    options[:noncefile] = v
  end

  opts.on('-v', '--log-level LEVEL', LEVELS, "Logging level (#{LEVELS.join(', ')}) [#{options[:log_level]}]") do |v|
    options[:log_level] = v
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

logger = get_logger options[:log_level]

if options[:noncefile].nil?
  begin
    win_gpghome = %x[gpgconf.exe --list-dirs homedir].chomp
    noncefile = 'gpgbridge.nonce'
    options[:noncefile] = "#{win_gpghome}\\#{noncefile}"
  rescue StandardError => e
    logger.error 'constructing path to noncefile'
    logger.error e
    exit 1
  end
end

logger = get_logger options[:log_level]

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

# write process id to file (skip for socket activation - systemd tracks the process)
File.open(options[:pidfile], mode: 'w', perm: 0o644) {|f| f.puts Process.pid.to_s} if options[:pidfile] && !options[:systemd]

logger.info 'starting gpg_relay_win'
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

Dir.chdir File.dirname(__FILE__)
WindowsBridge.new(options, logger).run
