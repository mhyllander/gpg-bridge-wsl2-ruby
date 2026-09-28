require 'socket'

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
            @logger.debug "msg from client: (len=#{msg&.length}) #{msg}"
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
          @logger.debug "msg from server: (len=#{msg&.length}) #{msg}"
          if msg.nil? # || msg.empty?
            loop = false
          else
            client.send msg, 0
          end
        rescue Errno::ECONNRESET => e
          @logger.error "Exception while receiving msg from server: #{e.inspect}"
          Thread.exit
        rescue StandardError => e
          @logger.error "StandardError while receiving msg from server: #{e.inspect}"
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
