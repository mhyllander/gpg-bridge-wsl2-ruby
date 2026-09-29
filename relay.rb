require 'socket'

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
      directions = [
        Thread.new {copy_direction(client, server)},
        Thread.new {copy_direction(server, client)},
      ]
      directions.each(&:join)
    ensure
      @logger.debug 'closing sockets'
      close_socket(client)
      close_socket(server)
    end
  end

  private

  def copy_direction(source, destination)
    copied = IO.copy_stream(source, destination)
    @logger.debug {"copied #{copied} bytes before EOF"}
    destination.shutdown(Socket::SHUT_WR)
  rescue IOError, SystemCallError => e
    @logger.error "socket relay failed: #{e.inspect}"
    close_socket(source)
    close_socket(destination)
  end

  def close_socket(socket)
    socket.close unless socket.closed?
  rescue IOError, SystemCallError => e
    @logger.debug {"socket close failed: #{e.inspect}"}
  end
end
