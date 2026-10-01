# frozen_string_literal: true

require 'open3'

# One SSH agent pipe is shared by all clients of the WSL SSH socket.
class SSHRelay
  MAX_MESSAGE = 16 * 1024 * 1024
  IDLE_TIMEOUT = 60

  def initialize(logger, idle_timeout: IDLE_TIMEOUT, command: 'npiperelay')
    @logger = logger
    @idle_timeout = idle_timeout
    @command = command
    @mutex = Mutex.new
    @ready = ConditionVariable.new
    @queue = []
    @clients = []
    @readers = []
    @closed = false
    @worker = nil
    @input = @output = @wait_thread = nil
  end

  def accept(client)
    @mutex.synchronize do
      if @closed
        client.close
        return
      end
      @clients << client
      @worker ||= Thread.new {run}
      @readers << Thread.new {read_client(client)}
    end
  end

  def close
    clients = worker = readers = pid = nil
    @mutex.synchronize do
      return if @closed

      @closed = true
      clients = @clients.dup
      readers = @readers.dup
      worker = @worker
      pid = @wait_thread&.pid
      @queue.each {|request| request[:done] << false}
      @queue.clear
      @ready.broadcast
    end
    clients.each do |client|
      client.close
    rescue StandardError
      nil
    end
    kill_process(pid) if pid
    worker&.join
    readers.each(&:join)
  end

  private

  def read_client(client)
    loop do
      header = read_exact(client, 4)
      length = header.unpack1('N')
      raise IOError, "invalid SSH agent packet length #{length}" if length.zero? || length > MAX_MESSAGE

      packet = header + read_exact(client, length)
      done = Queue.new
      @mutex.synchronize do
        return if @closed

        @queue << { client: client, packet: packet, done: done }
        @ready.signal
      end
      break unless done.pop
    end
  rescue EOFError
    # A client can close after any completed response.
  rescue IOError, SystemCallError => e
    @logger.debug "SSH client closed: #{e.inspect}"
  ensure
    @mutex.synchronize do
      @clients.delete(client)
      @readers.delete(Thread.current)
    end
    client.close unless client.closed?
  end

  def read_exact(io, length)
    result = ''.b
    result << io.readpartial(length - result.bytesize) while result.bytesize < length
    result
  end

  def write_all(io, bytes)
    offset = 0
    while offset < bytes.bytesize
      written = io.write(bytes.byteslice(offset..))
      raise IOError, 'short SSH agent write' if written.zero?

      offset += written
    end
  end

  def start_process
    @input, @output, @wait_thread = Open3.popen2(
      @command, '-p', '-l', '-s', '-ep', '//./pipe/openssh-ssh-agent'
    )
    @mutex.synchronize {@ready.broadcast}
    Process.clock_gettime(Process::CLOCK_MONOTONIC) + @idle_timeout
  rescue StandardError => e
    @logger.error "start SSH npiperelay failed: #{e.inspect}"
    @input = @output = @wait_thread = nil
    nil
  end

  def kill_process(pid)
    Process.kill('KILL', pid)
  rescue Errno::ESRCH
    nil
  end

  def stop_process
    input = @input
    output = @output
    wait_thread = @wait_thread
    @input = @output = @wait_thread = nil
    input&.close unless input&.closed?
    kill_process(wait_thread.pid) if wait_thread&.alive?
    wait_thread&.join
    output&.close unless output&.closed?
  end

  def run
    deadline = start_process
    loop do
      request = nil
      @mutex.synchronize do
        while @queue.empty? && !@closed
          remaining = deadline && deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          break if remaining && remaining <= 0

          @ready.wait(@mutex, remaining)
        end
        return if @closed

        request = @queue.shift unless @queue.empty?
      end
      if request.nil?
        stop_process
        deadline = nil
        next
      end
      # A process that exited while idle is replaced before taking the request.
      if @wait_thread.nil? || !@wait_thread.alive?
        stop_process
        deadline = start_process
      end
      unless @wait_thread
        request[:done] << false
        next
      end
      begin
        write_all(@input, request[:packet])
        header = read_exact(@output, 4)
        length = header.unpack1('N')
        raise IOError, "invalid SSH agent response length #{length}" if length.zero? || length > MAX_MESSAGE

        response = header + read_exact(@output, length)
      rescue IOError, SystemCallError, EOFError => e
        @logger.debug "SSH npiperelay request failed: #{e.inspect}"
        request[:done] << false
        stop_process
        deadline = nil
        next
      end
      begin
        write_all(request[:client], response)
        request[:done] << true
      rescue IOError, SystemCallError => e
        @logger.debug "SSH client response failed: #{e.inspect}"
        request[:done] << false
      end
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @idle_timeout
    end
  ensure
    stop_process
  end
end
