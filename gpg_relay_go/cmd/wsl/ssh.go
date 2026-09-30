package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"time"
)

const maxSSHMessage = 16 << 20
const sshIdleTimeout = 60 * time.Second

type sshRequest struct {
	client net.Conn
	packet []byte
	done   chan error
}

type sshProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	exited chan error
}

func startSSHProcess(ctx context.Context) (*sshProcess, error) {
	cmd := exec.CommandContext(ctx, "npiperelay", "-p", "-l", "-s", "-ei", "-ep", "//./pipe/openssh-ssh-agent")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	p := &sshProcess{cmd: cmd, stdin: stdin, stdout: stdout, exited: make(chan error, 1)}
	go func() { p.exited <- cmd.Wait() }()
	return p, nil
}

func (p *sshProcess) stop() {
	_ = p.stdin.Close()
	_ = p.cmd.Process.Kill()
	<-p.exited
	_ = p.stdout.Close()
}

func readSSHPacket(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxSSHMessage {
		return nil, fmt.Errorf("invalid SSH agent packet length %d", n)
	}
	packet := make([]byte, 4+int(n))
	copy(packet, header[:])
	_, err := io.ReadFull(r, packet[4:])
	return packet, err
}

func serveSSHClient(ctx context.Context, client net.Conn, requests chan<- sshRequest) {
	defer client.Close()
	for {
		packet, err := readSSHPacket(client)
		if err != nil {
			return
		}
		req := sshRequest{client: client, packet: packet, done: make(chan error, 1)}
		select {
		case requests <- req:
		case <-ctx.Done():
			return
		}
		select {
		case err = <-req.done:
			if err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func writeAll(w io.Writer, packet []byte) error {
	for len(packet) > 0 {
		n, err := w.Write(packet)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}

func serveSSHRequests(ctx context.Context, requests <-chan sshRequest, log *slog.Logger) {
	serveSSHRequestsWithTimeout(ctx, requests, log, sshIdleTimeout)
}

func serveSSHRequestsWithTimeout(ctx context.Context, requests <-chan sshRequest, log *slog.Logger, idleTimeout time.Duration) {
	// The first accepted client starts this worker and its child process.
	process, err := startSSHProcess(ctx)
	idleTimer := time.NewTimer(idleTimeout)
	if process == nil {
		idleTimer.Stop()
	}
	defer idleTimer.Stop()
	if err != nil {
		log.Error("start SSH npiperelay", "error", err)
	}
	defer func() {
		if process != nil {
			process.stop()
		}
	}()
	for {
		var req sshRequest
		if process == nil {
			select {
			case <-ctx.Done():
				return
			case req = <-requests:
			}
			process, err = startSSHProcess(ctx)
			if err != nil {
				log.Error("start SSH npiperelay", "error", err)
				req.done <- err
				continue
			}
		} else {
			select {
			case <-ctx.Done():
				return
			case <-idleTimer.C:
				process.stop()
				process = nil
				continue
			case <-process.exited:
				idleTimer.Stop()
				_ = process.stdin.Close()
				_ = process.stdout.Close()
				process = nil
				continue
			case req = <-requests:
			}
			idleTimer.Stop()
			// Reap an idle child that exited just before this request arrived.
			select {
			case <-process.exited:
				_ = process.stdin.Close()
				_ = process.stdout.Close()
				process, err = startSSHProcess(ctx)
				if err != nil {
					req.done <- err
					process = nil
					continue
				}
			default:
			}
		}
		err = writeAll(process.stdin, req.packet)
		var response []byte
		if err == nil {
			response, err = readSSHPacket(process.stdout)
		}
		if err == nil {
			err = writeAll(req.client, response)
		}
		req.done <- err
		if err != nil {
			log.Debug("SSH npiperelay request failed", "error", err)
			// A client write failure does not desynchronize the child.
			if response == nil {
				process.stop()
				process = nil
			}
		}
		if process != nil {
			idleTimer.Reset(idleTimeout)
		}
	}
}
