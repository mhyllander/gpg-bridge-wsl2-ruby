package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"time"

	"gpg_relay_go/internal/relay"
)

var names = []string{"agent-socket", "agent-extra-socket", "agent-browser-socket"}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gpg_relay_win:", err)
		os.Exit(1)
	}
}

func run() error {
	port := flag.Int("port", 6910, "first of three GPG relay ports")
	noncePath := flag.String("noncefile", "", "nonce file (default: Windows GPG home)")
	address := flag.String("windows-address", "127.0.0.1", "IP address to listen on")
	logPath := flag.String("windows-logfile", "", "append logs to this file")
	pidPath := flag.String("windows-pidfile", "", "process ID file")
	level := flag.String("log-level", "WARN", "DEBUG, INFO, WARN, or ERROR")
	flag.Parse()
	if *port < 1 || *port > 65533 {
		return fmt.Errorf("invalid first port %d", *port)
	}
	if _, err := exec.LookPath("gpgconf.exe"); err != nil {
		return fmt.Errorf("cannot find gpgconf.exe in PATH: %w", err)
	}
	if _, err := exec.LookPath("gpg-agent.exe"); err != nil {
		return fmt.Errorf("cannot find gpg-agent.exe in PATH: %w", err)
	}
	log, closeLog, err := relay.Logger(*level, *logPath)
	if err != nil {
		return err
	}
	defer closeLog()
	if *noncePath == "" {
		home, err := relay.CommandOutput("gpgconf.exe", "--list-dirs", "homedir")
		if err != nil {
			return err
		}
		*noncePath = filepath.Join(home, "gpg_relay.nonce")
	}
	// Start gpg-agent before querying its socket descriptors.
	if err := exec.Command("gpg-connect-agent.exe", "/bye").Run(); err != nil {
		log.Warn("gpg-agent startup check failed", "error", err)
	}
	nonce := make([]byte, relay.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if err := os.WriteFile(*noncePath, nonce, 0600); err != nil {
		return err
	}
	defer os.Remove(*noncePath)
	if err := relay.WritePID(*pidPath); err != nil {
		return err
	}
	if *pidPath != "" {
		defer os.Remove(*pidPath)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	for i, name := range names {
		listener, err := net.Listen("tcp", net.JoinHostPort(*address, strconv.Itoa(*port+i)))
		if err != nil {
			return fmt.Errorf("listen %s: %w", name, err)
		}
		listeners = append(listeners, listener)
		go serve(ctx, listener, name, nonce, log)
		log.Info("listening", "socket", name, "address", listener.Addr())
	}
	<-ctx.Done()
	return nil
}

func serve(ctx context.Context, listener net.Listener, name string, nonce []byte, log *slog.Logger) {
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				log.Error("accept failed", "socket", name, "error", err)
			}
			return
		}
		go func() {
			defer client.Close()
			_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
			got := make([]byte, relay.NonceSize)
			if _, err := io.ReadFull(client, got); err != nil {
				log.Error("nonce read failed", "socket", name, "error", err)
				return
			}
			_ = client.SetReadDeadline(time.Time{})
			if subtle.ConstantTimeCompare(got, nonce) != 1 {
				log.Error("incorrect nonce", "socket", name)
				return
			}
			path, err := relay.CommandOutput("gpgconf.exe", "--list-dirs", name)
			if err != nil {
				log.Error("gpgconf failed", "socket", name, "error", err)
				return
			}
			upstream, err := relay.DialAssuan(path)
			if err != nil {
				log.Error("Assuan connection failed", "socket", name, "error", err)
				return
			}
			relay.Copy(client, upstream, log)
		}()
	}
}
