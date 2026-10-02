package main

import (
	"context"
	"errors"
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
	"strings"
	"sync"
	"syscall"
	"time"

	"gpg_relay_go/internal/relay"
)

type socket struct {
	name   string
	offset int
	ssh    bool
}

var sockets = []socket{{"agent-socket", 0, false}, {"agent-extra-socket", 1, false}, {"agent-browser-socket", 2, false}, {"agent-ssh-socket", 0, true}}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gpg_relay_wsl:", err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "mirrored", "GPG access mode: nat, mirrored, or npiperelay")
	ssh := flag.Bool("enable-ssh-support", false, "forward SSH through npiperelay")
	remote := flag.String("remote-address", "", "Windows relay address (default: gateway in NAT mode, localhost otherwise)")
	port := flag.Int("port", 6910, "first of three GPG relay ports")
	noncePath := flag.String("noncefile", "", "Windows relay nonce file")
	logPath := flag.String("logfile", "", "append logs to this file")
	pidPath := flag.String("pidfile", "", "process ID file")
	activated := flag.Bool("systemd", false, "use systemd socket activation")
	logLevel := flag.String("log-level", "WARN", "DEBUG, INFO, WARN, or ERROR")
	flag.Parse()
	if *mode != "nat" && *mode != "mirrored" && *mode != "npiperelay" {
		return fmt.Errorf("invalid mode %q", *mode)
	}
	if *port < 1 || *port > 65533 {
		return fmt.Errorf("invalid first port %d", *port)
	}
	if *ssh || *mode == "npiperelay" {
		if _, err := exec.LookPath("npiperelay"); err != nil {
			return fmt.Errorf("cannot find npiperelay in PATH: %w", err)
		}
	}
	if _, err := exec.LookPath("gpgconf.exe"); err != nil {
		return fmt.Errorf("cannot find gpgconf.exe in PATH: %w", err)
	}
	if *remote == "" {
		if *mode == "nat" {
			gateway, err := defaultGateway()
			if err != nil {
				return err
			}
			*remote = gateway
		} else {
			*remote = "127.0.0.1"
		}
	}
	if *noncePath == "" && *mode == "nat" {
		home, err := relay.CommandOutput("gpgconf.exe", "--list-dirs", "homedir")
		if err != nil {
			return err
		}
		converted, err := relay.CommandOutput("wslpath", "-u", home)
		if err != nil {
			return err
		}
		*noncePath = filepath.Join(converted, "gpg_relay.nonce")
	}
	if *mode == "nat" && *noncePath == "" {
		return errors.New("nonce file is required in NAT mode")
	}
	if *activated {
		*pidPath = ""
		*logPath = ""
	}
	log, closeLog, err := relay.Logger(*logLevel, *logPath)
	if err != nil {
		return err
	}
	defer closeLog()
	if err := relay.WritePID(*pidPath); err != nil {
		return err
	}
	if *pidPath != "" {
		defer os.Remove(*pidPath)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	var listeners []net.Listener
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
	}()
	var names []socket
	for _, s := range sockets {
		if !s.ssh || *ssh {
			names = append(names, s)
		}
	}
	fdNames := []string(nil)
	if *activated {
		fdNames, err = activationNames()
		if err != nil {
			return err
		}
	}
	for _, s := range names {
		var listener net.Listener
		if *activated {
			listener, err = activatedListener(fdNames, s.name)
		} else {
			path, pathErr := relay.CommandOutput("gpgconf", "--list-dirs", s.name)
			if pathErr != nil {
				return pathErr
			}
			listener, err = net.Listen("unix", path)
		}
		if err != nil {
			return fmt.Errorf("listen %s: %w", s.name, err)
		}
		listeners = append(listeners, listener)
		go serve(ctx, listener, s, *mode, *remote, *port, *noncePath, log)
		log.Info("listening on socket", "socket_name", s.name, "address", listener.Addr())
	}
	<-ctx.Done()
	return nil
}

func defaultGateway() (string, error) {
	out, err := relay.CommandOutput("ip", "route")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "default" && fields[1] == "via" {
			return fields[2], nil
		}
	}
	return "", errors.New("cannot determine Windows gateway from ip route; set --remote-address")
}

func activationNames() ([]string, error) {
	pid, err := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if err != nil || pid != os.Getpid() {
		return nil, errors.New("LISTEN_PID does not match this process")
	}
	count, err := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if err != nil || count < 1 {
		return nil, errors.New("invalid LISTEN_FDS")
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != count {
		return nil, errors.New("LISTEN_FDNAMES count does not match LISTEN_FDS")
	}
	return names, nil
}

func activatedListener(names []string, name string) (net.Listener, error) {
	for i, candidate := range names {
		if candidate != name {
			continue
		}
		file := os.NewFile(uintptr(3+i), name)
		if file == nil {
			return nil, fmt.Errorf("invalid fd for %s", name)
		}
		listener, err := net.FileListener(file)
		file.Close()
		if err != nil {
			return nil, err
		}
		if _, ok := listener.(*net.UnixListener); !ok {
			listener.Close()
			return nil, fmt.Errorf("%s is not a Unix listener", name)
		}
		return listener, nil
	}
	return nil, fmt.Errorf("missing systemd descriptor %s", name)
}

// socketPaths caches successful lookups for one listener. A failed lookup is retried.
type socketPaths struct {
	mu      sync.Mutex
	windows string
	wsl     string
}

func (p *socketPaths) windowsPath(name string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.windows != "" {
		return p.windows, nil
	}
	path, err := relay.CommandOutput("gpgconf.exe", "--list-dirs", name)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("gpgconf.exe returned an empty path for %s", name)
	}
	p.windows = path
	return path, nil
}

func (p *socketPaths) wslPath(name string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.wsl != "" {
		return p.wsl, nil
	}
	if p.windows == "" {
		path, err := relay.CommandOutput("gpgconf.exe", "--list-dirs", name)
		if err != nil {
			return "", err
		}
		if path == "" {
			return "", fmt.Errorf("gpgconf.exe returned an empty path for %s", name)
		}
		p.windows = path
	}
	path, err := relay.CommandOutput("wslpath", "-u", p.windows)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("wslpath returned an empty path for %s", name)
	}
	p.wsl = path
	return path, nil
}

func serve(ctx context.Context, listener net.Listener, s socket, mode, remote string, firstPort int, noncePath string, log *slog.Logger) {
	log = log.With("socket_name", s.name)
	paths := &socketPaths{}
	var sshRequests chan sshRequest
	for {
		client, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				log.Error("accept failed", "error", err)
			}
			return
		}
		if s.ssh {
			if sshRequests == nil {
				sshRequests = make(chan sshRequest)
				go serveSSHRequests(ctx, sshRequests, log)
			}
			go serveSSHClient(ctx, client, sshRequests)
			continue
		}
		go func() {
			if mode == "npiperelay" {
				path, err := paths.windowsPath(s.name)
				if err != nil {
					log.Error("Windows socket path lookup failed", "error", err)
					client.Close()
					return
				}
				log.Debug("relaying via npiperelay", "path", path)
				relayNpiperelay(client, []string{"-a", "-ei", "-ep"}, path, log)
				return
			}
			var upstream net.Conn
			var dialErr error
			if mode == "nat" {
				upstream, dialErr = relay.DialWindows(remote, firstPort+s.offset, noncePath)
			} else {
				path, err := paths.wslPath(s.name)
				if err != nil {
					dialErr = err
				} else {
					upstream, dialErr = relay.DialAssuan(path)
				}
			}
			if dialErr != nil {
				log.Error("upstream connection failed", "error", dialErr)
				client.Close()
				return
			}
			relay.Copy(client, upstream, log)
		}()
	}
}

func relayNpiperelay(client net.Conn, targetFlags []string, targetPath string, log *slog.Logger) {
	defer client.Close()
	args := append(targetFlags, targetPath)
	cmd := exec.Command("npiperelay", args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		log.Error("npiperelay stdin pipe creation failed", "error", err)
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Error("npiperelay stdout pipe creation failed", "error", err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Error("npiperelay start failed", "error", err)
		return
	}
	done := make(chan struct{})
	go func() { io.Copy(stdin, client); stdin.Close(); close(done) }()
	_, err = io.Copy(client, stdout)
	if err != nil {
		log.Debug("npiperelay output closed", "error", err)
	}
	if cw, ok := client.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	client.SetReadDeadline(time.Now())
	<-done
	if err := cmd.Wait(); err != nil {
		log.Debug("npiperelay exited", "error", err)
	}
}
