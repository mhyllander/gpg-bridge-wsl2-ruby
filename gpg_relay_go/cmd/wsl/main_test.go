package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func executable(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func startSocket(t *testing.T, s socket, mode, remote string, port int, nonce string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "listen.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go serve(ctx, listener, s, mode, remote, port, nonce, slog.Default())
	t.Cleanup(func() { cancel(); listener.Close() })
	return path
}

func exchange(t *testing.T, path string) {
	t.Helper()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	client.Write([]byte("ping"))
	client.(*net.UnixConn).CloseWrite()
	answer, err := io.ReadAll(client)
	if err != nil || string(answer) != "pong" {
		t.Fatalf("answer %q: %v", answer, err)
	}
}

func TestDirectAndNATForwarding(t *testing.T) {
	for _, mode := range []string{"wsl1", "wsl2_mirrored", "wsl2_nat"} {
		t.Run(mode, func(t *testing.T) {
			upstream, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer upstream.Close()
			nonce := strings.Repeat("n", 16)
			dir := t.TempDir()
			noncePath := filepath.Join(dir, "nonce")
			os.WriteFile(noncePath, []byte(nonce), 0600)
			if mode != "wsl2_nat" {
				assuan := filepath.Join(dir, "assuan")
				os.WriteFile(assuan, []byte(strconv.Itoa(upstream.Addr().(*net.TCPAddr).Port)+"\n"+nonce), 0600)
				bin := filepath.Join(dir, "bin")
				os.Mkdir(bin, 0755)
				os.WriteFile(filepath.Join(bin, "gpgconf.exe"), []byte("#!/bin/sh\necho '"+assuan+"'\n"), 0755)
				os.WriteFile(filepath.Join(bin, "wslpath"), []byte("#!/bin/sh\necho \"$2\"\n"), 0755)
				t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			}
			done := make(chan error, 1)
			go func() {
				peer, err := upstream.Accept()
				if err != nil {
					done <- err
					return
				}
				defer peer.Close()
				peer.SetDeadline(time.Now().Add(3 * time.Second))
				first := make([]byte, 16)
				_, err = io.ReadFull(peer, first)
				if err != nil {
					done <- err
					return
				}
				if string(first) != nonce {
					done <- io.ErrUnexpectedEOF
					return
				}
				request, err := io.ReadAll(peer)
				if err != nil {
					done <- err
					return
				}
				if string(request) != "ping" {
					done <- io.ErrUnexpectedEOF
					return
				}
				_, err = peer.Write([]byte("pong"))
				done <- err
			}()
			path := startSocket(t, socket{"agent-socket", 0, false}, mode, "127.0.0.1", upstream.Addr().(*net.TCPAddr).Port, noncePath)
			exchange(t, path)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSSHForwarding(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	os.Mkdir(bin, 0755)
	os.WriteFile(filepath.Join(bin, "npiperelay"), []byte("#!/bin/sh\n[ \"$*\" = '-ep -ei -p -s //./pipe/openssh-ssh-agent' ] || exit 2\nexec /bin/cat\n"), 0755)
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	path := startSocket(t, socket{"agent-ssh-socket", 0, true}, "wsl2_mirrored", "", 0, "")
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	client.Write([]byte("hello"))
	client.(*net.UnixConn).CloseWrite()
	answer, err := io.ReadAll(client)
	if err != nil || string(answer) != "hello" {
		t.Fatalf("SSH answer %q: %v", answer, err)
	}
}

func TestNpiperelayGPGForwardingAndPathCache(t *testing.T) {
	for _, name := range []string{"agent-socket", "agent-extra-socket", "agent-browser-socket"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0755); err != nil {
				t.Fatal(err)
			}
			windowsPath := `C:\Users\test user\AppData\Local\gnupg\` + name
			calls := filepath.Join(dir, "gpgconf-calls")
			args := filepath.Join(dir, "npiperelay-args")
			pids := filepath.Join(dir, "npiperelay-pids")
			gpgconf := "#!/bin/sh\nprintf '%s\\n' \"$2\" >> \"$TEST_GPGCONF_CALLS\"\nprintf '%s\\n' \"$TEST_WINDOWS_PATH\"\n"
			npipe := "#!/bin/sh\nfor arg do printf '%s|' \"$arg\"; done >> \"$TEST_NPIPE_ARGS\"\nprintf '\\n' >> \"$TEST_NPIPE_ARGS\"\nprintf '%s\\n' \"$$\" >> \"$TEST_NPIPE_PIDS\"\nexec /bin/cat\n"
			if err := os.WriteFile(filepath.Join(bin, "gpgconf.exe"), []byte(gpgconf), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "npiperelay"), []byte(npipe), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			t.Setenv("TEST_GPGCONF_CALLS", calls)
			t.Setenv("TEST_WINDOWS_PATH", windowsPath)
			t.Setenv("TEST_NPIPE_ARGS", args)
			t.Setenv("TEST_NPIPE_PIDS", pids)
			path := startSocket(t, socket{name, 0, false}, "npiperelay", "", 0, "")
			results := make(chan error, 2)
			for i := 0; i < 2; i++ {
				go func(i int) {
					client, err := net.Dial("unix", path)
					if err != nil {
						results <- err
						return
					}
					defer client.Close()
					client.SetDeadline(time.Now().Add(3 * time.Second))
					payload := "request-" + strconv.Itoa(i)
					if _, err := client.Write([]byte(payload)); err != nil {
						results <- err
						return
					}
					client.(*net.UnixConn).CloseWrite()
					response, err := io.ReadAll(client)
					if err == nil && string(response) != payload {
						err = fmt.Errorf("got %q, want %q", response, payload)
					}
					results <- err
				}(i)
			}
			for i := 0; i < 2; i++ {
				if err := <-results; err != nil {
					t.Fatal(err)
				}
			}
			callData, err := os.ReadFile(calls)
			if err != nil {
				t.Fatal(err)
			}
			if string(callData) != name+"\n" {
				t.Fatalf("gpgconf calls %q", callData)
			}
			argData, err := os.ReadFile(args)
			if err != nil {
				t.Fatal(err)
			}
			want := "-ep|-ei|-a|" + windowsPath + "|\n"
			if string(argData) != want+want {
				t.Fatalf("npiperelay arguments %q", argData)
			}
			pidData, err := os.ReadFile(pids)
			if err != nil {
				t.Fatal(err)
			}
			pidLines := strings.Fields(string(pidData))
			if len(pidLines) != 2 {
				t.Fatalf("child PIDs %q", pidData)
			}
			for _, line := range pidLines {
				pid, err := strconv.Atoi(line)
				if err != nil {
					t.Fatal(err)
				}
				if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
					t.Fatalf("child %d still alive: %v", pid, err)
				}
			}
		})
	}
}

func TestMissingNpiperelayInGPGMode(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "gpg_relay_wsl")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gpgconf.exe"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "--mode=npiperelay")
	cmd.Env = append(os.Environ(), "PATH="+dir)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "cannot find npiperelay in PATH") {
		t.Fatalf("missing executable: %v: %s", err, out)
	}
}

func TestSystemdActivatedNpiperelayGPG(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	windowsPath := `C:\gnupg\S.gpg-agent`
	args := filepath.Join(dir, "args")
	gpgconf := "#!/bin/sh\nprintf '%s\\n' \"$TEST_WINDOWS_PATH\"\n"
	npipe := "#!/bin/sh\nfor arg do printf '%s|' \"$arg\"; done >> \"$TEST_NPIPE_ARGS\"\nprintf '\\n' >> \"$TEST_NPIPE_ARGS\"\nexec /bin/cat\n"
	if err := os.WriteFile(filepath.Join(bin, "gpgconf.exe"), []byte(gpgconf), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "npiperelay"), []byte(npipe), 0755); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "activated.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := listener.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSystemdNpiperelayChild$")
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = append(os.Environ(), "TEST_SYSTEMD_NPIPE_CHILD=1", "PATH="+bin+":"+os.Getenv("PATH"), "TEST_WINDOWS_PATH="+windowsPath, "TEST_NPIPE_ARGS="+args)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte("activated")); err != nil {
		t.Fatal(err)
	}
	client.(*net.UnixConn).CloseWrite()
	response, err := io.ReadAll(client)
	client.Close()
	if err != nil || string(response) != "activated" {
		t.Fatalf("response %q: %v", response, err)
	}
	data, err := os.ReadFile(args)
	if err != nil || string(data) != "-ep|-ei|-a|"+windowsPath+"|\n" {
		t.Fatalf("npiperelay arguments %q: %v", data, err)
	}
}

func TestSystemdNpiperelayChild(t *testing.T) {
	if os.Getenv("TEST_SYSTEMD_NPIPE_CHILD") != "1" {
		return
	}
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", "agent-socket")
	names, err := activationNames()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := activatedListener(names, "agent-socket")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go serve(ctx, listener, socket{"agent-socket", 0, false}, "npiperelay", "", 0, "", slog.Default())
	time.Sleep(2 * time.Second)
}

func TestSocketPathCacheAndRetry(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	gpgconf := "#!/bin/sh\nprintf 'gpgconf\\n' >> \"$TEST_PATH_CALLS\"\nif [ -e \"$TEST_FAIL_LOOKUP\" ]; then exit 1; fi\nprintf 'C:/agent/%s\\n' \"$2\"\n"
	wslpath := "#!/bin/sh\nprintf 'wslpath\\n' >> \"$TEST_PATH_CALLS\"\nprintf '/tmp/agent/%s\\n' \"$2\"\n"
	if err := os.WriteFile(filepath.Join(bin, "gpgconf.exe"), []byte(gpgconf), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "wslpath"), []byte(wslpath), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("TEST_PATH_CALLS", calls)
	fail := filepath.Join(dir, "fail")
	t.Setenv("TEST_FAIL_LOOKUP", fail)
	if err := os.WriteFile(fail, nil, 0600); err != nil {
		t.Fatal(err)
	}
	paths := &socketPaths{}
	if _, err := paths.windowsPath("agent-socket"); err == nil {
		t.Fatal("expected lookup failure")
	}
	if err := os.Remove(fail); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if path, err := paths.windowsPath("agent-socket"); err != nil || path != "C:/agent/agent-socket" {
			t.Fatalf("Windows path %q: %v", path, err)
		}
		if path, err := paths.wslPath("agent-socket"); err != nil || path != "/tmp/agent/C:/agent/agent-socket" {
			t.Fatalf("WSL path %q: %v", path, err)
		}
	}
	data, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "gpgconf\ngpgconf\nwslpath\n" {
		t.Fatalf("path commands %q", data)
	}
}

func TestSystemdDescriptorValidation(t *testing.T) {
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "2")
	t.Setenv("LISTEN_FDNAMES", "agent-socket:agent-extra-socket")
	names, err := activationNames()
	if err != nil || len(names) != 2 {
		t.Fatalf("names %v: %v", names, err)
	}
	if _, err := activatedListener(names, "agent-browser-socket"); err == nil {
		t.Fatal("accepted missing descriptor")
	}
	t.Setenv("LISTEN_PID", "1")
	if _, err := activationNames(); err == nil {
		t.Fatal("accepted mismatched PID")
	}
}

func TestPassedSystemdListener(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "activated.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	file, err := listener.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := exec.Command(os.Args[0], "-test.run=TestSystemdDescriptorChild")
	cmd.ExtraFiles = []*os.File{file}
	cmd.Env = append(os.Environ(), "TEST_SYSTEMD_CHILD=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	answer := make([]byte, 2)
	if _, err := io.ReadFull(client, answer); err != nil {
		t.Fatal(err)
	}
	if string(answer) != "ok" {
		t.Fatalf("answer %q", answer)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestSystemdDescriptorChild(t *testing.T) {
	if os.Getenv("TEST_SYSTEMD_CHILD") != "1" {
		return
	}
	t.Setenv("LISTEN_PID", strconv.Itoa(os.Getpid()))
	t.Setenv("LISTEN_FDS", "1")
	t.Setenv("LISTEN_FDNAMES", "agent-socket")
	names, err := activationNames()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := activatedListener(names, "agent-socket")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if _, err := peer.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentSSHClients(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "npiperelay"), []byte("#!/bin/sh\nexec /bin/cat\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	path := startSocket(t, socket{"agent-ssh-socket", 0, true}, "wsl2_mirrored", "", 0, "")
	results := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func(i int) {
			client, err := net.Dial("unix", path)
			if err != nil {
				results <- err
				return
			}
			defer client.Close()
			client.SetDeadline(time.Now().Add(3 * time.Second))
			payload := "client-" + strconv.Itoa(i)
			if _, err := client.Write([]byte(payload)); err != nil {
				results <- err
				return
			}
			client.(*net.UnixConn).CloseWrite()
			response, err := io.ReadAll(client)
			if err == nil && string(response) != payload {
				err = fmt.Errorf("got %q, want %q", response, payload)
			}
			results <- err
		}(i)
	}
	for i := 0; i < 4; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}
