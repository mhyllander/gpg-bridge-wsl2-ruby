package relay

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAssuanEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "socket")
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	port := server.Addr().(*net.TCPAddr).Port
	nonce := strings.Repeat("n", NonceSize)
	if err := os.WriteFile(path, []byte(strconv.Itoa(port)+"\n"+nonce), 0600); err != nil {
		t.Fatal(err)
	}
	address, got, err := AssuanEndpoint(path)
	if err != nil || address != server.Addr().String() || string(got) != nonce {
		t.Fatalf("endpoint: %q %q %v", address, got, err)
	}
	connected := make(chan error, 1)
	go func() {
		peer, err := server.Accept()
		if err != nil {
			connected <- err
			return
		}
		defer peer.Close()
		data := make([]byte, NonceSize)
		_, err = io.ReadFull(peer, data)
		if err == nil && string(data) != nonce {
			err = io.ErrUnexpectedEOF
		}
		connected <- err
	}()
	client, err := DialAssuan(path)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	if err := <-connected; err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{"", "no-newline", "invalid\n" + nonce, "0\n" + nonce, "123\nshort"} {
		os.WriteFile(path, []byte(content), 0600)
		if _, _, err := AssuanEndpoint(path); err == nil {
			t.Fatalf("accepted %q", content)
		}
	}
}

func TestWindowsNonceAndCopy(t *testing.T) {
	noncePath := filepath.Join(t.TempDir(), "nonce")
	os.WriteFile(noncePath, []byte(strings.Repeat("a", NonceSize)), 0600)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(3 * time.Second))
		got := make([]byte, NonceSize)
		_, err = io.ReadFull(peer, got)
		if err != nil {
			done <- err
			return
		}
		if string(got) != strings.Repeat("a", NonceSize) {
			done <- io.ErrUnexpectedEOF
			return
		}
		data, err := io.ReadAll(peer)
		if err != nil {
			done <- err
			return
		}
		if string(data) != "request" {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, err = peer.Write([]byte("response"))
		done <- err
	}()
	client, err := DialWindows("127.0.0.1", listener.Addr().(*net.TCPAddr).Port, noncePath)
	if err != nil {
		t.Fatal(err)
	}
	client.SetDeadline(time.Now().Add(3 * time.Second))
	client.Write([]byte("request"))
	client.(*net.TCPConn).CloseWrite()
	answer, err := io.ReadAll(client)
	client.Close()
	if err != nil || string(answer) != "response" {
		t.Fatalf("response %q: %v", answer, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	os.WriteFile(noncePath, []byte("short"), 0600)
	if _, err := ReadNonce(noncePath); err == nil {
		t.Fatal("accepted short nonce")
	}
}

func TestBidirectionalCopy(t *testing.T) {
	leftListener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer leftListener.Close()
	rightListener, _ := net.Listen("tcp", "127.0.0.1:0")
	defer rightListener.Close()
	leftClient, _ := net.Dial("tcp", leftListener.Addr().String())
	defer leftClient.Close()
	leftRelay, _ := leftListener.Accept()
	rightRelay, _ := net.Dial("tcp", rightListener.Addr().String())
	rightServer, _ := rightListener.Accept()
	defer rightServer.Close()
	done := make(chan struct{})
	go func() { Copy(leftRelay, rightRelay, slog.Default()); close(done) }()
	leftClient.SetDeadline(time.Now().Add(3 * time.Second))
	rightServer.SetDeadline(time.Now().Add(3 * time.Second))
	leftClient.Write([]byte("hello"))
	leftClient.(*net.TCPConn).CloseWrite()
	input, _ := io.ReadAll(rightServer)
	if string(input) != "hello" {
		t.Fatalf("got %q", input)
	}
	rightServer.Write([]byte("world"))
	rightServer.(*net.TCPConn).CloseWrite()
	output, _ := io.ReadAll(leftClient)
	if string(output) != "world" {
		t.Fatalf("got %q", output)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not exit")
	}
}
