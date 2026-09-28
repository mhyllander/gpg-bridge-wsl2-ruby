package relay

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const NonceSize = 16

// AssuanEndpoint reads Gpg4win's port-newline-nonce socket descriptor.
func AssuanEndpoint(path string) (string, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	portText, nonce, found := strings.Cut(string(data), "\n")
	if !found {
		return "", nil, fmt.Errorf("%s: missing port separator", path)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", nil, fmt.Errorf("%s: invalid port %q", path, portText)
	}
	if len(nonce) != NonceSize {
		return "", nil, fmt.Errorf("%s: nonce length %d, want 16", path, len(nonce))
	}
	return net.JoinHostPort("127.0.0.1", portText), []byte(nonce), nil
}

func DialAssuan(path string) (net.Conn, error) {
	address, nonce, err := AssuanEndpoint(path)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", address, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err = conn.Write(nonce); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func ReadNonce(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != NonceSize {
		return nil, fmt.Errorf("%s: nonce length %d, want 16", path, len(data))
	}
	return data, nil
}

func DialWindows(address string, port int, noncePath string) (net.Conn, error) {
	nonce, err := ReadNonce(noncePath)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(address, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err = conn.Write(nonce); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

type closeWriter interface{ CloseWrite() error }

// Copy moves bytes in both directions, preserving a peer's ability to respond
// after the other peer has finished writing.
func Copy(a, b net.Conn, log *slog.Logger) {
	var wg sync.WaitGroup
	wg.Add(2)
	transfer := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Debug("relay copy ended", "error", err)
		}
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetWriteDeadline(time.Now())
		}
		if err != nil {
			_ = src.Close()
			_ = dst.Close()
		}
	}
	go transfer(a, b)
	go transfer(b, a)
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}
