.PHONY: all test clean gpg_relay_wsl gpg_relay_win.exe

all: gpg_relay_wsl gpg_relay_win.exe

gpg_relay_wsl:
	GOOS=linux GOARCH=amd64 go build -o $@ ./cmd/wsl

gpg_relay_win.exe:
	GOOS=windows GOARCH=amd64 go build -o $@ ./cmd/win

test:
	go test ./...

clean:
	rm -f gpg_relay_wsl gpg_relay_win.exe
