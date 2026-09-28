# GPG Relay for WSL1 and WSL2, written in Go

This utility forwards requests from gpg clients in WSL1 and WSL2 to
[Gpg4win](https://gpg4win.org/)'s gpg-agent.exe in Windows. It can also
forward ssh requests to gpg-agent.exe, when using a PGP key for ssh
authentication. It is especially useful when you store your PGP key on a
Yubikey, since WSL cannot share access to USB devices with Windows.

## Architecture

This solution consists of two relay components:

- **WSL Relay** (`gpg_relay_wsl`): Runs in WSL. Receives GPG and SSH
  requests through local Unix sockets. It connects GPG traffic directly
  to Gpg4win or through the Win Relay, and starts `npiperelay` for SSH.
- **Win Relay** (`gpg_relay_win.exe`): Runs in Windows only for WSL2 NAT
  mode. Receives GPG requests over TCP and forwards them to Gpg4win.

Both executables share Go relay code in `internal/relay`.

Gpg4win's GPG Assuan socket files contain a TCP port and a nonce used
to authenticate the connection. WSL1 and WSL2 mirrored mode can use
these sockets directly. WSL2 NAT mode uses the Win Relay for GPG traffic.

For SSH, the WSL Relay starts `npiperelay -ei -s
//./pipe/openssh-ssh-agent` for each client and forwards bytes to
Gpg4win's named pipe. SSH traffic never passes through the Win Relay.
 Gpg4win's gpg-agent must be configured with `enable-ssh-support` and
 `enable-win32-openssh-support`.

### WSL Modes

The WSL Relay supports three networking modes, selected with `--wsl-mode`:

**WSL1** (`wsl1`):

```
gpg -> (Unix socket) -> WSL Relay -> (Assuan/TCP socket) -> gpg-agent.exe
ssh -> (Unix socket) -> WSL Relay -> npiperelay -> (named pipe) -> gpg-agent.exe
```

WSL1 can connect directly to 127.0.0.1 in Windows, so no firewall changes
are needed. The Win Relay is not required in this mode.

**WSL2 with NAT networking** (`wsl2_nat`):

```
gpg -> (Unix socket) -> WSL Relay -> [Windows Firewall] -> (TCP socket) -> Win Relay -> (Assuan/TCP socket) -> gpg-agent.exe
ssh -> (Unix socket) -> WSL Relay -> npiperelay -> (named pipe) -> gpg-agent.exe
```

WSL2 in NAT mode has a different IP address than the Windows host, so
network traffic to Windows is external (public). The Win Relay must listen
on `0.0.0.0` and the three GPG ports must be proxied. A firewall rule
is required for the three GPG ports (see [Firewall and Security](#firewall-and-security)).

**WSL2 with Mirrored networking** (`wsl2_mirrored`):

```
gpg -> (Unix socket) -> WSL Relay -> (Assuan/TCP socket) -> gpg-agent.exe
ssh -> (Unix socket) -> WSL Relay -> npiperelay -> (named pipe) -> gpg-agent.exe
```

WSL2 in mirrored mode can connect to gpg-agent.exe on 127.0.0.1 directly,
so no firewall changes or Win Relay are needed.

### Access Modes

- **Direct GPG access** (WSL1, WSL2 mirrored): The WSL Relay connects to
  Gpg4win's Assuan sockets.
- **GPG relay access** (WSL2 NAT): The WSL Relay connects to the Win Relay
  over TCP. The Win Relay connects to Gpg4win's Assuan sockets.
- **SSH access** (all modes): The WSL Relay connects to Gpg4win's
  `//./pipe/openssh-ssh-agent` through `npiperelay`.

### Authentication

To prevent unauthorized access to the Win Relay in WSL2 NAT mode, a nonce-based authentication scheme is used.
The Win Relay generates a random 16-byte nonce and stores it in a file.
The WSL Relay reads the nonce from the file and sends it when connecting.
The Win Relay rejects connections with an incorrect nonce.

## Firewall and Security

### Firewall Rules

**WSL1** and **WSL2 Mirrored** modes do not require any firewall changes,
since they connect to 127.0.0.1 in Windows directly.

**WSL2 NAT** mode requires a Windows Firewall rule to allow incoming
connections to the Win Relay. A firewall rule must allow incoming connections to `gpg_relay_win.exe`
on the three configured ports.

Specifically, add an incoming rule for the Public profile that allows
connections from `172.16.0.0/12` and `192.168.0.0/16` to TCP ports
`6910-6912` (or the three ports starting at the custom `--port`).

The private IP address ranges listed above are used by WSL2, but probably
also by computers on your local LAN. To limit access to the Win Relay, a
simple nonce authentication scheme similar to Assuan sockets is used. The
Win Relay stores a nonce in a file that should only be accessible by the
user. By default it saves the file in the GPG home directory in Windows.
The WSL Relay reads the nonce from the file and sends it to the Win Relay
to authenticate.

This ensures that only local processes that can read the nonce file can
authenticate with the Win Relay. Other connections will fail, which means
that connections from other computers on the LAN will be rejected.

## Installation

Build from this directory with Go 1.22 or newer:

```bash
make gpg_relay_wsl gpg_relay_win.exe
make test
```

The Makefile cross-compiles the Linux amd64 WSL executable and Windows amd64
executable. Copy `gpg_relay_wsl` to a path in WSL (for example,
`/usr/local/bin/gpg_relay_wsl`) and `gpg_relay_win.exe` to Windows. Gpg4win
and its `gpgconf.exe`, `gpg-connect-agent.exe`, and `gpg-agent.exe` must be
available on the Windows PATH. WSL needs access to `gpgconf.exe` and
`wslpath`; direct modes also invoke `gpgconf` to locate local socket paths.

For SSH support, install `npiperelay.exe` in Windows and create a WSL
symlink at `/usr/local/bin/npiperelay` pointing to it. Ensure
`/usr/local/bin` is on the WSL Relay's `PATH`, including when started
by systemd. The relay reports an error at startup if SSH support is
enabled and `npiperelay` cannot be found.

### WSL Relay

```bash
gpg_relay_wsl --help
```

The Go executable uses long flags with a single or double leading dash.
Supported flags are `--wsl-mode`, `--enable-ssh-support`, `--remote-address`,
`--port`, `--noncefile`, `--logfile`, `--pidfile`, `--systemd`, and
`--log-level`. Defaults are mirrored mode, port 6910, SSH disabled, and WARN
logging. The default remote address is the NAT gateway in NAT mode and
127.0.0.1 otherwise; an explicit `--remote-address` takes precedence.

### Win Relay

```bash
gpg_relay_win.exe --help
```

Start `gpg_relay_win.exe` independently on Windows for NAT mode. It listens
for GPG traffic on the three ports beginning at `--port` (default 6910).
Its flags are `--port`, `--noncefile`, `--log-level`, `--windows-address`,
`--windows-logfile`, and `--windows-pidfile`. The default listening address
is 127.0.0.1; use `--windows-address=0.0.0.0` for WSL2 NAT traffic and
configure the Windows firewall as described below. The nonce file defaults
to `gpg_relay.nonce` in the Windows GPG home directory.

### WSL Mode Selection

- **`wsl1`**: Use this mode when running in WSL1. No firewall changes needed.
- **`wsl2_nat`**: Use this mode when WSL2 is configured with NAT networking.
  Requires a Windows Firewall rule (see [Firewall and Security](#firewall-and-security)).
- **`wsl2_mirrored`** (default): Use this mode when WSL2 is configured with
  mirrored networking. No firewall changes or Win Relay are needed.

When the WSL mode is set to `wsl2_nat`, the remote address is automatically
detected from the default gateway. For other modes, the remote address
defaults to `127.0.0.1` and can be overridden with `--remote-address`.

## Systemd Socket Activation

The recommended way to run the WSL Relay is via systemd socket activation. This
eliminates the need for manual startup scripts and provides better startup
ordering and resource management.

### Installation

1. Copy the systemd unit files to your user systemd directory:

   ```bash
   mkdir -p ~/.config/systemd/user
   cp systemd/*.socket systemd/*.service ~/.config/systemd/user/
   ```

2. Reload the systemd user daemon:

   ```bash
   systemctl --user daemon-reload
   ```

3. Enable the socket units:

   ```bash
   systemctl --user enable --now gpg-relay-agent-socket.socket gpg-relay-agent-extra-socket.socket gpg-relay-agent-browser-socket.socket gpg-relay-agent-ssh-socket.socket
   ```

4. You may need to mask the gpg-agent socket units:

   ```bash
   systemctl --user mask gpg-agent.socket gpg-agent-browser.socket gpg-agent-extra.socket gpg-agent-ssh.socket
   ```

The service will now automatically start when any of the GPG sockets are
accessed. The four sockets are:

- `S.gpg-agent` - Main GPG agent socket
- `S.gpg-agent.browser` - Browser GPG agent socket
- `S.gpg-agent.extra` - Extra GPG agent socket
- `S.gpg-agent.ssh` - SSH GPG agent socket

### Configuration

The systemd service file can be customized by creating a drop-in override:

```bash
systemctl --user edit gpg-relay-agent.service
```

For example, to change the WSL mode or enable SSH support:

```ini
[Service]
ExecStart=/usr/local/bin/gpg_relay_wsl --enable-ssh-support --wsl-mode=wsl2_mirrored
```

## Tips when using Remote Desktop

If you are using RDP to a remote host, RDP can redirect the local Yubikey
smartcard to the remote host, so that the remote gpg-agent.exe can access
it.

Sometimes the Yubikey smartcard will be blocked on the local host so that
the remote host cannot access it. When that happens the solution is to
remove the Yubikey and insert it again, while an RDP session is active.
This allows RDP to grab the smartcard.

An alternative to re-inserting the Yubikey is to restart some local
services to free the Yubikey for use on the remote host. The
[rdp_yubikey.cmd](../utils/rdp_yubikey.cmd) batch command automates stopping
and/or restarting local processes. It must be run as Administrator.
