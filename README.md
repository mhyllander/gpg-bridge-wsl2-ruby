# GPG Relay for WSL1 and WSL2, written in Ruby

This utility forwards requests from gpg clients in WSL1 and WSL2 to
[Gpg4win](https://gpg4win.org/)'s gpg-agent.exe in Windows. It can also
forward ssh requests to gpg-agent.exe, when using a PGP key for ssh
authentication. It is especially useful when you store your PGP key on a
Yubikey, since WSL cannot share access to USB devices with Windows.

This tool is inspired by
[wsl-gpg-bridge](https://github.com/Riebart/wsl-gpg-bridge), which works
with WSL1 together with Gpg4win and a Yubikey.

## Architecture

This solution consists of two relay components:

- **WSL Relay** (`gpg_relay_wsl.rb`): Runs in WSL. Receives GPG and SSH
  requests through local Unix sockets. It connects GPG traffic
  to Gpg4win directly, through the Win Relay, or through `npiperelay`.
- **Win Relay** (`gpg_relay_win.rb`): Runs in Windows only for WSL2 NAT
  mode. Receives GPG requests over TCP and forwards them to Gpg4win.

Both components share a common base class in `relay.rb`.

Gpg4win's GPG Assuan socket files contain a TCP port and a nonce used
to authenticate the connection. WSL1 and WSL2 mirrored mode can use
these sockets directly. WSL2 NAT mode uses the Win Relay for GPG traffic.
The `npiperelay` mode opens the Windows Assuan sockets through a Windows
process, independent of the WSL networking mode.

For SSH, the WSL Relay starts `npiperelay -ei -s
//./pipe/openssh-ssh-agent` for each client and forwards bytes to
Gpg4win's named pipe. SSH traffic never passes through the Win Relay.
 Gpg4win's gpg-agent must be configured with `enable-ssh-support` and
 `enable-win32-openssh-support`.

### GPG Access Modes

The WSL Relay supports four modes, selected with `--mode`:

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

**npiperelay** (`npiperelay`):

```
gpg -> (Unix socket) -> WSL Relay -> npiperelay -> (Windows Assuan socket) -> gpg-agent.exe
ssh -> (Unix socket) -> WSL Relay -> npiperelay -> (named pipe) -> gpg-agent.exe
```

This mode works in any WSL variant when Windows
executable interop is enabled. It does not need the Win Relay or a Windows
Firewall rule. It starts one `npiperelay` process per GPG client connection.

### Access Modes

- **Direct GPG access** (WSL1, WSL2 mirrored): The WSL Relay connects to
  Gpg4win's Assuan sockets.
- **GPG relay access** (WSL2 NAT): The WSL Relay connects to the Win Relay
  over TCP. The Win Relay connects to Gpg4win's Assuan sockets.
- **GPG access through npiperelay** (`npiperelay`): The WSL Relay starts
  `npiperelay` on the Windows Assuan
  socket path for each GPG connection.
- **SSH access** (all modes): The WSL Relay starts
  `npiperelay` on Gpg4win's
  `//./pipe/openssh-ssh-agent`.

### Authentication

To prevent unauthorized access to the Win Relay in WSL2 NAT mode, a nonce-based authentication scheme is used.
The Win Relay generates a random 16-byte nonce and stores it in a file.
The WSL Relay reads the nonce from the file and sends it when connecting.
The Win Relay rejects connections with an incorrect nonce.

## Firewall and Security

### Firewall Rules

**WSL1** and **WSL2 Mirrored** modes connect to 127.0.0.1 in Windows.
The **npiperelay** mode runs a Windows process to connect to the local
Assuan socket. None of these modes requires a firewall change.

**WSL2 NAT** mode requires a Windows Firewall rule to allow incoming
connections to the Win Relay. A general rule may exist that denies
incoming Public TCP requests to the Ruby interpreter. You will need to
disable this rule, and instead add a rule that allows incoming traffic to
certain ports.

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

In Windows, install [Ruby](https://rubyinstaller.org/downloads/). Ensure
that both the ruby and gpg executables are in the Path.

In each WSL, install ruby.

Unpack the release in a suitable location in the Windows
filesystem that is reachable from both Windows and WSL.

Install dependencies. From the unpacked release folder, run `bundle
install` in Windows and each WSL distribution to install the gems needed in
each environment.

Or, if you prefer to do it manually:

1. In Windows: `gem install -N sys-proctable`
2. In each WSL distribution: `gem install -N sys-proctable`

For SSH support or `npiperelay` GPG mode, install a current release of
[albertony's npiperelay fork](https://github.com/albertony/npiperelay/releases)
in Windows. This fork supports the `-a` Assuan socket option; the original
`jstarks/npiperelay` release does not. Create a WSL symlink at
`/usr/local/bin/npiperelay` pointing to `npiperelay.exe` and ensure
`/usr/local/bin` is on the WSL Relay's `PATH`, including when started
by systemd. The relay reports an error at startup if `npiperelay` is
required and cannot be found. Windows executable interop must be enabled.

### WSL Relay

In the example below, the release was unpacked in `C:\Program1\gpgrelay`,
which is `/mnt/c/Program1/gpgrelay` in WSL.

```bash
$ ruby /mnt/c/Program1/gpgrelay/gpg_relay_wsl.rb --help
Usage: gpg_relay_wsl.rb [options]
    -m, --mode MODE                  The GPG access mode (wsl1, wsl2_nat, wsl2_mirrored, npiperelay) [wsl2_mirrored]
    -s, --[no-]enable-ssh-support    Relay SSH through the Gpg4win named pipe using npiperelay
    -r, --remote-address IPADDR      The remote address of the Windows relay component [127.0.0.1]
    -p, --port PORT                  The first of three ports used for GPG sockets
    -n, --noncefile PATH             The nonce file path (defaults to file in Windows gpg homedir)
    -l, --logfile PATH               The log file path
    -i, --pidfile PATH               The PID file path
        --systemd                    Use systemd socket activation (listen fds passed by systemd)
    -v, --log-level LEVEL            Logging level (DEBUG, INFO, WARN, ERROR, FATAL, UNKNOWN) [WARN]
    -h, --help                       Prints this help
```

### Win Relay

In `wsl2_nat` mode, start the Win Relay independently in Windows (e.g., via
Task Scheduler, a batch file, or PowerShell). It handles only GPG traffic.

```bash
$ ruby C:\Program1\gpgrelay\gpg_relay_win.rb --help
Usage: gpg_relay_win.rb [options]
    -p, --port PORT                  The first of three ports used for GPG sockets
    -n, --noncefile PATH             The nonce file path (defaults to file in Windows gpg homedir)
    -v, --log-level LEVEL            Logging level (DEBUG, INFO, WARN, ERROR, FATAL, UNKNOWN) [WARN]
    -R, --windows-address IPADDR     The IP listening address [127.0.0.1]
    -L, --windows-logfile PATH       The log file path
    -I, --windows-pidfile PATH       The PID file path
    -h, --help                       Prints this help
```

### Mode Selection

- **`wsl1`**: Use this mode when running in WSL1. No firewall changes needed.
- **`wsl2_nat`**: Use this mode when WSL2 is configured with NAT networking.
  Requires a Windows Firewall rule (see [Firewall and Security](#firewall-and-security)).
- **`wsl2_mirrored`** (default): Use this mode when WSL2 is configured with
  mirrored networking. No firewall changes or Win Relay are needed.
- **`npiperelay`**: Use this mode with any WSL networking configuration to
  reach GPG through Windows executable interop. No Win Relay is needed.

When the mode is set to `wsl2_nat`, the remote address is automatically
detected from the default gateway. In `wsl1` and `wsl2_mirrored` modes, the remote address is set to
`127.0.0.1`.
The `npiperelay` mode does not use the remote address.

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

4. You may need to mask the gpg-agent service and socket units:

   ```bash
   systemctl --user mask gpg-agent.service gpg-agent.socket gpg-agent-browser.socket gpg-agent-extra.socket gpg-agent-ssh.socket
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

For example, to change the access mode or enable SSH support:

```ini
[Service]
ExecStart=/usr/bin/ruby /mnt/c/Program1/gpgrelay/gpg_relay_wsl.rb --systemd --enable-ssh-support --mode=wsl2_mirrored
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
[rdp_yubikey.cmd](utils/rdp_yubikey.cmd) batch command automates stopping
and/or restarting local processes. It must be run as Administrator.
