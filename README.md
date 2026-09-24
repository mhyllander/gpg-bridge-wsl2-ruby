# GPG Bridge for WSL1 and WSL2, written in Ruby

This utility forwards requests from gpg clients in WSL1 and WSL2 to
[Gpg4win](https://gpg4win.org/)'s gpg-agent.exe in Windows. It can also
forward ssh requests to gpg-agent.exe, when using a PGP key for ssh
authentication. It is especially useful when you store your PGP key on a
Yubikey, since WSL cannot share access to USB devices with Windows.

This tool is inspired by
[wsl-gpg-bridge](https://github.com/Riebart/wsl-gpg-bridge), which works
with WSL1 together with Gpg4win and a Yubikey.

## Architecture

This solution consists of two bridge components:

- **WSL-bridge** (`gpgbridge.rb`): Runs in WSL. Receives requests from gpg/ssh
  clients through local Unix sockets and forwards them to the Win-bridge in
  Windows.
- **Win-bridge** (also `gpgbridge.rb` with `--windows-bridge`): Runs in Windows.
  Receives requests over TCP from the WSL-bridge and forwards them through
  Assuan sockets to gpg-agent.exe in Gpg4win.

Since Windows does not support Unix sockets, gpg-agent.exe uses a mechanism
called an Assuan socket. This is a file that contains the TCP port that
gpg-agent is listening on, and a nonce that is sent as authentication after
connecting. The Win-bridge reads the Assuan socket files and connects
directly with gpg-agent.exe (except for the ssh-agent socket).

Gpg4win's gpg-agent.exe does not currently support standard ssh-agent (or
rather, the implementation is broken). Therefore, Pageant ssh support must
be enabled in gpg-agent.exe. To communicate with the Pageant server, the
Win-bridge uses [net-ssh](https://github.com/net-ssh/net-ssh).

### WSL Modes

The WSL-bridge supports three networking modes, selected with `--wsl-mode`:

**WSL1** (`wsl1`):

```
gpg -> (Unix socket) -> WSL-bridge -> (Assuan/TCP socket) -> gpg-agent.exe
ssh -> (Unix socket) -> WSL-bridge -> (TCP socket) -> Win-bridge -> (Pageant socket) -> gpg-agent.exe
```

WSL1 can connect directly to 127.0.0.1 in Windows, so no firewall changes
are needed. The Win-bridge is only required when SSH support is enabled
(see below).

**WSL2 with NAT networking** (`wsl2_nat`):

```
gpg -> (Unix socket) -> WSL-bridge -> [Windows Firewall] -> (TCP socket) -> Win-bridge -> (Assuan/TCP socket) -> gpg-agent.exe
ssh -> (Unix socket) -> WSL-bridge -> [Windows Firewall] -> (TCP socket) -> Win-bridge -> (Pageant socket) -> gpg-agent.exe
```

WSL2 in NAT mode has a different IP address than the Windows host, so
network traffic to Windows is external (public). The Win-bridge must listen
on `0.0.0.0` and all gpg-agent.exe ports must be proxied. A firewall rule
is required (see [Firewall and Security](#firewall-and-security)).

**WSL2 with Mirrored networking** (`wsl2_mirrored`):

```
gpg -> (Unix socket) -> WSL-bridge -> (Assuan/TCP socket) -> gpg-agent.exe
ssh -> (Unix socket) -> WSL-bridge -> (TCP socket) -> Win-bridge -> (Pageant socket) -> gpg-agent.exe
```

WSL2 in mirrored mode can connect to gpg-agent.exe on 127.0.0.1 directly,
so no firewall changes are needed. However, the Win-bridge is still required
to proxy the SSH socket (see below).

### Access Modes

The bridge uses two different access modes depending on the WSL mode:

- **Assuan access** (WSL1, WSL2 Mirrored): The WSL-bridge connects directly
  to gpg-agent.exe's Assuan sockets. This is simpler and does not require
  the Win-bridge for gpg traffic.
- **Relay access** (WSL2 NAT, and all cases with SSH support): The
  WSL-bridge relays traffic through the Win-bridge over TCP. This is needed
  when direct access to gpg-agent.exe is not possible, or for SSH
  authentication (which requires the Pageant protocol workaround).

When SSH support is enabled, the Win-bridge is always started because
gpg-agent.exe does not respond on the SSH Assuan socket. The Win-bridge proxies
the SSH port using the PuTTY Pageant protocol.

### Authentication

To prevent unauthorized access to the Win-bridge (since WSL2 NAT mode
exposes it to the network), a nonce-based authentication scheme is used.
The Win-bridge generates a random 16-byte nonce and stores it in a file.
The WSL-bridge reads the nonce and sends it when connecting. The Win-bridge
rejects connections with an incorrect nonce.

## Firewall and Security

### Firewall Rules

**WSL1** and **WSL2 Mirrored** modes do not require any firewall changes,
since they connect to 127.0.0.1 in Windows directly.

**WSL2 NAT** mode requires a Windows Firewall rule to allow incoming
connections to the Win-bridge. There is probably a general rule that denies
incoming Public TCP requests to the Ruby interpreter. You will need to
disable this rule, and instead add a rule that allows incoming traffic to
certain ports.

Specifically, add an incoming rule for the Public profile that allows
connections from `172.16.0.0/12` and `192.168.0.0/16` to TCP ports
`6910-6913` (or the custom port range you selected with `--port`).

The private IP address ranges listed above are used by WSL2, but probably
also by computers on your local LAN. To limit access to the Win-bridge, a
simple nonce authentication scheme similar to Assuan sockets is used. The
Win-bridge stores a nonce in a file that should only be accessible by the
user. By default it saves the file in the GPG home directory in Windows.
The WSL-bridge reads the nonce from the file and sends it to the Win-bridge
to authenticate.

This ensures that only local processes that can read the nonce file can
authenticate with Win-bridge. Other connections will fail, which means that
connections from other computers on the LAN will be rejected.

## Installation

In Windows, install [Ruby](https://rubyinstaller.org/downloads/). Ensure
that both the ruby and gpg executables are in the Path.

In each WSL, install ruby.

Unpack the gpgbridge release in a suitable location in the Windows
filesystem that is reachable from both Windows and WSL.

Install dependencies. From the unpacked gpgbridge folder, run "bundle
install" in Windows and each WSL distribution to install the gems needed in
each environment.

Or, if you prefer to do it manually:

1. In Windows: gem install -N sys-proctable net-ssh
2. In each WSL distribution: gem install -N sys-proctable ptools

## Usage

In the example below the release was unpacked in `C:\Program1\gpgbridge`,
which is `/mnt/c/Program1/gpgbridge` in WSL.

```
$ ruby /mnt/c/Program1/gpgbridge/gpgbridge.rb --help
Usage: gpgbridge.rb [options]
    -m, --wsl-mode MODE                  The WSL networking mode (wsl1, wsl2_nat, wsl2_mirrored) [wsl2_mirrored]
    -r, --remote-address IPADDR          The remote address of the Windows bridge component [127.0.0.1]
    -s, --[no-]enable-ssh-support        Enable proxying of gpg-agent SSH sockets
    -d, --[no-]daemon                    Run as a daemon in the background
    -p, --port PORT                      The first port (of three or four) to use for proxying sockets
    -n, --noncefile PATH                 The nonce file path (defaults to file in Windows gpg homedir)
    -l, --logfile PATH                   The log file path
    -i, --pidfile PATH                   The PID file path
    -v, --log-level LEVEL                Logging level (DEBUG, INFO, WARN, ERROR, FATAL, UNKNOWN) [WARN]
    -W, --[no-]windows-bridge            Start the Windows bridge (used by the WSL bridge)
    -R, --windows-address IPADDR         The IP listening address of the Windows bridge [127.0.0.1]
    -L, --windows-logfile PATH           The log file path of the Windows bridge
    -I, --windows-pidfile PATH           The PID file path of the Windows bridge
    -h, --help                           Prints this help
```

### WSL Mode Selection

- **`wsl1`**: Use this mode when running in WSL1. No firewall changes needed.
- **`wsl2_nat`**: Use this mode when WSL2 is configured with NAT networking.
  Requires a Windows Firewall rule (see [Firewall and Security](#firewall-and-security)).
- **`wsl2_mirrored`** (default): Use this mode when WSL2 is configured with
  mirrored networking. No firewall changes needed, but the Win-bridge is
  still required for SSH support.

When the WSL mode is set to `wsl2_nat`, the remote address is automatically
detected from the default gateway. For other modes, the remote address
defaults to `127.0.0.1` and can be overridden with `--remote-address`.

## Example bash/zsh/sh helper functions

Unpack the release file to a suitable location in the Windows filesystem
that is reachable from both Windows and WSL.

Edit the PATHS section in the [`gpgbridge_helper.sh`](gpgbridge_helper.sh)
file (or set the variables before sourcing the file.) When `SCRIPT_DIR_WSL`
is set appropriately, the helper file can be used from all WSL
distributions.

Add the following commands to your `~/.bash_profile`, `~/.bashrc`,
`~/.zshrc` or similar.

  1. Source the file: `source path/to/gpgbridge_helper.sh`.
  2. Call the start function with the appropriate flags:

     ```
     # For WSL1:
     start_gpgbridge --wsl1

     # For WSL2 with NAT networking:
     start_gpgbridge --wsl2-nat

     # For WSL2 with mirrored networking (default):
     start_gpgbridge --wsl2-mirrored

     # Add --ssh to enable SSH forwarding:
     start_gpgbridge --wsl2-mirrored --ssh
     ```

This will start the WSL-bridge in WSL, which will in turn start the
Win-bridge in Windows. Note that only one WSL-bridge will be started per
WSL distribution, and they will all share the same single Win-bridge
running in Windows.

## Timeout during PIN entry

Net/ssh normally has a hard-coded timeout of 5s when communicating with
Pageant. This does not work well when gpg-agent.exe is the Pageant server,
because the Pageant client will probably time out while gpg-agent.exe is
prompting for PIN entry. The result is that ssh authentication fails
unless you are really fast when entering the PIN.

This is handled by specializing `Net::SSH::Authentication::Pageant::Socket`
with a custom `SocketWithTimeout` class that uses a configurable timeout
(default 30 seconds) via `SendMessageTimeout` instead of the default.
This allows gpg-agent.exe enough time to prompt for PIN entry.

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
