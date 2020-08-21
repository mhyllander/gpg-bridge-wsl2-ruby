# GPG Bridge for WSL1 and WSL2, written in Ruby

This utility forwards requests from gpg clients in WSL1 and WSL2 to
[Gpg4win](https://gpg4win.org/)'s gpg-agent.exe in Windows. It can also
forward ssh requests to gpg-agent.exe, when using a PGP key for ssh
authentication. It is especially useful when you store your PGP key on a
Yubikey, since WSL cannot (yet) access USB devices.

This tool is inspired by
[wsl-gpg-bridge](https://github.com/Riebart/wsl-gpg-bridge), which works
with WSL1 together with Gpg4win and a Yubikey.

When WSL2 became available, wsl-gpg-bridge did not work anymore. The main
problem is that WSL2 distributions run in a separate VM, with a different
IP address, and therefore WSL2 processes can no longer connect directly
with gpg-agent.exe in Windows (because gpg-agent.exe binds to 127.0.0.1).

To solve the connection problem, this solution consists of two bridges (or
proxy applications):

WSL1:

```
gpg/ssh -> (Unix socket) WSL-bridge ->
    -> (TCP socket) Win-bridge -> (TCP/Assuan socket) gpg-agent.exe
```

WSL2:

```
gpg/ssh -> (Unix socket) WSL-bridge -> (Windows Firewall) ->
    -> (TCP socket) Win-bridge -> (TCP/Assuan socket) gpg-agent.exe
```

In WSL2, network traffic to Windows is external, or public. Therefore it
must be allowed by the Windows Firewall.

Since Windows does not support Unix sockets, gpg-agent.exe uses a mechanism
called an Assuan socket. This is a file that contains the TCP port that
gpg-agent is listening on, and a nonce that is sent as authentication after
connecting. The Win-bridge reads the Assuan socket files and connects
directly with gpg-agent.exe (except for the ssh-agent socket).

Gpg4win's gpg-agent.exe does not currently support standard ssh-agent (or
rather, the implementation is broken). Therefore, PuTTY Pageant ssh support
must be enabled in gpg-agent.exe. To communicate with the Pagent server,
the Win-bridge uses [net-ssh](https://github.com/net-ssh/net-ssh).

## Security

Since WSL2 has a different IP address than the Windows host, the Windows
firewall must allow incoming connections to the Win-bridge. Specifically it
must allow incoming connections from 172.16.0.0/12 and 192.168.0.0/16 to
TCP ports 6910-6913 (you can select other ports if you want).

To secure connections with the Win-bridge, a simple nonce authentication
scheme similar to Assuan sockets is used. The Win-bridge stores a nonce in
a file that should only be accessible by the user. By default it saves the
file in the GPG home directory in Windows. The WSL-bridge reads the nonce
from the file and sends it to the Win-bridge to authenticate. This ensures
that only processes that can read the nonce file can authenticate.

## Installation

In Windows, install [Ruby](https://rubyinstaller.org/downloads/). Ensure
that both the ruby and gpg executables are in the Path.

Unpack the gpgbridge release in a suitable location in the Windows
filesystem that is reachable from both Windows and WSL.

Install dependencies. From the unpacked gpgbridge folder, run "bundle
install" in Windows and each WSL distribution to install the gems needed in
each environment.

Or, if you prefer to do it manually:

1. In Windows: gem install -N sys-proctable net-ssh
2. In each WSL distribution: gem install -N sys-proctable ptools

Install gpgbridge.rb in a suitable location in the Windows filesystem that
is reachable from both Windows and WSL.

## Usage

In the examples below the release was unpacked in C:\Program1\gpgbridge,
which is /mnt/c/Program1/gpgbridge in WSL.

```
$ ruby /mnt/c/Program1/gpgbridge/gpgbridge.rb --help
Usage: gpgbridge.rb [options]
    -s, --[no-]enable-ssh-support    Enable proxying of gpg-agent SSH sockets
    -d, --[no-]daemon                Run as a daemon in the background
    -r, --remote-address IPADDR      The remote address of the Windows bridge component. Needed for WSL2. [127.0.0.1]
    -p, --port PORT                  The first port (of three or four) to use for proxying sockets
    -n, --noncefile PATH             The nonce file path (defaults to file in Windows gpg homedir)
    -l, --logfile PATH               The log file path
    -i, --pidfile PATH               The PID file path
    -v, --log-level LEVEL            Logging level (DEBUG, INFO, WARN, ERROR, FATAL, UNKNOWN) [WARN]
    -W, --[no-]windows-bridge        Start the Windows bridge (used by the WSL bridge)
    -R, --windows-address IPADDR     The IP address of the Windows bridge. [0.0.0.0]
    -L, --windows-logfile PATH       The log file path of the Windows bridge
    -I, --windows-pidfile PATH       The PID file path of the Windows bridge
    -h, --help                       Prints this help
```

## Example bash helper functions

Copy the script below to somewhere accessible from WSL, make it executable
(`chmod +x path/to/gpgbridge_helper.sh`).

Then add `source path/to/gpgbridge_helper.sh` to your `~/.bash_profile`,
`~/.bashrc` or `~/.zshrc`. If you are running this from WSL 2 you should also
add `WSL2=true` before the `source` line.

Make sure to edit the variables in the start of the script according to your
setup.

```bash
#!/usr/bin/env bash
#--------------------------------------------------------------------------
# GPG bridging from WSL gpg to gpg4win gpg-agent.exe
# (needed to use a Yubikey, since WSL cannot access USB devices)

# Set WSL2=true before running this script if you're running this from WSL2. 
WSL2=${WSL2:-false}

SCRIPT_DIR_WSL='/mnt/c/Program1/gpgbridge'
# shellcheck disable=SC1003
SCRIPT_DIR_WIN='C:\\Program1\\gpgbridge\\'

PIDFILE_WSL="$HOME/.gpgbridge.pid"
LOGFILE_WSL="$HOME/.gpgbridge.log"

PIDFILE_WIN="${SCRIPT_DIR_WIN}gpgbridge.pid"
LOGFILE_WIN="${SCRIPT_DIR_WIN}gpgbridge.log"

SCRIPT_FILE_NAME='gpgbridge.rb'

SCRIPT_PATH_WSL="${SCRIPT_DIR_WSL}${SCRIPT_FILE_NAME}"

# Set to true to redirect output to /dev/null
QUIET=false

function start_gpgbridge
{
    if ! command -v ruby.exe >/dev/null
    then
        echo 'No ruby.exe found in path'
        return
    fi

    local cmd=( \
        'ruby' \
        "$SCRIPT_PATH_WSL" \
        '--daemon' \
        "--pidfile $PIDFILE_WSL" \
        "--logfile $LOGFILE_WSL" \
        "--windows-pidfile $PIDFILE_WIN" \
        "--windows-logfile $LOGFILE_WIN" \
    )

    if [ "$1" = 'ssh' ]
    then
        cmd+=('--enable-ssh-support')
        SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
        export SSH_AUTH_SOCK
    fi

    if [ "$WSL2" = true ]
    then
        cmd+=("--remote-address $(ip route | awk '/^default via / {print $3}')")
    fi

    if [ "$QUIET" = true ]
    then
        cmd+=('>/dev/null 2>&1')
    fi

    printf -v _cmd '%s ' "${cmd[@]}"

    eval "$_cmd"
}

function stop_gpgbridge
{
    pkill -TERM -f 'ruby.*gpgbridge\.rb'
}

function restart_gpgbridge
{
    stop_gpgbridge
    sleep 1
    start_gpgbridge "$@"
}

if [ -f "$SCRIPT_PATH_WSL" ]
then
    start_gpgbridge ssh
fi
```

This will start the WSL-bridge in WSL, which will in turn start the
Win-bridge in Windows. Note that only one WSL-bridge will be started per
WSL distribution, and they will all share the same single Win-bridge
running in Windows.

## Known and handled problems

Net/ssh has a hard-coded timeout of 5s when communicating with Pageant.
This does not work well when gpg-agent.exe is the Pageant server, because
the Pageant client will probably time out while gpg-agent.exe is prompting
for PIN entry. The result is that ssh fails unless you are really fast with
entering the PIN.

This is currently worked around this by overriding a function in net/ssh to
enable setting a custom timeout. The timeout is now 30s. A better future
solution would be for net/ssh to allow setting a custom timeout.

## Tips when using Remote Desktop

If you are using RDP to a remote host, RDP can redirect the local Yubikey
smartcard to the remote host, so that the remote gpg-agent.exe can access
it.

Sometimes the Yubikey smartcard will be blocked on the local host so that
the remote host cannot access it. When that happens you need to restart
some local services to free the Yubikey for use on the remote host.

The [rdp_yubikey.cmd](utils/rdp_yubikey.cmd) batch command automates
stopping and/or restarting local processes. It must be run as
Administrator.

Alternatively, removing and re-inserting the Yubikey while an RDP session
is open seems to let RDP grab the smartcard before local processes.
