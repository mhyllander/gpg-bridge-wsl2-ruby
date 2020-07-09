# GPG Bridge for WSL1 and WSL2, written in Ruby

This is a tool inspired by
[wsl-gpg-bridge](https://github.com/Riebart/wsl-gpg-bridge), which I used
in WSL1 with much satisfaction, together with
[Gpg4win](https://gpg4win.org/) and a Yubikey. I use the PGP key on the
Yubikey for ssh. Gpg4win's gpg-agent.exe is configured with enabled PuTTY
support (Pageant).

When I switched to WSL2, I found that wsl-gpg-bridge did not work anymore.
The main problem is that the wsl-gpg-bridge runs in WSL but can no longer
connect with gpg-agent.exe in Windows, because that only binds to
127.0.0.1.

After looking at the code, I decided I would try to write a similar GPG
bridge in Ruby. To solve the access problem, the bridge is actually two
bridges:

gpg/ssh -> Unix socket -> WSL-bridge -> Win-bridge -> (Assuan socket) -> gpg-agent.exe

Since Windows does not support Unix sockets, gpg-agent.exe uses something
called an Assuan socket. This is a file that contains the TCP port that
gpg-agent is listening on, and a nonce that must be sent after connecting
to authenticate. The Win-bridge reads the Assuan socket files and connects
directly with gpg-agent.exe (except for the socket for ssh).

To support ssh Pagent, the Win-bridge uses
[net-ssh](https://github.com/net-ssh/net-ssh) to talk directly with the
gpg-agent.exe Pageant socket.

## Security

Since WSL2 has a different IP address than the Windows host, the Windows
firewall must allow incoming connections to the Win-bridge. Specifically it
must allow incoming connections from 172.16.0.0/12 and 192.168.0.0/16 to
TCP ports 6910-6913.

To secure connections to the Win-bridge, a simple nonce authentication
scheme similar to Assuan sockets is used. The Win-bridge stores a nonce in
a file that should only be accessible by the user. By default it saves the
file in the GPG home directory in Windows. The WSL-bridge reads the nonce
from the file and sends it to the Win-bridge to authenticate. This ensures
that only processes that can read the nonce file can authenticate.

## Dependencies

In Windows, install [Ruby](https://rubyinstaller.org/downloads/). Ensure
that both the ruby and gpg executables are in the Path.

In both Windows and WSL, you must install a few gems:

1. In Windows: gem install -N net-ssh sys-proctable
2. In WSL: gem install -N ptools sys-proctable

## Usage:

Install gpgbridge.rb in a suitable location in the Windows filesystem that
is reachable from both Windows and WSL.

```bash
$ ruby /mnt/c/Program1/gpgbridge.rb --help
Usage: gpgbridge.rb [options]
    -s, --[no-]enable-ssh-support    Enable proxying of gpg-agent SSH sockets
    -d, --[no-]daemon                Run as a daemon in the background
    -r, --remote-address IPADDR      The remote address of the Windows bridge component. Needed for WSL2. [127.0.0.1]
    -p, --port PORT                  The first port (of three or four) to use for proxying sockets
    -n, --noncefile PATH             The nonce file path (defaults to file in Windows gpg homedir)
    -l, --logfile PATH               The log file path
    -i, --pidfile PATH               The PID file path
    -v, --[no-]verbose               Verbose logging
    -W, --[no-]windows-bridge        Start the Windows bridge (used by the WSL bridge)
    -R, --windows-address IPADDR     The IP address of the Windows bridge. [0.0.0.0]
    -L, --windows-logfile PATH       The log file path of the Windows bridge
    -I, --windows-pidfile PATH       The PID file path of the Windows bridge
    -h, --help                       Prints this help
```

## Example

I have the following in my `~/.bash_profile` in WSL:

```bash
#--------------------------------------------------------------------------
# GPG bridging from WSL gpg to gpg4win gpg-agent.exe
# (needed to use a Yubikey, since WSL cannot access USB devices)

if [[ -f /mnt/c/Program1/gpgbridge.rb ]]
then
    # gpgbridge.rb replaces the separate solutions provided by npiperelay,
    # weasel_pageant and wsl-gpg-bridge. It can also forward ssh-agent requests
    # to gpg-agent, when using PGP keys for ssh authentication. It will also
    # work with WSL2.

    # Install gpgbridge.rb in a location reachable by Windows.
    # Install Ruby for Windows. https://rubyinstaller.org/downloads/
    #  Ensure that the GPG and Ruby executables are in the PATH.
    # In WSL, run "sudo gem install -N sys-proctable ptools".
    # In Windows, start a Ruby command windows, run "gem install -N sys-proctable net-ssh".
    function start_gpgbridge
    {
	local opts=''
	if ! command -v ruby.exe >/dev/null
	then
	    echo 'No ruby.exe found in path'
	    return
	fi
	# Uncomment the following line for WSL2 to set the remote address
	#opts="--remote-address $(ip route | awk '/^default via / {print $3}')"
	if [[ $1 == ssh ]]; then
	    opts="$opts --enable-ssh-support"
	    export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
	fi
	ruby /mnt/c/Program1/gpgbridge.rb --daemon --pidfile ~/.gpgbridge.pid --logfile ~/.gpgbridge.log --verbose --windows-logfile 'C:\Program1\gpgbridge.log' --windows-pidfile 'C:\Program1\gpgbridge.pid' $opts
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
    start_gpgbridge ssh
fi
```

This will start the WSL-bridge in WSL, which will in turn start the
Win-bridge in Windows. Note that only one WSL-bridge will be started per
WSL distribution, and they will all share the same single Win-bridge
running in Windows.

## Known problems

The first time you use ssh, gpg-agent.exe will prompt you for the PIN
entry. The ssh command will either timeout and fail, or fail after you
entered the PIN. The timeout is hard-coded in net-ssh.

Either way, if you try the ssh command again it will now work, since
gpg-agent.exe has cached the PIN for future use.

## Remote Desktop

When you are using RDP to a remote host, RDP can redirect the local Yubikey
smartcard to the remote host, where the remote gpg-agent.exe can access it.

Sometimes the Yubikey smart card will be blocked on the local host so that
the remote host cannot access it. When that happens you need to restart
some local services to free the Yubikey for use on the remote host.

I have a Windows batch script that I run as Administrator to handle that
situation. See [rdp_yubikey.cmd](rdp_yubikey.cmd).
