#--------------------------------------------------------------------------
# GPG bridging from WSL gpg to gpg4win gpg-agent.exe
# (needed to use a Yubikey, since WSL cannot access USB devices)
#
# Manual start (legacy):
# 1. Edit the PATHS section below (or set the variables before sourcing this file.)
# 2. Source this file
# 3. Call "start_gpgbridge [ --ssh ] [ --wsl2 | --wsl2-mirrored | --wsl2-nat ]".
#
# Systemd socket activation (recommended, user-level):
# 1. Copy the systemd unit files to ~/.config/systemd/user/
#    mkdir -p ~/.config/systemd/user
#    cp systemd/*.socket systemd/*.service ~/.config/systemd/user/
# 2. Reload systemd user daemon
#    systemctl --user daemon-reload
# 3. Enable and start the service
#    systemctl --user enable --now gpg-bridge-wsl.service
#
# The systemd service uses socket activation and receives listen file descriptors
# from systemd. It no longer creates sockets itself. This provides better startup
# ordering and resource management.

# PATHS
SCRIPT_DIR_WSL="${SCRIPT_DIR_WSL:-/mnt/c/Program1/gpgbridge}"

PIDFILE_WSL="${PIDFILE_WSL:-$HOME/.gpgbridge_wsl.pid}"
LOGFILE_WSL="${LOGFILE_WSL:-$HOME/.gpgbridge_wsl.log}"

PIDFILE_WIN="${PIDFILE_WIN:-$SCRIPT_DIR_WSL/gpgbridge_win.pid}"
LOGFILE_WIN="${LOGFILE_WIN:-$SCRIPT_DIR_WSL/gpgbridge_win.log}"

#---------------------------------------------------------------------------
# Do not edit below this line

start_gpgbridge()
{
    if ! command -v ruby.exe >/dev/null
    then
	echo 'No ruby.exe found in path'
	return 1
    fi

    # Parse arguments
    #local _opts _parsed_args _is_args_valid
    _parsed_args=$(getopt -a -n start_gpgbridge -o h --long ssh,wsl1,wsl2-nat,wsl2-mirrored,help -- "$@")
    _is_args_valid=$?

    if [ ! $_is_args_valid ] ; then
	echo "Usage: start_gpgbridge [ --ssh ] [ --wsl1 | --wsl2-nat | --wsl2-mirrored ]"
	unset _parsed_args _is_args_valid
	exit 1
    fi

    _opts=''
    eval set -- "$_parsed_args"
    while :
    do
        case "$1" in
            --ssh)
            _opts="$_opts --enable-ssh-support"
            SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
            export SSH_AUTH_SOCK
            shift
            ;;
            --wsl1)
            _opts="$_opts --wsl-mode=wsl1"
            shift
            ;;
            --wsl2-nat)
            _opts="$_opts --wsl-mode=wsl2_nat"
            shift
            ;;
            --wsl2-mirrored)
            _opts="$_opts --wsl-mode=wsl2_mirrored"
            shift
            ;;
            --)
            shift
            break
        esac
    done

    # Only applies to ZSH and command not found in (ba)sh
    setopt shwordsplit 2>/dev/null ||

    touch "$PIDFILE_WIN" "$LOGFILE_WIN"  # Needs to exist otherwise wslpath complains
    ruby "$SCRIPT_DIR_WSL/gpgbridge.rb" --daemon --pidfile "$PIDFILE_WSL" --logfile "$LOGFILE_WSL" --windows-pidfile "$(wslpath -wa "$PIDFILE_WIN")" --windows-logfile "$(wslpath -wa "$LOGFILE_WIN")" ${_opts}

    unsetopt shwordsplit 2>/dev/null ||

    unset _parsed_args _is_args_valid _opts
}

stop_gpgbridge()
{
    # Kill gpgbridge if running, else return
    pkill -TERM -f 'ruby.*gpgbridge\.rb' || return 0
}

restart_gpgbridge()
{
    stop_gpgbridge
    sleep 1
    start_gpgbridge "$@"
}
