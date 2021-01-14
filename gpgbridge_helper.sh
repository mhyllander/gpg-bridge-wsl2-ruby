#!/bin/sh
#--------------------------------------------------------------------------
# GPG bridging from WSL gpg to gpg4win gpg-agent.exe
# (needed to use a Yubikey, since WSL cannot access USB devices)
#
# 1. Edit the PATHS section below (or set the variables before sourcing this file.)
# 2. Source this file
# 3. Call "start_gpgbridge [ --ssh ] [ --wsl2 ]".

# PATHS
SCRIPT_DIR_WSL="${SCRIPT_DIR_WSL:-/mnt/c/Program1/gpgbridge}"

PIDFILE_WSL="${PIDFILE_WSL:-$HOME/.gpgbridge_wsl.pid}"
LOGFILE_WSL="${LOGFILE_WSL:-$HOME/.gpgbridge_wsl.log}"

PIDFILE_WIN="${PIDFILE_WIN:-$SCRIPT_DIR_WSL/gpgbridge_win.pid}"
LOGFILE_WIN="${LOGFILE_WIN:-$SCRIPT_DIR_WSL/gpgbridge_win.log}"

#---------------------------------------------------------------------------
# Do not edit below this line

touch "$PIDFILE_WIN" "$LOGFILE_WIN"  # Needs to be created otherwise wslpath complains
PIDFILE_WIN="$(wslpath -wa "$PIDFILE_WIN")"
LOGFILE_WIN="$(wslpath -wa "$LOGFILE_WIN")"

start_gpgbridge()
{
    if ! command -v ruby.exe >/dev/null
    then
	echo 'No ruby.exe found in path'
	return 1
    fi

    # Parse arguments
    #local _opts _parsed_args _is_args_valid
    _parsed_args=$(getopt -a -n start_gpgbridge -o h --long ssh,wsl2,help -- "$@")
    _is_args_valid=$?

    if [ ! $_is_args_valid ] ; then
	echo "Usage: start_gpgbridge [ --ssh ] [ --wsl2 ]"
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
	    --wsl2)
		_opts="$_opts --remote-address $(ip route | awk '/^default via / {print $3}')"
		shift
		;;
	    --)
		shift
		break
	esac
    done

    # Only applies to ZSH and command not found in (ba)sh
    setopt shwordsplit 2>/dev/null ||

    ruby "$SCRIPT_DIR_WSL/gpgbridge.rb" --daemon --pidfile "$PIDFILE_WSL" --logfile "$LOGFILE_WSL" --windows-pidfile "$PIDFILE_WIN" --windows-logfile "$LOGFILE_WIN" ${_opts}

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
