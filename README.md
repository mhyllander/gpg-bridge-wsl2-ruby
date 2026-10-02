# GPG Relay

Forward GPG and SSH requests from WSL to [Gpg4win](https://gpg4win.org/) running in Windows.

GPG Relay bridges the gap between WSL and Windows by relaying GPG traffic over TCP and named pipes. It works with different WSL networking modes and supports SSH authentication via PGP keys, making it especially useful when your PGP key is stored on a Yubikey — since WSL cannot share USB access with Windows.

## Implementations

GPG Relay is available in two implementations:

| | [**Go**](gpg_relay_go/) | [**Ruby**](gpg_relay_ruby/) |
|---|---|---|
| **Distribution** | Self-contained executables | Requires Ruby and gems in WSL (and possibly Windows) |
| **Components** | `gpg_relay_wsl` and `gpg_relay_win.exe` | `gpg_relay_wsl.rb` and `gpg_relay_win.rb` |
| **Best for** | Users who want a simple, dependency-free setup | Users who prefer Ruby for ease of updating |

## Quick start

1. Install [Gpg4win](https://gpg4win.org/) in Windows and enable `enable-ssh-support` and `enable-win32-openssh-support` in `gpg-agent.conf`.
2. Choose an implementation and follow its [Ruby setup instructions](gpg_relay_ruby/README.md) or [Go setup instructions](gpg_relay_go/README.md).
3. Configure your [WSL networking mode](https://learn.microsoft.com/en-us/windows/wsl/wsl-config#main-wsl-settings) in `.wslconfig` (may require a restart of WSL).
4. Start the relay.

## Relaying using only npiperelay

It's possible to use only `npiperelay` to relay GPG and SSH requests to gpg-agent.exe.
An example of this is in the [npiperelay](npiperelay) folder, where `socat` and `npiperelay` are used
to relay ssh requests to the ssh named pipe in Windows.

While this works, this approach might have problems if you start multiple SSH clients simultaneously,
since one `npiperelay` process is started per SSH connection. See the [notes on gpg-agent.exe](gpg_relay_go/README.md#a-note-about-gpg-agentexe-and-its-support-for-ssh)
for more about the SSH support.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
