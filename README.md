# GPG Relay

Forward GPG and SSH requests from WSL to [Gpg4win](https://gpg4win.org/) running in Windows.

GPG Relay bridges the gap between WSL and Windows by relaying GPG traffic over TCP and named pipes. It works with different WSL networking modes and supports SSH authentication via PGP keys, making it especially useful when your PGP key is stored on a Yubikey — since WSL cannot share USB access with Windows.

## Implementations

GPG Relay is available in two implementations:

| | [**Go**](gpg_relay_go/) | [**Ruby**](gpg_relay_ruby/) |
|---|---|---|
| **Distribution** | Self-contained executables | Requires Ruby and gems in WSL (and possibly Windows) |
| **Components** | `gpg_relay_wsl` and `gpg_relay_win.exe` | `gpg_relay_wsl.rb` and `gpg_relay_win.rb` |
| **Best for** | Users who want a simple, dependency-free setup | Users who prefer Ruby to easily modify the code |

## Quick start

1. Install [Gpg4win](https://gpg4win.org/) in Windows and enable `enable-ssh-support` and `enable-win32-openssh-support` in `gpg-agent.conf`.
2. Choose an implementation and follow its [Ruby setup instructions](gpg_relay_ruby/README.md) or [Go setup instructions](gpg_relay_go/README.md).
3. Configure your [WSL networking mode](https://learn.microsoft.com/en-us/windows/wsl/wsl-config#main-wsl-settings) in `.wslconfig` (may require a restart of WSL).
4. Start the relay.

## Running under systemd

The [systemd](systemd) folder contains examples of running gpg_relay_wsl under systemd. You will need to update the `ExecStart` command with the command to run.

The [npiperelay](npiperelay) folder contains an example of using `socat` and `npiperelay` to relay ssh requests to the ssh named pipe in Windows.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
