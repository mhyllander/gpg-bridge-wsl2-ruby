---
name: npiperelay
description: "Use when: calling npiperelay to relay named pipes between Windows and WSL2, configuring SSH agent proxying, or debugging pipe relay issues. Covers CLI flags from albertony/npiperelay, and integration patterns."
---

# npiperelay Skill

## Purpose

npiperelay relays Windows named pipes between Windows and WSL2, enabling SSH agent and GPG agent access across the boundary.

This skill covers the [albertony/npiperelay](https://github.com/albertony/npiperelay) fork, which adds Assuan socket support on top of the upstream [jstarks/npiperelay](https://github.com/jstarks/npiperelay).

## CLI Flags (from albertony/npiperelay source code)

### Named Pipe Flags (only for `//./pipe/...` targets)

| Flag | Description |
|------|-------------|
| `-p` | Poll every 200ms until the named pipe exists and is not busy |
| `-l` | When polling, fail after 300 attempts (do not poll indefinitely) |
| `-s` | Send a 0-byte message to the pipe after EOF on stdin |

### Assuan Socket Flag (only for `-a` targets)

| Flag | Description |
|------|-------------|
| `-a` | Treat the target as an Assuan file socket (for WinGnuPG/libassuan sockets) |

### Common (apply to both Named Pipe and Assuan targets)

| Flag | Description |
|------|-------------|
| `-ep` | Terminate on EOF reading from the pipe, even if there is more data to write |
| `-ei` | Terminate on EOF reading from stdin, even if there is more data to write |
| `-bg` | Hide console window and run in background |

### Other

| Flag | Description |
|------|-------------|
| `-v` | Verbose output on stderr |

**Positional argument**: The named pipe path (e.g. `//./pipe/openssh-ssh-agent`) or Assuan socket path.

### Flag Scope

- `-p`, `-l`, `-s` — only apply to **Windows Named Pipe** targets
- `-a` — only applies to **Assuan file socket** targets
- `-ep`, `-ei`, `-bg` — apply to **both** Named Pipe and Assuan targets
- `-ei` take precedence over `-s`: if `-ei` is specified, `-s` has no effect (npiperelay exits on stdin EOF instead of sending the 0-byte close message)

## Common Patterns

### SSH Agent Relay (Named Pipe)

```bash
npiperelay -p -l -s -ep //./pipe/openssh-ssh-agent
```

All flags are **Named Pipe** flags:

| Flag | Purpose |
|------|---------|
| `-p` | Poll if pipe is busy (pipe may be temporarily locked) |
| `-l` | Limit polling to 300 attempts (~60 seconds) |
| `-s` | Send 0-byte message after stdin EOF (notifies Windows side of close) |
| `-ep` | Exit when pipe reaches EOF (notifies WSL side of close) |

> **Note**: `-ei` can be used instead of `-s`. If both are specified, `-ei` takes precedence and `-s` is ignored.

### GPG Assuan Socket Relay (Assuan)

```bash
npiperelay -a -ei -ep /path/to/agent-socket
```

| Flag | Purpose |
|------|---------|
| `-a` | Target is a Gpg4win Assuan file socket (reads port + nonce, connects to TCP) |
| `-ei` | Exit when stdin reaches EOF |
| `-ep` | Exit when pipe reaches EOF (notifies WSL side of close) |

When `-a` is used, npiperelay reads the Assuan socket file (which contains a TCP port number, a newline, and a 16-byte nonce), connects to that TCP port on localhost, sends the nonce for authentication, then relays bidirectionally.

## Troubleshooting

1. **Pipe not found**: Verify the named pipe exists in Windows (`\\.\\pipe\\openssh-ssh-agent`)
2. **Connection refused / pipe busy**: Use `-p -l` flags to poll until the pipe is available
3. **Permission denied**: Ensure the WSL user has access to the named pipe
4. **Nonce mismatch**: With `-a` flag, the Assuan socket file must contain the correct port and 16-byte nonce
5. **Console window pops up**: Use `-bg` to hide the Windows console window
