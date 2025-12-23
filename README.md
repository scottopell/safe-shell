# safe-shell: Landlock-Sandboxed Shell for LLM Agents

A prototype for giving LLM agents access to a real POSIX shell while preventing any mutations to the host system. The sandbox allows read-only system inspection (`ps`, `cat /proc/*`, `df`, etc.) while blocking file writes, network connections, and dangerous syscalls.

## Why?

LLMs already understand POSIX tools. Wrapping primitives in custom tool APIs means the LLM must re-learn what it already knows, and we lose composability (pipes, redirection, etc.). A real shell is more powerful—but we need to make it safe.

Previous approaches like `rbash` (restricted bash) fail because they're blocklists—you're forever chasing binaries that might mutate state (even `awk` can write files).

## Approach: Defense in Depth

This sandbox uses multiple Linux security mechanisms in an **allowlist** model:

### 1. Landlock LSM (Linux 5.13+)
- **Filesystem**: Read-only access to `/`, `/proc`, `/sys`, etc. Write access only to `/dev` (for PTY)
- **Network**: TCP connect/bind blocked (ABI v3+)

### 2. seccomp-bpf
Blocks dangerous syscalls:
- `kill`, `tkill`, `tgkill` — can't signal other processes
- `ptrace` — can't debug/inject into processes
- `setuid`, `setgid`, etc. — can't escalate privileges
- `mount`, `umount2`, `pivot_root` — can't modify mounts
- `reboot`, `sethostname` — can't affect system state
- `init_module`, `finit_module` — can't load kernel modules
- `socket(SOCK_DGRAM)` — blocks UDP (until Landlock crate supports it)

### 3. rlimits
- `RLIMIT_AS = 512MB` — max virtual memory (prevents OOM attacks)
- `RLIMIT_FSIZE = 0` — can't create/extend files
- `RLIMIT_NPROC = 64` — limits processes (fork bomb protection)
- `RLIMIT_CPU = 30s` — limits CPU time (runaway process protection)

## Security Status

| Category | Protection | Mechanism |
|----------|------------|-----------|
| File reads | ✅ Allowed | Landlock (allowlist) |
| File writes | ❌ Blocked | Landlock + RLIMIT_FSIZE |
| TCP network | ❌ Blocked | Landlock |
| UDP network | ❌ Blocked | seccomp |
| kill/ptrace | ❌ Blocked | seccomp |
| Privilege escalation | ❌ Blocked | seccomp |
| Memory exhaustion | ❌ Blocked | RLIMIT_AS |
| Fork bombs | ❌ Blocked | RLIMIT_NPROC |
| CPU exhaustion | ❌ Blocked | RLIMIT_CPU |

## Project Structure

```
.
├── vm/
│   ├── safe-shell-vm.yaml   # Lima VM config (Fedora 41, kernel 6.11+)
│   ├── create.sh            # Create and start the VM
│   └── destroy.sh           # Tear down the VM
└── sandbox/
    ├── Cargo.toml           # Rust dependencies
    └── src/
        └── main.rs          # Sandbox implementation
```

## Quick Start

### Prerequisites
- macOS with [Lima](https://lima-vm.io/) installed (`brew install lima`)
- Or a Linux machine with kernel 6.2+ (for Landlock network support)

### Setup (macOS with Lima)

```bash
# Create the development VM
cd vm && ./create.sh

# Enter the VM
limactl shell safe-shell-vm

# Build the sandbox
cd /workspace/sandbox
cargo build --release

# Test it
./target/release/safe-shell "ps aux"           # works
./target/release/safe-shell "cat /etc/passwd"  # works
./target/release/safe-shell "touch /tmp/test"  # blocked
./target/release/safe-shell "curl example.com" # blocked
```

### Usage

```bash
# Basic usage
safe-shell "command to run"

# Verbose mode (shows sandbox setup)
safe-shell -v "command"

# Skip sandbox (for testing/comparison)
safe-shell --no-sandbox "command"
```

## Testing the Sandbox

```bash
# Should WORK (read operations)
safe-shell "ps aux"
safe-shell "cat /proc/meminfo"
safe-shell "df -h"
safe-shell "ls -la /"

# Should FAIL (write operations)
safe-shell "touch /tmp/test"        # Permission denied (Landlock)
safe-shell "echo hi > /tmp/x"       # Permission denied (Landlock)
safe-shell "rm /etc/passwd"         # Permission denied (Landlock)

# Should FAIL (network)
safe-shell "curl http://example.com"  # Permission denied (Landlock)

# Should FAIL (dangerous syscalls)
safe-shell "strace ls"              # PTRACE blocked (seccomp)
# kill is blocked (seccomp)

# Should FAIL (resource exhaustion)
safe-shell "python3 -c 'x=bytearray(600*1024*1024)'"  # MemoryError (rlimit)
```

## Known Limitations

1. **DNS resolution works** — Goes through systemd-resolved (local Unix socket), not direct UDP. Full DNS blocking would require network namespaces.

2. **Landlock UDP support** — The `landlock` crate (0.4.4) only exposes TCP. UDP blocking is done via seccomp as a workaround until the crate supports `AccessNet::BindUdp/ConnectUdp`.

3. **RLIMIT_AS counts virtual memory** — Sparse allocations count fully even if pages aren't touched. 512MB is generous for shell commands.

4. **Some paths may be missing** — The Landlock allowlist may need tuning for specific tools that access unusual paths.

## Future Work

- [ ] Integration with LLM API (forward commands from agent to sandbox)
- [ ] Session support (persistent shell with state)
- [ ] Output streaming
- [ ] Timeout handling at the API level
- [ ] Audit logging of all commands
- [ ] Network namespace for complete network isolation
- [ ] Update to Landlock crate with UDP support when available

## Requirements

- Linux kernel 6.2+ (for Landlock ABI v3 network support)
- Rust 1.70+
- libseccomp-devel (for seccomp bindings)

## License

MIT
