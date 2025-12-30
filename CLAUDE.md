# Claude Code Instructions

## Project Overview
Landlock-sandboxed shell prototype for safe LLM command execution. Includes a Python agent that exposes a generic "Bash" tool to the LLM, routing commands through the sandboxed safe-shell binary.

## Development Environment
- Use Lima VM for testing: `cd vm && ./create.sh`
- Build inside VM: `limactl shell safe-shell-vm` then `cd /workspace/sandbox && cargo build --release`
- Workspace is mounted at `/workspace` in the VM
- API key: Create `/workspace/.env` with `ANTHROPIC_API_KEY=sk-...`

## Key Files

### Rust Sandbox (workspace)
- `sandbox/lib/src/lib.rs` — Public API: `setup_sandbox()` returns `SandboxCapabilities`
- `sandbox/lib/src/landlock_setup.rs` — Landlock LSM filesystem/network/scope restrictions (ABI v6)
- `sandbox/lib/src/seccomp.rs` — seccomp-bpf syscall filtering (conditional signal rules based on ABI)
- `sandbox/lib/src/rlimits.rs` — Resource limits (memory, CPU, processes)
- `sandbox/bin/src/main.rs` — CLI wrapper that calls lib

### Python Agent
- `agent/src/agent.py` — Agent loop with streaming
- `agent/src/tools/bash.py` — "Bash" tool (routes to safe-shell internally)
- `agent/run.sh` — Entry point script

### VM Configuration
- `vm/safe-shell-vm.yaml` — Lima VM configuration (Fedora 42, kernel 6.14+, Landlock ABI v6)
- `vm/safe-shell-vm-abi-v5.yaml` — Fallback VM (Fedora 41, kernel 6.11, for testing ABI v5 behavior)
- `vm/create.sh` — Create and start the VM

## Running the Agent
```bash
limactl shell safe-shell-vm
cd /workspace/agent && ./run.sh
```
