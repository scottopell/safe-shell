# Claude Code Instructions

## Project Overview
Landlock-sandboxed shell prototype for safe LLM command execution.

## Development Environment
- Use Lima VM for testing: `cd vm && ./create.sh`
- Build inside VM: `limactl shell safe-shell-vm` then `cd /workspace/sandbox && cargo build`
- Workspace is mounted at `/workspace` in the VM

## Key Files
- `sandbox/src/main.rs` — Main sandbox implementation (Landlock + seccomp + rlimits)
- `vm/safe-shell-vm.yaml` — Lima VM configuration (Fedora 41)
