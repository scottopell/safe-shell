//! safe-shell-lib: Security primitives for sandboxed command execution
//!
//! This library provides Landlock, seccomp, and rlimit setup functions
//! for creating a restrictive sandbox environment.

use anyhow::{Context, Result};

mod landlock_setup;
mod rlimits;
mod seccomp;

pub use landlock_setup::setup_landlock;
pub use rlimits::setup_rlimits;
pub use seccomp::setup_seccomp;

/// Tracks which sandbox features were successfully enabled
///
/// This struct communicates what security features are active between
/// sandbox setup modules. For example, if Landlock's signal scoping is
/// enabled (kernel 6.12+), seccomp doesn't need its PID-based workaround.
#[derive(Debug, Default)]
pub struct SandboxCapabilities {
    /// Landlock filesystem/network restrictions are active
    pub landlock_enabled: bool,
    /// Landlock Scope::Signal is active (kernel 6.12+, ABI v6)
    pub signal_scoping_enabled: bool,
    /// Landlock Scope::AbstractUnixSocket is active (kernel 6.12+, ABI v6)
    pub socket_scoping_enabled: bool,
}

/// Set up all sandbox restrictions
///
/// This is the main entry point for creating a sandbox. It applies:
/// - Landlock: Read-only filesystem, no network, signal/socket scoping (if kernel supports)
/// - rlimits: Memory, file size, process count, CPU time limits
/// - seccomp: Block dangerous syscalls; signal filtering only if Landlock scopes unavailable
///
/// After calling this, the current process (and any children) will be
/// restricted to the sandbox.
///
/// Returns `SandboxCapabilities` indicating which features were enabled.
pub fn setup_sandbox(verbose: bool) -> Result<SandboxCapabilities> {
    let caps = setup_landlock(verbose).context("Failed to set up Landlock sandbox")?;
    setup_rlimits(verbose).context("Failed to set up rlimits")?;
    setup_seccomp(verbose, &caps).context("Failed to set up seccomp filter")?;
    Ok(caps)
}
