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

/// Set up all sandbox restrictions
///
/// This is the main entry point for creating a sandbox. It applies:
/// - Landlock: Read-only filesystem, no network
/// - rlimits: Memory, file size, process count, CPU time limits
/// - seccomp: Block dangerous syscalls (kill, ptrace, setuid, etc.)
///
/// After calling this, the current process (and any children) will be
/// restricted to the sandbox.
pub fn setup_sandbox(verbose: bool) -> Result<()> {
    setup_landlock(verbose).context("Failed to set up Landlock sandbox")?;
    setup_rlimits(verbose).context("Failed to set up rlimits")?;
    setup_seccomp(verbose).context("Failed to set up seccomp filter")?;
    Ok(())
}
