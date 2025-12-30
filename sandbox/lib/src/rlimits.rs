//! Resource limits to prevent abuse

use anyhow::{Context, Result};
use nix::sys::resource::{setrlimit, Resource};

/// Set up resource limits to prevent abuse
pub fn setup_rlimits(verbose: bool) -> Result<()> {
    // AS (Address Space): Limit total virtual memory to prevent memory exhaustion
    // 512MB is generous enough for most shell commands but prevents runaway allocation
    let max_memory = 512 * 1024 * 1024; // 512MB
    setrlimit(Resource::RLIMIT_AS, max_memory, max_memory)
        .context("Failed to set RLIMIT_AS")?;
    if verbose {
        eprintln!("[safe-shell] Set RLIMIT_AS = 512MB (max virtual memory)");
    }

    // FSIZE = 0: Cannot create or extend files
    setrlimit(Resource::RLIMIT_FSIZE, 0, 0).context("Failed to set RLIMIT_FSIZE")?;
    if verbose {
        eprintln!("[safe-shell] Set RLIMIT_FSIZE = 0 (no file creation/extension)");
    }

    // NPROC: Limit number of processes to prevent fork bombs
    let max_procs = 64;
    setrlimit(Resource::RLIMIT_NPROC, max_procs, max_procs)
        .context("Failed to set RLIMIT_NPROC")?;
    if verbose {
        eprintln!(
            "[safe-shell] Set RLIMIT_NPROC = {} (max processes)",
            max_procs
        );
    }

    // CPU: Limit CPU time to prevent runaway processes
    let max_cpu_seconds = 30;
    setrlimit(Resource::RLIMIT_CPU, max_cpu_seconds, max_cpu_seconds)
        .context("Failed to set RLIMIT_CPU")?;
    if verbose {
        eprintln!(
            "[safe-shell] Set RLIMIT_CPU = {}s (max CPU time)",
            max_cpu_seconds
        );
    }

    // NOFILE: Limit open file descriptors to prevent FD exhaustion
    let max_files = 256;
    setrlimit(Resource::RLIMIT_NOFILE, max_files, max_files)
        .context("Failed to set RLIMIT_NOFILE")?;
    if verbose {
        eprintln!(
            "[safe-shell] Set RLIMIT_NOFILE = {} (max open files)",
            max_files
        );
    }

    // CORE = 0: Disable core dumps to prevent information leakage
    setrlimit(Resource::RLIMIT_CORE, 0, 0).context("Failed to set RLIMIT_CORE")?;
    if verbose {
        eprintln!("[safe-shell] Set RLIMIT_CORE = 0 (no core dumps)");
    }

    Ok(())
}
