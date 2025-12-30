//! safe-shell: A Landlock-sandboxed shell for safe LLM command execution
//!
//! This binary sets up a restrictive sandbox using safe-shell-lib,
//! then executes a command in bash within that sandbox.
//!
//! Process isolation: We create a new process group and kill all processes
//! in the group when the main command exits. This prevents fork bombs and
//! backgrounded processes from escaping the sandbox.

use anyhow::{Context, Result};
use clap::Parser;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, setpgid, ForkResult, Pid};
use std::os::unix::process::CommandExt;
use std::process::{exit, Command};

/// Landlock-sandboxed shell for safe command execution
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Command to execute (passed to bash -c). If omitted, starts interactive shell.
    command: Option<String>,

    /// Skip sandbox setup (for testing/comparison)
    #[arg(long, default_value_t = false)]
    no_sandbox: bool,

    /// Verbose output showing sandbox setup
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verbose {
        if let Some(ref cmd) = args.command {
            eprintln!("[safe-shell] Command: {}", cmd);
        } else {
            eprintln!("[safe-shell] Mode: interactive");
        }
        eprintln!("[safe-shell] Sandbox enabled: {}", !args.no_sandbox);
    }

    // Fork to create a child process that we can manage
    // The child will exec bash, the parent will wait and cleanup
    match unsafe { fork() }.context("Failed to fork")? {
        ForkResult::Child => {
            // Child process: set up sandbox and exec bash
            run_child(&args)
        }
        ForkResult::Parent { child } => {
            // Parent process: wait for child and cleanup process group
            run_parent(child, args.verbose)
        }
    }
}

/// Child process: create process group, setup sandbox, exec bash
fn run_child(args: &Args) -> Result<()> {
    // Create a new process group with this process as the leader
    // This allows the parent to kill all descendants with kill(-pgid, sig)
    setpgid(Pid::from_raw(0), Pid::from_raw(0))
        .context("Failed to create new process group")?;

    // Set up the sandbox (Landlock, seccomp, rlimits)
    if !args.no_sandbox {
        safe_shell_lib::setup_sandbox(args.verbose)?;
    }

    // Execute bash
    // Using exec() replaces this process with bash - sandbox restrictions are inherited
    // --norc skips profile scripts that fail due to Landlock restrictions
    let err = if let Some(ref cmd) = args.command {
        Command::new("/bin/bash")
            .args(["--norc", "-c", cmd])
            .exec()
    } else {
        // Interactive mode - bash auto-detects TTY
        Command::new("/bin/bash").arg("--norc").exec()
    };

    // exec() only returns on error
    Err(anyhow::anyhow!("Failed to exec bash: {}", err))
}

/// Parent process: wait for child to exit, then kill entire process group
fn run_parent(child: Pid, verbose: bool) -> Result<()> {
    // Wait for the child (bash) to exit
    let status = waitpid(child, None).context("Failed to wait for child")?;

    // Kill the entire process group to clean up any backgrounded processes
    // or fork bomb remnants. Use SIGKILL to ensure they can't ignore it.
    // The negative PID means "kill process group with PGID = |pid|"
    if let Err(e) = kill(Pid::from_raw(-child.as_raw()), Signal::SIGKILL) {
        // ESRCH (no such process) is fine - means all processes already exited
        if e != nix::errno::Errno::ESRCH {
            if verbose {
                eprintln!("[safe-shell] Warning: failed to kill process group: {}", e);
            }
        }
    } else if verbose {
        eprintln!("[safe-shell] Killed process group {}", child);
    }

    // Exit with the same code as the child
    let exit_code = match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
        _ => 1,
    };

    exit(exit_code);
}
