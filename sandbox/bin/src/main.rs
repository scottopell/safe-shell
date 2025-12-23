//! safe-shell: A Landlock-sandboxed shell for safe LLM command execution
//!
//! This binary sets up a restrictive sandbox using safe-shell-lib,
//! then executes a command in bash within that sandbox.

use anyhow::Result;
use clap::Parser;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Landlock-sandboxed shell for safe command execution
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Command to execute (passed to bash -c)
    #[arg(required = true)]
    command: String,

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
        eprintln!("[safe-shell] Command: {}", args.command);
        eprintln!("[safe-shell] Sandbox enabled: {}", !args.no_sandbox);
    }

    if !args.no_sandbox {
        safe_shell_lib::setup_sandbox(args.verbose)?;
    }

    // Execute the command via bash
    // Using exec() replaces this process with bash - sandbox restrictions are inherited
    // --norc skips profile scripts that fail due to Landlock restrictions
    let err = Command::new("/bin/bash")
        .args(["--norc", "-c", &args.command])
        .exec();

    // exec() only returns on error
    Err(anyhow::anyhow!("Failed to exec bash: {}", err))
}
