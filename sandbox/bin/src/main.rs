//! safe-shell: A Landlock-sandboxed shell for safe LLM command execution
//!
//! This binary sets up a restrictive sandbox using safe-shell-lib,
//! then executes a command in bash within that sandbox.
//!
//! If no command is provided, starts an interactive sandboxed shell.

use anyhow::Result;
use clap::Parser;
use std::os::unix::process::CommandExt;
use std::process::Command;

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

    if !args.no_sandbox {
        safe_shell_lib::setup_sandbox(args.verbose)?;
    }

    // Execute bash
    // Using exec() replaces this process with bash - sandbox restrictions are inherited
    // --norc skips profile scripts that fail due to Landlock restrictions
    let err = if let Some(cmd) = args.command {
        Command::new("/bin/bash")
            .args(["--norc", "-c", &cmd])
            .exec()
    } else {
        // Interactive mode - bash auto-detects TTY
        Command::new("/bin/bash")
            .arg("--norc")
            .exec()
    };

    // exec() only returns on error
    Err(anyhow::anyhow!("Failed to exec bash: {}", err))
}
