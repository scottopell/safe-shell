//! safe-shell: A Landlock-sandboxed shell for safe LLM command execution
//!
//! This binary sets up a restrictive sandbox using:
//! - Landlock: Read-only filesystem access, no network
//! - seccomp-bpf: Block dangerous syscalls (kill, ptrace, etc.)
//! - rlimits: Prevent resource abuse
//!
//! Then executes a command in bash within that sandbox.

use anyhow::{Context, Result};
use clap::Parser;
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, ABI,
};
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Landlock-sandboxed shell for safe command execution
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Command to execute (passed to bash -c)
    #[arg(required = true)]
    command: String,

    /// Skip Landlock setup (for testing/comparison)
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
        setup_landlock(args.verbose).context("Failed to set up Landlock sandbox")?;
        setup_rlimits(args.verbose).context("Failed to set up rlimits")?;
        setup_seccomp(args.verbose).context("Failed to set up seccomp filter")?;
    }

    // Execute the command via bash
    // Using exec() replaces this process with bash - sandbox restrictions are inherited
    let err = Command::new("/bin/bash")
        .args(["-c", &args.command])
        .exec();

    // exec() only returns on error
    Err(anyhow::anyhow!("Failed to exec bash: {}", err))
}

/// Set up Landlock filesystem restrictions
///
/// Landlock uses an allowlist model:
/// 1. Declare which access types we're restricting (handle_access)
/// 2. Create the ruleset
/// 3. Add rules for what IS allowed
/// 4. Restrict self - everything not allowed is denied
fn setup_landlock(verbose: bool) -> Result<()> {
    // Target the latest ABI - the library will gracefully degrade
    let abi = ABI::V5;

    if verbose {
        eprintln!("[safe-shell] Setting up Landlock with target ABI: {:?}", abi);
    }

    // Access rights we allow for read-only paths
    let read_only_access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;

    // Access rights for /dev (need read/write for PTY interaction)
    let dev_access = read_only_access | AccessFs::WriteFile;

    // Get all access types supported by this ABI - we'll handle (restrict) all of them
    let all_fs_access = AccessFs::from_all(abi);
    let all_net_access = AccessNet::from_all(abi);

    // Create the ruleset - we're handling all filesystem and network access types
    // By handling network access but not adding any rules, all network is blocked
    let mut ruleset = Ruleset::default()
        .handle_access(all_fs_access)
        .context("Failed to configure Landlock filesystem access handling")?
        .handle_access(all_net_access)
        .context("Failed to configure Landlock network access handling")?
        .create()
        .context("Failed to create Landlock ruleset")?;

    // Paths to allow read-only access
    let read_only_paths: &[&str] = &[
        "/bin", "/usr/bin", "/sbin", "/usr/sbin", // Executables
        "/lib", "/lib64", "/usr/lib", "/usr/lib64", // Libraries
        "/etc",       // Configuration (read-only)
        "/proc",      // Process info (ps, top, etc.)
        "/sys",       // System info
        "/run",       // Runtime data (read-only)
        "/var",       // Variable data (read-only for logs, etc.)
        "/home",      // Home directories (read-only)
        "/root",      // Root home (read-only)
        "/tmp",       // Temp (read-only - we don't allow writes)
        "/opt",       // Optional packages
    ];

    // Add read-only rules using the helper
    let ro_rules = path_beneath_rules(read_only_paths, read_only_access);
    ruleset = ruleset
        .add_rules(ro_rules)
        .context("Failed to add read-only path rules")?;

    if verbose {
        eprintln!(
            "[safe-shell] Added read-only access to: {}",
            read_only_paths.join(", ")
        );
    }

    // Add /dev with read/write for PTY access
    let dev_rules = path_beneath_rules(&["/dev"], dev_access);
    ruleset = ruleset
        .add_rules(dev_rules)
        .context("Failed to add /dev rules")?;

    if verbose {
        eprintln!("[safe-shell] Added read/write access to: /dev (for PTY)");
        eprintln!("[safe-shell] Network access: BLOCKED (no rules added)");
    }

    // Enforce the ruleset
    let status = ruleset
        .restrict_self()
        .context("Failed to restrict process with Landlock")?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            if verbose {
                eprintln!("[safe-shell] Landlock fully enforced");
            }
        }
        RulesetStatus::PartiallyEnforced => {
            eprintln!("[safe-shell] Warning: Landlock only partially enforced");
        }
        RulesetStatus::NotEnforced => {
            anyhow::bail!("Landlock not enforced - kernel may not support Landlock");
        }
    }

    Ok(())
}

/// Set up resource limits to prevent abuse
fn setup_rlimits(verbose: bool) -> Result<()> {
    use nix::sys::resource::{setrlimit, Resource};

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

    Ok(())
}

/// Set up seccomp-bpf syscall filtering
///
/// We use a default-allow policy and block specific dangerous syscalls.
/// This is less secure than a default-deny allowlist, but much more practical
/// for running arbitrary shell commands.
fn setup_seccomp(verbose: bool) -> Result<()> {
    use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

    // Create a filter with default action: ALLOW
    // We'll explicitly block dangerous syscalls
    let mut filter =
        ScmpFilterContext::new_filter(ScmpAction::Allow).context("Failed to create seccomp filter")?;

    // Block UDP sockets: socket(domain, type, protocol) where type contains SOCK_DGRAM
    // SOCK_DGRAM = 2, but type can have flags OR'd in (SOCK_NONBLOCK, SOCK_CLOEXEC)
    // So we use a mask to check only the socket type bits (lower 4 bits)
    //
    // NOTE: The landlock crate 0.4.4 only supports TCP (BindTcp, ConnectTcp).
    // UDP support exists in kernel Landlock ABI v4 but isn't exposed by the crate yet.
    // Once the crate adds AccessNet::BindUdp/ConnectUdp, we can remove this seccomp
    // workaround and handle UDP via Landlock alongside TCP.
    const SOCK_TYPE_MASK: u64 = 0xf;
    const SOCK_DGRAM: u64 = 2;

    if let Ok(socket_syscall) = ScmpSyscall::from_name("socket") {
        // Block socket() when (type & SOCK_TYPE_MASK) == SOCK_DGRAM
        let cmp = ScmpArgCompare::new(1, ScmpCompareOp::MaskedEqual(SOCK_TYPE_MASK), SOCK_DGRAM);
        filter
            .add_rule_conditional(ScmpAction::Errno(libc::EPERM), socket_syscall, &[cmp])
            .context("Failed to add UDP socket block rule")?;
        if verbose {
            eprintln!("[safe-shell] Blocked UDP socket creation (SOCK_DGRAM)");
        }
    }

    // Syscalls to block - these return EPERM when called
    let blocked_syscalls = [
        // Process manipulation - can't kill or trace other processes
        ("kill", ScmpSyscall::from_name("kill")),
        ("tkill", ScmpSyscall::from_name("tkill")),
        ("tgkill", ScmpSyscall::from_name("tgkill")),
        ("ptrace", ScmpSyscall::from_name("ptrace")),

        // System state changes
        ("reboot", ScmpSyscall::from_name("reboot")),
        ("sethostname", ScmpSyscall::from_name("sethostname")),
        ("setdomainname", ScmpSyscall::from_name("setdomainname")),

        // Mounting - can't modify filesystem mounts
        ("mount", ScmpSyscall::from_name("mount")),
        ("umount2", ScmpSyscall::from_name("umount2")),
        ("pivot_root", ScmpSyscall::from_name("pivot_root")),

        // Module loading
        ("init_module", ScmpSyscall::from_name("init_module")),
        ("finit_module", ScmpSyscall::from_name("finit_module")),
        ("delete_module", ScmpSyscall::from_name("delete_module")),

        // Privilege escalation
        ("setuid", ScmpSyscall::from_name("setuid")),
        ("setgid", ScmpSyscall::from_name("setgid")),
        ("setreuid", ScmpSyscall::from_name("setreuid")),
        ("setregid", ScmpSyscall::from_name("setregid")),
        ("setresuid", ScmpSyscall::from_name("setresuid")),
        ("setresgid", ScmpSyscall::from_name("setresgid")),
        ("setgroups", ScmpSyscall::from_name("setgroups")),
    ];

    let mut blocked_count = 0;
    for (name, syscall_result) in blocked_syscalls {
        match syscall_result {
            Ok(syscall) => {
                filter
                    .add_rule(ScmpAction::Errno(libc::EPERM), syscall)
                    .with_context(|| format!("Failed to add seccomp rule for {}", name))?;
                blocked_count += 1;
            }
            Err(_) => {
                // Syscall might not exist on this architecture, skip it
                if verbose {
                    eprintln!("[safe-shell] Warning: syscall '{}' not found, skipping", name);
                }
            }
        }
    }

    // Load the filter
    filter.load().context("Failed to load seccomp filter")?;

    if verbose {
        eprintln!(
            "[safe-shell] Seccomp filter loaded: {} syscalls blocked",
            blocked_count
        );
    }

    Ok(())
}
