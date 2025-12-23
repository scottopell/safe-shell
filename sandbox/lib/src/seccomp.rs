//! seccomp-bpf syscall filtering

use anyhow::{Context, Result};
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

/// Set up seccomp-bpf syscall filtering
///
/// We use a default-allow policy and block specific dangerous syscalls.
/// This is less secure than a default-deny allowlist, but much more practical
/// for running arbitrary shell commands.
pub fn setup_seccomp(verbose: bool) -> Result<()> {
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
        // Process signals - can't signal other processes
        // NOTE: This breaks readline's Ctrl+C handling in interactive mode because
        // readline uses kill(getpid(), SIGINT) to re-raise signals after cleanup.
        // This is acceptable since LLM agents don't use interactive shells.
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
