//! seccomp-bpf syscall filtering

use anyhow::{Context, Result};
use libseccomp::{ScmpAction, ScmpArgCompare, ScmpCompareOp, ScmpFilterContext, ScmpSyscall};

use crate::SandboxCapabilities;

/// Set up seccomp-bpf syscall filtering
///
/// We use a default-allow policy and block specific dangerous syscalls.
/// This is less secure than a default-deny allowlist, but much more practical
/// for running arbitrary shell commands.
///
/// If Landlock signal scoping is enabled (kernel 6.12+), we skip the PID-based
/// signal filtering workaround since Landlock handles it better.
pub fn setup_seccomp(verbose: bool, caps: &SandboxCapabilities) -> Result<()> {
    // Create a filter with default action: ALLOW
    // We'll explicitly block dangerous syscalls
    let mut filter =
        ScmpFilterContext::new_filter(ScmpAction::Allow).context("Failed to create seccomp filter")?;

    // Block UDP sockets: socket(domain, type, protocol) where type contains SOCK_DGRAM
    // SOCK_DGRAM = 2, but type can have flags OR'd in (SOCK_NONBLOCK, SOCK_CLOEXEC)
    // So we use a mask to check only the socket type bits (lower 4 bits)
    //
    // NOTE: Landlock network access is TCP-only at the kernel level (ABI v4+).
    // The kernel only defines LANDLOCK_ACCESS_NET_BIND_TCP and CONNECT_TCP.
    // There are no UDP equivalents in the kernel Landlock API, so seccomp is
    // the correct approach for blocking UDP until/unless the kernel adds support.
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

    // Signal syscall filtering: only needed if Landlock signal scoping is unavailable
    //
    // On kernel 6.12+ with Landlock ABI v6, Scope::Signal handles this better:
    // - Allows all processes in the Landlock domain to signal each other
    // - Blocks signals to processes outside the domain
    //
    // On older kernels, we fall back to PID-based filtering:
    // - Only allows the initial bash process to signal itself
    // - Child processes cannot signal themselves or others (a known limitation)
    if caps.signal_scoping_enabled {
        if verbose {
            eprintln!("[safe-shell] Signal filtering: delegated to Landlock (kernel 6.12+)");
        }
    } else {
        // Fallback: PID-based signal filtering
        let self_pid = std::process::id() as u64;

        // For each signal syscall: block all EXCEPT when targeting self
        // We use NotEqual to block, since default action is Allow
        // kill(pid, sig) - block when pid != self
        if let Ok(kill_syscall) = ScmpSyscall::from_name("kill") {
            let cmp = ScmpArgCompare::new(0, ScmpCompareOp::NotEqual, self_pid);
            filter
                .add_rule_conditional(ScmpAction::Errno(libc::EPERM), kill_syscall, &[cmp])
                .context("Failed to add kill block rule")?;
        }

        // tkill(tid, sig) - block when tid != self
        if let Ok(tkill_syscall) = ScmpSyscall::from_name("tkill") {
            let cmp = ScmpArgCompare::new(0, ScmpCompareOp::NotEqual, self_pid);
            filter
                .add_rule_conditional(ScmpAction::Errno(libc::EPERM), tkill_syscall, &[cmp])
                .context("Failed to add tkill block rule")?;
        }

        // tgkill(tgid, tid, sig) - block when tgid != self
        if let Ok(tgkill_syscall) = ScmpSyscall::from_name("tgkill") {
            let cmp = ScmpArgCompare::new(0, ScmpCompareOp::NotEqual, self_pid);
            filter
                .add_rule_conditional(ScmpAction::Errno(libc::EPERM), tgkill_syscall, &[cmp])
                .context("Failed to add tgkill block rule")?;
        }

        if verbose {
            eprintln!("[safe-shell] Signal filtering: PID-based workaround (PID {})", self_pid);
        }
    }

    // Syscalls to block unconditionally - these return EPERM when called
    let blocked_syscalls = [
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
