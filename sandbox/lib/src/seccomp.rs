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

    // Block connect() on Unix domain sockets (AF_UNIX = 1)
    // This prevents communication with host services via path-based Unix sockets
    // like /run/dbus/system_bus_socket or /var/run/docker.sock
    //
    // Note: Landlock's Scope::AbstractUnixSocket only blocks *abstract* sockets
    // (those with null byte prefix), not filesystem-based Unix sockets.
    //
    // We check the socket's domain by looking at the sa_family field of the
    // sockaddr structure passed to connect(). For AF_UNIX, sa_family = 1.
    // connect(sockfd, addr, addrlen) - addr->sa_family is at offset 0, 2 bytes
    //
    // Unfortunately, seccomp can only inspect syscall arguments (registers),
    // not memory pointed to by arguments. So we block AF_UNIX socket creation instead.
    const AF_UNIX: u64 = 1;

    if let Ok(socket_syscall) = ScmpSyscall::from_name("socket") {
        // Block socket(AF_UNIX, ...) - prevents creating Unix domain sockets entirely
        let cmp = ScmpArgCompare::new(0, ScmpCompareOp::Equal, AF_UNIX);
        filter
            .add_rule_conditional(ScmpAction::Errno(libc::EPERM), socket_syscall, &[cmp])
            .context("Failed to add AF_UNIX socket block rule")?;
        if verbose {
            eprintln!("[safe-shell] Blocked Unix domain socket creation (AF_UNIX)");
        }
    }

    // NOTE: socketpair(AF_UNIX) is intentionally NOT blocked.
    // It creates anonymous connected socket pairs for internal IPC (parent-child
    // communication, Go runtime, etc). These sockets cannot connect to external
    // services like docker.sock or dbus - they're purely for sandbox-internal use.
    // Exfil is not possible because:
    // 1. No filesystem path - cannot connect to external services
    // 2. FD passing to outside sandbox requires Unix sockets (blocked) or ptrace
    //    (blocked by Landlock signal scoping on kernel 6.12+)

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
    //
    // NOTE: ptrace is NOT blocked here. Landlock automatically restricts ptrace
    // based on domain hierarchy - a sandboxed process can only ptrace targets in
    // an equal or more restricted domain. This means processes outside the sandbox
    // cannot be ptraced, but debugging within the sandbox (strace, gdb) works.
    // See: https://docs.kernel.org/userspace-api/landlock.html
    let blocked_syscalls = [
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

        // Security hardening - block exploitation helpers
        // personality() can disable ASLR (ADDR_NO_RANDOMIZE), making exploitation easier
        ("personality", ScmpSyscall::from_name("personality")),
    ];

    // prctl() filtering: surgical approach instead of blanket block
    //
    // prctl() is a kitchen-sink syscall with 50+ distinct operations. Blocking all
    // of them breaks legitimate use cases:
    //   - PR_SET_NAME (15): thread naming for debugging (ps/top)
    //   - PR_SET_NO_NEW_PRIVS (38): security hardening - Landlock recommends this!
    //   - PR_SET_PDEATHSIG (1): clean child termination
    //   - PR_SET_TIMERSLACK (29): power management
    //
    // We block only the dangerous operations:
    //   - PR_SET_DUMPABLE (4): could enable core dumps (info leak) or ptrace attachment
    //   - PR_SET_MM (35): manipulate process memory map, includes PR_SET_MM_EXE_FILE
    //     which can replace /proc/self/exe symlink
    //
    // This follows Chromium's approach of surgical prctl filtering rather than
    // blanket blocking. See: https://chromium.googlesource.com/chromium/src/+/HEAD/sandbox/linux/
    //
    // Note: PR_SET_PTRACER (0x59616d61) is NOT blocked because Landlock already
    // restricts ptrace based on domain hierarchy - it would be redundant.
    const PR_SET_DUMPABLE: u64 = 4;
    const PR_SET_MM: u64 = 35;

    if let Ok(prctl_syscall) = ScmpSyscall::from_name("prctl") {
        // Block PR_SET_DUMPABLE - prevents enabling core dumps and ptrace attachment
        let cmp_dumpable = ScmpArgCompare::new(0, ScmpCompareOp::Equal, PR_SET_DUMPABLE);
        filter
            .add_rule_conditional(ScmpAction::Errno(libc::EPERM), prctl_syscall, &[cmp_dumpable])
            .context("Failed to add prctl(PR_SET_DUMPABLE) block rule")?;

        // Block PR_SET_MM - prevents memory map manipulation
        let cmp_mm = ScmpArgCompare::new(0, ScmpCompareOp::Equal, PR_SET_MM);
        filter
            .add_rule_conditional(ScmpAction::Errno(libc::EPERM), prctl_syscall, &[cmp_mm])
            .context("Failed to add prctl(PR_SET_MM) block rule")?;

        if verbose {
            eprintln!("[safe-shell] Blocked prctl operations: PR_SET_DUMPABLE, PR_SET_MM");
        }
    }

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
