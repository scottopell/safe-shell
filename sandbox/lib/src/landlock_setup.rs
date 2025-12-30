//! Landlock filesystem and network restrictions

use anyhow::{Context, Result};
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, Scope, ABI,
};

use crate::SandboxCapabilities;

/// Set up Landlock filesystem and network restrictions
///
/// Landlock uses an allowlist model:
/// 1. Declare which access types we're restricting (handle_access)
/// 2. Create the ruleset with optional scope restrictions (ABI v6+)
/// 3. Add rules for what IS allowed
/// 4. Restrict self - everything not allowed is denied
///
/// Returns `SandboxCapabilities` indicating which features were enabled.
/// Signal/socket scoping requires kernel 6.12+ (ABI v6).
pub fn setup_landlock(verbose: bool) -> Result<SandboxCapabilities> {
    // Target ABI v6 for scope support - the library will gracefully degrade
    let abi = ABI::V6;

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
    //
    // We also request scope restrictions (ABI v6+):
    // - Scope::Signal: Restrict signals to processes in the same Landlock domain
    // - Scope::AbstractUnixSocket: Restrict abstract Unix socket connections similarly
    // These will be silently ignored on older kernels (best-effort mode)
    let all_scopes = Scope::from_all(abi);
    let mut ruleset = Ruleset::default()
        .handle_access(all_fs_access)
        .context("Failed to configure Landlock filesystem access handling")?
        .handle_access(all_net_access)
        .context("Failed to configure Landlock network access handling")?
        .scope(all_scopes)
        .context("Failed to configure Landlock scope restrictions")?
        .create()
        .context("Failed to create Landlock ruleset")?;

    // Paths to allow read-only access
    // We allow read access to the entire filesystem - Landlock still blocks writes
    let read_only_paths: &[&str] = &[
        "/", // Root - allows ls /, traversal everywhere (read-only)
    ];

    // Add read-only rules using the helper
    let ro_rules = path_beneath_rules(read_only_paths, read_only_access);
    ruleset = ruleset
        .add_rules(ro_rules)
        .context("Failed to add read-only path rules")?;

    if verbose {
        eprintln!("[safe-shell] Added read-only access to: / (entire filesystem)");
    }

    // Add /dev with read/write for PTY access
    let dev_rules = path_beneath_rules(&["/dev"], dev_access);
    ruleset = ruleset
        .add_rules(dev_rules)
        .context("Failed to add /dev rules")?;

    if verbose {
        eprintln!("[safe-shell] Added read/write access to: /dev (for PTY)");
    }

    // Add /dev/shm with file creation for POSIX shared memory and semaphores
    // This enables Python multiprocessing (Queue, Pool, ProcessPoolExecutor)
    // Security: /dev/shm is tmpfs (memory-only, no persistence), low risk
    let shm_access = AccessFs::ReadFile
        | AccessFs::ReadDir
        | AccessFs::WriteFile
        | AccessFs::MakeReg    // create semaphore/shm files
        | AccessFs::RemoveFile; // cleanup when done
    let shm_rules = path_beneath_rules(&["/dev/shm"], shm_access);
    ruleset = ruleset
        .add_rules(shm_rules)
        .context("Failed to add /dev/shm rules")?;

    if verbose {
        eprintln!("[safe-shell] Added read/write/create access to: /dev/shm (for multiprocessing)");
        eprintln!("[safe-shell] Network access: BLOCKED (no rules added)");
    }

    // Enforce the ruleset
    let status = ruleset
        .restrict_self()
        .context("Failed to restrict process with Landlock")?;

    // Determine what was actually enforced based on RulesetStatus
    // FullyEnforced with V6 target means scopes are active
    // PartiallyEnforced means some features (likely scopes) were unavailable
    let mut caps = SandboxCapabilities::default();

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            caps.landlock_enabled = true;
            caps.signal_scoping_enabled = true;
            caps.socket_scoping_enabled = true;
            if verbose {
                eprintln!("[safe-shell] Landlock fully enforced");
                eprintln!("[safe-shell] Signal scoping: enabled (kernel 6.12+)");
                eprintln!("[safe-shell] Abstract Unix socket scoping: enabled");
            }
        }
        RulesetStatus::PartiallyEnforced => {
            caps.landlock_enabled = true;
            // Scopes likely not available on this kernel
            caps.signal_scoping_enabled = false;
            caps.socket_scoping_enabled = false;
            eprintln!("[safe-shell] Warning: Landlock only partially enforced");
            if verbose {
                eprintln!("[safe-shell] Signal scoping: not available (kernel <6.12)");
                eprintln!("[safe-shell] Abstract Unix socket scoping: not available");
            }
        }
        RulesetStatus::NotEnforced => {
            anyhow::bail!("Landlock not enforced - kernel may not support Landlock");
        }
    }

    Ok(caps)
}
