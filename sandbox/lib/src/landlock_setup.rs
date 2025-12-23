//! Landlock filesystem and network restrictions

use anyhow::{Context, Result};
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, ABI,
};

/// Set up Landlock filesystem and network restrictions
///
/// Landlock uses an allowlist model:
/// 1. Declare which access types we're restricting (handle_access)
/// 2. Create the ruleset
/// 3. Add rules for what IS allowed
/// 4. Restrict self - everything not allowed is denied
pub fn setup_landlock(verbose: bool) -> Result<()> {
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
