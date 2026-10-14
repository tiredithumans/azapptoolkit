//! The Tauri event names the backend emits and the frontend listens to.
//!
//! One table imported by both sides: each name used to be spelled by hand in
//! `commands/*` and again in `web-rs/src/bindings/events.rs`, with nothing
//! pinning them equal — a rename on one side silently ended the stream.
//! `repo_invariants/ipc.rs` fails any literal that reappears.

/// The security audit's per-principal progress (`AuditProgress`).
pub const AUDIT_PROGRESS: &str = "audit-progress";
/// Every bulk action's per-item progress (`BulkProgress`).
pub const BULK_PROGRESS: &str = "bulk-progress";
/// The DR backup's progress (`BulkProgress`).
pub const BACKUP_PROGRESS: &str = "backup-progress";
/// The DR restore's progress (`BulkProgress`).
pub const RESTORE_PROGRESS: &str = "restore-progress";
/// The `Sites.Selected` tenant sweep's progress (`SiteSweepProgress`).
pub const SITE_SWEEP_PROGRESS: &str = "site-sweep-progress";
/// The Key Vault RBAC sweep's progress (`KeyVaultSweepProgress`).
pub const KEYVAULT_SWEEP_PROGRESS: &str = "keyvault-sweep-progress";
/// The mailbox-reach probe's progress (`MailboxProbeProgress`).
pub const MAILBOX_PROBE_PROGRESS: &str = "mailbox-probe-progress";
/// The updater's download progress (`UpdateProgress`).
pub const UPDATER_PROGRESS: &str = "updater-progress";
/// The sign-in flow could not open the system browser; the payload is the
/// URL to open by hand.
pub const AUTH_BROWSER_FALLBACK: &str = "auth-browser-fallback";

/// Every name, for the pins that need the whole set.
pub const ALL: &[&str] = &[
    AUDIT_PROGRESS,
    BULK_PROGRESS,
    BACKUP_PROGRESS,
    RESTORE_PROGRESS,
    SITE_SWEEP_PROGRESS,
    KEYVAULT_SWEEP_PROGRESS,
    MAILBOX_PROBE_PROGRESS,
    UPDATER_PROGRESS,
    AUTH_BROWSER_FALLBACK,
];

#[cfg(test)]
mod tests {
    use super::ALL;

    /// Every `pub const NAME: &str = "value";` in this file, as `(NAME, value)`,
    /// read from the source so a constant left out of [`ALL`] cannot pass: the
    /// pins in `repo_invariants/ipc.rs` loop over `ALL`, so a name missing from
    /// it would be checked nowhere.
    fn declared_names() -> Vec<(String, String)> {
        include_str!("events.rs")
            .lines()
            .filter_map(|line| {
                let rest = line.trim_start().strip_prefix("pub const ")?;
                let (name, rest) = rest.split_once(": &str = \"")?;
                let (value, _) = rest.split_once('"')?;
                Some((name.to_string(), value.to_string()))
            })
            .collect()
    }

    #[test]
    fn every_name_is_distinct_kebab_case() {
        let mut seen = std::collections::BTreeSet::new();
        for name in ALL {
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{name}"
            );
            assert!(seen.insert(*name), "{name} is listed twice");
        }
        let declared = declared_names();
        assert!(declared.len() >= 5, "the source scan found {declared:?}");
        let declared_values: std::collections::BTreeSet<&str> =
            declared.iter().map(|(_, v)| v.as_str()).collect();
        assert_eq!(
            seen, declared_values,
            "ALL must list every event constant declared in this file, and nothing else"
        );
        // `repo_invariants/ipc.rs` derives each constant's name from its value
        // (upper snake of the kebab value), so state that contract here.
        for (name, value) in &declared {
            assert_eq!(
                *name,
                value.to_uppercase().replace('-', "_"),
                "constant {name} must be the upper-snake form of {value:?}"
            );
        }
    }
}
