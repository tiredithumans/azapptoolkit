//! Audit remediation DTOs crossing the IPC boundary.

use serde::{Deserialize, Serialize};

/// Result of a one-click remediation. Counts are what was *actually* removed
/// from the live application (the backend re-resolves the expired set before
/// acting), so the UI can report an honest summary even if the audit snapshot
/// was stale.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationOutcome {
    pub removed_secrets: u32,
    pub removed_certificates: u32,
}

impl RemediationOutcome {
    pub fn total(&self) -> u32 {
        self.removed_secrets + self.removed_certificates
    }
}

/// Result of the remove-redundant-permissions remediation. `removed` lists the
/// permission values actually removed (grant revoked when present, declaration
/// dropped); `skipped` lists values the audit flagged but the live re-resolution
/// found unsafe to remove (the covering broader grant is no longer present), so
/// the UI can report an honest summary against a stale snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RedundantPermissionsOutcome {
    pub removed: Vec<String>,
    pub skipped: Vec<String>,
}
