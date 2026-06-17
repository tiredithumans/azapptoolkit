//! Readiness-checklist IPC DTOs.
//!
//! The `check_readiness` command checks what the signed-in user currently holds
//! against the capability catalog (`azapptoolkit_core::capabilities`) and returns
//! a per-capability verdict on **two axes** — the standing **role** and the
//! consented **scope** ("Two halves, both required", `OPERATOR-ROLES.md`). The
//! frontend renders ✓ / ✗ / ? per axis, grouped by authorization plane.

use serde::{Deserialize, Serialize};

/// Whether a requirement is confirmed met (✓ `Have`), confirmed missing
/// (✗ `Missing`), or couldn't be determined (? `Unknown`). `Unknown` is the
/// graceful-degradation verdict — the checklist never hard-fails when a probe
/// can't run (e.g. Azure RBAC isn't enumerable per-user, or a directory read is
/// blocked).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Have,
    Missing,
    Unknown,
}

/// One capability's readiness, split into its role and scope halves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessItem {
    /// Capability key (matches `azapptoolkit_core::capabilities`).
    pub key: String,
    /// Authorization-plane key (`Plane::as_str`) — the UI groups on it.
    pub plane: String,
    /// Human plane name for the section header.
    pub plane_label: String,
    pub label: String,
    pub description: String,
    /// The standing-role half: active directory-role membership, or an
    /// Azure/Exchange RBAC role (the latter often `Unknown`, not enumerable).
    pub role_verdict: Verdict,
    pub role_detail: String,
    /// The consented-delegated-scope half.
    pub scope_verdict: Verdict,
    pub scope_detail: String,
    /// What to do when either half is missing (from `Capability::remediation`).
    pub remediation: String,
}

/// The full checklist for the signed-in user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub items: Vec<ReadinessItem>,
    /// True when the user's active directory roles couldn't be read at all (every
    /// directory-role verdict is `Unknown`), so the UI can show one banner
    /// instead of N "?"s.
    pub directory_roles_indeterminate: bool,
}
