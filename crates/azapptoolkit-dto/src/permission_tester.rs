//! Permission-tester IPC DTOs.
//!
//! The tester answers "does this app actually have access to *this* Exchange
//! mailbox / *this* SharePoint site?" by exercising the authoritative live
//! checks (Exchange `Test-ServicePrincipalAuthorization`; SharePoint per-site
//! permissions unioned with org-wide `Sites.*` grants). Snake-case fields; the
//! Tauri IPC boundary handles the camelCase bridge.

use serde::{Deserialize, Serialize};

/// Outcome of a single permission test against one resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionTestResult {
    /// `true` when the app can reach the resource (via any path).
    pub has_access: bool,
    /// Short machine-stable verdict: one of `org_wide`, `scoped`, `no_access`,
    /// `unknown`. The UI maps these to a badge + label.
    pub verdict: String,
    /// Role/permission names that grant the access (e.g. EXO role names, or
    /// SharePoint site roles like `read`/`write`/`owner`). Empty on no access.
    pub roles: Vec<String>,
    /// Human-readable explanation of the verdict (why access is/ isn't granted,
    /// or why it couldn't be determined).
    pub detail: Option<String>,
    /// Resolved resource label (the mailbox identity, or the site display name)
    /// echoed back so the UI can confirm what was actually tested.
    pub resource_label: String,
}

impl PermissionTestResult {
    /// Verdict shown when the check couldn't run (e.g. not an Exchange admin):
    /// never reported as "no access", which would be misleading.
    pub fn unknown(resource_label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            has_access: false,
            verdict: "unknown".into(),
            roles: Vec::new(),
            detail: Some(detail.into()),
            resource_label: resource_label.into(),
        }
    }
}

/// Progress event payload for the mailbox reverse-lookup probe, emitted as
/// `mailbox-probe-progress` after each candidate principal is tested.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxProbeProgress {
    pub done: usize,
    pub total: usize,
    pub current_app: Option<String>,
    pub cancelled: bool,
}

/// One candidate principal's verdict against the target mailbox — the inverse
/// of [`PermissionTestResult`] (resource → identities instead of identity →
/// resource). Candidates are every service principal holding a mail-scopable
/// Graph application permission, plus every principal registered in
/// Exchange's SP store (the RBAC-for-Applications population — the only place
/// an app with no Entra grant is visible).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxReacherRow {
    pub app_id: String,
    pub principal_id: String,
    pub display_name: Option<String>,
    /// Mail-scopable Graph application permissions the principal holds (the
    /// Entra side). Empty for a candidate discovered only via Exchange's SP
    /// store — its access, if any, comes solely from Exchange RBAC.
    pub held_permissions: Vec<String>,
    /// Same machine-stable verdicts as [`PermissionTestResult::verdict`]:
    /// `org_wide` / `scoped` / `no_access` / `unknown`.
    pub verdict: String,
    /// Exchange role names backing the verdict, when Exchange answered.
    pub roles: Vec<String>,
    pub detail: Option<String>,
}

/// Result of probing every candidate against one mailbox. `exchange_available`
/// is `false` when the Exchange client couldn't be built at all — verdicts then
/// derive from the Entra grants alone (org-wide unless scoped, the audit's
/// never-under-report posture) and the UI should say so.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MailboxReachersResult {
    pub tenant_id: String,
    pub mailbox: String,
    pub total_candidates: usize,
    pub rows: Vec<MailboxReacherRow>,
    pub exchange_available: bool,
    pub cancelled: bool,
}
