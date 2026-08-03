//! Bulk-operation IPC DTOs.

use serde::{Deserialize, Serialize};

use crate::UiError;

/// A per-item failure inside a bulk run.
///
/// Structured rather than a bare string. The handlers used to flatten a
/// [`UiError`] into `Some(e.message)`, which threw away the two fields the UI
/// needs to *act*: `code` and `retryable`. The consequence was specific and bad
/// — a mid-run `refresh_missing` (the session died) became indistinguishable
/// from "this one app failed", so the loop ground through every remaining app
/// against a dead session and produced N identical opaque failures instead of
/// one actionable re-auth prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

impl From<UiError> for BulkError {
    fn from(err: UiError) -> Self {
        BulkError {
            code: err.code,
            message: err.message,
            retryable: err.retryable,
        }
    }
}

impl BulkError {
    /// See [`UiError::is_reauth_fatal`] — the session is dead, so every
    /// remaining item in the run would fail the same way. The bulk driver stops
    /// on this rather than burning through the rest of the selection.
    pub fn is_reauth_fatal(&self) -> bool {
        UiError::new(self.code.clone(), String::new(), self.retryable).is_reauth_fatal()
    }
}

impl std::fmt::Display for BulkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkProgress {
    pub done: usize,
    pub total: usize,
    pub current_app: Option<String>,
    pub cancelled: bool,
    /// Current adaptive in-flight concurrency cap, when the emitting command
    /// runs under a [`ConcurrencyThrottle`](../../desktop) (the DR backup).
    /// `None` for the bulk-credential/create/delete flows, which use a fixed
    /// cap. The DR view surfaces a back-off notice when this drops below its
    /// observed peak. Additive + skipped when absent, so existing emitters that
    /// don't set it stay wire-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_flight_cap: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRemovalSummary {
    pub object_id: String,
    pub display_name: String,
    pub removed_key_ids: Vec<String>,
    pub failed_key_ids: Vec<String>,
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRemoveExpiredResult {
    pub apps_scanned: usize,
    pub summaries: Vec<AppRemovalSummary>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDeleteFailure {
    pub object_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDeleteResult {
    pub deleted: Vec<String>,
    pub failed: Vec<BulkDeleteFailure>,
    pub cancelled: bool,
}

// ---------------- Bulk grant admin consent ----------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkGrantOutcome {
    pub object_id: String,
    pub granted: usize,
    pub skipped: usize,
    pub failed: usize,
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkGrantResult {
    pub outcomes: Vec<BulkGrantOutcome>,
    pub cancelled: bool,
}

// ---------------- Bulk create applications ----------------

/// One app to create in a bulk run. Parsed from the user's JSON import.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkCreateSpec {
    pub display_name: String,
    pub sign_in_audience: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkCreateOutcome {
    pub display_name: String,
    /// `valid` / `invalid` for a validation-only run; `created` / `failed` for
    /// a real run.
    pub status: String,
    pub app_id: Option<String>,
    /// Human-readable detail for ANY non-success status, including the
    /// validation ones (`invalid`) that never involve a backend call.
    pub message: Option<String>,
    /// Set only when the failure came from a backend call, so the create path
    /// can participate in the run-level fatal check like every other bulk
    /// command. A validation rejection leaves this `None` — it carries no wire
    /// code, and it says nothing about the health of the session.
    #[serde(default)]
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkCreateResult {
    pub validate_only: bool,
    pub outcomes: Vec<BulkCreateOutcome>,
    pub cancelled: bool,
}

// ---------------- Bulk remove redundant permissions ----------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRemoveRedundantOutcome {
    pub object_id: String,
    /// Permission values actually removed (the narrower, fully-covered ones).
    pub removed: Vec<String>,
    /// Permission values left in place because removing them would have lost a
    /// load-bearing grant (re-resolved live, per the single-app safety rules).
    pub skipped: Vec<String>,
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRemoveRedundantResult {
    pub outcomes: Vec<BulkRemoveRedundantOutcome>,
    pub cancelled: bool,
}

// ---------------- Bulk scope access (Exchange mailbox / SharePoint) ----------

/// One app's outcome from a bulk scoping run. `error: None` = scoped OK.
/// Shared by the mailbox and SharePoint bulk commands (same shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkScopeOutcome {
    pub object_id: String,
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkScopeResult {
    pub outcomes: Vec<BulkScopeOutcome>,
    pub cancelled: bool,
}

// ---------------- Bulk add owner ----------------

/// One app's outcome from a bulk add-owner run. `skipped` = the principal was
/// already an owner (re-resolved live), so nothing was written.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOwnerOutcome {
    pub object_id: String,
    pub added: bool,
    pub skipped: bool,
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkAddOwnerResult {
    pub outcomes: Vec<BulkOwnerOutcome>,
    pub cancelled: bool,
}

// ---------------- Bulk disable sign-in ----------------

/// One app's outcome from a bulk disable-sign-in run. `error: None` = its
/// service principal was disabled OK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDisableOutcome {
    pub object_id: String,
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDisableSignInResult {
    pub outcomes: Vec<BulkDisableOutcome>,
    pub cancelled: bool,
}
