//! Bulk-operation IPC DTOs.

use serde::{Deserialize, Serialize};

use crate::UiError;
use crate::permissions::PermissionKind;

/// A per-item failure inside a bulk run.
///
/// Structured rather than a bare string: the handlers used to flatten a
/// [`UiError`] into `Some(e.message)`, throwing away the `code` and
/// `retryable` fields the UI needs to *act* on. The consequence — a
/// mid-run `refresh_missing` (the session died) became indistinguishable
/// from "this one app failed", so the loop ground through every remaining
/// app against a dead session, producing N identical opaque failures
/// instead of one actionable re-auth prompt.
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
    /// observed peak. Additive + skipped when absent, so existing emitters
    /// stay wire-compatible.
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

/// One app a bulk delete could not remove.
///
/// `code` is the failure's wire code (`UiError::code`) when the backend had
/// one: it is what lets the bar tell "this app failed" from "the session died
/// on this app and the run stopped" (`is_reauth_fatal`), the same way the
/// other bulk outcomes carry a [`BulkError`]. `None` for a failure the backend
/// synthesised without a code (a task that ended without reporting). Additive
/// and skipped when absent, so older payloads still decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDeleteFailure {
    pub object_id: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// A bulk delete's outcome. Returned — never replaced by an error — once any
/// DELETE has landed: a run the session killed partway reports the ids it
/// deleted (so they leave the selection and can be restored) beside a failure
/// carrying the fatal code, and the tail it never dispatched is simply absent
/// from both lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDeleteResult {
    pub deleted: Vec<String>,
    pub failed: Vec<BulkDeleteFailure>,
    /// Stopped by the operator's Cancel. A run the dead session stopped is
    /// NOT cancelled: its failure list says why it stopped.
    pub cancelled: bool,
}

// ---------------- Bulk restore (recycle bin) ----------------

/// One recycle-bin restore: the app, then its paired service principals (Graph
/// does not cascade-restore them). `sp_restored` is `false` both when there
/// were no paired SPs to restore and when one failed — `error` carries the
/// message in the failure case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRestoreOutcome {
    pub object_id: String,
    pub restored: bool,
    pub sp_restored: bool,
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRestoreResult {
    pub outcomes: Vec<BulkRestoreOutcome>,
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

/// One app to create in a bulk run. Parsed from the user's JSON import, or
/// loaded from a CSV/JSON file by `load_bulk_create_specs_from_file`.
///
/// `owner_upns` and `permissions` are additive (F283): absent in older JSON,
/// and omitted on the wire when empty so a plain spec round-trips unchanged.
/// Both are resolved live **before** the app is created — an unknown UPN or
/// permission rejects the row without writing anything.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkCreateSpec {
    pub display_name: String,
    pub sign_in_audience: Option<String>,
    pub description: Option<String>,
    /// Users to add as owners, by `userPrincipalName`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_upns: Vec<String>,
    /// Permissions to **declare** in `requiredResourceAccess` at creation.
    /// Declaring is not consenting: the operator grants consent afterwards with
    /// the existing bulk Grant consent action, so an inventory import can never
    /// silently hand out tenant-wide access.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<BulkCreatePermission>,
}

/// One permission to declare on a bulk-created app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkCreatePermission {
    /// The resource API: its `appId`, or the display name of a resource in the
    /// bundled directory (e.g. `Microsoft Graph`), matched case-insensitively.
    pub resource: String,
    /// The permission's `value`, e.g. `User.Read.All`.
    pub value: String,
    pub kind: PermissionKind,
}

/// What a bulk create did with one spec. On the wire as the lowercase word.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BulkCreateStatus {
    /// Validation-only run: the spec would be created as described.
    Valid,
    /// Rejected before anything was created (either run kind): local
    /// validation failed, or a named owner or permission does not resolve in
    /// the tenant. `message` says why and `error` stays `None`.
    Invalid,
    /// The app exists — as described, or with a `message` naming what did not
    /// land (an owner, a later step).
    Created,
    /// A backend call failed and nothing was created.
    Failed,
}

impl BulkCreateStatus {
    /// The wire word, for display when an outcome carries no message.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Created => "created",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkCreateOutcome {
    pub display_name: String,
    pub status: BulkCreateStatus,
    pub app_id: Option<String>,
    /// Human-readable detail for ANY non-success status, including the
    /// rejections (`invalid`) that created nothing.
    pub message: Option<String>,
    /// Set only when the failure came from a backend call, so the create path
    /// can participate in the run-level fatal check like every other bulk
    /// command. A validation rejection leaves this `None` — it carries no wire
    /// code and says nothing about the health of the session.
    #[serde(default)]
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkCreateResult {
    pub validate_only: bool,
    pub outcomes: Vec<BulkCreateOutcome>,
    pub cancelled: bool,
}

#[cfg(test)]
mod bulk_create_status_tests {
    use super::BulkCreateStatus as S;

    /// The wire words are the ones the frontend matched as strings before the
    /// enum; serde and `as_str` must agree with them and each other.
    #[test]
    fn bulk_create_status_wire_words_are_stable() {
        for (s, word) in [
            (S::Valid, "valid"),
            (S::Invalid, "invalid"),
            (S::Created, "created"),
            (S::Failed, "failed"),
        ] {
            assert_eq!(serde_json::to_value(s).unwrap(), serde_json::json!(word));
            assert_eq!(
                serde_json::from_value::<S>(serde_json::json!(word)).unwrap(),
                s
            );
            assert_eq!(s.as_str(), word);
        }
    }
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

// ---------------- Bulk stage SAML signing certificates ----------------

/// One app's outcome from a bulk signing-certificate **staging** run.
///
/// `object_id` is the **service principal** id here, not an app-registration
/// object id — SAML signing certificates live on the SP. The field keeps the
/// shared name so the bar's failure-labelling machinery works unchanged, and
/// the host supplies SP-keyed display names to match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkStageCertOutcome {
    pub object_id: String,
    /// Thumbprint of the newly staged certificate. `None` when this app was
    /// skipped or failed.
    pub thumbprint: Option<String>,
    /// True when nothing was minted because a valid replacement was **already**
    /// staged. Distinct from an error: re-running over a filter that still lists
    /// a half-finished rollover must not mint a second spare certificate.
    #[serde(default)]
    pub skipped: bool,
    pub error: Option<BulkError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkStageCertResult {
    pub outcomes: Vec<BulkStageCertOutcome>,
    pub cancelled: bool,
}
