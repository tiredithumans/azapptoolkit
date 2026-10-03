//! Credential-expiry dashboard IPC DTOs.

use azapptoolkit_core::audit::{CredentialKind, CredentialStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One credential (client secret or certificate) belonging to an app
/// registration, flattened for the tenant-wide credential-expiry dashboard.
/// `days_to_expiry`/`status` are computed server-side via
/// [`azapptoolkit_core::audit::summarize_credentials`] so the dashboard renders
/// the same expiry semantics as the security audit.
/// Tenant-wide per-credential last-used signal for the Credentials tab, read
/// from the beta `appCredentialSignInActivities` report (**global cloud
/// only**). Joined client-side on `(app_id, key_id)`.
///
/// A credential with NO matching row has an *unknown* last-used — the report
/// is preview data whose coverage of never-used credentials is not
/// contractual, so absence never means "unused". `available = false` says the
/// report could not be read at all (no `AuditLog.Read.All` consent, a
/// sovereign cloud, or a failed read); the tab then degrades its Last-used
/// column rather than rendering a wrong answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialUsageDto {
    pub available: bool,
    pub rows: Vec<CredentialUsageRow>,
}

/// One tracked credential's aggregated last-used. `last_used = None` =
/// tracked-but-never-used (render "No use recorded"); a credential present
/// under both `application` and `servicePrincipal` origins is folded to one
/// row with the NEWEST date.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialUsageRow {
    pub app_id: String,
    pub key_id: String,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRowDto {
    /// The app registration's object id — used to deep-link into its detail.
    pub app_object_id: String,
    pub app_id: String,
    pub app_display_name: String,
    /// The credential's display name (e.g. secret description / cert name).
    pub credential_name: String,
    pub kind: CredentialKind,
    pub start_date_time: Option<DateTime<Utc>>,
    pub end_date_time: Option<DateTime<Utc>>,
    pub days_to_expiry: Option<i64>,
    pub status: CredentialStatus,
}
