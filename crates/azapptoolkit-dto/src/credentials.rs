//! Credential-expiry dashboard IPC DTOs.

use azapptoolkit_core::audit::{CredentialKind, CredentialStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One credential (client secret or certificate) belonging to an app
/// registration, flattened for the tenant-wide credential-expiry dashboard.
/// `days_to_expiry`/`status` are computed server-side via
/// [`azapptoolkit_core::audit::summarize_credentials`] so the dashboard renders
/// the same expiry semantics as the security audit.
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
