//! Credential-expiry dashboard IPC DTOs.

use azapptoolkit_core::audit::{CredentialKind, CredentialStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The lifetime ceilings the app enforces on the credentials it creates, and
/// the defaults it applies when a form or a caller leaves the lifetime blank,
/// in days. One home for both trees: the backend (`commands/applications/
/// credentials.rs`, `cert.rs`, the SSO create path, the Key Vault rotation,
/// the DR restore's re-issued secrets) and the frontend forms (the
/// Credentials tab, the SSO wizard) each restated these by hand, with nothing
/// pinning them equal.
///
/// The secret cap is the portal's 24-month hard cap; the certificate cap is
/// Graph's three years, even across a leap day. The secret default is the
/// portal's recommended preset. The certificate default is deliberately ONE
/// year, not the three that Graph and the portal default to: a signing
/// certificate's lifetime is the window a stolen key stays useful, and the
/// staged rollover makes renewing cheap enough that three years of exposure
/// isn't worth the saved effort.
pub const MAX_SECRET_LIFETIME_DAYS: u32 = 730;
pub const MAX_CERT_LIFETIME_DAYS: u32 = 1095;
pub const DEFAULT_SECRET_LIFETIME_DAYS: u32 = 180;
pub const DEFAULT_CERT_LIFETIME_DAYS: u32 = 365;

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

/// Per-app secret-lifetime policy context for the Credentials tab, decided
/// from the tenant's DEFAULT app-management policy plus any per-app override
/// assigned to this application (the same precedence the audit scorer applies:
/// an override REPLACES the default; ≥2 overrides on one principal is a
/// combination Graph does not document, so it reads as no cap).
///
/// `available = false` says the policy reads could not be completed (no
/// `Policy.Read.All`, a failed read, or a failed app read) — the tab then shows
/// nothing rather than claiming "no cap enforced", the same never-flag-on-
/// unknown contract as [`CredentialUsageDto`]. `effective_cap_days = None` with
/// `available = true` means the policy is known to enforce no lifetime cap on
/// this app.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppCredentialPolicyDto {
    pub available: bool,
    pub effective_cap_days: Option<i64>,
    /// Display names of the per-app override policies assigned to this
    /// application — what to name the override in the tab's advisory.
    pub custom_policy_names: Vec<String>,
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
