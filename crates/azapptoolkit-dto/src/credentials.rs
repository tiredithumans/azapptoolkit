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

/// Display-only "critical" expiry tier (the legacy `Constants.ps1:203` 7-day
/// tier). The audit's `CredentialStatus` has no such bucket
/// (`core/audit/permissions.rs:15-18`), so it lives with the rows it is
/// applied to, beside the shared warning threshold
/// (`azapptoolkit_core::audit::EXPIRY_WARNING_DAYS`).
pub const EXPIRY_CRITICAL_DAYS: i64 = 7;

/// Home's Credential Health card: the counts, not the rows (one row per
/// credential, so usually more than there are apps).
/// `get_credential_health_counts`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialHealthCounts {
    /// [`CredentialRowDto::is_expired`], the "Expired" chip.
    pub expired: usize,
    /// Expiring within [`EXPIRY_CRITICAL_DAYS`], the "≤ 7 days" chip.
    pub within_critical: usize,
    /// Expiring within `EXPIRY_WARNING_DAYS`, the "≤ 30 days" chip.
    pub within_warning: usize,
}

impl CredentialHealthCounts {
    /// Counts `rows` with the Credentials tab's own facet predicates.
    pub fn of(rows: &[CredentialRowDto]) -> Self {
        Self {
            expired: rows.iter().filter(|r| r.is_expired()).count(),
            within_critical: rows
                .iter()
                .filter(|r| r.expires_within(EXPIRY_CRITICAL_DAYS))
                .count(),
            within_warning: rows
                .iter()
                .filter(|r| r.expires_within(azapptoolkit_core::audit::EXPIRY_WARNING_DAYS))
                .count(),
        }
    }
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

impl CredentialRowDto {
    /// Already expired — the "Expired" facet and count.
    pub fn is_expired(&self) -> bool {
        matches!(self.status, CredentialStatus::Expired)
    }

    /// Not yet expired and ending within `days` days (inclusive) — the
    /// "≤ 7 days" / "≤ 30 days" facets and counts.
    pub fn expires_within(&self, days: i64) -> bool {
        matches!(self.days_to_expiry, Some(d) if (0..=days).contains(&d))
    }
}

#[cfg(test)]
mod counts_tests {
    use super::*;
    use azapptoolkit_core::audit::EXPIRY_WARNING_DAYS;

    fn row(status: CredentialStatus, days: Option<i64>) -> CredentialRowDto {
        CredentialRowDto {
            app_object_id: "obj".into(),
            app_id: "app".into(),
            app_display_name: "App".into(),
            credential_name: "cred".into(),
            kind: CredentialKind::Secret,
            start_date_time: None,
            end_date_time: None,
            days_to_expiry: days,
            status,
        }
    }

    /// Home's Credential Health numbers are the Credentials tab's facets: the
    /// two tiers are inclusive, nest (≤ 7 is inside ≤ 30), and an expired
    /// credential (negative days) counts only as expired.
    #[test]
    fn health_counts_use_the_facet_predicates() {
        let rows = vec![
            row(CredentialStatus::Expired, Some(-3)),
            row(CredentialStatus::ExpiringSoon, Some(0)),
            row(CredentialStatus::ExpiringSoon, Some(EXPIRY_CRITICAL_DAYS)),
            row(CredentialStatus::ExpiringSoon, Some(EXPIRY_WARNING_DAYS)),
            row(CredentialStatus::Active, Some(EXPIRY_WARNING_DAYS + 1)),
            row(CredentialStatus::Active, None),
        ];
        let counts = CredentialHealthCounts::of(&rows);
        assert_eq!(
            counts,
            CredentialHealthCounts {
                expired: 1,
                within_critical: 2,
                within_warning: 3,
            }
        );
        assert_eq!(
            counts.within_critical,
            rows.iter()
                .filter(|r| r.expires_within(EXPIRY_CRITICAL_DAYS))
                .count()
        );
    }
}
