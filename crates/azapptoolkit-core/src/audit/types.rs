//! The audit's serde types — most cross the Tauri IPC boundary as-is
//! (see the boundary note on [`AuditItem`]) — plus the stable [`issue`]
//! markers the UI facets key off.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::{KeyCredential, PasswordCredential};

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: u32) -> Self {
        if score >= RISK_CRITICAL {
            RiskLevel::Critical
        } else if score >= RISK_HIGH {
            RiskLevel::High
        } else if score >= RISK_MEDIUM {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "Low",
            RiskLevel::Medium => "Medium",
            RiskLevel::High => "High",
            RiskLevel::Critical => "Critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialStatus {
    Active,
    ExpiringSoon,
    Expired,
    Unknown,
}

impl CredentialStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialStatus::Active => "Active",
            CredentialStatus::ExpiringSoon => "Expiring Soon",
            CredentialStatus::Expired => "Expired",
            CredentialStatus::Unknown => "Unknown",
        }
    }
}

/// Credential-expiry lens for the App Registrations **list** rows, computed
/// backend-side so the credential arrays themselves never cross IPC. Distinct
/// from [`CredentialStatus`] (the audit lens): the list adds an explicit
/// `None` bucket for credential-less apps, and any credential valid beyond
/// [`EXPIRY_WARNING_DAYS`] reads as `Active` even alongside an expired sibling
/// — an inventory lens, not a risk lens. Serialized lowercase to match the
/// list's filter-chip facet values exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListCredentialStatus {
    Active,
    Expiring,
    Expired,
    None,
}

impl ListCredentialStatus {
    /// The filter-chip facet value this status answers to.
    pub fn as_facet(&self) -> &'static str {
        match self {
            ListCredentialStatus::Active => "active",
            ListCredentialStatus::Expiring => "expiring",
            ListCredentialStatus::Expired => "expired",
            ListCredentialStatus::None => "none",
        }
    }

    /// Classifies a principal's secret + certificate expiries at `now`
    /// (injectable so the time-based classification is unit-testable).
    /// Credentials without an end date are ignored — an app holding only
    /// those classifies as `None`.
    pub fn classify(
        passwords: &[PasswordCredential],
        certs: &[KeyCredential],
        now: DateTime<Utc>,
    ) -> Self {
        let mut has_any = false;
        let mut any_active = false;
        let mut any_expiring = false;

        for cred in passwords
            .iter()
            .filter_map(|c| c.end_date_time)
            .chain(certs.iter().filter_map(|c| c.end_date_time))
        {
            has_any = true;
            let days = (cred - now).num_days();
            if days > EXPIRY_WARNING_DAYS {
                any_active = true;
            } else if (0..=EXPIRY_WARNING_DAYS).contains(&days) {
                any_expiring = true;
            }
        }

        if !has_any {
            ListCredentialStatus::None
        } else if any_active {
            ListCredentialStatus::Active
        } else if any_expiring {
            ListCredentialStatus::Expiring
        } else {
            ListCredentialStatus::Expired
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialKind {
    Secret,
    Certificate,
}

impl CredentialKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            CredentialKind::Secret => "Secret",
            CredentialKind::Certificate => "Certificate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialSummary {
    pub name: String,
    pub kind: CredentialKind,
    pub start_date_time: Option<DateTime<Utc>>,
    pub end_date_time: Option<DateTime<Utc>>,
    pub days_to_expiry: Option<i64>,
    pub status: CredentialStatus,
}

/// Effective Exchange-mailbox scoping verdict for a single Graph mail/calendar/
/// contacts application permission. Only that permission family is scopable via
/// Exchange RBAC for Applications; everything else is org-wide by nature.
///
/// How a mail permission's access is confined to specific mailboxes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMechanism {
    /// Exchange RBAC for Applications (a management scope + scoped role
    /// assignment) — the recommended, current model. The default.
    #[default]
    Rbac,
    /// A legacy Application Access Policy (`New-ApplicationAccessPolicy`). Still
    /// effective, but deprecated — surfaced so it can be migrated to RBAC.
    LegacyApplicationAccessPolicy,
}

/// The verdict is *effective*, not declared: it must account for the union of
/// the org-wide Entra app-role grant and any Exchange RBAC role assignment.
/// `Test-ServicePrincipalAuthorization` reports only the Exchange RBAC layer;
/// the Entra-grant half is reconciled separately (`held_orgwide_mail_grants` +
/// `reconcile_orgwide_grant` in `commands::exchange`), so a scoped RBAC
/// verdict coexisting with an un-stripped org-wide grant resolves to
/// `OrgWide`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MailPermissionScope {
    /// Not an Exchange-scopable mail permission — scoping does not apply.
    NotScopable,
    /// Scopable, but effective access reaches every mailbox in the tenant (no
    /// confining Exchange RBAC scope, or an org-wide grant wins the union).
    OrgWide,
    /// Confined to specific mailboxes — either via an Exchange management scope
    /// (RBAC for Applications) or a legacy Application Access Policy (the
    /// `mechanism` field distinguishes the two).
    Scoped {
        /// The Exchange management scope name (e.g. `azapptoolkit_<app-id>`),
        /// or the legacy policy's scope group.
        scope_name: Option<String>,
        /// The scope's OPATH recipient filter, when resolved (display only).
        recipient_filter: Option<String>,
        /// Number of `MemberOfGroup` clauses in the filter, when resolved.
        group_count: Option<u32>,
        /// Which scoping model confines the access — RBAC for Applications (the
        /// recommended model) or a legacy Application Access Policy.
        #[serde(default)]
        mechanism: ScopeMechanism,
    },
    /// Could not be determined — Exchange unavailable / caller is not an
    /// Exchange admin / `Exchange.Manage` not consented / the call failed.
    /// Scored as `OrgWide` (never *under*-report risk) but labeled "unknown".
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppPermissions {
    /// Values (e.g. `User.Read.All`) of Role-type entries on the app's
    /// `requiredResourceAccess`. Resolved from the bundled catalog / Graph.
    pub app_role_values: Vec<String>,
    /// Values of Scope-type entries.
    pub scope_values: Vec<String>,
    /// True if at least one `oauth2PermissionGrants` row has
    /// `consentType=AllPrincipals` (admin-consented delegated permission).
    pub has_admin_consent: bool,
    /// Effective Exchange-mailbox scoping per scopable mail permission `value`.
    /// Empty (the default) means scoping was not resolved — every mail
    /// permission is then scored at its full org-wide weight, i.e. exactly the
    /// behavior before scope-awareness was added (e.g. the signed-in user lacks
    /// the Exchange-admin rights the per-app RBAC probe needs).
    #[serde(default)]
    pub mail_scopes: HashMap<String, MailPermissionScope>,
}

impl AppPermissions {
    /// True when `value` is a mail permission that has been *confirmed* scoped
    /// to specific mailboxes via Exchange RBAC, so it earns the reduced weight.
    /// `OrgWide`/`Unknown`/absent all return false (full weight).
    pub(super) fn is_scoped(&self, value: &str) -> bool {
        matches!(
            self.mail_scopes.get(value),
            Some(MailPermissionScope::Scoped { .. })
        )
    }
}

/// A machine-actionable remediation a finding suggests — the structured
/// counterpart to the free-text `recommendations`. Drives the audit view's
/// one-click "Fix" buttons. Only findings whose fix maps to a safe, existing
/// mutation get one; everything else stays advisory text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationKind {
    /// Remove every *expired* secret/certificate on the app registration.
    /// Safe: an expired credential can't authenticate, so removing it can't
    /// break a working sign-in. The backend re-resolves the live expired set
    /// before acting — the snapshot here is advisory.
    RemoveExpiredCredentials,
    /// Confine org-wide mailbox permissions (Rule 11) to specific groups via
    /// Exchange RBAC for Applications. The "Fix" opens a guided group picker;
    /// the backend delegates to the same grant-before-strip scoping core, so the
    /// app is never left with no mailbox access. Needs admin-supplied groups.
    ScopeMailboxAccess,
    /// Convert org-wide `Sites.*` permissions (Rule 12) to the `Sites.Selected`
    /// model on admin-supplied site URLs. The backend delegates to the shared
    /// convert-to-selected core (grant per-site access before stripping the
    /// broad grant). Needs admin-supplied site URLs (Graph has no reverse
    /// appId→sites lookup).
    ScopeSharePointAccess,
    /// Remove *redundant* application permissions (Rule 18) — narrower
    /// permissions whose access a broader held permission already fully covers
    /// (e.g. `Mail.Read` alongside `Mail.ReadWrite`). Safe: Graph authorizes
    /// app-only calls by the union of granted roles, so the broader role keeps
    /// authorizing every call the narrower one did. The backend re-resolves the
    /// live manifest + grants and removes a narrower permission's grant only
    /// while a covering broader grant is still present.
    RemoveRedundantPermissions,
    /// Add an owner to an app with the Rule-14 ownership gap (no owners, or a
    /// single owner). Safe: purely additive — granting ownership can't break a
    /// working sign-in or revoke access. The "Fix" opens a guided user picker;
    /// the existing add-owner mutation does the write.
    AddOwner,
    /// Disable sign-in for an *unused* app (no sign-in past [`UNUSED_APP_DAYS`])
    /// by setting `accountEnabled: false` on its service principal. Safe because
    /// it is reversible — re-enable any time from the enterprise app's Overview.
    /// Attached by the audit *runner*, not `score_application`: `unused` is a
    /// runner post-pass flag (the sign-in report is fetched separately).
    DisableSignIn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemediationAction {
    pub kind: RemediationKind,
    /// Button label, e.g. "Remove 2 expired credentials".
    pub label: String,
    /// In-row preview of what will be affected (e.g. the credential names),
    /// shown beside the button because the confirm dialog body is static.
    pub detail: String,
    /// The specific permission `value`s the fix targets — passed to the scoping
    /// command (e.g. which mail permissions to confine). Empty for fixes that
    /// re-resolve their own target set live (remove-expired-credentials).
    #[serde(default)]
    pub targets: Vec<String>,
}

/// What kind of principal an [`AuditItem`] row scores — an application
/// registration (with its local manifest + credentials) or a service principal
/// with **no local application object** (a foreign-tenant enterprise app, a
/// managed identity, or an orphaned SP whose app registration was deleted).
/// Drives the audit view's routing: SP rows open the enterprise/MI detail and
/// their Fix buttons call the SP-only scoping commands; app-registration bulk
/// actions must never receive an SP row's `object_id`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditPrincipalKind {
    /// A local application registration; `object_id` is the application
    /// object id. The default, so pre-existing cached runs deserialize as-is.
    #[default]
    Application,
    /// A service principal with no local application; `object_id` is the SP
    /// object id.
    ServicePrincipal,
    /// A managed identity (also SP-only, but opens the MI detail).
    ManagedIdentity,
}

impl AuditPrincipalKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditPrincipalKind::Application => "Application",
            AuditPrincipalKind::ServicePrincipal => "ServicePrincipal",
            AuditPrincipalKind::ManagedIdentity => "ManagedIdentity",
        }
    }
}

/// One scored application — the audit's output row.
///
/// **Boundary note:** unlike most command payloads, `AuditItem` does not get a
/// DTO — it is serialized across the Tauri IPC bridge *as-is* (the WASM
/// frontend deserializes this same type), embedded in
/// `azapptoolkit_dto::audit::AuditRunResult`, and written verbatim into the
/// JSON export. Renaming a field here is therefore a wire-format change. The
/// whole payload is snake_case (no serde rename on this struct or its nested
/// remediation/scope types).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditItem {
    pub application_name: String,
    pub app_id: String,
    pub object_id: String,
    pub created_date: Option<DateTime<Utc>>,
    pub publisher: Option<String>,
    pub sign_in_audience: Option<String>,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub issues: Vec<String>,
    pub recommendations: Vec<String>,
    /// Structured one-click fixes derived from the findings (see
    /// [`RemediationAction`]). Empty when nothing is safely auto-remediable.
    pub remediations: Vec<RemediationAction>,
    pub credential_status: CredentialStatus,
    pub permission_count: u32,
    pub service_principal_enabled: Option<bool>,
    pub days_since_created: Option<i64>,
    pub certificates: Vec<CredentialSummary>,
    pub secrets: Vec<CredentialSummary>,
    /// Last observed interactive/app sign-in for this app's service principal,
    /// from the sign-in activity report. `None` = no sign-in recorded *or* the
    /// report was unavailable — disambiguate with [`Self::sign_in_report_available`].
    /// Set by the audit runner after [`score_application`]; defaults to `None`.
    #[serde(default)]
    pub last_sign_in: Option<DateTime<Utc>>,
    /// `true` when the app is flagged unused (no sign-in past [`UNUSED_APP_DAYS`]),
    /// the structured equivalent of the free-text unused advisory. Drives the
    /// audit view's "Unused" facet without parsing issue text.
    #[serde(default)]
    pub unused: bool,
    /// Whether the sign-in activity report was available for this run (needs
    /// `AuditLog.Read.All` + Entra ID P1/P2). When `false`, [`Self::last_sign_in`]
    /// /[`Self::unused`] carry no signal and the UI shows a "report unavailable"
    /// state instead of a blank Unused tab.
    #[serde(default)]
    pub sign_in_report_available: bool,
    /// Which kind of principal this row scores (see [`AuditPrincipalKind`]).
    /// Defaults to `Application` so cached runs from before the field existed
    /// deserialize unchanged.
    #[serde(default)]
    pub principal_kind: AuditPrincipalKind,
}

/// Stable markers the UI keys audit facets/home cards off. The scorer emits
/// issues that **start with** these (or, for [`issue::SCOPED_VIA_RBAC`],
/// *contain* it); the frontend matches the same constants instead of repeating
/// the literals, so a wording change can't silently zero a facet. The
/// `emitted_issue_markers_are_stable` test asserts the scorer still emits each,
/// tying these constants to `score_application`'s output.
pub mod issue {
    pub const HIGH_RISK_APP_PERMS: &str = "High-risk application permissions:";
    pub const HIGH_RISK_DELEGATED_PERMS: &str = "High-risk delegated permissions:";
    pub const ORG_WIDE_MAILBOX: &str = "Organization-wide mailbox access";
    /// Substring shared by every "…scoped via RBAC for Applications…" advisory.
    pub const SCOPED_VIA_RBAC: &str = "scoped via RBAC for Applications";
    pub const ORG_WIDE_SHAREPOINT: &str = "Organization-wide SharePoint access";
    pub const SCOPED_SHAREPOINT: &str = "SharePoint access scoped to selected sites";
    pub const NO_OWNERS: &str = "No owners assigned";
    pub const SINGLE_OWNER: &str = "Single owner";
    pub const INSTANCE_LOCK_DISABLED: &str = "App instance property lock is not fully enabled";
    pub const PUBLIC_CLIENT_CREDENTIALS: &str =
        "Public client flows are enabled and credentials are present";
    pub const PREFER_CERT_OVER_SECRET: &str = "Uses client secret(s)";
    pub const REDUNDANT_APP_PERMS: &str = "Redundant application permissions:";
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 22, 12, 0, 0).unwrap()
    }

    #[test]
    fn list_credential_status_classifies_by_expiry_window() {
        let now = now();
        let secret = |days: i64| PasswordCredential {
            end_date_time: Some(now + Duration::days(days)),
            ..Default::default()
        };
        let classify = |p: &[PasswordCredential], c: &[KeyCredential]| {
            ListCredentialStatus::classify(p, c, now)
        };
        assert_eq!(classify(&[], &[]), ListCredentialStatus::None);
        assert_eq!(classify(&[secret(60)], &[]), ListCredentialStatus::Active);
        assert_eq!(classify(&[secret(7)], &[]), ListCredentialStatus::Expiring);
        assert_eq!(classify(&[secret(-1)], &[]), ListCredentialStatus::Expired);
        // Any credential valid for >30d wins, even alongside an expired one.
        assert_eq!(
            classify(&[secret(60), secret(-1)], &[]),
            ListCredentialStatus::Active
        );
        // A cert counts the same as a secret.
        let cert = KeyCredential {
            end_date_time: Some(now + Duration::days(10)),
            ..Default::default()
        };
        assert_eq!(classify(&[], &[cert]), ListCredentialStatus::Expiring);
        // Lowercase serde + facet strings line up with the filter chips.
        assert_eq!(
            serde_json::to_string(&ListCredentialStatus::Expiring).unwrap(),
            "\"expiring\""
        );
        assert_eq!(ListCredentialStatus::Expiring.as_facet(), "expiring");
    }

    #[test]
    fn level_thresholds_match_ps() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(7), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(8), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(14), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(15), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(24), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(25), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(999), RiskLevel::Critical);
    }
}
