//! Security audit risk scoring.
//!
//! Ported rule-for-rule from the original `azapptoolkit` PowerShell module's
//! audit risk analysis. Every numeric constant below was chosen to match that
//! module; change one only after updating the corresponding test in the owning
//! submodule.
//!
//! The scoring function is pure: it takes an [`Application`] plus already-
//! resolved dependencies (SP, permission names, granted-consent flag) and
//! returns an [`AuditItem`]. The Tauri layer owns the orchestration — fetching
//! those dependencies, streaming concurrent scans, caching results, emitting
//! progress events.

mod credentials;
mod permissions;
mod scoring;
mod types;

pub use credentials::{
    SignInStatus, expired_password_key_ids, is_expired, summarize_credentials, unused_app_advisory,
};
pub use permissions::{
    EXPIRY_WARNING_DAYS, HIGH_RISK_APP_PERMISSIONS, HIGH_RISK_DELEGATED_PERMISSIONS,
    LONG_LIVED_SECRET_DAYS, MEDIUM_RISK_APP_PERMISSIONS, RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM,
    STALE_APP_DAYS, UNUSED_APP_DAYS, classify_app_permission_risk, downgrade_alternatives,
    is_risky_delegated_scope, least_privilege_alternative, redundant_app_permissions,
    risk_level_for_app_permission, subsuming_app_permissions,
};
pub use scoring::{
    SpAuditInput, disable_sign_in_remediation, score_application, score_service_principal,
};
pub use types::{
    AppPermissions, AuditItem, AuditPrincipalKind, CredentialKind, CredentialStatus,
    CredentialSummary, ListCredentialStatus, MailPermissionScope, RemediationAction,
    RemediationKind, RiskLevel, ScopeMechanism, issue,
};
