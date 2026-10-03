//! Security audit risk scoring.
//!
//! Ported rule-for-rule from the original `azapptoolkit` PowerShell module's
//! audit risk analysis (`Constants.ps1`, `Credential-Analysis.ps1`,
//! `Resource-Analysis.ps1`). That module is **not vendored in this repository**
//! and no URL or commit for it is recorded, so the `file:line` citations here
//! and in the tests are provenance notes from the port, not references a
//! reviewer can check. Every constant that cites a `.ps1` line (in
//! `permissions.rs`) matches that module; change one only after updating the
//! corresponding test in the owning submodule. Net-new rules, weights and list
//! entries say so where they are defined.
//!
//! The numbered rules (1–22) with their helper, weight, issue marker, finding
//! key, remediation and provenance are catalogued in
//! `docs/architecture/audit-findings-and-remediation.md` ("Rule catalog").
//!
//! The scoring function is pure: it takes an [`crate::models::Application`] plus already-
//! resolved dependencies (SP, permission names, granted-consent flag) and
//! returns an [`AuditItem`]. The Tauri layer owns the orchestration — fetching
//! those dependencies, streaming concurrent scans, caching results, emitting
//! progress events.

mod credentials;
mod finding;
mod permissions;
mod posture;
mod scoring;
mod types;

pub use credentials::{
    CredentialActivity, SignInStatus, expired_password_key_ids, is_expired, summarize_credentials,
    unused_app_advisory, unused_credential_advisory,
};
pub use finding::{finding_issue_marker, matches_finding};
pub use permissions::{
    EXPIRY_WARNING_DAYS, HIGH_RISK_APP_PERMISSIONS, HIGH_RISK_DELEGATED_PERMISSIONS,
    LONG_LIVED_SECRET_DAYS, MEDIUM_RISK_APP_PERMISSIONS, RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM,
    STALE_APP_DAYS, UNUSED_APP_DAYS, UNUSED_CREDENTIAL_DAYS, classify_app_permission_risk,
    downgrade_alternatives, is_risky_delegated_scope, least_privilege_alternative_for,
    redundant_app_permissions, risk_level_for_app_permission, subsuming_app_permissions,
};
pub use posture::{POSTURE_FINDING_KEYS, PostureCounts, finding_worst, posture_counts};
pub use scoring::{
    SpAuditInput, apply_service_principal_risk, disable_sign_in_remediation, score_application,
    score_service_principal,
};
pub use types::{
    AppPermissions, AuditItem, AuditPrincipalKind, CredentialKind, CredentialStatus,
    CredentialSummary, ListCredentialStatus, MailPermissionScope, RemediationAction,
    RemediationKind, ResourcePermission, RiskLevel, ScopeMechanism, issue,
};
