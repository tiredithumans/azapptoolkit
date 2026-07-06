//! The rule helpers and the two scoring entry points ([`score_application`]
//! and [`score_service_principal`]) that fold them into an [`AuditItem`].

use chrono::{DateTime, Utc};

use crate::models::Application;

use super::*;
// Sibling internals `mod.rs` deliberately does not re-export: the PTS_*
// score weights and the credential-status folding helpers.
use super::credentials::{is_long_lived, overall_credential_status};
use super::permissions::{
    PTS_ADMIN_CONSENT_DELEGATED, PTS_ALL_CREDS_EXPIRED, PTS_ALL_EXPIRING_SOON,
    PTS_HIGH_RISK_APP_PERM, PTS_LONG_LIVED, PTS_MEDIUM_RISK_APP_PERM, PTS_MIXED_EXPIRED,
    PTS_MIXED_EXPIRING, PTS_SCOPED_HIGH_RISK_MAIL, PTS_SCOPED_MEDIUM_RISK_MAIL, PTS_SP_DISABLED,
    PTS_STALE_APP,
};

/// Builds an [`AuditItem`] for `app`. All inputs must be pre-resolved: the
/// caller is responsible for turning Graph IDs into permission name strings
/// (via the bundled catalog or a live lookup).
///
/// `now` is a parameter so tests can use deterministic timestamps.
/// One scoring rule's contribution: a risk-score delta plus the issues and
/// recommendations it raises. Each `rule_*` helper returns one; `score_application`
/// folds them in rule order so the issue / recommendation ordering is preserved
/// by construction.
#[derive(Default)]
struct RuleContribution {
    score: u32,
    issues: Vec<String>,
    recommendations: Vec<String>,
}

impl RuleContribution {
    /// Folds another rule's contribution into this one, in call order.
    fn merge(&mut self, other: RuleContribution) {
        self.score += other.score;
        self.issues.extend(other.issues);
        self.recommendations.extend(other.recommendations);
    }
}

/// Rules 1 & 2: high- and medium-risk application permissions. A high/medium-risk
/// *mail* permission confirmed scoped to specific mailboxes via Exchange RBAC
/// earns the reduced scoped weight instead. With an empty `mail_scopes` (scoping
/// not resolved) every hit is treated as org-wide — byte-for-byte the original.
fn rule_app_permission_risk(perms: &AppPermissions) -> RuleContribution {
    let mut c = RuleContribution::default();

    let high_hits: Vec<&String> = perms
        .app_role_values
        .iter()
        .filter(|v| HIGH_RISK_APP_PERMISSIONS.contains(&v.as_str()))
        .collect();
    let (high_scoped, high_full): (Vec<&String>, Vec<&String>) =
        high_hits.into_iter().partition(|v| perms.is_scoped(v));
    if !high_full.is_empty() {
        c.score += PTS_HIGH_RISK_APP_PERM * high_full.len() as u32;
        c.issues.push(format!(
            "High-risk application permissions: {}",
            join_refs(&high_full)
        ));
        c.recommendations.push(
            "Review necessity of high-risk permissions and consider principle of least privilege"
                .to_string(),
        );
    }
    if !high_scoped.is_empty() {
        c.score += PTS_SCOPED_HIGH_RISK_MAIL * high_scoped.len() as u32;
        c.issues.push(format!(
            "High-risk mailbox permissions scoped via RBAC for Applications (reduced risk): {}",
            join_refs(&high_scoped)
        ));
    }

    let medium_hits: Vec<&String> = perms
        .app_role_values
        .iter()
        .filter(|v| MEDIUM_RISK_APP_PERMISSIONS.contains(&v.as_str()))
        .collect();
    let (medium_scoped, medium_full): (Vec<&String>, Vec<&String>) =
        medium_hits.into_iter().partition(|v| perms.is_scoped(v));
    if !medium_full.is_empty() {
        c.score += PTS_MEDIUM_RISK_APP_PERM * medium_full.len() as u32;
        c.issues.push(format!(
            "Medium-risk application permissions: {}",
            join_refs(&medium_full)
        ));
    }
    if !medium_scoped.is_empty() {
        c.score += PTS_SCOPED_MEDIUM_RISK_MAIL * medium_scoped.len() as u32;
        c.issues.push(format!(
            "Medium-risk mailbox permissions scoped via RBAC for Applications (reduced risk): {}",
            join_refs(&medium_scoped)
        ));
    }
    c
}

/// Rules 5/6 (expired), 8/9 (expiring-soon, only when nothing is expired), and
/// 7 (long-lived secrets), emitted in that order. Takes the precomputed
/// credential subsets — `expired` is also consumed by the remediation block, so
/// it is resolved once in `score_application`.
fn rule_credentials(
    expired: &[&CredentialSummary],
    expiring: &[&CredentialSummary],
    active_count: usize,
    long_lived: &[&CredentialSummary],
) -> RuleContribution {
    let mut c = RuleContribution::default();
    if !expired.is_empty() && active_count == 0 {
        c.score += PTS_ALL_CREDS_EXPIRED;
        c.issues
            .push(format!("All credentials expired: {}", join_names(expired)));
        c.recommendations
            .push("Remove expired credentials and update authentication configuration".to_string());
    } else if !expired.is_empty() {
        c.score += PTS_MIXED_EXPIRED;
        c.issues.push(format!(
            "Mixed credential status: {} are expired but {} credentials are active",
            join_names(expired),
            active_count
        ));
        c.recommendations.push(
            "Remove expired credentials to clean up authentication configuration".to_string(),
        );
    }
    if expired.is_empty() {
        if !expiring.is_empty() && active_count == 0 {
            c.score += PTS_ALL_EXPIRING_SOON;
            c.issues.push(format!(
                "All credentials expiring soon: {}",
                join_names(expiring)
            ));
            c.recommendations
                .push("Plan credential renewal for expiring certificates/secrets".to_string());
        } else if !expiring.is_empty() {
            c.score += PTS_MIXED_EXPIRING;
            c.issues.push(format!(
                "Credentials expiring soon: {} but {} credentials are active",
                join_names(expiring),
                active_count
            ));
            c.recommendations
                .push("Plan credential renewal for expiring certificates/secrets".to_string());
        }
    }
    if !long_lived.is_empty() {
        c.score += PTS_LONG_LIVED;
        c.issues.push(format!(
            "Long-lived secrets (>1 year): {}",
            join_names(long_lived)
        ));
        c.recommendations
            .push("Consider shorter credential lifespans and automated rotation".to_string());
    }
    c
}

/// Rule 3: admin consent on delegated permissions (+5 flat).
fn rule_admin_consent(perms: &AppPermissions) -> RuleContribution {
    let mut c = RuleContribution::default();
    if perms.has_admin_consent {
        c.score += PTS_ADMIN_CONSENT_DELEGATED;
        c.issues
            .push("Admin consent granted for delegated permissions".to_string());
        c.recommendations.push(
            "Review delegated permissions with admin consent - consider user consent where appropriate"
                .to_string(),
        );
    }
    c
}

/// Rule 4: service principal disabled (+2).
fn rule_sp_disabled(sp_enabled: Option<bool>) -> RuleContribution {
    let mut c = RuleContribution::default();
    if matches!(sp_enabled, Some(false)) {
        c.score += PTS_SP_DISABLED;
        c.issues.push("Service principal is disabled".to_string());
        c.recommendations
            .push("Enable service principal if application is actively used".to_string());
    }
    c
}

/// Rule 10: stale application (created more than [`STALE_APP_DAYS`] ago).
fn rule_stale_app(days_since_created: Option<i64>) -> RuleContribution {
    let mut c = RuleContribution::default();
    if let Some(days) = days_since_created
        && days > STALE_APP_DAYS
    {
        c.score += PTS_STALE_APP;
        c.issues.push(format!(
            "Application created {days} days ago - consider if still needed"
        ));
        c.recommendations
            .push("Review application usage and consider removal if no longer needed".to_string());
    }
    c
}

/// Rule 11 (advisory, no score): organization-wide mailbox access — broad
/// `Mail.*` reach every mailbox unless scoped via Exchange RBAC. Returns the
/// org-wide (unscoped) set for the ScopeMailboxAccess remediation. Empty
/// `mail_scopes` ⇒ every hit is org-wide ⇒ original behavior.
fn rule_mailbox_advisory(perms: &AppPermissions) -> (RuleContribution, Vec<&String>) {
    let mut c = RuleContribution::default();
    let mailbox_hits: Vec<&String> = perms
        .app_role_values
        .iter()
        .filter(|v| v.starts_with("Mail.") || v.starts_with("MailboxSettings."))
        .collect();
    let (mailbox_scoped, mailbox_unscoped): (Vec<&String>, Vec<&String>) =
        mailbox_hits.into_iter().partition(|v| perms.is_scoped(v));
    if !mailbox_unscoped.is_empty() {
        c.issues.push(format!(
            "Organization-wide mailbox access: {}",
            join_refs(&mailbox_unscoped)
        ));
        c.recommendations.push(
            "Scope mailbox access to specific mailboxes using RBAC for Applications".to_string(),
        );
    }
    if !mailbox_scoped.is_empty() {
        c.issues.push(format!(
            "Mailbox access scoped via RBAC for Applications: {}",
            join_refs(&mailbox_scoped)
        ));
    }
    (c, mailbox_unscoped)
}

/// Rule 12 (advisory, no score): organization-wide SharePoint access. SharePoint
/// scoping is encoded by the permission itself (`Sites.Selected` is scoped,
/// every other `Sites.*` is org-wide), so no live lookup is needed. Returns the
/// org-wide set for the ScopeSharePointAccess remediation.
fn rule_sharepoint_advisory(perms: &AppPermissions) -> (RuleContribution, Vec<&String>) {
    let mut c = RuleContribution::default();
    let sharepoint_orgwide: Vec<&String> = perms
        .app_role_values
        .iter()
        .filter(|v| crate::scoping::is_sharepoint_orgwide(v))
        .collect();
    if !sharepoint_orgwide.is_empty() {
        c.issues.push(format!(
            "Organization-wide SharePoint access: {}",
            join_refs(&sharepoint_orgwide)
        ));
        c.recommendations
            .push("Restrict SharePoint access to specific sites using Sites.Selected".to_string());
    }
    if perms
        .app_role_values
        .iter()
        .any(|v| v.as_str() == "Sites.Selected")
    {
        c.issues
            .push("SharePoint access scoped to selected sites: Sites.Selected".to_string());
    }
    (c, sharepoint_orgwide)
}

/// Rule 13 (advisory, no score): high-risk delegated permissions. The legacy
/// module weighted delegated permissions only via the admin-consent check
/// (Rule 3), so this surfaces the specific scopes without altering the score.
fn rule_high_risk_delegated(perms: &AppPermissions) -> RuleContribution {
    let mut c = RuleContribution::default();
    let high_risk_delegated: Vec<&String> = perms
        .scope_values
        .iter()
        .filter(|v| HIGH_RISK_DELEGATED_PERMISSIONS.contains(&v.as_str()))
        .collect();
    if !high_risk_delegated.is_empty() {
        c.issues.push(format!(
            "High-risk delegated permissions: {}",
            join_refs(&high_risk_delegated)
        ));
        c.recommendations.push(
            "Review high-risk delegated permissions; prefer narrowly-scoped delegated permissions and user consent where appropriate"
                .to_string(),
        );
    }
    c
}

/// Rules 14-17 (advisory, no score), in emit order: ownership hygiene, the
/// app-instance property lock, public-client flows with credentials, and the
/// prefer-cert guidance. The booleans are precomputed in `score_application`
/// (where `all_creds`/`secrets` already exist).
fn rule_app_hygiene(
    app: &Application,
    has_app_permissions: bool,
    has_credentials: bool,
    has_secrets: bool,
) -> RuleContribution {
    let mut c = RuleContribution::default();
    // Rule 14: ownership. `None` = owners not fetched, so skip rather than flag.
    if let Some(owners) = &app.owners {
        match owners.len() {
            0 => {
                c.issues
                    .push("No owners assigned — ownership/accountability gap".to_string());
                c.recommendations.push(
                    "Assign at least one owner so the application has clear accountability"
                        .to_string(),
                );
            }
            1 => {
                c.issues
                    .push("Single owner — vulnerable to owner departure".to_string());
                c.recommendations.push(
                    "Assign a second owner to avoid losing management access if the sole owner leaves"
                        .to_string(),
                );
            }
            _ => {}
        }
    }
    // Rule 15: app instance property lock — only for apps that hold app
    // permissions or credentials (where an injected credential is dangerous).
    let lock_fully_set = app
        .service_principal_lock_configuration
        .as_ref()
        .is_some_and(|l| l.is_fully_locked());
    if !lock_fully_set && (has_app_permissions || has_credentials) {
        c.issues.push(format!(
            "{} — credentials could be added to the service principal to abuse its permissions",
            issue::INSTANCE_LOCK_DISABLED
        ));
        c.recommendations.push(
            "Enable the app instance property lock for all sensitive properties (servicePrincipalLockConfiguration) — especially for multitenant apps, where a foreign tenant's admin could otherwise add credentials to the service principal"
                .to_string(),
        );
    }
    // Rule 16: public-client flows enabled while credentials are present.
    if app.is_fallback_public_client == Some(true) && has_credentials {
        c.issues.push(format!(
            "{} — if this app is used only as a public/installed client, the credentials should be removed",
            issue::PUBLIC_CLIENT_CREDENTIALS
        ));
        c.recommendations.push(
            "If this app is used only as a public/installed client, remove its client secrets/certificates — public clients authenticate without app credentials. (A confidential app that merely allows public-client flows can keep them.)"
                .to_string(),
        );
    }
    // Rule 17: prefer certificates / federation over client secrets.
    if has_secrets {
        c.issues.push(format!(
            "{} — less secure than certificates or federated credentials",
            issue::PREFER_CERT_OVER_SECRET
        ));
        c.recommendations.push(
            "Prefer a certificate or federated identity credential over client secrets where possible"
                .to_string(),
        );
    }
    c
}

/// Rule 18 (advisory, no score): redundant application permissions — a narrower
/// permission a broader held permission already fully covers. Returns the
/// redundancy list for the RemoveRedundantPermissions remediation.
fn rule_redundant_permissions(
    perms: &AppPermissions,
) -> (RuleContribution, Vec<(String, Vec<String>)>) {
    let mut c = RuleContribution::default();
    let redundant = redundant_app_permissions(&perms.app_role_values, |b| perms.is_scoped(b));
    if !redundant.is_empty() {
        let listing = redundant
            .iter()
            .map(|(narrower, covered_by)| {
                format!("{narrower} (covered by {})", covered_by.join(", "))
            })
            .collect::<Vec<_>>()
            .join(", ");
        c.issues
            .push(format!("{} {listing}", issue::REDUNDANT_APP_PERMS));
        c.recommendations.push(
            "Remove redundant narrower permissions — a broader permission the app holds already grants the same access"
                .to_string(),
        );
    }
    (c, redundant)
}

/// Least-privilege downgrade pointers (recommendation only — no issue, no
/// score): names the concrete narrower alternative for each risk-flagged
/// permission so the Rule-1/2 advice is actionable. Admin-judged, so never a
/// one-click remediation.
fn rule_downgrade_pointers(perms: &AppPermissions) -> RuleContribution {
    let mut c = RuleContribution::default();
    let downgrades: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        perms
            .app_role_values
            .iter()
            .filter(|v| {
                (HIGH_RISK_APP_PERMISSIONS.contains(&v.as_str())
                    || MEDIUM_RISK_APP_PERMISSIONS.contains(&v.as_str()))
                    && seen.insert(v.as_str())
            })
            .filter_map(|v| {
                let alts = downgrade_alternatives(v);
                match alts.len() {
                    0 => None,
                    // Closest tiers only — Directory.ReadWrite.All has seven
                    // alternatives; three keep the advice readable in CSV/detail.
                    1..=3 => Some(format!("{v} → {}", alts.join(" / "))),
                    _ => Some(format!("{v} → {} / …", alts[..3].join(" / "))),
                }
            })
            .collect()
    };
    if !downgrades.is_empty() {
        c.recommendations.push(format!(
            "Narrower alternatives exist if the broader capability is unused: {}",
            downgrades.join("; ")
        ));
    }
    c
}

/// Structured one-click remediations, keyed off the same rule-computed sets
/// that raised the corresponding issues — so a "Fix" button appears exactly
/// when its finding does. The backend re-resolves live state before acting;
/// `targets`/`detail` are the advisory preview. Emitted in a fixed order:
/// remove-expired, scope-mailbox, scope-SharePoint, remove-redundant,
/// add-owner. `owner_count` is the same `app.owners` data Rule 14 keys off
/// (`None` = owners not fetched — SP-only rows — so no AddOwner is attached).
fn build_remediations(
    expired: &[&CredentialSummary],
    mailbox_unscoped: &[&String],
    sharepoint_orgwide: &[&String],
    redundant: &[(String, Vec<String>)],
    owner_count: Option<usize>,
) -> Vec<RemediationAction> {
    let mut remediations: Vec<RemediationAction> = Vec::new();
    if !expired.is_empty() {
        let n = expired.len();
        remediations.push(RemediationAction {
            kind: RemediationKind::RemoveExpiredCredentials,
            label: format!(
                "Remove {n} expired credential{}",
                if n == 1 { "" } else { "s" }
            ),
            detail: format!("Removes: {}", join_names(expired)),
            targets: Vec::new(),
        });
    }
    if !mailbox_unscoped.is_empty() {
        let n = mailbox_unscoped.len();
        remediations.push(RemediationAction {
            kind: RemediationKind::ScopeMailboxAccess,
            label: format!(
                "Scope {n} mailbox permission{} to specific mailboxes",
                if n == 1 { "" } else { "s" }
            ),
            detail: format!(
                "Confines via Exchange RBAC: {}",
                join_refs(mailbox_unscoped)
            ),
            targets: mailbox_unscoped.iter().map(|v| v.to_string()).collect(),
        });
    }
    if !sharepoint_orgwide.is_empty() {
        let n = sharepoint_orgwide.len();
        remediations.push(RemediationAction {
            kind: RemediationKind::ScopeSharePointAccess,
            label: format!(
                "Restrict {n} SharePoint permission{} to selected sites",
                if n == 1 { "" } else { "s" }
            ),
            detail: format!(
                "Converts to Sites.Selected: {}",
                join_refs(sharepoint_orgwide)
            ),
            targets: sharepoint_orgwide.iter().map(|v| v.to_string()).collect(),
        });
    }
    if !redundant.is_empty() {
        let n = redundant.len();
        remediations.push(RemediationAction {
            kind: RemediationKind::RemoveRedundantPermissions,
            label: format!(
                "Remove {n} redundant permission{}",
                if n == 1 { "" } else { "s" }
            ),
            detail: format!(
                "Removes: {}",
                redundant
                    .iter()
                    .map(|(narrower, _)| narrower.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            targets: redundant.iter().map(|(n, _)| n.clone()).collect(),
        });
    }
    match owner_count {
        Some(0) => remediations.push(RemediationAction {
            kind: RemediationKind::AddOwner,
            label: "Add an owner".to_string(),
            detail: "No owners assigned — ownership/accountability gap".to_string(),
            targets: Vec::new(),
        }),
        Some(1) => remediations.push(RemediationAction {
            kind: RemediationKind::AddOwner,
            label: "Add a second owner".to_string(),
            detail: "Single owner — vulnerable to owner departure".to_string(),
            targets: Vec::new(),
        }),
        _ => {}
    }
    remediations
}

/// The [`RemediationKind::DisableSignIn`] action for an unused app. Pushed by
/// the audit runner's sign-in post-pass (where `unused` is set), not by
/// [`score_application`] — the sign-in report is resolved after scoring.
pub fn disable_sign_in_remediation() -> RemediationAction {
    RemediationAction {
        kind: RemediationKind::DisableSignIn,
        label: "Disable sign-in".to_string(),
        detail: "No recent sign-in activity — disables the service principal (reversible)"
            .to_string(),
        targets: Vec::new(),
    }
}

pub fn score_application(
    app: &Application,
    sp_enabled: Option<bool>,
    perms: &AppPermissions,
    now: DateTime<Utc>,
) -> AuditItem {
    // Each rule is a focused `rule_*` helper; `acc` folds their contributions
    // in call order, so the issue / recommendation ordering is preserved by
    // construction (pinned by the characterization tests).
    let mut acc = RuleContribution::default();
    acc.merge(rule_app_permission_risk(perms)); // Rules 1 & 2
    acc.merge(rule_admin_consent(perms)); // Rule 3
    acc.merge(rule_sp_disabled(sp_enabled)); // Rule 4

    // Credential subsets are resolved once: the credential rules consume them,
    // and `expired` is reused by the remediation block below.
    let (secrets, certificates) = summarize_credentials(app, now);
    let all_creds: Vec<&CredentialSummary> = secrets.iter().chain(certificates.iter()).collect();
    let overall_status = overall_credential_status(&all_creds);
    let expired: Vec<&CredentialSummary> = all_creds
        .iter()
        .copied()
        .filter(|c| c.status == CredentialStatus::Expired)
        .collect();
    let expiring: Vec<&CredentialSummary> = all_creds
        .iter()
        .copied()
        .filter(|c| c.status == CredentialStatus::ExpiringSoon)
        .collect();
    let active_count = all_creds
        .iter()
        .filter(|c| c.status == CredentialStatus::Active)
        .count();
    let long_lived: Vec<&CredentialSummary> = all_creds
        .iter()
        .copied()
        .filter(|c| is_long_lived(c))
        .collect();
    acc.merge(rule_credentials(
        &expired,
        &expiring,
        active_count,
        &long_lived,
    )); // Rules 5-9

    // Rule 10 (days_since_created is also stored on the AuditItem).
    let days_since_created = app.created_date_time.map(|c| (now - c).num_days());
    acc.merge(rule_stale_app(days_since_created));

    // Rules 11, 12, 18 also return the sets the remediation block keys off.
    let (mail_contrib, mailbox_unscoped) = rule_mailbox_advisory(perms);
    acc.merge(mail_contrib);
    let (sharepoint_contrib, sharepoint_orgwide) = rule_sharepoint_advisory(perms);
    acc.merge(sharepoint_contrib);
    acc.merge(rule_high_risk_delegated(perms)); // Rule 13

    let has_app_permissions = !perms.app_role_values.is_empty();
    let has_credentials = !all_creds.is_empty();
    acc.merge(rule_app_hygiene(
        app,
        has_app_permissions,
        has_credentials,
        !secrets.is_empty(),
    )); // Rules 14-17

    let (redundant_contrib, redundant) = rule_redundant_permissions(perms); // Rule 18
    acc.merge(redundant_contrib);
    acc.merge(rule_downgrade_pointers(perms)); // least-privilege downgrade pointers

    let permission_count = (perms.app_role_values.len() + perms.scope_values.len()) as u32;

    let remediations = build_remediations(
        &expired,
        &mailbox_unscoped,
        &sharepoint_orgwide,
        &redundant,
        app.owners.as_ref().map(Vec::len),
    );

    AuditItem {
        application_name: app.display_name.clone(),
        app_id: app.app_id.clone(),
        object_id: app.id.clone(),
        created_date: app.created_date_time,
        publisher: app.publisher_domain.clone(),
        sign_in_audience: app.sign_in_audience.clone(),
        risk_score: acc.score,
        risk_level: RiskLevel::from_score(acc.score),
        issues: acc.issues,
        recommendations: acc.recommendations,
        remediations,
        credential_status: overall_status,
        permission_count,
        service_principal_enabled: sp_enabled,
        days_since_created,
        certificates,
        secrets,
        // Sign-in fields are populated by the audit runner (the report is fetched
        // separately and is optional); `score_application` itself is sign-in-agnostic.
        last_sign_in: None,
        unused: false,
        sign_in_report_available: false,
        principal_kind: AuditPrincipalKind::Application,
    }
}

/// Inputs for scoring a service principal that has **no local application
/// object** — a foreign-tenant enterprise app, a managed identity, or an
/// orphaned local SP whose app registration was deleted. Everything is
/// pre-resolved by the caller (the audit runner), mirroring
/// [`score_application`]'s contract.
#[derive(Debug, Clone)]
pub struct SpAuditInput {
    pub display_name: String,
    pub app_id: String,
    pub sp_object_id: String,
    pub created_date_time: Option<DateTime<Utc>>,
    pub account_enabled: Option<bool>,
    /// Home tenant of the owning application — surfaced as the item's
    /// `publisher` so the table/CSV show where a foreign app lives.
    pub app_owner_organization_id: Option<String>,
    /// Graph `servicePrincipalType`; `ManagedIdentity` selects
    /// [`AuditPrincipalKind::ManagedIdentity`] (drives Open/Fix routing).
    pub service_principal_type: Option<String>,
}

/// Builds an [`AuditItem`] for a service principal with no local application
/// object. Only the rules that read *granted* state apply: permission risk
/// (Rules 1 & 2), admin consent (3), disabled SP (4), the mailbox / SharePoint
/// scoping advisories (11, 12), and high-risk delegated permissions (13).
/// Credential rules (5-9) and manifest rules (10, 14-18, downgrade pointers)
/// are deliberately absent — credentials and the manifest live on the
/// application object in its home tenant, which this tenant can neither see
/// nor fix. `perms.app_role_values` are the SP's *granted* app roles (its
/// `appRoleAssignments`), not a declared manifest.
pub fn score_service_principal(
    sp: &SpAuditInput,
    perms: &AppPermissions,
    now: DateTime<Utc>,
) -> AuditItem {
    let mut acc = RuleContribution::default();
    acc.merge(rule_app_permission_risk(perms)); // Rules 1 & 2
    acc.merge(rule_admin_consent(perms)); // Rule 3
    acc.merge(rule_sp_disabled(sp.account_enabled)); // Rule 4

    // Rules 11 & 12 also return the sets the remediation block keys off.
    let (mail_contrib, mailbox_unscoped) = rule_mailbox_advisory(perms);
    acc.merge(mail_contrib);
    let (sharepoint_contrib, sharepoint_orgwide) = rule_sharepoint_advisory(perms);
    acc.merge(sharepoint_contrib);
    acc.merge(rule_high_risk_delegated(perms)); // Rule 13

    // No expired credentials (unknowable), no redundant-permission removal
    // (its remediation edits the application manifest), and no add-owner
    // (`None`: SP owners aren't audited) — only the two scope remediations,
    // whose SP-only command cores exist.
    let remediations = build_remediations(&[], &mailbox_unscoped, &sharepoint_orgwide, &[], None);

    AuditItem {
        application_name: sp.display_name.clone(),
        app_id: sp.app_id.clone(),
        object_id: sp.sp_object_id.clone(),
        created_date: sp.created_date_time,
        publisher: sp.app_owner_organization_id.clone(),
        sign_in_audience: None,
        risk_score: acc.score,
        risk_level: RiskLevel::from_score(acc.score),
        issues: acc.issues,
        recommendations: acc.recommendations,
        remediations,
        // Credentials live on the application in its home tenant — unknowable
        // here, and deliberately never flagged.
        credential_status: CredentialStatus::Unknown,
        permission_count: (perms.app_role_values.len() + perms.scope_values.len()) as u32,
        service_principal_enabled: sp.account_enabled,
        days_since_created: sp.created_date_time.map(|c| (now - c).num_days()),
        certificates: Vec::new(),
        secrets: Vec::new(),
        last_sign_in: None,
        unused: false,
        sign_in_report_available: false,
        principal_kind: if sp.service_principal_type.as_deref() == Some("ManagedIdentity") {
            AuditPrincipalKind::ManagedIdentity
        } else {
            AuditPrincipalKind::ServicePrincipal
        },
    }
}

fn join_refs(items: &[&String]) -> String {
    items
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<&str>>()
        .join(", ")
}

fn join_names(items: &[&CredentialSummary]) -> String {
    items
        .iter()
        .map(|c| c.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::models::{
        Application, KeyCredential, PasswordCredential, ServicePrincipalLockConfiguration,
    };
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 22, 12, 0, 0).unwrap()
    }

    fn base_app() -> Application {
        Application {
            id: "obj-1".into(),
            app_id: "app-1".into(),
            display_name: "Demo".into(),
            created_date_time: Some(now() - Duration::days(10)),
            ..Default::default()
        }
    }

    fn base_sp() -> SpAuditInput {
        SpAuditInput {
            display_name: "Foreign App".into(),
            app_id: "app-f".into(),
            sp_object_id: "sp-1".into(),
            created_date_time: Some(now() - Duration::days(10)),
            account_enabled: Some(true),
            app_owner_organization_id: Some("11111111-2222-3333-4444-555555555555".into()),
            service_principal_type: Some("Application".into()),
        }
    }

    fn sp_perms(roles: &[&str]) -> AppPermissions {
        AppPermissions {
            app_role_values: roles.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    // ---- score_service_principal (SP-only principals: foreign enterprise
    // apps, managed identities, orphaned SPs) --------------------------------

    #[test]
    fn sp_orgwide_mail_grant_scores_high_risk_with_scope_remediation() {
        let item = score_service_principal(&base_sp(), &sp_perms(&["Mail.ReadWrite"]), now());
        assert_eq!(item.risk_score, PTS_HIGH_RISK_APP_PERM);
        assert!(
            item.issues
                .iter()
                .any(|x| x.starts_with(issue::ORG_WIDE_MAILBOX))
        );
        let fix = item
            .remediations
            .iter()
            .find(|r| r.kind == RemediationKind::ScopeMailboxAccess)
            .expect("org-wide mail grant gets a scope-mailbox Fix");
        assert_eq!(fix.targets, vec!["Mail.ReadWrite".to_string()]);
        // Row identity is the SP object id; the owner tenant rides `publisher`.
        assert_eq!(item.object_id, "sp-1");
        assert_eq!(
            item.publisher.as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
        assert_eq!(item.principal_kind, AuditPrincipalKind::ServicePrincipal);
    }

    #[test]
    fn sp_scoped_mail_verdict_earns_reduced_weight_and_no_fix() {
        let mut perms = sp_perms(&["Mail.ReadWrite"]);
        perms.mail_scopes.insert(
            "Mail.ReadWrite".into(),
            MailPermissionScope::Scoped {
                scope_name: Some("azapptoolkit_app-f".into()),
                recipient_filter: None,
                group_count: Some(1),
                mechanism: ScopeMechanism::Rbac,
            },
        );
        let item = score_service_principal(&base_sp(), &perms, now());
        assert_eq!(item.risk_score, PTS_SCOPED_HIGH_RISK_MAIL);
        assert!(
            item.issues
                .iter()
                .any(|x| x.contains(issue::SCOPED_VIA_RBAC))
        );
        assert!(
            !item
                .remediations
                .iter()
                .any(|r| r.kind == RemediationKind::ScopeMailboxAccess)
        );
    }

    #[test]
    fn sp_orgwide_sharepoint_grant_gets_sites_selected_remediation() {
        let item = score_service_principal(&base_sp(), &sp_perms(&["Sites.Read.All"]), now());
        assert!(
            item.issues
                .iter()
                .any(|x| x.starts_with(issue::ORG_WIDE_SHAREPOINT))
        );
        let fix = item
            .remediations
            .iter()
            .find(|r| r.kind == RemediationKind::ScopeSharePointAccess)
            .expect("org-wide Sites grant gets a scope-SharePoint Fix");
        assert_eq!(fix.targets, vec!["Sites.Read.All".to_string()]);

        // Sites.Selected is the scoped model: advisory only, no Fix.
        let scoped = score_service_principal(&base_sp(), &sp_perms(&["Sites.Selected"]), now());
        assert!(
            scoped
                .issues
                .iter()
                .any(|x| x.starts_with(issue::SCOPED_SHAREPOINT))
        );
        assert!(scoped.remediations.is_empty());
    }

    #[test]
    fn sp_disabled_and_consent_rules_apply() {
        let disabled = SpAuditInput {
            account_enabled: Some(false),
            ..base_sp()
        };
        let item = score_service_principal(&disabled, &sp_perms(&["User.Read.All"]), now());
        assert!(
            item.issues
                .iter()
                .any(|x| x.starts_with("Service principal is disabled"))
        );
        assert_eq!(item.service_principal_enabled, Some(false));

        let mut perms = sp_perms(&[]);
        perms.has_admin_consent = true;
        perms.scope_values = vec!["Directory.AccessAsUser.All".into()];
        let consented = score_service_principal(&base_sp(), &perms, now());
        assert_eq!(consented.risk_score, PTS_ADMIN_CONSENT_DELEGATED);
        assert!(
            consented
                .issues
                .iter()
                .any(|x| x.starts_with(issue::HIGH_RISK_DELEGATED_PERMS))
        );
    }

    #[test]
    fn sp_scoring_never_emits_credential_or_manifest_findings() {
        // Old SP + a redundant permission pair — the app path would raise the
        // stale-app and Rule-18 findings; the SP path must not (credentials and
        // the manifest live on the application in its home tenant).
        let old = SpAuditInput {
            created_date_time: Some(now() - Duration::days(2000)),
            ..base_sp()
        };
        let item =
            score_service_principal(&old, &sp_perms(&["Mail.Read", "Mail.ReadWrite"]), now());
        assert_eq!(item.credential_status, CredentialStatus::Unknown);
        assert!(item.certificates.is_empty() && item.secrets.is_empty());
        assert!(!item.issues.iter().any(|x| x.contains("days ago")));
        assert!(
            !item
                .issues
                .iter()
                .any(|x| x.starts_with(issue::REDUNDANT_APP_PERMS))
        );
        assert!(item.remediations.iter().all(|r| matches!(
            r.kind,
            RemediationKind::ScopeMailboxAccess | RemediationKind::ScopeSharePointAccess
        )));
        // days_since_created still populates the column.
        assert_eq!(item.days_since_created, Some(2000));
    }

    #[test]
    fn sp_principal_kind_follows_service_principal_type() {
        let mi = SpAuditInput {
            service_principal_type: Some("ManagedIdentity".into()),
            ..base_sp()
        };
        let item = score_service_principal(&mi, &sp_perms(&["User.Read.All"]), now());
        assert_eq!(item.principal_kind, AuditPrincipalKind::ManagedIdentity);
        let none = SpAuditInput {
            service_principal_type: None,
            ..base_sp()
        };
        let item = score_service_principal(&none, &sp_perms(&[]), now());
        assert_eq!(item.principal_kind, AuditPrincipalKind::ServicePrincipal);
    }

    #[test]
    fn principal_kind_is_additive_on_the_wire() {
        // snake_case wire values, matching the rest of the AuditItem payload…
        assert_eq!(
            serde_json::to_string(&AuditPrincipalKind::ServicePrincipal).unwrap(),
            "\"service_principal\""
        );
        // …and absent-field JSON (a cached run from before the field existed)
        // deserializes as Application — the additive-only wire guarantee.
        let scored = score_application(&base_app(), None, &AppPermissions::default(), now());
        let mut v = serde_json::to_value(&scored).unwrap();
        v.as_object_mut().unwrap().remove("principal_kind");
        let item: AuditItem = serde_json::from_value(v).unwrap();
        assert_eq!(item.principal_kind, AuditPrincipalKind::Application);
    }

    #[test]
    fn clean_app_scores_zero() {
        let item = score_application(&base_app(), Some(true), &AppPermissions::default(), now());
        assert_eq!(item.risk_score, 0);
        assert_eq!(item.risk_level, RiskLevel::Low);
        assert!(item.issues.is_empty());
    }

    #[test]
    fn one_high_risk_permission_adds_ten() {
        let perms = AppPermissions {
            app_role_values: vec!["Directory.ReadWrite.All".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, 10);
        assert_eq!(item.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn two_high_risk_permissions_adds_twenty() {
        let perms = AppPermissions {
            app_role_values: vec!["Directory.ReadWrite.All".into(), "Mail.Send".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, 20);
        assert_eq!(item.risk_level, RiskLevel::High);
    }

    #[test]
    fn medium_risk_permission_adds_five() {
        let perms = AppPermissions {
            app_role_values: vec!["User.Read.All".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, 5);
    }

    #[test]
    fn admin_consent_delegated_adds_five() {
        let perms = AppPermissions {
            scope_values: vec!["User.Read".into()],
            has_admin_consent: true,
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, 5);
    }

    #[test]
    fn high_risk_delegated_permissions_surface_without_score() {
        // Rule 13, ported from `Constants.ps1:104-130`. High-risk delegated
        // scopes are advisory: they add an issue but no score (the legacy module
        // weighted delegated perms only via the admin-consent check). Each row
        // is (scope value, expect_issue).
        let cases = [
            ("Directory.AccessAsUser.All", true),
            ("user_impersonation", true),
            ("User.Read", false),
        ];
        for (scope, expect_issue) in cases {
            let perms = AppPermissions {
                scope_values: vec![scope.into()],
                ..Default::default()
            };
            let item = score_application(&base_app(), Some(true), &perms, now());
            // Advisory only — never changes the score.
            assert_eq!(item.risk_score, 0, "{scope} must not add score");
            let surfaced = item
                .issues
                .iter()
                .any(|i| i.starts_with("High-risk delegated permissions:") && i.contains(scope));
            assert_eq!(surfaced, expect_issue, "issue mismatch for {scope}");
        }
    }

    #[test]
    fn emitted_issue_markers_are_stable() {
        // Ties `score_application`'s issue strings to the `issue::*` constants the
        // UI facets match on: renaming a scorer string without updating the
        // constant (and the facet that reads it) fails here instead of silently
        // zeroing a facet. One app triggers the perm / org-wide / ownerless
        // markers at once.
        use crate::models::DirectoryObject;
        let mut app = base_app();
        app.owners = Some(Vec::new()); // ownerless → NO_OWNERS
        let perms = AppPermissions {
            app_role_values: vec![
                "Directory.ReadWrite.All".into(), // HIGH_RISK_APP_PERMS
                "Directory.Read.All".into(),      // REDUNDANT_APP_PERMS (⊂ ReadWrite)
                "Mail.Read".into(),               // ORG_WIDE_MAILBOX
                "Sites.Read.All".into(),          // ORG_WIDE_SHAREPOINT
                "Sites.Selected".into(),          // SCOPED_SHAREPOINT
            ],
            scope_values: vec!["Directory.AccessAsUser.All".into()], // HIGH_RISK_DELEGATED_PERMS
            ..Default::default()
        };
        let issues = score_application(&app, Some(true), &perms, now()).issues;
        let emits = |m: &str| issues.iter().any(|i| i.starts_with(m));
        for marker in [
            issue::HIGH_RISK_APP_PERMS,
            issue::HIGH_RISK_DELEGATED_PERMS,
            issue::ORG_WIDE_MAILBOX,
            issue::ORG_WIDE_SHAREPOINT,
            issue::SCOPED_SHAREPOINT,
            issue::NO_OWNERS,
            issue::REDUNDANT_APP_PERMS,
        ] {
            assert!(
                emits(marker),
                "scorer no longer emits {marker:?}: {issues:?}"
            );
        }

        // A single-owner app triggers SINGLE_OWNER.
        let mut solo = base_app();
        solo.owners = Some(vec![DirectoryObject {
            id: "o0".into(),
            display_name: None,
            user_principal_name: None,
            mail: None,
            odata_type: None,
        }]);
        let solo_issues =
            score_application(&solo, Some(true), &AppPermissions::default(), now()).issues;
        assert!(
            solo_issues
                .iter()
                .any(|i| i.starts_with(issue::SINGLE_OWNER)),
            "scorer no longer emits {:?}: {solo_issues:?}",
            issue::SINGLE_OWNER
        );

        // A confirmed-scoped mail permission's advisory contains SCOPED_VIA_RBAC.
        let mut mail_scopes = HashMap::new();
        mail_scopes.insert("Mail.Read".to_string(), scoped());
        let scoped_perms = AppPermissions {
            app_role_values: vec!["Mail.Read".into()],
            mail_scopes,
            ..Default::default()
        };
        let scoped_issues = score_application(&base_app(), Some(true), &scoped_perms, now()).issues;
        assert!(
            scoped_issues
                .iter()
                .any(|i| i.contains(issue::SCOPED_VIA_RBAC)),
            "scorer no longer emits {:?}: {scoped_issues:?}",
            issue::SCOPED_VIA_RBAC
        );
    }

    #[test]
    fn ownership_rules_are_advisory_and_owner_aware() {
        use crate::models::DirectoryObject;
        let owners = |n: usize| {
            Some(
                (0..n)
                    .map(|i| DirectoryObject {
                        id: format!("o{i}"),
                        display_name: None,
                        user_principal_name: None,
                        mail: None,
                        odata_type: None,
                    })
                    .collect::<Vec<_>>(),
            )
        };
        // (owners, expected issue substring or None) — advisory: never scores.
        let cases: [(Option<Vec<DirectoryObject>>, Option<&str>); 4] = [
            (None, None),                            // not fetched → skip
            (owners(0), Some("No owners assigned")), // ownerless
            (owners(1), Some("Single owner")),       // single owner
            (owners(2), None),                       // healthy
        ];
        for (owners, expect) in cases {
            let mut app = base_app();
            app.owners = owners;
            let item = score_application(&app, Some(true), &AppPermissions::default(), now());
            assert_eq!(item.risk_score, 0, "ownership rule must not add score");
            match expect {
                Some(sub) => assert!(
                    item.issues.iter().any(|i| i.starts_with(sub)),
                    "expected issue starting with {sub:?}, got {:?}",
                    item.issues
                ),
                None => assert!(
                    item.issues.is_empty(),
                    "expected no issues, got {:?}",
                    item.issues
                ),
            }
        }
    }

    #[test]
    fn ownership_gap_offers_add_owner_remediation() {
        use crate::models::DirectoryObject;
        let owners = |n: usize| {
            Some(
                (0..n)
                    .map(|i| DirectoryObject {
                        id: format!("o{i}"),
                        display_name: None,
                        user_principal_name: None,
                        mail: None,
                        odata_type: None,
                    })
                    .collect::<Vec<_>>(),
            )
        };
        // (owners, expected AddOwner label) — attaches exactly when Rule 14 fires.
        let cases: [(Option<Vec<DirectoryObject>>, Option<&str>); 4] = [
            (None, None), // not fetched → skip, like the issue
            (owners(0), Some("Add an owner")),
            (owners(1), Some("Add a second owner")),
            (owners(2), None), // healthy
        ];
        for (owners, expect) in cases {
            let mut app = base_app();
            app.owners = owners;
            let item = score_application(&app, Some(true), &AppPermissions::default(), now());
            let add_owner: Vec<_> = item
                .remediations
                .iter()
                .filter(|r| r.kind == RemediationKind::AddOwner)
                .collect();
            match expect {
                Some(label) => {
                    assert_eq!(add_owner.len(), 1, "expected one AddOwner remediation");
                    assert_eq!(add_owner[0].label, label);
                    assert!(add_owner[0].targets.is_empty());
                }
                None => assert!(
                    add_owner.is_empty(),
                    "expected no AddOwner remediation, got {:?}",
                    item.remediations
                ),
            }
        }

        // SP-only rows never get AddOwner (owners aren't audited there).
        let sp_item = score_service_principal(&base_sp(), &AppPermissions::default(), now());
        assert!(
            !sp_item
                .remediations
                .iter()
                .any(|r| r.kind == RemediationKind::AddOwner)
        );
    }

    #[test]
    fn disable_sign_in_remediation_shape() {
        // Runner-attached (unused is a post-pass flag) — pin the action the
        // runner pushes so the frontend's kind-matching stays honest.
        let r = disable_sign_in_remediation();
        assert_eq!(r.kind, RemediationKind::DisableSignIn);
        assert_eq!(r.label, "Disable sign-in");
        assert!(r.detail.contains("reversible"));
        assert!(r.targets.is_empty());
    }

    fn scoped() -> MailPermissionScope {
        MailPermissionScope::Scoped {
            scope_name: Some("azapptoolkit_app-1".into()),
            recipient_filter: Some("MemberOfGroup -eq 'CN=Shared,DC=x'".into()),
            group_count: Some(1),
            mechanism: ScopeMechanism::Rbac,
        }
    }

    #[test]
    fn scoped_mail_permission_uses_reduced_weight() {
        // Mail.Send is high-risk (+10 org-wide). Confirmed scoped via Exchange
        // RBAC ⇒ reduced to PTS_SCOPED_HIGH_RISK_MAIL (+3), and Rule 11 emits the
        // positive "scoped" note instead of the org-wide advisory.
        let mut mail_scopes = HashMap::new();
        mail_scopes.insert("Mail.Send".to_string(), scoped());
        let perms = AppPermissions {
            app_role_values: vec!["Mail.Send".into()],
            mail_scopes,
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, PTS_SCOPED_HIGH_RISK_MAIL);
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with("High-risk mailbox permissions scoped via RBAC"))
        );
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with("Mailbox access scoped via RBAC for Applications:"))
        );
        // No org-wide advisory once it's scoped.
        assert!(
            !item
                .issues
                .iter()
                .any(|i| i.starts_with("Organization-wide mailbox access"))
        );
    }

    #[test]
    fn medium_scoped_mail_permission_uses_reduced_weight() {
        // Mail.Read is medium-risk (+5 org-wide) → +2 when scoped.
        let mut mail_scopes = HashMap::new();
        mail_scopes.insert("Mail.Read".to_string(), scoped());
        let perms = AppPermissions {
            app_role_values: vec!["Mail.Read".into()],
            mail_scopes,
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, PTS_SCOPED_MEDIUM_RISK_MAIL);
    }

    #[test]
    fn org_wide_and_unknown_verdicts_keep_full_weight() {
        // A scopable mail perm that resolved to OrgWide or Unknown must score
        // exactly like the unresolved (empty-map) case — never under-report.
        for verdict in [MailPermissionScope::OrgWide, MailPermissionScope::Unknown] {
            let mut mail_scopes = HashMap::new();
            mail_scopes.insert("Mail.Send".to_string(), verdict.clone());
            let perms = AppPermissions {
                app_role_values: vec!["Mail.Send".into()],
                mail_scopes,
                ..Default::default()
            };
            let item = score_application(&base_app(), Some(true), &perms, now());
            assert_eq!(
                item.risk_score, PTS_HIGH_RISK_APP_PERM,
                "verdict {verdict:?}"
            );
            assert!(
                item.issues
                    .iter()
                    .any(|i| i.starts_with("Organization-wide mailbox access"))
            );
        }
    }

    #[test]
    fn scoped_only_reduces_the_scoped_permission() {
        // Mail.Send scoped (+3) but Directory.ReadWrite.All is not a mail perm
        // and keeps full weight (+10) → 13. Confirms scoping is per-permission,
        // not all-or-nothing.
        let mut mail_scopes = HashMap::new();
        mail_scopes.insert("Mail.Send".to_string(), scoped());
        let perms = AppPermissions {
            app_role_values: vec!["Mail.Send".into(), "Directory.ReadWrite.All".into()],
            mail_scopes,
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(
            item.risk_score,
            PTS_SCOPED_HIGH_RISK_MAIL + PTS_HIGH_RISK_APP_PERM
        );
    }

    /// A rich app that triggers most scoring + advisory rules at once: used by
    /// the characterization tests to pin the exact ordered issues /
    /// recommendations / remediations before the rule-extraction refactor.
    fn rich_app() -> Application {
        let n = now();
        Application {
            id: "obj-rich".into(),
            app_id: "app-rich".into(),
            display_name: "Rich".into(),
            created_date_time: Some(n - Duration::days(400)), // stale (>90d)
            owners: Some(vec![]),                             // no owners
            service_principal_lock_configuration: None,       // lock off
            is_fallback_public_client: Some(true),            // public-client flows
            password_credentials: vec![
                PasswordCredential {
                    key_id: "k-exp".into(),
                    display_name: Some("expired".into()),
                    start_date_time: Some(n - Duration::days(800)),
                    end_date_time: Some(n - Duration::days(5)), // expired
                    ..Default::default()
                },
                PasswordCredential {
                    key_id: "k-act".into(),
                    display_name: Some("active-long".into()),
                    start_date_time: Some(n - Duration::days(200)),
                    end_date_time: Some(n + Duration::days(200)), // active, 400d span > 365 = long-lived
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    fn rich_perms() -> AppPermissions {
        AppPermissions {
            app_role_values: vec![
                "Directory.ReadWrite.All".into(), // high
                "Mail.ReadWrite".into(),          // high + org-wide mailbox
                "Mail.Read".into(), // medium + mailbox; redundant (covered by Mail.ReadWrite)
                "Sites.ReadWrite.All".into(), // high + org-wide SharePoint
                "User.Read.All".into(), // medium
            ],
            scope_values: vec!["Directory.AccessAsUser.All".into()], // high-risk delegated
            has_admin_consent: true,
            ..Default::default()
        }
    }

    /// A second scenario covering the branches the rich app's mutual exclusions
    /// skip: scoped (not org-wide) mail, all-credentials-expiring-soon, single
    /// owner, and the Sites.Selected scoped-SharePoint note.
    fn scoped_app() -> Application {
        let n = now();
        Application {
            id: "obj-scoped".into(),
            app_id: "app-scoped".into(),
            display_name: "Scoped".into(),
            created_date_time: Some(n - Duration::days(10)), // fresh (not stale)
            owners: Some(vec![crate::models::DirectoryObject::default()]), // single owner
            service_principal_lock_configuration: Some(ServicePrincipalLockConfiguration {
                is_enabled: Some(true),
                all_properties: Some(true),
                ..Default::default()
            }),
            password_credentials: vec![PasswordCredential {
                key_id: "k-soon".into(),
                display_name: Some("soon".into()),
                start_date_time: Some(n - Duration::days(30)),
                end_date_time: Some(n + Duration::days(7)), // expiring soon, none active
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn scoped_perms() -> AppPermissions {
        let mut mail_scopes = std::collections::HashMap::new();
        mail_scopes.insert(
            "Mail.ReadWrite".to_string(),
            MailPermissionScope::Scoped {
                scope_name: Some("azapptoolkit_x".into()),
                recipient_filter: None,
                group_count: None,
                mechanism: ScopeMechanism::Rbac,
            },
        );
        AppPermissions {
            app_role_values: vec!["Mail.ReadWrite".into(), "Sites.Selected".into()],
            mail_scopes,
            ..Default::default()
        }
    }

    fn as_strs(v: &[String]) -> Vec<&str> {
        v.iter().map(String::as_str).collect()
    }

    // ---- score_application characterization (Q-H1) -------------------------
    // These snapshot the ENTIRE pipeline output — exact issue / recommendation
    // text AND order, plus remediation kinds — for two scenarios chosen to hit
    // (between them) every rule branch. The per-rule tests below pin individual
    // contributions; these pin how they compose and order, so the rule
    // extraction is provably behavior-preserving. A deliberate wording change
    // updates the snapshot; an accidental reorder/edit fails the test.

    #[test]
    fn characterizes_full_output_for_a_rich_app() {
        let item = score_application(&rich_app(), Some(false), &rich_perms(), now());
        assert_eq!(item.risk_score, 56);
        assert_eq!(item.risk_level, RiskLevel::Critical);
        assert_eq!(
            as_strs(&item.issues),
            vec![
                "High-risk application permissions: Directory.ReadWrite.All, Mail.ReadWrite, Sites.ReadWrite.All",
                "Medium-risk application permissions: Mail.Read, User.Read.All",
                "Admin consent granted for delegated permissions",
                "Service principal is disabled",
                "Mixed credential status: expired are expired but 1 credentials are active",
                "Long-lived secrets (>1 year): expired, active-long",
                "Application created 400 days ago - consider if still needed",
                "Organization-wide mailbox access: Mail.ReadWrite, Mail.Read",
                "Organization-wide SharePoint access: Sites.ReadWrite.All",
                "High-risk delegated permissions: Directory.AccessAsUser.All",
                "No owners assigned — ownership/accountability gap",
                "App instance property lock is not fully enabled — credentials could be added to the service principal to abuse its permissions",
                "Public client flows are enabled and credentials are present — if this app is used only as a public/installed client, the credentials should be removed",
                "Uses client secret(s) — less secure than certificates or federated credentials",
                "Redundant application permissions: Mail.Read (covered by Mail.ReadWrite), User.Read.All (covered by Directory.ReadWrite.All)",
            ]
        );
        assert_eq!(
            as_strs(&item.recommendations),
            vec![
                "Review necessity of high-risk permissions and consider principle of least privilege",
                "Review delegated permissions with admin consent - consider user consent where appropriate",
                "Enable service principal if application is actively used",
                "Remove expired credentials to clean up authentication configuration",
                "Consider shorter credential lifespans and automated rotation",
                "Review application usage and consider removal if no longer needed",
                "Scope mailbox access to specific mailboxes using RBAC for Applications",
                "Restrict SharePoint access to specific sites using Sites.Selected",
                "Review high-risk delegated permissions; prefer narrowly-scoped delegated permissions and user consent where appropriate",
                "Assign at least one owner so the application has clear accountability",
                "Enable the app instance property lock for all sensitive properties (servicePrincipalLockConfiguration) — especially for multitenant apps, where a foreign tenant's admin could otherwise add credentials to the service principal",
                "If this app is used only as a public/installed client, remove its client secrets/certificates — public clients authenticate without app credentials. (A confidential app that merely allows public-client flows can keep them.)",
                "Prefer a certificate or federated identity credential over client secrets where possible",
                "Remove redundant narrower permissions — a broader permission the app holds already grants the same access",
                "Narrower alternatives exist if the broader capability is unused: Directory.ReadWrite.All → Directory.Read.All / User.Read.All / Group.Read.All / …; Mail.ReadWrite → Mail.Read / Mail.ReadBasic / Mail.ReadBasic.All; Mail.Read → Mail.ReadBasic / Mail.ReadBasic.All; Sites.ReadWrite.All → Sites.Read.All; User.Read.All → User.ReadBasic.All",
            ]
        );
        assert_eq!(
            item.remediations.iter().map(|r| r.kind).collect::<Vec<_>>(),
            vec![
                RemediationKind::RemoveExpiredCredentials,
                RemediationKind::ScopeMailboxAccess,
                RemediationKind::ScopeSharePointAccess,
                RemediationKind::RemoveRedundantPermissions,
                RemediationKind::AddOwner,
            ]
        );
    }

    #[test]
    fn characterizes_scoped_and_expiring_branches() {
        let item = score_application(&scoped_app(), Some(true), &scoped_perms(), now());
        assert_eq!(item.risk_score, 6);
        assert_eq!(
            as_strs(&item.issues),
            vec![
                "High-risk mailbox permissions scoped via RBAC for Applications (reduced risk): Mail.ReadWrite",
                "All credentials expiring soon: soon",
                "Mailbox access scoped via RBAC for Applications: Mail.ReadWrite",
                "SharePoint access scoped to selected sites: Sites.Selected",
                "Single owner — vulnerable to owner departure",
                "Uses client secret(s) — less secure than certificates or federated credentials",
            ]
        );
        assert_eq!(
            as_strs(&item.recommendations),
            vec![
                "Plan credential renewal for expiring certificates/secrets",
                "Assign a second owner to avoid losing management access if the sole owner leaves",
                "Prefer a certificate or federated identity credential over client secrets where possible",
                "Narrower alternatives exist if the broader capability is unused: Mail.ReadWrite → Mail.Read / Mail.ReadBasic / Mail.ReadBasic.All",
            ]
        );
        assert_eq!(
            item.remediations.iter().map(|r| r.kind).collect::<Vec<_>>(),
            vec![RemediationKind::AddOwner],
            "no expired creds, no org-wide mailbox/SharePoint, no redundancy — only the single-owner AddOwner fix"
        );
    }

    #[test]
    fn empty_mail_scopes_is_byte_for_byte_original_behavior() {
        // The default (scoping not resolved) must not change any score: Mail.Send
        // stays at the full high-risk weight with the org-wide advisory.
        let perms = AppPermissions {
            app_role_values: vec!["Mail.Send".into()],
            ..Default::default()
        };
        assert!(perms.mail_scopes.is_empty());
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, PTS_HIGH_RISK_APP_PERM);
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with("Organization-wide mailbox access"))
        );
    }

    #[test]
    fn disabled_sp_adds_two() {
        let item = score_application(&base_app(), Some(false), &AppPermissions::default(), now());
        assert_eq!(item.risk_score, 2);
        assert!(
            item.issues
                .iter()
                .any(|i| i.contains("Service principal is disabled"))
        );
    }

    #[test]
    fn all_creds_expired_adds_eight() {
        let mut app = base_app();
        app.password_credentials = vec![PasswordCredential {
            key_id: "k1".into(),
            display_name: Some("s1".into()),
            start_date_time: Some(now() - Duration::days(200)),
            end_date_time: Some(now() - Duration::days(10)),
            ..Default::default()
        }];
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert_eq!(item.risk_score, 8);
        assert_eq!(item.credential_status, CredentialStatus::Expired);
    }

    #[test]
    fn expired_creds_offer_remove_remediation() {
        // A clean app exposes no remediation.
        let clean = score_application(&base_app(), Some(true), &AppPermissions::default(), now());
        assert!(clean.remediations.is_empty());

        // An app with two expired secrets offers exactly one remove-expired fix.
        let mut app = base_app();
        app.password_credentials = vec![
            PasswordCredential {
                key_id: "k1".into(),
                display_name: Some("old-a".into()),
                end_date_time: Some(now() - Duration::days(10)),
                ..Default::default()
            },
            PasswordCredential {
                key_id: "k2".into(),
                display_name: Some("old-b".into()),
                end_date_time: Some(now() - Duration::days(3)),
                ..Default::default()
            },
        ];
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert_eq!(item.remediations.len(), 1);
        let r = &item.remediations[0];
        assert_eq!(r.kind, RemediationKind::RemoveExpiredCredentials);
        assert!(r.label.contains('2'), "label = {}", r.label);
        assert!(r.detail.contains("old-a") && r.detail.contains("old-b"));
    }

    #[test]
    fn scope_remediations_track_the_org_wide_findings() {
        // ScopeMailboxAccess appears for org-wide mail perms; ScopeSharePointAccess
        // for org-wide Sites.* — keyed off the same Rule-11/12 sets as the issues.
        let perms = AppPermissions {
            app_role_values: vec!["Mail.Send".into(), "Sites.ReadWrite.All".into()],
            ..Default::default()
        };
        let kinds: Vec<_> = score_application(&base_app(), Some(true), &perms, now())
            .remediations
            .iter()
            .map(|r| r.kind)
            .collect();
        assert!(kinds.contains(&RemediationKind::ScopeMailboxAccess));
        assert!(kinds.contains(&RemediationKind::ScopeSharePointAccess));

        // A confirmed-scoped mail perm + the least-privilege Sites.Selected offer
        // no scoping fix (nothing org-wide left to confine).
        let mut mail_scopes = HashMap::new();
        mail_scopes.insert("Mail.Send".to_string(), scoped());
        let scoped_perms = AppPermissions {
            app_role_values: vec!["Mail.Send".into(), "Sites.Selected".into()],
            mail_scopes,
            ..Default::default()
        };
        let kinds2: Vec<_> = score_application(&base_app(), Some(true), &scoped_perms, now())
            .remediations
            .iter()
            .map(|r| r.kind)
            .collect();
        assert!(!kinds2.contains(&RemediationKind::ScopeMailboxAccess));
        assert!(!kinds2.contains(&RemediationKind::ScopeSharePointAccess));
    }

    #[test]
    fn redundant_permissions_rule_is_advisory_with_remediation() {
        // Rule 18: issue + one-click remediation, no score beyond what the
        // permissions already earn individually (Mail.ReadWrite high=10,
        // Mail.Read medium=5 — redundancy itself adds nothing).
        let perms = AppPermissions {
            app_role_values: vec!["Mail.ReadWrite".into(), "Mail.Read".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, 15, "redundancy must not add score");
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with(issue::REDUNDANT_APP_PERMS)
                    && i.contains("Mail.Read (covered by Mail.ReadWrite)"))
        );

        let r = item
            .remediations
            .iter()
            .find(|r| r.kind == RemediationKind::RemoveRedundantPermissions)
            .expect("remediation should track the finding");
        assert!(r.label.contains('1'), "label = {}", r.label);
        assert_eq!(r.targets, vec!["Mail.Read".to_string()]);

        // A broader mail permission confirmed scoped via Exchange RBAC no longer
        // covers the org-wide narrower one — finding and fix both disappear.
        let mut mail_scopes = HashMap::new();
        mail_scopes.insert("Mail.ReadWrite".to_string(), scoped());
        let scoped_perms = AppPermissions {
            app_role_values: vec!["Mail.ReadWrite".into(), "Mail.Read".into()],
            mail_scopes,
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &scoped_perms, now());
        assert!(
            !item
                .issues
                .iter()
                .any(|i| i.starts_with(issue::REDUNDANT_APP_PERMS))
        );
        assert!(
            !item
                .remediations
                .iter()
                .any(|r| r.kind == RemediationKind::RemoveRedundantPermissions)
        );
    }

    #[test]
    fn downgrade_recommendation_names_concrete_alternatives() {
        // Risk-flagged permission with a narrower equivalent → recommendation
        // names the concrete swap. Recommendation only: no issue, no score change.
        let perms = AppPermissions {
            app_role_values: vec!["Mail.ReadWrite".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert!(
            item.recommendations
                .iter()
                .any(|r| r.starts_with("Narrower alternatives exist")
                    && r.contains("Mail.ReadWrite → Mail.Read")),
            "recommendations = {:?}",
            item.recommendations
        );
        assert!(
            !item
                .issues
                .iter()
                .any(|i| i.contains("Narrower alternatives"))
        );

        // A risk-flagged permission with no narrower equivalent suggests nothing.
        let perms = AppPermissions {
            app_role_values: vec!["Mail.Send".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert!(
            !item
                .recommendations
                .iter()
                .any(|r| r.starts_with("Narrower alternatives exist"))
        );
    }

    #[test]
    fn mixed_expired_and_active_adds_four() {
        let mut app = base_app();
        app.password_credentials = vec![
            PasswordCredential {
                key_id: "k1".into(),
                display_name: Some("expired".into()),
                start_date_time: Some(now() - Duration::days(200)),
                end_date_time: Some(now() - Duration::days(1)),
                ..Default::default()
            },
            PasswordCredential {
                key_id: "k2".into(),
                display_name: Some("fresh".into()),
                start_date_time: Some(now() - Duration::days(10)),
                end_date_time: Some(now() + Duration::days(200)),
                ..Default::default()
            },
        ];
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert_eq!(item.risk_score, 4);
        assert_eq!(item.credential_status, CredentialStatus::Expired);
    }

    #[test]
    fn all_expiring_soon_adds_three() {
        let mut app = base_app();
        app.password_credentials = vec![PasswordCredential {
            key_id: "k1".into(),
            display_name: Some("s1".into()),
            start_date_time: Some(now() - Duration::days(10)),
            end_date_time: Some(now() + Duration::days(3)),
            ..Default::default()
        }];
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert_eq!(item.risk_score, 3);
        assert_eq!(item.credential_status, CredentialStatus::ExpiringSoon);
        // Expiring-soon is not yet expired, so no remove-expired remediation is
        // offered (guards the `!expired.is_empty()` gate against regressions).
        assert!(item.remediations.is_empty());
    }

    #[test]
    fn mixed_expiring_and_active_adds_two() {
        let mut app = base_app();
        app.password_credentials = vec![
            PasswordCredential {
                key_id: "k1".into(),
                display_name: Some("expiring".into()),
                start_date_time: Some(now() - Duration::days(10)),
                end_date_time: Some(now() + Duration::days(3)),
                ..Default::default()
            },
            PasswordCredential {
                key_id: "k2".into(),
                display_name: Some("fresh".into()),
                start_date_time: Some(now() - Duration::days(10)),
                end_date_time: Some(now() + Duration::days(200)),
                ..Default::default()
            },
        ];
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert_eq!(item.risk_score, 2);
    }

    #[test]
    fn long_lived_secret_adds_three() {
        let mut app = base_app();
        app.password_credentials = vec![PasswordCredential {
            key_id: "k1".into(),
            display_name: Some("s1".into()),
            start_date_time: Some(now() - Duration::days(10)),
            end_date_time: Some(now() + Duration::days(400)),
            ..Default::default()
        }];
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert_eq!(item.risk_score, 3);
    }

    #[test]
    fn stale_app_adds_two() {
        let mut app = base_app();
        app.created_date_time = Some(now() - Duration::days(100));
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert_eq!(item.risk_score, 2);
        assert_eq!(item.days_since_created, Some(100));
    }

    // ---- Tier-2 advisory rules (net-new; no PowerShell source) ----

    fn full_lock() -> ServicePrincipalLockConfiguration {
        ServicePrincipalLockConfiguration {
            is_enabled: Some(true),
            all_properties: Some(true),
            ..Default::default()
        }
    }

    // A secret that is Active: not expired, not within EXPIRY_WARNING_DAYS, and
    // a lifetime under LONG_LIVED_SECRET_DAYS — so it trips no scoring rule and
    // an advisory's "no score" claim is isolable.
    fn active_secret() -> PasswordCredential {
        PasswordCredential {
            key_id: "k1".into(),
            display_name: Some("s1".into()),
            start_date_time: Some(now() - Duration::days(10)),
            end_date_time: Some(now() + Duration::days(100)),
            ..Default::default()
        }
    }

    #[test]
    fn instance_lock_disabled_is_advisory_for_apps_with_permissions() {
        let mut app = base_app();
        // Holds an application permission, lock not configured (None).
        // A benign (non-risky) permission keeps the score at 0 so the advisory's
        // "no score" property is observable.
        let perms = AppPermissions {
            app_role_values: vec!["Benign.Read".into()],
            ..Default::default()
        };
        let item = score_application(&app, Some(true), &perms, now());
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with(issue::INSTANCE_LOCK_DISABLED))
        );
        assert_eq!(item.risk_score, 0, "instance-lock advisory must not score");

        // A fully-set lock clears the advisory.
        app.service_principal_lock_configuration = Some(full_lock());
        let locked = score_application(&app, Some(true), &perms, now());
        assert!(
            !locked
                .issues
                .iter()
                .any(|i| i.starts_with(issue::INSTANCE_LOCK_DISABLED))
        );
    }

    #[test]
    fn instance_lock_not_flagged_for_app_with_nothing_to_protect() {
        // No permissions and no credentials → no advisory even with the lock off.
        let item = score_application(&base_app(), Some(true), &AppPermissions::default(), now());
        assert!(
            !item
                .issues
                .iter()
                .any(|i| i.starts_with(issue::INSTANCE_LOCK_DISABLED))
        );
    }

    #[test]
    fn partial_lock_is_not_treated_as_fully_locked() {
        let mut app = base_app();
        app.service_principal_lock_configuration = Some(ServicePrincipalLockConfiguration {
            is_enabled: Some(true),
            all_properties: Some(false),
            // Missing token_encryption_key_id ⇒ not fully locked.
            credentials_with_usage_verify: Some(true),
            credentials_with_usage_sign: Some(true),
            token_encryption_key_id: None,
        });
        let perms = AppPermissions {
            app_role_values: vec!["Benign.Read".into()],
            ..Default::default()
        };
        let item = score_application(&app, Some(true), &perms, now());
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with(issue::INSTANCE_LOCK_DISABLED))
        );
    }

    #[test]
    fn public_client_with_credentials_is_advised() {
        let mut app = base_app();
        app.is_fallback_public_client = Some(true);
        app.password_credentials = vec![active_secret()];
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with(issue::PUBLIC_CLIENT_CREDENTIALS))
        );

        // A public client with no credentials is fine.
        let mut clean = base_app();
        clean.is_fallback_public_client = Some(true);
        let clean_item = score_application(&clean, Some(true), &AppPermissions::default(), now());
        assert!(
            !clean_item
                .issues
                .iter()
                .any(|i| i.starts_with(issue::PUBLIC_CLIENT_CREDENTIALS))
        );
    }

    #[test]
    fn client_secret_nudges_toward_certificate() {
        let mut app = base_app();
        app.password_credentials = vec![active_secret()];
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with(issue::PREFER_CERT_OVER_SECRET))
        );
        assert_eq!(item.risk_score, 0, "cert/secret nudge must not score");

        // A certificate-only app gets no secret nudge.
        let mut cert_app = base_app();
        cert_app.key_credentials = vec![KeyCredential {
            key_id: "c1".into(),
            ..Default::default()
        }];
        let cert_item = score_application(&cert_app, Some(true), &AppPermissions::default(), now());
        assert!(
            !cert_item
                .issues
                .iter()
                .any(|i| i.starts_with(issue::PREFER_CERT_OVER_SECRET))
        );
    }

    #[test]
    fn certificates_do_not_trip_long_lived_when_no_dates() {
        let mut app = base_app();
        app.key_credentials = vec![KeyCredential {
            key_id: "c1".into(),
            display_name: Some("cert".into()),
            ..Default::default()
        }];
        let item = score_application(&app, Some(true), &AppPermissions::default(), now());
        assert_eq!(item.risk_score, 0);
        assert_eq!(item.certificates.len(), 1);
        assert_eq!(item.certificates[0].status, CredentialStatus::Unknown);
    }

    #[test]
    fn worst_case_combines_multiple_rules() {
        // 2 high-risk app perms (+20) + admin consent (+5) + disabled SP (+2)
        // + all-expired (+8) + stale (+2) = 37 → Critical
        let mut app = base_app();
        app.created_date_time = Some(now() - Duration::days(200));
        app.password_credentials = vec![PasswordCredential {
            key_id: "k1".into(),
            display_name: Some("s1".into()),
            start_date_time: Some(now() - Duration::days(200)),
            end_date_time: Some(now() - Duration::days(10)),
            ..Default::default()
        }];
        let perms = AppPermissions {
            app_role_values: vec!["Directory.ReadWrite.All".into(), "Mail.Send".into()],
            scope_values: vec!["Directory.AccessAsUser.All".into()],
            has_admin_consent: true,
            ..Default::default()
        };
        let item = score_application(&app, Some(false), &perms, now());
        assert_eq!(item.risk_score, 37);
        assert_eq!(item.risk_level, RiskLevel::Critical);
        // 9 issues: high perms, admin consent, SP disabled, all expired, stale
        // app, the advisory org-wide mailbox access flag (Mail.Send), the advisory
        // high-risk delegated flag (Directory.AccessAsUser.All), the instance-lock
        // advisory (app holds permissions/credentials with the lock off), and the
        // prefer-certificate-over-secret advisory (the app carries a secret). All
        // advisory flags add no score (still 37).
        assert_eq!(item.issues.len(), 9);
    }

    #[test]
    fn broad_mailbox_access_flags_issue_without_extra_score() {
        // Mail.Send is already a high-risk perm (+10); the advisory mailbox flag
        // adds an issue but no extra score.
        // Source: Resource-Analysis.ps1::Add-ExchangePermissionAnalysis.
        let perms = AppPermissions {
            app_role_values: vec!["Mail.Send".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, 10);
        assert!(
            item.issues
                .iter()
                .any(|i| i.contains("Organization-wide mailbox access"))
        );
        assert!(
            item.recommendations
                .iter()
                .any(|r| r.contains("RBAC for Applications"))
        );
    }

    #[test]
    fn broad_sharepoint_readwrite_is_high_risk_and_flagged() {
        // Normalized (net-new vs the PowerShell source): org-wide
        // `Sites.ReadWrite.All` now scores as high-risk (+10), consistent with
        // `Sites.FullControl.All`, AND still raises the org-wide advisory.
        let perms = AppPermissions {
            app_role_values: vec!["Sites.ReadWrite.All".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, PTS_HIGH_RISK_APP_PERM);
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with("Organization-wide SharePoint access"))
        );
    }

    #[test]
    fn broad_sharepoint_manage_flags_issue_without_score() {
        // A broad `Sites.*` that is *not* in a risk list (e.g. Sites.Manage.All)
        // still raises the advisory with no score — confirms Rule 12 is
        // independent of the risk-list weighting.
        let perms = AppPermissions {
            app_role_values: vec!["Sites.Manage.All".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, 0);
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with("Organization-wide SharePoint access"))
        );
    }

    #[test]
    fn sites_selected_is_scoped_not_org_wide() {
        // Sites.Selected is the scoped model: no score, no org-wide advisory, but
        // a positive "scoped to selected sites" note (parity with the mailbox
        // scoped note).
        let perms = AppPermissions {
            app_role_values: vec!["Sites.Selected".into()],
            ..Default::default()
        };
        let item = score_application(&base_app(), Some(true), &perms, now());
        assert_eq!(item.risk_score, 0);
        assert!(
            !item
                .issues
                .iter()
                .any(|i| i.starts_with("Organization-wide SharePoint access"))
        );
        assert!(
            item.issues
                .iter()
                .any(|i| i.starts_with("SharePoint access scoped to selected sites"))
        );
    }
}
