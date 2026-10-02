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
    PTS_MIXED_EXPIRING, PTS_MULTITENANT_EXPOSURE, PTS_SCOPED_HIGH_RISK_MAIL,
    PTS_SCOPED_MEDIUM_RISK_MAIL, PTS_SP_DISABLED, PTS_STALE_APP, PTS_UNVERIFIED_PUBLISHER,
    RedundantPermission,
};

/// One rule's contribution: score delta plus the issues/recommendations it
/// raises. `score_application` folds the `rule_*` helpers in rule order, so
/// issue / recommendation ordering is preserved by construction.
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

/// Rules 1 & 2: high/medium-risk application permissions. A high/medium-risk
/// *mail* permission confirmed scoped via Exchange RBAC earns the reduced
/// scoped weight. Empty `mail_scopes` (unresolved) ⇒ every hit is org-wide —
/// byte-for-byte the original.
fn rule_app_permission_risk(perms: &AppPermissions) -> RuleContribution {
    let mut c = RuleContribution::default();

    // Partitioned on the *grant*, not the value: `is_scoped` gates on the
    // grant's resource, so an unscopable legacy Exchange Online namesake keeps
    // full weight even while its same-named Graph permission is scoped.
    let (high_scoped, high_full): (Vec<&ResourcePermission>, Vec<&ResourcePermission>) = perms
        .app_role_grants
        .iter()
        .filter(|g| HIGH_RISK_APP_PERMISSIONS.contains(&g.value.as_str()))
        .partition(|g| perms.is_scoped(g));
    if !high_full.is_empty() {
        c.score += PTS_HIGH_RISK_APP_PERM * high_full.len() as u32;
        c.issues.push(format!(
            "High-risk application permissions: {}",
            join_values(&high_full)
        ));
        c.recommendations.push(
            "Review necessity of high-risk permissions and consider principle of least privilege"
                .to_string(),
        );
    }
    if !high_scoped.is_empty() {
        c.score += PTS_SCOPED_HIGH_RISK_MAIL * high_scoped.len() as u32;
        push_scoped_risk_issue(&mut c, "High-risk", &high_scoped, perms);
    }

    let (medium_scoped, medium_full): (Vec<&ResourcePermission>, Vec<&ResourcePermission>) = perms
        .app_role_grants
        .iter()
        .filter(|g| MEDIUM_RISK_APP_PERMISSIONS.contains(&g.value.as_str()))
        .partition(|g| perms.is_scoped(g));
    if !medium_full.is_empty() {
        c.score += PTS_MEDIUM_RISK_APP_PERM * medium_full.len() as u32;
        c.issues.push(format!(
            "Medium-risk application permissions: {}",
            join_values(&medium_full)
        ));
    }
    if !medium_scoped.is_empty() {
        c.score += PTS_SCOPED_MEDIUM_RISK_MAIL * medium_scoped.len() as u32;
        push_scoped_risk_issue(&mut c, "Medium-risk", &medium_scoped, perms);
    }
    c
}

/// The reduced-weight advisory for one tier's confirmed-scoped mailbox
/// permissions, **split by confining mechanism** (score identical either way —
/// only wording differs). The RBAC line carries [`issue::SCOPED_VIA_RBAC`],
/// which the UI matches mid-string to populate the *healthy* "Mailbox access
/// scoped" group; emitting it for a legacy AAP would bury Rule 11's migration
/// finding for the same permission.
fn push_scoped_risk_issue(
    c: &mut RuleContribution,
    tier: &str,
    scoped: &[&ResourcePermission],
    perms: &AppPermissions,
) {
    let (legacy, rbac): (Vec<&ResourcePermission>, Vec<&ResourcePermission>) =
        scoped.iter().copied().partition(|g| {
            matches!(
                perms.scope_mechanism(g),
                Some(ScopeMechanism::LegacyApplicationAccessPolicy)
            )
        });
    if !rbac.is_empty() {
        c.issues.push(format!(
            "{tier} mailbox permissions scoped via RBAC for Applications (reduced risk): {}",
            join_values(&rbac)
        ));
    }
    if !legacy.is_empty() {
        c.issues.push(format!(
            "{tier} mailbox permissions confined by a legacy Application Access Policy \
             (reduced risk): {}",
            join_values(&legacy)
        ));
    }
}

/// Rules 5/6 (expired), 8/9 (expiring-soon, only when nothing is expired), and
/// 7 (long-lived secrets and certificates), in that order. Credential subsets
/// are precomputed once in `score_application` (`expired` is reused by the
/// remediation block).
fn rule_credentials(
    expired: &[&CredentialSummary],
    expiring: &[&CredentialSummary],
    active_count: usize,
    long_lived: &[&CredentialSummary],
) -> RuleContribution {
    let mut c = RuleContribution::default();
    // `active_count` excludes `ExpiringSoon` (sound for the expiring-soon rules
    // below, NOT here): one expired + one expiring-soon secret gives
    // `active_count == 0` while a working credential still authenticates, so
    // "All credentials expired" would misread as a dead app and overstate risk.
    // Only credentials that still WORK decide this branch.
    let still_working = active_count + expiring.len();
    if !expired.is_empty() && still_working == 0 {
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
            still_working
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
        // Scored flat and once, whatever the mix of kinds; only the wording
        // splits, so a multi-year certificate is not filed as a "secret".
        c.score += PTS_LONG_LIVED;
        let (secrets, certs): (Vec<&CredentialSummary>, Vec<&CredentialSummary>) = long_lived
            .iter()
            .copied()
            .partition(|cred| cred.kind == CredentialKind::Secret);
        if !secrets.is_empty() {
            c.issues.push(format!(
                "Long-lived secrets (>1 year): {}",
                join_names(&secrets)
            ));
        }
        if !certs.is_empty() {
            c.issues.push(format!(
                "Long-lived certificates (>1 year): {}",
                join_names(&certs)
            ));
        }
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

/// Rule 11 (advisory, no score): organization-wide mailbox access. Splits the
/// mailbox-reaching grants five ways because the remedy differs per bucket:
///
/// - **confirmed scoped** via Exchange RBAC → informational only;
/// - **legacy Application Access Policy** → its own finding + the
///   `MigrateApplicationAccessPolicy` fix. The access really is confined (keeps
///   the reduced scoped weight, so it is not an org-wide finding), but AAP is a
///   legacy all-or-nothing per-app gate that only constrains Entra grants; its
///   replacement is RBAC for Applications;
/// - **org-wide and scopable** → the `ScopeMailboxAccess` remediation, decided
///   by [`crate::scoping::is_scopable_exchange_resource_permission`] — the same
///   positive gate [`AppPermissions::is_scoped`] uses, never the negation of the
///   legacy test below (which admits three unscopable shapes);
/// - **org-wide on legacy Office 365 Exchange Online** → its own finding, **no**
///   remediation: RBAC for Applications covers Graph and EWS only, so nothing
///   can confine that resource's Outlook REST `Mail.*` roles; a "Scope…" button
///   would promise a fix that cannot be honoured;
/// - **org-wide but unconfinable otherwise** (a `Mail.*`/`MailboxSettings.*`
///   name outside the mapped role set, an unmapped resource, or a failed
///   resolution) → its own finding, **no** remediation — "remove the grant" is
///   wrong advice for access that may be entirely legitimate.
///
/// Membership comes from [`crate::scoping::is_mailbox_reaching_permission`]
/// (resource-aware): a bare `Mail.*` name test misses the tenant-wide EWS
/// `full_access_as_app` scope.
///
/// Returns the *scopable* org-wide set and the legacy-policy-scoped set, for
/// their two remediations. Empty `mail_scopes` ⇒ nothing scoped ⇒ every scopable
/// hit is org-wide (the original behavior).
type MailboxAdvisory<'a> = (
    RuleContribution,
    Vec<&'a ResourcePermission>,
    Vec<&'a ResourcePermission>,
);

fn rule_mailbox_advisory(perms: &AppPermissions) -> MailboxAdvisory<'_> {
    let mut c = RuleContribution::default();
    // Partitioned straight off the filter (runs once per app in a tenant-wide
    // audit; the intermediate `Vec` existed only for the next line).
    let (mailbox_scoped, mailbox_orgwide): (Vec<&ResourcePermission>, Vec<&ResourcePermission>) =
        perms
            .app_role_grants
            .iter()
            .filter(|g| {
                crate::scoping::is_mailbox_reaching_permission(
                    g.resource_app_id.as_deref(),
                    &g.value,
                )
            })
            .partition(|g| perms.is_scoped(g));
    // Positive gate, deliberately: only permissions RBAC for Applications can
    // confine get the ScopeMailboxAccess fix. A negative test let through
    // `None`/unmapped resources and unmapped Graph `Mail.*`/`MailboxSettings.*`
    // names — all declared unscopable, so their Fix could only fail or
    // mis-apply. Mirrors the gate `AppPermissions::is_scoped` uses.
    let (mailbox_unscoped, unconfinable): (Vec<&ResourcePermission>, Vec<&ResourcePermission>) =
        mailbox_orgwide.into_iter().partition(|g| {
            crate::scoping::is_scopable_exchange_resource_permission(
                g.resource_app_id.as_deref(),
                &g.value,
            )
        });
    // Split the unconfinable by *why*: removing the grant is the only remedy for
    // the legacy Outlook-REST roles, but wrong for a resource that failed to
    // resolve.
    let (unscopable_legacy, unconfinable_other): (
        Vec<&ResourcePermission>,
        Vec<&ResourcePermission>,
    ) = unconfinable.into_iter().partition(|g| {
        g.resource_app_id.as_deref().is_some_and(|resource| {
            crate::scoping::is_unscopable_legacy_exchange_permission(resource, &g.value)
        })
    });

    if !mailbox_unscoped.is_empty() {
        c.issues.push(format!(
            "{}: {}",
            issue::ORG_WIDE_MAILBOX,
            join_values(&mailbox_unscoped)
        ));
        c.recommendations.push(
            "Scope mailbox access to specific mailboxes using RBAC for Applications".to_string(),
        );
    }
    if !unscopable_legacy.is_empty() {
        c.issues.push(format!(
            "{}: {}",
            issue::UNSCOPABLE_LEGACY_MAILBOX,
            join_values(&unscopable_legacy)
        ));
        c.recommendations.push(
            "Remove these legacy Office 365 Exchange Online grants — they reach every mailbox, \
             RBAC for Applications cannot confine them (it covers Microsoft Graph and EWS only), \
             and the Outlook REST endpoints they authorized were decommissioned in March 2024. \
             Use the identically named Microsoft Graph permission instead."
                .to_string(),
        );
    }
    if !unconfinable_other.is_empty() {
        c.issues.push(format!(
            "{}: {}",
            issue::UNCONFINABLE_MAILBOX,
            join_values(&unconfinable_other)
        ));
        c.recommendations.push(
            "These grants reach every mailbox, but RBAC for Applications exposes no supported \
             application role for them (or their resource could not be resolved), so the toolkit \
             cannot confine them. Review whether the access is needed, and prefer a Microsoft \
             Graph mail permission that RBAC can scope."
                .to_string(),
        );
    }
    // Confined access, split by confining mechanism (RBAC = end state, legacy AAP
    // = migrate off). Both keep the reduced scoped weight — the policy really
    // does confine the grant.
    let (scoped_legacy, scoped_rbac): (Vec<&ResourcePermission>, Vec<&ResourcePermission>) =
        mailbox_scoped.into_iter().partition(|g| {
            matches!(
                perms.scope_mechanism(g),
                Some(ScopeMechanism::LegacyApplicationAccessPolicy)
            )
        });
    if !scoped_legacy.is_empty() {
        c.issues.push(format!(
            "{}: {}",
            issue::LEGACY_MAILBOX_POLICY,
            join_values(&scoped_legacy)
        ));
        c.recommendations.push(
            "Migrate this app to RBAC for Applications. An Application Access Policy is a \
             legacy per-app gate (replaced by RBAC for Applications; Microsoft has said its \
             deprecation will be announced) that constrains only Microsoft Entra grants — it cannot \
             confine access granted through Exchange RBAC, applies to every mailbox permission \
             the app holds at once, and Microsoft's replacement is a management scope plus \
             scoped role assignments."
                .to_string(),
        );
    }
    if !scoped_rbac.is_empty() {
        c.issues.push(format!(
            "Mailbox access scoped via RBAC for Applications: {}",
            join_values(&scoped_rbac)
        ));
    }
    (c, mailbox_unscoped, scoped_legacy)
}

/// Rule 12 (advisory, no score): organization-wide SharePoint access. Scoping
/// is encoded by the permission itself (`Sites.Selected` scoped, other `Sites.*`
/// org-wide) — no live lookup. Gates on each grant's resource: only Graph's
/// org-wide `Sites.*` (`is_scopable_sharepoint_resource_permission`) carries the
/// `ScopeSharePointAccess` fix; Office 365 SharePoint Online's goes to
/// `UNCONFINABLE_SHAREPOINT`; the healthy note needs
/// `is_scoped_sharepoint_resource_permission`. Returns the Graph org-wide set.
fn rule_sharepoint_advisory(
    perms: &AppPermissions,
) -> (RuleContribution, Vec<&ResourcePermission>) {
    use crate::scoping::{
        is_scopable_sharepoint_resource_permission, is_sharepoint_orgwide_permission,
    };
    let mut c = RuleContribution::default();

    // POSITIVE gate, never the negation of a legacy test: only grants the
    // Sites.Selected handler can confine carry the fix. Partitioned straight
    // off the filter, as in the mailbox rule.
    let (scopable, unconfinable): (Vec<&ResourcePermission>, Vec<&ResourcePermission>) = perms
        .app_role_grants
        .iter()
        .filter(|g| is_sharepoint_orgwide_permission(g.resource_app_id.as_deref(), &g.value))
        .partition(|g| {
            is_scopable_sharepoint_resource_permission(g.resource_app_id.as_deref(), &g.value)
        });

    if !scopable.is_empty() {
        c.issues.push(format!(
            "{}: {}",
            issue::ORG_WIDE_SHAREPOINT,
            join_values(&scopable)
        ));
        c.recommendations
            .push("Restrict SharePoint access to specific sites using Sites.Selected".to_string());
    }
    if !unconfinable.is_empty() {
        // Its own finding, and no Fix: converting would grant Graph's
        // `Sites.Selected`, strip nothing, and leave the app org-wide while the
        // audit reported it confined.
        c.issues.push(format!(
            "{}: {}",
            issue::UNCONFINABLE_SHAREPOINT,
            join_values(&unconfinable)
        ));
        c.recommendations.push(
            "Remove the org-wide Sites.* grant on Office 365 SharePoint Online, or re-declare it \
             on Microsoft Graph where it can be confined to selected sites"
                .to_string(),
        );
    }
    // POSITIVE gate, not a bare `value == "Sites.Selected"`: Office 365 SharePoint
    // Online exposes that value too, and the healthy note claims reach is
    // confined AND knowable — a legacy-resource grant is neither (the per-site
    // grants read here are Graph's). A value-keyed check reported uninspectable
    // apps as confirmed-scoped.
    if perms.app_role_grants.iter().any(|g| {
        crate::scoping::is_scoped_sharepoint_resource_permission(
            g.resource_app_id.as_deref(),
            &g.value,
        )
    }) {
        c.issues
            .push(format!("{}: Sites.Selected", issue::SCOPED_SHAREPOINT));
    }
    (c, scopable)
}

/// Rule 13 (advisory, no score): high-risk delegated permissions — the legacy
/// module weighted delegated only via Rule 3, so this surfaces specific scopes
/// without altering the score. Two halves, gated differently:
/// - the ported pair [`HIGH_RISK_DELEGATED_PERMISSIONS`] (`Constants.ps1:104-130`)
///   is reported whenever requested, consented or not;
/// - the net-new broad-reach prefixes ([`is_risky_delegated_scope`]: `Mail.`,
///   `Files.`, `Directory.`, `Group.`, `Sites.`, …) only when an admin
///   consented for every user (AllPrincipals) — a user-consented delegated
///   scope reaches only that user's data, so a declared `Mail.Read` is not the
///   tenant-wide reach this finding names.
///
/// `declared` = requested scopes; `admin_consented` = the AllPrincipals grant
/// set (includes consented-but-undeclared dynamic-consent scopes). `None` =
/// consent state unknown → broad prefixes fall back to declared scopes,
/// over-reporting rather than hiding.
fn rule_high_risk_delegated(
    declared: &[String],
    admin_consented: Option<&[String]>,
) -> RuleContribution {
    let mut c = RuleContribution::default();
    // The module's OWN broader predicate (`is_risky_delegated_scope`, also used by
    // the consent-grant audit), not just the two-entry exact list. Declared
    // first, then consented-but-undeclared, each named once.
    let mut hits: Vec<&str> = Vec::new();
    for v in declared.iter().chain(admin_consented.unwrap_or_default()) {
        let v = v.as_str();
        let flagged = HIGH_RISK_DELEGATED_PERMISSIONS.contains(&v)
            || (is_risky_delegated_scope(v)
                && admin_consented.is_none_or(|set| set.iter().any(|s| s == v)));
        if flagged && !hits.contains(&v) {
            hits.push(v);
        }
    }
    if !hits.is_empty() {
        c.issues.push(format!(
            "{} {}",
            issue::HIGH_RISK_DELEGATED_PERMS,
            join_refs(&hits)
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

/// Rules 19 & 20: exposure beyond this directory. `signInAudience` decides
/// whether permissions and credentials are reachable from *other* directories,
/// so it is a blast-radius multiplier, scored **only when the app has something
/// worth reaching** (an app permission or a credential) — flagging empty
/// multi-tenant apps buries the ones that matter. Publisher verification rides
/// the same rule: it is how a *consenting* tenant's admin attributes the app to
/// a real MPN-verified author, meaningless on a single-tenant internal app.
/// (Rule 15's guidance already leaned on this reasoning without anything
/// scoring the audience it named.)
fn rule_external_exposure(
    app: &Application,
    has_app_permissions: bool,
    has_credentials: bool,
) -> RuleContribution {
    let mut c = RuleContribution::default();
    let audience = app.sign_in_audience.as_deref().unwrap_or_default();
    let reach = match audience {
        "AzureADMultipleOrgs" => "any Entra tenant",
        "AzureADandPersonalMicrosoftAccount" => "any Entra tenant and personal Microsoft accounts",
        // Personal Microsoft accounts ONLY — no other Entra directory can
        // consent, so naming "any Entra tenant" here would be false.
        "PersonalMicrosoftAccount" => "personal Microsoft accounts",
        // "AzureADMyOrg" and anything unrecognised: treat as single-tenant. An
        // unknown value must never *inflate* a score.
        _ => return c,
    };
    if !(has_app_permissions || has_credentials) {
        return c;
    }

    c.score += PTS_MULTITENANT_EXPOSURE;
    c.issues.push(format!(
        "{} — this app can be consented to from {reach}, so its permissions and credentials are not confined to this directory",
        issue::MULTITENANT_AUDIENCE
    ));
    let intent = if audience == "PersonalMicrosoftAccount" {
        "to accept personal Microsoft accounts"
    } else {
        "to be multi-tenant"
    };
    c.recommendations.push(format!(
        "Confirm this app is intended {intent}. If it is only used by this organization, set its sign-in audience to 'Accounts in this organizational directory only' (AzureADMyOrg)"
    ));

    if app.verified_publisher.as_ref().is_none_or(|p| {
        p.verified_publisher_id
            .as_deref()
            .unwrap_or_default()
            .is_empty()
    }) {
        c.score += PTS_UNVERIFIED_PUBLISHER;
        c.issues.push(format!(
            "{} — admins in other tenants cannot attribute this app to a verified author when consenting",
            issue::UNVERIFIED_PUBLISHER
        ));
        c.recommendations.push(
            "Complete publisher verification so consenting admins see a verified publisher name (and so the app is eligible for the default user-consent policies that require one)"
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
) -> (RuleContribution, Vec<RedundantPermission>) {
    let mut c = RuleContribution::default();
    // `value_fully_scoped`, not `is_scoped`: the broader permission confines the
    // narrower only if EVERY grant of that name is confined (a surviving
    // unscopable legacy namesake still reaches every mailbox). Takes GRANTS, not
    // a resource-stripped value list — stripping let a Graph permission pair with
    // a legacy same-name covering nothing. See `redundant_app_permissions`.
    let redundant =
        redundant_app_permissions(&perms.app_role_grants, |b| perms.value_fully_scoped(b));
    if !redundant.is_empty() {
        // Name the resource: `Mail.Read` exists on both Graph and the legacy resource,
        // and only the pair on ONE is redundant — an unqualified listing made
        // the operator guess, and guessing wrong removes uncovered access.
        let listing = redundant
            .iter()
            .map(|r| {
                format!(
                    "{} on {} (covered by {})",
                    r.value,
                    crate::scoping::resource_label(&r.resource_app_id),
                    r.covered_by.join(", ")
                )
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
/// score): names the concrete narrower alternative per risk-flagged permission.
/// Admin-judged, so never a one-click remediation. Takes the GRANTS, not bare
/// values: the alternatives in [`SUBSUMED_APP_PERMISSIONS`] are Graph-only (a
/// legacy-resource `Mail.Read` has no `Mail.ReadBasic` to name), and an
/// already-confined grant needs no narrower alternative.
fn rule_downgrade_pointers(
    grants: &[ResourcePermission],
    is_confined: impl Fn(&ResourcePermission) -> bool,
) -> RuleContribution {
    let mut c = RuleContribution::default();
    let downgrades: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        grants
            .iter()
            // A downgrade alternative is only meaningful on the resource that
            // actually exposes it. The subsumption table is Graph's.
            .filter(|g| {
                g.resource_app_id.as_deref() == Some(crate::scoping::MICROSOFT_GRAPH_APP_ID)
            })
            // Already confined ⇒ not org-wide; the advice names a solved problem.
            .filter(|g| !is_confined(g))
            .map(|g| g.value.as_str())
            .filter(|v| {
                (HIGH_RISK_APP_PERMISSIONS.contains(v) || MEDIUM_RISK_APP_PERMISSIONS.contains(v))
                    && seen.insert(*v)
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

/// One-click remediations, keyed off the same rule-computed sets as their
/// issues — a "Fix" button appears exactly when its finding does. The backend
/// re-resolves live state before acting; `targets`/`detail` are the preview.
/// Fixed order: remove-expired, scope-mailbox, migrate-legacy-policy,
/// scope-SharePoint, remove-redundant, add-owner. `None` `owner_count` =
/// owners not fetched (SP-only rows) ⇒ no AddOwner.
fn build_remediations(
    expired: &[&CredentialSummary],
    mailbox_unscoped: &[&ResourcePermission],
    mailbox_legacy: &[&ResourcePermission],
    sharepoint_orgwide: &[&ResourcePermission],
    redundant: &[RedundantPermission],
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
                join_values(mailbox_unscoped)
            ),
            targets: mailbox_unscoped.iter().map(|g| g.value.clone()).collect(),
        });
    }
    if !mailbox_legacy.is_empty() {
        let n = mailbox_legacy.len();
        remediations.push(RemediationAction {
            kind: RemediationKind::MigrateApplicationAccessPolicy,
            label: "Migrate to RBAC for Applications".to_string(),
            detail: format!(
                "Replaces the legacy policy confining {n} permission{}: {}",
                if n == 1 { "" } else { "s" },
                join_values(mailbox_legacy)
            ),
            // Migration is keyed per app (one AAP gates every mailbox
            // permission); the values ride along as the scope-preview.
            targets: mailbox_legacy.iter().map(|g| g.value.clone()).collect(),
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
                join_values(sharepoint_orgwide)
            ),
            targets: sharepoint_orgwide.iter().map(|g| g.value.clone()).collect(),
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
                    .map(|r| format!(
                        "{} on {}",
                        r.value,
                        crate::scoping::resource_label(&r.resource_app_id)
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            targets: redundant.iter().map(|r| r.value.clone()).collect(),
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

/// Builds an [`AuditItem`] for `app`. All inputs must be pre-resolved: the
/// caller is responsible for turning Graph IDs into permission name strings
/// (via a live resource-SP lookup).
///
/// `now` is a parameter so tests can use deterministic timestamps.
pub fn score_application(
    app: &Application,
    sp_enabled: Option<bool>,
    perms: &AppPermissions,
    now: DateTime<Utc>,
) -> AuditItem {
    // Collapse duplicate grants on (resource, value) BEFORE any rule counts
    // them: risk points scale with grant count, so a twice-listed permission
    // scored twice and could cross a risk threshold. Done here so no caller can
    // forget it. See `AppPermissions::deduped`.
    let deduped = perms.deduped();
    let perms = &deduped;

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
    // Credentials that STILL WORK, including no-end-date (`Unknown`) ones.
    // Counting only `Active` let an app with one expired + one never-expiring
    // secret report "All credentials expired" — it reads as a dead app, hiding
    // the permanent credential that most needs finding.
    // `ExpiringSoon` is deliberately NOT counted: the branches below use
    // `active_count == 0` for "nothing but expiring left".
    let active_count = all_creds
        .iter()
        .filter(|c| {
            matches!(
                c.status,
                CredentialStatus::Active | CredentialStatus::Unknown
            )
        })
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

    // Invariant: every rule classifies from `app_role_grants`, so the resource
    // is available at every decision (the resource-stripped value list is gone).

    // Rules 11, 12, 18 also return the sets the remediation block keys off.
    let (mail_contrib, mailbox_unscoped, mailbox_legacy) = rule_mailbox_advisory(perms);
    acc.merge(mail_contrib);
    let (sharepoint_contrib, sharepoint_orgwide) = rule_sharepoint_advisory(perms);
    acc.merge(sharepoint_contrib);
    acc.merge(rule_high_risk_delegated(
        &perms.scope_values,
        perms.admin_consented_scopes.as_deref(),
    )); // Rule 13

    let has_app_permissions = !perms.app_role_grants.is_empty();
    let has_credentials = !all_creds.is_empty();
    acc.merge(rule_app_hygiene(
        app,
        has_app_permissions,
        has_credentials,
        !secrets.is_empty(),
    )); // Rules 14-17

    let (redundant_contrib, redundant) = rule_redundant_permissions(perms); // Rule 18
    acc.merge(redundant_contrib);
    acc.merge(rule_external_exposure(
        app,
        has_app_permissions,
        has_credentials,
    )); // Rules 19 & 20
    // The grants, not `values`: the alternatives are Graph-only, and an
    // already-confined grant needs no downgrade advice. See the rule's doc.
    acc.merge(rule_downgrade_pointers(&perms.app_role_grants, |g| {
        perms.is_scoped(g)
    })); // least-privilege downgrade pointers

    let permission_count = (perms.app_role_grants.len() + perms.scope_values.len()) as u32;

    let remediations = build_remediations(
        &expired,
        &mailbox_unscoped,
        &mailbox_legacy,
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
        // An application lives in this tenant; the owner-tenant column is for
        // SP-only rows.
        app_owner_organization_id: None,
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
    /// `app_owner_organization_id` (its own export column), not `publisher`,
    /// which is an application's verified publisher domain.
    pub app_owner_organization_id: Option<String>,
    /// Graph `servicePrincipalType`; `ManagedIdentity` selects
    /// [`AuditPrincipalKind::ManagedIdentity`] (drives Open/Fix routing).
    pub service_principal_type: Option<String>,
}

/// Builds an [`AuditItem`] for a service principal with no local application
/// object. Only *granted*-state rules apply (1/2, 3, 4, 11, 12, 13); credential
/// and manifest rules (5-9, 10, 14-18, downgrade pointers) are absent — those
/// live on the home tenant's application, which this tenant can neither see nor
/// fix. `app_role_grants` are the SP's *granted* app roles
/// (`appRoleAssignments`) and `scope_values` its AllPrincipals delegated scopes,
/// so Rule 13 treats them as consented and ignores `admin_consented_scopes`.
pub fn score_service_principal(
    sp: &SpAuditInput,
    perms: &AppPermissions,
    now: DateTime<Utc>,
) -> AuditItem {
    // Same normalization as `score_application` — an SP's granted roles can
    // repeat too, and the risk rules count them the same way.
    let deduped = perms.deduped();
    let perms = &deduped;

    let mut acc = RuleContribution::default();
    acc.merge(rule_app_permission_risk(perms)); // Rules 1 & 2
    acc.merge(rule_admin_consent(perms)); // Rule 3
    acc.merge(rule_sp_disabled(sp.account_enabled)); // Rule 4

    // Rules 11 & 12 also return the sets the remediation block keys off.
    let (mail_contrib, mailbox_unscoped, mailbox_legacy) = rule_mailbox_advisory(perms);
    acc.merge(mail_contrib);
    let (sharepoint_contrib, sharepoint_orgwide) = rule_sharepoint_advisory(perms);
    acc.merge(sharepoint_contrib);
    // An SP row's `scope_values` already ARE its AllPrincipals grant set.
    acc.merge(rule_high_risk_delegated(
        &perms.scope_values,
        Some(&perms.scope_values),
    )); // Rule 13

    // Only the scope remediations (SP-only cores exist): expired credentials
    // are unknowable, redundancy removal edits the manifest, and SP owners
    // aren't audited. Legacy-policy migration keys on appId from *granted*
    // roles, so it applies to a bare SP too.
    let remediations = build_remediations(
        &[],
        &mailbox_unscoped,
        &mailbox_legacy,
        &sharepoint_orgwide,
        &[],
        None,
    );

    AuditItem {
        application_name: sp.display_name.clone(),
        app_id: sp.app_id.clone(),
        object_id: sp.sp_object_id.clone(),
        created_date: sp.created_date_time,
        // The owner tenant is a GUID, not a publisher domain: it rides its own
        // field so the Publisher column means one thing on every row.
        publisher: None,
        app_owner_organization_id: sp.app_owner_organization_id.clone(),
        sign_in_audience: None,
        risk_score: acc.score,
        risk_level: RiskLevel::from_score(acc.score),
        issues: acc.issues,
        recommendations: acc.recommendations,
        remediations,
        // Credentials live on the application in its home tenant — unknowable
        // here, and deliberately never flagged.
        credential_status: CredentialStatus::Unknown,
        permission_count: (perms.app_role_grants.len() + perms.scope_values.len()) as u32,
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

fn join_refs<S: AsRef<str>>(items: &[S]) -> String {
    items
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<&str>>()
        .join(", ")
}

/// `join_refs` over grant *values*. The resource stays out of operator-facing
/// text — same-named grants on different resources read as one name, as in the
/// portal.
fn join_values(items: &[&ResourcePermission]) -> String {
    items
        .iter()
        .map(|g| g.value.as_str())
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
mod tests;
