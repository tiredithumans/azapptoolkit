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

    // Partitioned on the *grant*, not the value: `is_scoped` gates on the
    // grant's own resource, so an unscopable legacy Exchange Online namesake
    // keeps full weight even while the Graph permission of the same name is
    // confirmed scoped.
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

/// The reduced-weight advisory for one risk tier's confirmed-scoped mailbox
/// permissions, **split by the mechanism confining them**. The score is
/// identical either way (both genuinely confine the access) — only the wording
/// differs, and it has to: the RBAC line carries [`issue::SCOPED_VIA_RBAC`],
/// which the UI matches mid-string to populate the *healthy* "Mailbox access
/// scoped" group. Emitting it for a legacy Application Access Policy would file
/// the row under a positive signal and bury the migration finding Rule 11
/// raises for the very same permission.
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
    // `active_count` deliberately excludes `ExpiringSoon` so the expiring-soon
    // rules below can say "nothing but expiring credentials left". That is sound
    // there and NOT sound here: with one expired secret and one expiring-soon
    // secret, `active_count == 0` while a working credential is still
    // authenticating. Reporting "All credentials expired" then reads as a dead
    // app, so an operator stops looking — and the ranking overstates the risk.
    // Only the count of credentials that still WORK decides this branch.
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

/// Rule 11 (advisory, no score): organization-wide mailbox access. Splits the
/// mailbox-reaching grants five ways, because the remedy differs per bucket:
///
/// - **confirmed scoped** via Exchange RBAC → informational only;
/// - **confirmed scoped by a legacy Application Access Policy** → its own
///   finding plus the `MigrateApplicationAccessPolicy` fix. The access really is
///   confined (so it keeps the reduced scoped weight the risk rules give it —
///   this is not an org-wide finding), but the mechanism is deprecated: AAPs are
///   an all-or-nothing per-app gate that only constrains Entra grants, and
///   Microsoft's replacement is RBAC for Applications;
/// - **org-wide and scopable** → the `ScopeMailboxAccess` remediation. Decided
///   by [`crate::scoping::is_scopable_exchange_resource_permission`], the same
///   positive gate [`AppPermissions::is_scoped`] uses — never by the negation
///   of the legacy test below, which admits three unscopable shapes;
/// - **org-wide on the legacy Office 365 Exchange Online resource** → its own
///   finding and **no** remediation. RBAC for Applications covers Microsoft
///   Graph and EWS only, so nothing can confine that resource's Outlook REST
///   `Mail.*` roles — removing the grant is the only remedy, and a "Scope…"
///   button there would promise a fix that cannot be honoured;
/// - **org-wide but unconfinable for any other reason** — a `Mail.*` /
///   `MailboxSettings.*` name outside the mapped role set, a resource this
///   build doesn't map, or a resource that failed to resolve at all → its own
///   finding and **no** remediation, because "remove the legacy grant" is the
///   wrong advice for access that may be entirely legitimate.
///
/// Membership comes from [`crate::scoping::is_mailbox_reaching_permission`],
/// which is resource-aware — a bare `Mail.*` name test misses the EWS
/// `full_access_as_app` scope entirely, and that grant reaches every mailbox in
/// the tenant.
///
/// Returns the *scopable* org-wide set and the legacy-policy-scoped set, for
/// their two remediations. Empty `mail_scopes` ⇒ nothing is scoped ⇒ every
/// scopable hit is org-wide (the original behavior).
type MailboxAdvisory<'a> = (
    RuleContribution,
    Vec<&'a ResourcePermission>,
    Vec<&'a ResourcePermission>,
);

fn rule_mailbox_advisory(perms: &AppPermissions) -> MailboxAdvisory<'_> {
    let mut c = RuleContribution::default();
    // Partitioned straight off the filter — this runs once per application in a
    // tenant-wide audit, and the intermediate `Vec` was built only to be
    // consumed by the very next line.
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
    // Positive test, deliberately: only a permission RBAC for Applications can
    // actually confine may carry the ScopeMailboxAccess remediation. Asking the
    // negative question ("is it *not* the legacy Outlook-REST case?") let three
    // other shapes through into the fix — a `None` resource, a resource this
    // build doesn't map, and a `Mail.*`/`MailboxSettings.*` name on Microsoft
    // Graph outside the mapped role set — every one of which
    // `is_scopable_exchange_resource_permission` declares unscopable, so the
    // handler could only fail on (or worse, mis-apply) the Fix it was offered.
    // This mirrors the gate `AppPermissions::is_scoped` already uses.
    let (mailbox_unscoped, unconfinable): (Vec<&ResourcePermission>, Vec<&ResourcePermission>) =
        mailbox_orgwide.into_iter().partition(|g| {
            crate::scoping::is_scopable_exchange_resource_permission(
                g.resource_app_id.as_deref(),
                &g.value,
            )
        });
    // Split what cannot be confined by *why*, because the advice differs:
    // removing the grant is the only remedy for the legacy Outlook-REST roles,
    // but plain wrong for a permission whose resource merely failed to resolve.
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
    // Confined access, split by the mechanism doing the confining: RBAC for
    // Applications is the end state, a legacy Application Access Policy is a
    // deprecated one to migrate off. Both keep the reduced scoped weight the
    // risk rules already applied — the policy really does confine the grant.
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
             deprecated per-app gate that constrains only Microsoft Entra grants — it cannot \
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

/// Rule 12 (advisory, no score): organization-wide SharePoint access. SharePoint
/// scoping is encoded by the permission itself (`Sites.Selected` is scoped,
/// every other `Sites.*` is org-wide), so no live lookup is needed. Returns the
/// org-wide set for the ScopeSharePointAccess remediation.
/// Takes the resource-stripped values: SharePoint scoping is encoded by the
/// permission name alone, so unlike the mailbox rule it needs no resource.
fn rule_sharepoint_advisory(
    perms: &AppPermissions,
) -> (RuleContribution, Vec<&ResourcePermission>) {
    use crate::scoping::{
        is_scopable_sharepoint_resource_permission, is_sharepoint_orgwide_permission,
    };
    let mut c = RuleContribution::default();

    // Split on the POSITIVE gate, never on the negation of a legacy test: only
    // grants the Sites.Selected handler can actually confine may carry the fix.
    // Partitioned straight off the filter, as in the mailbox rule above.
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
        // Its own finding, and no Fix: converting these would grant Graph's
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
    // POSITIVE gate, like the org-wide split above and the mailbox rule's — not
    // a bare `value == "Sites.Selected"`. Office 365 SharePoint Online exposes
    // `Sites.Selected` too, and this healthy note claims the app's SharePoint
    // reach is confined AND knowable; for a legacy-resource grant it is neither
    // (the per-site grants the toolkit reads are Graph's). A value-keyed check
    // here reported an app the toolkit cannot inspect as confirmed-scoped.
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

/// Rule 13 (advisory, no score): high-risk delegated permissions. The legacy
/// module weighted delegated permissions only via the admin-consent check
/// (Rule 3), so this surfaces the specific scopes without altering the score.
fn rule_high_risk_delegated(perms: &AppPermissions) -> RuleContribution {
    let mut c = RuleContribution::default();
    // The module's OWN broader predicate, not just the two-entry exact list.
    //
    // `is_risky_delegated_scope` already encodes what "risky delegated scope"
    // means here — the two named scopes PLUS the broad-reach prefixes (Mail.,
    // Files., Directory., Group., AppRoleAssignment., RoleManagement., Sites.)
    // — and the consent-grant audit uses it. This rule matched only the exact
    // pair, so an admin-consented `Mail.ReadWrite` or `Directory.ReadWrite.All`
    // DELEGATED scope produced no advisory at all: two definitions of the same
    // idea, and the narrower one was in front of the operator.
    let high_risk_delegated: Vec<&String> = perms
        .scope_values
        .iter()
        .filter(|v| is_risky_delegated_scope(v))
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

/// Rules 19 & 20: exposure beyond this directory.
///
/// `signInAudience` decides whether an app's permissions and credentials are
/// reachable by principals in *other* directories at all, so it is a blast-radius
/// multiplier on every other finding rather than a finding on its own. It is
/// therefore scored **only when the app has something worth reaching** — an
/// application permission or a credential. A multi-tenant app holding neither is
/// not interesting, and flagging it would bury the ones that matter.
///
/// Publisher verification rides the same rule because it is only meaningful in
/// the same situation: it is how a *consenting* tenant's admin attributes the
/// app to a real, MPN-verified author. On a single-tenant internal app there is
/// nobody to attribute it to, so the absence is not a finding.
///
/// This is the reasoning Rule 15's own guidance already leans on ("especially
/// for multitenant apps, where a foreign tenant's admin could otherwise add
/// credentials"), previously with nothing scoring the audience it named.
fn rule_external_exposure(
    app: &Application,
    has_app_permissions: bool,
    has_credentials: bool,
) -> RuleContribution {
    let mut c = RuleContribution::default();
    let audience = app.sign_in_audience.as_deref().unwrap_or_default();
    let (multitenant, personal) = match audience {
        "AzureADMultipleOrgs" => (true, false),
        "AzureADandPersonalMicrosoftAccount" | "PersonalMicrosoftAccount" => (true, true),
        // "AzureADMyOrg" and anything unrecognised: treat as single-tenant. An
        // unknown value must never *inflate* a score.
        _ => (false, false),
    };
    if !multitenant || !(has_app_permissions || has_credentials) {
        return c;
    }

    c.score += PTS_MULTITENANT_EXPOSURE;
    let reach = if personal {
        "any Entra tenant and personal Microsoft accounts"
    } else {
        "any Entra tenant"
    };
    c.issues.push(format!(
        "{} — this app can be consented to from {reach}, so its permissions and credentials are not confined to this directory",
        issue::MULTITENANT_AUDIENCE
    ));
    c.recommendations.push(
        "Confirm this app is intended to be multi-tenant. If it is only used by this organization, set its sign-in audience to 'Accounts in this organizational directory only' (AzureADMyOrg)"
            .to_string(),
    );

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
    // `value_fully_scoped`, not `is_scoped`: the broader permission only
    // confines the narrower one if EVERY grant of that name is confined. A
    // `Mail.ReadWrite` scoped on Graph while its unscopable legacy Exchange
    // Online namesake survives still reaches every mailbox.
    // The GRANTS, not `perms.app_role_values()`: stripping the resource here
    // let a Graph permission pair with a same-named one on the legacy Office 365
    // resource, which covers nothing of it. See `redundant_app_permissions`.
    let redundant =
        redundant_app_permissions(&perms.app_role_grants, |b| perms.value_fully_scoped(b));
    if !redundant.is_empty() {
        // Name the resource: `Mail.Read` exists on Microsoft Graph AND on the
        // legacy Office 365 Exchange Online resource, and only the pair on ONE
        // of them is redundant. "Mail.Read (covered by Mail.ReadWrite)" left the
        // operator to guess which grant to remove — and guessing wrong removes
        // access nothing covers.
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
/// score): names the concrete narrower alternative for each risk-flagged
/// permission so the Rule-1/2 advice is actionable. Admin-judged, so never a
/// one-click remediation.
/// Takes the GRANTS, not bare values. It was the last rule reading
/// `perms.app_role_values()`, and stripping the resource made it wrong twice
/// over: the narrower alternatives in [`SUBSUMED_APP_PERMISSIONS`] are Microsoft
/// Graph permissions, so pointing an Office 365 Exchange Online `Mail.Read` at
/// "Mail.ReadBasic" named a permission that resource does not expose; and a
/// grant already confined via Exchange RBAC does not need a narrower
/// alternative, so the advice fired on permissions the operator had already
/// dealt with.
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
            // Already confined ⇒ the broader capability is not org-wide, so
            // "narrower alternatives exist" is advice for a problem that has
            // been solved by a different mechanism.
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

/// Structured one-click remediations, keyed off the same rule-computed sets
/// that raised the corresponding issues — so a "Fix" button appears exactly
/// when its finding does. The backend re-resolves live state before acting;
/// `targets`/`detail` are the advisory preview. Emitted in a fixed order:
/// remove-expired, scope-mailbox, migrate-legacy-policy, scope-SharePoint,
/// remove-redundant, add-owner. `owner_count` is the same `app.owners` data
/// Rule 14 keys off (`None` = owners not fetched — SP-only rows — so no
/// AddOwner is attached).
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
            // The migration is keyed on the application, not per permission —
            // one Application Access Policy gates every mailbox permission the
            // app holds — but the values ride along as the in-row preview of
            // what the new management scope will carry.
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

pub fn score_application(
    app: &Application,
    sp_enabled: Option<bool>,
    perms: &AppPermissions,
    now: DateTime<Utc>,
) -> AuditItem {
    // Collapse duplicate grants on (resource, value) BEFORE any rule counts
    // them: the risk rules scale their point constants by the length of the
    // matching grant vector, so a permission listed twice in the manifest
    // scored twice and could cross a risk-level threshold. Done here rather
    // than in each caller so none can forget it. See `AppPermissions::deduped`.
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
    // Credentials that STILL WORK — which includes one with no end date.
    //
    // `credential_status(None)` is `Unknown`, and counting only `Active` meant a
    // never-expiring credential counted as nothing: an app holding one expired
    // secret plus one that never expires reported "All credentials expired" and
    // scored as though it had no working credential at all. That reads as a dead
    // app, so an operator stops looking — while the app in fact holds a
    // permanent, never-rotating credential, which is the one most worth finding.
    // `ExpiringSoon` is deliberately NOT counted here: the branches below use
    // `active_count == 0` to mean "nothing but expiring credentials left", and
    // folding it in would silence that warning entirely.
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

    // (No resource-stripped value list any more: `rule_downgrade_pointers` was
    // the last rule reading one, and it now takes the grants. Every rule in
    // `score_application` classifies from `app_role_grants`, so the resource is
    // available at every decision — which is the invariant, not an optimization.)

    // Rules 11, 12, 18 also return the sets the remediation block keys off.
    let (mail_contrib, mailbox_unscoped, mailbox_legacy) = rule_mailbox_advisory(perms);
    acc.merge(mail_contrib);
    let (sharepoint_contrib, sharepoint_orgwide) = rule_sharepoint_advisory(perms);
    acc.merge(sharepoint_contrib);
    acc.merge(rule_high_risk_delegated(perms)); // Rule 13

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
    acc.merge(rule_high_risk_delegated(perms)); // Rule 13

    // No expired credentials (unknowable), no redundant-permission removal
    // (its remediation edits the application manifest), and no add-owner
    // (`None`: SP owners aren't audited) — only the scope remediations, whose
    // SP-only command cores exist. The legacy-policy migration is keyed on the
    // appId and works from *granted* roles, so it applies to a bare SP too.
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

/// `join_refs` over the *values* of a set of resource-qualified grants. The
/// resource stays out of the operator-facing text: two identically named grants
/// on different resources read as one name, which is exactly what the reader
/// sees in the portal.
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
