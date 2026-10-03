//! Tenant-wide reads resolved once, before the per-app fan-out. Each is
//! best-effort: a failure degrades coverage, it never fails the run.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use azapptoolkit_core::audit::{CredentialActivity, MailPermissionScope};
use azapptoolkit_core::cache::Cache;
use azapptoolkit_core::models::ServicePrincipal;
use azapptoolkit_core::scoping::{EWS_FULL_ACCESS_AS_APP, OFFICE365_EXCHANGE_ONLINE_APP_ID};
use azapptoolkit_exchange::ExchangeClient;
use azapptoolkit_exchange::verdict::aap_verdict_for;
use azapptoolkit_graph::GraphClient;
use azapptoolkit_graph::GraphError;
use chrono::{DateTime, Utc};

use crate::commands::exchange::exchange_client;
use crate::commands::graph_err::looks_like_missing_license;
use crate::commands::graph_roles::graph_role_index;
use crate::dto::UiError;
use crate::dto::audit::AuditCoverageGap;
use crate::state::AppState;

use super::AppPolicyData;

/// Best-effort Exchange client for mailbox-scoping resolution. `None` (with an
/// info log) when the Exchange client can't be built — the signed-in user isn't
/// an Exchange admin, or there's no UPN for the anchor mailbox — so mail
/// permissions score at their full org-wide weight.
pub(crate) fn audit_exchange_client(
    state: &AppState,
    tenant_id: &str,
) -> Option<Arc<ExchangeClient>> {
    match exchange_client(state, tenant_id) {
        Ok(exo) => Some(exo),
        Err(err) => {
            tracing::info!(?err, "audit: Exchange scoping unavailable");
            None
        }
    }
}

/// ONE tenant-wide `oauth2PermissionGrants` read → (AllPrincipals client ids,
/// per-client delegated scope values, whether the read succeeded). The scope
/// strings are kept per client so the SP-only phase can score high-risk
/// delegated permissions (an SP has no manifest to resolve them from), and so
/// phase 1 can tell an admin-consented scope from a merely declared one.
/// Best-effort: on failure no principal gets the admin-consent flag, the flag
/// is `false` (consent unknown, not "none") and the audit proceeds.
pub(crate) async fn prefetch_admin_consent_grants(
    client: &GraphClient,
) -> (HashSet<String>, HashMap<String, Vec<String>>, bool) {
    match client.list_all_oauth2_grants().await {
        Ok(grants) => {
            let mut clients: HashSet<String> = HashSet::new();
            let mut scopes: HashMap<String, Vec<String>> = HashMap::new();
            for g in grants {
                if g.consent_type != "AllPrincipals" {
                    continue;
                }
                scopes
                    .entry(g.client_id.clone())
                    .or_default()
                    .extend(g.scope.split_whitespace().map(str::to_string));
                clients.insert(g.client_id);
            }
            (clients, scopes, true)
        }
        Err(err) => {
            tracing::info!(
                ?err,
                "audit: tenant-wide grants read failed; admin-consent flags unavailable"
            );
            (HashSet::new(), HashMap::new(), false)
        }
    }
}

/// ONE tenant-wide `appRoleAssignedTo` read on the Microsoft Graph SP →
/// `spObjectId -> granted Graph permission values`. Feeds both the SP-only
/// scoring phase and (via [`derive_orgwide_mail_scopes`]) score_one's scoped-mail
/// reconciliation.
///
/// Still best-effort — a failure must not abort the whole audit — but it now
/// REPORTS the failure alongside the empty map. An empty map is
/// indistinguishable from "this tenant has no such grants", so swallowing the
/// error made the run score LOWER risk and present the result as complete.
pub(crate) async fn prefetch_graph_app_roles(
    client: &GraphClient,
) -> (HashMap<String, Vec<String>>, Option<AuditCoverageGap>) {
    let mut graph_roles_by_sp: HashMap<String, Vec<String>> = HashMap::new();
    if let Ok((graph_sp_id, role_value_by_id)) = graph_role_index(client).await {
        match client.list_app_role_assigned_to_cached(&graph_sp_id).await {
            Ok(assigned) => {
                for a in assigned {
                    // App permissions held by an app's SP — Users/Groups can't
                    // hold Graph app roles.
                    if a.principal_type.as_deref() != Some("ServicePrincipal") {
                        continue;
                    }
                    if let Some(v) = role_value_by_id.get(&a.app_role_id) {
                        graph_roles_by_sp
                            .entry(a.principal_id)
                            .or_default()
                            .push(v.clone());
                    }
                }
            }
            Err(err) => {
                tracing::info!(
                    ?err,
                    "audit: tenant-wide app-role assignments read failed; SP coverage and org-wide mail reconciliation unavailable"
                );
                return (
                    graph_roles_by_sp,
                    Some(AuditCoverageGap::GraphAppRoleAssignments),
                );
            }
        }
    } else {
        // The role index itself failed, so nothing below could run either.
        return (
            graph_roles_by_sp,
            Some(AuditCoverageGap::GraphAppRoleAssignments),
        );
    }
    (graph_roles_by_sp, None)
}

/// Service principals holding the EWS `full_access_as_app` scope as an org-wide
/// grant, from ONE tenant-wide `appRoleAssignedTo` read on the legacy Office 365
/// Exchange Online resource.
///
/// That resource is not Microsoft Graph, so [`prefetch_graph_app_roles`] can't see
/// these grants — and a surviving one reaches **every** mailbox with full access,
/// which defeats any RBAC mailbox scope on the same principal. Without it the
/// audit reported a scoped verdict (and the reduced scoped-mail weight) for a
/// principal that still had org-wide reach.
///
/// Best-effort: a tenant with no EWS-consenting app has no service principal for
/// the resource at all, which is normal — an empty set simply means no blanket
/// grant to reconcile against.
pub(crate) async fn prefetch_ews_full_access_grants(
    client: &GraphClient,
) -> (HashSet<String>, Option<AuditCoverageGap>) {
    let mut out = HashSet::new();
    // A tenant with no EWS-consenting app has no service principal for the
    // resource at all. That is an ordinary empty answer, NOT a gap — reporting
    // it as one would flag most tenants as degraded and teach operators to
    // ignore the banner.
    let Ok(Some(sp)) = client
        .resolve_resource_sp(OFFICE365_EXCHANGE_ONLINE_APP_ID)
        .await
    else {
        return (out, None);
    };
    let full_access_role_ids: HashSet<&str> = sp
        .app_roles
        .iter()
        .filter(|r| r.value == EWS_FULL_ACCESS_AS_APP)
        .map(|r| r.id.as_str())
        .collect();
    if full_access_role_ids.is_empty() {
        return (out, None);
    }
    match client.list_app_role_assigned_to(&sp.id).await {
        Ok(assigned) => {
            for a in assigned {
                if a.principal_type.as_deref() == Some("ServicePrincipal")
                    && full_access_role_ids.contains(a.app_role_id.as_str())
                {
                    out.insert(a.principal_id);
                }
            }
        }
        Err(err) => {
            tracing::info!(
                ?err,
                "audit: Office 365 Exchange Online app-role assignments read failed; \
                 org-wide EWS reconciliation unavailable"
            );
            // The SP exists, so this tenant DOES use the resource — the read
            // genuinely failed, and a principal that looks scoped may hold
            // blanket mailbox access.
            return (out, Some(AuditCoverageGap::EwsFullAccessGrants));
        }
    }
    (out, None)
}

/// ONE tenant-wide `Get-ApplicationAccessPolicy` read → the legacy scoping
/// verdict per **appId**: `Scoped { LegacyApplicationAccessPolicy }` for every
/// app a `RestrictAccess` policy confines (`DenyAccess` is a blocklist — still
/// effectively org-wide — so [`aap_verdict_for`] leaves it out).
///
/// A policy gates the whole application, so one cmdlet answers for every app in
/// the tenant. The per-app RBAC probe skips this lookup on the audit path (it
/// would be an extra admin-API call per app), which is why an app confined only
/// by a policy used to read org-wide here while the Permissions tab reported it
/// scoped.
///
/// Best-effort: no Exchange client, no Exchange-admin rights, or a failed read
/// all yield an empty map — every mail permission then scores at its full
/// org-wide weight, the same never-under-report degradation the rest of the
/// Exchange path takes. The `bool` is `true` only when a client existed and the
/// read FAILED: an app confined only by a policy then reads org-wide, which
/// the run reports as unresolved mailbox scoping.
pub(crate) async fn prefetch_legacy_access_policies(
    exo: Option<&ExchangeClient>,
) -> (HashMap<String, MailPermissionScope>, bool) {
    let mut out = HashMap::new();
    let Some(exo) = exo else {
        return (out, false);
    };
    let policies = match exo.get_application_access_policies().await {
        Ok(policies) => policies,
        Err(err) => {
            tracing::info!(
                code = err.ui_code(),
                "audit: legacy Application Access Policy read failed; legacy-scoping findings unavailable"
            );
            return (out, true);
        }
    };
    for app_id in policies.iter().filter_map(|p| p.app_id.clone()) {
        if out.contains_key(&app_id) {
            continue;
        }
        if let Some(verdict) = aap_verdict_for(&policies, &app_id) {
            out.insert(app_id, verdict);
        }
    }
    (out, false)
}

/// The tenant's service-principal index (get-or-fetch, cached under
/// `CacheKind::Lists` — the same shared index as `list_enterprise_applications`),
/// the candidate pool for the SP-only scoring phase. Best-effort: on failure the
/// run covers app registrations only.
pub(crate) async fn prefetch_sp_index(
    cache: &Cache,
    client: &GraphClient,
    tenant_id: &str,
) -> (Arc<Vec<ServicePrincipal>>, Option<AuditCoverageGap>) {
    if let Some(cached) = crate::commands::applications::sp_index_hit(cache, tenant_id) {
        return (cached, None);
    }
    // Captured BEFORE the scan: it takes seconds under no lock, and re-pinning
    // a pre-mutation snapshot would outlive the invalidation it raced.
    let watch = cache.generation_for(
        azapptoolkit_core::cache::CacheKind::Lists,
        &crate::commands::applications::sp_index_key(tenant_id),
    );
    match client.list_service_principals_index().await {
        Ok(sps) => (
            crate::commands::applications::sp_index_store_if_current(cache, sps, watch),
            None,
        ),
        Err(err) => {
            // NOT just a log. Returning an empty index silently drops the whole
            // SP-only scoring phase — enterprise apps, managed identities and
            // orphaned service principals — and without a gap the run reported
            // itself complete and `run_is_cacheable` cached it as authoritative,
            // so an operator could not tell "no findings" from "never looked".
            // The sibling `prefetch_graph_app_roles` already returns a gap for
            // exactly this consequence.
            tracing::warn!(
                ?err,
                "audit: SP index unavailable; scanning app registrations only"
            );
            (
                Arc::new(Vec::new()),
                Some(AuditCoverageGap::ServicePrincipalIndex),
            )
        }
    }
}

/// The `servicePrincipalSignInActivities` report → `(available,
/// consent_required, appId -> last sign-in)`. Pre-acquires the
/// `AuditLog.Read.All` token with a typed call so a *missing-consent* failure (→
/// `consent_required`, a "Grant consent" button) is distinguishable from a
/// license/availability one. Either failure disables unused-app detection
/// (`available = false` ⇒ no app is flagged "unused").
pub(crate) async fn prefetch_sign_in_activity(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
) -> (bool, bool, Arc<HashMap<String, Option<DateTime<Utc>>>>) {
    match state.ensure_audit_log_token(tenant_id).await {
        Ok(()) => match client.list_service_principal_sign_in_activities().await {
            Ok(items) => {
                let map: HashMap<String, Option<DateTime<Utc>>> = items
                    .into_iter()
                    .filter_map(|a| {
                        a.app_id.map(|id| {
                            (
                                id,
                                a.last_sign_in_activity
                                    .and_then(|s| s.last_sign_in_date_time),
                            )
                        })
                    })
                    .collect();
                (true, false, Arc::new(map))
            }
            Err(err) => {
                tracing::info!(
                    ?err,
                    "sign-in activity report unavailable; skipping unused-app detection"
                );
                (false, false, Arc::new(HashMap::new()))
            }
        },
        Err(err) => {
            let ui = UiError::from(err);
            let consent_required = ui.is_consent_required();
            tracing::info!(
                code = %ui.code,
                "AuditLog.Read.All token unavailable; skipping unused-app detection"
            );
            (false, consent_required, Arc::new(HashMap::new()))
        }
    }
}

/// The tenant-wide Identity Protection risky-service-principal report →
/// `(available, sp_objectId -> (riskState, riskLevel), gap)`.
///
/// The availability split follows the sign-in/report precedent, NOT the
/// grant-matrix reads: a tenant that has not consented `IdentityRiskyService
/// Principal.Read.All` (or lacks a Workload Identities premium license — the
/// endpoint 403s `Authentication_RequestFromNonPremiumTenantOrB2CTenant` for
/// unlicensed tenants) reads as *unavailable*, no gap, so most tenants do not
/// get a permanent "degraded" banner that would train operators to ignore it.
/// A genuine failed read on an entitled tenant IS a coverage gap: the
/// risky-SP check silently stopped working there, so the run must not be
/// cached or shown as an all-clear.
///
/// Only `confirmedCompromised` / `atRisk` rows are kept — the report ships
/// every principal it tracks, and Rule 22 fires on those two states only.
/// Deliberately not cached (unlike the sign-in report): a compromised-SP flag
/// must be re-read by every run, and the payload is one row per flagged
/// principal.
pub(crate) async fn prefetch_risky_service_principals(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
) -> (
    bool,
    Arc<HashMap<String, (String, String)>>,
    Option<AuditCoverageGap>,
) {
    let empty = || (false, Arc::new(HashMap::new()), None);
    // Pre-acquire the scoped token so a missing consent/license surfaces
    // before the read. Failure means the tenant cannot use the feature today
    // — unavailable, not a gap (see the doc comment).
    let Ok(()) = state.ensure_risky_service_principal_token(tenant_id).await else {
        tracing::info!(
            "audit: risky-service-principal report unavailable; skipping risky-SP check"
        );
        return empty();
    };
    match client.list_risky_service_principals().await {
        Ok(rows) => {
            let map: HashMap<String, (String, String)> = rows
                .into_iter()
                .filter(|r| {
                    matches!(
                        r.risk_state.as_deref(),
                        Some("confirmedCompromised") | Some("atRisk")
                    )
                })
                .filter_map(|r| {
                    Some((
                        r.service_principal_id?,
                        (
                            r.risk_state?,
                            r.risk_level.unwrap_or_else(|| "unknown".to_string()),
                        ),
                    ))
                })
                .collect();
            (true, Arc::new(map), None)
        }
        Err(err) if matches!(&err, GraphError::Forbidden(body) if looks_like_missing_license(body)) =>
        {
            // Entitlement failed at the endpoint, not the token: the tenant is
            // not on Workload Identities premium (or the feature is not
            // provisioned). Same "unavailable" class as the token arm.
            tracing::info!(
                ?err,
                "audit: risky-service-principal report not licensed in this tenant; skipping risky-SP check"
            );
            (false, Arc::new(HashMap::new()), None)
        }
        Err(err) => {
            tracing::warn!(
                ?err,
                "audit: risky-service-principal read failed; risky-SP coverage gap"
            );
            (
                false,
                Arc::new(HashMap::new()),
                Some(AuditCoverageGap::RiskyServicePrincipals),
            )
        }
    }
}

/// ONE tenant-wide per-credential last-used read (beta
/// `appCredentialSignInActivities`, **global cloud only**) → `(available,
/// "appId|keyId" -> CredentialActivity)`. Rides the same `AuditLog.Read.All`
/// token as [`prefetch_sign_in_activity`]; a missing-consent failure there
/// already surfaces the "Grant consent" button, so this report has no consent
/// state of its own — either way `available = false` just disables the
/// unused-credential advisory, and on a sovereign build the 404 lands here as
/// the same graceful degradation.
///
/// An app's own credential can appear twice (once per `credentialOrigin`);
/// the fold keeps the NEWEST date per credential, and a credential with any
/// dated row never collapses to `Never`. A credential absent from the report
/// has no key at all and scores `Unknown` — never "unused": the preview
/// report's coverage of never-used credentials is not contractual, so
/// inferring non-use from absence would flag live credentials whose use it
/// simply does not surface.
pub(crate) async fn prefetch_credential_activity(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
) -> (bool, Arc<HashMap<String, CredentialActivity>>) {
    let unavailable = || (false, Arc::new(HashMap::new()));
    match state.ensure_audit_log_token(tenant_id).await {
        Ok(()) => match client.list_app_credential_sign_in_activities().await {
            Ok(rows) => {
                let mut map: HashMap<String, CredentialActivity> = HashMap::new();
                for row in rows {
                    let (Some(app_id), Some(key_id)) =
                        (row.app_id.as_deref(), row.key_id.as_deref())
                    else {
                        continue;
                    };
                    if app_id.is_empty() || key_id.is_empty() {
                        continue;
                    }
                    // A present row says the credential IS tracked: no dated
                    // activity reads as `Never` (the one case the advisory may
                    // flag alongside stale-but-used). Any dated row upgrades —
                    // and refreshes — that, newest date winning across origins.
                    let entry = map
                        .entry(format!("{app_id}|{key_id}"))
                        .or_insert(CredentialActivity::Never);
                    if let Some(dt) = row
                        .sign_in_activity
                        .as_ref()
                        .and_then(|s| s.last_sign_in_date_time)
                    {
                        let fresher = match *entry {
                            CredentialActivity::LastSeen(prev) => dt > prev,
                            _ => true,
                        };
                        if fresher {
                            *entry = CredentialActivity::LastSeen(dt);
                        }
                    }
                }
                (true, Arc::new(map))
            }
            Err(err) => {
                tracing::info!(
                    ?err,
                    "audit: credential sign-in report unavailable; skipping unused-credential checks"
                );
                unavailable()
            }
        },
        Err(err) => {
            tracing::info!(
                code = %UiError::from(err).code,
                "audit: AuditLog.Read.All token unavailable; skipping unused-credential checks"
            );
            unavailable()
        }
    }
}

/// ONE tenant-wide app-management policy pair (default policy + custom
/// policies with their `appliesTo` targets, both v1.0 on the `Policy.Read.All`
/// token) → `(available, policy data)`. Either read failing makes the pair
/// unavailable: without the target map, a default-policy cap could mis-flag an
/// app that adopted an override, so partial policy data is no data.
///
/// Like the credential reports, a failure here is an unavailable advisory, not
/// a coverage gap: the lifetime signal is operator context on top of the
/// expiry findings, its absence never hides a finding, and a tenant that never
/// consented `Policy.Read.All` would otherwise carry a permanent "degraded"
/// banner that trains operators to ignore it. The token rides the client's
/// policy bearer (acquired on demand, like Conditional Access) — no
/// consent-state UI is needed because no audit finding depends on this pair.
pub(crate) async fn prefetch_app_management_policy(
    client: &GraphClient,
) -> (bool, Arc<AppPolicyData>) {
    let unavailable = || (false, Arc::new(AppPolicyData::default()));
    let (default_read, custom_read) = tokio::join!(
        client.get_default_app_management_policy(),
        client.list_app_management_policies()
    );
    let (default_policy, policies) = match (default_read, custom_read) {
        (Ok(default_policy), Ok(policies)) => (default_policy, policies),
        (Err(err), _) | (_, Err(err)) => {
            tracing::info!(
                ?err,
                "audit: app-management policy pair unavailable; skipping credential-lifetime checks"
            );
            return unavailable();
        }
    };
    let mut by_target: HashMap<String, Vec<_>> = HashMap::new();
    for policy in policies {
        // A policy with no listed targets is assigned to nobody; a disabled
        // override still lands in the map, because "assigned but disabled"
        // still replaces the default in a way the audit cannot resolve —
        // `secret_cap_for` then returns no verdict for that app.
        for target in &policy.applies_to {
            if !target.id.is_empty() {
                by_target
                    .entry(target.id.clone())
                    .or_default()
                    .push(policy.clone());
            }
        }
    }
    (
        true,
        Arc::new(AppPolicyData {
            default: default_policy,
            by_target,
        }),
    )
}
