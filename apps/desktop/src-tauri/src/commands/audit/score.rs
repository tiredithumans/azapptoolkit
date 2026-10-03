//! Per-object scoring: the pure reconciliation helpers and the two scoring
//! entry points the fan-out calls (apps via `score_one`, SP-only principals
//! via `score_sp_only`).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use azapptoolkit_core::audit::{
    AppPermissions, AuditItem, ResourcePermission, SpAuditInput, score_application,
    score_service_principal, unused_app_advisory,
};
use azapptoolkit_core::models::{Application, RequiredResourceAccess, ServicePrincipal};
use azapptoolkit_core::scoping::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, exchange_role_for_resource_permission,
    is_scopable_exchange_resource_permission,
};
use azapptoolkit_exchange::ExchangeError;
use azapptoolkit_exchange::verdict::apply_legacy_policy_verdict;
use chrono::{DateTime, Utc};

use crate::commands::exchange::resolve_mail_scopes_audit_cached;
use crate::dto::UiError;

use super::{ResourceIndex, ResourceResolver, ScoreCtx};

/// The org-wide-granted mailbox permissions `score_one` reconciles against a
/// scoped RBAC verdict: the mail-scopable subset of each SP's granted Graph roles,
/// **plus** the EWS `full_access_as_app` scope for the principals in
/// `ews_full_access_sps`. Empty sets are dropped.
pub(crate) fn derive_orgwide_mail_scopes(
    graph_roles_by_sp: &HashMap<String, Vec<String>>,
    ews_full_access_sps: &HashSet<String>,
) -> HashMap<String, HashSet<String>> {
    let mut out: HashMap<String, HashSet<String>> = graph_roles_by_sp
        .iter()
        .map(|(sp_id, values)| {
            // `graph_roles_by_sp` holds Microsoft Graph roles by construction,
            // so name that resource rather than testing the bare value: the
            // value-only form also answers `true` for Office 365 Exchange
            // Online's identically-named legacy appRoles, which RBAC for
            // Applications cannot confine.
            let mail: HashSet<String> = values
                .iter()
                .filter(|v| {
                    is_scopable_exchange_resource_permission(Some(MICROSOFT_GRAPH_APP_ID), v)
                })
                .cloned()
                .collect();
            (sp_id.clone(), mail)
        })
        .filter(|(_, mail)| !mail.is_empty())
        .collect();
    // A principal can hold the EWS scope and no Graph mail role at all, so this
    // inserts as well as extends.
    for sp_id in ews_full_access_sps {
        out.entry(sp_id.clone())
            .or_default()
            .insert(EWS_FULL_ACCESS_AS_APP.to_string());
    }
    out
}

/// Scores one SP-only candidate (foreign enterprise app, managed identity,
/// orphaned SP). Pure scoring — every input was resolved tenant-wide, so there's
/// no per-item Graph traffic. No **RBAC** verdict is resolved ON PURPOSE: a held
/// mail value here IS an un-stripped org-wide Entra grant (it comes from the
/// grant matrix), and grant ∪ RBAC reach is always org-wide, so the
/// reconciliation score_one applies would force OrgWide regardless of any RBAC
/// verdict — skipping the 1-5s Exchange probe per SP scores identically. A
/// principal whose grant the scoping flow stripped no longer holds the value and
/// drops out of the candidate set entirely.
///
/// A legacy Application Access Policy is the one exception, and it comes free
/// from the run's tenant-wide policy read: unlike an RBAC scope, a policy DOES
/// constrain the org-wide Entra grant these rows are scored from, so a confined
/// foreign app / managed identity would otherwise be reported org-wide.
pub(crate) fn score_sp_only(
    sp: &ServicePrincipal,
    ctx: &ScoreCtx,
    graph_roles_by_sp: &HashMap<String, Vec<String>>,
    delegated_scopes_by_client: &HashMap<String, Vec<String>>,
    ews_full_access_sps: &HashSet<String>,
    now: DateTime<Utc>,
) -> AuditItem {
    // The Graph matrix holds Microsoft Graph roles by construction; the EWS
    // blanket scope lives on the legacy Office 365 Exchange Online resource and
    // is tracked separately, so it has to be re-attached here with its own
    // resource or the scorer cannot see the tenant's broadest mailbox grant.
    let mut app_role_grants: Vec<ResourcePermission> = graph_roles_by_sp
        .get(&sp.id)
        .map(|values| {
            values
                .iter()
                .map(ResourcePermission::graph)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if ews_full_access_sps.contains(&sp.id) {
        app_role_grants.push(ResourcePermission::exchange_online(EWS_FULL_ACCESS_AS_APP));
    }
    let mut perms = AppPermissions {
        app_role_grants,
        scope_values: delegated_scopes_by_client
            .get(&sp.id)
            .cloned()
            .unwrap_or_default(),
        has_admin_consent: ctx.admin_consent_clients.contains(&sp.id),
        // The SP scorer treats `scope_values` (already the AllPrincipals set)
        // as the consented set, so this per-scope copy would be redundant.
        admin_consented_scopes: None,
        mail_scopes: HashMap::new(),
    };
    let granted_grants = perms.app_role_grants.clone();
    apply_legacy_policy_verdict(
        &mut perms.mail_scopes,
        &granted_grants,
        ctx.legacy_policies.get(&sp.app_id),
    );
    let input = SpAuditInput {
        display_name: sp.display_name.clone(),
        app_id: sp.app_id.clone(),
        sp_object_id: sp.id.clone(),
        created_date_time: sp.created_date_time,
        account_enabled: sp.account_enabled,
        disabled_by_microsoft_status: sp.disabled_by_microsoft_status.clone(),
        app_owner_organization_id: sp.app_owner_organization_id.clone(),
        service_principal_type: sp.service_principal_type.clone(),
    };
    let mut item = score_service_principal(&input, &perms, now);
    let last_sign_in = ctx.last_sign_in_for(&sp.app_id);
    item.sign_in_report_available = last_sign_in.is_some();
    item.last_sign_in = last_sign_in.flatten();
    if let Some((issue, rec)) = unused_app_advisory(last_sign_in.into(), sp.created_date_time, now)
    {
        item.unused = true;
        item.issues.push(issue);
        item.recommendations.push(rec);
    }
    item
}

/// The SP-only scoring candidates: service principals whose `appId` has no
/// local application object (foreign enterprise apps, managed identities,
/// orphaned SPs — paired SPs are already scored via the app-registration
/// phase) AND that hold at least one Graph application-permission grant. The
/// grant requirement is the noise filter: it drops the hundreds of grantless
/// first-party Microsoft SPs every tenant carries. Disabled SPs stay in (Rule
/// 4 flags them).
///
/// "Holds a grant" spans **both** mailbox resources: an SP holding only the EWS
/// `full_access_as_app` scope has no Graph role at all, yet reaches every mailbox
/// in the tenant — filtering on the Graph matrix alone dropped exactly the
/// principal most worth scoring. Known limitation: roles held only on *other*
/// non-Graph resources still aren't in any matrix, so such an SP is not scored.
pub(crate) fn sp_audit_candidates(
    sp_index: &[ServicePrincipal],
    local_app_ids: &HashSet<String>,
    graph_roles_by_sp: &HashMap<String, Vec<String>>,
    ews_full_access_sps: &HashSet<String>,
) -> Vec<ServicePrincipal> {
    sp_index
        .iter()
        .filter(|sp| !local_app_ids.contains(&sp.app_id))
        .filter(|sp| {
            graph_roles_by_sp.get(&sp.id).is_some_and(|v| !v.is_empty())
                || ews_full_access_sps.contains(&sp.id)
        })
        .cloned()
        .collect()
}

async fn resolve_permissions(
    resolver: &ResourceResolver,
    access: &[RequiredResourceAccess],
) -> AppPermissions {
    let resources: HashSet<String> = access.iter().map(|r| r.resource_app_id.clone()).collect();
    // Resolve each distinct resource's index concurrently rather than one serial
    // await at a time (mirrors `resolve_required_resource_access` in
    // applications.rs). Each lookup is independent and Permissions-cached, so on a
    // cold cache this collapses N serial round-trips into one concurrent batch;
    // warm hits cost nothing.
    let indexes: HashMap<String, Arc<ResourceIndex>> =
        futures::future::join_all(resources.into_iter().map(|id| async move {
            let index = resolver.index(&id).await;
            (id, index)
        }))
        .await
        .into_iter()
        .collect();

    let mut out = AppPermissions::default();
    for resource in access {
        let index = match indexes.get(&resource.resource_app_id) {
            Some(i) => i,
            None => continue,
        };
        for perm in &resource.resource_access {
            let value = match index.by_id.get(&perm.id) {
                Some(v) => v.clone(),
                None => continue,
            };
            match perm.r#type.as_str() {
                // Carry the resource, don't drop it: two resources expose an
                // identically named `Mail.Read`/`Mail.Send`/`Contacts.*` and only
                // Microsoft Graph's are confinable by RBAC for Applications. The
                // scorer gates every mailbox verdict on this id.
                "Role" => out
                    .app_role_grants
                    .push(ResourcePermission::on(&resource.resource_app_id, value)),
                "Scope" => out.scope_values.push(value),
                _ => {}
            }
        }
    }
    out
}

pub(crate) async fn score_one(
    ctx: &ScoreCtx,
    app: &Application,
    last_sign_in: Option<Option<DateTime<Utc>>>,
) -> Result<AuditItem, UiError> {
    // Lean lookup: the audit reads only `sp.id` and `sp.account_enabled`. The
    // prewarm above seeds the matching `|lean` cache key, so this is a hit.
    //
    // A FAILED lookup is an error, never `None`. `Ok(None)` means the app truly
    // has no service principal; mapping a failed read to that same `None` took
    // away the input of the admin-consent and disabled-SP rules and emptied
    // `orgwide` below, so a `Scoped { Rbac }` verdict was never reconciled
    // against a surviving org-wide grant — and the run, with nothing in
    // `degraded`, was cached as a clean complete scan. Propagated, the error
    // reaches the run's collector: a transient failure counts the app as
    // unscored (→ `PerPrincipalScoring`, never cached), a dead session stops
    // the run for re-auth.
    let sp = ctx
        .client
        .get_service_principal_by_app_id_lean(&app.app_id)
        .await
        .map_err(|err| {
            tracing::warn!(
                app = %app.display_name,
                ?err,
                "audit: SP lookup failed; app left unscored"
            );
            UiError::from(err)
        })?;

    let mut perms = resolve_permissions(&ctx.resolver, &app.required_resource_access).await;

    // Admin-consent flag: true if any AllPrincipals grant names this SP as the
    // client (membership in the run's one tenant-wide prefetch).
    if let Some(ref sp) = sp {
        perms.has_admin_consent = ctx.admin_consent_clients.contains(&sp.id);
    }
    // Per-scope consent state for Rule 13: the scopes this app's SP holds under
    // AllPrincipals grants. An app with no SP can hold no grant (`Some(empty)`);
    // a failed grants read leaves it `None` (unknown — Rule 13 falls back to the
    // declared scopes rather than hiding them).
    perms.admin_consented_scopes = ctx
        .admin_consented_scopes_by_client
        .as_ref()
        .map(|by_client| {
            sp.as_ref()
                .and_then(|sp| by_client.get(&sp.id))
                .cloned()
                .unwrap_or_default()
        });

    // Resolve effective Exchange mailbox scoping so a mail permission confined to
    // specific mailboxes scores below an org-wide one. Skips the Exchange round
    // trip entirely for apps with no scopable mail permissions (the resolver
    // returns an empty map), and for the rest of the run once the circuit
    // breaker has tripped (an auth failure recurs for every app; an open
    // breaker scores identically to the swallowed error — org-wide weight).
    // `enrich=false` — the audit needs only the org-wide/scoped distinction,
    // not the recipient filter.
    let exo = if ctx.exo_tripped.load(Ordering::Acquire) {
        None
    } else {
        ctx.exo.as_deref()
    };
    // The Exchange-scopable declared grants with the role each one's OWN
    // resource maps it to: Microsoft Graph's mail family and the EWS
    // `full_access_as_app` scope on Office 365 Exchange Online. Carrying the
    // role from here is what lets the resolver see the EWS row — re-deriving
    // it against Graph dropped that row, so a correctly RBAC-scoped EWS grant
    // scored at full org-wide weight.
    let scopable: Vec<(String, &'static str)> = perms
        .app_role_grants
        .iter()
        .filter_map(|g| {
            exchange_role_for_resource_permission(g.resource_app_id.as_deref()?, &g.value)
                .map(|role| (g.value.clone(), role))
        })
        .collect();
    if let Some(exo) = exo {
        // Reconcile a scoped RBAC verdict against an un-stripped org-wide Entra
        // grant — `Test-ServicePrincipalAuthorization` can't see Entra grants, so
        // a scoped role coexisting with the org-wide grant still reaches every
        // mailbox. Only worth the extra read when the app declares a scopable mail
        // permission and its SP resolved.
        let orgwide = match &sp {
            Some(sp) if !scopable.is_empty() => {
                // One tenant-wide read (above) replaces the former per-app
                // appRoleAssignments GET; a map miss ⇒ empty set, same as before.
                ctx.orgwide_mail_by_sp
                    .get(&sp.id)
                    .cloned()
                    .unwrap_or_default()
            }
            _ => HashSet::new(),
        };
        // Degrade gracefully: an Exchange failure (e.g. a 403 from missing
        // Exchange RBAC) leaves `mail_scopes` empty, so every mail permission
        // scores at full org-wide weight — never under-reporting risk. An
        // auth failure additionally trips the run-wide breaker: it would
        // recur for every remaining app, each one a doomed cmdlet POST.
        // Cached lean verdict: a re-run within the TTL (no intervening mutation)
        // skips the 1-5s Test-ServicePrincipalAuthorization probe. Distinct key
        // from the Permissions tab's verdicts — see resolve_mail_scopes_audit_cached.
        perms.mail_scopes = match resolve_mail_scopes_audit_cached(
            &ctx.cache,
            &ctx.tenant_id,
            exo,
            &app.app_id,
            &scopable,
            &orgwide,
        )
        .await
        {
            Ok(scopes) => scopes,
            Err(err) => {
                // Unconditionally, before the breaker test: any failed probe
                // left this app's mail permissions at org-wide weight.
                ctx.mail_scoping_unresolved.store(true, Ordering::Release);
                if matches!(
                    err,
                    ExchangeError::Unauthorized | ExchangeError::Forbidden { .. }
                ) {
                    ctx.exo_tripped.store(true, Ordering::Release);
                    tracing::info!(
                        ?err,
                        "audit: Exchange authorization failed; skipping mailbox-scope probes for the rest of the run"
                    );
                }
                HashMap::new()
            }
        };
    } else if !scopable.is_empty() {
        // No Exchange client, or the breaker is open: a scopable mail
        // permission scores at org-wide weight without being checked.
        ctx.mail_scoping_unresolved.store(true, Ordering::Release);
    }

    // Fold in the run's tenant-wide legacy-policy verdict. Outside the Exchange
    // block on purpose: the policy read already happened (before the breaker
    // could trip), and a `RestrictAccess` policy confines the app whether or not
    // this app's RBAC probe ran, failed, or was skipped.
    let declared_grants = perms.app_role_grants.clone();
    apply_legacy_policy_verdict(
        &mut perms.mail_scopes,
        &declared_grants,
        ctx.legacy_policies.get(&app.app_id),
    );

    let sp_enabled = sp.as_ref().and_then(|s| s.account_enabled);
    let now = chrono::Utc::now();
    let mut item = score_application(app, sp_enabled, &perms, now);
    // Carry the sign-in signal as structured fields (the "Unused" facet keys off
    // `unused`, the table shows `last_sign_in`) and keep the human-readable
    // advisory in `issues` for export/detail. Outer `Some` = report available.
    item.sign_in_report_available = last_sign_in.is_some();
    item.last_sign_in = last_sign_in.flatten();
    if let Some((issue, rec)) = unused_app_advisory(last_sign_in.into(), app.created_date_time, now)
    {
        item.unused = true;
        item.issues.push(issue);
        item.recommendations.push(rec);
        // Attached here rather than in `score_application` because `unused` is
        // this post-pass's flag. Skip when there's no SP to disable, or the SP
        // is already disabled — either way the fix has nothing to do.
        if sp.is_some() && item.service_principal_enabled != Some(false) {
            item.remediations
                .push(azapptoolkit_core::audit::disable_sign_in_remediation());
        }
    }
    Ok(item)
}
