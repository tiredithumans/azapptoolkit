//! Per-object scoring: the pure reconciliation helpers and the two scoring
//! entry points the fan-out calls (apps via `score_one`, SP-only principals
//! via `score_sp_only`).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use azapptoolkit_core::audit::{
    AppPermissions, AuditItem, CredentialActivity, CredentialLifetime, RemediationKind,
    ResourcePermission, SpAuditInput, apply_service_principal_risk, is_expired, score_application,
    score_service_principal, secret_lifetime_advisory, unused_app_advisory,
    unused_credential_advisory,
};
use azapptoolkit_core::models::{Application, RequiredResourceAccess, ServicePrincipal};
use azapptoolkit_core::scoping::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, is_scopable_exchange_resource_permission,
};
use azapptoolkit_exchange::ExchangeError;
use azapptoolkit_exchange::targets::ScopableMailPermission;
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

/// The principals holding the EWS `full_access_as_app` scope on Office 365
/// Exchange Online, from the run's Office 365 grant read — the set
/// [`derive_orgwide_mail_scopes`] reconciles against. Resource-checked, not
/// value-only: the scope is unambiguous today, but the map carries the
/// resource precisely so no caller has to rely on that.
pub(crate) fn ews_full_access_holders(
    office365_grants_by_sp: &HashMap<String, Vec<ResourcePermission>>,
) -> HashSet<String> {
    let ews = ResourcePermission::exchange_online(EWS_FULL_ACCESS_AS_APP);
    office365_grants_by_sp
        .iter()
        .filter(|(_, grants)| grants.contains(&ews))
        .map(|(sp_id, _)| sp_id.clone())
        .collect()
}

/// Every app role granted to each service principal, with its resource: the
/// run's Microsoft Graph matrix (bare values, Graph by construction) joined to
/// the Office 365 Exchange Online / SharePoint Online grants. The one
/// "what does this principal actually hold" map — the SP-only phase scores
/// from it, and `score_one` merges an app's undeclared grants out of it.
pub(crate) fn combine_granted_roles(
    graph_roles_by_sp: &HashMap<String, Vec<String>>,
    office365_grants_by_sp: &HashMap<String, Vec<ResourcePermission>>,
) -> HashMap<String, Vec<ResourcePermission>> {
    let mut out: HashMap<String, Vec<ResourcePermission>> = graph_roles_by_sp
        .iter()
        .map(|(sp_id, values)| {
            (
                sp_id.clone(),
                values.iter().map(ResourcePermission::graph).collect(),
            )
        })
        .collect();
    for (sp_id, grants) in office365_grants_by_sp {
        out.entry(sp_id.clone())
            .or_default()
            .extend(grants.iter().cloned());
    }
    out.retain(|_, grants| !grants.is_empty());
    out
}

/// Folds the app roles actually GRANTED to an app's service principal into
/// its manifest-derived permissions. Each granted `(resource, value)` the
/// manifest does not declare is appended to `app_role_grants` — so Rules 1/2
/// score the principal's real reach, not the manifest's claim — and recorded in
/// `undeclared_grants` for the Rule 23 advisory. Declared-and-granted roles are
/// already present and are skipped (the scorer dedups anyway). Resource ids
/// compare case-insensitively: the manifest's `resourceAppId` and the
/// well-known constants are both GUIDs, and casing is not identity.
///
/// `unresolved_resources` (lower-cased resource app ids) are DECLARED resources
/// whose permission index failed to resolve, so their declarations were
/// dropped: a grant on one is still merged for scoring, but never recorded as
/// undeclared — whether the manifest names it is unknowable this run, and a
/// false Rule 23 would tell the operator to revoke a declared permission.
///
/// Pure: the granted list comes from the run's tenant-wide matrices, so an
/// undeclared grant costs no per-app read. An app registration was scored only
/// on `requiredResourceAccess` before this, so a role granted straight to its
/// SP — the classic way to hide privilege on an innocuous app — scored zero.
pub(crate) fn merge_granted_roles(
    perms: &mut AppPermissions,
    granted: &[ResourcePermission],
    unresolved_resources: &HashSet<String>,
) {
    let key = |g: &ResourcePermission| {
        (
            g.resource_app_id.as_deref().map(str::to_ascii_lowercase),
            g.value.clone(),
        )
    };
    let mut held: HashSet<(Option<String>, String)> =
        perms.app_role_grants.iter().map(key).collect();
    for g in granted {
        if held.insert(key(g)) {
            perms.app_role_grants.push(g.clone());
            let unknowable = g
                .resource_app_id
                .as_deref()
                .is_some_and(|r| unresolved_resources.contains(&r.to_ascii_lowercase()));
            if !unknowable {
                perms.undeclared_grants.push(g.clone());
            }
        }
    }
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
    delegated_scopes_by_client: &HashMap<String, Vec<String>>,
    now: DateTime<Utc>,
) -> AuditItem {
    // Every granted role with its own resource: Microsoft Graph's, plus the
    // Office 365 Exchange Online (EWS `full_access_as_app`,
    // `Exchange.ManageAsApp`, the retired Outlook REST roles) and SharePoint
    // Online roles the Graph matrix cannot see. Dropping the resource here
    // would let a legacy-resource grant borrow a Graph grant's verdict.
    let app_role_grants: Vec<ResourcePermission> = ctx
        .granted_roles_by_sp
        .get(&sp.id)
        .cloned()
        .unwrap_or_default();
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
        // An SP-only row has no manifest: its grants ARE its permissions,
        // so nothing is "undeclared".
        undeclared_grants: Vec::new(),
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
    // Rule 22: join the run's tenant-wide risky-SP map before the unused
    // post-pass so the DisableSignIn dedupe in core sees one Fix per row.
    if let Some((state, level)) = ctx.risk_for(&sp.id) {
        item.sp_risk_state = Some(state.to_string());
        item.sp_risk_level = Some(level.to_string());
        apply_service_principal_risk(&mut item);
    }
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
/// phase) AND that hold at least one application-permission grant OR are
/// flagged risky by Identity Protection. The grant requirement is the noise
/// filter: it drops the hundreds of grantless first-party Microsoft SPs every
/// tenant carries. Disabled SPs stay in (Rule 4 flags them).
///
/// "Holds a grant" spans every resource the run reads ([`combine_granted_roles`]):
/// Microsoft Graph, Office 365 Exchange Online and Office 365 SharePoint
/// Online. An SP holding only the EWS `full_access_as_app` scope, only
/// `Exchange.ManageAsApp`, or only SharePoint Online's `Sites.FullControl.All`
/// has no Graph role at all, yet reaches every mailbox or site — filtering on
/// the Graph matrix alone dropped exactly the principals most worth scoring.
/// Known limitation: roles held only on OTHER resources (a third-party or
/// custom API) are in no matrix, so an unflagged SP holding only those is not
/// scored.
///
/// The risky set joins as a second admission path: a compromised managed
/// identity or foreign SP often holds NO enumerable grant (or its grant lives
/// on a resource no matrix reads), and "Identity Protection says it is
/// compromised" is precisely the case where "no grants ⇒ skip it" is the wrong
/// inference.
pub(crate) fn sp_audit_candidates(
    sp_index: &[ServicePrincipal],
    local_app_ids: &HashSet<String>,
    granted_roles_by_sp: &HashMap<String, Vec<ResourcePermission>>,
    risky_by_sp: &HashMap<String, (String, String)>,
) -> Vec<ServicePrincipal> {
    sp_index
        .iter()
        .filter(|sp| !local_app_ids.contains(&sp.app_id))
        .filter(|sp| {
            granted_roles_by_sp
                .get(&sp.id)
                .is_some_and(|v| !v.is_empty())
                || risky_by_sp.contains_key(&sp.id)
        })
        .cloned()
        .collect()
}

/// The app's declared permissions, plus the (lower-cased) ids of declared
/// resources whose permission index could NOT be resolved. Their declarations
/// were dropped below, so `merge_granted_roles` must not call a grant on one of
/// them "not in the manifest" — that is unknowable this run (which already
/// carries the `PermissionResolution` gap).
async fn resolve_permissions(
    resolver: &ResourceResolver,
    access: &[RequiredResourceAccess],
) -> (AppPermissions, HashSet<String>) {
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

    let unresolved: HashSet<String> = indexes
        .iter()
        .filter(|(_, index)| index.by_id.is_empty())
        .map(|(id, _)| id.to_ascii_lowercase())
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
    (out, unresolved)
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

    let (mut perms, unresolved_resources) =
        resolve_permissions(&ctx.resolver, &app.required_resource_access).await;
    // Score what the SP actually HOLDS, not only what the manifest declares:
    // fold its granted roles (from the run's tenant-wide matrices) in before
    // any rule — or the mailbox-scope probe below — reads `app_role_grants`.
    if let Some(ref sp) = sp
        && let Some(granted) = ctx.granted_roles_by_sp.get(&sp.id)
    {
        merge_granted_roles(&mut perms, granted, &unresolved_resources);
    }

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
    let scopable: Vec<ScopableMailPermission> = perms
        .app_role_grants
        .iter()
        .filter_map(|g| {
            ScopableMailPermission::on_resource(g.resource_app_id.as_deref()?, &g.value)
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
    // Rule 22: the risky-SP report is tenant-wide; join it onto this row by
    // the SP's object id (the same key the grant matrices use), then let the
    // core post-pass fold in the +20, the marker and the DisableSignIn fix.
    // Runs BEFORE the unused post-pass, which must not stack a second Fix.
    if let Some((state, level)) = sp.as_ref().and_then(|s| ctx.risk_for(&s.id)) {
        item.sp_risk_state = Some(state.to_string());
        item.sp_risk_level = Some(level.to_string());
        apply_service_principal_risk(&mut item);
    }
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
        // is already disabled — either way the fix has nothing to do. Skip also
        // when the risky pass already attached one for this row (a risky AND
        // unused SP gets one Fix, not two).
        if sp.is_some()
            && item.service_principal_enabled != Some(false)
            && !item
                .remediations
                .iter()
                .any(|r| r.kind == RemediationKind::DisableSignIn)
        {
            item.remediations
                .push(azapptoolkit_core::audit::disable_sign_in_remediation());
        }
    }
    // Per-credential last-used advisory (SP-only rows are skipped: a
    // service principal carries no local credentials to judge). Only
    // still-valid credentials are considered — an expired one is the
    // expired-credential finding's job — and only ones the report actually
    // tracks can flag: everything without a report row resolves to `Unknown`
    // inside `unused_credential_advisory`, so a missing or partial report
    // never mis-flags a credential. Credential age falls back to the app's
    // creation date; a secret with no start date is as old as its app.
    if ctx.credential_usage_available {
        let activity = |key_id: &str| ctx.credential_activity_for(&app.app_id, key_id);
        let usage: Vec<(String, CredentialActivity, Option<DateTime<Utc>>)> = app
            .password_credentials
            .iter()
            .filter(|c| !is_expired(c.end_date_time, now))
            .map(|c| {
                (
                    format!("secret \"{}\"", c.display_name.as_deref().unwrap_or("—")),
                    activity(&c.key_id),
                    c.start_date_time.or(app.created_date_time),
                )
            })
            .chain(
                app.key_credentials
                    .iter()
                    .filter(|c| !is_expired(c.end_date_time, now))
                    .map(|c| {
                        (
                            format!("cert \"{}\"", c.display_name.as_deref().unwrap_or("—")),
                            activity(&c.key_id),
                            c.start_date_time.or(app.created_date_time),
                        )
                    }),
            )
            .collect();
        let usage_refs: Vec<(&str, CredentialActivity, Option<DateTime<Utc>>)> =
            usage.iter().map(|(l, a, s)| (l.as_str(), *a, *s)).collect();
        if let Some((issue, rec)) = unused_credential_advisory(&usage_refs, now) {
            item.issues.push(issue);
            item.recommendations.push(rec);
        }
    }
    // Per-app secret-lifetime advisory: judge still-valid secrets against the
    // app-management policy cap enforced ON THIS PRINCIPAL (assigned override
    // first, tenant default only without one). Recommendation-only — the cap
    // is operator context, so there is no issue marker, no finding key and no
    // score. `secret_cap_for` yielding `None` means NO verdict (policy
    // unreadable, unenforced, grandfathered by a date gate, or an unknowable
    // multi-policy combination), never "compliant".
    if let Some(cap) = ctx.secret_cap_for(
        &app.id,
        sp.as_ref().map(|s| s.id.as_str()),
        app.created_date_time,
    ) {
        type OwnedLifetime = (String, Option<DateTime<Utc>>, Option<DateTime<Utc>>);
        let lifetimes: Vec<OwnedLifetime> = app
            .password_credentials
            .iter()
            .filter(|c| !is_expired(c.end_date_time, now))
            .map(|c| {
                (
                    format!("secret \"{}\"", c.display_name.as_deref().unwrap_or("—")),
                    c.end_date_time,
                    c.start_date_time.or(app.created_date_time),
                )
            })
            .collect();
        let lifetime_refs: Vec<CredentialLifetime> = lifetimes
            .iter()
            .map(|(l, e, s)| (l.as_str(), *e, *s))
            .collect();
        if let Some(rec) = secret_lifetime_advisory(&lifetime_refs, cap) {
            item.recommendations.push(rec);
        }
    }
    Ok(item)
}
