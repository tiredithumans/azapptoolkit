//! Grant expiries (B3): set one on a grant, and revoke the grants whose
//! expiry has passed.
//!
//! An expiry is a tag on the holding service principal
//! (`audit::grant_expiry`). Every SP tag write — these and the HideApp toggle —
//! runs under one per-SP gate ([`sp_tags_gate_key`]) and re-reads the live set
//! first, so concurrent writers can't drop each other's tags.

use std::collections::{HashMap, HashSet};

use jiff::Timestamp;
use jiff::civil::Date;
use tauri::State;

use azapptoolkit_core::audit::{
    AuditPrincipalKind, GrantExpiry, expiries_in, expiry_has_passed, with_expiry,
};
use azapptoolkit_core::guid::is_guid;
use azapptoolkit_core::models::AppRoleAssignment;
use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
use azapptoolkit_graph::GraphError;

use crate::commands::applications::{invalidate_app_detail_state, record_sp_tags};
use crate::commands::permissions::remove_declared_access;
use crate::commands::session::prove_tenant_session;
use crate::dto::UiError;
use crate::dto::permissions::{GrantRef, RevokeExpiredResult};
use crate::state::AppState;

/// The per-SP gate every service-principal tag writer takes.
pub(crate) fn sp_tags_gate_key(tenant_id: &str, sp_object_id: &str) -> String {
    format!("{tenant_id}|sp_tags|{sp_object_id}")
}

fn invalid_id() -> UiError {
    UiError::validation(
        "invalid_id",
        "The permission or resource id isn't a valid id.",
    )
}

/// Validates a set-expiry date: `YYYY-MM-DD` that hasn't passed (today is
/// allowed — it expires at the end of the day, UTC). `None` clears.
pub(crate) fn parse_expiry_date(
    expires_on: Option<&str>,
    now: Timestamp,
) -> Result<Option<Date>, UiError> {
    let Some(raw) = expires_on else {
        return Ok(None);
    };
    let date: Date = raw
        .trim()
        .parse()
        .map_err(|_| UiError::validation("invalid_date", "Use a date like 2026-12-31."))?;
    if expiry_has_passed(date, now) {
        return Err(UiError::validation(
            "invalid_date",
            "That date has already passed.",
        ));
    }
    Ok(Some(date))
}

/// What the Fix does with each passed expiry.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct RevocationPlan {
    /// `(assignment id, expiry)`: held, and granted before its date passed.
    pub revoke: Vec<(String, GrantExpiry)>,
    /// Nothing held for it (revoked by hand, or the resource is gone).
    pub gone: Vec<GrantExpiry>,
    /// The resource didn't resolve, but some assignment still carries the
    /// role: never called gone (that would clear the tag of a held grant).
    pub unresolved: Vec<GrantExpiry>,
    /// Held, but every holding assignment was created after the date had
    /// passed: a later grant, not the one the date was set for.
    pub regranted: Vec<GrantExpiry>,
}

/// Which assignments to revoke for the passed `expiries`: those on the
/// expiry's resource (by its service-principal id) with its role, created
/// before the date passed.
pub(crate) fn plan_revocations(
    expiries: &[GrantExpiry],
    assignments: &[AppRoleAssignment],
    resource_sp_ids: &HashMap<String, String>,
) -> RevocationPlan {
    let mut plan = RevocationPlan::default();
    for e in expiries {
        let holds_role =
            |a: &&AppRoleAssignment| a.app_role_id.eq_ignore_ascii_case(&e.app_role_id);
        let Some(res) = resource_sp_ids.get(&e.resource_app_id) else {
            // Fail closed: a role id still held may be this grant on a
            // resource a cached "not found" hides.
            if assignments.iter().any(|a| holds_role(&a)) {
                plan.unresolved.push(e.clone());
            } else {
                plan.gone.push(e.clone());
            }
            continue;
        };
        let held: Vec<&AppRoleAssignment> = assignments
            .iter()
            .filter(|a| a.resource_id.eq_ignore_ascii_case(res) && holds_role(a))
            .collect();
        // An assignment with no creation time is treated as the dated one:
        // revoking is what the operator asked for.
        let dated: Vec<&AppRoleAssignment> = held
            .iter()
            .copied()
            .filter(|a| {
                a.created_date_time
                    .is_none_or(|c| !expiry_has_passed(e.expires_on, c))
            })
            .collect();
        if held.is_empty() {
            plan.gone.push(e.clone());
        } else if dated.is_empty() {
            plan.regranted.push(e.clone());
        } else {
            plan.revoke
                .extend(dated.into_iter().map(|a| (a.id.clone(), e.clone())));
        }
    }
    plan
}

/// Most grants one expiry write may name: a wizard cart, never a tenant.
const MAX_GRANTS_PER_WRITE: usize = 50;

fn invalid_sp_id() -> UiError {
    UiError::validation("invalid_id", "The service principal id isn't a valid id.")
}

/// Shape-checks the grants a write names: GUID pairs, at least one, a bounded
/// number.
pub(crate) fn check_grants(grants: &[GrantRef]) -> Result<(), UiError> {
    if grants.is_empty() || grants.len() > MAX_GRANTS_PER_WRITE {
        return Err(UiError::validation(
            "invalid_grants",
            format!("Name between 1 and {MAX_GRANTS_PER_WRITE} grants."),
        ));
    }
    if grants
        .iter()
        .any(|g| !is_guid(&g.resource_app_id) || !is_guid(&g.app_role_id))
    {
        return Err(invalid_id());
    }
    Ok(())
}

/// Writes `date` on every grant in `grants` held by `sp_object_id` (`None`
/// clears), re-reading the live tags under the per-SP gate.
pub(crate) async fn write_expiries(
    state: &AppState,
    tenant_id: &str,
    sp_object_id: &str,
    grants: &[GrantRef],
    date: Option<Date>,
) -> Result<(), UiError> {
    let client = state.graph_for(tenant_id);
    let gate = state.single_flight(&sp_tags_gate_key(tenant_id, sp_object_id));
    let _held = gate.lock().await;
    // One read-modify-write for every grant: back-to-back writes would each
    // re-read a directory that may not show the previous write yet.
    let tags = client.get_service_principal_tags(sp_object_id).await?;
    let mut next = tags.clone();
    for g in grants {
        next =
            with_expiry(&next, &g.resource_app_id, &g.app_role_id, date).ok_or_else(invalid_id)?;
    }
    if next != tags {
        client
            .set_service_principal_tags(sp_object_id, &next)
            .await?;
        record_sp_tags(&state.cache, tenant_id, sp_object_id, &next);
        // The audit run reads expiries (Rule 25).
        invalidate_app_detail_state(&state.cache, tenant_id);
    }
    Ok(())
}

/// Best-effort, after a revoke landed: drops the expiry tags on
/// `sp_object_id` whose app role it no longer holds, so a later grant of the
/// same permission doesn't inherit a date set for the revoked one.
pub(crate) async fn prune_unheld_expiries(state: &AppState, tenant_id: &str, sp_object_id: &str) {
    let client = state.graph_for(tenant_id);
    let gate = state.single_flight(&sp_tags_gate_key(tenant_id, sp_object_id));
    let _held = gate.lock().await;
    let tags = match client.get_service_principal_tags(sp_object_id).await {
        Ok(tags) => tags,
        Err(err) => {
            tracing::warn!(code = err.ui_code(), "expiry prune: tags unreadable");
            return;
        }
    };
    let expiries = expiries_in(&tags);
    if expiries.is_empty() {
        return;
    }
    let held: HashSet<String> = match client.list_app_role_assignments(sp_object_id).await {
        Ok(held) => held
            .iter()
            .map(|a| a.app_role_id.to_ascii_lowercase())
            .collect(),
        Err(err) => {
            tracing::warn!(code = err.ui_code(), "expiry prune: grants unreadable");
            return;
        }
    };
    // Role ids are GUIDs, so matching on the role alone is exact in practice
    // (assignments name the resource by its SP object id, tags by its appId).
    let mut next = tags.clone();
    for e in expiries.iter().filter(|e| !held.contains(&e.app_role_id)) {
        if let Some(n) = with_expiry(&next, &e.resource_app_id, &e.app_role_id, None) {
            next = n;
        }
    }
    if next != tags {
        match client.set_service_principal_tags(sp_object_id, &next).await {
            Ok(()) => {
                record_sp_tags(&state.cache, tenant_id, sp_object_id, &next);
                invalidate_app_detail_state(&state.cache, tenant_id);
            }
            Err(err) => tracing::warn!(code = err.ui_code(), "expiry prune: write failed"),
        }
    }
}

/// Best-effort, after a downgrade swapped `from_role` for `to_role` on
/// `resource_app_id`: moves the expiry set on the revoked grant onto its
/// narrower replacement.
pub(crate) async fn carry_expiry(
    state: &AppState,
    tenant_id: &str,
    sp_object_id: &str,
    resource_app_id: &str,
    from_role: &str,
    to_role: &str,
) {
    let client = state.graph_for(tenant_id);
    let gate = state.single_flight(&sp_tags_gate_key(tenant_id, sp_object_id));
    let _held = gate.lock().await;
    let tags = match client.get_service_principal_tags(sp_object_id).await {
        Ok(tags) => tags,
        Err(err) => {
            tracing::warn!(code = err.ui_code(), "expiry carry: tags unreadable");
            return;
        }
    };
    let Some(date) = expiries_in(&tags)
        .into_iter()
        .find(|e| {
            e.resource_app_id.eq_ignore_ascii_case(resource_app_id)
                && e.app_role_id.eq_ignore_ascii_case(from_role)
        })
        .map(|e| e.expires_on)
    else {
        return;
    };
    let Some(next) = with_expiry(&tags, resource_app_id, from_role, None)
        .and_then(|t| with_expiry(&t, resource_app_id, to_role, Some(date)))
    else {
        return;
    };
    if next != tags {
        match client.set_service_principal_tags(sp_object_id, &next).await {
            Ok(()) => {
                record_sp_tags(&state.cache, tenant_id, sp_object_id, &next);
                invalidate_app_detail_state(&state.cache, tenant_id);
            }
            Err(err) => tracing::warn!(code = err.ui_code(), "expiry carry: write failed"),
        }
    }
}

/// Sets (or, with `expires_on: None`, clears) the expiry of each application
/// grant in `grants` held by `sp_object_id`, in one tag write.
#[tauri::command]
pub async fn set_grant_expiry(
    state: State<'_, AppState>,
    tenant_id: String,
    sp_object_id: String,
    grants: Vec<GrantRef>,
    expires_on: Option<String>,
) -> Result<(), UiError> {
    prove_tenant_session(&state, &tenant_id)?;
    if !is_guid(&sp_object_id) {
        return Err(invalid_sp_id());
    }
    check_grants(&grants)?;
    let date = parse_expiry_date(expires_on.as_deref(), Timestamp::now())?;
    write_expiries(&state, &tenant_id, &sp_object_id, &grants, date).await
}

/// The expiries set on `sp_object_id`'s grants, read live (the held-permission
/// panels show and prefill them).
#[tauri::command]
pub async fn get_grant_expiries(
    state: State<'_, AppState>,
    tenant_id: String,
    sp_object_id: String,
) -> Result<Vec<GrantExpiry>, UiError> {
    prove_tenant_session(&state, &tenant_id)?;
    if !is_guid(&sp_object_id) {
        return Err(invalid_sp_id());
    }
    let tags = state
        .graph_for(&tenant_id)
        .get_service_principal_tags(&sp_object_id)
        .await?;
    Ok(expiries_in(&tags))
}

/// The audit's Fix for Rule 25: revokes every still-held grant whose expiry
/// has passed (re-read live), removes those declarations from an app
/// registration's manifest (so the portal's "Grant admin consent" can't
/// restore them without an expiry), and clears the processed expiries.
#[tauri::command]
pub async fn remediate_revoke_expired_grants(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_kind: AuditPrincipalKind,
    grants: Vec<GrantRef>,
) -> Result<RevokeExpiredResult, UiError> {
    prove_tenant_session(&state, &tenant_id)?;
    if !is_guid(&object_id) {
        return Err(invalid_id());
    }
    check_grants(&grants)?;
    revoke_expired(
        &state,
        &tenant_id,
        &object_id,
        principal_kind,
        &grants,
        Timestamp::now(),
    )
    .await
}

/// [`remediate_revoke_expired_grants`]'s core, at `now`: acts only on the
/// `confirmed` grants that are still tagged and still past their date.
pub(crate) async fn revoke_expired(
    state: &AppState,
    tenant_id: &str,
    object_id: &str,
    principal_kind: AuditPrincipalKind,
    confirmed: &[GrantRef],
    now: Timestamp,
) -> Result<RevokeExpiredResult, UiError> {
    let client = state.graph_for(tenant_id);
    // An app row's `object_id` is the application; an SP-only row's is the SP.
    let (sp_id, app) = match principal_kind {
        AuditPrincipalKind::Application => {
            let app = client.get_application(object_id).await?;
            let sp = client
                .get_service_principal_by_app_id(&app.app_id)
                .await?
                .ok_or_else(|| {
                    UiError::not_found("service_principal", "This app has no service principal")
                })?;
            (sp.id, Some(app))
        }
        AuditPrincipalKind::ServicePrincipal | AuditPrincipalKind::ManagedIdentity => {
            (object_id.to_string(), None)
        }
    };
    let gate = state.single_flight(&sp_tags_gate_key(tenant_id, &sp_id));
    let _held = gate.lock().await;
    let tags = client.get_service_principal_tags(&sp_id).await?;
    let is_pair = |e: &GrantExpiry, g: &GrantRef| {
        e.resource_app_id.eq_ignore_ascii_case(&g.resource_app_id)
            && e.app_role_id.eq_ignore_ascii_case(&g.app_role_id)
    };
    let live = expiries_in(&tags);
    let mut expired: Vec<GrantExpiry> = Vec::new();
    let mut unchanged: Vec<&GrantRef> = Vec::new();
    for g in confirmed {
        if expired.iter().any(|x| is_pair(x, g)) {
            continue;
        }
        match live
            .iter()
            .find(|e| is_pair(e, g) && expiry_has_passed(e.expires_on, now))
        {
            Some(e) => expired.push(e.clone()),
            None => unchanged.push(g),
        }
    }

    // Resolve each named resource once: its SP id and role names. A resource
    // that can't be read keeps its expiries (reported failed), never guessed.
    let mut resource_sp_ids: HashMap<String, String> = HashMap::new();
    let mut role_names: HashMap<(String, String), String> = HashMap::new();
    // Display names of resources other than Graph, so a name says which.
    let mut resource_names: HashMap<String, String> = HashMap::new();
    let mut unreadable: HashSet<String> = HashSet::new();
    let mut result = RevokeExpiredResult::default();
    let resources: HashSet<String> = expired
        .iter()
        .map(|e| e.resource_app_id.clone())
        .chain(
            unchanged
                .iter()
                .map(|g| g.resource_app_id.to_ascii_lowercase()),
        )
        .collect();
    for resource in resources {
        match client.resolve_resource_sp(&resource).await {
            Ok(Some(sp)) => {
                if !resource.eq_ignore_ascii_case(MICROSOFT_GRAPH_APP_ID)
                    && !sp.display_name.is_empty()
                {
                    resource_names.insert(resource.clone(), sp.display_name.clone());
                }
                for role in &sp.app_roles {
                    role_names.insert(
                        (resource.clone(), role.id.to_ascii_lowercase()),
                        role.value.clone(),
                    );
                }
                resource_sp_ids.insert(resource, sp.id);
            }
            Ok(None) => {}
            Err(err) => {
                tracing::warn!(code = err.ui_code(), "expired grants: resource unreadable");
                if result.error.is_none() {
                    result.error = Some(UiError::from(err));
                }
                unreadable.insert(resource);
            }
        }
    }
    let name_of = |resource: &str, role: &str| {
        let value = role_names
            .get(&(resource.to_ascii_lowercase(), role.to_ascii_lowercase()))
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| role.to_string());
        match resource_names.get(&resource.to_ascii_lowercase()) {
            Some(r) => format!("{value} on {r}"),
            None => value,
        }
    };
    let name = |e: &GrantExpiry| name_of(&e.resource_app_id, &e.app_role_id);
    result.unchanged = unchanged
        .iter()
        .map(|g| name_of(&g.resource_app_id, &g.app_role_id))
        .collect();
    if expired.is_empty() {
        return Ok(result);
    }
    let readable: Vec<GrantExpiry> = expired
        .iter()
        .filter(|e| !unreadable.contains(&e.resource_app_id))
        .cloned()
        .collect();
    result.failed.extend(
        expired
            .iter()
            .filter(|e| unreadable.contains(&e.resource_app_id))
            .map(name),
    );
    let assignments = client.list_app_role_assignments(&sp_id).await?;
    let plan = plan_revocations(&readable, &assignments, &resource_sp_ids);

    // Ended: revoked now or already gone. Their expiries clear. Only the ones
    // revoked now also leave an app registration's manifest: a grant ended
    // elsewhere may be declared on purpose (the Exchange-scoped path keeps a
    // permission declared after stripping its org-wide grant).
    let mut ended: Vec<GrantExpiry> = plan.gone.clone();
    let mut revoked_now: Vec<GrantExpiry> = Vec::new();
    result.already_gone.extend(plan.gone.iter().map(name));
    // Unresolved but possibly still held: kept, and reported failed.
    result.failed.extend(plan.unresolved.iter().map(name));
    result.regranted.extend(plan.regranted.iter().map(name));
    let mut stopped = false;
    for (assignment_id, e) in plan.revoke {
        if stopped {
            result.failed.push(name(&e));
            continue;
        }
        match client
            .remove_app_role_assignment(&sp_id, &assignment_id)
            .await
        {
            Ok(()) => {
                if !result.revoked.contains(&name(&e)) {
                    result.revoked.push(name(&e));
                }
                revoked_now.push(e.clone());
                ended.push(e);
            }
            Err(GraphError::NotFound(_)) => {
                result.already_gone.push(name(&e));
                ended.push(e);
            }
            Err(err) => {
                tracing::warn!(code = err.ui_code(), "expired grants: revoke failed");
                let ui = UiError::from(err);
                // A dead session fails every later call too: stop here.
                stopped = ui.is_reauth_fatal();
                if result.error.is_none() {
                    result.error = Some(ui);
                }
                result.failed.push(name(&e));
            }
        }
    }

    // One manifest PATCH for every role revoked now on an app registration.
    // If it fails, their expiries stay, so the next audit flags them again.
    let mut manifest_failed = false;
    if let Some(app) = app
        && !revoked_now.is_empty()
    {
        let mut next = app.required_resource_access.clone();
        let mut changed = false;
        for e in &revoked_now {
            changed |=
                remove_declared_access(&mut next, &e.resource_app_id, &e.app_role_id, Some("Role"));
        }
        if changed {
            let patch = azapptoolkit_graph::client::AppPatch {
                required_resource_access: Some(next),
                ..Default::default()
            };
            if let Err(err) = client.update_application(object_id, &patch).await {
                tracing::warn!(
                    code = err.ui_code(),
                    "expired grants: manifest update failed"
                );
                manifest_failed = true;
                if result.error.is_none() {
                    result.error = Some(UiError::from(err));
                }
                result.warnings.push(
                    "Removing them from the app's API permissions failed, so their expiry dates \
                     stay and the next audit lists them again. Remove them on the Permissions \
                     tab so \"Grant admin consent\" can't restore them."
                        .to_string(),
                );
            }
        }
    }

    // Clear the expiries that are done with: re-granted, ended elsewhere, and
    // revoked now unless the manifest still declares them.
    let mut cleared: Vec<&GrantExpiry> = plan.regranted.iter().collect();
    cleared.extend(
        ended
            .iter()
            .filter(|e| !(manifest_failed && revoked_now.contains(e))),
    );
    let mut next_tags = tags.clone();
    for e in cleared {
        if let Some(n) = with_expiry(&next_tags, &e.resource_app_id, &e.app_role_id, None) {
            next_tags = n;
        }
    }
    let mut tags_written = false;
    if next_tags != tags {
        match client.set_service_principal_tags(&sp_id, &next_tags).await {
            Ok(()) => {
                record_sp_tags(&state.cache, tenant_id, &sp_id, &next_tags);
                tags_written = true;
            }
            Err(err) => {
                tracing::warn!(code = err.ui_code(), "expired grants: tag cleanup failed");
                result.warnings.push(
                    "The expiry dates could not be cleared; the next audit will list these again."
                        .to_string(),
                );
            }
        }
    }
    if !result.revoked.is_empty() || tags_written || !ended.is_empty() {
        invalidate_app_detail_state(&state.cache, tenant_id);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use azapptoolkit_core::cache::{Cache, CacheKind};
    use azapptoolkit_core::models::{AppRoleAssignment, ServicePrincipal};

    const RES: &str = "00000003-0000-0000-c000-000000000000";
    const ROLE: &str = "45bbb07e-7321-4fd7-a8f6-3ff27e6a81c8";
    const OTHER_ROLE: &str = "7ab1d382-f21e-4acd-a863-ba3e13f7da61";
    const UNHELD_ROLE: &str = "0e263e50-5827-48a4-b97c-d940288653c7";

    fn expiry(role: &str) -> GrantExpiry {
        GrantExpiry {
            resource_app_id: RES.into(),
            app_role_id: role.into(),
            expires_on: "2026-11-01".parse().unwrap(),
        }
    }

    fn assignment(id: &str, resource: &str, role: &str) -> AppRoleAssignment {
        AppRoleAssignment {
            id: id.into(),
            principal_id: "sp-1".into(),
            resource_id: resource.into(),
            app_role_id: role.into(),
            ..Default::default()
        }
    }

    #[test]
    fn plan_revocations_matches_resource_and_role() {
        let resources = HashMap::from([(RES.to_string(), "graph-sp".to_string())]);
        let assignments = vec![
            assignment("a-1", "GRAPH-SP", &ROLE.to_uppercase()),
            assignment("a-2", "other-sp", OTHER_ROLE),
        ];
        let plan = plan_revocations(
            &[expiry(ROLE), expiry(OTHER_ROLE)],
            &assignments,
            &resources,
        );
        assert_eq!(plan.revoke, vec![("a-1".to_string(), expiry(ROLE))]);
        assert_eq!(
            plan.gone,
            vec![expiry(OTHER_ROLE)],
            "the other role is held on another resource"
        );
        // An unresolved resource (a cached "not found") with the role still
        // held is never called gone: its tag stays (B3b). Nothing revokes on
        // a role-only match.
        let plan = plan_revocations(&[expiry(ROLE)], &assignments, &HashMap::new());
        assert!(plan.revoke.is_empty());
        assert!(plan.gone.is_empty(), "{:?}", plan.gone);
        assert_eq!(plan.unresolved, vec![expiry(ROLE)]);
        // A role nobody holds is gone, resolved or not.
        let plan = plan_revocations(&[expiry(UNHELD_ROLE)], &assignments, &HashMap::new());
        assert_eq!(plan.gone, vec![expiry(UNHELD_ROLE)]);
        assert!(plan.unresolved.is_empty());
        // A grant created after its expiry date passed is a later grant.
        let mut late = assignment("a-3", "graph-sp", ROLE);
        late.created_date_time = Some("2026-11-02T00:00:00Z".parse().unwrap());
        let mut on_the_day = assignment("a-4", "graph-sp", ROLE);
        on_the_day.created_date_time = Some("2026-11-01T23:00:00Z".parse().unwrap());
        let plan = plan_revocations(&[expiry(ROLE)], &[late.clone()], &resources);
        assert_eq!(plan.regranted, vec![expiry(ROLE)]);
        let plan = plan_revocations(&[expiry(ROLE)], &[late, on_the_day], &resources);
        assert_eq!(
            plan.revoke,
            vec![("a-4".to_string(), expiry(ROLE))],
            "made on its last day, so it is the dated grant"
        );
    }

    #[test]
    fn expiry_input_validation() {
        let now: jiff::Timestamp = "2026-11-25T12:00:00Z".parse().unwrap();
        let code = |d: Option<&str>| parse_expiry_date(d, now).err().map(|e| e.code);
        assert_eq!(code(Some("2026-11-24")), Some("invalid_date".into()));
        assert_eq!(code(Some("24/11/2026")), Some("invalid_date".into()));
        assert_eq!(code(None), None, "clearing needs no date");
        assert_eq!(
            parse_expiry_date(Some("2026-11-25"), now).unwrap(),
            Some("2026-11-25".parse().unwrap()),
            "today is allowed: it expires at the end of the day"
        );
        let pair = |r: &str, role: &str| GrantRef {
            resource_app_id: r.into(),
            app_role_id: role.into(),
        };
        let grants_code = |g: &[GrantRef]| check_grants(g).err().map(|e| e.code);
        assert_eq!(grants_code(&[pair(RES, ROLE)]), None);
        assert_eq!(
            grants_code(&[pair("nope", ROLE)]),
            Some("invalid_id".into())
        );
        assert_eq!(grants_code(&[]), Some("invalid_grants".into()));
        assert_eq!(
            grants_code(&vec![pair(RES, ROLE); 51]),
            Some("invalid_grants".into())
        );
    }

    #[test]
    fn record_sp_tags_patches_the_index_row_and_keeps_others() {
        use crate::commands::applications::{record_sp_tags, sp_index_key};
        const T: &str = "tenant-1";
        let cache = Cache::new();
        let sp = |id: &str, tags: &[&str]| ServicePrincipal {
            id: id.into(),
            app_id: format!("app-{id}"),
            tags: tags.iter().map(|t| t.to_string()).collect(),
            ..Default::default()
        };
        cache.put_typed_index(
            CacheKind::Lists,
            sp_index_key(T),
            std::sync::Arc::new(vec![sp("sp-1", &["HideApp"]), sp("sp-2", &[])]),
        );
        let tags = vec![
            "HideApp".to_string(),
            "azapptoolkit:grantExpiry:v1|x".to_string(),
        ];
        record_sp_tags(&cache, T, "sp-1", &tags);
        let index = cache
            .get_typed::<Vec<ServicePrincipal>>(CacheKind::Lists, &sp_index_key(T))
            .expect("the index is patched, not dropped");
        assert_eq!(index[0].tags, tags);
        assert!(index[1].tags.is_empty());
        // An SP the index doesn't hold leaves it alone.
        record_sp_tags(&cache, T, "sp-9", &tags);
        assert!(
            cache
                .get_typed::<Vec<ServicePrincipal>>(CacheKind::Lists, &sp_index_key(T))
                .is_some()
        );
    }

    // ---- the Fix and the writers against a mock Graph ---------------------

    mod graph {
        use super::*;
        use wiremock::matchers::{body_json, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const T: &str = "tenant-1";
        const SP: &str = "5f8b2c1a-0d3e-4b6f-9a7c-1e2d3f4a5b6c";
        const OBJ: &str = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
        const APP: &str = "11111111-2222-4333-8444-555555555555";
        const RES_SP: &str = "99999999-8888-4777-8666-555555555555";
        const NOW: &str = "2026-11-25T12:00:00Z";

        fn now() -> Timestamp {
            NOW.parse().unwrap()
        }

        fn tag(role: &str, date: &str) -> String {
            azapptoolkit_core::audit::encode_expiry_tag(&GrantExpiry {
                resource_app_id: RES.into(),
                app_role_id: role.into(),
                expires_on: date.parse().unwrap(),
            })
            .unwrap()
        }

        fn grant(role: &str) -> GrantRef {
            GrantRef {
                resource_app_id: RES.into(),
                app_role_id: role.into(),
            }
        }

        async fn mount_sp_tags(server: &MockServer, tags: &[String]) {
            Mock::given(method("GET"))
                .and(path(format!("/v1.0/servicePrincipals/{SP}")))
                .and(query_param("$select", "id,tags"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({ "id": SP, "tags": tags })),
                )
                .mount(server)
                .await;
        }

        /// The tag write, expected `times` times with exactly `tags`.
        async fn expect_sp_tags(server: &MockServer, tags: &[String], times: u64) {
            Mock::given(method("PATCH"))
                .and(path(format!("/v1.0/servicePrincipals/{SP}")))
                .and(body_json(serde_json::json!({ "tags": tags })))
                .respond_with(ResponseTemplate::new(204))
                .expect(times)
                .mount(server)
                .await;
        }

        async fn no_sp_tag_write(server: &MockServer) {
            Mock::given(method("PATCH"))
                .and(path(format!("/v1.0/servicePrincipals/{SP}")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(server)
                .await;
        }

        /// Microsoft Graph's service principal, defining both roles.
        async fn mount_resource(server: &MockServer) {
            Mock::given(method("GET"))
                .and(path("/v1.0/servicePrincipals"))
                .and(query_param("$filter", format!("appId eq '{RES}'")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [{
                        "id": RES_SP, "appId": RES, "displayName": "Microsoft Graph",
                        "appRoles": [
                            { "id": ROLE, "value": "Chat.Read.All", "allowedMemberTypes": ["Application"] },
                            { "id": OTHER_ROLE, "value": "CallRecords.Read.All", "allowedMemberTypes": ["Application"] }
                        ]
                    }]
                })))
                .mount(server)
                .await;
        }

        /// The SP's held assignments: `(assignment id, role, created)`.
        async fn mount_assignments(server: &MockServer, held: &[(&str, &str, &str)]) {
            let value: Vec<serde_json::Value> = held
                .iter()
                .map(|(id, role, created)| {
                    serde_json::json!({
                        "id": id, "principalId": SP, "resourceId": RES_SP,
                        "appRoleId": role, "createdDateTime": created
                    })
                })
                .collect();
            Mock::given(method("GET"))
                .and(path(format!(
                    "/v1.0/servicePrincipals/{SP}/appRoleAssignments"
                )))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": value })),
                )
                .mount(server)
                .await;
        }

        async fn expect_delete(server: &MockServer, assignment: &str, status: u16, times: u64) {
            Mock::given(method("DELETE"))
                .and(path(format!(
                    "/v1.0/servicePrincipals/{SP}/appRoleAssignments/{assignment}"
                )))
                .respond_with(ResponseTemplate::new(status).set_body_json(serde_json::json!({
                    "error": { "code": "Authorization_RequestDenied", "message": "Insufficient privileges" }
                })))
                .expect(times)
                .mount(server)
                .await;
        }

        /// App registration [`OBJ`] (app [`APP`], paired with [`SP`]),
        /// declaring both roles.
        async fn mount_app(server: &MockServer) {
            Mock::given(method("GET"))
                .and(path(format!("/v1.0/applications/{OBJ}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": OBJ, "appId": APP, "displayName": "Call Analytics",
                    "requiredResourceAccess": [{
                        "resourceAppId": RES,
                        "resourceAccess": [
                            { "id": ROLE, "type": "Role" },
                            { "id": OTHER_ROLE, "type": "Role" }
                        ]
                    }]
                })))
                .mount(server)
                .await;
            Mock::given(method("GET"))
                .and(path("/v1.0/servicePrincipals"))
                .and(query_param("$filter", format!("appId eq '{APP}'")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [{ "id": SP, "appId": APP, "displayName": "Call Analytics" }]
                })))
                .mount(server)
                .await;
        }

        /// The manifest write, expected once, declaring only `OTHER_ROLE`.
        async fn expect_manifest_without_role(server: &MockServer, status: u16) {
            Mock::given(method("PATCH"))
                .and(path(format!("/v1.0/applications/{OBJ}")))
                .and(body_json(serde_json::json!({
                    "requiredResourceAccess": [{
                        "resourceAppId": RES,
                        "resourceAccess": [{ "id": OTHER_ROLE, "type": "Role" }]
                    }]
                })))
                .respond_with(
                    ResponseTemplate::new(status).set_body_json(serde_json::json!({
                        "error": { "code": "Request_BadRequest", "message": "bad" }
                    })),
                )
                .expect(1)
                .mount(server)
                .await;
        }

        /// I3: the Fix revokes exactly the grants the confirm named, never one
        /// that passed its date after the audit ran.
        #[tokio::test]
        async fn the_fix_revokes_only_the_confirmed_grants() {
            let server = MockServer::start().await;
            let (a, b) = (tag(ROLE, "2026-11-01"), tag(OTHER_ROLE, "2026-11-20"));
            mount_sp_tags(&server, &["HideApp".into(), a, b.clone()]).await;
            mount_resource(&server).await;
            mount_assignments(
                &server,
                &[
                    ("a-1", ROLE, "2026-01-01T00:00:00Z"),
                    ("a-2", OTHER_ROLE, "2026-01-01T00:00:00Z"),
                ],
            )
            .await;
            expect_delete(&server, "a-1", 204, 1).await;
            expect_delete(&server, "a-2", 204, 0).await;
            expect_sp_tags(&server, &["HideApp".into(), b], 1).await;
            let state = AppState::for_test(T, &server.uri());

            let r = revoke_expired(
                &state,
                T,
                SP,
                AuditPrincipalKind::ServicePrincipal,
                &[grant(ROLE)],
                now(),
            )
            .await
            .unwrap();
            assert_eq!(r.revoked, vec!["Chat.Read.All".to_string()]);
            assert!(r.failed.is_empty() && r.warnings.is_empty(), "{r:?}");
        }

        /// I4: a revoke whose manifest declaration can't be removed keeps its
        /// expiry (the next audit flags it again) and says so.
        #[tokio::test]
        async fn a_failed_manifest_write_keeps_the_expiry_and_warns() {
            let server = MockServer::start().await;
            mount_sp_tags(&server, &[tag(ROLE, "2026-11-01")]).await;
            mount_app(&server).await;
            mount_resource(&server).await;
            mount_assignments(&server, &[("a-1", ROLE, "2026-01-01T00:00:00Z")]).await;
            expect_delete(&server, "a-1", 204, 1).await;
            expect_manifest_without_role(&server, 400).await;
            no_sp_tag_write(&server).await;
            let state = AppState::for_test(T, &server.uri());

            let r = revoke_expired(
                &state,
                T,
                OBJ,
                AuditPrincipalKind::Application,
                &[grant(ROLE)],
                now(),
            )
            .await
            .unwrap();
            assert_eq!(r.revoked, vec!["Chat.Read.All".to_string()]);
            assert_eq!(r.warnings.len(), 1, "{r:?}");
        }

        /// A grant already revoked elsewhere only has its expiry cleared: its
        /// declaration may be deliberate (the Exchange-scoped path keeps a
        /// permission declared after stripping its org-wide grant).
        #[tokio::test]
        async fn an_already_gone_grant_only_has_its_expiry_cleared() {
            let server = MockServer::start().await;
            mount_sp_tags(&server, &[tag(ROLE, "2026-11-01")]).await;
            mount_app(&server).await;
            mount_resource(&server).await;
            mount_assignments(&server, &[]).await;
            Mock::given(method("PATCH"))
                .and(path(format!("/v1.0/applications/{OBJ}")))
                .respond_with(ResponseTemplate::new(204))
                .expect(0)
                .mount(&server)
                .await;
            expect_sp_tags(&server, &[], 1).await;
            let state = AppState::for_test(T, &server.uri());

            let r = revoke_expired(
                &state,
                T,
                OBJ,
                AuditPrincipalKind::Application,
                &[grant(ROLE)],
                now(),
            )
            .await
            .unwrap();
            assert_eq!(r.already_gone, vec!["Chat.Read.All".to_string()]);
            assert!(r.revoked.is_empty() && r.warnings.is_empty(), "{r:?}");
        }

        /// A grant on a resource other than Graph says which resource: both
        /// define `Mail.Read` (B3c).
        #[tokio::test]
        async fn a_non_graph_grant_is_named_with_its_resource() {
            const EXO: &str = "00000002-0000-0ff1-ce00-000000000000";
            let server = MockServer::start().await;
            let exo_tag = azapptoolkit_core::audit::encode_expiry_tag(&GrantExpiry {
                resource_app_id: EXO.into(),
                app_role_id: ROLE.into(),
                expires_on: "2026-11-01".parse().unwrap(),
            })
            .unwrap();
            mount_sp_tags(&server, &[exo_tag]).await;
            mount_app(&server).await;
            Mock::given(method("GET"))
                .and(path("/v1.0/servicePrincipals"))
                .and(query_param("$filter", format!("appId eq '{EXO}'")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [{
                        "id": RES_SP, "appId": EXO, "displayName": "Office 365 Exchange Online",
                        "appRoles": [
                            { "id": ROLE, "value": "Mail.Read", "allowedMemberTypes": ["Application"] }
                        ]
                    }]
                })))
                .mount(&server)
                .await;
            mount_assignments(&server, &[]).await;
            expect_sp_tags(&server, &[], 1).await;
            let state = AppState::for_test(T, &server.uri());

            let r = revoke_expired(
                &state,
                T,
                OBJ,
                AuditPrincipalKind::Application,
                &[GrantRef {
                    resource_app_id: EXO.into(),
                    app_role_id: ROLE.into(),
                }],
                now(),
            )
            .await
            .unwrap();
            assert_eq!(
                r.already_gone,
                vec!["Mail.Read on Office 365 Exchange Online".to_string()]
            );
        }

        /// A downgrade moves the broad grant's expiry onto its narrower
        /// replacement, so the safeguard survives the swap.
        #[tokio::test]
        async fn a_downgrade_carries_the_expiry_to_the_narrower_grant() {
            let server = MockServer::start().await;
            mount_sp_tags(&server, &["HideApp".into(), tag(ROLE, "2026-12-25")]).await;
            expect_sp_tags(
                &server,
                &["HideApp".into(), tag(OTHER_ROLE, "2026-12-25")],
                1,
            )
            .await;
            let state = AppState::for_test(T, &server.uri());

            carry_expiry(&state, T, SP, RES, ROLE, OTHER_ROLE).await;
        }

        /// I1: a grant created after its expiry date isn't the grant the date
        /// was set for (it was revoked and granted again): kept, tag cleared.
        #[tokio::test]
        async fn a_grant_made_after_its_expiry_date_is_kept() {
            let server = MockServer::start().await;
            mount_sp_tags(&server, &[tag(ROLE, "2026-11-01")]).await;
            mount_resource(&server).await;
            mount_assignments(&server, &[("a-1", ROLE, "2026-11-10T09:00:00Z")]).await;
            expect_delete(&server, "a-1", 204, 0).await;
            expect_sp_tags(&server, &[], 1).await;
            let state = AppState::for_test(T, &server.uri());

            let r = revoke_expired(
                &state,
                T,
                SP,
                AuditPrincipalKind::ServicePrincipal,
                &[grant(ROLE)],
                now(),
            )
            .await
            .unwrap();
            assert_eq!(r.regranted, vec!["Chat.Read.All".to_string()]);
            assert!(r.revoked.is_empty(), "{r:?}");
        }

        /// I5: a refused revoke keeps its expiry and carries its error code,
        /// so the row raises the right lever.
        #[tokio::test]
        async fn a_refused_revoke_keeps_its_expiry_and_carries_its_error() {
            let server = MockServer::start().await;
            mount_sp_tags(&server, &[tag(ROLE, "2026-11-01")]).await;
            mount_resource(&server).await;
            mount_assignments(&server, &[("a-1", ROLE, "2026-01-01T00:00:00Z")]).await;
            expect_delete(&server, "a-1", 403, 1).await;
            no_sp_tag_write(&server).await;
            let state = AppState::for_test(T, &server.uri());

            let r = revoke_expired(
                &state,
                T,
                SP,
                AuditPrincipalKind::ServicePrincipal,
                &[grant(ROLE)],
                now(),
            )
            .await
            .unwrap();
            assert_eq!(r.failed, vec!["Chat.Read.All".to_string()]);
            assert_eq!(r.error.map(|e| e.code).as_deref(), Some("forbidden"));
        }

        /// A confirmed grant whose date was changed since the audit is left
        /// alone and reported as such — never "already gone".
        #[tokio::test]
        async fn a_confirmed_grant_no_longer_past_its_date_is_left_alone() {
            let server = MockServer::start().await;
            mount_sp_tags(&server, &[tag(ROLE, "2027-01-31")]).await;
            no_sp_tag_write(&server).await;
            let state = AppState::for_test(T, &server.uri());

            let r = revoke_expired(
                &state,
                T,
                SP,
                AuditPrincipalKind::ServicePrincipal,
                &[grant(ROLE)],
                now(),
            )
            .await
            .unwrap();
            assert_eq!(r.unchanged.len(), 1, "{r:?}");
            assert!(r.already_gone.is_empty(), "{r:?}");
        }

        /// I2: every grant in one write lands in one tag write.
        #[tokio::test]
        async fn one_write_sets_every_grant_in_a_single_tag_write() {
            let server = MockServer::start().await;
            mount_sp_tags(&server, &["HideApp".into()]).await;
            expect_sp_tags(
                &server,
                &[
                    "HideApp".into(),
                    tag(ROLE, "2026-12-25"),
                    tag(OTHER_ROLE, "2026-12-25"),
                ],
                1,
            )
            .await;
            let state = AppState::for_test(T, &server.uri());

            write_expiries(
                &state,
                T,
                SP,
                &[grant(ROLE), grant(OTHER_ROLE)],
                Some("2026-12-25".parse().unwrap()),
            )
            .await
            .unwrap();
        }

        /// I1: after a revoke, an expiry whose role is no longer held is
        /// pruned, so a later grant doesn't inherit it.
        #[tokio::test]
        async fn a_revoke_prunes_the_expiries_of_grants_no_longer_held() {
            let server = MockServer::start().await;
            let kept = tag(OTHER_ROLE, "2026-12-25");
            mount_sp_tags(
                &server,
                &["HideApp".into(), tag(ROLE, "2026-12-25"), kept.clone()],
            )
            .await;
            mount_assignments(&server, &[("a-2", OTHER_ROLE, "2026-01-01T00:00:00Z")]).await;
            expect_sp_tags(&server, &["HideApp".into(), kept], 1).await;
            let state = AppState::for_test(T, &server.uri());

            prune_unheld_expiries(&state, T, SP).await;
        }

        /// Minor 6 (re-graded): a tag write patches the SP index row but keeps
        /// the cached audit run — a HideApp toggle can't change any finding.
        #[test]
        fn record_sp_tags_keeps_the_cached_audit_run() {
            use crate::commands::applications::record_sp_tags;
            use crate::commands::audit::audit_cache_key;
            let cache = Cache::new();
            cache.put(CacheKind::Audit, audit_cache_key(T), &"audit".to_string());
            record_sp_tags(&cache, T, SP, &["HideApp".to_string()]);
            assert!(
                cache
                    .get::<String>(CacheKind::Audit, &audit_cache_key(T))
                    .is_some()
            );
        }
    }
}
