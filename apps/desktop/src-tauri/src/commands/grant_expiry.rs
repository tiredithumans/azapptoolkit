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
use azapptoolkit_graph::GraphError;

use crate::commands::applications::{invalidate_app_detail_state, record_sp_tags};
use crate::commands::permissions::remove_declared_access;
use crate::commands::session::prove_tenant_session;
use crate::dto::UiError;
use crate::dto::permissions::RevokeExpiredResult;
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

/// Validates a set-expiry request: GUID ids, and a `YYYY-MM-DD` date that
/// hasn't passed (today is allowed — it expires at the end of the day, UTC).
/// `None` clears the expiry.
pub(crate) fn parse_expiry_input(
    resource_app_id: &str,
    app_role_id: &str,
    expires_on: Option<&str>,
    now: Timestamp,
) -> Result<Option<Date>, UiError> {
    if !is_guid(resource_app_id) || !is_guid(app_role_id) {
        return Err(invalid_id());
    }
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

/// Which assignments to revoke for the passed `expiries`: those on the
/// expiry's resource (by its service-principal id) with its role. An expiry
/// with nothing held — the grant was revoked by hand, or the resource is gone
/// — is `gone` (its tag is cleared, nothing revoked).
pub(crate) fn plan_revocations(
    expiries: &[GrantExpiry],
    assignments: &[AppRoleAssignment],
    resource_sp_ids: &HashMap<String, String>,
) -> (Vec<(String, GrantExpiry)>, Vec<GrantExpiry>) {
    let mut revoke = Vec::new();
    let mut gone = Vec::new();
    for e in expiries {
        let held: Vec<&AppRoleAssignment> = resource_sp_ids
            .get(&e.resource_app_id)
            .map(|res| {
                assignments
                    .iter()
                    .filter(|a| {
                        a.resource_id.eq_ignore_ascii_case(res)
                            && a.app_role_id.eq_ignore_ascii_case(&e.app_role_id)
                    })
                    .collect()
            })
            .unwrap_or_default();
        if held.is_empty() {
            gone.push(e.clone());
        } else {
            revoke.extend(held.into_iter().map(|a| (a.id.clone(), e.clone())));
        }
    }
    (revoke, gone)
}

/// Sets (or, with `expires_on: None`, clears) the expiry of one application
/// grant held by `sp_object_id`.
#[tauri::command]
pub async fn set_grant_expiry(
    state: State<'_, AppState>,
    tenant_id: String,
    sp_object_id: String,
    resource_app_id: String,
    app_role_id: String,
    expires_on: Option<String>,
) -> Result<(), UiError> {
    prove_tenant_session(&state, &tenant_id)?;
    if !is_guid(&sp_object_id) {
        return Err(invalid_id());
    }
    let date = parse_expiry_input(
        &resource_app_id,
        &app_role_id,
        expires_on.as_deref(),
        Timestamp::now(),
    )?;
    let client = state.graph_for(&tenant_id);
    let gate = state.single_flight(&sp_tags_gate_key(&tenant_id, &sp_object_id));
    let _held = gate.lock().await;
    let tags = client
        .get_service_principal_tags(&sp_object_id)
        .await
        .map_err(UiError::from)?;
    let next = with_expiry(&tags, &resource_app_id, &app_role_id, date).ok_or_else(invalid_id)?;
    if next != tags {
        client
            .set_service_principal_tags(&sp_object_id, &next)
            .await
            .map_err(UiError::from)?;
        record_sp_tags(&state.cache, &tenant_id, &sp_object_id, &next);
    }
    Ok(())
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
) -> Result<RevokeExpiredResult, UiError> {
    prove_tenant_session(&state, &tenant_id)?;
    let client = state.graph_for(&tenant_id);
    // An app row's `object_id` is the application; an SP-only row's is the SP.
    let (sp_id, app) = match principal_kind {
        AuditPrincipalKind::Application => {
            let app = client.get_application(&object_id).await?;
            let sp = client
                .get_service_principal_by_app_id(&app.app_id)
                .await?
                .ok_or_else(|| {
                    UiError::not_found("service_principal", "This app has no service principal")
                })?;
            (sp.id, Some(app))
        }
        AuditPrincipalKind::ServicePrincipal | AuditPrincipalKind::ManagedIdentity => {
            (object_id.clone(), None)
        }
    };
    let gate = state.single_flight(&sp_tags_gate_key(&tenant_id, &sp_id));
    let _held = gate.lock().await;
    let tags = client.get_service_principal_tags(&sp_id).await?;
    let now = Timestamp::now();
    let expired: Vec<GrantExpiry> = expiries_in(&tags)
        .into_iter()
        .filter(|e| expiry_has_passed(e.expires_on, now))
        .collect();
    let mut result = RevokeExpiredResult::default();
    if expired.is_empty() {
        return Ok(result);
    }

    // Resolve each named resource once: its SP id and role names. A resource
    // that can't be read keeps its expiries (reported failed), never guessed.
    let mut resource_sp_ids: HashMap<String, String> = HashMap::new();
    let mut role_names: HashMap<(String, String), String> = HashMap::new();
    let mut unreadable: HashSet<String> = HashSet::new();
    for resource in expired
        .iter()
        .map(|e| e.resource_app_id.clone())
        .collect::<HashSet<_>>()
    {
        match client.resolve_resource_sp(&resource).await {
            Ok(Some(sp)) => {
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
                unreadable.insert(resource);
            }
        }
    }
    let name = |e: &GrantExpiry| {
        role_names
            .get(&(e.resource_app_id.clone(), e.app_role_id.clone()))
            .filter(|v| !v.is_empty())
            .cloned()
            .unwrap_or_else(|| e.app_role_id.clone())
    };
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
    let (to_revoke, gone) = plan_revocations(&readable, &assignments, &resource_sp_ids);

    let mut processed: Vec<GrantExpiry> = gone.clone();
    result.already_gone.extend(gone.iter().map(name));
    let mut revoked_expiries: Vec<GrantExpiry> = Vec::new();
    for (assignment_id, e) in to_revoke {
        match client
            .remove_app_role_assignment(&sp_id, &assignment_id)
            .await
        {
            Ok(()) => {
                result.revoked.push(name(&e));
                revoked_expiries.push(e.clone());
                processed.push(e);
            }
            Err(GraphError::NotFound(_)) => {
                result.already_gone.push(name(&e));
                processed.push(e);
            }
            Err(err) => {
                tracing::warn!(code = err.ui_code(), "expired grants: revoke failed");
                result.failed.push(name(&e));
            }
        }
    }

    // One manifest PATCH for every revoked role on an app registration.
    if let Some(app) = app
        && !revoked_expiries.is_empty()
    {
        let mut next = app.required_resource_access.clone();
        let mut changed = false;
        for e in &revoked_expiries {
            changed |=
                remove_declared_access(&mut next, &e.resource_app_id, &e.app_role_id, Some("Role"));
        }
        if changed {
            let patch = azapptoolkit_graph::client::AppPatch {
                required_resource_access: Some(next),
                ..Default::default()
            };
            if let Err(err) = client.update_application(&object_id, &patch).await {
                tracing::warn!(
                    code = err.ui_code(),
                    "expired grants: manifest update failed"
                );
                result.warnings.push(
                    "The grants were revoked, but removing them from the app's API permissions \
                     failed — remove them on the Permissions tab so \"Grant admin consent\" \
                     can't restore them."
                        .to_string(),
                );
            }
        }
    }

    // Clear the processed expiries (revoked, or already gone).
    let mut next_tags = tags.clone();
    for e in &processed {
        if let Some(n) = with_expiry(&next_tags, &e.resource_app_id, &e.app_role_id, None) {
            next_tags = n;
        }
    }
    let landed = !result.revoked.is_empty();
    if next_tags != tags {
        match client.set_service_principal_tags(&sp_id, &next_tags).await {
            Ok(()) => record_sp_tags(&state.cache, &tenant_id, &sp_id, &next_tags),
            Err(err) => {
                tracing::warn!(code = err.ui_code(), "expired grants: tag cleanup failed");
                result.warnings.push(
                    "The expiry dates could not be cleared; the next audit will list these again."
                        .to_string(),
                );
            }
        }
    }
    if landed {
        invalidate_app_detail_state(&state.cache, &tenant_id);
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
        let (revoke, gone) = plan_revocations(
            &[expiry(ROLE), expiry(OTHER_ROLE)],
            &assignments,
            &resources,
        );
        assert_eq!(revoke, vec![("a-1".to_string(), expiry(ROLE))]);
        assert_eq!(
            gone,
            vec![expiry(OTHER_ROLE)],
            "the other role is held on another resource"
        );
        // An unresolvable resource has nothing to revoke.
        let (revoke, gone) = plan_revocations(&[expiry(ROLE)], &assignments, &HashMap::new());
        assert!(revoke.is_empty());
        assert_eq!(gone, vec![expiry(ROLE)]);
    }

    #[test]
    fn expiry_input_validation() {
        let now: jiff::Timestamp = "2026-11-25T12:00:00Z".parse().unwrap();
        let code = |r: &str, role: &str, d: Option<&str>| {
            parse_expiry_input(r, role, d, now).err().map(|e| e.code)
        };
        assert_eq!(
            code(RES, ROLE, Some("2026-11-24")),
            Some("invalid_date".into())
        );
        assert_eq!(
            code(RES, ROLE, Some("24/11/2026")),
            Some("invalid_date".into())
        );
        assert_eq!(
            code("nope", ROLE, Some("2026-12-01")),
            Some("invalid_id".into())
        );
        assert_eq!(code(RES, ROLE, None), None, "clearing needs no date");
        assert_eq!(
            parse_expiry_input(RES, ROLE, Some("2026-11-25"), now).unwrap(),
            Some("2026-11-25".parse().unwrap()),
            "today is allowed: it expires at the end of the day"
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
}
