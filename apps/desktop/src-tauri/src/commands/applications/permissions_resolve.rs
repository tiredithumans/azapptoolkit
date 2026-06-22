use std::collections::{HashMap, HashSet};

use tauri::State;

use azapptoolkit_core::models::ServicePrincipal;
use azapptoolkit_permissions::PermissionsCatalog;

use crate::dto::applications::PermissionDescriptor;
use crate::dto::permissions::{PermissionKind, ResolvedPermission};
use crate::dto::UiError;
use crate::state::AppState;

/// Resolves one declared permission to a [`ResolvedPermission`] through the
/// fixed fallback ladder — bundled catalog → live resource SP (`appRoles` then
/// `oauth2PermissionScopes`) → raw GUID with the declared Role/Scope kind —
/// joining the matching runtime grant via the caller's per-resource closures.
/// Extracted so the ladder reads once instead of three near-identical struct
/// builds inside the loop.
#[allow(clippy::too_many_arguments)]
fn resolve_one_permission(
    catalog: &PermissionsCatalog,
    resource_app_id: &str,
    resource_display_name: &Option<String>,
    cataloged: Option<&azapptoolkit_permissions::ResourceEntry>,
    live_sp: Option<&ServicePrincipal>,
    access: &azapptoolkit_core::models::ResourceAccess,
    runtime_assignment_for: &impl Fn(&str) -> Option<String>,
    runtime_grant_for: &impl Fn(&str) -> Option<String>,
) -> ResolvedPermission {
    // 1. Catalog.
    if let Some((display, kind)) = catalog.lookup_permission(resource_app_id, &access.id) {
        let permission_value = cataloged.and_then(|r| {
            r.app_roles
                .iter()
                .find(|x| x.id == access.id)
                .map(|x| x.value.clone())
                .or_else(|| {
                    r.oauth2_permission_scopes
                        .iter()
                        .find(|x| x.id == access.id)
                        .map(|x| x.value.clone())
                })
        });
        let permission_kind = PermissionKind::from_catalog_kind(kind);
        let (runtime_assignment_id, runtime_grant_id) = match permission_kind {
            PermissionKind::Application => (runtime_assignment_for(&access.id), None),
            PermissionKind::Delegated => (
                None,
                permission_value.as_deref().and_then(runtime_grant_for),
            ),
            PermissionKind::Unknown => (None, None),
        };
        return ResolvedPermission {
            resource_app_id: resource_app_id.to_string(),
            resource_display_name: resource_display_name.clone(),
            permission_id: access.id.clone(),
            permission_value,
            permission_display_name: Some(display),
            permission_kind,
            runtime_assignment_id,
            runtime_grant_id,
        };
    }

    // 2. Live SP fallback (appRoles, then oauth2PermissionScopes).
    if let Some(sp) = live_sp {
        if let Some(role) = sp.app_roles.iter().find(|r| r.id == access.id) {
            return ResolvedPermission {
                resource_app_id: resource_app_id.to_string(),
                resource_display_name: resource_display_name.clone(),
                permission_id: access.id.clone(),
                permission_value: Some(role.value.clone()),
                permission_display_name: Some(role.display_name.clone()),
                permission_kind: PermissionKind::Application,
                runtime_assignment_id: runtime_assignment_for(&access.id),
                runtime_grant_id: None,
            };
        }
        if let Some(scope) = sp
            .oauth2_permission_scopes
            .iter()
            .find(|s| s.id == access.id)
        {
            let display = scope
                .admin_consent_display_name
                .clone()
                .unwrap_or_else(|| scope.value.clone());
            return ResolvedPermission {
                resource_app_id: resource_app_id.to_string(),
                resource_display_name: resource_display_name.clone(),
                permission_id: access.id.clone(),
                permission_value: Some(scope.value.clone()),
                permission_display_name: Some(display),
                permission_kind: PermissionKind::Delegated,
                runtime_assignment_id: None,
                runtime_grant_id: runtime_grant_for(&scope.value),
            };
        }
    }

    // 3. Total miss: surface raw GUIDs with the declared Role/Scope kind.
    let permission_kind = match access.r#type.as_str() {
        "Role" => PermissionKind::Application,
        "Scope" => PermissionKind::Delegated,
        _ => PermissionKind::Unknown,
    };
    let runtime_assignment_id = matches!(permission_kind, PermissionKind::Application)
        .then(|| runtime_assignment_for(&access.id))
        .flatten();
    ResolvedPermission {
        resource_app_id: resource_app_id.to_string(),
        resource_display_name: resource_display_name.clone(),
        permission_id: access.id.clone(),
        permission_value: None,
        permission_display_name: None,
        permission_kind,
        runtime_assignment_id,
        runtime_grant_id: None,
    }
}

pub(super) async fn resolve_required_resource_access(
    client: &azapptoolkit_graph::GraphClient,
    declared: &[azapptoolkit_core::models::RequiredResourceAccess],
    app_role_assignments: &[azapptoolkit_core::models::AppRoleAssignment],
    oauth2_permission_grants: &[azapptoolkit_core::models::OAuth2PermissionGrant],
) -> Vec<ResolvedPermission> {
    let catalog = PermissionsCatalog::bundled();

    // Resolve every distinct declared resource's SP up front and concurrently
    // (each is an independent, Permissions-cached Graph lookup) so the per-row
    // formatting below reads `live_sps` without awaiting, instead of paying one
    // serial round trip per resource on a cold cache. We need each SP's id to
    // join runtime assignments/grants to the declared rows.
    let unique_resource_ids: Vec<String> = {
        let mut seen = HashSet::new();
        declared
            .iter()
            .map(|r| r.resource_app_id.clone())
            .filter(|id| seen.insert(id.clone()))
            .collect()
    };
    let live_sps: HashMap<String, Option<ServicePrincipal>> =
        futures::future::join_all(unique_resource_ids.into_iter().map(|id| async move {
            let sp = client.resolve_resource_sp(&id).await.ok().flatten();
            (id, sp)
        }))
        .await
        .into_iter()
        .collect();

    let mut out = Vec::new();

    for resource in declared {
        let cataloged = catalog.resource(&resource.resource_app_id);
        let resource_display_from_catalog = cataloged.map(|r| r.display_name.clone());

        let live_sp = live_sps
            .get(&resource.resource_app_id)
            .and_then(|o| o.as_ref());
        let resource_sp_id = live_sp.map(|sp| sp.id.as_str());

        let resource_display_name =
            resource_display_from_catalog.or_else(|| live_sp.map(|sp| sp.display_name.clone()));

        // Runtime-grant joins. Application: assignment.resource_id ==
        // resource_sp.id && assignment.app_role_id == permission_id.
        // Delegated: grant.resource_id == resource_sp.id and the scope
        // string contains the scope value (split_whitespace handles weird
        // whitespace exactly like the revoke command does).
        let runtime_assignment_for = |permission_id: &str| -> Option<String> {
            let sp_id = resource_sp_id?;
            app_role_assignments
                .iter()
                .find(|a| a.resource_id == sp_id && a.app_role_id == permission_id)
                .map(|a| a.id.clone())
        };
        let runtime_grant_for = |scope_value: &str| -> Option<String> {
            let sp_id = resource_sp_id?;
            oauth2_permission_grants
                .iter()
                .find(|g| {
                    g.resource_id == sp_id && g.scope.split_whitespace().any(|s| s == scope_value)
                })
                .and_then(|g| g.id.clone())
        };

        for access in &resource.resource_access {
            out.push(resolve_one_permission(
                catalog,
                &resource.resource_app_id,
                &resource_display_name,
                cataloged,
                live_sp,
                access,
                &runtime_assignment_for,
                &runtime_grant_for,
            ));
        }
    }

    out
}

#[tauri::command]
pub async fn resolve_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    resource_app_id: String,
    permission_id: String,
) -> Result<PermissionDescriptor, UiError> {
    let catalog = PermissionsCatalog::bundled();
    if let Some((display_name, kind)) = catalog.lookup_permission(&resource_app_id, &permission_id)
    {
        let resource_display_name = catalog
            .resource(&resource_app_id)
            .map(|r| r.display_name.clone())
            .unwrap_or_else(|| resource_app_id.clone());
        return Ok(PermissionDescriptor {
            display_name,
            kind: kind.to_string(),
            resource_display_name,
            source: "bundled".to_string(),
        });
    }

    let client = state.graph_for(&tenant_id);
    let sp = client
        .resolve_resource_sp(&resource_app_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "resource",
                format!("resource app id {resource_app_id} not found"),
            )
        })?;

    if let Some(role) = sp.app_roles.iter().find(|r| r.id == permission_id) {
        return Ok(PermissionDescriptor {
            display_name: role.display_name.clone(),
            kind: "Role".into(),
            resource_display_name: sp.display_name,
            source: "graph".into(),
        });
    }
    if let Some(scope) = sp
        .oauth2_permission_scopes
        .iter()
        .find(|s| s.id == permission_id)
    {
        let name = scope
            .admin_consent_display_name
            .clone()
            .unwrap_or_else(|| scope.value.clone());
        return Ok(PermissionDescriptor {
            display_name: name,
            kind: "Scope".into(),
            resource_display_name: sp.display_name,
            source: "graph".into(),
        });
    }

    Err(UiError::not_found(
        "permission",
        format!("permission id {permission_id} not found on {resource_app_id}"),
    ))
}
