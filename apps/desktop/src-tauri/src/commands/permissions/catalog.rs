use tauri::State;

use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_core::models::ServicePrincipal;

use crate::commands::applications::app_role_resources_key;
use crate::dto::UiError;
use crate::dto::permissions::{CatalogResourceSummary, ResourcePermissions, RoleEntry, ScopeEntry};
use crate::state::AppState;

/// The bundled resource directory for the permission picker's dropdown. The
/// directory carries names only, so both counts are 0 here; the picker fills
/// its per-resource counts from [`list_resource_permission_counts`], which
/// resolves each resource's live service principal.
#[tauri::command]
pub fn list_catalog_resources() -> Vec<CatalogResourceSummary> {
    azapptoolkit_permissions::bundled_resources_slice()
        .iter()
        .map(|r| CatalogResourceSummary {
            app_id: r.app_id.clone(),
            display_name: r.display_name.clone(),
            role_count: 0,
            scope_count: 0,
        })
        .collect()
}

/// Tenant-owned resources (the org's own app registrations / service
/// principals) that expose at least one enabled Application app role, for the
/// Grant-access picker's "Tenant app registrations" group. Returns only the
/// directory (name + appId + a role count for the dropdown label); the picker
/// resolves the actual roles live via [`list_resource_permissions`] when one is
/// selected, and the grant path (`grant_managed_identity_permission` /
/// `grant_single_permission`) already accepts an arbitrary `resource_app_id`, so
/// this adds no grant surface. Cached under [`CacheKind::Lists`] (tenant-scoped
/// key, [`app_role_resources_key`]). Busted by `invalidate_app_lists` (an app/SP
/// create or delete changes the set) and by the App roles tab's writers through
/// `invalidate_app_role_resources` (the first enabled Application role added, or
/// the last one disabled/removed, moves an SP in or out of this directory and
/// shifts its count); the Lists TTL and the sign-out tenant sweep cover the rest.
#[tauri::command]
pub async fn list_app_role_resources(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<CatalogResourceSummary>, UiError> {
    // The cache-HIT path below returns before any client is built, so the
    // `graph_for` on the miss path is not a session proof for it.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    let key = app_role_resources_key(&tenant_id);
    if let Some(cached) = state
        .cache
        .get::<Vec<CatalogResourceSummary>>(CacheKind::Lists, &key)
    {
        tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = %key, "hit");
        return Ok(cached);
    }
    tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = %key, "miss");
    // Before the tenant SP scan: an app create/delete or an App roles write
    // that lands while it pages busts this key, and the store below must not
    // re-cache the pre-mutation directory over it.
    let watch = state.cache.generation_for(CacheKind::Lists, &key);

    let client = state.graph_for(&tenant_id);
    let mut rows: Vec<CatalogResourceSummary> = client
        .list_tenant_app_role_resources()
        .await?
        .into_iter()
        .filter_map(app_role_resource_summary)
        .collect();
    rows.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    state.cache.put_if_current(watch, &rows);
    Ok(rows)
}

/// An SP → summary **iff** it exposes ≥1 grantable Application app role: enabled
/// (`isEnabled != false`), a non-empty `value` (what the picker and grant match
/// on), and `allowedMemberTypes` containing "Application" (case-insensitive) —
/// user-only roles can't be assigned to a service principal / managed identity.
/// `role_count` is that count; `scope_count` is 0 (the tenant-app group lists app
/// roles only). Pure so it's unit-testable without a Graph client (mirrors
/// [`service_principal_to_permissions`]).
fn app_role_resource_summary(sp: ServicePrincipal) -> Option<CatalogResourceSummary> {
    let role_count = sp
        .app_roles
        .iter()
        .filter(|r| {
            r.is_enabled != Some(false)
                && !r.value.is_empty()
                && r.allowed_member_types
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case("Application"))
        })
        .count();
    (role_count > 0).then_some(CatalogResourceSummary {
        app_id: sp.app_id,
        display_name: sp.display_name,
        role_count,
        scope_count: 0,
    })
}

/// Returns the roles + scopes for `resource_app_id`, resolved **live** from
/// Microsoft Graph (`source: "graph"`). The bundled catalog supplies only the
/// resource *directory* for the picker dropdown; permission definitions are
/// never bundled, so the picker always reflects the complete, current
/// Application + Delegated set. A missing SP is `resource_not_found`; an
/// offline/throttled/consent failure surfaces as an error (there is no stale
/// fallback by design).
#[tauri::command]
pub async fn list_resource_permissions(
    state: State<'_, AppState>,
    tenant_id: String,
    resource_app_id: String,
) -> Result<ResourcePermissions, UiError> {
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
    Ok(service_principal_to_permissions(sp))
}

/// Maps a live resource service principal to the picker DTO. Drops disabled
/// (retired) roles/scopes — `isEnabled == false` — and sorts each list by
/// `value` so the long live list is scannable.
fn service_principal_to_permissions(sp: ServicePrincipal) -> ResourcePermissions {
    let mut app_roles: Vec<RoleEntry> = sp
        .app_roles
        .into_iter()
        .filter(|r| r.is_enabled != Some(false))
        .map(|r| RoleEntry {
            id: r.id,
            value: r.value,
            display_name: r.display_name,
            description: r.description,
            allowed_member_types: r.allowed_member_types,
        })
        .collect();
    app_roles.sort_by(|a, b| a.value.cmp(&b.value));

    let mut oauth2_permission_scopes: Vec<ScopeEntry> = sp
        .oauth2_permission_scopes
        .into_iter()
        .filter(|s| s.is_enabled != Some(false))
        .map(|s| ScopeEntry {
            id: s.id,
            value: s.value,
            admin_consent_display_name: s.admin_consent_display_name,
            admin_consent_description: s.admin_consent_description,
        })
        .collect();
    oauth2_permission_scopes.sort_by(|a, b| a.value.cmp(&b.value));

    ResourcePermissions {
        app_id: sp.app_id,
        display_name: sp.display_name,
        app_roles,
        oauth2_permission_scopes,
        source: "graph".into(),
    }
}

/// Live permission counts per well-known resource, for the picker dropdown
/// labels. Resolves each directory resource's service principal in parallel
/// (cached under `CacheKind::Permissions`), counting only enabled roles/scopes
/// so the numbers match what the picker actually lists. A resource that can't
/// be resolved (offline/unknown) reports 0/0 rather than failing the whole
/// call — the dropdown still lists every resource by name.
#[tauri::command]
pub async fn list_resource_permission_counts(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<CatalogResourceSummary>, UiError> {
    let client = state.graph_for(&tenant_id);
    let summaries = futures::future::join_all(
        azapptoolkit_permissions::bundled_resources_slice()
            .iter()
            .map(|r| {
                let client = client.clone();
                let app_id = r.app_id.clone();
                let display_name = r.display_name.clone();
                async move {
                    let (role_count, scope_count) = match client.resolve_resource_sp(&app_id).await
                    {
                        Ok(Some(sp)) => (
                            sp.app_roles
                                .iter()
                                .filter(|x| x.is_enabled != Some(false))
                                .count(),
                            sp.oauth2_permission_scopes
                                .iter()
                                .filter(|x| x.is_enabled != Some(false))
                                .count(),
                        ),
                        _ => (0, 0),
                    };
                    CatalogResourceSummary {
                        app_id,
                        display_name,
                        role_count,
                        scope_count,
                    }
                }
            }),
    )
    .await;
    Ok(summaries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::{AppRole, OAuth2PermissionScope};

    #[test]
    fn catalog_resources_list_the_directory_without_counts() {
        let resources = list_catalog_resources();
        assert_eq!(
            resources.len(),
            azapptoolkit_permissions::bundled_resources_slice().len()
        );
        assert!(
            resources
                .iter()
                .any(|r| r.app_id == "00000003-0000-0000-c000-000000000000")
        );
        // Counts come live from `list_resource_permission_counts`; the
        // directory itself carries none.
        assert!(
            resources
                .iter()
                .all(|r| r.role_count == 0 && r.scope_count == 0)
        );
    }

    fn role(value: &str, enabled: Option<bool>) -> AppRole {
        AppRole {
            id: format!("id-{value}"),
            value: value.into(),
            display_name: format!("{value} role"),
            is_enabled: enabled,
            allowed_member_types: vec!["Application".into()],
            ..Default::default()
        }
    }

    fn scope(value: &str, enabled: Option<bool>) -> OAuth2PermissionScope {
        OAuth2PermissionScope {
            id: format!("id-{value}"),
            value: value.into(),
            is_enabled: enabled,
            ..Default::default()
        }
    }

    #[test]
    fn maps_live_sp_dropping_disabled_and_sorting_by_value() {
        let sp = ServicePrincipal {
            app_id: "00000003-0000-0000-c000-000000000000".into(),
            display_name: "Microsoft Graph".into(),
            app_roles: vec![
                role("User.Read.All", Some(true)),
                role("Application.ReadWrite.All", None), // null isEnabled => kept
                role("Legacy.Disabled", Some(false)),    // dropped
            ],
            oauth2_permission_scopes: vec![
                scope("offline_access", Some(true)),
                scope("email", Some(false)), // dropped
                scope("User.Read", None),    // kept
            ],
            ..Default::default()
        };

        let perms = service_principal_to_permissions(sp);

        assert_eq!(perms.source, "graph");
        // Disabled entries dropped; the rest sorted alphabetically by value.
        assert_eq!(
            perms
                .app_roles
                .iter()
                .map(|r| r.value.as_str())
                .collect::<Vec<_>>(),
            ["Application.ReadWrite.All", "User.Read.All"]
        );
        assert_eq!(
            perms
                .oauth2_permission_scopes
                .iter()
                .map(|s| s.value.as_str())
                .collect::<Vec<_>>(),
            ["User.Read", "offline_access"]
        );
        // allowedMemberTypes is carried through for the picker's app-only filter.
        assert!(
            perms.app_roles[1]
                .allowed_member_types
                .iter()
                .any(|t| t == "Application")
        );
    }

    /// `role()` with explicit `allowedMemberTypes` (it hardcodes `Application`).
    fn role_with_types(value: &str, enabled: Option<bool>, types: &[&str]) -> AppRole {
        AppRole {
            allowed_member_types: types.iter().map(|t| t.to_string()).collect(),
            ..role(value, enabled)
        }
    }

    #[test]
    fn app_role_resource_summary_keeps_sp_exposing_application_roles() {
        let sp = ServicePrincipal {
            app_id: "11111111-1111-1111-1111-111111111111".into(),
            display_name: "Contoso Orders API".into(),
            app_roles: vec![
                role("Orders.Read", Some(true)),
                role("Orders.Write", None), // null isEnabled => kept
            ],
            ..Default::default()
        };
        let summary = app_role_resource_summary(sp).expect("exposes application roles");
        assert_eq!(summary.app_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(summary.display_name, "Contoso Orders API");
        assert_eq!(summary.role_count, 2);
        assert_eq!(summary.scope_count, 0);
    }

    #[test]
    fn app_role_resource_summary_counts_only_grantable_application_roles() {
        let sp = ServicePrincipal {
            app_id: "app".into(),
            display_name: "Mixed".into(),
            app_roles: vec![
                role("Orders.Read", Some(true)),                    // counted
                role("Legacy", Some(false)),                        // disabled -> dropped
                role_with_types("UserOnly", Some(true), &["User"]), // user-only -> dropped
                role_with_types("Both", Some(true), &["Application", "User"]), // counted
                role_with_types("", Some(true), &["Application"]), // empty value -> dropped (not matchable by the grant)
            ],
            ..Default::default()
        };
        let summary = app_role_resource_summary(sp).expect("has grantable roles");
        assert_eq!(summary.role_count, 2);
    }

    #[test]
    fn app_role_resource_summary_drops_sp_without_grantable_roles() {
        // No app roles at all (e.g. a managed identity, which the owner filter
        // returns but exposes none).
        assert!(
            app_role_resource_summary(ServicePrincipal {
                app_id: "a".into(),
                display_name: "Bare".into(),
                ..Default::default()
            })
            .is_none()
        );
        // Only user-only / disabled roles → not grantable to a service principal.
        let sp = ServicePrincipal {
            app_id: "a".into(),
            display_name: "UserApp".into(),
            app_roles: vec![
                role_with_types("UserOnly", Some(true), &["User"]),
                role("Disabled", Some(false)),
            ],
            ..Default::default()
        };
        assert!(app_role_resource_summary(sp).is_none());
    }
}
