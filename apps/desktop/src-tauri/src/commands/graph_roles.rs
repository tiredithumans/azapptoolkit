//! Shared Microsoft Graph app-role resolution.
//!
//! Several commands need to translate the appRole GUIDs in an app's
//! declared/granted permissions into permission names (`Mail.Read`,
//! `Sites.Selected`, …) and back. This is the one place that resolves Graph's
//! service principal and builds that index, so the Exchange and SharePoint
//! scoping commands stay in sync.

use std::collections::HashMap;

use tauri::State;

use azapptoolkit_core::models::AppRoleAssignment;
use azapptoolkit_graph::GraphClient;

use crate::dto::managed_identity::AppRoleGrantDto;
use crate::dto::UiError;
use crate::state::AppState;

/// Lists the application permissions a service principal **holds** — its granted
/// `appRoleAssignments`, with Microsoft Graph role ids resolved to permission
/// values (`Mail.Read`, …) and roles on other resources passed through id-only.
///
/// One command for every service-principal type: an enterprise application's SP
/// and a managed identity are both service principals, so "what permissions does
/// this identity hold?" is the same Graph read for each. (Replaces the
/// byte-identical `list_enterprise_app_permissions` and
/// `list_managed_identity_permissions`.)
#[tauri::command]
pub async fn list_held_app_role_grants(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<Vec<AppRoleGrantDto>, UiError> {
    let client = state.graph_for(&tenant_id);
    let assignments = client
        .list_app_role_assignments(&service_principal_id)
        .await?;
    Ok(resolve_app_role_grants(&client, assignments).await)
}

/// Microsoft Graph's first-party app id; mail/calendar/contacts and
/// `Sites.*` application permissions are exposed as appRoles on this resource.
pub(crate) const MICROSOFT_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// Builds `appRoleId -> permission value` for Microsoft Graph's appRoles, plus
/// the Graph resource service-principal id. Used to translate the GUIDs in an
/// app's declared/granted permissions into permission names like `Mail.Read`,
/// and (via a reverse scan) to find the appRole id for a known value.
pub(crate) async fn graph_role_index(
    client: &GraphClient,
) -> Result<(String, HashMap<String, String>), UiError> {
    let sp = client
        .resolve_resource_sp(MICROSOFT_GRAPH_APP_ID)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "resource",
                "Microsoft Graph service principal not found in tenant",
            )
        })?;
    let map = sp
        .app_roles
        .iter()
        .map(|r| (r.id.clone(), r.value.clone()))
        .collect();
    Ok((sp.id, map))
}

/// Resolves a service principal's **held** app-role assignments
/// (`appRoleAssignments`) into display DTOs, translating Microsoft Graph
/// appRole ids to permission values (e.g. `Mail.Read`). Roles on non-Graph
/// resources keep the id only (`app_role_value = None`), matching what the UI
/// can render today. Shared by the managed-identity and enterprise-app
/// "held permissions" views — both read the same assignments.
///
/// Best effort: if the Graph role index can't be built, every row falls back to
/// id-only rather than failing the surrounding view.
pub(crate) async fn resolve_app_role_grants(
    client: &GraphClient,
    assignments: Vec<AppRoleAssignment>,
) -> Vec<AppRoleGrantDto> {
    let (graph_sp_id, graph_roles) = graph_role_index(client).await.unwrap_or_default();
    map_app_role_grants(&graph_sp_id, &graph_roles, assignments)
}

/// Pure mapping of held app-role assignments to DTOs given a resolved Graph
/// role index. Split from [`resolve_app_role_grants`] so the resolution logic is
/// unit-testable without a live Graph client.
fn map_app_role_grants(
    graph_sp_id: &str,
    graph_roles: &HashMap<String, String>,
    assignments: Vec<AppRoleAssignment>,
) -> Vec<AppRoleGrantDto> {
    assignments
        .into_iter()
        .map(|a| {
            // Only Microsoft Graph's appRole ids are resolvable to values here;
            // a role on any other resource keeps its id (value stays `None`).
            let app_role_value = if a.resource_id == graph_sp_id {
                graph_roles.get(&a.app_role_id).cloned()
            } else {
                None
            };
            AppRoleGrantDto {
                assignment_id: a.id,
                resource_id: a.resource_id,
                resource_display_name: a.resource_display_name,
                app_role_id: a.app_role_id,
                app_role_value,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_app_role_grants_resolves_graph_roles_and_passes_others_through() {
        let mut roles = HashMap::new();
        roles.insert("role-mail-read".to_string(), "Mail.Read".to_string());
        let assignments = vec![
            AppRoleAssignment {
                id: "a1".into(),
                resource_id: "graph-sp".into(),
                app_role_id: "role-mail-read".into(),
                resource_display_name: Some("Microsoft Graph".into()),
                ..Default::default()
            },
            AppRoleAssignment {
                id: "a2".into(),
                resource_id: "other-sp".into(),
                app_role_id: "role-x".into(),
                resource_display_name: Some("Other API".into()),
                ..Default::default()
            },
        ];
        let out = map_app_role_grants("graph-sp", &roles, assignments);
        assert_eq!(out.len(), 2);
        // Graph role id resolved to its value…
        assert_eq!(out[0].app_role_value.as_deref(), Some("Mail.Read"));
        // …a role on a non-Graph resource keeps the id only.
        assert_eq!(out[1].app_role_value, None);
        assert_eq!(out[1].app_role_id, "role-x");
        assert_eq!(out[1].resource_display_name.as_deref(), Some("Other API"));
    }

    #[test]
    fn map_app_role_grants_with_empty_index_yields_id_only() {
        // An empty Graph index (lookup failed) must not match any resource id,
        // so every row falls back to id-only rather than mis-resolving.
        let assignments = vec![AppRoleAssignment {
            id: "a1".into(),
            resource_id: "graph-sp".into(),
            app_role_id: "role-mail-read".into(),
            ..Default::default()
        }];
        let out = map_app_role_grants("", &HashMap::new(), assignments);
        assert_eq!(out[0].app_role_value, None);
    }
}
