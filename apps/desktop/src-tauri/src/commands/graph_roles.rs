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
use azapptoolkit_core::scoping::OFFICE365_EXCHANGE_ONLINE_APP_ID;
use azapptoolkit_graph::GraphClient;

use crate::dto::UiError;
use crate::dto::managed_identity::AppRoleGrantDto;
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
/// Re-exported from `azapptoolkit_core::scoping` (which the WASM frontend shares)
/// so the id has one definition.
pub(crate) use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;

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

// `ResourceRoles` and the two resolvers now live in `azapptoolkit-exchange`
// (crate `targets` module) — they are pure, State-free domain logic and had no
// business only being reachable through a Tauri command. Re-exported here so
// this module stays the one place the command layer asks about resource roles.
pub(crate) use azapptoolkit_exchange::targets::{ResourceRoles, resolve_grant, resolve_value};

/// The appRole indexes for **every resource that carries mailbox permissions**:
/// Microsoft Graph (mail/calendar/contacts) and the legacy Office 365 Exchange
/// Online resource (the EWS `full_access_as_app` scope).
///
/// Exchange scoping used to read Microsoft Graph alone, which made
/// `full_access_as_app` invisible to it — an AAP migration then removed the
/// legacy policy without assigning `Application EWS.AccessAsApp` or revoking the
/// org-wide grant, silently widening the app's reach to every mailbox. Every
/// target-derivation, grant-stripping and org-wide-reconciliation path resolves
/// its resources through here so none of them can regress to Graph-only.
///
/// Microsoft Graph is required (its absence is a broken tenant and a hard error,
/// as before). Office 365 Exchange Online is **best-effort**: a tenant with no
/// EWS-consenting app has no service principal for it, which is normal and must
/// not fail a scoping operation.
pub(crate) async fn mailbox_resource_roles(
    client: &GraphClient,
) -> Result<Vec<ResourceRoles>, UiError> {
    let (graph_sp_id, graph_roles) = graph_role_index(client).await?;
    let mut out = vec![ResourceRoles {
        app_id: MICROSOFT_GRAPH_APP_ID,
        sp_object_id: graph_sp_id,
        role_value_by_id: graph_roles,
    }];
    if let Ok(Some(sp)) = client
        .resolve_resource_sp(OFFICE365_EXCHANGE_ONLINE_APP_ID)
        .await
    {
        out.push(ResourceRoles {
            app_id: OFFICE365_EXCHANGE_ONLINE_APP_ID,
            sp_object_id: sp.id,
            role_value_by_id: sp
                .app_roles
                .iter()
                .map(|r| (r.id.clone(), r.value.clone()))
                .collect(),
        });
    }
    Ok(out)
}

/// Resolves a service principal's **held** app-role assignments
/// (`appRoleAssignments`) into display DTOs, translating appRole ids to
/// permission values (e.g. `Mail.Read`, `full_access_as_app`) for the resources
/// the toolkit resolves. Roles on any other resource keep the id only
/// (`app_role_value = None`), matching what the UI can render today. Shared by
/// the managed-identity and enterprise-app "held permissions" views — both read
/// the same assignments.
///
/// Office 365 Exchange Online is resolved alongside Microsoft Graph so a
/// principal holding the EWS `full_access_as_app` scope reads as that scope
/// instead of a bare GUID — the scope the audit and the Permission tester now
/// treat as org-wide mailbox reach, which the UI has to be able to name and
/// offer to confine.
///
/// Best effort: if the role indexes can't be built, every row falls back to
/// id-only rather than failing the surrounding view.
pub(crate) async fn resolve_app_role_grants(
    client: &GraphClient,
    assignments: Vec<AppRoleAssignment>,
) -> Vec<AppRoleGrantDto> {
    let resources = mailbox_resource_roles(client).await.unwrap_or_default();
    map_app_role_grants(&resources, assignments)
}

/// Pure mapping of held app-role assignments to DTOs given resolved resource
/// role indexes. Split from [`resolve_app_role_grants`] so the resolution logic
/// is unit-testable without a live Graph client.
fn map_app_role_grants(
    resources: &[ResourceRoles],
    assignments: Vec<AppRoleAssignment>,
) -> Vec<AppRoleGrantDto> {
    assignments
        .into_iter()
        .map(|a| {
            // A grant is resolved against the resource it was actually made on, so
            // an appRole id can never be read off the wrong resource's index.
            let resolved = resolve_grant(resources, &a.resource_id, &a.app_role_id);
            AppRoleGrantDto {
                assignment_id: a.id,
                resource_app_id: resolved.map(|(app_id, _, _)| app_id.to_string()),
                resource_id: a.resource_id,
                resource_display_name: a.resource_display_name,
                app_role_id: a.app_role_id,
                app_role_value: resolved.map(|(_, _, value)| value.to_string()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resources() -> Vec<ResourceRoles> {
        vec![
            ResourceRoles {
                app_id: MICROSOFT_GRAPH_APP_ID,
                sp_object_id: "graph-sp".to_string(),
                role_value_by_id: [("role-mail-read".to_string(), "Mail.Read".to_string())].into(),
            },
            ResourceRoles {
                app_id: OFFICE365_EXCHANGE_ONLINE_APP_ID,
                sp_object_id: "exo-sp".to_string(),
                role_value_by_id: [("role-ews".to_string(), "full_access_as_app".to_string())]
                    .into(),
            },
        ]
    }

    #[test]
    fn map_app_role_grants_resolves_both_resources_and_passes_others_through() {
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
                resource_id: "exo-sp".into(),
                app_role_id: "role-ews".into(),
                resource_display_name: Some("Office 365 Exchange Online".into()),
                ..Default::default()
            },
            AppRoleAssignment {
                id: "a3".into(),
                resource_id: "other-sp".into(),
                app_role_id: "role-x".into(),
                resource_display_name: Some("Other API".into()),
                ..Default::default()
            },
        ];
        let out = map_app_role_grants(&resources(), assignments);
        assert_eq!(out.len(), 3);
        // Graph role id resolved to its value, with its resource app id…
        assert_eq!(out[0].app_role_value.as_deref(), Some("Mail.Read"));
        assert_eq!(
            out[0].resource_app_id.as_deref(),
            Some(MICROSOFT_GRAPH_APP_ID)
        );
        // …the EWS scope reads as itself rather than a bare GUID, so the UI can
        // name it and offer to confine it…
        assert_eq!(out[1].app_role_value.as_deref(), Some("full_access_as_app"));
        assert_eq!(
            out[1].resource_app_id.as_deref(),
            Some(OFFICE365_EXCHANGE_ONLINE_APP_ID)
        );
        // …and a role on any other resource keeps the id only.
        assert_eq!(out[2].app_role_value, None);
        assert_eq!(out[2].resource_app_id, None);
        assert_eq!(out[2].app_role_id, "role-x");
        assert_eq!(out[2].resource_display_name.as_deref(), Some("Other API"));
    }

    #[test]
    fn map_app_role_grants_never_reads_a_role_off_the_wrong_resource() {
        // Both mailbox resources expose an appRole named `Mail.Read` under
        // different ids. A grant is resolved against the resource it was made on,
        // so Graph's id must not resolve against the Exchange Online index.
        let assignments = vec![AppRoleAssignment {
            id: "a1".into(),
            resource_id: "exo-sp".into(),
            app_role_id: "role-mail-read".into(), // Graph's id, EXO's resource
            ..Default::default()
        }];
        let out = map_app_role_grants(&resources(), assignments);
        assert_eq!(out[0].app_role_value, None);
    }

    #[test]
    fn map_app_role_grants_with_empty_index_yields_id_only() {
        // No resolved resources (lookup failed) must not match any resource id,
        // so every row falls back to id-only rather than mis-resolving.
        let assignments = vec![AppRoleAssignment {
            id: "a1".into(),
            resource_id: "graph-sp".into(),
            app_role_id: "role-mail-read".into(),
            ..Default::default()
        }];
        let out = map_app_role_grants(&[], assignments);
        assert_eq!(out[0].app_role_value, None);
    }
}
