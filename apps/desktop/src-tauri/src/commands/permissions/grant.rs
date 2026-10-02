use tauri::State;

use crate::dto::UiError;
use crate::dto::permissions::{
    GrantFailure, GrantResult, PermissionKind, ScopeGrantSummary, SkippedRole,
};
use crate::state::AppState;

use super::manifest::declare_resource_access;
use super::{GrantRun, empty_grant, entry_type_for, grant_failure_message, invalidate_after_grant};

/// Grants a single permission to `object_id`. Adds the entry to the app's
/// `requiredResourceAccess` manifest if missing, then creates the matching
/// runtime grant (`appRoleAssignment` for Application, upserted
/// `oauth2PermissionGrant` for Delegated). Idempotent for both halves —
/// safe to retry.
#[tauri::command]
pub async fn grant_single_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    resource_app_id: String,
    permission_id: String,
    kind: PermissionKind,
) -> Result<GrantResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let run =
        grant_single_permission_core(&client, &object_id, &resource_app_id, &permission_id, kind)
            .await?;
    // A first grant that materializes the app's SP adds an Enterprise App row /
    // search-index entry, so the full list tier; otherwise detail+audit — and
    // both even when a later step failed, since the PATCH/SP had landed.
    invalidate_after_grant(&state.cache, &tenant_id, &run);
    match run.error {
        Some(e) => Err(e),
        None => Ok(run.result),
    }
}

/// Shared core of [`grant_single_permission`]: manifest patch + runtime grant,
/// with no `State` and no cache side effects. Returns a [`GrantRun`]: the
/// result, whether the manifest PATCH landed and whether the grant materialized
/// the app's service principal (which decide how far the caller must
/// invalidate). A failure after either write comes back as `error: Some(..)`
/// beside those flags, not as an `Err` that would lose them.
///
/// Extracted for the reason `grant_admin_consent_core` and
/// `grant_managed_identity_roles_core` already were: behind a `#[tauri::command]`
/// taking `State`, the idempotence rules below (an already-assigned app role is a
/// skip, a scope id the resource does not expose is a structured failure rather
/// than an error) were only reachable from a signed-in app.
pub(crate) async fn grant_single_permission_core(
    client: &azapptoolkit_graph::GraphClient,
    object_id: &str,
    resource_app_id: &str,
    permission_id: &str,
    kind: PermissionKind,
) -> Result<GrantRun, UiError> {
    let entry_type = entry_type_for(kind)?;
    let mut app = client.get_application(object_id).await?;

    // 1) Patch requiredResourceAccess if the (resource, permission, kind)
    //    triple isn't already declared. Empty resource entry with the right
    //    appId is created when needed. The PATCH is the first write: its own
    //    failure landed nothing, so it stays a plain `Err`.
    let manifest_changed = declare_resource_access(
        &mut app.required_resource_access,
        resource_app_id,
        permission_id,
        entry_type,
    );
    if manifest_changed {
        let patch = azapptoolkit_graph::client::AppPatch {
            required_resource_access: Some(app.required_resource_access.clone()),
            ..Default::default()
        };
        client.update_application(object_id, &patch).await?;
    }

    // 2) Create the runtime grant. Errors stay structured so the UI can
    //    show a per-row failure without losing the manifest patch.
    let (client_sp, sp_created) = match client.ensure_service_principal(&app.app_id).await {
        Ok(ensured) => ensured,
        Err(e) if manifest_changed => {
            return Ok(GrantRun {
                result: empty_grant(String::new()),
                manifest_changed,
                sp_created: false,
                error: Some(e.into()),
            });
        }
        Err(e) => return Err(e.into()),
    };
    match single_runtime_grant(client, &client_sp.id, resource_app_id, permission_id, kind).await {
        Ok(result) => Ok(GrantRun {
            result,
            manifest_changed,
            sp_created,
            error: None,
        }),
        Err(e) if manifest_changed || sp_created => Ok(GrantRun {
            result: empty_grant(client_sp.id),
            manifest_changed,
            sp_created,
            error: Some(e),
        }),
        Err(e) => Err(e),
    }
}

/// [`grant_single_permission_core`] past the client SP: resolve the resource
/// SP and create (or skip) the one runtime grant.
async fn single_runtime_grant(
    client: &azapptoolkit_graph::GraphClient,
    client_sp_id: &str,
    resource_app_id: &str,
    permission_id: &str,
    kind: PermissionKind,
) -> Result<GrantResult, UiError> {
    let resource_app_id = resource_app_id.to_string();
    let permission_id = permission_id.to_string();
    let resource_sp = client
        .resolve_resource_sp(&resource_app_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "resource",
                format!("resource service principal {resource_app_id} not found"),
            )
        })?;

    let mut role_assignments_created = Vec::new();
    let mut role_assignments_skipped = Vec::new();
    let mut scope_grants_upserted = Vec::new();
    let mut failures = Vec::new();

    match kind {
        PermissionKind::Application => {
            let existing = client.list_app_role_assignments(client_sp_id).await?;
            let already = existing
                .iter()
                .any(|a| a.resource_id == resource_sp.id && a.app_role_id == permission_id);
            if already {
                role_assignments_skipped.push(SkippedRole {
                    resource_app_id: resource_app_id.clone(),
                    app_role_id: permission_id.clone(),
                    reason: "already assigned".into(),
                });
            } else {
                match client
                    .grant_app_role(client_sp_id, &resource_sp.id, &permission_id)
                    .await
                {
                    Ok(ara) => role_assignments_created.push(ara),
                    Err(err) => failures.push(GrantFailure {
                        resource_app_id: resource_app_id.clone(),
                        permission_id: Some(permission_id.clone()),
                        kind: "Role".into(),
                        message: grant_failure_message(&err),
                    }),
                }
            }
        }
        PermissionKind::Delegated => {
            // Resolve the scope value from the resource SP — Graph's
            // oauth2PermissionGrant.scope is space-separated VALUES, not ids.
            let scope_value = resource_sp
                .oauth2_permission_scopes
                .iter()
                .find(|s| s.id == permission_id)
                .map(|s| s.value.as_str());
            match scope_value {
                Some(value) => {
                    match client
                        .upsert_admin_oauth2_grant(client_sp_id, &resource_sp.id, &[value])
                        .await
                    {
                        Ok(grant) => scope_grants_upserted.push(ScopeGrantSummary {
                            resource_app_id: resource_app_id.clone(),
                            grant,
                            scopes_added: vec![value.to_string()],
                        }),
                        Err(err) => failures.push(GrantFailure {
                            resource_app_id: resource_app_id.clone(),
                            permission_id: Some(permission_id.clone()),
                            kind: "Scope".into(),
                            message: grant_failure_message(&err),
                        }),
                    }
                }
                None => failures.push(GrantFailure {
                    resource_app_id: resource_app_id.clone(),
                    permission_id: Some(permission_id.clone()),
                    kind: "Scope".into(),
                    message: "scope id not exposed by resource SP".into(),
                }),
            }
        }
        PermissionKind::Unknown => unreachable!("guarded by `entry_type_for` in the caller"),
    }

    Ok(GrantResult {
        client_service_principal_id: client_sp_id.to_string(),
        role_assignments_created,
        role_assignments_skipped,
        scope_grants_upserted,
        failures,
    })
}
