use tauri::State;

use crate::commands::applications::invalidate_app_detail_state;
use crate::dto::UiError;
use crate::dto::permissions::RevokeScopeOutcome;
use crate::state::AppState;

/// Deletes a single `appRoleAssignment` on a service principal. Used to
/// revoke an Application permission previously granted by admin consent or
/// by `grant_managed_identity_permission`. Leaves `requiredResourceAccess`
/// (the declaration) untouched.
#[tauri::command]
pub async fn revoke_app_role_assignment(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    assignment_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client
        .remove_app_role_assignment(&service_principal_id, &assignment_id)
        .await?;
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

/// Removes a single scope from an `oauth2PermissionGrant`. If the resulting
/// scope string is empty, the grant itself is deleted. Whitespace handling
/// is via `split_whitespace` + `join(" ")` so grants saved with tabs,
/// double spaces, or trailing whitespace still roundtrip correctly.
#[tauri::command]
pub async fn revoke_oauth2_scope(
    state: State<'_, AppState>,
    tenant_id: String,
    grant_id: String,
    scope_value: String,
) -> Result<RevokeScopeOutcome, UiError> {
    let client = state.graph_for(&tenant_id);
    let grant = client.get_oauth2_grant(&grant_id).await?;
    let target = scope_value.trim();
    let remaining: Vec<&str> = grant
        .scope
        .split_whitespace()
        .filter(|s| *s != target)
        .collect();
    let outcome = if remaining.is_empty() {
        client.delete_oauth2_grant(&grant_id).await?;
        RevokeScopeOutcome::Deleted
    } else {
        let joined = remaining.join(" ");
        client.update_oauth2_grant_scope(&grant_id, &joined).await?;
        RevokeScopeOutcome::Updated { remaining: joined }
    };
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(outcome)
}
