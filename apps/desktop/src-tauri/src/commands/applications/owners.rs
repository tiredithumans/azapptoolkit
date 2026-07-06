use std::collections::HashSet;

use tauri::State;

use azapptoolkit_core::models::DirectoryObject;

use crate::dto::UiError;
use crate::dto::applications::{OwnerChangeFailure, SetOwnersResult};
use crate::state::AppState;

use super::invalidate_app_detail_state;

#[tauri::command]
pub async fn add_application_owner(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.add_owner(&object_id, &principal_id).await?;
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

#[tauri::command]
pub async fn remove_application_owner(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.remove_owner(&object_id, &principal_id).await?;
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

/// Reconciles an application's owner set to exactly `principal_ids`, mirroring
/// `Set-AzAppOwner`. Owners present in the target but not currently assigned are
/// added first (so the app is never transiently ownerless), then owners no
/// longer in the target are removed. Per-principal failures are collected rather
/// than aborting the whole operation.
#[tauri::command]
pub async fn set_application_owners(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_ids: Vec<String>,
) -> Result<SetOwnersResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let current = client.list_owners(&object_id).await?;
    let current_ids: HashSet<String> = current.into_iter().map(|o| o.id).collect();
    let desired: HashSet<String> = principal_ids.into_iter().collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut failures = Vec::new();

    for id in desired.iter().filter(|id| !current_ids.contains(*id)) {
        match client.add_owner(&object_id, id).await {
            Ok(()) => added.push(id.clone()),
            Err(err) => failures.push(OwnerChangeFailure {
                principal_id: id.clone(),
                action: "add".into(),
                message: err.to_string(),
            }),
        }
    }
    for id in current_ids.iter().filter(|id| !desired.contains(*id)) {
        match client.remove_owner(&object_id, id).await {
            Ok(()) => removed.push(id.clone()),
            Err(err) => failures.push(OwnerChangeFailure {
                principal_id: id.clone(),
                action: "remove".into(),
                message: err.to_string(),
            }),
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        invalidate_app_detail_state(&state.cache, &tenant_id);
    }

    Ok(SetOwnersResult {
        added,
        removed,
        failures,
    })
}

#[tauri::command]
pub async fn search_users(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<Vec<DirectoryObject>, UiError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let client = state.graph_for(&tenant_id);
    client.search_users(q).await.map_err(Into::into)
}

#[tauri::command]
pub async fn search_groups(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<Vec<DirectoryObject>, UiError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let client = state.graph_for(&tenant_id);
    client.search_groups(q).await.map_err(Into::into)
}

/// Searches mail-enabled groups / distribution lists (returns those with a mail
/// address) — used to seed the SSO notification-email default from a team DL.
#[tauri::command]
pub async fn search_distribution_lists(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<Vec<DirectoryObject>, UiError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let client = state.graph_for(&tenant_id);
    client
        .search_distribution_lists(q)
        .await
        .map_err(Into::into)
}
