//! Recycle-bin surface: list / purge of deleted app registrations.
//!
//! The restore half lives in `commands::bulk` (`bulk_restore_deleted`) —
//! the sequential bulk driver owns it because restoring an app must carry its
//! paired service principals, which makes it a multi-call fan-out, not a
//! single-app core.
//!
//! Neither command caches. The recycle bin is a low-frequency recovery surface
//! and its entries expire on their own (~30 days); a cached stale bin would
//! offer Restore on objects that are already gone, and purge changes nothing
//! about the live app set that a cached list could contradict.

use tauri::State;

use azapptoolkit_graph::client::DELETED_APPS_MAX;

use crate::dto::UiError;
use crate::dto::applications::{DeletedAppDto, DeletedAppsDto};
use crate::state::AppState;

/// The tenant's deleted app registrations, newest window first (Graph's own
/// order). `truncated` passes the cap flag straight through — a partial bin
/// must never render as the whole bin.
#[tauri::command]
pub async fn list_recently_deleted(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<DeletedAppsDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let (apps, truncated) = client
        .list_deleted_applications(DELETED_APPS_MAX)
        .await
        .map_err(UiError::from)?;
    Ok(DeletedAppsDto {
        apps: apps
            .into_iter()
            .map(|a| DeletedAppDto {
                object_id: a.id,
                app_id: a.app_id,
                display_name: a.display_name,
                deleted_date_time: a.deleted_date_time,
            })
            .collect(),
        truncated,
    })
}

/// Permanently deletes one recycle-bin entry, skipping the ~30-day window.
/// This is the option the reworded bulk-delete copy points at; two-step
/// confirmation lives in the dialog, which is why this takes no `dry_run`.
#[tauri::command]
pub async fn purge_deleted_application(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.purge_deleted_application(&object_id).await?;
    Ok(())
}
