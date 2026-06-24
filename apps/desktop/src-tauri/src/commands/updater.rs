//! In-app auto-update commands.
//!
//! Replaces the former silent background auto-install: the front-end checks on
//! launch ([`check_for_update`]) and, if an update is waiting, shows a changelog
//! splash whose "Update & restart" calls [`perform_update`] — which downloads,
//! installs, and relaunches into the new version. The changelog text rides the
//! updater manifest's `notes` field (populated from `CHANGELOG.md` at release
//! time); download progress streams on the `updater-progress` channel.

use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::UpdaterExt;

use crate::dto::UiError;
use crate::dto::updater::{UpdateInfo, UpdateProgress};

/// Updater errors are transient by nature (network / GitHub availability), so
/// mark them retryable; the front-end swallows a launch-check failure silently
/// and surfaces a manual-check failure as a dismissable toast.
fn updater_err(e: impl std::fmt::Display) -> UiError {
    UiError::new("updater", e.to_string(), true)
}

/// Checks the configured endpoint for a newer signed release. Returns `None`
/// when up to date (or when the updater isn't available, e.g. a dev build).
#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<Option<UpdateInfo>, UiError> {
    let updater = app.updater().map_err(updater_err)?;
    match updater.check().await.map_err(updater_err)? {
        Some(update) => Ok(Some(UpdateInfo {
            version: update.version.clone(),
            current_version: update.current_version.clone(),
            notes: update.body.clone().unwrap_or_default(),
            pub_date: update.date.map(|d| d.to_string()),
        })),
        None => Ok(None),
    }
}

/// Downloads + installs the pending update (re-checked here so a stale handle
/// can't drive it), streaming byte progress on `updater-progress`, then
/// relaunches into the new version. Never returns on success (`app.restart()`
/// diverges); the awaiting webview is torn down by the relaunch.
#[tauri::command]
pub async fn perform_update(app: AppHandle) -> Result<(), UiError> {
    let updater = app.updater().map_err(updater_err)?;
    let Some(update) = updater.check().await.map_err(updater_err)? else {
        // Nothing to install (already current) — treat as a no-op success.
        return Ok(());
    };

    let app_progress = app.clone();
    let mut downloaded: u64 = 0;
    update
        .download_and_install(
            move |chunk_len, content_len| {
                downloaded += chunk_len as u64;
                let _ = app_progress.emit(
                    "updater-progress",
                    UpdateProgress {
                        downloaded,
                        total: content_len,
                    },
                );
            },
            || {},
        )
        .await
        .map_err(updater_err)?;

    // On Windows (NSIS, passive) the installer has run; relaunch applies it.
    app.restart()
}
