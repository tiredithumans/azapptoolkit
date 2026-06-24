//! Auto-updater IPC bindings. Download progress streams live in
//! `bindings::events::updater_progress`.

use azapptoolkit_dto::UiError;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::updater::{UpdateInfo, UpdateProgress};

/// Checks for a newer signed release. `Ok(None)` = up to date (or unavailable
/// in a dev build); the launch check treats any error as "no update" silently.
pub async fn check_for_update() -> Result<Option<UpdateInfo>, UiError> {
    invoke_result("check_for_update", ()).await
}

/// Downloads + installs the pending update and relaunches. Never returns on
/// success — the webview is torn down by the relaunch.
pub async fn perform_update() -> Result<(), UiError> {
    invoke_result("perform_update", ()).await
}
