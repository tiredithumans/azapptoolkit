//! Auto-updater IPC DTOs — surfaced to the WASM front-end's update splash.

use serde::{Deserialize, Serialize};

/// A pending update, as returned by the updater check. `notes` is the release
/// changelog (the manifest's `notes` field, populated from `CHANGELOG.md` at
/// release time) — may be empty for older releases whose manifest predates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub current_version: String,
    pub notes: String,
    pub pub_date: Option<String>,
}

/// Download progress emitted on the `updater-progress` channel while an update
/// installs. `total` is `None` until the server reports a content length.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProgress {
    pub downloaded: u64,
    pub total: Option<u64>,
}
