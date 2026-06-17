//! Bulk-operation IPC DTOs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkProgress {
    pub done: usize,
    pub total: usize,
    pub current_app: Option<String>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRemovalSummary {
    pub object_id: String,
    pub display_name: String,
    pub removed_key_ids: Vec<String>,
    pub failed_key_ids: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRemoveExpiredResult {
    pub apps_scanned: usize,
    pub summaries: Vec<AppRemovalSummary>,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDeleteFailure {
    pub object_id: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDeleteResult {
    pub deleted: Vec<String>,
    pub failed: Vec<BulkDeleteFailure>,
    pub cancelled: bool,
}

// ---------------- Bulk grant admin consent ----------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkGrantOutcome {
    pub object_id: String,
    pub granted: usize,
    pub skipped: usize,
    pub failed: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkGrantResult {
    pub outcomes: Vec<BulkGrantOutcome>,
    pub cancelled: bool,
}

// ---------------- Bulk create applications ----------------

/// One app to create in a bulk run. Parsed from the user's JSON import.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkCreateSpec {
    pub display_name: String,
    pub sign_in_audience: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkCreateOutcome {
    pub display_name: String,
    /// `valid` / `invalid` for a validation-only run; `created` / `failed` for
    /// a real run.
    pub status: String,
    pub app_id: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkCreateResult {
    pub validate_only: bool,
    pub outcomes: Vec<BulkCreateOutcome>,
    pub cancelled: bool,
}
