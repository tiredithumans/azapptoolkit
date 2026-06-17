//! Graph-activity usage IPC DTOs (the granted-vs-used analysis).

use serde::{Deserialize, Serialize};

/// One observed Graph call pattern for an app over the queried window.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphUsageRow {
    pub method: String,
    /// GUID-normalized request path (resource ids replaced with `{id}`).
    pub path: String,
    pub count: u64,
    /// ISO-8601 timestamp of the most recent matching call.
    pub last_seen: Option<String>,
}

/// Result of the per-app Graph activity summary. Empty `rows` with a workspace
/// present means the app made no Graph calls in the window — itself a strong
/// least-privilege signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphUsageResult {
    pub app_id: String,
    pub days: u32,
    /// The Log Analytics workspace the data came from, for provenance.
    pub workspace_name: String,
    pub rows: Vec<GraphUsageRow>,
    /// True when the row cap was hit — long-tail call patterns beyond it are
    /// not shown (coverage honesty).
    pub truncated: bool,
}
