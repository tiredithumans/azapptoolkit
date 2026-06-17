//! Global-search IPC DTOs.
//!
//! The frontend's top-bar search invokes `global_search` with a free-form
//! query; the backend routes it to display-name `startswith` lookups or
//! GUID exact lookups across all three identity kinds, then returns
//! grouped, lightweight rows for the dropdown.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub app_id: Option<String>,
    pub display_name: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalSearchResults {
    pub query: String,
    pub looked_up_as_guid: bool,
    pub app_registrations: Vec<SearchHit>,
    pub enterprise_apps: Vec<SearchHit>,
    pub managed_identities: Vec<SearchHit>,
}
