//! Global-search IPC binding for the top-bar search.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::search::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchArgs<'a> {
    tenant_id: &'a str,
    query: &'a str,
}

pub async fn global_search(tenant_id: &str, query: &str) -> Result<GlobalSearchResults, UiError> {
    invoke_result("global_search", SearchArgs { tenant_id, query }).await
}
