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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantArgs<'a> {
    tenant_id: &'a str,
}

/// Warms the tenant's search corpus so the first query doesn't pay for the two
/// directory scans that rebuild it. Fired when the search box takes focus;
/// best-effort, so callers discard the result.
pub async fn prefetch_search_corpus(tenant_id: &str) -> Result<(), UiError> {
    invoke_result("prefetch_search_corpus", TenantArgs { tenant_id }).await
}
