//! Global-search IPC binding for the top-bar search.

use super::ipc::invoke_result;
use azapptoolkit_dto::UiError;
use serde::Serialize;

use crate::bindings::TenantArg;

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

/// Warms the tenant's search corpus so the first query doesn't pay for the two
/// directory scans that rebuild it. Fired when the search box takes focus;
/// best-effort, so callers discard the result.
pub async fn prefetch_search_corpus(tenant_id: &str) -> Result<(), UiError> {
    invoke_result("prefetch_search_corpus", TenantArg { tenant_id }).await
}
