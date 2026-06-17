//! Cache diagnostics IPC bindings. DTOs come from the shared `azapptoolkit-dto`.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::{invoke, invoke_result};

pub use azapptoolkit_dto::diagnostics::{
    CacheKindDto, CacheStatsDto, ListCacheKindDto, SetCacheConfigInput,
};

pub async fn cache_stats() -> CacheStatsDto {
    invoke("cache_stats", ()).await
}

#[derive(Serialize)]
struct ClearCacheArgs {
    kind: CacheKindDto,
}

pub async fn clear_cache(kind: CacheKindDto) {
    invoke::<()>("clear_cache", ClearCacheArgs { kind }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvalidateListArgs {
    tenant_id: String,
    kind: ListCacheKindDto,
}

/// Drops the cached list entries for `tenant_id` matching `kind`. Used by
/// per-page Refresh buttons; does not touch unrelated kinds.
pub async fn invalidate_list_cache(tenant_id: String, kind: ListCacheKindDto) {
    invoke::<()>(
        "invalidate_list_cache",
        InvalidateListArgs { tenant_id, kind },
    )
    .await
}

#[derive(Serialize)]
struct EnabledArgs {
    enabled: bool,
}

pub async fn set_cache_enabled(enabled: bool) {
    invoke::<()>("set_cache_enabled", EnabledArgs { enabled }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetCacheConfigArgs {
    input: SetCacheConfigInput,
}

pub async fn set_cache_config(input: SetCacheConfigInput) -> Result<(), UiError> {
    invoke_result("set_cache_config", SetCacheConfigArgs { input }).await
}
