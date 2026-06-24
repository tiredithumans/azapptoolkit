use std::time::Duration;

use tauri::State;

use azapptoolkit_core::cache::CacheKind;

use crate::dto::UiError;
use crate::dto::diagnostics::{CacheKindDto, CacheStatsDto, ListCacheKindDto, SetCacheConfigInput};
use crate::state::AppState;

#[tauri::command]
pub fn cache_stats(state: State<'_, AppState>) -> CacheStatsDto {
    let stats = state.cache.stats();
    let config = state.cache.config();
    CacheStatsDto {
        service_principal_hits: stats.service_principal_hits,
        service_principal_misses: stats.service_principal_misses,
        permissions_hits: stats.permissions_hits,
        permissions_misses: stats.permissions_misses,
        audit_hits: stats.audit_hits,
        audit_misses: stats.audit_misses,
        lists_hits: stats.lists_hits,
        lists_misses: stats.lists_misses,
        enabled: config.enabled,
        service_principal_ttl_secs: config.service_principal_ttl.as_secs(),
        permissions_ttl_secs: config.permissions_ttl.as_secs(),
        audit_ttl_secs: config.audit_ttl.as_secs(),
        lists_ttl_secs: config.lists_ttl.as_secs(),
        max_cache_size: config.max_size as u64,
    }
}

#[tauri::command]
pub fn clear_cache(state: State<'_, AppState>, kind: CacheKindDto) {
    let core_kind = match kind {
        CacheKindDto::ServicePrincipal => Some(CacheKind::ServicePrincipal),
        CacheKindDto::Permissions => Some(CacheKind::Permissions),
        CacheKindDto::Audit => Some(CacheKind::Audit),
        CacheKindDto::Lists => Some(CacheKind::Lists),
        CacheKindDto::All => None,
    };
    match core_kind {
        Some(k) => state.cache.clear_kind(k),
        None => state.cache.clear(),
    }
}

/// Drops cached list entries for the active tenant. Used by per-page Refresh
/// buttons so the user can force-bypass the cache without touching unrelated
/// entries.
#[tauri::command]
pub fn invalidate_list_cache(
    state: State<'_, AppState>,
    tenant_id: String,
    kind: ListCacheKindDto,
) {
    match kind {
        // The App Registrations and Enterprise Apps lists both join against the
        // shared SP index, so a manual refresh of either must also drop it to
        // re-pull service principals.
        ListCacheKindDto::Apps => {
            state
                .cache
                .invalidate_prefix(CacheKind::Lists, &format!("{tenant_id}|apps_pairing"));
            state.cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::sp_index_key(&tenant_id),
            );
            // The global-search corpus is derived from the SP index + the
            // app-name index; an app create/rename only reaches search once both
            // fall, so a manual Apps refresh must drop them too (matching what
            // the mutation paths do via `invalidate_app_lists`).
            state.cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::app_name_index_key(&tenant_id),
            );
            state.cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::search_corpus_key(&tenant_id),
            );
        }
        ListCacheKindDto::Enterprise => {
            state
                .cache
                .invalidate_prefix(CacheKind::Lists, &format!("{tenant_id}|enterprise"));
            state.cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::sp_index_key(&tenant_id),
            );
            // Dropping the shared SP index leaves the search corpus (built from
            // it) stale; bust it so the next global search rebuilds.
            state.cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::search_corpus_key(&tenant_id),
            );
        }
        ListCacheKindDto::ManagedIdentities => {
            state
                .cache
                .invalidate_prefix(CacheKind::Lists, &format!("{tenant_id}|mi"));
        }
        // The whole-tenant prefix already covers the shared SP index.
        ListCacheKindDto::All => {
            state
                .cache
                .invalidate_prefix(CacheKind::Lists, &format!("{tenant_id}|"));
        }
    }
}

#[tauri::command]
pub fn set_cache_enabled(state: State<'_, AppState>, enabled: bool) {
    state.cache.set_enabled(enabled);
}

/// Ports `Set-azapptoolkitCacheConfiguration`: toggle caching and adjust the
/// service-principal / permissions TTLs and the per-kind entry cap at runtime.
/// TTLs are bounded to 1 minute..24 hours and the cap to 10..10000, matching
/// the PowerShell validation.
#[tauri::command]
pub fn set_cache_config(
    state: State<'_, AppState>,
    input: SetCacheConfigInput,
) -> Result<(), UiError> {
    let validate_ttl = |secs: u64, field: &str| -> Result<Duration, UiError> {
        if !(60..=86_400).contains(&secs) {
            return Err(UiError::validation(
                "invalid_cache_config",
                format!("{field} must be between 1 minute and 24 hours"),
            ));
        }
        Ok(Duration::from_secs(secs))
    };

    let sp_ttl = input
        .service_principal_ttl_secs
        .map(|s| validate_ttl(s, "servicePrincipalTtlSecs"))
        .transpose()?;
    let perm_ttl = input
        .permissions_ttl_secs
        .map(|s| validate_ttl(s, "permissionsTtlSecs"))
        .transpose()?;
    let audit_ttl = input
        .audit_ttl_secs
        .map(|s| validate_ttl(s, "auditTtlSecs"))
        .transpose()?;
    let lists_ttl = input
        .lists_ttl_secs
        .map(|s| validate_ttl(s, "listsTtlSecs"))
        .transpose()?;

    let max_size = match input.max_cache_size {
        Some(m) if !(10..=10_000).contains(&m) => {
            return Err(UiError::validation(
                "invalid_cache_config",
                "maxCacheSize must be between 10 and 10000",
            ));
        }
        Some(m) => Some(m as usize),
        None => None,
    };

    state.cache.configure(
        input.enabled,
        sp_ttl,
        perm_ttl,
        audit_ttl,
        lists_ttl,
        max_size,
    );
    Ok(())
}
