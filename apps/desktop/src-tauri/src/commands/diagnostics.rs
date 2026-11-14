use std::path::{Path, PathBuf};
use std::time::Duration;

use tauri::State;

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::settings::SETTINGS_FILE;

use crate::dto::UiError;
use crate::dto::diagnostics::{
    CacheKindDto, CacheStatsDto, ListCacheKindDto, SetCacheConfigInput, SupportPaths,
};
use crate::state::AppState;

/// Where this install writes its logs and its `settings.json`, so the UI can
/// show both with a Copy button: Settings → Tenant connection, and under a
/// failing sign-in, config save or update — the moments an operator is told
/// to "check the log" without knowing the per-OS folder (README "Logs").
/// Absolute even when no home folder was found and the config directory fell
/// back to the working directory; `io` when that cannot be resolved.
#[tauri::command]
pub fn get_support_paths() -> Result<SupportPaths, UiError> {
    support_paths_in(&crate::log_directory(), &crate::config_directory())
}

/// [`get_support_paths`] over explicit folders, so the shape is testable
/// without the process environment.
fn support_paths_in(log_dir: &Path, config_dir: &Path) -> Result<SupportPaths, UiError> {
    let absolute = |p: PathBuf| {
        std::path::absolute(&p)
            .map(|p| p.display().to_string())
            .map_err(|e| UiError::io(format!("Could not resolve {}: {e}", p.display())))
    };
    Ok(SupportPaths {
        log_dir: absolute(log_dir.to_path_buf())?,
        settings_file: absolute(config_dir.join(SETTINGS_FILE))?,
    })
}

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
    invalidate_list_cache_in(&state.cache, &tenant_id, kind);
}

/// The body of [`invalidate_list_cache`], on a bare [`Cache`] so the per-kind
/// key sets are unit-testable.
///
/// Every list derived from the shared SP index must drop that index too:
/// dropping only the derived list re-derives it from the same stale index, so
/// Refresh would be a no-op for a principal created since the index was built.
pub(crate) fn invalidate_list_cache_in(cache: &Cache, tenant_id: &str, kind: ListCacheKindDto) {
    match kind {
        // The App Registrations and Enterprise Apps lists both join against the
        // shared SP index, so a manual refresh of either must also drop it to
        // re-pull service principals.
        ListCacheKindDto::Apps => {
            cache.invalidate_prefix(CacheKind::Lists, &format!("{tenant_id}|apps_pairing"));
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::sp_index_key(tenant_id),
            );
            // The global-search corpus is derived from the SP index + the
            // app-name index; an app create/rename only reaches search once both
            // fall, so a manual Apps refresh must drop them too (matching what
            // the mutation paths do via `invalidate_app_lists`).
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::app_name_index_key(tenant_id),
            );
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::search_corpus_key(tenant_id),
            );
        }
        ListCacheKindDto::Enterprise => {
            cache.invalidate_prefix(CacheKind::Lists, &format!("{tenant_id}|enterprise"));
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::sp_index_key(tenant_id),
            );
            // Dropping the shared SP index leaves the search corpus (built from
            // it) stale; bust it so the next global search rebuilds.
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::search_corpus_key(tenant_id),
            );
        }
        ListCacheKindDto::ManagedIdentities => {
            // The exact key: a prefix would also catch any future `|mi…` key.
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::managed_identity::mi_key(tenant_id),
            );
            // The MI list is a filtered projection of the shared SP index
            // (`list_managed_identities` reads `sp_index_cached`), so dropping
            // only `{tenant}|mi` re-derives it from the same stale index and a
            // just-created managed identity stays missing. Drop the index, and
            // the search corpus built from it — mirroring the Enterprise arm.
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::sp_index_key(tenant_id),
            );
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::search_corpus_key(tenant_id),
            );
        }
        // The roll-up alone: a miss on it runs the shared app scan, which
        // re-reads every app registration from Graph and re-seeds the roll-up
        // (and the App Registrations rows) from that fresh read.
        ListCacheKindDto::Credentials => {
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::applications::credential_expirations_key(tenant_id),
            );
        }
        // The board is its own scan of the tenant's SAML service principals.
        ListCacheKindDto::SsoCertificates => {
            cache.invalidate(
                CacheKind::Lists,
                &crate::commands::sso::sso_certificate_expirations_key(tenant_id),
            );
        }
        // The whole-tenant prefix already covers the shared SP index.
        ListCacheKindDto::All => {
            cache.invalidate_prefix(CacheKind::Lists, &format!("{tenant_id}|"));
        }
    }
}

/// How old the cached data behind a list page is, in whole seconds — what its
/// "Updated … ago" stamp shows. `None` when nothing is cached for it (the page
/// then stamps the moment its own read returned).
///
/// The lists are served from a cache with a long TTL and patched in place, so
/// "when did the frontend last ask" says nothing about how old the rows are;
/// only the cache knows when the scan behind them ran.
///
/// Cache-only, so it proves the session itself.
#[tauri::command]
pub fn list_cache_age(
    state: State<'_, AppState>,
    tenant_id: String,
    kind: ListCacheKindDto,
) -> Result<Option<u64>, UiError> {
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    Ok(list_cache_age_in(&state.cache, &tenant_id, kind))
}

/// The body of [`list_cache_age`], on a bare [`Cache`] so the per-kind keys are
/// unit-testable. Each kind dates the entry its page renders — not everything
/// [`invalidate_list_cache_in`] drops for it (the shared SP index is older or
/// newer than a list derived from it, and is not what the page shows).
pub(crate) fn list_cache_age_in(
    cache: &Cache,
    tenant_id: &str,
    kind: ListCacheKindDto,
) -> Option<u64> {
    let prefix = match kind {
        ListCacheKindDto::Apps => crate::commands::applications::apps_pairing_key(tenant_id),
        ListCacheKindDto::Enterprise => crate::commands::applications::enterprise_key(tenant_id),
        ListCacheKindDto::ManagedIdentities => crate::commands::managed_identity::mi_key(tenant_id),
        ListCacheKindDto::Credentials => {
            crate::commands::applications::credential_expirations_key(tenant_id)
        }
        ListCacheKindDto::SsoCertificates => {
            crate::commands::sso::sso_certificate_expirations_key(tenant_id)
        }
        ListCacheKindDto::All => format!("{tenant_id}|"),
    };
    cache
        .oldest_age_for_prefix(CacheKind::Lists, &prefix)
        .map(|age| age.as_secs())
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

#[cfg(test)]
mod tests {
    use super::{invalidate_list_cache_in, list_cache_age_in, support_paths_in};
    use crate::commands::applications::{
        apps_pairing_key, credential_expirations_key, enterprise_key, search_corpus_key,
        sp_index_hit, sp_index_store,
    };
    use crate::commands::managed_identity::mi_key;
    use crate::commands::sso::sso_certificate_expirations_key;
    use crate::dto::diagnostics::ListCacheKindDto;
    use azapptoolkit_core::cache::{Cache, CacheKind};

    /// Every list rebuilt from the shared SP index must drop the index on
    /// Refresh, and the search corpus built from it; otherwise the list is
    /// re-derived from the same stale index. The Managed Identities arm had
    /// dropped only its own list. Scoped to the tenant being refreshed.
    #[test]
    fn every_refresh_of_an_sp_index_derived_list_drops_the_index() {
        for kind in [
            ListCacheKindDto::Apps,
            ListCacheKindDto::Enterprise,
            ListCacheKindDto::ManagedIdentities,
            ListCacheKindDto::All,
        ] {
            let label = format!("{kind:?}");
            let cache = Cache::new();
            sp_index_store(&cache, "t1", Vec::new());
            sp_index_store(&cache, "t2", Vec::new());
            cache.put(CacheKind::Lists, search_corpus_key("t1"), &1u32);

            invalidate_list_cache_in(&cache, "t1", kind);

            assert!(
                sp_index_hit(&cache, "t1").is_none(),
                "{label}: SP index kept"
            );
            assert!(
                cache
                    .get::<u32>(CacheKind::Lists, &search_corpus_key("t1"))
                    .is_none(),
                "{label}: search corpus kept"
            );
            assert!(
                sp_index_hit(&cache, "t2").is_some(),
                "{label}: another tenant's SP index was dropped"
            );
        }
    }

    /// The settings path names the file itself, and a relative fallback (no
    /// home folder found) is still shown as a path the operator can open.
    #[test]
    fn support_paths_are_absolute_and_name_the_settings_file() {
        let paths =
            support_paths_in(std::path::Path::new("logs"), std::path::Path::new(".")).unwrap();
        let log_dir = std::path::Path::new(&paths.log_dir);
        let settings = std::path::Path::new(&paths.settings_file);
        assert!(log_dir.is_absolute(), "{}", paths.log_dir);
        assert!(settings.is_absolute(), "{}", paths.settings_file);
        assert!(log_dir.ends_with("logs"));
        assert_eq!(
            settings.file_name().and_then(|f| f.to_str()),
            Some(azapptoolkit_core::settings::SETTINGS_FILE)
        );
    }

    /// The two Security lenses' Refresh drops exactly the entry the lens reads
    /// — it used to drop nothing, so "Refresh" re-served the cached board —
    /// and leaves the tenant-wide indexes and the other tenant alone.
    #[test]
    fn a_lens_refresh_drops_its_own_board_and_nothing_else() {
        for (kind, key) in [
            (
                ListCacheKindDto::Credentials,
                credential_expirations_key("t1"),
            ),
            (
                ListCacheKindDto::SsoCertificates,
                sso_certificate_expirations_key("t1"),
            ),
        ] {
            let label = format!("{kind:?}");
            let cache = Cache::new();
            cache.put(CacheKind::Lists, key.clone(), &1u32);
            cache.put(CacheKind::Lists, key.replace("t1|", "t2|"), &2u32);
            sp_index_store(&cache, "t1", Vec::new());

            invalidate_list_cache_in(&cache, "t1", kind);

            assert!(
                cache
                    .oldest_age_for_prefix(CacheKind::Lists, &key)
                    .is_none(),
                "{label}: the board survived its own Refresh"
            );
            assert!(
                cache
                    .oldest_age_for_prefix(CacheKind::Lists, &key.replace("t1|", "t2|"))
                    .is_some(),
                "{label}: another tenant's board was dropped"
            );
            assert!(
                sp_index_hit(&cache, "t1").is_some(),
                "{label}: the SP index is not this lens's to drop"
            );
        }
    }

    /// Each kind dates the entry its own page renders, per tenant; a page with
    /// nothing cached has no age.
    #[test]
    fn a_list_age_is_read_from_the_entry_its_page_shows() {
        let cache = Cache::new();
        for (kind, key) in [
            (ListCacheKindDto::Apps, apps_pairing_key("t1")),
            (ListCacheKindDto::Enterprise, enterprise_key("t1")),
            (ListCacheKindDto::ManagedIdentities, mi_key("t1")),
            (
                ListCacheKindDto::Credentials,
                credential_expirations_key("t1"),
            ),
            (
                ListCacheKindDto::SsoCertificates,
                sso_certificate_expirations_key("t1"),
            ),
        ] {
            let label = format!("{kind:?}");
            assert_eq!(
                list_cache_age_in(&cache, "t1", kind),
                None,
                "{label}: nothing cached yet"
            );
            cache.put(CacheKind::Lists, key, &1u32);
            assert!(
                list_cache_age_in(&cache, "t1", kind).is_some(),
                "{label}: its own entry is not what it dates"
            );
            assert_eq!(
                list_cache_age_in(&cache, "t2", kind),
                None,
                "{label}: another tenant read this tenant's age"
            );
        }
        assert!(list_cache_age_in(&cache, "t1", ListCacheKindDto::All).is_some());
    }

    #[test]
    fn managed_identity_refresh_drops_its_own_list() {
        let cache = Cache::new();
        cache.put(CacheKind::Lists, mi_key("t1"), &1u32);
        invalidate_list_cache_in(&cache, "t1", ListCacheKindDto::ManagedIdentities);
        assert!(cache.get::<u32>(CacheKind::Lists, &mi_key("t1")).is_none());
    }
}
