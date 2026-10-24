//! Cache-diagnostics and support-path IPC DTOs.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheStatsDto {
    pub service_principal_hits: u64,
    pub service_principal_misses: u64,
    pub permissions_hits: u64,
    pub permissions_misses: u64,
    pub audit_hits: u64,
    pub audit_misses: u64,
    pub lists_hits: u64,
    pub lists_misses: u64,
    pub enabled: bool,
    // Current effective configuration (mirrors `Get-azapptoolkitCache -Configuration`).
    pub service_principal_ttl_secs: u64,
    pub permissions_ttl_secs: u64,
    pub audit_ttl_secs: u64,
    pub lists_ttl_secs: u64,
    pub max_cache_size: u64,
}

/// Partial cache-configuration update. Any `None` field is left unchanged,
/// mirroring `Set-azapptoolkitCacheConfiguration`'s bound-parameter behavior.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetCacheConfigInput {
    pub enabled: Option<bool>,
    pub service_principal_ttl_secs: Option<u64>,
    pub permissions_ttl_secs: Option<u64>,
    pub audit_ttl_secs: Option<u64>,
    pub lists_ttl_secs: Option<u64>,
    pub max_cache_size: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheKindDto {
    ServicePrincipal,
    Permissions,
    Audit,
    Lists,
    All,
}

/// Where this install keeps the two files support asks for, from
/// `get_support_paths`: shown with a Copy button in Settings → Tenant
/// connection and wherever sign-in, the config save or an update fails, so an
/// operator can find the log or the settings file without knowing the
/// per-OS layout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportPaths {
    /// The folder holding the daily `azapptoolkit.YYYY-MM-DD.log` files.
    pub log_dir: String,
    /// The `settings.json` file (it may not exist yet on a fresh install).
    pub settings_file: String,
}

/// Which list shape to invalidate. Sent by the per-page Refresh button.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListCacheKindDto {
    Apps,
    Enterprise,
    ManagedIdentities,
    All,
}
