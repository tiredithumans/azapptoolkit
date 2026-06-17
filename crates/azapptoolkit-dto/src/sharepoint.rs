//! SharePoint Sites.Selected IPC DTOs.

use serde::{Deserialize, Serialize};

/// A site permission projected for the UI: the granted roles plus the
/// application principal (when the entry is an app grant).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitePermissionDto {
    pub id: String,
    pub roles: Vec<String>,
    pub app_id: Option<String>,
    pub app_display_name: Option<String>,
}

/// Outcome of `grant_site_access`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantSiteAccessResult {
    pub site_id: String,
    pub site_display_name: Option<String>,
    pub permission: SitePermissionDto,
}

/// One site granted during a `convert_site_access_to_selected` run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteGrantDto {
    pub site_id: String,
    pub site_display_name: Option<String>,
    pub permission: SitePermissionDto,
}

/// Progress event payload for the site-permission sweep, emitted as
/// `site-sweep-progress` after each scanned site.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSweepProgress {
    pub done: usize,
    pub total: usize,
    pub current_site: Option<String>,
    pub cancelled: bool,
}

/// One application grant found on one site during the sweep — the unit the
/// reverse lookup is built from. Filter by `app_id` to answer "which sites can
/// this app reach?" (the `Sites.Selected` blind spot — Graph has no reverse
/// lookup) and by site to answer "which apps can touch this site?".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SiteAppGrantRow {
    pub site_id: String,
    pub site_display_name: Option<String>,
    pub site_url: Option<String>,
    pub permission_id: String,
    pub roles: Vec<String>,
    pub app_id: Option<String>,
    pub app_display_name: Option<String>,
}

/// Result of a full site-permission sweep. `sites_failed` counts sites whose
/// permission read errored (never silently folded into "no grants"), so the
/// UI can say "covered 140 of 142 sites" instead of overstating coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSweepResult {
    pub tenant_id: String,
    pub total_sites: usize,
    pub sites_scanned: usize,
    pub sites_failed: usize,
    pub rows: Vec<SiteAppGrantRow>,
    pub cancelled: bool,
}

/// Outcome of `convert_site_access_to_selected`: restricting an org-wide
/// `Sites.*` grant to the `Sites.Selected` model on specific sites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteScopeResult {
    /// True when the `Sites.Selected` app role had to be granted (it wasn't
    /// already held).
    pub granted_role_added: bool,
    /// The sites the principal was granted access to.
    pub sites_granted: Vec<SiteGrantDto>,
    /// The org-wide `Sites.*` permission values that were removed so the scoped
    /// model is actually effective. Empty when none applied or removal was
    /// skipped.
    pub removed_orgwide_grants: Vec<String>,
    pub warnings: Vec<String>,
}
