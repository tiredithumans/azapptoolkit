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

/// One principal's slice of the sweep index: the sites it can reach under the
/// `Sites.Selected` model, with the roles it holds on each — the answer to
/// "which sites is this app scoped to?" *without* the operator having to know a
/// site URL, which Graph itself cannot answer (there is no reverse
/// `appId → sites` lookup, only per-site permission reads).
///
/// The coverage fields ride along because they qualify the answer: an empty
/// `sites` list means "no grant found in the sites we could read", and the UI
/// has to be able to say which sites those were.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AppSiteAccessDto {
    /// This principal's grants only, in the sweep's site order.
    pub sites: Vec<SiteAppGrantRow>,
    pub total_sites: usize,
    pub sites_scanned: usize,
    /// Sites whose permission read failed — their grants are unknown, so a
    /// non-zero count means this list may be incomplete.
    pub sites_failed: usize,
    /// The sweep stopped early, so the list is a prefix of the tenant.
    pub cancelled: bool,
}

impl AppSiteAccessDto {
    /// Projects one app's rows out of a full sweep.
    ///
    /// Shared on purpose: the backend serves this from the *cached* tenant sweep
    /// (so a per-app panel never ships thousands of rows across IPC), while the
    /// frontend applies it to a sweep it just ran — which is never cached when
    /// partial or cancelled, and so could not be re-read. One definition means
    /// the two paths can't disagree about what "this app's sites" means.
    ///
    /// Matches `app_id` case-insensitively: these are GUIDs, and Graph is not
    /// consistent about their casing across endpoints.
    pub fn from_sweep(sweep: &SiteSweepResult, app_id: &str) -> Self {
        Self {
            sites: sweep
                .rows
                .iter()
                .filter(|r| {
                    r.app_id
                        .as_deref()
                        .is_some_and(|id| id.eq_ignore_ascii_case(app_id))
                })
                .cloned()
                .collect(),
            total_sites: sweep.total_sites,
            sites_scanned: sweep.sites_scanned,
            sites_failed: sweep.sites_failed,
            cancelled: sweep.cancelled,
        }
    }

    /// True when every enumerable site was read successfully, so an empty
    /// `sites` list really does mean "no per-site grants".
    pub fn is_complete(&self) -> bool {
        !self.cancelled && self.sites_failed == 0
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn row(site: &str, app: Option<&str>, roles: &[&str]) -> SiteAppGrantRow {
        SiteAppGrantRow {
            site_id: format!("id-{site}"),
            site_display_name: Some(site.to_string()),
            site_url: Some(format!("https://contoso.sharepoint.com/sites/{site}")),
            permission_id: format!("perm-{site}"),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            app_id: app.map(str::to_string),
            app_display_name: app.map(|_| "App".to_string()),
        }
    }

    fn sweep(rows: Vec<SiteAppGrantRow>, failed: usize, cancelled: bool) -> SiteSweepResult {
        SiteSweepResult {
            tenant_id: "t".into(),
            total_sites: 10,
            sites_scanned: 10 - failed,
            sites_failed: failed,
            rows,
            cancelled,
        }
    }

    #[test]
    fn from_sweep_keeps_only_this_app_and_carries_its_roles() {
        let s = sweep(
            vec![
                row("Marketing", Some("APP-1"), &["read"]),
                row("Finance", Some("app-2"), &["write"]),
                // Casing differs across Graph endpoints, so the match folds it.
                row("Sales", Some("app-1"), &["write", "read"]),
                // A non-application grant (a user/group) carries no app id.
                row("HR", None, &["read"]),
            ],
            0,
            false,
        );
        let mine = AppSiteAccessDto::from_sweep(&s, "app-1");
        let names: Vec<&str> = mine
            .sites
            .iter()
            .filter_map(|r| r.site_display_name.as_deref())
            .collect();
        assert_eq!(names, vec!["Marketing", "Sales"]);
        assert_eq!(mine.sites[1].roles, vec!["write", "read"]);
        assert!(mine.is_complete());
    }

    #[test]
    fn coverage_rides_along_so_an_empty_list_can_be_qualified() {
        // No grants for this app — but two sites could not be read, so "no
        // access" is not a conclusion the UI may draw.
        let partial = AppSiteAccessDto::from_sweep(
            &sweep(vec![row("Marketing", Some("other"), &["read"])], 2, false),
            "app-1",
        );
        assert!(partial.sites.is_empty());
        assert!(!partial.is_complete());
        assert_eq!(partial.sites_failed, 2);

        // A cancelled sweep is likewise a prefix, not an answer.
        let cancelled = AppSiteAccessDto::from_sweep(&sweep(Vec::new(), 0, true), "app-1");
        assert!(!cancelled.is_complete());
    }
}
