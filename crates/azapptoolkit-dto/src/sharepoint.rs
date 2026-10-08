//! SharePoint Selected-permission IPC DTOs — the `Sites.Selected` site model
//! and the sub-site `*.SelectedOperations.Selected` family.

use serde::{Deserialize, Serialize};

use azapptoolkit_core::scoping::SelectedScopeLevel;

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
/// UI can say "covered 140 of 142 sites" — or "stopped at the 5000-site cap" —
/// instead of overstating coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSweepResult {
    pub tenant_id: String,
    pub total_sites: usize,
    pub sites_scanned: usize,
    pub sites_failed: usize,
    pub rows: Vec<SiteAppGrantRow>,
    pub cancelled: bool,
    /// The site enumeration stopped at the sweep's safety cap, so `total_sites`
    /// is the cap and `rows` are a prefix of the tenant. Unlike `cancelled` and
    /// `sites_failed` this is deterministic — re-running hits the same cap.
    #[serde(default)]
    pub truncated: bool,
}

/// One principal's slice of the sweep index: the sites it can reach under the
/// `Sites.Selected` model, with the roles it holds on each — the answer to
/// "which sites is this app scoped to?" without the operator knowing a site
/// URL, which Graph itself cannot answer (no reverse `appId → sites` lookup,
/// only per-site permission reads).
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
    /// The sweep stopped at its site cap; the list is a prefix of the tenant,
    /// like `cancelled` — but re-running will not extend it.
    #[serde(default)]
    pub truncated: bool,
}

impl AppSiteAccessDto {
    /// Projects one app's rows out of a full sweep.
    ///
    /// Shared on purpose: the backend serves this from the *cached* tenant
    /// sweep (so a per-app panel never ships thousands of rows across IPC),
    /// while the frontend applies it to a sweep it just ran — never cached when
    /// partial or cancelled, and so not re-readable. One definition means the
    /// two paths can't disagree about what "this app's sites" means.
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
            truncated: sweep.truncated,
        }
    }

    /// True when every enumerable site was read successfully AND the
    /// enumeration itself was not capped, so an empty `sites` list really does
    /// mean "no per-site grants". Same three-way conjunction shape as
    /// `AuditExportCoverage::is_complete`; a cached capped sweep rides on this
    /// carrying its flag, so no consumer can read it as an all-clear.
    pub fn is_complete(&self) -> bool {
        !self.cancelled && !self.truncated && self.sites_failed == 0
    }
}

/// Outcome of `convert_site_access_to_selected`: restricting an org-wide
/// `Sites.*` grant to the `Sites.Selected` model on specific sites.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteScopeResult {
    /// True when the `Sites.Selected` app role had to be granted (it wasn't
    /// already held).
    pub granted_role_added: bool,
    /// True when `Sites.Selected` had to be added to the app registration's
    /// `requiredResourceAccess`. Always false for a service-principal-only
    /// principal, which has no registration to declare on.
    pub declared_permission: bool,
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

    fn sweep(
        rows: Vec<SiteAppGrantRow>,
        failed: usize,
        cancelled: bool,
        truncated: bool,
    ) -> SiteSweepResult {
        SiteSweepResult {
            tenant_id: "t".into(),
            total_sites: 10,
            sites_scanned: 10 - failed,
            sites_failed: failed,
            rows,
            cancelled,
            truncated,
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
            &sweep(
                vec![row("Marketing", Some("other"), &["read"])],
                2,
                false,
                false,
            ),
            "app-1",
        );
        assert!(partial.sites.is_empty());
        assert!(!partial.is_complete());
        assert_eq!(partial.sites_failed, 2);

        // A cancelled sweep is likewise a prefix, not an answer.
        let cancelled = AppSiteAccessDto::from_sweep(&sweep(Vec::new(), 0, true, false), "app-1");
        assert!(!cancelled.is_complete());
    }

    /// A sweep that stopped at the site cap read every site it enumerated
    /// without a failure and was never cancelled — exactly the shape that used
    /// to read as complete. It is a prefix of the tenant, so an empty per-app
    /// list is "not found in the first N sites", never "no grants"; and the
    /// single projection must carry the flag, or the cached (backend-side) and
    /// fresh (frontend-side) paths would disagree about it.
    #[test]
    fn a_capped_sweep_is_a_prefix_not_an_answer() {
        let capped = AppSiteAccessDto::from_sweep(&sweep(Vec::new(), 0, false, true), "app-1");
        assert!(capped.sites.is_empty());
        assert!(capped.truncated, "from_sweep must carry the cap flag");
        assert!(!capped.is_complete());

        // And the positive, so the conjunction can't be over-tightened.
        let full = AppSiteAccessDto::from_sweep(&sweep(Vec::new(), 0, false, false), "app-1");
        assert!(full.is_complete());
    }
}

// ---------------- Sub-site Selected scopes ----------------

/// A SharePoint URL resolved to the securable a Selected grant would address.
///
/// Mirrors `azapptoolkit_core::models::ResolvedSharePointResource`, projected
/// for the UI: the panel echoes `display_path` and `level` back to the operator
/// *before* anything is granted, because a folder grant breaks permission
/// inheritance and is not something to discover after the fact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SharePointResourceRef {
    /// The level the URL resolved to — not the level the operator's permission
    /// grants at. The two are reconciled by
    /// `azapptoolkit_core::scoping::selected_scope_accepts`.
    pub level: SelectedScopeLevel,
    pub site_id: String,
    pub site_url: Option<String>,
    pub site_name: Option<String>,
    pub list_id: Option<String>,
    pub list_name: Option<String>,
    pub item_id: Option<String>,
    pub drive_id: Option<String>,
    pub is_folder: bool,
    pub display_path: String,
    /// The URL the operator supplied, echoed back so a panel row can be keyed
    /// and re-rendered against its own input.
    pub input_url: String,
}

/// A permission entry on a list, folder or file, projected for the UI.
///
/// Separate from [`SitePermissionDto`] because the principal arrives under a
/// different field (`grantedToV2`, not `grantedToIdentities`) and the row needs
/// to say which securable it was read from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SelectedItemPermissionDto {
    pub id: String,
    pub roles: Vec<String>,
    /// Set only for an app grant. The one field revoke keys off, so a user's or
    /// group's access can never be revoked from an app-centric view.
    pub app_id: Option<String>,
    pub app_display_name: Option<String>,
    /// Who the entry grants to, for display: one principal for a direct grant,
    /// or a [`PrincipalKind::SharingLink`] followed by the people it was sent
    /// to. Empty when Graph named no identity the app recognises.
    #[serde(default)]
    pub principals: Vec<PermissionPrincipalDto>,
}

/// What kind of principal a SharePoint permission entry grants to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Application,
    /// An Entra user account.
    User,
    /// An Entra group (security or Microsoft 365).
    Group,
    /// A SharePoint user profile with no Entra identity in the entry.
    SiteUser,
    /// A SharePoint group, such as "Finance Members".
    SiteGroup,
    Device,
    /// A sharing link. `detail` holds its scope and type.
    SharingLink,
}

/// One principal of a SharePoint permission entry, projected for display.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionPrincipalDto {
    pub kind: PrincipalKind,
    /// A directory object id for `User`/`Group`/`Application`; SharePoint-local
    /// otherwise.
    pub id: Option<String>,
    pub display_name: Option<String>,
    /// The email or sign-in name for a person or group, or "scope, type" for a
    /// sharing link.
    pub detail: Option<String>,
}

/// The principals of one permission entry. A sharing link comes first, then
/// the identity it grants to, then the people it was sent to; a person seen as
/// both `user` and `siteUser` is one principal, not two.
pub fn principals_of(
    p: &azapptoolkit_core::models::SelectedPermission,
) -> Vec<PermissionPrincipalDto> {
    let mut out: Vec<PermissionPrincipalDto> = Vec::new();
    if let Some(link) = &p.link {
        let detail = [link.scope.as_deref(), link.link_type.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ");
        out.push(PermissionPrincipalDto {
            kind: PrincipalKind::SharingLink,
            id: None,
            display_name: None,
            detail: (!detail.is_empty()).then_some(detail),
        });
    }
    for principal in p
        .granted_to_set()
        .into_iter()
        .chain(&p.granted_to_identities_v2)
        .filter_map(principal_of_set)
    {
        let seen = out
            .iter()
            .any(|o| o.kind == principal.kind && o.id.is_some() && o.id == principal.id);
        if !seen {
            out.push(principal);
        }
    }
    out
}

/// The single most specific principal of an identity set: an app, then the
/// Entra user or group (with the SharePoint profile's login as a fallback
/// detail), then the SharePoint-only identities.
fn principal_of_set(
    set: &azapptoolkit_core::models::SiteIdentitySet,
) -> Option<PermissionPrincipalDto> {
    use azapptoolkit_core::models::SiteIdentity;
    let make = |kind, identity: &SiteIdentity, detail: Option<String>| PermissionPrincipalDto {
        kind,
        id: identity.id.clone(),
        display_name: identity.display_name.clone().filter(|n| !n.is_empty()),
        detail,
    };
    let login = |identity: Option<&SiteIdentity>| {
        identity
            .and_then(|i| i.login_name.as_deref())
            .map(|l| l.rsplit('|').next().unwrap_or(l).to_string())
            .filter(|l| !l.is_empty())
    };
    if let Some(app) = &set.application {
        return Some(make(PrincipalKind::Application, app, None));
    }
    if let Some(user) = &set.user {
        let detail = user.email.clone().or_else(|| login(set.site_user.as_ref()));
        return Some(make(PrincipalKind::User, user, detail));
    }
    if let Some(group) = &set.group {
        return Some(make(PrincipalKind::Group, group, group.email.clone()));
    }
    if let Some(site_group) = &set.site_group {
        return Some(make(PrincipalKind::SiteGroup, site_group, None));
    }
    if let Some(site_user) = &set.site_user {
        return Some(make(
            PrincipalKind::SiteUser,
            site_user,
            login(Some(site_user)),
        ));
    }
    set.device
        .as_ref()
        .map(|device| make(PrincipalKind::Device, device, None))
}

/// One target granted (or attempted) during a `grant_selected_item_access` run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedItemGrantDto {
    pub resource: SharePointResourceRef,
    pub permission: SelectedItemPermissionDto,
}

/// Outcome of `grant_selected_item_access`.
///
/// `warnings` carries the per-target failures. A run that granted nothing still
/// returns `Ok` with an empty `granted` and the reasons in `warnings`, so the
/// panel can show which URLs were rejected and why rather than collapsing the
/// whole batch into one error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectedItemScopeResult {
    /// True when the Selected appRole had to be added (it is granted
    /// idempotently, so a re-run reports false).
    pub granted_role_added: bool,
    /// True when the Selected permission had to be added to the app
    /// registration's `requiredResourceAccess` — what makes the grant visible in
    /// the Permissions tab, which renders declarations and joins runtime
    /// assignments onto them. Always false for a service-principal-only
    /// principal, which has no registration to declare on.
    pub declared_permission: bool,
    pub granted: Vec<SelectedItemGrantDto>,
    pub warnings: Vec<String>,
    /// True when every granted target was recorded on the app registration
    /// (its `tags`), so the per-app "SharePoint item access" list shows it.
    /// False for a service-principal-only principal, which has no registration
    /// to record on; a failed record is also listed in `warnings`.
    #[serde(default)]
    pub recorded_on_app: bool,
}

/// A library, folder or file grant recorded on an app registration, addressed
/// by ids so it survives renames and moves. `level` is
/// [`SelectedScopeLevel::List`], [`SelectedScopeLevel::ListItem`] or
/// [`SelectedScopeLevel::File`] (folders included, as the resolver reports).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ItemScopeRef {
    pub level: SelectedScopeLevel,
    pub site_id: String,
    pub list_id: String,
    pub item_id: Option<String>,
}

/// What SharePoint says now about one recorded grant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ItemScopeStatus {
    /// This app holds an entry on the resource.
    Granted {
        permission_id: String,
        roles: Vec<String>,
    },
    /// The resource's entries were read, and none is this app's.
    NotGranted,
    /// The resource no longer exists (404).
    Missing,
    /// The entries could not be read, so nothing is claimed either way.
    Unreadable { message: String },
}

/// One row of the per-app "SharePoint item access" list.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppItemScopeDto {
    pub scope: ItemScopeRef,
    /// The library, folder or file name, when SharePoint returned one.
    pub name: Option<String>,
    pub web_url: Option<String>,
    pub is_folder: bool,
    pub status: ItemScopeStatus,
}

/// Outcome of `list_app_item_scopes`: the grants recorded on one app, each
/// with its live status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppItemScopesDto {
    pub entries: Vec<AppItemScopeDto>,
    /// Recorded tags that were not valid and were ignored.
    pub malformed: usize,
}

/// `principals_of` against the shapes Graph returns on list, list-item and
/// driveItem permission entries.
#[cfg(test)]
mod principal_tests {
    use super::{PermissionPrincipalDto, PrincipalKind, principals_of};
    use azapptoolkit_core::models::SelectedPermission;

    fn principals(entry: serde_json::Value) -> Vec<PermissionPrincipalDto> {
        let p: SelectedPermission = serde_json::from_value(entry).expect("a Graph permission");
        principals_of(&p)
    }

    fn one(
        kind: PrincipalKind,
        id: &str,
        name: &str,
        detail: Option<&str>,
    ) -> PermissionPrincipalDto {
        PermissionPrincipalDto {
            kind,
            id: Some(id.into()),
            display_name: Some(name.into()),
            detail: detail.map(Into::into),
        }
    }

    #[test]
    fn each_identity_kind_is_named() {
        let cases = [
            (
                serde_json::json!({ "id": "p", "grantedToV2": {
                    "application": { "id": "app-1", "displayName": "Sync" } } }),
                one(PrincipalKind::Application, "app-1", "Sync", None),
            ),
            (
                // A person arrives as both the Entra user and the SharePoint
                // profile: one principal, named by the user, email as detail.
                serde_json::json!({ "id": "p", "grantedToV2": {
                    "user": { "id": "u-1", "displayName": "Jane Doe", "email": "jane@contoso.com" },
                    "siteUser": { "id": "12", "displayName": "Jane Doe",
                                  "loginName": "i:0#.f|membership|jane@contoso.com" } } }),
                one(
                    PrincipalKind::User,
                    "u-1",
                    "Jane Doe",
                    Some("jane@contoso.com"),
                ),
            ),
            (
                serde_json::json!({ "id": "p", "grantedToV2": {
                    "user": { "id": "u-2", "displayName": "Raj" },
                    "siteUser": { "id": "13", "loginName": "i:0#.f|membership|raj@contoso.com" } } }),
                one(PrincipalKind::User, "u-2", "Raj", Some("raj@contoso.com")),
            ),
            (
                serde_json::json!({ "id": "p", "grantedToV2": {
                    "group": { "id": "g-1", "displayName": "Finance", "email": "finance@contoso.com" } } }),
                one(
                    PrincipalKind::Group,
                    "g-1",
                    "Finance",
                    Some("finance@contoso.com"),
                ),
            ),
            (
                serde_json::json!({ "id": "p", "grantedToV2": {
                    "siteGroup": { "id": "10", "displayName": "Finance Members" } } }),
                one(PrincipalKind::SiteGroup, "10", "Finance Members", None),
            ),
            (
                serde_json::json!({ "id": "p", "grantedToV2": {
                    "siteUser": { "id": "14", "displayName": "Ops",
                                  "loginName": "i:0#.f|membership|ops@contoso.com" } } }),
                one(
                    PrincipalKind::SiteUser,
                    "14",
                    "Ops",
                    Some("ops@contoso.com"),
                ),
            ),
        ];
        for (entry, want) in cases {
            assert_eq!(principals(entry.clone()), vec![want], "{entry}");
        }
    }

    /// The driveItem endpoint echoes the deprecated singular `grantedTo`.
    #[test]
    fn granted_to_is_read_when_granted_to_v2_is_absent() {
        let got = principals(serde_json::json!({ "id": "p", "grantedTo": {
            "user": { "id": "u-1", "displayName": "Jane Doe" } } }));
        assert_eq!(got[0].kind, PrincipalKind::User);
        assert_eq!(got[0].display_name.as_deref(), Some("Jane Doe"));
    }

    /// A sharing link is named as one, followed by each person it was sent to.
    #[test]
    fn a_sharing_link_lists_its_scope_and_recipients() {
        let got = principals(serde_json::json!({
            "id": "p",
            "roles": ["read"],
            "link": { "scope": "users", "type": "view", "webUrl": "https://x" },
            "grantedToIdentitiesV2": [
                { "user": { "id": "u-1", "displayName": "Jane Doe", "email": "jane@contoso.com" } },
                { "user": { "id": "u-2", "displayName": "Raj" } },
                { "user": { "id": "u-1", "displayName": "Jane Doe" } }
            ]
        }));
        assert_eq!(got[0].kind, PrincipalKind::SharingLink);
        assert_eq!(got[0].detail.as_deref(), Some("users, view"));
        assert_eq!(
            got[1..]
                .iter()
                .map(|p| p.id.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["u-1", "u-2"],
            "recipients in order, each once"
        );
    }

    /// An entry naming nothing the app knows yields no principal, not a guess.
    #[test]
    fn an_unrecognised_entry_has_no_principal() {
        assert!(principals(serde_json::json!({ "id": "p", "grantedToV2": {} })).is_empty());
        assert!(principals(serde_json::json!({ "id": "p", "grantedToV2": null })).is_empty());
        assert!(
            principals(serde_json::json!({ "id": "p", "grantedToIdentitiesV2": null })).is_empty()
        );
    }
}
