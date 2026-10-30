//! SharePoint Selected-permission commands.
//!
//! Grants/lists/revokes per-site application permissions via Microsoft Graph
//! (`/sites/{id}/permissions`) — the supported "current-context / delegated"
//! strategy from the legacy `Grant-SharePointSiteAccess`. The signed-in user
//! needs `Sites.FullControl.All` (a SharePoint admin or site owner); the temp-
//! app strategy is a future phase. Each command resolves the site from its URL
//! first, since the UI works in terms of the browser site URL.

use std::collections::HashMap;
use std::sync::Arc;

use tauri::{AppHandle, State};

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{
    AppRoleAssignment, ResolvedSharePointResource, SelectedPermission, Site, SitePermission,
};
use azapptoolkit_core::scoping::{
    MICROSOFT_GRAPH_APP_ID, OFFICE365_SHAREPOINT_ONLINE_APP_ID, SP_SITES_SELECTED,
    SelectedScopeLevel, is_files_orgwide_permission, is_grantable_selected_role,
    is_scopable_sharepoint_resource_permission, is_sharepoint_orgwide,
    is_sharepoint_orgwide_permission, resource_label, selected_scope_accepts,
    selected_scope_level_for,
};

use crate::commands::applications::invalidate_app_detail_state;
use crate::commands::dispatch::{SessionDead, dispatch_capped};
use crate::commands::export::{coverage_comment_block, coverage_json, csv_field};
use crate::commands::graph_err::forbidden_remediation;
use crate::commands::graph_roles::{
    ResourceRoles, graph_resource_roles, graph_role_id, graph_role_index, resolve_grant,
    resource_roles, strip_app_role_grants,
};
use crate::commands::permissions::{declare_resource_access, grant_failure_message};
use crate::commands::progress::emit_progress;
use crate::commands::throttle::FanOutMeter;
use crate::dto::UiError;
use crate::dto::sharepoint::{
    AppSiteAccessDto, GrantSiteAccessResult, SelectedItemGrantDto, SelectedItemPermissionDto,
    SelectedItemScopeResult, SharePointResourceRef, SiteAppGrantRow, SiteGrantDto,
    SitePermissionDto, SiteScopeResult, SiteSweepProgress, SiteSweepResult,
};
use crate::state::AppState;

/// Whether to strip the broad org-wide grant: only when the caller asked for it
/// AND at least one site grant landed, so a principal is never left with no
/// access because every site grant failed.
fn should_remove_orgwide(remove_orgwide: bool, any_site_granted: bool) -> bool {
    remove_orgwide && any_site_granted
}

/// Refuses a role the UI never offers before anything is granted. The commands
/// take the role as a free string from the webview, and the per-resource
/// permission endpoints accept stronger ones (`owner`, `fullcontrol`,
/// `manage`), so without this a webview call could grant more than the
/// wizard shows.
fn require_grantable_roles(roles: &[String]) -> Result<(), UiError> {
    match roles.iter().find(|r| !is_grantable_selected_role(r)) {
        None if roles.is_empty() => Err(UiError::validation(
            "unsupported_role",
            "no role to grant; use read or write",
        )),
        None => Ok(()),
        Some(_) => Err(UiError::validation(
            "unsupported_role",
            "a role other than read or write was requested; a Selected grant carries read or write",
        )),
    }
}

/// Declares `role_id` as a Microsoft Graph **application** permission on the app
/// registration, mirroring what the ordinary grant path
/// (`permissions::grant_single_permission_core`) does before it creates the
/// assignment. Returns whether a declaration was actually added.
///
/// Both SharePoint apply paths used to create the app-role assignment and stop
/// there. The permission was genuinely granted, but the Permissions tab renders
/// `requiredResourceAccess` and joins runtime assignments **onto** declared rows
/// (`applications::permissions_resolve`), so a grant with no declaration was
/// invisible on the app registration — and the wizard's picker is the full live
/// catalog, not the declared set, so undeclared is the *normal* case here.
///
/// `object_id` is `None` for a service-principal-only principal (enterprise app
/// or managed identity): there is no local app registration to declare on, and
/// the app-role assignment is the whole story.
async fn declare_graph_role(
    client: &azapptoolkit_graph::GraphClient,
    cache: &Cache,
    tenant_id: &str,
    object_id: Option<&str>,
    app_id: &str,
    role_id: &str,
) -> Result<bool, UiError> {
    let Some(object_id) = object_id else {
        return Ok(false);
    };
    let mut app = client.get_application(object_id).await?;
    // The registration being declared on must be the app the resource grant
    // names: the three ids arrive separately from the webview, and a pairing
    // that drifted would declare on one app while another received the
    // per-resource permission.
    require_same_app(&app.app_id, app_id, "app registration")?;
    if !declare_resource_access(
        &mut app.required_resource_access,
        MICROSOFT_GRAPH_APP_ID,
        role_id,
        "Role",
    ) {
        return Ok(false);
    }
    let patch = azapptoolkit_graph::client::AppPatch {
        required_resource_access: Some(app.required_resource_access.clone()),
        ..Default::default()
    };
    client.update_application(object_id, &patch).await?;
    // The manifest PATCH is a completed mutation on its own, and the steps after
    // it can still fail. Invalidate here rather than only on the command's final
    // `Ok`, or a later failure leaves the detail cache showing an app that
    // doesn't declare what it was just given.
    invalidate_app_detail_state(cache, tenant_id);
    Ok(true)
}

/// The principal a Selected grant is for. Named fields because three adjacent
/// `&str` ids transpose easily (the `ApplyExchangeMailboxScopeParams`
/// reasoning in `exchange/grants.rs`).
struct GraphRolePrincipal<'a> {
    tenant_id: &'a str,
    /// The app registration to declare on; `None` for an SP-only principal.
    object_id: Option<&'a str>,
    sp_object_id: &'a str,
    /// The appId the per-resource grant is made to. Both objects above are
    /// checked against it before anything is written.
    app_id: &'a str,
}

/// Refuses an object whose `appId` is not the one the grant names.
fn require_same_app(found: &str, app_id: &str, what: &str) -> Result<(), UiError> {
    if found.eq_ignore_ascii_case(app_id) {
        Ok(())
    } else {
        Err(UiError::validation(
            "principal_mismatch",
            format!(
                "the {what} does not belong to the app being granted; nothing was declared, \
                 assigned or granted"
            ),
        ))
    }
}

/// What [`declare_and_grant_graph_role`] changed.
struct GraphRoleGrant {
    declared_permission: bool,
    granted_role_added: bool,
}

/// Declares Microsoft Graph application permission `value` on the app
/// registration ([`declare_graph_role`]), THEN assigns it to the principal's
/// service principal unless `existing` already holds it — declared before
/// assigned, and idempotent. Shared by both Selected apply paths
/// (`convert_site_access_to_selected` and `grant_selected_item_access`).
///
/// Declared first for the reason the ordinary grant path declares first: the
/// manifest should never promise less than what is assigned. The wizard's
/// picker is the full live catalog, so this is usually a permission the app has
/// never declared — and an assignment with no declaration does not appear in
/// the Permissions tab at all. Without the assigned appRole in the token, the
/// per-resource permissions the callers grant next give nothing at all.
async fn declare_and_grant_graph_role(
    client: &azapptoolkit_graph::GraphClient,
    cache: &Cache,
    principal: &GraphRolePrincipal<'_>,
    graph_sp_id: &str,
    role_value_by_id: &HashMap<String, String>,
    existing: &[AppRoleAssignment],
    value: &str,
) -> Result<GraphRoleGrant, UiError> {
    let role_id = graph_role_id(role_value_by_id, value)?;
    // The service principal the appRole is assigned to must be the app the
    // resource grant names — resolved from the object id, never trusted from
    // the pairing the webview sent.
    let sp = client
        .get_service_principal_by_object_id(principal.sp_object_id)
        .await?
        .ok_or_else(|| UiError::not_found("service_principal", "Service principal not found."))?;
    require_same_app(&sp.app_id, principal.app_id, "service principal")?;
    let declared_permission = declare_graph_role(
        client,
        cache,
        principal.tenant_id,
        principal.object_id,
        principal.app_id,
        &role_id,
    )
    .await?;
    let already_held = existing
        .iter()
        .any(|a| a.resource_id == graph_sp_id && a.app_role_id == role_id);
    let mut granted_role_added = false;
    if !already_held {
        client
            .grant_app_role(principal.sp_object_id, graph_sp_id, &role_id)
            .await
            .map_err(|err| grant_role_err(err, value))?;
        granted_role_added = true;
    }
    Ok(GraphRoleGrant {
        declared_permission,
        granted_role_added,
    })
}

/// A failed Microsoft Graph appRole assignment, with its code kept.
///
/// Every failure used to come back as `grant_failed`, which hid the three that
/// each have their own way out: `forbidden` (the operator lacks the role),
/// `consent_required` (the write scope was never consented — for a
/// service-principal-only principal, or a role already declared, this is the
/// first write of the run) and `refresh_missing` (a dead session, which also
/// stops a bulk run). The message names the permission, and a 403 carries the
/// `admin_consent` catalog guidance through the grant paths' shared
/// [`grant_failure_message`]: assigning a Microsoft Graph application role
/// needs Privileged Role Administrator, which is what a forbidden here means.
fn grant_role_err(err: azapptoolkit_graph::GraphError, value: &str) -> UiError {
    let message = format!("failed to grant {value}: {}", grant_failure_message(&err));
    UiError {
        message,
        ..UiError::from(err)
    }
}

/// The value assignment `a` grants when it is an org-wide `Sites.*` grant on
/// Microsoft Graph — the one the `Sites.Selected` conversion strips — and
/// `None` for anything else (another resource, a role the index does not know,
/// or a Selected scope, which is the confinement itself).
fn orgwide_sites_value(
    graph_sp_id: &str,
    role_value_by_id: &HashMap<String, String>,
    a: &AppRoleAssignment,
) -> Option<String> {
    if a.resource_id != graph_sp_id {
        return None;
    }
    role_value_by_id
        .get(&a.app_role_id)
        .filter(|value| is_sharepoint_orgwide(value))
        .cloned()
}

/// The org-wide SharePoint reach `existing` still carries once the conversion
/// has removed `removed_from_graph`, as `(resource app id, value)` pairs in
/// assignment order — the SharePoint counterpart of the Exchange core's
/// `still_held_orgwide`.
///
/// Classified by the audit's own Rule 12 gates, keyed by `(resource, value)`
/// and never the value alone: an org-wide `Sites.*` on either SharePoint-bearing
/// resource (`is_sharepoint_orgwide_permission`, behind `ORG_WIDE_SHAREPOINT`
/// and `UNCONFINABLE_SHAREPOINT`) reaches every site, and Graph's
/// `Files.Read.All` / `Files.ReadWrite.All` (`is_files_orgwide_permission`,
/// behind `ORG_WIDE_FILES`) every file — whatever the `Sites.Selected` grants
/// allow. The strip ([`orgwide_sites_value`]) removes Microsoft Graph's
/// `Sites.*` only, so `removed_from_graph` excuses a Graph grant and nothing
/// else: Office 365 SharePoint Online's `Sites.Read.All` is a different grant
/// from Graph's, and nothing here removes it.
fn residual_orgwide_reach<'a>(
    resources: &'a [ResourceRoles],
    existing: &[AppRoleAssignment],
    removed_from_graph: &[String],
) -> Vec<(&'a str, &'a str)> {
    let mut held: Vec<(&'a str, &'a str)> = Vec::new();
    for a in existing {
        let Some((resource, _, value)) = resolve_grant(resources, &a.resource_id, &a.app_role_id)
        else {
            continue;
        };
        let orgwide = is_sharepoint_orgwide_permission(Some(resource), value)
            || is_files_orgwide_permission(Some(resource), value);
        let removed = resource == MICROSOFT_GRAPH_APP_ID
            && removed_from_graph.iter().any(|r| r.as_str() == value);
        if orgwide && !removed && !held.contains(&(resource, value)) {
            held.push((resource, value));
        }
    }
    held
}

/// One "Scoping is NOT effective" line naming each grant in `held` with its
/// resource, or `None` when nothing org-wide is left. The step lines above it
/// say what failed; this says what that means, once, in the Exchange core's
/// voice.
///
/// A Microsoft Graph `Sites.*` is still held only because its removal was
/// stopped (no site grant landed, or the DELETE failed) or not asked for, so
/// it points back at those lines. Anything else is beyond what the conversion
/// removes at all, so the line says so rather than implying a re-run helps.
fn orgwide_reach_warning(held: &[(&str, &str)], remove_orgwide: bool) -> Option<String> {
    if held.is_empty() {
        return None;
    }
    let names: Vec<String> = held
        .iter()
        .map(|&(resource, value)| format!("{value} ({})", resource_label(resource)))
        .collect();
    let sites = held
        .iter()
        .any(|&(r, v)| is_sharepoint_orgwide_permission(Some(r), v));
    let files = held
        .iter()
        .any(|&(r, v)| is_files_orgwide_permission(Some(r), v));
    let reach = match (sites, files) {
        (true, true) => "every site and every file",
        (false, true) => "every file",
        _ => "every site",
    };
    let one = held.len() == 1;
    let mut line = format!(
        "Scoping is NOT effective for SharePoint: {} {} still granted organization-wide in \
         Microsoft Entra ID, so the app still reaches {reach} through {}, not only the sites \
         granted here.",
        names.join(", "),
        if one { "is" } else { "are" },
        if one { "it" } else { "them" },
    );
    if held
        .iter()
        .any(|&(r, v)| !is_scopable_sharepoint_resource_permission(Some(r), v))
    {
        line.push_str(
            " This conversion removes only Microsoft Graph's Sites.* grants: remove the others \
             yourself if the app should be confined.",
        );
    }
    if remove_orgwide
        && held
            .iter()
            .any(|&(r, v)| is_scopable_sharepoint_resource_permission(Some(r), v))
    {
        line.push_str(" Re-run once the problems above are fixed.");
    }
    Some(line)
}

/// Whether `existing` holds a grant on a resource none of `resources` is, so
/// the residual check cannot classify it. Asked only when Office 365 SharePoint
/// Online's role index could not be read: such a grant may then be an org-wide
/// `Sites.*` there, and "could not check" must not read as "holds nothing".
fn holds_unidentified_grant(resources: &[ResourceRoles], existing: &[AppRoleAssignment]) -> bool {
    existing
        .iter()
        .any(|a| !resources.iter().any(|r| r.sp_object_id == a.resource_id))
}

/// The distinct resources in a pasted target list, in the order given. Both
/// Selected apply paths iterate this, never the raw list.
///
/// Two spellings of one resource would create two permission entries on it, each
/// consuming another of the library's unique permission scopes for no extra
/// access — and a repeated line in a pasted block is easy not to notice. On the
/// site path a repeat is a second grant call for the same site, counted twice in
/// the result. Compared case- and trailing-slash-insensitively, which is how
/// SharePoint treats its own URLs.
fn dedupe_targets(urls: &[String]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for url in urls {
        let key = url.trim().trim_end_matches('/').to_ascii_lowercase();
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        out.push(url.clone());
    }
    out
}

/// Pre-acquires the `Sites.FullControl.All` token with a typed call — so a
/// not-yet-consented SharePoint scope surfaces as `consent_required` (the tab
/// shows a "Grant consent" button for the `sharepoint` feature) before any
/// SharePoint work starts, rather than partway through it — then returns the
/// tenant's Graph client. Mirrors `exchange_client_checked`; every SharePoint
/// command routes its pre-acquire through here so the "consent is checked
/// before side effects" contract lives in one place.
pub(crate) async fn sharepoint_client_checked(
    state: &AppState,
    tenant_id: &str,
) -> Result<Arc<azapptoolkit_graph::GraphClient>, UiError> {
    state
        .ensure_sharepoint_token(tenant_id)
        .await
        .map_err(UiError::from)?;
    Ok(state.graph_for(tenant_id))
}

/// Maps a **site-collection** SharePoint Graph error to a `UiError`, replacing a
/// 403's message with the `sharepoint_sites_selected` role guidance. A forbidden
/// *after* the `Sites.FullControl.All` scope is consented means the signed-in
/// user lacks the SharePoint Administrator role — not a consent gap (that
/// surfaces earlier as `consent_required` from `ensure_sharepoint_token`).
/// Single copy of the text lives in the capability catalog.
fn sharepoint_err(err: azapptoolkit_graph::GraphError) -> UiError {
    map_sharepoint_err(err, "sharepoint_sites_selected")
}

/// The **sub-site** sibling of [`sharepoint_err`], for the list / folder / file
/// endpoints.
///
/// A separate capability key rather than a reworded copy: the two levels differ
/// on the *user* half, not the scope. A delegated call is the intersection of
/// the token's scopes and the caller's own SharePoint permissions, and a grant
/// below the site collection writes a role assignment onto a securable inside
/// the site's content — which the tenant SharePoint Administrator role doesn't
/// reach. Sending both through one message told an operator whose site-level
/// grants worked that they lacked a role they demonstrably held.
/// A 403 from the permission tester's reads means the *operator* lacks rights
/// on the resource, so it routes through here too.
pub(crate) fn sharepoint_item_err(err: azapptoolkit_graph::GraphError) -> UiError {
    map_sharepoint_err(err, "sharepoint_selected_items")
}

/// Shared body: swap a 403's message for `capability_key`'s catalog remediation,
/// **after** recording what Graph actually said.
///
/// The substitution is lossy by design (never leak a raw Graph body into the
/// UI), but Graph's `error.code`/`error.message` is the only thing that
/// separates "you lack rights on this site" from any other denial, and nothing
/// else on these paths logs it. Without this line the sole record of a 403 was
/// a fixed sentence naming a role the operator may well already hold.
fn map_sharepoint_err(err: azapptoolkit_graph::GraphError, capability_key: &str) -> UiError {
    let mut ui = UiError::from(err);
    if let Some(remediation) = forbidden_remediation(&ui, capability_key) {
        tracing::warn!(
            capability = capability_key,
            detail = %ui.message,
            "SharePoint call forbidden; replacing message with catalog remediation"
        );
        ui.message = remediation.to_string();
    }
    ui
}

fn to_dto(p: SitePermission) -> SitePermissionDto {
    let app = p
        .granted_to_identities
        .into_iter()
        .find_map(|s| s.application);
    SitePermissionDto {
        id: p.id,
        roles: p.roles,
        app_id: app.as_ref().and_then(|a| a.id.clone()),
        app_display_name: app.and_then(|a| a.display_name),
    }
}

/// Grants `app_id` the given `roles` (e.g. `["read"]` / `["write"]`) on the
/// site identified by `site_url`.
#[tauri::command]
pub async fn grant_site_access(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    app_display_name: String,
    site_url: String,
    roles: Vec<String>,
) -> Result<GrantSiteAccessResult, UiError> {
    require_grantable_roles(&roles)?;
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    let site = client
        .get_site_by_url(&site_url)
        .await
        .map_err(sharepoint_err)?;
    let perm = client
        .grant_site_permission(&site.id, &app_id, &app_display_name, &roles)
        .await
        .map_err(sharepoint_err)?;
    // The new per-site grant is exactly what the cached sweep indexes.
    invalidate_site_sweep(&state.cache, &tenant_id);
    Ok(GrantSiteAccessResult {
        site_id: site.id,
        site_display_name: site.display_name,
        permission: to_dto(perm),
    })
}

/// Lists all application permissions on the site identified by `site_url`.
#[tauri::command]
pub async fn list_site_permissions(
    state: State<'_, AppState>,
    tenant_id: String,
    site_url: String,
) -> Result<Vec<SitePermissionDto>, UiError> {
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    let site = client
        .get_site_by_url(&site_url)
        .await
        .map_err(sharepoint_err)?;
    let perms = client
        .list_site_permissions(&site.id)
        .await
        .map_err(sharepoint_err)?;
    Ok(perms.into_iter().map(to_dto).collect())
}

/// Removes a site permission by id from the site identified by `site_url`.
#[tauri::command]
pub async fn remove_site_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    site_url: String,
    permission_id: String,
) -> Result<(), UiError> {
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    let site = client
        .get_site_by_url(&site_url)
        .await
        .map_err(sharepoint_err)?;
    client
        .remove_site_permission(&site.id, &permission_id)
        .await
        .map_err(sharepoint_err)?;
    // The removed per-site grant is exactly what the cached sweep indexes —
    // without this, the sweep keeps reporting the revoked access for up to an
    // hour, the worst kind of staleness in a least-privilege view.
    invalidate_site_sweep(&state.cache, &tenant_id);
    Ok(())
}

/// Restricts a service principal's **already-held** org-wide SharePoint access
/// to the `Sites.Selected` model on specific sites — the after-the-fact analog
/// of the Exchange RBAC flow. Works for both an app registration's SP and a
/// managed identity (both are service principals; the caller supplies the SP
/// object id + app id directly). Ordering mirrors Exchange: grant the scoped
/// access *before* removing the broad grant, so a failure never strands the
/// principal with no access.
///
/// Steps: (1) grant `Sites.Selected` (idempotent); (2) grant `role` on each
/// distinct `site_url`; (3) only if ≥1 site grant succeeded and
/// `remove_orgwide`, strip Microsoft Graph's org-wide `Sites.*` Entra grants;
/// (4) report, as a "Scoping is NOT effective" warning, any org-wide
/// SharePoint reach the principal still holds — an Office 365 SharePoint Online
/// `Sites.*` or a Graph `Files.*.All`, which the strip does not touch, or a
/// Graph `Sites.*` it could not remove. Graph has no reverse `appId → sites`
/// lookup, so the sites must be supplied by the caller.
///
/// A thin wrapper: the role gate and the SharePoint pre-acquire, then
/// `convert_site_access_core`, which holds everything else.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn convert_site_access_to_selected(
    state: State<'_, AppState>,
    tenant_id: String,
    sp_object_id: String,
    object_id: Option<String>,
    app_id: String,
    app_display_name: String,
    site_urls: Vec<String>,
    role: String,
    remove_orgwide: bool,
) -> Result<SiteScopeResult, UiError> {
    require_grantable_roles(std::slice::from_ref(&role))?;
    // The per-site grants ride the SharePoint scope, pre-acquired here.
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    convert_site_access_core(
        &client,
        &state.cache,
        &GraphRolePrincipal {
            tenant_id: &tenant_id,
            object_id: object_id.as_deref(),
            sp_object_id: &sp_object_id,
            app_id: &app_id,
        },
        SiteConversion {
            app_display_name: &app_display_name,
            site_urls: &site_urls,
            role: &role,
            remove_orgwide,
        },
    )
    .await
}

/// What a `Sites.Selected` conversion grants, and whether it may strip. Named
/// fields for the reason [`GraphRolePrincipal`] has them.
struct SiteConversion<'a> {
    /// Recorded on each per-site grant, as Graph shows it on the site.
    app_display_name: &'a str,
    site_urls: &'a [String],
    /// `read` or `write`: the command gates it ([`require_grantable_roles`])
    /// before the SharePoint token is even acquired.
    role: &'a str,
    remove_orgwide: bool,
}

/// The body of [`convert_site_access_to_selected`], over a client and a cache
/// rather than `State`, so the orchestration is testable against a mock Graph
/// (`tauri::test` is deliberately not enabled; see `progress.rs`).
///
/// Every read the conversion decides on comes first, so a failed read aborts
/// with nothing changed: the Graph role index, Office 365 SharePoint Online's
/// (held as a `Result` — only the final report reads it, and "unreadable" must
/// never read as "holds nothing there"), and the principal's assignments.
async fn convert_site_access_core(
    client: &azapptoolkit_graph::GraphClient,
    cache: &Cache,
    principal: &GraphRolePrincipal<'_>,
    conversion: SiteConversion<'_>,
) -> Result<SiteScopeResult, UiError> {
    let SiteConversion {
        app_display_name,
        site_urls,
        role,
        remove_orgwide,
    } = conversion;
    let graph = graph_resource_roles(client).await?;
    let online = resource_roles(client, OFFICE365_SHAREPOINT_ONLINE_APP_ID).await;

    let mut warnings = Vec::new();

    // Snapshot the current assignments once: drives the idempotency check for
    // the Sites.Selected grant, the org-wide-removal scan, and the report of
    // what is still org-wide afterwards.
    let existing = client
        .list_app_role_assignments(principal.sp_object_id)
        .await?;

    // 0-1. Declare Sites.Selected on the app registration (so the grant is
    //      visible in the Permissions tab), then grant it (idempotent).
    let GraphRoleGrant {
        declared_permission,
        granted_role_added,
    } = declare_and_grant_graph_role(
        client,
        cache,
        principal,
        &graph.sp_object_id,
        &graph.role_value_by_id,
        &existing,
        SP_SITES_SELECTED,
    )
    .await?;

    // 2. Grant the scoped per-site access (before removing the broad grant),
    //    once per site: `dedupe_targets` folds the spellings it can see as one,
    //    and a site already granted in this run is skipped for the ones it
    //    cannot (no scheme, a page inside the site) — one site, one grant, one
    //    row in the count.
    let roles = vec![role.to_string()];
    let mut sites_granted: Vec<SiteGrantDto> = Vec::new();
    for url in &dedupe_targets(site_urls) {
        let site = match client.get_site_by_url(url).await {
            Ok(site) => site,
            Err(err) => {
                // Through the module's own mapper, not `Display`, so a 403
                // carries its `sharepoint_sites_selected` remediation and
                // Graph's raw body stays out of the panel.
                let ui = sharepoint_err(err);
                warnings.push(format!("could not resolve site '{url}': {}", ui.message));
                continue;
            }
        };
        if sites_granted.iter().any(|g| g.site_id == site.id) {
            continue;
        }
        match client
            .grant_site_permission(&site.id, principal.app_id, app_display_name, &roles)
            .await
        {
            Ok(perm) => sites_granted.push(SiteGrantDto {
                site_id: site.id,
                site_display_name: site.display_name,
                permission: to_dto(perm),
            }),
            Err(err) => {
                let ui = sharepoint_err(err);
                warnings.push(format!("failed to grant access to '{url}': {}", ui.message));
            }
        }
    }

    // 3. Strip Microsoft Graph's org-wide Sites.* grants — but only if some
    //    site access actually landed.
    let mut removed_orgwide_grants = Vec::new();
    if should_remove_orgwide(remove_orgwide, !sites_granted.is_empty()) {
        removed_orgwide_grants = strip_app_role_grants(
            client,
            principal.sp_object_id,
            &existing,
            |a| orgwide_sites_value(&graph.sp_object_id, &graph.role_value_by_id, a),
            &mut warnings,
        )
        .await;
    } else if remove_orgwide {
        warnings.push(
            "no site access was granted, so the org-wide Sites.* grant was left in place".into(),
        );
    }

    // 4. Say what the principal can STILL reach org-wide. The strip removes
    //    Graph's Sites.* and nothing else, so an Office 365 SharePoint Online
    //    Sites.* or a Graph Files.*.All keeps every site (or file) in reach —
    //    and a result that reported only the removals told the operator the
    //    app was confined when it was not.
    let (online, online_unreadable) = match online {
        Ok(roles) => (roles, None),
        Err(err) => (None, Some(err)),
    };
    let resources: Vec<ResourceRoles> = std::iter::once(graph).chain(online).collect();
    let held = residual_orgwide_reach(&resources, &existing, &removed_orgwide_grants);
    warnings.extend(orgwide_reach_warning(&held, remove_orgwide));
    if let Some(err) = online_unreadable
        && holds_unidentified_grant(&resources, &existing)
    {
        warnings.push(format!(
            "could not read the Office 365 SharePoint Online permissions, so this cannot say \
             whether the app still reaches every site through one of them: {}",
            err.message
        ));
    }

    // The Sites.Selected grant / org-wide removal change the SP's app-role
    // assignments: detail-pane and audit state, never a list row (no list
    // shows assignments), so the detail tier, not a tenant-wide list rescan.
    // Invalidate only on this success path.
    invalidate_app_detail_state(cache, principal.tenant_id);
    // The per-site grants are what the cached sweep indexes (the org-wide
    // strip is not — the sweep holds per-site rows only), so bust it whenever
    // at least one site grant landed.
    if !sites_granted.is_empty() {
        invalidate_site_sweep(cache, principal.tenant_id);
    }

    Ok(SiteScopeResult {
        granted_role_added,
        declared_permission,
        sites_granted,
        removed_orgwide_grants,
        warnings,
    })
}

// ---------------- Sub-site Selected scopes ----------------
//
// `Lists.`/`ListItems.`/`Files.SelectedOperations.Selected` confine an app to a
// single list, folder or file. Same three-step model as `Sites.Selected`
// (consent the scope → grant a per-resource permission → present a token
// carrying the scope), one level down — and the same reason a consented scope
// alone grants nothing.
//
// Two properties the site path does not have:
//
// * **Reach is not enumerable.** `sweep_site_permissions` can walk every site in
//   the tenant; nothing can walk every folder. There is no sweep here and no
//   cached index, so a caller must never read "no rows" as "no grants" — it
//   means "nothing was asked about". See `get_selected_item_permissions`.
// * **A grant breaks permission inheritance** on its target and consumes one of
//   the library's unique permission scopes. The UI warns before granting; the
//   backend just records it in the result.

pub(crate) fn to_item_dto(p: SelectedPermission) -> SelectedItemPermissionDto {
    SelectedItemPermissionDto {
        id: p.id.clone(),
        roles: p.roles.clone(),
        app_id: p.app_id().map(str::to_string),
        app_display_name: p.app_display_name().map(str::to_string),
        principals: crate::dto::sharepoint::principals_of(&p),
    }
}

/// Names the Entra users and groups Graph listed by id alone.
///
/// SharePoint usually echoes a `displayName`, but an entry for a principal it
/// has not cached can arrive with only the directory object id. Those ids go
/// through one read-token `$batch` of `/directoryObjects/{id}`. SharePoint-local
/// ids (`siteUser`, `siteGroup`) are never sent: they are not directory ids.
/// Best effort: a failed lookup leaves the id on the row, never drops the row.
pub(crate) async fn fill_principal_names(
    client: &azapptoolkit_graph::GraphClient,
    perms: &mut [SelectedItemPermissionDto],
) {
    use crate::dto::sharepoint::PrincipalKind;
    use azapptoolkit_core::models::DirectoryObject;

    let mut ids: Vec<String> = perms
        .iter()
        .flat_map(|p| &p.principals)
        .filter(|p| matches!(p.kind, PrincipalKind::User | PrincipalKind::Group))
        .filter(|p| p.display_name.is_none())
        .filter_map(|p| p.id.clone())
        .filter(|id| azapptoolkit_core::guid::is_guid(id))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    if ids.is_empty() {
        return;
    }
    let urls: Vec<String> = ids
        .iter()
        .map(|id| format!("/directoryObjects/{id}?$select=id,displayName,userPrincipalName,mail"))
        .collect();
    let found: HashMap<String, DirectoryObject> =
        match client.batch_get_json::<DirectoryObject>(&urls).await {
            Ok(results) => results
                .into_iter()
                .filter_map(Result::ok)
                .map(|o| (o.id.clone(), o))
                .collect(),
            Err(err) => {
                tracing::debug!(?err, "principal name lookup failed; showing ids");
                return;
            }
        };
    for principal in perms.iter_mut().flat_map(|p| p.principals.iter_mut()) {
        if principal.display_name.is_some() {
            continue;
        }
        if let Some(object) = principal.id.as_ref().and_then(|id| found.get(id)) {
            principal.display_name = object.display_name.clone();
            if principal.detail.is_none() {
                principal.detail = object.mail.clone().or(object.user_principal_name.clone());
            }
        }
    }
}

pub(crate) fn to_resource_ref(
    r: ResolvedSharePointResource,
    input_url: String,
) -> SharePointResourceRef {
    SharePointResourceRef {
        level: r.level,
        site_id: r.site_id,
        site_url: r.site_url,
        site_name: r.site_name,
        list_id: r.list_id,
        list_name: r.list_name,
        item_id: r.item_id,
        drive_id: r.drive_id,
        is_folder: r.is_folder,
        display_path: r.display_path,
        input_url,
    }
}

/// Resolves a SharePoint URL to the securable a Selected grant would address,
/// so the UI can echo *what* it is about to touch before the operator commits.
#[tauri::command]
pub async fn resolve_sharepoint_resource(
    state: State<'_, AppState>,
    tenant_id: String,
    url: String,
) -> Result<SharePointResourceRef, UiError> {
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    let resolved = client
        .resolve_sharepoint_resource(&url)
        .await
        .map_err(sharepoint_item_err)?;
    Ok(to_resource_ref(resolved, url))
}

/// Grants `app_id` the `role` on each resolved target — the sub-site sibling of
/// [`convert_site_access_to_selected`].
///
/// Ordering matches the site path: grant the Selected appRole first
/// (idempotently), then the per-resource permissions. Nothing org-wide is
/// stripped here, because these scopes have no org-wide predecessor to strip —
/// an operator reaching for `Files.SelectedOperations.Selected` is granting
/// least-privilege access from the start, not converting an existing broad
/// grant. (Converting `Files.Read.All` is a separate, audit-driven flow.)
///
/// **Fail-closed on level.** Each target is checked with
/// [`selected_scope_accepts`] against the level `permission_value` grants at. A
/// mismatch — a site URL pasted while the cart holds a file scope — is recorded
/// as a warning and skipped, never granted one level up. This is the whole point
/// of resolving the URL first.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn grant_selected_item_access(
    state: State<'_, AppState>,
    tenant_id: String,
    sp_object_id: String,
    object_id: Option<String>,
    app_id: String,
    app_display_name: String,
    permission_value: String,
    target_urls: Vec<String>,
    role: String,
) -> Result<SelectedItemScopeResult, UiError> {
    require_grantable_roles(std::slice::from_ref(&role))?;
    let scope_level = selected_scope_level_for(Some(MICROSOFT_GRAPH_APP_ID), &permission_value)
        .filter(|l| l.breaks_inheritance())
        .ok_or_else(|| {
            UiError::validation(
                "unsupported_permission",
                format!(
                    "{permission_value} is not a sub-site Selected scope on Microsoft Graph; \
                 site-level access is granted with Sites.Selected"
                ),
            )
        })?;

    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    let (graph_sp_id, role_value_by_id) = graph_role_index(&client).await?;

    let mut warnings = Vec::new();

    // Read the assignments BEFORE the manifest PATCH, so a failed read aborts
    // with nothing mutated.
    let existing = client.list_app_role_assignments(&sp_object_id).await?;

    // 0-1. Declare the Selected permission on the app registration, then grant
    //      the appRole (idempotent) — without it in the token, the per-resource
    //      permissions below grant nothing at all.
    let GraphRoleGrant {
        declared_permission,
        granted_role_added,
    } = declare_and_grant_graph_role(
        &client,
        &state.cache,
        &GraphRolePrincipal {
            tenant_id: &tenant_id,
            object_id: object_id.as_deref(),
            sp_object_id: &sp_object_id,
            app_id: &app_id,
        },
        &graph_sp_id,
        &role_value_by_id,
        &existing,
        &permission_value,
    )
    .await?;

    // 2. Grant per resource. A target that fails to resolve, sits at the wrong
    //    level, or is rejected by SharePoint is reported and skipped — one bad
    //    URL must not discard the grants that did land.
    let roles = vec![role];
    let mut granted = Vec::new();
    for url in &dedupe_targets(&target_urls) {
        let resolved = match client.resolve_sharepoint_resource(url).await {
            Ok(r) => r,
            Err(err) => {
                // Through the module's own mapper, not `Display`: a 403 on the
                // subsite probe now propagates typed (the resolver used to
                // collapse it into "did not resolve"), and this is where its
                // `sharepoint_selected_items` remediation is spliced in — and
                // where Graph's raw body is kept out of the panel's warnings.
                let ui = sharepoint_item_err(err);
                warnings.push(format!("could not resolve '{url}': {}", ui.message));
                continue;
            }
        };
        if !selected_scope_accepts(scope_level, resolved.level) {
            warnings.push(format!(
                "'{url}' is a {}, which {permission_value} cannot grant against — it grants at the {} level",
                resolved.level.label(),
                scope_level.label()
            ));
            continue;
        }
        let outcome = match resolved.level {
            SelectedScopeLevel::List => {
                grant_on_list(&client, &resolved, &app_id, &app_display_name, &roles).await
            }
            SelectedScopeLevel::ListItem | SelectedScopeLevel::File => {
                grant_on_item(&client, &resolved, &app_id, &app_display_name, &roles).await
            }
            // Unreachable: `selected_scope_accepts` rejects a site target for
            // every sub-site scope, and `scope_level` is sub-site by construction.
            SelectedScopeLevel::Site => Err(UiError::validation(
                "level_mismatch",
                "site-level access is granted with Sites.Selected".to_string(),
            )),
        };
        match outcome {
            Ok(perm) => granted.push(SelectedItemGrantDto {
                resource: to_resource_ref(resolved, url.clone()),
                permission: perm,
            }),
            Err(err) => warnings.push(format!(
                "failed to grant access to '{url}': {}",
                err.message
            )),
        }
    }

    // The Selected appRole grant changes the SP's app-role assignments:
    // detail-pane and audit state, never a list row, so the detail tier.
    // Invalidate only on this success path.
    //
    // The per-resource permissions are deliberately NOT swept into
    // `invalidate_site_sweep`: that index holds `/sites/{id}/permissions` rows,
    // and a list or item grant creates none of those. Busting it here would
    // force a tenant-wide re-sweep for a change it cannot observe.
    invalidate_app_detail_state(&state.cache, &tenant_id);

    // 3. Record each landed grant on the app registration, the only per-app
    //    list of them there is (Graph can't enumerate an app's item grants).
    let recorded_on_app = crate::commands::sharepoint_item_scopes::record_granted(
        &state,
        &client,
        &tenant_id,
        object_id.as_deref(),
        &granted,
        &mut warnings,
    )
    .await;

    Ok(SelectedItemScopeResult {
        granted_role_added,
        declared_permission,
        granted,
        warnings,
        recorded_on_app,
    })
}

async fn grant_on_list(
    client: &azapptoolkit_graph::GraphClient,
    resolved: &ResolvedSharePointResource,
    app_id: &str,
    app_display_name: &str,
    roles: &[String],
) -> Result<SelectedItemPermissionDto, UiError> {
    let list_id = resolved
        .list_id
        .as_deref()
        .ok_or_else(|| UiError::validation("unresolved", "no list id for this target"))?;
    client
        .grant_list_permission(&resolved.site_id, list_id, app_id, app_display_name, roles)
        .await
        .map(to_item_dto)
        .map_err(sharepoint_item_err)
}

async fn grant_on_item(
    client: &azapptoolkit_graph::GraphClient,
    resolved: &ResolvedSharePointResource,
    app_id: &str,
    app_display_name: &str,
    roles: &[String],
) -> Result<SelectedItemPermissionDto, UiError> {
    let (Some(list_id), Some(item_id)) = (resolved.list_id.as_deref(), resolved.item_id.as_deref())
    else {
        return Err(UiError::validation(
            "unresolved",
            "no list/item id for this target",
        ));
    };
    client
        .grant_list_item_permission(
            &resolved.site_id,
            list_id,
            item_id,
            app_id,
            app_display_name,
            roles,
        )
        .await
        .map(to_item_dto)
        .map_err(sharepoint_item_err)
}

/// Lists the application permissions on the resource `url` names.
///
/// This is a **verify-by-URL** read, not a reverse lookup: there is no
/// `appId → items` index and no way to enumerate every folder in a tenant, so
/// an empty result means "this resource has no app grants", never "this app has
/// no item-level access anywhere".
#[tauri::command]
pub async fn list_selected_item_permissions(
    state: State<'_, AppState>,
    tenant_id: String,
    url: String,
) -> Result<Vec<SelectedItemPermissionDto>, UiError> {
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    let resolved = client
        .resolve_sharepoint_resource(&url)
        .await
        .map_err(sharepoint_item_err)?;
    let perms = read_permissions(&client, &resolved).await?;
    let mut rows: Vec<SelectedItemPermissionDto> = perms.into_iter().map(to_item_dto).collect();
    fill_principal_names(&client, &mut rows).await;
    Ok(rows)
}

async fn read_permissions(
    client: &azapptoolkit_graph::GraphClient,
    resolved: &ResolvedSharePointResource,
) -> Result<Vec<SelectedPermission>, UiError> {
    match (resolved.list_id.as_deref(), resolved.item_id.as_deref()) {
        (Some(list_id), Some(item_id)) => client
            .list_list_item_permissions(&resolved.site_id, list_id, item_id)
            .await
            .map_err(sharepoint_item_err),
        (Some(list_id), None) => client
            .list_list_permissions(&resolved.site_id, list_id)
            .await
            .map_err(sharepoint_item_err),
        // A site URL: the site endpoint owns that read.
        (None, _) => Err(UiError::validation(
            "level_mismatch",
            "use the site permissions view for a site collection".to_string(),
        )),
    }
}

/// Revokes one permission from the resource `url` names.
#[tauri::command]
pub async fn remove_selected_item_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    url: String,
    permission_id: String,
) -> Result<(), UiError> {
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    let resolved = client
        .resolve_sharepoint_resource(&url)
        .await
        .map_err(sharepoint_item_err)?;
    match (resolved.list_id.as_deref(), resolved.item_id.as_deref()) {
        (Some(list_id), Some(item_id)) => client
            .remove_list_item_permission(&resolved.site_id, list_id, item_id, &permission_id)
            .await
            .map_err(sharepoint_item_err),
        (Some(list_id), None) => client
            .remove_list_permission(&resolved.site_id, list_id, &permission_id)
            .await
            .map_err(sharepoint_item_err),
        (None, _) => Err(UiError::validation(
            "level_mismatch",
            "use the site permissions view for a site collection".to_string(),
        )),
    }
}

// ---------------- Site-permission sweep (reverse lookup) ----------------

/// In-flight cap on concurrent *chunk tasks*, each a `$batch` fan-out over up
/// to [`SWEEP_BATCH`] sites — so up to `SWEEP_CONCURRENCY × SWEEP_BATCH` site
/// reads, in `$batch` POSTs of 20, are in flight, not six single reads.
/// SharePoint throttles harder than the directory endpoints, so this stays
/// below the audit's initial cap, and the `ConcurrencyThrottle` halves it on
/// 429s. The per-request retry (`scoped_get_retried` / the batch transport)
/// absorbs a transient 429 with `Retry-After` honored; only a *persistently*
/// failing site lands in `sites_failed`.
const SWEEP_CONCURRENCY: usize = 6;
/// Sites resolved per progress step. The Graph `$batch` cap is 20 sub-requests,
/// and `batch_list_site_permissions` chunks internally, so this is the
/// **cancellation and progress** granularity: small enough that Cancel feels
/// immediate and a whole-batch failure costs one step, large enough that the
/// batching win isn't given back in round trips.
const SWEEP_BATCH: usize = 100;
/// Safety cap on sites per sweep — prevents a pathological tenant from
/// queueing an unbounded scan. Hitting it is *reported*
/// (`SiteSweepResult::truncated`, logged at warn), never silent — raise it if
/// a tenant legitimately hits it.
const MAX_SITES_PER_SWEEP: usize = 5_000;

/// Tenant-prefixed cache key (cross-tenant leakage guard, same convention as
/// the list caches).
fn sweep_cache_key(tenant_id: &str) -> String {
    format!("{tenant_id}|site_sweep")
}

/// Drops the cached sweep for this tenant. The sweep lives under its own
/// `CacheKind::Audit` key, so neither `invalidate_app_lists` nor
/// `invalidate_audit_cache` reaches it — every mutation that changes a site's
/// per-app permissions must call this on its success path, or the Resource
/// Access reverse-lookup (a security-posture view) keeps showing the
/// pre-mutation grants until the TTL expires.
pub(crate) fn invalidate_site_sweep(cache: &Cache, tenant_id: &str) {
    cache.invalidate(CacheKind::Audit, &sweep_cache_key(tenant_id));
}

/// Folds one site's permission-read outcome into the sweep accumulators. A
/// failed site counts toward `sites_failed` — it must never read as "no
/// grants", so coverage is never overstated.
fn fold_site_result(
    rows: &mut Vec<SiteAppGrantRow>,
    sites_scanned: &mut usize,
    sites_failed: &mut usize,
    site: &Site,
    result: Result<Vec<SitePermission>, azapptoolkit_graph::GraphError>,
) {
    match result {
        Ok(perms) => {
            *sites_scanned += 1;
            for p in perms {
                // App grants only — a site permission without an application
                // identity (e.g. user-granted) isn't part of this index.
                let app = p
                    .granted_to_identities
                    .into_iter()
                    .find_map(|s| s.application);
                let Some(app) = app else { continue };
                rows.push(SiteAppGrantRow {
                    site_id: site.id.clone(),
                    site_display_name: site.display_name.clone(),
                    site_url: site.web_url.clone(),
                    permission_id: p.id,
                    roles: p.roles,
                    app_id: app.id,
                    app_display_name: app.display_name,
                });
            }
        }
        Err(err) => {
            *sites_failed += 1;
            tracing::warn!(site = %site.id, ?err, "site sweep: permission read failed");
        }
    }
}

/// Sweeps every enumerable site's application permissions to build the
/// reverse-lookup index Graph doesn't offer: site → apps ("who can touch this
/// site?") and, filtered by appId, app → sites (the `Sites.Selected` blind
/// spot). Enumerates sites via `/sites?search=*` (team/communication sites;
/// OneDrive personal sites aren't returned by the delegated search endpoint),
/// then reads `/sites/{id}/permissions` in `$batch` chunks under an adaptive
/// in-flight cap.
///
/// Long-running: emits `site-sweep-progress` after each chunk of
/// [`SWEEP_BATCH`] sites and polls its own `AppState.site_sweep_cancel` token
/// (stopped only by [`cancel_site_sweep`] and by sign-out
/// (`AppState::forget_tenant`), so no other run's Cancel can abort
/// it, and it aborts no other run) between dispatches. Per-site read failures increment `sites_failed`
/// rather than aborting or silently reading as "no grants", so coverage is
/// never overstated. The result is cached (60-minute audit TTL) under a
/// tenant-prefixed key; a cancelled or partially-failed run is never cached,
/// and a run that hit [`MAX_SITES_PER_SWEEP`] is cached *with* `truncated` set
/// so it is never presented as complete.
#[tauri::command]
pub async fn sweep_site_permissions(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Arc<SiteSweepResult>, UiError> {
    // Claimed before the first await: `list_all_sites` walks every site in the
    // tenant, and a token claimed after it carries a higher generation than a
    // cancel issued during it, which `is_cancelled()` then discards. Pinned by
    // `repo_invariants::cancel`.
    let cancel = state.site_sweep_cancel.claim();
    // Watched before the first await too: a site grant or removal mid-sweep
    // busts this key, and the store below must not undo that with the
    // pre-mutation index.
    let sweep_watch = state
        .cache
        .generation_for(CacheKind::Audit, &sweep_cache_key(&tenant_id));
    let client = sharepoint_client_checked(&state, &tenant_id).await?;

    let (sites, truncated) = client
        .list_all_sites(MAX_SITES_PER_SWEEP)
        .await
        .map_err(sharepoint_err)?;
    let total = sites.len();
    if truncated {
        tracing::warn!(
            cap = MAX_SITES_PER_SWEEP,
            "site sweep: site enumeration hit the cap; coverage is partial"
        );
    }
    emit_progress(
        &app_handle,
        crate::dto::events::SITE_SWEEP_PROGRESS,
        SiteSweepProgress {
            done: 0,
            total,
            current_site: None,
            cancelled: false,
        },
    );

    // Adaptive throttling, like the audit and DR fan-outs. `/sites/*` is the
    // throttle-happiest endpoint family in the transport, and this sweep
    // previously ran at a FIXED width with no backoff — the per-request retry
    // absorbed 429s but the in-flight cap never yielded, so a throttling tenant
    // just ground through retries.
    //
    // Through the shared `FanOutMeter` like every other capped fan-out. Only its
    // cap is read: progress counts SITES on the collect side below (one joined
    // result is a whole `$batch` chunk), so the per-task tick goes unused.
    let meter = FanOutMeter::attach(client.clone(), SWEEP_CONCURRENCY);

    let mut rows: Vec<SiteAppGrantRow> = Vec::new();
    let mut sites_scanned = 0usize;
    let mut sites_failed = 0usize;
    let mut done = 0usize;

    // `/sites/{id}/permissions` is a plain GET, so the sweep reads them in
    // `$batch` POSTs of 20 instead of one request per site — at the 5000-site
    // cap that is 250 round trips rather than 5000. Chunked so cancellation and
    // progress stay responsive between batches, and so a whole-batch failure
    // costs one chunk rather than the run.
    // Chunks are independent and results are folded per-chunk, so order does not
    // matter — dispatch them through the shared driver with the meter as the
    // cap. Previously this loop awaited one chunk at a time, which meant the
    // tracker attached above was never READ: the observer dutifully halved a
    // number nothing consulted, so the adaptive back-off the comment advertises
    // did not exist and the walk was fully serial besides.
    let chunks: Vec<Vec<Site>> = sites.chunks(SWEEP_BATCH).map(<[Site]>::to_vec).collect();
    let session = SessionDead::new();
    let stopped_early = dispatch_capped(
        chunks,
        || meter.limit(),
        |chunk| {
            // A dead session fails every remaining chunk identically — an
            // incomplete sweep must not be reported as the tenant's full
            // Sites.Selected picture.
            if cancel.is_cancelled() || session.is_dead() {
                return None;
            }
            let client = client.clone();
            let cancel = cancel.clone();
            Some(tokio::spawn(async move {
                let ids: Vec<String> = chunk.iter().map(|s| s.id.clone()).collect();
                match client.batch_list_site_permissions(&ids).await {
                    Ok(results) => (chunk, results),
                    Err(err) => {
                        // Whole-batch failure degrades to per-site reads rather
                        // than losing the chunk (the batched fan-out contract).
                        tracing::warn!(?err, "site sweep: batch failed; falling back to per-site");
                        let mut out = Vec::with_capacity(chunk.len());
                        for site in &chunk {
                            if cancel.is_cancelled() {
                                break;
                            }
                            out.push(client.list_site_permissions(&site.id).await);
                        }
                        (chunk, out)
                    }
                }
            }))
        },
        |joined| {
            let Ok((chunk, results)) = joined else {
                tracing::warn!("site sweep: chunk task failed to join");
                return;
            };
            for err in results.iter().filter_map(|r| r.as_ref().err()) {
                session.note_code(err.ui_code());
            }
            // A degraded chunk cut short by cancellation yields fewer results
            // than sites; `zip` folds only the pairs that exist.
            for (site, result) in chunk.iter().zip(results) {
                fold_site_result(
                    &mut rows,
                    &mut sites_scanned,
                    &mut sites_failed,
                    site,
                    result,
                );
            }
            done += chunk.len();
            emit_progress(
                &app_handle,
                crate::dto::events::SITE_SWEEP_PROGRESS,
                SiteSweepProgress {
                    done,
                    total,
                    current_site: chunk
                        .last()
                        .and_then(|s| s.display_name.clone().or_else(|| s.web_url.clone())),
                    cancelled: cancel.is_cancelled(),
                },
            );
        },
    )
    .await;
    if session.is_dead() {
        // Never cache or return a dead-session sweep: `AppSiteAccessDto::from_sweep`
        // reads an empty site list as "no grants" whenever the sweep claims to
        // be complete, so a partial run understates an app's reach.
        return Err(session.err("the SharePoint site sweep"));
    }
    let cancelled = stopped_early || cancel.is_cancelled();
    tracing::info!(
        total,
        sites_scanned,
        sites_failed,
        cancelled,
        truncated,
        "site sweep complete"
    );
    rows.sort_by(|a, b| {
        a.site_display_name
            .cmp(&b.site_display_name)
            .then_with(|| a.app_display_name.cmp(&b.app_display_name))
    });

    let result = Arc::new(SiteSweepResult {
        tenant_id: tenant_id.clone(),
        total_sites: total,
        sites_scanned,
        sites_failed,
        rows,
        cancelled,
        truncated,
    });
    // Never cache a cancelled or partially-failed sweep: serving that gap for
    // the next hour would overstate coverage — the "coverage is never
    // overstated" promise extends to the cache. A capped sweep IS cached, with
    // its flag; see `sweep_is_cacheable` for why that is safe.
    //
    // Typed: the cached readers (`get_cached_site_sweep`, every per-app panel's
    // `get_app_site_access`) take a refcount clone instead of decoding up to
    // `MAX_SITES_PER_SWEEP` sites' grants from JSON per read. Read only with
    // `get_typed` — an untyped `get` on this entry misses.
    if sweep_is_cacheable(cancelled, sites_failed) {
        state
            .cache
            .put_typed_if_current(sweep_watch, Arc::clone(&result));
    }
    Ok(result)
}

/// Whether a finished sweep may be written to the sweep cache.
///
/// A cancelled or partially-failed run is a *transient* prefix — a re-run can
/// complete it — so caching it would serve the gap for an hour. A run that hit
/// [`MAX_SITES_PER_SWEEP`] IS cached: the cap is deterministic, so a re-run
/// would cost another 250 `$batch` round trips for the same prefix. That is
/// safe only because `SiteSweepResult::truncated` rides along and
/// `AppSiteAccessDto::is_complete()` folds it, so no consumer — the per-app
/// panel, the Sites tab summary or the export — can read the cached prefix as
/// "no grants" (pinned by `a_capped_sweep_is_cached_but_never_reads_complete`).
///
/// Extracted from [`sweep_site_permissions`] purely so it can be table-tested,
/// like the audit's `run_is_cacheable`; that function takes a Tauri `State`.
fn sweep_is_cacheable(cancelled: bool, sites_failed: usize) -> bool {
    !cancelled && sites_failed == 0
}

/// Signals an in-progress [`sweep_site_permissions`] run to stop at the next
/// dispatch boundary. Covers both the Resource Access Sites tab and the per-app
/// site panel: same sweep, same flag (`AppState.site_sweep_cancel`).
#[tauri::command]
pub fn cancel_site_sweep(state: State<'_, AppState>) {
    state.site_sweep_cancel.cancel();
}

/// Returns the cached sweep for this tenant, if one finished within the cache
/// TTL — so the view (and any future surface) can render without re-scanning.
/// A capped run is served with its `truncated` flag, which the view renders as
/// a coverage caveat.
///
/// `async` (off the main thread) and answering with the cached `Arc` — no copy
/// of the sweep before serialization. Pinned by
/// `repo_invariants::cache::cached_scan_reads_are_async_commands`.
#[tauri::command]
pub async fn get_cached_site_sweep(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Option<Arc<SiteSweepResult>>, UiError> {
    // A cache-only answer makes the `tenant_id` argument the only thing deciding
    // whose directory data is returned, so prove the session first (AGENTS.md's
    // #1 footgun). Pinned by `a_command_answering_from_cache_alone_checks_the_session`.
    let Some(_) = state.auth.tenant_context(&tenant_id) else {
        return Ok(None);
    };
    Ok(state
        .cache
        .get_typed::<SiteSweepResult>(CacheKind::Audit, &sweep_cache_key(&tenant_id)))
}

/// The sites one principal can reach under `Sites.Selected`, and the roles it
/// holds on each — read from the cached tenant sweep, `None` when no finished
/// sweep is cached (the caller then offers to run one). A capped run is served
/// with its `truncated` flag, which `is_complete()` carries, so the panel never
/// reads the prefix as "no grants".
///
/// This is the per-app read of the same index the Resource Access Sites tab
/// builds, and it exists because Graph has **no reverse `appId → sites`
/// lookup**: the only way to answer "which sites is this app scoped to?" is to
/// read every site's permissions once. That scan is tenant-wide, so it is shared
/// — one sweep serves every app's panel for the cache TTL.
///
/// Filters **backend-side** on purpose. A tenant sweep holds up to
/// [`MAX_SITES_PER_SWEEP`] sites' grants; shipping all of them across the IPC
/// bridge so one collapsible panel could keep a handful would put a multi-MB
/// payload on the Permissions tab of every app that declares a `Sites.*`
/// permission.
///
/// `async`, and the projection borrows the typed cached sweep: it used to
/// decode the whole tenant sweep from JSON on the main thread per panel open.
#[tauri::command]
pub async fn get_app_site_access(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<Option<AppSiteAccessDto>, UiError> {
    // A cache-only answer makes the `tenant_id` argument the only thing deciding
    // whose directory data is returned, so prove the session first (AGENTS.md's
    // #1 footgun). Pinned by `a_command_answering_from_cache_alone_checks_the_session`.
    let Some(_) = state.auth.tenant_context(&tenant_id) else {
        return Ok(None);
    };
    Ok(state
        .cache
        .get_typed::<SiteSweepResult>(CacheKind::Audit, &sweep_cache_key(&tenant_id))
        .map(|sweep| AppSiteAccessDto::from_sweep(&sweep, &app_id)))
}

/// Exports the (frontend-filtered) site-grant rows to CSV/JSON via the OS save
/// dialog. Returns the path, or `None` if the user cancelled.
///
/// "Which apps can touch this site?" — and its inverse — is an answer an
/// operator is routinely asked to produce in writing, and until this existed the
/// only way out of the app was a screenshot. The rows come from the frontend
/// because the filter that produced them does: one search box serves both
/// directions, so what is on screen is the export the operator means.
///
/// `summary` is the panel's own coverage sentence, and it is load-bearing. A
/// site whose permission read failed contributes no rows, and this index is the
/// ONLY way `Sites.Selected` reach is knowable at all — so a file that dropped
/// "(2 failed — coverage is partial)" would present a partial sweep as the
/// complete answer, which is precisely the claim the sweep refuses to make on
/// screen.
#[tauri::command]
pub async fn save_site_access_to_file(
    app_handle: AppHandle,
    rows: Vec<SiteAppGrantRow>,
    summary: String,
    format: String,
) -> Result<Option<String>, UiError> {
    crate::commands::export::save_export_via_dialog(
        &app_handle,
        "site-access",
        &format,
        || site_access_to_csv(&rows, &summary),
        || coverage_json(&summary, &rows),
    )
    .await
}

/// Serializes site-grant rows as CSV under the shared coverage comment block.
/// Site and app display names are directory data, so every field is routed
/// through `csv_field` (formula-injection guard + delimiter quoting).
fn site_access_to_csv(rows: &[SiteAppGrantRow], summary: &str) -> String {
    let mut out = coverage_comment_block(
        "azapptoolkit — SharePoint site access (per-site application permissions)",
        summary,
    );
    out.push_str("Site,SiteUrl,SiteId,Application,AppId,Roles,PermissionId\n");
    for r in rows {
        let row = [
            csv_field(r.site_display_name.as_deref().unwrap_or("")),
            csv_field(r.site_url.as_deref().unwrap_or("")),
            csv_field(&r.site_id),
            csv_field(r.app_display_name.as_deref().unwrap_or("")),
            csv_field(r.app_id.as_deref().unwrap_or("")),
            // One cell, semicolon-joined: an app commonly holds `read` and
            // `write` on the same site, and a comma would split the row.
            csv_field(&r.roles.join("; ")),
            csv_field(&r.permission_id),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // `is_sharepoint_orgwide` itself is unit-tested in azapptoolkit_core::scoping.
    use crate::commands::export::csv_columns;

    fn grant_row(site: &str, app: &str) -> SiteAppGrantRow {
        SiteAppGrantRow {
            site_id: format!("contoso.sharepoint.com,{site}"),
            site_display_name: Some(site.into()),
            site_url: Some(format!("https://contoso.sharepoint.com/sites/{site}")),
            permission_id: "perm-1".into(),
            roles: vec!["read".into(), "write".into()],
            app_id: Some("11111111-1111-1111-1111-111111111111".into()),
            app_display_name: Some(app.into()),
        }
    }

    #[test]
    fn site_csv_leads_with_the_coverage_line_then_a_header_and_one_row_each() {
        let csv = site_access_to_csv(
            &[
                grant_row("Finance", "Contoso API"),
                grant_row("HR", "Fabrikam Web"),
            ],
            "2 app grants across 2 sites — scanned 140 of 142 sites (2 failed — coverage is partial)",
        );
        let lines: Vec<&str> = csv.lines().collect();
        // The sweep never overstates coverage on screen; the file must not either.
        assert!(lines[1].contains("coverage is partial"));
        let header = lines.iter().position(|l| l.starts_with("Site,")).unwrap();
        assert_eq!(lines.len() - header, 3); // header + 2 rows
        assert!(lines[header + 1].starts_with("Finance,"));
    }

    #[test]
    fn site_csv_keeps_multiple_roles_in_one_cell() {
        // Comma-joining roles would silently shift every column right of them —
        // as would the site id's own commas (a Graph site id is literally
        // `hostname,siteId,webId`), which is why the count is quote-aware.
        let csv = site_access_to_csv(&[grant_row("Finance", "Contoso API")], "complete");
        assert!(csv.contains("read; write"));
        let header = csv.lines().position(|l| l.starts_with("Site,")).unwrap();
        let columns = csv_columns(csv.lines().nth(header).unwrap());
        assert_eq!(csv_columns(csv.lines().nth(header + 1).unwrap()), columns);
    }

    #[test]
    fn site_csv_neutralizes_formula_injection_in_a_display_name() {
        // CWE-1236: site and app names are directory data. The comma in the
        // payload is the point: neutralization has to compose with quoting.
        let csv = site_access_to_csv(&[grant_row("Finance", "=cmd|'/c calc',A1")], "complete");
        assert!(csv.contains("\"'=cmd|'/c calc',A1\""));
    }

    #[test]
    fn org_wide_removal_requires_a_landed_site_grant() {
        // Never strip the broad grant if every site grant failed — that would
        // leave the principal with no access at all.
        assert!(should_remove_orgwide(true, true));
        assert!(!should_remove_orgwide(true, false));
        assert!(!should_remove_orgwide(false, true));
        assert!(!should_remove_orgwide(false, false));
    }

    use azapptoolkit_core::models::{SiteIdentity, SiteIdentitySet};
    use azapptoolkit_graph::GraphError;

    fn site(id: &str) -> Site {
        Site {
            id: id.into(),
            display_name: Some(id.to_uppercase()),
            web_url: None,
        }
    }

    fn app_perm(perm_id: &str, app_id: &str) -> SitePermission {
        SitePermission {
            id: perm_id.into(),
            roles: vec!["read".into()],
            granted_to_identities: vec![SiteIdentitySet {
                application: Some(SiteIdentity {
                    id: Some(app_id.into()),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        }
    }

    #[test]
    fn a_failed_site_increments_failed_and_never_reads_as_no_grants() {
        let (mut rows, mut scanned, mut failed) = (Vec::new(), 0usize, 0usize);
        fold_site_result(
            &mut rows,
            &mut scanned,
            &mut failed,
            &site("s1"),
            Err(GraphError::Throttled {
                retry_after_secs: Some(5),
            }),
        );
        assert_eq!((scanned, failed, rows.len()), (0, 1, 0));
        // A later success still folds normally alongside the recorded failure.
        fold_site_result(
            &mut rows,
            &mut scanned,
            &mut failed,
            &site("s2"),
            Ok(vec![app_perm("perm-1", "app-1")]),
        );
        assert_eq!((scanned, failed, rows.len()), (1, 1, 1));
        assert_eq!(rows[0].app_id.as_deref(), Some("app-1"));
    }

    #[test]
    fn site_mutations_bust_the_sweep_cache_tenant_scoped() {
        // grant_site_access / remove_site_permission / convert_site_access_to_
        // selected change exactly what the cached sweep indexes, and the sweep
        // key is NOT covered by invalidate_app_lists or invalidate_audit_cache
        // (different Audit-kind keys) — so the mutations bust it directly. A
        // stale sweep shows revoked access as still present in a
        // security-posture view; the other tenant's sweep must survive.
        let cache = Cache::new();
        let sweep = SiteSweepResult {
            tenant_id: "t1".into(),
            total_sites: 1,
            sites_scanned: 1,
            sites_failed: 0,
            rows: Vec::new(),
            cancelled: false,
            truncated: false,
        };
        // Typed, as the sweep stores it: an untyped `get` would miss either way
        // and make the survival assertion meaningless.
        let sweep = std::sync::Arc::new(sweep);
        cache.put_typed(
            CacheKind::Audit,
            sweep_cache_key("t1"),
            std::sync::Arc::clone(&sweep),
        );
        cache.put_typed(CacheKind::Audit, sweep_cache_key("t2"), sweep);

        invalidate_site_sweep(&cache, "t1");

        assert!(
            cache
                .get_typed::<SiteSweepResult>(CacheKind::Audit, &sweep_cache_key("t1"))
                .is_none()
        );
        assert!(
            cache
                .get_typed::<SiteSweepResult>(CacheKind::Audit, &sweep_cache_key("t2"))
                .is_some(),
            "other tenant must survive"
        );
    }

    /// The cache guard and the completeness verdict, exhaustively — the pair is
    /// what proves a cached capped sweep cannot be read as "no grants".
    ///
    /// Cacheability ignores `truncated` on purpose (the cap is deterministic;
    /// re-sweeping 5000 sites buys the same prefix), but completeness must fold
    /// it: a sweep with zero failures and no cancel that stopped at the cap is
    /// exactly the shape that used to read as complete and was cached as such.
    /// Every combination, because the failure mode is one condition dropped
    /// from a conjunction, which a single-case test would miss.
    #[test]
    fn a_capped_sweep_is_cached_but_never_reads_complete() {
        for &cancelled in &[false, true] {
            for &sites_failed in &[0usize, 1] {
                for &truncated in &[false, true] {
                    assert_eq!(
                        sweep_is_cacheable(cancelled, sites_failed),
                        !cancelled && sites_failed == 0,
                        "cancelled={cancelled} sites_failed={sites_failed} truncated={truncated} \
                         — a transient prefix cached here serves the gap for an hour; \
                         the cap alone must not block caching"
                    );
                    let sweep = SiteSweepResult {
                        tenant_id: "t".into(),
                        total_sites: 2,
                        sites_scanned: 2 - sites_failed,
                        sites_failed,
                        rows: Vec::new(),
                        cancelled,
                        truncated,
                    };
                    assert_eq!(
                        AppSiteAccessDto::from_sweep(&sweep, "app-1").is_complete(),
                        !cancelled && sites_failed == 0 && !truncated,
                        "cancelled={cancelled} sites_failed={sites_failed} truncated={truncated} \
                         — an empty per-app list over a prefix is not 'no grants'"
                    );
                }
            }
        }
    }

    /// The export copies the panel's coverage sentence verbatim, so a cap
    /// caveat in the summary reaches the CSV comment block unchanged.
    #[test]
    fn site_csv_carries_a_cap_caveat_from_the_summary() {
        let csv = site_access_to_csv(
            &[grant_row("Finance", "Contoso API")],
            "1 app grant across 1 site — scanned 5000 of 5000 sites — stopped at the 5000-site scan cap, coverage is partial",
        );
        // Title line, then the coverage line.
        let coverage = csv.lines().nth(1).unwrap_or_default();
        assert!(
            coverage.contains("stopped at the 5000-site scan cap"),
            "coverage line must carry the cap caveat: {coverage}"
        );
    }

    #[test]
    fn non_application_grants_are_excluded_from_the_index() {
        // A user-granted site permission has no application identity; the
        // site still counts as scanned but contributes no rows.
        let (mut rows, mut scanned, mut failed) = (Vec::new(), 0usize, 0usize);
        let user_perm = SitePermission {
            id: "perm-u".into(),
            roles: vec!["read".into()],
            granted_to_identities: vec![SiteIdentitySet::default()],
        };
        fold_site_result(
            &mut rows,
            &mut scanned,
            &mut failed,
            &site("s1"),
            Ok(vec![user_perm, app_perm("perm-a", "app-1")]),
        );
        assert_eq!((scanned, failed, rows.len()), (1, 0, 1));
        assert_eq!(rows[0].permission_id, "perm-a");
    }

    #[test]
    fn dedupe_targets_collapses_the_spellings_sharepoint_treats_as_one() {
        let urls = [
            "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices",
            // Trailing slash, and SharePoint paths are case-insensitive.
            "https://contoso.sharepoint.com/sites/Finance/Shared Documents/invoices/",
            "  https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices  ",
            // A genuinely different folder survives.
            "https://contoso.sharepoint.com/sites/Finance/Shared Documents/Receipts",
        ]
        .map(String::from);
        let out = dedupe_targets(&urls);
        assert_eq!(out.len(), 2, "three spellings of one folder are one target");
        // The first spelling wins, so the operator sees back what they typed.
        assert_eq!(out[0], urls[0]);
        assert_eq!(out[1], urls[3]);
    }

    /// The gate that keeps a `Files.*` grant off a site or a plain list item.
    /// Held here as well as in `azapptoolkit-core` because this command is the
    /// only caller that can act on the answer.
    #[test]
    fn the_grant_refuses_a_target_the_scope_cannot_reach() {
        use azapptoolkit_core::scoping::SelectedScopeLevel::{File, List, ListItem, Site};

        // A folder in a document library resolves at File level, which is what
        // both item scopes are for.
        assert!(selected_scope_accepts(File, File));
        assert!(selected_scope_accepts(ListItem, File));
        // A site URL pasted while a file scope is in the cart — the mistake the
        // resolve-first step exists to catch.
        assert!(!selected_scope_accepts(File, Site));
        assert!(!selected_scope_accepts(List, Site));
        // And a file scope never reaches an item in a plain list.
        assert!(!selected_scope_accepts(File, ListItem));
    }

    /// Only the three sub-site scopes drive this command; `Sites.Selected` has
    /// its own conversion path and must not be routed here.
    #[test]
    fn only_sub_site_selected_scopes_reach_the_item_grant() {
        use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
        let level = |v: &str| {
            selected_scope_level_for(Some(MICROSOFT_GRAPH_APP_ID), v)
                .filter(|l| l.breaks_inheritance())
        };
        for v in [
            "Files.SelectedOperations.Selected",
            "Lists.SelectedOperations.Selected",
            "ListItems.SelectedOperations.Selected",
        ] {
            assert!(level(v).is_some(), "{v} drives the item grant");
        }
        for v in ["Sites.Selected", "Sites.Read.All", "Files.Read.All"] {
            assert!(level(v).is_none(), "{v} must not route to the item grant");
        }
    }

    #[test]
    fn orgwide_strip_selects_only_orgwide_sites_roles_on_graph() {
        let index: HashMap<String, String> = [
            ("role-read-all".to_string(), "Sites.Read.All".to_string()),
            ("role-selected".to_string(), "Sites.Selected".to_string()),
        ]
        .into();
        let on = |resource: &str, role: &str| AppRoleAssignment {
            id: "a".into(),
            resource_id: resource.into(),
            app_role_id: role.into(),
            ..Default::default()
        };
        assert_eq!(
            orgwide_sites_value("graph-sp", &index, &on("graph-sp", "role-read-all")).as_deref(),
            Some("Sites.Read.All")
        );
        // Sites.Selected IS the confinement — never stripped by the conversion.
        assert_eq!(
            orgwide_sites_value("graph-sp", &index, &on("graph-sp", "role-selected")),
            None
        );
        // Graph's role id on another resource is not Graph's grant.
        assert_eq!(
            orgwide_sites_value("graph-sp", &index, &on("spo-sp", "role-read-all")),
            None
        );
        // A role the Graph index does not know is left alone.
        assert_eq!(
            orgwide_sites_value("graph-sp", &index, &on("graph-sp", "role-unknown")),
            None
        );
    }

    #[tokio::test]
    async fn a_held_selected_role_is_neither_regranted_nor_declared_for_an_sp_only_principal() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex(r"/appRoleAssignments$"))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(path_regex(r"^/v1\.0/applications"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"/servicePrincipals/sp1$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sp1", "appId": "app-1", "displayName": "App"
            })))
            .mount(&server)
            .await;

        let client = crate::commands::test_support::mock_graph(&server);
        let index: HashMap<String, String> =
            [("role-selected".to_string(), "Sites.Selected".to_string())].into();
        let existing = vec![AppRoleAssignment {
            id: "a1".into(),
            resource_id: "graph-sp".into(),
            app_role_id: "role-selected".into(),
            ..Default::default()
        }];
        let out = declare_and_grant_graph_role(
            &client,
            &Cache::new(),
            &GraphRolePrincipal {
                tenant_id: "t1",
                object_id: None,
                sp_object_id: "sp1",
                app_id: "app-1",
            },
            "graph-sp",
            &index,
            &existing,
            SP_SITES_SELECTED,
        )
        .await
        .expect("nothing to do is success");
        assert!(!out.declared_permission);
        assert!(!out.granted_role_added);
    }

    /// The webview sends `sp_object_id`, `object_id` and `app_id` as three
    /// separate arguments. A pairing that drifted would assign the appRole to
    /// one principal while another app received the per-resource permission,
    /// so both objects are resolved and checked against `app_id` before any
    /// write — and nothing is declared, assigned or granted on a mismatch.
    #[tokio::test]
    async fn a_principal_that_is_not_the_named_app_is_refused_before_any_write() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/servicePrincipals/sp1$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sp1", "appId": "someone-else", "displayName": "Other"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;

        let client = crate::commands::test_support::mock_graph(&server);
        let index: HashMap<String, String> =
            [("role-selected".to_string(), "Sites.Selected".to_string())].into();
        let err = declare_and_grant_graph_role(
            &client,
            &Cache::new(),
            &GraphRolePrincipal {
                tenant_id: "t1",
                object_id: None,
                sp_object_id: "sp1",
                app_id: "app-1",
            },
            "graph-sp",
            &index,
            &[],
            SP_SITES_SELECTED,
        )
        .await;
        let Err(err) = err else {
            panic!("a service principal of another app must be refused");
        };
        assert_eq!(err.code, "principal_mismatch", "{err:?}");
    }

    /// The app-registration half of the pairing: the SP is this app's, but the
    /// `object_id` names another registration. Nothing is patched or posted.
    #[tokio::test]
    async fn a_registration_that_is_not_the_named_app_is_refused_before_any_write() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/servicePrincipals/sp1$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sp1", "appId": "app-1", "displayName": "App"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"/applications/obj-other$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "obj-other", "appId": "someone-else", "displayName": "Other",
                "requiredResourceAccess": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;

        let client = crate::commands::test_support::mock_graph(&server);
        let index: HashMap<String, String> =
            [("role-selected".to_string(), "Sites.Selected".to_string())].into();
        let err = declare_and_grant_graph_role(
            &client,
            &Cache::new(),
            &GraphRolePrincipal {
                tenant_id: "t1",
                object_id: Some("obj-other"),
                sp_object_id: "sp1",
                app_id: "app-1",
            },
            "graph-sp",
            &index,
            &[],
            SP_SITES_SELECTED,
        )
        .await;
        let Err(err) = err else {
            panic!("a registration of another app must be refused");
        };
        assert_eq!(err.code, "principal_mismatch", "{err:?}");
    }

    #[test]
    fn only_read_and_write_pass_the_role_gate() {
        assert!(require_grantable_roles(&["read".into()]).is_ok());
        assert!(require_grantable_roles(&["read".into(), "write".into()]).is_ok());
        for bad in [
            vec![],
            vec!["owner".to_string()],
            vec!["read".to_string(), "fullcontrol".to_string()],
        ] {
            let err = require_grantable_roles(&bad).expect_err("refused");
            assert_eq!(err.code, "unsupported_role", "{bad:?}");
        }
    }

    // ── The Sites.Selected conversion: what it grants, strips and reports ──

    use azapptoolkit_core::scoping::OFFICE365_SHAREPOINT_ONLINE_APP_ID as SPO;

    /// Microsoft Graph and Office 365 SharePoint Online as the residual check
    /// sees them. `Sites.Read.All` sits on both, under different role ids.
    fn sharepoint_resources() -> Vec<ResourceRoles> {
        let index = |roles: &[(&str, &str)]| -> HashMap<String, String> {
            roles
                .iter()
                .map(|(id, value)| (id.to_string(), value.to_string()))
                .collect()
        };
        vec![
            ResourceRoles {
                app_id: MICROSOFT_GRAPH_APP_ID,
                sp_object_id: "graph-sp".into(),
                role_value_by_id: index(&[
                    ("r-read", "Sites.Read.All"),
                    ("r-sel", "Sites.Selected"),
                    ("r-files", "Files.ReadWrite.All"),
                    ("r-files-sel", "Files.SelectedOperations.Selected"),
                    ("r-mail", "Mail.Read"),
                ]),
            },
            ResourceRoles {
                app_id: SPO,
                sp_object_id: "spo-sp".into(),
                role_value_by_id: index(&[
                    ("s-full", "Sites.FullControl.All"),
                    ("s-read", "Sites.Read.All"),
                    ("s-sel", "Sites.Selected"),
                ]),
            },
        ]
    }

    fn held_on(resource: &str, role: &str) -> AppRoleAssignment {
        AppRoleAssignment {
            id: format!("{resource}/{role}"),
            resource_id: resource.into(),
            app_role_id: role.into(),
            ..Default::default()
        }
    }

    /// The strip takes Graph's `Sites.*` and nothing else, so what is
    /// left org-wide is named — keyed by resource, never by value: the same
    /// `Sites.Read.All` on SharePoint Online stays named after Graph's is gone.
    #[test]
    fn the_residual_check_names_what_the_strip_leaves_on_either_resource() {
        let resources = sharepoint_resources();
        let removed = vec!["Sites.Read.All".to_string()];
        let existing = vec![
            held_on("graph-sp", "r-read"),
            held_on("spo-sp", "s-full"),
            held_on("graph-sp", "r-files"),
            held_on("spo-sp", "s-read"),
            // Confinement, not reach — never named.
            held_on("graph-sp", "r-sel"),
            held_on("spo-sp", "s-sel"),
            held_on("graph-sp", "r-files-sel"),
            // Not SharePoint at all.
            held_on("graph-sp", "r-mail"),
            held_on("other-sp", "r-read"),
        ];
        assert_eq!(
            residual_orgwide_reach(&resources, &existing, &removed),
            vec![
                (SPO, "Sites.FullControl.All"),
                (MICROSOFT_GRAPH_APP_ID, "Files.ReadWrite.All"),
                (SPO, "Sites.Read.All"),
            ]
        );
        // A Graph Sites.* the strip did not remove (no site landed, or its
        // DELETE failed) is still reach.
        assert_eq!(
            residual_orgwide_reach(&resources, &[held_on("graph-sp", "r-read")], &[]),
            vec![(MICROSOFT_GRAPH_APP_ID, "Sites.Read.All")]
        );
        assert!(
            residual_orgwide_reach(&resources, &[held_on("graph-sp", "r-sel")], &[]).is_empty()
        );
    }

    #[test]
    fn the_residual_warning_names_each_grant_with_its_resource() {
        let beyond = orgwide_reach_warning(
            &[
                (SPO, "Sites.FullControl.All"),
                (MICROSOFT_GRAPH_APP_ID, "Files.ReadWrite.All"),
            ],
            true,
        )
        .expect("org-wide reach is left");
        assert!(beyond.starts_with("Scoping is NOT effective for SharePoint"));
        assert!(beyond.contains("Sites.FullControl.All (Office 365 SharePoint Online)"));
        assert!(beyond.contains("Files.ReadWrite.All (Microsoft Graph)"));
        assert!(beyond.contains("every site and every file"), "{beyond}");
        // Neither is something a re-run of this conversion removes.
        assert!(beyond.contains("removes only Microsoft Graph's Sites.*"));
        assert!(!beyond.contains("Re-run"), "{beyond}");

        let stopped = orgwide_reach_warning(&[(MICROSOFT_GRAPH_APP_ID, "Sites.Read.All")], true)
            .expect("org-wide reach is left");
        assert!(stopped.contains("Sites.Read.All (Microsoft Graph) is still granted"));
        assert!(stopped.contains("Re-run once the problems above are fixed"));
        assert!(!stopped.contains("removes only"), "{stopped}");

        assert_eq!(orgwide_reach_warning(&[], true), None);
    }

    /// An unreadable SharePoint Online index cannot classify a grant on a
    /// resource nothing resolved — which is exactly where an org-wide
    /// `Sites.*` there would sit — so that case is "could not check".
    #[test]
    fn a_grant_on_an_unresolved_resource_is_unidentified() {
        let graph_only = &sharepoint_resources()[..1];
        assert!(holds_unidentified_grant(
            graph_only,
            &[held_on("graph-sp", "r-read"), held_on("spo-sp", "s-full")]
        ));
        assert!(!holds_unidentified_grant(
            graph_only,
            &[held_on("graph-sp", "r-read"), held_on("graph-sp", "r-sel")]
        ));
    }

    const FINANCE: &str = "https://contoso.sharepoint.com/sites/Finance";
    const FINANCE_PATH: &str = "/v1.0/sites/contoso.sharepoint.com:/sites/Finance";
    const FINANCE_ID: &str = "contoso.sharepoint.com,fin-site,fin-web";

    fn assignment(id: &str, resource: &str, role: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id, "principalId": "sp1", "resourceId": resource, "appRoleId": role
        })
    }

    /// Mounts what every conversion reads — Graph's role index, `spo` as
    /// Office 365 SharePoint Online's lookup, the principal `sp1` (app `app-1`)
    /// and `assignments` — plus an accepting `Sites.Selected` grant and the
    /// Finance site, whose per-site grant answers `site_grant`.
    async fn conversion_tenant(
        server: &wiremock::MockServer,
        spo: wiremock::ResponseTemplate,
        assignments: serde_json::Value,
        site_grant: wiremock::ResponseTemplate,
    ) {
        use wiremock::matchers::{method, path, path_regex, query_param};
        use wiremock::{Mock, ResponseTemplate};

        let lookup = |app_id: &str| {
            Mock::given(method("GET"))
                .and(path("/v1.0/servicePrincipals"))
                .and(query_param("$filter", format!("appId eq '{app_id}'")))
        };
        lookup(MICROSOFT_GRAPH_APP_ID)
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{"id": "graph-sp", "appId": MICROSOFT_GRAPH_APP_ID, "appRoles": [
                    {"id": "r-sel", "value": "Sites.Selected"},
                    {"id": "r-read", "value": "Sites.Read.All"},
                    {"id": "r-files", "value": "Files.ReadWrite.All"}
                ]}]
            })))
            .mount(server)
            .await;
        lookup(SPO).respond_with(spo).mount(server).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals/sp1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sp1", "appId": "app-1", "displayName": "App"
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals/sp1/appRoleAssignments"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": assignments })),
            )
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1.0/servicePrincipals/sp1/appRoleAssignments"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(assignment("a-sel", "graph-sp", "r-sel")),
            )
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(FINANCE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": FINANCE_ID, "displayName": "Finance"
            })))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/v1\.0/sites/[^/]+/permissions$"))
            .respond_with(site_grant)
            .mount(server)
            .await;
    }

    /// Office 365 SharePoint Online as the tenant resolves it.
    fn spo_resource() -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "spo-sp", "appId": SPO, "appRoles": [
                {"id": "s-full", "value": "Sites.FullControl.All"}
            ]}]
        }))
    }

    fn site_granted() -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "perm-1", "roles": ["read"],
            "grantedToIdentities": [{"application": {"id": "app-1", "displayName": "App"}}]
        }))
    }

    /// Runs the conversion core for the SP-only principal `sp1` (no app
    /// registration, so nothing is declared) against `server`.
    async fn convert(
        server: &wiremock::MockServer,
        cache: &Cache,
        urls: &[&str],
    ) -> SiteScopeResult {
        let client = crate::commands::test_support::mock_graph(server)
            .with_sharepoint_token(azapptoolkit_core::token::StaticTokenProvider::new("sp"));
        let site_urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
        convert_site_access_core(
            &client,
            cache,
            &GraphRolePrincipal {
                tenant_id: "t1",
                object_id: None,
                sp_object_id: "sp1",
                app_id: "app-1",
            },
            SiteConversion {
                app_display_name: "App",
                site_urls: &site_urls,
                role: "read",
                remove_orgwide: true,
            },
        )
        .await
        .expect("the conversion runs")
    }

    /// End to end: Sites.Selected, then the site grant, and only
    /// then the strip of Graph's `Sites.Read.All`. The SharePoint Online
    /// `Sites.*` and Graph's `Files.ReadWrite.All` survive the strip, so the
    /// result says the app is NOT confined instead of reporting only removals.
    #[tokio::test]
    async fn a_conversion_grants_before_it_strips_and_names_the_reach_it_leaves() {
        use wiremock::matchers::{method, path, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        conversion_tenant(
            &server,
            spo_resource(),
            serde_json::json!([
                assignment("a-read", "graph-sp", "r-read"),
                assignment("a-spo", "spo-sp", "s-full"),
                assignment("a-files", "graph-sp", "r-files"),
            ]),
            site_granted(),
        )
        .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/v1.0/servicePrincipals/sp1/appRoleAssignments/a-read",
            ))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        // Neither grant the conversion cannot confine is touched.
        Mock::given(method("DELETE"))
            .and(path_regex(r"/appRoleAssignments/"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;
        let cache = Cache::new();
        let sweep = std::sync::Arc::new(SiteSweepResult {
            tenant_id: "t1".into(),
            total_sites: 1,
            sites_scanned: 1,
            sites_failed: 0,
            rows: Vec::new(),
            cancelled: false,
            truncated: false,
        });
        cache.put_typed(CacheKind::Audit, sweep_cache_key("t1"), sweep);

        let out = convert(&server, &cache, &[FINANCE]).await;

        assert!(out.granted_role_added);
        assert_eq!(out.sites_granted.len(), 1);
        assert_eq!(
            out.removed_orgwide_grants,
            vec!["Sites.Read.All".to_string()]
        );
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        let warning = &out.warnings[0];
        assert!(warning.starts_with("Scoping is NOT effective for SharePoint"));
        assert!(warning.contains("Sites.FullControl.All (Office 365 SharePoint Online)"));
        assert!(warning.contains("Files.ReadWrite.All (Microsoft Graph)"));
        assert!(
            !warning.contains("Sites.Read.All"),
            "the removed grant is not reach: {warning}"
        );

        // The order is the point: scoped access first, the strip last.
        let requests = server.received_requests().await.expect("recorded");
        let position = |verb: &str, ends_with: &str| {
            requests
                .iter()
                .position(|r| r.method.as_str() == verb && r.url.path().ends_with(ends_with))
                .unwrap_or_else(|| panic!("no {verb} …{ends_with}"))
        };
        let selected = position("POST", "/servicePrincipals/sp1/appRoleAssignments");
        let site = position("POST", "/permissions");
        let strip = position("DELETE", "/appRoleAssignments/a-read");
        assert!(
            selected < site && site < strip,
            "{selected} < {site} < {strip}"
        );

        assert!(
            cache
                .get_typed::<SiteSweepResult>(CacheKind::Audit, &sweep_cache_key("t1"))
                .is_none(),
            "a landed site grant busts the site sweep"
        );
    }

    /// Every site grant refused → the org-wide grant stays, and the result
    /// says the app still reaches every site rather than reading as scoped.
    #[tokio::test]
    async fn no_landed_site_grant_strips_nothing_and_says_the_app_is_still_org_wide() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        conversion_tenant(
            &server,
            spo_resource(),
            serde_json::json!([assignment("a-read", "graph-sp", "r-read")]),
            ResponseTemplate::new(403),
        )
        .await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .expect(0)
            .mount(&server)
            .await;

        let out = convert(&server, &Cache::new(), &[FINANCE]).await;

        assert!(out.sites_granted.is_empty());
        assert!(out.removed_orgwide_grants.is_empty());
        let all = out.warnings.join("\n");
        assert!(all.contains("failed to grant access to"), "{all}");
        assert!(all.contains("no site access was granted"), "{all}");
        assert!(
            all.contains("Sites.Read.All (Microsoft Graph) is still granted"),
            "{all}"
        );
        assert!(
            all.contains("Re-run once the problems above are fixed"),
            "{all}"
        );
    }

    /// A repeated site — another case, a trailing slash, no scheme — is
    /// one site: one grant call and one row, never "Scoped to 3 sites".
    #[tokio::test]
    async fn a_site_listed_three_ways_is_granted_once() {
        use wiremock::MockServer;
        use wiremock::matchers::{method, path, path_regex};

        let server = MockServer::start().await;
        // Mounted ahead of `conversion_tenant`'s copies, so these count.
        wiremock::Mock::given(method("GET"))
            .and(path(FINANCE_PATH))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": FINANCE_ID, "displayName": "Finance"
                })),
            )
            // The case/slash variant is folded before any read; the
            // scheme-less one resolves, then matches the site already granted.
            .expect(2)
            .mount(&server)
            .await;
        wiremock::Mock::given(method("POST"))
            .and(path_regex(r"^/v1\.0/sites/[^/]+/permissions$"))
            .respond_with(site_granted())
            .expect(1)
            .mount(&server)
            .await;
        conversion_tenant(
            &server,
            spo_resource(),
            serde_json::json!([]),
            site_granted(),
        )
        .await;

        let out = convert(
            &server,
            &Cache::new(),
            &[
                FINANCE,
                "https://contoso.sharepoint.com/sites/finance/",
                "contoso.sharepoint.com/sites/Finance",
            ],
        )
        .await;

        assert_eq!(out.sites_granted.len(), 1);
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    }

    /// An Office 365 SharePoint Online lookup that fails does not stop the
    /// conversion, and is never read as "holds nothing there": a grant on a
    /// resource nothing resolved is reported as unchecked.
    #[tokio::test]
    async fn an_unreadable_sharepoint_online_index_is_reported_not_read_as_empty() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        conversion_tenant(
            &server,
            // A 4xx, not a 5xx: the retry policy would back off on a 5xx.
            ResponseTemplate::new(400),
            serde_json::json!([
                assignment("a-read", "graph-sp", "r-read"),
                assignment("a-spo", "spo-sp", "s-full"),
            ]),
            site_granted(),
        )
        .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/v1.0/servicePrincipals/sp1/appRoleAssignments/a-read",
            ))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let out = convert(&server, &Cache::new(), &[FINANCE]).await;

        assert_eq!(
            out.removed_orgwide_grants,
            vec!["Sites.Read.All".to_string()]
        );
        assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
        assert!(
            out.warnings[0]
                .starts_with("could not read the Office 365 SharePoint Online permissions"),
            "{}",
            out.warnings[0]
        );
    }

    /// A write token that answers this way for every request.
    struct FailingToken(&'static str);

    #[async_trait::async_trait]
    impl azapptoolkit_core::token::BearerProvider for FailingToken {
        async fn bearer(&self) -> Result<String, azapptoolkit_core::token::TokenError> {
            Err(azapptoolkit_core::token::TokenError::new(
                self.0,
                "token refused",
            ))
        }
    }

    /// A refused appRole assignment keeps its code. `grant_failed` used to
    /// stand in for all three, so a 403 named no role, a missing consent
    /// offered no "Grant consent", and a dead session neither read as one nor
    /// stopped a bulk run.
    #[tokio::test]
    async fn a_refused_selected_grant_keeps_its_code() {
        use azapptoolkit_core::token::{BearerProvider, StaticTokenProvider};
        use std::sync::Arc;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let admin_consent = azapptoolkit_core::capabilities::capability("admin_consent")
            .expect("catalog entry")
            .remediation;
        let cases: [(Arc<dyn BearerProvider>, &str); 3] = [
            (StaticTokenProvider::new("tok"), "forbidden"),
            (
                Arc::new(FailingToken("consent_required")),
                "consent_required",
            ),
            (Arc::new(FailingToken("refresh_missing")), "refresh_missing"),
        ];
        for (write, code) in cases {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/v1.0/servicePrincipals/sp1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": "sp1", "appId": "app-1", "displayName": "App"
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path("/v1.0/servicePrincipals/sp1/appRoleAssignments"))
                .respond_with(ResponseTemplate::new(403))
                .mount(&server)
                .await;
            let client = crate::commands::test_support::mock_graph_rw(
                &server,
                StaticTokenProvider::new("tok"),
                write,
                Cache::new(),
            );
            let index: HashMap<String, String> =
                [("role-selected".to_string(), "Sites.Selected".to_string())].into();
            let Err(err) = declare_and_grant_graph_role(
                &client,
                &Cache::new(),
                &GraphRolePrincipal {
                    tenant_id: "t1",
                    object_id: None,
                    sp_object_id: "sp1",
                    app_id: "app-1",
                },
                "graph-sp",
                &index,
                &[],
                SP_SITES_SELECTED,
            )
            .await
            else {
                panic!("{code}: the grant was refused");
            };
            assert_eq!(err.code, code, "{err:?}");
            assert!(
                err.message.starts_with("failed to grant Sites.Selected"),
                "{err:?}"
            );
            assert_eq!(
                err.message.contains(admin_consent),
                code == "forbidden",
                "the admin-consent guidance rides a 403 only: {err:?}"
            );
            assert_eq!(err.is_reauth_fatal(), code == "refresh_missing", "{err:?}");
        }
    }
}
