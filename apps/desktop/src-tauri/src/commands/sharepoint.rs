//! SharePoint Selected-permission commands.
//!
//! Grants/lists/revokes per-site application permissions via Microsoft Graph
//! (`/sites/{id}/permissions`) — the supported "current-context / delegated"
//! strategy from the legacy `Grant-SharePointSiteAccess`. The signed-in user
//! needs `Sites.FullControl.All` (a SharePoint admin or site owner); the temp-
//! app strategy is a future phase. Each command resolves the site from its URL
//! first, since the UI works in terms of the browser site URL.

use std::sync::Arc;

use tauri::{AppHandle, State};

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{
    ResolvedSharePointResource, SelectedPermission, Site, SitePermission,
};
use azapptoolkit_core::scoping::{
    MICROSOFT_GRAPH_APP_ID, SelectedScopeLevel, is_sharepoint_orgwide, selected_scope_accepts,
    selected_scope_level_for,
};

use crate::commands::applications::invalidate_app_lists;
use crate::commands::dispatch::{SessionDead, dispatch_capped};
use crate::commands::graph_err::forbidden_remediation;
use crate::commands::graph_roles::graph_role_index;
use crate::commands::progress::emit_progress;
use crate::commands::throttle::{ConcurrencyThrottle, ThrottleGuard};
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

/// The distinct resources in a pasted target list, in the order given.
///
/// Two spellings of one resource would create two permission entries on it, each
/// consuming another of the library's unique permission scopes for no extra
/// access — and a repeated line in a pasted block is easy not to notice.
/// Compared case- and trailing-slash-insensitively, which is how SharePoint
/// treats its own URLs.
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
/// shows a "Grant consent" button) instead of a generic `token_error` from deep
/// inside the scoped Graph call — then returns the tenant's Graph client.
/// Mirrors `exchange_client_checked`; every SharePoint command routes its
/// pre-acquire through here so the "consent_required survives the BearerProvider"
/// contract lives in one place.
async fn sharepoint_client_checked(
    state: &AppState,
    tenant_id: &str,
) -> Result<Arc<azapptoolkit_graph::GraphClient>, UiError> {
    state
        .ensure_sharepoint_token(tenant_id)
        .await
        .map_err(UiError::from)?;
    Ok(state.graph_for(tenant_id))
}

/// Maps a SharePoint Graph error to a `UiError`, replacing a 403's message with
/// the `sharepoint_sites_selected` role guidance. A forbidden *after* the
/// `Sites.FullControl.All` scope is consented means the signed-in user lacks the
/// SharePoint Administrator role — not a consent gap (that surfaces earlier as
/// `consent_required` from `ensure_sharepoint_token`). Single copy of the text
/// lives in the capability catalog.
fn sharepoint_err(err: azapptoolkit_graph::GraphError) -> UiError {
    let mut ui = UiError::from(err);
    if let Some(remediation) = forbidden_remediation(&ui, "sharepoint_sites_selected") {
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
/// `site_url`; (3) only if ≥1 site grant succeeded and `remove_orgwide`, strip
/// the org-wide `Sites.*` Entra grants so the scoping is effective. Graph has no
/// reverse `appId → sites` lookup, so the sites must be supplied by the caller.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn convert_site_access_to_selected(
    state: State<'_, AppState>,
    tenant_id: String,
    sp_object_id: String,
    app_id: String,
    app_display_name: String,
    site_urls: Vec<String>,
    role: String,
    remove_orgwide: bool,
) -> Result<SiteScopeResult, UiError> {
    // The per-site grants ride the SharePoint scope, pre-acquired here.
    let client = sharepoint_client_checked(&state, &tenant_id).await?;
    let (graph_sp_id, role_value_by_id) = graph_role_index(&client).await?;

    // Reverse-lookup the Sites.Selected appRole id so we can grant it.
    let sites_selected_id = role_value_by_id
        .iter()
        .find(|(_, value)| value.as_str() == "Sites.Selected")
        .map(|(id, _)| id.clone())
        .ok_or_else(|| {
            UiError::not_found(
                "role",
                "Sites.Selected application role not found on Microsoft Graph",
            )
        })?;

    let mut warnings = Vec::new();

    // Snapshot the current assignments once: drives both the idempotency check
    // for the Sites.Selected grant and the org-wide-removal scan below.
    let existing = client.list_app_role_assignments(&sp_object_id).await?;

    // 1. Grant Sites.Selected (idempotent).
    let already_selected = existing
        .iter()
        .any(|a| a.resource_id == graph_sp_id && a.app_role_id == sites_selected_id);
    let mut granted_role_added = false;
    if !already_selected {
        client
            .grant_app_role(&sp_object_id, &graph_sp_id, &sites_selected_id)
            .await
            .map_err(|err| {
                UiError::validation(
                    "grant_failed",
                    format!("failed to grant Sites.Selected: {err}"),
                )
            })?;
        granted_role_added = true;
    }

    // 2. Grant the scoped per-site access (before removing the broad grant).
    let roles = vec![role];
    let mut sites_granted = Vec::new();
    for url in &site_urls {
        let site = match client.get_site_by_url(url).await {
            Ok(site) => site,
            Err(err) => {
                warnings.push(format!("could not resolve site '{url}': {err}"));
                continue;
            }
        };
        match client
            .grant_site_permission(&site.id, &app_id, &app_display_name, &roles)
            .await
        {
            Ok(perm) => sites_granted.push(SiteGrantDto {
                site_id: site.id,
                site_display_name: site.display_name,
                permission: to_dto(perm),
            }),
            Err(err) => warnings.push(format!("failed to grant access to '{url}': {err}")),
        }
    }

    // 3. Strip the org-wide Sites.* grants so the scoped model is effective —
    //    but only if some site access actually landed.
    let mut removed_orgwide_grants = Vec::new();
    if should_remove_orgwide(remove_orgwide, !sites_granted.is_empty()) {
        for a in &existing {
            if a.resource_id != graph_sp_id {
                continue;
            }
            let Some(value) = role_value_by_id.get(&a.app_role_id) else {
                continue;
            };
            if !is_sharepoint_orgwide(value) {
                continue;
            }
            match client
                .remove_app_role_assignment(&sp_object_id, &a.id)
                .await
            {
                Ok(()) => removed_orgwide_grants.push(value.clone()),
                Err(err) => {
                    warnings.push(format!("failed to remove org-wide grant {value}: {err}"))
                }
            }
        }
    } else if remove_orgwide {
        warnings.push(
            "no site access was granted, so the org-wide Sites.* grant was left in place".into(),
        );
    }

    // The Sites.Selected grant / org-wide removal change the SP's app-role
    // assignments the cached lists reflect. Invalidate only on this success path.
    invalidate_app_lists(&state.cache, &tenant_id);
    // The per-site grants are what the cached sweep indexes (the org-wide
    // strip is not — the sweep holds per-site rows only), so bust it whenever
    // at least one site grant landed.
    if !sites_granted.is_empty() {
        invalidate_site_sweep(&state.cache, &tenant_id);
    }

    Ok(SiteScopeResult {
        granted_role_added,
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

fn to_item_dto(p: SelectedPermission) -> SelectedItemPermissionDto {
    SelectedItemPermissionDto {
        id: p.id.clone(),
        roles: p.roles.clone(),
        app_id: p.app_id().map(str::to_string),
        app_display_name: p.app_display_name().map(str::to_string),
    }
}

fn to_resource_ref(r: ResolvedSharePointResource, input_url: String) -> SharePointResourceRef {
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
        .map_err(sharepoint_err)?;
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
    app_id: String,
    app_display_name: String,
    permission_value: String,
    target_urls: Vec<String>,
    role: String,
) -> Result<SelectedItemScopeResult, UiError> {
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

    let role_id = role_value_by_id
        .iter()
        .find(|(_, value)| value.as_str() == permission_value)
        .map(|(id, _)| id.clone())
        .ok_or_else(|| {
            UiError::not_found(
                "role",
                format!("{permission_value} application role not found on Microsoft Graph"),
            )
        })?;

    let mut warnings = Vec::new();

    // 1. Grant the Selected appRole (idempotent) — without it in the token, the
    //    per-resource permissions below grant nothing at all.
    let existing = client.list_app_role_assignments(&sp_object_id).await?;
    let already_held = existing
        .iter()
        .any(|a| a.resource_id == graph_sp_id && a.app_role_id == role_id);
    let mut granted_role_added = false;
    if !already_held {
        client
            .grant_app_role(&sp_object_id, &graph_sp_id, &role_id)
            .await
            .map_err(|err| {
                UiError::validation(
                    "grant_failed",
                    format!("failed to grant {permission_value}: {err}"),
                )
            })?;
        granted_role_added = true;
    }

    // 2. Grant per resource. A target that fails to resolve, sits at the wrong
    //    level, or is rejected by SharePoint is reported and skipped — one bad
    //    URL must not discard the grants that did land.
    let roles = vec![role];
    let mut granted = Vec::new();
    for url in &dedupe_targets(&target_urls) {
        let resolved = match client.resolve_sharepoint_resource(url).await {
            Ok(r) => r,
            Err(err) => {
                warnings.push(format!("could not resolve '{url}': {err}"));
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

    // The Selected appRole grant changes the SP's app-role assignments the
    // cached lists reflect. Invalidate only on this success path.
    //
    // The per-resource permissions are deliberately NOT swept into
    // `invalidate_site_sweep`: that index holds `/sites/{id}/permissions` rows,
    // and a list or item grant creates none of those. Busting it here would
    // force a tenant-wide re-sweep for a change it cannot observe.
    invalidate_app_lists(&state.cache, &tenant_id);

    Ok(SelectedItemScopeResult {
        granted_role_added,
        granted,
        warnings,
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
        .map_err(sharepoint_err)
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
        .map_err(sharepoint_err)
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
        .map_err(sharepoint_err)?;
    let perms = read_permissions(&client, &resolved).await?;
    Ok(perms.into_iter().map(to_item_dto).collect())
}

async fn read_permissions(
    client: &azapptoolkit_graph::GraphClient,
    resolved: &ResolvedSharePointResource,
) -> Result<Vec<SelectedPermission>, UiError> {
    match (resolved.list_id.as_deref(), resolved.item_id.as_deref()) {
        (Some(list_id), Some(item_id)) => client
            .list_list_item_permissions(&resolved.site_id, list_id, item_id)
            .await
            .map_err(sharepoint_err),
        (Some(list_id), None) => client
            .list_list_permissions(&resolved.site_id, list_id)
            .await
            .map_err(sharepoint_err),
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
        .map_err(sharepoint_err)?;
    match (resolved.list_id.as_deref(), resolved.item_id.as_deref()) {
        (Some(list_id), Some(item_id)) => client
            .remove_list_item_permission(&resolved.site_id, list_id, item_id, &permission_id)
            .await
            .map_err(sharepoint_err),
        (Some(list_id), None) => client
            .remove_list_permission(&resolved.site_id, list_id, &permission_id)
            .await
            .map_err(sharepoint_err),
        (None, _) => Err(UiError::validation(
            "level_mismatch",
            "use the site permissions view for a site collection".to_string(),
        )),
    }
}

// ---------------- Site-permission sweep (reverse lookup) ----------------

/// In-flight cap for per-site permission reads. SharePoint throttles harder
/// than the directory endpoints, so this stays below the audit's initial cap.
/// The per-site read rides the client's retrying transport
/// (`scoped_get_retried`), so a transient 429 is absorbed with `Retry-After`
/// honored; only a *persistently* failing site lands in `sites_failed`.
const SWEEP_CONCURRENCY: usize = 6;
/// Sites resolved per progress step. The Graph `$batch` cap is 20 sub-requests,
/// and `batch_list_site_permissions` chunks internally, so this is the
/// **cancellation and progress** granularity: small enough that Cancel feels
/// immediate and a whole-batch failure costs one step, large enough that the
/// batching win isn't given back in round trips.
const SWEEP_BATCH: usize = 100;
/// Safety cap on sites per sweep — prevents a pathological tenant from
/// queueing an unbounded scan. Raise if a user legitimately hits it.
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
/// then reads `/sites/{id}/permissions` with bounded concurrency.
///
/// Long-running: emits `site-sweep-progress` after each site and polls the
/// dedicated `AppState.sweep_cancel` atomic (NOT `audit_cancel` — a sweep
/// cancel must not abort a concurrent audit/bulk run) between dispatches.
/// Per-site read failures increment `sites_failed` rather than aborting or
/// silently reading as "no grants", so coverage is never overstated. The
/// completed result is cached (60-minute audit TTL) under a tenant-prefixed
/// key; a cancelled or partially-failed run is never cached.
#[tauri::command]
pub async fn sweep_site_permissions(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<SiteSweepResult, UiError> {
    // Claimed before the first await: `list_all_sites` walks every site in the
    // tenant, and a token claimed after it carries a higher generation than a
    // cancel issued during it, which `is_cancelled()` then discards. Pinned by
    // `repo_invariants::cancel`.
    let cancel = state.sweep_cancel.claim();
    let client = sharepoint_client_checked(&state, &tenant_id).await?;

    let sites = client
        .list_all_sites(MAX_SITES_PER_SWEEP)
        .await
        .map_err(sharepoint_err)?;
    let total = sites.len();
    emit_progress(
        &app_handle,
        "site-sweep-progress",
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
    let tracker = Arc::new(ConcurrencyThrottle::new(SWEEP_CONCURRENCY));
    let _observer_guard = ThrottleGuard::attach(client.clone(), tracker.clone());

    let mut rows: Vec<SiteAppGrantRow> = Vec::new();
    let mut sites_scanned = 0usize;
    let mut sites_failed = 0usize;
    let mut done = 0usize;
    let mut cancelled = false;

    // `/sites/{id}/permissions` is a plain GET, so the sweep reads them in
    // `$batch` POSTs of 20 instead of one request per site — at the 5000-site
    // cap that is 250 round trips rather than 5000. Chunked so cancellation and
    // progress stay responsive between batches, and so a whole-batch failure
    // costs one chunk rather than the run.
    // Chunks are independent and results are folded per-chunk, so order does not
    // matter — dispatch them through the shared driver with the tracker as the
    // cap. Previously this loop awaited one chunk at a time, which meant the
    // tracker attached above was never READ: the observer dutifully halved a
    // number nothing consulted, so the adaptive back-off the comment advertises
    // did not exist and the walk was fully serial besides.
    let chunks: Vec<Vec<Site>> = sites.chunks(SWEEP_BATCH).map(<[Site]>::to_vec).collect();
    let session = SessionDead::new();
    let stopped_early = dispatch_capped(
        chunks,
        {
            let tracker = tracker.clone();
            move || tracker.current_limit()
        },
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
                "site-sweep-progress",
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
        // Never cache or return a truncated sweep: `AppSiteAccessDto::from_sweep`
        // reads an empty site list as "no grants" whenever the sweep claims to
        // be complete, so a partial run understates an app's reach.
        return Err(session.err("the SharePoint site sweep"));
    }
    cancelled = cancelled || stopped_early;

    cancelled = cancelled || cancel.is_cancelled();
    tracing::info!(
        total,
        sites_scanned,
        sites_failed,
        cancelled,
        "site sweep complete"
    );
    rows.sort_by(|a, b| {
        a.site_display_name
            .cmp(&b.site_display_name)
            .then_with(|| a.app_display_name.cmp(&b.app_display_name))
    });

    let result = SiteSweepResult {
        tenant_id: tenant_id.clone(),
        total_sites: total,
        sites_scanned,
        sites_failed,
        rows,
        cancelled,
    };
    // Cache only a COMPLETE sweep: serving a cancelled or partially-failed
    // result for the next hour would overstate coverage — the "coverage is
    // never overstated" promise extends to the cache.
    if !cancelled && sites_failed == 0 {
        state
            .cache
            .put(CacheKind::Audit, sweep_cache_key(&tenant_id), &result);
    }
    Ok(result)
}

/// Signals the in-progress resource sweep/probe (site sweep or mailbox probe —
/// both poll `sweep_cancel`) to stop at the next dispatch boundary.
#[tauri::command]
pub fn cancel_resource_sweep(state: State<'_, AppState>) {
    state.sweep_cancel.cancel();
}

/// Returns the cached sweep for this tenant, if one completed within the cache
/// TTL — so the view (and any future surface) can render without re-scanning.
#[tauri::command]
pub fn get_cached_site_sweep(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Option<SiteSweepResult> {
    // A cache-only answer makes the `tenant_id` argument the only thing deciding
    // whose directory data is returned, so prove the session first (AGENTS.md's
    // #1 footgun). Pinned by `a_command_answering_from_cache_alone_checks_the_session`.
    state.auth.tenant_context(&tenant_id)?;
    state
        .cache
        .get(CacheKind::Audit, &sweep_cache_key(&tenant_id))
}

/// The sites one principal can reach under `Sites.Selected`, and the roles it
/// holds on each — read from the cached tenant sweep, `None` when no completed
/// sweep is cached (the caller then offers to run one).
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
#[tauri::command]
pub fn get_app_site_access(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Option<AppSiteAccessDto> {
    // A cache-only answer makes the `tenant_id` argument the only thing deciding
    // whose directory data is returned, so prove the session first (AGENTS.md's
    // #1 footgun). Pinned by `a_command_answering_from_cache_alone_checks_the_session`.
    state.auth.tenant_context(&tenant_id)?;
    let sweep: SiteSweepResult = state
        .cache
        .get(CacheKind::Audit, &sweep_cache_key(&tenant_id))?;
    Some(AppSiteAccessDto::from_sweep(&sweep, &app_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    // `is_sharepoint_orgwide` itself is unit-tested in azapptoolkit_core::scoping.

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
                    display_name: None,
                }),
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
        };
        cache.put(CacheKind::Audit, sweep_cache_key("t1"), &sweep);
        cache.put(CacheKind::Audit, sweep_cache_key("t2"), &sweep);

        invalidate_site_sweep(&cache, "t1");

        assert!(
            cache
                .get::<SiteSweepResult>(CacheKind::Audit, &sweep_cache_key("t1"))
                .is_none()
        );
        assert!(
            cache
                .get::<SiteSweepResult>(CacheKind::Audit, &sweep_cache_key("t2"))
                .is_some(),
            "other tenant must survive"
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
            granted_to_identities: vec![SiteIdentitySet { application: None }],
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
}
