//! SharePoint Sites.Selected commands.
//!
//! Grants/lists/revokes per-site application permissions via Microsoft Graph
//! (`/sites/{id}/permissions`) — the supported "current-context / delegated"
//! strategy from the legacy `Grant-SharePointSiteAccess`. The signed-in user
//! needs `Sites.FullControl.All` (a SharePoint admin or site owner); the temp-
//! app strategy is a future phase. Each command resolves the site from its URL
//! first, since the UI works in terms of the browser site URL.

use std::sync::Arc;

use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{Site, SitePermission};
use azapptoolkit_core::scoping::is_sharepoint_orgwide;

use crate::commands::applications::invalidate_app_lists;
use crate::commands::dispatch::dispatch_capped;
use crate::commands::graph_roles::graph_role_index;
use crate::dto::sharepoint::{
    GrantSiteAccessResult, SiteAppGrantRow, SiteGrantDto, SitePermissionDto, SiteScopeResult,
    SiteSweepProgress, SiteSweepResult,
};
use crate::dto::UiError;
use crate::state::AppState;

/// Whether to strip the broad org-wide grant: only when the caller asked for it
/// AND at least one site grant landed, so a principal is never left with no
/// access because every site grant failed.
fn should_remove_orgwide(remove_orgwide: bool, any_site_granted: bool) -> bool {
    remove_orgwide && any_site_granted
}

/// Maps a SharePoint Graph error to a `UiError`, replacing a 403's message with
/// the `sharepoint_sites_selected` role guidance. A forbidden *after* the
/// `Sites.FullControl.All` scope is consented means the signed-in user lacks the
/// SharePoint Administrator role — not a consent gap (that surfaces earlier as
/// `consent_required` from `ensure_sharepoint_token`). Single copy of the text
/// lives in the capability catalog.
fn sharepoint_err(err: azapptoolkit_graph::GraphError) -> UiError {
    let mut ui = UiError::from(err);
    if ui.code == "forbidden" {
        if let Some(cap) = azapptoolkit_core::capabilities::capability("sharepoint_sites_selected")
        {
            ui.message = cap.remediation.to_string();
        }
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
    // Pre-acquire the SharePoint scope so a missing-consent rejection surfaces
    // as `consent_required` (the tab shows a "Grant consent" button) instead of
    // a generic token error from inside the scoped Graph call.
    state
        .ensure_sharepoint_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);
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
    // Pre-acquire the SharePoint scope so a missing-consent rejection surfaces
    // as `consent_required` (the tab shows a "Grant consent" button) instead of
    // a generic token error from inside the scoped Graph call.
    state
        .ensure_sharepoint_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);
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
    // Pre-acquire the SharePoint scope so a missing-consent rejection surfaces
    // as `consent_required` (the tab shows a "Grant consent" button) instead of
    // a generic token error from inside the scoped Graph call.
    state
        .ensure_sharepoint_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);
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
    // Pre-acquire the SharePoint scope (the per-site grants ride it) so a
    // missing-consent rejection surfaces as `consent_required` for the UI.
    state
        .ensure_sharepoint_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);
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

// ---------------- Site-permission sweep (reverse lookup) ----------------

/// In-flight cap for per-site permission reads. SharePoint throttles harder
/// than the directory endpoints, so this stays below the audit's initial cap.
/// The per-site read rides the client's retrying transport
/// (`scoped_get_retried`), so a transient 429 is absorbed with `Retry-After`
/// honored; only a *persistently* failing site lands in `sites_failed`.
const SWEEP_CONCURRENCY: usize = 6;
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

fn emit_sweep_progress(app_handle: &AppHandle, progress: SiteSweepProgress) {
    if let Err(err) = app_handle.emit("site-sweep-progress", progress) {
        tracing::warn!(?err, "failed to emit site-sweep-progress event");
    }
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
    state.sweep_cancel.reset();

    // Pre-acquire the SharePoint scope so a missing-consent rejection surfaces
    // as `consent_required` (the view shows a "Grant consent" button).
    state
        .ensure_sharepoint_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);

    let sites = client
        .list_all_sites(MAX_SITES_PER_SWEEP)
        .await
        .map_err(sharepoint_err)?;
    let total = sites.len();
    emit_sweep_progress(
        &app_handle,
        SiteSweepProgress {
            done: 0,
            total,
            current_site: None,
            cancelled: false,
        },
    );

    let done = Arc::new(Mutex::new(0usize));
    let cancel = state.sweep_cancel.clone();

    let mut rows: Vec<SiteAppGrantRow> = Vec::new();
    let mut sites_scanned = 0usize;
    let mut sites_failed = 0usize;
    let mut cancelled = dispatch_capped(
        sites,
        || SWEEP_CONCURRENCY,
        |site| {
            if cancel.is_cancelled() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let cancel_for_task = cancel.clone();
            Some(tokio::spawn(async move {
                let result = client.list_site_permissions(&site.id).await;
                let mut guard = done.lock().await;
                *guard += 1;
                let progress = SiteSweepProgress {
                    done: *guard,
                    total,
                    current_site: site.display_name.clone().or_else(|| site.web_url.clone()),
                    cancelled: cancel_for_task.is_cancelled(),
                };
                drop(guard);
                emit_sweep_progress(&app_handle, progress);
                (site, result)
            }))
        },
        |joined| match joined {
            Ok((site, result)) => fold_site_result(
                &mut rows,
                &mut sites_scanned,
                &mut sites_failed,
                &site,
                result,
            ),
            Err(err) => {
                sites_failed += 1;
                tracing::warn!(?err, "site sweep: join error");
            }
        },
    )
    .await;

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
    state
        .cache
        .get(CacheKind::Audit, &sweep_cache_key(&tenant_id))
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

        assert!(cache
            .get::<SiteSweepResult>(CacheKind::Audit, &sweep_cache_key("t1"))
            .is_none());
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
}
