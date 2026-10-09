//! Tenant-scoped list/detail cache keys and the tiered invalidation policy —
//! the home of the backend's #1-footgun contract (cross-tenant cache leakage).
//! Keys are always `{tenant_id}|…`-prefixed; the `invalidate_*` fns run only on
//! `Ok`. The tiering (`invalidate_app_lists` vs `invalidate_app_credentials`
//! vs `invalidate_app_detail_state`) is deliberate — relocate call sites, but
//! never merge the tiers (the credential tier exists to keep tenant-wide index
//! re-scans off the credential path).

use std::sync::Arc;

use azapptoolkit_core::cache::{Cache, CacheKind, IndexWatch};
use azapptoolkit_core::models::{Application, PasswordCredential, ServicePrincipal};
use azapptoolkit_graph::{GraphClient, GraphError};

use crate::dto::applications::ApplicationListRowDto;
use crate::dto::credentials::CredentialRowDto;
use crate::state::AppState;

/// Lists cache keys are namespaced by tenant so a tenant switch never bleeds.
/// Mutations on app registrations also bust the enterprise-app key because a
/// new app may produce a paired SP that changes that list's join.
pub(crate) fn apps_pairing_key(tenant_id: &str) -> String {
    format!("{tenant_id}|apps_pairing")
}

pub(crate) fn enterprise_key(tenant_id: &str) -> String {
    format!("{tenant_id}|enterprise")
}

/// Cache key for the shared per-tenant service-principal index. Both list
/// views' pairing joins read through this entry, so a tab switch (or a
/// debounced search keystroke) reuses one directory scan instead of
/// re-enumerating every SP in the tenant.
pub(crate) fn sp_index_key(tenant_id: &str) -> String {
    format!("{tenant_id}|sp_index")
}

/// Cache key for the per-tenant app-registration index (`id`, `appId`,
/// `displayName`) — the `/applications` twin of [`sp_index_key`]. Distinct from
/// `sp_index` (service principals): app registrations without a paired SP only
/// live here.
///
/// Named for its original reader (the global search substring match), but every
/// surface that needs "which app registrations exist in this tenant" now joins
/// against this one entry — global search, the Enterprise Apps pairing join, the
/// DR backup's estate enumeration, and the mailbox probe's routing map. Those
/// last three each used to run their own uncached `/applications` scan.
pub(crate) fn app_name_index_key(tenant_id: &str) -> String {
    format!("{tenant_id}|app_name_index")
}

/// Cache key for the pre-lowercased global-search corpus (`commands::search`),
/// derived from the SP + app-name indexes. Typed-cached so a debounced
/// keystroke reuses it without re-deserializing or re-lowercasing; busted by
/// `invalidate_app_lists` since it's built from those indexes.
pub(crate) fn search_corpus_key(tenant_id: &str) -> String {
    format!("{tenant_id}|search_corpus")
}

/// Cache key for a single application's detail-pane payload (the full
/// [`ApplicationDetail`]: app + paired SP + owners + role assignments +
/// delegated grants + resolved permissions). Keyed by tenant **and** object id
/// so two tenants holding the same object id never collide.
pub(crate) fn app_detail_key(tenant_id: &str, object_id: &str) -> String {
    format!("{tenant_id}|app_detail|{object_id}")
}

/// Cache key for the tenant-wide credential-expiry list (`list_credential_expirations`:
/// every app registration's secrets + certs, flattened and expiry-sorted). Read
/// by the Home dashboard's credential tile and the Credential Expiry security
/// sub-tab. Busted by both [`invalidate_app_credentials`] (a credential change
/// shifts an expiry) and [`invalidate_app_lists`] (a create/delete changes the
/// app set), so a rotated/removed credential is never shown as still-expiring.
pub(crate) fn credential_expirations_key(tenant_id: &str) -> String {
    format!("{tenant_id}|credential_expirations")
}

/// Cache key for the Grant-access picker's "Tenant app registrations" directory
/// (`permissions::list_app_role_resources`): the tenant-owned service principals
/// exposing at least one enabled Application role, each with its role count.
/// Lives here (not in `permissions.rs`) because two mutation families bust it —
/// see [`invalidate_app_role_resources`]. The key string is unchanged from its
/// original home, so no cached format changed.
pub(crate) fn app_role_resources_key(tenant_id: &str) -> String {
    format!("{tenant_id}|app_role_resources")
}

/// Drops the cached app-role resource directory for `tenant_id`.
///
/// Two triggers move an SP in or out of that directory (or shift its count):
/// the App roles tab's writers (`upsert_enterprise_app_role` /
/// `delete_enterprise_app_role` — the first enabled Application role added, or
/// the last one disabled or removed), which call this directly after their
/// `invalidate_app_details`; and any create/delete of an app or SP, which
/// reaches it through [`invalidate_app_lists`]. The graph crate already busts
/// its own `resource:` prefix on the same writes; this is the command-side
/// directory that had been left out. Call only on `Ok`.
pub(crate) fn invalidate_app_role_resources(cache: &Cache, tenant_id: &str) {
    cache.invalidate(CacheKind::Lists, &app_role_resources_key(tenant_id));
}

/// Drops every cached detail-pane payload for `tenant_id`. Detail entries are
/// invalidated as a per-tenant group rather than one key at a time because
/// several mutations that change detail-visible state (revoking a role
/// assignment or an OAuth2 scope) only know the service-principal / grant id,
/// not the parent application's object id. Clearing the whole prefix is the
/// can't-miss option; the only cost is a re-fetch on the next navigation, and
/// these are user-initiated, infrequent writes.
pub(crate) fn invalidate_app_details(cache: &Cache, tenant_id: &str) {
    cache.invalidate_prefix(CacheKind::Lists, &format!("{tenant_id}|app_detail|"));
    // The resolved per-permission mailbox-scope verdicts
    // (`commands::exchange::mail_scopes_key`) are detail-pane state too: any
    // mutation that busts the detail payload (grant/revoke/scope) can change a
    // verdict, so they ride the same can't-miss prefix sweep.
    cache.invalidate_prefix(CacheKind::Lists, &format!("{tenant_id}|mail_scopes|"));
}

/// Drops the detail-pane payloads **and** the cached audit run for `tenant_id` —
/// the pairing a detail-affecting mutation needs when it can't change the app/SP
/// *set* (so the lists stay valid) but does change detail-visible and
/// audit-relevant state (grant/revoke/scope a permission, remediate, …).
/// [`invalidate_app_lists`] already bundles this same pair internally; this is
/// the no-list-change variant, factored out so the ~dozen call sites can't drop
/// one half of the pair. Call only on `Ok`.
pub(crate) fn invalidate_app_detail_state(cache: &Cache, tenant_id: &str) {
    invalidate_app_details(cache, tenant_id);
    crate::commands::audit::invalidate_audit_cache(cache, tenant_id);
}

/// Drops the App Registrations and Enterprise Apps list caches for `tenant_id`,
/// plus the shared SP index they both join against. Called after a successful
/// mutation; runs only on `Ok` so a failed write can't clear a fresh entry.
pub(crate) fn invalidate_app_lists(cache: &Cache, tenant_id: &str) {
    cache.invalidate(CacheKind::Lists, &apps_pairing_key(tenant_id));
    cache.invalidate(CacheKind::Lists, &enterprise_key(tenant_id));
    // A create/delete can add or remove a paired SP (e.g. via
    // ensure_service_principal), changing the shared index both joins depend on.
    cache.invalidate(CacheKind::Lists, &sp_index_key(tenant_id));
    // A create/delete/rename also changes the app-registration name index the
    // global search reads.
    cache.invalidate(CacheKind::Lists, &app_name_index_key(tenant_id));
    // The search corpus is derived from those two indexes, so it must fall too.
    cache.invalidate(CacheKind::Lists, &search_corpus_key(tenant_id));
    // The managed-identity list is now a filtered projection OF the SP index
    // (rather than its own scan), so it is stale whenever the index is. Without
    // this it could outlive its own source by up to the 60-minute TTL.
    cache.invalidate(
        CacheKind::Lists,
        &crate::commands::managed_identity::mi_key(tenant_id),
    );
    // A create/delete changes the app set the credential-expiry list scans.
    cache.invalidate(CacheKind::Lists, &credential_expirations_key(tenant_id));
    // A create/delete adds or removes an SP that may expose Application roles,
    // so the Grant-access picker's tenant-app directory is stale too.
    invalidate_app_role_resources(cache, tenant_id);
    // Any list-changing mutation (create/delete, credential add/remove, …) also
    // changes the affected app's detail payload, so drop the cached details too.
    invalidate_app_details(cache, tenant_id);
    // A list-changing mutation also changes audit-relevant state (the app set,
    // its credentials/permissions), so drop the cached audit too.
    crate::commands::audit::invalidate_audit_cache(cache, tenant_id);
}

/// Tiered invalidation for a **credential-only** mutation on one app
/// registration (add/remove secret, cert add/remove, generate-self-signed,
/// remove-expired). A credential change shows in three places — the App
/// Registrations list row (its credential-status badge / soonest expiry), the
/// mutated app's detail payload, and the audit (expiring-credential findings) —
/// but it can **not** add, remove, or rename a service principal or app
/// registration. So unlike [`invalidate_app_lists`], this deliberately *leaves*
/// the shared SP pairing index (`sp_index`), the app-name search index
/// (`app_name_index`), the Enterprise Apps list, and every mailbox-scope verdict
/// intact. Keeping the two tenant-wide indexes is the point: dropping them forces
/// the next list visit to re-enumerate every app **and** every service principal
/// (tens of seconds on a large tenant) for a change that touched neither. Pass
/// the mutated app's `object_id`; call only on `Ok`.
pub(crate) fn invalidate_app_credentials(cache: &Cache, tenant_id: &str, object_id: &str) {
    // The list row carries the credential-status badge + soonest expiry, so the
    // apps list must refresh — but the SP-index join it reuses is cached and kept.
    cache.invalidate(CacheKind::Lists, &apps_pairing_key(tenant_id));
    // Only the mutated app's detail payload changed.
    cache.invalidate(CacheKind::Lists, &app_detail_key(tenant_id, object_id));
    // A credential add/remove/rotate shifts this app's row in the tenant-wide
    // credential-expiry list, so drop the cached list (the index stays — the app
    // set is unchanged).
    cache.invalidate(CacheKind::Lists, &credential_expirations_key(tenant_id));
    // Expiring-credential findings change ⇒ the cached audit run is stale.
    crate::commands::audit::invalidate_audit_cache(cache, tenant_id);
}

// ---------------- The patch tier ----------------
//
// A create, delete or rename changes the app set, which used to mean
// `invalidate_app_lists` and a full `/applications` + `/servicePrincipals`
// re-enumeration on the next list visit. These writes already hold what
// changed (Graph returns the created objects, a delete knows its ids, a
// rename knows its fields), so the four scanned entries are patched with
// `Cache::patch_typed_index` instead. Everything else `invalidate_app_lists`
// drops is a projection the next read rebuilds without a tenant scan, so it is
// dropped the same way. Each patch falls back to dropping its key when it
// can't apply, so the worst case is the old cost. Call only on a clean `Ok`.
// A partial failure may have landed a write nobody can describe, so it takes
// `invalidate_app_lists`.

/// One app registration a write just created, as Graph returned it.
pub(crate) struct CreatedApp<'a> {
    pub(crate) application: &'a Application,
    /// The paired service principal, when the same write created it.
    pub(crate) service_principal: Option<&'a ServicePrincipal>,
    /// A secret added after the create POST (the dialog's initial secret, the
    /// OIDC wizard's client secret). The POST response predates it, but the
    /// list row's credential badge and the expiry roll-up must show it. Its
    /// `secret_text` is never copied into the cache.
    pub(crate) added_password: Option<&'a PasswordCredential>,
}

/// `app` projected to the app-name index's three fields. The scan and the
/// patch tier share it, so a patched row matches a scanned one.
pub(crate) fn app_name_index_row(app: &Application) -> Application {
    Application {
        id: app.id.clone(),
        app_id: app.app_id.clone(),
        display_name: app.display_name.clone(),
        ..Default::default()
    }
}

/// Replaces the row `same` picks, or appends `row` when there is none, so a
/// patch re-applied after a lost race (or to a scan that already saw the
/// write) cannot duplicate it.
fn upsert<T>(rows: &mut Vec<T>, row: T, same: impl Fn(&T) -> bool) {
    match rows.iter_mut().find(|r| same(r)) {
        Some(slot) => *slot = row,
        None => rows.push(row),
    }
}

/// What `invalidate_app_lists` drops besides the four scanned entries the
/// patch tier rewrites. All are rebuilt from the patched indexes (or, for the
/// role directory, only when the Grant-access picker opens).
fn invalidate_app_list_projections(cache: &Cache, tenant_id: &str) {
    cache.invalidate(CacheKind::Lists, &enterprise_key(tenant_id));
    cache.invalidate(CacheKind::Lists, &search_corpus_key(tenant_id));
    cache.invalidate(
        CacheKind::Lists,
        &crate::commands::managed_identity::mi_key(tenant_id),
    );
    invalidate_app_role_resources(cache, tenant_id);
    invalidate_app_details(cache, tenant_id);
    crate::commands::audit::invalidate_audit_cache(cache, tenant_id);
}

/// The patch tier for app registrations a write created. Rows are upserted
/// into the App Registrations list, the app-name index and the expiry roll-up.
/// A created service principal goes into the SP index.
pub(crate) fn record_created_apps(cache: &Cache, tenant_id: &str, created: &[CreatedApp<'_>]) {
    let now = chrono::Utc::now();
    let apps: Vec<(Application, Option<String>)> = created
        .iter()
        .map(|c| {
            let mut app = c.application.clone();
            if let Some(added) = c.added_password {
                app.password_credentials
                    .retain(|p| p.key_id != added.key_id);
                app.password_credentials.push(PasswordCredential {
                    secret_text: None,
                    ..added.clone()
                });
            }
            (app, c.service_principal.map(|sp| sp.id.clone()))
        })
        .collect();
    let created_ids: std::collections::HashSet<&str> =
        apps.iter().map(|(app, _)| app.id.as_str()).collect();

    let pairing_patched = cache.patch_typed_index::<Vec<ApplicationListRowDto>>(
        CacheKind::Lists,
        &apps_pairing_key(tenant_id),
        |rows| {
            let mut next = rows.clone();
            for (app, sp_id) in &apps {
                let row = ApplicationListRowDto::from_application(app.clone(), sp_id.clone(), now);
                upsert(&mut next, row, |r| r.id == app.id);
            }
            // Past the cap the scan truncated, and only a rescan knows which
            // rows belong in the first `APPS_MAX`.
            (next.len() <= super::APPS_MAX).then_some(next)
        },
    );
    cache.patch_typed_index::<Vec<Application>>(
        CacheKind::Lists,
        &app_name_index_key(tenant_id),
        |rows| {
            let mut next = rows.clone();
            for (app, _) in &apps {
                upsert(&mut next, app_name_index_row(app), |r| r.id == app.id);
            }
            (next.len() <= super::APPS_MAX).then_some(next)
        },
    );
    // The roll-up has one row per credential, so it cannot see the app cap
    // itself: it follows the app list's verdict. A list that was not patched
    // (at the cap, or cold) is rebuilt by the next scan, which rebuilds both.
    if pairing_patched {
        let created_apps: Vec<Application> = apps.iter().map(|(app, _)| app.clone()).collect();
        let created_rows = crate::commands::credentials::credential_rows(&created_apps, now);
        cache.patch_typed_index::<Vec<CredentialRowDto>>(
            CacheKind::Lists,
            &credential_expirations_key(tenant_id),
            |rows| {
                let mut next: Vec<CredentialRowDto> = rows
                    .iter()
                    .filter(|r| !created_ids.contains(r.app_object_id.as_str()))
                    .cloned()
                    .collect();
                next.extend(created_rows.iter().cloned());
                crate::commands::credentials::sort_credential_rows(&mut next);
                Some(next)
            },
        );
    } else {
        cache.invalidate(CacheKind::Lists, &credential_expirations_key(tenant_id));
    }
    let sps: Vec<ServicePrincipal> = created
        .iter()
        .filter_map(|c| {
            c.service_principal
                .map(azapptoolkit_graph::client::sp_index_row)
        })
        .collect();
    if !sps.is_empty() {
        cache.patch_typed_index::<Vec<ServicePrincipal>>(
            CacheKind::Lists,
            &sp_index_key(tenant_id),
            |index| {
                let mut next = index.clone();
                for sp in &sps {
                    upsert(&mut next, sp.clone(), |s| s.id == sp.id);
                }
                (next.len() <= azapptoolkit_graph::client::SP_INDEX_MAX).then_some(next)
            },
        );
    }
    invalidate_app_list_projections(cache, tenant_id);
}

/// The patch tier for deleted app registrations. Their rows leave the App
/// Registrations list, the app-name index and the expiry roll-up. Their
/// home-tenant service principals leave the SP index, because Graph deletes
/// an app's SP in its home tenant along with it.
///
/// The SP index is keyed by `appId`, which a delete doesn't carry, so the ids
/// are resolved from the cached app entries before those are patched. If one
/// can't be resolved, the SP index is dropped rather than left holding a
/// deleted SP.
pub(crate) fn record_deleted_apps(cache: &Cache, tenant_id: &str, object_ids: &[String]) {
    let deleted: std::collections::HashSet<&str> = object_ids.iter().map(String::as_str).collect();
    let app_ids: Option<std::collections::HashSet<String>> = {
        let names = app_name_index_hit(cache, tenant_id);
        let rows = apps_pairing_hit(cache, tenant_id);
        deleted
            .iter()
            .map(|id| {
                let from_names = names
                    .as_deref()
                    .and_then(|n| n.iter().find(|a| a.id == *id))
                    .map(|a| a.app_id.clone());
                from_names.or_else(|| {
                    rows.as_deref()
                        .and_then(|r| r.iter().find(|row| row.id == *id))
                        .map(|row| row.app_id.clone())
                })
            })
            .collect()
    };

    // A truncated index loses a row here that a rescan would backfill from
    // past the cap, so a full index is dropped, not patched.
    let pairing_patched = cache.patch_typed_index::<Vec<ApplicationListRowDto>>(
        CacheKind::Lists,
        &apps_pairing_key(tenant_id),
        |rows| {
            (rows.len() < super::APPS_MAX).then(|| {
                rows.iter()
                    .filter(|r| !deleted.contains(r.id.as_str()))
                    .cloned()
                    .collect()
            })
        },
    );
    cache.patch_typed_index::<Vec<Application>>(
        CacheKind::Lists,
        &app_name_index_key(tenant_id),
        |rows| {
            (rows.len() < super::APPS_MAX).then(|| {
                rows.iter()
                    .filter(|a| !deleted.contains(a.id.as_str()))
                    .cloned()
                    .collect()
            })
        },
    );
    if pairing_patched {
        cache.patch_typed_index::<Vec<CredentialRowDto>>(
            CacheKind::Lists,
            &credential_expirations_key(tenant_id),
            |rows| {
                Some(
                    rows.iter()
                        .filter(|r| !deleted.contains(r.app_object_id.as_str()))
                        .cloned()
                        .collect(),
                )
            },
        );
    } else {
        cache.invalidate(CacheKind::Lists, &credential_expirations_key(tenant_id));
    }
    match app_ids {
        Some(app_ids) => {
            cache.patch_typed_index::<Vec<ServicePrincipal>>(
                CacheKind::Lists,
                &sp_index_key(tenant_id),
                |index| {
                    (index.len() < azapptoolkit_graph::client::SP_INDEX_MAX).then(|| {
                        index
                            .iter()
                            .filter(|sp| !app_ids.contains(&sp.app_id))
                            .cloned()
                            .collect()
                    })
                },
            );
        }
        None => cache.invalidate(CacheKind::Lists, &sp_index_key(tenant_id)),
    }
    invalidate_app_list_projections(cache, tenant_id);
}

/// The patch tier for a rename (or sign-in audience change) of one app
/// registration. The fields are rewritten wherever the scanned entries carry
/// them.
///
/// The SP index is left alone. Graph syncs a service principal's
/// `displayName` from its app only eventually, so the Enterprise Apps row
/// keeps the name Graph currently returns until the TTL or a Refresh.
pub(crate) fn record_renamed_app(
    cache: &Cache,
    tenant_id: &str,
    object_id: &str,
    display_name: Option<&str>,
    sign_in_audience: Option<&str>,
) {
    cache.patch_typed_index::<Vec<ApplicationListRowDto>>(
        CacheKind::Lists,
        &apps_pairing_key(tenant_id),
        |rows| {
            let mut next = rows.clone();
            if let Some(row) = next.iter_mut().find(|r| r.id == object_id) {
                if let Some(name) = display_name {
                    row.display_name = name.to_string();
                }
                if let Some(audience) = sign_in_audience {
                    row.sign_in_audience = Some(audience.to_string());
                }
            }
            Some(next)
        },
    );
    if let Some(name) = display_name {
        cache.patch_typed_index::<Vec<Application>>(
            CacheKind::Lists,
            &app_name_index_key(tenant_id),
            |rows| {
                let mut next = rows.clone();
                if let Some(app) = next.iter_mut().find(|a| a.id == object_id) {
                    app.display_name = name.to_string();
                }
                Some(next)
            },
        );
        cache.patch_typed_index::<Vec<CredentialRowDto>>(
            CacheKind::Lists,
            &credential_expirations_key(tenant_id),
            |rows| {
                let mut next = rows.clone();
                for row in next.iter_mut().filter(|r| r.app_object_id == object_id) {
                    row.app_display_name = name.to_string();
                }
                Some(next)
            },
        );
    }
    invalidate_app_list_projections(cache, tenant_id);
}

/// Reads the cached per-tenant service-principal index, if present.
///
/// Stored on the **typed** path ([`Cache::put_typed_index`]), so a hit is a
/// refcount clone rather than a walk of a 10 000-entry JSON tree — this entry is
/// read by six surfaces (both entity lists, global search, the audit, the
/// consent audit, DR backup), and re-materializing it on each was pure CPU on a
/// runtime worker. It is also **pinned**, so the per-app `app_detail|…` /
/// `mail_scopes|…` entries sharing its bucket can't evict an index that costs a
/// full `/servicePrincipals` scan to rebuild.
///
/// Every reader must go through this (and [`sp_index_store_if_current`])
/// rather than `cache.get`: a typed entry read untyped reads as a miss,
/// silently costing a tenant-wide rescan.
pub(crate) fn sp_index_hit(cache: &Cache, tenant_id: &str) -> Option<Arc<Vec<ServicePrincipal>>> {
    cache.get_typed::<Vec<ServicePrincipal>>(CacheKind::Lists, &sp_index_key(tenant_id))
}

/// Unconditional store. Production readers fetch live and must use
/// [`sp_index_store_if_current`] so a mutation landing mid-scan isn't
/// overwritten by the pre-mutation snapshot; this shape is for tests that
/// construct the index directly.
///
/// `#[cfg(test)]` is the enforcement, not the doc comment: this wrapper passes
/// a generation captured *after* the fetch, which makes the guard a no-op, and
/// two production call sites (the App Registrations pairing join and the
/// audit's SP prefetch) had quietly taken it. Its `/applications` twin was
/// already gated — that asymmetry is what let them drift.
#[cfg(test)]
pub(crate) fn sp_index_store(
    cache: &Cache,
    tenant_id: &str,
    sps: Vec<ServicePrincipal>,
) -> Arc<Vec<ServicePrincipal>> {
    let watch = cache.generation_for(CacheKind::Lists, &sp_index_key(tenant_id));
    sp_index_store_if_current(cache, sps, watch)
}

/// Stores the index only if THIS KEY was not invalidated since `since`.
/// Callers that fetched live must capture [`Cache::generation_for`] BEFORE the
/// fetch: the scan takes seconds under no lock, and re-pinning a pre-mutation
/// snapshot would serve stale authorization data for the full `Lists` TTL, out
/// of LRU's reach.
pub(crate) fn sp_index_store_if_current(
    cache: &Cache,
    sps: Vec<ServicePrincipal>,
    watch: IndexWatch<'_>,
) -> Arc<Vec<ServicePrincipal>> {
    let shared = Arc::new(sps);
    cache.put_typed_index_if_current(watch, Arc::clone(&shared));
    shared
}

/// The per-tenant service-principal index, read through the same cache entry
/// the Enterprise Apps / App Registrations lists populate ([`sp_index_key`]),
/// so a tenant-wide scan (DR backup, consent audit) right after browsing those
/// lists doesn't re-pull `/servicePrincipals`. Falls back to a live fetch (and
/// seeds the cache) on a miss.
pub(crate) async fn sp_index_cached(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
) -> Result<Arc<Vec<ServicePrincipal>>, GraphError> {
    if let Some(cached) = sp_index_hit(&state.cache, tenant_id) {
        return Ok(cached);
    }
    // Single-flight. Six surfaces read this index (both lists, global search,
    // the audit, the consent audit, DR backup); on a cold tenant they fire
    // together, and a bare check-then-fetch had every one of them pay the same
    // multi-second `/servicePrincipals` scan and then race to overwrite the same
    // pinned key.
    let key = sp_index_key(tenant_id);
    let gate = state.single_flight(&key);
    let _held = gate.lock().await;
    // Re-check: the fetch we queued behind has already populated the cache.
    if let Some(cached) = sp_index_hit(&state.cache, tenant_id) {
        return Ok(cached);
    }
    // Captured BEFORE the multi-second scan: a mutation landing mid-flight
    // invalidates the key, and re-pinning this pre-mutation snapshot would
    // outlive the invalidation it raced. Watched per KEY, so a credential-only
    // mutation elsewhere in this tenant cannot make a valid index refuse.
    let watch = state.cache.generation_for(CacheKind::Lists, &key);
    // `?` here drops `watch`, ending the watch. That is the whole point of the
    // guard: a failed scan used to leave its registration behind forever, and
    // enough of those fill the table until every pinned-index store refuses.
    let sps = client.list_service_principals_index().await?;
    Ok(sp_index_store_if_current(&state.cache, sps, watch))
}

/// Reads the cached per-tenant app-registration index, if present.
///
/// The `/applications` counterpart of [`sp_index_hit`], and typed + pinned for
/// the same two reasons: four surfaces read it (global search, the Enterprise
/// Apps pairing join, the DR backup, the mailbox probe), so re-materializing a
/// 10 000-entry JSON tree per read was pure CPU on a runtime worker; and it
/// shares its bucket with the thousands of per-app `app_detail|…` /
/// `mail_scopes|…` writes, which must not be able to evict an entry that costs
/// a full `/applications` scan to rebuild.
///
/// Every reader must go through this (and [`app_name_index_store`]) rather than
/// `cache.get`: a typed entry read untyped reads as a miss, silently costing a
/// tenant-wide rescan.
pub(crate) fn app_name_index_hit(cache: &Cache, tenant_id: &str) -> Option<Arc<Vec<Application>>> {
    cache.get_typed::<Vec<Application>>(CacheKind::Lists, &app_name_index_key(tenant_id))
}

/// Caches a freshly-fetched app-registration index and hands back the shared
/// handle. Pair with [`app_name_index_hit`].
/// Unconditional store. Production readers fetch live and must use
/// [`app_name_index_store_if_current`] so a mutation landing mid-scan isn't
/// overwritten by the pre-mutation snapshot; this shape is for tests that
/// construct the index directly.
#[cfg(test)]
pub(crate) fn app_name_index_store(
    cache: &Cache,
    tenant_id: &str,
    apps: Vec<Application>,
) -> Arc<Vec<Application>> {
    let watch = cache.generation_for(CacheKind::Lists, &app_name_index_key(tenant_id));
    app_name_index_store_if_current(cache, apps, watch)
}

/// The `/applications` counterpart of [`sp_index_store_if_current`], with the
/// same rule: capture the generation before the live fetch, not after.
pub(crate) fn app_name_index_store_if_current(
    cache: &Cache,
    apps: Vec<Application>,
    watch: IndexWatch<'_>,
) -> Arc<Vec<Application>> {
    let shared = Arc::new(apps);
    cache.put_typed_index_if_current(watch, Arc::clone(&shared));
    shared
}

/// The per-tenant app-registration index, read through the shared cache entry
/// ([`app_name_index_key`]) and fetched on a miss. The `/applications` sibling
/// of [`sp_index_cached`].
///
/// Bounded by [`APPS_MAX`](super::APPS_MAX), like every other tenant-wide
/// enumeration in the backend — the caps must not drift, or one surface silently
/// knows about apps another does not.
pub(crate) async fn app_name_index_cached(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
) -> Result<Arc<Vec<Application>>, GraphError> {
    if let Some(cached) = app_name_index_hit(&state.cache, tenant_id) {
        return Ok(cached);
    }
    // Single-flight, for the same reason as [`sp_index_cached`] — four surfaces
    // read this one, and a cold tenant would otherwise buy a full
    // `/applications` scan per concurrent reader. The gate is the SHARED
    // [`app_scan_gate`], not one of its own: a cold reader here queues behind
    // an in-flight App Registrations scan, which seeds this index, and the
    // re-check below then hits. Worst case (this reader wins the race) is one
    // lean scan, then one full scan, serially — down from three concurrent ones.
    let key = app_name_index_key(tenant_id);
    let gate = app_scan_gate(state, tenant_id);
    let _held = gate.lock().await;
    if let Some(cached) = app_name_index_hit(&state.cache, tenant_id) {
        return Ok(cached);
    }
    // Captured BEFORE the scan — see `sp_index_cached`.
    let watch = state.cache.generation_for(CacheKind::Lists, &key);
    // `?` drops `watch` — see `sp_index_cached`.
    let apps = client
        .list_application_index_named(Some(super::APPS_MAX))
        .await?;
    Ok(app_name_index_store_if_current(&state.cache, apps, watch))
}

/// The ONE single-flight gate for every full `/applications` list read: the
/// App Registrations pairing rows, the credential-expiry roll-up and the
/// app-name index. Keyed on [`apps_pairing_key`] because that scan
/// ([`super::scan_app_list`]) is the superset the other two are projected from.
///
/// Lock order is this gate, then the SP-index gate — never the reverse.
pub(crate) fn app_scan_gate(state: &AppState, tenant_id: &str) -> Arc<tokio::sync::Mutex<()>> {
    state.single_flight(&apps_pairing_key(tenant_id))
}

/// The cached App Registrations list rows, if present — a refcount clone of
/// the typed, pinned entry [`super::scan_app_list`] stores.
///
/// Typed for the same reason as the two indexes: a warm visit used to walk the
/// whole JSON tree back into rows on every read. Read only through this (or
/// `get_typed`): an untyped `get` on a typed entry misses, silently costing a
/// full `/applications` rescan (pinned by
/// `repo_invariants::cache::pinned_keys_are_read_only_through_get_typed`).
pub(crate) fn apps_pairing_hit(
    cache: &Cache,
    tenant_id: &str,
) -> Option<Arc<Vec<ApplicationListRowDto>>> {
    cache.get_typed::<Vec<ApplicationListRowDto>>(CacheKind::Lists, &apps_pairing_key(tenant_id))
}

/// The cached credential-expiry roll-up, if present. Typed + pinned; see
/// [`apps_pairing_hit`].
pub(crate) fn credential_expirations_hit(
    cache: &Cache,
    tenant_id: &str,
) -> Option<Arc<Vec<CredentialRowDto>>> {
    cache.get_typed::<Vec<CredentialRowDto>>(
        CacheKind::Lists,
        &credential_expirations_key(tenant_id),
    )
}

/// The App Registrations list rows, read through [`apps_pairing_key`] and, on a
/// miss, produced by the shared scan behind [`app_scan_gate`] — which also
/// seeds the credential-expiry roll-up and the app-name index.
pub(crate) async fn apps_pairing_cached(
    state: &AppState,
    tenant_id: &str,
) -> Result<Arc<Vec<ApplicationListRowDto>>, GraphError> {
    if let Some(cached) = apps_pairing_hit(&state.cache, tenant_id) {
        tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = "apps_pairing", "hit");
        return Ok(cached);
    }
    tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = "apps_pairing", "miss");
    let gate = app_scan_gate(state, tenant_id);
    let _held = gate.lock().await;
    // Re-check: the scan we queued behind has already populated the cache.
    if let Some(cached) = apps_pairing_hit(&state.cache, tenant_id) {
        return Ok(cached);
    }
    Ok(super::scan_app_list(state, tenant_id).await?.rows)
}

/// The tenant-wide credential-expiry roll-up, read through
/// [`credential_expirations_key`] and, on a miss, derived from the shared App
/// Registrations scan behind [`app_scan_gate`] rather than a scan of its own.
pub(crate) async fn credential_expirations_cached(
    state: &AppState,
    tenant_id: &str,
) -> Result<Arc<Vec<CredentialRowDto>>, GraphError> {
    if let Some(cached) = credential_expirations_hit(&state.cache, tenant_id) {
        tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = "credential_expirations", "hit");
        return Ok(cached);
    }
    tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = "credential_expirations", "miss");
    let gate = app_scan_gate(state, tenant_id);
    let _held = gate.lock().await;
    // Re-check: the scan we queued behind has already populated the cache.
    if let Some(cached) = credential_expirations_hit(&state.cache, tenant_id) {
        return Ok(cached);
    }
    Ok(super::scan_app_list(state, tenant_id).await?.credentials)
}

/// Both tenant-wide indexes, fetching only the cold ones — and, when both are
/// cold, fetching them **concurrently**, so a first visit to a list that joins
/// them waits on one directory scan rather than two serial ones.
pub(crate) async fn indexes_cached(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
) -> Result<(Arc<Vec<ServicePrincipal>>, Arc<Vec<Application>>), GraphError> {
    // Each side already hit-checks before fetching, so this covers all four
    // cases on its own: both warm returns immediately, one cold fetches one, and
    // both cold still fetches concurrently — the two gates are distinct keys, so
    // single-flight never serializes them against each other.
    //
    // Deliberately routed through the gated helpers rather than calling the
    // client directly: the previous `(None, None)` arm reached past both gates,
    // which is precisely the concurrent-cold-reader case single-flight exists to
    // collapse.
    futures::future::try_join(
        sp_index_cached(state, client, tenant_id),
        app_name_index_cached(state, client, tenant_id),
    )
    .await
}

/// The `/applications` index carries the same three contracts the SP index
/// does — shared allocation, typed-only reachability, pinned against per-app
/// churn, dropped on the tenant sweep and on `invalidate_app_lists`. Mirrored
/// test for test in `sp_index_tests` rather than folded into one module, so a
/// regression names the index that broke — keep the two in step.
#[cfg(test)]
mod app_name_index_tests {
    use super::{app_name_index_hit, app_name_index_key, app_name_index_store};
    use azapptoolkit_core::cache::{Cache, CacheKind};
    use azapptoolkit_core::models::Application;

    fn app(id: &str) -> Application {
        Application {
            id: id.to_string(),
            app_id: format!("app-{id}"),
            display_name: id.to_string(),
            ..Default::default()
        }
    }

    /// A hit must hand back the SAME allocation, not a rebuild: four surfaces
    /// read this entry, and an untyped read walked a 10 000-entry JSON tree on
    /// a runtime worker every time.
    #[test]
    fn a_hit_is_a_refcount_clone_not_a_deserialize() {
        let cache = Cache::new();
        let stored = app_name_index_store(&cache, "t1", vec![app("a"), app("b")]);
        let hit = app_name_index_hit(&cache, "t1").expect("index hit");
        assert!(std::sync::Arc::ptr_eq(&stored, &hit));
    }

    /// The trap this design carries: stored typed, so a reader reaching for it
    /// with the plain `get` reads a MISS and silently pays for a full
    /// `/applications` rescan. Every reader must go through
    /// `app_name_index_hit` / `app_name_index_cached`.
    ///
    /// The second half is what this test used to be missing. Asserting only
    /// `.is_none()` is satisfied just as well by a DELETE, and a delete is what
    /// actually happened: the untyped `get` failed to decode the typed entry's
    /// `Value::Null` body and took the poison path, evicting the pinned
    /// tenant-wide index outright. The documented cost was "a miss and a
    /// rescan"; the real cost was losing the index for every surface until
    /// something rebuilt it. A guard that cannot tell a miss from an eviction
    /// cannot guard this.
    #[test]
    fn the_index_is_not_reachable_through_the_untyped_get() {
        let cache = Cache::new();
        let stored = app_name_index_store(&cache, "t1", vec![app("a")]);
        assert!(
            cache
                .get::<Vec<Application>>(CacheKind::Lists, &app_name_index_key("t1"))
                .is_none(),
            "read the typed index untyped — use app_name_index_hit instead"
        );
        let hit = app_name_index_hit(&cache, "t1")
            .expect("the untyped read must MISS the pinned index, not evict it");
        assert!(
            std::sync::Arc::ptr_eq(&stored, &hit),
            "the entry survived but was rebuilt — the untyped read must not disturb it at all"
        );
    }

    /// Pinning must never defeat the cross-tenant sweep — the repo's #1 footgun.
    #[test]
    fn the_pinned_index_is_still_dropped_on_tenant_sweep() {
        let cache = Cache::new();
        app_name_index_store(&cache, "t1", vec![app("a")]);
        app_name_index_store(&cache, "t2", vec![app("b")]);
        cache.invalidate_tenant("t1");
        assert!(app_name_index_hit(&cache, "t1").is_none(), "swept tenant");
        assert!(
            app_name_index_hit(&cache, "t2").is_some(),
            "other tenant kept"
        );
    }

    /// Per-app entries share this index's bucket; a mail-heavy audit writes
    /// thousands of them. Before pinning, that churn could evict an entry that
    /// costs a full `/applications` scan to rebuild.
    #[test]
    fn per_app_churn_cannot_evict_the_index() {
        let cache = Cache::new();
        cache.configure(None, None, None, None, None, Some(8));
        app_name_index_store(&cache, "t1", vec![app("a")]);
        for i in 0..200 {
            cache.put(
                CacheKind::Lists,
                format!("t1|app_detail|{i}"),
                &i.to_string(),
            );
        }
        assert!(app_name_index_hit(&cache, "t1").is_some());
    }

    /// The list-changing bust must reach the index — a create/delete/rename
    /// changes the app set every reader joins against.
    #[test]
    fn invalidate_app_lists_drops_the_index() {
        let cache = Cache::new();
        app_name_index_store(&cache, "t1", vec![app("a")]);
        app_name_index_store(&cache, "t2", vec![app("b")]);
        super::invalidate_app_lists(&cache, "t1");
        assert!(app_name_index_hit(&cache, "t1").is_none());
        assert!(
            app_name_index_hit(&cache, "t2").is_some(),
            "other tenant must survive"
        );
    }
}

#[cfg(test)]
mod sp_index_tests {
    use super::{sp_index_hit, sp_index_key, sp_index_store};
    use azapptoolkit_core::cache::{Cache, CacheKind};
    use azapptoolkit_core::models::ServicePrincipal;

    fn sp(id: &str) -> ServicePrincipal {
        serde_json::from_value(serde_json::json!({
            "id": id,
            "appId": format!("app-{id}"),
            "displayName": id,
        }))
        .expect("sample SP deserializes")
    }

    /// A hit must hand back the SAME allocation, not a rebuild — the whole
    /// reason the index is on the typed path (six surfaces read it, and each
    /// untyped read walked a 10 000-entry JSON tree on a runtime worker).
    #[test]
    fn a_hit_is_a_refcount_clone_not_a_deserialize() {
        let cache = Cache::new();
        let stored = sp_index_store(&cache, "t1", vec![sp("a"), sp("b")]);
        let hit = sp_index_hit(&cache, "t1").expect("index hit");
        assert!(std::sync::Arc::ptr_eq(&stored, &hit));
    }

    /// Guards the trap in this design: the index is stored typed, so a reader
    /// reaching for it with the plain `get` reads a MISS and silently pays for a
    /// full tenant rescan. Every reader must go through `sp_index_hit`.
    ///
    /// Asserting only `.is_none()` cannot tell a miss from an eviction — the
    /// untyped `get`'s poison path deletes an entry it can't decode — so the
    /// second half proves the pinned index is still there, untouched (the same
    /// guard as the `app_name_index` twin).
    #[test]
    fn the_index_is_not_reachable_through_the_untyped_get() {
        let cache = Cache::new();
        let stored = sp_index_store(&cache, "t1", vec![sp("a")]);
        assert!(
            cache
                .get::<Vec<ServicePrincipal>>(CacheKind::Lists, &sp_index_key("t1"))
                .is_none(),
            "read the typed index untyped — use sp_index_hit instead"
        );
        let hit = sp_index_hit(&cache, "t1")
            .expect("the untyped read must MISS the pinned index, not evict it");
        assert!(
            std::sync::Arc::ptr_eq(&stored, &hit),
            "the entry survived but was rebuilt — the untyped read must not disturb it at all"
        );
    }

    /// The index is pinned against LRU, but pinning must never defeat the
    /// cross-tenant sweep — that is the repo's #1 footgun.
    #[test]
    fn the_pinned_index_is_still_dropped_on_tenant_sweep() {
        let cache = Cache::new();
        sp_index_store(&cache, "t1", vec![sp("a")]);
        sp_index_store(&cache, "t2", vec![sp("b")]);
        cache.invalidate_tenant("t1");
        assert!(sp_index_hit(&cache, "t1").is_none(), "swept tenant");
        assert!(sp_index_hit(&cache, "t2").is_some(), "other tenant kept");
    }

    /// Per-app entries share the index's bucket; a mail-heavy audit writes
    /// thousands of them. The index must survive that pressure or the next list
    /// visit pays for a fresh `/servicePrincipals` scan.
    #[test]
    fn per_app_churn_cannot_evict_the_index() {
        let cache = Cache::new();
        cache.configure(None, None, None, None, None, Some(8));
        sp_index_store(&cache, "t1", vec![sp("a")]);
        for i in 0..200 {
            cache.put(
                CacheKind::Lists,
                format!("t1|mail_scopes|{i}"),
                &i.to_string(),
            );
        }
        assert!(sp_index_hit(&cache, "t1").is_some());
    }

    /// The list-changing bust must reach the index — a create/delete can add
    /// or remove a paired SP every join reads.
    #[test]
    fn invalidate_app_lists_drops_the_index() {
        let cache = Cache::new();
        sp_index_store(&cache, "t1", vec![sp("a")]);
        sp_index_store(&cache, "t2", vec![sp("b")]);
        super::invalidate_app_lists(&cache, "t1");
        assert!(sp_index_hit(&cache, "t1").is_none());
        assert!(
            sp_index_hit(&cache, "t2").is_some(),
            "other tenant must survive"
        );
    }
}

#[cfg(test)]
mod detail_cache_tests {
    use super::{app_detail_key, invalidate_app_details, invalidate_app_lists};
    use crate::commands::exchange::mail_scopes_key;
    use azapptoolkit_core::cache::{Cache, CacheKind};

    fn put_detail(cache: &Cache, tenant: &str, object_id: &str) {
        cache.put(
            CacheKind::Lists,
            app_detail_key(tenant, object_id),
            &object_id.to_string(),
        );
    }

    fn has_detail(cache: &Cache, tenant: &str, object_id: &str) -> bool {
        cache
            .get::<String>(CacheKind::Lists, &app_detail_key(tenant, object_id))
            .is_some()
    }

    fn put_mail_scopes(cache: &Cache, tenant: &str, discriminator: &str) {
        cache.put(
            CacheKind::Lists,
            mail_scopes_key(tenant, discriminator),
            &discriminator.to_string(),
        );
    }

    fn has_mail_scopes(cache: &Cache, tenant: &str, discriminator: &str) -> bool {
        cache
            .get::<String>(CacheKind::Lists, &mail_scopes_key(tenant, discriminator))
            .is_some()
    }

    #[test]
    fn detail_key_is_tenant_scoped() {
        // Same object id in two tenants must never share a cache entry.
        assert_ne!(app_detail_key("t1", "obj"), app_detail_key("t2", "obj"));
    }

    #[test]
    fn invalidate_app_details_clears_only_target_tenant() {
        let cache = Cache::new();
        put_detail(&cache, "t1", "a");
        put_detail(&cache, "t1", "b");
        put_detail(&cache, "t2", "a");

        invalidate_app_details(&cache, "t1");

        assert!(!has_detail(&cache, "t1", "a"));
        assert!(!has_detail(&cache, "t1", "b"));
        assert!(has_detail(&cache, "t2", "a"), "other tenant must survive");
    }

    #[test]
    fn invalidate_app_lists_also_clears_details() {
        // A list-level mutation must drop the detail pane too, or the pane would
        // render stale credentials/owners until the 60-minute TTL.
        let cache = Cache::new();
        put_detail(&cache, "t1", "a");
        invalidate_app_lists(&cache, "t1");
        assert!(!has_detail(&cache, "t1", "a"));
    }

    #[test]
    fn invalidate_app_lists_also_clears_the_audit_run() {
        // The transitive audit-leg: a list-changing mutation re-scores the
        // tenant, so the cached audit run must fall too. Pinned because a prior
        // review cycle mis-read this as a missing invalidation — the details and
        // mail-scopes legs were tested, the audit leg was not.
        use crate::commands::audit::audit_cache_key;
        let cache = Cache::new();
        cache.put(
            CacheKind::Audit,
            audit_cache_key("t1"),
            &"audit".to_string(),
        );
        cache.put(
            CacheKind::Audit,
            audit_cache_key("t2"),
            &"audit".to_string(),
        );
        invalidate_app_lists(&cache, "t1");
        assert!(
            cache
                .get::<String>(CacheKind::Audit, &audit_cache_key("t1"))
                .is_none()
        );
        assert!(
            cache
                .get::<String>(CacheKind::Audit, &audit_cache_key("t2"))
                .is_some(),
            "other tenant's audit must survive"
        );
    }

    /// The whole list tier, as one ratchet: every tenant key derived from the
    /// app/SP set falls for the mutated tenant, the other tenant keeps all of
    /// them, and a Lists key outside the tier is untouched. The doc paragraph in
    /// `caching-and-search.md` names the same set (pinned by
    /// `repo_invariants/cache.rs`), so a key added here without a doc line, or
    /// dropped from the function, fails one of the two.
    #[test]
    fn invalidate_app_lists_drops_every_app_set_key_and_nothing_else() {
        use super::{
            app_name_index_key, app_role_resources_key, apps_pairing_key,
            credential_expirations_key, enterprise_key, search_corpus_key, sp_index_key,
        };
        use crate::commands::audit::audit_cache_key;
        use crate::commands::managed_identity::mi_key;

        let list_keys = |t: &str| {
            vec![
                apps_pairing_key(t),
                enterprise_key(t),
                sp_index_key(t),
                app_name_index_key(t),
                search_corpus_key(t),
                mi_key(t),
                credential_expirations_key(t),
                app_role_resources_key(t),
                app_detail_key(t, "obj"),
                mail_scopes_key(t, "declared|obj"),
            ]
        };
        let cache = Cache::new();
        for t in ["t1", "t2"] {
            for key in list_keys(t) {
                cache.put(CacheKind::Lists, key.clone(), &key);
            }
            cache.put(CacheKind::Audit, audit_cache_key(t), &"audit".to_string());
        }
        cache.put(
            CacheKind::Lists,
            "t1|unrelated".to_string(),
            &"sentinel".to_string(),
        );

        invalidate_app_lists(&cache, "t1");

        let has = |kind, k: &str| cache.get::<String>(kind, k).is_some();
        for key in list_keys("t1") {
            assert!(
                !has(CacheKind::Lists, &key),
                "{key} must fall with the list tier"
            );
        }
        assert!(
            !has(CacheKind::Audit, &audit_cache_key("t1")),
            "the audit run must fall with the list tier"
        );
        for key in list_keys("t2") {
            assert!(
                has(CacheKind::Lists, &key),
                "other tenant's {key} must survive"
            );
        }
        assert!(has(CacheKind::Audit, &audit_cache_key("t2")));
        assert!(
            has(CacheKind::Lists, "t1|unrelated"),
            "a Lists key outside the tier is not an app-set key"
        );
    }

    /// A create/delete adds or removes an SP that may expose Application roles,
    /// so the Grant-access picker's "Tenant app registrations" directory must
    /// fall with the lists — a deleted app lingered there (and a fresh API was
    /// missing) for the full Lists TTL before this was wired.
    #[test]
    fn invalidate_app_lists_also_clears_the_app_role_resources_directory() {
        use super::app_role_resources_key;
        let cache = Cache::new();
        cache.put(
            CacheKind::Lists,
            app_role_resources_key("t1"),
            &"dir".to_string(),
        );
        cache.put(
            CacheKind::Lists,
            app_role_resources_key("t2"),
            &"dir".to_string(),
        );
        invalidate_app_lists(&cache, "t1");
        assert!(
            cache
                .get::<String>(CacheKind::Lists, &app_role_resources_key("t1"))
                .is_none()
        );
        assert!(
            cache
                .get::<String>(CacheKind::Lists, &app_role_resources_key("t2"))
                .is_some(),
            "other tenant's directory must survive"
        );
    }

    /// The App roles tab's targeted bust: one tenant's directory, nothing else.
    #[test]
    fn invalidate_app_role_resources_is_tenant_scoped() {
        use super::{app_role_resources_key, invalidate_app_role_resources};
        let cache = Cache::new();
        cache.put(
            CacheKind::Lists,
            app_role_resources_key("t1"),
            &"dir".to_string(),
        );
        cache.put(
            CacheKind::Lists,
            app_role_resources_key("t2"),
            &"dir".to_string(),
        );
        put_detail(&cache, "t1", "a");
        invalidate_app_role_resources(&cache, "t1");
        assert!(
            cache
                .get::<String>(CacheKind::Lists, &app_role_resources_key("t1"))
                .is_none()
        );
        assert!(
            cache
                .get::<String>(CacheKind::Lists, &app_role_resources_key("t2"))
                .is_some(),
            "other tenant's directory must survive"
        );
        assert!(
            has_detail(&cache, "t1", "a"),
            "a directory bust is not a detail bust"
        );
    }

    #[test]
    fn invalidate_app_details_also_clears_mail_scopes_tenant_scoped() {
        // A grant/revoke/scope mutation can change a mailbox-scope verdict, so
        // the cached verdicts must fall with the detail payloads — but only for
        // the mutated tenant.
        let cache = Cache::new();
        put_mail_scopes(&cache, "t1", "declared|obj");
        put_mail_scopes(&cache, "t1", "held|app|Mail.Read");
        put_mail_scopes(&cache, "t2", "declared|obj");

        invalidate_app_details(&cache, "t1");

        assert!(!has_mail_scopes(&cache, "t1", "declared|obj"));
        assert!(!has_mail_scopes(&cache, "t1", "held|app|Mail.Read"));
        assert!(
            has_mail_scopes(&cache, "t2", "declared|obj"),
            "other tenant must survive"
        );
    }

    #[test]
    fn invalidate_app_credentials_keeps_indexes_drops_row_detail_and_audit() {
        // A credential-only mutation can't add/remove/rename an SP or app, so
        // the tenant-wide SP and name indexes (whose re-scan is the expensive
        // part) must SURVIVE, while the apps list row, the mutated app's
        // detail, and the audit (it scores expiring credentials) are dropped.
        // Other apps' details, the mail-scope verdicts, and the other tenant
        // are untouched.
        use super::{
            app_name_index_key, app_role_resources_key, apps_pairing_key, enterprise_key,
            invalidate_app_credentials, sp_index_key,
        };
        use crate::commands::audit::audit_cache_key;

        let cache = Cache::new();
        cache.put(CacheKind::Lists, sp_index_key("t1"), &"sp".to_string());
        cache.put(
            CacheKind::Lists,
            app_role_resources_key("t1"),
            &"dir".to_string(),
        );
        cache.put(
            CacheKind::Lists,
            app_name_index_key("t1"),
            &"names".to_string(),
        );
        cache.put(CacheKind::Lists, enterprise_key("t1"), &"ent".to_string());
        cache.put(
            CacheKind::Lists,
            apps_pairing_key("t1"),
            &"apps".to_string(),
        );
        cache.put(
            CacheKind::Audit,
            audit_cache_key("t1"),
            &"audit".to_string(),
        );
        put_detail(&cache, "t1", "mutated");
        put_detail(&cache, "t1", "other");
        put_mail_scopes(&cache, "t1", "held|mutated|Mail.Read");
        cache.put(CacheKind::Lists, sp_index_key("t2"), &"sp2".to_string());

        invalidate_app_credentials(&cache, "t1", "mutated");

        let kept = |k: &str| cache.get::<String>(CacheKind::Lists, k).is_some();
        assert!(kept(&sp_index_key("t1")), "sp_index kept (no SP change)");
        assert!(kept(&app_name_index_key("t1")), "name index kept");
        assert!(kept(&enterprise_key("t1")), "enterprise list kept");
        assert!(
            kept(&app_role_resources_key("t1")),
            "app-role resource directory kept (a credential can't change which SPs expose roles)"
        );
        assert!(has_detail(&cache, "t1", "other"), "other app's detail kept");
        assert!(
            has_mail_scopes(&cache, "t1", "held|mutated|Mail.Read"),
            "mailbox-scope verdicts kept"
        );
        assert!(kept(&sp_index_key("t2")), "other tenant kept");

        assert!(!kept(&apps_pairing_key("t1")), "apps list row dropped");
        assert!(
            !has_detail(&cache, "t1", "mutated"),
            "mutated detail dropped"
        );
        assert!(
            cache
                .get::<String>(CacheKind::Audit, &audit_cache_key("t1"))
                .is_none(),
            "audit run dropped"
        );
    }
}

/// The patch tier: each `record_*` rewrites the four scanned entries in place
/// and drops exactly the projections `invalidate_app_lists` would have dropped
/// alongside them. Its end-to-end twins, which also prove no rescan follows,
/// are in `applications::handler_tests`.
#[cfg(test)]
mod patch_tier_tests {
    use super::*;
    use crate::commands::audit::audit_cache_key;
    use crate::commands::exchange::mail_scopes_key;
    use crate::commands::managed_identity::mi_key;
    use std::collections::BTreeSet;

    const T: &str = "t1";

    fn app(id: &str) -> Application {
        Application {
            id: id.to_string(),
            app_id: format!("app-{id}"),
            display_name: id.to_string(),
            password_credentials: vec![PasswordCredential {
                key_id: format!("k-{id}"),
                end_date_time: Some("2099-01-01T00:00:00Z".parse().unwrap()),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn sp(id: &str, app_id: &str) -> ServicePrincipal {
        ServicePrincipal {
            id: id.to_string(),
            app_id: app_id.to_string(),
            ..Default::default()
        }
    }

    /// Everything `invalidate_app_lists` drops besides the scanned four.
    fn projection_keys(t: &str) -> Vec<String> {
        vec![
            enterprise_key(t),
            search_corpus_key(t),
            mi_key(t),
            app_role_resources_key(t),
            app_detail_key(t, "obj"),
            mail_scopes_key(t, "declared|obj"),
        ]
    }

    /// The four scanned entries as `scan_app_list` and `sp_index_cached` store
    /// them (typed, pinned), holding `obj-1`, plus every projection.
    fn seeded(apps_in_list: Vec<Application>) -> Arc<Cache> {
        let cache = Cache::new();
        let now = chrono::Utc::now();
        let rows: Vec<ApplicationListRowDto> = apps_in_list
            .iter()
            .map(|a| ApplicationListRowDto::from_application(a.clone(), None, now))
            .collect();
        let names: Vec<Application> = apps_in_list.iter().map(app_name_index_row).collect();
        let creds = crate::commands::credentials::credential_rows(&apps_in_list, now);
        let sps: Vec<ServicePrincipal> =
            apps_in_list.iter().map(|a| sp("sp-1", &a.app_id)).collect();
        cache.put_typed_index(CacheKind::Lists, apps_pairing_key(T), Arc::new(rows));
        cache.put_typed_index(CacheKind::Lists, app_name_index_key(T), Arc::new(names));
        cache.put_typed_index(
            CacheKind::Lists,
            credential_expirations_key(T),
            Arc::new(creds),
        );
        cache.put_typed_index(CacheKind::Lists, sp_index_key(T), Arc::new(sps));
        for key in projection_keys(T) {
            cache.put(CacheKind::Lists, key.clone(), &key);
        }
        cache.put(CacheKind::Audit, audit_cache_key(T), &"audit".to_string());
        cache
    }

    fn list_ids(cache: &Cache) -> Vec<String> {
        apps_pairing_hit(cache, T)
            .expect("the list rows are kept")
            .iter()
            .map(|r| r.id.clone())
            .collect()
    }

    fn assert_projections_dropped(cache: &Cache, what: &str) {
        for key in projection_keys(T) {
            assert!(
                cache.get::<String>(CacheKind::Lists, &key).is_none(),
                "{what}: {key} must fall"
            );
        }
        assert!(
            cache
                .get::<String>(CacheKind::Audit, &audit_cache_key(T))
                .is_none(),
            "{what}: the audit run must fall"
        );
    }

    #[test]
    fn a_create_patches_the_scanned_entries_and_drops_the_projections() {
        let cache = seeded(vec![app("obj-1")]);
        let new_app = app("obj-2");
        let new_sp = sp("sp-2", "app-obj-2");
        record_created_apps(
            &cache,
            T,
            &[CreatedApp {
                application: &new_app,
                service_principal: Some(&new_sp),
                added_password: None,
            }],
        );

        assert_eq!(list_ids(&cache), ["obj-1", "obj-2"]);
        assert_eq!(app_name_index_hit(&cache, T).unwrap().len(), 2);
        assert_eq!(credential_expirations_hit(&cache, T).unwrap().len(), 2);
        assert!(
            sp_index_hit(&cache, T)
                .unwrap()
                .iter()
                .any(|s| s.id == "sp-2")
        );
        assert_projections_dropped(&cache, "create");
    }

    /// The cache retries a patch that lost a race against a newer entry, and
    /// a scan that ran after the create already holds the app. Either way a
    /// create applied twice must leave one row, not two.
    #[test]
    fn a_create_applied_twice_leaves_one_row() {
        let cache = seeded(vec![app("obj-1")]);
        let new_app = app("obj-2");
        let created = [CreatedApp {
            application: &new_app,
            service_principal: None,
            added_password: None,
        }];
        record_created_apps(&cache, T, &created);
        record_created_apps(&cache, T, &created);

        assert_eq!(list_ids(&cache), ["obj-1", "obj-2"]);
        assert_eq!(app_name_index_hit(&cache, T).unwrap().len(), 2);
        assert_eq!(credential_expirations_hit(&cache, T).unwrap().len(), 2);
    }

    /// A secret minted after the POST shows in the row and the roll-up.
    #[test]
    fn a_secret_added_after_the_post_reaches_the_row_and_the_roll_up() {
        let cache = seeded(vec![]);
        let bare = Application {
            id: "obj-2".into(),
            app_id: "app-2".into(),
            ..Default::default()
        };
        let secret = PasswordCredential {
            key_id: "k-new".into(),
            end_date_time: Some("2099-01-01T00:00:00Z".parse().unwrap()),
            secret_text: Some("s3cret".into()),
            ..Default::default()
        };
        record_created_apps(
            &cache,
            T,
            &[CreatedApp {
                application: &bare,
                service_principal: None,
                added_password: Some(&secret),
            }],
        );

        let rows = apps_pairing_hit(&cache, T).unwrap();
        assert_eq!(rows[0].password_credential_count, 1);
        assert_eq!(credential_expirations_hit(&cache, T).unwrap().len(), 1);
    }

    #[test]
    fn a_delete_patches_the_scanned_entries_and_drops_the_projections() {
        let cache = seeded(vec![app("obj-1"), app("obj-2")]);
        record_deleted_apps(&cache, T, &["obj-1".to_string()]);

        assert_eq!(list_ids(&cache), ["obj-2"]);
        assert_eq!(app_name_index_hit(&cache, T).unwrap().len(), 1);
        assert!(
            credential_expirations_hit(&cache, T)
                .unwrap()
                .iter()
                .all(|r| r.app_object_id != "obj-1")
        );
        assert!(
            sp_index_hit(&cache, T)
                .unwrap()
                .iter()
                .all(|s| s.app_id != "app-obj-1"),
            "Graph deletes the home-tenant SP with its app"
        );
        assert_projections_dropped(&cache, "delete");
    }

    /// The SP index is keyed by `appId`, which a delete doesn't carry. When no
    /// cached entry can resolve it, the index is dropped rather than left
    /// holding the deleted app's SP. The other entries are still patched.
    #[test]
    fn a_delete_with_an_unresolvable_app_id_drops_only_the_sp_index() {
        let cache = seeded(vec![app("obj-1")]);
        record_deleted_apps(&cache, T, &["obj-unknown".to_string()]);

        assert!(sp_index_hit(&cache, T).is_none());
        assert_eq!(list_ids(&cache), ["obj-1"]);
        assert!(app_name_index_hit(&cache, T).is_some());
    }

    #[test]
    fn a_rename_patches_the_scanned_entries_and_drops_the_projections() {
        let cache = seeded(vec![app("obj-1")]);
        record_renamed_app(&cache, T, "obj-1", Some("Renamed"), None);

        assert_eq!(
            apps_pairing_hit(&cache, T).unwrap()[0].display_name,
            "Renamed"
        );
        assert_eq!(
            app_name_index_hit(&cache, T).unwrap()[0].display_name,
            "Renamed"
        );
        assert_eq!(
            credential_expirations_hit(&cache, T).unwrap()[0].app_display_name,
            "Renamed"
        );
        assert!(
            sp_index_hit(&cache, T).is_some(),
            "the SP index is untouched"
        );
        assert_projections_dropped(&cache, "rename");
    }

    /// A list at `APPS_MAX` came from a truncated scan. Only a rescan knows
    /// which rows belong in it, so the patch tier drops it instead.
    #[test]
    fn a_list_at_the_cap_is_dropped_not_patched() {
        let full: Vec<Application> = (0..APPS_MAX_FOR_TEST)
            .map(|i| Application {
                id: format!("obj-{i}"),
                app_id: format!("app-{i}"),
                ..Default::default()
            })
            .collect();
        let cache = seeded(full);
        let new_app = app("obj-new");
        record_created_apps(
            &cache,
            T,
            &[CreatedApp {
                application: &new_app,
                service_principal: None,
                added_password: None,
            }],
        );
        assert!(apps_pairing_hit(&cache, T).is_none(), "create past the cap");
        assert!(
            credential_expirations_hit(&cache, T).is_none(),
            "the roll-up follows the app list's verdict on a create"
        );

        let cache = seeded(
            (0..APPS_MAX_FOR_TEST)
                .map(|i| Application {
                    id: format!("obj-{i}"),
                    app_id: format!("app-{i}"),
                    ..Default::default()
                })
                .collect(),
        );
        record_deleted_apps(&cache, T, &["obj-0".to_string()]);
        assert!(
            apps_pairing_hit(&cache, T).is_none(),
            "delete from a full list"
        );
        assert!(
            credential_expirations_hit(&cache, T).is_none(),
            "the roll-up follows the app list's verdict on a delete"
        );
    }

    const APPS_MAX_FOR_TEST: usize = super::super::APPS_MAX;

    /// `invalidate_app_list_projections` must keep dropping exactly what
    /// `invalidate_app_lists` drops besides the four scanned entries. A key
    /// added to the list tier and not here would survive every create, delete
    /// and rename, stale until the TTL. Read from the source, like the doc pin
    /// in `repo_invariants/cache.rs`.
    #[test]
    fn the_projections_are_what_the_list_tier_drops_besides_the_scanned_entries() {
        // Windows checks the source out with CRLF line endings.
        let src = include_str!("cache.rs").replace("\r\n", "\n");
        let body = |name: &str| {
            let start = src
                .find(&format!("fn {name}("))
                .unwrap_or_else(|| panic!("{name} moved"));
            // From the opening brace, so the function's own name isn't a call.
            let rest = &src[start..];
            let rest = &rest[rest.find('{').expect("function body")..];
            &rest[..rest.find("\n}\n").expect("function end")]
        };
        let calls = |text: &str| -> BTreeSet<String> {
            text.match_indices('(')
                .filter_map(|(at, _)| {
                    let head = &text[..at];
                    let start = head
                        .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .map_or(0, |i| i + 1);
                    let ident = &head[start..];
                    (ident.ends_with("_key") || ident.starts_with("invalidate_"))
                        .then(|| ident.to_string())
                })
                .collect()
        };

        let list_tier = calls(body("invalidate_app_lists"));
        let mut patch_tier = calls(body("invalidate_app_list_projections"));
        patch_tier.extend(
            [
                "apps_pairing_key",
                "app_name_index_key",
                "credential_expirations_key",
                "sp_index_key",
            ]
            .map(String::from),
        );
        assert!(list_tier.len() >= 8, "parsed {list_tier:?}");
        assert_eq!(patch_tier, list_tier);
    }
}
