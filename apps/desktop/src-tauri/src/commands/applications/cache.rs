//! Tenant-scoped list/detail cache keys and the tiered invalidation policy —
//! the home of the backend's #1-footgun contract (cross-tenant cache leakage).
//! Keys are always `{tenant_id}|…`-prefixed; the `invalidate_*` fns run only on
//! `Ok`. The tiering (`invalidate_app_lists` vs `invalidate_app_credentials`
//! vs `invalidate_app_detail_state`) is deliberate — relocate call sites, but
//! never merge the tiers (the credential tier exists to keep tenant-wide index
//! re-scans off the credential path).

use std::sync::Arc;

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{Application, ServicePrincipal};
use azapptoolkit_graph::{GraphClient, GraphError};

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
/// Every reader must go through this (and [`sp_index_store`]) rather than
/// `cache.get`: a typed entry read untyped reads as a miss, silently costing a
/// tenant-wide rescan.
pub(crate) fn sp_index_hit(cache: &Cache, tenant_id: &str) -> Option<Arc<Vec<ServicePrincipal>>> {
    cache.get_typed::<Vec<ServicePrincipal>>(CacheKind::Lists, &sp_index_key(tenant_id))
}

/// Caches a freshly-fetched service-principal index and hands back the shared
/// handle. Pair with [`sp_index_hit`].
pub(crate) fn sp_index_store(
    cache: &Cache,
    tenant_id: &str,
    sps: Vec<ServicePrincipal>,
) -> Arc<Vec<ServicePrincipal>> {
    let shared = Arc::new(sps);
    cache.put_typed_index(
        CacheKind::Lists,
        sp_index_key(tenant_id),
        Arc::clone(&shared),
    );
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
    let sps = client.list_service_principals_index().await?;
    Ok(sp_index_store(&state.cache, tenant_id, sps))
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
pub(crate) fn app_name_index_store(
    cache: &Cache,
    tenant_id: &str,
    apps: Vec<Application>,
) -> Arc<Vec<Application>> {
    let shared = Arc::new(apps);
    cache.put_typed_index(
        CacheKind::Lists,
        app_name_index_key(tenant_id),
        Arc::clone(&shared),
    );
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
    // `/applications` scan per concurrent reader.
    let key = app_name_index_key(tenant_id);
    let gate = state.single_flight(&key);
    let _held = gate.lock().await;
    if let Some(cached) = app_name_index_hit(&state.cache, tenant_id) {
        return Ok(cached);
    }
    let apps = client
        .list_application_index_named(Some(super::APPS_MAX))
        .await?;
    Ok(app_name_index_store(&state.cache, tenant_id, apps))
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
/// churn, dropped on the tenant sweep. Mirrored here rather than folded into
/// `sp_index_tests` so a regression names the index that broke.
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
    #[test]
    fn the_index_is_not_reachable_through_the_untyped_get() {
        let cache = Cache::new();
        app_name_index_store(&cache, "t1", vec![app("a")]);
        assert!(
            cache
                .get::<Vec<Application>>(CacheKind::Lists, &app_name_index_key("t1"))
                .is_none(),
            "read the typed index untyped — use app_name_index_hit instead"
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
    #[test]
    fn the_index_is_not_reachable_through_the_untyped_get() {
        let cache = Cache::new();
        sp_index_store(&cache, "t1", vec![sp("a")]);
        assert!(
            cache
                .get::<Vec<ServicePrincipal>>(CacheKind::Lists, &sp_index_key("t1"))
                .is_none(),
            "read the typed index untyped — use sp_index_hit instead"
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
            app_name_index_key, apps_pairing_key, enterprise_key, invalidate_app_credentials,
            sp_index_key,
        };
        use crate::commands::audit::audit_cache_key;

        let cache = Cache::new();
        cache.put(CacheKind::Lists, sp_index_key("t1"), &"sp".to_string());
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
