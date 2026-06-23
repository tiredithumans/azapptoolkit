use std::collections::HashMap;
use std::time::Duration;

use tauri::{AppHandle, State};

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{Application, Organization, Paged, ServicePrincipal};
use azapptoolkit_graph::client::{AppListQuery, AppPatch, CreateApplicationRequest};

use crate::dto::applications::{
    ApplicationDetail, ApplicationListRowDto, CreateApplicationInput, CreateApplicationResult,
    UpdateApplicationInput,
};
use crate::dto::UiError;
use crate::state::AppState;

mod authentication;
mod credentials;
mod federated;
mod owners;
mod permissions_resolve;

// Glob re-exports keep every item reachable at `crate::commands::applications::*`
// (the pre-split path) — crucially including the hidden `__cmd__<name>` items
// that `#[tauri::command]` generates, which `generate_handler!` resolves at
// `commands::applications::<fn>` alongside the function itself.
pub use authentication::*;
pub use credentials::*;
pub use federated::*;
pub use owners::*;
pub use permissions_resolve::*;

/// Lists cache keys are namespaced by tenant so a tenant switch never bleeds.
/// Mutations on app registrations also bust the enterprise-app key because a
/// new app may produce a paired SP that changes that list's join.
fn apps_pairing_key(tenant_id: &str) -> String {
    format!("{tenant_id}|apps_pairing")
}

fn enterprise_key(tenant_id: &str) -> String {
    format!("{tenant_id}|enterprise")
}

/// Cache key for the shared per-tenant service-principal index. Both list
/// views' pairing joins read through this entry, so a tab switch (or a
/// debounced search keystroke) reuses one directory scan instead of
/// re-enumerating every SP in the tenant.
pub(crate) fn sp_index_key(tenant_id: &str) -> String {
    format!("{tenant_id}|sp_index")
}

/// Cache key for the per-tenant app-registration name index (`id`, `appId`,
/// `displayName`) the global search substring-matches against. Distinct from
/// `sp_index` (service principals): app registrations without a paired SP only
/// live here.
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
fn app_detail_key(tenant_id: &str, object_id: &str) -> String {
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

// ---------------- Reads ----------------

#[tauri::command]
pub async fn get_organization(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Organization, UiError> {
    let client = state.graph_for(&tenant_id);
    client.get_organization().await.map_err(Into::into)
}

#[tauri::command]
pub async fn list_applications(
    state: State<'_, AppState>,
    tenant_id: String,
    search: Option<String>,
    top: Option<u32>,
) -> Result<Paged<Application>, UiError> {
    let mut query = AppListQuery::default();
    if let Some(s) = search.filter(|s| !s.trim().is_empty()) {
        query = query.with_search(s);
    }
    if let Some(t) = top {
        query = query.with_top(t);
    }
    let client = state.graph_for(&tenant_id);
    client.list_applications(query).await.map_err(Into::into)
}

/// `$select` for the App Registrations list rows. Drops `requiredResourceAccess`
/// and `description` (not rendered by the list; the detail pane re-fetches the
/// full application). Keeps the credential arrays — the credential-status
/// classification, per-kind counts, and soonest expiry are computed from them
/// *here* so only those scalars cross IPC (the arrays dominate the payload at
/// thousands of rows) — plus `createdDateTime` (the created-after filter) and
/// the scalar `signInAudience` / `publisherDomain` (the inventory export
/// reports them).
fn list_row_select() -> Vec<&'static str> {
    vec![
        "id",
        "appId",
        "displayName",
        "signInAudience",
        "publisherDomain",
        "createdDateTime",
        "passwordCredentials",
        "keyCredentials",
    ]
}

/// Graph caps `$top` at 100 on `/applications`; we page through with that window.
const APPS_PAGE_SIZE: u32 = 100;
/// Safety cap on total apps materialized for the browse list, mirroring the
/// audit/credential scans. Well above real-world app-registration counts.
const APPS_MAX: usize = 10_000;

/// Lean list-row variant of [`list_applications`]: each row is flattened to
/// the scalars the list renders, with credential status/counts/soonest-expiry
/// pre-computed here, and carries the paired Enterprise Application
/// service-principal object id (when one exists in this tenant). The list's
/// search/date/credential filters all run in the frontend over this result,
/// so a search keystroke never re-enters Graph.
///
/// Follows `@odata.nextLink` to completion (bounded by [`APPS_MAX`]) so large
/// tenants see every app, not just the first Graph page, then caches the whole
/// joined result under `apps_pairing_key` — one paginated scan serves repeated
/// browsing until the TTL. (Credential statuses are classified at fetch time,
/// so within the TTL a row's bucket can lag reality by at most that long;
/// Refresh re-classifies.)
#[tauri::command]
pub async fn list_applications_with_pairing(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<ApplicationListRowDto>, UiError> {
    let cache_key = apps_pairing_key(&tenant_id);
    if let Some(cached) = state
        .cache
        .get::<Vec<ApplicationListRowDto>>(CacheKind::Lists, &cache_key)
    {
        tracing::debug!(
            target = "azapptoolkit::cache",
            kind = "Lists",
            key = cache_key,
            "hit"
        );
        return Ok(cached);
    }
    tracing::debug!(
        target = "azapptoolkit::cache",
        kind = "Lists",
        key = cache_key,
        "miss"
    );

    let query = AppListQuery::default()
        .with_select(list_row_select())
        .with_top(APPS_PAGE_SIZE);
    let client = state.graph_for(&tenant_id);

    // The pairing join reads the shared SP index. When it is already cached,
    // just enumerate the apps; on a cold miss fetch both concurrently so the
    // join's long pole is one directory scan, not two serial ones. Both sides
    // follow `@odata.nextLink` to completion.
    let index_key = sp_index_key(&tenant_id);
    let (apps, sps) = match state
        .cache
        .get::<Vec<ServicePrincipal>>(CacheKind::Lists, &index_key)
    {
        Some(cached_index) => (
            client.list_applications_all(query, Some(APPS_MAX)).await?,
            cached_index,
        ),
        None => {
            let (apps, sps) = futures::future::try_join(
                client.list_applications_all(query, Some(APPS_MAX)),
                client.list_service_principals_index(),
            )
            .await?;
            state.cache.put(CacheKind::Lists, index_key, &sps);
            (apps, sps)
        }
    };

    let by_app_id: HashMap<String, String> = sps.into_iter().map(|sp| (sp.app_id, sp.id)).collect();

    let now = chrono::Utc::now();
    let rows: Vec<ApplicationListRowDto> = apps
        .into_iter()
        .map(|application| {
            let paired = by_app_id.get(&application.app_id).cloned();
            ApplicationListRowDto::from_application(application, paired, now)
        })
        .collect();

    state.cache.put(CacheKind::Lists, cache_key, &rows);

    Ok(rows)
}

#[tauri::command]
pub async fn get_application_detail(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<ApplicationDetail, UiError> {
    // Read-through cache: clicking between apps re-runs this ~6-call fan-out, so
    // a 60-minute (LISTS_CACHE_TTL) entry makes back-and-forth navigation free.
    // Every mutation that touches detail-visible state busts it (see
    // `invalidate_app_details` / `invalidate_app_lists`).
    let detail_key = app_detail_key(&tenant_id, &object_id);
    if let Some(cached) = state
        .cache
        .get::<ApplicationDetail>(CacheKind::Lists, &detail_key)
    {
        return Ok(cached);
    }

    let client = state.graph_for(&tenant_id);
    let application = client.get_application(&object_id).await?;

    // Wave 1: the SP lookup (keyed by appId) and the owners list (keyed by the
    // application object id) are independent — run them concurrently.
    let (service_principal, owners) = futures::future::try_join(
        client.get_service_principal_by_app_id(&application.app_id),
        client.list_owners(&application.id),
    )
    .await?;

    // Wave 2: role assignments and delegated grants both key off the SP id and
    // are independent of each other.
    let (app_role_assignments, oauth2_permission_grants) = match service_principal.as_ref() {
        Some(sp) => {
            futures::future::try_join(
                client.list_app_role_assignments(&sp.id),
                client.list_oauth2_grants(&sp.id),
            )
            .await?
        }
        None => (Vec::new(), Vec::new()),
    };

    let resolved_permissions = permissions_resolve::resolve_required_resource_access(
        &client,
        &application.required_resource_access,
        &app_role_assignments,
        &oauth2_permission_grants,
    )
    .await;

    let detail = ApplicationDetail {
        application,
        service_principal,
        owners,
        app_role_assignments,
        oauth2_permission_grants,
        resolved_permissions,
    };
    state.cache.put(CacheKind::Lists, detail_key, &detail);
    Ok(detail)
}

/// Drops the cached detail payload for a *single* application so the next
/// `get_application_detail` re-fetches it from Graph. Backs the detail-pane
/// Refresh button: unlike `invalidate_app_details` (whole-tenant prefix), this
/// targets one app, so refreshing one open detail leaves other apps' caches
/// warm.
#[tauri::command]
pub async fn invalidate_application_detail(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<(), UiError> {
    state
        .cache
        .invalidate(CacheKind::Lists, &app_detail_key(&tenant_id, &object_id));
    Ok(())
}

// ---------------- M3 mutations ----------------

#[tauri::command]
pub async fn create_application(
    state: State<'_, AppState>,
    tenant_id: String,
    input: CreateApplicationInput,
) -> Result<CreateApplicationResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let result = create_application_core(&client, input).await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(result)
}

/// Shared application-creation logic, reused by the single-app command and the
/// bulk path so both have identical semantics.
pub(crate) async fn create_application_core(
    client: &azapptoolkit_graph::GraphClient,
    input: CreateApplicationInput,
) -> Result<CreateApplicationResult, UiError> {
    let body = CreateApplicationRequest {
        display_name: input.display_name,
        sign_in_audience: input.sign_in_audience,
        description: input.description,
    };
    let application = client.create_application(&body).await?;

    let service_principal = if input.create_service_principal {
        // `create_application` already busts the list caches below, so the
        // `created` flag is unused here.
        Some(
            client
                .ensure_service_principal(&application.app_id)
                .await?
                .0,
        )
    } else {
        None
    };

    let initial_secret = if let Some(name) = input.initial_secret_display_name.as_deref() {
        let days = input.initial_secret_lifetime_days.unwrap_or(180);
        let lifetime = Duration::from_secs(days as u64 * 86_400);
        Some(client.add_password(&application.id, name, lifetime).await?)
    } else {
        None
    };

    let mut added_owner_ids = Vec::with_capacity(input.initial_owner_ids.len());
    let mut failed_owner_ids = Vec::new();
    for owner in input.initial_owner_ids {
        match client.add_owner(&application.id, &owner).await {
            Ok(()) => added_owner_ids.push(owner),
            Err(err) => {
                tracing::warn!(%owner, ?err, "failed to add initial owner on create");
                failed_owner_ids.push(owner);
            }
        }
    }

    Ok(CreateApplicationResult {
        application,
        service_principal,
        initial_secret,
        added_owner_ids,
        failed_owner_ids,
    })
}

#[tauri::command]
pub async fn update_application(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    patch: UpdateApplicationInput,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    let graph_patch = AppPatch {
        display_name: patch.display_name,
        sign_in_audience: patch.sign_in_audience,
        description: patch.description,
        required_resource_access: None,
    };
    client.update_application(&object_id, &graph_patch).await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(())
}

#[tauri::command]
pub async fn delete_application(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.delete_application(&object_id).await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(())
}

// ---------------- Inventory export ----------------

/// Serializes the app-registration list as CSV for an access review. Display
/// names are app-controllable, so every text field goes through `csv_field`
/// (formula-injection guard + delimiter quoting), reused from the audit export.
fn applications_to_csv(rows: &[ApplicationListRowDto]) -> String {
    use super::audit::csv_field;
    let mut out = String::new();
    out.push_str("DisplayName,AppId,ObjectId,SignInAudience,PublisherDomain,Created,Secrets,Certificates,SoonestCredentialExpiry,PairedEnterpriseAppId\n");
    for r in rows {
        let row = [
            csv_field(&r.display_name),
            csv_field(&r.app_id),
            csv_field(&r.id),
            csv_field(r.sign_in_audience.as_deref().unwrap_or("")),
            csv_field(r.publisher_domain.as_deref().unwrap_or("")),
            csv_field(
                &r.created_date_time
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            ),
            r.password_credential_count.to_string(),
            r.key_credential_count.to_string(),
            csv_field(
                &r.soonest_credential_expiry
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            ),
            csv_field(r.paired_service_principal_id.as_deref().unwrap_or("")),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// Exports the (frontend-filtered) app-registration list to a CSV/JSON file via
/// the OS save dialog. The rows are passed from the frontend so the export
/// reflects exactly the active filters (which live there). Returns the path, or
/// `None` if the user cancelled.
#[tauri::command]
pub async fn save_applications_to_file(
    app_handle: AppHandle,
    rows: Vec<ApplicationListRowDto>,
    format: String,
) -> Result<Option<String>, UiError> {
    super::audit::save_export_via_dialog(
        &app_handle,
        "app-registrations",
        &format,
        || applications_to_csv(&rows),
        || serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string()),
    )
    .await
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
        assert!(cache
            .get::<String>(CacheKind::Audit, &audit_cache_key("t1"))
            .is_none());
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

#[cfg(test)]
mod export_tests {
    use super::*;
    use azapptoolkit_core::models::PasswordCredential;

    fn row(name: &str, paired: Option<&str>) -> ApplicationListRowDto {
        let now = chrono::DateTime::parse_from_rfc3339("2024-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let app = Application {
            id: "obj-1".into(),
            app_id: "app-1".into(),
            display_name: name.into(),
            password_credentials: vec![PasswordCredential {
                end_date_time: Some(
                    chrono::DateTime::parse_from_rfc3339("2024-09-01T00:00:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                ),
                ..Default::default()
            }],
            ..Default::default()
        };
        ApplicationListRowDto::from_application(app, paired.map(str::to_string), now)
    }

    #[test]
    fn csv_has_header_and_one_row_per_app() {
        let csv = applications_to_csv(&[row("App A", Some("sp-1")), row("App B", None)]);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("DisplayName,AppId,ObjectId"));
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[1].starts_with("App A,"));
        // Soonest-expiry column is populated from the credential.
        assert!(lines[1].contains("2024-09-01"));
        // Per-kind counts come from the pre-computed scalars.
        assert!(lines[1].contains(",1,0,"));
    }

    #[test]
    fn csv_neutralizes_formula_injection_in_display_name() {
        let csv = applications_to_csv(&[row("=cmd|'/c calc',A1", None)]);
        assert!(csv.contains("\"'=cmd|'/c calc',A1\""));
        assert!(!csv.lines().skip(1).any(|l| l.starts_with('=')));
    }

    #[test]
    fn json_round_trips_rows() {
        let rows = vec![row("App A", Some("sp-1"))];
        let json = serde_json::to_string_pretty(&rows).unwrap();
        let back: Vec<ApplicationListRowDto> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].display_name, "App A");
        assert_eq!(back[0].paired_service_principal_id.as_deref(), Some("sp-1"));
    }
}
