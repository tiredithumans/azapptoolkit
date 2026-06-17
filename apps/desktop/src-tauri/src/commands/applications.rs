use std::collections::{HashMap, HashSet};
use std::time::Duration;

use tauri::{AppHandle, State};

use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{
    Application, DirectoryObject, FederatedIdentityCredential, NewKeyCredential, Organization,
    Paged, PasswordCredential, ServicePrincipal,
};
use azapptoolkit_graph::client::{
    AppListQuery, AppPatch, ApplicationAuthenticationPatch, ApplicationPublicClientPatch,
    ApplicationSpaPatch, ApplicationWebPatch, CreateApplicationRequest, FederatedCredentialPatch,
    FederatedCredentialRequest, ImplicitGrantSettingsPatch,
};
use azapptoolkit_permissions::PermissionsCatalog;

use crate::dto::applications::{
    AddCertificateInput, AddFederatedCredentialInput, AddPasswordInput,
    ApplicationAuthenticationDto, ApplicationDetail, ApplicationListRowDto, CreateApplicationInput,
    CreateApplicationResult, FederatedCredentialDto, GenerateCertificateInput,
    GeneratedCertificateResult, KeyFailure, OwnerChangeFailure, PermissionDescriptor,
    RemoveExpiredResult, SetApplicationAuthenticationInput, SetOwnersResult,
    UpdateApplicationInput, UpdateFederatedCredentialInput,
};
use crate::dto::permissions::{PermissionKind, ResolvedPermission};
use crate::dto::UiError;
use crate::state::AppState;

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

    let resolved_permissions = resolve_required_resource_access(
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

/// Resolves one declared permission to a [`ResolvedPermission`] through the
/// fixed fallback ladder — bundled catalog → live resource SP (`appRoles` then
/// `oauth2PermissionScopes`) → raw GUID with the declared Role/Scope kind —
/// joining the matching runtime grant via the caller's per-resource closures.
/// Extracted so the ladder reads once instead of three near-identical struct
/// builds inside the loop.
#[allow(clippy::too_many_arguments)]
fn resolve_one_permission(
    catalog: &PermissionsCatalog,
    resource_app_id: &str,
    resource_display_name: &Option<String>,
    cataloged: Option<&azapptoolkit_permissions::ResourceEntry>,
    live_sp: Option<&ServicePrincipal>,
    access: &azapptoolkit_core::models::ResourceAccess,
    runtime_assignment_for: &impl Fn(&str) -> Option<String>,
    runtime_grant_for: &impl Fn(&str) -> Option<String>,
) -> ResolvedPermission {
    // 1. Catalog.
    if let Some((display, kind)) = catalog.lookup_permission(resource_app_id, &access.id) {
        let permission_value = cataloged.and_then(|r| {
            r.app_roles
                .iter()
                .find(|x| x.id == access.id)
                .map(|x| x.value.clone())
                .or_else(|| {
                    r.oauth2_permission_scopes
                        .iter()
                        .find(|x| x.id == access.id)
                        .map(|x| x.value.clone())
                })
        });
        let permission_kind = PermissionKind::from_catalog_kind(kind);
        let (runtime_assignment_id, runtime_grant_id) = match permission_kind {
            PermissionKind::Application => (runtime_assignment_for(&access.id), None),
            PermissionKind::Delegated => (
                None,
                permission_value.as_deref().and_then(runtime_grant_for),
            ),
            PermissionKind::Unknown => (None, None),
        };
        return ResolvedPermission {
            resource_app_id: resource_app_id.to_string(),
            resource_display_name: resource_display_name.clone(),
            permission_id: access.id.clone(),
            permission_value,
            permission_display_name: Some(display),
            permission_kind,
            runtime_assignment_id,
            runtime_grant_id,
        };
    }

    // 2. Live SP fallback (appRoles, then oauth2PermissionScopes).
    if let Some(sp) = live_sp {
        if let Some(role) = sp.app_roles.iter().find(|r| r.id == access.id) {
            return ResolvedPermission {
                resource_app_id: resource_app_id.to_string(),
                resource_display_name: resource_display_name.clone(),
                permission_id: access.id.clone(),
                permission_value: Some(role.value.clone()),
                permission_display_name: Some(role.display_name.clone()),
                permission_kind: PermissionKind::Application,
                runtime_assignment_id: runtime_assignment_for(&access.id),
                runtime_grant_id: None,
            };
        }
        if let Some(scope) = sp
            .oauth2_permission_scopes
            .iter()
            .find(|s| s.id == access.id)
        {
            let display = scope
                .admin_consent_display_name
                .clone()
                .unwrap_or_else(|| scope.value.clone());
            return ResolvedPermission {
                resource_app_id: resource_app_id.to_string(),
                resource_display_name: resource_display_name.clone(),
                permission_id: access.id.clone(),
                permission_value: Some(scope.value.clone()),
                permission_display_name: Some(display),
                permission_kind: PermissionKind::Delegated,
                runtime_assignment_id: None,
                runtime_grant_id: runtime_grant_for(&scope.value),
            };
        }
    }

    // 3. Total miss: surface raw GUIDs with the declared Role/Scope kind.
    let permission_kind = match access.r#type.as_str() {
        "Role" => PermissionKind::Application,
        "Scope" => PermissionKind::Delegated,
        _ => PermissionKind::Unknown,
    };
    let runtime_assignment_id = matches!(permission_kind, PermissionKind::Application)
        .then(|| runtime_assignment_for(&access.id))
        .flatten();
    ResolvedPermission {
        resource_app_id: resource_app_id.to_string(),
        resource_display_name: resource_display_name.clone(),
        permission_id: access.id.clone(),
        permission_value: None,
        permission_display_name: None,
        permission_kind,
        runtime_assignment_id,
        runtime_grant_id: None,
    }
}

async fn resolve_required_resource_access(
    client: &azapptoolkit_graph::GraphClient,
    declared: &[azapptoolkit_core::models::RequiredResourceAccess],
    app_role_assignments: &[azapptoolkit_core::models::AppRoleAssignment],
    oauth2_permission_grants: &[azapptoolkit_core::models::OAuth2PermissionGrant],
) -> Vec<ResolvedPermission> {
    let catalog = PermissionsCatalog::bundled();

    // Resolve every distinct declared resource's SP up front and concurrently
    // (each is an independent, Permissions-cached Graph lookup) so the per-row
    // formatting below reads `live_sps` without awaiting, instead of paying one
    // serial round trip per resource on a cold cache. We need each SP's id to
    // join runtime assignments/grants to the declared rows.
    let unique_resource_ids: Vec<String> = {
        let mut seen = HashSet::new();
        declared
            .iter()
            .map(|r| r.resource_app_id.clone())
            .filter(|id| seen.insert(id.clone()))
            .collect()
    };
    let live_sps: HashMap<String, Option<ServicePrincipal>> =
        futures::future::join_all(unique_resource_ids.into_iter().map(|id| async move {
            let sp = client.resolve_resource_sp(&id).await.ok().flatten();
            (id, sp)
        }))
        .await
        .into_iter()
        .collect();

    let mut out = Vec::new();

    for resource in declared {
        let cataloged = catalog.resource(&resource.resource_app_id);
        let resource_display_from_catalog = cataloged.map(|r| r.display_name.clone());

        let live_sp = live_sps
            .get(&resource.resource_app_id)
            .and_then(|o| o.as_ref());
        let resource_sp_id = live_sp.map(|sp| sp.id.as_str());

        let resource_display_name =
            resource_display_from_catalog.or_else(|| live_sp.map(|sp| sp.display_name.clone()));

        // Runtime-grant joins. Application: assignment.resource_id ==
        // resource_sp.id && assignment.app_role_id == permission_id.
        // Delegated: grant.resource_id == resource_sp.id and the scope
        // string contains the scope value (split_whitespace handles weird
        // whitespace exactly like the revoke command does).
        let runtime_assignment_for = |permission_id: &str| -> Option<String> {
            let sp_id = resource_sp_id?;
            app_role_assignments
                .iter()
                .find(|a| a.resource_id == sp_id && a.app_role_id == permission_id)
                .map(|a| a.id.clone())
        };
        let runtime_grant_for = |scope_value: &str| -> Option<String> {
            let sp_id = resource_sp_id?;
            oauth2_permission_grants
                .iter()
                .find(|g| {
                    g.resource_id == sp_id && g.scope.split_whitespace().any(|s| s == scope_value)
                })
                .and_then(|g| g.id.clone())
        };

        for access in &resource.resource_access {
            out.push(resolve_one_permission(
                catalog,
                &resource.resource_app_id,
                &resource_display_name,
                cataloged,
                live_sp,
                access,
                &runtime_assignment_for,
                &runtime_grant_for,
            ));
        }
    }

    out
}

#[tauri::command]
pub async fn resolve_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    resource_app_id: String,
    permission_id: String,
) -> Result<PermissionDescriptor, UiError> {
    let catalog = PermissionsCatalog::bundled();
    if let Some((display_name, kind)) = catalog.lookup_permission(&resource_app_id, &permission_id)
    {
        let resource_display_name = catalog
            .resource(&resource_app_id)
            .map(|r| r.display_name.clone())
            .unwrap_or_else(|| resource_app_id.clone());
        return Ok(PermissionDescriptor {
            display_name,
            kind: kind.to_string(),
            resource_display_name,
            source: "bundled".to_string(),
        });
    }

    let client = state.graph_for(&tenant_id);
    let sp = client
        .resolve_resource_sp(&resource_app_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "resource",
                format!("resource app id {resource_app_id} not found"),
            )
        })?;

    if let Some(role) = sp.app_roles.iter().find(|r| r.id == permission_id) {
        return Ok(PermissionDescriptor {
            display_name: role.display_name.clone(),
            kind: "Role".into(),
            resource_display_name: sp.display_name,
            source: "graph".into(),
        });
    }
    if let Some(scope) = sp
        .oauth2_permission_scopes
        .iter()
        .find(|s| s.id == permission_id)
    {
        let name = scope
            .admin_consent_display_name
            .clone()
            .unwrap_or_else(|| scope.value.clone());
        return Ok(PermissionDescriptor {
            display_name: name,
            kind: "Scope".into(),
            resource_display_name: sp.display_name,
            source: "graph".into(),
        });
    }

    Err(UiError::not_found(
        "permission",
        format!("permission id {permission_id} not found on {resource_app_id}"),
    ))
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
        Some(client.ensure_service_principal(&application.app_id).await?)
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

/// Reads the app's Authentication-tab settings (per-platform reply URLs, logout
/// URL, implicit-grant flags, fallback-public-client flag). A live read — these
/// fields aren't on the cached list shape, so the tab fetches them on demand.
#[tauri::command]
pub async fn get_application_authentication(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<ApplicationAuthenticationDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let raw = client
        .get_application_auth_fields(&object_id)
        .await?
        .ok_or_else(|| UiError::not_found("application", "application not found"))?;
    Ok(extract_auth_fields(&raw))
}

/// Flattens the raw `/applications/{id}` JSON (the
/// `web`/`spa`/`publicClient`/`isFallbackPublicClient` projection) into the
/// Authentication DTO. A missing block ⇒ empty list / `false` / `None`.
pub(crate) fn extract_auth_fields(v: &serde_json::Value) -> ApplicationAuthenticationDto {
    let uris = |parent: &str| -> Vec<String> {
        v.get(parent)
            .and_then(|p| p.get("redirectUris"))
            .and_then(|u| u.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let web = v.get("web");
    let logout_url = web
        .and_then(|w| w.get("logoutUrl"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let implicit = web.and_then(|w| w.get("implicitGrantSettings"));
    let flag = |obj: Option<&serde_json::Value>, key: &str| -> bool {
        obj.and_then(|o| o.get(key))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    };
    ApplicationAuthenticationDto {
        web_redirect_uris: uris("web"),
        spa_redirect_uris: uris("spa"),
        public_client_redirect_uris: uris("publicClient"),
        logout_url,
        is_fallback_public_client: flag(Some(v), "isFallbackPublicClient"),
        enable_access_token_issuance: flag(implicit, "enableAccessTokenIssuance"),
        enable_id_token_issuance: flag(implicit, "enableIdTokenIssuance"),
    }
}

/// Writes the app's Authentication-tab settings. Each redirect-URI list is a
/// full replace of that platform's set (an empty list clears it), so the editor
/// loads current values before saving. All URIs are validated (reusing the SSO
/// redirect rules — no wildcards, https or loopback-http or custom schemes only)
/// before the PATCH. On success the app-detail cache is busted, and the audit
/// cache too (the public-client / implicit-grant flags feed audit rules).
#[tauri::command]
pub async fn set_application_authentication(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: SetApplicationAuthenticationInput,
) -> Result<(), UiError> {
    for set in [
        &input.web_redirect_uris,
        &input.spa_redirect_uris,
        &input.public_client_redirect_uris,
    ] {
        azapptoolkit_core::redirect::validate_redirect_uris(set)
            .map_err(|e| UiError::validation("invalid_redirect_uri", e))?;
    }
    let client = state.graph_for(&tenant_id);
    let body = ApplicationAuthenticationPatch {
        web: Some(ApplicationWebPatch {
            redirect_uris: Some(input.web_redirect_uris),
            // Full-replace: an empty string clears the front-channel logout URL.
            logout_url: Some(input.logout_url.unwrap_or_default()),
            implicit_grant_settings: Some(ImplicitGrantSettingsPatch {
                enable_access_token_issuance: Some(input.enable_access_token_issuance),
                enable_id_token_issuance: Some(input.enable_id_token_issuance),
            }),
        }),
        spa: Some(ApplicationSpaPatch {
            redirect_uris: Some(input.spa_redirect_uris),
        }),
        public_client: Some(ApplicationPublicClientPatch {
            redirect_uris: Some(input.public_client_redirect_uris),
        }),
        is_fallback_public_client: Some(input.is_fallback_public_client),
    };
    client.patch_application_web(&object_id, &body).await?;
    invalidate_app_details(&state.cache, &tenant_id);
    super::audit::invalidate_audit_cache(&state.cache, &tenant_id);
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

#[tauri::command]
pub async fn add_application_owner(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.add_owner(&object_id, &principal_id).await?;
    invalidate_app_details(&state.cache, &tenant_id);
    super::audit::invalidate_audit_cache(&state.cache, &tenant_id);
    Ok(())
}

#[tauri::command]
pub async fn remove_application_owner(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.remove_owner(&object_id, &principal_id).await?;
    invalidate_app_details(&state.cache, &tenant_id);
    super::audit::invalidate_audit_cache(&state.cache, &tenant_id);
    Ok(())
}

/// Reconciles an application's owner set to exactly `principal_ids`, mirroring
/// `Set-AzAppOwner`. Owners present in the target but not currently assigned are
/// added first (so the app is never transiently ownerless), then owners no
/// longer in the target are removed. Per-principal failures are collected rather
/// than aborting the whole operation.
#[tauri::command]
pub async fn set_application_owners(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    principal_ids: Vec<String>,
) -> Result<SetOwnersResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let current = client.list_owners(&object_id).await?;
    let current_ids: HashSet<String> = current.into_iter().map(|o| o.id).collect();
    let desired: HashSet<String> = principal_ids.into_iter().collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut failures = Vec::new();

    for id in desired.iter().filter(|id| !current_ids.contains(*id)) {
        match client.add_owner(&object_id, id).await {
            Ok(()) => added.push(id.clone()),
            Err(err) => failures.push(OwnerChangeFailure {
                principal_id: id.clone(),
                action: "add".into(),
                message: err.to_string(),
            }),
        }
    }
    for id in current_ids.iter().filter(|id| !desired.contains(*id)) {
        match client.remove_owner(&object_id, id).await {
            Ok(()) => removed.push(id.clone()),
            Err(err) => failures.push(OwnerChangeFailure {
                principal_id: id.clone(),
                action: "remove".into(),
                message: err.to_string(),
            }),
        }
    }

    if !added.is_empty() || !removed.is_empty() {
        invalidate_app_details(&state.cache, &tenant_id);
        super::audit::invalidate_audit_cache(&state.cache, &tenant_id);
    }

    Ok(SetOwnersResult {
        added,
        removed,
        failures,
    })
}

#[tauri::command]
pub async fn search_users(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<Vec<DirectoryObject>, UiError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let client = state.graph_for(&tenant_id);
    client.search_users(q).await.map_err(Into::into)
}

#[tauri::command]
pub async fn search_groups(
    state: State<'_, AppState>,
    tenant_id: String,
    query: String,
) -> Result<Vec<DirectoryObject>, UiError> {
    let q = query.trim();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    let client = state.graph_for(&tenant_id);
    client.search_groups(q).await.map_err(Into::into)
}

#[tauri::command]
pub async fn add_password(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: AddPasswordInput,
) -> Result<PasswordCredential, UiError> {
    let (start, end) = resolve_password_window(&input, chrono::Utc::now())
        .map_err(|msg| UiError::validation("invalid_secret_window", msg))?;
    let client = state.graph_for(&tenant_id);
    let cred = client
        .add_password_window(&object_id, &input.display_name, start, end)
        .await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    Ok(cred)
}

/// Maximum client-secret lifetime — the portal's 24-month hard cap.
const MAX_SECRET_LIFETIME_DAYS: i64 = 730;

/// Resolves an [`AddPasswordInput`] to the `(start, end)` window sent to
/// Graph. An explicit `end_date_time` (portal "Custom" expiry) wins over
/// `lifetime_days`; without either, defaults to 180 days, matching the
/// portal's recommended preset.
fn resolve_password_window(
    input: &AddPasswordInput,
    now: chrono::DateTime<chrono::Utc>,
) -> std::result::Result<
    (
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
    ),
    String,
> {
    match input.end_date_time {
        Some(end) => {
            let effective_start = input.start_date_time.unwrap_or(now);
            if end <= effective_start {
                return Err("expiry must be after the start date".to_string());
            }
            if end - effective_start > chrono::Duration::days(MAX_SECRET_LIFETIME_DAYS) {
                return Err("secret lifetime cannot exceed 24 months".to_string());
            }
            Ok((input.start_date_time, end))
        }
        None => {
            let days =
                i64::from(input.lifetime_days.unwrap_or(180)).clamp(1, MAX_SECRET_LIFETIME_DAYS);
            Ok((None, now + chrono::Duration::days(days)))
        }
    }
}

#[tauri::command]
pub async fn remove_password(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    key_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.remove_password(&object_id, &key_id).await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    Ok(())
}

// ---------------- Certificate credentials ----------------

#[tauri::command]
pub async fn add_certificate_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: AddCertificateInput,
) -> Result<(), UiError> {
    let key_b64 = normalize_cert_blob(&input.pem_or_base64)
        .map_err(|msg| UiError::validation("invalid_certificate", msg))?;
    let client = state.graph_for(&tenant_id);
    let new_cred = NewKeyCredential {
        display_name: Some(input.display_name),
        kind: Some("AsymmetricX509Cert".into()),
        usage: Some("Verify".into()),
        key: key_b64,
        end_date_time: input.end_date_time,
        ..Default::default()
    };
    client.add_key_credential(&object_id, new_cred).await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    Ok(())
}

/// Generates a self-signed RSA certificate, attaches its public part to the
/// application as a verify-only key credential, and returns the private key
/// once (it is never persisted by the backend). Ports the legacy
/// `New-SelfSignedCertificate` + upload flow.
#[tauri::command]
pub async fn generate_self_signed_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    input: GenerateCertificateInput,
) -> Result<GeneratedCertificateResult, UiError> {
    let validity = input.validity_days.unwrap_or(365);
    let mut generated = crate::cert::generate_self_signed(&input.subject, i64::from(validity))
        .map_err(|msg| UiError::validation("cert_generation_failed", msg))?;

    let expires_dt =
        chrono::DateTime::<chrono::Utc>::from_timestamp(generated.not_after.unix_timestamp(), 0);

    let client = state.graph_for(&tenant_id);
    // `GeneratedCert: Drop` (zeroizes `private_key_pem` on drop), which means
    // none of its `String` fields can be moved out — we extract each via
    // `mem::take`, leaving an empty husk for `Drop` to zeroize harmlessly.
    let new_cred = NewKeyCredential {
        display_name: Some(input.subject.clone()),
        kind: Some("AsymmetricX509Cert".into()),
        usage: Some("Verify".into()),
        key: std::mem::take(&mut generated.cert_der_base64),
        end_date_time: expires_dt,
        ..Default::default()
    };
    client
        .add_key_credential(&input.object_id, new_cred)
        .await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &input.object_id);

    Ok(GeneratedCertificateResult {
        thumbprint: std::mem::take(&mut generated.thumbprint),
        certificate_pem: std::mem::take(&mut generated.cert_pem),
        private_key_pem: std::mem::take(&mut generated.private_key_pem),
        expires: expires_dt.map(|d| d.to_rfc3339()).unwrap_or_default(),
    })
}

#[tauri::command]
pub async fn remove_certificate_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    key_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.remove_key_credential(&object_id, &key_id).await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    Ok(())
}

/// Accepts either PEM-armoured text (`-----BEGIN CERTIFICATE-----`...) or a
/// raw base64 blob. Returns a clean base64-encoded DER string suitable for
/// the `key` field on Graph's `keyCredentials`. Performs minimal validation:
/// strips headers/whitespace and confirms the remainder is valid base64.
fn normalize_cert_blob(input: &str) -> std::result::Result<String, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let stripped: String = input
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .flat_map(|line| line.chars())
        .filter(|c| !c.is_whitespace())
        .collect();

    if stripped.is_empty() {
        return Err("certificate body is empty".to_string());
    }
    STANDARD
        .decode(&stripped)
        .map_err(|e| format!("not valid base64: {e}"))?;
    Ok(stripped)
}

#[cfg(test)]
mod password_window_tests {
    use super::{resolve_password_window, AddPasswordInput};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn input(
        lifetime_days: Option<u32>,
        start: Option<&str>,
        end: Option<&str>,
    ) -> AddPasswordInput {
        AddPasswordInput {
            display_name: "s".into(),
            lifetime_days,
            start_date_time: start.map(at),
            end_date_time: end.map(at),
        }
    }

    const NOW: &str = "2026-01-01T00:00:00Z";

    #[test]
    fn preset_days_resolve_relative_to_now() {
        let (start, end) = resolve_password_window(&input(Some(90), None, None), at(NOW)).unwrap();
        assert!(start.is_none());
        assert_eq!(end, at("2026-04-01T00:00:00Z"));
    }

    #[test]
    fn defaults_to_180_days_and_clamps_to_cap() {
        let (_, end) = resolve_password_window(&input(None, None, None), at(NOW)).unwrap();
        assert_eq!(end, at(NOW) + chrono::Duration::days(180));
        let (_, end) = resolve_password_window(&input(Some(9999), None, None), at(NOW)).unwrap();
        assert_eq!(end, at(NOW) + chrono::Duration::days(730));
    }

    #[test]
    fn explicit_end_wins_over_lifetime_days() {
        let (start, end) = resolve_password_window(
            &input(
                Some(90),
                Some("2026-02-01T00:00:00Z"),
                Some("2026-06-01T00:00:00Z"),
            ),
            at(NOW),
        )
        .unwrap();
        assert_eq!(start, Some(at("2026-02-01T00:00:00Z")));
        assert_eq!(end, at("2026-06-01T00:00:00Z"));
    }

    #[test]
    fn rejects_end_not_after_start() {
        let err = resolve_password_window(
            &input(
                None,
                Some("2026-06-01T00:00:00Z"),
                Some("2026-06-01T00:00:00Z"),
            ),
            at(NOW),
        )
        .unwrap_err();
        assert!(err.contains("after the start"));
        // Without an explicit start, "now" anchors the window.
        assert!(
            resolve_password_window(&input(None, None, Some("2025-12-31T00:00:00Z")), at(NOW))
                .is_err()
        );
    }

    #[test]
    fn rejects_lifetime_over_24_months() {
        let err = resolve_password_window(
            &input(
                None,
                Some("2026-01-01T00:00:00Z"),
                Some("2028-06-01T00:00:00Z"),
            ),
            at(NOW),
        )
        .unwrap_err();
        assert!(err.contains("24 months"));
    }
}

#[cfg(test)]
mod fic_audience_tests {
    use super::{resolve_fic_audiences, DEFAULT_FIC_AUDIENCE};

    #[test]
    fn absent_or_empty_falls_back_to_default() {
        assert_eq!(resolve_fic_audiences(None), vec![DEFAULT_FIC_AUDIENCE]);
        assert_eq!(
            resolve_fic_audiences(Some(vec![])),
            vec![DEFAULT_FIC_AUDIENCE]
        );
    }

    #[test]
    fn override_is_passed_through() {
        assert_eq!(
            resolve_fic_audiences(Some(vec!["api://custom".into()])),
            vec!["api://custom"]
        );
    }
}

#[cfg(test)]
mod cert_tests {
    use super::normalize_cert_blob;

    #[test]
    fn strips_pem_armour_and_whitespace() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAAAA==\n-----END CERTIFICATE-----\n";
        let out = normalize_cert_blob(pem).unwrap();
        assert_eq!(out, "AAAAAA==");
    }

    #[test]
    fn accepts_raw_base64() {
        let out = normalize_cert_blob("AAAAAA==").unwrap();
        assert_eq!(out, "AAAAAA==");
    }

    #[test]
    fn rejects_non_base64() {
        assert!(normalize_cert_blob("!!!!").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(normalize_cert_blob("").is_err());
        assert!(
            normalize_cert_blob("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
                .is_err()
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
mod auth_fields_tests {
    use super::extract_auth_fields;

    #[test]
    fn extracts_all_blocks() {
        let v = serde_json::json!({
            "id": "obj-1",
            "appId": "app-1",
            "isFallbackPublicClient": true,
            "web": {
                "redirectUris": ["https://app/cb", "https://app/cb2"],
                "logoutUrl": "https://app/logout",
                "implicitGrantSettings": {
                    "enableAccessTokenIssuance": true,
                    "enableIdTokenIssuance": false
                }
            },
            "spa": { "redirectUris": ["https://app/spa"] },
            "publicClient": { "redirectUris": ["http://localhost"] }
        });
        let dto = extract_auth_fields(&v);
        assert_eq!(dto.web_redirect_uris, ["https://app/cb", "https://app/cb2"]);
        assert_eq!(dto.spa_redirect_uris, ["https://app/spa"]);
        assert_eq!(dto.public_client_redirect_uris, ["http://localhost"]);
        assert_eq!(dto.logout_url.as_deref(), Some("https://app/logout"));
        assert!(dto.is_fallback_public_client);
        assert!(dto.enable_access_token_issuance);
        assert!(!dto.enable_id_token_issuance);
    }

    #[test]
    fn missing_blocks_default_empty() {
        // A bare app (no web/spa/publicClient) ⇒ empty lists, false flags, no logout.
        let dto = extract_auth_fields(&serde_json::json!({ "id": "obj-1", "appId": "app-1" }));
        assert!(dto.web_redirect_uris.is_empty());
        assert!(dto.spa_redirect_uris.is_empty());
        assert!(dto.public_client_redirect_uris.is_empty());
        assert!(dto.logout_url.is_none());
        assert!(!dto.is_fallback_public_client);
        assert!(!dto.enable_access_token_issuance);
        assert!(!dto.enable_id_token_issuance);
    }

    #[test]
    fn empty_logout_url_becomes_none() {
        let v = serde_json::json!({ "web": { "logoutUrl": "" } });
        assert!(extract_auth_fields(&v).logout_url.is_none());
    }
}

/// Removes every expired password credential, by the audit's shared whole-day
/// rule (`azapptoolkit_core::audit::is_expired` — a sub-day lapse is still
/// "expiring soon" and is left alone). Mirrors `Remove-AzAppExpiredCredential`.
/// Partial success is surfaced via `failures` rather than aborting on the
/// first error.
#[tauri::command]
pub async fn remove_expired_passwords(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<RemoveExpiredResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let app = client.get_application(&object_id).await?;
    let now = chrono::Utc::now();

    let mut removed_key_ids = Vec::new();
    let mut failures = Vec::new();
    for cred in app.password_credentials.iter() {
        if !azapptoolkit_core::audit::is_expired(cred.end_date_time, now) {
            continue;
        }
        match client.remove_password(&object_id, &cred.key_id).await {
            Ok(()) => removed_key_ids.push(cred.key_id.clone()),
            Err(err) => failures.push(KeyFailure {
                key_id: cred.key_id.clone(),
                message: err.to_string(),
            }),
        }
    }

    if !removed_key_ids.is_empty() {
        invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    }
    Ok(RemoveExpiredResult {
        removed_key_ids,
        failures,
    })
}

/// Maps a Graph [`FederatedIdentityCredential`] to its IPC DTO. Shared by the
/// list and add commands so the six-field projection lives in one place.
fn fic_dto(c: FederatedIdentityCredential) -> FederatedCredentialDto {
    FederatedCredentialDto {
        id: c.id,
        name: c.name,
        issuer: c.issuer,
        subject: c.subject,
        description: c.description,
        audiences: c.audiences,
    }
}

/// Lists an application's federated identity credentials (workload identity
/// federation — GitHub Actions, Kubernetes, …).
#[tauri::command]
pub async fn list_federated_credentials(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<Vec<FederatedCredentialDto>, UiError> {
    let client = state.graph_for(&tenant_id);
    let creds = client.list_federated_credentials(&object_id).await?;
    Ok(creds.into_iter().map(fic_dto).collect())
}

/// The audience Entra recommends (and the portal defaults to) for workload
/// identity federation token exchange.
const DEFAULT_FIC_AUDIENCE: &str = "api://AzureADTokenExchange";

/// Resolves a caller-supplied audience override to the list sent to Graph:
/// absent or empty falls back to [`DEFAULT_FIC_AUDIENCE`] (only the portal's
/// "Other issuer" flow sends an override).
fn resolve_fic_audiences(audiences: Option<Vec<String>>) -> Vec<String> {
    audiences
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| vec![DEFAULT_FIC_AUDIENCE.to_string()])
}

/// Creates a federated identity credential. The audience defaults to
/// `api://AzureADTokenExchange` (the value Entra recommends for token
/// exchange) unless the caller supplies an override.
#[tauri::command]
pub async fn add_federated_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: AddFederatedCredentialInput,
) -> Result<FederatedCredentialDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let body = FederatedCredentialRequest {
        name: input.name,
        issuer: input.issuer,
        subject: input.subject,
        audiences: resolve_fic_audiences(input.audiences),
        description: input.description,
    };
    let c = client.add_federated_credential(&object_id, &body).await?;
    Ok(fic_dto(c))
}

/// Updates a federated identity credential in place (issuer / subject /
/// description / audiences — `name` is immutable in Graph). No cache
/// invalidation: FICs aren't part of any cached list or detail payload; the
/// tab refetches live.
#[tauri::command]
pub async fn update_federated_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    credential_id: String,
    input: UpdateFederatedCredentialInput,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    let body = FederatedCredentialPatch {
        issuer: input.issuer,
        subject: input.subject,
        audiences: resolve_fic_audiences(input.audiences),
        description: input.description,
    };
    client
        .update_federated_credential(&object_id, &credential_id, &body)
        .await?;
    Ok(())
}

/// Removes a federated identity credential.
#[tauri::command]
pub async fn remove_federated_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    credential_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client
        .remove_federated_credential(&object_id, &credential_id)
        .await?;
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
