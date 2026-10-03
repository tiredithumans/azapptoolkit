use std::collections::HashMap;

use tauri::{AppHandle, State};

use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_core::models::{Application, Organization};
use azapptoolkit_graph::GraphError;
use azapptoolkit_graph::client::{AppListQuery, AppPatch, CreateApplicationRequest, SP_INDEX_MAX};

use crate::dto::UiError;
use crate::dto::applications::{
    ApplicationDetail, ApplicationListRowDto, CreateApplicationInput, CreateApplicationResult,
    DirectoryIndexStatus, UpdateApplicationInput,
};
use crate::dto::credentials::CredentialRowDto;
use crate::state::AppState;

mod authentication;
mod cache;
mod credentials;
mod deleted;
mod federated;
mod owners;
mod permissions_resolve;

// Glob re-exports keep every item reachable at `crate::commands::applications::*`
// (the pre-split path) — crucially including the hidden `__cmd__<name>` items
// that `#[tauri::command]` generates, which `generate_handler!` resolves at
// `commands::applications::<fn>` alongside the function itself.
pub use authentication::*;
pub(crate) use cache::*;
pub use credentials::*;
pub use deleted::*;
pub use federated::*;
pub use owners::*;

// ---------------- Reads ----------------

#[tauri::command]
pub async fn get_organization(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Organization, UiError> {
    let client = state.graph_for(&tenant_id);
    client.get_organization().await.map_err(Into::into)
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

/// Page size for the browse-list scan — the shared `/applications` maximum.
const APPS_PAGE_SIZE: u32 = azapptoolkit_graph::client::DEFAULT_APP_PAGE_SIZE;
/// Safety cap on total apps materialized for a tenant-wide enumeration. One
/// definition, in `azapptoolkit_dto::applications` (see its doc), so the
/// frontend's cap notice reads the same value.
pub(crate) const APPS_MAX: usize = crate::dto::applications::APPS_MAX;

/// Reports whether the shared SP index truncated for this tenant.
///
/// Reads through the same cache entry the lists populate, so on a warm tenant
/// this is free and on a cold one it seeds the index the caller is about to
/// need anyway. Deliberately fallible (`invoke_result`): a failure here must
/// only cost the notice, never the list.
#[tauri::command]
pub async fn get_directory_index_status(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<DirectoryIndexStatus, UiError> {
    // A warm SP index answers below before any request is sent; `graph_for`
    // only builds token adapters, so it is not a session proof.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    let client = state.graph_for(&tenant_id);
    let sps = cache::sp_index_cached(&state, &client, &tenant_id).await?;
    Ok(DirectoryIndexStatus {
        sp_index_truncated: sps.len() >= SP_INDEX_MAX,
        sp_index_cap: SP_INDEX_MAX,
    })
}

/// One full `/applications` list scan, projected three ways. See
/// [`scan_app_list`].
pub(crate) struct AppListScan {
    /// The App Registrations list rows (`apps_pairing`).
    pub(crate) rows: Vec<ApplicationListRowDto>,
    /// The tenant-wide credential-expiry roll-up (`credential_expirations`).
    pub(crate) credentials: Vec<CredentialRowDto>,
}

/// The ONE full `/applications` list scan behind the App Registrations list,
/// the credential-expiry roll-up and the app-name index.
///
/// [`list_row_select`] is a strict superset of both other projections, and all
/// three keys are busted by the same mutation tiers, so a single paged scan
/// seeds all three. Launch used to run three concurrent scans of the same
/// collection (the Home App Registrations, Enterprise Apps and Credential
/// health cards) — 18 serial round trips at 5,000 apps, two of them selecting
/// the throttled `keyCredentials`.
///
/// Caller contract:
/// - Hold [`app_scan_gate`] and re-check your own key before calling, so a
///   concurrent reader queues behind this scan instead of starting another.
/// - Never call `app_name_index_cached` or `indexes_cached` from here: both take
///   the same gate, and tokio's `Mutex` is not re-entrant, so that would
///   self-deadlock.
/// - Lock order is scan gate, then the SP-index gate (`sp_index_cached`), never
///   the reverse.
///
/// Each store has its own per-key watch, captured before the scan, so a
/// credential write landing mid-scan drops only the two credential-bearing
/// entries and leaves the two tenant-wide indexes this scan also produced.
pub(crate) async fn scan_app_list(
    state: &AppState,
    tenant_id: &str,
) -> Result<AppListScan, GraphError> {
    let client = state.graph_for(tenant_id);
    let query = AppListQuery::default()
        .with_select(list_row_select())
        .with_top(APPS_PAGE_SIZE);

    // Captured BEFORE the scan: all three entries are PINNED, so a snapshot that
    // loses the race to a mutation is not a stale read that ages out, it is out
    // of LRU's reach for the full TTL. Watches are per KEY — one per store.
    let rows_watch = state
        .cache
        .generation_for(CacheKind::Lists, &apps_pairing_key(tenant_id));
    let creds_watch = state
        .cache
        .generation_for(CacheKind::Lists, &credential_expirations_key(tenant_id));
    let name_watch = state
        .cache
        .generation_for(CacheKind::Lists, &app_name_index_key(tenant_id));

    // The pairing join reads the shared SP index through its gated accessor
    // (hit-check, single-flight, its own per-key watch), fetched concurrently
    // with the app scan so a cold join waits on one directory scan, not two
    // serial ones. Both sides follow `@odata.nextLink` to completion.
    //
    // `_truncated`: the App Registrations list is a browse surface with its own
    // "showing N of M" affordance, and the credential roll-up covers the first
    // APPS_MAX registrations. A tenant past that cap loses the tail, which
    // understates expiries — acceptable only because the same cap governs every
    // other tenant-wide view, so the numbers shown are consistent with them
    // rather than silently different.
    let ((apps, _truncated), sps) = futures::future::try_join(
        client.list_applications_all(query, Some(APPS_MAX)),
        cache::sp_index_cached(state, &client, tenant_id),
    )
    .await?;

    let now = chrono::Utc::now();

    // The credential roll-up, pinned and guarded: a credential add/remove that
    // raced this scan dropped the key, and the pre-mutation snapshot must not
    // re-land for the full TTL.
    let credentials = crate::commands::credentials::credential_rows(&apps, now);
    state.cache.put_index_if_current(creds_watch, &credentials);

    // The app-name index, stripped to the three fields it carries: six surfaces
    // hold an `Arc` to this entry, and the credential arrays must not be pinned
    // into it. Stored every time; the store is guarded, so a warm index is
    // simply left as it is.
    let lean: Vec<Application> = apps
        .iter()
        .map(|a| Application {
            id: a.id.clone(),
            app_id: a.app_id.clone(),
            display_name: a.display_name.clone(),
            ..Default::default()
        })
        .collect();
    cache::app_name_index_store_if_current(&state.cache, lean, name_watch);

    let by_app_id: HashMap<&str, &str> = sps
        .iter()
        .map(|sp| (sp.app_id.as_str(), sp.id.as_str()))
        .collect();
    let rows: Vec<ApplicationListRowDto> = apps
        .into_iter()
        .map(|application| {
            let paired = by_app_id
                .get(application.app_id.as_str())
                .map(|id| (*id).to_string());
            ApplicationListRowDto::from_application(application, paired, now)
        })
        .collect();

    // Pinned: a tenant-wide index (one paginated scan over every app
    // registration), not a per-object entry — it must not be evictable by the
    // thousands of `app_detail|…` writes that share this bucket. The caller
    // still gets these rows; only the caching of a snapshot that lost the race
    // is skipped.
    state.cache.put_index_if_current(rows_watch, &rows);

    Ok(AppListScan { rows, credentials })
}

/// Lean list-row variant of [`list_applications`]: each row is flattened to
/// the scalars the list renders, with credential status/counts/soonest-expiry
/// pre-computed here, and carries the paired Enterprise Application
/// service-principal object id (when one exists in this tenant). The list's
/// search/date/credential filters all run in the frontend over this result,
/// so a search keystroke never re-enters Graph.
///
/// The rows come from the shared App Registrations scan ([`scan_app_list`]),
/// which follows `@odata.nextLink` to completion (bounded by [`APPS_MAX`]) and
/// also seeds the credential-expiry roll-up and the app-name index, so one
/// paginated scan serves repeated browsing and the Home cards until the TTL.
/// (Credential statuses are classified at fetch time, so within the TTL a row's
/// bucket can lag reality by at most that long; Refresh re-classifies.)
#[tauri::command]
pub async fn list_applications_with_pairing(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<ApplicationListRowDto>, UiError> {
    // The cache-HIT path returns before any client is built, so it needs its
    // own session proof.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    Ok(cache::apps_pairing_cached(&state, &tenant_id).await?)
}

#[tauri::command]
pub async fn get_application_detail(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<ApplicationDetail, UiError> {
    // The cache-HIT path below returns before any client is built, so the
    // `graph_for` on the miss path is not a session proof for it.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
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

    // Wave 1: the owners list keys off the application OBJECT id — the same id
    // the caller passed — so it never needed the fetched application and was
    // waiting a full round trip for nothing. Only the SP lookup genuinely
    // depends on the manifest (it keys off `appId`).
    let (application, owners) = futures::future::try_join(
        client.get_application(&object_id),
        client.list_owners(&object_id),
    )
    .await?;

    // Wave 2: the SP lookup needs `appId` from the manifest above.
    let service_principal = client
        .get_service_principal_by_app_id(&application.app_id)
        .await?;

    // Wave 3: role assignments and delegated grants both key off the SP id and
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

    let (resolved_permissions, resolution_degraded) =
        permissions_resolve::resolve_required_resource_access(
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
        resolution_degraded,
    };
    // A degraded run is never cached nor shown as all-clear (AGENTS.md): a
    // resource SP that couldn't be read leaves its granted permissions reading
    // "Not granted", and caching that would pin the wrong answer for the whole
    // Lists TTL. The flag rides the payload so the tab can say so instead.
    if !detail.resolution_degraded {
        state.cache.put(CacheKind::Lists, detail_key, &detail);
    }
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
    create_application_in_state(&state, &tenant_id, input).await
}

/// The body of [`create_application`], taking `&AppState` so the partial-create
/// rule is reachable from a test (the `add_password_core` seam; the `_core`
/// name is the Graph-only helper below).
///
/// Once the registration POST has landed the app exists, so the list tier is
/// busted **whatever** happens after it — a partial success is a real write —
/// and only then is a later step's error surfaced, naming the new app's object
/// id so the operator can finish or delete it instead of creating a duplicate.
pub(crate) async fn create_application_in_state(
    state: &AppState,
    tenant_id: &str,
    input: CreateApplicationInput,
) -> Result<CreateApplicationResult, UiError> {
    let client = state.graph_for(tenant_id);
    let (result, error) = create_application_core(&client, input).await?;
    invalidate_app_lists(&state.cache, tenant_id);
    match error {
        Some(e) => Err(augment_with_object_id(e, &result.application.id)),
        None => Ok(result),
    }
}

/// Annotates an error message with the created object id so a partial failure
/// after a create tells the user which half-configured app to finish/clean up.
/// Shared by the plain create and the SSO create flows.
pub(crate) fn augment_with_object_id(mut err: UiError, object_id: &str) -> UiError {
    err.message = format!(
        "{} (the application was created — object id {object_id}; you can finish or delete it from the list).",
        err.message
    );
    err
}

/// Shared application-creation logic, reused by the single-app command and the
/// bulk path so both have identical semantics.
///
/// Returns `(result, error)` rather than `Result<result>` for the reason
/// `downgrade_application_permission_core` does: a failure *after* the
/// registration POST still has a real write to report. A failure of the POST
/// itself is a plain `Err` (nothing landed). After it, the first failing step
/// (service principal, initial secret, a re-auth-fatal owner add) stops the
/// run and comes back as `Some(error)` beside what did land; the caller busts
/// the list tier on the `Ok` and then surfaces the error. A minted initial
/// secret is never paired with an error: its value is returned only once, so
/// an owner failure after it is reported through `failed_owner_ids` alone.
pub(crate) async fn create_application_core(
    client: &azapptoolkit_graph::GraphClient,
    input: CreateApplicationInput,
) -> Result<(CreateApplicationResult, Option<UiError>), UiError> {
    create_application_core_tagged(client, input, Vec::new()).await
}

/// [`create_application_core`] with `tags` written in the create POST itself.
/// The DR restore uses it to stamp its restore marker, so no app it creates can
/// exist untagged (a follow-up PATCH would leave that window open).
pub(crate) async fn create_application_core_tagged(
    client: &azapptoolkit_graph::GraphClient,
    input: CreateApplicationInput,
    tags: Vec<String>,
) -> Result<(CreateApplicationResult, Option<UiError>), UiError> {
    let body = CreateApplicationRequest {
        display_name: input.display_name,
        sign_in_audience: input.sign_in_audience,
        description: input.description,
        tags,
    };
    let application = client.create_application(&body).await?;
    // The registration exists from here on: a later failure is collected, not
    // `?`-returned, so the caller still sees the app it must invalidate for.
    // Nothing after a failed step is attempted — a secret minted after an
    // error would be lost, since its value only travels in the `Ok` result.
    let mut error: Option<UiError> = None;

    let service_principal = if input.create_service_principal {
        // The caller busts the list tier for the new app anyway, so the
        // `created` flag is unused here.
        match client.ensure_service_principal(&application.app_id).await {
            Ok((sp, _)) => Some(sp),
            Err(e) => {
                error = Some(e.into());
                None
            }
        }
    } else {
        None
    };

    let mut initial_secret = None;
    if error.is_none()
        && let Some(name) = input.initial_secret_display_name.as_deref()
    {
        let end = preset_secret_end(input.initial_secret_lifetime_days, chrono::Utc::now());
        match client
            .add_password_window(&application.id, name, None, end)
            .await
        {
            Ok(secret) => initial_secret = Some(secret),
            Err(e) => error = Some(e.into()),
        }
    }

    let mut added_owner_ids = Vec::with_capacity(input.initial_owner_ids.len());
    let mut failed_owner_ids = Vec::new();
    // Set by an earlier step's error or by a dead session below.
    let mut stopped = error.is_some();
    for owner in input.initial_owner_ids {
        // After a stop the remaining owners are reported as failed without
        // being attempted.
        if stopped {
            failed_owner_ids.push(owner);
            continue;
        }
        match client.add_owner(&application.id, &owner).await {
            Ok(()) => added_owner_ids.push(owner),
            Err(err) => {
                tracing::warn!(%owner, ?err, "failed to add initial owner on create");
                let e = UiError::from(err);
                failed_owner_ids.push(owner);
                // A dead session fails every remaining owner identically, so
                // the loop stops, and the caller must see the code to offer
                // Re-authenticate. The one exception: once a secret has been
                // minted, the run must stay `Ok`, because an error would drop
                // the only copy of its value. The failed owners are still
                // listed, and the next command meets the dead session anyway.
                if e.is_reauth_fatal() {
                    stopped = true;
                    if initial_secret.is_none() {
                        error = Some(e);
                    }
                }
            }
        }
    }

    Ok((
        CreateApplicationResult {
            application,
            service_principal,
            initial_secret,
            added_owner_ids,
            failed_owner_ids,
        },
        error,
    ))
}

#[tauri::command]
pub async fn update_application(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    patch: UpdateApplicationInput,
) -> Result<(), UiError> {
    // A patch that names nothing is not a write (F342): a clean Overview form
    // used to dispatch `{}`, which cost a Graph round trip AND busted every
    // list-tier cache for zero change. `None` means "untouched" on every
    // field, so a default patch can only ever be a no-op — skip it entirely.
    if patch == UpdateApplicationInput::default() {
        return Ok(());
    }
    let client = state.graph_for(&tenant_id);
    let graph_patch = AppPatch {
        display_name: patch.display_name,
        sign_in_audience: patch.sign_in_audience,
        description: patch.description,
        notes: patch.notes,
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
    use super::export::csv_field;
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
    super::export::save_export_via_dialog(
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
    use azapptoolkit_core::models::{Application, PasswordCredential};

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

/// Partial-write tests: `create_application_core` takes `&GraphClient`, so a
/// mock Graph drives it as-is; `create_application_in_state` adds the command's
/// cache rule on an [`AppState::for_test`].
#[cfg(test)]
mod handler_tests {
    use super::*;

    use azapptoolkit_core::cache::Cache;
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::commands::test_support::{
        dies_after, indexes_intact, mock_graph, mock_graph_rw, mock_state,
        mock_state_with_write_token, seed_indexes_and_detail,
    };

    const TENANT: &str = "t1";

    /// One app with a secret that has an end date, as the list scan returns it.
    fn app_page() -> serde_json::Value {
        serde_json::json!({ "value": [{
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "Demo App",
            "passwordCredentials": [{
                "keyId": "k1",
                "displayName": "secret",
                "endDateTime": "2099-01-01T00:00:00Z"
            }],
            "keyCredentials": []
        }]})
    }

    /// The SP index: one principal paired with `app-1`.
    async fn mount_sp_index(server: &MockServer, hits: u64) {
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "sp-1", "appId": "app-1", "displayName": "Demo App" }]
            })))
            .expect(hits)
            .mount(server)
            .await;
    }

    /// Three cold readers firing together (the Home App Registrations,
    /// Credential health and Enterprise Apps cards) share ONE `/applications`
    /// scan and one SP scan, and the name index it seeds is stripped to the
    /// fields it carries.
    #[tokio::test]
    async fn one_scan_serves_the_list_the_credential_rollup_and_the_name_index() {
        let (server, state) = mock_state(TENANT).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/applications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(app_page()))
            .expect(1)
            .mount(&server)
            .await;
        mount_sp_index(&server, 1).await;
        let client = state.graph_for(TENANT);

        let (rows, creds, names) = tokio::join!(
            apps_pairing_cached(&state, TENANT),
            credential_expirations_cached(&state, TENANT),
            app_name_index_cached(&state, &client, TENANT),
        );
        let rows = rows.expect("pairing rows");
        let creds = creds.expect("credential roll-up");
        let names = names.expect("name index");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].paired_service_principal_id.as_deref(), Some("sp-1"));
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].app_object_id, "obj-1");
        assert_eq!(names.len(), 1);
        let indexed = app_name_index_hit(&state.cache, TENANT).expect("name index seeded");
        assert_eq!(indexed[0].app_id, "app-1");
        assert!(indexed[0].password_credentials.is_empty());
        assert!(indexed[0].key_credentials.is_empty());
        server.verify().await;
    }

    /// Answers the `/applications` page after running a credential-only
    /// invalidation, as if a secret were removed while the scan was in flight.
    struct CredentialWriteMidScan(std::sync::Arc<Cache>);

    impl wiremock::Respond for CredentialWriteMidScan {
        fn respond(&self, _: &wiremock::Request) -> ResponseTemplate {
            invalidate_app_credentials(&self.0, TENANT, "obj-1");
            ResponseTemplate::new(200).set_body_json(app_page())
        }
    }

    /// A credential write that lands mid-scan must not be re-pinned by the
    /// scan's pre-write snapshot: the two credential-bearing entries refuse,
    /// while the SP index and the name index — which the credential tier keeps
    /// — still land, because every store watches its own key.
    #[tokio::test]
    async fn a_credential_write_mid_scan_is_not_re_pinned() {
        let (server, state) = mock_state(TENANT).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/applications"))
            .respond_with(CredentialWriteMidScan(state.cache.clone()))
            .mount(&server)
            .await;
        mount_sp_index(&server, 1).await;

        let scan = scan_app_list(&state, TENANT).await.expect("scan");

        assert_eq!(scan.rows.len(), 1, "the caller still gets its rows");
        assert!(
            state
                .cache
                .get::<Vec<CredentialRowDto>>(CacheKind::Lists, &credential_expirations_key(TENANT))
                .is_none(),
            "the credential roll-up re-pinned a pre-write snapshot"
        );
        assert!(
            state
                .cache
                .get::<Vec<ApplicationListRowDto>>(CacheKind::Lists, &apps_pairing_key(TENANT))
                .is_none(),
            "the list rows re-pinned a pre-write snapshot"
        );
        assert!(sp_index_hit(&state.cache, TENANT).is_some());
        assert!(app_name_index_hit(&state.cache, TENANT).is_some());
    }

    /// The roll-up is pinned like the other tenant-wide list caches: per-app
    /// churn in its bucket cannot evict it. Mirrors
    /// `per_app_churn_cannot_evict_the_index` in `cache.rs`.
    #[tokio::test]
    async fn the_credential_rollup_survives_per_app_churn() {
        let (server, state) = mock_state(TENANT).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/applications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(app_page()))
            .mount(&server)
            .await;
        mount_sp_index(&server, 1).await;
        state.cache.configure(None, None, None, None, None, Some(8));

        scan_app_list(&state, TENANT).await.expect("scan");
        for i in 0..200 {
            state.cache.put(
                CacheKind::Lists,
                format!("{TENANT}|app_detail|{i}"),
                &i.to_string(),
            );
        }

        assert!(
            state
                .cache
                .get::<Vec<CredentialRowDto>>(CacheKind::Lists, &credential_expirations_key(TENANT))
                .is_some()
        );
    }

    /// The app POST lands (`obj-new` / `app-new`), no SP exists yet, and the
    /// SP POST is refused.
    async fn mount_app_created_sp_refused(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/v1.0/applications"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "obj-new",
                "appId": "app-new",
                "displayName": "New",
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", "appId eq 'app-new'"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
            )
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1.0/servicePrincipals"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
            .mount(server)
            .await;
    }

    fn with_sp() -> CreateApplicationInput {
        CreateApplicationInput {
            display_name: "New".into(),
            create_service_principal: true,
            initial_secret_display_name: None,
            initial_owner_ids: vec![],
            ..Default::default()
        }
    }

    async fn count(server: &MockServer, verb: &str, suffix: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.method.as_str() == verb && r.url.path().ends_with(suffix))
            .count()
    }

    #[tokio::test]
    async fn create_application_core_reports_the_landed_app_when_sp_creation_fails() {
        let server = MockServer::start().await;
        mount_app_created_sp_refused(&server).await;
        let client = mock_graph(&server);

        let (res, err) = create_application_core(&client, with_sp())
            .await
            .expect("the registration landed, so the run is Ok with an error beside it");
        let err = err.expect("the SP failure is reported");
        assert_eq!(err.code, "forbidden");
        assert_eq!(res.application.id, "obj-new");
        assert!(res.service_principal.is_none());
        assert_eq!(
            count(&server, "POST", "/v1.0/applications").await,
            1,
            "the app registration was created once"
        );
    }

    /// The command half of the rule: the app exists, so the list tier (and
    /// with it both tenant-wide indexes) is busted even though the command
    /// errs — and the error names the new object id so a retry is not a
    /// blind duplicate create.
    #[tokio::test]
    async fn create_application_command_busts_the_list_tier_and_names_the_app_after_a_partial_create()
     {
        let (server, state) = mock_state(TENANT).await;
        mount_app_created_sp_refused(&server).await;
        seed_indexes_and_detail(&state, TENANT, "obj-1");

        let err = create_application_in_state(&state, TENANT, with_sp())
            .await
            .expect_err("the SP failure still surfaces");
        assert_eq!(err.code, "forbidden");
        assert!(err.message.contains("obj-new"), "{}", err.message);
        assert!(
            !indexes_intact(&state, TENANT),
            "a landed create must bust the list tier even when a later step failed"
        );
    }

    /// A failure of the registration POST itself landed nothing: plain `Err`,
    /// nothing busted.
    #[tokio::test]
    async fn a_refused_create_busts_nothing() {
        let (server, state) = mock_state(TENANT).await;
        Mock::given(method("POST"))
            .and(path("/v1.0/applications"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
            .mount(&server)
            .await;
        seed_indexes_and_detail(&state, TENANT, "obj-1");

        let err = create_application_in_state(&state, TENANT, with_sp())
            .await
            .expect_err("a refused create is an error");
        assert_eq!(err.code, "forbidden");
        assert!(!err.message.contains("was created"), "{}", err.message);
        assert!(indexes_intact(&state, TENANT), "invalidate only on Ok");
    }

    /// A dead session on the first initial owner stops the loop: the rest are
    /// reported failed without being sent, and the fatal code comes back.
    #[tokio::test]
    async fn create_application_core_stops_the_owner_loop_on_a_dead_session() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/applications"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "obj-new",
                "appId": "app-new",
                "displayName": "New",
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1.0/applications/obj-new/owners/$ref"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        // One write bearer: the app POST gets it, the first owner add dies.
        let client = mock_graph_rw(
            &server,
            StaticTokenProvider::new("tok"),
            dies_after(1),
            Cache::new(),
        );

        let (res, err) = create_application_core(
            &client,
            CreateApplicationInput {
                display_name: "New".into(),
                initial_owner_ids: vec!["u1".into(), "u2".into()],
                ..Default::default()
            },
        )
        .await
        .expect("the registration landed");
        let err = err.expect("the dead session is reported");
        assert_eq!(err.code, "refresh_missing");
        assert!(res.added_owner_ids.is_empty());
        assert_eq!(res.failed_owner_ids, ["u1", "u2"]);
        assert_eq!(
            count(&server, "POST", "/owners/$ref").await,
            0,
            "no owner add reached Graph after the session died"
        );
    }

    /// Once the initial secret is minted, a dead session in the owner loop
    /// must not turn the command into an `Err`: that would drop the only copy
    /// of the secret value. The loop still stops and lists every owner as
    /// failed, and the list tier is still busted.
    #[tokio::test]
    async fn a_dead_session_after_the_initial_secret_keeps_the_secret() {
        // Two write bearers: the app POST and the addPassword get them, the
        // first owner add dies.
        let (server, state) = mock_state_with_write_token(TENANT, dies_after(2)).await;
        Mock::given(method("POST"))
            .and(path("/v1.0/applications"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "obj-new",
                "appId": "app-new",
                "displayName": "New",
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1.0/applications/obj-new/addPassword"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keyId": "k1",
                "displayName": "initial",
                "secretText": "s3cret",
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1.0/applications/obj-new/owners/$ref"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        seed_indexes_and_detail(&state, TENANT, "obj-1");

        let res = create_application_in_state(
            &state,
            TENANT,
            CreateApplicationInput {
                display_name: "New".into(),
                initial_secret_display_name: Some("initial".into()),
                initial_owner_ids: vec!["u1".into(), "u2".into()],
                ..Default::default()
            },
        )
        .await
        .expect("a minted secret keeps the command Ok");
        let secret = res.initial_secret.expect("the secret value is returned");
        assert_eq!(secret.secret_text.as_deref(), Some("s3cret"));
        assert!(res.added_owner_ids.is_empty());
        assert_eq!(res.failed_owner_ids, ["u1", "u2"]);
        assert_eq!(
            count(&server, "POST", "/owners/$ref").await,
            0,
            "no owner add reached Graph after the session died"
        );
        assert!(
            !indexes_intact(&state, TENANT),
            "the landed create still busts the list tier"
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::dto::applications::UpdateApplicationInput;

    /// The no-op gate in `update_application` compares against `default()`
    /// field-by-field (derived `PartialEq`). Pin the two directions that
    /// matter: a clean Overview form must be skipped, and any field the form
    /// actually touched — including a deliberate `Some("")` clear — must not
    /// be.
    #[test]
    fn only_an_all_none_patch_reads_as_no_change() {
        assert_eq!(
            UpdateApplicationInput::default(),
            UpdateApplicationInput::default()
        );
        let clear_notes = UpdateApplicationInput {
            notes: Some(String::new()),
            ..Default::default()
        };
        assert_ne!(UpdateApplicationInput::default(), clear_notes);
        for touched in [
            UpdateApplicationInput {
                display_name: Some("x".into()),
                ..Default::default()
            },
            UpdateApplicationInput {
                sign_in_audience: Some("AzureADMultipleOrgs".into()),
                ..Default::default()
            },
            UpdateApplicationInput {
                description: Some("d".into()),
                ..Default::default()
            },
        ] {
            assert_ne!(UpdateApplicationInput::default(), touched);
        }
    }
}
