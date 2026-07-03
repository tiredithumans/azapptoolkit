use std::collections::HashMap;
use std::time::Duration;

use tauri::{AppHandle, State};

use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_core::models::{Organization, ServicePrincipal};
use azapptoolkit_graph::client::{AppListQuery, AppPatch, CreateApplicationRequest};

use crate::dto::UiError;
use crate::dto::applications::{
    ApplicationDetail, ApplicationListRowDto, CreateApplicationInput, CreateApplicationResult,
    UpdateApplicationInput,
};
use crate::state::AppState;

mod authentication;
mod cache;
mod credentials;
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
pub use federated::*;
pub use owners::*;
pub use permissions_resolve::*;

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
