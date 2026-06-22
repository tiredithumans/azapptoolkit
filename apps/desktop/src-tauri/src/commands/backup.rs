//! Disaster-recovery backup export.
//!
//! Produces a portable [`TenantBackup`] — the file-bridged DR artifact — by
//! fanning out the existing read paths over the tenant's app estate. Read-only:
//! it never mutates and never invalidates a cache.
//!
//! Two constraints are baked in here (see `docs/architecture/backup-and-restore.md`):
//! - **Secret/cert values are unrecoverable** (Graph returns them once at
//!   creation), so this captures credential *metadata* only — never a value.
//!   Restore regenerates fresh credentials and emits a redistribution report.
//! - **App registrations are captured in full** (manifest, auth, Expose-an-API,
//!   federated creds, owners, declared permissions, credential metadata) — they
//!   are the primary DR target and what the app-registration restore replays.
//!   Enterprise apps and managed identities are captured at the inventory level
//!   here; their per-principal assignment / held-permission / Azure-RBAC detail
//!   is captured alongside the restore logic that consumes it (the enterprise
//!   and managed-identity restore slices).

use std::collections::HashMap;
use std::sync::Arc;

use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_core::models::{
    AppRoleAssignment, Application, ApplicationExposeApi, DirectoryObject,
    FederatedIdentityCredential, GroupSummary, KeyCredential, PasswordCredential, ServicePrincipal,
};
use azapptoolkit_graph::{GraphClient, GraphError};

use crate::commands::applications::{extract_auth_fields, sp_index_key};
use crate::commands::dispatch::dispatch_capped;
use crate::commands::throttle::ConcurrencyThrottle;
use crate::dto::backup::{
    AppRegistrationBackup, AppRoleAssigneeRef, AppRoleGrantRef, CredentialMeta,
    EnterpriseAppBackup, ManagedIdentityBackup, PrincipalRef, TenantBackup, BACKUP_SCHEMA_VERSION,
};
use crate::dto::bulk::BulkProgress;
use crate::dto::managed_identity::MiSubtype;
use crate::dto::UiError;
use crate::state::{AppState, CancelFlag};

/// Objects per `$batch` POST. Graph's hard cap is 20 sub-requests per batch, so
/// each dispatched chunk is one POST per batched read.
const BATCH_CHUNK: usize = 20;

/// Initial concurrent chunks. The unit of work is now a 20-object `$batch`, and
/// each chunk task fires up to three batched reads at once (Pass 2 sends the SP
/// read, the assignees, and the group memberships together), so the peak
/// in-flight sub-request count is roughly `cap * 3 * BATCH_CHUNK`. Kept low — the
/// adaptive `ConcurrencyThrottle` raises it toward this value on a healthy tenant
/// and halves it toward a floor of 1 on a throttling one.
const INITIAL_DR_CONCURRENCY: usize = 4;

/// Tenant-wide enumeration cap, matching the lists' `APPS_MAX` / `SP_INDEX_MAX`.
const ESTATE_CAP: usize = 10_000;

/// Captures a full, portable backup of the tenant's app estate. Long-running
/// (a batched per-app fan-out), so it polls the dedicated [`AppState::dr_cancel`]
/// flag — its own, not `audit_cancel`, so a backup and a concurrent audit/bulk
/// run can't cancel each other. Emits `backup-progress` ([`BulkProgress`]) events
/// carrying the live adaptive concurrency cap.
#[tauri::command]
pub async fn backup_tenant(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<TenantBackup, UiError> {
    state.dr_cancel.reset();
    let client = state.graph_for(&tenant_id);

    // Adaptive in-flight concurrency: every 429 (including the per-sub-request
    // 429s Graph reports inside a `$batch`) halves the chunk cap; it recovers
    // after a quiet window. Detach the observer however the run exits — an early
    // `?` (e.g. the index reads below failing) must not leave a stale tracker
    // halving the shared per-tenant client's cap on unrelated traffic.
    let throttle = Arc::new(ConcurrencyThrottle::new(INITIAL_DR_CONCURRENCY));
    client.set_throttle_observer(throttle.clone());
    struct ObserverGuard(Arc<GraphClient>);
    impl Drop for ObserverGuard {
        fn drop(&mut self) {
            self.0.clear_throttle_observer();
        }
    }
    let _observer_guard = ObserverGuard(client.clone());

    // Enumerate the estate up front so progress has a real denominator. The SP
    // index reuses the cache the Enterprise Apps list populates (it's the same
    // per-tenant scan) so we don't re-pull it; the app index is one cheap read.
    let app_index = client.list_application_index(Some(ESTATE_CAP)).await?;
    let sp_index = sp_index_cached(&state, &client, &tenant_id).await?;
    let managed = client.list_managed_identities().await?;

    let app_total = app_index.len();
    let ent_total = sp_index
        .iter()
        .filter(|sp| !is_managed_identity(sp))
        .count();
    let total = app_total + ent_total + managed.len();
    emit(&app_handle, 0, total, None, Some(throttle.current_limit()));

    // ---- App registrations: batched full-config fan-out ----
    // The set of appIds that have a service principal — derived from the index
    // we already hold, so the per-app capture needs no SP lookup of its own.
    let sp_app_ids: Arc<std::collections::HashSet<String>> =
        Arc::new(sp_index.iter().map(|sp| sp.app_id.clone()).collect());
    let done = Arc::new(Mutex::new(0usize));
    let app_chunks: Vec<Vec<(String, String)>> =
        app_index.chunks(BATCH_CHUNK).map(<[_]>::to_vec).collect();
    let mut app_backups: Vec<AppRegistrationBackup> = Vec::with_capacity(app_total);
    let cancel = state.dr_cancel.clone();
    let cancelled = dispatch_capped(
        app_chunks,
        || throttle.current_limit(),
        |chunk| {
            if cancel.is_cancelled() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let sp_app_ids = sp_app_ids.clone();
            let throttle = throttle.clone();
            Some(tokio::spawn(async move {
                let report = |count: usize| {
                    emit(
                        &app_handle,
                        count,
                        total,
                        None,
                        Some(throttle.current_limit()),
                    );
                };
                backup_app_chunk(&client, chunk, &sp_app_ids, &done, &report).await
            }))
        },
        |joined| {
            if let Ok(mut v) = joined {
                app_backups.append(&mut v);
            }
        },
    )
    .await;
    // A partial backup is a dangerous DR artifact (it reads as complete), so a
    // cancelled run is an error, not a truncated success.
    if cancelled || state.dr_cancel.is_cancelled() {
        return Err(cancelled_err());
    }

    // appId → source object id, so an enterprise-app SP backed by an in-backup
    // app registration can point at it.
    let app_obj_by_app_id: HashMap<String, String> = app_backups
        .iter()
        .map(|a| (a.source_app_id.clone(), a.source_object_id.clone()))
        .collect();

    // ---- Enterprise apps: batched per-SP fan-out (full SP + assignments +
    // group memberships). Foreign/gallery SPs are captured the same way; their
    // restore is a runbook (re-consent / re-instantiate), not an automatic
    // replay. The managed-identity Azure-RBAC detail is captured by the MI
    // re-bind slice.
    let app_obj_by_app_id = Arc::new(app_obj_by_app_id);
    let tenant_arc: Arc<str> = Arc::from(tenant_id.as_str());
    let enterprise_sps: Vec<ServicePrincipal> = sp_index
        .into_iter()
        .filter(|sp| !is_managed_identity(sp))
        .collect();
    let ent_chunks: Vec<Vec<ServicePrincipal>> = enterprise_sps
        .chunks(BATCH_CHUNK)
        .map(<[_]>::to_vec)
        .collect();
    let mut enterprise_apps: Vec<EnterpriseAppBackup> = Vec::with_capacity(ent_total);
    let ent_cancel = state.dr_cancel.clone();
    let ent_cancelled = dispatch_capped(
        ent_chunks,
        || throttle.current_limit(),
        |chunk| {
            if ent_cancel.is_cancelled() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let map = app_obj_by_app_id.clone();
            let tenant = tenant_arc.clone();
            let throttle = throttle.clone();
            Some(tokio::spawn(async move {
                backup_enterprise_chunk(
                    &client,
                    chunk,
                    &tenant,
                    &map,
                    &app_handle,
                    &done,
                    total,
                    &throttle,
                )
                .await
            }))
        },
        |joined| {
            if let Ok(mut v) = joined {
                enterprise_apps.append(&mut v);
            }
        },
    )
    .await;
    if ent_cancelled || state.dr_cancel.is_cancelled() {
        return Err(cancelled_err());
    }

    // ---- Managed identities: identity + held Graph app-roles (the re-bindable
    // permission). Azure RBAC isn't scanned here — it's runbook-only on restore
    // (source scopes don't exist in the destination) and the MI detail view
    // already surfaces it for DR planning.
    let managed_identities = backup_managed_identities(
        &client,
        &managed,
        &state.dr_cancel,
        &app_handle,
        &done,
        total,
        &throttle,
    )
    .await?;

    Ok(TenantBackup {
        schema_version: BACKUP_SCHEMA_VERSION,
        created_at: chrono::Utc::now(),
        source_tenant_id: tenant_id,
        cloud: state.auth.cloud().as_str().to_string(),
        app_registrations: app_backups,
        enterprise_apps,
        managed_identities,
    })
}

/// A cancelled backup is an error, not a truncated success — a partial manifest
/// reads as complete and is a dangerous DR artifact.
fn cancelled_err() -> UiError {
    UiError::new("cancelled", "backup cancelled before completion", false)
}

/// Writes a [`TenantBackup`] to a JSON file via the OS save dialog. JSON only:
/// the manifest is a structured restore artifact, not a spreadsheet — CSV would
/// flatten away the nested config a restore needs. The backup carries **no**
/// secret values (only credential metadata), so the file is config-sensitive,
/// not secret-bearing. Returns the chosen path, or `None` if cancelled.
#[tauri::command]
pub async fn save_backup_to_file(
    app_handle: AppHandle,
    backup: TenantBackup,
    format: String,
) -> Result<Option<String>, UiError> {
    if format != "json" {
        return Err(UiError::validation(
            "unsupported_format",
            "tenant backup is JSON only",
        ));
    }
    super::audit::save_export_via_dialog(
        &app_handle,
        "tenant-backup",
        "json",
        String::new, // unreachable: format is validated to "json" above
        || serde_json::to_string_pretty(&backup).unwrap_or_else(|_| "{}".to_string()),
    )
    .await
}

/// Opens a backup JSON file via the OS file dialog and parses it into a
/// [`TenantBackup`]. Returns `None` if the user cancelled the dialog; errors if
/// the file isn't a valid backup manifest. Runs the dialog + read on a blocking
/// thread (Tauri 2: a sync command would freeze the webview).
#[tauri::command]
pub async fn load_backup_from_file(app_handle: AppHandle) -> Result<Option<TenantBackup>, UiError> {
    use tauri_plugin_dialog::DialogExt;
    tauri::async_runtime::spawn_blocking(move || {
        let chosen = app_handle
            .dialog()
            .file()
            .add_filter("JSON", &["json"])
            .blocking_pick_file();
        let Some(path) = chosen else {
            return Ok(None);
        };
        let path_buf = path
            .into_path()
            .map_err(|e| UiError::validation("invalid_path", e.to_string()))?;
        let content = std::fs::read_to_string(&path_buf).map_err(|e| UiError::io(e.to_string()))?;
        let backup: TenantBackup = serde_json::from_str(&content)
            .map_err(|e| UiError::serde(format!("not a valid backup file: {e}")))?;
        Ok(Some(backup))
    })
    .await
    .map_err(|e| UiError::io(e.to_string()))?
}

/// Signals an in-progress backup or restore to stop at the next dispatch
/// boundary. In-flight per-app reads finish so their results don't dangle.
#[tauri::command]
pub fn cancel_dr(state: State<'_, AppState>) {
    state.dr_cancel.cancel();
}

// ---------------- internals ----------------

/// The per-tenant service-principal index, reusing the cache the Enterprise
/// Apps / App Registrations lists populate (same `sp_index_key`) so a backup
/// right after browsing those lists doesn't re-pull the whole `/servicePrincipals`
/// scan. Falls back to a live fetch (and seeds the cache) on a miss.
async fn sp_index_cached(
    state: &AppState,
    client: &GraphClient,
    tenant_id: &str,
) -> Result<Vec<ServicePrincipal>, GraphError> {
    let key = sp_index_key(tenant_id);
    if let Some(cached) = state
        .cache
        .get::<Vec<ServicePrincipal>>(CacheKind::Lists, &key)
    {
        return Ok(cached);
    }
    let sps = client.list_service_principals_index().await?;
    state.cache.put(CacheKind::Lists, key, &sps);
    Ok(sps)
}

/// Backs up one chunk (≤ [`BATCH_CHUNK`]) of app registrations: the full-config
/// reads and the federated-credential lists each go out as one `$batch` POST,
/// instead of two individual GETs per app. A whole-batch failure degrades to
/// per-app reads for this chunk only (never failing the backup); a per-app
/// failure skips that one app. Emits per-app progress so the bar still advances
/// smoothly (in bursts of ≤20). Returns the assembled backups for the chunk.
async fn backup_app_chunk(
    client: &GraphClient,
    chunk: Vec<(String, String)>,
    sp_app_ids: &std::collections::HashSet<String>,
    done: &Mutex<usize>,
    // Called once per processed app with the new running total, so the chunk
    // stays decoupled from the Tauri `AppHandle` (the caller closes over the
    // handle + throttle to emit progress; tests pass a no-op). `+ Sync` so the
    // reference can be held across the `.await`s in a `Send` future.
    report: &(dyn Fn(usize) + Sync),
) -> Vec<AppRegistrationBackup> {
    let object_ids: Vec<String> = chunk.iter().map(|(_, oid)| oid.clone()).collect();
    let (apps_res, feds_res) = tokio::join!(
        client.batch_get_applications_backup_json(&object_ids),
        client.batch_list_federated_credentials(&object_ids),
    );
    let app_jsons: Vec<Result<serde_json::Value, GraphError>> = match apps_res {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "backup: app batch failed; per-app fallback");
            let mut v = Vec::with_capacity(object_ids.len());
            for oid in &object_ids {
                v.push(client.get_application_backup_json(oid).await);
            }
            v
        }
    };
    let feds: Vec<Result<Vec<FederatedIdentityCredential>, GraphError>> = match feds_res {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "backup: federated-cred batch failed; per-app fallback");
            let mut v = Vec::with_capacity(object_ids.len());
            for oid in &object_ids {
                v.push(client.list_federated_credentials(oid).await);
            }
            v
        }
    };

    let mut out = Vec::with_capacity(chunk.len());
    for (i, (app_id, object_id)) in chunk.iter().enumerate() {
        let has_sp = sp_app_ids.contains(app_id);
        match &app_jsons[i] {
            Ok(value) => match &feds[i] {
                Ok(federated) => match assemble_app_backup(value, federated.clone(), has_sp) {
                    Ok(b) => out.push(b),
                    Err(err) => {
                        tracing::warn!(%object_id, error = %err, "backup: app deserialize failed; skipping")
                    }
                },
                Err(err) => {
                    tracing::warn!(%object_id, error = %err, "backup: federated creds failed; skipping app")
                }
            },
            Err(err) => {
                tracing::warn!(%object_id, error = %err, "backup: app read failed; skipping")
            }
        }
        let count = {
            let mut d = done.lock().await;
            *d += 1;
            *d
        };
        report(count);
    }
    out
}

/// Assembles one app registration's backup from an already-fetched config JSON
/// (`$expand=owners`) and federated-credential list — no I/O. The full app +
/// Authentication + Expose-an-API + owners all come from the one JSON document.
///
/// `has_service_principal` is taken from the already-fetched SP index (no per-app
/// SP lookup), and `admin_consent_granted` is derived from the declared
/// permissions rather than probing the SP's live grants: restore re-grants admin
/// consent idempotently whenever permissions are declared, which is the
/// DR-correct default and removes three calls per app.
fn assemble_app_backup(
    value: &serde_json::Value,
    federated: Vec<FederatedIdentityCredential>,
    has_service_principal: bool,
) -> Result<AppRegistrationBackup, serde_json::Error> {
    // The typed model tolerates Graph's nulls; the Expose-an-API projection and
    // owners come from the same document. `?` surfaces a deserialize failure.
    let app: Application = serde_json::from_value(value.clone())?;
    let expose: ApplicationExposeApi = serde_json::from_value(value.clone()).unwrap_or_default();
    let auth = extract_auth_fields(value);
    let owners: Vec<DirectoryObject> = value
        .get("owners")
        .cloned()
        .and_then(|o| serde_json::from_value(o).ok())
        .unwrap_or_default();

    Ok(AppRegistrationBackup {
        source_object_id: app.id.clone(),
        source_app_id: app.app_id.clone(),
        display_name: app.display_name.clone(),
        sign_in_audience: app.sign_in_audience.clone(),
        description: app.description.clone(),
        identifier_uris: expose.identifier_uris,
        api_scopes: expose.api.oauth2_permission_scopes,
        pre_authorized_applications: expose.api.pre_authorized_applications,
        web_redirect_uris: auth.web_redirect_uris,
        spa_redirect_uris: auth.spa_redirect_uris,
        public_client_redirect_uris: auth.public_client_redirect_uris,
        logout_url: auth.logout_url,
        is_fallback_public_client: auth.is_fallback_public_client,
        enable_access_token_issuance: auth.enable_access_token_issuance,
        enable_id_token_issuance: auth.enable_id_token_issuance,
        required_resource_access: app.required_resource_access.clone(),
        admin_consent_granted: !app.required_resource_access.is_empty(),
        secrets: app
            .password_credentials
            .iter()
            .map(cred_meta_from_password)
            .collect(),
        certificates: app.key_credentials.iter().map(cred_meta_from_key).collect(),
        federated_credentials: federated,
        owners: owners.iter().map(principal_ref_from_dir).collect(),
        has_service_principal,
    })
}

/// Backs up one chunk (≤ [`BATCH_CHUNK`]) of enterprise apps: the full SP read,
/// the inbound role assignments, and the group memberships each go out as one
/// `$batch` POST (three POSTs per chunk, fired concurrently), instead of three
/// individual reads per SP. A whole-batch failure for any of the three degrades
/// to per-SP reads for this chunk; assignment/group per-SP failures degrade to
/// empty (matching the prior best-effort reads); an SP that vanished between the
/// index read and now is skipped. Emits per-SP progress.
#[allow(clippy::too_many_arguments)]
async fn backup_enterprise_chunk(
    client: &GraphClient,
    chunk: Vec<ServicePrincipal>,
    tenant_id: &str,
    app_obj_by_app_id: &HashMap<String, String>,
    app_handle: &AppHandle,
    done: &Mutex<usize>,
    total: usize,
    throttle: &ConcurrencyThrottle,
) -> Vec<EnterpriseAppBackup> {
    let sp_ids: Vec<String> = chunk.iter().map(|sp| sp.id.clone()).collect();
    let (sps_res, assigned_res, groups_res) = tokio::join!(
        client.batch_get_service_principals(&sp_ids),
        client.batch_list_app_role_assigned_to(&sp_ids),
        client.batch_list_service_principal_groups(&sp_ids),
    );
    let full_sps: Vec<Result<Option<ServicePrincipal>, GraphError>> = match sps_res {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "backup: enterprise SP batch failed; per-SP fallback");
            let mut v = Vec::with_capacity(sp_ids.len());
            for id in &sp_ids {
                v.push(client.get_service_principal_by_object_id(id).await);
            }
            v
        }
    };
    let assigned: Vec<Result<Vec<AppRoleAssignment>, GraphError>> = match assigned_res {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "backup: assignee batch failed; per-SP fallback");
            let mut v = Vec::with_capacity(sp_ids.len());
            for id in &sp_ids {
                v.push(client.list_app_role_assigned_to(id).await);
            }
            v
        }
    };
    let groups: Vec<Result<Vec<GroupSummary>, GraphError>> = match groups_res {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(error = %err, "backup: group-membership batch failed; per-SP fallback");
            let mut v = Vec::with_capacity(sp_ids.len());
            for id in &sp_ids {
                v.push(client.list_service_principal_groups(id).await);
            }
            v
        }
    };

    let mut out = Vec::with_capacity(chunk.len());
    for (i, index_sp) in chunk.iter().enumerate() {
        let entry = match &full_sps[i] {
            Ok(Some(sp)) => {
                // Assignment/group failures degrade to empty, like the prior reads.
                let assigned_i = match &assigned[i] {
                    Ok(v) => v.clone(),
                    Err(_) => Vec::new(),
                };
                let groups_i = match &groups[i] {
                    Ok(v) => v.clone(),
                    Err(_) => Vec::new(),
                };
                let paired = app_obj_by_app_id.get(&sp.app_id).cloned();
                Some(assemble_enterprise_backup(
                    sp, assigned_i, groups_i, tenant_id, paired,
                ))
            }
            Ok(None) => None, // vanished between the index read and now
            Err(err) => {
                tracing::warn!(sp = %index_sp.id, error = %err, "backup: enterprise SP fetch failed; skipping");
                None
            }
        };
        if let Some(b) = entry {
            out.push(b);
        }
        let count = {
            let mut d = done.lock().await;
            *d += 1;
            *d
        };
        emit(
            app_handle,
            count,
            total,
            Some(index_sp.display_name.clone()),
            Some(throttle.current_limit()),
        );
    }
    out
}

/// Assembles one enterprise application's backup from already-fetched data — no
/// I/O. Settings (tags, assignment-required), the users/groups assigned to its
/// roles (`appRoleAssignedTo`, role values resolved against the SP's own
/// `appRoles`), and the groups the SP belongs to.
fn assemble_enterprise_backup(
    sp: &ServicePrincipal,
    assigned: Vec<AppRoleAssignment>,
    groups: Vec<GroupSummary>,
    tenant_id: &str,
    paired_app_registration_object_id: Option<String>,
) -> EnterpriseAppBackup {
    // The role is defined on *this* SP, so its value resolves locally.
    let role_value = |role_id: &str| -> Option<String> {
        sp.app_roles
            .iter()
            .find(|r| r.id == role_id)
            .map(|r| r.value.clone())
            .filter(|v| !v.is_empty())
    };
    let app_role_assignees = assigned
        .into_iter()
        .map(|a| AppRoleAssigneeRef {
            app_role_value: role_value(&a.app_role_id),
            app_role_id: a.app_role_id,
            // `appRoleAssignedTo` gives the display name + type but not the UPN,
            // so restore remaps these by display name.
            principal: PrincipalRef {
                source_id: a.principal_id,
                display_name: a.principal_display_name,
                user_principal_name: None,
                principal_type: a.principal_type,
            },
        })
        .collect();
    let group_memberships = groups
        .into_iter()
        .map(|g| PrincipalRef {
            source_id: g.id,
            display_name: g.display_name,
            user_principal_name: None,
            principal_type: Some("#microsoft.graph.group".into()),
        })
        .collect();
    let is_foreign = sp
        .app_owner_organization_id
        .as_deref()
        .map(|o| o != tenant_id)
        .unwrap_or(false);

    EnterpriseAppBackup {
        source_sp_object_id: sp.id.clone(),
        source_app_id: sp.app_id.clone(),
        display_name: sp.display_name.clone(),
        account_enabled: sp.account_enabled,
        app_role_assignment_required: sp.app_role_assignment_required,
        service_principal_type: sp.service_principal_type.clone(),
        app_owner_organization_id: sp.app_owner_organization_id.clone(),
        is_foreign_tenant: is_foreign,
        paired_app_registration_object_id,
        tags: sp.tags.clone(),
        app_role_assignees,
        group_memberships,
        held_app_roles: Vec::new(),
    }
}

/// Backs up the managed identities: their identity + held Graph app-roles (the
/// re-bindable permission). Three batched phases: (1) every MI's held
/// assignments in one batched read, (2) resolve each distinct resource SP once
/// via a batched prewarm, (3) assemble (all resolves are now cache hits). Azure
/// RBAC isn't scanned here — it's runbook-only on restore. Polls `dr_cancel`
/// between phases and per MI. (Uses the batch helpers' own internal concurrency
/// rather than the adaptive chunk cap: the MI set is small and Pass 1/2 are the
/// throttle pressure that matters.)
#[allow(clippy::too_many_arguments)]
async fn backup_managed_identities(
    client: &GraphClient,
    managed: &[ServicePrincipal],
    cancel: &CancelFlag,
    app_handle: &AppHandle,
    done: &Mutex<usize>,
    total: usize,
    throttle: &ConcurrencyThrottle,
) -> Result<Vec<ManagedIdentityBackup>, UiError> {
    if cancel.is_cancelled() {
        return Err(cancelled_err());
    }
    let mi_ids: Vec<String> = managed.iter().map(|sp| sp.id.clone()).collect();

    // Phase 1: every MI's held app-role assignments. A read failure (whole-batch
    // or per-MI) degrades to empty, matching the prior best-effort per-MI read.
    let assignments: Vec<Vec<AppRoleAssignment>> =
        match client.batch_list_app_role_assignments(&mi_ids).await {
            Ok(v) => v.into_iter().map(Result::unwrap_or_default).collect(),
            Err(err) => {
                tracing::warn!(error = %err, "backup: MI assignment batch failed; per-MI fallback");
                let mut v = Vec::with_capacity(mi_ids.len());
                for id in &mi_ids {
                    v.push(
                        client
                            .list_app_role_assignments(id)
                            .await
                            .unwrap_or_default(),
                    );
                }
                v
            }
        };

    if cancel.is_cancelled() {
        return Err(cancelled_err());
    }

    // Phase 2: resolve each distinct resource SP once, batched, seeding the
    // lookup so the per-MI assembly below makes no further round trips.
    let mut resolver = ResourceLookup::new(client);
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<String> = assignments
        .iter()
        .flatten()
        .filter(|a| seen.insert(a.resource_id.clone()))
        .map(|a| a.resource_id.clone())
        .collect();
    resolver.prewarm(&unique).await;

    // Phase 3: assemble (cache hits).
    let mut out = Vec::with_capacity(managed.len());
    let mut count = *done.lock().await;
    for (i, sp) in managed.iter().enumerate() {
        if cancel.is_cancelled() {
            return Err(cancelled_err());
        }
        let subtype = MiSubtype::from_alternative_names(&sp.alternative_names);
        let held_app_roles = resolver.held_app_roles_from(&assignments[i]).await;
        out.push(ManagedIdentityBackup {
            source_principal_id: sp.id.clone(),
            source_app_id: sp.app_id.clone(),
            display_name: sp.display_name.clone(),
            subtype: mi_subtype_label(subtype).to_string(),
            arm_resource_id: user_assigned_arm_id(&sp.alternative_names),
            held_app_roles,
            ..Default::default()
        });
        count += 1;
        emit(
            app_handle,
            count,
            total,
            Some(sp.display_name.clone()),
            Some(throttle.current_limit()),
        );
    }
    Ok(out)
}

fn is_managed_identity(sp: &ServicePrincipal) -> bool {
    sp.service_principal_type.as_deref() == Some("ManagedIdentity")
}

/// Resolves a resource service-principal object id to the keys a held-app-role
/// grant needs to survive a tenant move — the resource's stable `appId` and the
/// role's resolved `value` — caching each SP fetch (a held grant references the
/// resource only by its source-tenant SP object id, which is useless in the
/// destination).
struct ResourceLookup<'a> {
    client: &'a GraphClient,
    cache: HashMap<String, Option<ResourceInfo>>,
}

#[derive(Clone)]
struct ResourceInfo {
    app_id: String,
    display_name: String,
    role_value_by_id: HashMap<String, String>,
}

impl ResourceInfo {
    fn from_sp(sp: &ServicePrincipal) -> Self {
        Self {
            app_id: sp.app_id.clone(),
            display_name: sp.display_name.clone(),
            role_value_by_id: sp
                .app_roles
                .iter()
                .map(|r| (r.id.clone(), r.value.clone()))
                .collect(),
        }
    }
}

impl<'a> ResourceLookup<'a> {
    fn new(client: &'a GraphClient) -> Self {
        Self {
            client,
            cache: HashMap::new(),
        }
    }

    /// Resolves many resource SPs in one batched read, seeding the cache so the
    /// per-MI [`Self::held_app_roles_from`] below makes no further round trips.
    /// A vanished resource (404) caches `None`; a per-id error is left cold so a
    /// later `resolve` retries it; a whole-batch failure leaves every id cold.
    async fn prewarm(&mut self, resource_ids: &[String]) {
        let missing: Vec<String> = resource_ids
            .iter()
            .filter(|id| !self.cache.contains_key(*id))
            .cloned()
            .collect();
        if missing.is_empty() {
            return;
        }
        match self.client.batch_get_service_principals(&missing).await {
            Ok(results) => {
                for (id, res) in missing.iter().zip(results) {
                    match res {
                        Ok(Some(sp)) => {
                            self.cache
                                .insert(id.clone(), Some(ResourceInfo::from_sp(&sp)));
                        }
                        Ok(None) => {
                            self.cache.insert(id.clone(), None);
                        }
                        // Leave cold: `resolve` retries this id per-request.
                        Err(_) => {}
                    }
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "backup: resource-SP prewarm batch failed; per-id resolves")
            }
        }
    }

    async fn resolve(&mut self, resource_sp_id: &str) -> Option<ResourceInfo> {
        if let Some(hit) = self.cache.get(resource_sp_id) {
            return hit.clone();
        }
        let info = match self
            .client
            .get_service_principal_by_object_id(resource_sp_id)
            .await
        {
            Ok(Some(sp)) => Some(ResourceInfo::from_sp(&sp)),
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(%resource_sp_id, error = %err, "backup: resource SP resolve failed; recording raw ids");
                None
            }
        };
        self.cache.insert(resource_sp_id.to_string(), info.clone());
        info
    }

    /// The application permissions a managed identity holds, from its
    /// already-fetched assignment list, resolving each grant's resource against
    /// the (prewarmed) cache. A resolve miss degrades that grant to raw ids.
    async fn held_app_roles_from(
        &mut self,
        assignments: &[AppRoleAssignment],
    ) -> Vec<AppRoleGrantRef> {
        let mut out = Vec::with_capacity(assignments.len());
        for a in assignments {
            let info = self.resolve(&a.resource_id).await;
            out.push(AppRoleGrantRef {
                resource_app_id: info.as_ref().map(|i| i.app_id.clone()).unwrap_or_default(),
                resource_display_name: a
                    .resource_display_name
                    .clone()
                    .or_else(|| info.as_ref().map(|i| i.display_name.clone())),
                app_role_value: info
                    .as_ref()
                    .and_then(|i| i.role_value_by_id.get(&a.app_role_id).cloned())
                    .filter(|v| !v.is_empty()),
                app_role_id: a.app_role_id.clone(),
            });
        }
        out
    }
}

/// The first `alternativeNames` entry that is an ARM resource id for a
/// user-assigned managed identity (the entry that marks the MI as
/// user-assigned). `None` for system-assigned MIs (recreated with their host).
fn user_assigned_arm_id<S: AsRef<str>>(alternative_names: &[S]) -> Option<String> {
    alternative_names
        .iter()
        .map(AsRef::as_ref)
        .find(|n| n.to_ascii_lowercase().contains("userassignedidentities"))
        .map(str::to_string)
}

/// Stable camelCase label for [`MiSubtype`], matching its serde wire form so the
/// backup's `subtype` string round-trips against the same vocabulary the UI uses.
fn mi_subtype_label(subtype: MiSubtype) -> &'static str {
    match subtype {
        MiSubtype::SystemAssigned => "systemAssigned",
        MiSubtype::UserAssigned => "userAssigned",
        MiSubtype::Unknown => "unknown",
    }
}

/// Secret metadata — never a value. The `secretText` is only present on an
/// add-password response and is deliberately dropped here.
fn cred_meta_from_password(c: &PasswordCredential) -> CredentialMeta {
    CredentialMeta {
        display_name: c.display_name.clone(),
        start_date_time: c.start_date_time,
        end_date_time: c.end_date_time,
        thumbprint: None,
    }
}

/// Certificate metadata — public thumbprint only; the private key never reaches
/// Graph and so is never in the backup.
fn cred_meta_from_key(c: &KeyCredential) -> CredentialMeta {
    CredentialMeta {
        display_name: c.display_name.clone(),
        start_date_time: c.start_date_time,
        end_date_time: c.end_date_time,
        thumbprint: c.custom_key_identifier.clone(),
    }
}

fn principal_ref_from_dir(o: &DirectoryObject) -> PrincipalRef {
    PrincipalRef {
        source_id: o.id.clone(),
        display_name: o.display_name.clone(),
        user_principal_name: o.user_principal_name.clone(),
        principal_type: o.odata_type.clone(),
    }
}

fn emit(
    app_handle: &AppHandle,
    done: usize,
    total: usize,
    current_app: Option<String>,
    in_flight_cap: Option<usize>,
) {
    let progress = BulkProgress {
        done,
        total,
        current_app,
        cancelled: false,
        in_flight_cap,
    };
    if let Err(err) = app_handle.emit("backup-progress", progress) {
        tracing::warn!(?err, "failed to emit backup-progress event");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_assigned_arm_id_extracts_resource_id() {
        let names = [
            "isExplicit=True",
            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1",
        ];
        assert_eq!(
            user_assigned_arm_id(&names).as_deref(),
            Some("/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1")
        );
        // System-assigned (host resource id, no userAssignedIdentities marker).
        let sys = [
            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1",
        ];
        assert_eq!(user_assigned_arm_id(&sys), None);
    }

    #[test]
    fn mi_subtype_label_matches_camel_case_wire_form() {
        assert_eq!(mi_subtype_label(MiSubtype::UserAssigned), "userAssigned");
        assert_eq!(
            mi_subtype_label(MiSubtype::SystemAssigned),
            "systemAssigned"
        );
        assert_eq!(mi_subtype_label(MiSubtype::Unknown), "unknown");
    }

    #[test]
    fn cred_meta_drops_secret_and_keeps_cert_thumbprint() {
        let secret = PasswordCredential {
            key_id: "k".into(),
            display_name: Some("s".into()),
            secret_text: Some("super-secret-value".into()),
            ..Default::default()
        };
        let meta = cred_meta_from_password(&secret);
        // No field on CredentialMeta can carry the value; assert the round-trip
        // can't reintroduce it.
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("super-secret-value"));

        let cert = KeyCredential {
            key_id: "c".into(),
            custom_key_identifier: Some("THUMBPRINT==".into()),
            ..Default::default()
        };
        assert_eq!(
            cred_meta_from_key(&cert).thumbprint.as_deref(),
            Some("THUMBPRINT==")
        );
    }

    // The DR backup's headline invariant: a whole-`$batch` failure must degrade to
    // per-object reads (never failing the run), and a per-object read that fails
    // must skip only that object. Exercised against a mock Graph server, the same
    // way the graph crate tests its client.
    #[tokio::test]
    async fn backup_app_chunk_degrades_to_per_app_reads_and_skips_failures() {
        use azapptoolkit_core::cache::Cache;
        use azapptoolkit_core::token::StaticTokenProvider;
        use std::collections::HashSet;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Every `$batch` POST 503s — forcing the per-object fallback for both the
        // app-config and the federated-credential reads.
        Mock::given(method("POST"))
            .and(path("/$batch"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        // obj-1 resolves via the fallback GETs.
        let app_json = serde_json::json!({
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "Demo App",
            "signInAudience": "AzureADMyOrg",
            "passwordCredentials": [],
            "keyCredentials": [],
            "requiredResourceAccess": []
        });
        Mock::given(method("GET"))
            .and(path("/applications/obj-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(app_json))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/applications/obj-1/federatedIdentityCredentials"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
            )
            .mount(&server)
            .await;

        // obj-2's per-object read fails (500): it must be skipped, not abort the run.
        Mock::given(method("GET"))
            .and(path("/applications/obj-2"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/applications/obj-2/federatedIdentityCredentials"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
            )
            .mount(&server)
            .await;

        let token = StaticTokenProvider::new("tok");
        let client = GraphClient::with_base_url(
            "tenant-test",
            token.clone(),
            token,
            Cache::new(),
            server.uri(),
        );

        let done = Mutex::new(0usize);
        let chunk = vec![
            ("app-1".to_string(), "obj-1".to_string()),
            ("app-2".to_string(), "obj-2".to_string()),
        ];
        let sp_app_ids = HashSet::new();

        // No-op progress callback — the degrade logic under test doesn't depend on
        // it, and this keeps the test free of a Tauri AppHandle / mock runtime.
        let report = |_count: usize| {};
        let out = backup_app_chunk(&client, chunk, &sp_app_ids, &done, &report).await;

        // The run never fails: obj-1 is recovered via the per-object fallback, and
        // obj-2's failed read is skipped rather than aborting the chunk.
        assert_eq!(
            out.len(),
            1,
            "the failed object should be skipped, not fatal"
        );
        // Progress still advances for every object in the chunk, including the skip.
        assert_eq!(*done.lock().await, 2);
    }
}
