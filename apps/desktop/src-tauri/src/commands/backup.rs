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
//!   Enterprise apps are captured with their settings, assignments and group
//!   memberships; managed identities with their held Graph app-roles. Azure
//!   RBAC is deliberately not captured — restore lists it as a runbook item.

use std::collections::HashMap;
use std::sync::Arc;

use tauri::{AppHandle, State};

use azapptoolkit_core::models::{
    AppRoleAssignment, Application, ApplicationExposeApi, DirectoryObject,
    FederatedIdentityCredential, GroupSummary, KeyCredential, PasswordCredential, ServicePrincipal,
};
use azapptoolkit_graph::{GraphClient, GraphError};

use crate::commands::applications::{extract_auth_fields, indexes_cached};
use crate::commands::dispatch::{SessionDead, batch_or_serial, dispatch_capped};
use crate::commands::progress::{ProgressSink, emit_progress};
use crate::commands::throttle::{FanOutMeter, FanOutTicker};
use crate::dto::UiError;
use crate::dto::backup::{
    AppRegistrationBackup, AppRoleAssigneeRef, AppRoleGrantRef, BACKUP_SCHEMA_VERSION,
    CredentialMeta, EnterpriseAppBackup, ManagedIdentityBackup, PrincipalRef, SkippedObject,
    TenantBackup,
};
use crate::dto::bulk::BulkProgress;
use crate::dto::managed_identity::MiSubtype;
use crate::state::{AppState, CancelToken};

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

/// Largest backup file `load_backup_from_file` reads. A manifest is
/// configuration only, but a large tenant's runs to tens of MiB (every app's
/// permissions, scopes, owners and credential metadata), so the bound sits well
/// above any real one — it exists to refuse the wrong file, or a hostile one,
/// before it is held in memory and parsed.
const MAX_BACKUP_BYTES: u64 = 256 * 1024 * 1024;

// The estate's enumeration cap is no longer restated here: both indexes now come
// from the shared cached accessors (`indexes_cached`), which bound themselves by
// the lists' `APPS_MAX` / `SP_INDEX_MAX`. A local copy could only drift from them.

/// Captures a full, portable backup of the tenant's app estate. Long-running
/// (a batched per-app fan-out), so it polls its own [`AppState::backup_cancel`]
/// token, stopped only by [`cancel_backup`] and by sign-out
/// (`AppState::forget_tenant`): a restore's Cancel cannot stop it
/// and vice versa, nor can an audit/bulk run's. Emits `backup-progress` ([`BulkProgress`]) events
/// carrying the live adaptive concurrency cap.
#[tauri::command]
pub async fn backup_tenant(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<TenantBackup, UiError> {
    // The two tenant-wide indexes below can answer from cache before any
    // request is sent; `graph_for` only builds token adapters, so it is not a
    // session proof. Sync, so it does not delay the claim past an await.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    // Claimed before the first await, not beside the dispatch it feeds. A token
    // claimed after a long read carries a HIGHER generation than a cancel
    // issued during that read, and `is_cancelled()` (`cancelled >= generation`)
    // discards it — so a Cancel pressed during the index enumeration below,
    // which on a large tenant is most of the wait before any progress appears,
    // did nothing. Pinned by `repo_invariants::cancel`.
    let cancel = state.backup_cancel.claim();
    let session = SessionDead::new();
    let client = state.graph_for(&tenant_id);

    // Adaptive in-flight concurrency: every 429 (including the per-sub-request
    // 429s Graph reports inside a `$batch`) halves the chunk cap; it recovers
    // after a quiet window. Detach the observer however the run exits — an early
    // `?` (e.g. the index reads below failing) must not leave a stale tracker
    // halving the shared per-tenant client's cap on unrelated traffic. The
    // meter's completion counter is the backup's running `done`, shared by all
    // three passes (it used to be a hand-rolled tracker + an async-locked count).
    let meter = FanOutMeter::attach(client.clone(), INITIAL_DR_CONCURRENCY);

    // Enumerate the estate up front so progress has a real denominator. BOTH
    // indexes are the shared per-tenant entries the lists populate, so a backup
    // run right after browsing costs no directory scan at all, and a cold run
    // fetches the two concurrently instead of serially.
    let (sp_index, app_index) = indexes_cached(&state, &client, &tenant_id).await?;

    // The managed identities are a FILTER over the SP index we already hold —
    // `/servicePrincipals?$filter=servicePrincipalType eq 'ManagedIdentity'` is
    // a second full scan of the same collection, and the index projection is a
    // superset of what the MI pass reads (`id`/`appId`/`displayName`/
    // `alternativeNames`). Same reasoning as `list_managed_identities`, which is
    // itself a filter over this index.
    let managed: Vec<ServicePrincipal> = sp_index
        .iter()
        .filter(|sp| is_managed_identity(sp))
        .cloned()
        .collect();

    let app_total = app_index.len();
    let ent_total = sp_index.len() - managed.len();
    let total = app_total + ent_total + managed.len();
    emit(&app_handle, 0, total, None, Some(meter.limit()));

    // ---- App registrations: batched full-config fan-out ----
    // The set of appIds that have a service principal — derived from the index
    // we already hold, so the per-app capture needs no SP lookup of its own.
    let sp_app_ids: Arc<std::collections::HashSet<String>> =
        Arc::new(sp_index.iter().map(|sp| sp.app_id.clone()).collect());
    let app_pairs: Vec<(String, String)> = app_index
        .iter()
        .map(|a| (a.app_id.clone(), a.id.clone()))
        .collect();
    let app_chunks: Vec<Vec<(String, String)>> =
        app_pairs.chunks(BATCH_CHUNK).map(<[_]>::to_vec).collect();
    let mut app_backups: Vec<AppRegistrationBackup> = Vec::with_capacity(app_total);
    // Carried onto the manifest so a short backup says so — see
    // `TenantBackup::skipped`.
    let mut skipped: Vec<SkippedObject> = Vec::new();
    let cancelled = dispatch_capped(
        app_chunks,
        || meter.limit(),
        |chunk| {
            if cancel.is_cancelled() || session.is_dead() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let ticker = meter.ticker();
            let sp_app_ids = sp_app_ids.clone();
            let session = session.clone();
            Some(tokio::spawn(async move {
                let tick = BackupTicker {
                    sink: &app_handle,
                    ticker: &ticker,
                    total,
                };
                backup_app_chunk(&client, chunk, &sp_app_ids, &tick, &session).await
            }))
        },
        |joined| {
            if let Ok((mut v, mut s)) = joined {
                app_backups.append(&mut v);
                skipped.append(&mut s);
            }
        },
    )
    .await;
    // A partial backup is a dangerous DR artifact (it reads as complete), so a
    // cancelled run is an error, not a truncated success.
    if session.is_dead() {
        return Err(session.err("the tenant backup"));
    }
    if cancelled || cancel.is_cancelled() {
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
    // replay.
    let app_obj_by_app_id = Arc::new(app_obj_by_app_id);
    let tenant_arc: Arc<str> = Arc::from(tenant_id.as_str());
    let enterprise_sps: Vec<ServicePrincipal> = sp_index
        .iter()
        .filter(|sp| !is_managed_identity(sp))
        .cloned()
        .collect();
    let ent_chunks: Vec<Vec<ServicePrincipal>> = enterprise_sps
        .chunks(BATCH_CHUNK)
        .map(<[_]>::to_vec)
        .collect();
    let mut enterprise_apps: Vec<EnterpriseAppBackup> = Vec::with_capacity(ent_total);
    let ent_cancelled = dispatch_capped(
        ent_chunks,
        || meter.limit(),
        |chunk| {
            if cancel.is_cancelled() || session.is_dead() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let ticker = meter.ticker();
            let map = app_obj_by_app_id.clone();
            let tenant = tenant_arc.clone();
            let session = session.clone();
            Some(tokio::spawn(async move {
                let tick = BackupTicker {
                    sink: &app_handle,
                    ticker: &ticker,
                    total,
                };
                backup_enterprise_chunk(&client, chunk, &tenant, &map, &tick, &session).await
            }))
        },
        |joined| {
            if let Ok((mut v, mut s)) = joined {
                enterprise_apps.append(&mut v);
                skipped.append(&mut s);
            }
        },
    )
    .await;
    if session.is_dead() {
        return Err(session.err("the tenant backup"));
    }
    if ent_cancelled || cancel.is_cancelled() {
        return Err(cancelled_err());
    }

    // ---- Managed identities: identity + held Graph app-roles (the re-bindable
    // permission). Azure RBAC isn't scanned here — it's runbook-only on restore
    // (source scopes don't exist in the destination) and the MI detail view
    // already surfaces it for DR planning. A per-MI read failure is recorded in
    // `skipped`; a dead session or a cancel aborts the backup (the `?`).
    let ticker = meter.ticker();
    let tick = BackupTicker {
        sink: &app_handle,
        ticker: &ticker,
        total,
    };
    let (managed_identities, mut mi_skipped) =
        backup_managed_identities(&client, &managed, &cancel, &tick, &session).await?;
    skipped.append(&mut mi_skipped);

    Ok(TenantBackup {
        schema_version: BACKUP_SCHEMA_VERSION,
        created_at: chrono::Utc::now(),
        source_tenant_id: tenant_id,
        cloud: state.auth.cloud(),
        app_registrations: app_backups,
        enterprise_apps,
        managed_identities,
        skipped,
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
    // Serialized up front so a failure is an error, never an empty `{}` written
    // and reported as a saved backup.
    let json = serde_json::to_string_pretty(&backup)
        .map_err(|e| UiError::serde(format!("could not serialize the tenant backup: {e}")))?;
    super::export::save_export_via_dialog(
        &app_handle,
        "tenant-backup",
        "json",
        String::new, // unreachable: format is validated to "json" above
        move || json,
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
        read_backup_file(&path_buf, MAX_BACKUP_BYTES).map(Some)
    })
    .await
    .map_err(|e| UiError::io(e.to_string()))?
}

/// Reads and parses the backup file at `path`, refusing one over `cap` bytes
/// (`MAX_BACKUP_BYTES` in production; a parameter so the bound is testable
/// without a 256 MiB fixture).
fn read_backup_file(path: &std::path::Path, cap: u64) -> Result<TenantBackup, UiError> {
    let content = super::export::read_capped_utf8(path, cap, "invalid_backup_file")?;
    serde_json::from_str(&content)
        .map_err(|e| UiError::serde(format!("not a valid backup file: {e}")))
}

/// Signals an in-progress backup to stop at the next dispatch boundary.
/// In-flight per-app reads finish so their results don't dangle.
#[tauri::command]
pub fn cancel_backup(state: State<'_, AppState>) {
    state.backup_cancel.cancel();
}

// ---------------- internals ----------------

/// Backs up one chunk (≤ [`BATCH_CHUNK`]) of app registrations: the full-config
/// reads and the federated-credential lists each go out as one `$batch` POST,
/// instead of two individual GETs per app. A whole-batch failure degrades to
/// per-app reads for this chunk only (never failing the backup); a per-app
/// failure skips that one app. Emits per-app progress so the bar still advances
/// smoothly (in bursts of ≤20). Returns the assembled backups for the chunk.
/// Classifies the per-item failures of a batched read. A dead session makes
/// every remaining read fail identically, and a DR backup that quietly drops
/// what it couldn't read restores as if those objects never existed.
fn note_graph_failures<'a, T: 'a>(
    session: &SessionDead,
    results: impl Iterator<Item = Result<&'a T, &'a GraphError>>,
) {
    for err in results.filter_map(Result::err) {
        session.note_code(err.ui_code());
    }
}

async fn backup_app_chunk<S: ProgressSink>(
    client: &GraphClient,
    chunk: Vec<(String, String)>,
    sp_app_ids: &std::collections::HashSet<String>,
    tick: &BackupTicker<'_, S>,
    session: &SessionDead,
) -> (Vec<AppRegistrationBackup>, Vec<SkippedObject>) {
    let object_ids: Vec<String> = chunk.iter().map(|(_, oid)| oid.clone()).collect();
    let (apps_res, feds_res) = tokio::join!(
        client.batch_get_applications_backup_json(&object_ids),
        client.batch_list_federated_credentials(&object_ids),
    );
    let app_jsons: Vec<Result<serde_json::Value, GraphError>> = batch_or_serial(
        "backup app",
        &object_ids,
        apps_res,
        |oid: String| async move { client.get_application_backup_json(&oid).await },
    )
    .await;
    let feds: Vec<Result<Vec<FederatedIdentityCredential>, GraphError>> = batch_or_serial(
        "backup federated-cred",
        &object_ids,
        feds_res,
        |oid: String| async move { client.list_federated_credentials(&oid).await },
    )
    .await;

    // A DR backup that silently drops apps is the most dangerous artifact this
    // app produces — it restores as if those apps never existed. Classify every
    // per-item failure so a dead session aborts the run instead of thinning it.
    note_graph_failures(session, app_jsons.iter().map(Result::as_ref));
    note_graph_failures(session, feds.iter().map(Result::as_ref));

    let mut out = Vec::with_capacity(chunk.len());
    // Every `skipping` below used to end at a `warn!` and nowhere else, so the
    // resulting manifest was short by exactly these apps with no record of it.
    // Collected and carried on the backup instead.
    let mut skipped: Vec<SkippedObject> = Vec::new();
    for (i, (app_id, object_id)) in chunk.iter().enumerate() {
        let has_sp = sp_app_ids.contains(app_id);
        match &app_jsons[i] {
            Ok(value) => match &feds[i] {
                Ok(federated) => match assemble_app_backup(value, federated.clone(), has_sp) {
                    Ok(b) => out.push(b),
                    Err(err) => {
                        tracing::warn!(%object_id, error = %err, "backup: app deserialize failed; skipping");
                        skipped.push(SkippedObject::new(
                            "application",
                            object_id,
                            None,
                            format!("configuration could not be read: {err}"),
                        ));
                    }
                },
                Err(err) => {
                    tracing::warn!(%object_id, error = %err, "backup: federated creds failed; skipping app");
                    skipped.push(SkippedObject::new(
                        "application",
                        object_id,
                        None,
                        format!("federated credentials could not be read: {err}"),
                    ));
                }
            },
            Err(err) => {
                tracing::warn!(%object_id, error = %err, "backup: app read failed; skipping");
                skipped.push(SkippedObject::new(
                    "application",
                    object_id,
                    None,
                    format!("application could not be read: {err}"),
                ));
            }
        }
        tick.advance(None);
    }
    (out, skipped)
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
/// to per-SP reads for this chunk; an assignment/group per-SP failure still
/// captures the SP, without that part, and is recorded in `skipped` as a
/// partial entry (see [`enterprise_entry`]); an SP that vanished between the
/// index read and now is left out. Emits per-SP progress.
async fn backup_enterprise_chunk<S: ProgressSink>(
    client: &GraphClient,
    chunk: Vec<ServicePrincipal>,
    tenant_id: &str,
    app_obj_by_app_id: &HashMap<String, String>,
    tick: &BackupTicker<'_, S>,
    session: &SessionDead,
) -> (Vec<EnterpriseAppBackup>, Vec<SkippedObject>) {
    let sp_ids: Vec<String> = chunk.iter().map(|sp| sp.id.clone()).collect();
    let (sps_res, assigned_res, groups_res) = tokio::join!(
        client.batch_get_service_principals(&sp_ids),
        client.batch_list_app_role_assigned_to(&sp_ids),
        client.batch_list_service_principal_groups(&sp_ids),
    );
    let full_sps: Vec<Result<Option<ServicePrincipal>, GraphError>> = batch_or_serial(
        "backup enterprise SP",
        &sp_ids,
        sps_res,
        |id: String| async move { client.get_service_principal_by_object_id(&id).await },
    )
    .await;
    let assigned: Vec<Result<Vec<AppRoleAssignment>, GraphError>> = batch_or_serial(
        "backup assignee",
        &sp_ids,
        assigned_res,
        |id: String| async move { client.list_app_role_assigned_to(&id).await },
    )
    .await;
    let groups: Vec<Result<Vec<GroupSummary>, GraphError>> = batch_or_serial(
        "backup group-membership",
        &sp_ids,
        groups_res,
        |id: String| async move { client.list_service_principal_groups(&id).await },
    )
    .await;

    note_graph_failures(session, full_sps.iter().map(Result::as_ref));
    note_graph_failures(session, assigned.iter().map(Result::as_ref));
    note_graph_failures(session, groups.iter().map(Result::as_ref));

    let mut out = Vec::with_capacity(chunk.len());
    let mut skipped: Vec<SkippedObject> = Vec::new();
    for (i, index_sp) in chunk.iter().enumerate() {
        let entry = enterprise_entry(
            index_sp,
            &full_sps[i],
            &assigned[i],
            &groups[i],
            tenant_id,
            app_obj_by_app_id,
            &mut skipped,
        );
        if let Some(b) = entry {
            out.push(b);
        }
        tick.advance(Some(index_sp.display_name.clone()));
    }
    (out, skipped)
}

/// Turns one enterprise SP's three already-fetched reads into its backup entry —
/// no I/O. A failed SP read leaves the app out (an `enterpriseApp` skip); a
/// vanished SP (`Ok(None)`) is left out silently. A failed assignee or group
/// read still captures the app, without that part, and records the gap as an
/// `enterpriseAppAssignments` / `enterpriseAppGroups` skip: an entry with zero
/// assignees restores as "nobody had access", so the manifest has to say it
/// does not know.
fn enterprise_entry(
    index_sp: &ServicePrincipal,
    full: &Result<Option<ServicePrincipal>, GraphError>,
    assigned: &Result<Vec<AppRoleAssignment>, GraphError>,
    groups: &Result<Vec<GroupSummary>, GraphError>,
    tenant_id: &str,
    app_obj_by_app_id: &HashMap<String, String>,
    skipped: &mut Vec<SkippedObject>,
) -> Option<EnterpriseAppBackup> {
    match full {
        Ok(Some(sp)) => {
            let assigned = match assigned {
                Ok(v) => v.clone(),
                Err(err) => {
                    tracing::warn!(sp = %sp.id, error = %err, "backup: enterprise assignee read failed; recording as partial");
                    skipped.push(SkippedObject::new(
                        "enterpriseAppAssignments",
                        &sp.id,
                        Some(sp.display_name.clone()),
                        format!(
                            "assigned users/groups could not be read: {err}; captured without them"
                        ),
                    ));
                    Vec::new()
                }
            };
            let groups = match groups {
                Ok(v) => v.clone(),
                Err(err) => {
                    tracing::warn!(sp = %sp.id, error = %err, "backup: enterprise group-membership read failed; recording as partial");
                    skipped.push(SkippedObject::new(
                        "enterpriseAppGroups",
                        &sp.id,
                        Some(sp.display_name.clone()),
                        format!(
                            "group memberships could not be read: {err}; captured without them"
                        ),
                    ));
                    Vec::new()
                }
            };
            let paired = app_obj_by_app_id.get(&sp.app_id).cloned();
            Some(assemble_enterprise_backup(
                sp, assigned, groups, tenant_id, paired,
            ))
        }
        Ok(None) => None, // vanished between the index read and now
        Err(err) => {
            tracing::warn!(sp = %index_sp.id, error = %err, "backup: enterprise SP fetch failed; skipping");
            skipped.push(SkippedObject::new(
                "enterpriseApp",
                &index_sp.id,
                Some(index_sp.display_name.clone()),
                format!("service principal could not be read: {err}"),
            ));
            None
        }
    }
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
/// RBAC isn't scanned here — it's runbook-only on restore. Polls the backup's token
/// between phases and per MI. (Uses the batch helpers' own internal concurrency
/// rather than the adaptive chunk cap: the MI set is small and Pass 1/2 are the
/// throttle pressure that matters.)
///
/// Like Passes 1 and 2, every read failure is classified through `session`: a
/// dead session aborts the backup rather than saving a manifest whose managed
/// identities all hold nothing. A per-MI assignment read failure still captures
/// the MI (so its redeploy runbook item exists) and records a `managedIdentity`
/// skip, so the missing app-roles are never read as "holds none".
async fn backup_managed_identities<S: ProgressSink>(
    client: &GraphClient,
    managed: &[ServicePrincipal],
    cancel: &CancelToken,
    tick: &BackupTicker<'_, S>,
    session: &SessionDead,
) -> Result<(Vec<ManagedIdentityBackup>, Vec<SkippedObject>), UiError> {
    if cancel.is_cancelled() {
        return Err(cancelled_err());
    }
    let mi_ids: Vec<String> = managed.iter().map(|sp| sp.id.clone()).collect();

    // Phase 1: every MI's held app-role assignments. A whole-batch failure takes
    // the per-MI path; each per-MI result is kept so a failure is recorded below.
    let assignments: Vec<Result<Vec<AppRoleAssignment>, GraphError>> = batch_or_serial(
        "backup MI assignment",
        &mi_ids,
        client.batch_list_app_role_assignments(&mi_ids).await,
        |id: String| async move { client.list_app_role_assignments(&id).await },
    )
    .await;
    note_graph_failures(session, assignments.iter().map(Result::as_ref));
    if session.is_dead() {
        return Err(session.err("the tenant backup"));
    }

    if cancel.is_cancelled() {
        return Err(cancelled_err());
    }

    // Phase 2: resolve each distinct resource SP once, batched, seeding the
    // lookup so the per-MI assembly below makes no further round trips.
    let mut resolver = ResourceLookup::new(client, session);
    let mut seen = std::collections::HashSet::new();
    let unique: Vec<String> = assignments
        .iter()
        .filter_map(|r| r.as_ref().ok())
        .flatten()
        .filter(|a| seen.insert(a.resource_id.clone()))
        .map(|a| a.resource_id.clone())
        .collect();
    resolver.prewarm(&unique).await;

    // Phase 3: assemble (cache hits).
    let mut out = Vec::with_capacity(managed.len());
    let mut skipped: Vec<SkippedObject> = Vec::new();
    for (i, sp) in managed.iter().enumerate() {
        if cancel.is_cancelled() {
            return Err(cancelled_err());
        }
        let held_app_roles = match &assignments[i] {
            Ok(a) => resolver.held_app_roles_from(a).await,
            Err(err) => {
                tracing::warn!(mi = %sp.id, error = %err, "backup: MI app-role read failed; recording as partial");
                skipped.push(SkippedObject::new(
                    "managedIdentity",
                    &sp.id,
                    Some(sp.display_name.clone()),
                    format!("held Graph app-roles could not be read: {err}; captured without them"),
                ));
                Vec::new()
            }
        };
        out.push(ManagedIdentityBackup {
            source_principal_id: sp.id.clone(),
            source_app_id: sp.app_id.clone(),
            display_name: sp.display_name.clone(),
            subtype: MiSubtype::from_alternative_names(&sp.alternative_names),
            arm_resource_id: user_assigned_arm_id(&sp.alternative_names),
            held_app_roles,
        });
        tick.advance(Some(sp.display_name.clone()));
    }
    // A resource-SP resolve can latch the session too.
    if session.is_dead() {
        return Err(session.err("the tenant backup"));
    }
    Ok((out, skipped))
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
    // A resolve miss degrades to raw ids, but its failure is still classified:
    // a dead session must stop the backup, not thin every grant to raw ids.
    session: &'a SessionDead,
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
    fn new(client: &'a GraphClient, session: &'a SessionDead) -> Self {
        Self {
            client,
            session,
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
                        Err(err) => {
                            self.session.note_code(err.ui_code());
                        }
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
                self.session.note_code(err.ui_code());
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
///
/// The thumbprint is normalised to uppercase hex on the way out. This field's
/// whole job is to tell an operator which certificate to re-supply from their
/// PKI, and hex is what their PKI and the Entra portal show — Graph's raw
/// base64 `customKeyIdentifier` matches neither.
fn cred_meta_from_key(c: &KeyCredential) -> CredentialMeta {
    CredentialMeta {
        display_name: c.display_name.clone(),
        start_date_time: c.start_date_time,
        end_date_time: c.end_date_time,
        thumbprint: c
            .custom_key_identifier
            .as_deref()
            .and_then(azapptoolkit_core::thumbprint::canonical),
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

/// Advances the backup's shared running count by one processed object and
/// emits the matching `backup-progress` event, carrying the live adaptive cap.
///
/// One per spawned chunk (and one for the MI pass), all sharing the run's
/// [`FanOutMeter`] count through their [`FanOutTicker`]. The
/// passes take this instead of an `&AppHandle` so they run in a test with a
/// `Recorder` sink — see `progress::ProgressSink` for why that is the seam.
struct BackupTicker<'a, S> {
    sink: &'a S,
    ticker: &'a FanOutTicker,
    total: usize,
}

impl<S: ProgressSink> BackupTicker<'_, S> {
    fn advance(&self, current_app: Option<String>) {
        let (count, cap) = self.ticker.tick();
        emit(self.sink, count, self.total, current_app, Some(cap));
    }
}

fn emit(
    sink: &impl ProgressSink,
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
    emit_progress(sink, "backup-progress", progress);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::test_support::{
        Recorder, dead_token, mock_graph, mock_graph_with, sample_app_json, temp_file,
    };
    use azapptoolkit_core::cache::Cache;

    /// The loader reads through the shared bound: one byte over the cap is
    /// refused before parsing, a file at the cap loads, and a UTF-16 file is
    /// named as such.
    #[test]
    fn a_backup_file_over_the_cap_is_refused() {
        let json = serde_json::to_vec(&TenantBackup {
            schema_version: BACKUP_SCHEMA_VERSION,
            created_at: chrono::DateTime::from_timestamp(1_000_000, 0).unwrap(),
            source_tenant_id: "src-tenant".into(),
            cloud: azapptoolkit_core::cloud::CloudEnvironment::Commercial,
            app_registrations: Vec::new(),
            enterprise_apps: Vec::new(),
            managed_identities: Vec::new(),
            skipped: Vec::new(),
        })
        .unwrap();
        let file = temp_file(&json);
        let cap = json.len() as u64;
        assert!(read_backup_file(&file.0, cap).is_ok());
        let err = read_backup_file(&file.0, cap - 1).unwrap_err();
        assert_eq!(err.code, "invalid_backup_file");

        let utf16 = temp_file(&[0xFF, 0xFE, b'{', 0, b'}', 0]);
        let err = read_backup_file(&utf16.0, cap).unwrap_err();
        assert_eq!(err.code, "invalid_backup_file");
        assert!(err.message.contains("UTF-16"), "{}", err.message);
    }

    /// A ticker that records into `rec`; the events carry `fan`'s cap, so a
    /// test can assert it.
    fn ticker<'a>(
        rec: &'a Recorder,
        fan: &'a FanOutTicker,
        total: usize,
    ) -> BackupTicker<'a, Recorder> {
        BackupTicker {
            sink: rec,
            ticker: fan,
            total,
        }
    }

    #[test]
    fn user_assigned_arm_id_extracts_resource_id() {
        let names = [
            "isExplicit=True",
            "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1",
        ];
        assert_eq!(
            user_assigned_arm_id(&names).as_deref(),
            Some(
                "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-1"
            )
        );
        // System-assigned (host resource id, no userAssignedIdentities marker).
        let sys =
            ["/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-1"];
        assert_eq!(user_assigned_arm_id(&sys), None);
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

        // The thumbprint is exported as hex, not Graph's raw base64: an
        // operator matches this against their PKI and the portal, and both
        // show hex. (Microsoft's own documented pair for one certificate.)
        let cert = KeyCredential {
            key_id: "c".into(),
            custom_key_identifier: Some("2iD8ppbE+D6Kmu1ZvjM2jtQh88E=".into()),
            ..Default::default()
        };
        assert_eq!(
            cred_meta_from_key(&cert).thumbprint.as_deref(),
            Some("DA20FCA696C4F83E8A9AED59BE33368ED421F3C1")
        );
    }

    // The DR backup's headline invariant: a whole-`$batch` failure must degrade to
    // per-object reads (never failing the run), and a per-object read that fails
    // must skip only that object. Exercised against a mock Graph server, the same
    // way the graph crate tests its client.
    #[tokio::test]
    async fn backup_app_chunk_degrades_to_per_app_reads_and_skips_failures() {
        use std::collections::HashSet;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Every `$batch` POST 503s — forcing the per-object fallback for both the
        // app-config and the federated-credential reads.
        Mock::given(method("POST"))
            .and(path("/v1.0/$batch"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        // obj-1 resolves via the fallback GETs.
        Mock::given(method("GET"))
            .and(path("/v1.0/applications/obj-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_app_json()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/v1.0/applications/obj-1/federatedIdentityCredentials",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
            )
            .mount(&server)
            .await;

        // obj-2's per-object read fails (500): it must be skipped, not abort the run.
        Mock::given(method("GET"))
            .and(path("/v1.0/applications/obj-2"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/v1.0/applications/obj-2/federatedIdentityCredentials",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
            )
            .mount(&server)
            .await;

        let client = mock_graph(&server);

        let chunk = vec![
            ("app-1".to_string(), "obj-1".to_string()),
            ("app-2".to_string(), "obj-2".to_string()),
        ];
        let sp_app_ids = HashSet::new();

        // A recording sink stands in for the Tauri AppHandle, so the progress
        // this pass emits is asserted too.
        let rec = Recorder::default();
        let fan = FanOutTicker::detached(4);
        let tick = ticker(&rec, &fan, 2);
        let session = SessionDead::new();
        let (out, skipped) = backup_app_chunk(&client, chunk, &sp_app_ids, &tick, &session).await;

        // The run never fails: obj-1 is recovered via the per-object fallback, and
        // obj-2's failed read is skipped rather than aborting the chunk.
        assert_eq!(
            out.len(),
            1,
            "the failed object should be skipped, not fatal"
        );
        // ...and the skip is REPORTED. Dropping obj-2 silently is what makes a
        // short manifest read as a complete one: restore would recreate the
        // tenant without it and nothing would say why.
        assert_eq!(skipped.len(), 1, "the dropped object must be recorded");
        assert_eq!(skipped[0].object_id, "obj-2");
        assert_eq!(skipped[0].kind, "application");
        assert!(
            !skipped[0].reason.is_empty(),
            "the operator needs to know what failed"
        );
        // Progress still advances for every object in the chunk, including the skip.
        assert_eq!(fan.done(), 2);
        // ...one `backup-progress` event per object, each carrying the live cap.
        // The app pass names no current app.
        let events = rec.payloads::<BulkProgress>("backup-progress");
        assert_eq!(events.iter().map(|e| e.done).collect::<Vec<_>>(), [1, 2]);
        assert!(events.iter().all(|e| e.total == 2
            && e.current_app.is_none()
            && e.in_flight_cap == Some(4)
            && !e.cancelled));
        // A transient failure is a per-object skip, never the end of the session.
        assert!(
            !session.is_dead(),
            "a transient 500 must not latch the session"
        );
    }

    fn mi(id: &str, name: &str) -> ServicePrincipal {
        ServicePrincipal {
            id: id.into(),
            app_id: format!("{id}-app"),
            display_name: name.into(),
            service_principal_type: Some("ManagedIdentity".into()),
            ..Default::default()
        }
    }

    // The latch the backup's per-item classification exists for: a re-auth-fatal
    // read must end the run, not thin the manifest by every app it touches.
    #[tokio::test]
    async fn a_reauth_fatal_read_latches_the_backup_session() {
        // Never answered: the token fails before any request is sent.
        let server = wiremock::MockServer::start().await;
        let client = mock_graph_with(&server, dead_token(), Cache::new());
        let rec = Recorder::default();
        let fan = FanOutTicker::detached(4);
        let tick = ticker(&rec, &fan, 1);
        let session = SessionDead::new();
        let (out, _skipped) = backup_app_chunk(
            &client,
            vec![("app-1".to_string(), "obj-1".to_string())],
            &std::collections::HashSet::new(),
            &tick,
            &session,
        )
        .await;
        assert!(out.is_empty());
        assert!(
            session.is_dead(),
            "a dead refresh token must latch the session"
        );
    }

    // Pass 3 used to replace a failed held-app-role read with an empty list and
    // record nothing, so the MI restored as "holds no permissions".
    #[tokio::test]
    async fn backup_managed_identities_records_an_unreadable_mi_as_skipped() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1.0/$batch"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals/mi-1/appRoleAssignments"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals/mi-2/appRoleAssignments"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
            )
            .mount(&server)
            .await;
        let client = mock_graph(&server);

        let managed = vec![mi("mi-1", "mi-one"), mi("mi-2", "mi-two")];
        let cancel = crate::state::CancelFlag::new().claim();
        let rec = Recorder::default();
        let fan = FanOutTicker::detached(4);
        let tick = ticker(&rec, &fan, 2);
        let session = SessionDead::new();
        let (out, skipped) = backup_managed_identities(&client, &managed, &cancel, &tick, &session)
            .await
            .expect("a transient per-MI failure must not fail the backup");

        // Both MIs are captured — the unreadable one still needs its runbook item.
        assert_eq!(out.len(), 2);
        let mi1 = out
            .iter()
            .find(|m| m.source_principal_id == "mi-1")
            .unwrap();
        assert!(mi1.held_app_roles.is_empty());
        // ...and the gap is recorded, so the empty list doesn't read as "holds none".
        assert_eq!(skipped.len(), 1, "only the unreadable MI is recorded");
        assert_eq!(skipped[0].kind, "managedIdentity");
        assert_eq!(skipped[0].object_id, "mi-1");
        assert_eq!(skipped[0].display_name.as_deref(), Some("mi-one"));
        assert!(!skipped[0].reason.is_empty());
        assert!(!session.is_dead(), "a transient 500 must not latch");
        assert_eq!(fan.done(), 2);
        // One event per MI, in input order, naming the MI — the unreadable one
        // included, since it is still captured.
        let events = rec.payloads::<BulkProgress>("backup-progress");
        assert_eq!(
            events
                .iter()
                .map(|e| (e.done, e.current_app.as_deref()))
                .collect::<Vec<_>>(),
            [(1, Some("mi-one")), (2, Some("mi-two"))]
        );
        assert!(events.iter().all(|e| e.in_flight_cap == Some(4)));
    }

    #[tokio::test]
    async fn backup_managed_identities_aborts_on_a_dead_session() {
        let server = wiremock::MockServer::start().await;
        let client = mock_graph_with(&server, dead_token(), Cache::new());
        let managed = vec![mi("mi-1", "mi-one"), mi("mi-2", "mi-two")];
        let cancel = crate::state::CancelFlag::new().claim();
        let rec = Recorder::default();
        let fan = FanOutTicker::detached(4);
        let tick = ticker(&rec, &fan, 2);
        let session = SessionDead::new();
        let err = backup_managed_identities(&client, &managed, &cancel, &tick, &session)
            .await
            .expect_err("a dead session must stop the backup, not save empty MIs");
        assert_eq!(err.code, "refresh_missing");
        assert!(session.is_dead());
    }

    fn api_err() -> GraphError {
        GraphError::Api {
            status: 500,
            body: "boom".into(),
        }
    }

    fn ent_sp() -> ServicePrincipal {
        ServicePrincipal {
            id: "sp-1".into(),
            app_id: "app-1".into(),
            display_name: "Gallery App".into(),
            ..Default::default()
        }
    }

    fn entry_with(
        full: Result<Option<ServicePrincipal>, GraphError>,
        assigned: Result<Vec<AppRoleAssignment>, GraphError>,
        groups: Result<Vec<GroupSummary>, GraphError>,
    ) -> (Option<EnterpriseAppBackup>, Vec<SkippedObject>) {
        let mut skipped = Vec::new();
        let entry = enterprise_entry(
            &ent_sp(),
            &full,
            &assigned,
            &groups,
            "tenant-test",
            &HashMap::new(),
            &mut skipped,
        );
        (entry, skipped)
    }

    // An enterprise app whose assignees could not be read is captured, but the
    // gap is recorded — zero assignees would otherwise restore as "nobody had
    // access".
    #[test]
    fn enterprise_entry_records_an_unreadable_assignee_list() {
        let (entry, skipped) = entry_with(Ok(Some(ent_sp())), Err(api_err()), Ok(Vec::new()));
        let entry = entry.expect("the SP itself was read, so it is captured");
        assert!(entry.app_role_assignees.is_empty());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].kind, "enterpriseAppAssignments");
        assert_eq!(skipped[0].object_id, "sp-1");
        assert_eq!(skipped[0].display_name.as_deref(), Some("Gallery App"));
        assert!(!skipped[0].reason.is_empty());
    }

    #[test]
    fn enterprise_entry_records_an_unreadable_group_list() {
        let (entry, skipped) = entry_with(Ok(Some(ent_sp())), Ok(Vec::new()), Err(api_err()));
        assert!(entry.expect("captured").group_memberships.is_empty());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].kind, "enterpriseAppGroups");
        assert_eq!(skipped[0].object_id, "sp-1");
    }

    #[test]
    fn enterprise_entry_with_every_read_ok_records_nothing() {
        let group = GroupSummary {
            id: "g-1".into(),
            ..Default::default()
        };
        let (entry, skipped) = entry_with(Ok(Some(ent_sp())), Ok(Vec::new()), Ok(vec![group]));
        assert_eq!(entry.expect("captured").group_memberships.len(), 1);
        assert!(skipped.is_empty());
    }

    #[test]
    fn enterprise_entry_leaves_out_an_unreadable_sp() {
        let (entry, skipped) = entry_with(Err(api_err()), Ok(Vec::new()), Ok(Vec::new()));
        assert!(entry.is_none());
        assert_eq!(skipped.len(), 1);
        assert_eq!(skipped[0].kind, "enterpriseApp");
        assert_eq!(skipped[0].object_id, "sp-1");
    }
}
