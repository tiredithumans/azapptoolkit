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
    Application, ApplicationExposeApi, DirectoryObject, KeyCredential, PasswordCredential,
    ServicePrincipal,
};
use azapptoolkit_graph::{GraphClient, GraphError};

use crate::commands::applications::{extract_auth_fields, sp_index_key};
use crate::commands::dispatch::dispatch_capped;
use crate::dto::backup::{
    AppRegistrationBackup, AppRoleAssigneeRef, AppRoleGrantRef, CredentialMeta,
    EnterpriseAppBackup, ManagedIdentityBackup, PrincipalRef, TenantBackup, BACKUP_SCHEMA_VERSION,
};
use crate::dto::bulk::BulkProgress;
use crate::dto::managed_identity::MiSubtype;
use crate::dto::UiError;
use crate::state::AppState;

/// Max concurrent per-app read fan-outs. Bounds Graph load on a large estate;
/// the client retries 429s with backoff, so a big tenant just takes
/// proportionally longer rather than tripping throttling.
const CONCURRENCY: usize = 6;

/// Tenant-wide enumeration cap, matching the lists' `APPS_MAX` / `SP_INDEX_MAX`.
const ESTATE_CAP: usize = 10_000;

/// Captures a full, portable backup of the tenant's app estate. Long-running
/// (a per-app fan-out), so it polls the dedicated [`AppState::dr_cancel`] flag
/// — its own, not `audit_cancel`, so a backup and a concurrent audit/bulk run
/// can't cancel each other. Emits `backup-progress` ([`BulkProgress`]) events.
#[tauri::command]
pub async fn backup_tenant(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<TenantBackup, UiError> {
    state.dr_cancel.reset();
    let client = state.graph_for(&tenant_id);

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
    emit(&app_handle, 0, total, None);

    // ---- App registrations: concurrent full-config fan-out ----
    // The set of appIds that have a service principal — derived from the index
    // we already hold, so the per-app capture needs no SP lookup of its own.
    let sp_app_ids: std::collections::HashSet<String> =
        sp_index.iter().map(|sp| sp.app_id.clone()).collect();
    let done = Arc::new(Mutex::new(0usize));
    let cancel = state.dr_cancel.clone();
    let mut app_backups: Vec<AppRegistrationBackup> = Vec::with_capacity(app_total);
    let cancelled = dispatch_capped(
        app_index, // (app_id, object_id) pairs
        || CONCURRENCY,
        |(app_id, object_id)| {
            if cancel.is_cancelled() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let has_sp = sp_app_ids.contains(&app_id);
            Some(tokio::spawn(async move {
                let result = backup_one_application(&client, &object_id, has_sp).await;
                let count = {
                    let mut d = done.lock().await;
                    *d += 1;
                    *d
                };
                emit(&app_handle, count, total, None);
                match result {
                    Ok(b) => Some(b),
                    Err(err) => {
                        tracing::warn!(%object_id, error = %err, "backup: failed to capture app registration; skipping");
                        None
                    }
                }
            }))
        },
        |joined| {
            if let Ok(Some(b)) = joined {
                app_backups.push(b);
            }
        },
    )
    .await;
    // A partial backup is a dangerous DR artifact (it reads as complete), so a
    // cancelled run is an error, not a truncated success.
    if cancelled || state.dr_cancel.is_cancelled() {
        return Err(UiError::new(
            "cancelled",
            "backup cancelled before completion",
            false,
        ));
    }

    // appId → source object id, so an enterprise-app SP backed by an in-backup
    // app registration can point at it.
    let app_obj_by_app_id: HashMap<String, String> = app_backups
        .iter()
        .map(|a| (a.source_app_id.clone(), a.source_object_id.clone()))
        .collect();

    // ---- Enterprise apps: per-SP fan-out (assignments + group memberships +
    // settings). Foreign/gallery SPs are captured the same way; their restore is
    // a runbook (re-consent / re-instantiate), not an automatic replay. The
    // managed-identity Azure-RBAC detail is captured by the MI re-bind slice.
    let app_obj_by_app_id = Arc::new(app_obj_by_app_id);
    let tenant_arc: Arc<str> = Arc::from(tenant_id.as_str());
    let enterprise_sps: Vec<ServicePrincipal> = sp_index
        .into_iter()
        .filter(|sp| !is_managed_identity(sp))
        .collect();
    let mut enterprise_apps: Vec<EnterpriseAppBackup> = Vec::with_capacity(enterprise_sps.len());
    let ent_cancel = state.dr_cancel.clone();
    let ent_cancelled = dispatch_capped(
        enterprise_sps,
        || CONCURRENCY,
        |sp| {
            if ent_cancel.is_cancelled() {
                return None;
            }
            let client = client.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let map = app_obj_by_app_id.clone();
            let tenant = tenant_arc.clone();
            Some(tokio::spawn(async move {
                let paired = map.get(&sp.app_id).cloned();
                let result = backup_one_enterprise_app(&client, &sp, &tenant, paired).await;
                let count = {
                    let mut d = done.lock().await;
                    *d += 1;
                    *d
                };
                emit(&app_handle, count, total, Some(sp.display_name.clone()));
                result
            }))
        },
        |joined| {
            if let Ok(Some(b)) = joined {
                enterprise_apps.push(b);
            }
        },
    )
    .await;
    if ent_cancelled || state.dr_cancel.is_cancelled() {
        return Err(UiError::new(
            "cancelled",
            "backup cancelled before completion",
            false,
        ));
    }

    // ---- Managed identities: identity + held Graph app-roles (the re-bindable
    // permission). Azure RBAC isn't scanned here — it's runbook-only on restore
    // (source scopes don't exist in the destination) and the MI detail view
    // already surfaces it for DR planning. Sequential, sharing one resource
    // resolver so a repeated resource (e.g. Microsoft Graph) resolves once.
    let mut count = *done.lock().await;
    let mut resolver = ResourceLookup::new(&client);
    let mut managed_identities: Vec<ManagedIdentityBackup> = Vec::with_capacity(managed.len());
    for sp in &managed {
        if state.dr_cancel.is_cancelled() {
            return Err(UiError::new(
                "cancelled",
                "backup cancelled before completion",
                false,
            ));
        }
        let subtype = MiSubtype::from_alternative_names(&sp.alternative_names);
        let held_app_roles = resolver.held_app_roles(&sp.id).await;
        managed_identities.push(ManagedIdentityBackup {
            source_principal_id: sp.id.clone(),
            source_app_id: sp.app_id.clone(),
            display_name: sp.display_name.clone(),
            subtype: mi_subtype_label(subtype).to_string(),
            arm_resource_id: user_assigned_arm_id(&sp.alternative_names),
            held_app_roles,
            ..Default::default()
        });
        count += 1;
        emit(&app_handle, count, total, Some(sp.display_name.clone()));
    }

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

/// Assembles one app registration's full backup from a **single** Graph read
/// (`get_application_backup_json`, `$expand=owners`) plus the federated-credential
/// list — two calls, where the per-tab paths would make eight. The full app +
/// Authentication + Expose-an-API + owners all come from the one JSON document.
///
/// `has_service_principal` is taken from the already-fetched SP index (no per-app
/// SP lookup), and `admin_consent_granted` is derived from the declared
/// permissions rather than probing the SP's live grants: restore re-grants admin
/// consent idempotently whenever permissions are declared, which is the
/// DR-correct default and removes three calls per app.
async fn backup_one_application(
    client: &GraphClient,
    object_id: &str,
    has_service_principal: bool,
) -> Result<AppRegistrationBackup, GraphError> {
    let value = client.get_application_backup_json(object_id).await?;
    // The typed model tolerates Graph's nulls; the Expose-an-API projection and
    // owners come from the same document. `?` maps a deserialize failure to
    // `GraphError::Deserialize`.
    let app: Application = serde_json::from_value(value.clone())?;
    let expose: ApplicationExposeApi = serde_json::from_value(value.clone()).unwrap_or_default();
    let auth = extract_auth_fields(&value);
    let owners: Vec<DirectoryObject> = value
        .get("owners")
        .cloned()
        .and_then(|o| serde_json::from_value(o).ok())
        .unwrap_or_default();

    let federated = client.list_federated_credentials(object_id).await?;

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

/// Captures one enterprise application's full backup: settings (tags,
/// assignment-required), the users/groups assigned to its roles
/// (`appRoleAssignedTo`, role values resolved against the SP's own `appRoles`),
/// and the groups the SP belongs to. Returns `None` if the SP vanished between
/// the index read and this fetch. The group-membership read is gated (advanced
/// query) and degrades to empty on failure.
async fn backup_one_enterprise_app(
    client: &GraphClient,
    index_sp: &ServicePrincipal,
    tenant_id: &str,
    paired_app_registration_object_id: Option<String>,
) -> Option<EnterpriseAppBackup> {
    let sp = match client
        .get_service_principal_by_object_id(&index_sp.id)
        .await
    {
        Ok(Some(sp)) => sp,
        Ok(None) => return None,
        Err(err) => {
            tracing::warn!(sp = %index_sp.id, error = %err, "backup: enterprise SP fetch failed; skipping");
            return None;
        }
    };
    let assigned = client
        .list_app_role_assigned_to(&sp.id)
        .await
        .unwrap_or_default();
    let groups = client
        .list_service_principal_groups(&sp.id)
        .await
        .unwrap_or_default();

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

    Some(EnterpriseAppBackup {
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
    })
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

impl<'a> ResourceLookup<'a> {
    fn new(client: &'a GraphClient) -> Self {
        Self {
            client,
            cache: HashMap::new(),
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
            Ok(Some(sp)) => Some(ResourceInfo {
                app_id: sp.app_id.clone(),
                display_name: sp.display_name.clone(),
                role_value_by_id: sp
                    .app_roles
                    .iter()
                    .map(|r| (r.id.clone(), r.value.clone()))
                    .collect(),
            }),
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(%resource_sp_id, error = %err, "backup: resource SP resolve failed; recording raw ids");
                None
            }
        };
        self.cache.insert(resource_sp_id.to_string(), info.clone());
        info
    }

    /// The application permissions held by `sp_id`, resource-relative. A read
    /// failure degrades to an empty list (best-effort, like the other reads).
    async fn held_app_roles(&mut self, sp_id: &str) -> Vec<AppRoleGrantRef> {
        let assignments = self
            .client
            .list_app_role_assignments(sp_id)
            .await
            .unwrap_or_default();
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
                app_role_id: a.app_role_id,
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

fn emit(app_handle: &AppHandle, done: usize, total: usize, current_app: Option<String>) {
    let progress = BulkProgress {
        done,
        total,
        current_app,
        cancelled: false,
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
}
