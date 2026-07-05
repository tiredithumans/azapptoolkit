//! Key Vault Azure-RBAC reverse lookup.
//!
//! The resource → identities view Graph/ARM don't offer directly: sweep every
//! Key Vault the signed-in user can reach and, for each, list the principals
//! holding an Azure RBAC role **directly on the vault** — "which apps / managed
//! identities can touch this vault?". Complements the per-managed-identity
//! forward view (MI → its Azure roles); this is the reverse.
//!
//! ARM plane (management.azure.com), so it mirrors the SharePoint site sweep's
//! sweep/cancel/progress/cache *machinery* but the managed-identity Azure-roles
//! command's *token/consent/role-name-resolution*.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use tauri::{AppHandle, Emitter, State};
use tokio::sync::Mutex;

use azapptoolkit_arm::{KeyVaultResource, RoleAssignment};
use azapptoolkit_core::cache::CacheKind;

use crate::commands::dispatch::dispatch_capped;
use crate::dto::UiError;
use crate::dto::keyvault::{KeyVaultAccessRow, KeyVaultSweepProgress, KeyVaultSweepResult};
use crate::state::AppState;

/// Max concurrent ARM calls (vault enumeration, per-vault role reads, role-def
/// resolution). Matches the managed-identity Azure-roles command so a large
/// estate stays inside ARM's rate limits (429s retried in the client).
const ARM_CONCURRENCY: usize = 8;
/// Safety cap on vaults per sweep — bounds a pathological estate. Raise if a
/// user legitimately hits it.
const MAX_VAULTS_PER_SWEEP: usize = 2_000;

/// Built-in Azure roles that grant broad management or data-plane reach over a
/// Key Vault — flagged so the reverse lookup surfaces the risky grants first.
const KV_HIGH_PRIVILEGE_ROLES: &[&str] = &[
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Role Based Access Control Administrator",
    "Key Vault Administrator",
    "Key Vault Data Access Administrator",
    "Key Vault Secrets Officer",
    "Key Vault Certificates Officer",
    "Key Vault Crypto Officer",
];

/// Tenant-prefixed cache key (cross-tenant leakage guard, same convention as
/// the site sweep and the list caches).
fn kv_sweep_cache_key(tenant_id: &str) -> String {
    format!("{tenant_id}|keyvault_sweep")
}

fn emit_kv_progress(app_handle: &AppHandle, progress: KeyVaultSweepProgress) {
    if let Err(err) = app_handle.emit("keyvault-sweep-progress", progress) {
        tracing::warn!(?err, "failed to emit keyvault-sweep-progress event");
    }
}

/// Maps an ARM error to a `UiError`, replacing a 403's message with the
/// capability's role guidance (a forbidden *after* the ARM scope is consented
/// means the signed-in user lacks Reader, not a consent gap — that surfaces
/// earlier as `consent_required` from `ensure_arm_token`). Single copy of the
/// text lives in the capability catalog.
fn keyvault_rbac_err(err: azapptoolkit_arm::ArmError) -> UiError {
    let mut ui = UiError::from(err);
    if ui.code == "forbidden"
        && let Some(cap) = azapptoolkit_core::capabilities::capability("keyvault_rbac_reads")
    {
        ui.message = cap.remediation.to_string();
    }
    ui
}

/// Sweeps every reachable Key Vault's direct Azure-RBAC role assignments to
/// build the reverse-lookup index: vault → principals ("who can touch this
/// vault?") and, filtered by principal, principal → vaults. Enumerates vaults
/// across every accessible subscription, then reads each vault's `atScope()`
/// role assignments with bounded concurrency, resolving role-definition ids to
/// names and service-principal ids to display names.
///
/// Long-running: emits `keyvault-sweep-progress` per vault and polls the shared
/// `AppState.sweep_cancel` (NOT `audit_cancel`) between dispatches. A per-vault
/// read failure increments `vaults_failed` rather than aborting or silently
/// reading as "no access", so coverage is never overstated. A complete result
/// is cached (60-minute audit TTL) under a tenant-prefixed key; a cancelled or
/// partially-failed run is never cached.
#[tauri::command]
pub async fn sweep_key_vault_access(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<KeyVaultSweepResult, UiError> {
    state.sweep_cancel.reset();

    // Acquire the ARM token up front so a missing-consent rejection surfaces as
    // the typed `consent_required` code (the UI offers a consent button)
    // instead of a generic error deep inside the ARM client.
    state
        .ensure_arm_token(&tenant_id)
        .await
        .map_err(UiError::from)?;

    let arm = state.arm_for(&tenant_id);
    let graph = state.graph_for(&tenant_id);
    let cache = state.cache.clone();

    // Phase 1 — enumerate vaults across every subscription the user can reach.
    // A failed subscription is logged and skipped (its vaults are simply
    // absent), not fatal; the initial subscription list IS fatal.
    let subs = arm.list_subscriptions().await.map_err(keyvault_rbac_err)?;
    let mut vaults: Vec<KeyVaultResource> = stream::iter(subs)
        .map(|sub| {
            let arm = arm.clone();
            async move {
                match arm.list_key_vaults(&sub.subscription_id).await {
                    Ok(v) => v,
                    Err(err) => {
                        tracing::warn!(?err, subscription = %sub.subscription_id, "kv sweep: vault enumeration failed; skipping subscription");
                        Vec::new()
                    }
                }
            }
        })
        .buffer_unordered(ARM_CONCURRENCY)
        .collect::<Vec<Vec<KeyVaultResource>>>()
        .await
        .into_iter()
        .flatten()
        .collect();
    vaults.truncate(MAX_VAULTS_PER_SWEEP);
    // A vault without an ARM id can't be scoped for a role-assignment query.
    let scoped_vaults: Vec<(String, KeyVaultResource)> = vaults
        .into_iter()
        .filter_map(|v| v.id.clone().map(|scope| (scope, v)))
        .collect();
    let total = scoped_vaults.len();
    emit_kv_progress(
        &app_handle,
        KeyVaultSweepProgress {
            done: 0,
            total,
            current_vault: None,
            cancelled: false,
        },
    );

    // Phase 2 — role assignments directly on each vault (bounded, cancellable).
    let done = Arc::new(Mutex::new(0usize));
    let cancel = state.sweep_cancel.clone();
    let mut pairs: Vec<(KeyVaultResource, Vec<RoleAssignment>)> = Vec::new();
    let mut vaults_scanned = 0usize;
    let mut vaults_failed = 0usize;
    let mut cancelled = dispatch_capped(
        scoped_vaults,
        || ARM_CONCURRENCY,
        |(scope, vault)| {
            if cancel.is_cancelled() {
                return None;
            }
            let arm = arm.clone();
            let app_handle = app_handle.clone();
            let done = done.clone();
            let cancel_for_task = cancel.clone();
            Some(tokio::spawn(async move {
                let result = arm.list_role_assignments_at_scope(&scope).await;
                let mut guard = done.lock().await;
                *guard += 1;
                let progress = KeyVaultSweepProgress {
                    done: *guard,
                    total,
                    current_vault: vault.name.clone().or_else(|| vault.id.clone()),
                    cancelled: cancel_for_task.is_cancelled(),
                };
                drop(guard);
                emit_kv_progress(&app_handle, progress);
                (vault, result)
            }))
        },
        |joined| match joined {
            Ok((vault, Ok(assignments))) => {
                vaults_scanned += 1;
                pairs.push((vault, assignments));
            }
            Ok((vault, Err(err))) => {
                vaults_failed += 1;
                tracing::warn!(vault = ?vault.id, ?err, "kv sweep: role-assignment read failed");
            }
            Err(err) => {
                vaults_failed += 1;
                tracing::warn!(?err, "kv sweep: join error");
            }
        },
    )
    .await;
    cancelled = cancelled || cancel.is_cancelled();

    // Flatten to (vault, assignment) pairs.
    let flat: Vec<(KeyVaultResource, RoleAssignment)> = pairs
        .into_iter()
        .flat_map(|(v, list)| list.into_iter().map(move |a| (v.clone(), a)))
        .collect();

    // Resolve the unique role-definition ids to names (cached, tenant-stable —
    // Owner/Contributor/Key Vault Administrator/…), mirroring the MI Azure-roles
    // command so both surfaces read the same names.
    let unique_roledefs: HashSet<String> = flat
        .iter()
        .filter_map(|(_, a)| a.properties.role_definition_id.clone())
        .filter(|id| !id.is_empty())
        .collect();
    let role_names: HashMap<String, String> = stream::iter(unique_roledefs)
        .map(|id| {
            let arm = arm.clone();
            let cache = cache.clone();
            let tenant_id = tenant_id.clone();
            async move {
                let key = format!("{tenant_id}|arm_roledef|{id}");
                if let Some(name) = cache.get::<String>(CacheKind::Permissions, &key) {
                    return (id, name);
                }
                match arm
                    .get_role_definition(&id)
                    .await
                    .ok()
                    .and_then(|d| d.properties.role_name)
                {
                    Some(name) => {
                        cache.put(CacheKind::Permissions, key, &name);
                        (id, name)
                    }
                    None => {
                        let fallback = id.rsplit('/').next().unwrap_or("role").to_string();
                        (id, fallback)
                    }
                }
            }
        })
        .buffer_unordered(ARM_CONCURRENCY)
        .collect()
        .await;

    // Resolve principal display names via the Graph SP batch. Apps and managed
    // identities are both service principals, so they resolve; users/groups
    // 404 → `Ok(None)` and fall back to their `principal_type` + id in the UI.
    let unique_principals: Vec<String> = flat
        .iter()
        .filter_map(|(_, a)| a.properties.principal_id.clone())
        .filter(|id| !id.is_empty())
        .collect::<HashSet<String>>()
        .into_iter()
        .collect();
    let principal_names = resolve_principal_names(&graph, &unique_principals).await;

    let mut rows: Vec<KeyVaultAccessRow> =
        flat.into_iter()
            .map(|(vault, a)| {
                let props = a.properties;
                let vault_id = vault.id.unwrap_or_default();
                let scope = props.scope.unwrap_or_else(|| vault_id.clone());
                let role_def_id = props.role_definition_id.unwrap_or_default();
                let role_name = if role_def_id.is_empty() {
                    "(unknown role)".to_string()
                } else {
                    role_names.get(&role_def_id).cloned().unwrap_or_else(|| {
                        role_def_id.rsplit('/').next().unwrap_or("role").to_string()
                    })
                };
                let high_privilege = KV_HIGH_PRIVILEGE_ROLES.contains(&role_name.as_str());
                let principal_id = props.principal_id.unwrap_or_default();
                let principal_display_name = principal_names.get(&principal_id).cloned();
                KeyVaultAccessRow {
                    vault_id,
                    vault_name: vault.name,
                    scope,
                    role_name,
                    principal_id,
                    principal_type: props.principal_type,
                    principal_display_name,
                    high_privilege,
                }
            })
            .collect();
    // High-privilege first, then by vault, then by role — the risky grants lead.
    rows.sort_by(|a, b| {
        b.high_privilege
            .cmp(&a.high_privilege)
            .then_with(|| a.vault_name.cmp(&b.vault_name))
            .then_with(|| a.role_name.cmp(&b.role_name))
    });

    tracing::info!(
        total,
        vaults_scanned,
        vaults_failed,
        rows = rows.len(),
        cancelled,
        "key vault rbac sweep complete"
    );

    let result = KeyVaultSweepResult {
        tenant_id: tenant_id.clone(),
        total_vaults: total,
        vaults_scanned,
        vaults_failed,
        rows,
        cancelled,
    };
    // Cache only a COMPLETE sweep — serving a cancelled/partial result for the
    // next hour would overstate coverage.
    if !cancelled && vaults_failed == 0 {
        cache.put(CacheKind::Audit, kv_sweep_cache_key(&tenant_id), &result);
    }
    Ok(result)
}

/// Batch-resolves service-principal object ids to display names. A non-SP id
/// (user/group/deleted) resolves to `Ok(None)` and is simply absent from the
/// map; a whole-batch failure degrades to an empty map (ids show as raw GUIDs)
/// rather than failing the sweep.
async fn resolve_principal_names(
    graph: &azapptoolkit_graph::GraphClient,
    ids: &[String],
) -> HashMap<String, String> {
    if ids.is_empty() {
        return HashMap::new();
    }
    match graph.batch_get_service_principals(ids).await {
        Ok(results) => ids
            .iter()
            .zip(results)
            .filter_map(|(id, r)| match r {
                Ok(Some(sp)) if !sp.display_name.is_empty() => Some((id.clone(), sp.display_name)),
                _ => None,
            })
            .collect(),
        Err(err) => {
            tracing::warn!(
                ?err,
                "kv sweep: principal name resolution failed; showing ids"
            );
            HashMap::new()
        }
    }
}

/// Returns the cached sweep for this tenant, if one completed within the cache
/// TTL — so the view renders instantly without re-scanning.
#[tauri::command]
pub fn get_cached_key_vault_access(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Option<KeyVaultSweepResult> {
    state
        .cache
        .get(CacheKind::Audit, &kv_sweep_cache_key(&tenant_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_tenant_scoped() {
        assert_eq!(kv_sweep_cache_key("t1"), "t1|keyvault_sweep");
        assert_ne!(kv_sweep_cache_key("t1"), kv_sweep_cache_key("t2"));
    }

    #[test]
    fn high_privilege_roles_flagged_exactly() {
        assert!(KV_HIGH_PRIVILEGE_ROLES.contains(&"Key Vault Administrator"));
        assert!(KV_HIGH_PRIVILEGE_ROLES.contains(&"Owner"));
        // A read-only data role is NOT high-privilege.
        assert!(!KV_HIGH_PRIVILEGE_ROLES.contains(&"Key Vault Secrets User"));
        assert!(!KV_HIGH_PRIVILEGE_ROLES.contains(&"Reader"));
    }
}
