//! Key Vault Azure-RBAC reverse lookup.
//!
//! The resource → identities view Graph/ARM don't offer directly: sweep every
//! Key Vault the signed-in user can reach and, for each, list the principals
//! holding an Azure RBAC role that applies to the vault — made on it or
//! inherited from an ancestor scope — "which apps / managed identities can
//! touch this vault?". Complements the per-managed-identity
//! forward view (MI → its Azure roles); this is the reverse.
//!
//! ARM plane (management.azure.com), so it mirrors the SharePoint site sweep's
//! sweep/cancel/progress/cache *machinery* but the managed-identity Azure-roles
//! command's *token/consent/role-name-resolution*.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::stream::{self, StreamExt};
use tauri::{AppHandle, State};
use tokio::sync::Mutex;

use azapptoolkit_arm::{KeyVaultResource, RoleAssignment};
use azapptoolkit_core::azure_roles::{RoleContext, is_high_privilege_role};
use azapptoolkit_core::cache::{Cache, CacheKind};

use crate::commands::arm_roles::{resolve_role_names_cached, role_display_name};
use crate::commands::dispatch::{ARM_CONCURRENCY, SessionDead, dispatch_capped};
use crate::commands::export::{coverage_comment_block, coverage_json, csv_field};
use crate::commands::graph_err::forbidden_remediation;
use crate::commands::progress::emit_progress;
use crate::dto::UiError;
use crate::dto::keyvault::{KeyVaultAccessRow, KeyVaultSweepProgress, KeyVaultSweepResult};
use crate::state::AppState;

/// Safety cap on vaults per sweep — bounds a pathological estate. Raise if a
/// user legitimately hits it.
const MAX_VAULTS_PER_SWEEP: usize = 2_000;

/// Tenant-prefixed cache key (cross-tenant leakage guard, same convention as
/// the site sweep and the list caches).
fn kv_sweep_cache_key(tenant_id: &str) -> String {
    format!("{tenant_id}|keyvault_sweep")
}

/// Drops the cached vault-access sweep for this tenant. The sweep lives under
/// its own `CacheKind::Audit` key, so neither `invalidate_app_lists` nor
/// `invalidate_audit_cache` reaches it (mirrors `sharepoint::invalidate_site_sweep`).
/// The sweep itself is read-only about vault roles, but the app's own
/// `assign_managed_identity_azure_role` changes "who can touch this vault", so
/// every in-app mutation that can change the answer calls this on `Ok` — or the
/// pre-assignment sweep is served as current for the rest of the audit TTL.
pub(crate) fn invalidate_kv_sweep(cache: &Cache, tenant_id: &str) {
    cache.invalidate(CacheKind::Audit, &kv_sweep_cache_key(tenant_id));
}

/// Maps an ARM error to a `UiError`, replacing a 403's message with the
/// capability's role guidance (a forbidden *after* the ARM scope is consented
/// means the signed-in user lacks Reader, not a consent gap — that surfaces
/// earlier as `consent_required` from `ensure_arm_token`). Single copy of the
/// text lives in the capability catalog.
fn keyvault_rbac_err(err: azapptoolkit_arm::ArmError) -> UiError {
    let mut ui = UiError::from(err);
    if let Some(remediation) = forbidden_remediation(&ui, "keyvault_rbac_reads") {
        ui.message = remediation.to_string();
    }
    ui
}

/// Sweeps every reachable Key Vault's Azure-RBAC role assignments to
/// build the reverse-lookup index: vault → principals ("who can touch this
/// vault?") and, filtered by principal, principal → vaults. Enumerates vaults
/// across every accessible subscription, then reads each vault's at-or-above-scope
/// (`atScope()`) role assignments — direct and inherited, flagged per row —
/// with bounded concurrency, resolving role-definition ids to
/// names and service-principal ids to display names.
///
/// Long-running: emits `keyvault-sweep-progress` per vault and polls its own
/// `AppState.key_vault_sweep_cancel` token (stopped only by
/// [`cancel_key_vault_sweep`] and by sign-out, `AppState::forget_tenant`)
/// between dispatches. A per-vault
/// read failure increments `vaults_failed` rather than aborting or silently
/// reading as "no access", so coverage is never overstated. A complete result
/// is cached (60-minute audit TTL) under a tenant-prefixed key; a cancelled or
/// partially-failed run is never cached.
#[tauri::command]
pub async fn sweep_key_vault_access(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Arc<KeyVaultSweepResult>, UiError> {
    // Names resolved below can come from cache; the rule counts only an
    // explicit proof ahead of every read (a client factory only builds token
    // adapters). Sync, so the claim still precedes every await.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    // Claimed before the first await — the token acquisition, subscription list
    // and per-subscription vault enumeration below all precede the dispatch,
    // and a token claimed after them discards any cancel issued during them
    // (`is_cancelled()` compares `cancelled >= generation`). Pinned by
    // `repo_invariants::cancel`.
    let cancel = state.key_vault_sweep_cancel.claim();
    // Watched before the first await too: an Azure role assignment mid-sweep
    // busts this key, and the store below must not undo that with the
    // pre-mutation rows.
    let sweep_watch = state
        .cache
        .generation_for(CacheKind::Audit, &kv_sweep_cache_key(&tenant_id));
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
    emit_progress(
        &app_handle,
        crate::dto::events::KEYVAULT_SWEEP_PROGRESS,
        KeyVaultSweepProgress {
            done: 0,
            total,
            current_vault: None,
            cancelled: false,
        },
    );

    // Phase 2 — role assignments that apply to each vault, made on it or
    // inherited from an ancestor (bounded, cancellable).
    let done = Arc::new(Mutex::new(0usize));
    let mut pairs: Vec<(KeyVaultResource, Vec<RoleAssignment>)> = Vec::new();
    let mut vaults_scanned = 0usize;
    let mut vaults_failed = 0usize;
    let mut vaults_ap_mode = 0usize;
    let session = SessionDead::new();
    let mut cancelled = dispatch_capped(
        scoped_vaults,
        || ARM_CONCURRENCY,
        |(scope, vault)| {
            // A dead session fails every remaining vault identically — stop
            // rather than report a sweep that only looks complete.
            if cancel.is_cancelled() || session.is_dead() {
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
                emit_progress(
                    &app_handle,
                    crate::dto::events::KEYVAULT_SWEEP_PROGRESS,
                    progress,
                );
                (vault, result)
            }))
        },
        |joined| match joined {
            Ok((vault, Ok(assignments))) => {
                vaults_scanned += 1;
                // A legacy access-policy vault answers the RBAC listing empty
                // BY DESIGN — its data grants ride access policies. Count it so
                // the summary says "invisible here" instead of letting a clean
                // run read as all-clear.
                if vault.access_policy_mode() {
                    vaults_ap_mode += 1;
                }
                pairs.push((vault, assignments));
            }
            Ok((vault, Err(err))) => {
                vaults_failed += 1;
                session.note_code(err.ui_code());
                tracing::warn!(vault = ?vault.id, ?err, "kv sweep: role-assignment read failed");
            }
            Err(err) => {
                vaults_failed += 1;
                tracing::warn!(?err, "kv sweep: join error");
            }
        },
    )
    .await;
    if session.is_dead() {
        return Err(session.err("the Key Vault access sweep"));
    }
    cancelled = cancelled || cancel.is_cancelled();

    // Flatten to (vault, assignment) pairs.
    let flat: Vec<(KeyVaultResource, RoleAssignment)> = pairs
        .into_iter()
        .flat_map(|(v, list)| list.into_iter().map(move |a| (v.clone(), a)))
        .collect();

    // Resolve the role-definition ids to names (one fetch per role GUID, cached
    // per tenant), shared with the MI Azure-roles command so both surfaces read
    // the same names.
    let role_names = resolve_role_names_cached(
        &arm,
        &cache,
        &tenant_id,
        flat.iter()
            .filter_map(|(_, a)| a.properties.role_definition_id.as_deref()),
        ARM_CONCURRENCY,
    )
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

    let mut rows: Vec<KeyVaultAccessRow> = flat
        .into_iter()
        .map(|(vault, a)| {
            let props = a.properties;
            let vault_id = vault.id.unwrap_or_default();
            let inherited = is_inherited(props.scope.as_deref(), &vault_id);
            let scope = props.scope.unwrap_or_else(|| vault_id.clone());
            let role_def_id = props.role_definition_id.unwrap_or_default();
            let role_name = role_display_name(&role_names, &role_def_id);
            let high_privilege = is_high_privilege_role(&role_name, RoleContext::KeyVault);
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
                inherited,
            }
        })
        .collect();
    // High-privilege first, then by vault (its direct grants before its
    // inherited ones), then by role — the risky grants lead.
    rows.sort_by(|a, b| {
        b.high_privilege
            .cmp(&a.high_privilege)
            .then_with(|| a.vault_name.cmp(&b.vault_name))
            .then_with(|| a.inherited.cmp(&b.inherited))
            .then_with(|| a.role_name.cmp(&b.role_name))
    });

    tracing::info!(
        total,
        vaults_scanned,
        vaults_failed,
        vaults_ap_mode,
        rows = rows.len(),
        cancelled,
        "key vault rbac sweep complete"
    );

    let result = Arc::new(KeyVaultSweepResult {
        tenant_id: tenant_id.clone(),
        total_vaults: total,
        vaults_scanned,
        vaults_failed,
        vaults_access_policy_mode: vaults_ap_mode,
        rows,
        cancelled,
    });
    // Cache only a COMPLETE sweep — serving a cancelled/partial result for the
    // next hour would overstate coverage. Typed, so `get_cached_key_vault_access`
    // answers with the same `Arc` rather than a JSON decode; read it only with
    // `get_typed`.
    if !cancelled && vaults_failed == 0 {
        state
            .cache
            .put_typed_if_current(sweep_watch, Arc::clone(&result));
    }
    Ok(result)
}

/// Signals an in-progress [`sweep_key_vault_access`] run to stop at the next
/// dispatch boundary.
#[tauri::command]
pub fn cancel_key_vault_sweep(state: State<'_, AppState>) {
    state.key_vault_sweep_cancel.cancel();
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
/// TTL — so the view renders instantly without re-scanning. `async` (off the
/// main thread) and answering with the cached `Arc`; pinned by
/// `repo_invariants::cache::cached_scan_reads_are_async_commands`.
#[tauri::command]
pub async fn get_cached_key_vault_access(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Option<Arc<KeyVaultSweepResult>>, UiError> {
    // A cache-only answer makes the `tenant_id` argument the only thing deciding
    // whose directory data is returned, so prove the session first (AGENTS.md's
    // #1 footgun). Pinned by `a_command_answering_from_cache_alone_checks_the_session`.
    let Some(_) = state.auth.tenant_context(&tenant_id) else {
        return Ok(None);
    };
    Ok(state
        .cache
        .get_typed::<KeyVaultSweepResult>(CacheKind::Audit, &kv_sweep_cache_key(&tenant_id)))
}

/// Exports the (frontend-filtered) vault-access rows to CSV/JSON via the OS save
/// dialog. Returns the path, or `None` if the user cancelled.
///
/// "Who can read this vault?" is an answer an operator is routinely asked to
/// produce in writing, and until this existed the only way out of the app was a
/// screenshot. The rows come from the frontend because the filter that produced
/// them does: the panel's one search box serves both lookup directions, so what
/// is on screen — one vault's principals, or one principal's vaults — is the
/// export the operator means.
///
/// `summary` is that panel's own coverage sentence, and it is not decoration:
/// a vault whose role read failed contributes no rows, so a file that dropped
/// "(2 failed — coverage is partial)" would read as a complete answer to a
/// question the sweep could not fully answer.
#[tauri::command]
pub async fn save_key_vault_access_to_file(
    app_handle: AppHandle,
    rows: Vec<KeyVaultAccessRow>,
    summary: String,
    format: String,
) -> Result<Option<String>, UiError> {
    crate::commands::export::save_export_via_dialog(
        &app_handle,
        "vault-access",
        &format,
        || key_vault_access_to_csv(&rows, &summary),
        || coverage_json(&summary, &rows),
    )
    .await
}

/// True when an assignment returned for `vault_id` by `atScope()` was made at
/// an ancestor scope (resource group, subscription, management group, root)
/// rather than on the vault itself. ARM scopes are case-insensitive; an absent
/// or empty scope falls back to the vault (as the row builder does), so it
/// reads as direct.
fn is_inherited(scope: Option<&str>, vault_id: &str) -> bool {
    match scope.filter(|s| !s.is_empty()) {
        None => false,
        Some(scope) => !scope
            .trim_end_matches('/')
            .eq_ignore_ascii_case(vault_id.trim_end_matches('/')),
    }
}

/// Serializes vault-access rows as CSV under the shared coverage comment block.
/// Principal display names come from the directory, so every field is routed
/// through `csv_field` (formula-injection guard + delimiter quoting).
fn key_vault_access_to_csv(rows: &[KeyVaultAccessRow], summary: &str) -> String {
    let mut out = coverage_comment_block(
        "azapptoolkit — Key Vault access (Azure RBAC role assignments, direct and inherited)",
        summary,
    );
    out.push_str(
        "Vault,VaultResourceId,Scope,Inherited,Role,HighPrivilege,Principal,PrincipalId,PrincipalType\n",
    );
    for r in rows {
        let row = [
            csv_field(r.vault_name.as_deref().unwrap_or("")),
            csv_field(&r.vault_id),
            csv_field(&r.scope),
            r.inherited.to_string(),
            csv_field(&r.role_name),
            r.high_privilege.to_string(),
            csv_field(r.principal_display_name.as_deref().unwrap_or("")),
            csv_field(&r.principal_id),
            csv_field(r.principal_type.as_deref().unwrap_or("")),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access_row(vault: &str, principal: &str) -> KeyVaultAccessRow {
        KeyVaultAccessRow {
            vault_id: format!(
                "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{vault}"
            ),
            vault_name: Some(vault.into()),
            scope: format!(
                "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{vault}"
            ),
            role_name: "Key Vault Secrets User".into(),
            principal_id: "11111111-1111-1111-1111-111111111111".into(),
            principal_type: Some("ServicePrincipal".into()),
            principal_display_name: Some(principal.into()),
            high_privilege: false,
            inherited: false,
        }
    }

    #[test]
    fn is_inherited_compares_scope_to_the_vault_case_insensitively() {
        let vault = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv";
        assert!(!is_inherited(Some(vault), vault));
        assert!(!is_inherited(Some(&vault.to_uppercase()), vault));
        assert!(!is_inherited(Some(&format!("{vault}/")), vault));
        assert!(!is_inherited(None, vault));
        assert!(!is_inherited(Some(""), vault));
        assert!(is_inherited(Some("/subscriptions/s"), vault));
        assert!(is_inherited(
            Some("/subscriptions/s/resourceGroups/rg"),
            vault
        ));
        assert!(is_inherited(
            Some("/providers/Microsoft.Management/managementGroups/mg"),
            vault
        ));
    }

    #[test]
    fn csv_carries_an_inherited_column_after_scope() {
        let mut inherited = access_row("kv", "Contoso API");
        inherited.scope = "/subscriptions/s".into();
        inherited.inherited = true;
        let csv = key_vault_access_to_csv(&[inherited], "complete");
        assert!(csv.contains(",Scope,Inherited,"), "{csv}");
        assert!(csv.contains(",/subscriptions/s,true,"), "{csv}");
    }

    #[test]
    fn csv_leads_with_the_coverage_line_then_a_header_and_one_row_each() {
        let csv = key_vault_access_to_csv(
            &[
                access_row("kv-prod", "Contoso API"),
                access_row("kv-dev", "Fabrikam Web"),
            ],
            "2 role assignments across 2 vaults — scanned 9 of 11 vaults (2 failed — coverage is partial)",
        );
        let lines: Vec<&str> = csv.lines().collect();
        // The partial-coverage caveat must reach the file, ahead of the data.
        assert!(lines[1].contains("coverage is partial"));
        let header = lines.iter().position(|l| l.starts_with("Vault,")).unwrap();
        assert_eq!(lines.len() - header, 3); // header + 2 rows
        assert!(lines[header + 1].starts_with("kv-prod,"));
    }

    #[test]
    fn csv_neutralizes_formula_injection_in_a_principal_name() {
        // CWE-1236: display names are directory data. A leading '=' must be
        // defused so a spreadsheet treats the cell as text, not a formula — and
        // the comma in the payload is the point: it has to compose with quoting.
        let csv = key_vault_access_to_csv(&[access_row("kv", "=cmd|'/c calc',A1")], "complete");
        assert!(csv.contains("\"'=cmd|'/c calc',A1\""));
    }

    #[test]
    fn cache_key_is_tenant_scoped() {
        assert_eq!(kv_sweep_cache_key("t1"), "t1|keyvault_sweep");
        assert_ne!(kv_sweep_cache_key("t1"), kv_sweep_cache_key("t2"));
    }

    /// An Azure role assignment made from the Managed Identities pane changes
    /// which principals the sweep would list, and the sweep key is NOT covered
    /// by `invalidate_app_lists` or `invalidate_audit_cache` (a different
    /// Audit-kind key) — so the assignment busts it directly. The other tenant's
    /// sweep must survive.
    #[test]
    fn invalidate_kv_sweep_drops_only_the_target_tenant() {
        let cache = Cache::new();
        let sweep = KeyVaultSweepResult {
            tenant_id: "t1".into(),
            total_vaults: 1,
            vaults_scanned: 1,
            vaults_failed: 0,
            vaults_access_policy_mode: 0,
            rows: Vec::new(),
            cancelled: false,
        };
        // Typed, as the sweep stores it: an untyped `get` would miss either way
        // and make the survival assertion meaningless.
        let sweep = std::sync::Arc::new(sweep);
        cache.put_typed(
            CacheKind::Audit,
            kv_sweep_cache_key("t1"),
            std::sync::Arc::clone(&sweep),
        );
        cache.put_typed(CacheKind::Audit, kv_sweep_cache_key("t2"), sweep);

        invalidate_kv_sweep(&cache, "t1");

        assert!(
            cache
                .get_typed::<KeyVaultSweepResult>(CacheKind::Audit, &kv_sweep_cache_key("t1"))
                .is_none()
        );
        assert!(
            cache
                .get_typed::<KeyVaultSweepResult>(CacheKind::Audit, &kv_sweep_cache_key("t2"))
                .is_some(),
            "other tenant must survive"
        );
    }

    #[test]
    fn high_privilege_roles_flagged_exactly() {
        let flagged = |name: &str| is_high_privilege_role(name, RoleContext::KeyVault);
        assert!(flagged("Key Vault Administrator"));
        assert!(flagged("Owner"));
        // A read-only data role is NOT high-privilege.
        assert!(!flagged("Key Vault Secrets User"));
        assert!(!flagged("Reader"));
    }
}
