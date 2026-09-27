use tauri::State;

use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_core::models::{RequiredResourceAccess, ResourceAccess, ServicePrincipal};

use crate::commands::applications::app_role_resources_key;
use crate::dto::UiError;
use crate::dto::permissions::{
    CatalogResourceSummary, DowngradeOutcome, GrantFailure, GrantResult, PermissionKind,
    ResourcePermissions, RevokeScopeOutcome, RoleEntry, ScopeEntry, ScopeGrantSummary, SkippedRole,
};
use crate::state::AppState;

// ---------------- Catalog browse ----------------

#[tauri::command]
pub fn list_catalog_resources() -> Vec<CatalogResourceSummary> {
    azapptoolkit_permissions::bundled_resources_slice()
        .iter()
        .map(|r| CatalogResourceSummary {
            app_id: r.app_id.clone(),
            display_name: r.display_name.clone(),
            role_count: r.app_roles.len(),
            scope_count: r.oauth2_permission_scopes.len(),
        })
        .collect()
}

/// Tenant-owned resources (the org's own app registrations / service
/// principals) that expose at least one enabled Application app role, for the
/// Grant-access picker's "Tenant app registrations" group. Returns only the
/// directory (name + appId + a role count for the dropdown label); the picker
/// resolves the actual roles live via [`list_resource_permissions`] when one is
/// selected, and the grant path (`grant_managed_identity_permission` /
/// `grant_single_permission`) already accepts an arbitrary `resource_app_id`, so
/// this adds no grant surface. Cached under [`CacheKind::Lists`] (tenant-scoped
/// key, [`app_role_resources_key`]). Busted by `invalidate_app_lists` (an app/SP
/// create or delete changes the set) and by the App roles tab's writers through
/// `invalidate_app_role_resources` (the first enabled Application role added, or
/// the last one disabled/removed, moves an SP in or out of this directory and
/// shifts its count); the Lists TTL and the sign-out tenant sweep cover the rest.
#[tauri::command]
pub async fn list_app_role_resources(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<CatalogResourceSummary>, UiError> {
    // The cache-HIT path below returns before any client is built, so the
    // `graph_for` on the miss path is not a session proof for it.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    let key = app_role_resources_key(&tenant_id);
    if let Some(cached) = state
        .cache
        .get::<Vec<CatalogResourceSummary>>(CacheKind::Lists, &key)
    {
        tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = %key, "hit");
        return Ok(cached);
    }
    tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = %key, "miss");

    let client = state.graph_for(&tenant_id);
    let mut rows: Vec<CatalogResourceSummary> = client
        .list_tenant_app_role_resources()
        .await?
        .into_iter()
        .filter_map(app_role_resource_summary)
        .collect();
    rows.sort_by(|a, b| a.display_name.cmp(&b.display_name));
    state.cache.put(CacheKind::Lists, key, &rows);
    Ok(rows)
}

/// An SP → summary **iff** it exposes ≥1 grantable Application app role: enabled
/// (`isEnabled != false`), a non-empty `value` (what the picker and grant match
/// on), and `allowedMemberTypes` containing "Application" (case-insensitive) —
/// user-only roles can't be assigned to a service principal / managed identity.
/// `role_count` is that count; `scope_count` is 0 (the tenant-app group lists app
/// roles only). Pure so it's unit-testable without a Graph client (mirrors
/// [`service_principal_to_permissions`]).
fn app_role_resource_summary(sp: ServicePrincipal) -> Option<CatalogResourceSummary> {
    let role_count = sp
        .app_roles
        .iter()
        .filter(|r| {
            r.is_enabled != Some(false)
                && !r.value.is_empty()
                && r.allowed_member_types
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case("Application"))
        })
        .count();
    (role_count > 0).then_some(CatalogResourceSummary {
        app_id: sp.app_id,
        display_name: sp.display_name,
        role_count,
        scope_count: 0,
    })
}

/// Returns the roles + scopes for `resource_app_id`, resolved **live** from
/// Microsoft Graph (`source: "graph"`). The bundled catalog supplies only the
/// resource *directory* for the picker dropdown; permission definitions are
/// never bundled, so the picker always reflects the complete, current
/// Application + Delegated set. A missing SP is `resource_not_found`; an
/// offline/throttled/consent failure surfaces as an error (there is no stale
/// fallback by design).
#[tauri::command]
pub async fn list_resource_permissions(
    state: State<'_, AppState>,
    tenant_id: String,
    resource_app_id: String,
) -> Result<ResourcePermissions, UiError> {
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
    Ok(service_principal_to_permissions(sp))
}

/// Maps a live resource service principal to the picker DTO. Drops disabled
/// (retired) roles/scopes — `isEnabled == false` — and sorts each list by
/// `value` so the long live list is scannable.
fn service_principal_to_permissions(sp: ServicePrincipal) -> ResourcePermissions {
    let mut app_roles: Vec<RoleEntry> = sp
        .app_roles
        .into_iter()
        .filter(|r| r.is_enabled != Some(false))
        .map(|r| RoleEntry {
            id: r.id,
            value: r.value,
            display_name: r.display_name,
            description: r.description,
            allowed_member_types: r.allowed_member_types,
        })
        .collect();
    app_roles.sort_by(|a, b| a.value.cmp(&b.value));

    let mut oauth2_permission_scopes: Vec<ScopeEntry> = sp
        .oauth2_permission_scopes
        .into_iter()
        .filter(|s| s.is_enabled != Some(false))
        .map(|s| ScopeEntry {
            id: s.id,
            value: s.value,
            admin_consent_display_name: s.admin_consent_display_name,
            admin_consent_description: s.admin_consent_description,
        })
        .collect();
    oauth2_permission_scopes.sort_by(|a, b| a.value.cmp(&b.value));

    ResourcePermissions {
        app_id: sp.app_id,
        display_name: sp.display_name,
        app_roles,
        oauth2_permission_scopes,
        source: "graph".into(),
    }
}

/// Live permission counts per well-known resource, for the picker dropdown
/// labels. Resolves each directory resource's service principal in parallel
/// (cached under `CacheKind::Permissions`), counting only enabled roles/scopes
/// so the numbers match what the picker actually lists. A resource that can't
/// be resolved (offline/unknown) reports 0/0 rather than failing the whole
/// call — the dropdown still lists every resource by name.
#[tauri::command]
pub async fn list_resource_permission_counts(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<CatalogResourceSummary>, UiError> {
    let client = state.graph_for(&tenant_id);
    let summaries = futures::future::join_all(
        azapptoolkit_permissions::bundled_resources_slice()
            .iter()
            .map(|r| {
                let client = client.clone();
                let app_id = r.app_id.clone();
                let display_name = r.display_name.clone();
                async move {
                    let (role_count, scope_count) = match client.resolve_resource_sp(&app_id).await
                    {
                        Ok(Some(sp)) => (
                            sp.app_roles
                                .iter()
                                .filter(|x| x.is_enabled != Some(false))
                                .count(),
                            sp.oauth2_permission_scopes
                                .iter()
                                .filter(|x| x.is_enabled != Some(false))
                                .count(),
                        ),
                        _ => (0, 0),
                    };
                    CatalogResourceSummary {
                        app_id,
                        display_name,
                        role_count,
                        scope_count,
                    }
                }
            }),
    )
    .await;
    Ok(summaries)
}

// ---------------- Declared permissions persist ----------------

/// Removes one declared permission from an application's `requiredResourceAccess`.
/// Re-resolves the live manifest before acting (the UI snapshot is advisory):
/// drops the `ResourceAccess` whose `id` matches `permission_id` (and `type`
/// matches `kind`, when known), then prunes any resource entry left with no
/// permissions. Runtime grants are left untouched — the UI offers this only for
/// *not-granted* (declared-only) rows; a granted permission is revoked first.
/// Idempotent: removing an already-absent permission is a no-op success.
#[tauri::command]
pub async fn remove_declared_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    resource_app_id: String,
    permission_id: String,
    kind: PermissionKind,
) -> Result<(), UiError> {
    // `None` for Unknown — a raw-GUID row whose declared type we couldn't
    // classify, so match on the permission id alone.
    let entry_type = entry_type_for(kind).ok();

    let client = state.graph_for(&tenant_id);
    let app = client.get_application(&object_id).await?;

    let mut next = app.required_resource_access.clone();
    // Nothing matched — already gone. Succeed without a write so a double-click
    // (or a stale snapshot) doesn't clobber the manifest.
    if !remove_declared_access(&mut next, &resource_app_id, &permission_id, entry_type) {
        return Ok(());
    }

    let patch = azapptoolkit_graph::client::AppPatch {
        required_resource_access: Some(next),
        ..Default::default()
    };
    client.update_application(&object_id, &patch).await?;
    super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

/// Removes the `(permission_id, entry_type)` access from `required` in place,
/// then prunes any resource entry the removal emptied. Returns whether anything
/// was removed. `entry_type` is `None` for an unclassified (Unknown-kind) row —
/// the match is on `permission_id` alone then. Pure so it can be unit-tested
/// without a Graph client. Shared with the remove-redundant-permissions
/// remediation, which drops several declarations in one manifest patch.
pub(crate) fn remove_declared_access(
    required: &mut Vec<RequiredResourceAccess>,
    resource_app_id: &str,
    permission_id: &str,
    entry_type: Option<&str>,
) -> bool {
    let mut removed = false;
    for resource in required.iter_mut() {
        if resource.resource_app_id != resource_app_id {
            continue;
        }
        let before = resource.resource_access.len();
        resource
            .resource_access
            .retain(|a| !(a.id == permission_id && entry_type.is_none_or(|t| a.r#type == t)));
        removed |= resource.resource_access.len() != before;
    }
    if removed {
        required.retain(|r| !r.resource_access.is_empty());
    }
    removed
}

/// Adds the `(resource_app_id, permission_id, entry_type)` access to `required`
/// in place unless it's already declared, creating the resource entry when the
/// app declares nothing for that resource yet. Returns whether the manifest
/// changed (`false` = already declared, so the caller skips the PATCH). Pure so
/// the declaration semantics are unit-testable without a Graph client; shared by
/// `grant_single_permission` (declare-then-grant) and `declare_app_permission`
/// (declare-only).
pub(crate) fn declare_resource_access(
    required: &mut Vec<RequiredResourceAccess>,
    resource_app_id: &str,
    permission_id: &str,
    entry_type: &str,
) -> bool {
    let already = required
        .iter()
        .find(|r| r.resource_app_id == resource_app_id)
        .is_some_and(|r| {
            r.resource_access
                .iter()
                .any(|a| a.id == permission_id && a.r#type == entry_type)
        });
    if already {
        return false;
    }
    let access = ResourceAccess {
        id: permission_id.to_string(),
        r#type: entry_type.to_string(),
    };
    if let Some(existing) = required
        .iter_mut()
        .find(|r| r.resource_app_id == resource_app_id)
    {
        existing.resource_access.push(access);
    } else {
        required.push(RequiredResourceAccess {
            resource_app_id: resource_app_id.to_string(),
            resource_access: vec![access],
        });
    }
    true
}

// ---------------- Admin consent ----------------

/// Ensures admin consent is granted for every permission declared in the
/// application's `requiredResourceAccess`. Mirrors `Grant-AzAppAdminConsent`.
///
/// Order of operations:
///   1. Read the target application.
///   2. Ensure the client service principal exists (create if missing).
///   3. Snapshot the client SP's existing `appRoleAssignments` **and**
///      `oauth2PermissionGrants` — once, concurrently. Both drive idempotency
///      inside the per-resource loop, so neither may be read from within it.
///   4. For each resource group:
///      a. Resolve the resource SP (live Graph; cached under `Permissions` kind).
///      b. For each `Role` permission: skip if already assigned, else POST
///         `appRoleAssignments`.
///      c. For each `Scope` permission: resolve the scope value from the
///         resource SP's `oauth2PermissionScopes`, then
///         `upsert_admin_oauth2_grant_in` (the pre-read-grants variant) with the
///         aggregate scope list for that resource.
///
/// Partial failures are collected in `failures` rather than aborting the run.
#[tauri::command]
pub async fn grant_admin_consent(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<GrantResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let run = grant_admin_consent_core(&client, &object_id).await?;
    // Bust for what landed first — a created SP survives a later failure —
    // then surface that failure.
    invalidate_after_grant(&state.cache, &tenant_id, &run);
    match run.error {
        Some(e) => Err(e),
        None => Ok(run.result),
    }
}

/// Builds a grant-failure message from a Graph error, appending the admin-consent
/// role guidance when the failure is a 403. A forbidden on a *grant* operation
/// means the signed-in user lacks the directory role to consent (the
/// `admin_consent` capability — Privileged Role Administrator / Global
/// Administrator for high-privilege permissions), not that the permission itself
/// is wrong, so the hint points there.
fn grant_failure_message(err: &azapptoolkit_graph::GraphError) -> String {
    let base = err.to_string();
    if matches!(err, azapptoolkit_graph::GraphError::Forbidden(_))
        && let Some(cap) = azapptoolkit_core::capabilities::capability("admin_consent")
    {
        return format!("{base}\n\n{}", cap.remediation);
    }
    base
}

/// What a grant core did: its [`GrantResult`] plus the writes that landed, so
/// the caller can bust the right tier **even when a later step failed**.
///
/// The `downgrade_application_permission_core` shape: a failure before the
/// first write is a plain `Err` (nothing landed, nothing to invalidate); a
/// failure after one comes back here as `error: Some(..)` beside the landed
/// flags, with `result` empty — the run stops at the failed step, as the
/// earlier `?` did. Backend-only, never an IPC type.
#[derive(Debug)]
pub(crate) struct GrantRun {
    pub(crate) result: GrantResult,
    /// The app's `requiredResourceAccess` was PATCHed (single grant only).
    pub(crate) manifest_changed: bool,
    /// Ensuring the client SP created a brand-new one — a new Enterprise App
    /// row / search-index entry.
    pub(crate) sp_created: bool,
    /// The step that failed after a write had landed; `None` for a full run.
    pub(crate) error: Option<UiError>,
}

/// An empty [`GrantResult`] for a run that stopped after a landed write.
fn empty_grant(client_service_principal_id: String) -> GrantResult {
    GrantResult {
        client_service_principal_id,
        role_assignments_created: Vec::new(),
        role_assignments_skipped: Vec::new(),
        scope_grants_upserted: Vec::new(),
        failures: Vec::new(),
    }
}

/// The cache bust a grant run's landed writes need: a brand-new SP is a new
/// Enterprise App row / search-index entry, so the full list tier; any other
/// completed run, or a stopped one whose manifest PATCH landed, the cheaper
/// detail + audit tier. A stopped run that landed nothing busts nothing.
fn invalidate_after_grant(
    cache: &azapptoolkit_core::cache::Cache,
    tenant_id: &str,
    run: &GrantRun,
) {
    if run.sp_created {
        super::applications::invalidate_app_lists(cache, tenant_id);
    } else if run.error.is_none() || run.manifest_changed {
        super::applications::invalidate_app_detail_state(cache, tenant_id);
    }
}

/// Shared admin-consent orchestration, reused by the single-app command and
/// the bulk path so both keep identical semantics.
///
/// Returns a [`GrantRun`]: the [`GrantResult`] **and** whether ensuring the
/// client SP created a brand-new one — callers bust the list caches (not just
/// detail) on that path, since a new SP is a new Enterprise App row /
/// search-index entry. That flag survives a later failure: once the SP was
/// created, a failing snapshot read stops the run as `error: Some(..)` rather
/// than an `Err` that would lose it.
pub(crate) async fn grant_admin_consent_core(
    client: &azapptoolkit_graph::GraphClient,
    object_id: &str,
) -> Result<GrantRun, UiError> {
    let app = client.get_application(object_id).await?;
    let (client_sp, sp_created) = client.ensure_service_principal(&app.app_id).await?;
    match consent_with_sp(client, &app, &client_sp).await {
        Ok(result) => Ok(GrantRun {
            result,
            manifest_changed: false,
            sp_created,
            error: None,
        }),
        // The SP POST landed before the failure: report it so the caller
        // still busts for the new Enterprise App row.
        Err(e) if sp_created => Ok(GrantRun {
            result: empty_grant(client_sp.id),
            manifest_changed: false,
            sp_created,
            error: Some(e),
        }),
        Err(e) => Err(e),
    }
}

/// [`grant_admin_consent_core`] past the client SP: the idempotency snapshots
/// and the per-resource grant loop.
async fn consent_with_sp(
    client: &azapptoolkit_graph::GraphClient,
    app: &azapptoolkit_core::models::Application,
    client_sp: &ServicePrincipal,
) -> Result<GrantResult, UiError> {
    // Both idempotency snapshots are read ONCE, before the per-resource loop:
    // the assignments for the Role branch and the delegated grants for the Scope
    // branch. Each is a paged tenant read filtered to this client SP, and the
    // loop below runs per declared resource — so leaving either inside it
    // (`upsert_admin_oauth2_grant` reads the grants itself) is an N+1 in the
    // number of resources the app declares.
    //
    // Must not swallow these: with the granted set unknown we can't tell which
    // roles/scopes are already in place, and proceeding would re-grant
    // everything (duplicate/conflicting assignments). The run stops here; a
    // client SP created just before still reaches the caller (see above).
    let (existing_assignments, existing_grants) = futures::future::try_join(
        client.list_app_role_assignments(&client_sp.id),
        client.list_oauth2_grants(&client_sp.id),
    )
    .await?;

    // Batch-prewarm the resource SPs (one $batch POST per 20) so the loop
    // below hits the Permissions cache instead of one sequential GET per
    // declared resource. Best-effort: a batch failure degrades to the
    // per-resource lookups, and the loop's failure handling is unchanged.
    let resource_app_ids: Vec<String> = app
        .required_resource_access
        .iter()
        .map(|r| r.resource_app_id.clone())
        .collect();
    client.prewarm_resource_sps(&resource_app_ids).await;

    let mut role_assignments_created = Vec::new();
    let mut role_assignments_skipped = Vec::new();
    let mut scope_grants_upserted = Vec::new();
    let mut failures = Vec::new();

    for resource in &app.required_resource_access {
        let resource_sp = match client.resolve_resource_sp(&resource.resource_app_id).await {
            Ok(Some(sp)) => sp,
            Ok(None) => {
                failures.push(GrantFailure {
                    resource_app_id: resource.resource_app_id.clone(),
                    permission_id: None,
                    kind: "Resource".into(),
                    message: "resource service principal not found".into(),
                });
                continue;
            }
            Err(err) => {
                failures.push(GrantFailure {
                    resource_app_id: resource.resource_app_id.clone(),
                    permission_id: None,
                    kind: "Resource".into(),
                    message: err.to_string(),
                });
                continue;
            }
        };

        // App permissions (Role): idempotent per (principal, resource, appRole).
        let roles = resource
            .resource_access
            .iter()
            .filter(|a| a.r#type == "Role");
        for role in roles {
            let already = existing_assignments
                .iter()
                .any(|a| a.resource_id == resource_sp.id && a.app_role_id == role.id);
            if already {
                role_assignments_skipped.push(SkippedRole {
                    resource_app_id: resource.resource_app_id.clone(),
                    app_role_id: role.id.clone(),
                    reason: "already assigned".into(),
                });
                continue;
            }
            match client
                .grant_app_role(&client_sp.id, &resource_sp.id, &role.id)
                .await
            {
                Ok(ara) => role_assignments_created.push(ara),
                Err(err) => failures.push(GrantFailure {
                    resource_app_id: resource.resource_app_id.clone(),
                    permission_id: Some(role.id.clone()),
                    kind: "Role".into(),
                    message: grant_failure_message(&err),
                }),
            }
        }

        // Delegated permissions (Scope): upsert a single admin-consent grant
        // per resource with the aggregate scope list.
        let scope_ids: Vec<&str> = resource
            .resource_access
            .iter()
            .filter(|a| a.r#type == "Scope")
            .map(|a| a.id.as_str())
            .collect();
        if scope_ids.is_empty() {
            continue;
        }
        let scope_values: Vec<&str> = scope_ids
            .iter()
            .filter_map(|id| {
                resource_sp
                    .oauth2_permission_scopes
                    .iter()
                    .find(|s| s.id == *id)
                    .map(|s| s.value.as_str())
            })
            .collect();

        // Report any scope ids we couldn't resolve.
        for id in &scope_ids {
            if !resource_sp
                .oauth2_permission_scopes
                .iter()
                .any(|s| s.id == *id)
            {
                failures.push(GrantFailure {
                    resource_app_id: resource.resource_app_id.clone(),
                    permission_id: Some((*id).to_string()),
                    kind: "Scope".into(),
                    message: "scope id not exposed by resource SP".into(),
                });
            }
        }

        if scope_values.is_empty() {
            continue;
        }

        match client
            .upsert_admin_oauth2_grant_in(
                &client_sp.id,
                &resource_sp.id,
                &scope_values,
                &existing_grants,
            )
            .await
        {
            Ok(grant) => {
                let scopes_added = scope_values.iter().map(|s| (*s).to_string()).collect();
                scope_grants_upserted.push(ScopeGrantSummary {
                    resource_app_id: resource.resource_app_id.clone(),
                    grant,
                    scopes_added,
                });
            }
            Err(err) => failures.push(GrantFailure {
                resource_app_id: resource.resource_app_id.clone(),
                permission_id: None,
                kind: "Scope".into(),
                message: grant_failure_message(&err),
            }),
        }
    }

    Ok(GrantResult {
        client_service_principal_id: client_sp.id.clone(),
        role_assignments_created,
        role_assignments_skipped,
        scope_grants_upserted,
        failures,
    })
}

// ---------------- Single-permission grant ----------------

/// Grants a single permission to `object_id`. Adds the entry to the app's
/// `requiredResourceAccess` manifest if missing, then creates the matching
/// runtime grant (`appRoleAssignment` for Application, upserted
/// `oauth2PermissionGrant` for Delegated). Idempotent for both halves —
/// safe to retry.
#[tauri::command]
pub async fn grant_single_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    resource_app_id: String,
    permission_id: String,
    kind: PermissionKind,
) -> Result<GrantResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let run =
        grant_single_permission_core(&client, &object_id, &resource_app_id, &permission_id, kind)
            .await?;
    // A first grant that materializes the app's SP adds an Enterprise App row /
    // search-index entry, so the full list tier; otherwise detail+audit — and
    // both even when a later step failed, since the PATCH/SP had landed.
    invalidate_after_grant(&state.cache, &tenant_id, &run);
    match run.error {
        Some(e) => Err(e),
        None => Ok(run.result),
    }
}

/// The manifest entry type a permission kind declares, or a validation error for
/// `Unknown`.
///
/// Split out so the mapping is testable without a session: `Unknown` reaching
/// Graph would declare a `requiredResourceAccess` entry with a meaningless type.
fn entry_type_for(kind: PermissionKind) -> Result<&'static str, UiError> {
    match kind {
        PermissionKind::Application => Ok("Role"),
        PermissionKind::Delegated => Ok("Scope"),
        PermissionKind::Unknown => Err(UiError::validation(
            "invalid_permission_kind",
            "permission kind must be Application or Delegated",
        )),
    }
}

/// Shared core of [`grant_single_permission`]: manifest patch + runtime grant,
/// with no `State` and no cache side effects. Returns a [`GrantRun`]: the
/// result, whether the manifest PATCH landed and whether the grant materialized
/// the app's service principal (which decide how far the caller must
/// invalidate). A failure after either write comes back as `error: Some(..)`
/// beside those flags, not as an `Err` that would lose them.
///
/// Extracted for the reason `grant_admin_consent_core` and
/// `grant_managed_identity_roles_core` already were: behind a `#[tauri::command]`
/// taking `State`, the idempotence rules below (an already-assigned app role is a
/// skip, a scope id the resource does not expose is a structured failure rather
/// than an error) were only reachable from a signed-in app.
pub(crate) async fn grant_single_permission_core(
    client: &azapptoolkit_graph::GraphClient,
    object_id: &str,
    resource_app_id: &str,
    permission_id: &str,
    kind: PermissionKind,
) -> Result<GrantRun, UiError> {
    let entry_type = entry_type_for(kind)?;
    let mut app = client.get_application(object_id).await?;

    // 1) Patch requiredResourceAccess if the (resource, permission, kind)
    //    triple isn't already declared. Empty resource entry with the right
    //    appId is created when needed. The PATCH is the first write: its own
    //    failure landed nothing, so it stays a plain `Err`.
    let manifest_changed = declare_resource_access(
        &mut app.required_resource_access,
        resource_app_id,
        permission_id,
        entry_type,
    );
    if manifest_changed {
        let patch = azapptoolkit_graph::client::AppPatch {
            required_resource_access: Some(app.required_resource_access.clone()),
            ..Default::default()
        };
        client.update_application(object_id, &patch).await?;
    }

    // 2) Create the runtime grant. Errors stay structured so the UI can
    //    show a per-row failure without losing the manifest patch.
    let (client_sp, sp_created) = match client.ensure_service_principal(&app.app_id).await {
        Ok(ensured) => ensured,
        Err(e) if manifest_changed => {
            return Ok(GrantRun {
                result: empty_grant(String::new()),
                manifest_changed,
                sp_created: false,
                error: Some(e.into()),
            });
        }
        Err(e) => return Err(e.into()),
    };
    match single_runtime_grant(client, &client_sp.id, resource_app_id, permission_id, kind).await {
        Ok(result) => Ok(GrantRun {
            result,
            manifest_changed,
            sp_created,
            error: None,
        }),
        Err(e) if manifest_changed || sp_created => Ok(GrantRun {
            result: empty_grant(client_sp.id),
            manifest_changed,
            sp_created,
            error: Some(e),
        }),
        Err(e) => Err(e),
    }
}

/// [`grant_single_permission_core`] past the client SP: resolve the resource
/// SP and create (or skip) the one runtime grant.
async fn single_runtime_grant(
    client: &azapptoolkit_graph::GraphClient,
    client_sp_id: &str,
    resource_app_id: &str,
    permission_id: &str,
    kind: PermissionKind,
) -> Result<GrantResult, UiError> {
    let resource_app_id = resource_app_id.to_string();
    let permission_id = permission_id.to_string();
    let resource_sp = client
        .resolve_resource_sp(&resource_app_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "resource",
                format!("resource service principal {resource_app_id} not found"),
            )
        })?;

    let mut role_assignments_created = Vec::new();
    let mut role_assignments_skipped = Vec::new();
    let mut scope_grants_upserted = Vec::new();
    let mut failures = Vec::new();

    match kind {
        PermissionKind::Application => {
            let existing = client.list_app_role_assignments(client_sp_id).await?;
            let already = existing
                .iter()
                .any(|a| a.resource_id == resource_sp.id && a.app_role_id == permission_id);
            if already {
                role_assignments_skipped.push(SkippedRole {
                    resource_app_id: resource_app_id.clone(),
                    app_role_id: permission_id.clone(),
                    reason: "already assigned".into(),
                });
            } else {
                match client
                    .grant_app_role(client_sp_id, &resource_sp.id, &permission_id)
                    .await
                {
                    Ok(ara) => role_assignments_created.push(ara),
                    Err(err) => failures.push(GrantFailure {
                        resource_app_id: resource_app_id.clone(),
                        permission_id: Some(permission_id.clone()),
                        kind: "Role".into(),
                        message: grant_failure_message(&err),
                    }),
                }
            }
        }
        PermissionKind::Delegated => {
            // Resolve the scope value from the resource SP — Graph's
            // oauth2PermissionGrant.scope is space-separated VALUES, not ids.
            let scope_value = resource_sp
                .oauth2_permission_scopes
                .iter()
                .find(|s| s.id == permission_id)
                .map(|s| s.value.as_str());
            match scope_value {
                Some(value) => {
                    match client
                        .upsert_admin_oauth2_grant(client_sp_id, &resource_sp.id, &[value])
                        .await
                    {
                        Ok(grant) => scope_grants_upserted.push(ScopeGrantSummary {
                            resource_app_id: resource_app_id.clone(),
                            grant,
                            scopes_added: vec![value.to_string()],
                        }),
                        Err(err) => failures.push(GrantFailure {
                            resource_app_id: resource_app_id.clone(),
                            permission_id: Some(permission_id.clone()),
                            kind: "Scope".into(),
                            message: grant_failure_message(&err),
                        }),
                    }
                }
                None => failures.push(GrantFailure {
                    resource_app_id: resource_app_id.clone(),
                    permission_id: Some(permission_id.clone()),
                    kind: "Scope".into(),
                    message: "scope id not exposed by resource SP".into(),
                }),
            }
        }
        PermissionKind::Unknown => unreachable!("guarded by `entry_type_for` in the caller"),
    }

    Ok(GrantResult {
        client_service_principal_id: client_sp_id.to_string(),
        role_assignments_created,
        role_assignments_skipped,
        scope_grants_upserted,
        failures,
    })
}

/// Declares a single permission in `object_id`'s `requiredResourceAccess`
/// **without** creating any runtime grant — the manifest half of
/// `grant_single_permission`, nothing else. Used by the scoped-mailbox flow: the
/// permission is declared so it's visible in the UI and the Exchange scoping path
/// can derive its target from the manifest, while effective access comes solely
/// from a scoped Exchange RBAC role assignment — never an org-wide Entra app-role
/// grant (RBAC for Applications authorizes independently of the Entra consent).
/// Idempotent: an already-declared permission is a no-op success (no write, no
/// cache bust).
#[tauri::command]
pub async fn declare_app_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    resource_app_id: String,
    permission_id: String,
    kind: PermissionKind,
) -> Result<(), UiError> {
    let entry_type = entry_type_for(kind)?;

    let client = state.graph_for(&tenant_id);
    let mut app = client.get_application(&object_id).await?;
    if declare_resource_access(
        &mut app.required_resource_access,
        &resource_app_id,
        &permission_id,
        entry_type,
    ) {
        let patch = azapptoolkit_graph::client::AppPatch {
            required_resource_access: Some(app.required_resource_access.clone()),
            ..Default::default()
        };
        client.update_application(&object_id, &patch).await?;
        super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    Ok(())
}

// ---------------- Least-privilege downgrade ----------------

/// Swaps the declared `(broad_id → narrow_id)` Role access on `resource_app_id`
/// in place: removes the broad entry and adds the narrow one unless already
/// declared. Returns whether the manifest changed (`false` = broad wasn't
/// declared, nothing touched). `remove_declared_access` prunes a resource entry
/// it empties, so a broad-only resource is recreated to carry the narrow entry.
/// Pure so the swap semantics are unit-testable without a Graph client.
fn swap_declared_role(
    required: &mut Vec<RequiredResourceAccess>,
    resource_app_id: &str,
    broad_id: &str,
    narrow_id: &str,
) -> bool {
    if !remove_declared_access(required, resource_app_id, broad_id, Some("Role")) {
        return false;
    }
    let narrow_declared = required.iter().any(|r| {
        r.resource_app_id == resource_app_id
            && r.resource_access
                .iter()
                .any(|a| a.id == narrow_id && a.r#type == "Role")
    });
    if !narrow_declared {
        let access = ResourceAccess {
            id: narrow_id.to_string(),
            r#type: "Role".into(),
        };
        if let Some(existing) = required
            .iter_mut()
            .find(|r| r.resource_app_id == resource_app_id)
        {
            existing.resource_access.push(access);
        } else {
            required.push(RequiredResourceAccess {
                resource_app_id: resource_app_id.to_string(),
                resource_access: vec![access],
            });
        }
    }
    true
}

/// Replaces a broad application permission with a documented narrower
/// alternative (the least-privilege "Downgrade…" action; pairs come from
/// `azapptoolkit_core::audit::downgrade_alternatives` and the request is
/// re-validated against that table). NOT safe by construction — the narrower
/// permission only suffices if the app never uses the broader capability — so
/// the UI presents it as an admin-judged choice; this command just makes the
/// chosen swap atomic-ish and non-stranding:
///
/// 1. Grant the narrower appRoleAssignment **before** revoking the broad one
///    (grant-before-strip, as the Exchange/SharePoint scoping cores do), so a
///    mid-flight failure leaves the app with extra access, never none.
/// 2. Swap the `requiredResourceAccess` declaration in one trailing patch.
///
/// Idempotent: a broad permission already gone (re-run, stale UI) is a no-op
/// success with every outcome flag `false`.
#[tauri::command]
pub async fn downgrade_application_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    resource_app_id: String,
    broad_value: String,
    narrow_value: String,
) -> Result<DowngradeOutcome, UiError> {
    let client = state.graph_for(&tenant_id);
    let (outcome, error) = downgrade_application_permission_core(
        &client,
        &object_id,
        &resource_app_id,
        &broad_value,
        &narrow_value,
    )
    .await?;

    if outcome.narrow_granted || outcome.broad_revoked || outcome.declaration_swapped {
        super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    if let Some(e) = error {
        return Err(e);
    }
    Ok(outcome)
}

/// True when `narrow_value` is a documented narrower alternative of
/// `broad_value`.
///
/// The request arrives from the UI, so it is re-validated here rather than
/// trusted: the pair table is the only thing that makes this action a
/// *downgrade* rather than an arbitrary permission swap.
fn is_documented_downgrade(broad_value: &str, narrow_value: &str) -> bool {
    azapptoolkit_core::audit::downgrade_alternatives(broad_value).contains(&narrow_value)
}

/// Shared core of [`downgrade_application_permission`]: grant-before-strip, then
/// the declaration swap. No `State`, no cache side effects.
///
/// Returns `(outcome, error)` rather than `Result<outcome>` because a failure
/// *after* the first mutation still has real writes to report — the caller must
/// invalidate on the partial success before surfacing the error, which is
/// exactly the ordering the command layer used to inline.
pub(crate) async fn downgrade_application_permission_core(
    client: &azapptoolkit_graph::GraphClient,
    object_id: &str,
    resource_app_id: &str,
    broad_value: &str,
    narrow_value: &str,
) -> Result<(DowngradeOutcome, Option<UiError>), UiError> {
    if !is_documented_downgrade(broad_value, narrow_value) {
        return Err(UiError::validation(
            "not_a_downgrade",
            format!("{narrow_value} is not a documented narrower alternative of {broad_value}"),
        ));
    }

    let app = client.get_application(object_id).await?;
    let resource_sp = client
        .resolve_resource_sp(resource_app_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "resource",
                format!("resource app id {resource_app_id} not found"),
            )
        })?;
    let role_id = |value: &str| {
        resource_sp
            .app_roles
            .iter()
            .find(|r| r.value == value && r.is_enabled != Some(false))
            .map(|r| r.id.clone())
    };
    let Some(broad_id) = role_id(broad_value) else {
        return Err(UiError::validation(
            "unknown_permission",
            format!("{broad_value} is not an app role on this resource"),
        ));
    };
    let Some(narrow_id) = role_id(narrow_value) else {
        return Err(UiError::validation(
            "unknown_permission",
            format!("this resource does not expose {narrow_value}, so it cannot be swapped in"),
        ));
    };

    let mut outcome = DowngradeOutcome::default();
    let mut error: Option<UiError> = None;

    // Live grants first. Failures before the first mutation return early via
    // `?`; once anything has landed, errors are collected so the cache bust
    // below still runs (partial success = real write).
    let sp = client.get_service_principal_by_app_id(&app.app_id).await?;
    if let Some(sp) = &sp {
        let assignments = client.list_app_role_assignments(&sp.id).await?;
        let broad_assignment = assignments
            .iter()
            .find(|a| a.resource_id == resource_sp.id && a.app_role_id == broad_id);
        if let Some(broad_assignment) = broad_assignment {
            let narrow_already = assignments
                .iter()
                .any(|a| a.resource_id == resource_sp.id && a.app_role_id == narrow_id);
            if !narrow_already {
                client
                    .grant_app_role(&sp.id, &resource_sp.id, &narrow_id)
                    .await?;
                outcome.narrow_granted = true;
            }
            match client
                .remove_app_role_assignment(&sp.id, &broad_assignment.id)
                .await
            {
                Ok(()) => outcome.broad_revoked = true,
                Err(e) => error = Some(e.into()),
            }
        }
    }

    // Declaration swap in one PATCH — skipped when the revoke failed, so the
    // manifest keeps matching the live grants (both still present).
    if error.is_none() {
        let mut next = app.required_resource_access.clone();
        if swap_declared_role(&mut next, resource_app_id, &broad_id, &narrow_id) {
            let patch = azapptoolkit_graph::client::AppPatch {
                required_resource_access: Some(next),
                ..Default::default()
            };
            match client.update_application(object_id, &patch).await {
                Ok(_) => outcome.declaration_swapped = true,
                Err(e) => error = Some(e.into()),
            }
        }
    }

    Ok((outcome, error))
}

// ---------------- Revoke ----------------

/// Deletes a single `appRoleAssignment` on a service principal. Used to
/// revoke an Application permission previously granted by admin consent or
/// by `grant_managed_identity_permission`. Leaves `requiredResourceAccess`
/// (the declaration) untouched.
#[tauri::command]
pub async fn revoke_app_role_assignment(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    assignment_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client
        .remove_app_role_assignment(&service_principal_id, &assignment_id)
        .await?;
    super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

/// Removes a single scope from an `oauth2PermissionGrant`. If the resulting
/// scope string is empty, the grant itself is deleted. Whitespace handling
/// is via `split_whitespace` + `join(" ")` so grants saved with tabs,
/// double spaces, or trailing whitespace still roundtrip correctly.
#[tauri::command]
pub async fn revoke_oauth2_scope(
    state: State<'_, AppState>,
    tenant_id: String,
    grant_id: String,
    scope_value: String,
) -> Result<RevokeScopeOutcome, UiError> {
    let client = state.graph_for(&tenant_id);
    let grant = client.get_oauth2_grant(&grant_id).await?;
    let target = scope_value.trim();
    let remaining: Vec<&str> = grant
        .scope
        .split_whitespace()
        .filter(|s| *s != target)
        .collect();
    let outcome = if remaining.is_empty() {
        client.delete_oauth2_grant(&grant_id).await?;
        RevokeScopeOutcome::Deleted
    } else {
        let joined = remaining.join(" ");
        client.update_oauth2_grant_scope(&grant_id, &joined).await?;
        RevokeScopeOutcome::Updated { remaining: joined }
    };
    super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::{AppRole, OAuth2PermissionScope};

    fn role(value: &str, enabled: Option<bool>) -> AppRole {
        AppRole {
            id: format!("id-{value}"),
            value: value.into(),
            display_name: format!("{value} role"),
            is_enabled: enabled,
            allowed_member_types: vec!["Application".into()],
            ..Default::default()
        }
    }

    fn scope(value: &str, enabled: Option<bool>) -> OAuth2PermissionScope {
        OAuth2PermissionScope {
            id: format!("id-{value}"),
            value: value.into(),
            is_enabled: enabled,
            ..Default::default()
        }
    }

    #[test]
    fn only_application_and_delegated_declare_a_manifest_entry() {
        // `Unknown` reaching Graph would PATCH `requiredResourceAccess` with a
        // meaningless entry type, which is not something the portal can show or
        // a later grant can match. It is rejected before any round trip.
        assert_eq!(entry_type_for(PermissionKind::Application).unwrap(), "Role");
        assert_eq!(entry_type_for(PermissionKind::Delegated).unwrap(), "Scope");
        let err = entry_type_for(PermissionKind::Unknown).expect_err("Unknown must be refused");
        assert_eq!(err.code, "invalid_permission_kind");
    }

    #[test]
    fn a_downgrade_is_only_a_downgrade_if_the_table_says_so() {
        // The request comes from the UI, so the pair is re-validated here. Without
        // this the action would swap any permission for any other while still
        // being presented to the operator as "downgrade to least privilege".
        let broad = "Mail.ReadWrite";
        let narrower = azapptoolkit_core::audit::downgrade_alternatives(broad);
        assert!(
            !narrower.is_empty(),
            "fixture assumes {broad} has documented alternatives"
        );
        for n in narrower {
            assert!(is_documented_downgrade(broad, n));
        }
        // Not a documented pair, and not the reverse direction either.
        assert!(!is_documented_downgrade(broad, "Directory.ReadWrite.All"));
        assert!(!is_documented_downgrade(broad, broad));
        for n in azapptoolkit_core::audit::downgrade_alternatives(broad) {
            assert!(
                !is_documented_downgrade(n, broad),
                "{n} -> {broad} widens access and must never validate as a downgrade"
            );
        }
    }

    #[test]
    fn maps_live_sp_dropping_disabled_and_sorting_by_value() {
        let sp = ServicePrincipal {
            app_id: "00000003-0000-0000-c000-000000000000".into(),
            display_name: "Microsoft Graph".into(),
            app_roles: vec![
                role("User.Read.All", Some(true)),
                role("Application.ReadWrite.All", None), // null isEnabled => kept
                role("Legacy.Disabled", Some(false)),    // dropped
            ],
            oauth2_permission_scopes: vec![
                scope("offline_access", Some(true)),
                scope("email", Some(false)), // dropped
                scope("User.Read", None),    // kept
            ],
            ..Default::default()
        };

        let perms = service_principal_to_permissions(sp);

        assert_eq!(perms.source, "graph");
        // Disabled entries dropped; the rest sorted alphabetically by value.
        assert_eq!(
            perms
                .app_roles
                .iter()
                .map(|r| r.value.as_str())
                .collect::<Vec<_>>(),
            ["Application.ReadWrite.All", "User.Read.All"]
        );
        assert_eq!(
            perms
                .oauth2_permission_scopes
                .iter()
                .map(|s| s.value.as_str())
                .collect::<Vec<_>>(),
            ["User.Read", "offline_access"]
        );
        // allowedMemberTypes is carried through for the picker's app-only filter.
        assert!(
            perms.app_roles[1]
                .allowed_member_types
                .iter()
                .any(|t| t == "Application")
        );
    }

    /// `role()` with explicit `allowedMemberTypes` (it hardcodes `Application`).
    fn role_with_types(value: &str, enabled: Option<bool>, types: &[&str]) -> AppRole {
        AppRole {
            allowed_member_types: types.iter().map(|t| t.to_string()).collect(),
            ..role(value, enabled)
        }
    }

    #[test]
    fn app_role_resource_summary_keeps_sp_exposing_application_roles() {
        let sp = ServicePrincipal {
            app_id: "11111111-1111-1111-1111-111111111111".into(),
            display_name: "Contoso Orders API".into(),
            app_roles: vec![
                role("Orders.Read", Some(true)),
                role("Orders.Write", None), // null isEnabled => kept
            ],
            ..Default::default()
        };
        let summary = app_role_resource_summary(sp).expect("exposes application roles");
        assert_eq!(summary.app_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(summary.display_name, "Contoso Orders API");
        assert_eq!(summary.role_count, 2);
        assert_eq!(summary.scope_count, 0);
    }

    #[test]
    fn app_role_resource_summary_counts_only_grantable_application_roles() {
        let sp = ServicePrincipal {
            app_id: "app".into(),
            display_name: "Mixed".into(),
            app_roles: vec![
                role("Orders.Read", Some(true)),                    // counted
                role("Legacy", Some(false)),                        // disabled -> dropped
                role_with_types("UserOnly", Some(true), &["User"]), // user-only -> dropped
                role_with_types("Both", Some(true), &["Application", "User"]), // counted
                role_with_types("", Some(true), &["Application"]), // empty value -> dropped (not matchable by the grant)
            ],
            ..Default::default()
        };
        let summary = app_role_resource_summary(sp).expect("has grantable roles");
        assert_eq!(summary.role_count, 2);
    }

    #[test]
    fn app_role_resource_summary_drops_sp_without_grantable_roles() {
        // No app roles at all (e.g. a managed identity, which the owner filter
        // returns but exposes none).
        assert!(
            app_role_resource_summary(ServicePrincipal {
                app_id: "a".into(),
                display_name: "Bare".into(),
                ..Default::default()
            })
            .is_none()
        );
        // Only user-only / disabled roles → not grantable to a service principal.
        let sp = ServicePrincipal {
            app_id: "a".into(),
            display_name: "UserApp".into(),
            app_roles: vec![
                role_with_types("UserOnly", Some(true), &["User"]),
                role("Disabled", Some(false)),
            ],
            ..Default::default()
        };
        assert!(app_role_resource_summary(sp).is_none());
    }

    fn access(id: &str, ty: &str) -> ResourceAccess {
        ResourceAccess {
            id: id.into(),
            r#type: ty.into(),
        }
    }

    fn manifest(entries: &[(&str, &[(&str, &str)])]) -> Vec<RequiredResourceAccess> {
        entries
            .iter()
            .map(|(res, accesses)| RequiredResourceAccess {
                resource_app_id: (*res).into(),
                resource_access: accesses.iter().map(|(id, ty)| access(id, ty)).collect(),
            })
            .collect()
    }

    #[test]
    fn remove_declared_access_drops_match_and_prunes_empty_resource() {
        // A resource with a single Role; removing it empties and prunes the
        // whole resource entry.
        let mut req = manifest(&[("graph", &[("role-1", "Role")])]);
        assert!(remove_declared_access(
            &mut req,
            "graph",
            "role-1",
            Some("Role")
        ));
        assert!(req.is_empty(), "emptied resource entry should be pruned");
    }

    #[test]
    fn remove_declared_access_keeps_siblings() {
        // Removing one access leaves the resource (with its other access) intact.
        let mut req = manifest(&[("graph", &[("role-1", "Role"), ("scope-1", "Scope")])]);
        assert!(remove_declared_access(
            &mut req,
            "graph",
            "role-1",
            Some("Role")
        ));
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].id, "scope-1");
    }

    #[test]
    fn remove_declared_access_respects_type_when_ids_collide() {
        // Same id declared as both a Role and a Scope: the type narrows it to one.
        let mut req = manifest(&[("graph", &[("dup", "Role"), ("dup", "Scope")])]);
        assert!(remove_declared_access(
            &mut req,
            "graph",
            "dup",
            Some("Scope")
        ));
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].r#type, "Role");
    }

    #[test]
    fn remove_declared_access_unknown_kind_matches_id_alone() {
        // `None` type (an unclassified raw-GUID row) matches on id regardless of type.
        let mut req = manifest(&[("graph", &[("dup", "Role")])]);
        assert!(remove_declared_access(&mut req, "graph", "dup", None));
        assert!(req.is_empty());
    }

    #[test]
    fn declare_resource_access_creates_resource_entry_when_absent() {
        // No declaration for the resource yet — a fresh entry carries the access.
        let mut req = manifest(&[]);
        assert!(declare_resource_access(&mut req, "graph", "role-1", "Role"));
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].resource_app_id, "graph");
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].id, "role-1");
        assert_eq!(req[0].resource_access[0].r#type, "Role");
    }

    #[test]
    fn declare_resource_access_appends_to_existing_resource() {
        // Resource already declared with a sibling — the new access is appended,
        // not a duplicate resource entry.
        let mut req = manifest(&[("graph", &[("scope-1", "Scope")])]);
        assert!(declare_resource_access(&mut req, "graph", "role-1", "Role"));
        assert_eq!(req.len(), 1);
        let ids: Vec<(&str, &str)> = req[0]
            .resource_access
            .iter()
            .map(|a| (a.id.as_str(), a.r#type.as_str()))
            .collect();
        assert_eq!(ids, [("scope-1", "Scope"), ("role-1", "Role")]);
    }

    #[test]
    fn declare_resource_access_already_declared_is_noop() {
        // Same (id, type) already present → no change, so the caller skips the PATCH.
        let mut req = manifest(&[("graph", &[("role-1", "Role")])]);
        assert!(!declare_resource_access(
            &mut req, "graph", "role-1", "Role"
        ));
        assert_eq!(req[0].resource_access.len(), 1);
        // Same id but a different type is a distinct declaration and is added.
        assert!(declare_resource_access(
            &mut req, "graph", "role-1", "Scope"
        ));
        assert_eq!(req[0].resource_access.len(), 2);
    }

    #[test]
    fn swap_declared_role_replaces_broad_with_narrow() {
        // Broad + sibling: broad goes, narrow is appended, sibling untouched.
        let mut req = manifest(&[("graph", &[("id-broad", "Role"), ("id-other", "Scope")])]);
        assert!(swap_declared_role(
            &mut req,
            "graph",
            "id-broad",
            "id-narrow"
        ));
        let ids: Vec<(&str, &str)> = req[0]
            .resource_access
            .iter()
            .map(|a| (a.id.as_str(), a.r#type.as_str()))
            .collect();
        assert_eq!(ids, [("id-other", "Scope"), ("id-narrow", "Role")]);
    }

    #[test]
    fn swap_declared_role_recreates_a_pruned_resource_entry() {
        // Broad was the resource's only access: remove_declared_access prunes
        // the entry, so the swap must recreate it to carry the narrow role.
        let mut req = manifest(&[("graph", &[("id-broad", "Role")])]);
        assert!(swap_declared_role(
            &mut req,
            "graph",
            "id-broad",
            "id-narrow"
        ));
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].resource_app_id, "graph");
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].id, "id-narrow");
        assert_eq!(req[0].resource_access[0].r#type, "Role");
    }

    #[test]
    fn swap_declared_role_skips_duplicate_narrow_and_missing_broad() {
        // Narrow already declared → no duplicate entry is added.
        let mut req = manifest(&[("graph", &[("id-broad", "Role"), ("id-narrow", "Role")])]);
        assert!(swap_declared_role(
            &mut req,
            "graph",
            "id-broad",
            "id-narrow"
        ));
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].id, "id-narrow");

        // Broad absent → untouched no-op (idempotent re-run).
        let mut req = manifest(&[("graph", &[("id-narrow", "Role")])]);
        assert!(!swap_declared_role(
            &mut req,
            "graph",
            "id-broad",
            "id-narrow"
        ));
        assert_eq!(req[0].resource_access.len(), 1);
    }

    #[test]
    fn remove_declared_access_no_match_is_noop() {
        // Wrong type, wrong resource, and wrong id each leave the manifest untouched.
        // (RequiredResourceAccess has no PartialEq, so compare projected tuples.)
        let project = |req: &[RequiredResourceAccess]| {
            req.iter()
                .map(|r| {
                    (
                        r.resource_app_id.clone(),
                        r.resource_access
                            .iter()
                            .map(|a| (a.id.clone(), a.r#type.clone()))
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let original = manifest(&[("graph", &[("role-1", "Role")])]);
        for (res, id, ty) in [
            ("graph", "role-1", Some("Scope")), // right id, wrong type
            ("other", "role-1", Some("Role")),  // wrong resource
            ("graph", "missing", Some("Role")), // wrong id
        ] {
            let mut req = original.clone();
            assert!(!remove_declared_access(&mut req, res, id, ty));
            assert_eq!(
                project(&req),
                project(&original),
                "no-match must not mutate the manifest"
            );
        }
    }
}

/// Core-level partial-write tests: the grant cores take `&GraphClient`, so a
/// mock Graph drives them as-is. A failure after a landed write comes back as a
/// [`GrantRun`] carrying the landed flags; one before any write stays `Err`.
#[cfg(test)]
mod handler_tests {
    use super::*;

    use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::commands::test_support::{
        detail_cached, indexes_intact, mock_graph, sample_app_json, seed_indexes_and_detail,
    };

    /// `sample_app_json()` (obj-1 / app-1, nothing declared) and no SP for
    /// app-1 yet — the state in which both cores must create one.
    async fn mount_app_without_sp(server: &MockServer) {
        mount_app(server, sample_app_json()).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", "appId eq 'app-1'"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
            )
            .mount(server)
            .await;
    }

    async fn mount_app(server: &MockServer, app: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path("/v1.0/applications/obj-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(app))
            .mount(server)
            .await;
    }

    async fn refuse_sp_create(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/v1.0/servicePrincipals"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
            .mount(server)
            .await;
    }

    /// The idempotency snapshot the admin-consent core reads right after the
    /// client SP: its app-role assignments are refused.
    async fn refuse_assignment_snapshot(server: &MockServer, sp_id: &str) {
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1.0/servicePrincipals/{sp_id}/appRoleAssignments"
            )))
            .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1.0/oauth2PermissionGrants"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
            )
            .mount(server)
            .await;
    }

    async fn received(server: &MockServer, verb: &str, url_path: &str) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method.as_str() == verb && r.url.path() == url_path)
            .map(|r| String::from_utf8_lossy(&r.body).into_owned())
            .collect()
    }

    #[tokio::test]
    async fn grant_single_permission_core_reports_the_landed_manifest_patch_when_sp_creation_fails()
    {
        let server = MockServer::start().await;
        mount_app_without_sp(&server).await;
        Mock::given(method("PATCH"))
            .and(path("/v1.0/applications/obj-1"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        refuse_sp_create(&server).await;
        let client = mock_graph(&server);

        let run = grant_single_permission_core(
            &client,
            "obj-1",
            MICROSOFT_GRAPH_APP_ID,
            "role-1",
            PermissionKind::Application,
        )
        .await
        .expect("the manifest PATCH landed, so the run is Ok with an error beside it");
        assert!(run.manifest_changed, "the PATCH is reported");
        assert!(!run.sp_created);
        assert_eq!(
            run.error.expect("the SP failure is reported").code,
            "forbidden"
        );

        let patches = received(&server, "PATCH", "/v1.0/applications/obj-1").await;
        assert_eq!(patches.len(), 1, "exactly one manifest PATCH was sent");
        assert!(patches[0].contains("role-1"), "{}", patches[0]);
        assert!(
            patches[0].contains(MICROSOFT_GRAPH_APP_ID),
            "{}",
            patches[0]
        );
        assert_eq!(
            received(&server, "POST", "/v1.0/servicePrincipals")
                .await
                .len(),
            1
        );
    }

    /// Already declared → no PATCH, so an SP failure landed nothing: plain Err.
    #[tokio::test]
    async fn grant_single_permission_core_errs_when_nothing_landed_before_the_failure() {
        let server = MockServer::start().await;
        let mut app = sample_app_json();
        app["requiredResourceAccess"] = serde_json::json!([{
            "resourceAppId": MICROSOFT_GRAPH_APP_ID,
            "resourceAccess": [{ "id": "role-1", "type": "Role" }],
        }]);
        mount_app(&server, app).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", "appId eq 'app-1'"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
            )
            .mount(&server)
            .await;
        refuse_sp_create(&server).await;
        let client = mock_graph(&server);

        let err = grant_single_permission_core(
            &client,
            "obj-1",
            MICROSOFT_GRAPH_APP_ID,
            "role-1",
            PermissionKind::Application,
        )
        .await
        .expect_err("nothing landed, so the failure is a plain Err");
        assert_eq!(err.code, "forbidden");
        assert!(
            received(&server, "PATCH", "/v1.0/applications/obj-1")
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn grant_admin_consent_core_reports_the_created_sp_when_the_grant_snapshot_fails() {
        let server = MockServer::start().await;
        mount_app_without_sp(&server).await;
        Mock::given(method("POST"))
            .and(path("/v1.0/servicePrincipals"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "sp-new",
                "appId": "app-1",
                "displayName": "Demo App",
            })))
            .mount(&server)
            .await;
        refuse_assignment_snapshot(&server, "sp-new").await;
        let client = mock_graph(&server);

        let run = grant_admin_consent_core(&client, "obj-1")
            .await
            .expect("the SP was created, so the run is Ok with an error beside it");
        assert!(run.sp_created, "the created SP survives the later failure");
        assert!(!run.manifest_changed);
        assert_eq!(run.result.client_service_principal_id, "sp-new");
        assert!(run.result.role_assignments_created.is_empty());
        assert_eq!(
            run.error.expect("the snapshot failure is reported").code,
            "forbidden"
        );
        assert_eq!(
            received(&server, "POST", "/v1.0/servicePrincipals")
                .await
                .len(),
            1,
            "the SP creation landed before the failure"
        );
        assert!(
            received(
                &server,
                "POST",
                "/v1.0/servicePrincipals/sp-new/appRoleAssignments"
            )
            .await
            .is_empty(),
            "the run stops: no grant is written with the granted set unknown"
        );
    }

    /// The SP already existed → nothing landed before the snapshot failure:
    /// plain Err.
    #[tokio::test]
    async fn grant_admin_consent_core_errs_when_the_sp_already_existed() {
        let server = MockServer::start().await;
        mount_app(&server, sample_app_json()).await;
        Mock::given(method("GET"))
            .and(path("/v1.0/servicePrincipals"))
            .and(query_param("$filter", "appId eq 'app-1'"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "sp-1", "appId": "app-1", "displayName": "Demo App" }]
            })))
            .mount(&server)
            .await;
        refuse_assignment_snapshot(&server, "sp-1").await;
        let client = mock_graph(&server);

        let err = grant_admin_consent_core(&client, "obj-1")
            .await
            .expect_err("nothing landed, so the failure is a plain Err");
        assert_eq!(err.code, "forbidden");
        assert!(
            received(&server, "POST", "/v1.0/servicePrincipals")
                .await
                .is_empty()
        );
    }

    /// Each landed-write shape busts exactly the tier it needs — and a stopped
    /// run that landed nothing busts nothing.
    #[test]
    fn invalidate_after_grant_busts_the_tier_the_landed_writes_need() {
        const TENANT: &str = "t1";
        const OBJECT: &str = "obj-1";
        let forbidden = || Some(UiError::new("forbidden", "no", false));
        // (manifest_changed, sp_created, error, detail kept, indexes kept)
        let rows: [(bool, bool, Option<UiError>, bool, bool); 5] = [
            (false, true, None, false, false),
            (false, true, forbidden(), false, false),
            (false, false, None, false, true),
            (true, false, forbidden(), false, true),
            (false, false, forbidden(), true, true),
        ];
        for (i, (manifest_changed, sp_created, error, detail_kept, indexes_kept)) in
            rows.into_iter().enumerate()
        {
            let state = AppState::for_test(TENANT, "http://127.0.0.1:9");
            seed_indexes_and_detail(&state, TENANT, OBJECT);
            let run = GrantRun {
                result: empty_grant(String::new()),
                manifest_changed,
                sp_created,
                error,
            };
            invalidate_after_grant(&state.cache, TENANT, &run);
            assert_eq!(
                detail_cached(&state, TENANT, OBJECT),
                detail_kept,
                "row {i}"
            );
            assert_eq!(indexes_intact(&state, TENANT), indexes_kept, "row {i}");
        }
    }
}
