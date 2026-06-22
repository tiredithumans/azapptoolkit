use tauri::State;

use azapptoolkit_core::models::{RequiredResourceAccess, ResourceAccess, ServicePrincipal};

use crate::dto::permissions::{
    CatalogResourceSummary, DowngradeOutcome, GrantFailure, GrantResult, PermissionKind,
    ResourcePermissions, RevokeScopeOutcome, RoleEntry, ScopeEntry, ScopeGrantSummary, SkippedRole,
};
use crate::dto::UiError;
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

#[tauri::command]
pub async fn update_required_resource_access(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    required_resource_access: Vec<RequiredResourceAccess>,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    let patch = azapptoolkit_graph::client::AppPatch {
        required_resource_access: Some(required_resource_access),
        ..Default::default()
    };
    client.update_application(&object_id, &patch).await?;
    super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

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
    let entry_type = match kind {
        PermissionKind::Application => Some("Role"),
        PermissionKind::Delegated => Some("Scope"),
        PermissionKind::Unknown => None,
    };

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

// ---------------- Admin consent ----------------

/// Ensures admin consent is granted for every permission declared in the
/// application's `requiredResourceAccess`. Mirrors `Grant-AzAppAdminConsent`.
///
/// Order of operations:
///   1. Read the target application.
///   2. Ensure the client service principal exists (create if missing).
///   3. For each resource group:
///      a. Resolve the resource SP (live Graph; cached under `Permissions` kind).
///      b. For each `Role` permission: skip if already assigned, else POST
///         `appRoleAssignments`.
///      c. For each `Scope` permission: resolve the scope value from the
///         resource SP's `oauth2PermissionScopes`, then `upsert_admin_oauth2_grant`
///         with the aggregate scope list for that resource.
///
/// Partial failures are collected in `failures` rather than aborting the run.
#[tauri::command]
pub async fn grant_admin_consent(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<GrantResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let result = grant_admin_consent_core(&client, &object_id).await?;
    super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(result)
}

/// Builds a grant-failure message from a Graph error, appending the admin-consent
/// role guidance when the failure is a 403. A forbidden on a *grant* operation
/// means the signed-in user lacks the directory role to consent (the
/// `admin_consent` capability — Privileged Role Administrator / Global
/// Administrator for high-privilege permissions), not that the permission itself
/// is wrong, so the hint points there.
fn grant_failure_message(err: &azapptoolkit_graph::GraphError) -> String {
    let base = err.to_string();
    if matches!(err, azapptoolkit_graph::GraphError::Forbidden(_)) {
        if let Some(cap) = azapptoolkit_core::capabilities::capability("admin_consent") {
            return format!("{base}\n\n{}", cap.remediation);
        }
    }
    base
}

/// Shared admin-consent orchestration, reused by the single-app command and
/// the bulk path so both keep identical semantics.
pub(crate) async fn grant_admin_consent_core(
    client: &azapptoolkit_graph::GraphClient,
    object_id: &str,
) -> Result<GrantResult, UiError> {
    let app = client.get_application(object_id).await?;
    let client_sp = client.ensure_service_principal(&app.app_id).await?;
    // Must not swallow this: if the existing-assignments lookup fails we can't
    // tell which roles are already granted, and proceeding would re-grant
    // everything (duplicate/conflicting assignments).
    let existing_assignments = client.list_app_role_assignments(&client_sp.id).await?;

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
            .upsert_admin_oauth2_grant(&client_sp.id, &resource_sp.id, &scope_values)
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
        client_service_principal_id: client_sp.id,
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
    let entry_type = match kind {
        PermissionKind::Application => "Role",
        PermissionKind::Delegated => "Scope",
        PermissionKind::Unknown => {
            return Err(UiError::validation(
                "invalid_permission_kind",
                "permission kind must be Application or Delegated",
            ));
        }
    };

    let client = state.graph_for(&tenant_id);
    let mut app = client.get_application(&object_id).await?;

    // 1) Patch requiredResourceAccess if the (resource, permission, kind)
    //    triple isn't already declared. Empty resource entry with the right
    //    appId is created when needed.
    let needs_manifest_patch = {
        let resource = app
            .required_resource_access
            .iter()
            .find(|r| r.resource_app_id == resource_app_id);
        match resource {
            None => true,
            Some(r) => !r
                .resource_access
                .iter()
                .any(|a| a.id == permission_id && a.r#type == entry_type),
        }
    };

    if needs_manifest_patch {
        let mut next = app.required_resource_access.clone();
        if let Some(existing) = next
            .iter_mut()
            .find(|r| r.resource_app_id == resource_app_id)
        {
            existing.resource_access.push(ResourceAccess {
                id: permission_id.clone(),
                r#type: entry_type.to_string(),
            });
        } else {
            next.push(RequiredResourceAccess {
                resource_app_id: resource_app_id.clone(),
                resource_access: vec![ResourceAccess {
                    id: permission_id.clone(),
                    r#type: entry_type.to_string(),
                }],
            });
        }
        let patch = azapptoolkit_graph::client::AppPatch {
            required_resource_access: Some(next.clone()),
            ..Default::default()
        };
        client.update_application(&object_id, &patch).await?;
        app.required_resource_access = next;
    }

    // 2) Create the runtime grant. Errors stay structured so the UI can
    //    show a per-row failure without losing the manifest patch.
    let client_sp = client.ensure_service_principal(&app.app_id).await?;
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
            let existing = client.list_app_role_assignments(&client_sp.id).await?;
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
                    .grant_app_role(&client_sp.id, &resource_sp.id, &permission_id)
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
                        .upsert_admin_oauth2_grant(&client_sp.id, &resource_sp.id, &[value])
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
        PermissionKind::Unknown => unreachable!("guarded above"),
    }

    super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(GrantResult {
        client_service_principal_id: client_sp.id,
        role_assignments_created,
        role_assignments_skipped,
        scope_grants_upserted,
        failures,
    })
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
    if !azapptoolkit_core::audit::downgrade_alternatives(&broad_value)
        .contains(&narrow_value.as_str())
    {
        return Err(UiError::validation(
            "not_a_downgrade",
            format!("{narrow_value} is not a documented narrower alternative of {broad_value}"),
        ));
    }

    let client = state.graph_for(&tenant_id);
    let app = client.get_application(&object_id).await?;
    let resource_sp = client
        .resolve_resource_sp(&resource_app_id)
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
    let Some(broad_id) = role_id(&broad_value) else {
        return Err(UiError::validation(
            "unknown_permission",
            format!("{broad_value} is not an app role on this resource"),
        ));
    };
    let Some(narrow_id) = role_id(&narrow_value) else {
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
        if swap_declared_role(&mut next, &resource_app_id, &broad_id, &narrow_id) {
            let patch = azapptoolkit_graph::client::AppPatch {
                required_resource_access: Some(next),
                ..Default::default()
            };
            match client.update_application(&object_id, &patch).await {
                Ok(_) => outcome.declaration_swapped = true,
                Err(e) => error = Some(e.into()),
            }
        }
    }

    if outcome.narrow_granted || outcome.broad_revoked || outcome.declaration_swapped {
        super::applications::invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    if let Some(e) = error {
        return Err(e);
    }
    Ok(outcome)
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
        assert!(perms.app_roles[1]
            .allowed_member_types
            .iter()
            .any(|t| t == "Application"));
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
