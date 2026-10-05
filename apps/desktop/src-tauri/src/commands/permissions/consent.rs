use tauri::State;

use azapptoolkit_core::models::ServicePrincipal;

use crate::dto::UiError;
use crate::dto::permissions::{GrantFailure, GrantResult, ScopeGrantSummary, SkippedRole};
use crate::state::AppState;

use super::{GrantRun, empty_grant, grant_failure_message, invalidate_after_grant};

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
    grant_admin_consent_to_app_core(client, &app).await
}

/// [`grant_admin_consent_core`] for an application the caller has already
/// read — and checked: the DR restore consents exactly the declared
/// permissions it compared against the approved plan, never a second read
/// that could have changed in between.
pub(crate) async fn grant_admin_consent_to_app_core(
    client: &azapptoolkit_graph::GraphClient,
    app: &azapptoolkit_core::models::Application,
) -> Result<GrantRun, UiError> {
    let (client_sp, sp_created) = client.ensure_service_principal(&app.app_id).await?;
    match consent_with_sp(client, app, &client_sp).await {
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
