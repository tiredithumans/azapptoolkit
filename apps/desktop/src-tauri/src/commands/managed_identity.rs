//! Managed-identity commands.
//!
//! Managed identities are service principals (`servicePrincipalType ==
//! "ManagedIdentity"`). Granting one an application permission is an app-role
//! assignment on that service principal — the same Graph operation used for
//! ordinary admin consent, just targeting the managed identity's SP as the
//! principal. Mirrors the legacy `Get-AzManagedIdentity` /
//! `Grant-AzManagedIdentityPermission` cmdlets.

use std::collections::HashSet;

use futures::stream::{self, StreamExt};
use tauri::{AppHandle, State};

use azapptoolkit_arm::RoleAssignment;
use azapptoolkit_core::azure_roles::{RoleContext, is_high_privilege_role};
use azapptoolkit_core::cache::CacheKind;

use crate::commands::arm_roles::{resolve_role_names_cached, role_display_name};
use crate::commands::graph_err::forbidden_remediation;
use crate::commands::guid::new_v4_guid;
use crate::dto::UiError;
use crate::dto::managed_identity::{
    AzureRoleDto, AzureRolesResult, GrantManagedIdentityResult, ManagedIdentityDto, MiSubtype,
};
use crate::state::AppState;

/// Max concurrent ARM calls (per-subscription fetches + role-def resolution).
/// Bounds fan-out so scanning every subscription stays within ARM's rate limits
/// (429s are retried with backoff in the client); a large estate just takes
/// proportionally longer rather than truncating the result.
const ARM_CONCURRENCY: usize = 8;

pub(crate) fn mi_key(tenant_id: &str) -> String {
    format!("{tenant_id}|mi")
}

/// Lists managed-identity service principals in the tenant.
#[tauri::command]
pub async fn list_managed_identities(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<ManagedIdentityDto>, UiError> {
    // The cache-HIT path below returns before any client is built, so the
    // `graph_for` on the miss path is not a session proof for it.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    let key = mi_key(&tenant_id);
    if let Some(cached) = state
        .cache
        .get::<Vec<ManagedIdentityDto>>(CacheKind::Lists, &key)
    {
        tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = %key, "hit");
        return Ok(cached);
    }
    tracing::debug!(target: "azapptoolkit::cache", kind = "Lists", key = %key, "miss");

    // Filter the SHARED service-principal index rather than running a second,
    // near-identical `/servicePrincipals` scan of our own. That index is
    // unfiltered by design (the App Registrations join needs every SP), already
    // carries `servicePrincipalType` and `alternativeNames`, and is read by five
    // other surfaces — so on a warm tenant this list now costs nothing, and on a
    // cold one it seeds the index everything else then reuses.
    let client = state.graph_for(&tenant_id);
    // Captured BEFORE the scan the index accessor may run — this list is
    // PINNED, so a snapshot that loses the race to a mutation would sit out of
    // LRU's reach for the full TTL.
    let watch = state.cache.generation_for(CacheKind::Lists, &key);
    let sps = crate::commands::applications::sp_index_cached(&state, &client, &tenant_id).await?;
    let rows: Vec<ManagedIdentityDto> = sps
        .iter()
        .filter(|sp| sp.service_principal_type.as_deref() == Some("ManagedIdentity"))
        .map(|sp| ManagedIdentityDto {
            id: sp.id.clone(),
            app_id: sp.app_id.clone(),
            display_name: sp.display_name.clone(),
            account_enabled: sp.account_enabled,
            mi_subtype: MiSubtype::from_alternative_names(&sp.alternative_names),
        })
        .collect();

    // Guarded like its source index: a mutation that landed mid-scan already
    // dropped this key, and re-pinning the pre-mutation rows would outlive it.
    state.cache.put_index_if_current(watch, &rows);
    Ok(rows)
}

/// Grants application permissions (`roles`, given as permission values like
/// `Mail.Read`) on `resource_app_id` to the managed identity
/// `managed_identity_id` (its service-principal object id). Idempotent: roles
/// already assigned are reported as skipped.
#[tauri::command]
pub async fn grant_managed_identity_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    managed_identity_id: String,
    resource_app_id: String,
    roles: Vec<String>,
) -> Result<GrantManagedIdentityResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let (granted, skipped, failures) =
        grant_managed_identity_roles_core(&client, &managed_identity_id, &resource_app_id, &roles)
            .await?;
    // No list bust: the cached `{tenant}|mi` list holds only identity rows
    // (id/name/enabled), which a grant doesn't change; the MI's held grants are
    // read live, and granting a new mail permission yields a new `mail_scopes`
    // key (no stale verdict). The audit DOES score SP-only principals from
    // their granted roles, so a successful grant busts the cached run.
    if !granted.is_empty() {
        crate::commands::audit::invalidate_audit_cache(&state.cache, &tenant_id);
    }
    Ok(GrantManagedIdentityResult {
        managed_identity_id,
        granted,
        skipped,
        failures,
    })
}

/// Grants application permissions (`roles`, given as permission values like
/// `Mail.Read`) on `resource_app_id` to a managed identity's service principal.
/// Idempotent: already-assigned roles are reported as skipped. Returns
/// `(granted, skipped, failures)`. Shared by the single-MI command and the DR
/// restore's MI re-bind — both resolve the resource SP in the *current* tenant,
/// so a backed-up grant re-binds to the destination's resource appId by value.
pub(crate) async fn grant_managed_identity_roles_core(
    client: &azapptoolkit_graph::GraphClient,
    managed_identity_id: &str,
    resource_app_id: &str,
    roles: &[String],
) -> Result<(Vec<String>, Vec<String>, Vec<String>), UiError> {
    let resource_sp = client
        .resolve_resource_sp(resource_app_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "resource",
                format!("resource app id {resource_app_id} not found in tenant"),
            )
        })?;

    // Existing assignments make the grant idempotent.
    let existing = client
        .list_app_role_assignments(managed_identity_id)
        .await?;

    let mut granted = Vec::new();
    let mut skipped = Vec::new();
    let mut failures = Vec::new();

    for role_value in roles {
        let Some(role) = resource_sp.app_roles.iter().find(|r| {
            &r.value == role_value && r.allowed_member_types.iter().any(|t| t == "Application")
        }) else {
            failures.push(format!(
                "{role_value}: not an application role on {}",
                resource_sp.display_name
            ));
            continue;
        };

        let already = existing
            .iter()
            .any(|a| a.resource_id == resource_sp.id && a.app_role_id == role.id);
        if already {
            skipped.push(role_value.clone());
            continue;
        }

        match client
            .grant_app_role(managed_identity_id, &resource_sp.id, &role.id)
            .await
        {
            Ok(_) => granted.push(role_value.clone()),
            Err(err) => failures.push(format!("{role_value}: {err}")),
        }
    }
    Ok((granted, skipped, failures))
}

/// Lists the Azure RBAC role assignments held by a managed identity across the
/// subscriptions the signed-in user can reach (via ARM). Complements the Graph
/// app-role view with the Azure-resource side of the identity's privilege.
///
/// Best effort: an ARM/consent failure on the subscription list surfaces as an
/// error (the UI degrades to "unavailable"); a failure on a single subscription
/// is logged and skipped so partial results still render. Role-definition names
/// are resolved (and cached) so the UI shows "Contributor", not a GUID.
#[tauri::command]
pub async fn list_managed_identity_azure_roles(
    state: State<'_, AppState>,
    tenant_id: String,
    principal_id: String,
) -> Result<AzureRolesResult, UiError> {
    // The role-definition names below are resolved from cache; a client
    // factory only builds token adapters, so it is not a session proof.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    // Acquire the ARM token up front so a missing-consent rejection surfaces as
    // the typed `consent_required` code before any ARM call, bound to the `arm`
    // feature the UI's interactive consent button requests. On success the
    // token is cached and the call below reuses it — no extra round trip on the
    // happy path.
    state
        .ensure_arm_token(&tenant_id)
        .await
        .map_err(UiError::from)?;

    let arm = state.arm_for(&tenant_id);
    let subscriptions = arm.list_subscriptions().await?;
    // Scan every subscription the signed-in user can reach so the Azure RBAC
    // picture is complete (no cap). Coverage is still tracked: `total` is what
    // the user can reach, `scanned` now equals it, and `skipped` counts scanned
    // subs whose role-assignment lookup failed — the only remaining source of a
    // partial view. Fan-out stays bounded by `ARM_CONCURRENCY`.
    let total = subscriptions.len();
    let scanned = total;
    let subs = subscriptions;

    // Fetch each subscription's assignments concurrently (bounded). A failed
    // subscription is logged and skipped (counted via `skipped`), not fatal —
    // `None` marks a failed lookup so partial results still render.
    let per_sub: Vec<(String, Option<Vec<RoleAssignment>>)> = stream::iter(subs)
        .map(|sub| {
            let arm = arm.clone();
            let principal_id = principal_id.clone();
            async move {
                let display = sub
                    .display_name
                    .clone()
                    .unwrap_or_else(|| sub.subscription_id.clone());
                match arm
                    .list_role_assignments_for_principal(&sub.subscription_id, &principal_id)
                    .await
                {
                    Ok(a) => (display, Some(a)),
                    Err(err) => {
                        tracing::warn!(?err, subscription = %sub.subscription_id, "arm: role-assignment lookup failed; skipping subscription");
                        (display, None)
                    }
                }
            }
        })
        .buffer_unordered(ARM_CONCURRENCY)
        .collect()
        .await;

    let skipped = per_sub.iter().filter(|(_, list)| list.is_none()).count();

    // Flatten, keeping each assignment's owning subscription display name and
    // collapsing the above-subscription copies every subscription returns.
    let flat = flatten_assignments(per_sub);

    // Resolve the role-definition ids to names (one fetch per role GUID,
    // cached per tenant — see `arm_roles`).
    let role_names = resolve_role_names_cached(
        &arm,
        &state.cache,
        &tenant_id,
        flat.iter()
            .filter_map(|(_, a)| a.properties.role_definition_id.as_deref()),
        ARM_CONCURRENCY,
    )
    .await;

    let mut rows: Vec<AzureRoleDto> = flat
        .into_iter()
        .map(|(sub_display, a)| {
            let scope = a.properties.scope.unwrap_or_default();
            let role_def_id = a.properties.role_definition_id.unwrap_or_default();
            let role_name = role_display_name(&role_names, &role_def_id);
            let high_privilege = is_high_privilege_role(&role_name, RoleContext::AzureResources);
            AzureRoleDto {
                scope_level: scope_level(&scope),
                role_name,
                scope,
                subscription: sub_display,
                high_privilege,
            }
        })
        .collect();

    // High-privilege roles first, then by name.
    rows.sort_by_key(|r| (std::cmp::Reverse(r.high_privilege), r.role_name.clone()));
    Ok(AzureRolesResult {
        roles: rows,
        scanned,
        total,
        skipped,
    })
}

/// The Subscription column's label for an assignment made above the
/// subscription level (a management group or the tenant root): every
/// subscription beneath it returns it, so no single subscription owns it.
const ABOVE_SUBSCRIPTION_LABEL: &str = "(inherited from above the subscription)";

/// Dedupe key for one role assignment: its ARM id (an absolute path embedding
/// the assignment's own scope, so identical whichever subscription surfaced
/// it), lowercased; `scope|roleDefinitionId|principalId` when the id is absent.
fn assignment_key(a: &RoleAssignment) -> String {
    match a.id.as_deref().filter(|id| !id.is_empty()) {
        Some(id) => id.to_ascii_lowercase(),
        None => {
            let p = &a.properties;
            format!(
                "{}|{}|{}",
                p.scope.as_deref().unwrap_or_default(),
                p.role_definition_id.as_deref().unwrap_or_default(),
                p.principal_id.as_deref().unwrap_or_default(),
            )
            .to_ascii_lowercase()
        }
    }
}

/// Flattens the per-subscription `principalId eq` results into one
/// `(subscription label, assignment)` list, each assignment once.
///
/// ARM's `principalId eq {id}` filter returns assignments **at, above or
/// below** the subscription queried, so a management-group or tenant-root
/// assignment comes back once per subscription beneath it — without this
/// dedupe one Reader on a management group over 20 subscriptions renders as
/// 20 rows. Such an above-subscription row is labelled
/// [`ABOVE_SUBSCRIPTION_LABEL`] rather than the subscription that happened to
/// return it first, so the output does not depend on the `buffer_unordered`
/// arrival order; a subscription-or-below assignment is only ever returned by
/// its own subscription, so first-wins is exact for it. An empty or absent
/// scope keeps the subscription label (where it sits is unknown). A failed
/// subscription (`None`) contributes nothing. `readiness.rs` needs no such
/// dedupe: it collects role GUIDs into a `HashSet`.
fn flatten_assignments(
    per_sub: Vec<(String, Option<Vec<RoleAssignment>>)>,
) -> Vec<(String, RoleAssignment)> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut flat = Vec::new();
    for (display, list) in per_sub {
        for a in list.into_iter().flatten() {
            if !seen.insert(assignment_key(&a)) {
                continue;
            }
            let above_subscription =
                a.properties.scope.as_deref().is_some_and(|scope| {
                    !scope.is_empty() && subscription_from_scope(scope).is_none()
                });
            let label = if above_subscription {
                ABOVE_SUBSCRIPTION_LABEL.to_string()
            } else {
                display.clone()
            };
            flat.push((label, a));
        }
    }
    flat
}

/// Extracts the subscription id from an ARM `scope` path
/// (`/subscriptions/{sub}/...`). `None` for a non-subscription scope (e.g. a
/// management group), which this assignment path doesn't support.
fn subscription_from_scope(scope: &str) -> Option<&str> {
    let mut segs = scope.split('/').filter(|s| !s.is_empty());
    while let Some(s) = segs.next() {
        if s.eq_ignore_ascii_case("subscriptions") {
            return segs.next().filter(|s| !s.is_empty());
        }
    }
    None
}

/// Creates an Azure RBAC role assignment for a managed identity (or any service
/// principal) at `scope` (a `/subscriptions/{sub}/...` path). `role_definition_id`
/// may be a bare built-in/custom role GUID or a full role-definition path; it is
/// normalized to the subscription-scoped ARM path. Pre-acquires the ARM token so
/// a missing-consent rejection surfaces as the typed `consent_required` (the UI
/// offers a "Grant consent" button); a 403 from lacking
/// `Microsoft.Authorization/roleAssignments/write` returns an actionable message.
#[tauri::command]
pub async fn assign_managed_identity_azure_role(
    state: State<'_, AppState>,
    tenant_id: String,
    scope: String,
    role_definition_id: String,
    principal_id: String,
) -> Result<(), UiError> {
    let scope = scope.trim();
    let subscription_id = subscription_from_scope(scope).ok_or_else(|| {
        UiError::validation(
            "invalid_scope",
            "Scope must be a /subscriptions/{id}/… path (subscription, resource group, or resource).",
        )
    })?;

    state
        .ensure_arm_token(&tenant_id)
        .await
        .map_err(UiError::from)?;

    let role_guid = role_definition_id
        .rsplit('/')
        .next()
        .unwrap_or(role_definition_id.as_str());
    let role_definition_path = format!(
        "/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_guid}"
    );
    let assignment_name = new_v4_guid();

    let arm = state.arm_for(&tenant_id);
    arm.create_role_assignment(
        scope,
        &assignment_name,
        &role_definition_path,
        &principal_id,
    )
    .await
    .map_err(|err| {
        let mut ui = UiError::from(err);
        if ui.code == "forbidden" {
            // Append the concrete scope so the user knows *where* the role is
            // needed; the guidance itself comes from the capability catalog.
            let base = forbidden_remediation(&ui, "azure_role_assign")
                .unwrap_or("Not authorized to create role assignments at this scope.");
            ui.message = format!("{base} (scope: {scope})");
        }
        ui
    })?;
    // An assignment at ANY level can change who can reach a vault — the Key
    // Vault sweep keeps the assignment's own scope, and a resource-group or
    // subscription grant covers every vault beneath it — so bust unconditionally
    // rather than only for a `/providers/Microsoft.KeyVault/vaults/` scope. One
    // key per tenant, refilled only by an explicit sweep: the bust costs nothing.
    crate::commands::keyvault_rbac::invalidate_kv_sweep(&state.cache, &tenant_id);
    Ok(())
}

/// Classifies an ARM scope string by level for display.
fn scope_level(scope: &str) -> String {
    let lower = scope.to_lowercase();
    if lower.contains("/resourcegroups/") {
        // A `/providers/.../<resource>` segment after the RG means resource scope.
        if lower.contains("/providers/") {
            "Resource".to_string()
        } else {
            "Resource group".to_string()
        }
    } else if lower.contains("/subscriptions/") {
        "Subscription".to_string()
    } else if lower.starts_with("/providers/microsoft.management") {
        "Management group".to_string()
    } else {
        "Other".to_string()
    }
}

// ---------------- Inventory export ----------------

/// Human label for a managed-identity sub-type, for the export's Subtype column
/// and the restore runbook's "not found" item.
pub(crate) fn mi_subtype_label(subtype: MiSubtype) -> &'static str {
    match subtype {
        MiSubtype::SystemAssigned => "System-assigned",
        MiSubtype::UserAssigned => "User-assigned",
        MiSubtype::Unknown => "Unknown",
    }
}

/// Serializes the managed-identity list as CSV for an access review. Display
/// names route through `csv_field` (formula-injection guard), reused from audit.
fn managed_identities_to_csv(rows: &[ManagedIdentityDto]) -> String {
    use crate::commands::export::csv_field;
    let mut out = String::new();
    out.push_str("DisplayName,AppId,ObjectId,Subtype,Enabled\n");
    for r in rows {
        let row = [
            csv_field(&r.display_name),
            csv_field(&r.app_id),
            csv_field(&r.id),
            csv_field(mi_subtype_label(r.mi_subtype)),
            r.account_enabled.map(|b| b.to_string()).unwrap_or_default(),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// Exports the (frontend-filtered) managed-identity list to a CSV/JSON file via
/// the OS save dialog. Rows are passed from the frontend so the export reflects
/// the active filters. Returns the path, or `None` if cancelled.
#[tauri::command]
pub async fn save_managed_identities_to_file(
    app_handle: AppHandle,
    rows: Vec<ManagedIdentityDto>,
    format: String,
) -> Result<Option<String>, UiError> {
    crate::commands::export::save_export_via_dialog(
        &app_handle,
        "managed-identities",
        &format,
        || managed_identities_to_csv(&rows),
        || serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string()),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_arm::ArmError;

    fn mi_row(name: &str, subtype: MiSubtype) -> ManagedIdentityDto {
        ManagedIdentityDto {
            id: "sp-1".into(),
            app_id: "app-1".into(),
            display_name: name.into(),
            account_enabled: Some(true),
            mi_subtype: subtype,
        }
    }

    #[test]
    fn mi_csv_has_header_subtype_label_and_neutralizes_injection() {
        let csv = managed_identities_to_csv(&[
            mi_row("mi-prod", MiSubtype::UserAssigned),
            mi_row("=cmd", MiSubtype::SystemAssigned),
        ]);
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines[0], "DisplayName,AppId,ObjectId,Subtype,Enabled");
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("User-assigned"));
        assert!(!lines[2].starts_with('='));
    }

    fn ra(id: Option<&str>, scope: &str, roledef: &str) -> RoleAssignment {
        RoleAssignment {
            id: id.map(str::to_string),
            properties: azapptoolkit_arm::RoleAssignmentProperties {
                role_definition_id: Some(roledef.to_string()),
                scope: Some(scope.to_string()),
                principal_id: Some("mi-principal".to_string()),
                principal_type: None,
            },
        }
    }

    #[test]
    fn flatten_dedupes_a_management_group_assignment_returned_by_every_subscription() {
        const MG: &str = "/providers/Microsoft.Management/managementGroups/mg";
        let mg_id = format!("{MG}/providers/Microsoft.Authorization/roleAssignments/ra-1");
        let rg = "/subscriptions/sub-1/resourceGroups/rg";
        let rg_id = format!("{rg}/providers/Microsoft.Authorization/roleAssignments/ra-2");
        let prod = (
            "Prod".to_string(),
            Some(vec![
                ra(Some(&mg_id), MG, "/roleDefinitions/reader"),
                ra(Some(&rg_id), rg, "/roleDefinitions/contributor"),
            ]),
        );
        let dev = (
            "Dev".to_string(),
            Some(vec![ra(Some(&mg_id), MG, "/roleDefinitions/reader")]),
        );
        let broken = ("Broken".to_string(), None);

        // `per_sub` arrives in `buffer_unordered` order: the result must not
        // depend on which subscription returned the MG row first.
        for per_sub in [
            vec![prod.clone(), dev.clone(), broken.clone()],
            vec![dev.clone(), broken.clone(), prod.clone()],
        ] {
            let flat = flatten_assignments(per_sub);
            assert_eq!(flat.len(), 2, "one row per assignment: {flat:?}");
            let label_of = |id: &str| {
                flat.iter()
                    .find(|(_, a)| a.id.as_deref() == Some(id))
                    .map(|(label, _)| label.clone())
                    .expect("row present")
            };
            assert_eq!(label_of(&mg_id), ABOVE_SUBSCRIPTION_LABEL);
            assert_eq!(label_of(&rg_id), "Prod");
        }
    }

    #[test]
    fn flatten_dedupes_ids_case_insensitively_and_falls_back_to_scope_role_principal() {
        let sub = "/subscriptions/sub-1";
        let flat = flatten_assignments(vec![
            (
                "Prod".to_string(),
                Some(vec![
                    ra(
                        Some("/subscriptions/sub-1/providers/x/ra-1"),
                        sub,
                        "/rd/reader",
                    ),
                    ra(None, sub, "/rd/owner"),
                    ra(None, sub, "/rd/contributor"),
                ]),
            ),
            (
                "Prod again".to_string(),
                Some(vec![
                    ra(
                        Some("/SUBSCRIPTIONS/SUB-1/providers/X/RA-1"),
                        sub,
                        "/rd/reader",
                    ),
                    ra(None, "/Subscriptions/Sub-1", "/RD/Owner"),
                ]),
            ),
        ]);
        let roledefs: Vec<&str> = flat
            .iter()
            .map(|(_, a)| a.properties.role_definition_id.as_deref().unwrap())
            .collect();
        // Same id in a different case collapses; two id-less copies with the
        // same scope/role/principal collapse; a different role is kept.
        assert_eq!(roledefs, ["/rd/reader", "/rd/owner", "/rd/contributor"]);
        assert!(flat.iter().all(|(label, _)| label == "Prod"));
    }

    #[test]
    fn scope_level_classifies_arm_scope_strings() {
        assert_eq!(scope_level("/subscriptions/sub-1"), "Subscription");
        assert_eq!(
            scope_level("/subscriptions/sub-1/resourceGroups/rg-1"),
            "Resource group"
        );
        assert_eq!(
            scope_level(
                "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Storage/storageAccounts/acct"
            ),
            "Resource"
        );
        assert_eq!(
            scope_level("/providers/Microsoft.Management/managementGroups/mg-1"),
            "Management group"
        );
        assert_eq!(scope_level(""), "Other");
    }

    #[test]
    fn subscription_from_scope_extracts_the_subscription_id() {
        assert_eq!(
            subscription_from_scope("/subscriptions/sub-1"),
            Some("sub-1")
        );
        assert_eq!(
            subscription_from_scope("/subscriptions/sub-1/resourceGroups/rg/providers/x/y/z"),
            Some("sub-1")
        );
        // A management-group scope has no subscription segment.
        assert_eq!(
            subscription_from_scope("/providers/Microsoft.Management/managementGroups/mg-1"),
            None
        );
        assert_eq!(subscription_from_scope(""), None);
    }

    #[test]
    fn scope_level_is_case_insensitive() {
        // ARM scope casing is not guaranteed; the classifier lowercases first.
        assert_eq!(
            scope_level("/SUBSCRIPTIONS/sub-1/RESOURCEGROUPS/rg-1"),
            "Resource group"
        );
    }

    #[test]
    fn arm_error_converts_to_ui_with_code_and_retryable() {
        // The dto `From<ArmError>` impl carries the error's ui_code + retryable.
        let ui = UiError::from(ArmError::Throttled {
            retry_after_secs: Some(3),
        });
        assert_eq!(ui.code, "throttled");
        assert!(ui.retryable);

        let ui = UiError::from(ArmError::Forbidden("denied".into()));
        assert_eq!(ui.code, "forbidden");
        assert!(!ui.retryable);
        assert!(ui.message.contains("denied"));
    }
}
