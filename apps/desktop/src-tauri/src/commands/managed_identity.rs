//! Managed-identity commands.
//!
//! Managed identities are service principals (`servicePrincipalType ==
//! "ManagedIdentity"`). Granting one an application permission is an app-role
//! assignment on that service principal — the same Graph operation used for
//! ordinary admin consent, just targeting the managed identity's SP as the
//! principal. Mirrors the legacy `Get-AzManagedIdentity` /
//! `Grant-AzManagedIdentityPermission` cmdlets.

use std::collections::{HashMap, HashSet};

use futures::stream::{self, StreamExt};
use tauri::{AppHandle, State};

use azapptoolkit_arm::RoleAssignment;
use azapptoolkit_core::cache::CacheKind;

use crate::dto::managed_identity::{
    AzureRoleDto, AzureRolesResult, GrantManagedIdentityResult, ManagedIdentityDto, MiSubtype,
};
use crate::dto::UiError;
use crate::state::AppState;

/// Broadly-privileged built-in Azure roles flagged in the MI RBAC view.
const HIGH_PRIVILEGE_ROLES: &[&str] = &[
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Role Based Access Control Administrator",
];
/// Max concurrent ARM calls (per-subscription fetches + role-def resolution).
/// Bounds fan-out so scanning every subscription stays within ARM's rate limits
/// (429s are retried with backoff in the client); a large estate just takes
/// proportionally longer rather than truncating the result.
const ARM_CONCURRENCY: usize = 8;

fn mi_key(tenant_id: &str) -> String {
    format!("{tenant_id}|mi")
}

/// Lists managed-identity service principals in the tenant.
#[tauri::command]
pub async fn list_managed_identities(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<ManagedIdentityDto>, UiError> {
    let key = mi_key(&tenant_id);
    if let Some(cached) = state
        .cache
        .get::<Vec<ManagedIdentityDto>>(CacheKind::Lists, &key)
    {
        tracing::debug!(target = "azapptoolkit::cache", kind = "Lists", key = %key, "hit");
        return Ok(cached);
    }
    tracing::debug!(target = "azapptoolkit::cache", kind = "Lists", key = %key, "miss");

    let client = state.graph_for(&tenant_id);
    let identities = client.list_managed_identities().await?;
    let rows: Vec<ManagedIdentityDto> = identities
        .into_iter()
        .map(|sp| {
            let mi_subtype = MiSubtype::from_alternative_names(&sp.alternative_names);
            ManagedIdentityDto {
                id: sp.id,
                app_id: sp.app_id,
                display_name: sp.display_name,
                account_enabled: sp.account_enabled,
                mi_subtype,
            }
        })
        .collect();

    state.cache.put(CacheKind::Lists, key, &rows);
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
    // No cache bust: the cached `{tenant}|mi` list holds only identity rows
    // (id/name/enabled), which a grant doesn't change; the MI's held grants are
    // read live, and granting a new mail permission yields a new `mail_scopes`
    // key (no stale verdict). The audit scans only app registrations.
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
    // Acquire the ARM token up front so a missing-consent rejection surfaces as
    // the typed `consent_required` code (the UI offers an interactive consent
    // button) instead of being flattened to a generic `token_error` deep inside
    // the ARM client. On success the token is cached and the call below reuses
    // it — no extra round trip on the happy path.
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

    // Flatten, keeping each assignment's owning subscription display name.
    let flat: Vec<(String, RoleAssignment)> = per_sub
        .into_iter()
        .flat_map(|(display, list)| {
            list.unwrap_or_default()
                .into_iter()
                .map(move |a| (display.clone(), a))
        })
        .collect();

    // Resolve the unique role-definition ids to names concurrently.
    let unique_ids: HashSet<String> = flat
        .iter()
        .filter_map(|(_, a)| a.properties.role_definition_id.clone())
        .filter(|id| !id.is_empty())
        .collect();
    let cache = state.cache.clone();
    let role_names: HashMap<String, String> = stream::iter(unique_ids)
        .map(|id| {
            let arm = arm.clone();
            let cache = cache.clone();
            let tenant_id = tenant_id.clone();
            async move {
                // Role definitions (Owner, Contributor, custom roles) are
                // tenant-stable, so cache the resolved name — otherwise every
                // managed-identity Azure-RBAC view re-fetches the same handful
                // (and ARM throttles aggressively). Only a real name is cached;
                // a fetch failure falls back to the GUID tail without poisoning.
                // Read-only until TTL / sign-out by design: a role-definition
                // rename is rare, so no mutation busts this — it's cleared by the
                // 60-min Permissions TTL and the sign-out tenant sweep.
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

    let mut rows: Vec<AzureRoleDto> =
        flat.into_iter()
            .map(|(sub_display, a)| {
                let scope = a.properties.scope.unwrap_or_default();
                let role_def_id = a.properties.role_definition_id.unwrap_or_default();
                let role_name = if role_def_id.is_empty() {
                    "(unknown role)".to_string()
                } else {
                    role_names.get(&role_def_id).cloned().unwrap_or_else(|| {
                        role_def_id.rsplit('/').next().unwrap_or("role").to_string()
                    })
                };
                let high_privilege = HIGH_PRIVILEGE_ROLES.contains(&role_name.as_str());
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

/// A random v4 GUID for a role-assignment name. ARM requires the *client* to
/// supply the assignment's GUID name; generating it here makes the PUT idempotent
/// (a retry reuses the same name rather than creating a duplicate).
fn new_role_assignment_guid() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1 (RFC 4122)
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
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
    let assignment_name = new_role_assignment_guid();

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
            // Single copy of the role guidance lives in the capability catalog;
            // append the concrete scope so the user knows *where* it's needed.
            let base = azapptoolkit_core::capabilities::capability("azure_role_assign")
                .map(|c| c.remediation)
                .unwrap_or("Not authorized to create role assignments at this scope.");
            ui.message = format!("{base} (scope: {scope})");
        }
        ui
    })?;
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

/// Human label for a managed-identity sub-type, for the export's Subtype column.
fn mi_subtype_label(subtype: MiSubtype) -> &'static str {
    match subtype {
        MiSubtype::SystemAssigned => "System-assigned",
        MiSubtype::UserAssigned => "User-assigned",
        MiSubtype::Unknown => "Unknown",
    }
}

/// Serializes the managed-identity list as CSV for an access review. Display
/// names route through `csv_field` (formula-injection guard), reused from audit.
fn managed_identities_to_csv(rows: &[ManagedIdentityDto]) -> String {
    use crate::commands::audit::csv_field;
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
    crate::commands::audit::save_export_via_dialog(
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
    fn role_assignment_guid_is_well_formed_v4() {
        let g = new_role_assignment_guid();
        assert_eq!(g.len(), 36);
        let parts: Vec<&str> = g.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        assert!(g.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        // Version nibble is 4; variant nibble is 8/9/a/b.
        assert_eq!(&parts[2][0..1], "4");
        assert!(matches!(&parts[3][0..1], "8" | "9" | "a" | "b"));
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
