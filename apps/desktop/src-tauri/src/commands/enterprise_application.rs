//! Enterprise-application commands.
//!
//! Surfaces non-managed-identity service principals — first-party Microsoft
//! SPs, gallery apps, and foreign-tenant apps the user has consented to. Each
//! row is paired with its local App Registration (if one exists) via a single
//! batched index call so the list view can render the cross-tab jump arrow
//! without per-row Graph round trips.

use std::collections::HashMap;

use tauri::{AppHandle, State};

use azapptoolkit_core::cache::CacheKind;
use azapptoolkit_core::models::{ServicePrincipal, SynchronizationJob};
use azapptoolkit_graph::GraphError;

use crate::commands::applications::{enterprise_key, invalidate_app_lists, sp_index_key};
use crate::dto::UiError;
use crate::dto::enterprise_application::{
    AppAssignmentDto, EnterpriseApplicationDetail, EnterpriseApplicationDto, GroupMembershipDto,
    ProvisioningJobDto,
};
use crate::state::AppState;

/// Builds an [`EnterpriseApplicationDto`] from a service principal. `tenant_id`
/// drives the foreign-tenant flag; `paired_app_registration_id` is resolved by
/// the caller (a batched index in the list, a single lookup in the detail).
/// Shared so the field projection lives in one place.
fn sp_to_enterprise_dto(
    sp: ServicePrincipal,
    tenant_id: &str,
    paired_app_registration_id: Option<String>,
) -> EnterpriseApplicationDto {
    let is_foreign_tenant = sp
        .app_owner_organization_id
        .as_deref()
        .is_some_and(|owner| !owner.eq_ignore_ascii_case(tenant_id));
    EnterpriseApplicationDto {
        id: sp.id,
        app_id: sp.app_id,
        display_name: sp.display_name,
        account_enabled: sp.account_enabled,
        app_role_assignment_required: sp.app_role_assignment_required,
        service_principal_type: sp.service_principal_type,
        app_owner_organization_id: sp.app_owner_organization_id,
        is_foreign_tenant,
        paired_app_registration_id,
        password_credentials: sp.password_credentials,
        key_credentials: sp.key_credentials,
        app_roles: sp.app_roles,
        oauth2_permission_scopes: sp.oauth2_permission_scopes,
        created_date_time: sp.created_date_time,
        tags: sp.tags,
        notes: sp.notes,
    }
}

/// Lists enterprise-application service principals in the tenant, paired with
/// their matching App Registration object ids when one exists locally.
#[tauri::command]
pub async fn list_enterprise_applications(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<EnterpriseApplicationDto>, UiError> {
    let key = enterprise_key(&tenant_id);
    if let Some(cached) = state
        .cache
        .get::<Vec<EnterpriseApplicationDto>>(CacheKind::Lists, &key)
    {
        tracing::debug!(target = "azapptoolkit::cache", kind = "Lists", key = %key, "hit");
        return Ok(cached);
    }
    tracing::debug!(target = "azapptoolkit::cache", kind = "Lists", key = %key, "miss");

    let client = state.graph_for(&tenant_id);

    // Both the rows and the pairing index come from whole-tenant scans. Reuse
    // the shared SP index (cached across both list views); on a cold miss fetch
    // it concurrently with the app-registration pairing index so the two scans
    // overlap. The SP index is unfiltered (it is shared with the App
    // Registrations join), so filter managed identities out below — matching
    // the prior server-side `servicePrincipalType ne 'ManagedIdentity'`.
    let index_key = sp_index_key(&tenant_id);
    let (sps, app_reg_index_pairs) = match state
        .cache
        .get::<Vec<ServicePrincipal>>(CacheKind::Lists, &index_key)
    {
        Some(cached) => (cached, client.list_application_index(Some(5000)).await?),
        None => {
            let (sps, pairs) = futures::future::try_join(
                client.list_service_principals_index(),
                client.list_application_index(Some(5000)),
            )
            .await?;
            state.cache.put(CacheKind::Lists, index_key, &sps);
            (sps, pairs)
        }
    };

    let by_app_id: HashMap<String, String> = app_reg_index_pairs.into_iter().collect();

    let rows: Vec<EnterpriseApplicationDto> = sps
        .into_iter()
        .filter(|sp| sp.service_principal_type.as_deref() != Some("ManagedIdentity"))
        .map(|sp| {
            let paired = by_app_id.get(&sp.app_id).cloned();
            sp_to_enterprise_dto(sp, &tenant_id, paired)
        })
        .collect();

    state.cache.put(CacheKind::Lists, key, &rows);
    Ok(rows)
}

#[tauri::command]
pub async fn get_enterprise_application_detail(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<EnterpriseApplicationDetail, UiError> {
    let client = state.graph_for(&tenant_id);

    let sp = client
        .get_service_principal_by_object_id(&service_principal_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "service_principal",
                format!("service principal {service_principal_id} not found"),
            )
        })?;

    let paired_app_registration_id = client
        .find_application_by_app_id(&sp.app_id)
        .await?
        .map(|a| a.id);

    // Best-effort: a transient failure or a 403 must not blank the whole detail
    // pane, but log it rather than letting it read as "this app has no owners".
    let owners = client
        .list_service_principal_owners(&service_principal_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!(%service_principal_id, error = %e, "failed to load enterprise-app owners; showing none");
            Vec::new()
        });

    // The full SP from get_service_principal_by_object_id carries all fields.
    let dto = sp_to_enterprise_dto(sp, &tenant_id, paired_app_registration_id);

    Ok(EnterpriseApplicationDetail {
        service_principal: dto,
        owners,
    })
}

/// Lists the principals (users/groups) assigned to this enterprise application —
/// the "who has access" view (`appRoleAssignedTo`). Role ids are resolved to
/// names client-side against the SP's `app_roles` (already loaded by the detail).
#[tauri::command]
pub async fn list_enterprise_app_assignments(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<Vec<AppAssignmentDto>, UiError> {
    let client = state.graph_for(&tenant_id);
    let assignments = client
        .list_app_role_assigned_to(&service_principal_id)
        .await?;
    Ok(assignments
        .into_iter()
        .map(|a| AppAssignmentDto {
            assignment_id: a.id,
            principal_display_name: a.principal_display_name,
            principal_type: a.principal_type,
            app_role_id: a.app_role_id,
        })
        .collect())
}

/// Grants a principal (user/group) access to an enterprise application by
/// assigning it to one of the app's roles. `app_role_id` may be the all-zero
/// GUID for the "default access" assignment.
#[tauri::command]
pub async fn assign_enterprise_app_access(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    principal_id: String,
    app_role_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client
        .assign_app_role_to(&service_principal_id, &principal_id, &app_role_id)
        .await?;
    // No cache bust: app-role assignments to an enterprise app are read live
    // (the detail pane's "who has access" is uncached) and appear in no cached
    // list/audit payload (the audit reads roles held ON the Graph resource SP,
    // not who is assigned to this app).
    Ok(())
}

/// Revokes a principal's access to an enterprise application by removing its
/// app-role assignment.
#[tauri::command]
pub async fn remove_enterprise_app_access(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    assignment_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client
        .remove_app_role_assigned_to(&service_principal_id, &assignment_id)
        .await?;
    // No cache bust: same as assign_enterprise_app_access — the assignment list
    // is read live and is in no cached list/detail/audit payload.
    Ok(())
}

/// Lists the groups this service principal is a **direct member of** — the
/// outbound direction (the reverse of [`list_enterprise_app_assignments`]).
/// Group-gated APIs (e.g. Power BI's "Service principals can use Fabric APIs"
/// tenant setting) admit SPs via security-group membership, so integrations
/// commonly need the SP added to a group right after creation. Reads ride the
/// sign-in read scope; not cached (mirrors the assignments list).
#[tauri::command]
pub async fn list_sp_group_memberships(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<Vec<GroupMembershipDto>, UiError> {
    let client = state.graph_for(&tenant_id);
    let groups = client
        .list_service_principal_groups(&service_principal_id)
        .await?;
    Ok(groups.into_iter().map(map_group_membership).collect())
}

/// Adds the service principal as a member of `group_id`. Pre-acquires the
/// `GroupMember.ReadWrite.All` token with a typed call so a not-yet-consented
/// scope reaches the UI as `consent_required` (the panel offers "Grant
/// consent & retry") instead of a flattened `token_error`.
#[tauri::command]
pub async fn add_sp_to_group(
    state: State<'_, AppState>,
    tenant_id: String,
    group_id: String,
    service_principal_id: String,
) -> Result<(), UiError> {
    state
        .ensure_group_member_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);
    client
        .add_group_member(&group_id, &service_principal_id)
        .await
        .map_err(group_membership_err)?;
    // No cache bust: SP group memberships are read live (list_sp_group_memberships
    // is uncached) and appear in no cached list/detail/audit payload.
    Ok(())
}

/// Removes the service principal from `group_id`. Same token contract as
/// [`add_sp_to_group`].
#[tauri::command]
pub async fn remove_sp_from_group(
    state: State<'_, AppState>,
    tenant_id: String,
    group_id: String,
    service_principal_id: String,
) -> Result<(), UiError> {
    state
        .ensure_group_member_token(&tenant_id)
        .await
        .map_err(UiError::from)?;
    let client = state.graph_for(&tenant_id);
    client
        .remove_group_member(&group_id, &service_principal_id)
        .await
        .map_err(group_membership_err)?;
    // No cache bust: same as add_sp_to_group — memberships are read live, in no
    // cached payload.
    Ok(())
}

/// Maps a group-membership Graph failure to a `UiError`, appending the
/// capability catalog's remediation to a 403 (mechanism 1 of the role-feedback
/// catalog — a membership 403 is unambiguous enough to name the role).
fn group_membership_err(e: GraphError) -> UiError {
    let forbidden = matches!(e, GraphError::Forbidden(_));
    let mut err = UiError::from(e);
    if forbidden && let Some(cap) = azapptoolkit_core::capabilities::capability("group_membership")
    {
        err.message = format!("{} {}", err.message, cap.remediation);
    }
    err
}

fn map_group_membership(g: azapptoolkit_core::models::GroupSummary) -> GroupMembershipDto {
    GroupMembershipDto {
        display_name: g.display_name.unwrap_or_else(|| g.id.clone()),
        id: g.id,
        security_enabled: g.security_enabled,
        group_types: g.group_types,
    }
}

/// Returns the enterprise application's SCIM provisioning job status (best
/// effort). An empty list means provisioning isn't configured (Graph 404); a
/// hard error means the `Synchronization.Read.All` scope / license is missing,
/// which the UI surfaces as a graceful "unavailable" message.
#[tauri::command]
pub async fn get_enterprise_app_provisioning(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<Vec<ProvisioningJobDto>, UiError> {
    let client = state.graph_for(&tenant_id);
    match client
        .list_synchronization_jobs(&service_principal_id)
        .await
    {
        Ok(jobs) => Ok(jobs.into_iter().map(map_provisioning_job).collect()),
        // Not configured for this SP — surface as "no provisioning", not an error.
        Err(GraphError::NotFound(_)) => Ok(Vec::new()),
        Err(e) => Err(e.into()),
    }
}

/// Hides or shows the enterprise application on the My Apps portal by toggling
/// the `HideApp` tag. Fetches the current tags first so the rest are preserved.
#[tauri::command]
pub async fn set_enterprise_app_visibility(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    hidden: bool,
) -> Result<(), UiError> {
    const HIDE_APP: &str = "HideApp";
    let client = state.graph_for(&tenant_id);
    let sp = client
        .get_service_principal_by_object_id(&service_principal_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "service_principal",
                format!("service principal {service_principal_id} not found"),
            )
        })?;

    let mut tags: Vec<String> = sp.tags.into_iter().filter(|t| t != HIDE_APP).collect();
    if hidden {
        tags.push(HIDE_APP.to_string());
    }
    client
        .set_service_principal_tags(&service_principal_id, &tags)
        .await?;
    // The `HideApp` tag is cached in the enterprise list DTO (and the shared SP
    // index it derives from), so bust the list caches on success per the
    // invalidate-on-Ok rule — otherwise the toggle stays stale until the TTL.
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(())
}

/// Enables or disables user sign-in for the enterprise application by setting
/// `accountEnabled` on its service principal. Disabling stops all token issuance
/// for the app (the portal's "Enabled for users to sign in?" toggle). Busts the
/// list caches on success — `accountEnabled` is on the enterprise list DTO and
/// the shared SP index it derives from.
#[tauri::command]
pub async fn set_enterprise_app_account_enabled(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    enabled: bool,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    let body = serde_json::json!({ "accountEnabled": enabled });
    client
        .patch_service_principal(&service_principal_id, &body)
        .await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(())
}

/// Sets `appRoleAssignmentRequired` on the service principal (the portal's
/// "Assignment required?" toggle). When `true`, only assigned users/services can
/// obtain a token for the app. Busts the list caches on success — the flag is on
/// the enterprise list DTO and the shared SP index.
#[tauri::command]
pub async fn set_enterprise_app_assignment_required(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    required: bool,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    let body = serde_json::json!({ "appRoleAssignmentRequired": required });
    client
        .patch_service_principal(&service_principal_id, &body)
        .await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(())
}

/// Sets the free-text management `notes` on the service principal (max 1024
/// chars; an empty string clears it to `null`). No cache bust: `notes` is read
/// live on the (uncached) detail and is on no cached list/audit payload.
#[tauri::command]
pub async fn set_enterprise_app_notes(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    notes: String,
) -> Result<(), UiError> {
    let trimmed = notes.trim();
    if trimmed.chars().count() > 1024 {
        return Err(UiError::validation(
            "invalid_notes",
            "Notes can be at most 1024 characters.",
        ));
    }
    let client = state.graph_for(&tenant_id);
    // Empty ⇒ JSON null clears the field; otherwise store the trimmed text.
    let body = serde_json::json!({
        "notes": if trimmed.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(trimmed.to_string()) }
    });
    client
        .patch_service_principal(&service_principal_id, &body)
        .await?;
    Ok(())
}

/// Adds a user as an owner of the enterprise application's service principal.
/// Only users can own a service principal (groups can't), so the UI searches
/// users only. No cache bust: SP owners are read live on the (uncached) detail
/// and appear in no cached list/audit payload.
#[tauri::command]
pub async fn add_enterprise_app_owner(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    principal_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client
        .add_service_principal_owner(&service_principal_id, &principal_id)
        .await?;
    Ok(())
}

/// Removes an owner from the enterprise application's service principal. No cache
/// bust (same rationale as [`add_enterprise_app_owner`]).
#[tauri::command]
pub async fn remove_enterprise_app_owner(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    principal_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client
        .remove_service_principal_owner(&service_principal_id, &principal_id)
        .await?;
    Ok(())
}

/// Deletes an enterprise application's service principal
/// (`DELETE /servicePrincipals/{id}`). Destructive: removing a first-party or
/// foreign-tenant SP can break tenant-wide sign-in or orphan consent, so the UI
/// guards this behind an explicit confirmation (with an extra warning for those
/// SP kinds) and never offers it for managed identities (their lifecycle is
/// owned by the Azure resource). Busts the list caches on success.
#[tauri::command]
pub async fn delete_enterprise_application(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client
        .delete_service_principal(&service_principal_id)
        .await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    Ok(())
}

// ---------------- Inventory export ----------------

/// Serializes the enterprise-application list as CSV for an access review.
/// Credentials aren't on the list index (`$select`), so they're omitted here —
/// per-app credentials live on the detail. Display names route through
/// `csv_field` (formula-injection guard), reused from the audit export.
fn enterprise_apps_to_csv(rows: &[EnterpriseApplicationDto]) -> String {
    use crate::commands::export::csv_field;
    let mut out = String::new();
    out.push_str(
        "DisplayName,AppId,ObjectId,Enabled,ForeignTenant,AppOwnerOrgId,PairedAppRegistrationId,Created\n",
    );
    for r in rows {
        let row = [
            csv_field(&r.display_name),
            csv_field(&r.app_id),
            csv_field(&r.id),
            r.account_enabled.map(|b| b.to_string()).unwrap_or_default(),
            r.is_foreign_tenant.to_string(),
            csv_field(r.app_owner_organization_id.as_deref().unwrap_or("")),
            csv_field(r.paired_app_registration_id.as_deref().unwrap_or("")),
            csv_field(
                &r.created_date_time
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            ),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}

/// Exports the (frontend-filtered) enterprise-application list to a CSV/JSON
/// file via the OS save dialog. Rows are passed from the frontend so the export
/// reflects the active filters. Returns the path, or `None` if cancelled.
#[tauri::command]
pub async fn save_enterprise_applications_to_file(
    app_handle: AppHandle,
    rows: Vec<EnterpriseApplicationDto>,
    format: String,
) -> Result<Option<String>, UiError> {
    crate::commands::export::save_export_via_dialog(
        &app_handle,
        "enterprise-applications",
        &format,
        || enterprise_apps_to_csv(&rows),
        || serde_json::to_string_pretty(&rows).unwrap_or_else(|_| "[]".to_string()),
    )
    .await
}

fn map_provisioning_job(j: SynchronizationJob) -> ProvisioningJobDto {
    let status = j.status;
    let last_exec = status.as_ref().and_then(|s| s.last_execution.clone());
    ProvisioningJobDto {
        id: j.id,
        template_id: j.template_id,
        status_code: status.as_ref().and_then(|s| s.code.clone()),
        last_state: last_exec.as_ref().and_then(|e| e.state.clone()),
        last_run: last_exec
            .as_ref()
            .and_then(|e| e.time_ended.map(|d| d.to_rfc3339())),
        quarantine_reason: status
            .as_ref()
            .and_then(|s| s.quarantine.as_ref().and_then(|q| q.reason.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::models::{
        SynchronizationExecution, SynchronizationQuarantine, SynchronizationStatus,
    };
    use chrono::{TimeZone, Utc};

    #[test]
    fn maps_a_fully_populated_provisioning_job() {
        let job = SynchronizationJob {
            id: "job-1".into(),
            template_id: Some("AzureAD2AAD".into()),
            status: Some(SynchronizationStatus {
                code: Some("Active".into()),
                last_execution: Some(SynchronizationExecution {
                    state: Some("Succeeded".into()),
                    time_ended: Some(Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap()),
                }),
                quarantine: Some(SynchronizationQuarantine {
                    reason: Some("EncounteredBaseEscrowThreshold".into()),
                }),
            }),
        };
        let dto = map_provisioning_job(job);
        assert_eq!(dto.id, "job-1");
        assert_eq!(dto.template_id.as_deref(), Some("AzureAD2AAD"));
        assert_eq!(dto.status_code.as_deref(), Some("Active"));
        assert_eq!(dto.last_state.as_deref(), Some("Succeeded"));
        assert_eq!(dto.last_run.as_deref(), Some("2026-05-01T12:00:00+00:00"));
        assert_eq!(
            dto.quarantine_reason.as_deref(),
            Some("EncounteredBaseEscrowThreshold")
        );
    }

    #[test]
    fn maps_a_job_with_no_status_to_all_none() {
        // A job that has never run carries no status — every derived field
        // must flatten to None rather than panic on the nested Options.
        let dto = map_provisioning_job(SynchronizationJob {
            id: "job-2".into(),
            template_id: None,
            status: None,
        });
        assert_eq!(dto.id, "job-2");
        assert!(dto.status_code.is_none());
        assert!(dto.last_state.is_none());
        assert!(dto.last_run.is_none());
        assert!(dto.quarantine_reason.is_none());
    }

    #[test]
    fn maps_group_membership_with_display_name_fallback() {
        use azapptoolkit_core::models::GroupSummary;
        let dto = map_group_membership(GroupSummary {
            id: "g-1".into(),
            display_name: Some("PowerBI-SPs".into()),
            security_enabled: Some(true),
            group_types: vec![],
        });
        assert_eq!(dto.display_name, "PowerBI-SPs");
        assert_eq!(dto.security_enabled, Some(true));

        // A group the caller can't read the name of falls back to its id
        // rather than rendering an empty cell.
        let dto = map_group_membership(GroupSummary {
            id: "g-2".into(),
            display_name: None,
            security_enabled: None,
            group_types: vec!["Unified".into(), "DynamicMembership".into()],
        });
        assert_eq!(dto.display_name, "g-2");
        assert_eq!(dto.group_types.len(), 2);
    }

    fn ent_row(name: &str) -> EnterpriseApplicationDto {
        EnterpriseApplicationDto {
            id: "sp-1".into(),
            app_id: "app-1".into(),
            display_name: name.into(),
            account_enabled: Some(true),
            app_role_assignment_required: None,
            service_principal_type: Some("Application".into()),
            app_owner_organization_id: Some("home-tenant".into()),
            is_foreign_tenant: false,
            paired_app_registration_id: Some("appreg-1".into()),
            password_credentials: Vec::new(),
            key_credentials: Vec::new(),
            app_roles: Vec::new(),
            oauth2_permission_scopes: Vec::new(),
            created_date_time: None,
            tags: Vec::new(),
            notes: None,
        }
    }

    #[test]
    fn enterprise_csv_has_header_and_neutralizes_injection() {
        let csv = enterprise_apps_to_csv(&[ent_row("App A"), ent_row("=HYPERLINK(1)")]);
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("DisplayName,AppId,ObjectId,Enabled"));
        assert_eq!(lines.len(), 3); // header + 2 rows
        assert!(lines[1].starts_with("App A,"));
        // Formula-injection in the display name is defused.
        assert!(!lines[2].starts_with('='));
    }
}
