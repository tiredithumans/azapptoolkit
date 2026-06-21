//! Enterprise-application IPC bindings.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

use crate::bindings::TenantArg;
pub use azapptoolkit_dto::enterprise_application::*;

pub async fn list_enterprise_applications(
    tenant_id: &str,
) -> Result<Vec<EnterpriseApplicationDto>, UiError> {
    invoke_result("list_enterprise_applications", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DetailArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
}

pub async fn get_enterprise_application_detail(
    tenant_id: &str,
    service_principal_id: &str,
) -> Result<EnterpriseApplicationDetail, UiError> {
    invoke_result(
        "get_enterprise_application_detail",
        DetailArgs {
            tenant_id,
            service_principal_id,
        },
    )
    .await
}

/// Lists the users/groups assigned to this enterprise application's app roles.
pub async fn list_enterprise_app_assignments(
    tenant_id: &str,
    service_principal_id: &str,
) -> Result<Vec<AppAssignmentDto>, UiError> {
    invoke_result(
        "list_enterprise_app_assignments",
        DetailArgs {
            tenant_id,
            service_principal_id,
        },
    )
    .await
}

/// Deletes the enterprise application's service principal. Destructive — the UI
/// guards this behind explicit confirmation.
pub async fn delete_enterprise_application(
    tenant_id: &str,
    service_principal_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "delete_enterprise_application",
        DetailArgs {
            tenant_id,
            service_principal_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    principal_id: &'a str,
    app_role_id: &'a str,
}

/// Grants a principal access to the enterprise application (assigns it to a role).
pub async fn assign_enterprise_app_access(
    tenant_id: &str,
    service_principal_id: &str,
    principal_id: &str,
    app_role_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "assign_enterprise_app_access",
        AssignArgs {
            tenant_id,
            service_principal_id,
            principal_id,
            app_role_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveAccessArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    assignment_id: &'a str,
}

/// Revokes a principal's access to the enterprise application.
pub async fn remove_enterprise_app_access(
    tenant_id: &str,
    service_principal_id: &str,
    assignment_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_enterprise_app_access",
        RemoveAccessArgs {
            tenant_id,
            service_principal_id,
            assignment_id,
        },
    )
    .await
}

/// Lists the groups this service principal is a direct member of — the
/// outbound direction (the reverse of `list_enterprise_app_assignments`).
pub async fn list_sp_group_memberships(
    tenant_id: &str,
    service_principal_id: &str,
) -> Result<Vec<GroupMembershipDto>, UiError> {
    invoke_result(
        "list_sp_group_memberships",
        DetailArgs {
            tenant_id,
            service_principal_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupMembershipArgs<'a> {
    tenant_id: &'a str,
    group_id: &'a str,
    service_principal_id: &'a str,
}

/// Adds the service principal as a member of the group. Fails with
/// `consent_required` until `GroupMember.ReadWrite.All` is consented.
pub async fn add_sp_to_group(
    tenant_id: &str,
    group_id: &str,
    service_principal_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "add_sp_to_group",
        GroupMembershipArgs {
            tenant_id,
            group_id,
            service_principal_id,
        },
    )
    .await
}

/// Removes the service principal from the group. Same consent contract as
/// `add_sp_to_group`.
pub async fn remove_sp_from_group(
    tenant_id: &str,
    group_id: &str,
    service_principal_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_sp_from_group",
        GroupMembershipArgs {
            tenant_id,
            group_id,
            service_principal_id,
        },
    )
    .await
}

/// SCIM provisioning job status for the enterprise application (best effort —
/// empty = not configured; an error means the scope/license is unavailable).
pub async fn get_enterprise_app_provisioning(
    tenant_id: &str,
    service_principal_id: &str,
) -> Result<Vec<ProvisioningJobDto>, UiError> {
    invoke_result(
        "get_enterprise_app_provisioning",
        DetailArgs {
            tenant_id,
            service_principal_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VisibilityArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    hidden: bool,
}

/// Hides/shows the enterprise application on the My Apps portal (`HideApp` tag).
pub async fn set_enterprise_app_visibility(
    tenant_id: &str,
    service_principal_id: &str,
    hidden: bool,
) -> Result<(), UiError> {
    invoke_result(
        "set_enterprise_app_visibility",
        VisibilityArgs {
            tenant_id,
            service_principal_id,
            hidden,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountEnabledArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    enabled: bool,
}

/// Enables/disables user sign-in for the app (`accountEnabled`).
pub async fn set_enterprise_app_account_enabled(
    tenant_id: &str,
    service_principal_id: &str,
    enabled: bool,
) -> Result<(), UiError> {
    invoke_result(
        "set_enterprise_app_account_enabled",
        AccountEnabledArgs {
            tenant_id,
            service_principal_id,
            enabled,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AssignmentRequiredArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    required: bool,
}

/// Sets whether user assignment is required (`appRoleAssignmentRequired`).
pub async fn set_enterprise_app_assignment_required(
    tenant_id: &str,
    service_principal_id: &str,
    required: bool,
) -> Result<(), UiError> {
    invoke_result(
        "set_enterprise_app_assignment_required",
        AssignmentRequiredArgs {
            tenant_id,
            service_principal_id,
            required,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NotesArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    notes: &'a str,
}

/// Sets the free-text management `notes` (empty string clears it).
pub async fn set_enterprise_app_notes(
    tenant_id: &str,
    service_principal_id: &str,
    notes: &str,
) -> Result<(), UiError> {
    invoke_result(
        "set_enterprise_app_notes",
        NotesArgs {
            tenant_id,
            service_principal_id,
            notes,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    principal_id: &'a str,
}

/// Adds a user as an owner of the enterprise application's service principal.
pub async fn add_enterprise_app_owner(
    tenant_id: &str,
    service_principal_id: &str,
    principal_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "add_enterprise_app_owner",
        OwnerArgs {
            tenant_id,
            service_principal_id,
            principal_id,
        },
    )
    .await
}

/// Removes an owner from the enterprise application's service principal.
pub async fn remove_enterprise_app_owner(
    tenant_id: &str,
    service_principal_id: &str,
    principal_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_enterprise_app_owner",
        OwnerArgs {
            tenant_id,
            service_principal_id,
            principal_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppRolesListArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    app_id: &'a str,
}

/// Reads the enterprise app's exposed app roles plus where they're defined
/// (`application` when a local app registration backs the SP, else
/// `servicePrincipal`).
pub async fn list_enterprise_app_roles(
    tenant_id: &str,
    service_principal_id: &str,
    app_id: &str,
) -> Result<AppRolesView, UiError> {
    invoke_result(
        "list_enterprise_app_roles",
        AppRolesListArgs {
            tenant_id,
            service_principal_id,
            app_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpsertAppRoleArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    app_id: &'a str,
    input: &'a AppRoleInput,
}

/// Creates (`input.id = None`) or updates one exposed app role.
pub async fn upsert_enterprise_app_role(
    tenant_id: &str,
    service_principal_id: &str,
    app_id: &str,
    input: &AppRoleInput,
) -> Result<(), UiError> {
    invoke_result(
        "upsert_enterprise_app_role",
        UpsertAppRoleArgs {
            tenant_id,
            service_principal_id,
            app_id,
            input,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteAppRoleArgs<'a> {
    tenant_id: &'a str,
    service_principal_id: &'a str,
    app_id: &'a str,
    role_id: &'a str,
}

/// Deletes one exposed app role (disabling it first when needed).
pub async fn delete_enterprise_app_role(
    tenant_id: &str,
    service_principal_id: &str,
    app_id: &str,
    role_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "delete_enterprise_app_role",
        DeleteAppRoleArgs {
            tenant_id,
            service_principal_id,
            app_id,
            role_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveEnterpriseArgs<'a> {
    rows: &'a [EnterpriseApplicationDto],
    format: &'a str,
}

/// Exports the (filtered) enterprise-application list to a CSV/JSON file via the
/// OS save dialog. Returns the chosen path, or `None` if the user cancelled.
pub async fn save_enterprise_applications_to_file(
    rows: &[EnterpriseApplicationDto],
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result(
        "save_enterprise_applications_to_file",
        SaveEnterpriseArgs { rows, format },
    )
    .await
}
