//! Application-management IPC bindings: organization, list/get/create/update/
//! delete applications, owners, password & certificate credentials, search.

use azapptoolkit_core::models::{
    Application, DirectoryObject, Organization, Paged, PasswordCredential,
};
use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::applications::*;

// ---------------- Reads ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantArg<'a> {
    tenant_id: &'a str,
}

pub async fn get_organization(tenant_id: &str) -> Result<Organization, UiError> {
    invoke_result("get_organization", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListApplicationsArgs<'a> {
    tenant_id: &'a str,
    search: Option<&'a str>,
    top: Option<u32>,
}

pub async fn list_applications(
    tenant_id: &str,
    search: Option<&str>,
    top: Option<u32>,
) -> Result<Paged<Application>, UiError> {
    invoke_result(
        "list_applications",
        ListApplicationsArgs {
            tenant_id,
            search,
            top,
        },
    )
    .await
}

/// Returns the full set of app registrations (paginated to completion on the
/// backend, bounded by a safety cap) as lean list rows, each paired with its
/// Enterprise App SP id. Search/date/credential filtering happens caller-side
/// over this result — a keystroke never re-enters Graph.
pub async fn list_applications_with_pairing(
    tenant_id: &str,
) -> Result<Vec<ApplicationListRowDto>, UiError> {
    invoke_result("list_applications_with_pairing", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectIdArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
}

pub async fn get_application_detail(
    tenant_id: &str,
    object_id: &str,
) -> Result<ApplicationDetail, UiError> {
    invoke_result(
        "get_application_detail",
        ObjectIdArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

/// Drops the cached detail payload for a single application so the next
/// `get_application_detail` re-fetches from Graph. Backs the detail-pane
/// Refresh button.
pub async fn invalidate_application_detail(
    tenant_id: &str,
    object_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "invalidate_application_detail",
        ObjectIdArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResolvePermissionArgs<'a> {
    tenant_id: &'a str,
    resource_app_id: &'a str,
    permission_id: &'a str,
}

pub async fn resolve_permission(
    tenant_id: &str,
    resource_app_id: &str,
    permission_id: &str,
) -> Result<PermissionDescriptor, UiError> {
    invoke_result(
        "resolve_permission",
        ResolvePermissionArgs {
            tenant_id,
            resource_app_id,
            permission_id,
        },
    )
    .await
}

// ---------------- Mutations ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateAppArgs<'a> {
    tenant_id: &'a str,
    input: &'a CreateApplicationInput,
}

pub async fn create_application(
    tenant_id: &str,
    input: &CreateApplicationInput,
) -> Result<CreateApplicationResult, UiError> {
    invoke_result("create_application", CreateAppArgs { tenant_id, input }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateAppArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    patch: &'a UpdateApplicationInput,
}

pub async fn update_application(
    tenant_id: &str,
    object_id: &str,
    patch: &UpdateApplicationInput,
) -> Result<(), UiError> {
    invoke_result(
        "update_application",
        UpdateAppArgs {
            tenant_id,
            object_id,
            patch,
        },
    )
    .await
}

pub async fn delete_application(tenant_id: &str, object_id: &str) -> Result<(), UiError> {
    invoke_result(
        "delete_application",
        ObjectIdArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnerArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    principal_id: &'a str,
}

pub async fn add_application_owner(
    tenant_id: &str,
    object_id: &str,
    principal_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "add_application_owner",
        OwnerArgs {
            tenant_id,
            object_id,
            principal_id,
        },
    )
    .await
}

pub async fn remove_application_owner(
    tenant_id: &str,
    object_id: &str,
    principal_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_application_owner",
        OwnerArgs {
            tenant_id,
            object_id,
            principal_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetOwnersArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    principal_ids: &'a [String],
}

pub async fn set_application_owners(
    tenant_id: &str,
    object_id: &str,
    principal_ids: &[String],
) -> Result<SetOwnersResult, UiError> {
    invoke_result(
        "set_application_owners",
        SetOwnersArgs {
            tenant_id,
            object_id,
            principal_ids,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SearchUsersArgs<'a> {
    tenant_id: &'a str,
    query: &'a str,
}

pub async fn search_users(tenant_id: &str, query: &str) -> Result<Vec<DirectoryObject>, UiError> {
    invoke_result("search_users", SearchUsersArgs { tenant_id, query }).await
}

pub async fn search_groups(tenant_id: &str, query: &str) -> Result<Vec<DirectoryObject>, UiError> {
    invoke_result("search_groups", SearchUsersArgs { tenant_id, query }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddPasswordArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    input: &'a AddPasswordInput,
}

pub async fn add_password(
    tenant_id: &str,
    object_id: &str,
    input: &AddPasswordInput,
) -> Result<PasswordCredential, UiError> {
    invoke_result(
        "add_password",
        AddPasswordArgs {
            tenant_id,
            object_id,
            input,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyIdArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    key_id: &'a str,
}

pub async fn remove_password(
    tenant_id: &str,
    object_id: &str,
    key_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_password",
        KeyIdArgs {
            tenant_id,
            object_id,
            key_id,
        },
    )
    .await
}

pub async fn remove_expired_passwords(
    tenant_id: &str,
    object_id: &str,
) -> Result<RemoveExpiredResult, UiError> {
    invoke_result(
        "remove_expired_passwords",
        ObjectIdArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddCertArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    input: &'a AddCertificateInput,
}

pub async fn add_certificate_credential(
    tenant_id: &str,
    object_id: &str,
    input: &AddCertificateInput,
) -> Result<(), UiError> {
    invoke_result(
        "add_certificate_credential",
        AddCertArgs {
            tenant_id,
            object_id,
            input,
        },
    )
    .await
}

pub async fn remove_certificate_credential(
    tenant_id: &str,
    object_id: &str,
    key_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_certificate_credential",
        KeyIdArgs {
            tenant_id,
            object_id,
            key_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateCertArgs<'a> {
    tenant_id: &'a str,
    input: &'a GenerateCertificateInput,
}

pub async fn generate_self_signed_certificate(
    tenant_id: &str,
    input: &GenerateCertificateInput,
) -> Result<GeneratedCertificateResult, UiError> {
    invoke_result(
        "generate_self_signed_certificate",
        GenerateCertArgs { tenant_id, input },
    )
    .await
}

// ---------------- Authentication (redirect URIs + flow toggles) ----------------

/// Reads the Authentication-tab settings (per-platform reply URLs, logout URL,
/// implicit-grant flags, fallback-public-client flag).
pub async fn get_application_authentication(
    tenant_id: &str,
    object_id: &str,
) -> Result<ApplicationAuthenticationDto, UiError> {
    invoke_result(
        "get_application_authentication",
        ObjectIdArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetAuthArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    input: &'a SetApplicationAuthenticationInput,
}

/// Full-replace write of the Authentication-tab settings.
pub async fn set_application_authentication(
    tenant_id: &str,
    object_id: &str,
    input: &SetApplicationAuthenticationInput,
) -> Result<(), UiError> {
    invoke_result(
        "set_application_authentication",
        SetAuthArgs {
            tenant_id,
            object_id,
            input,
        },
    )
    .await
}

// ---------------- Federated identity credentials ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FederatedListArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
}

pub async fn list_federated_credentials(
    tenant_id: &str,
    object_id: &str,
) -> Result<Vec<FederatedCredentialDto>, UiError> {
    invoke_result(
        "list_federated_credentials",
        FederatedListArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddFederatedArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    input: &'a AddFederatedCredentialInput,
}

pub async fn add_federated_credential(
    tenant_id: &str,
    object_id: &str,
    input: &AddFederatedCredentialInput,
) -> Result<FederatedCredentialDto, UiError> {
    invoke_result(
        "add_federated_credential",
        AddFederatedArgs {
            tenant_id,
            object_id,
            input,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateFederatedArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    credential_id: &'a str,
    input: &'a UpdateFederatedCredentialInput,
}

/// Updates a federated credential in place (`name` is immutable in Graph).
pub async fn update_federated_credential(
    tenant_id: &str,
    object_id: &str,
    credential_id: &str,
    input: &UpdateFederatedCredentialInput,
) -> Result<(), UiError> {
    invoke_result(
        "update_federated_credential",
        UpdateFederatedArgs {
            tenant_id,
            object_id,
            credential_id,
            input,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveFederatedArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    credential_id: &'a str,
}

pub async fn remove_federated_credential(
    tenant_id: &str,
    object_id: &str,
    credential_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_federated_credential",
        RemoveFederatedArgs {
            tenant_id,
            object_id,
            credential_id,
        },
    )
    .await
}

// ---------------- Inventory export ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveApplicationsArgs<'a> {
    rows: &'a [ApplicationListRowDto],
    format: &'a str,
}

/// Exports the (filtered) app-registration list to a CSV/JSON file via the OS
/// save dialog. Returns the chosen path, or `None` if the user cancelled.
pub async fn save_applications_to_file(
    rows: &[ApplicationListRowDto],
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result(
        "save_applications_to_file",
        SaveApplicationsArgs { rows, format },
    )
    .await
}
