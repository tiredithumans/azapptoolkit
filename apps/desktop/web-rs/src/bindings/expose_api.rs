//! "Expose an API" IPC bindings: Application ID URIs, the delegated scopes the
//! app defines, and pre-authorized client applications.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::expose_api::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectIdArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
}

/// Live read of the app's Expose-an-API state (these fields aren't on the
/// cached list shape).
pub async fn get_expose_api(tenant_id: &str, object_id: &str) -> Result<ExposeApiDto, UiError> {
    invoke_result(
        "get_expose_api",
        ObjectIdArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetUrisArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    uris: &'a [String],
}

/// Full-replace write of the Application ID URIs — callers send the complete
/// desired list (loaded from `get_expose_api`).
pub async fn set_identifier_uris(
    tenant_id: &str,
    object_id: &str,
    uris: &[String],
) -> Result<(), UiError> {
    invoke_result(
        "set_identifier_uris",
        SetUrisArgs {
            tenant_id,
            object_id,
            uris,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpsertScopeArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    input: &'a UpsertApiScopeInput,
}

/// Creates (`input.id = None`) or updates one delegated scope.
pub async fn upsert_api_scope(
    tenant_id: &str,
    object_id: &str,
    input: &UpsertApiScopeInput,
) -> Result<(), UiError> {
    invoke_result(
        "upsert_api_scope",
        UpsertScopeArgs {
            tenant_id,
            object_id,
            input,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeleteScopeArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    scope_id: &'a str,
}

/// Deletes one delegated scope (the backend disables it first when needed and
/// strips it from pre-authorized clients).
pub async fn delete_api_scope(
    tenant_id: &str,
    object_id: &str,
    scope_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "delete_api_scope",
        DeleteScopeArgs {
            tenant_id,
            object_id,
            scope_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetPreAuthorizedArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    input: &'a SetPreAuthorizedAppInput,
}

/// Adds or updates a pre-authorized client (`scope_ids` is the full set the
/// client may use — a replace, not a merge).
pub async fn set_pre_authorized_app(
    tenant_id: &str,
    object_id: &str,
    input: &SetPreAuthorizedAppInput,
) -> Result<(), UiError> {
    invoke_result(
        "set_pre_authorized_app",
        SetPreAuthorizedArgs {
            tenant_id,
            object_id,
            input,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemovePreAuthorizedArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    client_app_id: &'a str,
}

/// Removes a pre-authorized client application.
pub async fn remove_pre_authorized_app(
    tenant_id: &str,
    object_id: &str,
    client_app_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_pre_authorized_app",
        RemovePreAuthorizedArgs {
            tenant_id,
            object_id,
            client_app_id,
        },
    )
    .await
}
