//! Bulk-operation IPC bindings. Progress streams live in
//! `bindings::events::bulk_progress`.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::{invoke, invoke_result};

pub use azapptoolkit_dto::bulk::*;

/// Signals the in-flight bulk action to stop at the next item boundary. Shares
/// the audit cancel flag on the backend; returns nothing (fire-and-forget).
pub async fn cancel_bulk() {
    invoke::<()>("cancel_bulk", ()).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveExpiredArgs<'a> {
    tenant_id: &'a str,
    /// `None` sweeps the whole tenant; `Some` scopes the sweep to these apps.
    object_ids: Option<&'a [String]>,
}

pub async fn bulk_remove_expired_credentials(
    tenant_id: &str,
    object_ids: Option<&[String]>,
) -> Result<BulkRemoveExpiredResult, UiError> {
    invoke_result(
        "bulk_remove_expired_credentials",
        RemoveExpiredArgs {
            tenant_id,
            object_ids,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkDeleteArgs<'a> {
    tenant_id: &'a str,
    object_ids: &'a [String],
}

pub async fn bulk_delete_applications(
    tenant_id: &str,
    object_ids: &[String],
) -> Result<BulkDeleteResult, UiError> {
    invoke_result(
        "bulk_delete_applications",
        BulkDeleteArgs {
            tenant_id,
            object_ids,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkGrantArgs<'a> {
    tenant_id: &'a str,
    object_ids: &'a [String],
}

pub async fn bulk_grant_permissions(
    tenant_id: &str,
    object_ids: &[String],
) -> Result<BulkGrantResult, UiError> {
    invoke_result(
        "bulk_grant_permissions",
        BulkGrantArgs {
            tenant_id,
            object_ids,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkCreateArgs<'a> {
    tenant_id: &'a str,
    specs: &'a [BulkCreateSpec],
    validate_only: bool,
}

pub async fn bulk_create_applications(
    tenant_id: &str,
    specs: &[BulkCreateSpec],
    validate_only: bool,
) -> Result<BulkCreateResult, UiError> {
    invoke_result(
        "bulk_create_applications",
        BulkCreateArgs {
            tenant_id,
            specs,
            validate_only,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkObjectIdsArgs<'a> {
    tenant_id: &'a str,
    object_ids: &'a [String],
}

pub async fn bulk_remove_redundant_permissions(
    tenant_id: &str,
    object_ids: &[String],
) -> Result<BulkRemoveRedundantResult, UiError> {
    invoke_result(
        "bulk_remove_redundant_permissions",
        BulkObjectIdsArgs {
            tenant_id,
            object_ids,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkScopeMailboxArgs<'a> {
    tenant_id: &'a str,
    object_ids: &'a [String],
    groups: &'a [String],
}

pub async fn bulk_scope_mailbox_access(
    tenant_id: &str,
    object_ids: &[String],
    groups: &[String],
) -> Result<BulkScopeResult, UiError> {
    invoke_result(
        "bulk_scope_mailbox_access",
        BulkScopeMailboxArgs {
            tenant_id,
            object_ids,
            groups,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkScopeSharePointArgs<'a> {
    tenant_id: &'a str,
    object_ids: &'a [String],
    site_urls: &'a [String],
    role: &'a str,
}

pub async fn bulk_scope_sharepoint_access(
    tenant_id: &str,
    object_ids: &[String],
    site_urls: &[String],
    role: &str,
) -> Result<BulkScopeResult, UiError> {
    invoke_result(
        "bulk_scope_sharepoint_access",
        BulkScopeSharePointArgs {
            tenant_id,
            object_ids,
            site_urls,
            role,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkAddOwnerArgs<'a> {
    tenant_id: &'a str,
    object_ids: &'a [String],
    principal_id: &'a str,
}

/// Adds one directory principal as an owner of each selected app. Already-owner
/// apps are reported `skipped` (the backend pre-reads live owners).
pub async fn bulk_add_owner(
    tenant_id: &str,
    object_ids: &[String],
    principal_id: &str,
) -> Result<BulkAddOwnerResult, UiError> {
    invoke_result(
        "bulk_add_owner",
        BulkAddOwnerArgs {
            tenant_id,
            object_ids,
            principal_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BulkDisableSignInArgs<'a> {
    tenant_id: &'a str,
    object_ids: &'a [String],
}

/// Disables sign-in for each selected app (sets `accountEnabled: false` on its
/// service principal) — reversible from the enterprise app's Overview toggle.
pub async fn bulk_disable_sign_in(
    tenant_id: &str,
    object_ids: &[String],
) -> Result<BulkDisableSignInResult, UiError> {
    invoke_result(
        "bulk_disable_sign_in",
        BulkDisableSignInArgs {
            tenant_id,
            object_ids,
        },
    )
    .await
}
