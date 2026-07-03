//! Audit remediation IPC bindings — one-click fixes invoked from the audit view.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::exchange::ExchangeAccessResult;
pub use azapptoolkit_dto::remediation::{RedundantPermissionsOutcome, RemediationOutcome};
pub use azapptoolkit_dto::sharepoint::SiteScopeResult;

/// Args shared by the fixes that target one app registration and re-resolve
/// everything else live (remove-expired-credentials, remove-redundant-permissions).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppTargetArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
}

/// Removes every currently-expired secret/certificate from one app registration.
/// The backend re-resolves the live expired set before acting, so a stale audit
/// snapshot can't target the wrong credential.
pub async fn remediate_remove_expired_credentials(
    tenant_id: &str,
    object_id: &str,
) -> Result<RemediationOutcome, UiError> {
    invoke_result(
        "remediate_remove_expired_credentials",
        AppTargetArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

/// Removes the app's redundant application permissions — narrower permissions a
/// broader held permission already fully covers. The backend re-plans the
/// removable set from the live manifest + grants, so a stale audit snapshot
/// can't remove a permission whose covering grant has since gone away.
pub async fn remediate_remove_redundant_permissions(
    tenant_id: &str,
    object_id: &str,
) -> Result<RedundantPermissionsOutcome, UiError> {
    invoke_result(
        "remediate_remove_redundant_permissions",
        AppTargetArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

/// Disables sign-in for an unused app by setting `accountEnabled: false` on its
/// service principal — reversible from the enterprise app's Overview toggle.
/// The backend re-resolves the SP from the live application.
pub async fn remediate_disable_sign_in(tenant_id: &str, object_id: &str) -> Result<(), UiError> {
    invoke_result(
        "remediate_disable_sign_in",
        AppTargetArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeMailboxArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    permissions: &'a [String],
    groups: &'a [String],
}

/// Confines an app's org-wide mailbox permissions to `groups` via Exchange RBAC.
/// The backend delegates to the shared grant-before-strip scoping core.
pub async fn remediate_scope_mailbox_access(
    tenant_id: &str,
    object_id: &str,
    permissions: &[String],
    groups: &[String],
) -> Result<ExchangeAccessResult, UiError> {
    invoke_result(
        "remediate_scope_mailbox_access",
        ScopeMailboxArgs {
            tenant_id,
            object_id,
            permissions,
            groups,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeSharePointArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    site_urls: &'a [String],
    role: &'a str,
}

/// Converts an app's org-wide `Sites.*` access to `Sites.Selected` on `site_urls`.
/// The backend resolves the service principal and delegates to the shared
/// convert-to-selected core (grant per-site access before stripping the broad grant).
pub async fn remediate_scope_sharepoint_access(
    tenant_id: &str,
    object_id: &str,
    site_urls: &[String],
    role: &str,
) -> Result<SiteScopeResult, UiError> {
    invoke_result(
        "remediate_scope_sharepoint_access",
        ScopeSharePointArgs {
            tenant_id,
            object_id,
            site_urls,
            role,
        },
    )
    .await
}
