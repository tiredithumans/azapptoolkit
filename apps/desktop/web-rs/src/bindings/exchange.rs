//! Exchange Online RBAC-for-Applications IPC bindings: grant/list/remove scoped
//! mailbox access and migrate legacy Application Access Policies. DTOs come
//! from the shared `azapptoolkit-dto` crate (re-exported here for callers).

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::exchange::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
    permissions: Option<&'a [String]>,
    groups: &'a [String],
    remove_unscoped_entra_grants: bool,
}

/// Scopes an app's mailbox access via Exchange RBAC. `permissions = None` scopes
/// every declared mail permission (the coarse "scope all" action in the
/// Exchange scoping section); `Some` scopes only the listed values (the
/// per-permission "Scope…" action).
pub async fn grant_exchange_mailbox_access(
    tenant_id: &str,
    object_id: &str,
    permissions: Option<&[String]>,
    groups: &[String],
    remove_unscoped_entra_grants: bool,
) -> Result<ExchangeAccessResult, UiError> {
    invoke_result(
        "grant_exchange_mailbox_access",
        GrantArgs {
            tenant_id,
            object_id,
            permissions,
            groups,
            remove_unscoped_entra_grants,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MiScopeArgs<'a> {
    tenant_id: &'a str,
    managed_identity_id: &'a str,
    app_id: &'a str,
    app_display_name: &'a str,
    mail_permissions: &'a [String],
    groups: &'a [String],
    remove_unscoped_entra_grants: bool,
}

/// Scopes a managed identity's mail permission(s) to mailbox group(s) via
/// Exchange RBAC for Applications. Mirrors `grant_exchange_mailbox_access` but
/// targets the permissions being granted rather than an app manifest.
#[allow(clippy::too_many_arguments)]
pub async fn grant_managed_identity_scoped_exchange_access(
    tenant_id: &str,
    managed_identity_id: &str,
    app_id: &str,
    app_display_name: &str,
    mail_permissions: &[String],
    groups: &[String],
    remove_unscoped_entra_grants: bool,
) -> Result<ExchangeAccessResult, UiError> {
    invoke_result(
        "grant_managed_identity_scoped_exchange_access",
        MiScopeArgs {
            tenant_id,
            managed_identity_id,
            app_id,
            app_display_name,
            mail_permissions,
            groups,
            remove_unscoped_entra_grants,
        },
    )
    .await
}

pub async fn list_exchange_role_assignments(
    tenant_id: &str,
    app_id: &str,
) -> Result<Vec<ExchangeRoleAssignmentDto>, UiError> {
    invoke_result(
        "list_exchange_role_assignments",
        AppArgs { tenant_id, app_id },
    )
    .await
}

pub async fn remove_exchange_mailbox_access(
    tenant_id: &str,
    app_id: &str,
) -> Result<ExchangeAccessRemovalResult, UiError> {
    invoke_result(
        "remove_exchange_mailbox_access",
        AppArgs { tenant_id, app_id },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
    mailboxes: &'a [String],
}

/// State of the toolkit-managed scope group (`azapptoolkit_<appId>`): whether it
/// exists, how to reference it, and its current members. Degrades to a
/// `consent_required` / 403 error when the caller isn't an Exchange admin.
pub async fn list_exchange_scope_group(
    tenant_id: &str,
    app_id: &str,
) -> Result<ExchangeScopeGroupDto, UiError> {
    invoke_result("list_exchange_scope_group", AppArgs { tenant_id, app_id }).await
}

/// Adds mailboxes to the managed scope group, creating it on first use.
pub async fn add_exchange_scope_group_members(
    tenant_id: &str,
    app_id: &str,
    mailboxes: &[String],
) -> Result<ExchangeMemberMutationResult, UiError> {
    invoke_result(
        "add_exchange_scope_group_members",
        MemberArgs {
            tenant_id,
            app_id,
            mailboxes,
        },
    )
    .await
}

/// Removes mailboxes from the managed scope group.
pub async fn remove_exchange_scope_group_members(
    tenant_id: &str,
    app_id: &str,
    mailboxes: &[String],
) -> Result<ExchangeMemberMutationResult, UiError> {
    invoke_result(
        "remove_exchange_scope_group_members",
        MemberArgs {
            tenant_id,
            app_id,
            mailboxes,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectArgs<'a> {
    tenant_id: &'a str,
    object_id: &'a str,
}

/// Per-permission effective mailbox scoping for an app's declared mail/calendar/
/// contacts permissions. Degrades gracefully: when the signed-in user is not an
/// Exchange admin, every entry's scope is `Unknown` rather than an error.
pub async fn get_mail_permission_scopes(
    tenant_id: &str,
    object_id: &str,
) -> Result<Vec<MailScopeEntry>, UiError> {
    invoke_result(
        "get_mail_permission_scopes",
        ObjectArgs {
            tenant_id,
            object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrincipalScopeArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
    permissions: &'a [String],
}

/// Effective mailbox scoping for a service principal (by `app_id`) given the
/// Graph permission values it holds — used for principals with no app
/// registration manifest, notably managed identities. Degrades to `Unknown`.
pub async fn get_mail_scopes_for_principal(
    tenant_id: &str,
    app_id: &str,
    permissions: &[String],
) -> Result<Vec<MailScopeEntry>, UiError> {
    invoke_result(
        "get_mail_scopes_for_principal",
        PrincipalScopeArgs {
            tenant_id,
            app_id,
            permissions,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MigrateArgs<'a> {
    tenant_id: &'a str,
    app_id: Option<&'a str>,
    dry_run: bool,
}

pub async fn migrate_application_access_policies(
    tenant_id: &str,
    app_id: Option<&str>,
    dry_run: bool,
) -> Result<AapMigrationReport, UiError> {
    invoke_result(
        "migrate_application_access_policies",
        MigrateArgs {
            tenant_id,
            app_id,
            dry_run,
        },
    )
    .await
}
