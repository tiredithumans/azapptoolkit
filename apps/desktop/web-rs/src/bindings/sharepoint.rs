//! SharePoint Selected-permission IPC bindings. DTOs come from the shared
//! `azapptoolkit-dto` crate (re-exported here for callers).

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

use crate::bindings::TenantArg;
pub use azapptoolkit_dto::sharepoint::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
    app_display_name: &'a str,
    site_url: &'a str,
    roles: &'a [String],
}

/// Grants a service principal access to a SharePoint site.
pub async fn grant_site_access(
    tenant_id: &str,
    app_id: &str,
    app_display_name: &str,
    site_url: &str,
    roles: &[String],
) -> Result<GrantSiteAccessResult, UiError> {
    invoke_result(
        "grant_site_access",
        GrantArgs {
            tenant_id,
            app_id,
            app_display_name,
            site_url,
            roles,
        },
    )
    .await
}

/// Runs the tenant-wide site-permission sweep (long-running; progress arrives
/// via the `site-sweep-progress` event stream — see `bindings::events`).
pub async fn sweep_site_permissions(tenant_id: &str) -> Result<SiteSweepResult, UiError> {
    invoke_result("sweep_site_permissions", TenantArg { tenant_id }).await
}

/// Signals the in-progress resource sweep/probe (site sweep or mailbox probe)
/// to stop at the next dispatch boundary.
pub async fn cancel_resource_sweep() -> Result<(), UiError> {
    invoke_result("cancel_resource_sweep", ()).await
}

/// The cached sweep for this tenant, if one completed within the cache TTL.
pub async fn get_cached_site_sweep(tenant_id: &str) -> Result<Option<SiteSweepResult>, UiError> {
    invoke_result("get_cached_site_sweep", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppSiteAccessArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
}

/// The sites this principal can reach under `Sites.Selected`, with the roles it
/// holds on each — projected backend-side out of the cached tenant sweep, so
/// this stays a small payload. `None` = no completed sweep is cached; the caller
/// offers to run one (`sweep_site_permissions`) and projects the fresh result
/// with `AppSiteAccessDto::from_sweep` instead.
pub async fn get_app_site_access(
    tenant_id: &str,
    app_id: &str,
) -> Result<Option<AppSiteAccessDto>, UiError> {
    invoke_result(
        "get_app_site_access",
        AppSiteAccessArgs { tenant_id, app_id },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListArgs<'a> {
    tenant_id: &'a str,
    site_url: &'a str,
}

pub async fn list_site_permissions(
    tenant_id: &str,
    site_url: &str,
) -> Result<Vec<SitePermissionDto>, UiError> {
    invoke_result(
        "list_site_permissions",
        ListArgs {
            tenant_id,
            site_url,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveArgs<'a> {
    tenant_id: &'a str,
    site_url: &'a str,
    permission_id: &'a str,
}

pub async fn remove_site_permission(
    tenant_id: &str,
    site_url: &str,
    permission_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_site_permission",
        RemoveArgs {
            tenant_id,
            site_url,
            permission_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConvertArgs<'a> {
    tenant_id: &'a str,
    sp_object_id: &'a str,
    /// The app-registration object id, when the principal has one — `None` for a
    /// bare service principal (enterprise app / managed identity), which has no
    /// manifest to declare the permission on.
    object_id: Option<&'a str>,
    app_id: &'a str,
    app_display_name: &'a str,
    site_urls: &'a [String],
    role: &'a str,
    remove_orgwide: bool,
}

/// Restricts a service principal's already-held org-wide `Sites.*` access to the
/// `Sites.Selected` model on specific sites. Works for app registrations and
/// managed identities alike (the caller supplies the SP object id + app id).
#[allow(clippy::too_many_arguments)]
pub async fn convert_site_access_to_selected(
    tenant_id: &str,
    sp_object_id: &str,
    object_id: Option<&str>,
    app_id: &str,
    app_display_name: &str,
    site_urls: &[String],
    role: &str,
    remove_orgwide: bool,
) -> Result<SiteScopeResult, UiError> {
    invoke_result(
        "convert_site_access_to_selected",
        ConvertArgs {
            tenant_id,
            sp_object_id,
            object_id,
            app_id,
            app_display_name,
            site_urls,
            role,
            remove_orgwide,
        },
    )
    .await
}

// ---------------- Sub-site Selected scopes ----------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResourceUrlArgs<'a> {
    tenant_id: &'a str,
    url: &'a str,
}

/// Resolves a SharePoint URL to the securable a Selected grant would address.
///
/// The panel calls this **before** offering to grant, so the operator sees
/// *"Folder · Finance / Documents / Invoices / 2026"* rather than discovering
/// after the fact that a grant landed somewhere else — and so a level mismatch
/// is caught while it is still a correctable typo.
pub async fn resolve_sharepoint_resource(
    tenant_id: &str,
    url: &str,
) -> Result<SharePointResourceRef, UiError> {
    invoke_result(
        "resolve_sharepoint_resource",
        ResourceUrlArgs { tenant_id, url },
    )
    .await
}

/// The application permissions on the resource `url` names.
///
/// A **verify-by-URL** read: there is no `appId → items` reverse lookup, so an
/// empty result means "this resource has no app grants", never "this app has no
/// item-level access".
pub async fn list_selected_item_permissions(
    tenant_id: &str,
    url: &str,
) -> Result<Vec<SelectedItemPermissionDto>, UiError> {
    invoke_result(
        "list_selected_item_permissions",
        ResourceUrlArgs { tenant_id, url },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoveSelectedItemArgs<'a> {
    tenant_id: &'a str,
    url: &'a str,
    permission_id: &'a str,
}

pub async fn remove_selected_item_permission(
    tenant_id: &str,
    url: &str,
    permission_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_selected_item_permission",
        RemoveSelectedItemArgs {
            tenant_id,
            url,
            permission_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GrantSelectedItemArgs<'a> {
    tenant_id: &'a str,
    sp_object_id: &'a str,
    /// See [`ConvertArgs::object_id`].
    object_id: Option<&'a str>,
    app_id: &'a str,
    app_display_name: &'a str,
    permission_value: &'a str,
    target_urls: &'a [String],
    role: &'a str,
}

/// Grants a service principal access to specific lists, folders or files under
/// one of the `*.SelectedOperations.Selected` scopes.
///
/// Unlike `convert_site_access_to_selected` this strips nothing: these scopes
/// have no org-wide predecessor to remove — the operator is granting
/// least-privilege access from the start.
#[allow(clippy::too_many_arguments)]
pub async fn grant_selected_item_access(
    tenant_id: &str,
    sp_object_id: &str,
    object_id: Option<&str>,
    app_id: &str,
    app_display_name: &str,
    permission_value: &str,
    target_urls: &[String],
    role: &str,
) -> Result<SelectedItemScopeResult, UiError> {
    invoke_result(
        "grant_selected_item_access",
        GrantSelectedItemArgs {
            tenant_id,
            sp_object_id,
            object_id,
            app_id,
            app_display_name,
            permission_value,
            target_urls,
            role,
        },
    )
    .await
}
