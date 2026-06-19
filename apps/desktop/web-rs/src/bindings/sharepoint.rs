//! SharePoint Sites.Selected IPC bindings. DTOs come from the shared
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
            app_id,
            app_display_name,
            site_urls,
            role,
            remove_orgwide,
        },
    )
    .await
}
