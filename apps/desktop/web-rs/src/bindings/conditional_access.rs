//! Conditional Access IPC bindings.

use super::ipc::invoke_result;
use azapptoolkit_dto::UiError;

use serde::Serialize;

use crate::bindings::{AppIdArgs, TenantArg};
pub use azapptoolkit_dto::conditional_access::{
    ConditionalAccessPolicyDto, CreatedLock, NamedLocationDto, NetworkLockStatus, NewLocationArgs,
    ReportOnlyReadout, ToolkitLockDto,
};

/// Conditional Access policies that apply to `app_id` (the application's appId /
/// client id). Degrades gracefully when the tenant is unlicensed or the account
/// lacks a policy-reading role (`code == "ca_unavailable"`); a missing consent
/// arrives as `consent_required`, and a dead session or step-up keeps its own
/// code.
pub async fn list_conditional_access_for_app(
    tenant_id: &str,
    app_id: &str,
) -> Result<Vec<ConditionalAccessPolicyDto>, UiError> {
    invoke_result(
        "list_conditional_access_for_app",
        AppIdArgs { tenant_id, app_id },
    )
    .await
}

/// The app's Network lock state: eligibility, the toolkit's own lock (any
/// state), other policies' verdict, and — for a report-only lock — what it
/// would have blocked in the last week.
pub async fn get_network_lock(tenant_id: &str, app_id: &str) -> Result<NetworkLockStatus, UiError> {
    invoke_result("get_network_lock", AppIdArgs { tenant_id, app_id }).await
}

/// The tenant's IP named locations, for the lock picker.
pub async fn list_named_locations(tenant_id: &str) -> Result<Vec<NamedLocationDto>, UiError> {
    invoke_result("list_named_locations", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateNetworkLockArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
    named_location_ids: &'a [String],
    new_location: Option<&'a NewLocationArgs>,
}

/// Creates the app's lock, report-only (and an untrusted named location first
/// when `new_location` is given).
pub async fn create_network_lock(
    tenant_id: &str,
    app_id: &str,
    named_location_ids: &[String],
    new_location: Option<&NewLocationArgs>,
) -> Result<CreatedLock, UiError> {
    invoke_result(
        "create_network_lock",
        CreateNetworkLockArgs {
            tenant_id,
            app_id,
            named_location_ids,
            new_location,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NetworkLockPolicyArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
    policy_id: &'a str,
}

/// Turns the app's toolkit lock on.
pub async fn enable_network_lock(
    tenant_id: &str,
    app_id: &str,
    policy_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "enable_network_lock",
        NetworkLockPolicyArgs {
            tenant_id,
            app_id,
            policy_id,
        },
    )
    .await
}

/// Deletes the app's toolkit lock (named locations stay).
pub async fn remove_network_lock(
    tenant_id: &str,
    app_id: &str,
    policy_id: &str,
) -> Result<(), UiError> {
    invoke_result(
        "remove_network_lock",
        NetworkLockPolicyArgs {
            tenant_id,
            app_id,
            policy_id,
        },
    )
    .await
}
