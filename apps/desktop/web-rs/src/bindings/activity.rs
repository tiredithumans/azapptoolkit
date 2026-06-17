//! Directory activity / change-log IPC bindings.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::activity::{ActivityLogItem, SignInActivityDto};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListArgs<'a> {
    tenant_id: &'a str,
    primary_object_id: &'a str,
    secondary_object_id: Option<&'a str>,
}

/// Recent directory changes targeting two related directory objects (an app
/// registration and its paired service principal, in either order). Degrades
/// gracefully when AuditLog.Read.All is un-consented / unlicensed
/// (`code == "activity_unavailable"`).
pub async fn list_directory_audits_for_app(
    tenant_id: &str,
    primary_object_id: &str,
    secondary_object_id: Option<&str>,
) -> Result<Vec<ActivityLogItem>, UiError> {
    invoke_result(
        "list_directory_audits_for_app",
        ListArgs {
            tenant_id,
            primary_object_id,
            secondary_object_id,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignInArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
}

/// Most recent recorded sign-in for an app's service principal (keyed on appId).
/// Always `Ok` — a missing scope/license/consent comes back as a populated
/// `SignInActivityDto` with `available = false` (or `consent_required = true`).
pub async fn get_app_sign_in_activity(
    tenant_id: &str,
    app_id: &str,
) -> Result<SignInActivityDto, UiError> {
    invoke_result("get_app_sign_in_activity", SignInArgs { tenant_id, app_id }).await
}
