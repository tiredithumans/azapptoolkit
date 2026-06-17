//! Conditional Access IPC bindings.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::conditional_access::ConditionalAccessPolicyDto;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
}

/// Conditional Access policies that apply to `app_id` (the application's appId /
/// client id). Degrades gracefully when Policy.Read.All is un-consented /
/// unlicensed (`code == "ca_unavailable"`).
pub async fn list_conditional_access_for_app(
    tenant_id: &str,
    app_id: &str,
) -> Result<Vec<ConditionalAccessPolicyDto>, UiError> {
    invoke_result(
        "list_conditional_access_for_app",
        ListArgs { tenant_id, app_id },
    )
    .await
}
