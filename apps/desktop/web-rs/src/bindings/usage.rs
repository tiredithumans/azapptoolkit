//! Graph-activity usage IPC bindings (granted-vs-used analysis).

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::usage::*;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
    days: u32,
}

/// Summarizes an app's observed Graph calls over the last `days` from the
/// tenant's MicrosoftGraphActivityLogs workspace. Typed failures the panel
/// acts on: `consent_required` (Grant-consent button) and `usage_unavailable`
/// (diagnostic-settings setup guidance).
pub async fn get_app_graph_usage(
    tenant_id: &str,
    app_id: &str,
    days: u32,
) -> Result<GraphUsageResult, UiError> {
    invoke_result(
        "get_app_graph_usage",
        UsageArgs {
            tenant_id,
            app_id,
            days,
        },
    )
    .await
}
