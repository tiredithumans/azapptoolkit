//! First-run configuration IPC bindings. DTOs come from the shared `azapptoolkit-dto`.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::{invoke, invoke_result};

pub use azapptoolkit_dto::config::AuthConfigStatus;

/// Whether the app has usable client/tenant IDs (and their current values for
/// prefilling the config form). Infallible — reads in-memory state.
pub async fn get_auth_config() -> AuthConfigStatus {
    invoke("get_auth_config", ()).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetAuthConfigArgs {
    client_id: String,
    tenant_id: String,
}

/// Persists the user-entered IDs to `settings.json`. The backend validates the
/// GUID/domain shape and returns a `UiError` on bad input.
pub async fn set_auth_config(client_id: String, tenant_id: String) -> Result<(), UiError> {
    invoke_result(
        "set_auth_config",
        SetAuthConfigArgs {
            client_id,
            tenant_id,
        },
    )
    .await
}

/// Relaunches the app so the freshly-saved IDs take effect. The process exits,
/// so this future never resolves — the relaunched window replaces the caller.
pub async fn restart_app() {
    invoke::<()>("restart_app", ()).await
}
