//! First-run configuration: read the resolved client/tenant IDs and persist
//! user-entered ones to `settings.json`, so a downloaded release can be
//! configured in-app instead of only via environment variables.

use tauri::{AppHandle, State};

use azapptoolkit_core::settings::UserSettings;

use crate::dto::UiError;

use super::guid::is_guid;
use crate::dto::config::AuthConfigStatus;
use crate::state::AppState;

/// Reports whether the app has usable client/tenant IDs and what they are (so
/// the config form can prefill when reconfiguring). Drives the first-run gate.
#[tauri::command]
pub fn get_auth_config(state: State<'_, AppState>) -> AuthConfigStatus {
    AuthConfigStatus {
        configured: state.is_configured(),
        client_id: state.display_client_id().to_string(),
        tenant_id: state.display_tenant_id().to_string(),
    }
}

/// Persists the user-entered client/tenant IDs to `settings.json`, preserving
/// other settings. The new IDs take effect on the next launch (the frontend
/// calls `restart_app` after a successful save), since `AppState` resolves them
/// once at startup.
#[tauri::command]
pub fn set_auth_config(client_id: String, tenant_id: String) -> Result<(), UiError> {
    let client_id = client_id.trim().to_string();
    let tenant_id = tenant_id.trim().to_string();

    if !is_guid(&client_id) {
        return Err(UiError::validation(
            "invalid_client_id",
            "Application (client) ID must be a GUID, e.g. 00000000-0000-0000-0000-000000000000.",
        ));
    }
    if !is_valid_tenant(&tenant_id) {
        return Err(UiError::validation(
            "invalid_tenant_id",
            "Directory (tenant) ID must be a GUID or a tenant domain, e.g. contoso.onmicrosoft.com.",
        ));
    }

    let config_dir = crate::config_directory();
    let mut settings = UserSettings::stored(&config_dir);
    settings.client_id = Some(client_id);
    settings.tenant_id = Some(tenant_id);
    settings
        .save(&config_dir)
        .map_err(|e| UiError::io(format!("Could not write settings.json: {e}")))?;
    Ok(())
}

/// Relaunches the app so `AppState::new` re-resolves the freshly-saved IDs.
/// Diverges — the process exits and a new one starts — so the invoke never
/// resolves on the calling side (the relaunched window replaces it).
#[tauri::command]
pub fn restart_app(app: AppHandle) {
    app.restart();
}

/// A tenant id is either a GUID or a verified domain (e.g.
/// `contoso.onmicrosoft.com`). Domains are accepted loosely — a dotted,
/// whitespace-free host — since Entra also takes one as an authority segment.
fn is_valid_tenant(s: &str) -> bool {
    is_guid(s) || (s.contains('.') && !s.contains(char::is_whitespace) && s.len() <= 253)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_accepts_guid_or_domain() {
        assert!(is_valid_tenant("3fa85f64-5717-4562-b3fc-2c963f66afa6"));
        assert!(is_valid_tenant("contoso.onmicrosoft.com"));
        assert!(is_valid_tenant("contoso.com"));
        assert!(!is_valid_tenant("contoso")); // no dot and not a GUID
        assert!(!is_valid_tenant("has space.com"));
        assert!(!is_valid_tenant(""));
    }
}
