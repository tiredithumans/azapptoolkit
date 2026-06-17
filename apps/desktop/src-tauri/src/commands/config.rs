//! First-run configuration: read the resolved client/tenant IDs and persist
//! user-entered ones to `settings.json`, so a downloaded release can be
//! configured in-app instead of only via environment variables.

use tauri::{AppHandle, State};

use azapptoolkit_core::settings::UserSettings;

use crate::dto::config::AuthConfigStatus;
use crate::dto::UiError;
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

/// 8-4-4-4-12 hexadecimal, the canonical GUID shape Entra uses for both the
/// client (application) ID and the tenant (directory) ID.
fn is_guid(s: &str) -> bool {
    let groups = [8usize, 4, 4, 4, 12];
    let mut parts = s.split('-');
    for &len in &groups {
        match parts.next() {
            Some(p) if p.len() == len && p.bytes().all(|b| b.is_ascii_hexdigit()) => {}
            _ => return false,
        }
    }
    parts.next().is_none()
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
    fn guid_accepts_canonical_and_rejects_junk() {
        assert!(is_guid("00000000-0000-0000-0000-000000000000"));
        assert!(is_guid("3fa85f64-5717-4562-b3fc-2c963f66afa6"));
        assert!(is_guid("3FA85F64-5717-4562-B3FC-2C963F66AFA6")); // hex is case-insensitive
        assert!(!is_guid("not-a-guid"));
        assert!(!is_guid("3fa85f64-5717-4562-b3fc")); // too few groups
        assert!(!is_guid("3fa85f64-5717-4562-b3fc-2c963f66afa6-extra")); // trailing group
        assert!(!is_guid("zzzzzzzz-5717-4562-b3fc-2c963f66afa6")); // non-hex
        assert!(!is_guid(""));
    }

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
