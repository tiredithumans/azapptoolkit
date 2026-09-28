//! First-run configuration: read the resolved client/tenant IDs and persist
//! user-entered ones to `settings.json`, so a downloaded release can be
//! configured in-app instead of only via environment variables.

use tauri::{AppHandle, State};

use azapptoolkit_core::identity::canonical_tenant_id;
use azapptoolkit_core::settings::UserSettings;

use crate::dto::UiError;

use super::guid::is_guid;
use crate::dto::config::AuthConfigStatus;
use crate::state::AppState;

/// Reports whether the app has usable client/tenant IDs, what they are (so
/// the config form can prefill when reconfiguring) and which resolution tier
/// supplied each (so the Tenant connection tab can say when an env var or the
/// build overrides a saved value). Drives the first-run gate.
#[tauri::command]
pub fn get_auth_config(state: State<'_, AppState>) -> AuthConfigStatus {
    AuthConfigStatus {
        configured: state.is_configured(),
        client_id: state.display_client_id().to_string(),
        tenant_id: state.display_tenant_id().to_string(),
        client_id_source: state.client_id_source,
        tenant_id_source: state.tenant_id_source,
    }
}

/// Persists the user-entered client/tenant IDs to `settings.json`, preserving
/// other settings. The new IDs take effect on the next launch (the frontend
/// calls `restart_app` after a successful save), since `AppState` resolves them
/// once at startup.
#[tauri::command]
pub fn set_auth_config(client_id: String, tenant_id: String) -> Result<(), UiError> {
    let (client_id, tenant_id) = validated_ids(&client_id, &tenant_id)?;

    let config_dir = crate::config_directory();
    // Every settings.json writer goes through `UserSettings::mutate`: several
    // read-modify-write this file from different threads, and an interleaved
    // pair silently drops one side's write.
    UserSettings::mutate(&config_dir, |settings| {
        settings.client_id = Some(client_id);
        settings.tenant_id = Some(tenant_id);
    })
    .map_err(|e| UiError::io(format!("Could not write settings.json: {e}")))?;
    Ok(())
}

/// The IDs `set_auth_config` would save, or the validation error it returns.
/// Split out so the rules are testable without writing `settings.json`.
fn validated_ids(client_id: &str, tenant_id: &str) -> Result<(String, String), UiError> {
    let client_id = client_id.trim().to_string();
    // Lowercase, the spelling of the id token's `tid`: a GUID is
    // case-insensitive, but the tid check and launch restore compare verbatim.
    let tenant_id = canonical_tenant_id(tenant_id);

    if !is_guid(&client_id) {
        return Err(UiError::validation(
            "invalid_client_id",
            "Application (client) ID must be a GUID, e.g. 00000000-0000-0000-0000-000000000000.",
        ));
    }
    // GUID only: the id token's `tid` claim is always the (lowercase) tenant
    // GUID and `sign_in` compares it to this string verbatim (as does the
    // launch-restore lookup), so a domain here could be saved but never signed
    // in with.
    if !is_guid(&tenant_id) {
        return Err(UiError::validation(
            "invalid_tenant_id",
            "Directory (tenant) ID must be a GUID, e.g. 00000000-0000-0000-0000-000000000000 — copy it from the app registration's Overview page.",
        ));
    }
    Ok((client_id, tenant_id))
}

/// Relaunches the app so `AppState::new` re-resolves the freshly-saved IDs.
/// Diverges — the process exits and a new one starts — so the invoke never
/// resolves on the calling side (the relaunched window replaces it).
#[tauri::command]
pub fn restart_app(app: AppHandle) {
    app.restart();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A domain is refused: the id token's `tid` is the GUID, so a
    /// domain-configured install could never complete a sign-in.
    #[test]
    fn tenant_must_be_a_guid() {
        let save_with_tenant =
            |tenant: &str| validated_ids("3fa85f64-5717-4562-b3fc-2c963f66afa6", tenant);
        for rejected in [
            "contoso.onmicrosoft.com",
            "contoso.com",
            "contoso",
            "has space.com",
            "",
        ] {
            let err = save_with_tenant(rejected).expect_err(rejected);
            assert_eq!(err.code, "invalid_tenant_id", "{rejected}");
        }
    }

    /// An uppercase GUID is accepted but saved lowercase: Entra's `tid` is
    /// lowercase and the sign-in and launch-restore checks compare verbatim.
    #[test]
    fn tenant_is_saved_in_the_lowercase_tid_spelling() {
        let (_, tenant) = validated_ids(
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            " 3FA85F64-5717-4562-B3FC-2C963F66AFA6 ",
        )
        .unwrap();
        assert_eq!(tenant, "3fa85f64-5717-4562-b3fc-2c963f66afa6");
    }
}
