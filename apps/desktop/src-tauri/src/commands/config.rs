//! First-run configuration: read the resolved client/tenant IDs and persist
//! user-entered ones to `settings.json`, so a downloaded release can be
//! configured in-app instead of only via environment variables.

use tauri::{AppHandle, State};

use azapptoolkit_core::identity::canonical_tenant_id;
use azapptoolkit_core::settings::{SettingsUnreadable, UserSettings};

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
        cloud: state.auth.cloud().display_name().to_string(),
        cloud_warning: state.cloud_warning.clone(),
        settings_error: state.settings_error.clone(),
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
    .map_err(|e| settings_write_error(&e))?;
    Ok(())
}

/// The `UiError` for a `settings.json` save that `UserSettings::mutate`
/// refused or could not complete. A file that exists but cannot be used is
/// `settings_unreadable`, naming the file — "check the folder is writable"
/// would send the operator the wrong way. Damaged JSON is not retryable
/// (nothing changes until it is fixed or moved aside); a file that could not
/// be READ is (a permission, an antivirus scan or a sync client holding it
/// can clear), and the frontend's hint tells the two apart by that flag. Any
/// other failure is the generic, retryable `io`. Shared by every Settings
/// save.
pub(crate) fn settings_write_error(e: &std::io::Error) -> UiError {
    match SettingsUnreadable::find(e) {
        Some(refusal) if refusal.is_parse_error() => UiError::validation(
            "settings_unreadable",
            format!("settings.json is damaged: {refusal}."),
        ),
        Some(refusal) => UiError::new(
            "settings_unreadable",
            format!("settings.json couldn't be read: {refusal}."),
            true,
        ),
        None => UiError::io(format!("Could not write settings.json: {e}")),
    }
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

    /// A damaged file is its own code naming the file, not retryable; one that
    /// can't be read is the same code, retryable, pointing at its access; any
    /// other write failure stays the retryable `io`.
    #[test]
    fn a_refused_save_over_a_damaged_file_is_settings_unreadable() {
        let dir = std::env::temp_dir().join(format!(
            "azapptoolkit-config-unreadable-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(azapptoolkit_core::settings::SETTINGS_FILE);
        std::fs::write(&file, b"{ not json").unwrap();

        let refused = UserSettings::mutate(&dir, |_| ()).unwrap_err();
        let err = settings_write_error(&refused);
        assert_eq!(err.code, "settings_unreadable");
        assert!(!err.retryable);
        assert!(
            err.message.contains(&file.display().to_string()),
            "{}",
            err.message
        );
        assert!(err.message.contains("line 1"), "{}", err.message);
        assert!(err.message.contains("is damaged"), "{}", err.message);

        // A directory in the file's place: it exists, and it can't be read.
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        let refused = UserSettings::mutate(&dir, |_| ()).unwrap_err();
        let err = settings_write_error(&refused);
        assert_eq!(err.code, "settings_unreadable");
        assert!(err.retryable, "a lock or a permission can clear");
        assert!(err.message.contains("couldn't be read"), "{}", err.message);
        assert!(
            err.message.contains("check its permissions"),
            "{}",
            err.message
        );
        assert!(!err.message.contains("damaged"), "{}", err.message);

        let other = settings_write_error(&std::io::Error::other("disk full"));
        assert_eq!(other.code, "io");
        assert!(other.retryable);
        let _ = std::fs::remove_dir_all(&dir);
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
