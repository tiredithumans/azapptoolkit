//! First-run app-configuration IPC DTOs.
//!
//! The client/tenant IDs the app signs in with are resolved on the backend
//! (env var → `settings.json` → build-time bake → placeholder). This status
//! lets the frontend decide whether to show the first-run config screen and
//! prefill the form when reconfiguring.

use serde::{Deserialize, Serialize};

/// Which resolution tier supplied a client/tenant ID, in precedence order.
/// Logged at startup and reported by `get_auth_config`, because "is the env
/// override, settings.json or the build winning?" is the classic support
/// question the resolution order raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConfigSource {
    /// A non-empty `AZAPPTOOLKIT_*` environment variable on this machine
    /// (MDM/automation override) — beats anything saved in-app.
    Env,
    /// The user's `settings.json`, written by the first-run config screen and
    /// Settings → Tenant connection.
    Settings,
    /// The build-time bake from `.env` (a team build).
    Baked,
    /// Nothing supplied a value; the placeholder is in use.
    #[default]
    Unset,
}

impl ConfigSource {
    /// The spelling used in the startup `resolved auth config` log line.
    pub fn as_str(self) -> &'static str {
        match self {
            ConfigSource::Env => "env",
            ConfigSource::Settings => "settings.json",
            ConfigSource::Baked => "baked",
            ConfigSource::Unset => "unset",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfigStatus {
    /// True once both client and tenant IDs resolve to a real (non-placeholder)
    /// value — i.e. sign-in has a chance of succeeding.
    pub configured: bool,
    /// Current effective client ID, or empty when still the placeholder (so the
    /// config form renders blank rather than showing the all-zeros GUID).
    pub client_id: String,
    /// Current effective tenant ID, or empty when still the placeholder. Also
    /// what the sign-in card names ("Signing in to …"), so a wrong tenant is
    /// caught before the browser round trip rather than after it comes back as
    /// an opaque token-exchange failure.
    pub tenant_id: String,
    /// Which tier supplied [`Self::client_id`]. Defaults to `Unset` so a
    /// payload (or fixture) without it still deserialises.
    #[serde(default)]
    pub client_id_source: ConfigSource,
    /// Which tier supplied [`Self::tenant_id`]; see [`Self::client_id_source`].
    #[serde(default)]
    pub tenant_id_source: ConfigSource,
    /// The cloud sign-in targets, as its display name ("US Gov (GCC High)"),
    /// named on the sign-in card beside the tenant. Empty from an older backend.
    #[serde(default)]
    pub cloud: String,
    /// Set when `AZAPPTOOLKIT_CLOUD` named a cloud this build does not know and
    /// was ignored: the ignored value, the cloud used instead and the valid
    /// values, shown as a warning on the sign-in card.
    #[serde(default)]
    pub cloud_warning: Option<String>,
    /// Set when `settings.json` exists but could not be read at startup, so the
    /// app is running without it (saved IDs, tenant defaults and the update
    /// opt-out ignored): the path and where it broke, never its contents.
    /// Shown as a warning on the config and sign-in screens.
    #[serde(default)]
    pub settings_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_without_sources_deserialises_as_unset() {
        let s: AuthConfigStatus =
            serde_json::from_str(r#"{"configured":true,"clientId":"c","tenantId":"t"}"#).unwrap();
        assert_eq!(s.client_id_source, ConfigSource::Unset);
        assert_eq!(s.tenant_id_source, ConfigSource::Unset);
        assert!(s.cloud.is_empty());
        assert_eq!(s.cloud_warning, None);
        assert_eq!(s.settings_error, None);
    }

    #[test]
    fn sources_round_trip_in_camel_case() {
        let s = AuthConfigStatus {
            configured: true,
            client_id: "c".into(),
            tenant_id: "t".into(),
            client_id_source: ConfigSource::Env,
            tenant_id_source: ConfigSource::Baked,
            cloud: "US Gov (GCC High)".into(),
            cloud_warning: Some("w".into()),
            settings_error: Some("e".into()),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""clientIdSource":"env""#), "{json}");
        assert!(json.contains(r#""tenantIdSource":"baked""#), "{json}");
        let back: AuthConfigStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back.client_id_source, ConfigSource::Env);
        assert_eq!(back.tenant_id_source, ConfigSource::Baked);
        assert!(json.contains(r#""cloudWarning":"w""#), "{json}");
        assert!(json.contains(r#""settingsError":"e""#), "{json}");
        assert_eq!(back.cloud, "US Gov (GCC High)");
    }
}
