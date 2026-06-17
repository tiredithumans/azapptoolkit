//! User-editable runtime settings.
//!
//! Loaded once at startup from `<config_dir>/settings.json`. The env var
//! `AZAPPTOOLKIT_AUTO_UPDATE` (accepting `0`/`false`/`off`/`no`) takes
//! precedence — useful for MDM-managed deployments that ship a wrapper
//! script, and for CI/automation that should never auto-install.

use std::path::Path;

use serde::{Deserialize, Serialize};

pub const SETTINGS_FILE: &str = "settings.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    #[serde(default = "default_true")]
    pub auto_update: bool,
    /// Entra app-registration client (application) ID, set via the first-run
    /// config screen. `None` until the user configures it — or when the IDs are
    /// baked at build time / supplied by an env var instead (in which case the
    /// config screen never appears). See `state.rs` for the resolution order.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Entra directory (tenant) ID — a GUID or a verified domain — set via the
    /// first-run config screen. See [`Self::client_id`].
    #[serde(default)]
    pub tenant_id: Option<String>,
}

fn default_true() -> bool {
    true
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            auto_update: true,
            client_id: None,
            tenant_id: None,
        }
    }
}

impl UserSettings {
    /// Settings exactly as persisted on disk (no env overrides applied),
    /// falling back to defaults if the file is missing or unparseable. A writer
    /// should start from this so it preserves fields it isn't changing.
    pub fn stored(config_dir: &Path) -> Self {
        Self::from_file(&config_dir.join(SETTINGS_FILE)).unwrap_or_default()
    }

    /// Loads from `<config_dir>/settings.json`, falling back to defaults if
    /// the file is missing or unparseable. The `AZAPPTOOLKIT_AUTO_UPDATE`
    /// env var overrides whatever the file says.
    pub fn load(config_dir: &Path) -> Self {
        let mut s = Self::stored(config_dir);
        if let Some(env_override) = auto_update_env_override() {
            s.auto_update = env_override;
        }
        s
    }

    /// Writes the settings to `<config_dir>/settings.json` (creating the
    /// directory if needed), pretty-printed. Used by the first-run config
    /// screen — the only writer of this file.
    pub fn save(&self, config_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(config_dir)?;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(config_dir.join(SETTINGS_FILE), json)
    }

    fn from_file(path: &Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        match serde_json::from_slice::<Self>(&bytes) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "ignoring unparseable settings.json");
                None
            }
        }
    }
}

fn auto_update_env_override() -> Option<bool> {
    let raw = std::env::var("AZAPPTOOLKIT_AUTO_UPDATE").ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "0" | "false" | "off" | "no" => Some(false),
        "1" | "true" | "on" | "yes" => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_auto_update_on() {
        let dir = tempdir();
        let s = UserSettings::load(dir.path());
        assert!(s.auto_update);
    }

    #[test]
    fn settings_file_can_disable_auto_update() {
        let dir = tempdir();
        std::fs::write(dir.path().join(SETTINGS_FILE), br#"{"auto_update": false}"#).unwrap();
        let s = UserSettings::load(dir.path());
        assert!(!s.auto_update);
    }

    #[test]
    fn unparseable_file_falls_back_to_defaults() {
        let dir = tempdir();
        std::fs::write(dir.path().join(SETTINGS_FILE), b"not json").unwrap();
        let s = UserSettings::load(dir.path());
        assert!(s.auto_update);
    }

    #[test]
    fn save_round_trips_client_and_tenant_ids() {
        let dir = tempdir();
        let s = UserSettings {
            auto_update: false,
            client_id: Some("11111111-1111-1111-1111-111111111111".into()),
            tenant_id: Some("contoso.onmicrosoft.com".into()),
        };
        s.save(dir.path()).unwrap();
        // `stored` (not `load`) so an `AZAPPTOOLKIT_AUTO_UPDATE` in the test env
        // can't perturb the round-trip assertion.
        let loaded = UserSettings::stored(dir.path());
        assert!(!loaded.auto_update);
        assert_eq!(
            loaded.client_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(loaded.tenant_id.as_deref(), Some("contoso.onmicrosoft.com"));
    }

    #[test]
    fn ids_default_to_none_when_absent() {
        let dir = tempdir();
        std::fs::write(dir.path().join(SETTINGS_FILE), br#"{"auto_update": true}"#).unwrap();
        let s = UserSettings::stored(dir.path());
        assert!(s.client_id.is_none());
        assert!(s.tenant_id.is_none());
    }

    // Tiny self-contained temp-dir helper to avoid pulling in the `tempfile`
    // crate just for these tests.
    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        let mut p = std::env::temp_dir();
        let n: u64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        p.push(format!(
            "azapptoolkit-settings-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
