//! User-editable runtime settings.
//!
//! Loaded once at startup from `<config_dir>/settings.json`. The env var
//! `AZAPPTOOLKIT_AUTO_UPDATE` (accepting `0`/`false`/`off`/`no`) takes
//! precedence — useful for MDM-managed deployments that ship a wrapper
//! script, and for CI/automation that should never auto-install.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::defaults::TenantDefaults;

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
    /// Per-tenant operator defaults (default owners, SSO notification emails,
    /// scope-name pattern, vault bindings), keyed by tenant id. Edited from the
    /// Settings page via `get_tenant_defaults` / `set_tenant_defaults`.
    #[serde(default)]
    pub tenant_defaults: BTreeMap<String, TenantDefaults>,
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
            tenant_defaults: BTreeMap::new(),
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

    /// The defaults saved for `tenant_id`, or an empty default set if none.
    pub fn defaults_for(&self, tenant_id: &str) -> TenantDefaults {
        self.tenant_defaults
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Applies the operator-editable half of `incoming` for `tenant_id` —
    /// default owners, SSO notification emails, and the Exchange scope-/group-name
    /// patterns — while **preserving** the vault fields (`default_vault`,
    /// `app_vaults`), which are owned by the credential-rotation flow, not the
    /// Settings page. This keeps a Settings save from clobbering a binding a
    /// concurrent rotation just recorded.
    pub fn apply_tenant_defaults(&mut self, tenant_id: &str, incoming: TenantDefaults) {
        let entry = self
            .tenant_defaults
            .entry(tenant_id.to_string())
            .or_default();
        entry.app_registration = incoming.app_registration;
        entry.enterprise_application = incoming.enterprise_application;
        entry.scope_name_pattern = incoming.scope_name_pattern;
        entry.group_name_pattern = incoming.group_name_pattern;
        entry.secret_name_pattern = incoming.secret_name_pattern;
        // default_vault + app_vaults are intentionally preserved.
    }

    /// Records where an app registration's client secret was last rotated, keyed
    /// by the app's client id. Owned by the credential-rotation flow (the
    /// Settings page's [`apply_tenant_defaults`](Self::apply_tenant_defaults)
    /// deliberately preserves these), so it writes the binding directly.
    pub fn set_app_vault_binding(
        &mut self,
        tenant_id: &str,
        app_id: &str,
        binding: crate::defaults::AppVaultBinding,
    ) {
        self.tenant_defaults
            .entry(tenant_id.to_string())
            .or_default()
            .app_vaults
            .insert(app_id.to_string(), binding);
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
            tenant_defaults: BTreeMap::new(),
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
    fn tenant_defaults_default_to_empty_and_round_trip() {
        use crate::defaults::{AppRegistrationDefaults, StoredPrincipal, TenantDefaults};
        let dir = tempdir();
        // Absent map => empty.
        std::fs::write(dir.path().join(SETTINGS_FILE), br#"{"auto_update": true}"#).unwrap();
        assert!(
            UserSettings::stored(dir.path())
                .defaults_for("t-1")
                .app_registration
                .default_owners
                .is_empty()
        );

        // Save a tenant's defaults and read them back.
        let mut s = UserSettings::stored(dir.path());
        s.apply_tenant_defaults(
            "t-1",
            TenantDefaults {
                app_registration: AppRegistrationDefaults {
                    default_owners: vec![StoredPrincipal {
                        id: "u-1".into(),
                        display_name: Some("Ada".into()),
                        ..Default::default()
                    }],
                },
                ..Default::default()
            },
        );
        s.save(dir.path()).unwrap();
        let loaded = UserSettings::stored(dir.path());
        assert_eq!(
            loaded.defaults_for("t-1").app_registration.default_owners[0].id,
            "u-1"
        );
        // A different tenant is unaffected.
        assert!(
            loaded
                .defaults_for("t-2")
                .app_registration
                .default_owners
                .is_empty()
        );
    }

    #[test]
    fn apply_tenant_defaults_preserves_vault_fields() {
        use crate::defaults::{AppVaultBinding, TenantDefaults};
        let mut s = UserSettings::default();
        // Seed a vault binding (as the rotation flow would).
        s.tenant_defaults.insert(
            "t-1".into(),
            TenantDefaults {
                default_vault: Some("kv-a".into()),
                app_vaults: std::collections::BTreeMap::from([(
                    "app-1".into(),
                    AppVaultBinding {
                        vault_name: "kv-a".into(),
                        secret_name: Some("s".into()),
                    },
                )]),
                ..Default::default()
            },
        );
        // A Settings save (which carries no vault fields) must not wipe them.
        s.apply_tenant_defaults("t-1", TenantDefaults::default());
        let d = s.defaults_for("t-1");
        assert_eq!(d.default_vault.as_deref(), Some("kv-a"));
        assert!(d.app_vaults.contains_key("app-1"));
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
        // pid disambiguates across parallel test binaries; the atomic counter
        // disambiguates across this binary's threads — together guaranteeing a
        // unique path without relying on clock resolution (tests run in parallel).
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "azapptoolkit-settings-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
