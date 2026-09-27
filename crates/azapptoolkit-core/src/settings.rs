//! User-editable runtime settings.
//!
//! Persisted in `<config_dir>/settings.json`: every writer goes through
//! [`UserSettings::mutate`]; readers use [`UserSettings::stored`], and the
//! updater commands read `auto_update` through [`UserSettings::load`] on each
//! call. The env var `AZAPPTOOLKIT_AUTO_UPDATE` (accepting
//! `0`/`false`/`off`/`no`) takes precedence over the file — useful for
//! MDM-managed deployments that ship a wrapper script, and for CI/automation
//! that should never check for or install updates.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::defaults::TenantDefaults;
use crate::identity::TenantContext;

pub const SETTINGS_FILE: &str = "settings.json";

/// The cross-process advisory lock file [`UserSettings::mutate`] holds for the
/// duration of a read-modify-write, so a second app instance cannot interleave
/// with this one. Empty, and never deleted: removing it while another process
/// held it would let the next writer lock a *different* inode and race again.
pub const SETTINGS_LOCK_FILE: &str = "settings.lock";

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
    /// Entra directory (tenant) ID — a GUID (the id token's `tid` is compared
    /// to it verbatim, so a domain never signs in) — set via the first-run
    /// config screen. See [`Self::client_id`].
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Per-tenant operator defaults (default owners, SSO notification emails,
    /// scope-name pattern, vault bindings), keyed by tenant id. Edited from the
    /// Settings page via `get_tenant_defaults` / `set_tenant_defaults`.
    #[serde(default)]
    pub tenant_defaults: BTreeMap<String, TenantDefaults>,
    /// The account the operator last signed in as, so a relaunch can revive the
    /// session from the keyring refresh token instead of showing the sign-in
    /// card (the `restore_session` command). Written on a successful sign-in,
    /// cleared on sign-out.
    ///
    /// **Not a secret.** The refresh token stays in the OS keyring; this is only
    /// the *pointer* to it — directory object ids plus the operator's own UPN and
    /// display name, all of which the app already renders in its own chrome. The
    /// whole [`TenantContext`] is stored rather than a narrower struct so a
    /// restored session is indistinguishable from a fresh sign-in (same tenant
    /// chip, same `login_hint` on a later re-auth) and so there is no parallel
    /// shape to drift from the one the rest of the app passes around. The file is
    /// written owner-only ([`crate::private_file::write_owner_only`]) like every
    /// other artifact this app persists.
    #[serde(default)]
    pub last_account: Option<TenantContext>,
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
            last_account: None,
        }
    }
}

impl UserSettings {
    /// Settings exactly as persisted on disk (no env overrides applied),
    /// falling back to defaults if the file is missing, unreadable or
    /// unparseable. For readers only — a writer goes through [`Self::mutate`],
    /// which refuses to overwrite a file it cannot read.
    pub fn stored(config_dir: &Path) -> Self {
        Self::from_file(&config_dir.join(SETTINGS_FILE)).unwrap_or_default()
    }

    /// Loads from `<config_dir>/settings.json`, falling back to defaults if
    /// the file is missing, unreadable or unparseable (read-only, like
    /// [`Self::stored`]). The `AZAPPTOOLKIT_AUTO_UPDATE` env var overrides
    /// whatever the file says.
    pub fn load(config_dir: &Path) -> Self {
        let mut s = Self::stored(config_dir);
        if let Some(env_override) = auto_update_env_override() {
            s.auto_update = env_override;
        }
        s
    }

    /// Read, modify and write `settings.json` under a process-wide lock.
    ///
    /// The file has several read-modify-write callers — the auth config
    /// (`commands::config`), the tenant defaults (`commands::defaults`), the Key
    /// Vault rotation's vault binding (`commands::keyvault`) and the remembered
    /// account (`AppState::remember_account` / `forget_account`). The tenant
    /// defaults save is a synchronous Tauri command on the main thread while the
    /// rotation is async on the runtime pool, so they genuinely run on different
    /// OS threads. Interleaved either way, one side's read predates the other's
    /// write and that write is silently dropped: the operator's just-saved
    /// defaults, or the freshly recorded vault binding the rotation flow needs
    /// to find the secret again.
    ///
    /// Every writer must go through here. Paired with the atomic
    /// temp-and-rename in `private_file`, a concurrent *reader* also never sees
    /// a partial file. A second app instance is kept out by an OS advisory lock
    /// on [`SETTINGS_LOCK_FILE`], taken inside the process lock (best-effort:
    /// see [`Self::lock_across_instances`]).
    ///
    /// Refuses, rather than overwrites, a `settings.json` that exists but
    /// cannot be read or parsed (a hand-edit typo, a transient read failure):
    /// writing defaults over it would permanently lose the tenant defaults and
    /// the vault bindings. `f` does not run and the file is left untouched; a
    /// missing or blank file starts from defaults.
    pub fn mutate<T>(
        config_dir: &Path,
        f: impl FnOnce(&mut Self) -> T,
    ) -> std::io::Result<(T, Self)> {
        static SETTINGS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // A poisoned lock means a previous writer panicked mid-mutation. The
        // file itself is still consistent (the write is atomic), so recovering
        // and carrying on beats refusing every subsequent save.
        let _guard = SETTINGS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The OS lock comes SECOND: two opens of the same lock file in one
        // process conflict with each other, so the Mutex above is what keeps
        // in-process callers from contending on it.
        std::fs::create_dir_all(config_dir)?;
        let lock_file = Self::lock_across_instances(config_dir);

        let path = config_dir.join(SETTINGS_FILE);
        let mut settings = Self::read_file(&path)
            .map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!(
                        "{} exists but could not be read ({e}); fix or remove it — it was left unchanged",
                        path.display()
                    ),
                )
            })?
            .unwrap_or_default();
        let out = f(&mut settings);
        settings.save_locked(config_dir)?;
        // Held to here on purpose: dropping the file releases the OS lock.
        drop(lock_file);
        Ok((out, settings))
    }

    /// Take the cross-process advisory lock on [`SETTINGS_LOCK_FILE`], blocking
    /// while another app instance holds it. Dropping the returned file
    /// releases the lock.
    ///
    /// Best-effort by design: any failure to open or lock the file (a
    /// filesystem without advisory locks, e.g. an NFS home with no lock
    /// service returning `ENOLCK`; a stray unwritable `settings.lock`) is
    /// logged and yields `None`. The process lock in [`Self::mutate`] still
    /// serialises this instance, and refusing every settings write would be
    /// far worse than the rare race between two running copies of the app.
    fn lock_across_instances(config_dir: &Path) -> Option<std::fs::File> {
        let lock_path = config_dir.join(SETTINGS_LOCK_FILE);
        let locked = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .and_then(|file| file.lock().map(|()| file));
        match locked {
            Ok(file) => Some(file),
            Err(e) => {
                tracing::warn!(
                    path = %lock_path.display(),
                    error = %e,
                    "could not take the settings lock; writes from another running instance are not serialised"
                );
                None
            }
        }
    }

    /// The write half of [`Self::mutate`]. Private so a caller cannot take the
    /// read-modify-write apart and reintroduce the race; the only serializer of
    /// this file.
    ///
    /// Owner-only: `tenant_defaults` records which Key Vault holds which
    /// application's secrets (`default_vault` / `app_vaults`), which is a map
    /// of where this tenant's credentials live. Written under the process
    /// umask it was commonly world-readable.
    fn save_locked(&self, config_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(config_dir)?;
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        crate::private_file::write_owner_only(&config_dir.join(SETTINGS_FILE), &json)
    }

    /// The defaults saved for `tenant_id`, or an empty default set if none.
    pub fn defaults_for(&self, tenant_id: &str) -> TenantDefaults {
        self.tenant_defaults
            .get(tenant_id)
            .cloned()
            .unwrap_or_default()
    }

    /// The remembered account — but only when it belongs to `tenant_id`, the
    /// tenant this process actually resolved at startup.
    ///
    /// The configured tenant is not fixed: an env var, the first-run config
    /// screen, or a rebuilt `.env` can all repoint it between launches, while
    /// `settings.json` still names the account from the previous one. Handing
    /// that account back would send the restore hunting for a keyring entry
    /// under `{new tenant}:{old oid}` — at best missing, and at worst a *second*
    /// directory's session revived under this tenant's caches, which is the
    /// cross-tenant leak this repo guards hardest against. Cheaper to refuse
    /// here than to detect it downstream.
    pub fn remembered_account_for(&self, tenant_id: &str) -> Option<&TenantContext> {
        self.last_account
            .as_ref()
            .filter(|account| account.tenant_id == tenant_id)
    }

    /// Applies the operator-editable half of `incoming` for `tenant_id` —
    /// default owners, SSO notification emails, and the Exchange scope-/group-name
    /// patterns — while **preserving** the vault fields (`default_vault`,
    /// `app_vaults`), which are owned by the credential-rotation flow, not the
    /// Settings page. This keeps a Settings save from clobbering a binding a
    /// concurrent rotation just recorded.
    pub fn apply_tenant_defaults(&mut self, tenant_id: &str, incoming: TenantDefaults) {
        // Destructured WITHOUT `..` on purpose: this is an allowlist of the
        // operator-editable fields, and an allowlist that silently ignores new
        // members is the failure mode — a field added to `TenantDefaults` and
        // wired into the Settings page would compile, save, and never persist.
        // Exhaustive destructuring makes the compiler demand a decision here.
        // Adding a field? Assign it below if the Settings page owns it, or bind
        // it to `_` with a note naming the flow that does.
        let TenantDefaults {
            app_registration,
            enterprise_application,
            scope_name_pattern,
            group_name_pattern,
            secret_name_pattern,
            // Owned by the credential-rotation flow (`set_app_vault_binding`),
            // not the Settings page: preserved so a Settings save cannot clobber
            // a binding a concurrent rotation just recorded.
            default_vault: _,
            app_vaults: _,
        } = incoming;

        let entry = self
            .tenant_defaults
            .entry(tenant_id.to_string())
            .or_default();
        entry.app_registration = app_registration;
        entry.enterprise_application = enterprise_application;
        entry.scope_name_pattern = scope_name_pattern;
        entry.group_name_pattern = group_name_pattern;
        entry.secret_name_pattern = secret_name_pattern;
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

    /// The strict reader behind [`Self::mutate`]. `Ok(None)` only when there is
    /// nothing to lose — the file is missing, or blank / whitespace-only (which
    /// an older build's torn truncate could leave behind; refusing it would
    /// wedge every later write). A file that exists but cannot be read or
    /// parsed is an error.
    fn read_file(path: &Path) -> std::io::Result<Option<Self>> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// The lenient reader behind [`Self::stored`] / [`Self::load`]: any failure
    /// reads as "no settings" (with a warning), never as an error.
    fn from_file(path: &Path) -> Option<Self> {
        Self::read_file(path).unwrap_or_else(|e| {
            tracing::warn!(path = %path.display(), error = %e, "ignoring unreadable settings.json");
            None
        })
    }
}

fn auto_update_env_override() -> Option<bool> {
    parse_auto_update_override(&std::env::var("AZAPPTOOLKIT_AUTO_UPDATE").ok()?)
}

/// The `AZAPPTOOLKIT_AUTO_UPDATE` grammar, kept pure so it is testable without
/// mutating the process environment. Anything unrecognised is ignored (the
/// settings file decides).
fn parse_auto_update_override(raw: &str) -> Option<bool> {
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
    fn auto_update_override_grammar() {
        for (raw, want) in [
            ("0", Some(false)),
            ("false", Some(false)),
            ("OFF", Some(false)),
            (" no ", Some(false)),
            ("1", Some(true)),
            ("true", Some(true)),
            ("on", Some(true)),
            ("yes", Some(true)),
            ("maybe", None),
            ("", None),
        ] {
            assert_eq!(parse_auto_update_override(raw), want, "{raw:?}");
        }
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
    fn mutate_round_trips_client_and_tenant_ids() {
        let dir = tempdir();
        UserSettings::mutate(dir.path(), |s| {
            s.auto_update = false;
            s.client_id = Some("11111111-1111-1111-1111-111111111111".into());
            s.tenant_id = Some("22222222-2222-2222-2222-222222222222".into());
        })
        .unwrap();
        // `stored` (not `load`) so an `AZAPPTOOLKIT_AUTO_UPDATE` in the test env
        // can't perturb the round-trip assertion.
        let loaded = UserSettings::stored(dir.path());
        assert!(!loaded.auto_update);
        assert_eq!(
            loaded.client_id.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(
            loaded.tenant_id.as_deref(),
            Some("22222222-2222-2222-2222-222222222222")
        );
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
        UserSettings::mutate(dir.path(), |s| {
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
        })
        .unwrap();
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

    /// The launch restore reads this pointer, so it has to survive the file and
    /// stay refused for a tenant it was not written under.
    #[test]
    fn remembered_account_round_trips_and_is_refused_across_tenants() {
        let dir = tempdir();
        // Written before this field existed: an old settings.json must still
        // load (the operator simply signs in once more).
        std::fs::write(dir.path().join(SETTINGS_FILE), br#"{"auto_update": true}"#).unwrap();
        assert!(UserSettings::stored(dir.path()).last_account.is_none());

        UserSettings::mutate(dir.path(), |s| {
            s.last_account = Some(TenantContext {
                tenant_id: "t-1".into(),
                account_oid: "oid-1".into(),
                username: Some("ada@contoso.com".into()),
                display_name: Some("Ada".into()),
            });
        })
        .unwrap();

        let loaded = UserSettings::stored(dir.path());
        let account = loaded.remembered_account_for("t-1").expect("remembered");
        assert_eq!(account.account_oid, "oid-1");
        assert_eq!(account.username.as_deref(), Some("ada@contoso.com"));
        // Repointed at another directory since the account was remembered: the
        // oid addresses a keyring entry that is not this tenant's.
        assert!(loaded.remembered_account_for("t-2").is_none());
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

    /// Concurrent read-modify-write must not lose a field.
    ///
    /// `settings.json` had three unsynchronized writers, one of them a
    /// synchronous Tauri command on the main thread while another is async on
    /// the runtime pool — so they genuinely run on different OS threads.
    /// Interleave a separate read and write either way and one side's write vanishes:
    /// the operator's just-saved defaults, or the vault binding the next
    /// rotation needs to find the secret again.
    #[test]
    fn concurrent_mutations_do_not_lose_each_others_writes() {
        let dir = tempdir();
        let path = dir.0.clone();

        // Two writers touching DIFFERENT fields — the case a lost update
        // silently corrupts rather than merely reorders.
        std::thread::scope(|scope| {
            for i in 0..8 {
                let path = path.clone();
                scope.spawn(move || {
                    if i % 2 == 0 {
                        UserSettings::mutate(&path, |s| {
                            s.client_id = Some("client".to_string());
                        })
                        .unwrap();
                    } else {
                        UserSettings::mutate(&path, |s| {
                            s.tenant_id = Some("tenant".to_string());
                        })
                        .unwrap();
                    }
                });
            }
        });

        let final_settings = UserSettings::stored(&path);
        assert_eq!(final_settings.client_id.as_deref(), Some("client"));
        assert_eq!(
            final_settings.tenant_id.as_deref(),
            Some("tenant"),
            "one writer's field was lost to an interleaved read-modify-write"
        );
    }

    /// `mutate` reads the file each time, so a later mutation sees the earlier
    /// one — the property that makes it a safe replacement for a separate read
    /// and write.
    #[test]
    fn mutate_observes_the_previous_write() {
        let dir = tempdir();
        UserSettings::mutate(&dir.0, |s| s.client_id = Some("first".into())).unwrap();
        let (seen, _) = UserSettings::mutate(&dir.0, |s| {
            let seen = s.client_id.clone();
            s.tenant_id = Some("t".into());
            seen
        })
        .unwrap();
        assert_eq!(seen.as_deref(), Some("first"));
        let stored = UserSettings::stored(&dir.0);
        assert_eq!(stored.client_id.as_deref(), Some("first"));
        assert_eq!(stored.tenant_id.as_deref(), Some("t"));
    }

    /// A hand-edit typo must not cost the operator their vault bindings: the
    /// next sign-in's `mutate` used to serialise defaults over the file.
    #[test]
    fn mutate_refuses_to_overwrite_an_unparseable_file() {
        let dir = tempdir();
        let path = dir.path().join(SETTINGS_FILE);
        // Trailing comma: a typical hand-edit slip, around a vault binding.
        let original: &[u8] =
            br#"{"tenant_defaults":{"t-1":{"app_vaults":{"app-1":{"vault_name":"kv-a"}}}},}"#;
        std::fs::write(&path, original).unwrap();

        let mut called = false;
        let err = UserSettings::mutate(dir.path(), |s| {
            called = true;
            s.last_account = None;
        })
        .unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(!called, "the mutation ran against defaults");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "file was overwritten"
        );
        // The read-only path stays lenient.
        assert!(UserSettings::stored(dir.path()).auto_update);
    }

    /// An I/O failure (EACCES, EIO, an antivirus lock) is not "missing". A
    /// directory in the file's place gives a read error that works even as root.
    #[test]
    fn mutate_refuses_when_the_file_exists_but_cannot_be_read() {
        let dir = tempdir();
        let path = dir.path().join(SETTINGS_FILE);
        std::fs::create_dir(&path).unwrap();

        let mut called = false;
        let result = UserSettings::mutate(dir.path(), |s| {
            called = true;
            s.client_id = Some("c".into());
        });

        assert!(result.is_err());
        // The discriminating half: before the fix the rename also failed on a
        // directory, but only after the mutation ran against defaults.
        assert!(!called, "the mutation ran against defaults");
        assert!(path.is_dir());
    }

    /// A blank file holds nothing to lose; refusing it would wedge every write.
    #[test]
    fn mutate_treats_a_blank_file_as_fresh() {
        let dir = tempdir();
        std::fs::write(dir.path().join(SETTINGS_FILE), b"  \n").unwrap();
        UserSettings::mutate(dir.path(), |s| s.client_id = Some("c".into())).unwrap();
        assert_eq!(
            UserSettings::stored(dir.path()).client_id.as_deref(),
            Some("c")
        );
    }

    /// A second app instance (a separate open file description holding the
    /// advisory lock) keeps `mutate` waiting until it lets go.
    #[test]
    fn mutate_waits_for_another_instance_holding_the_settings_lock() {
        let dir = tempdir();
        let other_instance = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.path().join(SETTINGS_LOCK_FILE))
            .unwrap();
        other_instance.lock().unwrap();

        let path = dir.0.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            UserSettings::mutate(&path, |s| s.client_id = Some("x".into())).unwrap();
            tx.send(()).unwrap();
        });

        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "mutate did not wait for the other instance's lock"
        );
        drop(other_instance);
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("mutate never finished after the lock was released");
        writer.join().unwrap();
        assert_eq!(
            UserSettings::stored(dir.path()).client_id.as_deref(),
            Some("x")
        );
    }

    /// The cross-instance lock is best-effort: when it cannot be taken (here a
    /// directory squats on `settings.lock`, so the open fails the way an NFS
    /// home without a lock service fails the `flock`), the write still lands
    /// under the process lock instead of being refused.
    #[test]
    fn mutate_still_writes_when_the_settings_lock_cannot_be_taken() {
        let dir = tempdir();
        std::fs::create_dir(dir.path().join(SETTINGS_LOCK_FILE)).unwrap();

        UserSettings::mutate(dir.path(), |s| s.client_id = Some("c".into())).unwrap();

        assert_eq!(
            UserSettings::stored(dir.path()).client_id.as_deref(),
            Some("c")
        );
    }
}
