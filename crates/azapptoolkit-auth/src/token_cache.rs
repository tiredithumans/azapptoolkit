//! Access- and refresh-token storage.
//!
//! Access tokens stay in memory (never written to disk) and are keyed by the
//! pair `(tenant_id, scope_key)` so multi-audience apps (Graph + Key Vault +
//! ARM) can keep a fresh token per resource without evicting the others.
//! Refresh tokens, which are scope-agnostic, live in the OS secret store via
//! [`keyring`] — Windows Credential Manager / macOS Keychain / Secret
//! Service — and are shared across audiences for the same account.

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use zeroize::Zeroize;

use crate::error::{AuthError, Result};

pub const KEYRING_SERVICE: &str = "azapptoolkit";

/// keyring v4 split out `keyring-core` and no longer auto-installs a platform
/// credential store, so the first `Entry::new` fails with "No default store has
/// been set" until one is registered. Register the OS-native store (macOS
/// Keychain / Windows Credential Manager / Linux keyutils) exactly once, on
/// first use, memoizing the outcome so a registration failure surfaces the same
/// error on every subsequent call.
fn ensure_keyring_store() -> Result<()> {
    static STORE: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    STORE
        .get_or_init(|| {
            // Keep a store that was already registered (e.g. a test mock installed
            // via `keyring_core::set_default_store`) rather than clobbering it;
            // otherwise install the OS-native store. In production nothing
            // registers a store first, so this is the native path unchanged.
            if keyring_core::get_default_store().is_some() {
                Ok(())
            } else {
                register_native_store()
            }
        })
        .clone()
        .map_err(AuthError::Keyring)
}

/// Registers the OS-native credential store as `keyring_core`'s default store.
/// keyring 4.1 moved `use_native_store` behind its `cli` feature (which drags in
/// `rusqlite`), and its `v1` `Entry` auto-registration runs unconditionally —
/// it would clobber an already-installed store (e.g. the test mock). So register
/// the native store directly, mirroring keyring's internal
/// `v1::set_credential_store`: macOS Keychain, Windows Credential Manager, or
/// (Linux/BSD) the Secret Service via zbus.
fn register_native_store() -> std::result::Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let store =
            apple_native_keyring_store::keychain::Store::new().map_err(|e| e.to_string())?;
        keyring_core::set_default_store(store);
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        let store = windows_native_keyring_store::Store::new().map_err(|e| e.to_string())?;
        keyring_core::set_default_store(store);
        Ok(())
    }
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        let store = zbus_secret_service_keyring_store::Store::new().map_err(|e| e.to_string())?;
        keyring_core::set_default_store(store);
        Ok(())
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "linux",
        target_os = "freebsd",
    )))]
    {
        Err("no OS-native credential store is available on this platform".to_string())
    }
}

/// In-memory access token. The bearer string is zeroized on drop so freed
/// heap pages cannot leak token material to a later allocation, and `Debug`
/// renders the token as `<redacted>` so it cannot appear in tracing logs.
/// Deliberately NOT serde-serializable: the type system enforces the
/// memory-only contract (nothing in the workspace ever persisted one).
#[derive(Clone)]
pub struct AccessToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub scopes: Vec<String>,
}

impl AccessToken {
    pub fn needs_refresh(&self, leeway_secs: i64) -> bool {
        let now = Utc::now();
        (self.expires_at - now).num_seconds() < leeway_secs
    }
}

impl Drop for AccessToken {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

impl std::fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Canonicalizes a scope list into a stable cache key: dedup, sort ASCII-
/// ascending, space-join. Matches the identity `scope_key(["b","a"]) ==
/// scope_key(["a","b","a"])`.
pub fn scope_key(scopes: &[String]) -> String {
    let mut owned: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
    owned.sort_unstable();
    owned.dedup();
    owned.join(" ")
}

/// Token storage keyed by `(tenant_id, scope_key)`.
#[derive(Default)]
pub struct TokenCache {
    by_key: RwLock<HashMap<(String, String), AccessToken>>,
}

impl TokenCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn get(&self, tenant_id: &str, scopes: &[String]) -> Option<AccessToken> {
        let key = (tenant_id.to_string(), scope_key(scopes));
        self.by_key.read().get(&key).cloned()
    }

    pub fn put(&self, tenant_id: String, scopes: &[String], token: AccessToken) {
        let key = (tenant_id, scope_key(scopes));
        self.by_key.write().insert(key, token);
    }

    /// Drops every cached access token for `tenant_id`, across all scopes.
    pub fn invalidate_tenant(&self, tenant_id: &str) {
        self.by_key.write().retain(|(t, _), _| t != tenant_id);
    }
}

/// Windows Credential Manager caps a single credential blob at
/// `CRED_MAX_CREDENTIAL_BLOB_SIZE` = 2560 bytes of UTF-16, and Entra refresh
/// tokens routinely exceed that. So the secret is split across
/// consecutively-numbered keyring entries and reassembled on load. macOS
/// Keychain and the Linux Secret Service have far larger limits, but chunking
/// on every platform keeps one code path. The budget is measured in bytes of
/// UTF-16 (how Windows counts it) with margin under the 2560 limit, and chunks
/// are cut only on `char` boundaries so concatenation round-trips exactly.
const MAX_CHUNK_UTF16_BYTES: usize = 2048;

/// Keyring account label for chunk `idx`. Chunk 0 keeps the bare
/// `{tenant}:{oid}` label, so a credential written before chunking existed
/// (always a single entry) still loads unchanged.
fn chunk_account(tenant_id: &str, account_oid: &str, idx: usize) -> String {
    if idx == 0 {
        format!("{tenant_id}:{account_oid}")
    } else {
        format!("{tenant_id}:{account_oid}#{idx}")
    }
}

/// Splits `token` into chunks that each fit under the Windows blob limit,
/// cutting only on `char` boundaries. Always returns at least one chunk (an
/// empty token yields a single empty chunk) so the stored entry count is never
/// zero.
fn split_into_chunks(token: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut start = 0;
    let mut bytes = 0;
    for (idx, ch) in token.char_indices() {
        let width = ch.len_utf16() * 2;
        if bytes > 0 && bytes + width > MAX_CHUNK_UTF16_BYTES {
            chunks.push(&token[start..idx]);
            start = idx;
            bytes = 0;
        }
        bytes += width;
    }
    chunks.push(&token[start..]);
    chunks
}

pub fn save_refresh_token(tenant_id: &str, account_oid: &str, token: &str) -> Result<()> {
    ensure_keyring_store()?;
    let chunks = split_into_chunks(token);
    for (idx, chunk) in chunks.iter().enumerate() {
        let account = chunk_account(tenant_id, account_oid, idx);
        keyring_core::Entry::new(KEYRING_SERVICE, &account)?.set_password(chunk)?;
    }
    // Clear any trailing chunks left by a previously larger token, so a shrunk
    // token doesn't load with stale tail bytes appended.
    let mut idx = chunks.len();
    loop {
        let account = chunk_account(tenant_id, account_oid, idx);
        match keyring_core::Entry::new(KEYRING_SERVICE, &account)?.delete_credential() {
            Ok(()) => idx += 1,
            Err(keyring_core::Error::NoEntry) => break,
            Err(err) => return Err(AuthError::Keyring(err.to_string())),
        }
    }
    Ok(())
}

pub fn load_refresh_token(tenant_id: &str, account_oid: &str) -> Result<Option<String>> {
    ensure_keyring_store()?;
    let mut combined = String::new();
    let mut idx = 0;
    loop {
        let account = chunk_account(tenant_id, account_oid, idx);
        match keyring_core::Entry::new(KEYRING_SERVICE, &account)?.get_password() {
            Ok(part) => {
                combined.push_str(&part);
                idx += 1;
            }
            Err(keyring_core::Error::NoEntry) => break,
            Err(err) => return Err(AuthError::Keyring(err.to_string())),
        }
    }
    if idx == 0 {
        Ok(None)
    } else {
        Ok(Some(combined))
    }
}

pub fn delete_refresh_token(tenant_id: &str, account_oid: &str) -> Result<()> {
    ensure_keyring_store()?;
    let mut idx = 0;
    loop {
        let account = chunk_account(tenant_id, account_oid, idx);
        match keyring_core::Entry::new(KEYRING_SERVICE, &account)?.delete_credential() {
            Ok(()) => idx += 1,
            Err(keyring_core::Error::NoEntry) => break,
            Err(err) => return Err(AuthError::Keyring(err.to_string())),
        }
    }
    Ok(())
}

/// Test-only: install the in-memory mock keyring store once per test binary so
/// keyring round-trips don't touch the OS keychain (which needs entitlements and
/// isn't available in CI). Shared across the crate's test modules so they all use
/// the *same* store instance — otherwise two modules racing to register separate
/// mocks would lose each other's entries. `ensure_keyring_store` keeps an
/// already-registered store, so this only has to run before the first keyring op.
#[cfg(test)]
pub(crate) fn init_mock_keyring() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn needs_refresh_returns_true_inside_leeway() {
        let tok = AccessToken {
            token: "t".into(),
            expires_at: Utc::now() + Duration::seconds(30),
            scopes: vec![],
        };
        assert!(tok.needs_refresh(60));
    }

    #[test]
    fn needs_refresh_returns_false_when_fresh() {
        let tok = AccessToken {
            token: "t".into(),
            expires_at: Utc::now() + Duration::seconds(3600),
            scopes: vec![],
        };
        assert!(!tok.needs_refresh(60));
    }

    #[test]
    fn split_into_chunks_round_trips_and_bounds_size() {
        // A token several times the per-chunk budget must split, with every
        // chunk under the Windows UTF-16 blob limit and the join lossless.
        let token = "a".repeat(4000);
        let chunks = split_into_chunks(&token);
        assert!(chunks.len() > 1, "large token should split");
        for chunk in &chunks {
            let utf16_bytes: usize = chunk.chars().map(|c| c.len_utf16() * 2).sum();
            assert!(utf16_bytes <= MAX_CHUNK_UTF16_BYTES);
        }
        assert_eq!(chunks.concat(), token);
    }

    #[test]
    fn split_into_chunks_round_trips_multibyte() {
        // Multi-byte chars must not be cut mid-character.
        let token: String = "🔐é".repeat(500);
        let chunks = split_into_chunks(&token);
        for chunk in &chunks {
            let utf16_bytes: usize = chunk.chars().map(|c| c.len_utf16() * 2).sum();
            assert!(utf16_bytes <= MAX_CHUNK_UTF16_BYTES);
        }
        assert_eq!(chunks.concat(), token);
    }

    #[test]
    fn split_into_chunks_keeps_small_token_single() {
        assert_eq!(split_into_chunks("short-token"), vec!["short-token"]);
        assert_eq!(split_into_chunks(""), vec![""]);
    }

    #[test]
    fn chunk_account_labels_are_distinct_and_back_compatible() {
        assert_eq!(chunk_account("t", "oid", 0), "t:oid");
        assert_eq!(chunk_account("t", "oid", 1), "t:oid#1");
        assert_ne!(chunk_account("t", "oid", 1), chunk_account("t", "oid", 2));
    }

    #[test]
    fn refresh_token_chunks_round_trip_through_the_keyring() {
        init_mock_keyring();
        let (tenant, oid) = ("rt-tenant", "rt-oid");

        // A multi-chunk token (>4 KB, several times the per-chunk budget) must
        // load back byte-identical after being split across numbered entries.
        let big: String = "x".repeat(MAX_CHUNK_UTF16_BYTES * 3 + 17);
        save_refresh_token(tenant, oid, &big).unwrap();
        assert_eq!(load_refresh_token(tenant, oid).unwrap(), Some(big));

        // Overwriting with a SHORTER (single-chunk) token must clear the larger
        // token's trailing chunks, so the load carries no stale tail — this is the
        // integrity path an off-by-one in the cleanup loop would break.
        let small = "short".to_string();
        save_refresh_token(tenant, oid, &small).unwrap();
        assert_eq!(load_refresh_token(tenant, oid).unwrap(), Some(small));
        assert!(
            matches!(
                keyring_core::Entry::new(KEYRING_SERVICE, &chunk_account(tenant, oid, 1))
                    .unwrap()
                    .get_password(),
                Err(keyring_core::Error::NoEntry)
            ),
            "trailing chunk #1 must be deleted when the token shrinks"
        );

        // Delete removes every chunk; load then reports nothing.
        delete_refresh_token(tenant, oid).unwrap();
        assert_eq!(load_refresh_token(tenant, oid).unwrap(), None);
    }

    #[test]
    fn scope_key_is_canonical() {
        let a = scope_key(&["b".into(), "a".into(), "a".into()]);
        let b = scope_key(&["a".into(), "b".into()]);
        assert_eq!(a, b);
        assert_eq!(a, "a b");
    }

    #[test]
    fn token_cache_separates_scopes() {
        let cache = TokenCache::new();
        let graph_scopes = vec!["https://graph.microsoft.com/.default".to_string()];
        let kv_scopes = vec!["https://vault.azure.net/.default".to_string()];
        cache.put(
            "tenant".into(),
            &graph_scopes,
            AccessToken {
                token: "graph".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
                scopes: graph_scopes.clone(),
            },
        );
        cache.put(
            "tenant".into(),
            &kv_scopes,
            AccessToken {
                token: "kv".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
                scopes: kv_scopes.clone(),
            },
        );
        assert_eq!(cache.get("tenant", &graph_scopes).unwrap().token, "graph");
        assert_eq!(cache.get("tenant", &kv_scopes).unwrap().token, "kv");
    }

    #[test]
    fn invalidate_tenant_drops_every_scope() {
        let cache = TokenCache::new();
        let scopes = vec!["a".to_string()];
        cache.put(
            "tenant".into(),
            &scopes,
            AccessToken {
                token: "t".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
                scopes: scopes.clone(),
            },
        );
        cache.invalidate_tenant("tenant");
        assert!(cache.get("tenant", &scopes).is_none());
    }
}
