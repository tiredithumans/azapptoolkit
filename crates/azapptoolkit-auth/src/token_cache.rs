//! Access- and refresh-token storage.
//!
//! Access tokens stay in memory (never written to disk), keyed by
//! `(tenant_id, scope_key, cae)`: a multi-audience app keeps a fresh token per
//! resource without evicting the others, and a token minted without the `cp1`
//! client capability is never served to a Continuous Access Evaluation consumer
//! (or vice versa).
//! Refresh tokens are scope-agnostic and live in the OS secret store via
//! [`keyring_core`] — Windows Credential Manager / macOS Keychain / the D-Bus
//! Secret Service on Linux (a hard requirement there: without a provider,
//! sign-in fails with [`AuthError::KeyringUnavailable`]) — shared across
//! audiences for the same account.

use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{AuthError, Result};

pub const KEYRING_SERVICE: &str = "azapptoolkit";

/// keyring v4 split out `keyring-core` and no longer auto-installs a platform
/// credential store, so the first `Entry::new` fails with "No default store has
/// been set" until one is registered. Register the OS-native store exactly once
/// on first use, memoizing the outcome so a registration failure surfaces the
/// same error on every subsequent call.
///
/// A registration failure is [`AuthError::KeyringUnavailable`] (no store at
/// all), never [`AuthError::Keyring`] (a store that exists but refused).
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
        .map_err(AuthError::KeyringUnavailable)
}

/// Registers the OS-native credential store as `keyring_core`'s default store,
/// mirroring keyring's internal `v1::set_credential_store`: macOS Keychain,
/// Windows Credential Manager, or (Linux/BSD) the Secret Service via zbus.
/// keyring 4.1 moved `use_native_store` behind its `cli` feature (which drags in
/// `rusqlite`), and its `v1` `Entry` auto-registration runs unconditionally —
/// it would clobber an already-installed store (e.g. the test mock).
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

/// In-memory access token. The bearer string is zeroized on drop so freed heap
/// pages cannot leak token material, and `Debug` renders `<redacted>` so it
/// cannot appear in tracing logs. Deliberately NOT serde-serializable: the type
/// system enforces the memory-only contract.
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

/// Canonicalizes a scope list into a stable cache key: dedup, sort
/// ASCII-ascending, space-join — `scope_key(["b","a"]) ==
/// scope_key(["a","b","a"])`.
pub fn scope_key(scopes: &[String]) -> String {
    let mut owned: Vec<&str> = scopes.iter().map(|s| s.as_str()).collect();
    owned.sort_unstable();
    owned.dedup();
    owned.join(" ")
}

/// Token storage keyed by `(tenant_id, scope_key, cae)`.
///
/// CAE-ness is part of the key because the same scope set is consumed both
/// ways: the Graph adapters (`ScopedTokenAdapter::new_cae`) need a token minted
/// with the `cp1` claims (revoked promptly on a password reset, disabled user
/// or risky sign-in), while a plain probe or a non-Graph audience does not.
/// Without it, whichever flow seeded the slot first decided for both; now a
/// mismatch costs one extra silent refresh instead of a wrong token.
#[derive(Default)]
pub struct TokenCache {
    by_key: RwLock<HashMap<(String, String, bool), AccessToken>>,
}

impl TokenCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The cached token for `scopes`, minted with (`cae = true`) or without
    /// the `cp1` CAE client capability.
    pub fn get(&self, tenant_id: &str, scopes: &[String], cae: bool) -> Option<AccessToken> {
        let key = (tenant_id.to_string(), scope_key(scopes), cae);
        self.by_key.read().get(&key).cloned()
    }

    /// Caches `token` for `scopes` in the CAE (`cae = true`) or non-CAE slot.
    pub fn put(&self, tenant_id: String, scopes: &[String], cae: bool, token: AccessToken) {
        let key = (tenant_id, scope_key(scopes), cae);
        self.by_key.write().insert(key, token);
    }

    /// Drops every cached access token for `tenant_id`, across all scopes and
    /// both CAE slots.
    pub fn invalidate_tenant(&self, tenant_id: &str) {
        self.by_key.write().retain(|(t, _, _), _| t != tenant_id);
    }
}

/// Windows Credential Manager caps a credential blob at
/// `CRED_MAX_CREDENTIAL_BLOB_SIZE` = 2560 bytes of UTF-16, and Entra refresh
/// tokens routinely exceed that, so the secret is split across
/// consecutively-numbered keyring entries and reassembled on load. macOS
/// Keychain and the Linux Secret Service have far larger limits, but chunking
/// on every platform keeps one code path. The budget is UTF-16 bytes (how
/// Windows counts) with margin under 2560, and chunks cut only on `char`
/// boundaries so concatenation round-trips exactly.
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

/// Marks a chunk-0 value that carries the set's chunk count, e.g. `azapp1:3:`.
///
/// The count is what makes a torn set **detectable**. `CHUNK_SET_LOCK`
/// serializes writers within one process, but not a hard crash mid-write or a
/// second app instance. Without it a partial set loads as a splice of two
/// tokens; Entra rejects it as `invalid_grant`, which reads as a revoked
/// session rather than a corrupt one.
///
/// Absent on a value written before this existed — read as a legacy set and
/// concatenated as before, so an upgrade does not sign everyone out.
const CHUNK_COUNT_PREFIX: &str = "azapp1:";

/// Builds chunk 0's stored value: the marker, the total chunk count, and the
/// payload.
fn encode_chunk_zero(total: usize, payload: &str) -> String {
    format!("{CHUNK_COUNT_PREFIX}{total}:{payload}")
}

/// Splits chunk 0's stored value into `(declared count, payload)`, or `None`
/// when it predates the marker.
fn decode_chunk_zero(stored: &str) -> Option<(usize, &str)> {
    let rest = stored.strip_prefix(CHUNK_COUNT_PREFIX)?;
    let (count, payload) = rest.split_once(':')?;
    Some((count.parse().ok()?, payload))
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

/// Serializes every read-modify-write of one account's chunk set.
///
/// `refresh_lock_for` is keyed per `(tenant, scope_key)` BY DESIGN, so refreshes
/// for different audiences run concurrently — Access Readiness fans about six
/// out at once — and each ends in `store_token_outcome`, writing the rotated
/// refresh token to the same `(tenant, oid)` chunk set on the blocking pool.
/// Interleave a 3-chunk writer with a 2-chunk writer and the store holds
/// `B0|A1|A2`; `load_refresh_token` returns the splice, the next silent refresh
/// fails `invalid_grant`, and the session is purged — reading as a revoked
/// token rather than a corrupt one.
///
/// A single global mutex rather than a per-account map: these are OS keyring
/// syscalls on a blocking thread, contention is a handful of writers, and a map
/// is one more thing to get wrong for no measurable gain.
///
/// `parking_lot`, so no poisoning — correct here: a panic mid-write leaves the
/// store possibly torn, the state the load path already fails closed on, so
/// later reads and writes proceed instead of turning a recoverable "sign in
/// again" into a permanently broken keyring.
static CHUNK_SET_LOCK: Mutex<()> = Mutex::new(());

pub fn save_refresh_token(tenant_id: &str, account_oid: &str, token: &str) -> Result<()> {
    ensure_keyring_store()?;
    let _guard = CHUNK_SET_LOCK.lock();
    // A refresh token spans N keyring entries and `load` simply concatenates
    // until one is missing — no length, no checksum, nothing marking where the
    // token ends. A write that stops half way leaves chunks 0..k with the NEW
    // token and k..old_len with the OLD one's tail, and the next load returns
    // that splice as if it were a token: Entra rejects it, and the failure
    // reads as a revoked refresh token rather than a corrupt one.
    //
    // So a partial write is rolled back to nothing: no session is a state the
    // app already handles (it prompts to sign in); a spliced one is not.
    //
    // Unless nothing was written: a write refused at chunk 0 (a locked store)
    // left the previous set whole, and that token is still valid — Entra does
    // not revoke a refresh token on rotation. Wiping it would turn one keyring
    // hiccup into a forced sign-in.
    let mut overwrote_chunk_zero = false;
    if let Err(err) = write_chunks(tenant_id, account_oid, token, &mut overwrote_chunk_zero) {
        if overwrote_chunk_zero {
            // Best-effort: if the keyring is failing the cleanup may fail too;
            // either way the original error is what the caller needs.
            // Lock-free form: this thread already holds the guard.
            let _ = delete_chunks(tenant_id, account_oid);
        }
        return Err(err);
    }
    Ok(())
}

/// The write itself: every chunk, then the trailing chunks of any previously
/// larger token — without which a shrunk token loads with a stale tail appended.
/// Sets `overwrote_chunk_zero` once chunk 0 is replaced, so a failure can tell
/// a torn set (roll back) from an untouched one (keep).
fn write_chunks(
    tenant_id: &str,
    account_oid: &str,
    token: &str,
    overwrote_chunk_zero: &mut bool,
) -> Result<()> {
    let chunks = split_into_chunks(token);
    for (idx, chunk) in chunks.iter().enumerate() {
        let account = chunk_account(tenant_id, account_oid, idx);
        // Chunk 0 carries the set's total count, so a load can tell a complete
        // set from a torn one. Written FIRST, so a crash leaves a count that
        // exceeds what is stored — which fails closed — rather than a
        // plausible-looking short set. Wiped once written (mirroring
        // `load_chunks`): each chunk copy is plaintext token material.
        let value = Zeroizing::new(if idx == 0 {
            encode_chunk_zero(chunks.len(), chunk)
        } else {
            (*chunk).to_string()
        });
        keyring_core::Entry::new(KEYRING_SERVICE, &account)?.set_password(&value)?;
        if idx == 0 {
            *overwrote_chunk_zero = true;
        }
    }
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

/// Reassembles a chunked refresh token.
///
/// Returns `Zeroizing<String>` rather than a bare `String`: the call site wraps
/// the result to keep the secret off freed heap pages, and that guarantee was
/// undone in here. Each `get_password()` chunk is a fully-materialized plaintext
/// `String` dropped un-wiped, and `push_str` reallocates as it grows, stranding
/// the earlier buffer too — a refresh token spans one to two 2048-byte chunks,
/// so at least one growth realloc happened on every refresh. Making it the
/// return type turns the contract from a convention into something structural.
pub fn load_refresh_token(tenant_id: &str, account_oid: &str) -> Result<Option<Zeroizing<String>>> {
    ensure_keyring_store()?;
    // Held for the read too: without it a load can observe a half-written set
    // and return a splice of two tokens as though it were one.
    let _guard = CHUNK_SET_LOCK.lock();
    load_chunks(tenant_id, account_oid)
}

/// The read itself, without taking the lock — for callers already holding it
/// (`delete_refresh_token_if_current` compares and deletes under one guard).
fn load_chunks(tenant_id: &str, account_oid: &str) -> Result<Option<Zeroizing<String>>> {
    // Preallocated so the common one-or-two-chunk token never reallocates and
    // leaves a plaintext copy behind.
    let mut combined = Zeroizing::new(String::with_capacity(MAX_CHUNK_UTF16_BYTES * 2));
    let mut idx = 0;
    let mut declared: Option<usize> = None;
    loop {
        let account = chunk_account(tenant_id, account_oid, idx);
        match keyring_core::Entry::new(KEYRING_SERVICE, &account)?.get_password() {
            Ok(part) => {
                // Bound mutably and wiped after appending: the chunk is
                // plaintext, and dropping it un-zeroized leaves the whole token
                // recoverable from freed pages. The wipe covers the
                // marker-carrying chunk 0 too — its payload is a borrow of
                // `part`, so it must be appended before the wipe, not after.
                let mut part = part;
                if idx == 0 {
                    match decode_chunk_zero(&part) {
                        Some((total, payload)) => {
                            declared = Some(total);
                            combined.push_str(payload);
                        }
                        // Written before the marker existed: always a complete
                        // set by construction, so read it as before.
                        None => combined.push_str(&part),
                    }
                } else {
                    combined.push_str(&part);
                }
                part.zeroize();
                idx += 1;
            }
            Err(keyring_core::Error::NoEntry) => break,
            Err(err) => return Err(AuthError::Keyring(err.to_string())),
        }
    }
    if idx == 0 {
        return Ok(None);
    }
    // Fail closed on a set that does not match its own declared length: "no
    // session" is a state the app already handles (it prompts to sign in); a
    // spliced token is not — it looks like a stored session until Entra
    // rejects it as revoked.
    if let Some(total) = declared
        && total != idx
    {
        tracing::warn!(
            target: "auth",
            expected = total,
            found = idx,
            "refresh token chunk set is incomplete; treating as no stored session"
        );
        return Ok(None);
    }
    Ok(Some(combined))
}

pub fn delete_refresh_token(tenant_id: &str, account_oid: &str) -> Result<()> {
    ensure_keyring_store()?;
    let _guard = CHUNK_SET_LOCK.lock();
    delete_chunks(tenant_id, account_oid)
}

/// What [`delete_refresh_token_if_current`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PurgeOutcome {
    /// The store still held the rejected token; it is gone now.
    Deleted,
    /// Nothing (or only a torn set, now cleared) was stored.
    AlreadyGone,
    /// A different token replaced the rejected one — a `reauthenticate` or
    /// consent that completed while the failing refresh was in flight. Kept.
    Superseded,
}

/// Deletes the stored refresh token only if it is still `rejected` — the one
/// that just failed `invalid_grant`.
///
/// Refreshes for different audiences run concurrently, so a slow one can fail
/// with the OLD token after the operator already re-authenticated and stored a
/// new one; an unconditional purge would erase that fresh session. The check
/// and the delete share `CHUNK_SET_LOCK` with every save, so no write can land
/// between them.
pub fn delete_refresh_token_if_current(
    tenant_id: &str,
    account_oid: &str,
    rejected: &str,
) -> Result<PurgeOutcome> {
    ensure_keyring_store()?;
    let _guard = CHUNK_SET_LOCK.lock();
    match load_chunks(tenant_id, account_oid)? {
        Some(current) if current.as_str() != rejected => Ok(PurgeOutcome::Superseded),
        Some(_) => {
            delete_chunks(tenant_id, account_oid)?;
            Ok(PurgeOutcome::Deleted)
        }
        // `load_chunks` reads a torn set as `None`; clearing it keeps the old
        // "purge whatever is there" behaviour for that case.
        None => {
            delete_chunks(tenant_id, account_oid)?;
            Ok(PurgeOutcome::AlreadyGone)
        }
    }
}

/// The deletion itself, without taking the lock — for callers already holding
/// it. Split out so `save_refresh_token`'s rollback cannot deadlock on its own
/// guard.
fn delete_chunks(tenant_id: &str, account_oid: &str) -> Result<()> {
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
/// keyring round-trips don't touch the OS keychain (which needs entitlements
/// and isn't available in CI). Shared across the crate's test modules so they
/// all use the *same* store instance — otherwise two modules racing to register
/// separate mocks would lose each other's entries. `ensure_keyring_store` keeps
/// an already-registered store, so this only has to run before the first op.
#[cfg(test)]
pub(crate) fn init_mock_keyring() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
    });
}

/// Test-only: make the NEXT keyring operation on chunk `chunk` of
/// `(tenant_id, account_oid)` fail, as a locked credential store would. The mock
/// store hands out the same credential for the same service/user and consumes
/// the error on the next call, so exactly one operation fails.
#[cfg(test)]
pub(crate) fn fail_next_keyring_op(tenant_id: &str, account_oid: &str, chunk: usize) {
    init_mock_keyring();
    let entry = keyring_core::Entry::new(
        KEYRING_SERVICE,
        &chunk_account(tenant_id, account_oid, chunk),
    )
    .unwrap();
    entry
        .as_any()
        .downcast_ref::<keyring_core::mock::Cred>()
        .expect("the mock keyring store is installed")
        .set_error(keyring_core::Error::Invalid(
            "mock".into(),
            "credential store locked".into(),
        ));
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
        assert_eq!(
            load_refresh_token(tenant, oid).unwrap().as_deref(),
            Some(&big)
        );

        // Overwriting with a SHORTER (single-chunk) token must clear the larger
        // token's trailing chunks, so the load carries no stale tail — this is the
        // integrity path an off-by-one in the cleanup loop would break.
        let small = "short".to_string();
        save_refresh_token(tenant, oid, &small).unwrap();
        assert_eq!(
            load_refresh_token(tenant, oid).unwrap().as_deref(),
            Some(&small)
        );
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

    /// The rollback a failed `save_refresh_token` performs must clear **every**
    /// chunk, however many are there — not just the ones this write created.
    ///
    /// A partial write leaves chunks 0..k holding the new token and k.. the
    /// previous one's tail, and `load` just concatenates until an entry is
    /// missing, so it would return the splice as if it were a real token. A
    /// rollback bounded by the *new* token's chunk count would leave exactly
    /// that tail behind.
    ///
    /// The failing write needs a keyring that can be made to fail mid-loop,
    /// which the mock store cannot do; this pins the property the rollback
    /// depends on.
    #[test]
    fn the_rollback_clears_chunks_it_did_not_write() {
        init_mock_keyring();
        let (tenant, oid) = ("rb-tenant", "rb-oid");

        // Stand in for the state a half-finished write leaves: more chunks on
        // disk than the token being written would produce.
        for idx in 0..4 {
            keyring_core::Entry::new(KEYRING_SERVICE, &chunk_account(tenant, oid, idx))
                .unwrap()
                .set_password("stale")
                .unwrap();
        }

        delete_refresh_token(tenant, oid).unwrap();

        assert_eq!(
            load_refresh_token(tenant, oid).unwrap(),
            None,
            "a rollback must leave NO session rather than a spliced one"
        );
    }

    /// A write the store refuses at chunk 0 changed nothing, so the previous
    /// (still valid) token must survive — rolling back there used to wipe it
    /// and force a sign-in over one locked-keyring moment.
    #[test]
    fn a_write_refused_at_chunk_zero_keeps_the_previous_token() {
        init_mock_keyring();
        let (tenant, oid) = ("chunk0-tenant", "chunk0-oid");
        save_refresh_token(tenant, oid, "old").unwrap();
        fail_next_keyring_op(tenant, oid, 0);

        let result = save_refresh_token(tenant, oid, "new");

        assert!(matches!(result, Err(AuthError::Keyring(_))), "{result:?}");
        assert_eq!(
            load_refresh_token(tenant, oid)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("old")
        );
    }

    #[test]
    fn conditional_delete_only_removes_the_rejected_token() {
        init_mock_keyring();
        let (tenant, oid) = ("cond-tenant", "cond-oid");
        save_refresh_token(tenant, oid, "a").unwrap();

        // A newer token replaced the rejected one: it must survive.
        assert_eq!(
            delete_refresh_token_if_current(tenant, oid, "b").unwrap(),
            PurgeOutcome::Superseded
        );
        assert_eq!(
            load_refresh_token(tenant, oid)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("a")
        );

        // The rejected token is still the stored one: it goes.
        assert_eq!(
            delete_refresh_token_if_current(tenant, oid, "a").unwrap(),
            PurgeOutcome::Deleted
        );
        assert_eq!(load_refresh_token(tenant, oid).unwrap(), None);
        assert_eq!(
            delete_refresh_token_if_current(tenant, oid, "a").unwrap(),
            PurgeOutcome::AlreadyGone
        );
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
            false,
            AccessToken {
                token: "graph".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
                scopes: graph_scopes.clone(),
            },
        );
        cache.put(
            "tenant".into(),
            &kv_scopes,
            false,
            AccessToken {
                token: "kv".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
                scopes: kv_scopes.clone(),
            },
        );
        assert_eq!(
            cache.get("tenant", &graph_scopes, false).unwrap().token,
            "graph"
        );
        assert_eq!(cache.get("tenant", &kv_scopes, false).unwrap().token, "kv");
    }

    #[test]
    fn token_cache_separates_cae_from_non_cae() {
        let cache = TokenCache::new();
        let scopes = vec!["https://graph.microsoft.com/Directory.Read.All".to_string()];
        let token = |t: &str| AccessToken {
            token: t.into(),
            expires_at: Utc::now() + Duration::seconds(3600),
            scopes: scopes.clone(),
        };
        // A non-CAE seed is never served to a CAE consumer.
        cache.put("tenant".into(), &scopes, false, token("plain"));
        assert!(cache.get("tenant", &scopes, true).is_none());
        // Both slots coexist, each returning its own token.
        cache.put("tenant".into(), &scopes, true, token("cae"));
        assert_eq!(cache.get("tenant", &scopes, false).unwrap().token, "plain");
        assert_eq!(cache.get("tenant", &scopes, true).unwrap().token, "cae");
        // Sign-out / refresh drops both.
        cache.invalidate_tenant("tenant");
        assert!(cache.get("tenant", &scopes, false).is_none());
        assert!(cache.get("tenant", &scopes, true).is_none());
    }

    #[test]
    fn invalidate_tenant_drops_every_scope() {
        let cache = TokenCache::new();
        let scopes = vec!["a".to_string()];
        cache.put(
            "tenant".into(),
            &scopes,
            true,
            AccessToken {
                token: "t".into(),
                expires_at: Utc::now() + Duration::seconds(3600),
                scopes: scopes.clone(),
            },
        );
        cache.invalidate_tenant("tenant");
        assert!(cache.get("tenant", &scopes, true).is_none());
    }

    /// A set whose chunks do not match its own declared count must load as "no
    /// session", not as a splice.
    ///
    /// The lock serializes writers within one process; it cannot cover a hard
    /// crash mid-write or a second app instance. Without the count a partial
    /// set loaded as a plausible-looking token, Entra rejected it as
    /// `invalid_grant`, and the failure read as a revoked session rather than
    /// a corrupt one.
    #[test]
    fn a_torn_chunk_set_fails_closed_instead_of_splicing() {
        init_mock_keyring();
        let (tenant, oid) = ("tenant-torn", "oid-torn");

        // A three-chunk token, then the tail deleted behind the loader's back —
        // exactly what a crash between chunk writes leaves.
        let big: String = "x".repeat(MAX_CHUNK_UTF16_BYTES * 2 + 17);
        save_refresh_token(tenant, oid, &big).unwrap();
        let last = chunk_account(tenant, oid, 2);
        keyring_core::Entry::new(KEYRING_SERVICE, &last)
            .unwrap()
            .delete_credential()
            .unwrap();

        assert_eq!(
            load_refresh_token(tenant, oid).unwrap(),
            None,
            "a short set must not load as a token"
        );
    }

    /// A value written before the count marker existed still loads, so shipping
    /// this does not sign every existing user out.
    #[test]
    fn a_legacy_unmarked_entry_still_loads() {
        init_mock_keyring();
        let (tenant, oid) = ("tenant-legacy", "oid-legacy");
        // The pre-marker shape: one entry, bare payload, no prefix.
        keyring_core::Entry::new(KEYRING_SERVICE, &chunk_account(tenant, oid, 0))
            .unwrap()
            .set_password("legacy-refresh-token")
            .unwrap();
        assert_eq!(
            load_refresh_token(tenant, oid)
                .unwrap()
                .as_deref()
                .map(String::as_str),
            Some("legacy-refresh-token")
        );
    }

    /// The marker is stripped, not returned as part of the secret.
    #[test]
    fn the_count_marker_never_leaks_into_the_token() {
        init_mock_keyring();
        let (tenant, oid) = ("tenant-marker", "oid-marker");
        save_refresh_token(tenant, oid, "plain-token").unwrap();
        let loaded = load_refresh_token(tenant, oid).unwrap().unwrap();
        assert_eq!(loaded.as_str(), "plain-token");
        assert!(!loaded.contains(CHUNK_COUNT_PREFIX));
    }
}
