//! LRU + TTL cache that mirrors `Private/Cache-Functions.ps1`.
//!
//! Keyed by `(CacheKind, String)`; each kind has its own TTL (see
//! [`crate::constants`]). Eviction is LRU once per-kind entry count exceeds
//! [`MAX_CACHE_SIZE`]. Hit/miss counters are exposed for the diagnostics
//! command surface.

use parking_lot::Mutex;
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::constants::{
    AUDIT_CACHE_TTL, LISTS_CACHE_TTL, MAX_CACHE_SIZE, PERMISSIONS_CACHE_TTL,
    SERVICE_PRINCIPAL_CACHE_TTL,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CacheKind {
    ServicePrincipal,
    Permissions,
    Audit,
    /// Tenant-scoped list responses (App Registrations, Enterprise apps,
    /// Managed identities). Keys are prefixed with `"{tenant_id}|"`.
    Lists,
}

impl CacheKind {
    /// All kinds, for whole-cache operations (clear, tenant sweep). Adding a
    /// variant must extend this — the per-kind bucket array is sized to it.
    const ALL: [CacheKind; 4] = [
        CacheKind::ServicePrincipal,
        CacheKind::Permissions,
        CacheKind::Audit,
        CacheKind::Lists,
    ];

    /// Index into the per-kind bucket array (matches enum declaration order).
    fn idx(self) -> usize {
        self as usize
    }
}

/// Runtime-mutable cache settings. Mirrors `Set-azapptoolkitCacheConfiguration`:
/// caching can be toggled and the per-kind TTLs / entry cap adjusted live.
/// Defaults come from [`crate::constants`].
#[derive(Debug, Clone, Copy)]
pub struct CacheConfig {
    pub enabled: bool,
    pub service_principal_ttl: Duration,
    pub permissions_ttl: Duration,
    pub audit_ttl: Duration,
    pub lists_ttl: Duration,
    pub max_size: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_principal_ttl: SERVICE_PRINCIPAL_CACHE_TTL,
            permissions_ttl: PERMISSIONS_CACHE_TTL,
            audit_ttl: AUDIT_CACHE_TTL,
            lists_ttl: LISTS_CACHE_TTL,
            max_size: MAX_CACHE_SIZE,
        }
    }
}

impl CacheConfig {
    fn ttl_for(&self, kind: CacheKind) -> Duration {
        match kind {
            CacheKind::ServicePrincipal => self.service_principal_ttl,
            CacheKind::Permissions => self.permissions_ttl,
            CacheKind::Audit => self.audit_ttl,
            CacheKind::Lists => self.lists_ttl,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CacheStats {
    pub service_principal_hits: u64,
    pub service_principal_misses: u64,
    pub permissions_hits: u64,
    pub permissions_misses: u64,
    pub audit_hits: u64,
    pub audit_misses: u64,
    pub lists_hits: u64,
    pub lists_misses: u64,
}

struct Entry {
    // `Arc` so a `get` clones a refcount, not the whole JSON tree, while holding
    // the buckets mutex. The index entries (`sp_index`, the cached audit run) are
    // multi-MB on a large tenant; deep-cloning one under the lock that every
    // other list read, per-app SP lookup, and invalidation also needs was the
    // cache's contention point. The deserialize then borrows the Arc'd value
    // after the lock is dropped, so the tree is never duplicated.
    value: Arc<serde_json::Value>,
    // Optional typed handle, set by `put_typed`, so `get_typed` returns the
    // original `Arc<T>` (a refcount clone) without re-deserializing — the hot
    // path for the multi-MB tenant search corpus, which a debounced keystroke
    // would otherwise rebuild from JSON every query.
    typed: Option<Arc<dyn Any + Send + Sync>>,
    inserted: Instant,
    // Monotonically-increasing counter used for LRU ordering.
    last_access: u64,
}

struct Bucket {
    entries: HashMap<String, Entry>,
    tick: u64,
}

impl Bucket {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            tick: 0,
        }
    }

    fn touch(&mut self, key: &str) {
        self.tick += 1;
        if let Some(e) = self.entries.get_mut(key) {
            e.last_access = self.tick;
        }
    }

    fn evict_lru(&mut self, max_size: usize) {
        // Shrink down to the cap, not just by one. A single eviction per call is
        // enough on the steady-insert path, but when `configure` lowers
        // `max_size` on an already-oversized bucket it would take that many more
        // `put`s to converge — and never converge at all if writes stop. Evict
        // the least-recently-used entry repeatedly until within the bound.
        while self.entries.len() > max_size {
            let oldest_key = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone());
            match oldest_key {
                Some(k) => {
                    self.entries.remove(&k);
                }
                None => break,
            }
        }
    }
}

pub struct Cache {
    // One lock PER kind (indexed by `CacheKind::idx`) instead of a single lock
    // over all kinds — so an interactive `Lists` read never blocks on an audit's
    // continuous `Audit`/`ServicePrincipal` writes (and vice versa).
    buckets: [Mutex<Bucket>; 4],
    stats: Mutex<CacheStats>,
    config: Mutex<CacheConfig>,
}

impl Cache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            buckets: [
                Mutex::new(Bucket::new()),
                Mutex::new(Bucket::new()),
                Mutex::new(Bucket::new()),
                Mutex::new(Bucket::new()),
            ],
            stats: Mutex::new(CacheStats::default()),
            config: Mutex::new(CacheConfig::default()),
        })
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.config.lock().enabled = enabled;
    }

    pub fn enabled(&self) -> bool {
        self.config.lock().enabled
    }

    /// Current effective configuration (for the diagnostics surface).
    pub fn config(&self) -> CacheConfig {
        *self.config.lock()
    }

    /// Applies the provided settings, leaving any `None` field unchanged.
    /// Mirrors `Set-azapptoolkitCacheConfiguration`'s bound-parameter semantics.
    pub fn configure(
        &self,
        enabled: Option<bool>,
        service_principal_ttl: Option<Duration>,
        permissions_ttl: Option<Duration>,
        audit_ttl: Option<Duration>,
        lists_ttl: Option<Duration>,
        max_size: Option<usize>,
    ) {
        let mut c = self.config.lock();
        if let Some(e) = enabled {
            c.enabled = e;
        }
        if let Some(t) = service_principal_ttl {
            c.service_principal_ttl = t;
        }
        if let Some(t) = permissions_ttl {
            c.permissions_ttl = t;
        }
        if let Some(t) = audit_ttl {
            c.audit_ttl = t;
        }
        if let Some(t) = lists_ttl {
            c.lists_ttl = t;
        }
        if let Some(m) = max_size {
            c.max_size = m;
        }
    }

    pub fn stats(&self) -> CacheStats {
        *self.stats.lock()
    }

    pub fn clear(&self) {
        for kind in CacheKind::ALL {
            let mut bucket = self.buckets[kind.idx()].lock();
            bucket.entries.clear();
            bucket.tick = 0;
        }
    }

    pub fn clear_kind(&self, kind: CacheKind) {
        let mut bucket = self.buckets[kind.idx()].lock();
        bucket.entries.clear();
        bucket.tick = 0;
    }

    /// Shared read prologue for [`Self::get`] / [`Self::get_typed`]: enforces the
    /// enabled flag + per-kind TTL, evicts an expired entry, and on a live hit
    /// `touch`es it (LRU) and returns `extract(entry)` — a refcount clone taken
    /// under the bucket lock, never a deep clone. Records the miss itself on the
    /// absent/expired path; the caller records the hit-or-miss of *decoding* the
    /// returned handle. Returns `None` without recording when caching is off.
    fn lookup<R>(
        &self,
        kind: CacheKind,
        key: &str,
        extract: impl FnOnce(&Entry) -> R,
    ) -> Option<R> {
        let ttl = {
            let c = self.config.lock();
            if !c.enabled {
                return None;
            }
            c.ttl_for(kind)
        };
        let mut bucket = self.buckets[kind.idx()].lock();
        let live = bucket
            .entries
            .get(key)
            .is_some_and(|e| e.inserted.elapsed() <= ttl);
        if !live {
            bucket.entries.remove(key);
            drop(bucket);
            self.record(kind, false);
            return None;
        }
        bucket.touch(key);
        let extracted = bucket.entries.get(key).map(extract);
        drop(bucket);
        extracted
    }

    pub fn get<T>(&self, kind: CacheKind, key: &str) -> Option<T>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        // Refcount bump under the lock, not a deep clone of the JSON tree.
        let raw = self.lookup(kind, key, |e| Arc::clone(&e.value))?;
        // Deserialize by BORROWING the Arc'd value (`&Value: Deserializer`), so
        // the tree is walked once and never copied.
        match <T as serde::Deserialize>::deserialize(&*raw) {
            Ok(value) => {
                self.record(kind, true);
                Some(value)
            }
            Err(err) => {
                tracing::warn!(?err, "cache value failed to deserialize; treating as miss");
                self.record(kind, false);
                None
            }
        }
    }

    pub fn put<T>(&self, kind: CacheKind, key: String, value: &T)
    where
        T: serde::Serialize,
    {
        let max_size = {
            let c = self.config.lock();
            if !c.enabled {
                return;
            }
            c.max_size
        };
        let json = match serde_json::to_value(value) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(?err, "cache put serialization failed; skipping");
                return;
            }
        };
        let mut bucket = self.buckets[kind.idx()].lock();
        bucket.tick += 1;
        let tick = bucket.tick;
        bucket.entries.insert(
            key,
            Entry {
                value: Arc::new(json),
                typed: None,
                inserted: Instant::now(),
                last_access: tick,
            },
        );
        bucket.evict_lru(max_size);
    }

    /// Caches `value` keeping the original `Arc<T>` so [`Self::get_typed`]
    /// returns it without re-deserializing. Skips the JSON serialize entirely
    /// (the value is stored as `Null` for the untyped path) — use this for
    /// large, read-hot entries only ever read back via `get_typed` (e.g. the
    /// tenant search corpus). TTL / LRU / tenant invalidation behave identically
    /// to [`Self::put`]; `get::<T>` on such a key reads `Null` and misses.
    pub fn put_typed<T: Send + Sync + 'static>(&self, kind: CacheKind, key: String, value: Arc<T>) {
        let max_size = {
            let c = self.config.lock();
            if !c.enabled {
                return;
            }
            c.max_size
        };
        let mut bucket = self.buckets[kind.idx()].lock();
        bucket.tick += 1;
        let tick = bucket.tick;
        bucket.entries.insert(
            key,
            Entry {
                value: Arc::new(serde_json::Value::Null),
                typed: Some(value),
                inserted: Instant::now(),
                last_access: tick,
            },
        );
        bucket.evict_lru(max_size);
    }

    /// Returns the typed value (a refcount clone — no deserialize) when present,
    /// unexpired, and stored via [`Self::put_typed`] as the same `T`. A type
    /// mismatch or an untyped entry reads as a miss.
    pub fn get_typed<T: Send + Sync + 'static>(
        &self,
        kind: CacheKind,
        key: &str,
    ) -> Option<Arc<T>> {
        let typed = self.lookup(kind, key, |e| e.typed.clone())?;
        match typed.and_then(|a| a.downcast::<T>().ok()) {
            Some(arc) => {
                self.record(kind, true);
                Some(arc)
            }
            None => {
                self.record(kind, false);
                None
            }
        }
    }

    pub fn invalidate(&self, kind: CacheKind, key: &str) {
        self.buckets[kind.idx()].lock().entries.remove(key);
    }

    /// Drops every entry of `kind` whose key begins with `prefix`. Used for
    /// tenant-scoped clears (e.g. on sign-out) without enumerating every
    /// list shape.
    pub fn invalidate_prefix(&self, kind: CacheKind, prefix: &str) {
        self.buckets[kind.idx()]
            .lock()
            .entries
            .retain(|k, _| !k.starts_with(prefix));
    }

    /// Drops every entry across **all** kinds whose key begins with
    /// `{tenant_id}|`. The cross-tenant-leakage guard on sign-out (the
    /// AGENTS.md "#1 footgun"): every kind uses the `{tenant_id}|` key
    /// convention, so sweeping all buckets catches them without naming each
    /// kind — and a future `CacheKind` is swept automatically, since it is a
    /// bucket too.
    pub fn invalidate_tenant(&self, tenant_id: &str) {
        let prefix = format!("{tenant_id}|");
        for kind in CacheKind::ALL {
            self.buckets[kind.idx()]
                .lock()
                .entries
                .retain(|k, _| !k.starts_with(&prefix));
        }
    }

    fn record(&self, kind: CacheKind, hit: bool) {
        let mut stats = self.stats.lock();
        match (kind, hit) {
            (CacheKind::ServicePrincipal, true) => stats.service_principal_hits += 1,
            (CacheKind::ServicePrincipal, false) => stats.service_principal_misses += 1,
            (CacheKind::Permissions, true) => stats.permissions_hits += 1,
            (CacheKind::Permissions, false) => stats.permissions_misses += 1,
            (CacheKind::Audit, true) => stats.audit_hits += 1,
            (CacheKind::Audit, false) => stats.audit_misses += 1,
            (CacheKind::Lists, true) => stats.lists_hits += 1,
            (CacheKind::Lists, false) => stats.lists_misses += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::thread::sleep;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Sample(String);

    #[test]
    fn put_typed_get_typed_returns_the_same_arc_without_deserialize() {
        let cache = Cache::new();
        let rows = Arc::new(vec![1u32, 2, 3]);
        cache.put_typed(CacheKind::Lists, "t1|corpus".into(), Arc::clone(&rows));
        let out = cache
            .get_typed::<Vec<u32>>(CacheKind::Lists, "t1|corpus")
            .expect("typed hit");
        assert_eq!(*out, vec![1, 2, 3]);
        // Same allocation — a refcount clone, not a rebuild.
        assert!(Arc::ptr_eq(&rows, &out));
        assert_eq!(cache.stats().lists_hits, 1);
    }

    #[test]
    fn get_typed_misses_on_type_mismatch_and_on_untyped_entries() {
        let cache = Cache::new();
        // Wrong type for a typed entry → miss (not a panic).
        cache.put_typed(CacheKind::Lists, "k".into(), Arc::new(vec![1u32]));
        assert!(cache
            .get_typed::<Vec<String>>(CacheKind::Lists, "k")
            .is_none());
        // A value stored via the untyped `put` has no typed slot → typed miss.
        cache.put(CacheKind::Lists, "u".into(), &Sample("v".into()));
        assert!(cache.get_typed::<Sample>(CacheKind::Lists, "u").is_none());
    }

    #[test]
    fn typed_entries_are_swept_by_tenant_invalidation() {
        let cache = Cache::new();
        cache.put_typed(CacheKind::Lists, "t1|corpus".into(), Arc::new(vec![1u32]));
        cache.put_typed(CacheKind::Lists, "t2|corpus".into(), Arc::new(vec![2u32]));
        cache.invalidate_tenant("t1");
        assert!(cache
            .get_typed::<Vec<u32>>(CacheKind::Lists, "t1|corpus")
            .is_none());
        assert!(cache
            .get_typed::<Vec<u32>>(CacheKind::Lists, "t2|corpus")
            .is_some());
    }

    #[test]
    fn put_and_get_roundtrip() {
        let cache = Cache::new();
        cache.put(
            CacheKind::ServicePrincipal,
            "k1".into(),
            &Sample("v".into()),
        );
        let out: Option<Sample> = cache.get(CacheKind::ServicePrincipal, "k1");
        assert_eq!(out, Some(Sample("v".into())));
        let s = cache.stats();
        assert_eq!(s.service_principal_hits, 1);
    }

    #[test]
    fn type_mismatch_deserializes_as_miss() {
        // The borrow-deserialize path must keep the corruption-tolerance
        // contract: a stored value that doesn't fit the requested type reads as
        // a miss (and is counted as one), never a panic.
        let cache = Cache::new();
        cache.put(CacheKind::Permissions, "k".into(), &Sample("v".into()));
        // Sample serializes to a JSON string; asking for a Vec<u8> can't fit it.
        let out: Option<Vec<u8>> = cache.get(CacheKind::Permissions, "k");
        assert!(out.is_none());
        assert_eq!(cache.stats().permissions_misses, 1);
    }

    #[test]
    fn nested_value_roundtrips_through_borrow_deserialize() {
        // A multi-field nested type (closer to the real index entries) must
        // round-trip through Arc<Value> + borrow-deserialize unchanged.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Row {
            id: String,
            tags: Vec<String>,
        }
        let cache = Cache::new();
        let rows = vec![
            Row {
                id: "a".into(),
                tags: vec!["x".into(), "y".into()],
            },
            Row {
                id: "b".into(),
                tags: vec![],
            },
        ];
        cache.put(CacheKind::Lists, "tenant|sp_index".into(), &rows);
        let out: Option<Vec<Row>> = cache.get(CacheKind::Lists, "tenant|sp_index");
        assert_eq!(out, Some(rows));
    }

    #[test]
    fn miss_counter_increments() {
        let cache = Cache::new();
        let out: Option<Sample> = cache.get(CacheKind::Permissions, "nope");
        assert!(out.is_none());
        assert_eq!(cache.stats().permissions_misses, 1);
    }

    #[test]
    fn disabled_cache_is_bypass() {
        let cache = Cache::new();
        cache.set_enabled(false);
        cache.put(CacheKind::ServicePrincipal, "k".into(), &Sample("v".into()));
        let out: Option<Sample> = cache.get(CacheKind::ServicePrincipal, "k");
        assert!(out.is_none());
    }

    #[test]
    fn invalidate_removes_entry() {
        let cache = Cache::new();
        cache.put(CacheKind::ServicePrincipal, "k".into(), &Sample("v".into()));
        cache.invalidate(CacheKind::ServicePrincipal, "k");
        let out: Option<Sample> = cache.get(CacheKind::ServicePrincipal, "k");
        assert!(out.is_none());
    }

    #[test]
    fn lru_eviction_keeps_max_cap() {
        let cache = Cache::new();
        for i in 0..(MAX_CACHE_SIZE + 25) {
            cache.put(
                CacheKind::Permissions,
                format!("k{i}"),
                &Sample(format!("v{i}")),
            );
        }
        // The earliest 25 should have been evicted.
        let first: Option<Sample> = cache.get(CacheKind::Permissions, "k0");
        assert!(first.is_none());
        let last: Option<Sample> =
            cache.get(CacheKind::Permissions, &format!("k{}", MAX_CACHE_SIZE + 24));
        assert!(last.is_some());
    }

    #[test]
    fn configured_max_size_overrides_default() {
        let cache = Cache::new();
        cache.configure(None, None, None, None, None, Some(2));
        for i in 0..5 {
            cache.put(
                CacheKind::Permissions,
                format!("k{i}"),
                &Sample(format!("v{i}")),
            );
        }
        // Only the cap (2) most-recent entries survive.
        let count = {
            let bucket = cache.buckets[CacheKind::Permissions.idx()].lock();
            bucket.entries.len()
        };
        assert_eq!(count, 2);
    }

    #[test]
    fn lowering_max_size_shrinks_oversized_bucket_on_next_put() {
        let cache = Cache::new();
        cache.configure(None, None, None, None, None, Some(5));
        for i in 0..5 {
            cache.put(
                CacheKind::Permissions,
                format!("k{i}"),
                &Sample(format!("v{i}")),
            );
        }
        // Lower the cap on an already-full bucket, then a single write must
        // bring it all the way down to the new cap (not just evict one entry).
        cache.configure(None, None, None, None, None, Some(2));
        cache.put(CacheKind::Permissions, "k5".into(), &Sample("v5".into()));
        let count = {
            let bucket = cache.buckets[CacheKind::Permissions.idx()].lock();
            bucket.entries.len()
        };
        assert_eq!(count, 2);
    }

    #[test]
    fn configured_audit_ttl_is_honored() {
        // Audit TTL is now runtime-tunable like the others (review A-M4).
        let cache = Cache::new();
        cache.configure(
            None,
            None,
            None,
            Some(Duration::from_millis(10)),
            None,
            None,
        );
        cache.put(CacheKind::Audit, "k".into(), &Sample("v".into()));
        sleep(Duration::from_millis(20));
        let out: Option<Sample> = cache.get(CacheKind::Audit, "k");
        assert!(out.is_none(), "Audit entry should have expired");
        assert_eq!(cache.config().audit_ttl, Duration::from_millis(10));
    }

    #[test]
    fn configured_ttl_is_honored() {
        let cache = Cache::new();
        cache.configure(
            None,
            Some(Duration::from_millis(10)),
            None,
            None,
            None,
            None,
        );
        cache.put(CacheKind::ServicePrincipal, "k".into(), &Sample("v".into()));
        sleep(Duration::from_millis(20));
        let out: Option<Sample> = cache.get(CacheKind::ServicePrincipal, "k");
        assert!(
            out.is_none(),
            "entry should have expired under the short TTL"
        );
    }

    #[test]
    fn lists_put_and_get_roundtrip() {
        let cache = Cache::new();
        cache.put(
            CacheKind::Lists,
            "tenant-a|apps_pairing".into(),
            &Sample("v".into()),
        );
        let out: Option<Sample> = cache.get(CacheKind::Lists, "tenant-a|apps_pairing");
        assert_eq!(out, Some(Sample("v".into())));
        assert_eq!(cache.stats().lists_hits, 1);
    }

    #[test]
    fn lists_configured_ttl_is_honored() {
        let cache = Cache::new();
        cache.configure(
            None,
            None,
            None,
            None,
            Some(Duration::from_millis(10)),
            None,
        );
        cache.put(CacheKind::Lists, "k".into(), &Sample("v".into()));
        sleep(Duration::from_millis(20));
        let out: Option<Sample> = cache.get(CacheKind::Lists, "k");
        assert!(out.is_none(), "Lists entry should have expired");
        assert_eq!(cache.stats().lists_misses, 1);
    }

    #[test]
    fn invalidate_tenant_sweeps_every_kind_for_one_tenant() {
        // Sign-out's cross-tenant-leakage guard: every kind's `{tenant}|`
        // entries fall, but a different tenant's survive in every kind.
        let cache = Cache::new();
        for kind in [
            CacheKind::Lists,
            CacheKind::Audit,
            CacheKind::ServicePrincipal,
            CacheKind::Permissions,
        ] {
            cache.put(kind, "t1|x".into(), &Sample("a".into()));
            cache.put(kind, "t2|x".into(), &Sample("b".into()));
        }

        cache.invalidate_tenant("t1");

        for kind in [
            CacheKind::Lists,
            CacheKind::Audit,
            CacheKind::ServicePrincipal,
            CacheKind::Permissions,
        ] {
            assert!(
                cache.get::<Sample>(kind, "t1|x").is_none(),
                "t1 entry must be swept from every kind"
            );
            assert!(
                cache.get::<Sample>(kind, "t2|x").is_some(),
                "other tenant must survive in every kind"
            );
        }
    }

    #[test]
    fn invalidate_prefix_drops_matching_keys() {
        let cache = Cache::new();
        cache.put(
            CacheKind::Lists,
            "tenant-a|apps_pairing".into(),
            &Sample("a".into()),
        );
        cache.put(
            CacheKind::Lists,
            "tenant-a|enterprise".into(),
            &Sample("b".into()),
        );
        cache.put(
            CacheKind::Lists,
            "tenant-b|apps_pairing".into(),
            &Sample("c".into()),
        );
        cache.invalidate_prefix(CacheKind::Lists, "tenant-a|");
        let a: Option<Sample> = cache.get(CacheKind::Lists, "tenant-a|apps_pairing");
        let b: Option<Sample> = cache.get(CacheKind::Lists, "tenant-a|enterprise");
        let c: Option<Sample> = cache.get(CacheKind::Lists, "tenant-b|apps_pairing");
        assert!(a.is_none());
        assert!(b.is_none());
        assert_eq!(c, Some(Sample("c".into())));
    }

    #[test]
    fn expired_entries_miss() {
        let cache = Cache::new();
        // Override by putting something and then manually ageing it: inject an
        // entry whose inserted instant is in the past via direct manipulation.
        cache.put(CacheKind::ServicePrincipal, "k".into(), &Sample("v".into()));
        {
            let mut bucket = cache.buckets[CacheKind::ServicePrincipal.idx()].lock();
            let entry = bucket.entries.get_mut("k").unwrap();
            entry.inserted = Instant::now() - SERVICE_PRINCIPAL_CACHE_TTL - Duration::from_secs(1);
        }
        let out: Option<Sample> = cache.get(CacheKind::ServicePrincipal, "k");
        assert!(out.is_none());
        // sanity: elapsed-free branches do not panic
        sleep(Duration::from_millis(1));
    }
}
