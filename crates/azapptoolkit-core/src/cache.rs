//! LRU + TTL cache that mirrors `Private/Cache-Functions.ps1`.
//!
//! Keyed by `(CacheKind, String)`; each kind has its own TTL (see
//! [`crate::constants`]). Eviction is LRU once per-kind entry count exceeds
//! [`MAX_CACHE_SIZE`]. Hit/miss counters are exposed for the diagnostics
//! command surface.

use parking_lot::Mutex;
use std::any::Any;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::constants::{
    AUDIT_CACHE_TTL, LISTS_CACHE_TTL, MAX_CACHE_SIZE, MAX_PER_OBJECT_CACHE_SIZE,
    PERMISSIONS_CACHE_TTL, SERVICE_PRINCIPAL_CACHE_TTL,
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
    /// variant must extend this — the per-kind bucket array is sized by it.
    /// Stable Rust can't count enum variants at compile time, so this can't by
    /// itself prove it lists *every* variant — the exhaustive `match` in
    /// `CacheConfig::ttl_for` (no wildcard) is what forces a new variant to be
    /// handled.
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

/// Type-erased handle kept alongside the JSON value by [`Cache::put_typed`].
type TypedValue = Arc<dyn Any + Send + Sync>;

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
    typed: Option<TypedValue>,
    inserted: Instant,
    // Monotonically-increasing counter used for LRU ordering.
    last_access: u64,
    // Exempt from LRU eviction. Set for the handful of tenant-wide *index*
    // entries (the service-principal index, the app-registration pairing rows,
    // the search/gallery corpora) that cost a full directory scan to rebuild and
    // that many surfaces read. Without this they share a bucket with thousands
    // of cheap per-app entries (`app_detail|…`, `mail_scopes|…`), so one
    // mail-heavy audit run evicts the indexes and the next list visit pays for a
    // fresh tenant scan. Pinned entries still expire on TTL and are still
    // dropped by explicit/tenant invalidation — they are only invisible to LRU.
    pinned: bool,
}

struct Bucket {
    entries: HashMap<String, Entry>,
    // LRU ordering index: `last_access` tick -> key, so eviction pops the oldest
    // in O(log n) instead of scanning every entry. Kept in step with `entries`
    // on insert/touch/remove; `retain`/`clear` rebuild it wholesale. May briefly
    // hold ticks whose entry is gone or has since been touched — `evict_lru`
    // treats those as stale and skips them, which is what keeps the bookkeeping
    // on the hot paths to a single `remove` + `insert`.
    lru: BTreeMap<u64, String>,
    tick: u64,
}

impl Bucket {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lru: BTreeMap::new(),
            tick: 0,
        }
    }

    fn touch(&mut self, key: &str) {
        self.tick += 1;
        let tick = self.tick;
        if let Some(e) = self.entries.get_mut(key) {
            let previous = e.last_access;
            e.last_access = tick;
            self.lru.remove(&previous);
            self.lru.insert(tick, key.to_string());
        }
    }

    /// Inserts (or replaces) an entry, keeping the LRU index in step.
    fn insert(
        &mut self,
        key: String,
        value: Arc<serde_json::Value>,
        typed: Option<TypedValue>,
        pinned: bool,
    ) {
        self.tick += 1;
        let tick = self.tick;
        let entry = Entry {
            value,
            typed,
            inserted: Instant::now(),
            last_access: tick,
            pinned,
        };
        if let Some(previous) = self.entries.insert(key.clone(), entry) {
            self.lru.remove(&previous.last_access);
        }
        self.lru.insert(tick, key);
    }

    /// Removes one entry, keeping the LRU index in step.
    fn remove(&mut self, key: &str) -> bool {
        match self.entries.remove(key) {
            Some(previous) => {
                self.lru.remove(&previous.last_access);
                true
            }
            None => false,
        }
    }

    /// Drops every entry whose key fails `keep`, then rebuilds the LRU index.
    /// Invalidation sweeps are infrequent, so a wholesale rebuild is cheaper to
    /// reason about than threading removals through the index.
    fn retain(&mut self, keep: impl Fn(&str) -> bool) {
        self.entries.retain(|k, _| keep(k));
        self.rebuild_lru();
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.lru.clear();
        self.tick = 0;
    }

    fn rebuild_lru(&mut self) {
        self.lru = self
            .entries
            .iter()
            .map(|(k, e)| (e.last_access, k.clone()))
            .collect();
    }

    /// Drops every entry older than `ttl`.
    ///
    /// TTL was otherwise enforced only on read, so an entry nothing ever looks
    /// up again occupied its slot until something evicted it — and a *pinned*
    /// index is invisible to LRU, so it occupied one indefinitely. Called from
    /// the eviction path, where the bucket lock is already held and the cost is
    /// paid only when a bucket is at its cap.
    fn evict_expired(&mut self, ttl: Duration) {
        self.entries.retain(|_, e| e.inserted.elapsed() <= ttl);
        self.rebuild_lru();
    }

    fn evict_lru(&mut self, max_size: usize) {
        // Shrink down to the cap, not just by one. A single eviction per call is
        // enough on the steady-insert path, but when `configure` lowers
        // `max_size` on an already-oversized bucket it would take that many more
        // `put`s to converge — and never converge at all if writes stop. Evict
        // the least-recently-used entry repeatedly until within the bound.
        //
        // Pinned entries are skipped, so a bucket that is entirely (or almost
        // entirely) pinned stops evicting rather than dropping an index: the
        // pinned set is a fixed handful of tenant-wide keys, not something a
        // caller can grow without bound.
        let mut skipped: Vec<(u64, String)> = Vec::new();
        while self.entries.len() > max_size {
            let Some((tick, key)) = self.lru.pop_first() else {
                break;
            };
            match self.entries.get(&key) {
                // Stale index row: the entry was removed, or touched since (its
                // current tick has its own, later, index row). Drop and move on.
                Some(e) if e.last_access != tick => continue,
                None => continue,
                Some(e) if e.pinned => {
                    skipped.push((tick, key));
                    continue;
                }
                Some(_) => {
                    self.entries.remove(&key);
                }
            }
        }
        // Put the pinned rows we stepped over back, so they stay ordered for the
        // next pass (and so a later unpin/replace can still evict them).
        self.lru.extend(skipped);
    }
}

pub struct Cache {
    // One lock PER kind (indexed by `CacheKind::idx`) instead of a single lock
    // over all kinds — so an interactive `Lists` read never blocks on an audit's
    // continuous `Audit`/`ServicePrincipal` writes (and vice versa).
    buckets: [Mutex<Bucket>; CacheKind::ALL.len()],
    stats: Mutex<CacheStats>,
    config: Mutex<CacheConfig>,
    /// Bumped by every invalidation. A reader that fetches a tenant-wide index
    /// live holds no lock for the seconds that scan takes, so a mutation can
    /// invalidate the key underneath it; storing the pre-mutation snapshot into
    /// a **pinned** entry afterwards would serve stale authorization data for
    /// the full `Lists` TTL, out of LRU's reach. Capture this before the fetch
    /// and store through [`Cache::put_typed_index_if_current`].
    generation: std::sync::atomic::AtomicU64,
}

impl Cache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            buckets: std::array::from_fn(|_| Mutex::new(Bucket::new())),
            stats: Mutex::new(CacheStats::default()),
            config: Mutex::new(CacheConfig::default()),
            generation: std::sync::atomic::AtomicU64::new(0),
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
        let new_max = c.max_size;
        // Release the config lock before taking any bucket lock: every other
        // path (`limits_if_enabled` → `put_inner`) reads the config and drops it
        // before locking a bucket, so never holding both keeps that ordering.
        drop(c);

        // Lowering `max_size` has to shrink the live buckets too. `evict_lru`
        // only ever runs from `put_inner`, so without this an oversized bucket
        // converges one `put` at a time — and not at all if writes to that kind
        // stop, which is exactly the case `evict_lru`'s own comment calls out.
        if max_size.is_some() {
            for kind in CacheKind::ALL {
                let cap = Self::cap_for(kind, new_max);
                let ttl = self.config.lock().ttl_for(kind);
                let mut bucket = self.buckets[kind.idx()].lock();
                bucket.evict_expired(ttl);
                bucket.evict_lru(cap);
            }
        }
    }

    pub fn stats(&self) -> CacheStats {
        *self.stats.lock()
    }

    /// Effective entry cap for `kind` under the current configuration. Callers
    /// that pre-seed a bucket in bulk use this to bound the pass, so seeding
    /// can't evict its own earlier entries.
    ///
    /// `max_size` is sized for kinds holding a handful of tenant-wide aggregates.
    /// Two kinds instead hold **one entry per directory object** and so are
    /// capped at the ceiling the tenant enumerations use
    /// ([`MAX_PER_OBJECT_CACHE_SIZE`]):
    ///
    /// - [`CacheKind::ServicePrincipal`] — the audit's `|lean` seeding;
    /// - [`CacheKind::Lists`] — despite the name it carries the per-app
    ///   `app_detail|` and `mail_scopes|` entries alongside the tenant
    ///   aggregates and pinned indexes, so the aggregate-sized cap let per-app
    ///   churn thrash the bucket and silently truncated any bulk seeding bounded
    ///   by `capacity_for(Lists)`.
    ///
    /// A caller that raises `max_size` past that ceiling gets the larger value
    /// for every kind.
    pub fn capacity_for(&self, kind: CacheKind) -> usize {
        Self::cap_for(kind, self.config.lock().max_size)
    }

    fn cap_for(kind: CacheKind, max_size: usize) -> usize {
        match kind {
            // The per-object headroom is a DEFAULT, not a floor an operator
            // can't get under. Clamping unconditionally made `max_size` a
            // no-op for the two buckets that actually hold the memory — so
            // lowering the cache size shrank nothing while diagnostics
            // reported the lowered number. Above the default the headroom
            // still applies, so a normal install fits a whole tenant.
            CacheKind::ServicePrincipal | CacheKind::Lists if max_size >= MAX_CACHE_SIZE => {
                max_size.max(MAX_PER_OBJECT_CACHE_SIZE)
            }
            _ => max_size,
        }
    }

    pub fn clear(&self) {
        self.bump_generation();
        for kind in CacheKind::ALL {
            self.buckets[kind.idx()].lock().clear();
        }
    }

    pub fn clear_kind(&self, kind: CacheKind) {
        self.bump_generation();
        self.buckets[kind.idx()].lock().clear();
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
            bucket.remove(key);
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
                tracing::warn!(?err, "cache value failed to deserialize; dropping entry");
                // Drop it rather than leaving it to re-fail on every read. The
                // `lookup` above already called `touch`, so a retained poisoned
                // entry would also keep refreshing its own LRU position and
                // survive until TTL expiry (60 min for `Lists`) while never
                // once serving a hit.
                self.buckets[kind.idx()].lock().remove(key);
                self.record(kind, false);
                None
            }
        }
    }

    pub fn put<T>(&self, kind: CacheKind, key: String, value: &T)
    where
        T: serde::Serialize,
    {
        self.put_inner(kind, key, value, false);
    }

    /// Like [`Self::put`], but marks the entry **pinned**: exempt from LRU
    /// eviction (TTL and invalidation still apply).
    ///
    /// Use only for tenant-wide *index* entries that cost a full directory scan
    /// to rebuild and that several surfaces read — the service-principal index,
    /// the app-registration pairing rows, the credential-expiry roll-up. These
    /// share a bucket with thousands of cheap per-app entries, so without the
    /// pin a single mail-heavy audit run evicts them and the next list visit
    /// pays for a fresh scan. The pinned set must stay a bounded handful of
    /// keys; never pin anything keyed per directory object.
    pub fn put_index<T>(&self, kind: CacheKind, key: String, value: &T)
    where
        T: serde::Serialize,
    {
        self.put_inner(kind, key, value, true);
    }

    /// [`Self::put_index`] under the store-after-invalidate guard — the
    /// serializing twin of [`Self::put_typed_index_if_current`], with the same
    /// contract: `since` is a [`Cache::generation`] captured **before** the
    /// live fetch, and a store that lost the race is skipped (returns `false`)
    /// rather than re-pinning a pre-mutation snapshot for the full TTL.
    ///
    /// Every pinned index built from a tenant-wide scan belongs on this path.
    /// A pinned entry is out of LRU's reach, so losing the race there is not a
    /// stale read that ages out in seconds — it is the wrong answer until the
    /// TTL expires.
    pub fn put_index_if_current<T>(
        &self,
        kind: CacheKind,
        key: String,
        value: &T,
        since: u64,
    ) -> bool
    where
        T: serde::Serialize,
    {
        if self.generation() != since {
            tracing::debug!(
                %key,
                "cache invalidated during the index fetch; not storing the stale snapshot"
            );
            return false;
        }
        self.put_inner(kind, key, value, true);
        true
    }

    fn put_inner<T>(&self, kind: CacheKind, key: String, value: &T, pinned: bool)
    where
        T: serde::Serialize,
    {
        let Some((max_size, ttl)) = self.limits_if_enabled(kind) else {
            return;
        };
        let json = match serde_json::to_value(value) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(?err, "cache put serialization failed; skipping");
                return;
            }
        };
        let mut bucket = self.buckets[kind.idx()].lock();
        bucket.insert(key, Arc::new(json), None, pinned);
        bucket.evict_expired(ttl);
        bucket.evict_lru(max_size);
    }

    /// Effective per-kind entry cap and TTL, or `None` when caching is
    /// disabled. Both are read under one config lock, which is then dropped
    /// before any bucket lock is taken (the ordering `configure` relies on).
    fn limits_if_enabled(&self, kind: CacheKind) -> Option<(usize, Duration)> {
        let c = self.config.lock();
        if !c.enabled {
            return None;
        }
        Some((Self::cap_for(kind, c.max_size), c.ttl_for(kind)))
    }

    /// Caches `value` keeping the original `Arc<T>` so [`Self::get_typed`]
    /// returns it without re-deserializing. Skips the JSON serialize entirely
    /// (the value is stored as `Null` for the untyped path) — use this for
    /// large, read-hot entries only ever read back via `get_typed` (e.g. the
    /// tenant search corpus). TTL / LRU / tenant invalidation behave identically
    /// to [`Self::put`]; `get::<T>` on such a key reads `Null` and misses.
    pub fn put_typed<T: Send + Sync + 'static>(&self, kind: CacheKind, key: String, value: Arc<T>) {
        self.put_typed_inner(kind, key, value, false);
    }

    /// [`Self::put_typed`] with the [`Self::put_index`] pin — the combination the
    /// large, read-hot tenant indexes want: no re-deserialize on read *and* not
    /// evictable by the per-app entries sharing their bucket.
    pub fn put_typed_index<T: Send + Sync + 'static>(
        &self,
        kind: CacheKind,
        key: String,
        value: Arc<T>,
    ) {
        self.put_typed_inner(kind, key, value, true);
    }

    /// Stores a pinned index **only if** nothing was invalidated since
    /// `since` (a [`Cache::generation`] captured before the live fetch).
    /// Returns `false` when the store was skipped.
    ///
    /// Closes the store-after-invalidate race: a tenant-wide index scan takes
    /// seconds and holds no lock, so a mutation that lands mid-flight drops the
    /// key — and an unconditional store would then re-pin the *pre-mutation*
    /// snapshot for the full `Lists` TTL, where LRU cannot reach it. Skipping
    /// costs one re-fetch; not skipping serves stale authorization data.
    pub fn put_typed_index_if_current<T: Send + Sync + 'static>(
        &self,
        kind: CacheKind,
        key: String,
        value: Arc<T>,
        since: u64,
    ) -> bool {
        if self.generation() != since {
            tracing::debug!(
                %key,
                "cache invalidated during the index fetch; not storing the stale snapshot"
            );
            return false;
        }
        self.put_typed_inner(kind, key, value, true);
        true
    }

    fn put_typed_inner<T: Send + Sync + 'static>(
        &self,
        kind: CacheKind,
        key: String,
        value: Arc<T>,
        pinned: bool,
    ) {
        let Some((max_size, ttl)) = self.limits_if_enabled(kind) else {
            return;
        };
        let mut bucket = self.buckets[kind.idx()].lock();
        bucket.insert(key, Arc::new(serde_json::Value::Null), Some(value), pinned);
        bucket.evict_expired(ttl);
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
                // Drop it, exactly as `get` does on a failed deserialize: an
                // entry that can never downcast will never serve a hit, and
                // `lookup` just touched it — so leaving it refreshes its own LRU
                // position and, if pinned, keeps the slot until TTL.
                self.buckets[kind.idx()].lock().remove(key);
                self.record(kind, false);
                None
            }
        }
    }

    /// Monotonic invalidation counter. Capture it *before* a long live fetch
    /// and pass it to [`Cache::put_typed_index_if_current`].
    pub fn generation(&self) -> u64 {
        self.generation.load(std::sync::atomic::Ordering::Acquire)
    }

    fn bump_generation(&self) {
        self.generation
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    pub fn invalidate(&self, kind: CacheKind, key: &str) {
        self.bump_generation();
        self.buckets[kind.idx()].lock().remove(key);
    }

    /// Drops every entry of `kind` whose key begins with `prefix`. Used for
    /// tenant-scoped clears (e.g. on sign-out) without enumerating every
    /// list shape.
    pub fn invalidate_prefix(&self, kind: CacheKind, prefix: &str) {
        self.bump_generation();
        self.buckets[kind.idx()]
            .lock()
            .retain(|k| !k.starts_with(prefix));
    }

    /// Drops every entry across **all** kinds whose key begins with
    /// `{tenant_id}|`. The cross-tenant-leakage guard on sign-out (the
    /// AGENTS.md "#1 footgun"): every kind uses the `{tenant_id}|` key
    /// convention, so sweeping all buckets catches them without naming each
    /// kind — and a future `CacheKind` is swept automatically, since it is a
    /// bucket too.
    pub fn invalidate_tenant(&self, tenant_id: &str) {
        self.bump_generation();
        let prefix = format!("{tenant_id}|");
        for kind in CacheKind::ALL {
            self.buckets[kind.idx()]
                .lock()
                .retain(|k| !k.starts_with(&prefix));
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

    /// Live entry count for a bucket — the tests live inside the module, so
    /// they can look straight at what eviction actually did.
    fn entry_count(cache: &Cache, kind: CacheKind) -> usize {
        cache.buckets[kind.idx()].lock().entries.len()
    }

    #[test]
    fn a_serialized_index_stored_after_an_invalidation_it_raced_is_dropped() {
        // The `put_index` twin of the typed race below. The three list caches
        // (App Registrations pairing, Enterprise Apps, Managed Identities) store
        // through this one, are pinned, and are dropped by the same
        // `invalidate_app_lists` a mutation fires — so an unconditional store
        // re-pinned the pre-mutation rows and showed a deleted app for the full
        // TTL.
        let cache = Cache::new();
        let key = "t1|apps_pairing".to_string();

        let since = cache.generation();
        // ... the paginated scan happens here, and a mutation lands during it.
        cache.invalidate_prefix(CacheKind::Lists, "t1|");

        let stored = cache.put_index_if_current(CacheKind::Lists, key.clone(), &vec![1u8], since);
        assert!(!stored, "a snapshot that lost the race must not be stored");
        assert!(
            cache.get::<Vec<u8>>(CacheKind::Lists, &key).is_none(),
            "the invalidated key must stay empty, not hold the stale scan"
        );

        // The uncontended path still stores, and still pins.
        let since = cache.generation();
        assert!(cache.put_index_if_current(CacheKind::Lists, key.clone(), &vec![2u8], since));
        assert_eq!(
            cache.get::<Vec<u8>>(CacheKind::Lists, &key),
            Some(vec![2u8])
        );
    }

    #[test]
    fn an_index_stored_after_an_invalidation_it_raced_is_dropped() {
        // The store-after-invalidate race: a tenant-wide scan takes seconds
        // under no lock, so a mutation can invalidate the key mid-flight. An
        // unconditional store then re-PINS the pre-mutation snapshot, which LRU
        // cannot evict, and serves stale authorization data for the full TTL.
        let cache = Cache::new();
        let key = "t1|sp_index".to_string();

        let since = cache.generation();
        // ... the live fetch happens here, and a mutation lands during it.
        cache.invalidate_prefix(CacheKind::Lists, "t1|");

        let stored = cache.put_typed_index_if_current(
            CacheKind::Lists,
            key.clone(),
            Arc::new(vec![1u8]),
            since,
        );
        assert!(!stored, "a snapshot that lost the race must not be stored");
        assert!(
            cache.get_typed::<Vec<u8>>(CacheKind::Lists, &key).is_none(),
            "the invalidated key must stay empty, not hold the stale scan"
        );

        // The uncontended path still stores.
        let since = cache.generation();
        assert!(cache.put_typed_index_if_current(
            CacheKind::Lists,
            key.clone(),
            Arc::new(vec![2u8]),
            since
        ));
        assert_eq!(
            cache
                .get_typed::<Vec<u8>>(CacheKind::Lists, &key)
                .as_deref(),
            Some(&vec![2u8])
        );
    }

    #[test]
    fn get_typed_drops_a_poisoned_entry_rather_than_re_reading_it() {
        // `get` already did this; `get_typed` recorded the miss and left the
        // entry in place — and `lookup` had just touched it, so a pinned one
        // survived to TTL while never serving a hit.
        let cache = Cache::new();
        cache.put_typed_index(CacheKind::Lists, "t1|idx".into(), Arc::new(vec![1u8]));
        // Wrong type: cannot downcast.
        assert!(
            cache
                .get_typed::<String>(CacheKind::Lists, "t1|idx")
                .is_none()
        );
        assert_eq!(
            entry_count(&cache, CacheKind::Lists),
            0,
            "a value that can never downcast must be dropped, not retained"
        );
    }

    #[test]
    fn lowering_max_size_also_shrinks_the_two_per_object_buckets() {
        // `cap_for` clamped ServicePrincipal/Lists up to the per-object ceiling
        // unconditionally, so the operator's setting was a no-op for exactly
        // the two buckets holding the memory — while diagnostics reported the
        // lowered number.
        let cache = Cache::new();
        for kind in [CacheKind::ServicePrincipal, CacheKind::Lists] {
            for i in 0..40 {
                cache.put(kind, format!("t1|k{i}"), &Sample(i.to_string()));
            }
        }
        cache.configure(None, None, None, None, None, Some(10));
        for kind in [CacheKind::ServicePrincipal, CacheKind::Lists] {
            assert_eq!(
                entry_count(&cache, kind),
                10,
                "{kind:?} must honour a lowered max_size"
            );
            assert_eq!(cache.capacity_for(kind), 10);
        }
        // At or above the default, the per-object headroom still applies so a
        // normal install fits a whole tenant enumeration.
        cache.configure(None, None, None, None, None, Some(MAX_CACHE_SIZE));
        assert_eq!(
            cache.capacity_for(CacheKind::Lists),
            MAX_PER_OBJECT_CACHE_SIZE
        );
    }

    #[test]
    fn an_expired_entry_is_swept_even_if_nothing_reads_it() {
        // TTL was enforced only on read, so an entry nothing looks up again held
        // its slot — and a PINNED one, invisible to LRU, held it indefinitely.
        let cache = Cache::new();
        cache.configure(
            None,
            None,
            None,
            None,
            Some(Duration::from_millis(10)),
            Some(100),
        );
        cache.put_typed_index(CacheKind::Lists, "t1|idx".into(), Arc::new(vec![1u8]));
        cache.put(CacheKind::Lists, "t1|other".into(), &Sample("x".into()));
        assert_eq!(entry_count(&cache, CacheKind::Lists), 2);

        sleep(Duration::from_millis(25));
        // Any write to the kind now sweeps the expired entries, pinned included.
        cache.put(CacheKind::Lists, "t1|fresh".into(), &Sample("y".into()));
        assert_eq!(
            entry_count(&cache, CacheKind::Lists),
            1,
            "expired entries must not keep occupying slots"
        );
    }

    #[test]
    fn lowering_max_size_shrinks_live_buckets_without_further_writes() {
        // Regression: `configure` only mutated the config, and `evict_lru` runs
        // solely from `put_inner` — so an oversized bucket converged one write
        // at a time, and not at all once writes to that kind stopped.
        let cache = Cache::new();
        for i in 0..20 {
            cache.put(
                CacheKind::Audit,
                format!("t1|audit|{i}"),
                &Sample(i.to_string()),
            );
        }
        assert_eq!(entry_count(&cache, CacheKind::Audit), 20);
        cache.configure(None, None, None, None, None, Some(5));
        assert_eq!(
            entry_count(&cache, CacheKind::Audit),
            5,
            "lowering max_size must evict immediately, with no further puts"
        );
    }

    #[test]
    fn a_poisoned_entry_is_dropped_rather_than_re_read_forever() {
        // Regression: a value that no longer deserializes into T was warned about
        // and left in place — and `lookup` had already touched it, so it kept
        // refreshing its own LRU position and re-failing on every read until TTL.
        let cache = Cache::new();
        cache.put(CacheKind::Lists, "t1|thing".into(), &Sample("x".into()));
        // Read it back as an incompatible type: a miss, and the entry must go.
        assert!(cache.get::<u64>(CacheKind::Lists, "t1|thing").is_none());
        assert_eq!(
            entry_count(&cache, CacheKind::Lists),
            0,
            "the undeserializable entry must be evicted, not retained"
        );
        // And the correctly-typed read now misses too, rather than hitting a
        // value that could never be decoded.
        assert!(cache.get::<Sample>(CacheKind::Lists, "t1|thing").is_none());
    }

    #[test]
    fn lists_is_capped_for_per_object_entries_not_aggregates() {
        // `Lists` carries the per-app `app_detail|` / `mail_scopes|` entries as
        // well as the tenant aggregates, so the aggregate-sized cap let per-app
        // churn thrash it and silently truncated bulk seeding bounded by
        // `capacity_for(Lists)`.
        let cache = Cache::new();
        assert_eq!(
            cache.capacity_for(CacheKind::Lists),
            cache.capacity_for(CacheKind::ServicePrincipal),
            "both per-object kinds share the per-object ceiling"
        );
        assert!(cache.capacity_for(CacheKind::Lists) >= MAX_PER_OBJECT_CACHE_SIZE);
        // Aggregate-only kinds keep the smaller configured cap.
        assert_eq!(cache.capacity_for(CacheKind::Audit), MAX_CACHE_SIZE);
    }

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
        assert!(
            cache
                .get_typed::<Vec<String>>(CacheKind::Lists, "k")
                .is_none()
        );
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
        assert!(
            cache
                .get_typed::<Vec<u32>>(CacheKind::Lists, "t1|corpus")
                .is_none()
        );
        assert!(
            cache
                .get_typed::<Vec<u32>>(CacheKind::Lists, "t2|corpus")
                .is_some()
        );
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

    /// The LRU index must track *recency*, not insertion order — a read of an
    /// old key has to rescue it from the next eviction. This is what the
    /// `tick -> key` index has to keep in step on `touch`.
    #[test]
    fn eviction_is_by_recency_not_insertion_order() {
        let cache = Cache::new();
        cache.configure(None, None, None, None, None, Some(3));
        for i in 0..3 {
            cache.put(
                CacheKind::Permissions,
                format!("k{i}"),
                &Sample(format!("v{i}")),
            );
        }
        // Re-read the oldest entry, making it the most recently used.
        assert!(cache.get::<Sample>(CacheKind::Permissions, "k0").is_some());
        // Inserting past the cap must now evict k1 (the true LRU), not k0.
        cache.put(CacheKind::Permissions, "k3".into(), &Sample("v3".into()));
        assert!(
            cache.get::<Sample>(CacheKind::Permissions, "k0").is_some(),
            "the touched entry must survive"
        );
        assert!(
            cache.get::<Sample>(CacheKind::Permissions, "k1").is_none(),
            "the least-recently-used entry must be the one evicted"
        );
    }

    /// A pinned index entry must outlive a flood of ordinary entries in the same
    /// bucket — the per-app `app_detail|…` / `mail_scopes|…` writes an audit run
    /// makes, which previously evicted the tenant-wide indexes.
    #[test]
    fn pinned_entries_survive_lru_pressure() {
        let cache = Cache::new();
        cache.configure(None, None, None, None, None, Some(4));
        cache.put_index(
            CacheKind::Permissions,
            "t1|sp_index".into(),
            &Sample("index".into()),
        );
        for i in 0..50 {
            cache.put(
                CacheKind::Permissions,
                format!("t1|app_detail|{i}"),
                &Sample(format!("v{i}")),
            );
        }
        let index: Option<Sample> = cache.get(CacheKind::Permissions, "t1|sp_index");
        assert_eq!(index, Some(Sample("index".into())));
    }

    /// Pinning is an LRU exemption only — an explicit tenant sweep still drops
    /// the entry, or sign-out would leak one tenant's index into the next.
    #[test]
    fn pinned_entries_are_still_swept_by_tenant_invalidation() {
        let cache = Cache::new();
        cache.put_index(CacheKind::Lists, "t1|sp_index".into(), &Sample("a".into()));
        cache.put_typed_index(CacheKind::Lists, "t1|corpus".into(), Arc::new(vec![1u32]));
        cache.invalidate_tenant("t1");
        assert!(
            cache
                .get::<Sample>(CacheKind::Lists, "t1|sp_index")
                .is_none()
        );
        assert!(
            cache
                .get_typed::<Vec<u32>>(CacheKind::Lists, "t1|corpus")
                .is_none()
        );
    }

    /// `ServicePrincipal` holds one small entry per app registration (the
    /// audit's `|lean` seeding), so it is capped at the tenant-enumeration
    /// ceiling rather than the aggregate-sized `MAX_CACHE_SIZE`. Without this a
    /// seeding pass over a large tenant evicts its own earlier entries and every
    /// one of them falls back to an individual Graph GET.
    #[test]
    fn service_principal_bucket_holds_a_whole_large_tenant() {
        let cache = Cache::new();
        let overflow = MAX_CACHE_SIZE + 500;
        for i in 0..overflow {
            cache.put(
                CacheKind::ServicePrincipal,
                format!("t1|{i}|lean"),
                &Sample(format!("v{i}")),
            );
        }
        // Nothing evicted: the cap is MAX_PER_OBJECT_CACHE_SIZE, well above this.
        assert!(
            cache
                .get::<Sample>(CacheKind::ServicePrincipal, "t1|0|lean")
                .is_some(),
            "the first-seeded entry must survive a full-tenant seeding pass"
        );
        let count = {
            let bucket = cache.buckets[CacheKind::ServicePrincipal.idx()].lock();
            bucket.entries.len()
        };
        assert_eq!(count, overflow);
    }

    /// The `tick -> key` index is only correct if it stays in step with
    /// `entries` across every mutation path. A leak would silently degrade
    /// eviction into skipping stale rows forever.
    #[test]
    fn lru_index_stays_in_step_with_entries() {
        let cache = Cache::new();
        for i in 0..20 {
            cache.put(
                CacheKind::Lists,
                format!("t1|k{i}"),
                &Sample(format!("v{i}")),
            );
        }
        // Touch some, replace some, remove some, sweep some.
        for i in 0..5 {
            let _: Option<Sample> = cache.get(CacheKind::Lists, &format!("t1|k{i}"));
        }
        for i in 5..10 {
            cache.put(
                CacheKind::Lists,
                format!("t1|k{i}"),
                &Sample(format!("replaced{i}")),
            );
        }
        for i in 10..15 {
            cache.invalidate(CacheKind::Lists, &format!("t1|k{i}"));
        }
        cache.put(CacheKind::Lists, "t2|other".into(), &Sample("x".into()));
        cache.invalidate_tenant("t2");

        let bucket = cache.buckets[CacheKind::Lists.idx()].lock();
        assert_eq!(
            bucket.lru.len(),
            bucket.entries.len(),
            "LRU index must hold exactly one live row per entry"
        );
        for (tick, key) in &bucket.lru {
            let entry = bucket
                .entries
                .get(key)
                .unwrap_or_else(|| panic!("LRU index references missing key {key}"));
            assert_eq!(
                entry.last_access, *tick,
                "LRU index tick must match the entry's last_access"
            );
        }
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
        // Age the entry past expiry with a short TTL + sleep. Do NOT back-date the
        // `inserted` Instant: `Instant::now() - <TTL>` panics on Windows, whose
        // monotonic clock starts near process boot ("overflow when subtracting
        // duration from instant"). Same expiry branch as the configured-TTL tests.
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
        assert!(out.is_none(), "entry should have expired past its TTL");
        assert_eq!(
            cache.stats().service_principal_misses,
            1,
            "an expired entry should read as a miss"
        );
    }
}
