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
    // Identity of the `insert` that produced THIS entry, so a caller holding a
    // stamp can prove the entry under a key is still its own before removing it.
    //
    // Distinct from `last_access` on purpose: `touch` bumps that on every read,
    // so it identifies the most recent *access*, not the write. A rollback keyed
    // on it would be defeated by any read landing in the window.
    stamp: u64,
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
    /// `inserted` of the oldest live entry, i.e. the first moment at which a
    /// TTL sweep could find anything to do. Lets the `put` path answer "is
    /// anything expired yet?" in one comparison instead of a full scan — see
    /// [`Bucket::evict_if_needed`].
    ///
    /// `None` when the bucket is empty. Recomputed after each sweep; never
    /// narrowed on plain removal, so it is a conservative *lower* bound — at
    /// worst it buys one unnecessary sweep, never a missed one.
    oldest_insert: Option<Instant>,
    /// Source of [`Entry::stamp`]. Only [`Bucket::insert`] advances it, and it
    /// is deliberately NOT reset by [`Bucket::clear`] — reusing a stamp after a
    /// clear would let a stale rollback match a brand-new entry, which is the
    /// bug the stamp exists to prevent.
    next_stamp: u64,
}

impl Bucket {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lru: BTreeMap::new(),
            tick: 0,
            oldest_insert: None,
            next_stamp: 0,
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

    /// Inserts (or replaces) an entry, keeping the LRU index in step. Returns
    /// the new entry's [`Entry::stamp`], which identifies *this* insert.
    fn insert(
        &mut self,
        key: String,
        value: Arc<serde_json::Value>,
        typed: Option<TypedValue>,
        pinned: bool,
    ) -> u64 {
        self.tick += 1;
        self.next_stamp += 1;
        let (tick, stamp) = (self.tick, self.next_stamp);
        let inserted = Instant::now();
        self.oldest_insert.get_or_insert(inserted);
        let entry = Entry {
            value,
            typed,
            inserted,
            last_access: tick,
            pinned,
            stamp,
        };
        if let Some(previous) = self.entries.insert(key.clone(), entry) {
            self.lru.remove(&previous.last_access);
        }
        self.lru.insert(tick, key);
        stamp
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

    /// Removes `key` **only if** the entry under it is still the one that
    /// `insert` returned `stamp` for. Returns whether it removed anything.
    ///
    /// The compare is the whole point. A rollback that removes by key name
    /// alone will happily delete a *newer* entry that a different writer stored
    /// in the meantime — see [`Cache::store_if_current`].
    fn remove_if_stamp(&mut self, key: &str, stamp: u64) -> bool {
        match self.entries.get(key) {
            Some(entry) if entry.stamp == stamp => self.remove(key),
            _ => false,
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
        self.oldest_insert = None;
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
        self.oldest_insert = self.entries.values().map(|e| e.inserted).min();
    }

    /// The `put` path's eviction pass, run only when there is actually
    /// something to evict.
    ///
    /// Both passes used to run on EVERY put, which made each write O(n):
    /// `evict_expired` is a full `retain` followed by a `rebuild_lru` that
    /// clones every key `String`, and `n` here runs to `MAX_CACHE_SIZE` — all
    /// of it under the bucket mutex that interactive list reads contend on. So
    /// the steady-state cost of caching one app's detail was proportional to
    /// everything else already cached, paid on the path a user is waiting on.
    ///
    /// Both conditions are load-bearing and neither subsumes the other:
    ///
    /// * **At cap** — LRU has to make room. Nothing else does.
    /// * **Something has expired** — the TTL sweep is what reclaims entries
    ///   nothing reads again, and the only thing that reclaims an expired
    ///   *pinned* index, which LRU cannot touch. A bucket that never reaches
    ///   its cap would otherwise hold them until the process exits.
    ///
    /// The expiry test is one `Instant` comparison against the oldest live
    /// entry, so the common put — bucket under cap, nothing expired yet — now
    /// costs the insert alone.
    fn evict_if_needed(&mut self, ttl: Duration, max_size: usize) {
        let anything_expired = self.oldest_insert.is_some_and(|o| o.elapsed() > ttl);
        if !anything_expired && self.entries.len() <= max_size {
            return;
        }
        self.evict_expired(ttl);
        self.evict_lru(max_size);
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
    /// Per-key invalidation counters, for the keys someone is currently
    /// fetching. A reader that fetches a tenant-wide index live holds no lock
    /// for the seconds that scan takes, so a mutation can invalidate the key
    /// underneath it; storing the pre-mutation snapshot into a **pinned** entry
    /// afterwards would serve stale authorization data for the full `Lists`
    /// TTL, out of LRU's reach.
    ///
    /// Deliberately per **key**, not one global counter and not per
    /// (tenant, kind): the invalidation tiers exist precisely so a
    /// credential-only mutation can drop `apps_pairing` and the per-app detail
    /// while PRESERVING the two tenant-wide indexes. A coarser counter makes
    /// those tier-preserved indexes refuse to store whenever any sibling key is
    /// dropped — turning the guard into the very tenant-wide rescan the tier
    /// was created to avoid, once per queued reader behind the single-flight
    /// gate.
    ///
    /// Bounded by construction: an entry lives only as long as the
    /// [`IndexWatch`] guard [`Cache::generation_for`] hands out — released by
    /// the paired store, and by the guard's `Drop` on every path that never
    /// reaches one (a failed fetch, a cancelled task, an early `?`). Without
    /// that `Drop` the table only grows, and once it reaches
    /// [`Cache::MAX_WATCHES`] every pinned-index store refuses **for the life
    /// of the process** — a silent, unrecoverable full-rescan-on-every-read.
    watches: Mutex<HashMap<(usize, String), Watch>>,
}

/// One watched key: the invalidation counter, and how many in-flight fetches
/// are relying on it. Refcounted because `generation_for` on an already-watched
/// key hands both fetchers the same counter; releasing on the first one to
/// finish would leave the other unable to prove its key current.
#[derive(Debug)]
struct Watch {
    counter: u64,
    refs: usize,
}

/// A live watch on one cache key, held across a long live index fetch.
///
/// Capture one *before* the fetch and hand it to the matching
/// `put_*_if_current`, which stores only if this exact key was not invalidated
/// in between. The guard exists so that the paths which never reach a store —
/// the fetch returned `Err`, the task was cancelled, a sibling future in a
/// `try_join` lost — still end the watch: [`Cache::generation_for`] is the only
/// thing that registers one, and a registration that outlives its fetch is
/// leaked forever.
///
/// Not `Clone` and not `Copy` on purpose: exactly one owner releases it.
#[must_use = "an IndexWatch must reach a put_*_if_current or be dropped promptly; \
              holding one open keeps the key watched"]
pub struct IndexWatch<'a> {
    cache: &'a Cache,
    kind: CacheKind,
    key: String,
    /// The counter read at registration, or [`Cache::WATCH_UNAVAILABLE`] when
    /// the table was full and nothing was registered.
    since: u64,
    /// Whether this guard owns a reference in the watch table. False for the
    /// unavailable case (nothing to release) and after a store consumed it.
    holds_ref: bool,
}

impl IndexWatch<'_> {
    /// The kind this watch covers.
    pub fn kind(&self) -> CacheKind {
        self.kind
    }

    /// The key this watch covers.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The key's live counter **without** giving up the reference, or `None`
    /// when this guard never held a watch.
    ///
    /// Exists so [`Cache::store_if_current`] can check currency while still
    /// holding the watch: releasing it first removes the last reference, and a
    /// concurrent invalidation then has nothing to bump.
    fn current(&self) -> Option<u64> {
        if !self.holds_ref {
            return None;
        }
        self.cache.peek_watch(self.kind, &self.key)
    }

    /// Consumes the guard, releasing its reference and returning
    /// `(kind, key, since, current)` — where `current` is the key's live
    /// counter, or `None` when this guard never held a watch.
    fn release(mut self) -> (CacheKind, String, u64, Option<u64>) {
        let current = if self.holds_ref {
            self.holds_ref = false;
            self.cache.release_watch(self.kind, &self.key)
        } else {
            None
        };
        (
            self.kind,
            std::mem::take(&mut self.key),
            self.since,
            current,
        )
    }
}

impl Drop for IndexWatch<'_> {
    fn drop(&mut self) {
        if self.holds_ref {
            self.cache.release_watch(self.kind, &self.key);
        }
    }
}

impl Cache {
    /// Ceiling on concurrently watched keys. Only tenant-wide index fetches
    /// watch, and `single_flight` already collapses concurrent fetchers of the
    /// same key, so the live set is a handful — this is a runaway guard, not a
    /// working limit. Past it `generation_for` returns
    /// [`Cache::WATCH_UNAVAILABLE`] and the paired store refuses.
    const MAX_WATCHES: usize = 256;

    /// Sentinel returned by [`Cache::generation_for`] when no watch could be
    /// registered. It can never equal a live counter (which starts at 0 and
    /// only increments), so the paired store always refuses — fail-closed.
    pub const WATCH_UNAVAILABLE: u64 = u64::MAX;

    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            buckets: std::array::from_fn(|_| Mutex::new(Bucket::new())),
            stats: Mutex::new(CacheStats::default()),
            config: Mutex::new(CacheConfig::default()),
            watches: Mutex::new(HashMap::new()),
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
        // Everything goes, so every watch is invalidated.
        self.bump_watches(None, |_| true);
        for kind in CacheKind::ALL {
            self.buckets[kind.idx()].lock().clear();
        }
    }

    pub fn clear_kind(&self, kind: CacheKind) {
        self.bump_watches(Some(kind), |_| true);
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
        // Refcount bump under the lock, not a deep clone of the JSON tree. The
        // `typed` flag rides along because it decides whether a decode failure
        // means "this entry is poisoned" or "this caller used the wrong door".
        let (raw, typed) = self.lookup(kind, key, |e| (Arc::clone(&e.value), e.typed.is_some()))?;
        // Deserialize by BORROWING the Arc'd value (`&Value: Deserializer`), so
        // the tree is walked once and never copied.
        match <T as serde::Deserialize>::deserialize(&*raw) {
            Ok(value) => {
                self.record(kind, true);
                Some(value)
            }
            Err(err) if typed => {
                // A `put_typed` entry stores `Value::Null` as its untyped body
                // (the payload lives in `typed`), so an untyped `get` against
                // one ALWAYS fails to decode. Removing it here turned the
                // documented "plain `get` = silent miss + rescan" footgun into
                // a permanent eviction of a pinned tenant-wide index: one read
                // through the wrong accessor destroyed the very entry pinning
                // exists to protect, and every surface then paid for a full
                // directory scan. The entry is not poisoned — the caller should
                // be using `get_typed` / the `sp_index_*` / `app_name_index_*`
                // accessors — so leave it alone and just miss.
                tracing::warn!(
                    ?err,
                    "untyped `get` against a typed cache entry; use `get_typed`. Entry kept."
                );
                self.record(kind, false);
                None
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
    /// contract: `since` is a [`Cache::generation_for`] captured **before** the
    /// live fetch, and a store that lost the race is skipped (returns `false`)
    /// rather than re-pinning a pre-mutation snapshot for the full TTL.
    ///
    /// Every pinned index built from a tenant-wide scan belongs on this path.
    /// A pinned entry is out of LRU's reach, so losing the race there is not a
    /// stale read that ages out in seconds — it is the wrong answer until the
    /// TTL expires.
    pub fn put_index_if_current<T>(&self, watch: IndexWatch<'_>, value: &T) -> bool
    where
        T: serde::Serialize,
    {
        self.store_if_current(watch, |cache, kind, key| {
            cache.put_inner(kind, key, value, true)
        })
    }

    /// Stores through `store` only if `watch`'s key was never invalidated —
    /// including during the store itself.
    ///
    /// The watch is deliberately held **across** `store` and released after.
    /// Releasing first (the obvious reading of "check, then write") left a real
    /// window: `release_watch` drops the last reference and *removes* the watch
    /// entry, so an `invalidate` landing between the check and the bucket lock
    /// found no watch to bump and no entry to remove — and the pre-mutation
    /// snapshot then landed, pinned, beyond LRU's reach for the whole TTL.
    /// Holding the reference means that invalidation has something to bump, and
    /// the post-store comparison sees it and undoes the write.
    ///
    /// Lock order is unchanged (watches, then bucket, never both at once), so
    /// this adds no deadlock risk — only a second look.
    ///
    /// `store` returns the [`Entry::stamp`] of what it wrote, and the rollback
    /// is a compare-and-remove against it. Removing by key name alone was a
    /// second, opposite race: A stores → an invalidation bumps the counter → B
    /// takes a fresh watch, fetches, and stores a *valid* index → A's second
    /// look fails and A deletes B's entry. Both writers behaved correctly and
    /// the tenant-wide index vanished anyway, costing a full rescan on the next
    /// read with nothing in the logs to explain it.
    fn store_if_current(
        &self,
        watch: IndexWatch<'_>,
        store: impl FnOnce(&Self, CacheKind, String) -> Option<u64>,
    ) -> bool {
        let (kind, key, since) = (watch.kind, watch.key.clone(), watch.since);

        // Pre-check: cheap, and it keeps the common lost-race case from paying
        // for a serialize + insert it is only going to undo. A key that is not
        // watched at all cannot be proven current — that covers both the
        // table-full case and a second store against a consumed watch.
        match watch.current() {
            Some(now) if now == since => {}
            other => {
                tracing::debug!(
                    %key,
                    watched = ?other,
                    since,
                    "key invalidated during the index fetch (or never watched); not storing"
                );
                return false; // `watch` releases on drop
            }
        }

        let stamp = store(self, kind, key.clone());

        // Second look, now that the store has landed. `watch` still held its
        // reference throughout, so any invalidation in the window bumped the
        // counter rather than passing through unseen.
        let (_, _, _, after) = watch.release();
        match after {
            Some(now) if now == since => true,
            other => {
                tracing::debug!(
                    %key,
                    watched = ?other,
                    since,
                    "key invalidated while the index store was in flight; rolling it back"
                );
                // Compare-and-remove: undo OUR write, never someone else's. A
                // `None` stamp means the store declined (disabled kind, or a
                // serialization failure), so there is nothing to undo.
                if let Some(stamp) = stamp {
                    let removed = self.buckets[kind.idx()].lock().remove_if_stamp(&key, stamp);
                    if !removed {
                        tracing::debug!(
                            %key,
                            "rollback skipped: a newer entry replaced ours, and it is not ours to \
                             evict"
                        );
                    }
                }
                false
            }
        }
    }

    /// Returns the stored entry's [`Entry::stamp`], or `None` when the store was
    /// declined (caching disabled for the kind, or the value failed to
    /// serialize). Only [`Cache::store_if_current`] reads it.
    fn put_inner<T>(&self, kind: CacheKind, key: String, value: &T, pinned: bool) -> Option<u64>
    where
        T: serde::Serialize,
    {
        let (max_size, ttl) = self.limits_if_enabled(kind)?;
        let json = match serde_json::to_value(value) {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!(?err, "cache put serialization failed; skipping");
                return None;
            }
        };
        let mut bucket = self.buckets[kind.idx()].lock();
        let stamp = bucket.insert(key, Arc::new(json), None, pinned);
        bucket.evict_if_needed(ttl, max_size);
        Some(stamp)
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

    /// Stores a pinned index **only if THIS KEY** was not invalidated since
    /// `since` (a [`Cache::generation_for`] captured before the live fetch).
    /// Returns `false` when the store was skipped.
    ///
    /// Closes the store-after-invalidate race: a tenant-wide index scan takes
    /// seconds and holds no lock, so a mutation that lands mid-flight drops the
    /// key — and an unconditional store would then re-pin the *pre-mutation*
    /// snapshot for the full `Lists` TTL, where LRU cannot reach it. Skipping
    /// costs one re-fetch; not skipping serves stale authorization data.
    ///
    /// Per-key, emphatically: a coarser counter would make a credential-only
    /// mutation — which invalidates `apps_pairing` and a per-app detail
    /// specifically in order to PRESERVE the tenant-wide indexes — refuse a
    /// perfectly valid index store, and the single-flight gate would then hand
    /// each queued reader its own multi-second rescan.
    pub fn put_typed_index_if_current<T: Send + Sync + 'static>(
        &self,
        watch: IndexWatch<'_>,
        value: Arc<T>,
    ) -> bool {
        self.store_if_current(watch, move |cache, kind, key| {
            cache.put_typed_inner(kind, key, value, true)
        })
    }

    /// See [`Cache::put_inner`] for the returned stamp.
    fn put_typed_inner<T: Send + Sync + 'static>(
        &self,
        kind: CacheKind,
        key: String,
        value: Arc<T>,
        pinned: bool,
    ) -> Option<u64> {
        let (max_size, ttl) = self.limits_if_enabled(kind)?;
        let mut bucket = self.buckets[kind.idx()].lock();
        let stamp = bucket.insert(key, Arc::new(serde_json::Value::Null), Some(value), pinned);
        bucket.evict_if_needed(ttl, max_size);
        Some(stamp)
    }

    /// Returns the typed value (a refcount clone — no deserialize) when present,
    /// unexpired, and stored via [`Self::put_typed`] as the same `T`. A type
    /// mismatch or an untyped entry reads as a miss — and **only** a miss: see
    /// the `None` arm.
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
                // Miss, and leave the entry alone — the mirror of the wrong-door
                // rule `get` already follows.
                //
                // This arm is reached in two ways, and NEITHER means the entry
                // is unusable. The stored payload is untyped (a plain `put` /
                // `put_index` entry, which has no `typed` body at all), or it is
                // typed as some other `T` — in both cases it still serves every
                // caller coming through the right door. It is *this* read that
                // is wrong.
                //
                // Removing it made one read through the wrong accessor
                // permanently evict a pinned tenant-wide index, the exact
                // failure `get` was fixed for: pinned entries are exempt from
                // LRU precisely so they survive pressure, and a `remove` here
                // discards that protection on a caller's mistake. Every surface
                // then pays for a full directory rescan.
                //
                // There is no poisoned case to clean up on this path. Unlike
                // `get`, nothing is being decoded: a downcast either matches or
                // it does not, so a failure says nothing about the entry's
                // integrity.
                tracing::warn!(
                    "`get_typed` against an entry stored untyped or as another type; \
                     use the matching accessor. Entry kept."
                );
                self.record(kind, false);
                None
            }
        }
    }

    /// Start watching one key for invalidation across a long live fetch.
    ///
    /// Capture this *before* the fetch and pass the returned guard to the
    /// matching `put_*_if_current`, which stores only if this exact key was not
    /// invalidated in between. Watching a key already being watched joins its
    /// existing watch, so two racing fetchers of the same key both refuse if it
    /// was dropped.
    ///
    /// The guard releases the watch on `Drop`, so a fetch that fails, is
    /// cancelled, or otherwise never reaches its store cannot leak the entry.
    /// That matters more than it looks: the table is capped at
    /// [`Cache::MAX_WATCHES`], and leaked entries are never reclaimed, so a
    /// steady trickle of failed index fetches would eventually fill it and make
    /// *every* pinned-index store refuse permanently — degrading every
    /// tenant-wide read to a full rescan with no signal and no way back short
    /// of a restart.
    ///
    /// When the table is genuinely full the guard carries
    /// [`Cache::WATCH_UNAVAILABLE`] and the paired store refuses — fail-closed,
    /// costing one re-fetch.
    pub fn generation_for(&self, kind: CacheKind, key: &str) -> IndexWatch<'_> {
        let mut watches = self.watches.lock();
        let id = (kind.idx(), key.to_string());
        if let Some(watch) = watches.get_mut(&id) {
            watch.refs += 1;
            let since = watch.counter;
            drop(watches);
            return IndexWatch {
                cache: self,
                kind,
                key: key.to_string(),
                since,
                holds_ref: true,
            };
        }
        if watches.len() >= Self::MAX_WATCHES {
            tracing::warn!(
                %key,
                watches = watches.len(),
                "cache watch table full; the index store will refuse and re-fetch"
            );
            drop(watches);
            return IndexWatch {
                cache: self,
                kind,
                key: key.to_string(),
                since: Self::WATCH_UNAVAILABLE,
                holds_ref: false,
            };
        }
        watches.insert(
            id,
            Watch {
                counter: 0,
                refs: 1,
            },
        );
        drop(watches);
        IndexWatch {
            cache: self,
            kind,
            key: key.to_string(),
            since: 0,
            holds_ref: true,
        }
    }

    /// Bumps the counter of every watched key this invalidation actually drops.
    /// `matches` decides membership, so the exact-key, prefix and tenant sweeps
    /// each bump precisely what they removed — and nothing else.
    fn bump_watches(&self, kind: Option<CacheKind>, matches: impl Fn(&str) -> bool) {
        let mut watches = self.watches.lock();
        for ((watched_kind, watched_key), watch) in watches.iter_mut() {
            if kind.is_none_or(|k| k.idx() == *watched_kind) && matches(watched_key) {
                watch.counter += 1;
            }
        }
    }

    /// Drops one reference to a watch, returning the key's live counter and
    /// removing the entry once the last holder lets go. `None` means the key
    /// was not watched at all, which callers treat as "cannot prove this is
    /// current" and therefore refuse.
    /// The live counter for a watched key, leaving the watch in place.
    fn peek_watch(&self, kind: CacheKind, key: &str) -> Option<u64> {
        self.watches
            .lock()
            .get(&(kind.idx(), key.to_string()))
            .map(|w| w.counter)
    }

    fn release_watch(&self, kind: CacheKind, key: &str) -> Option<u64> {
        let mut watches = self.watches.lock();
        let id = (kind.idx(), key.to_string());
        let watch = watches.get_mut(&id)?;
        let counter = watch.counter;
        watch.refs = watch.refs.saturating_sub(1);
        if watch.refs == 0 {
            watches.remove(&id);
        }
        Some(counter)
    }

    /// How many keys are currently watched. Test/diagnostic surface — a healthy
    /// process idles at zero, and a number that only ever climbs is the leak
    /// this guard exists to prevent.
    pub fn watch_count(&self) -> usize {
        self.watches.lock().len()
    }

    pub fn invalidate(&self, kind: CacheKind, key: &str) {
        self.bump_watches(Some(kind), |watched| watched == key);
        self.buckets[kind.idx()].lock().remove(key);
    }

    /// Drops every entry of `kind` whose key begins with `prefix`. Used for
    /// tenant-scoped clears (e.g. on sign-out) without enumerating every
    /// list shape.
    pub fn invalidate_prefix(&self, kind: CacheKind, prefix: &str) {
        self.bump_watches(Some(kind), |watched| watched.starts_with(prefix));
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
        let prefix = format!("{tenant_id}|");
        self.bump_watches(None, |watched| watched.starts_with(&prefix));
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

        let watch = cache.generation_for(CacheKind::Lists, &key);
        // ... the paginated scan happens here, and a mutation lands during it.
        cache.invalidate_prefix(CacheKind::Lists, "t1|");

        let stored = cache.put_index_if_current(watch, &vec![1u8]);
        assert!(!stored, "a snapshot that lost the race must not be stored");
        assert!(
            cache.get::<Vec<u8>>(CacheKind::Lists, &key).is_none(),
            "the invalidated key must stay empty, not hold the stale scan"
        );

        // The uncontended path still stores, and still pins.
        let watch = cache.generation_for(CacheKind::Lists, &key);
        assert!(cache.put_index_if_current(watch, &vec![2u8]));
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

        let watch = cache.generation_for(CacheKind::Lists, &key);
        // ... the live fetch happens here, and a mutation lands during it.
        cache.invalidate_prefix(CacheKind::Lists, "t1|");

        let stored = cache.put_typed_index_if_current(watch, Arc::new(vec![1u8]));
        assert!(!stored, "a snapshot that lost the race must not be stored");
        assert!(
            cache.get_typed::<Vec<u8>>(CacheKind::Lists, &key).is_none(),
            "the invalidated key must stay empty, not hold the stale scan"
        );

        // The uncontended path still stores.
        let watch = cache.generation_for(CacheKind::Lists, &key);
        assert!(cache.put_typed_index_if_current(watch, Arc::new(vec![2u8])));
        assert_eq!(
            cache
                .get_typed::<Vec<u8>>(CacheKind::Lists, &key)
                .as_deref(),
            Some(&vec![2u8])
        );
    }

    /// The guard must be keyed to the ONE key being written. The invalidation
    /// tiers exist so a credential-only mutation can drop `apps_pairing` and a
    /// per-app detail while deliberately PRESERVING the two tenant-wide
    /// indexes; a global (or per-kind, or per-tenant) counter makes those
    /// preserved indexes refuse a perfectly valid store, and behind the
    /// single-flight gate every queued reader then pays its own multi-second
    /// directory rescan — the exact cost the tier was created to avoid.
    #[test]
    fn a_sibling_key_invalidation_does_not_block_an_untouched_index() {
        let cache = Cache::new();
        let index = "t1|sp_index".to_string();

        let watch = cache.generation_for(CacheKind::Lists, &index);
        // A credential-only mutation lands mid-scan: it drops the pairing list,
        // one app's detail and the expiry roll-up — and keeps the indexes.
        cache.invalidate(CacheKind::Lists, "t1|apps_pairing");
        cache.invalidate(CacheKind::Lists, "t1|app_detail|obj-1");
        cache.invalidate(CacheKind::Lists, "t1|credential_expirations");
        // A different TENANT's sweep must not block it either.
        cache.invalidate_tenant("t2");

        assert!(
            cache.put_typed_index_if_current(watch, Arc::new(vec![7u8])),
            "no invalidation touched this key, so the scan's result must be stored"
        );
        assert_eq!(
            cache
                .get_typed::<Vec<u8>>(CacheKind::Lists, &index)
                .as_deref(),
            Some(&vec![7u8])
        );
    }

    #[test]
    fn a_store_consumes_its_watch_and_leaves_the_table_empty() {
        // The watch is moved into the store, so a replay is a *compile* error
        // rather than a runtime refusal. What is still worth pinning at runtime
        // is the other half: the store must release the entry, or the table
        // fills with the residue of successful fetches.
        let cache = Cache::new();
        let key = "t1|sp_index".to_string();

        let watch = cache.generation_for(CacheKind::Lists, &key);
        assert_eq!(cache.watch_count(), 1, "the fetch is watching its key");
        assert!(cache.put_typed_index_if_current(watch, Arc::new(vec![1u8])));
        assert_eq!(
            cache.watch_count(),
            0,
            "a completed store must stop watching"
        );

        // A second store needs a fresh watch, which proves the window since.
        let watch = cache.generation_for(CacheKind::Lists, &key);
        assert!(cache.put_typed_index_if_current(watch, Arc::new(vec![2u8])));
        assert_eq!(
            cache
                .get_typed::<Vec<u8>>(CacheKind::Lists, &key)
                .as_deref(),
            Some(&vec![2u8])
        );
        assert_eq!(cache.watch_count(), 0);
    }

    #[test]
    fn a_fetch_that_never_reaches_its_store_releases_its_watch() {
        // The leak this guard exists to prevent. A watch was registered by
        // `generation_for` and removed ONLY by the paired store, so every failed
        // or cancelled index fetch left one behind permanently. The table is
        // capped, entries were never reclaimed, and once the cap was reached
        // `generation_for` could no longer register — making EVERY pinned-index
        // store refuse for the life of the process. That presents as unexplained
        // slowness (a full rescan on every tenant-wide read) with no error, no
        // log at the point of failure, and no recovery short of a restart.
        let cache = Cache::new();

        for _ in 0..(Cache::MAX_WATCHES * 4) {
            let watch = cache.generation_for(CacheKind::Lists, "t1|sp_index");
            // ... the live scan fails here, so the store is never reached and
            // `watch` is dropped on the error path.
            drop(watch);
        }
        assert_eq!(
            cache.watch_count(),
            0,
            "a dropped watch must not outlive its fetch"
        );

        // And the table still works afterwards — the pre-guard failure mode was
        // that it did not.
        let watch = cache.generation_for(CacheKind::Lists, "t1|sp_index");
        assert!(
            cache.put_typed_index_if_current(watch, Arc::new(vec![1u8])),
            "an exhausted watch table would have refused this store forever"
        );
    }

    #[test]
    fn an_invalidation_landing_during_the_store_rolls_the_store_back() {
        // The window the release-then-store order left open, and the reason the
        // watch is now held ACROSS the store.
        //
        // Old order: release the watch (which removes the entry, since this is
        // the last reference), compare, then take the bucket lock and insert.
        // An `invalidate` interleaving there found no watch to bump — so the
        // comparison had already passed — and no entry to remove, because the
        // insert had not happened yet. The pre-mutation snapshot then landed
        // *pinned*, i.e. beyond LRU's reach, and served stale authorization
        // data for the whole `Lists` TTL.
        //
        // `store_if_current`'s callback is the exact instant that used to be
        // unprotected, so invalidating from inside it reproduces the race
        // deterministically rather than by thread timing.
        let cache = Cache::new();
        let key = "t1|sp_index".to_string();

        let watch = cache.generation_for(CacheKind::Lists, &key);
        let stored = cache.store_if_current(watch, |c, kind, k| {
            // A mutation lands while this store is in flight.
            c.invalidate(CacheKind::Lists, "t1|sp_index");
            c.put_inner(kind, k, &vec![1u8], true)
        });

        assert!(
            !stored,
            "a store that raced an invalidation must report that it lost"
        );
        assert!(
            cache.get::<Vec<u8>>(CacheKind::Lists, &key).is_none(),
            "the pre-mutation snapshot must not survive — pinned, it would outlive LRU"
        );
        assert_eq!(cache.watch_count(), 0, "the watch is released either way");
    }

    #[test]
    fn a_losing_writer_does_not_evict_the_winner_that_replaced_it() {
        // The opposite race from `an_invalidation_landing_during_the_store_...`,
        // and the one the by-name rollback got wrong.
        //
        // A stores → an invalidation bumps the counter → B takes a FRESH watch,
        // fetches, and stores a perfectly valid post-mutation index → A's second
        // look fails and A rolls back. Removing by key name deleted B's entry:
        // both writers behaved correctly, and the tenant-wide index vanished
        // anyway. Not stale data — a silent miss plus a multi-second rescan on
        // the next read, with nothing in the logs pointing at the cause.
        //
        // Driven from inside A's store callback so the interleaving is
        // deterministic rather than a thread race.
        let cache = Cache::new();
        let key = "t1|sp_index".to_string();

        let a_watch = cache.generation_for(CacheKind::Lists, &key);
        let a_stored = cache.store_if_current(a_watch, |c, kind, k| {
            let stamp = c.put_inner(kind, k.clone(), &vec![1u8], true);
            // A's write has landed. Now the world moves on without A.
            c.invalidate(CacheKind::Lists, &k);
            let b_watch = c.generation_for(CacheKind::Lists, &k);
            assert!(
                c.put_index_if_current(b_watch, &vec![2u8]),
                "B took its watch after the invalidation, so B must be allowed to store"
            );
            stamp
        });

        assert!(
            !a_stored,
            "A raced an invalidation and must report the loss"
        );
        assert_eq!(
            cache.get::<Vec<u8>>(CacheKind::Lists, &key),
            Some(vec![2u8]),
            "A's rollback must not evict B's newer, already-validated index — B's entry is the \
             current one and is not A's to remove"
        );
        assert_eq!(cache.watch_count(), 0, "both watches released");
    }

    #[test]
    fn a_rolled_back_store_still_removes_its_own_entry() {
        // The compare-and-remove must not have made the rollback a no-op: when
        // the entry under the key IS still ours, it has to go.
        let cache = Cache::new();
        let key = "t1|sp_index".to_string();

        let watch = cache.generation_for(CacheKind::Lists, &key);
        let stored = cache.store_if_current(watch, |c, kind, k| {
            let stamp = c.put_inner(kind, k.clone(), &vec![1u8], true);
            c.invalidate(CacheKind::Lists, &k);
            stamp
        });

        assert!(!stored);
        assert!(
            cache.get::<Vec<u8>>(CacheKind::Lists, &key).is_none(),
            "nothing replaced our entry, so the pre-mutation snapshot must still be rolled back"
        );
    }

    #[test]
    fn an_unraced_store_still_lands_and_stays_pinned() {
        // The other half of the rollback: the guard must not have become so
        // conservative that the healthy path refuses. A refusal here is not
        // visible as an error — it is a full tenant rescan on every read.
        let cache = Cache::new();
        let key = "t1|sp_index".to_string();

        let watch = cache.generation_for(CacheKind::Lists, &key);
        assert!(cache.put_typed_index_if_current(watch, Arc::new(vec![7u8])));
        assert_eq!(
            cache
                .get_typed::<Vec<u8>>(CacheKind::Lists, &key)
                .as_deref(),
            Some(&vec![7u8])
        );
        assert_eq!(cache.watch_count(), 0);
    }

    #[test]
    fn two_fetchers_of_one_key_each_hold_a_reference() {
        // `generation_for` on an already-watched key joins the existing watch.
        // Releasing on the FIRST holder to finish would leave the second unable
        // to prove its key current, turning a valid store into a needless
        // tenant-wide rescan — so the watch is refcounted.
        let cache = Cache::new();
        let key = "t1|sp_index".to_string();

        let first = cache.generation_for(CacheKind::Lists, &key);
        let second = cache.generation_for(CacheKind::Lists, &key);
        assert_eq!(cache.watch_count(), 1, "one key, one watch");

        drop(first);
        assert_eq!(
            cache.watch_count(),
            1,
            "the second fetcher is still relying on this watch"
        );
        assert!(
            cache.put_typed_index_if_current(second, Arc::new(vec![1u8])),
            "nothing invalidated the key, so the surviving fetcher must store"
        );
        assert_eq!(cache.watch_count(), 0);
    }

    #[test]
    fn both_racing_fetchers_refuse_when_their_shared_key_is_invalidated() {
        let cache = Cache::new();
        let key = "t1|sp_index".to_string();

        let first = cache.generation_for(CacheKind::Lists, &key);
        let second = cache.generation_for(CacheKind::Lists, &key);
        cache.invalidate(CacheKind::Lists, &key);

        assert!(!cache.put_typed_index_if_current(first, Arc::new(vec![1u8])));
        assert!(!cache.put_typed_index_if_current(second, Arc::new(vec![2u8])));
        assert!(cache.get_typed::<Vec<u8>>(CacheKind::Lists, &key).is_none());
        assert_eq!(cache.watch_count(), 0);
    }

    #[test]
    fn a_full_watch_table_refuses_rather_than_storing_unproven() {
        // Fail-closed: past the cap nothing is registered, so the paired store
        // cannot prove its key current and skips. One re-fetch, never a stale
        // pin. (Reaching this at all means watches are leaking — the guard
        // above is what keeps the live set to a handful.)
        let cache = Cache::new();
        let held: Vec<_> = (0..Cache::MAX_WATCHES)
            .map(|i| cache.generation_for(CacheKind::Lists, &format!("t1|key-{i}")))
            .collect();
        assert_eq!(cache.watch_count(), Cache::MAX_WATCHES);

        let overflow = cache.generation_for(CacheKind::Lists, "t1|one-too-many");
        assert!(
            !cache.put_typed_index_if_current(overflow, Arc::new(vec![1u8])),
            "an unregistered watch cannot authorize a store"
        );
        assert!(
            cache
                .get_typed::<Vec<u8>>(CacheKind::Lists, "t1|one-too-many")
                .is_none()
        );

        drop(held);
        assert_eq!(
            cache.watch_count(),
            0,
            "dropping the holders frees the table again"
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

    /// An untyped `get` against a typed index MISSES. It must not evict.
    ///
    /// `put_typed` stores `Value::Null` as the untyped body, so an untyped
    /// `get::<T>` can never decode one — and the decode-failure path used to
    /// `remove(key)`. That turned the documented "plain `get` = silent miss +
    /// rescan" footgun into a permanent eviction of a PINNED tenant-wide index:
    /// a single read through the wrong accessor destroyed the entry that
    /// pinning exists to protect, and the next visit to every surface reading
    /// it paid for a fresh directory scan.
    #[test]
    fn an_untyped_get_against_a_typed_index_misses_without_evicting_it() {
        let cache = Cache::new();
        cache.put_typed_index(CacheKind::Lists, "t1|sp_index".into(), Arc::new(vec![7u32]));

        // The wrong door: misses, as documented.
        assert!(
            cache
                .get::<Vec<u32>>(CacheKind::Lists, "t1|sp_index")
                .is_none()
        );

        // ...and the entry is STILL THERE, through the right one. This is the
        // assertion the old guard test lacked: it checked only that the untyped
        // read returned `None`, which a delete also satisfies.
        assert_eq!(
            cache
                .get_typed::<Vec<u32>>(CacheKind::Lists, "t1|sp_index")
                .as_deref(),
            Some(&vec![7u32]),
            "an untyped read must not evict the pinned index it failed to decode"
        );

        // A genuinely poisoned UNTYPED entry is still dropped — the fix must not
        // have turned the decode-failure path into a no-op for everyone.
        cache.put(CacheKind::Lists, "u".into(), &Sample("v".into()));
        assert!(cache.get::<Vec<u32>>(CacheKind::Lists, "u").is_none());
        assert!(
            cache.get::<Sample>(CacheKind::Lists, "u").is_none(),
            "an undecodable untyped entry is still evicted rather than re-failing every read"
        );
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

    /// A read through the WRONG accessor misses; it never destroys the entry.
    ///
    /// The twin of the `get` rule below. `put_typed` stores `Value::Null` as its
    /// untyped body and `put_index` stores no typed body at all, so each is
    /// guaranteed to fail through the other's door — which made a single
    /// mistaken read permanently evict a pinned tenant-wide index, the thing
    /// pinning exists to protect, and sent every surface into a full rescan.
    #[test]
    fn a_read_through_the_wrong_accessor_never_evicts_the_entry() {
        let cache = Cache::new();
        // Untyped + pinned, the shape `put_index` gives a tenant-wide index.
        cache.put_index(CacheKind::Lists, "t1|sp_index".into(), &Sample("a".into()));
        assert!(
            cache
                .get_typed::<Vec<u32>>(CacheKind::Lists, "t1|sp_index")
                .is_none(),
            "an untyped entry has no typed body to hand back"
        );
        assert_eq!(
            cache.get::<Sample>(CacheKind::Lists, "t1|sp_index"),
            Some(Sample("a".into())),
            "the wrong-door read must not have destroyed the index"
        );

        // Typed + pinned, read as a different `T`.
        cache.put_typed_index(CacheKind::Lists, "t1|corpus".into(), Arc::new(vec![1u32]));
        assert!(
            cache
                .get_typed::<Vec<String>>(CacheKind::Lists, "t1|corpus")
                .is_none()
        );
        assert_eq!(
            cache
                .get_typed::<Vec<u32>>(CacheKind::Lists, "t1|corpus")
                .as_deref(),
            Some(&vec![1u32]),
            "a type-mismatched read must not have destroyed the index either"
        );
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
