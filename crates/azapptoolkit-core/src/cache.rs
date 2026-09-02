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
    /// Test-only count of full TTL sweeps, so the "don't sweep when nothing can
    /// have expired" property is asserted rather than merely structural. Not in
    /// [`CacheStats`]: this is an implementation detail of the eviction policy,
    /// and it would otherwise become a public field the diagnostics UI has to
    /// render.
    #[cfg(test)]
    expired_sweeps: u64,
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
            #[cfg(test)]
            expired_sweeps: 0,
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
        #[cfg(test)]
        {
            self.expired_sweeps += 1;
        }
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
        // Honour the flag on BOTH branches, not just the early return. Past the
        // cap the sweep ran on every single `put` even though
        // `anything_expired == false` is a proof it would remove nothing — and
        // that sweep is a `retain` over `n`, plus a `rebuild_lru` that clones
        // every key `String` into a fresh `BTreeMap`, plus a `min()` scan, all
        // under the bucket mutex the interactive list reads contend on. The doc
        // above says both conditions are load-bearing; the code only honoured
        // one of them.
        if anything_expired {
            self.evict_expired(ttl);
        }
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
mod tests;
