//! LRU + TTL cache that mirrors `Private/Cache-Functions.ps1`.
//!
//! Keyed by `(CacheKind, String)`; each kind has its own TTL (see
//! [`crate::constants`]). Eviction is LRU once a kind's entry count exceeds its
//! cap — [`MAX_CACHE_SIZE`] for aggregate kinds, [`MAX_PER_OBJECT_CACHE_SIZE`]
//! by default for the per-object `ServicePrincipal` / `Lists` (see
//! [`Cache::capacity_for`]). Hit/miss counters are exposed for the diagnostics
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
    /// All kinds, for whole-cache operations (clear, tenant sweep). The
    /// per-kind bucket array is sized by it, so a missing kind would index past
    /// the end. The completeness proof is structural: [`Self::idx`] is an
    /// exhaustive `match` and each arm resolves its bucket through the `const`
    /// [`Self::position`] lookup, so a variant missing from `ALL` is a
    /// compile-time panic, never an index-out-of-bounds in a Tauri command.
    const ALL: [CacheKind; 4] = [
        CacheKind::ServicePrincipal,
        CacheKind::Permissions,
        CacheKind::Audit,
        CacheKind::Lists,
    ];

    /// Where `kind` sits in [`Self::ALL`]. Only ever evaluated in a `const`
    /// context (see [`Self::idx`]), so the panic is a build error. Compares
    /// discriminants because `PartialEq` isn't callable in a `const fn`.
    const fn position(kind: CacheKind) -> usize {
        let mut i = 0;
        while i < Self::ALL.len() {
            if Self::ALL[i] as usize == kind as usize {
                return i;
            }
            i += 1;
        }
        panic!(
            "CacheKind missing from CacheKind::ALL — extend ALL; the per-kind bucket array is sized by it"
        );
    }

    /// Index into the per-kind bucket array: the kind's position in
    /// [`Self::ALL`], resolved at compile time per arm.
    const fn idx(self) -> usize {
        match self {
            CacheKind::ServicePrincipal => {
                const { CacheKind::position(CacheKind::ServicePrincipal) }
            }
            CacheKind::Permissions => const { CacheKind::position(CacheKind::Permissions) },
            CacheKind::Audit => const { CacheKind::position(CacheKind::Audit) },
            CacheKind::Lists => const { CacheKind::position(CacheKind::Lists) },
        }
    }
}

/// `ALL` holds no duplicates: every entry indexes its own bucket, so two kinds
/// can never share one (and with `position` proving every kind is present,
/// `ALL` is exactly the variant set).
const _: () = {
    let mut i = 0;
    while i < CacheKind::ALL.len() {
        assert!(
            CacheKind::ALL[i].idx() == i,
            "CacheKind::ALL lists a kind twice"
        );
        i += 1;
    }
};

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
    // `Arc` so a `get` clones a refcount, not the JSON tree, under the buckets
    // mutex. The index entries (`sp_index`, the cached audit run) are multi-MB
    // on a large tenant; deep-cloning one under that lock was the cache's
    // contention point. Deserialization borrows the Arc'd value after the lock
    // drops, so the tree is never duplicated.
    value: Arc<serde_json::Value>,
    // Set by `put_typed` so `get_typed` returns the original `Arc<T>` without
    // re-deserializing — the hot path for the multi-MB tenant search corpus,
    // which a debounced keystroke would otherwise rebuild from JSON.
    typed: Option<TypedValue>,
    inserted: Instant,
    // Monotonically-increasing counter used for LRU ordering.
    last_access: u64,
    // Exempt from LRU eviction. Set for the handful of tenant-wide *index*
    // entries (service-principal index, app-registration pairing rows,
    // search/gallery corpora) that cost a full directory scan to rebuild. They
    // share a bucket with thousands of cheap per-app entries, so without this
    // one mail-heavy audit run evicts the indexes and the next list visit pays
    // for a fresh scan. Pinned entries still expire on TTL and still drop on
    // explicit/tenant invalidation — they are only invisible to LRU.
    pinned: bool,
    // Identity of the `insert` that produced THIS entry, so a caller can prove
    // the entry under a key is still its own before removing it. Distinct from
    // `last_access`, which `touch` bumps on every read: a rollback keyed on
    // that would be defeated by any read landing in the window.
    stamp: u64,
}

struct Bucket {
    entries: HashMap<String, Entry>,
    // LRU ordering index: `last_access` tick -> key, so eviction pops the oldest
    // in O(log n). Kept in step with `entries` on insert/touch/remove; after a
    // bulk removal (`retain`, `evict_expired`) `prune_lru` drops the rows of
    // removed entries in place, and `clear` empties it. May briefly hold stale
    // ticks (entry gone or re-touched) — `evict_lru` skips them, keeping hot-path
    // bookkeeping to a single `remove` + `insert`.
    lru: BTreeMap<u64, String>,
    tick: u64,
    /// `inserted` of the oldest live entry; `None` when the bucket is empty.
    /// Lets the `put` path answer "is anything expired yet?" in one comparison
    /// instead of a scan (see [`Bucket::evict_if_needed`]). Recomputed after
    /// each sweep, never narrowed on plain removal: a conservative lower bound,
    /// so it may buy one unnecessary sweep but never miss one.
    oldest_insert: Option<Instant>,
    /// When [`Bucket::evict_expired`] last ran; `None` before the first sweep.
    /// Rate-limits the at-cap exact-TTL sweep (see [`Bucket::evict_if_needed`]).
    last_sweep: Option<Instant>,
    /// Test-only count of full TTL sweeps, so the "don't sweep when nothing can
    /// have expired" property is asserted, not just structured. Kept out of
    /// [`CacheStats`]: a public field would force the diagnostics UI to render
    /// an eviction-policy detail.
    #[cfg(test)]
    expired_sweeps: u64,
    /// Source of [`Entry::stamp`]. Only [`Bucket::insert`] advances it, and
    /// [`Bucket::clear`] deliberately does NOT reset it: reusing a stamp after
    /// a clear would let a stale rollback match a brand-new entry.
    next_stamp: u64,
}

impl Bucket {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            lru: BTreeMap::new(),
            tick: 0,
            oldest_insert: None,
            last_sweep: None,
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

    /// Drops every entry whose key fails `keep`, then prunes the LRU index of
    /// the rows that no longer name a live entry.
    fn retain(&mut self, keep: impl Fn(&str) -> bool) {
        self.entries.retain(|k, _| keep(k));
        self.prune_lru();
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.lru.clear();
        self.tick = 0;
        self.oldest_insert = None;
    }

    /// Drops, in place, every LRU row whose entry is gone or has been touched
    /// since (its live tick has a row of its own). This used to rebuild the
    /// index wholesale, cloning every key `String` of the bucket into a fresh
    /// `BTreeMap` — per sweep, under the bucket mutex.
    fn prune_lru(&mut self) {
        let entries = &self.entries;
        self.lru
            .retain(|tick, key| entries.get(key).is_some_and(|e| e.last_access == *tick));
    }

    /// Drops every entry older than `ttl`. Without it TTL is enforced only on
    /// read, so an entry nothing reads again keeps its slot indefinitely — and
    /// a *pinned* index is invisible to LRU, so forever. Called from
    /// [`Bucket::evict_if_needed`].
    ///
    /// One pass over the entries computes the surviving `oldest_insert` too,
    /// rather than a second `min()` scan after the `retain`.
    fn evict_expired(&mut self, ttl: Duration) {
        #[cfg(test)]
        {
            self.expired_sweeps += 1;
        }
        let mut oldest: Option<Instant> = None;
        self.entries.retain(|_, e| {
            let keep = e.inserted.elapsed() <= ttl;
            if keep {
                oldest = Some(oldest.map_or(e.inserted, |o| o.min(e.inserted)));
            }
            keep
        });
        self.prune_lru();
        self.oldest_insert = oldest;
        self.last_sweep = Some(Instant::now());
    }

    /// How far past the TTL the oldest entry must be before a `put` sweeps.
    ///
    /// Without slack, a bucket whose entries were written as a steady stream
    /// sits on an *expiry front*: after each sweep the new oldest entry is a
    /// hair younger than the TTL, expires a moment later, and the next `put`
    /// sweeps again — an O(n) pass per write, O(n²) across the front, under the
    /// mutex the interactive list reads contend on. With `ttl / 8` of slack a
    /// sweep removes everything written in that window at once, so sweeps are
    /// at most one per `ttl / 8` however fast the writes come.
    ///
    /// Correctness does not depend on the sweep: [`Cache::lookup`] enforces the
    /// exact TTL on every read, so an expired entry the sweep has not reached
    /// yet is never served — it only holds its slot a little longer.
    fn sweep_after(ttl: Duration) -> Duration {
        ttl.saturating_add(ttl / 8)
    }

    /// The minimum gap between two at-cap exact-TTL sweeps: `ttl / 64`, but
    /// never under 5 ms. Without it a FULL bucket on an expiry front swept on
    /// every `put` again — each sweep frees one slot, the next put refills it
    /// and finds the next entry a hair past the TTL — the O(n²) the slack was
    /// added to remove. Inside the gap the put falls through to plain LRU
    /// eviction; the exact TTL is still enforced on read.
    fn at_cap_sweep_interval(ttl: Duration) -> Duration {
        (ttl / 64).max(Duration::from_millis(5))
    }

    /// The `put` path's eviction pass, run only when there is something to
    /// evict. Both passes used to run on EVERY put — O(n) per write under the
    /// bucket mutex interactive list reads contend on. Both conditions here are
    /// load-bearing and neither subsumes the other:
    ///
    /// * **At cap** — LRU has to make room. Nothing else does.
    /// * **Something has expired** (below the cap, by more than
    ///   [`Bucket::sweep_after`]'s slack; at the cap, at all) — the only pass that reclaims entries nothing reads again,
    ///   including an expired *pinned* index LRU cannot touch; a below-cap
    ///   bucket would hold those until the process exits.
    ///
    /// The expiry test is one `Instant` comparison against `oldest_insert`, so
    /// the common put — under cap, nothing expired — costs the insert alone.
    fn evict_if_needed(&mut self, ttl: Duration, max_size: usize) {
        // Over the cap, LRU is about to evict something, so sweep at the EXACT
        // TTL first: an entry expired but still inside the slack must go before
        // a live one is pushed out for its slot — unless a sweep ran within
        // `at_cap_sweep_interval`, which keeps a full bucket on an expiry front
        // from sweeping per put. Below the cap nothing is displaced, so the
        // slack only delays reclaiming dead memory.
        let over_cap = self.entries.len() > max_size;
        let exact_allowed = over_cap
            && self
                .last_sweep
                .is_none_or(|t| t.elapsed() > Self::at_cap_sweep_interval(ttl));
        let limit = if exact_allowed {
            ttl
        } else {
            Self::sweep_after(ttl)
        };
        let anything_expired = self.oldest_insert.is_some_and(|o| o.elapsed() > limit);
        if !anything_expired && !over_cap {
            return;
        }
        // Honour the flag on BOTH branches, not just the early return: past the
        // cap the sweep ran on every put even when `anything_expired == false`
        // proves it removes nothing.
        if anything_expired {
            self.evict_expired(ttl);
        }
        self.evict_lru(max_size);
    }

    fn evict_lru(&mut self, max_size: usize) {
        // Shrink to the cap, not by one: after `configure` lowers `max_size`,
        // one eviction per `put` would never converge if writes stop. Pinned
        // entries are skipped, so an entirely-pinned bucket stops evicting
        // rather than dropping an index — the pinned set is a fixed handful of
        // tenant-wide keys, not caller-growable.
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
    /// Per-key invalidation counters for keys being fetched. A live index
    /// fetch holds no lock for seconds, so a mutation can invalidate the key
    /// underneath it; re-storing the pre-mutation snapshot into a **pinned**
    /// entry would serve stale authorization data for the full `Lists` TTL, out
    /// of LRU's reach.
    ///
    /// Per **key**, not global or per-(tenant, kind): the invalidation tiers
    /// exist so a credential-only mutation preserves the two tenant-wide
    /// indexes; a coarser counter would make those indexes refuse to store
    /// whenever any sibling key drops — the very tenant-wide rescan the tier
    /// exists to avoid, once per queued reader behind the single-flight gate.
    ///
    /// Bounded by construction: an entry lives only as long as its
    /// [`IndexWatch`] guard — released by the paired store or by `Drop` on
    /// paths that never reach one. Without that `Drop` the table only grows,
    /// and past [`Cache::MAX_WATCHES`] every pinned-index store refuses for the
    /// life of the process.
    watches: Mutex<HashMap<(usize, String), Watch>>,
}

/// One watched key: invalidation counter + in-flight fetch refcount. Refcounted
/// because `generation_for` on an already-watched key shares the counter;
/// releasing on the first finisher would strip the other's currency proof.
#[derive(Debug)]
struct Watch {
    counter: u64,
    refs: usize,
}

/// A live watch on one cache key, captured *before* a long index fetch and
/// handed to the matching `put_*_if_current`, which stores only if this exact
/// key was not invalidated in between. `Drop` ends the watch on paths that
/// never reach a store (`Err`, cancel, lost `try_join` sibling) — a registered
/// watch that outlives its fetch leaks forever.
///
/// Not `Clone`/`Copy` on purpose: exactly one owner releases it.
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
    /// when this guard never held a watch. [`Cache::store_if_current`] needs
    /// this: releasing first removes the last reference, so a concurrent
    /// invalidation would have nothing to bump.
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
    /// Ceiling on concurrently watched keys. Tenant-wide index fetches
    /// (`single_flight` collapses same-key fetchers), one long scan per run
    /// kind, and per-app mailbox-scope probes (bounded by the audit's fan-out
    /// cap) watch, so the live set stays small — a runaway guard, not a
    /// working limit. Past it
    /// `generation_for` returns [`Cache::WATCH_UNAVAILABLE`] and the store
    /// refuses.
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
        // Release the config lock before any bucket lock: every other path
        // (`limits_if_enabled` → `put_inner`) drops config before locking a
        // bucket, so this keeps a single lock order.
        drop(c);

        // Lowering `max_size` has to shrink the live buckets too: `evict_lru`
        // only runs from `put_inner`, so without this an oversized bucket
        // converges one `put` at a time — or never, if writes to that kind
        // stop.
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

    /// Effective entry cap for `kind`. Bulk pre-seed callers use it to bound
    /// the pass so seeding can't evict its own earlier entries.
    ///
    /// `max_size` targets kinds holding a handful of tenant-wide aggregates;
    /// the two per-object kinds instead cap at [`MAX_PER_OBJECT_CACHE_SIZE`]:
    /// [`CacheKind::ServicePrincipal`] (the audit's `|lean` seeding) and
    /// [`CacheKind::Lists`] (carries per-app `app_detail|`/`mail_scopes|`
    /// entries, which the aggregate-sized cap let thrash the bucket). Raising
    /// `max_size` past the ceiling gives the larger value for every kind.
    pub fn capacity_for(&self, kind: CacheKind) -> usize {
        Self::cap_for(kind, self.config.lock().max_size)
    }

    fn cap_for(kind: CacheKind, max_size: usize) -> usize {
        match kind {
            // A DEFAULT, not a floor: clamping unconditionally made `max_size`
            // a no-op for the two buckets that hold the memory. Above the
            // default the headroom still applies, so a normal install fits a
            // whole tenant.
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
                // A `put_typed` entry stores `Value::Null` as its untyped body,
                // so an untyped `get` against one ALWAYS fails to decode.
                // Removing it here turned the "silent miss + rescan" footgun
                // into a permanent eviction of a pinned tenant-wide index — one
                // wrong-door read destroying the entry pinning exists to
                // protect. Not poisoned: use `get_typed` / the `sp_index_*` /
                // `app_name_index_*` accessors. Leave it and just miss.
                tracing::warn!(
                    ?err,
                    "untyped `get` against a typed cache entry; use `get_typed`. Entry kept."
                );
                self.record(kind, false);
                None
            }
            Err(err) => {
                tracing::warn!(?err, "cache value failed to deserialize; dropping entry");
                // Drop rather than re-fail on every read: `lookup` already
                // touched it, so a retained poisoned entry keeps refreshing its
                // LRU position and survives to TTL without serving a hit.
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

    /// [`Self::put`] under the store-after-invalidate guard, **unpinned** — for
    /// a long scan's result (an audit run, a tenant sweep, a per-app mailbox
    /// probe) that a mutation can invalidate while the scan is still awaiting.
    /// `watch` comes from a [`Cache::generation_for`] captured **before** the
    /// fetch's first await; a lost race is skipped (`false`), so the
    /// invalidation stands instead of being undone by the pre-mutation result
    /// for the full TTL. Per-object keys belong here, never in the pinned
    /// [`Self::put_typed_index_if_current`].
    pub fn put_if_current<T>(&self, watch: IndexWatch<'_>, value: &T) -> bool
    where
        T: serde::Serialize,
    {
        self.store_if_current(watch, |cache, kind, key| {
            cache.put_inner(kind, key, value, false)
        })
    }

    /// Stores through `store` only if `watch`'s key was never invalidated —
    /// including during the store itself.
    ///
    /// The watch is held **across** `store`. Releasing first (the obvious
    /// "check, then write") leaves a window: `release_watch` removes the watch
    /// entry, so an `invalidate` landing between the check and the bucket lock
    /// bumps nothing — the pre-mutation snapshot lands pinned for the whole
    /// TTL. Holding the reference gives that invalidation something to bump,
    /// and the post-store comparison sees it and undoes the write. Lock order
    /// is unchanged (watches, then bucket, never both), so no deadlock risk.
    ///
    /// `store` returns the [`Entry::stamp`] it wrote; rollback is a
    /// compare-and-remove against it. Removing by key name was the opposite
    /// race: A stores → invalidation bumps the counter → B stores a *valid*
    /// index → A's rollback deletes B's entry, silently costing a rescan.
    fn store_if_current(
        &self,
        watch: IndexWatch<'_>,
        store: impl FnOnce(&Self, CacheKind, String) -> Option<u64>,
    ) -> bool {
        let (kind, key, since) = (watch.kind, watch.key.clone(), watch.since);

        // Pre-check: cheap, and it keeps the common lost-race case from paying
        // for a serialize + insert it is only going to undo. An unwatched key
        // cannot be proven current — covers the table-full case and a second
        // store against a consumed watch.
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

        // Second look: `watch` held its reference throughout, so any
        // invalidation in the window bumped the counter rather than passing
        // unseen.
        let (_, _, _, after) = watch.release();
        match after {
            // A declined store (`None` stamp: caching disabled for the kind,
            // or a serialization failure) is not a store — report it as
            // skipped, as the `put_*_if_current` docs promise.
            Some(now) if now == since => stamp.is_some(),
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

    /// [`Self::put_typed`] under the store-after-invalidate guard, unpinned —
    /// the typed twin of [`Self::put_if_current`]. Returns `false` when the
    /// store was skipped.
    pub fn put_typed_if_current<T: Send + Sync + 'static>(
        &self,
        watch: IndexWatch<'_>,
        value: Arc<T>,
    ) -> bool {
        self.store_if_current(watch, move |cache, kind, key| {
            cache.put_typed_inner(kind, key, value, false)
        })
    }

    /// [`Self::put_typed`], but **pinned**: exempt from LRU eviction (TTL and
    /// invalidation still apply) — the combination the large, read-hot tenant
    /// indexes want: no re-deserialize on read *and* not evictable by the
    /// per-app entries sharing their bucket. Use only for tenant-wide *index*
    /// entries that cost a full directory scan to rebuild; the pinned set must
    /// stay a bounded handful of keys, never a per-directory-object key.
    ///
    /// There is deliberately no untyped (serializing) pinned store: every
    /// pinned entry is read on every warm list visit, so it is kept typed and a
    /// read is a refcount clone, not a JSON decode.
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
                // Miss, and leave the entry alone — the mirror of the
                // wrong-door rule `get` follows. Reached when the entry is
                // untyped or typed as another `T`; NEITHER means unusable — it
                // still serves callers using the right door, so it is *this*
                // read that is wrong. Removing it let one wrong-door read
                // permanently evict a pinned tenant-wide index, the exact
                // failure `get` was fixed for. And unlike `get` nothing is
                // decoded here: a failed downcast says nothing about entry
                // integrity, so there is no poisoned case to clean up.
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
    /// Capture it *before* the fetch and pass the guard to the matching
    /// `put_*_if_current`. Watching an already-watched key joins its watch, so
    /// two racing fetchers of one key both refuse if it was dropped.
    ///
    /// `Drop` releases the watch, so a fetch that never reaches its store
    /// cannot leak the entry — and leaks matter: entries are never reclaimed,
    /// so a trickle of them fills `Cache::MAX_WATCHES` and every pinned-index
    /// store then refuses permanently, with no recovery short of a restart. A
    /// genuinely full table yields [`Cache::WATCH_UNAVAILABLE`] — fail-closed,
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
                "cache watch table full; the guarded store will refuse and re-fetch"
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

    /// The live counter for a watched key, leaving the watch in place.
    fn peek_watch(&self, kind: CacheKind, key: &str) -> Option<u64> {
        self.watches
            .lock()
            .get(&(kind.idx(), key.to_string()))
            .map(|w| w.counter)
    }

    /// Drop one reference, returning the key's live counter and removing the
    /// entry once the last holder lets go. `None` = never watched, which
    /// callers treat as "cannot prove current" and refuse.
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
