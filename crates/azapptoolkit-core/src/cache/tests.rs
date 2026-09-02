//! Unit tests for the cache (`super`), kept out of `cache.rs` so the
//! production code reads in one pass.

/// A bucket at its entry cap must not run the full TTL sweep on every `put`
/// when nothing can have expired.
///
/// `evict_expired` is a `retain` over `n`, plus a `rebuild_lru` that clones
/// every key `String` into a fresh `BTreeMap`, plus a `min()` scan — all
/// under the bucket mutex the interactive list reads contend on. Past the
/// cap that ran on every insert although `anything_expired == false` is a
/// proof it would remove nothing.
#[test]
fn a_bucket_at_cap_does_not_sweep_when_nothing_has_expired() {
    const CAP: usize = 8;
    let ttl = Duration::from_secs(3600);
    let mut bucket = Bucket::new();

    // Fill past the cap with fresh entries.
    for i in 0..(CAP * 3) {
        bucket.insert(format!("k{i}"), Arc::new(serde_json::json!(i)), None, false);
        bucket.evict_if_needed(ttl, CAP);
    }

    assert_eq!(
        bucket.expired_sweeps, 0,
        "nothing is near the TTL, so every one of these sweeps was wasted work"
    );
    // LRU eviction still converges to the cap — the sweep was never what
    // made room.
    assert_eq!(bucket.entries.len(), CAP);
    // And the survivors are the most recent, i.e. `evict_lru` did the work.
    assert!(bucket.entries.contains_key(&format!("k{}", CAP * 3 - 1)));
    assert!(!bucket.entries.contains_key("k0"));
}

/// The other half of the rule: the sweep still runs when something HAS
/// expired, including for a bucket that never reaches its cap — it is the
/// only thing that reclaims an expired pinned index.
#[test]
fn an_expired_entry_is_still_swept_below_the_cap() {
    let ttl = Duration::from_millis(1);
    let mut bucket = Bucket::new();
    bucket.insert("old".into(), Arc::new(serde_json::json!(1)), None, false);
    std::thread::sleep(Duration::from_millis(5));

    bucket.evict_if_needed(ttl, 1024);
    assert_eq!(
        bucket.expired_sweeps, 1,
        "an expired entry must be reclaimed"
    );
    assert!(bucket.entries.is_empty());
}

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
