//! Tenant-scoped cache lifecycle: invalidate only on `Ok`, pin only the
//! tenant-wide indexes, and take the generation watch **before** the fetch it
//! guards.
//!
//! AGENTS.md calls cross-tenant leakage "the #1 footgun"; these are the rules
//! that keep it mechanical rather than remembered.

use crate::commands::COMMAND_SOURCES;

/// Cache invalidation runs **only on `Ok`** — AGENTS.md's rule, and until now
/// prose only.
///
/// A failed write that clears the cache throws away data that is still correct
/// and forces a full tenant re-fetch to rebuild it; worse, on the tiered paths
/// it discards the two indexes the tier exists to preserve. The check is
/// deliberately narrow — it catches the unambiguous shape, an invalidation
/// lexically inside an `Err(...)` arm — rather than trying to prove reachability
/// from a text scan. A narrow check that never cries wolf is worth more here
/// than a broad one someone learns to suppress.
#[test]
fn cache_invalidation_never_runs_on_an_error_path() {
    let mut offenders: Vec<String> = Vec::new();
    for (name, src) in COMMAND_SOURCES {
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || !INVALIDATORS.iter().any(|f| line.contains(f)) {
                continue;
            }
            // Skip the definitions themselves.
            if line.contains("fn invalidate_app") {
                continue;
            }
            let indent = line.len() - trimmed.len();
            // Nearest enclosing branch marker at shallower indentation decides.
            for previous in lines[..i].iter().rev().take(20) {
                let ptrim = previous.trim_start();
                if ptrim.is_empty() || ptrim.starts_with("//") {
                    continue;
                }
                let pindent = previous.len() - ptrim.len();
                if pindent >= indent {
                    continue;
                }
                if ptrim.starts_with("Err(") || ptrim.starts_with("Err ") {
                    offenders.push(format!("{name}:{} — {}", i + 1, trimmed));
                }
                break;
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "cache invalidation on an error path: {offenders:#?}\n\
         Invalidate only after the mutation succeeded — a failed write must leave fresh data \
         alone. See AGENTS.md, \"Invalidate caches only on `Ok`\"."
    );
}

const INVALIDATORS: &[&str] = &[
    "invalidate_app_lists(",
    "invalidate_app_credentials(",
    "invalidate_app_detail_state(",
    "invalidate_app_details(",
];

/// Every module that writes a **pinned** cache entry, and how many it writes.
///
/// Pinning exempts an entry from LRU, so a pinned per-object key is unevictable
/// junk that crowds out the tenant-wide indexes pinning exists to protect —
/// AGENTS.md: "Never pin a per-object key". The set of legitimately pinned keys
/// is a fixed handful of tenant-wide indexes, so a ratchet is the right shape:
/// adding a pin means editing this list, which is the review the rule wants.
const PINNED_WRITE_SITES: &[(&str, &str, usize)] = &[
    (
        "commands/search.rs",
        include_str!("../../src/commands/search.rs"),
        1,
    ),
    (
        "commands/gallery.rs",
        include_str!("../../src/commands/gallery.rs"),
        1,
    ),
    (
        "commands/enterprise_application.rs",
        include_str!("../../src/commands/enterprise_application.rs"),
        1,
    ),
    (
        "commands/applications/mod.rs",
        include_str!("../../src/commands/applications/mod.rs"),
        1,
    ),
    (
        "commands/managed_identity.rs",
        include_str!("../../src/commands/managed_identity.rs"),
        1,
    ),
    (
        "commands/applications/cache.rs",
        include_str!("../../src/commands/applications/cache.rs"),
        2,
    ),
];

#[test]
fn pinned_cache_writes_stay_on_the_tenant_wide_indexes() {
    for (name, src, expected) in PINNED_WRITE_SITES {
        let found = src.matches("put_index(").count()
            + src.matches("put_index_if_current(").count()
            + src.matches("put_typed_index(").count()
            + src.matches("put_typed_index_if_current(").count();
        assert_eq!(
            found, *expected,
            "{name} has {found} pinned cache write(s), expected {expected}. A pinned entry is \
             invisible to LRU, so it must be a tenant-wide INDEX (one per tenant), never a \
             per-object key — those belong in an unpinned `put`. If this is a new tenant-wide \
             index, update PINNED_WRITE_SITES."
        );
    }
}

/// A pinned index built from a **live tenant-wide scan** must store through the
/// `_if_current` guard.
///
/// The scan takes seconds under no lock, so a mutation can land mid-flight and
/// `invalidate_app_lists` drops the key — and an unconditional store then
/// re-pins the *pre-mutation* snapshot. Pinned means LRU cannot evict it, so
/// that is not a stale read that ages out in seconds: the list shows a deleted
/// app, or misses a new one, until the 60-minute TTL. The three list caches all
/// had this; the two directory indexes and the search corpus did not.
///
/// The one exemption is the application **gallery** corpus: a static,
/// tenant-independent catalog that no mutation in this app can invalidate, so
/// it has no race to lose.
#[test]
fn pinned_index_writes_are_guarded_except_the_static_gallery_corpus() {
    for (name, src, _) in PINNED_WRITE_SITES {
        // The trailing `(` is what separates these from their `_if_current`
        // siblings (and from doc links like [`Cache::put_index`]).
        let unguarded = src.matches("put_index(").count() + src.matches("put_typed_index(").count();
        let expected = usize::from(*name == "commands/gallery.rs");
        assert_eq!(
            unguarded, expected,
            "{name} has {unguarded} UNGUARDED pinned cache write(s), expected {expected}. \
             Capture `cache.generation()` BEFORE the fetch and store through \
             `put_index_if_current` / `put_typed_index_if_current`, so a snapshot that raced a \
             mutation is dropped instead of re-pinned for the full TTL."
        );
    }
}

/// Modules that capture a cache watch across a live fetch. Superset of
/// `PINNED_WRITE_SITES` — `applications/cache.rs` holds the two shared index
/// accessors that fetch on behalf of everyone else.
const WATCH_CAPTURE_SITES: &[(&str, &str)] = &[
    (
        "commands/search.rs",
        include_str!("../../src/commands/search.rs"),
    ),
    (
        "commands/enterprise_application.rs",
        include_str!("../../src/commands/enterprise_application.rs"),
    ),
    (
        "commands/applications/mod.rs",
        include_str!("../../src/commands/applications/mod.rs"),
    ),
    (
        "commands/applications/cache.rs",
        include_str!("../../src/commands/applications/cache.rs"),
    ),
    (
        "commands/managed_identity.rs",
        include_str!("../../src/commands/managed_identity.rs"),
    ),
    (
        "commands/audit.rs",
        include_str!("../../src/commands/audit.rs"),
    ),
];

/// The guard is only a guard if the watch is taken **before** the fetch it is
/// meant to cover.
///
/// Its sibling above pins the *shape* — that a pinned write goes through
/// `put_*_if_current` rather than `put_index` — and that is what let the real
/// bug through: a call site can use the guarded form and still capture the
/// generation *after* the awaited scan, at which point the window being checked
/// is empty and the guard cannot ever fire. Two production sites (the App
/// Registrations pairing join and the audit's SP prefetch) had quietly drifted
/// to exactly that, and every test kept passing, because a capture-after-fetch
/// is textually indistinguishable from a capture-before-fetch unless you look
/// at the order.
///
/// So this checks the order: inside an `async fn`, a capture must be separated
/// from the store it authorizes by at least one `.await` — the fetch. A capture
/// that sits after the fetch has nothing between it and the store, and fails
/// here.
///
/// Synchronous helpers are out of scope by construction: with no `.await` there
/// is no window to lose, which is why the scan only enters `async fn` bodies.
#[test]
fn a_watch_is_captured_before_the_fetch_it_guards_not_after() {
    /// Whether the function enclosing `at` is an `async fn`.
    fn in_async_fn(src: &str, at: usize) -> bool {
        match src[..at].rfind("fn ") {
            Some(f) => src[..f].trim_end().ends_with("async"),
            None => false,
        }
    }

    let mut bad: Vec<String> = Vec::new();
    let mut checked = 0usize;

    for (name, src) in WATCH_CAPTURE_SITES {
        let mut from = 0usize;
        while let Some(rel) = src[from..].find("generation_for(") {
            let capture = from + rel;
            from = capture + "generation_for(".len();
            if !in_async_fn(src, capture) {
                continue;
            }
            checked += 1;
            let Some(rel_store) = src[capture..].find("_if_current(") else {
                bad.push(format!(
                    "{name}: a watch is captured in an async fn but never reaches a store"
                ));
                continue;
            };
            let window = &src[capture..capture + rel_store];
            if !window.contains(".await") {
                let line = src[..capture].lines().count();
                bad.push(format!(
                    "{name}:{line}: nothing is awaited between the capture and the store"
                ));
            }
        }
    }

    assert!(
        checked > 0,
        "no watch captures found in any async fn — this test is checking nothing. \
         Did `generation_for` get renamed?"
    );
    assert!(
        bad.is_empty(),
        "cache watch(es) captured AFTER the fetch they are supposed to guard: {bad:#?}\n\
         Capture `cache.generation_for(kind, &key)` BEFORE the awaited scan and hand the \
         returned `IndexWatch` to `put_*_if_current`. Captured after, the guarded window is \
         empty: the store can never detect the mutation it raced, and re-pins a pre-mutation \
         snapshot that LRU cannot evict for the full TTL."
    );
}

/// Every watch must be released, so it must reach a store or be dropped.
///
/// `IndexWatch` is `#[must_use]` and releases on `Drop`, which is what makes an
/// early `?` on a failed fetch safe. This pins the type-level half of that: a
/// watch handed out by value, never `Copy`, so the compiler can enforce single
/// ownership. If `generation_for` is ever reverted to returning a bare counter,
/// the leak comes back — silently, and unrecoverably once the table fills.
#[test]
fn generation_for_hands_out_an_owned_guard_not_a_bare_counter() {
    let cache_src = include_str!("../../../../../crates/azapptoolkit-core/src/cache.rs");
    assert!(
        cache_src
            .contains("pub fn generation_for(&self, kind: CacheKind, key: &str) -> IndexWatch<'_>"),
        "generation_for must return an owned IndexWatch. A bare counter cannot release \
         itself, so a failed or cancelled fetch leaks its registration — and once the watch \
         table fills, EVERY pinned-index store refuses for the life of the process."
    );
    assert!(
        cache_src.contains("impl Drop for IndexWatch<'_>"),
        "IndexWatch must release its watch on Drop — that is what covers the error paths \
         that never reach a store."
    );
}

/// `CacheKind::ServicePrincipal` self-invalidates **in the graph client**, and
/// `invalidate_app_lists` must not touch it.
///
/// AGENTS.md states this as its own invariant, and it was the one cache rule in
/// that list with no mechanical backstop. It is easy to get wrong in a way that
/// looks like a tidy-up: the SP cache is keyed by `appId`, but every SP mutator
/// takes an SP *object* id, so a targeted bust is impossible and the client
/// sweeps the whole `{tenant}|` prefix instead. Someone "completing"
/// `invalidate_app_lists` by adding the missing kind to it would move the sweep
/// to the aggregators, where the object-id/appId mismatch makes it a silent
/// no-op — leaving a patched or deleted SP cached for up to the 60-minute TTL,
/// skewing the audit's `accountEnabled` read and the detail pane's paired-SP
/// fields.
#[test]
fn service_principal_cache_self_invalidates_in_the_client() {
    let client_src =
        include_str!("../../../../../crates/azapptoolkit-graph/src/client/service_principals.rs");
    assert!(
        client_src.contains("fn invalidate_sp_cache(&self)")
            && client_src.contains("invalidate_prefix(CacheKind::ServicePrincipal"),
        "the graph client must keep sweeping its own `{{tenant}}|` prefix for \
         CacheKind::ServicePrincipal. The SP mutators know only the SP object id while the cache \
         is keyed by appId, so the prefix sweep is the only bust that can't miss."
    );

    let cache_facade = include_str!("../../src/commands/applications/cache.rs");
    let lists = cache_facade
        .split_once("pub(crate) fn invalidate_app_lists")
        .expect("invalidate_app_lists moved")
        .1;
    let body = lists
        .split_once("\npub(crate) fn ")
        .map(|(b, _)| b)
        .unwrap_or(lists);
    assert!(
        !body.contains("CacheKind::ServicePrincipal"),
        "invalidate_app_lists must NOT invalidate CacheKind::ServicePrincipal. That kind is keyed \
         by appId and is swept by the graph client itself (`invalidate_sp_cache`); an \
         aggregator-side bust here is keyed wrong, so it silently clears nothing while reading as \
         though it covered the case."
    );
}
