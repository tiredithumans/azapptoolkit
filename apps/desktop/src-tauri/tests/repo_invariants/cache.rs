//! Tenant-scoped cache lifecycle: invalidate only on `Ok`, pin only the
//! tenant-wide indexes, and take the generation watch **before** the fetch it
//! guards.
//!
//! AGENTS.md calls cross-tenant leakage "the #1 footgun"; these are the rules
//! that keep it mechanical rather than remembered.

// No `include_str!` table here on purpose: every rule below derives its subject
// from `sources::command_modules()`, the same source-tree walk `sources.rs` was
// written to replace the fan-out/cancel tables with. Three hand-maintained
// tables outlived that change in this file — `COMMAND_SOURCES`,
// `PINNED_WRITE_SITES` and `WATCH_CAPTURE_SITES` — so these rules only ever
// looked at the files someone had remembered to list. See `sources.rs`: "A list
// you must remember to extend is not a ratchet."

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
    for (name, src) in super::sources::command_modules() {
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

/// Every pinned cache write lands on a **tenant-wide index key**, never a
/// per-object one.
///
/// A pinned entry is invisible to LRU, so a pinned per-object key is
/// unevictable junk that crowds out the indexes pinning exists to protect —
/// AGENTS.md, "Never pin a per-object key".
///
/// The subject is derived, and that is the whole point of this rewrite. This
/// rule used to iterate a hand-maintained `PINNED_WRITE_SITES` table of six
/// `include_str!`d files with an expected count each, in the same file whose
/// sibling module opens with "a list you must remember to extend is not a
/// ratchet". A seventh module pinning a key was invisible to it — the rule only
/// ever looked where someone had remembered to point it.
///
/// The list that remains is of *key builders that may be pinned*, which is the
/// semantic rule rather than a place to look: a new pinned write anywhere in
/// `src/commands` is now checked, and passes only if it pins one of these.
#[test]
fn pinned_cache_writes_stay_on_the_tenant_wide_indexes() {
    let mut offenders: Vec<String> = Vec::new();
    let mut found = 0usize;

    for (name, src) in super::sources::command_modules() {
        let lines: Vec<&str> = src.lines().collect();
        for (line_no, line) in lines.iter().enumerate() {
            if !PINNED_WRITES.iter().any(|w| line.contains(w)) {
                continue;
            }
            let trimmed = line.trim_start();
            // Skip doc links like [`Cache::put_index`] and the definitions.
            if trimmed.starts_with("//") || trimmed.starts_with("pub fn") {
                continue;
            }
            found += 1;
            // The guarded forms take an `IndexWatch`, which was itself minted by
            // `generation_for(kind, key)` — the key never appears here, so the
            // watch-capture rule below is what covers those. Only the direct
            // forms name a key at the call site.
            if line.contains("_if_current(") {
                continue;
            }
            // The key may be bound a few statements up (`let key = …_key(…)`),
            // so search back to the top of the enclosing function rather than a
            // fixed number of lines.
            let names_a_pinnable_key = lines[..=line_no]
                .iter()
                .rev()
                .take_while(|l| !l.starts_with("fn ") && !l.starts_with("pub"))
                .any(|l| PINNABLE_KEYS.iter().any(|k| l.contains(k)));
            if names_a_pinnable_key {
                continue;
            }
            offenders.push(format!("{name}:{} — {trimmed}", line_no + 1));
        }
    }

    assert!(
        found >= 5,
        "found only {found} pinned cache write(s) across the command tree — the source walk or \
         the call detector is broken, and a rule that scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "pinned cache write(s) on something that is not a known tenant-wide index: {offenders:#?}\n\
         A pinned entry is invisible to LRU, so it must be a tenant-wide INDEX (one per tenant), \
         never a per-object key — those belong in an unpinned `put`. If this really is a new \
         tenant-wide index, add its key builder to PINNABLE_KEYS."
    );
}

/// The pinned-write call forms.
const PINNED_WRITES: &[&str] = &[
    "put_index(",
    "put_index_if_current(",
    "put_typed_index(",
    "put_typed_index_if_current(",
];

/// Key builders whose entries are tenant-wide indexes — one entry per tenant,
/// costing a full directory scan to rebuild — and so may be pinned.
///
/// This is the rule itself, not a place to look: adding an entry means claiming
/// a new key is tenant-wide, which is exactly the review the pin deserves.
const PINNABLE_KEYS: &[&str] = &[
    "sp_index_key(",
    "app_name_index_key(",
    "search_corpus_key(",
    // The application gallery: a static, tenant-independent catalog.
    "gallery_corpus_key(",
];

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
/// Derived like its sibling above: every module in the tree is checked, so a
/// new unguarded pinned write cannot hide in a file no table names.
#[test]
fn pinned_index_writes_are_guarded_except_the_static_gallery_corpus() {
    let mut offenders: Vec<String> = Vec::new();
    for (name, src) in super::sources::command_modules() {
        // The trailing `(` is what separates these from their `_if_current`
        // siblings (and from doc links like [`Cache::put_index`]).
        let unguarded = src.matches("put_index(").count() + src.matches("put_typed_index(").count();
        let expected = usize::from(name == "commands/gallery.rs");
        if unguarded != expected {
            offenders.push(format!(
                "{name}: {unguarded} unguarded pinned write(s), expected {expected}"
            ));
        }
    }
    assert!(
        offenders.is_empty(),
        "UNGUARDED pinned cache write(s): {offenders:#?}\n\
         Capture `cache.generation_for(kind, key)` BEFORE the fetch and store through \
         `put_index_if_current` / `put_typed_index_if_current`, so a snapshot that raced a \
         mutation is dropped instead of re-pinned for the full TTL. The one exemption is the \
         application gallery corpus: a static, tenant-independent catalog with no race to lose."
    );
}

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

    // Derived, like both rules above. This used to iterate a hand-maintained
    // `WATCH_CAPTURE_SITES` table of six `include_str!`d files, so a seventh
    // module capturing a watch across a fetch was invisible to the rule.
    for (name, src) in super::sources::command_modules() {
        let src = src.as_str();
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
