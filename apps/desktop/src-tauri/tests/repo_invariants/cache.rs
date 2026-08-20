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

/// Searches back from `line_no` to the top of the enclosing function for a
/// pinnable key builder. Split out from the rule so the walk itself is
/// testable — a rule that stops firing is indistinguishable from a clean tree.
fn back_walk_names_a_pinnable_key(lines: &[&str], line_no: usize) -> bool {
    lines[..=line_no]
        .iter()
        .map(|l| l.trim_start())
        .rev()
        .take_while(|l| !is_fn_header(l))
        .filter(|l| !l.starts_with("//"))
        .any(|l| PINNABLE_KEYS.iter().any(|k| l.contains(k)))
}

/// Whether `trimmed` opens a function — at any indentation, with any
/// combination of visibility, `async`, `const`, `unsafe` or `extern`.
///
/// The walk above uses this as its boundary, so anything it fails to recognise
/// silently widens the search into the previous function.
fn is_fn_header(trimmed: &str) -> bool {
    let rest = trimmed
        .strip_prefix("pub(crate) ")
        .or_else(|| trimmed.strip_prefix("pub(super) "))
        .or_else(|| trimmed.strip_prefix("pub "))
        .unwrap_or(trimmed);
    let rest = rest
        .strip_prefix("const ")
        .or_else(|| rest.strip_prefix("async "))
        .or_else(|| rest.strip_prefix("unsafe "))
        .unwrap_or(rest);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    rest.starts_with("fn ")
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
            //
            // Two ways this whitewashed a real offender before, both from
            // testing the RAW line:
            //
            // * the boundary was `!l.starts_with("fn ")` on an untrimmed line,
            //   so any indented `fn` — inside an `impl`, an inner module, a
            //   nested helper — never ended the walk, and it ran back through
            //   whole earlier functions until it found some mention of a
            //   pinnable key;
            // * `///` lines fail both predicates too, so a doc link such as
            //   [`sp_index_key`] in the writer's OWN doc comment satisfied the
            //   search. A pinned per-object write could be excused by prose.
            //
            // Now: trim first, stop at any function header at any depth, and
            // read only code.
            let names_a_pinnable_key = back_walk_names_a_pinnable_key(&lines, line_no);
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

/// The walk this rule depends on, on the two shapes that used to slip past it.
///
/// Both were found by re-reading the rule rather than the code it guards: it
/// had been written against top-level `pub async fn` command handlers and
/// tested only against a tree that happened to have no counter-example, so it
/// passed while excusing exactly what it exists to catch.
#[test]
fn the_pinnable_key_back_walk_stops_at_the_function_it_is_in() {
    let indented = vec![
        "impl Foo {",
        "    fn earlier(&self) {",
        "        let key = sp_index_key(tenant);",
        "    }",
        "",
        "    fn offender(&self) {",
        "        cache.put_index(kind, per_object_key(id), &v);",
    ];
    assert!(
        !back_walk_names_a_pinnable_key(&indented, 6),
        "an INDENTED `fn` must end the walk — otherwise the key named in the previous \
         function excuses this pinned write, which is how a pinned per-object key passes"
    );

    let documented = vec![
        "fn offender() {",
        "    /// Mirrors [`sp_index_key`] for the per-object case.",
        "    cache.put_index(kind, per_object_key(id), &v);",
    ];
    assert!(
        !back_walk_names_a_pinnable_key(&documented, 2),
        "a doc comment naming a pinnable key is prose, not a key — it must not excuse the write"
    );

    let genuine = vec![
        "pub async fn real_index_write() {",
        "    let key = sp_index_key(tenant);",
        "    cache.put_index(kind, key, &v);",
    ];
    assert!(
        back_walk_names_a_pinnable_key(&genuine, 2),
        "the rule must still accept a genuine tenant-wide index write"
    );
}

#[test]
fn a_function_header_is_recognised_at_any_depth_or_visibility() {
    for header in [
        "fn f() {",
        "pub fn f() {",
        "pub(crate) fn f() {",
        "pub(super) fn f() {",
        "async fn f() {",
        "pub async fn f() {",
        "const fn f() {",
        "unsafe fn f() {",
    ] {
        assert!(
            is_fn_header(header),
            "not recognised as a function: {header}"
        );
    }
    for other in ["let fn_name = 1;", "// fn f() {", "pub struct S {", "}"] {
        assert!(!is_fn_header(other), "wrongly read as a function: {other}");
    }
}

/// A command that answers from the cache must prove the session itself.
///
/// Every ordinary read reaches a service through a client factory, so a tenant
/// with no session fails at the token and no data comes back — the session
/// check is implicit in the round trip. A command that answers from cache alone
/// skips that entirely, and then the `tenant_id` **argument** is the only thing
/// deciding whose directory data is returned. A stale or wrong id from the
/// webview (a tenant switch mid-flight is the realistic one) serves another
/// tenant's data: the cross-tenant leak AGENTS.md calls the #1 footgun.
///
/// So: read the cache, and either build a client or check `tenant_context`.
#[test]
fn a_command_answering_from_cache_alone_checks_the_session() {
    // Detection is whitespace-insensitive and the proof must DOMINATE the read.
    //
    // Both properties were added after a wavelet run found this rule passing
    // vacuously. The old detector was a literal `cache.get(` substring scan over
    // the raw body, which rustfmt defeats: `state\n.cache\n.get(...)` and the
    // turbofish form `cache.get::<Vec<T>>(...)` both contain no such substring.
    // It matched exactly ONE command — the compliant one — which cleared its own
    // `found >= 1` floor while four unproven reads went unseen.
    //
    // Dominance matters for the same reason: `get_mail_scopes_*` returns from the
    // cache and only then builds a Graph client, so a body-wide `graph_for(`
    // search "proved" a session the cache-hit path never reaches.
    let mut offenders: Vec<String> = Vec::new();
    let mut checked: Vec<String> = Vec::new();

    for cmd in super::sources::commands() {
        let (flat, map) = flatten_out_whitespace(&cmd.body);
        let Some(read_at) = first_cache_read(&flat) else {
            continue;
        };
        checked.push(format!("{}::{}", cmd.module, cmd.name));
        let proven_before = first_session_proof(&flat).is_some_and(|p| p < read_at);
        if !proven_before {
            let line = cmd.body[..map[read_at]].matches('\n').count() + 1;
            offenders.push(format!(
                "{}::{} (cache read at body line {line})",
                cmd.module, cmd.name
            ));
        }
    }

    // An explicit floor, not `>= 1`. The old floor was cleared by a single
    // compliant command, so a detector that had gone blind still passed. These
    // are the commands that genuinely answer from cache; if the walk or the
    // matcher breaks, the count drops and this fires.
    // The real count, not a token floor. The rule this replaced asserted
    // `found >= 1` and was cleared by the single compliant command while the
    // detector was blind to fifteen others.
    const KNOWN_CACHE_READING_COMMANDS: usize = 16;
    assert!(
        checked.len() >= KNOWN_CACHE_READING_COMMANDS,
        "the cache-read detector found only {} command(s) but at least {} answer from cache \
         ({:?}) — the source walk or the matcher is broken, and a rule that scans nothing \
         passes vacuously",
        checked.len(),
        KNOWN_CACHE_READING_COMMANDS,
        checked
    );
    assert!(
        offenders.is_empty(),
        "these commands answer from the cache without FIRST proving the tenant has a session, \
         so the `tenant_id` argument alone decides whose data is returned:\n  {}",
        offenders.join("\n  ")
    );
}

/// Strips every whitespace character, returning the stripped text plus a map
/// from each stripped index back to its offset in the original — so a match can
/// still be reported at the right line.
fn flatten_out_whitespace(body: &str) -> (String, Vec<usize>) {
    let mut flat = String::with_capacity(body.len());
    let mut map = Vec::with_capacity(body.len());
    for (i, c) in body.char_indices() {
        if !c.is_whitespace() {
            flat.push(c);
            map.push(i);
        }
    }
    (flat, map)
}

/// First `…cache.get(`, `…cache.get_typed(` or `…cache.get::<T>(` in flattened
/// text. Written as a scan rather than a substring list because the turbofish
/// form carries an arbitrary type between `::<` and `(` — including nested
/// generics like `Vec<MailScopeEntry>`, whose `>>` defeats a naive pattern.
fn first_cache_read(flat: &str) -> Option<usize> {
    let mut from = 0usize;
    while let Some(hit) = flat[from..].find("cache.get") {
        let at = from + hit;
        let rest = &flat[at + "cache.get".len()..];
        if rest.starts_with('(') || rest.starts_with("_typed") || rest.starts_with("::<") {
            return Some(at);
        }
        from = at + "cache.get".len();
    }
    None
}

/// Either proves a session: a client factory needs a token for that tenant, and
/// `tenant_context` is `None` unless that tenant signed in this session.
fn first_session_proof(flat: &str) -> Option<usize> {
    const SESSION_PROOFS: [&str; 6] = [
        // The shared helper, and the raw lookup it wraps (Option-returning
        // commands use `tenant_context(&tenant_id)?` directly).
        "prove_tenant_session(",
        "tenant_context(",
        // A client factory needs a token for that tenant, so reaching one is
        // itself a proof — but only when it happens BEFORE the cache read.
        "graph_for(",
        "exchange_for(",
        "arm_for(",
        "keyvault_for(",
    ];
    SESSION_PROOFS.iter().filter_map(|p| flat.find(p)).min()
}

#[test]
fn the_cache_read_detector_sees_the_forms_rustfmt_actually_produces() {
    // The regression guard for the guard. Each of these is a shape that existed
    // in the tree while the old literal scan reported zero.
    assert!(first_cache_read("state.cache.get(CacheKind::Audit,&k)").is_some());
    assert!(first_cache_read("state.cache.get_typed(CacheKind::Lists,&k)").is_some());
    assert!(
        first_cache_read("state.cache.get::<Vec<MailScopeEntry>>(CacheKind::Lists,&k)").is_some(),
        "nested generics in the turbofish must not defeat the matcher"
    );
    assert!(first_cache_read("self.cache.getter_helper()").is_none());
    assert!(first_cache_read("no_cache_here()").is_none());

    // And the flattener must survive the wrapping rustfmt applies.
    let (flat, map) = flatten_out_whitespace("state\n    .cache\n    .get(CacheKind::Audit)");
    assert!(first_cache_read(&flat).is_some(), "wrapped read must match");
    assert_eq!(flat.len(), map.len());
}
