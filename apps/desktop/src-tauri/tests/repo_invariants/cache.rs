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
            // Skip the definitions themselves — by the `fn` keyword, not by the
            // `invalidate_app` prefix, so a tiered invalidator defined in another
            // module (`invalidate_kv_sweep`, `invalidate_site_sweep`) is skipped
            // by name rather than by luck.
            if line.contains("fn invalidate_") {
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
    "invalidate_app_role_resources(",
    "invalidate_kv_sweep(",
];

/// An **in-place** write on one app never busts the list tier.
///
/// `invalidate_app_lists` drops the two tenant-wide indexes (`sp_index`,
/// `app_name_index`) that cost a full `/applications` + `/servicePrincipals`
/// re-enumeration — tens of seconds on a large tenant — and exists for writes
/// that add, remove or rename an app or SP. A credential add/remove, an
/// identifier/redirect-URI PATCH, an exposed-scope edit or a claims-policy
/// re-assignment changes one app in place and none of that; it takes the
/// credential tier (`invalidate_app_credentials`) or the detail tier
/// (`invalidate_app_details`). The tiering is documented in
/// `applications/cache.rs`, and four commands had drifted off it unnoticed —
/// the bulk expired-secret sweep and the three SSO URL/claims writers — because
/// nothing mechanical pinned which command may call which tier.
///
/// Lexical, like its siblings: a command body that contains one of the
/// in-place mutation calls and **no** set-changing call is an in-place writer,
/// and must not name `invalidate_app_lists(`. The set-changing fragments are
/// the reads-and-writes that can add or remove an object (`.create_`,
/// `.delete_`, `ensure_service_principal(`, `instantiate_application_template(`)
/// plus `_core(` — a body that delegates to a `*_core` helper is either a
/// create flow (`create_application_core`) or has its body checked by that
/// helper's own tests, so it is out of this rule's lexical reach on purpose. A
/// body that mixes an in-place write into a create flow is therefore excused
/// here, which is right: a create IS a set change.
#[test]
fn an_in_place_write_never_busts_the_list_tier() {
    const IN_PLACE_WRITES: &[&str] = &[
        ".add_password(",
        ".remove_password(",
        ".add_key_credential(",
        ".remove_key_credential(",
        ".patch_application_web(",
        ".patch_application_expose_api(",
        "apply_claims_policy(",
    ];
    const SET_CHANGING_WRITES: &[&str] = &[
        ".create_",
        ".delete_",
        "ensure_service_principal(",
        "instantiate_application_template(",
        "_core(",
    ];

    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for cmd in super::sources::commands() {
        let in_place = IN_PLACE_WRITES.iter().any(|w| cmd.body.contains(w));
        let set_changing = SET_CHANGING_WRITES.iter().any(|w| cmd.body.contains(w));
        if !in_place || set_changing {
            continue;
        }
        checked += 1;
        if cmd.body.contains("invalidate_app_lists(") {
            offenders.push(format!("{}::{}", cmd.module, cmd.name));
        }
    }
    offenders.sort();

    assert!(
        checked >= 8,
        "only {checked} in-place writer(s) found — the source walk or the fragment list is          broken, and a rule that scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "in-place write(s) that bust the LIST tier: {offenders:#?}\n\
         A write that changes one app in place adds, removes or renames no app or SP, so it must \
         not call `invalidate_app_lists` — that tier drops the two tenant-wide indexes, which cost \
         a full directory re-enumeration (tens of seconds on a large tenant) to rebuild. Use the \
         tier that matches the write: credential-only → `invalidate_app_credentials(cache, tenant, \
         object_id)`; in-place PATCH (URIs, exposed scopes/roles, claims) → \
         `invalidate_app_details(cache, tenant)`. See `applications/cache.rs`."
    );
}

/// Every writer of an app's exposed roles refreshes the Grant-access picker's
/// tenant-app directory.
///
/// `list_app_role_resources` caches which tenant SPs expose ≥1 enabled
/// Application role (plus a count) under its own `Lists` key. The App roles
/// tab's two writers change exactly that set — the first Application role added
/// moves an SP in, the last one disabled or removed moves it out — and for a
/// while called only `invalidate_app_details`, so a freshly published API was
/// missing from the picker (and a deleted role still counted) for up to the
/// Lists TTL. `write_roles(` is the one seam both go through.
#[test]
fn an_exposed_app_role_write_refreshes_the_role_resource_directory() {
    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for cmd in super::sources::commands() {
        if !cmd.body.contains("write_roles(") {
            continue;
        }
        checked += 1;
        if !cmd.body.contains("invalidate_app_role_resources(") {
            offenders.push(format!("{}::{}", cmd.module, cmd.name));
        }
    }
    assert!(
        checked >= 2,
        "only {checked} app-role writer(s) found (expected the upsert and the delete) — the          source walk or the `write_roles(` seam moved, and a rule that scans nothing passes          vacuously"
    );
    assert!(
        offenders.is_empty(),
        "exposed-app-role writer(s) that leave the role-resource directory stale: {offenders:#?}\n\
         Call `invalidate_app_role_resources(&state.cache, &tenant_id)` on the `Ok` path next to \
         `invalidate_app_details`, or the Grant-access picker's \"Tenant app registrations\" group \
         misses the new API (and keeps a removed one) until the Lists TTL."
    );
}

/// Every Azure role assignment made from this app busts the Key Vault sweep.
///
/// The sweep (`{tenant}|keyvault_sweep`, `CacheKind::Audit`) answers "who can
/// touch this vault?" and is reached by neither `invalidate_app_lists` nor
/// `invalidate_audit_cache`. It is read-only about vault roles, but
/// `assign_managed_identity_azure_role` changes the answer — and an assignment
/// at resource-group or subscription level reaches every vault beneath it, so
/// the bust is unconditional rather than gated on a vault-shaped scope.
#[test]
fn an_azure_role_assignment_busts_the_key_vault_sweep() {
    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for cmd in super::sources::commands() {
        if !cmd.body.contains(".create_role_assignment(") {
            continue;
        }
        checked += 1;
        if !cmd.body.contains("invalidate_kv_sweep(") {
            offenders.push(format!("{}::{}", cmd.module, cmd.name));
        }
    }
    assert!(
        checked >= 1,
        "no command creates an Azure role assignment — the source walk or the ARM call moved, and          a rule that scans nothing passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "Azure role assignment(s) that leave the Key Vault sweep cache stale: {offenders:#?}\n\
         Call `keyvault_rbac::invalidate_kv_sweep(&state.cache, &tenant_id)` on the `Ok` path — \
         the cached sweep otherwise serves the pre-assignment answer for the rest of the audit TTL."
    );
}

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

    let body = invalidate_app_lists_body();
    assert!(
        !body.contains("CacheKind::ServicePrincipal"),
        "invalidate_app_lists must NOT invalidate CacheKind::ServicePrincipal. That kind is keyed \
         by appId and is swept by the graph client itself (`invalidate_sp_cache`); an \
         aggregator-side bust here is keyed wrong, so it silently clears nothing while reading as \
         though it covered the case."
    );
}

/// The body of `invalidate_app_lists` in the applications cache facade — from
/// its header to the next `pub(crate) fn` (the next function's doc comment
/// rides along, which callers skip as comment lines).
fn invalidate_app_lists_body() -> &'static str {
    let cache_facade = include_str!("../../src/commands/applications/cache.rs");
    let lists = cache_facade
        .split_once("pub(crate) fn invalidate_app_lists")
        .expect("invalidate_app_lists moved")
        .1;
    lists
        .split_once("\npub(crate) fn ")
        .map(|(b, _)| b)
        .unwrap_or(lists)
}

/// Every function a code line calls whose name ends in `_key` or starts with
/// `invalidate_` — the keys and sub-tiers a list-tier bust drops. A path
/// prefix (`crate::commands::audit::`) is stripped; the method `.invalidate(`
/// itself does not match (no `invalidate_` prefix).
fn called_keys_and_tiers(body: &str) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for line in body.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let bytes = line.as_bytes();
        for (open, _) in line.match_indices('(') {
            let mut start = open;
            while start > 0 {
                let c = bytes[start - 1];
                if c.is_ascii_alphanumeric() || c == b'_' || c == b':' {
                    start -= 1;
                } else {
                    break;
                }
            }
            let path = &line[start..open];
            let name = path.rsplit("::").next().unwrap_or(path);
            if name.ends_with("_key") || name.starts_with("invalidate_") {
                names.insert(name.to_string());
            }
        }
    }
    names
}

/// `caching-and-search.md`'s list-tier paragraph must name every key and
/// sub-tier `invalidate_app_lists` drops.
///
/// That paragraph exists because reviewers mis-read an incomplete list as a
/// missing invalidation; the list then drifted three times (four keys, then
/// "seven", then "eight", against a body that dropped more each time). A count
/// word invites the drift, so it is banned outright; the names are checked
/// against the function body, so a key added there without a doc line fails
/// here. The runtime half is `detail_cache_tests::
/// invalidate_app_lists_drops_every_app_set_key_and_nothing_else`.
#[test]
fn the_list_tier_doc_names_every_key_invalidate_app_lists_drops() {
    let names = called_keys_and_tiers(invalidate_app_lists_body());
    assert!(
        names.len() >= 8,
        "expected invalidate_app_lists to call at least 8 key/tier functions, parsed {names:?} — \
         the body split or the call parser broke, so this rule would pass vacuously"
    );

    let doc = include_str!("../../../../../docs/architecture/caching-and-search.md");
    let marker = "`invalidate_app_lists` drops";
    let from = doc.find(marker).unwrap_or_else(|| {
        panic!(
            "caching-and-search.md lost the paragraph starting {marker:?} (the \
             \"Invalidation — only on `Ok`\" section) — restore it"
        )
    });
    let rest = &doc[from..];
    let paragraph = rest.split_once("\n\n").map(|(p, _)| p).unwrap_or(rest);

    for name in &names {
        assert!(
            paragraph.contains(&format!("`{name}`")),
            "invalidate_app_lists calls `{name}`, but the caching-and-search.md paragraph \
             starting {marker:?} (\"Invalidation — only on `Ok`\") does not name it in \
             backticks — add it there so the list can't drift into a false missing-invalidation \
             report again"
        );
    }
    for count in ["**seven**", "**eight**", "**nine**", "**ten**"] {
        assert!(
            !paragraph.contains(count),
            "the list-tier paragraph states a count ({count}); name the keys instead — every \
             past count went stale"
        );
    }
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
/// So: prove the session first (`prove_tenant_session`, or `tenant_context`
/// directly). Building a client is not a proof — see [`first_session_proof`].
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
    // detector was blind to fifteen others. It rose again when reads through the
    // index accessors ([`CACHED_ACCESSORS`]) started counting: search, the
    // directory-status probe and eight other tenant-wide scans read the cache
    // one call away from the command body, where a `cache.get` scan cannot see.
    const KNOWN_CACHE_READING_COMMANDS: usize = 25;
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

/// Helpers that read the cache on the caller's behalf. A command calling one
/// reads the cache exactly as if it had written the `cache.get` itself — the hit
/// path returns before any request is sent — so the call counts as the read.
///
/// Module-level so `every_index_accessor_counts_as_a_cache_read` can hold it to
/// the accessor definitions: a new `*_cached` / `*_hit` accessor that is missing
/// here would make every command reading through it invisible to this rule.
const CACHED_ACCESSORS: [&str; 10] = [
    "sp_index_cached(",
    "app_name_index_cached(",
    "apps_pairing_cached(",
    "credential_expirations_cached(",
    "indexes_cached(",
    "sp_index_hit(",
    "app_name_index_hit(",
    "search_corpus(",
    "load_gallery_corpus(",
    "resolve_mail_scopes_audit_cached(",
];

/// First cache read in flattened text: a direct `…cache.get(`,
/// `…cache.get_typed(` or `…cache.get::<T>(`, or a call to one of the
/// [`CACHED_ACCESSORS`] that reads the cache on the caller's behalf. The direct
/// form is a scan rather than a substring list because the turbofish carries an
/// arbitrary type between `::<` and `(` — including nested generics like
/// `Vec<MailScopeEntry>`, whose `>>` defeats a naive pattern.
fn first_cache_read(flat: &str) -> Option<usize> {
    let mut direct = None;
    let mut from = 0usize;
    while let Some(hit) = flat[from..].find("cache.get") {
        let at = from + hit;
        let rest = &flat[at + "cache.get".len()..];
        if rest.starts_with('(') || rest.starts_with("_typed") || rest.starts_with("::<") {
            direct = Some(at);
            break;
        }
        from = at + "cache.get".len();
    }
    let via_accessor = CACHED_ACCESSORS.iter().filter_map(|a| flat.find(a)).min();
    match (direct, via_accessor) {
        (Some(d), Some(a)) => Some(d.min(a)),
        (d, a) => d.or(a),
    }
}

/// The first session proof: `prove_tenant_session`, or the `tenant_context`
/// lookup it wraps, which is `None` unless that tenant signed in this session.
///
/// A client factory (`graph_for` / `exchange_for` / `arm_for` / `keyvault_for`)
/// is deliberately NOT a proof. It only builds `ScopedTokenAdapter`s; no token
/// is fetched until a request is sent, so a factory call ahead of a cache read
/// proves nothing. That is how a dead session (`known_tenants` purged on
/// `RefreshTokenMissing`, data caches kept) kept being served search results
/// from cache: `global_search` called `graph_for` first, and this rule counted
/// it. Neither is `ensure_*_token(` a proof: a caller may swallow its non-fatal
/// error, and text position cannot tell a real proof from a swallowed one.
fn first_session_proof(flat: &str) -> Option<usize> {
    const SESSION_PROOFS: [&str; 2] = [
        // The shared helper, and the raw lookup it wraps (Option-returning
        // commands use `tenant_context(&tenant_id)?` directly).
        "prove_tenant_session(",
        "tenant_context(",
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

    // A read one call away, through an index accessor, is still a read.
    assert!(first_cache_read("letc=search_corpus(&state,&client,&t).await;").is_some());
    assert!(first_cache_read("cache::sp_index_cached(&state,&client,&t)").is_some());
    assert!(first_cache_read("app_name_index_hit(&state.cache,&t)").is_some());
    assert!(
        first_cache_read("search_corpus_key(&t)").is_none(),
        "building a cache key is not a read"
    );
    assert!(
        first_session_proof("letclient=state.graph_for(&t);").is_none(),
        "a client factory is not a session proof"
    );

    // And the flattener must survive the wrapping rustfmt applies.
    let (flat, map) = flatten_out_whitespace("state\n    .cache\n    .get(CacheKind::Audit)");
    assert!(first_cache_read(&flat).is_some(), "wrapped read must match");
    assert_eq!(flat.len(), map.len());
}

/// Every tenant-wide index accessor is in [`CACHED_ACCESSORS`].
///
/// The session rule sees a read through an accessor only by name, so an
/// accessor missing from the list makes every command that reads through it
/// invisible — the vacuous pass this rule was hardened against. The accessors
/// live in one file, `commands/applications/cache.rs`, and are named for what
/// they are (`*_cached` reads through, `*_hit` reads only), so the ratchet reads
/// that file directly. It deliberately does not walk every command module: the
/// test helpers (`test_support::detail_cached`) share the suffix and are not
/// production readers.
#[test]
fn every_index_accessor_counts_as_a_cache_read() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands/applications/cache.rs");
    let src = std::fs::read_to_string(&path).expect("read the index accessors");
    let mut accessors: Vec<String> = Vec::new();
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let Some(at) = trimmed.find("fn ") else {
            continue;
        };
        let rest = &trimmed[at + "fn ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if name.ends_with("_cached") || name.ends_with("_hit") {
            accessors.push(name);
        }
    }
    assert!(
        accessors.len() >= 5,
        "found only {accessors:?} in {} — the scan is broken",
        path.display()
    );
    let missing: Vec<&String> = accessors
        .iter()
        .filter(|name| !CACHED_ACCESSORS.contains(&format!("{name}(").as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "these index accessors read the cache but are not in CACHED_ACCESSORS, so a command \
         reading through them escapes the session rule: {missing:?}"
    );
}

/// A full `/applications` list scan has exactly one caching home:
/// `applications::scan_app_list`, behind `app_scan_gate`.
///
/// Launch used to page the whole collection three times concurrently — the App
/// Registrations list, the credential-expiry roll-up and the app-name index each
/// ran their own scan, although one `$select` superset covers all three and the
/// same mutation tiers bust them. The two other callers are deliberate: the
/// audit run needs `$expand=owners`, and the expired-credential bulk sweep is a
/// write path that caches nothing. Counted per module on non-comment lines; the
/// total is asserted exactly so the rule cannot pass vacuously.
#[test]
fn the_full_application_list_scan_has_one_home() {
    const EXPECTED: [(&str, usize); 3] = [
        ("commands/applications/mod.rs", 1),
        ("commands/audit.rs", 1),
        ("commands/bulk.rs", 1),
    ];
    let mut offenders: Vec<String> = Vec::new();
    let mut total = 0usize;
    for (name, src) in super::sources::command_modules() {
        let found = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//") && l.contains("list_applications_all("))
            .count();
        total += found;
        let expected = EXPECTED
            .iter()
            .find(|(m, _)| *m == name)
            .map_or(0, |(_, n)| *n);
        if found != expected {
            offenders.push(format!("{name}: {found} scan(s), expected {expected}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "full `/applications` list scan(s) outside their homes: {offenders:#?}\n\
         Read the app list through `apps_pairing_cached` / `credential_expirations_cached` / \
         `app_name_index_cached`, which share one gated scan (`scan_app_list`). A new bare scan \
         is the third-concurrent-scan bug this rule exists for. The audit's `$expand=owners` run \
         and the bulk expired-credential sweep are the deliberate exceptions."
    );
    assert_eq!(
        total,
        EXPECTED.iter().map(|(_, n)| n).sum::<usize>(),
        "the scan counter found {total} call site(s) — the source walk or the matcher is broken"
    );
}

/// The audit run is written to the cache **only** inside
/// `if run_is_cacheable(…) { … }`.
///
/// AGENTS.md: "a cancelled/truncated/degraded run is never cached nor shown as
/// an all-clear". `run_is_cacheable` is exhaustively unit-tested in
/// `commands/audit.rs`, but that pins the predicate, not its use — a refactor
/// that moved the write out of the `if`, or added a second one for a "partial
/// snapshot", compiled and passed every test.
///
/// Keyed on the audit-run KEY rather than on `CacheKind::Audit`: that kind is
/// shared with the site and Key Vault sweeps, which carry their own guards. The
/// key is passed by value only on a write (reads and invalidations borrow it as
/// `&audit_cache_key(…)`), so the match below sees exactly the writes.
#[test]
fn the_audit_run_is_cached_only_behind_run_is_cacheable() {
    const WRITES: [&str; 3] = [".put(", ".put_typed(", ".put_index("];
    const KEY_ARG: &str = "CacheKind::Audit,audit_cache_key(";
    let mut sites = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    for (name, src) in super::sources::command_modules() {
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let (flat, _) = flatten_out_whitespace(&code);
        let mut from = 0usize;
        while let Some(hit) = flat[from..].find(KEY_ARG) {
            let at = from + hit;
            from = at + KEY_ARG.len();
            if !WRITES.iter().any(|w| flat[..at].ends_with(w)) {
                continue;
            }
            sites += 1;
            if !guarded_by_run_is_cacheable(&flat, at) {
                let start = at.saturating_sub(80);
                let start = (start..at)
                    .find(|&i| flat.is_char_boundary(i))
                    .unwrap_or(at);
                offenders.push(format!("{name}: …{}", &flat[start..from]));
            }
        }
    }
    assert!(
        sites >= 1,
        "no audit-run cache write (`.put(CacheKind::Audit, audit_cache_key(…)`) found in any \
         command module — the walk or the matcher is broken, and this rule is checking nothing"
    );
    assert!(
        offenders.is_empty(),
        "an audit-run cache write is not directly inside `if run_is_cacheable(…) {{ … }}`:\n  {}\n\
         AGENTS.md: \"a cancelled/truncated/degraded run is never cached\" — `run_is_cacheable` \
         is the one predicate that says so; write the run only inside its `if`.",
        offenders.join("\n  ")
    );
}

/// Whether the flattened code at `at` sits DIRECTLY in the block of an
/// `if run_is_cacheable(…)`: walk back to the nearest unmatched `{`, and the
/// statement text before it must be that `if`. Rejects a negated condition, an
/// `else` block, a write after the block, and a write nested in another `if`.
fn guarded_by_run_is_cacheable(flat: &str, at: usize) -> bool {
    let bytes = flat.as_bytes();
    let mut depth = 0usize;
    let mut open = None;
    for i in (0..at).rev() {
        match bytes[i] {
            b'}' => depth += 1,
            b'{' if depth == 0 => {
                open = Some(i);
                break;
            }
            b'{' => depth -= 1,
            _ => {}
        }
    }
    let Some(open) = open else {
        return false;
    };
    let head_start = flat[..open].rfind([';', '{', '}']).map_or(0, |i| i + 1);
    flat[head_start..open].starts_with("ifrun_is_cacheable(")
}

#[test]
fn the_run_is_cacheable_guard_detector_rejects_every_escape() {
    // The regression guard for the guard: each rejected shape is a refactor that
    // compiles and would otherwise pass.
    fn check(src: &str) -> bool {
        let (flat, _) = flatten_out_whitespace(src);
        let at = flat
            .find("CacheKind::Audit,audit_cache_key(")
            .expect("fixture carries a write");
        guarded_by_run_is_cacheable(&flat, at)
    }
    assert!(check(
        "let run = x;\nif run_is_cacheable(c, t, &d) {\n    state\n        .cache\n        \
         .put(CacheKind::Audit, audit_cache_key(&t), &run);\n}"
    ));
    for escape in [
        "fn f() { let run = x; state.cache.put(CacheKind::Audit, audit_cache_key(&t), &run); }",
        "fn f() { if !run_is_cacheable(c, t, &d) { state.cache.put(CacheKind::Audit, \
         audit_cache_key(&t), &run); } }",
        "fn f() { if run_is_cacheable(c, t, &d) {} else { state.cache.put(CacheKind::Audit, \
         audit_cache_key(&t), &run); } }",
        "fn f() { if run_is_cacheable(c, t, &d) { if other { state.cache.put(CacheKind::Audit, \
         audit_cache_key(&t), &run); } } }",
        "fn f() { if run_is_cacheable(c, t, &d) { log(); } state.cache.put(CacheKind::Audit, \
         audit_cache_key(&t), &run); }",
    ] {
        assert!(
            !check(escape),
            "detector accepted an unguarded write: {escape}"
        );
    }
}
