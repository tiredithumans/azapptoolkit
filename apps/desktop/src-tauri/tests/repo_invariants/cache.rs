//! Tenant-scoped cache lifecycle: invalidate only on `Ok`, pin only the
//! tenant-wide indexes, take the generation watch **before** the fetch it
//! guards, and forget every per-tenant map on sign-out.
//!
//! AGENTS.md calls cross-tenant leakage "the #1 footgun"; these are the rules
//! that keep it mechanical rather than remembered.

use super::sources::{code_lines, code_mask, is_fn_header};

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
        // Whole identifiers, so a future `foo_mi_key(` is not read as `mi_key(`.
        .any(|l| {
            key_calls_in(l)
                .iter()
                .any(|k| PINNABLE_KEYS.contains(&k.as_str()))
        })
}

/// Where a watch used at `line_no` came from.
#[derive(Debug, PartialEq)]
enum WatchSource {
    /// The key builders named at its `generation_for` capture — inline
    /// (`&sp_index_key(t)`) or through the `let key = …_key(…)` it reads.
    Keys(Vec<String>),
    /// A parameter of the enclosing fn, at this argument `index`: a store
    /// helper, so the key is whatever its callers captured the watch on.
    Param {
        helper: String,
        index: usize,
    },
    Unresolved,
}

/// Resolves the watch named `watch`, used at `line_no`, within its function.
///
/// In order: a parameter of the function (a store helper, `Param`); else the
/// `let [mut] watch = …` binding, which is either the `generation_for(kind,
/// key)` capture — whose key is then read inline (`&sp_index_key(t)`) or off
/// the `let key = …_key(…)` it names — or an alias (`let w = other;`)
/// resolved through `other`. Only when no identifier could be read at the use
/// site does the nearest preceding capture stand in. Anything else (an unbound
/// watch, a key that is a parameter or a field) is `Unresolved` and reported:
/// a bare back-walk would let a pinnable key mentioned anywhere earlier in the
/// function excuse a per-object capture.
fn resolve_watch(lines: &[&str], line_no: usize, watch: &str) -> WatchSource {
    resolve_watch_from(lines, line_no, watch, 0)
}

fn resolve_watch_from(lines: &[&str], line_no: usize, watch: &str, hops: usize) -> WatchSource {
    let header = (0..=line_no)
        .rev()
        .find(|&i| is_fn_header(lines[i].trim_start()));
    // The function's code lines before `line_no`, nearest first.
    let code: Vec<(usize, &str)> = (header.map_or(0, |h| h + 1)..line_no)
        .rev()
        .map(|i| (i, lines[i].trim_start()))
        .filter(|(_, l)| !l.starts_with("//"))
        .collect();
    // The statement starting at line `i`, up to its `;`.
    let statement = |i: usize| -> String {
        let mut text = String::new();
        for l in &lines[i..=line_no] {
            text.push_str(l.trim());
            if l.contains(';') {
                break;
            }
        }
        text
    };
    // `let var …` / `let mut var …`, a whole identifier.
    let bound = |l: &str, var: &str| {
        let rest = l
            .strip_prefix("let ")
            .map(|r| r.strip_prefix("mut ").unwrap_or(r));
        !var.is_empty()
            && rest.is_some_and(|r| {
                r.strip_prefix(var)
                    .is_some_and(|after| after.starts_with([' ', ':', '=']))
            })
    };

    // 1. A parameter: checked first, so a helper that also captures some other
    //    watch is still recognised as a helper.
    if let Some(h) = header
        && !watch.is_empty()
    {
        let signature: String = lines[h..=line_no]
            .iter()
            .map(|l| l.trim())
            .collect::<Vec<_>>()
            .join(" ");
        let helper: String = ident_after(&signature, "fn ");
        if let Some((_, params)) = signature.split_once(&format!("fn {helper}(")) {
            let params = top_level_args(params);
            if let Some(index) = params.iter().position(|p| {
                let p = p.strip_prefix("mut ").unwrap_or(p);
                p.strip_prefix(watch)
                    .is_some_and(|t| t.trim_start().starts_with(':'))
            }) {
                return if params[index].contains("IndexWatch") {
                    WatchSource::Param { helper, index }
                } else {
                    WatchSource::Unresolved
                };
            }
        }
    }

    // 2. The binding, or — only when no identifier was read — the nearest capture.
    let capture_line = if watch.is_empty() {
        code.iter()
            .find(|(_, l)| l.contains("generation_for("))
            .map(|&(i, _)| i)
    } else {
        let Some(&(b, _)) = code.iter().find(|(_, l)| bound(l, watch)) else {
            return WatchSource::Unresolved;
        };
        let stmt = statement(b);
        if !stmt.contains("generation_for(") {
            // An alias, `let w = other;`: resolve through `other`.
            let rhs = stmt.split_once('=').map_or("", |(_, r)| r.trim());
            let other = ident_after(rhs, "");
            let is_alias = !other.is_empty()
                && rhs
                    .trim_start_matches(['&', ' '])
                    .strip_prefix(other.as_str())
                    == Some(";");
            return if is_alias && hops < 4 {
                resolve_watch_from(lines, b, &other, hops + 1)
            } else {
                WatchSource::Unresolved
            };
        }
        Some(b)
    };
    let Some(capture_line) = capture_line else {
        return WatchSource::Unresolved;
    };
    let capture_stmt = statement(capture_line);
    let Some((_, key_arg)) = capture_stmt.split_once("generation_for(") else {
        return WatchSource::Unresolved;
    };
    let named = key_calls_in(key_arg);
    if !named.is_empty() {
        return WatchSource::Keys(named);
    }
    // 3. `generation_for(kind, &key)`: the key is a binding further up. A key
    //    that is a parameter or a field is not resolved: reported, not guessed.
    let args = top_level_args(key_arg);
    let var = ident_after(args.last().map_or("", String::as_str), "");
    match code
        .iter()
        .filter(|(i, _)| *i < capture_line)
        .find(|(_, l)| bound(l, &var))
    {
        Some(&(b, _)) => WatchSource::Keys(key_calls_in(&statement(b))),
        None => WatchSource::Unresolved,
    }
}

/// The identifier after the first `open` in `text`, past any `&`/spaces.
fn ident_after(text: &str, open: &str) -> String {
    text.split_once(open)
        .map(|(_, rest)| rest.trim_start_matches(['&', ' ']))
        .unwrap_or_default()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// The comma-separated arguments of a call or signature, given the text just
/// after its `(`, up to the matching `)`. Trimmed; nested brackets respected.
fn top_level_args(text: &str) -> Vec<String> {
    let (mut depth, mut args, mut cur) = (0i32, Vec::new(), String::new());
    for c in text.chars() {
        match c {
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' if depth == 0 => break,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                args.push(std::mem::take(&mut cur).trim().to_string());
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        args.push(cur.trim().to_string());
    }
    args
}

/// The watch argument of the guarded pinned store at `line_no`, which rustfmt
/// may wrap onto the next line.
fn watch_at_store(lines: &[&str], line_no: usize) -> String {
    let store: String = lines[line_no..lines.len().min(line_no + 3)]
        .iter()
        .map(|l| l.trim())
        .collect();
    ident_after(&store, "_index_if_current(")
}

/// Whether the GUARDED pinned store at `line_no` (`put_index_if_current(watch,
/// …)` / `put_typed_index_if_current(watch, …)`) pins a watch captured, in the
/// same function, on [`PINNABLE_KEYS`] keys only.
fn guarded_pin_watches_a_pinnable_key(lines: &[&str], line_no: usize) -> bool {
    matches!(
        resolve_watch(lines, line_no, &watch_at_store(lines, line_no)),
        WatchSource::Keys(k) if all_pinnable(&k)
    )
}

fn all_pinnable(keys: &[String]) -> bool {
    !keys.is_empty() && keys.iter().all(|k| PINNABLE_KEYS.contains(&k.as_str()))
}

/// The offenders among store helpers' callers. `helpers` holds each helper
/// store as `(module:line, helper fn, watch argument index)`.
fn store_helper_offenders(
    modules: &[(String, String)],
    helpers: &[(String, String, usize)],
) -> Vec<String> {
    let mut offenders = Vec::new();
    for (store, helper, index) in helpers {
        let calls = helper_call_sites(modules, helper, *index);
        if calls.is_empty() {
            offenders.push(format!(
                "{store} — `{helper}` pins a parameter watch but has no caller to resolve it"
            ));
        }
        let mut keys: Vec<&String> = Vec::new();
        for (site, source) in &calls {
            match source {
                WatchSource::Keys(k) if all_pinnable(k) => keys.extend(k),
                other => offenders.push(format!(
                    "{site} — `{helper}` called with a watch on {other:?}"
                )),
            }
        }
        keys.sort();
        keys.dedup();
        if keys.len() > 1 {
            offenders.push(format!(
                "{store} — `{helper}` is called with watches on different keys: {keys:?}"
            ));
        }
    }
    offenders
}

/// The call sites of the store helper `helper` (a fn pinning a watch it takes
/// as argument `index`), each as `(module:line, what its watch resolves to)`.
fn helper_call_sites(
    modules: &[(String, String)],
    helper: &str,
    index: usize,
) -> Vec<(String, WatchSource)> {
    let call = format!("{helper}(");
    let mut out = Vec::new();
    for (name, src) in modules {
        let lines: Vec<&str> = src.lines().collect();
        for (line_no, line) in lines.iter().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || is_fn_header(trimmed) {
                continue;
            }
            let Some(at) = line.match_indices(&call).map(|(at, _)| at).find(|&at| {
                !line[..at]
                    .chars()
                    .next_back()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
            }) else {
                continue;
            };
            let text: String = std::iter::once(&line[at + call.len()..])
                .chain(
                    lines[line_no + 1..lines.len().min(line_no + 6)]
                        .iter()
                        .copied(),
                )
                .map(str::trim)
                .collect::<Vec<_>>()
                .join(" ");
            let watch = top_level_args(&text)
                .get(index)
                .map(|a| ident_after(a, ""))
                .unwrap_or_default();
            out.push((
                format!("{name}:{}", line_no + 1),
                resolve_watch(&lines, line_no, &watch),
            ));
        }
    }
    out
}

/// The `…_key(` builder calls in `text` (whole identifiers, `(` included).
fn key_calls_in(text: &str) -> Vec<String> {
    text.match_indices("_key(")
        .map(|(at, _)| {
            let start = text[..at]
                .rfind(|c: char| !(c.is_alphanumeric() || c == '_'))
                .map_or(0, |i| i + 1);
            format!("{}(", &text[start..at + "_key".len()])
        })
        .collect()
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
    let mut helpers: Vec<(String, String, usize)> = Vec::new();
    let modules = super::sources::command_modules();

    for (name, src) in &modules {
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
            // `generation_for(kind, key)` — the key never appears at the store,
            // so it is read off the capture instead. This used to `continue`
            // on the theory that the watch-capture rule covered these lines,
            // but that rule only checks an `.await` sits between capture and
            // store: `generation_for(Lists, &app_detail_key(..))` followed by
            // `put_index_if_current(watch, ..)` pinned a per-object key and
            // passed both.
            if line.contains("_index_if_current(") {
                match resolve_watch(&lines, line_no, &watch_at_store(&lines, line_no)) {
                    WatchSource::Keys(keys) if all_pinnable(&keys) => {}
                    // A store helper: the key is fixed by the watch each
                    // caller hands it, so the callers are checked below.
                    WatchSource::Param { helper, index } => {
                        helpers.push((format!("{name}:{}", line_no + 1), helper, index));
                    }
                    _ => offenders.push(format!("{name}:{} — {trimmed}", line_no + 1)),
                }
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

    // A store helper pins whatever key its watch was captured on, and that
    // capture lives in the caller — where the line scan above never looks,
    // because the call names neither a pinned write nor a key. So each helper
    // is checked through its callers: every one must pass a watch captured on
    // a pinnable key, and all on the SAME key, since the helper stores one
    // typed value (an SP-index watch handed to the app-name helper would pin
    // the wrong type under the wrong key). Derived from the store, not a list
    // of helper names.
    offenders.extend(store_helper_offenders(&modules, &helpers));
    assert!(
        found >= 5,
        "found only {found} pinned cache write(s) across the command tree — the source walk or \
         the call detector is broken, and a rule that scans nothing passes vacuously"
    );
    assert!(
        helpers.len() >= 2,
        "found {} pinned store helper(s), expected the SP-index and app-name-index ones — the \
         helper resolution is broken: {helpers:?}",
        helpers.len()
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
    // The list caches and the credential roll-up: each one entry per tenant,
    // built from a whole-tenant scan.
    "apps_pairing_key(",
    "enterprise_key(",
    "mi_key(",
    "credential_expirations_key(",
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

/// A long scan's result is stored through the guard too — unpinned.
///
/// The pinned rules above cover the tenant-wide indexes; these keys hold what
/// a scan of minutes produces (the audit run, the site and Key Vault sweeps,
/// the SSO certificate board, the per-app mailbox-scope verdicts). Each was
/// stored with a plain `put`/`put_typed` after the last await, so a mutation's
/// invalidation that landed mid-scan — a remediation, a grant, a scope change,
/// sign-out's tenant sweep — was undone by the pre-mutation result, which then
/// served (say) a stale "all clear" or org-wide verdict for the TTL.
///
/// Rule: a function that builds one of these keys writes no cache entry except
/// through the unpinned `put_if_current` / `put_typed_if_current` — no plain
/// write, and no pinned one (a per-object key is never pinned). The key set is
/// [`GUARDED_SCAN_KEYS`] plus every key builder a command already watches for
/// an unpinned guarded store, so a new guarded scan joins on its own; the
/// listed keys must each still have such a store, so the list cannot rot.
#[test]
fn long_scan_results_store_through_the_guard() {
    use std::collections::BTreeSet;

    let modules = super::sources::command_modules();
    let fns: Vec<_> = modules
        .iter()
        .flat_map(|(name, src)| {
            super::sources::functions_in(src)
                .into_iter()
                .map(move |f| (name.as_str(), f))
        })
        .collect();
    let builders: BTreeSet<&str> = fns
        .iter()
        .map(|(_, f)| f.name.as_str())
        .filter(|n| n.ends_with("_key"))
        .collect();

    // Derived: the key builders behind the watches of unpinned guarded stores.
    let mut watched: BTreeSet<String> = BTreeSet::new();
    for (_, f) in &fns {
        if !UNPINNED_GUARDED_WRITES.iter().any(|w| f.body.contains(w)) {
            continue;
        }
        for (at, _) in f.body.match_indices("generation_for(") {
            let arg = &f.body[at..];
            let arg = &arg[..arg.find(';').unwrap_or(arg.len())];
            let named = key_builders_in(arg, &builders);
            if !named.is_empty() {
                watched.extend(named);
                continue;
            }
            // `generation_for(kind, &key)`: resolve `let key = …_key(…)`.
            let var: String = arg
                .rsplit('&')
                .next()
                .unwrap_or_default()
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if let Some(bind) = f.body[..at].rfind(&format!("let {var} ="))
                && let Some(first) = key_builders_in(&f.body[bind..at], &builders).first()
            {
                watched.insert(first.clone());
            }
        }
    }
    for key in GUARDED_SCAN_KEYS {
        assert!(
            watched.contains(*key),
            "`{key}` is a long-scan key, but no command stores it through an unpinned \
             `put_if_current` / `put_typed_if_current` behind a `generation_for` watch \
             (derived: {watched:?})"
        );
    }

    assert!(
        mounted_test_only("commands/test_support.rs")
            && mounted_test_only("commands/sso/handler_tests.rs")
            && !mounted_test_only("commands/sharepoint.rs"),
        "the test-only module detector no longer recognises the fixtures (or flags production)"
    );

    // Ordering, stricter than the general watch rule: the watch is captured
    // before the FIRST await of the function, not merely before some await
    // ahead of the store. A scan's result depends on everything it awaited, so
    // a capture after a leading await leaves that read outside the window.
    let mut late: Vec<String> = Vec::new();
    for (module, f) in &fns {
        if !UNPINNED_GUARDED_WRITES.iter().any(|w| f.body.contains(w)) {
            continue;
        }
        let capture = f.body.find("generation_for(");
        let first_await = f.body.find(".await");
        match (capture, first_await) {
            (Some(c), Some(a)) if c < a => {}
            (Some(_), None) => {}
            _ => late.push(format!("{module}::{}", f.name)),
        }
    }
    assert!(
        late.is_empty(),
        "an unpinned guarded store whose watch is not captured before the function's first \
         `.await`: {late:#?}\nMove `let watch = ….generation_for(kind, &key);` above the first \
         await (right after `claim()` / the cache miss)."
    );

    let mut offenders: Vec<String> = Vec::new();
    for (module, f) in &fns {
        // Fixtures seed these keys directly; they are production code to the
        // walk only because their test cfg sits on the parent's `mod` line.
        if mounted_test_only(module) {
            continue;
        }
        let keys: Vec<&String> = watched
            .iter()
            .filter(|k| f.body.contains(&format!("{k}(")))
            .collect();
        if keys.is_empty() {
            continue;
        }
        for write in PLAIN_OR_PINNED_WRITES {
            if f.body.contains(write) {
                offenders.push(format!("{module}::{} — `{write}` beside {keys:?}", f.name));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a long scan's result is cached without the generation guard: {offenders:#?}\n\
         Capture `cache.generation_for(kind, &key)` BEFORE the scan's first await (right after \
         its `claim()`) and store through `put_if_current` / `put_typed_if_current`, so a \
         mutation's invalidation during the scan is not undone by the pre-mutation result."
    );
}

/// The key builders that name a long scan's (unpinned) result. Adding one
/// claims its writes must ride the guard; see
/// `long_scan_results_store_through_the_guard`.
const GUARDED_SCAN_KEYS: &[&str] = &[
    "audit_cache_key",
    "sweep_cache_key",
    "kv_sweep_cache_key",
    "mail_scopes_key",
    "sso_certificate_expirations_key",
    "app_role_resources_key",
    "app_detail_key",
];

/// The unpinned guarded store forms.
const UNPINNED_GUARDED_WRITES: &[&str] = &["put_if_current(", "put_typed_if_current("];

/// Every other write form: unguarded, or pinned (a guarded scan key is never an
/// index).
const PLAIN_OR_PINNED_WRITES: &[&str] = &[
    ".put(",
    ".put_typed(",
    ".put_index(",
    ".put_typed_index(",
    "put_index_if_current(",
    "put_typed_index_if_current(",
];

/// Whether the command module `name` (`commands/…/x.rs`) is mounted by a
/// `#[cfg(test)] mod x;` in its parent. `strip_tests` cannot see that — the
/// cfg is in another file — so `test_support.rs` and the `tests.rs` /
/// `handler_tests.rs` siblings reach the walk whole.
fn mounted_test_only(name: &str) -> bool {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let file = std::path::Path::new(name);
    let (Some(dir), Some(stem)) = (file.parent(), file.file_stem().and_then(|s| s.to_str())) else {
        return false;
    };
    if stem == "mod" {
        return false;
    }
    let decl = [format!("mod {stem};"), format!("pub(crate) mod {stem};")];
    [
        src.join(dir).join("mod.rs"),
        src.join(dir.with_extension("rs")),
    ]
    .iter()
    .filter_map(|p| std::fs::read_to_string(p).ok())
    .any(|parent| {
        let lines: Vec<&str> = parent.lines().map(str::trim).collect();
        lines
            .windows(2)
            .any(|w| w[0] == "#[cfg(test)]" && decl.iter().any(|d| w[1] == d))
    })
}

/// The known key builders called in `text`, in order of appearance.
fn key_builders_in(text: &str, builders: &std::collections::BTreeSet<&str>) -> Vec<String> {
    let mut found: Vec<(usize, String)> = builders
        .iter()
        .flat_map(|b| {
            let call = format!("{b}(");
            text.match_indices(&call)
                // A whole identifier: `sweep_cache_key(` inside
                // `kv_sweep_cache_key(` is not a call of it.
                .filter(|(at, _)| {
                    !text[..*at]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_')
                })
                .map(|(at, _)| (at, (*b).to_string()))
                .collect::<Vec<_>>()
        })
        .collect();
    found.sort();
    found.into_iter().map(|(_, b)| b).collect()
}

/// Sign-out stops every in-flight **read** sweep, through the one sweep.
///
/// A sweep running when the operator signs out belongs to the forgotten
/// session: its guarded store will refuse (the tenant sweep bumps its watch),
/// but left running it keeps issuing requests for minutes. Derived from the
/// `CancelFlag` fields on `AppState`, so a new run kind fails here until it is
/// either cancelled in `forget_tenant` or listed as a write run.
#[test]
fn sign_out_stops_every_read_sweep() {
    // Write runs, deliberately NOT cancelled on sign-out: stopping a
    // multi-step write between steps is the operator's call, and with the
    // tokens purged each stops on its own at the dead-session latch.
    // `scope_move_cancel` is the "Move to managed group" member copy — writes
    // into a group, and a stopped copy already keeps the scope where it was.
    const WRITE_RUNS: [&str; 4] = [
        "bulk_cancel",
        "migration_cancel",
        "scope_move_cancel",
        "restore_cancel",
    ];

    let state = include_str!("../../src/state.rs").replace("\r\n", "\n");
    let (_, after) = state
        .split_once("pub struct AppState {")
        .expect("AppState struct in state.rs");
    let (body, _) = after.split_once("\n}\n").expect("end of AppState struct");
    let flags: Vec<&str> = code_lines(body)
        .filter(|l| l.contains(": CancelFlag,"))
        .filter_map(|l| l.split_once(':'))
        .filter_map(|(before, _)| before.split_whitespace().last())
        .collect();
    assert!(
        flags.len() >= 8,
        "expected the eight run-kind cancel flags on AppState, found {flags:?} — the field scan \
         has gone vacuous"
    );
    for write in WRITE_RUNS {
        assert!(
            flags.contains(&write),
            "WRITE_RUNS names `{write}`, which is not a CancelFlag on AppState: {flags:?}"
        );
    }

    let (_, after) = state
        .split_once("pub fn forget_tenant(")
        .expect("AppState::forget_tenant in state.rs");
    let (forget, _) = after.split_once("\n    }\n").expect("end of forget_tenant");
    let forget = code_lines(forget).collect::<Vec<_>>().join("\n");
    for flag in flags.iter().filter(|f| !WRITE_RUNS.contains(f)) {
        assert!(
            forget.contains(&format!("self.{flag}.cancel()")),
            "`AppState::{flag}` is a read sweep sign-out does not stop — call \
             `self.{flag}.cancel()` in `AppState::forget_tenant` (or, for a write run, add it to \
             WRITE_RUNS with the reason)"
        );
    }
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

/// The guarded pinned forms name no key at the store, so the rule reads it off
/// the watch's capture. These used to be skipped outright, which let a pinned
/// per-object key through as long as an `.await` sat between capture and store.
#[test]
fn a_guarded_pinned_store_is_checked_against_its_watchs_key() {
    let inline = vec![
        "pub async fn offender() {",
        "    let watch = cache.generation_for(CacheKind::Lists, &app_detail_key(t, id));",
        "    let v = fetch().await?;",
        "    cache.put_index_if_current(watch, &v);",
    ];
    assert!(
        !guarded_pin_watches_a_pinnable_key(&inline, 3),
        "a guarded pinned store whose watch is on a PER-OBJECT key must be reported"
    );

    // A pinnable key elsewhere in the function must not excuse it: a bare
    // back-walk from the capture would find `sp_index_key` and pass.
    let bound = vec![
        "async fn offender() {",
        "    let index = sp_index_key(t);",
        "    let key = app_detail_key(t, id);",
        "    let watch = state",
        "        .cache",
        "        .generation_for(CacheKind::Lists, &key);",
        "    let v = fetch().await?;",
        "    state",
        "        .cache",
        "        .put_typed_index_if_current(watch, Arc::clone(&v));",
    ];
    assert!(
        !guarded_pin_watches_a_pinnable_key(&bound, 9),
        "a per-object key bound to a variable must be resolved, not excused by a nearby index key"
    );

    // The production shapes: a bound key, and several watches in one function,
    // each store resolved to its OWN capture.
    let genuine = vec![
        "pub async fn list() {",
        "    let key = mi_key(&tenant_id);",
        "    let watch = state.cache.generation_for(CacheKind::Lists, &key);",
        "    let rows = scan().await?;",
        "    state.cache.put_index_if_current(watch, &rows);",
    ];
    assert!(
        guarded_pin_watches_a_pinnable_key(&genuine, 4),
        "a guarded store on a tenant-wide index key must pass"
    );
    let several = vec![
        "async fn scan() {",
        "    let rows_watch = state",
        "        .cache",
        "        .generation_for(CacheKind::Lists, &apps_pairing_key(tenant_id));",
        "    let detail_watch = state",
        "        .cache",
        "        .generation_for(CacheKind::Lists, &app_detail_key(tenant_id, id));",
        "    let rows = fetch().await?;",
        "    state.cache.put_index_if_current(rows_watch, &rows);",
        "    state.cache.put_index_if_current(detail_watch, &rows);",
    ];
    assert!(
        guarded_pin_watches_a_pinnable_key(&several, 8),
        "the store must resolve its own watch, not the nearest capture"
    );
    assert!(
        !guarded_pin_watches_a_pinnable_key(&several, 9),
        "the per-object watch's store must be reported even beside a pinnable capture"
    );
}

/// A store helper takes its watch as a parameter, so its key is decided by its
/// callers — which the line scan never sees, as the call names neither a pinned
/// write nor a key.
#[test]
fn a_pinned_store_helper_is_checked_through_its_callers() {
    let helper = "\
pub(crate) fn sp_index_store_if_current(
    cache: &Cache,
    sps: Vec<ServicePrincipal>,
    watch: IndexWatch<'_>,
) -> Arc<Vec<ServicePrincipal>> {
    let shared = Arc::new(sps);
    cache.put_typed_index_if_current(watch, Arc::clone(&shared));
    shared
}
";
    let lines: Vec<&str> = helper.lines().collect();
    assert_eq!(
        resolve_watch(&lines, 6, &watch_at_store(&lines, 6)),
        WatchSource::Param {
            helper: "sp_index_store_if_current".into(),
            index: 2
        },
        "a watch taken as a parameter must resolve to the helper and its argument position"
    );
    let helpers = [(
        "commands/a.rs:7".to_string(),
        "sp_index_store_if_current".to_string(),
        2,
    )];
    let caller = |key: &str| {
        format!(
            "pub async fn reader() {{\n    let watch = state\n        .cache\n        \
             .generation_for(CacheKind::Lists, &{key});\n    let sps = scan().await?;\n    \
             Ok(sp_index_store_if_current(&state.cache, sps, watch))\n}}\n"
        )
    };
    let module = |name: &str, src: String| (name.to_string(), src);

    let good = [
        module("commands/a.rs", helper.to_string()),
        module("commands/b.rs", caller("sp_index_key(t)")),
    ];
    assert_eq!(
        store_helper_offenders(&good, &helpers),
        Vec::<String>::new()
    );

    let per_object = [
        module("commands/a.rs", helper.to_string()),
        module("commands/b.rs", caller("app_detail_key(t, id)")),
    ];
    assert_eq!(
        store_helper_offenders(&per_object, &helpers).len(),
        1,
        "a caller handing the helper a per-object watch must be reported"
    );

    let mixed = [
        module("commands/a.rs", helper.to_string()),
        module("commands/b.rs", caller("sp_index_key(t)")),
        module("commands/c.rs", caller("app_name_index_key(t)")),
    ];
    assert_eq!(
        store_helper_offenders(&mixed, &helpers).len(),
        1,
        "callers handing one helper watches on different keys must be reported"
    );

    let uncalled = [module("commands/a.rs", helper.to_string())];
    assert_eq!(
        store_helper_offenders(&uncalled, &helpers).len(),
        1,
        "a helper with no caller cannot be resolved and must be reported"
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
        let Some((line, proven_before)) = first_cache_read_and_proof(&cmd.body) else {
            continue;
        };
        checked.push(format!("{}::{}", cmd.module, cmd.name));
        if !proven_before {
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
    const KNOWN_CACHE_READING_COMMANDS: usize = 27;
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

/// The body line of the first cache read in `body`, and whether a session
/// proof dominates it — `None` when the body reads no cache.
///
/// Comments and string literals are blanked first ([`code_mask`], newlines
/// kept so the line number still points at the body): a `// …
/// tenant_context(…)` in the prose explaining the proof used to count as the
/// proof itself — trailing `//` and `/* */` comments included.
fn first_cache_read_and_proof(body: &str) -> Option<(usize, bool)> {
    let mask = code_mask(body);
    let code: String = body
        .char_indices()
        .map(|(i, c)| if mask[i] || c == '\n' { c } else { ' ' })
        .collect();
    let (flat, map) = flatten_out_whitespace(&code);
    let read_at = first_cache_read(&flat)?;
    let line = code[..map[read_at]].matches('\n').count() + 1;
    Some((
        line,
        first_session_proof(&flat).is_some_and(|p| p < read_at),
    ))
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
const CACHED_ACCESSORS: [&str; 11] = [
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
    // Lives in `commands/arm_roles.rs`, not `applications/cache.rs`: the ARM
    // role-name lookup the MI Azure-roles view and the Key Vault sweep share.
    "resolve_role_names_cached(",
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
///
/// The same goes for the proofs themselves: a call counts only in a shape that
/// returns on a missing session — `prove_tenant_session(…)?`,
/// `tenant_context(…)?` (Option-returning commands use the raw lookup), or
/// `let Some(…) = ….tenant_context(…) else`. A bare mention used to count, so
/// `let _ = state.auth.tenant_context(&t);` or `….is_some();` — which discard
/// the answer and fall through to the read — "proved" the session.
fn first_session_proof(flat: &str) -> Option<usize> {
    const SESSION_PROOFS: [&str; 2] = ["prove_tenant_session(", "tenant_context("];
    SESSION_PROOFS
        .iter()
        .flat_map(|p| flat.match_indices(p).map(|(at, _)| (at, p.len())))
        .filter(|&(at, len)| {
            // A whole identifier: not `foo_tenant_context(`.
            if flat[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                return false;
            }
            let Some(close) = matching_paren(flat, at + len - 1) else {
                return false;
            };
            let after = &flat[close + 1..];
            if after.starts_with('?') {
                return true;
            }
            after.starts_with("else{") && let_some_binds(flat, at)
        })
        .map(|(at, _)| at)
        .min()
}

/// Whether the call at `at` is the right-hand side of a `let Some(pattern) =`
/// — any pattern, including a struct one (`let Some(Ctx { oid, .. }) =`),
/// whose braces a "statement starts after the last `;`/`{`/`}`" search would
/// stop inside. Between the `=` and the call only a receiver path may sit
/// (`state.auth.`, `crate::x::`), so this `let` is the call's own.
fn let_some_binds(flat: &str, at: usize) -> bool {
    let Some(let_at) = flat[..at].rfind("letSome(") else {
        return false;
    };
    let Some(close) = matching_paren(flat, let_at + "letSome".len()) else {
        return false;
    };
    close + 2 <= at
        && flat[close + 1..].starts_with('=')
        && flat[close + 2..at]
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | ':' | '&' | '*'))
}

/// The index of the `)` closing the `(` at `open`.
fn matching_paren(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in text[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i);
                }
            }
            _ => {}
        }
    }
    None
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

    // Only a proof that RETURNS on a missing session counts. Each of these
    // passed the old bare-mention detector.
    let read = "\nstate.cache.get(CacheKind::Audit, &k)";
    for (body, why) in [
        (
            "// First: state.auth.tenant_context(&tenant_id)?;",
            "a comment mentioning the proof",
        ),
        (
            "let _ = state.auth.tenant_context(&tenant_id);",
            "`let _ =` discards the answer",
        ),
        (
            "state.auth.tenant_context(&tenant_id).is_some();",
            "`.is_some();` discards the answer",
        ),
        (
            "let _ = crate::commands::session::prove_tenant_session(&state, &tenant_id);",
            "an unpropagated `prove_tenant_session` result",
        ),
        (
            "let x = 1; // state.auth.tenant_context(&tenant_id)?;",
            "a trailing comment",
        ),
        (
            "/* state.auth.tenant_context(&tenant_id)?; */",
            "a block comment",
        ),
        (
            "let msg = \"state.auth.tenant_context(&tenant_id)?;\";",
            "a string literal",
        ),
        (
            "let Some(a) = x else { return; }; let b = state.auth.tenant_context(&t) else { return; };",
            "a `let Some` that binds a different call",
        ),
    ] {
        assert_eq!(
            first_cache_read_and_proof(&format!("{body}{read}")),
            Some((2, false)),
            "not a session proof: {why}"
        );
    }
    for body in [
        "crate::commands::session::prove_tenant_session(&state, &tenant_id)?;",
        "crate::commands::session::prove_tenant_session(\n    &state,\n    &tenant_id,\n)?;",
        "state.auth.tenant_context(&tenant_id)?;",
        "let Some(ctx) = state.auth.tenant_context(&tenant_id) else {\n    return Ok(None);\n};",
        "if x {\n}\nlet Some(TenantCtx { account_oid, .. }) = state\n    .auth\n    .tenant_context(&tenant_id)\nelse {\n    return Ok(None);\n};",
    ] {
        assert!(
            first_cache_read_and_proof(&format!("{body}{read}")).is_some_and(|(_, ok)| ok),
            "a real session proof must still count: {body}"
        );
    }

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
        ("commands/audit/run.rs", 1),
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
/// `commands/audit/tests.rs`, but that pins the predicate, not its use — a refactor
/// that moved the write out of the `if`, or added a second one for a "partial
/// snapshot", compiled and passed every test.
///
/// Keyed on the audit-run KEY rather than on `CacheKind::Audit`: that kind is
/// shared with the site and Key Vault sweeps, which carry their own guards. The
/// key is passed by value only on a direct write (reads and invalidations
/// borrow it as `&audit_cache_key(…)`), so the match below sees exactly those
/// writes; the guarded write names no key, so it is found through the watch
/// minted for the audit-run key (`let <w> = ….generation_for(CacheKind::Audit,
/// &audit_cache_key(…))` → `…_if_current(<w>,`).
#[test]
fn the_audit_run_is_cached_only_behind_run_is_cacheable() {
    const WRITES: [&str; 3] = [".put(", ".put_typed(", ".put_index("];
    const KEY_ARG: &str = "CacheKind::Audit,audit_cache_key(";
    const WATCH: &str = "generation_for(CacheKind::Audit,&audit_cache_key(";
    let mut sites = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    for (name, src) in super::sources::command_modules() {
        let code: String = code_lines(&src).collect::<Vec<_>>().join("\n");
        let (flat, _) = flatten_out_whitespace(&code);
        let mut writes: Vec<(usize, usize)> = Vec::new();
        let mut from = 0usize;
        while let Some(hit) = flat[from..].find(KEY_ARG) {
            let at = from + hit;
            from = at + KEY_ARG.len();
            if WRITES.iter().any(|w| flat[..at].ends_with(w)) {
                writes.push((at, from));
            }
        }
        let mut from = 0usize;
        while let Some(hit) = flat[from..].find(WATCH) {
            let at = from + hit;
            from = at + WATCH.len();
            // `let<ident>=…generation_for(` — the binding the store will name.
            let Some(watch) = flat[..at]
                .rfind("let")
                .and_then(|l| flat[l + 3..at].split_once('='))
                .map(|(ident, _)| ident.to_string())
                .filter(|i| !i.is_empty() && i.chars().all(|c| c.is_alphanumeric() || c == '_'))
            else {
                continue;
            };
            let store = format!("_if_current({watch},");
            let mut s = from;
            while let Some(hit) = flat[s..].find(&store) {
                let at = s + hit;
                s = at + store.len();
                writes.push((at, s));
            }
        }
        for (at, end) in writes {
            sites += 1;
            if !guarded_by_run_is_cacheable(&flat, at) {
                let start = at.saturating_sub(80);
                let start = (start..at)
                    .find(|&i| flat.is_char_boundary(i))
                    .unwrap_or(at);
                offenders.push(format!("{name}: …{}", &flat[start..end]));
            }
        }
    }
    assert!(
        sites >= 1,
        "no audit-run cache write (a guarded store through the audit-run watch, or \
         `.put(CacheKind::Audit, audit_cache_key(…)`) found in any command module — the walk or \
         the matcher is broken, and this rule is checking nothing"
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

/// Sign-out forgets **every** per-tenant map on `AppState`, through one sweep.
///
/// `sign_out` used to drop two of the five client maps by hand and leave the Key
/// Vault / ARM / Log Analytics clients (and the tenant's single-flight gates)
/// behind — harmless today, since a client holds no token, but a list someone
/// must remember to extend. `AppState::forget_tenant` is the one sweep; this rule
/// derives the field list from the struct itself, so a new `Mutex<HashMap<…>>`
/// fails here until the sweep names it.
#[test]
fn sign_out_forgets_every_per_tenant_map_on_app_state() {
    // A Windows checkout has CRLF line endings, and the block ends below are
    // found by splitting on "\n}\n", so normalise before scanning.
    let state = include_str!("../../src/state.rs").replace("\r\n", "\n");
    let state = state.as_str();
    let (_, after) = state
        .split_once("pub struct AppState {")
        .expect("AppState struct in state.rs");
    let (body, _) = after.split_once("\n}\n").expect("end of AppState struct");
    let names: Vec<&str> = body
        .lines()
        .filter(|l| !l.trim_start().starts_with("//") && l.contains("Mutex<HashMap<"))
        .filter_map(|l| l.split_once(':'))
        .filter_map(|(before, _)| before.split_whitespace().last())
        .collect();
    assert!(
        names.len() >= 6,
        "expected the single-flight map plus five client maps on AppState, found {names:?} \
         — the field scan has gone vacuous"
    );
    assert!(
        names.contains(&"kv_clients"),
        "field scan missed kv_clients: {names:?}"
    );

    let (_, after) = state
        .split_once("pub fn forget_tenant(")
        .expect("AppState::forget_tenant in state.rs");
    let (forget, _) = after.split_once("\n    }\n").expect("end of forget_tenant");
    for name in &names {
        assert!(
            forget.contains(&format!("self.{name}")),
            "`AppState::{name}` is a per-tenant map sign-out does not forget — \
             name it in `AppState::forget_tenant`"
        );
    }
    assert!(
        forget.contains("invalidate_tenant("),
        "`AppState::forget_tenant` must sweep every cache kind via `invalidate_tenant`"
    );

    let auth = include_str!("../../src/commands/auth.rs").replace("\r\n", "\n");
    let (_, after) = auth
        .split_once("pub async fn sign_out(")
        .expect("sign_out command in commands/auth.rs");
    let (sign_out, _) = after.split_once("\n}\n").expect("end of sign_out");
    assert!(
        sign_out.contains("forget_tenant("),
        "`sign_out` must call `AppState::forget_tenant`, the one sign-out sweep"
    );
    assert!(
        !sign_out.contains("_clients.lock()"),
        "`sign_out` re-inlines a partial client sweep — call `AppState::forget_tenant` instead, \
         or a per-tenant map sign-out does not forget slips back in"
    );
}

/// Sign-in sweeps the tenant's data caches; re-authentication never does.
///
/// The account picker can hand back a different operator on the same tenant,
/// and every cache key is `{tenant_id}|{kind}` — no account — so without the
/// sweep the new operator was served the previous one's lists and audit run.
/// `reauthenticate` is the opposite contract (same account, enforced by an
/// oid check; the caches are the point of re-authenticating in place), so it
/// must not grow the same call.
#[test]
fn sign_in_forgets_the_tenant_but_reauthenticate_keeps_its_caches() {
    let auth = include_str!("../../src/commands/auth.rs").replace("\r\n", "\n");
    let body = |name: &str| -> String {
        let (_, after) = auth
            .split_once(&format!("pub async fn {name}("))
            .unwrap_or_else(|| panic!("{name} command in commands/auth.rs"));
        let (body, _) = after
            .split_once("\n}\n")
            .unwrap_or_else(|| panic!("end of {name}"));
        // Comments stripped, so prose that mentions the call can't satisfy
        // (or trip) the rule.
        code_lines(body).collect::<Vec<_>>().join("\n")
    };
    assert!(
        body("sign_in").contains("forget_tenant("),
        "`sign_in` must call `AppState::forget_tenant`: a different account on the same tenant \
         would otherwise read the previous account's cached data"
    );
    assert!(
        !body("reauthenticate").contains("forget_tenant("),
        "`reauthenticate` restores the SAME account in place and must keep the data caches"
    );
}
