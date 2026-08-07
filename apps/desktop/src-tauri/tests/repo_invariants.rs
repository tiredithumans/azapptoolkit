//! Cross-tree invariants that AGENTS.md could previously only state as prose.
//!
//! Sibling of `dependency_policy.rs` and written the same way: `include_str!` +
//! a small hand-rolled scan, so these run inside `just test` on every platform
//! rather than needing a shell script that `verify` could not portably call
//! (recipe lines run under PowerShell on Windows).
//!
//! Both rules below were enforced by "the docs tell you to", and one had already
//! drifted: `run_audit` warned its way through a dead session and cached the
//! truncated security report as authoritative.

/// The non-comment, non-blank lines of a TOML block, sorted.
///
/// `header` must be the exact table line; the block ends at the next table.
fn table_body(toml_src: &str, header: &str) -> Vec<String> {
    let Some(start) = toml_src.find(header) else {
        return Vec::new();
    };
    let mut out: Vec<String> = toml_src[start + header.len()..]
        .lines()
        .take_while(|line| !line.trim_start().starts_with('['))
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect();
    out.sort();
    out
}

/// web-rs is EXCLUDED from the root workspace (it targets `wasm32` and carries
/// its own lockfile), so it cannot inherit `[workspace.lints]` and restates the
/// block by hand. AGENTS.md says "keep it in sync with the root block"; nothing
/// but this test actually did.
#[test]
fn web_rs_lint_block_matches_the_workspace_block() {
    let root = table_body(
        include_str!("../../../../Cargo.toml"),
        "[workspace.lints.rust]",
    );
    let web = table_body(include_str!("../../web-rs/Cargo.toml"), "[lints.rust]");
    assert!(
        !root.is_empty(),
        "no [workspace.lints.rust] block found in the root Cargo.toml — this test is checking nothing"
    );
    assert_eq!(
        root, web,
        "apps/desktop/web-rs/Cargo.toml's [lints.rust] has drifted from the root \
         [workspace.lints.rust]. web-rs is outside the workspace, so it cannot inherit \
         the block — restate it verbatim."
    );
}

/// Command modules that drive a long-running fan-out. Kept as literal
/// `include_str!`s because a test binary has no reliable source-tree walk.
const FAN_OUT_MODULES: &[(&str, &str)] = &[
    (
        "commands/audit.rs",
        include_str!("../src/commands/audit.rs"),
    ),
    ("commands/bulk.rs", include_str!("../src/commands/bulk.rs")),
    (
        "commands/backup.rs",
        include_str!("../src/commands/backup.rs"),
    ),
    (
        "commands/sharepoint.rs",
        include_str!("../src/commands/sharepoint.rs"),
    ),
    (
        "commands/keyvault_rbac.rs",
        include_str!("../src/commands/keyvault_rbac.rs"),
    ),
    (
        "commands/permission_tester.rs",
        include_str!("../src/commands/permission_tester.rs"),
    ),
];

/// The `.alert` markup lives in exactly ONE component.
///
/// AGENTS.md states "one primitive per UI pattern", and `Callout` is that
/// primitive for inline notices — but 30 files had hand-rolled
/// `<div class="alert alert--…">` instead, none of them importing it. Nothing
/// caught that, because a bypass compiles and even looks right; it only shows
/// up when the tone vocabulary or the box's markup needs to change in 30 places
/// at once. The primitive now carries the `class`/`role` escape hatches those
/// sites needed, so there is no remaining reason to hand-roll one.
#[test]
fn inline_notice_markup_lives_only_in_the_callout_primitive() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps/desktop")
        .join("web-rs/src");
    let mut offenders: Vec<String> = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            // The primitive itself is where this markup belongs.
            if path.ends_with("ui/callout.rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&path) else {
                continue;
            };
            if src.contains("class=\"alert") {
                offenders.push(
                    path.strip_prefix(&root)
                        .unwrap_or(&path)
                        .display()
                        .to_string(),
                );
            }
        }
    }
    offenders.sort();
    assert!(
        offenders.is_empty(),
        "hand-rolled inline-notice markup outside the Callout primitive: {offenders:#?}\n\
         Use `components::ui::Callout` (tone=\"ok\"|\"warn\"|\"danger\", plus optional \
         class/role) instead of writing the `.alert` classes directly."
    );
}

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

/// Every command module, for the source-scanning invariants above.
const COMMAND_SOURCES: &[(&str, &str)] = &[
    (
        "commands/applications/mod.rs",
        include_str!("../src/commands/applications/mod.rs"),
    ),
    (
        "commands/applications/credentials.rs",
        include_str!("../src/commands/applications/credentials.rs"),
    ),
    (
        "commands/applications/owners.rs",
        include_str!("../src/commands/applications/owners.rs"),
    ),
    (
        "commands/permissions.rs",
        include_str!("../src/commands/permissions.rs"),
    ),
    (
        "commands/exchange.rs",
        include_str!("../src/commands/exchange.rs"),
    ),
    (
        "commands/sharepoint.rs",
        include_str!("../src/commands/sharepoint.rs"),
    ),
    (
        "commands/enterprise_application.rs",
        include_str!("../src/commands/enterprise_application.rs"),
    ),
    (
        "commands/expose_api.rs",
        include_str!("../src/commands/expose_api.rs"),
    ),
    (
        "commands/remediation.rs",
        include_str!("../src/commands/remediation.rs"),
    ),
    ("commands/bulk.rs", include_str!("../src/commands/bulk.rs")),
    (
        "commands/restore.rs",
        include_str!("../src/commands/restore.rs"),
    ),
    (
        "commands/app_roles.rs",
        include_str!("../src/commands/app_roles.rs"),
    ),
];

/// Long-running **sequential** flows: many writes in a row, each degrading to a
/// per-item failure or warning rather than aborting.
///
/// Held separately from [`FAN_OUT_MODULES`] because the rename-guard differs —
/// these dispatch nothing, so `dispatch_capped(`/`run_bulk_seq(` never appears
/// in them — but the hazard is identical and arguably worse: a dead session
/// mid-restore produced one indistinguishable failure per remaining item, so a
/// report full of "permission denied" read as a tenant rejecting the writes
/// rather than as a session that had expired on the first one.
const SEQUENTIAL_WRITE_MODULES: &[(&str, &str)] = &[(
    "commands/restore.rs",
    include_str!("../src/commands/restore.rs"),
)];

/// The sequential counterpart to [`every_fan_out_command_honours_is_reauth_fatal`].
#[test]
fn every_sequential_write_flow_stops_on_a_dead_session() {
    for (name, src) in SEQUENTIAL_WRITE_MODULES {
        assert!(
            src.contains("SessionDead") && src.contains("session.is_dead()"),
            "{name} performs a long sequence of writes but never latches or gates on a dead \
             session. Construct a `SessionDead`, note each failure through it (`note_code` keeps \
             `UiError::is_reauth_fatal` the single definition), and break out of each pass when \
             `is_dead()` — otherwise every remaining item fails identically and the report reads \
             as a tenant rejection rather than an expired session."
        );
    }
}

/// Fan-outs that still lack the branch. **Empty, and it must stay that way** —
/// every entry was a command that returned a silently partial result when the
/// session died mid-run. The list is kept (rather than deleted with its last
/// entry) so a NEW fan-out cannot be added without either the branch or an
/// explicit, reviewed admission here.
///
/// Closing the last four needed a root-cause fix, not four local branches:
/// `BearerProvider` returned `Result<String, String>`, so every client flattened
/// a dead session into the code `token_error` and `is_reauth_fatal` could never
/// fire for a Graph/Exchange/Key Vault/ARM call. `core::token::TokenError` now
/// carries the classification across that boundary.
const KNOWN_GAPS: &[&str] = &[];

/// A dead session makes every remaining item fail identically, so a fan-out that
/// only warns produces a silently partial result. `UiError::is_reauth_fatal` is
/// the single definition (azapptoolkit-dto, shared by both tiers) — AGENTS.md:
/// "Long-running loops must stop on it".
#[test]
fn every_fan_out_command_honours_is_reauth_fatal() {
    let mut missing: Vec<&str> = Vec::new();
    let mut stale: Vec<&str> = Vec::new();

    for (name, src) in FAN_OUT_MODULES {
        // Guard against a module being renamed out from under this list.
        assert!(
            src.contains("dispatch_capped(") || src.contains("run_bulk_seq("),
            "{name} no longer drives a fan-out — drop it from FAN_OUT_MODULES"
        );
        // Two accepted shapes. Either the module classifies the error itself
        // (`commands/audit.rs::classify_audit_failure`), or it uses the shared
        // `SessionDead` latch — which routes through `UiError::is_reauth_fatal`
        // internally. The latch only counts when the module also *gates* on it:
        // recording a dead session and dispatching anyway is the bug this rule
        // exists to catch.
        let handled = src.contains("is_reauth_fatal")
            || (src.contains("SessionDead") && src.contains("session.is_dead()"));
        match (handled, KNOWN_GAPS.contains(name)) {
            (false, false) => missing.push(name),
            (true, true) => stale.push(name),
            _ => {}
        }
    }

    assert!(
        missing.is_empty(),
        "fan-out command(s) with no is_reauth_fatal branch: {missing:?}\n\
         A dead session makes every remaining item fail identically — stop the loop and \
         do not cache a partial result. See commands/audit.rs::classify_audit_failure."
    );
    assert!(
        stale.is_empty(),
        "these now handle is_reauth_fatal — drop them from KNOWN_GAPS: {stale:?}"
    );
    // AGENTS.md: KNOWN_GAPS "is empty and must stay so". It was empty, and the
    // test above tolerated entries being ADDED to it — a new fan-out with no
    // dead-session branch could ship by appending one line, and the only
    // pushback would be a staleness message that never fires while the gap is
    // real. An allowlist that can grow is not a ratchet.
    //
    // Deliberately last, so the two diagnostics above (which say what to fix)
    // are reached first when several things are wrong at once.
    assert!(
        KNOWN_GAPS.is_empty(),
        "KNOWN_GAPS must stay empty: {KNOWN_GAPS:?}\n\
         Every fan-out honours is_reauth_fatal today. Fix the new one instead of \
         listing it — a fan-out that warns through a dead session returns a partial \
         result the UI presents as complete."
    );
}

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
        include_str!("../src/commands/search.rs"),
        1,
    ),
    (
        "commands/gallery.rs",
        include_str!("../src/commands/gallery.rs"),
        1,
    ),
    (
        "commands/enterprise_application.rs",
        include_str!("../src/commands/enterprise_application.rs"),
        1,
    ),
    (
        "commands/applications/mod.rs",
        include_str!("../src/commands/applications/mod.rs"),
        1,
    ),
    (
        "commands/managed_identity.rs",
        include_str!("../src/commands/managed_identity.rs"),
        1,
    ),
    (
        "commands/applications/cache.rs",
        include_str!("../src/commands/applications/cache.rs"),
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

/// A scope remediation must be gated on a POSITIVE "this resource can be
/// confined" test, never on the negation of a legacy/unscopable test.
///
/// AGENTS.md states this for mailbox, and the SharePoint sibling had already
/// drifted: `Sites.*` on Office 365 SharePoint Online was offered the Graph
/// `Sites.Selected` fix, which strips nothing on that resource and would have
/// left the app org-wide while the audit re-scored it as confined. A negation
/// silently admits every resource nobody has classified yet; the positive form
/// admits only what has been proved confinable.
#[test]
fn scope_fixes_are_gated_on_a_positive_resource_test() {
    let scoring = include_str!("../../../../crates/azapptoolkit-core/src/audit/scoring.rs");
    for positive in [
        "is_scopable_exchange_resource_permission",
        "is_scopable_sharepoint_resource_permission",
    ] {
        assert!(
            scoring.contains(positive),
            "audit/scoring.rs no longer references {positive} — a scope Fix must be gated on the \
             positive resource test, not on the negation of a legacy one"
        );
        assert!(
            !scoring.contains(&format!("!{positive}")),
            "audit/scoring.rs negates {positive}; the gate must stay positive"
        );
    }
    for negated in [
        "!is_unscopable_legacy_exchange_permission",
        "!crate::scoping::is_unscopable_legacy_exchange_permission",
    ] {
        assert!(
            !scoring.contains(negated),
            "audit/scoring.rs gates on {negated}. Negating the legacy test admits every resource \
             nobody has classified — gate on is_scopable_*_resource_permission instead."
        );
    }
}

/// Command modules that own a long-running fan-out, for the cancel-flag rule.
const CANCEL_FLAG_MODULES: &[(&str, &str)] = &[
    (
        "commands/audit.rs",
        include_str!("../src/commands/audit.rs"),
    ),
    ("commands/bulk.rs", include_str!("../src/commands/bulk.rs")),
    (
        "commands/backup.rs",
        include_str!("../src/commands/backup.rs"),
    ),
    (
        "commands/restore.rs",
        include_str!("../src/commands/restore.rs"),
    ),
    (
        "commands/sharepoint.rs",
        include_str!("../src/commands/sharepoint.rs"),
    ),
    (
        "commands/keyvault_rbac.rs",
        include_str!("../src/commands/keyvault_rbac.rs"),
    ),
    (
        "commands/permission_tester.rs",
        include_str!("../src/commands/permission_tester.rs"),
    ),
];

/// Every long-running command must `reset()` its cancel flag at the top.
///
/// The flags are shared (`audit_cancel` by the security audit AND every bulk
/// action; `sweep_cancel` by two sweeps), so a command that forgets is
/// cancelled before it starts by an unrelated earlier run — a failure that only
/// shows up as "the run did nothing" on the second use.
///
/// Splitting on `#[tauri::command]` gives one chunk per handler, which is enough
/// to tell "this handler drives a fan-out" from "this handler resets a flag".
#[test]
fn every_long_running_command_resets_its_cancel_flag() {
    let mut missing: Vec<String> = Vec::new();
    for (name, src) in CANCEL_FLAG_MODULES {
        for chunk in src.split("#[tauri::command]").skip(1) {
            // Stop at the module's test block: fixtures legitimately call the
            // fan-out helpers without being commands.
            let body = chunk.split("#[cfg(test)]").next().unwrap_or(chunk);
            let drives_fan_out =
                body.contains("dispatch_capped(") || body.contains("run_bulk_seq(");
            if drives_fan_out && !body.contains(".reset()") {
                let signature = body
                    .lines()
                    .find(|l| l.contains("pub async fn") || l.contains("pub fn"))
                    .unwrap_or("(unnamed)")
                    .trim();
                missing.push(format!("{name}: {signature}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "long-running command(s) that never reset their cancel flag: {missing:#?}\n\
         The flags are shared between commands, so a stale `true` cancels this run before it \
         starts. Call `state.<flag>_cancel.reset()` at the top."
    );
}

/// `## [X.Y.Z] - YYYY-MM-DD`, exactly — no `v` prefix, ASCII hyphen, one space.
///
/// TWO parsers depend on this and they cannot be merged (one is PowerShell in
/// `release.yml`, one is Rust in `web-rs/build.rs`), so the format contract is
/// checked here instead of by a comment in each. They already differ in
/// tolerance — the PowerShell matches `^##\s+\[` while the Rust requires a
/// single space — so a header the workflow accepts can bake empty in-app.
#[test]
fn changelog_headers_match_what_both_parsers_require() {
    let changelog = include_str!("../../../../CHANGELOG.md");
    let mut bad: Vec<&str> = Vec::new();
    let mut releases = 0usize;
    for line in changelog
        .lines()
        .filter(|l| l.trim_start().starts_with("##"))
    {
        // Section headers inside a release (### Added, …) aren't version rows.
        if !line.starts_with("## [") {
            if line.starts_with("##") && line.contains('[') && !line.starts_with("###") {
                bad.push(line);
            }
            continue;
        }
        let Some(rest) = line.strip_prefix("## [") else {
            bad.push(line);
            continue;
        };
        let Some((version, tail)) = rest.split_once(']') else {
            bad.push(line);
            continue;
        };
        if version.starts_with('v')
            || version.split('.').count() != 3
            || !version
                .split('.')
                .all(|p| p.chars().all(|c| c.is_ascii_digit()))
        {
            // `[Unreleased]` is the one legal non-version header.
            if version != "Unreleased" {
                bad.push(line);
            }
            continue;
        }
        releases += 1;
        // ` - YYYY-MM-DD`, ASCII hyphen both as separator and inside the date.
        let date = tail.trim();
        if !date.starts_with("- ") || date.len() != "- YYYY-MM-DD".len() {
            bad.push(line);
        }
    }
    assert!(
        bad.is_empty(),
        "CHANGELOG.md header(s) that one of the two parsers will mis-read: {bad:#?}\n\
         Required shape: `## [X.Y.Z] - YYYY-MM-DD` (no `v`, ASCII hyphen, single space)."
    );
    assert!(
        releases > 0,
        "no release headers found in CHANGELOG.md — this test is checking nothing"
    );
}

/// AGENTS.md is the index every agent loads on session start, and it documents
/// its own 28 000-byte budget. It had grown past it, which is precisely when the
/// file stops being an index and starts being the manual it tells you not to
/// write — so the budget is enforced rather than advertised.
#[test]
fn agents_md_stays_within_its_own_budget() {
    const BUDGET: usize = 28_000;
    // Measured with `\r` stripped: git checks this file out CRLF on Windows, so
    // a raw byte count would charge the file one extra byte per line and make
    // the budget platform-dependent (it failed on windows-latest alone).
    let size = include_str!("../../../../AGENTS.md")
        .bytes()
        .filter(|b| *b != b'\r')
        .count();
    assert!(
        size <= BUDGET,
        "AGENTS.md is {size} bytes, over its documented {BUDGET}-byte budget by {}. \
         Move the deep detail into docs/architecture/ and leave one invariant + a pointer.",
        size - BUDGET
    );
}

/// The shipped version number is stated in four places and hand-synced across
/// all of them.
///
/// `apps/desktop/src-tauri/Cargo.toml` already does the right thing
/// (`version.workspace = true`), which proves the single-source mechanism
/// exists here and is simply not applied to the rest. Cargo has no equivalent
/// for `tauri.conf.json` or for the excluded `web-rs` workspace, so the
/// remaining three genuinely are separate literals — and correctness of the
/// bump was delegated to a release *ritual* rather than to any check.
///
/// The failure mode is not cosmetic. `tauri.conf.json`'s version is what goes
/// into the bundle and into the updater's `latest.json`; the crate versions are
/// what the binaries report. A partial bump ships an installer whose update
/// metadata disagrees with the binary inside it, and the updater compares
/// versions to decide whether to offer an update at all — so a missed bump can
/// leave every existing install convinced it is already current.
///
/// The newest CHANGELOG release header is included because `web-rs/build.rs`
/// bakes that section into the in-app "What's new": a version with no matching
/// section renders an empty panel to the user.
#[test]
fn every_manifest_states_the_same_version() {
    /// First `version = "X.Y.Z"` at the start of a line, TOML-style.
    fn toml_version(src: &str) -> Option<&str> {
        src.lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix("version"))
            .and_then(|rest| rest.trim_start().strip_prefix('='))
            .and_then(|rest| rest.trim().strip_prefix('"'))
            .and_then(|rest| rest.split('"').next())
    }

    let root = toml_version(include_str!("../../../../Cargo.toml"))
        .expect("root Cargo.toml has no [workspace.package] version");
    let web = toml_version(include_str!("../../web-rs/Cargo.toml"))
        .expect("web-rs/Cargo.toml has no version");

    // Hand-scanned rather than parsed: this test must not pull a JSON
    // dependency into the dev tree just to read one field.
    let conf = include_str!("../tauri.conf.json");
    let tauri = conf
        .lines()
        .find_map(|l| l.trim().strip_prefix("\"version\":"))
        .and_then(|rest| rest.trim().strip_prefix('"'))
        .and_then(|rest| rest.split('"').next())
        .expect("tauri.conf.json has no \"version\" field");

    // The newest `## [X.Y.Z]` header, skipping `[Unreleased]`.
    let changelog = include_str!("../../../../CHANGELOG.md")
        .lines()
        .filter_map(|l| l.strip_prefix("## ["))
        .filter_map(|rest| rest.split_once(']').map(|(v, _)| v))
        .find(|v| *v != "Unreleased")
        .expect("CHANGELOG.md has no release header");

    assert_eq!(
        root, web,
        "Cargo.toml says {root}, apps/desktop/web-rs/Cargo.toml says {web}"
    );
    assert_eq!(
        root, tauri,
        "Cargo.toml says {root}, apps/desktop/src-tauri/tauri.conf.json says {tauri} — \
         tauri.conf.json is what the bundle and the updater's latest.json carry"
    );
    assert_eq!(
        root, changelog,
        "Cargo.toml says {root} but the newest CHANGELOG.md release header is {changelog} — \
         web-rs/build.rs bakes that section into the in-app \"What's new\", so a mismatch \
         ships an empty panel"
    );
}

/// Modules that capture a cache watch across a live fetch. Superset of
/// `PINNED_WRITE_SITES` — `applications/cache.rs` holds the two shared index
/// accessors that fetch on behalf of everyone else.
const WATCH_CAPTURE_SITES: &[(&str, &str)] = &[
    (
        "commands/search.rs",
        include_str!("../src/commands/search.rs"),
    ),
    (
        "commands/enterprise_application.rs",
        include_str!("../src/commands/enterprise_application.rs"),
    ),
    (
        "commands/applications/mod.rs",
        include_str!("../src/commands/applications/mod.rs"),
    ),
    (
        "commands/applications/cache.rs",
        include_str!("../src/commands/applications/cache.rs"),
    ),
    (
        "commands/managed_identity.rs",
        include_str!("../src/commands/managed_identity.rs"),
    ),
    (
        "commands/audit.rs",
        include_str!("../src/commands/audit.rs"),
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
    let cache_src = include_str!("../../../../crates/azapptoolkit-core/src/cache.rs");
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
