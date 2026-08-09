//! Release identity and the hand-mirrored definitions around it: the three
//! manifests, the web-rs lint block, the CHANGELOG header format, and the
//! AGENTS.md size budget.

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
        include_str!("../../../../../Cargo.toml"),
        "[workspace.lints.rust]",
    );
    let web = table_body(include_str!("../../../web-rs/Cargo.toml"), "[lints.rust]");
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

/// `## [X.Y.Z] - YYYY-MM-DD`, exactly — no `v` prefix, ASCII hyphen, one space.
///
/// TWO parsers depend on this and they cannot be merged (one is PowerShell in
/// `release.yml`, one is Rust in `web-rs/build.rs`), so the format contract is
/// checked here instead of by a comment in each. They already differ in
/// tolerance — the PowerShell matches `^##\s+\[` while the Rust requires a
/// single space — so a header the workflow accepts can bake empty in-app.
#[test]
fn changelog_headers_match_what_both_parsers_require() {
    let changelog = include_str!("../../../../../CHANGELOG.md");
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
    let size = include_str!("../../../../../AGENTS.md")
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

    let root = toml_version(include_str!("../../../../../Cargo.toml"))
        .expect("root Cargo.toml has no [workspace.package] version");
    let web = toml_version(include_str!("../../../web-rs/Cargo.toml"))
        .expect("web-rs/Cargo.toml has no version");

    // Hand-scanned rather than parsed: this test must not pull a JSON
    // dependency into the dev tree just to read one field.
    let conf = include_str!("../../tauri.conf.json");
    let tauri = conf
        .lines()
        .find_map(|l| l.trim().strip_prefix("\"version\":"))
        .and_then(|rest| rest.trim().strip_prefix('"'))
        .and_then(|rest| rest.split('"').next())
        .expect("tauri.conf.json has no \"version\" field");

    // The newest `## [X.Y.Z]` header, skipping `[Unreleased]`.
    let changelog = include_str!("../../../../../CHANGELOG.md")
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

/// The two CHANGELOG section extractors agree.
///
/// There are two, in different languages, and the Rust one's own header comment
/// says they "are expected to produce identical text for a release; nothing
/// checks that". This is that check.
///
/// * Rust — `web-rs/build_support.rs::section_for`, bakes the in-app
///   "What's new" panel at compile time.
/// * PowerShell — `release.yml`, fills the updater manifest's `notes` field,
///   which is what the update splash shows.
///
/// So the same release can describe itself two ways: one text in the installed
/// app, a different one in the update prompt that offered it. They drifted
/// apart in tolerance already — PowerShell matches `^##\s+\[` (any run of
/// whitespace) while Rust requires the exact `## [`, so a header written
/// `##  [1.2.3]` yields notes from one and silence from the other.
///
/// This pins agreement rather than removing the duplication: single-sourcing
/// would mean the release workflow shelling out to a Rust binary across the
/// 3-OS matrix, which costs more than it saves. `powershell_semantics` below is
/// a faithful port of the workflow's loop — if you change the workflow's
/// extraction, change this with it, and the differential over the real
/// CHANGELOG will tell you whether the two still match.
#[test]
fn both_changelog_extractors_produce_the_same_notes() {
    /// The Rust parser, mirroring `web-rs/build_support.rs::section_for`.
    fn rust_semantics(changelog: &str, version: &str) -> Option<String> {
        let header = format!("## [{version}]");
        let mut lines = changelog.lines().skip_while(|l| !l.starts_with(&header));
        lines.next()?;
        let body = lines
            .take_while(|l| !l.starts_with("## ["))
            .collect::<Vec<_>>()
            .join("\n")
            .trim()
            .to_string();
        (!body.is_empty()).then_some(body)
    }

    /// A port of `release.yml`'s loop: skip until the target header, collect
    /// until the next `## [` header, trim. Empty ⇒ the workflow substitutes its
    /// own fallback sentence, which is `None` here.
    fn powershell_semantics(changelog: &str, version: &str) -> Option<String> {
        fn is_header(l: &str) -> Option<&str> {
            let t = l.strip_prefix("##")?;
            if !t.starts_with(char::is_whitespace) {
                return None;
            }
            let rest = t.trim_start();
            rest.starts_with('[').then_some(rest)
        }
        let mut collecting = false;
        let mut buf: Vec<&str> = Vec::new();
        for line in changelog.lines() {
            if let Some(rest) = is_header(line) {
                if collecting {
                    break;
                }
                if rest.starts_with(&format!("[{version}]")) {
                    collecting = true;
                }
                continue;
            }
            if collecting {
                buf.push(line);
            }
        }
        let body = buf.join("\n").trim().to_string();
        (!body.is_empty()).then_some(body)
    }

    let changelog = include_str!("../../../../../CHANGELOG.md");

    // Every released version in the repo's own CHANGELOG, plus the shapes that
    // have historically differed.
    let mut versions: Vec<String> = changelog
        .lines()
        .filter_map(|l| l.strip_prefix("## ["))
        .filter_map(|r| r.split_once(']'))
        .map(|(v, _)| v.to_string())
        .collect();
    assert!(
        versions.len() > 3,
        "found {} version headers — the differential would be near-vacuous",
        versions.len()
    );
    versions.push("9.9.9-absent".into());

    for v in &versions {
        assert_eq!(
            rust_semantics(changelog, v),
            powershell_semantics(changelog, v),
            "the in-app 'What's new' panel and the updater's release notes would show DIFFERENT \
             text for {v}. One is baked by web-rs/build_support.rs, the other by release.yml — \
             reconcile them."
        );
    }

    // The known tolerance gap, pinned as a fixture so it stays a deliberate
    // decision rather than a surprise: a two-space header is legal to the
    // workflow and invisible to the bake. `changelog_headers_match_what_both_
    // parsers_require` is what keeps it out of the real file.
    let sloppy = "##  [1.2.3] - 2026-01-01\n\n- note\n";
    assert_eq!(rust_semantics(sloppy, "1.2.3"), None);
    assert_eq!(
        powershell_semantics(sloppy, "1.2.3"),
        Some("- note".to_string()),
        "if this stops differing, the header-format rule can be relaxed"
    );
}

/// `verify-full` runs every gate CI runs.
///
/// The recipe's own comment promises "full CI parity", and it is what a
/// contributor runs before opening a PR. It was missing `web-itest-size` — the
/// per-shard wasm ceiling the whole GUI-test sharding strategy depends on — so a
/// shard that had grown past the limit passed locally and failed in CI, which is
/// precisely the round trip the recipe exists to avoid.
///
/// Derived from `ci.yml` rather than listed here, so adding a gate to CI without
/// adding it to `verify-full` fails immediately instead of at someone's next PR.
#[test]
fn verify_full_runs_every_gate_ci_runs() {
    let justfile = include_str!("../../../../../justfile");
    let ci = include_str!("../../../../../.github/workflows/ci.yml");

    /// The dependency list on a recipe's header line: `name: dep1 dep2`.
    fn deps<'a>(justfile: &'a str, recipe: &str) -> Vec<&'a str> {
        justfile
            .lines()
            .find(|l| l.starts_with(&format!("{recipe}:")))
            .and_then(|l| l.split_once(':'))
            .map(|(_, rest)| rest.split_whitespace().collect())
            .unwrap_or_default()
    }

    let mut covered: Vec<&str> = deps(justfile, "verify-full");
    assert!(
        !covered.is_empty(),
        "verify-full has no dependencies — did the recipe move or get renamed?"
    );
    // One level of expansion is enough: `_verify-core` is the only aggregate
    // `verify-full` depends on.
    for agg in covered.clone() {
        covered.extend(deps(justfile, agg));
    }

    // Recipes CI invokes that are not gates `verify-full` should run.
    // `triggered` is the change-detection helper, not a check.
    const NOT_A_GATE: &[&str] = &["triggered"];

    let mut missing: Vec<&str> = Vec::new();
    for line in ci.lines() {
        let Some(rest) = line.split_once("just ") else {
            continue;
        };
        let recipe: &str = rest
            .1
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_matches(|c: char| !(c.is_alphanumeric() || c == '-'));
        if recipe.is_empty() || NOT_A_GATE.contains(&recipe) {
            continue;
        }
        if !covered.contains(&recipe) && !missing.contains(&recipe) {
            missing.push(recipe);
        }
    }
    missing.sort_unstable();
    assert!(
        missing.is_empty(),
        "ci.yml runs gate(s) `verify-full` does not: {missing:?}\n\
         `verify-full` documents itself as full CI parity and is what contributors run before \
         opening a PR. Add them to the recipe, or add them to NOT_A_GATE with a reason if they \
         are helpers rather than checks."
    );
}
