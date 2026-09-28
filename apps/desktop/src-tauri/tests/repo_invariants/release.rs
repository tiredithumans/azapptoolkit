//! Release identity and the hand-mirrored definitions around it: the three
//! manifests, the web-rs lint block, the CHANGELOG header format, the
//! AGENTS.md size budget — and who the shipped artifacts reach: the update gate,
//! the Linux glibc floor and the NSIS install mode.

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
/// its own 20 000-byte budget. It had grown past an earlier 28 000-byte one,
/// which is precisely when the file stops being an index and starts being the
/// manual it tells you not to write — so the budget is enforced rather than
/// advertised, and it was lowered once the per-subsystem elaborations moved to
/// `docs/architecture/` and the path-scoped `.claude/rules/`.
#[test]
fn agents_md_stays_within_its_own_budget() {
    const BUDGET: usize = 20_000;
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

/// The Conventional Commits scope allowlist has two copies that cannot be
/// merged: AGENTS.md documents it (the cross-agent contract every tool reads)
/// and `.claude/hooks/conventional-commit-validator.sh` enforces it (a hook
/// cannot parse prose reliably). CONTRIBUTING.md and the skills point at
/// AGENTS.md rather than carrying a third. This is what keeps the two honest.
#[test]
fn commit_scope_allowlist_agrees_between_agents_md_and_the_hook() {
    fn backticked(line: &str) -> Vec<String> {
        line.split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    }
    let agents = include_str!("../../../../../AGENTS.md");
    let line = agents
        .lines()
        .find(|l| l.trim_start().starts_with("- Scopes"))
        .expect("AGENTS.md has a `- Scopes …` line under Git & version control");
    // Only the list after the explanatory parenthetical counts: the prose before
    // it may itself name a file in backticks (this test, for one).
    let list = line.rsplit_once("):").map_or(line, |(_, rest)| rest);
    let mut documented = backticked(list);
    documented.sort_unstable();

    let hook = include_str!("../../../../../.claude/hooks/conventional-commit-validator.sh");
    let start = hook
        .find("scopes = {")
        .expect("the commit validator defines `scopes = {…}`");
    let block = &hook[start..];
    let block = &block[..block.find('}').expect("scopes set closes")];
    let mut enforced: Vec<String> = block
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect();
    enforced.sort_unstable();

    assert!(
        documented.len() >= 5,
        "parsed only {documented:?} from AGENTS.md — the line format changed and this test is          checking nothing"
    );
    assert_eq!(
        documented, enforced,
        "commit scope allowlist drift: AGENTS.md documents {documented:?} but conventional-commit-validator.sh enforces {enforced:?}. Change both."
    );
}

/// `web-rs/build_support.rs` — the parser `web-rs/build.rs` bakes "What's new"
/// with — mounted so the differential below runs the real `section_for`, not a
/// copy of it.
#[path = "../../../web-rs/build_support.rs"]
mod build_support;

/// The two CHANGELOG section extractors agree.
///
/// There are two, in different languages, and they are expected to produce
/// identical text for a release. This is the check that they do.
///
/// * Rust — `web-rs/build_support.rs::section_for`, bakes the in-app
///   "What's new" panel at compile time. The real function is mounted above
///   via `#[path]`, so an edit to the parser changes this differential.
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
            build_support::section_for(changelog, v),
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
    assert_eq!(build_support::section_for(sloppy, "1.2.3"), None);
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

    // Recipes CI invokes that are not gates `verify-full` should run. Empty:
    // every `just` recipe CI runs is a gate contributors should be able to run
    // too. It previously held `triggered`, which was never a recipe at all —
    // the scan below matched `just ` anywhere on a line, so the phrase "the run
    // it just triggered" in a comment at the top of ci.yml read as an
    // invocation. An allowlist entry papered over a detector bug, which is the
    // failure mode this suite exists to avoid.
    const NOT_A_GATE: &[&str] = &[];

    let mut missing: Vec<&str> = Vec::new();
    let mut invocations = 0usize;
    for line in ci.lines() {
        // Only a real invocation counts: `run: just <recipe>`, or `just
        // <recipe>` at the start of a line inside a `run: |` block. Matching
        // `just ` anywhere also matched English.
        let trimmed = line.trim_start();
        let Some(rest) = trimmed
            .strip_prefix("run: just ")
            .or_else(|| trimmed.strip_prefix("just "))
        else {
            continue;
        };
        let recipe: &str = rest
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .trim_matches(|c: char| !(c.is_alphanumeric() || c == '-'));
        if recipe.is_empty() || NOT_A_GATE.contains(&recipe) {
            continue;
        }
        invocations += 1;
        if !covered.contains(&recipe) && !missing.contains(&recipe) {
            missing.push(recipe);
        }
    }
    assert!(
        // fmt-check, clippy, test, web-fmt-check, web-clippy, web-test,
        // web-build, web-itest, web-itest-size, audit, web-audit, deny,
        // web-deny. A scan finding far fewer has stopped recognising the shape.
        invocations >= 10,
        "the scan found only {invocations} `just` invocation(s) in ci.yml — the recipe detector \
         is broken, and a parity rule that sees no gates passes vacuously"
    );
    missing.sort_unstable();
    assert!(
        missing.is_empty(),
        "ci.yml runs gate(s) `verify-full` does not: {missing:?}\n\
         `verify-full` documents itself as full CI parity and is what contributors run before \
         opening a PR. Add them to the recipe, or add them to NOT_A_GATE with a reason if they \
         are helpers rather than checks."
    );
}

/// The CI change detector must not classify as docs a file a test here pins.
///
/// ci.yml's `changes` job skips `just test` when a diff is docs-only (`*.md`,
/// `docs/`, `.claude/`, …) — yet AGENTS.md, CHANGELOG.md, README.md, an
/// architecture doc and the commit hook are all `include_str!`d by these tests.
/// A PR touching only one of them merged green with the test that pins it
/// skipped, and the failure surfaced on the next unrelated code PR (or, for the
/// CHANGELOG header, at release time). The detector therefore carries an
/// exceptions arm ahead of its docs arm.
///
/// Derived, not listed: every `include_str!` under `tests/` is resolved, and each
/// path the docs arm would match must also be matched by the exceptions arm. So
/// a new test that pins another doc fails here until the detector learns it.
#[test]
fn docs_only_ci_detector_runs_the_tests_that_pin_docs() {
    use std::path::{Path, PathBuf};

    let ci = include_str!("../../../../../.github/workflows/ci.yml");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo = manifest
        .join("../../..")
        .canonicalize()
        .expect("repo root resolves");

    /// A `case` arm's patterns: the text before `)`, split on `|`.
    fn arm_patterns(line: &str) -> Vec<&str> {
        line.trim()
            .split_once(')')
            .map(|(pats, _)| pats.split('|').map(str::trim).collect())
            .unwrap_or_default()
    }
    /// The subset of shell `case` globbing the detector uses: a leading `*` is a
    /// suffix match, a trailing `*` a prefix match (`*` crosses `/` in `case`),
    /// anything else exact.
    fn glob(pattern: &str, path: &str) -> bool {
        if let Some(suffix) = pattern.strip_prefix('*') {
            path.ends_with(suffix)
        } else if let Some(prefix) = pattern.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path == pattern
        }
    }

    // The exceptions arm (`… ) code=true ;;`, not the `*)` catch-all) and the
    // docs arm (`… ) : ;;`).
    let exceptions = ci
        .lines()
        .map(str::trim)
        .find(|l| l.ends_with(") code=true ;;") && !l.starts_with("*)"))
        .map(arm_patterns)
        .unwrap_or_default();
    let docs = ci
        .lines()
        .map(str::trim)
        .find(|l| l.contains(") : ;;"))
        .map(arm_patterns)
        .unwrap_or_default();
    assert!(
        !exceptions.is_empty(),
        "ci.yml's change detector has no exceptions arm (`<paths>) code=true ;;` ahead of the \
         docs arm) — the rule below would pass vacuously"
    );
    assert!(
        !docs.is_empty(),
        "ci.yml's change detector docs arm (`<globs>) : ;;`) not found — did the detector move?"
    );

    // Every `.rs` under tests/, recursively (same walk as `sources.rs`).
    let mut sources: Vec<PathBuf> = Vec::new();
    let mut stack = vec![manifest.join("tests")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                sources.push(path);
            }
        }
    }

    let needle = concat!("include_str", "!(");
    let mut pinned_docs: Vec<String> = Vec::new();
    for file in &sources {
        let src = std::fs::read_to_string(file).expect("test source is readable");
        // Comments may mention the macro; only code pins a file.
        let code: String = src
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut rest = code.as_str();
        while let Some(at) = rest.find(needle) {
            rest = rest[at + needle.len()..].trim_start();
            let Some(lit) = rest.strip_prefix('"') else {
                continue;
            };
            let Some(end) = lit.find('"') else {
                break;
            };
            let target = file
                .parent()
                .expect("a source file has a parent")
                .join(&lit[..end]);
            rest = &lit[end + 1..];
            let Ok(abs) = target.canonicalize() else {
                continue;
            };
            let Ok(rel) = abs.strip_prefix(&repo) else {
                continue;
            };
            let rel = rel.to_string_lossy().replace('\\', "/");
            if docs.iter().any(|p| glob(p, &rel)) && !pinned_docs.contains(&rel) {
                pinned_docs.push(rel);
            }
        }
    }
    pinned_docs.sort();
    assert!(
        // AGENTS.md, CHANGELOG.md, README.md, caching-and-search.md and the
        // commit hook today. Far fewer means the scan stopped seeing the pins.
        pinned_docs.len() >= 4,
        "found only {pinned_docs:?} docs-classified file(s) pinned by `include_str!` under tests/ \
         — the scan is broken, and this rule would pass vacuously"
    );

    let unguarded: Vec<&String> = pinned_docs
        .iter()
        .filter(|path| !exceptions.iter().any(|p| glob(p, path)))
        .collect();
    assert!(
        unguarded.is_empty(),
        "these files are `include_str!`d by a test yet ci.yml's change detector classifies them \
         as docs, so a PR touching only them skips `just test`: {unguarded:?}\n\
         Add each to the detector's exceptions arm (`… ) code=true ;;`, ahead of the docs arm) \
         in .github/workflows/ci.yml."
    );
}

/// The documented opt-out and the MSI / .deb / .rpm formats are honoured only
/// if both updater commands ask `update_gate` BEFORE they touch the updater
/// plugin — `app.updater()` is the first step towards the release endpoint.
/// The gate was once documented but never read by either command.
#[test]
fn updater_commands_consult_the_update_gate_before_the_network() {
    let commands = super::sources::commands();
    for name in ["check_for_update", "perform_update"] {
        let cmd = commands.iter().find(|c| c.name == name).unwrap_or_else(|| {
            panic!(
                "updater command `{name}` not found under src/commands — renamed? Update this \
                     rule rather than letting it pass vacuously"
            )
        });
        let gate = cmd.body.find("update_gate(").unwrap_or_else(|| {
            panic!(
                "`{name}` ({}) never calls `update_gate()`: the auto-update opt-out and the \
                 MSI/.deb gate would be ignored",
                cmd.module
            )
        });
        let network = cmd.body.find(".updater()").unwrap_or_else(|| {
            panic!(
                "`{name}` ({}) no longer calls `.updater()` — the scan cannot place the gate",
                cmd.module
            )
        });
        assert!(
            gate < network,
            "`{name}` ({}) reaches `.updater()` before `update_gate()`: an opted-out or \
             externally managed install would still contact the release endpoint",
            cmd.module
        );
    }
}

/// Auto-update is interactive (AGENTS.md): only the UpdateSplash's click
/// handler may install. A launch-time `perform_update` — or a second installer
/// path in the backend — would reintroduce the silent install.
#[test]
fn only_the_update_splash_installs_an_update() {
    let callers: Vec<String> = super::sources::web_modules()
        .into_iter()
        .filter(|(path, src)| path != "bindings/updater.rs" && src.contains("perform_update("))
        .map(|(path, _)| path)
        .collect();
    assert_eq!(
        callers,
        vec!["components/update_splash.rs".to_string()],
        "only the UpdateSplash may call `perform_update`: any other caller can install \
         without the operator's click"
    );
    let splash = super::sources::web_modules()
        .into_iter()
        .find(|(path, _)| path == "components/update_splash.rs")
        .map(|(_, src)| src)
        .expect("update_splash.rs");
    let handler = splash.find("let do_update").expect(
        "UpdateSplash no longer defines `do_update` — renamed? Update this rule rather than \
         letting it pass vacuously",
    );
    let call = splash.find("updater::perform_update(").expect(
        "UpdateSplash no longer calls `updater::perform_update(` — renamed? Update this rule \
         rather than letting it pass vacuously",
    );
    assert!(
        handler < call,
        "`perform_update` must be called from inside the `do_update` click handler"
    );
    assert!(
        splash.contains("on_click=Box::new(do_update)"),
        "`do_update` must be the Update button's click handler, not run on mount"
    );

    let installers: Vec<String> = super::sources::commands()
        .into_iter()
        .filter(|c| c.body.contains("download_and_install"))
        .map(|c| c.name.to_string())
        .collect();
    assert_eq!(
        installers,
        vec!["perform_update".to_string()],
        "only the `perform_update` command may download and install an update"
    );
    let total: usize = super::sources::command_modules()
        .iter()
        .map(|(_, src)| src.matches(".download_and_install(").count())
        .sum();
    assert_eq!(
        total, 1,
        "exactly one `.download_and_install(` may exist under src/commands (in `perform_update`)"
    );
}

/// glibc symbol versions bind to the BUILD host's libc, so the Linux release
/// runner IS the oldest distro the AppImage/.deb can start on. A floating
/// `ubuntu-latest` silently raised the floor to glibc 2.38; the pin, the
/// guard's floor and the README's stated floor must move together.
#[test]
fn the_linux_release_leg_is_pinned_to_its_glibc_floor() {
    let release = include_str!("../../../../../.github/workflows/release.yml");
    assert!(
        release.contains("- os: ubuntu-22.04"),
        "release.yml's Linux matrix leg must build on ubuntu-22.04 (glibc 2.35), the floor the \
         README documents"
    );
    assert!(
        !release.contains("- os: ubuntu-latest"),
        "a release matrix leg builds on floating ubuntu-latest: its glibc floor moves with \
         GitHub's runner image"
    );
    assert!(
        release.contains("GLIBC_FLOOR: \"2.35\""),
        "release.yml lost the objdump guard that fails a build needing glibc newer than 2.35"
    );
    let readme = include_str!("../../../../../README.md");
    assert!(
        readme.contains("glibc 2.35"),
        "README no longer states the Linux glibc floor (2.35) the release leg is pinned to"
    );
}

/// Tauri's default NSIS `installMode` is `currentUser`: per-user, no prompt, no
/// admin rights — what the README and release body promise, and what keeps the
/// passive `/P /UPDATE` relaunch UAC-free. Parsed, not string-matched:
/// `plugins.updater.windows.installMode` is an unrelated key of the same name.
#[test]
fn nsis_install_mode_stays_current_user() {
    for (file, src) in [
        ("tauri.conf.json", include_str!("../../tauri.conf.json")),
        (
            "updater-build.json",
            include_str!("../../updater-build.json"),
        ),
    ] {
        let conf: serde_json::Value =
            serde_json::from_str(src).unwrap_or_else(|e| panic!("{file} is not JSON: {e}"));
        let mode = &conf["bundle"]["windows"]["nsis"]["installMode"];
        assert!(
            mode.is_null() || mode == "currentUser",
            "{file} sets bundle.windows.nsis.installMode = {mode}; keep Tauri's default \
             `currentUser` (per-user, no admin, UAC-free passive updates)"
        );
    }
}
