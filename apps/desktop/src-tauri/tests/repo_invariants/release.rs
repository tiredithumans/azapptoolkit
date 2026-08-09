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
