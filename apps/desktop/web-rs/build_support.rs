// Pure CHANGELOG parsing for `build.rs`, kept in its own file so it can be
// tested.
//
// A build script is compiled into no test target, so this parser had no
// coverage — while being one of TWO independent implementations of the same
// extraction (the other is PowerShell, in `release.yml`). The two are expected
// to produce identical text for a release; nothing checks that, so the least
// this side can do is pin its own edge cases.
//
// `include!`d by `build.rs` and mounted again under `#[cfg(test)]` by
// `src/lib.rs`, so the same source is both used and tested.

/// The body of `## [version]`, up to the next `## [` header. `None` when the
/// version has no section (or an empty one) — e.g. a local build whose manifest
/// version was bumped before the changelog was finalized.
fn section_for(changelog: &str, version: &str) -> Option<String> {
    // The closing bracket is part of the match, so `[0.2.4]` cannot hit
    // `[0.2.41]`.
    let header = format!("## [{version}]");
    let mut lines = changelog.lines().skip_while(|l| !l.starts_with(&header));
    lines.next()?; // the header itself
    let body = lines
        .take_while(|l| !l.starts_with("## ["))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    (!body.is_empty()).then_some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANGELOG: &str = "\
# Changelog

## [Unreleased]

- work in progress

## [0.2.41] - 2026-08-08

### Added

- the longer version's note

## [0.2.4] - 2026-08-01

### Fixed

- the shorter version's note

## [0.2.3] - 2026-07-01

- older
";

    #[test]
    fn a_shorter_version_does_not_match_a_longer_one() {
        // The whole reason the closing bracket is part of the header match.
        // Prefix matching would hand 0.2.4 the 0.2.41 notes, so the in-app
        // "What's new" would describe a release the user is not running.
        let body = section_for(CHANGELOG, "0.2.4").expect("0.2.4 has a section");
        assert!(body.contains("the shorter version's note"));
        assert!(
            !body.contains("the longer version's note"),
            "0.2.4 must not absorb 0.2.41's section"
        );

        let body = section_for(CHANGELOG, "0.2.41").expect("0.2.41 has a section");
        assert!(body.contains("the longer version's note"));
        assert!(!body.contains("the shorter version's note"));
    }

    #[test]
    fn a_section_stops_at_the_next_release_header() {
        let body = section_for(CHANGELOG, "0.2.4").expect("section");
        assert!(
            !body.contains("older"),
            "0.2.3's notes are a separate release"
        );
        assert!(body.starts_with("### Fixed"), "leading blank lines trimmed");
        assert!(body.ends_with("the shorter version's note"));
    }

    #[test]
    fn an_unknown_version_bakes_nothing() {
        // The documented degradation: the dialog falls back to a link out to
        // the changelog on GitHub rather than showing an empty panel.
        assert_eq!(section_for(CHANGELOG, "9.9.9"), None);
    }

    #[test]
    fn an_empty_section_is_treated_as_absent() {
        let text = "## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-12-01\n\n- note\n";
        assert_eq!(section_for(text, "1.0.0"), None);
        assert!(section_for(text, "0.9.0").is_some());
    }

    #[test]
    fn the_unreleased_section_is_addressable_like_any_other() {
        // Not a version a build bakes, but the same parser reads it, and a
        // regression here would silently change what a pre-release build shows.
        let body = section_for(CHANGELOG, "Unreleased").expect("Unreleased section");
        assert_eq!(body, "- work in progress");
    }

    #[test]
    fn the_repos_own_changelog_has_a_section_for_the_current_version() {
        // The bake is silent on failure by design, so without this a release
        // could ship with an empty "What's new" and nothing would say so.
        let changelog = include_str!("../../../CHANGELOG.md");
        let version = env!("CARGO_PKG_VERSION");
        assert!(
            section_for(changelog, version).is_some(),
            "CHANGELOG.md has no non-empty `## [{version}]` section, so this build \
             would bake empty release notes. Finalize the section before releasing."
        );
    }
}
