//! Pins `styles.css` to what the frontend actually renders.
//!
//! The stylesheet is one global sheet of ~4.3k lines with no tooling that
//! notices an unused rule. Dead rules accumulate silently: the Cmd/Ctrl-K
//! command palette outlived its component by ~45 lines (focus reset included),
//! and a finished `.ui-kbd` key-chip rule sat unused while the shortcuts sheet
//! styled a bare `<kbd>` with a token that was never defined. An undefined
//! custom property is worse than dead: `var(--missing)` is invalid at computed
//! value time, so the declaration falls back to `transparent` / `initial` and
//! the element quietly loses its fill.
//!
//! Two scans hold the line:
//! - every class selector in `styles.css` is rendered somewhere in `src/` (or
//!   `index.html`), is a Thaw class we only override, or is a modifier built
//!   by `format!("{base}--{…}")`;
//! - every `var(--token)` used in `styles.css` is declared in `styles.css`
//!   (strict: a fallback does not excuse an undefined token).
//!
//! Runs natively under `just web-test` (no WASM, no browser); gated off for
//! wasm32 like `demo_fixture_coverage.rs`, because it reads the filesystem.
//! See `docs/architecture/frontend-workspace.md`.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// Class prefixes a third-party component renders. Thaw renders these, we only
/// override them, so they never appear in our own source.
const THIRD_PARTY_PREFIXES: &[&str] = &["thaw-"];

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn stylesheet() -> String {
    read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("styles.css"))
}

/// Removes every `/* … */` comment, so a class or token a comment mentions is
/// not read as a selector or a use.
fn strip_css_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start + 2..].find("*/") {
            Some(end) => rest = &rest[start + 2 + end + 2..],
            None => {
                rest = "";
                break;
            }
        }
    }
    out.push_str(rest);
    out
}

fn is_class_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Every class name in a selector position: for each `{`, the text since the
/// previous `{`, `}` or `;` is a rule prelude; an at-rule prelude (`@media`,
/// `@supports`, `@keyframes`) is skipped, and in a selector prelude every `.`
/// followed by a letter starts a class name. Declaration values never reach
/// the scan, and a dot after a digit (`0.5`) is not a class.
fn class_selectors(css: &str) -> BTreeSet<String> {
    let css = strip_css_comments(css);
    let mut out = BTreeSet::new();
    let mut prelude_start = 0usize;
    for (i, c) in css.char_indices() {
        match c {
            '{' => {
                let prelude = &css[prelude_start..i];
                if !prelude.trim_start().starts_with('@') {
                    collect_classes(prelude, &mut out);
                }
                prelude_start = i + 1;
            }
            '}' | ';' => prelude_start = i + 1,
            _ => {}
        }
    }
    out
}

fn collect_classes(selector: &str, out: &mut BTreeSet<String>) {
    let chars: Vec<char> = selector.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let after_digit = i > 0 && chars[i - 1].is_ascii_digit();
        if chars[i] == '.'
            && !after_digit
            && chars.get(i + 1).is_some_and(|c| c.is_ascii_alphabetic())
        {
            let mut j = i + 1;
            while j < chars.len() && is_class_char(chars[j]) {
                j += 1;
            }
            out.insert(chars[i + 1..j].iter().collect());
            i = j;
        } else {
            i += 1;
        }
    }
}

/// Every `--name` used through `var(--name`.
fn used_tokens(css: &str) -> BTreeSet<String> {
    let css = strip_css_comments(css);
    let mut out = BTreeSet::new();
    let mut rest = css.as_str();
    while let Some(at) = rest.find("var(--") {
        let tail = &rest[at + "var(".len()..];
        let end = tail.find(|c: char| !is_class_char(c)).unwrap_or(tail.len());
        out.insert(tail[..end].to_string());
        rest = &tail[end..];
    }
    out
}

/// Every `--name` declared as `--name:`.
fn defined_tokens(css: &str) -> BTreeSet<String> {
    let css = strip_css_comments(css);
    let mut out = BTreeSet::new();
    let mut rest = css.as_str();
    while let Some(at) = rest.find("--") {
        let tail = &rest[at..];
        let end = tail.find(|c: char| !is_class_char(c)).unwrap_or(tail.len());
        let preceded_by_name_char = rest[..at].chars().next_back().is_some_and(is_class_char);
        if !preceded_by_name_char && tail[end..].trim_start().starts_with(':') {
            out.insert(tail[..end].to_string());
        }
        rest = &tail[end.max(2)..];
    }
    out
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display())) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Drops whole-line `//` comments (doc comments included), so a comment that
/// names a class does not keep its rule alive.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The frontend source (`src/**/*.rs` + `index.html`), comment-stripped and
/// joined, plus its maximal `[A-Za-z0-9_-]` runs.
fn source_tokens() -> (String, HashSet<String>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();
    files.push(root.join("index.html"));

    let mut joined = String::new();
    for file in &files {
        joined.push_str(&strip_line_comments(&read(file)));
        joined.push('\n');
    }
    let tokens = joined
        .split(|c: char| !is_class_char(c))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();
    (joined, tokens)
}

#[test]
fn every_class_selector_is_rendered_by_the_frontend() {
    let selectors = class_selectors(&stylesheet());
    assert!(
        selectors.len() > 300,
        "extracted only {} class selectors from styles.css — the extractor is broken, and a \
         rule that scans nothing passes vacuously",
        selectors.len()
    );

    let (joined, tokens) = source_tokens();
    let offenders: Vec<&String> = selectors
        .iter()
        .filter(|class| {
            let rendered = tokens.contains(class.as_str());
            let third_party = THIRD_PARTY_PREFIXES.iter().any(|p| class.starts_with(p));
            let built_modifier = class
                .rsplit_once("--")
                .is_some_and(|(base, _)| joined.contains(&format!("{base}--{{")));
            !(rendered || third_party || built_modifier)
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "styles.css has class selectors that nothing in web-rs/src or index.html renders — \
         delete the rule, or render the class (a `format!(\"{{base}}--{{…}}\")` modifier and \
         the `thaw-*` overrides are recognised):\n  {}",
        offenders
            .iter()
            .map(|c| format!(".{c}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[test]
fn every_custom_property_used_is_defined() {
    let css = stylesheet();
    let used = used_tokens(&css);
    assert!(
        used.len() > 20,
        "found only {} `var(--…)` uses in styles.css — the scan is broken, and a rule that \
         scans nothing passes vacuously",
        used.len()
    );
    let defined = defined_tokens(&css);
    let undefined: Vec<&String> = used.difference(&defined).collect();
    assert!(
        undefined.is_empty(),
        "styles.css uses custom properties it never declares (an undefined token renders \
         transparent/initial, and a fallback only hides the gap) — use a defined token or \
         declare it in :root and the dark theme:\n  {}",
        undefined
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[test]
fn extractor_ignores_a_class_inside_a_comment() {
    let classes = class_selectors("/* .ghost { color: red; } */\n.live { color: red; }\n");
    assert_eq!(classes, BTreeSet::from(["live".to_string()]));
}

#[test]
fn extractor_finds_a_rule_nested_in_a_media_query() {
    let css = "@media (max-width: 640px) {\n  .a,\n  .b .c:hover {\n    margin: 0;\n  }\n}\n";
    let classes = class_selectors(css);
    assert_eq!(
        classes,
        BTreeSet::from(["a".to_string(), "b".to_string(), "c".to_string()])
    );
}

#[test]
fn extractor_reads_no_class_from_a_decimal_value() {
    let css = ".box {\n  padding: 0.5rem;\n  line-height: 1.2;\n  opacity: .8;\n}\n";
    assert_eq!(class_selectors(css), BTreeSet::from(["box".to_string()]));
}

#[test]
fn token_scan_pairs_uses_with_declarations() {
    let css = ":root {\n  --a: 1px;\n  --b-c: red;\n}\n.x {\n  margin: var(--a);\n  color: var(--missing, var(--b-c));\n}\n";
    assert_eq!(
        used_tokens(css),
        BTreeSet::from([
            "--a".to_string(),
            "--b-c".to_string(),
            "--missing".to_string()
        ])
    );
    assert_eq!(
        defined_tokens(css),
        BTreeSet::from(["--a".to_string(), "--b-c".to_string()])
    );
}
