//! Pins the gradual move off Thaw: a Thaw component the app has replaced with
//! its own primitive is never imported from `thaw` again.
//!
//! Thaw (a pre-1.0 Fluent UI port) is being retired a few components at a
//! time; its last release is a beta, and the proc-macro chain it pins is what
//! keeps the `proc-macro-error2` future-incompat warning in every web-rs
//! build. Each replacement is a primitive in `components::ui` that renders the
//! same plain HTML element, so the GUI tests carry over. Once a component is
//! retired, a stray `use thaw::Spinner` would quietly bring back the Thaw
//! version beside ours, with its own runtime-injected stylesheet and markup
//! (see `docs/architecture/frontend-workspace.md`, "Moving off Thaw"). Add a
//! name to [`RETIRED`] in the change that retires it.
//!
//! The scan reads every `use thaw::…;` (single or brace group, across lines)
//! and every fully qualified `thaw::Name` path in `src/`, skipping comments so
//! a doc comment may name what it replaced.
//!
//! Runs natively under `just web-test` (no WASM, no browser); gated off for
//! wasm32 like `dialogs_use_modal_shell.rs`, because it reads the filesystem.

#![cfg(not(target_arch = "wasm32"))]

use std::fs;
use std::path::{Path, PathBuf};

/// Thaw items the app still imports (the retirement order is the business of
/// `docs/architecture/frontend-workspace.md`, "Moving off Thaw"). The ratchet
/// only ever shortens: a Thaw item outside this list and [`RETIRED`] is a new
/// dependency on the library being retired, so it fails; retiring one moves
/// it to [`RETIRED`]. The list is not capped by count, because the
/// one-primitive rule routes a new button onto `thaw::Button` until
/// `ui::Button` exists.
const STILL_ON_THAW: &[&str] = &[
    "Button",
    "ButtonAppearance",
    "ButtonRef",
    "Input",
    "InputSuffix",
    "Field",
    "Textarea",
    "Select",
    "ComponentRef",
    "ConfigProvider",
    "Theme",
];

/// Thaw items the app no longer uses, each with the primitive that replaced it.
const RETIRED: &[(&str, &str)] = &[
    ("Body1", "a <span class=\"ui-text …\">"),
    ("Card", "a plain element carrying the view's own class"),
    ("DatePicker", "components::ui::DateInput"),
    ("ProgressBar", "components::ui::ProgressBar"),
    ("Spinner", "components::ui::Spinner"),
    ("SpinnerSize", "nothing: ui::Spinner has one size"),
];

/// Drops whole-line `//` comments (doc comments included) and cuts a trailing
/// ` //` comment, keeping newlines so reported line numbers stay true.
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| {
            if line.trim_start().starts_with("//") {
                ""
            } else if let Some(i) = line.find(" //") {
                &line[..i]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Every item name taken from `thaw` in `src` (comment-stripped): the names in
/// each `use thaw::…;` and the first segment of each other `thaw::` path.
fn thaw_items(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find("thaw::") {
        let preceded_by_ident = rest[..at].chars().next_back().is_some_and(is_ident_char);
        let tail = &rest[at + "thaw::".len()..];
        if preceded_by_ident {
            rest = tail;
            continue;
        }
        if let Some(group) = tail.strip_prefix('{') {
            let end = group.find('}').unwrap_or(group.len());
            out.extend(
                group[..end]
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.split("::").next().unwrap_or(s).to_string()),
            );
            rest = &group[end..];
        } else {
            let end = tail.find(|c: char| !is_ident_char(c)).unwrap_or(tail.len());
            out.push(tail[..end].to_string());
            rest = &tail[end..];
        }
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

#[test]
fn no_retired_thaw_component_is_imported() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();

    let mut offenders = Vec::new();
    for file in &files {
        let src = strip_line_comments(&fs::read_to_string(file).expect("read source"));
        for item in thaw_items(&src) {
            if let Some((name, instead)) = RETIRED.iter().find(|(name, _)| *name == item) {
                offenders.push(format!(
                    "{}: thaw::{name} (use {instead})",
                    file.strip_prefix(root).unwrap_or(file).display()
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these files import a Thaw component the app has retired:\n  {}",
        offenders.join("\n  ")
    );
}

/// A Thaw item the app has not imported before is a step backwards: the set
/// of items still on Thaw only shrinks.
#[test]
fn no_new_thaw_item_is_imported() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    files.sort();

    let mut offenders = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for file in &files {
        let src = strip_line_comments(&fs::read_to_string(file).expect("read source"));
        for item in thaw_items(&src) {
            seen.insert(item.clone());
            let known = STILL_ON_THAW.contains(&item.as_str())
                || RETIRED.iter().any(|(name, _)| *name == item);
            if !known {
                offenders.push(format!(
                    "{}: thaw::{item}",
                    file.strip_prefix(root).unwrap_or(file).display()
                ));
            }
        }
    }
    assert!(
        seen.len() >= 5,
        "found only {seen:?} Thaw items — has the import shape changed?"
    );
    assert!(
        offenders.is_empty(),
        "these files import a Thaw item the app did not use before; build on a `components::ui` \
         primitive instead, or retire the item and move it to RETIRED:\n  {}",
        offenders.join("\n  ")
    );
    let stale: Vec<&&str> = STILL_ON_THAW
        .iter()
        .filter(|name| !seen.contains(**name))
        .collect();
    assert!(
        stale.is_empty(),
        "no file imports {stale:?} any more: move them to RETIRED so they stay retired"
    );
}

#[test]
fn reads_single_grouped_multiline_and_qualified_imports() {
    let src = "use thaw::Card;\nuse thaw::{\n    Body1, Spinner,\n    SpinnerSize,\n};\nlet t = thaw::Theme::light();\nuse mythaw::Card;\n";
    assert_eq!(
        thaw_items(src),
        ["Card", "Body1", "Spinner", "SpinnerSize", "Theme"]
    );
}

#[test]
fn a_comment_does_not_count() {
    let src = strip_line_comments("/// Replaces `thaw::Spinner`.\nlet x = 1; // was thaw::Card\n");
    assert!(thaw_items(&src).is_empty());
}
