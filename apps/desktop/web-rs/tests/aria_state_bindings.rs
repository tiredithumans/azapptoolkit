//! Pins the ARIA-state string contract: every `true`/`false` ARIA state
//! (`aria-expanded`, `aria-selected`, `aria-pressed`, `aria-checked`, …) that is
//! bound to an expression must produce a *string*, never a bare `bool`.
//!
//! Leptos renders a `bool` attribute as an HTML boolean attribute, so
//! `aria-expanded=move || open.get()` emits `aria-expanded=""` when open and no
//! attribute at all when closed, and neither is a valid ARIA value: a screen
//! reader hears no state. The bug recurred after three separate fixes and three
//! warning comments, so this scan holds the line instead of the comments. See
//! `docs/architecture/frontend-workspace.md`.
//!
//! A binding passes when its expression yields a string: `.to_string()`,
//! `format!`, or a string literal in a value position (`"true"` / `"false"`,
//! `then_some("page")`, `Some("…")`, a block or match arm ending in one) —
//! never a literal that is only compared against (`x.get() == "a"`).
//! A bare identifier (`aria-selected=aria_selected`) is resolved to the nearest
//! preceding `let <ident> = …;` in the same file. Token-valued attributes such
//! as `aria-sort` are out of scope.
//!
//! Runs natively under `just web-test` (no WASM, no browser); gated off for
//! wasm32 like `demo_fixture_coverage.rs`, because it reads the filesystem.

#![cfg(not(target_arch = "wasm32"))]

use std::fs;
use std::path::{Path, PathBuf};

/// The ARIA states whose only valid values are strings like `"true"` /
/// `"false"` (or a token string, for `aria-current` / `aria-invalid`), and
/// which a bare `bool` therefore corrupts.
const STATES: &[&str] = &[
    "expanded",
    "selected",
    "pressed",
    "checked",
    "hidden",
    "disabled",
    "busy",
    "modal",
    "invalid",
    "required",
    "readonly",
    "current",
    "multiselectable",
    "atomic",
];

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Drops whole-line `//` comments and cuts a trailing ` //` comment, so the
/// warning comments that quote the bad form (`aria-…=move || x.get()`) are not
/// read as bindings. Newlines are kept.
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

/// The expression starting at `from`: up to the first newline (or, with
/// `until_semicolon`, the first `;`) at bracket depth 0, skipping string
/// literals. A line that ends in `{` therefore continues through its block.
fn expression_at(src: &str, from: usize, until_semicolon: bool) -> &str {
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    let mut i = from;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth < 0 {
                    break;
                }
            }
            b'\n' if depth == 0 && !until_semicolon => break,
            b';' if depth == 0 && until_semicolon => break,
            _ => {}
        }
        i += 1;
    }
    src[from..i.min(bytes.len())].trim()
}

/// The initializer of the nearest `let <ident> = …;` before `before`.
fn resolve_let<'a>(src: &'a str, ident: &str, before: usize) -> Option<&'a str> {
    let needle = format!("let {ident} =");
    let at = src[..before].rfind(&needle)?;
    Some(expression_at(src, at + needle.len(), true))
}

/// Whether `expr` *yields* a string. A string literal counts only in a value
/// position — `"true"` / `"false"`, `then_some("…")`, `Some("…")`, a block or
/// match arm that evaluates to one — never as a comparison operand:
/// `aria-pressed=move || facet.get() == "all"` is still a bare `bool`.
fn is_string_valued(expr: &str) -> bool {
    const YIELDS_STRING: &[&str] = &[
        ".to_string()",
        "format!(",
        "\"true\"",
        "\"false\"",
        "then_some(\"",
        "Some(\"",
        "{ \"",
        "=> \"",
    ];
    let squashed: String = expr.split_whitespace().collect::<Vec<_>>().join(" ");
    YIELDS_STRING.iter().any(|form| squashed.contains(form))
}

/// Every non-literal boolean-ARIA-state binding in `src` (already
/// comment-stripped), as `(line, attribute, expression, passes)`.
fn bindings(src: &str) -> Vec<(usize, String, String, bool)> {
    let mut out = Vec::new();
    for state in STATES {
        let attr = format!("aria-{state}=");
        let mut from = 0;
        while let Some(rel) = src[from..].find(&attr) {
            let at = from + rel;
            from = at + attr.len();
            // `aria-expanded=` or `attr:aria-expanded=`, never the tail of a
            // longer name.
            if src[..at]
                .chars()
                .next_back()
                .is_some_and(|c| is_ident(c) || c == '-')
            {
                continue;
            }
            let rest = &src[from..];
            let value_at = from + (rest.len() - rest.trim_start_matches(' ').len());
            if src[value_at..].starts_with('"') {
                continue; // a literal: `aria-hidden="true"`
            }
            let line = src[..at].matches('\n').count() + 1;
            let expr = expression_at(src, value_at, false);
            let resolved = if !expr.is_empty() && expr.chars().all(is_ident) {
                resolve_let(src, expr, at).unwrap_or(expr)
            } else {
                expr
            };
            out.push((
                line,
                format!("aria-{state}"),
                expr.to_string(),
                is_string_valued(resolved),
            ));
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
fn boolean_aria_states_are_bound_to_strings() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();

    let mut scanned = 0usize;
    let mut offenders = Vec::new();
    for file in &files {
        let src = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()))
            .replace("\r\n", "\n");
        let src = strip_line_comments(&src);
        for (line, attr, expr, ok) in bindings(&src) {
            scanned += 1;
            if !ok {
                let rel = file.strip_prefix(&root).unwrap_or(file);
                offenders.push(format!("src/{}:{line}  {attr}={expr}", rel.display()));
            }
        }
    }

    assert!(
        scanned >= 10,
        "scanned only {scanned} non-literal ARIA state bindings across {} files — the walk or \
         the matcher is broken, and a rule that scans nothing passes vacuously",
        files.len()
    );
    assert!(
        offenders.is_empty(),
        "ARIA state bound to a bare bool (Leptos renders it as a boolean attribute: \
         `aria-…=\"\"` when true, absent when false — neither is a valid ARIA value; see \
         docs/architecture/frontend-workspace.md). Bind a string instead, e.g. \
         `aria-expanded=move || open.get().to_string()`:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn the_aria_scanner_reads_the_shapes_the_tree_uses() {
    let verdicts = |src: &str| -> Vec<bool> {
        bindings(&strip_line_comments(src))
            .into_iter()
            .map(|(_, _, _, ok)| ok)
            .collect()
    };

    // Rejected: bare bools, in each binding shape.
    assert_eq!(
        verdicts("<button\n    aria-expanded=move || open.get()\n>"),
        [false]
    );
    assert_eq!(
        verdicts("<Button\n    attr:aria-pressed=move || on.get()\n/>"),
        [false]
    );
    assert_eq!(
        verdicts("let a = move || sel.get() == v;\nview! {\n    <button aria-selected=a\n    >\n}"),
        [false]
    );
    // A string literal as a comparison operand is still a bare bool.
    assert_eq!(
        verdicts("<button\n    aria-pressed=move || x.get() == \"a\"\n>"),
        [false]
    );
    assert_eq!(
        verdicts("<button\n    aria-selected=move || facet.with(|f| f == \"all\")\n>"),
        [false]
    );

    // Accepted: strings, in each binding shape.
    assert_eq!(
        verdicts("<button\n    aria-expanded=move || open.get().to_string()\n>"),
        [true]
    );
    assert_eq!(
        verdicts(
            "<input\n    aria-invalid=move || {\n        matches!(x.get(), Some(_))\n            \
             .then_some(\"true\")\n    }\n/>"
        ),
        [true]
    );
    assert_eq!(
        verdicts("<b aria-pressed=move || if x { \"true\" } else { \"false\" }\n>"),
        [true]
    );
    assert_eq!(
        verdicts(
            "let a = {\n    let v = 1;\n    move || (sel.get() == v).to_string()\n};\n\
             <button aria-selected=a\n>"
        ),
        [true]
    );

    // Not bindings at all: literals and the commented-out bad form.
    assert!(verdicts("<span aria-hidden=\"true\"></span>").is_empty());
    assert!(verdicts("// aria-expanded=move || open.get()\n<b/>").is_empty());
    assert!(verdicts("<b/> // was: aria-expanded=move || open.get()").is_empty());
    // A longer attribute name is not the ARIA state.
    assert!(verdicts("<b data-aria-expanded=move || x.get()\n/>").is_empty());
}
