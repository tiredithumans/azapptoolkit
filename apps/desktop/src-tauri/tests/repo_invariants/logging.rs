//! Tracing macro syntax: `target:` sets the event target, `target =` does not.
//!
//! `tracing::debug!(target = "azapptoolkit::cache", ...)` compiles, but it falls
//! into the macros' field arm: the event gains a field *named* `target` while
//! its real target stays `module_path!()`. The intended filter
//! (`RUST_LOG=azapptoolkit::cache=debug`) then matches nothing, and the log
//! file's target column names the module rather than the component. Twelve call
//! sites carried the misspelling; this keeps it from coming back.

/// Macro openings whose next argument may be a target override.
const MACROS: [&str; 6] = [
    "trace!(", "debug!(", "info!(", "warn!(", "error!(", "event!(",
];

/// 1-based line numbers in `src` where a tracing macro's first argument is
/// `target = …` (a field) rather than `target: …` (the event target).
///
/// Leading whitespace after the paren is skipped, so rustfmt's multi-line form
/// (`debug!(` then `target = "…",` on the next line) is covered.
fn misspelled_target_at(src: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    for mac in MACROS {
        for (at, _) in src.match_indices(mac) {
            let rest = src[at + mac.len()..].trim_start();
            let Some(after) = rest.strip_prefix("target") else {
                continue;
            };
            let after = after.trim_start();
            if after.starts_with('=') && !after.starts_with("==") {
                lines.push(src[..at].matches('\n').count() + 1);
            }
        }
    }
    lines.sort_unstable();
    lines
}

#[test]
fn the_target_detector_sees_the_rustfmt_forms() {
    // Flagged: the multi-line rustfmt form and the one-liner.
    assert_eq!(
        misspelled_target_at(
            "fn f() {\n    tracing::debug!(\n        target = \"x\",\n        \"m\"\n    );\n}"
        ),
        vec![2]
    );
    assert_eq!(
        misspelled_target_at("debug!(target = \"x\", \"m\")"),
        vec![1]
    );
    // Passed: the real override, and an HTML attribute that is not right after
    // a macro paren (web-rs views carry `target="_blank"`).
    assert!(misspelled_target_at("tracing::debug!(target: \"x\", \"m\")").is_empty());
    assert!(misspelled_target_at("view! { <a target=\"_blank\" href=\"x\">\"y\"</a> }").is_empty());
    // A comparison is not a field.
    assert!(misspelled_target_at("assert!(debug!(target == x))").is_empty());
}

#[test]
fn tracing_targets_use_the_colon_form() {
    // apps/desktop/src-tauri → apps/desktop → apps → repo root.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("apps/desktop/src-tauri → repo root")
        .to_path_buf();

    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;
    let mut stack = vec![root.join("crates"), root.join("apps")];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // `target/` holds built copies of the very sources being checked.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            // This file spells the misspelling out in its self-test.
            if path.ends_with("repo_invariants/logging.rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            for line in misspelled_target_at(&src) {
                offenders.push(format!(
                    "{}:{line}",
                    path.strip_prefix(&root).unwrap_or(&path).display()
                ));
            }
        }
    }

    assert!(
        scanned > 100,
        "the walk found only {scanned} .rs files — the root is wrong and the rule passes vacuously"
    );
    assert!(
        offenders.is_empty(),
        "`target = \"…\"` inside a tracing macro records a FIELD named `target`; the \
         event target stays the module path, so a `RUST_LOG=<target>=…` filter matches \
         nothing. Write `target: \"…\"` instead:\n  {}",
        offenders.join("\n  ")
    );
}
