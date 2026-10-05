//! Pins the post-await callback contract: inside a `spawn_local` task, a
//! `.run(` after the first `.await` must be `.try_run(`.
//!
//! A spawned task outlives the component that started it — sign-out unmounts
//! the whole authed shell, and closing a pane disposes its tab — and
//! `Callback::run` on a disposed callback panics the window, while
//! `Callback::try_run` skips it. Before the await, the component is provably
//! alive (the click handler is running in it); after it, nothing is. The
//! `on_ok` / `on_err` closures handed to `CommandState::run*` are guarded
//! centrally by `CommandState::land`, so this scan covers the hand-spawned
//! tasks only. See `docs/architecture/frontend-workspace.md`.
//!
//! The scan is textual, so a receiver whose `.run(` is a plain method rather
//! than a `Callback` is listed in [`NOT_CALLBACKS`] with its reason.
//!
//! Runs natively under `just web-test` (no WASM, no browser); gated off for
//! wasm32 like `aria_state_bindings.rs`, because it reads the filesystem.

#![cfg(not(target_arch = "wasm32"))]

use std::fs;
use std::path::{Path, PathBuf};

/// `(path suffix, receiver)` pairs whose post-await `.run(` is not a
/// `Callback`.
const NOT_CALLBACKS: &[(&str, &str, &str)] = &[(
    "views/audit_view/controller.rs",
    "self",
    "AuditController::run, a method on a Copy handle of session-owned signals",
)];

/// Drops whole-line `//` comments and cuts a trailing ` //` comment, keeping
/// newlines so reported line numbers stay true.
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

/// The byte index just past the `}` closing the block opened right before
/// `from`, skipping string and brace char literals.
fn block_end(src: &str, from: usize) -> usize {
    let bytes = src.as_bytes();
    let (mut depth, mut i) = (1i32, from);
    while i < bytes.len() && depth > 0 {
        match bytes[i] {
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    i += if bytes[i] == b'\\' { 2 } else { 1 };
                }
            }
            b'\'' if bytes.get(i + 2) == Some(&b'\'') => i += 2,
            b'{' => depth += 1,
            b'}' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    i
}

/// `(line, receiver)` of every `<receiver>.run(` that follows the first
/// `.await` inside a `spawn_local(async move { … })` block.
fn post_await_runs(src: &str) -> Vec<(usize, String)> {
    const OPEN: &str = "spawn_local(async move {";
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = src[from..].find(OPEN) {
        let start = from + at + OPEN.len();
        let end = block_end(src, start);
        let body = &src[start..end];
        if let Some(awaited) = body.find(".await") {
            let tail = &body[awaited..];
            let mut search = 0;
            while let Some(k) = tail[search..].find(".run(") {
                let dot = search + k;
                let receiver: String = tail[..dot]
                    .trim_end()
                    .chars()
                    .rev()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                let line = src[..start + awaited + dot].matches('\n').count() + 1;
                out.push((line, receiver));
                search = dot + ".run(".len();
            }
        }
        from = start;
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
fn spawned_tasks_never_run_a_callback_after_an_await() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();

    let mut tasks = 0usize;
    let mut offenders = Vec::new();
    for file in &files {
        let src = strip_line_comments(
            &fs::read_to_string(file)
                .unwrap_or_else(|e| panic!("read {}: {e}", file.display()))
                .replace("\r\n", "\n"),
        );
        tasks += src.matches("spawn_local(async move {").count();
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        for (line, receiver) in post_await_runs(&src) {
            let allowed = NOT_CALLBACKS
                .iter()
                .any(|(suffix, r, _)| rel.ends_with(suffix) && *r == receiver);
            if !allowed {
                offenders.push(format!(
                    "src/{rel}:{line}: `{receiver}.run(` after an await"
                ));
            }
        }
    }
    // A scan that silently matched nothing would pass forever.
    assert!(
        tasks > 20,
        "found only {tasks} spawn_local tasks — has the shape changed?"
    );
    assert!(
        offenders.is_empty(),
        "a spawned task outlives its component; use `.try_run(` after an await:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_scanner_reads_the_shapes_the_tree_uses() {
    let receivers = |src: &str| -> Vec<String> {
        post_await_runs(&strip_line_comments(src))
            .into_iter()
            .map(|(_, r)| r)
            .collect()
    };
    // Flagged: after the await, on one line or split across lines.
    assert_eq!(
        receivers("spawn_local(async move {\n    x().await;\n    on_done.run(());\n});"),
        ["on_done"]
    );
    assert_eq!(
        receivers(
            "spawn_local(async move {\n    x().await;\n    if let Some(cb) = f {\n        cb\n            .run(());\n    }\n});"
        ),
        ["cb"]
    );
    // Not flagged: before the await, `try_run`, a comment, after the block.
    assert!(receivers("spawn_local(async move {\n    cb.run(());\n    x().await;\n});").is_empty());
    assert!(
        receivers("spawn_local(async move {\n    x().await;\n    cb.try_run(());\n});").is_empty()
    );
    assert!(
        receivers("spawn_local(async move {\n    x().await;\n    // cb.run(());\n});").is_empty()
    );
    assert!(
        receivers("spawn_local(async move {\n    x(\"}\").await;\n});\ncb.run(());").is_empty()
    );
}
