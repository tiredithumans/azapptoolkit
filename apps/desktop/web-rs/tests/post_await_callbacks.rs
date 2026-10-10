//! Pins the post-await contract: inside a `spawn_local` task, after the first
//! `.await`, a `.run(` must be `.try_run(` and a signal read must be its
//! `try_` twin (`try_get_untracked`, `try_with`, …). An `is_disposed()` return
//! is for the reads a textual scan cannot see — a replay (`do_run()`) that
//! reads signals inside — and does not excuse a plain read after it.
//!
//! A spawned task outlives the component that started it — sign-out unmounts
//! the whole authed shell, and closing a pane disposes its tab — and
//! `Callback::run` on a disposed callback panics the window, as do `get`,
//! `get_untracked`, `with` and `read` on a disposed signal, while the `try_`
//! forms skip or return `None`. Before the await, the component is provably
//! alive (the click handler is running in it); after it, nothing is. The
//! `on_ok` / `on_err` closures handed to `CommandState::run*` are guarded
//! centrally by `CommandState::land`, so these scans cover the hand-spawned
//! tasks only. See `docs/architecture/frontend-workspace.md`.
//!
//! The scans are textual, so a receiver whose `.run(` is a plain method rather
//! than a `Callback` is listed in [`NOT_CALLBACKS`] with its reason, and a
//! receiver whose `.get(` is not a signal (a `HashMap`) in [`NOT_SIGNALS`].
//! A replay that reads signals indirectly (`do_run()` after a consent round
//! trip) is beyond a textual scan: gate it on `is_disposed()` and
//! `is_active_tenant` by hand.
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
    "AuditController::run, a method on a Copy handle whose signals SecurityView owns; its one \
     post-await call (grant_reports_consent) is gated on is_disposed and is_active_tenant",
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

/// `(path suffix, receiver, reason)` triples whose post-await `.get(` is a
/// plain collection, not a signal.
const NOT_SIGNALS: &[(&str, &str, &str)] = &[
    (
        "views/tabs/credentials_tab.rs",
        "app_vaults",
        "a HashMap on the TenantDefaults value the task itself owns",
    ),
    (
        "views/tabs/owners_tab.rs",
        "names",
        "a HashMap of principal names the task built before its await",
    ),
];

/// The signal (and `StoredValue`) accesses that panic once disposed; each has
/// a `try_` twin. `.set(`, `.update(`, `.set_value(` and `.update_value(` are
/// silent no-ops on a disposed handle, so they are not listed.
const DISPOSABLE_READS: &[&str] = &[
    ".get(",
    ".get_untracked(",
    ".with(",
    ".with_untracked(",
    ".read(",
    ".read_untracked(",
    ".write(",
    ".write_untracked(",
    ".update_untracked(",
    ".get_value(",
    ".with_value(",
];

/// `(line, receiver)` of every `<receiver><needle>` that follows the first
/// `.await` inside a `spawn_local(async move { … })` block.
fn post_await_calls(src: &str, needle: &str) -> Vec<(usize, String)> {
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
            while let Some(k) = tail[search..].find(needle) {
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
                search = dot + needle.len();
            }
        }
        from = start;
    }
    out
}

/// `(line, receiver)` of every `<receiver>.run(` after the first await.
fn post_await_runs(src: &str) -> Vec<(usize, String)> {
    post_await_calls(src, ".run(")
}

/// `(line, receiver, read)` of every panicking signal read after the first
/// await, in source order.
fn post_await_reads(src: &str) -> Vec<(usize, String, &'static str)> {
    let mut out: Vec<(usize, String, &'static str)> = DISPOSABLE_READS
        .iter()
        .flat_map(|needle| {
            post_await_calls(src, needle)
                .into_iter()
                .map(move |(line, receiver)| (line, receiver, *needle))
        })
        .collect();
    out.sort_by_key(|(line, _, _)| *line);
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
fn spawned_tasks_never_read_a_signal_after_an_await() {
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
        for (line, receiver, read) in post_await_reads(&src) {
            let allowed = NOT_SIGNALS
                .iter()
                .any(|(suffix, r, _)| rel.ends_with(suffix) && *r == receiver);
            if !allowed {
                offenders.push(format!(
                    "src/{rel}:{line}: `{receiver}{read}` after an await"
                ));
            }
        }
    }
    assert!(
        tasks > 20,
        "found only {tasks} spawn_local tasks — has the shape changed?"
    );
    assert!(
        offenders.is_empty(),
        "a spawned task outlives its component, and a read of a disposed signal panics the \
         window; use the `try_` form after an await (an `is_disposed()` return gates only the \
         reads inside a replay this scan cannot see):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_read_scanner_reads_the_shapes_the_tree_uses() {
    let reads = |src: &str| -> Vec<(String, &'static str)> {
        post_await_reads(&strip_line_comments(src))
            .into_iter()
            .map(|(_, r, n)| (r, n))
            .collect()
    };
    // Flagged: each panicking read after the await, with its receiver.
    assert_eq!(
        reads(
            "spawn_local(async move {\n    x().await;\n    if busy.get_untracked() { return; }\n    rows.with(|r| r.len());\n});"
        ),
        [
            ("busy".to_string(), ".get_untracked("),
            ("rows".to_string(), ".with(")
        ]
    );
    // A chained receiver reports its last segment, split across lines or not.
    assert_eq!(
        reads(
            "spawn_local(async move {\n    x().await;\n    self.scanning\n        .get_untracked();\n});"
        ),
        [("scanning".to_string(), ".get_untracked(")]
    );
    // Not flagged: the `try_` twins, a read before the await, a `.set(`.
    assert!(
        reads("spawn_local(async move {\n    let b = busy.get();\n    x().await;\n    let _ = busy.try_get_untracked();\n    rows.try_with(|r| r.len());\n    busy.set(false);\n});")
            .is_empty()
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
