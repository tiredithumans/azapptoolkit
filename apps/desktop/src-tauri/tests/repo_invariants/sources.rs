//! The command layer as data: every module, and every `#[tauri::command]`
//! body, read from the source tree at test time.
//!
//! Replaces the three hand-maintained `include_str!` tables the fan-out, cancel
//! and command rules each kept. Those tables were the reason a 7 822-insertion
//! PR could add a tenant-wide writer with no cancellation and still pass CI:
//! `SEQUENTIAL_WRITE_MODULES` held exactly one entry, so the rule only ever
//! looked at the file it was written against. A list you must remember to
//! extend is not a ratchet.
//!
//! The old tables justified themselves with "a test binary has no reliable
//! source-tree walk", which was never true here — `commands.rs`'s Callout rule
//! has always walked `web-rs/src` from `CARGO_MANIFEST_DIR`, and a `cargo test`
//! run always has the source tree. Same mechanism, applied to `src/commands`.

use std::path::{Path, PathBuf};

/// `apps/desktop/src-tauri/src/commands`.
fn commands_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands")
}

/// Drops everything from the first `#[cfg(test)]` onward.
///
/// Fixtures legitimately call the fan-out drivers and mutation helpers without
/// being commands, so scanning them produces findings against test code. The
/// driver's OWN unit tests were the first false positives the source walk
/// surfaced — four `dispatch_capped` call sites in `commands/dispatch.rs`.
pub(crate) fn strip_tests(src: &str) -> &str {
    src.split("#[cfg(test)]").next().unwrap_or(src)
}

/// Every `.rs` file under `src/commands`, as (repo-relative-ish name, source),
/// with test modules stripped.
///
/// Sorted, so failure messages are stable run to run.
pub(crate) fn command_modules() -> Vec<(String, String)> {
    let root = commands_root();
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            // A sibling `tests.rs` is the body of a `#[cfg(test)] mod tests;` —
            // test code with no marker of its own for `strip_tests` to cut at,
            // so it is skipped by name (the fixtures inside call the fan-out
            // drivers and mutation helpers without being commands).
            if path.file_name().is_some_and(|f| f == "tests.rs") {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&path) else {
                continue;
            };
            let name = format!(
                "commands/{}",
                path.strip_prefix(&root).unwrap_or(&path).display()
            );
            out.push((name.replace('\\', "/"), strip_tests(&src).to_string()));
        }
    }
    assert!(
        out.len() > 20,
        "walked {} command modules from {} — the source-tree walk is broken, and a rule that \
         scans nothing passes vacuously",
        out.len(),
        root.display()
    );
    out.sort();
    out
}

/// One `#[tauri::command]` handler: its name and its **own** body.
pub(crate) struct Command {
    pub(crate) module: String,
    pub(crate) name: String,
    /// Brace-balanced function body, `{` to matching `}`.
    pub(crate) body: String,
}

/// Extracts the brace-balanced block starting at the first `{` at or after
/// `from`. Skips string literals and `//` comments so a brace inside either
/// cannot unbalance the scan (same reasoning as `fanout::call_sites`; char
/// literals are deliberately not tracked because `'` also opens a lifetime).
fn balanced_block(src: &str, from: usize) -> Option<String> {
    let bytes = src.as_bytes();
    let open = src[from..].find('{')? + from;
    let (mut depth, mut i) = (0usize, open);
    let (mut in_str, mut in_line_comment) = (false, false);
    while i < bytes.len() {
        let c = bytes[i];
        if in_line_comment {
            if c == b'\n' {
                in_line_comment = false;
            }
        } else if in_str {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                in_str = false;
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            in_line_comment = true;
        } else if c == b'{' {
            depth += 1;
        } else if c == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(src[open..=i].to_string());
            }
        }
        i += 1;
    }
    None
}

/// Every `#[tauri::command]` in the command layer, each with its own body.
///
/// The rules that came before this split on `"#[tauri::command]"` and treated
/// everything up to the next attribute as "the body". That is wrong whenever a
/// command is followed by private helpers — which is the normal shape here — so
/// a command inherited every string in the helpers below it. Two of the three
/// commands the tenant-wide-writer rule first appeared to flag were this
/// artifact, not real findings, and the same bleed makes the rules silently
/// *lenient*: a command with no cancel check passes because an unrelated helper
/// 200 lines later happens to mention one.
pub(crate) fn commands() -> Vec<Command> {
    let mut out = Vec::new();
    for (module, src) in command_modules() {
        let mut from = 0usize;
        while let Some(hit) = src[from..].find("#[tauri::command]") {
            let at = from + hit;
            from = at + "#[tauri::command]".len();
            // Skip any further attributes, then read `fn <name>`.
            let Some(fn_at) = src[from..].find("fn ") else {
                continue;
            };
            let fn_at = from + fn_at;
            // Nothing but attributes/whitespace/`pub`/`async` may sit between.
            let between = &src[from..fn_at];
            if between.contains('}') || between.contains(';') {
                continue;
            }
            let rest = &src[fn_at + 3..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            // Start the body scan after the parameter list, so a default value
            // containing `{` cannot be mistaken for the body.
            let Some(params_end) = balanced_paren_end(&src, fn_at) else {
                continue;
            };
            let Some(body) = balanced_block(&src, params_end) else {
                continue;
            };
            from = params_end + body.len();
            out.push(Command {
                module: module.clone(),
                name,
                body,
            });
        }
    }
    assert!(
        out.len() > 100,
        "found only {} #[tauri::command] handlers — the extractor is broken",
        out.len()
    );
    out
}

/// Index just past the `)` closing the parameter list that starts at or after
/// `from`.
fn balanced_paren_end(src: &str, from: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let open = src[from..].find('(')? + from;
    let (mut depth, mut i) = (0usize, open);
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// The heads and bodies of every `for`/`while` loop in `src`.
pub(crate) fn loops(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(hit) = find_loop_keyword(&src[from..]) {
        let at = from + hit.0;
        let kw_end = at + hit.1;
        from = kw_end;
        // The head runs to the `{` that opens the body; a `{` cannot appear in
        // a loop head except inside a closure, which `balanced_block` handles
        // by counting depth from the first brace anyway.
        let Some(brace) = src[kw_end..].find('{') else {
            continue;
        };
        let head = src[kw_end..kw_end + brace].trim().to_string();
        let Some(block) = balanced_block(src, kw_end) else {
            continue;
        };
        from = kw_end + brace + block.len();
        out.push((head, block));
    }
    out
}

/// Offset and length of the next `for `/`while ` keyword that is a real
/// statement (preceded by a non-identifier character).
fn find_loop_keyword(src: &str) -> Option<(usize, usize)> {
    let bytes = src.as_bytes();
    let mut best: Option<(usize, usize)> = None;
    for (kw, len) in [("for ", 4usize), ("while ", 6)] {
        let mut from = 0usize;
        while let Some(hit) = src[from..].find(kw) {
            let at = from + hit;
            from = at + len;
            let ok = at == 0 || {
                let p = bytes[at - 1];
                !(p.is_ascii_alphanumeric() || p == b'_')
            };
            if ok && best.is_none_or(|(b, _)| at < b) {
                best = Some((at, len));
                break;
            }
            if ok {
                break;
            }
        }
    }
    best
}
