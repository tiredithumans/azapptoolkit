//! The command layer as data: every module, every `#[tauri::command]` body and
//! every function body, read from the source tree at test time.
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

/// Blanks every `#[cfg(test)]` item — the attribute and the item it gates —
/// keeping the newlines, so line numbers in findings still point at the file.
///
/// Fixtures legitimately call the fan-out drivers and mutation helpers without
/// being commands, so scanning them produces findings against test code. The
/// driver's OWN unit tests were the first false positives the source walk
/// surfaced — four `dispatch_capped` call sites in `commands/dispatch.rs`.
///
/// This used to be `src.split("#[cfg(test)]").next()`: everything from the
/// first occurrence of that TEXT onward. A doc comment mentioning the attribute
/// (`applications/cache.rs` has one) silently hid the rest of the file from
/// every rule, and a real `#[cfg(test)]` on one helper `fn` hid every production
/// item after it. Now only a real attribute counts — a code line whose trimmed
/// text starts with it, outside any comment or string — and only the item it
/// gates is dropped.
pub(crate) fn strip_tests(src: &str) -> String {
    // `all(test, …)` is test-only; `any(test, …)` is NOT, so it stays.
    const ATTRS: [&str; 3] = ["#[cfg(test)]", "#[cfg(all(test,", "#[cfg(all(test)"];
    let code = code_mask(src);
    let mut drop: Vec<(usize, usize)> = Vec::new();
    let mut line_start = 0usize;
    for line in src.split_inclusive('\n') {
        let indent = line.len() - line.trim_start().len();
        let at = line_start + indent;
        line_start += line.len();
        let trimmed = line.trim_start();
        if !ATTRS.iter().any(|a| trimmed.starts_with(a)) || !code[at] {
            continue;
        }
        if drop.last().is_some_and(|&(_, end)| at < end) {
            continue; // inside an item already dropped
        }
        drop.push((at, gated_item_end(src, &code, at)));
    }
    let mut out = String::with_capacity(src.len());
    for (i, c) in src.char_indices() {
        if c == '\n' || !drop.iter().any(|&(a, b)| (a..b).contains(&i)) {
            out.push(c);
        }
    }
    out
}

/// The end (exclusive) of the item gated by the attribute at `at`, which may
/// be an item, a field, a variant, a match arm, a parameter or a statement.
///
/// It ends at the first depth-0 `;` or `,` (included), at the `}` that closes
/// its own first block (`mod tests { … }`, a `fn`), or just before a closer
/// that would close the ENCLOSING scope (a last field, arm or parameter with
/// no trailing comma). Without the last two, a gated struct field
/// (`#[cfg(test)] expired_sweeps: u64,`) ran on through the rest of the file.
/// `<…>` counts as nesting only at depth 0, and only where it opens generics
/// (straight after an identifier, `:` or `&`), so `HashMap<K, V>` or
/// `fn f<A, B>` does not end the item at its comma while `a < b` and `->`
/// stay comparisons and arrows.
fn gated_item_end(src: &str, code: &[bool], at: usize) -> usize {
    let bytes = src.as_bytes();
    let (mut depth, mut angle) = (0i32, 0i32);
    for i in at + 1..bytes.len() {
        if !code[i] {
            continue;
        }
        match bytes[i] {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return i,
            b')' | b']' => depth -= 1,
            b'}' => {
                depth -= 1;
                if depth == 0 && angle == 0 {
                    return i + 1;
                }
            }
            b'<' if depth == 0
                && i > 0
                && (bytes[i - 1].is_ascii_alphanumeric()
                    || matches!(bytes[i - 1], b'_' | b':' | b'&')) =>
            {
                angle += 1;
            }
            b'>' if depth == 0 && angle > 0 && !matches!(bytes[i - 1], b'-' | b'=') => angle -= 1,
            b';' | b',' if depth == 0 && angle == 0 => return i + 1,
            _ => {}
        }
    }
    src.len()
}

/// For each byte of `src`, whether it is code: not inside a `//` or `/* */`
/// comment, a string (plain, byte or raw) or a char literal.
pub(crate) fn code_mask(src: &str) -> Vec<bool> {
    let b = src.as_bytes();
    let ident = |i: usize| b[i].is_ascii_alphanumeric() || b[i] == b'_';
    let mut mask = vec![true; b.len()];
    let mut i = 0usize;
    while i < b.len() {
        let start = i;
        if b[i] == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if b[i] == b'r'
            && (i == 0 || !ident(i - 1) || (b[i - 1] == b'b' && (i < 2 || !ident(i - 2))))
            && matches!(b.get(i + 1), Some(b'"' | b'#'))
        {
            let mut j = i + 1;
            while b.get(j) == Some(&b'#') {
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                i += 1;
                continue; // `r#ident`, not a raw string
            }
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', j - i - 1))
                .collect();
            i = b[j + 1..]
                .windows(close.len())
                .position(|w| w == close.as_slice())
                .map_or(b.len(), |p| j + 1 + p + close.len());
        } else if b[i] == b'"' {
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
        } else if b[i] == b'\'' {
            // A char literal (`'{'`, `'\n'`, `'\u{2014}'`), not a lifetime.
            let len = if b.get(i + 1) == Some(&b'\\') {
                src.get(i + 3..)
                    .and_then(|r| r.find('\''))
                    .map(|p| p + 4)
                    .filter(|&n| n <= 12)
            } else {
                src[i + 1..]
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .filter(|&n| b.get(i + 1 + n) == Some(&b'\''))
                    .map(|n| n + 2)
            };
            i += len.unwrap_or(1);
            if len.is_none() {
                continue;
            }
        } else {
            i += 1;
            continue;
        }
        let end = i.min(b.len());
        mask[start..end].fill(false);
    }
    mask
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
            out.push((name.replace('\\', "/"), strip_tests(&src)));
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

/// Every `.rs` file under the frontend's `web-rs/src`, as (path relative to
/// `src`, `/`-separated, source), sorted. Unlike [`command_modules`] nothing is
/// stripped: the frontend rules scan markup, and a `#[cfg(test)]` module
/// spelling that markup is as much a bypass as any other.
pub(crate) fn web_modules() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("apps/desktop")
        .join("web-rs/src");
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
            let Ok(src) = std::fs::read_to_string(&path) else {
                continue;
            };
            let name = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .display()
                .to_string();
            out.push((name.replace('\\', "/"), src));
        }
    }
    assert!(
        out.len() > 50,
        "walked {} frontend modules from {} — the source-tree walk is broken, and a rule that \
         scans nothing passes vacuously",
        out.len(),
        root.display()
    );
    out.sort();
    out
}

/// The lines of `src` that are not `//` comments (doc or plain), so a rule
/// keyed on markup never fires on prose that merely describes it.
pub(crate) fn code_lines(src: &str) -> impl Iterator<Item = &str> {
    src.lines().filter(|l| !l.trim_start().starts_with("//"))
}

/// One `#[tauri::command]` handler: its name and its **own** body.
pub(crate) struct Command {
    pub(crate) module: String,
    pub(crate) name: String,
    /// The raw parameter list, the text between the signature's parens.
    pub(crate) params: String,
    /// The declared return type with the leading `->` removed and trimmed;
    /// empty for a command that returns `()`.
    pub(crate) ret: String,
    /// Brace-balanced function body, `{` to matching `}`.
    pub(crate) body: String,
}

/// Whether the `#[tauri::command]` found at byte `at` opens its own line, i.e.
/// only whitespace sits between the previous newline (or the start of the
/// file) and it.
///
/// A doc comment that merely *mentions* the attribute (`/// behind a
/// `#[tauri::command]` …`) is otherwise read as a command: the extractor then
/// takes the next `fn` — a private `*_core` helper — and every rule counts a
/// phantom command no `generate_handler![]` could ever register. The advisory
/// `command-parity-check.sh` hook learned the same lesson ("anchored to line
/// start").
pub(crate) fn command_attribute_at_line_start(src: &str, at: usize) -> bool {
    let line_start = src[..at].rfind('\n').map_or(0, |n| n + 1);
    src[line_start..at].trim().is_empty()
}

/// Extracts the brace-balanced block starting at the first `{` at or after
/// `from`. Skips string literals and `//` comments so a brace inside either
/// cannot unbalance the scan (same reasoning as `fanout::call_sites`; char
/// literals are deliberately not tracked because `'` also opens a lifetime).
pub(crate) fn balanced_block(src: &str, from: usize) -> Option<String> {
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
            if !command_attribute_at_line_start(&src, at) {
                continue;
            }
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
            let Some(params_open) = src[fn_at..params_end].find('(').map(|p| fn_at + p) else {
                continue;
            };
            let params = src[params_open + 1..params_end - 1].to_string();
            let Some(body) = balanced_block(&src, params_end) else {
                continue;
            };
            let body_open = params_end + src[params_end..].find('{').unwrap_or(0);
            let ret = src[params_end..body_open]
                .trim()
                .trim_start_matches("->")
                .trim()
                .to_string();
            from = body_open + body.len();
            out.push(Command {
                module: module.clone(),
                name,
                params,
                ret,
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

/// Whether `trimmed` opens a function — at any indentation, with any
/// combination of visibility, `async`, `const`, `unsafe` or `extern`.
///
/// Both the cache rule's back-walk and [`functions_in`] use this as their
/// boundary, so anything it fails to recognise silently widens the search into
/// the previous function. One definition, so the two cannot disagree.
pub(crate) fn is_fn_header(trimmed: &str) -> bool {
    let rest = trimmed
        .strip_prefix("pub(crate) ")
        .or_else(|| trimmed.strip_prefix("pub(super) "))
        .or_else(|| trimmed.strip_prefix("pub "))
        .unwrap_or(trimmed);
    let rest = rest
        .strip_prefix("const ")
        .or_else(|| rest.strip_prefix("async "))
        .or_else(|| rest.strip_prefix("unsafe "))
        .unwrap_or(rest);
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    rest.starts_with("fn ")
}

/// One `fn` item — a command, a private helper, a nested fn — with its **own**
/// body.
pub(crate) struct Function {
    pub(crate) name: String,
    /// Brace-balanced body with every `//` line removed, so a comment that
    /// merely names a validator cannot satisfy a rule that asks for the call.
    pub(crate) body: String,
}

/// Every `fn` item in `src`, each with its own body.
///
/// [`commands`] stops at `#[tauri::command]` handlers; the trust rules also
/// need the private helpers a command delegates its write to (`configure_oidc`,
/// `wire_application`), because that is where the write sits and where the
/// check has to be proven. Every header is scanned independently — a nested fn
/// appears both inside its parent's body and as an item of its own. Bodiless
/// declarations (trait items) are skipped.
pub(crate) fn functions_in(src: &str) -> Vec<Function> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    for line in src.split_inclusive('\n') {
        let line_at = offset;
        offset += line.len();
        let trimmed = line.trim_start();
        if !is_fn_header(trimmed) {
            continue;
        }
        let Some(kw) = trimmed.find("fn ") else {
            continue;
        };
        let fn_at = line_at + (line.len() - trimmed.len()) + kw;
        let name: String = src[fn_at + 3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let Some(params_end) = balanced_paren_end(src, fn_at) else {
            continue;
        };
        let rest = &src[params_end..];
        let (Some(brace), semi) = (rest.find('{'), rest.find(';')) else {
            continue;
        };
        if semi.is_some_and(|semi| semi < brace) {
            continue;
        }
        let Some(block) = balanced_block(src, params_end) else {
            continue;
        };
        let body = block
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        out.push(Function { name, body });
    }
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

/// `strip_tests` drops only real `#[cfg(test)]` items. It used to cut the file
/// at the first occurrence of the TEXT, so a doc comment mentioning the
/// attribute hid every production item below it from every rule.
#[test]
fn strip_tests_drops_only_the_gated_items() {
    let src = "\
/// `#[cfg(test)]` is the enforcement, not this comment.
pub fn kept_after_doc() {}
const NOTE: &str = \"
#[cfg(test)] inside a string\";
#[cfg(test)]
pub(crate) fn test_only(x: [u8; 2]) {
    let _ = '}';
}
pub fn kept_after_fn() {}
#[cfg(test)]
mod tests;
pub fn kept_after_decl() {}
#[cfg(test)]
mod inline {
    fn fixture() {}
}
struct Bucket {
    kept_field_before: u64,
    #[cfg(test)]
    test_field: u64,
    #[cfg(test)]
    test_map: HashMap<String, Vec<u8>>,
    kept_field_after: u64,
    #[cfg(test)]
    test_last_field: u64
}
enum Kind {
    #[cfg(test)]
    TestVariant(u8),
    KeptVariant,
}
fn kept_match(k: Kind) -> u8 {
    match k {
        #[cfg(test)]
        Kind::TestVariant(n) => n,
        Kind::KeptVariant => 0,
    }
}
#[cfg(all(test, feature = \"x\"))]
fn all_gated() {}
#[cfg(any(test, feature = \"x\"))]
fn kept_any_gated() {}
";
    let out = strip_tests(src);
    assert_eq!(
        out.lines().count(),
        src.lines().count(),
        "line numbers must survive"
    );
    for kept in [
        "kept_after_doc",
        "inside a string",
        "kept_after_fn",
        "kept_after_decl",
        "kept_field_before",
        "kept_field_after",
        "KeptVariant",
        "kept_match",
        "Kind::KeptVariant => 0",
        "kept_any_gated",
    ] {
        assert!(out.contains(kept), "`{kept}` was stripped:\n{out}");
    }
    for gone in [
        "test_only",
        "mod tests",
        "fixture",
        "test_field",
        "test_map",
        "test_last_field",
        "TestVariant",
        "all_gated",
    ] {
        assert!(!out.contains(gone), "`{gone}` survived:\n{out}");
    }
}
