//! Pins the demo's contract with the bindings, in both directions:
//!
//! - every **infallible** `invoke()` / `invoke::<()>()` anywhere under `src/`
//!   has a fixture registered in the demo (the page-crash invariant);
//! - every **fallible read** (`invoke_result` on a `list_`/`get_`/`search_`/…
//!   command) is either fixtured or named in [`DEMO_READS_LEFT_UNFIXTURED`]
//!   with the reason — so a new read surface is classified before it ships to
//!   Pages instead of being discovered by a visitor staring at a rejection;
//! - every registered fixture names a command some binding still invokes (a
//!   dead fixture documents a command that no longer exists);
//! - the mock path holds no hand-written JSON (typed fixtures can't drift).
//!
//! Why the first one matters most: the mock IPC bridge answers an unregistered
//! route with a *rejected* promise. `invoke_result` turns that into an `Err` the
//! UI renders, but the infallible form has nowhere to put it and panics —
//! taking down the whole published GitHub Pages page, not just one widget.
//!
//! The scans read comment-stripped source, walk `src/` recursively, and count a
//! registration only where a `mock_*(` call (or a `for cmd in [ … ]` array)
//! names the command — a comment that merely mentions a command, or a binding
//! moved into a subdirectory, cannot satisfy or dodge them.
//!
//! Runs natively under `just web-test` (no WASM, no browser) — it only reads
//! source text. Gated OFF for wasm32, the mirror of the `tests/gui_*.rs`
//! shards' `#![cfg(target_arch = "wasm32")]`: this reads the filesystem, which
//! does not exist in the browser, and `just web-itest` builds every test target.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Infallible commands that are deliberately NOT mocked, with the reason they
/// cannot reach the demo. Keep this list short and justified — every entry is
/// a page-crash waiting to happen if the reasoning stops holding.
///
/// Empty today, and that is the healthy state: every infallible invoke in the
/// bindings currently has a fixture. The mechanism stays for the case where a
/// command genuinely cannot be reached.
const NOT_DEMO_REACHABLE: &[(&str, &str)] = &[];

/// Fallible reads the demo deliberately leaves to the friendly rejection, with
/// the reason that is the right answer for a browser page.
const DEMO_READS_LEFT_UNFIXTURED: &[(&str, &str)] = &[(
    "check_for_update",
    "no updater behind a browser page: shell.rs's launch check swallows the Err \
     and the manual check reports it as a toast",
)];

/// The command-name prefixes that make an `invoke_result` a read.
const READ_PREFIXES: &[&str] = &[
    "list_", "get_", "search_", "check_", "find_", "probe_", "current_",
];

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Removes `//` line comments and `/* */` block comments, keeping string and
/// char literals (and newlines) intact — so `"https://…"` survives, and a `'"'`
/// char literal doesn't flip the scanner into a phantom string.
fn strip_line_comments(src: &str) -> String {
    let chars: Vec<char> = src.chars().collect();
    let mut out = String::with_capacity(src.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match c {
            '/' if next == Some('/') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if next == Some('*') => {
                let mut depth = 0usize;
                while i < chars.len() {
                    if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                        depth += 1;
                        i += 2;
                    } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if chars[i] == '\n' {
                            out.push('\n');
                        }
                        i += 1;
                    }
                }
            }
            // Raw string: r"…", r#"…"#, … — no escapes inside.
            'r' if (i == 0 || !is_ident(chars[i - 1])) && matches!(next, Some('"') | Some('#')) => {
                let mut j = i + 1;
                let mut hashes = 0;
                while chars.get(j) == Some(&'#') {
                    hashes += 1;
                    j += 1;
                }
                if chars.get(j) != Some(&'"') {
                    out.push(c);
                    i += 1;
                    continue;
                }
                j += 1;
                loop {
                    match chars.get(j) {
                        None => break,
                        Some('"') if (1..=hashes).all(|k| chars.get(j + k) == Some(&'#')) => {
                            j += 1 + hashes;
                            break;
                        }
                        Some(_) => j += 1,
                    }
                }
                out.extend(&chars[i..j.min(chars.len())]);
                i = j;
            }
            '"' => {
                let mut j = i + 1;
                while j < chars.len() && chars[j] != '"' {
                    if chars[j] == '\\' {
                        j += 1;
                    }
                    j += 1;
                }
                let end = (j + 1).min(chars.len());
                out.extend(&chars[i..end]);
                i = end;
            }
            '\'' => {
                // A char literal ('x', '"', '\'', '\u{..}') or a lifetime.
                let end = if next == Some('\\') {
                    // Past the backslash AND the escaped char, so '\'' ends
                    // at its own closing quote.
                    let mut j = i + 3;
                    while j < chars.len() && chars[j] != '\'' {
                        j += 1;
                    }
                    j + 1
                } else if chars.get(i + 2) == Some(&'\'') {
                    i + 3
                } else {
                    i + 1
                };
                let end = end.min(chars.len());
                out.extend(&chars[i..end]);
                i = end;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Every `.rs` file under `root`, recursively and comment-stripped, skipping
/// the directories named in `skip` (relative to `root`).
fn rust_sources(root: &Path, skip: &[&str]) -> Vec<(PathBuf, String)> {
    fn walk(root: &Path, dir: &Path, skip: &[&str], out: &mut Vec<(PathBuf, String)>) {
        let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries {
            let path = entry.expect("dir entry").path();
            let rel = path.strip_prefix(root).expect("under root");
            if path.is_dir() {
                if !skip.iter().any(|s| rel == Path::new(s)) {
                    walk(root, &path, skip, out);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                let src = fs::read_to_string(&path).expect("read source");
                out.push((path, strip_line_comments(&src)));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, skip, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn src_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Everything a binding can reach: `src/` minus the mock bridge and the demo.
fn app_sources() -> Vec<(PathBuf, String)> {
    rust_sources(&src_root(), &["ipc_mock", "demo"])
}

fn demo_sources() -> Vec<(PathBuf, String)> {
    rust_sources(&src_root().join("demo"), &[])
}

/// The string literal starting at `s` (which must begin with `"`), unescaped
/// only as far as command names need (they are plain snake_case).
fn leading_literal(s: &str) -> Option<&str> {
    let rest = s.strip_prefix('"')?;
    let close = rest.find('"')?;
    Some(&rest[..close])
}

/// Skips a balanced `<…>` starting at `s[0] == '<'`; returns the rest.
fn skip_generics(s: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[i + 1..]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Commands named by calls to `name` (`invoke` or `invoke_result`) in `src`,
/// plus the call sites whose first argument is not a string literal.
///
/// A call is the bare identifier (not a path segment like
/// `tauri_sys::core::invoke_result`, not the tail of a longer identifier), an
/// optional turbofish, then `(`. A definition (`fn invoke_result<T…>`) or an
/// import (`use …::invoke;`) is not followed by `(`/`::<` and is skipped.
fn invoked_commands(src: &str, name: &str) -> (BTreeSet<String>, Vec<String>) {
    let mut commands = BTreeSet::new();
    let mut non_literal = Vec::new();
    let mut from = 0;
    while let Some(rel) = src[from..].find(name) {
        let start = from + rel;
        from = start + name.len();
        if src[..start]
            .chars()
            .next_back()
            .is_some_and(|p| is_ident(p) || p == ':')
        {
            continue;
        }
        let mut rest = src[from..].trim_start();
        if let Some(turbofish) = rest.strip_prefix("::") {
            let Some(after) = turbofish
                .trim_start()
                .starts_with('<')
                .then(|| skip_generics(turbofish.trim_start()))
                .flatten()
            else {
                continue;
            };
            rest = after.trim_start();
        }
        let Some(args) = rest.strip_prefix('(') else {
            continue;
        };
        let args = args.trim_start();
        match leading_literal(args) {
            Some(cmd) => {
                commands.insert(cmd.to_string());
            }
            None => non_literal.push(args.lines().next().unwrap_or_default().to_string()),
        }
    }
    (commands, non_literal)
}

/// Commands registered in comment-stripped demo source: the literal right
/// after `mock_ok(` / `mock_each(` / `mock_err(` (rustfmt may break the call
/// across lines), plus every literal inside a `for cmd in [ … ]` array.
fn registered_commands(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for call in ["mock_ok(", "mock_each(", "mock_err("] {
        let mut from = 0;
        while let Some(rel) = src[from..].find(call) {
            let start = from + rel;
            from = start + call.len();
            if src[..start].chars().next_back().is_some_and(is_ident) {
                continue;
            }
            if let Some(cmd) = leading_literal(src[from..].trim_start()) {
                out.insert(cmd.to_string());
            }
        }
    }
    let mut from = 0;
    while let Some(rel) = src[from..].find("for cmd in [") {
        let open = from + rel + "for cmd in [".len();
        let close = open + src[open..].find(']').expect("unterminated `for cmd in [`");
        let mut body = &src[open..close];
        while let Some(q) = body.find('"') {
            let lit = leading_literal(&body[q..]).expect("unterminated literal");
            out.insert(lit.to_string());
            body = &body[q + lit.len() + 2..];
        }
        from = close;
    }
    out
}

fn all_invoked(name: &str) -> (BTreeSet<String>, Vec<String>) {
    let mut commands = BTreeSet::new();
    let mut non_literal = Vec::new();
    for (path, src) in app_sources() {
        let (c, n) = invoked_commands(&src, name);
        commands.extend(c);
        non_literal.extend(n.into_iter().map(|s| format!("{}: {s}", path.display())));
    }
    (commands, non_literal)
}

fn all_registered() -> BTreeSet<String> {
    demo_sources()
        .iter()
        .flat_map(|(_, src)| registered_commands(src))
        .collect()
}

fn is_read(command: &str) -> bool {
    READ_PREFIXES.iter().any(|p| command.starts_with(p))
}

#[test]
fn every_infallible_invoke_has_a_demo_fixture() {
    let (commands, _) = all_invoked("invoke");
    let registered = all_registered();
    assert!(
        commands.len() >= 5,
        "the scan found only {} infallible invokes — it is broken, not the demo",
        commands.len()
    );

    let exempt: BTreeSet<&str> = NOT_DEMO_REACHABLE.iter().map(|(c, _)| *c).collect();
    let missing: Vec<&String> = commands
        .iter()
        .filter(|c| !exempt.contains(c.as_str()))
        .filter(|c| !registered.contains(*c))
        .collect();

    assert!(
        missing.is_empty(),
        "these infallible invokes have no fixture in demo::register_fixtures, so \
         reaching one PANICS the published demo page (the mock bridge rejects \
         unregistered routes and the infallible form cannot absorb it): {missing:?}\n\
         Register each in `register_fixtures`, or add it to NOT_DEMO_REACHABLE \
         with the reason it cannot be reached."
    );
}

#[test]
fn the_not_demo_reachable_allowlist_stays_honest() {
    // An exemption is dead weight in two directions, and both hide something:
    // for a command that no longer exists, and for one that IS registered (where
    // the exemption would suppress a check that already passes — and would keep
    // passing if the fixture were later deleted).
    let (commands, _) = all_invoked("invoke");
    let registered = all_registered();

    for (command, reason) in NOT_DEMO_REACHABLE {
        assert!(
            commands.contains(*command),
            "`{command}` is exempted (\"{reason}\") but is no longer an \
             infallible invoke — drop the entry"
        );
        assert!(
            !registered.contains(*command),
            "`{command}` is exempted as unreachable but IS registered in \
             register_fixtures — drop the exemption so the fixture is actually \
             required"
        );
    }
}

#[test]
fn every_fallible_read_is_fixtured_or_explained() {
    let (commands, _) = all_invoked("invoke_result");
    assert!(
        commands.len() >= 100,
        "the scan found only {} `invoke_result` commands — it is broken, not the demo",
        commands.len()
    );
    let registered = all_registered();
    let explained: BTreeSet<&str> = DEMO_READS_LEFT_UNFIXTURED.iter().map(|(c, _)| *c).collect();
    let unclassified: Vec<&String> = commands
        .iter()
        .filter(|c| is_read(c))
        .filter(|c| !registered.contains(*c) && !explained.contains(c.as_str()))
        .collect();
    assert!(
        unclassified.is_empty(),
        "these reads have no demo fixture, so the Pages demo renders its \
         \"not available in the live demo\" rejection where the surface should \
         be: {unclassified:?}\n\
         Register a typed fixture in demo::register_fixtures (args-aware via \
         `mock_each` when the payload names the object), or add the command to \
         DEMO_READS_LEFT_UNFIXTURED with the reason a rejection is right."
    );
}

#[test]
fn the_unfixtured_read_allowlist_stays_honest() {
    let (commands, _) = all_invoked("invoke_result");
    let registered = all_registered();
    for (command, reason) in DEMO_READS_LEFT_UNFIXTURED {
        assert!(
            commands.contains(*command) && is_read(command),
            "`{command}` is allowlisted (\"{reason}\") but is no longer a \
             read-shaped `invoke_result` — drop the entry"
        );
        assert!(
            !registered.contains(*command),
            "`{command}` is allowlisted as unfixtured but IS registered — drop \
             the entry so the fixture stays required"
        );
    }
}

#[test]
fn every_demo_fixture_names_a_bound_command() {
    let (mut bound, _) = all_invoked("invoke");
    bound.extend(all_invoked("invoke_result").0);
    let dead: Vec<String> = all_registered()
        .into_iter()
        .filter(|c| !bound.contains(c))
        .collect();
    assert!(
        dead.is_empty(),
        "the demo registers fixtures for commands no binding invokes (removed \
         from the IPC boundary, or renamed): {dead:?} — delete the fixture, or \
         fix the name"
    );
}

#[test]
fn every_invoke_names_its_command_literally() {
    // The scans key on the literal; a command passed through a variable would
    // be invisible to all of them.
    for name in ["invoke", "invoke_result"] {
        let (_, non_literal) = all_invoked(name);
        assert!(
            non_literal.is_empty(),
            "`{name}` calls whose command is not a string literal: {non_literal:?}"
        );
    }
}

#[test]
fn the_mock_path_has_no_hand_written_json() {
    // Fixtures are typed DTOs serialized through the same serde path the
    // bindings deserialize with, so a renamed field is a compile error. A
    // `json!` payload would turn it into a demo-runtime deserialize error.
    let mut sources = demo_sources();
    let fixtures = src_root().join("ipc_mock/fixtures.rs");
    sources.push((
        fixtures.clone(),
        strip_line_comments(&fs::read_to_string(&fixtures).expect("read fixtures.rs")),
    ));
    for (path, src) in sources {
        assert!(
            !src.contains("json!("),
            "{} builds a mock payload from hand-written JSON — use a typed DTO",
            path.display()
        );
    }
}

// ---- The scanners themselves ----

#[test]
fn the_scan_ignores_the_fallible_wrapper() {
    // `invoke_result` returns Err on a rejected promise, so it is safe
    // unregistered — and it must not inflate the required-fixture set.
    let src = r#"
        pub async fn a() -> Result<X, UiError> { invoke_result("safe_command", ()).await }
        pub async fn b() -> Y { invoke("must_be_mocked", ()).await }
        pub async fn c() { invoke::<()>("also_mocked", ()).await }
        pub async fn d() -> Z {
            invoke::<Vec<Option<String>>>(
                "turbofish_on_a_new_line",
                (),
            )
            .await
        }
    "#;
    let (got, non_literal) = invoked_commands(src, "invoke");
    assert!(got.contains("must_be_mocked"));
    assert!(got.contains("also_mocked"));
    assert!(got.contains("turbofish_on_a_new_line"), "got: {got:?}");
    assert!(!got.contains("safe_command"), "got: {got:?}");
    assert!(non_literal.is_empty());
    let (fallible, _) = invoked_commands(src, "invoke_result");
    assert_eq!(fallible.into_iter().collect::<Vec<_>>(), ["safe_command"]);
}

#[test]
fn the_scan_skips_definitions_imports_and_paths() {
    let src = r#"
        pub(crate) use tauri_sys::core::invoke;
        use super::ipc::{invoke, invoke_result};
        pub(crate) async fn invoke_result<T: DeserializeOwned>(cmd: &str) -> Result<T, UiError> {
            match tauri_sys::core::invoke_result::<Value, Value>(cmd, args).await { _ => todo!() }
        }
        fn e() { invoke_result(command_name, ()) }
    "#;
    let (got, non_literal) = invoked_commands(src, "invoke_result");
    assert!(got.is_empty(), "got: {got:?}");
    assert_eq!(non_literal, ["command_name, ()) }"]);
    assert!(invoked_commands(src, "invoke").0.is_empty());
}

#[test]
fn a_comment_mention_is_not_a_registration() {
    let src = strip_line_comments(
        r#"
        // mock_ok("ghost", &());
        /* mock_ok("block_ghost", &()); */
        let s = "loose";
        mock_ok(
            "real",
            &(),
        );
        mock_each("each", |_| ()); // see "cancel_audit"
        for cmd in ["arr_a", "arr_b"] {
            mock_ok(cmd, &());
        }
    "#,
    );
    let got = registered_commands(&src);
    assert_eq!(
        got.into_iter().collect::<Vec<_>>(),
        ["arr_a", "arr_b", "each", "real"]
    );
}

#[test]
fn comment_stripping_keeps_strings_and_char_literals() {
    let src = concat!(
        "let url = \"https://contoso.com/x\"; // trailing\n",
        "let q = '\"'; // \"x\"\n",
        "let e = '\\''; let lt: &'static str = \"a//b\";\n",
        "let raw = r#\"// not a comment\"#;\n",
    );
    let got = strip_line_comments(src);
    assert!(got.contains("\"https://contoso.com/x\""), "{got}");
    assert!(!got.contains("trailing"), "{got}");
    assert!(got.contains("'\"'"), "{got}");
    assert!(
        !got.contains("\"x\""),
        "the comment after a '\"' char literal must go: {got}"
    );
    assert!(got.contains("\"a//b\""), "{got}");
    assert!(got.contains("r#\"// not a comment\"#"), "{got}");
    assert_eq!(got.lines().count(), 4, "newlines survive: {got}");
}

#[test]
fn the_walk_reaches_nested_dirs_and_skips_the_mock() {
    let root = src_root();
    let paths: Vec<PathBuf> = app_sources()
        .into_iter()
        .map(|(p, _)| p.strip_prefix(&root).expect("under src").to_path_buf())
        .collect();
    assert!(
        paths.contains(&PathBuf::from("views/tabs/federated_tab.rs")),
        "the walk must recurse: {paths:?}"
    );
    assert!(
        paths
            .iter()
            .all(|p| !p.starts_with("demo") && !p.starts_with("ipc_mock")),
        "the mock and the demo are not bindings: {paths:?}"
    );
    assert!(!demo_sources().is_empty());
}
