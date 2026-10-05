//! The IPC contract, pinned end to end: `generate_handler![]` ↔
//! `#[tauri::command]` ↔ the typed bindings in `web-rs/src/bindings/`.
//!
//! Every mismatch here compiles on both sides and fails only at runtime, as an
//! opaque rejection: a command left out of `generate_handler![]`, a binding
//! whose command string is misspelt, an argument struct whose field no longer
//! matches the parameter it feeds, or a binding that decodes a different type
//! than the command returns. The browser GUI tests mock IPC, so they cannot see
//! any of it, and the `command-parity-check.sh` hook is advisory, fires only on
//! an agent's Write/Edit and skips without `jq`. This module is the gate; the
//! hook is the fast local escort.
//!
//! It also pins the single door to `tauri-sys` (`bindings/ipc.rs`): upstream
//! `invoke_result` unwraps a rejection that is not a `UiError` into a panic
//! that freezes the window, so a binding that imports it directly reopens that
//! hole.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::sources::{self, Command};

fn manifest() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn web_src() -> PathBuf {
    manifest()
        .parent()
        .expect("apps/desktop")
        .join("web-rs/src")
}

/// The wrapper module every binding reaches `tauri-sys` through.
const IPC_MODULE: &str = "ipc.rs";

// ---------------------------------------------------------------- scanners

/// The entries of `generate_handler![…]` in `src/lib.rs`, reduced to the
/// function name (the last `::` segment).
fn registered() -> Vec<String> {
    let lib = std::fs::read_to_string(manifest().join("src/lib.rs")).expect("read src/lib.rs");
    let start = lib
        .find("generate_handler![")
        .expect("src/lib.rs has no `generate_handler![` — the registry moved; update this rule");
    let mut out = Vec::new();
    for line in lib[start + "generate_handler![".len()..].lines() {
        let line = line.trim();
        if line.starts_with(']') {
            break;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let entry = line.trim_end_matches(',').trim();
        if entry.starts_with("commands::") {
            let name = entry.rsplit("::").next().unwrap_or(entry);
            out.push(name.to_string());
        }
    }
    out
}

/// Every `.rs` file directly under `web-rs/src/bindings`, as (file name,
/// source with test modules stripped). Sorted for stable messages.
fn binding_files() -> Vec<(String, String)> {
    let root = web_src().join("bindings");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("read {}: {e}", root.display()))
        .flatten()
    {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read binding");
        let name = path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        out.push((name, sources::strip_tests(&src)));
    }
    out.sort();
    assert!(
        out.len() > 20,
        "read only {} binding files from {} — the walk is broken, and a rule that scans nothing \
         passes vacuously",
        out.len(),
        root.display()
    );
    out
}

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Index of the delimiter closing the one opened at `open`, skipping string
/// literals and `//` comments (same reasoning as `sources::balanced_block`).
/// A `>` that ends `->` is not a closing angle bracket.
fn balance(src: &str, open: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let (o, c) = match bytes[open] {
        b'(' => (b'(', b')'),
        b'<' => (b'<', b'>'),
        b'{' => (b'{', b'}'),
        b'[' => (b'[', b']'),
        _ => return None,
    };
    let (mut depth, mut i) = (0usize, open);
    let (mut in_str, mut in_line_comment) = (false, false);
    while i < bytes.len() {
        let b = bytes[i];
        if in_line_comment {
            if b == b'\n' {
                in_line_comment = false;
            }
        } else if in_str {
            if b == b'\\' {
                i += 1;
            } else if b == b'"' {
                in_str = false;
            }
        } else if b == b'"' {
            in_str = true;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            in_line_comment = true;
        } else if b == o {
            depth += 1;
        } else if b == c && !(c == b'>' && i > 0 && bytes[i - 1] == b'-') {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Splits `s` on `sep` at nesting depth zero over `<>()[]{}` (a `->` arrow
/// does not close an angle bracket).
fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut prev = '\0';
    for ch in s.chars() {
        match ch {
            '<' | '(' | '[' | '{' => depth += 1,
            '>' if prev != '-' => depth -= 1,
            ')' | ']' | '}' => depth -= 1,
            _ => {}
        }
        if ch == sep && depth == 0 {
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
        prev = ch;
    }
    out.push(cur);
    out.into_iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

/// The frontend-supplied parameter names of a command, in order: everything
/// but the injected `State`/`AppHandle`/window/request parameters.
fn command_args(params: &str) -> Vec<String> {
    const INJECTED: [&str; 6] = [
        "State<",
        "AppHandle",
        "Window",
        "WebviewWindow",
        "Webview",
        "ipc::Request",
    ];
    split_top_level(params, ',')
        .into_iter()
        .filter_map(|p| {
            let (name, ty) = p.split_once(':')?;
            if INJECTED.iter().any(|i| ty.contains(i)) {
                return None;
            }
            let name = name.trim();
            // `strip_prefix`, never a character-set trim: `trim_start_matches`
            // over `['m','u','t',' ']` eats the `t` of `tenant_id`.
            let name = name.strip_prefix("mut ").unwrap_or(name).trim();
            Some(name.to_string())
        })
        .collect()
}

/// Tauri's default key for a command parameter, and serde's
/// `rename_all = "camelCase"` for a field: `service_principal_id` →
/// `servicePrincipalId`.
fn camel(snake: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for ch in snake.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// A type with whitespace and every lowercase path segment removed, so
/// `crate::dto::UiError` and `UiError`, or `azapptoolkit_core::models::X` and
/// `X`, compare equal.
fn norm_type(t: &str) -> String {
    let flat: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = flat.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if is_ident(bytes[i]) && (i == 0 || !is_ident(bytes[i - 1])) {
            let start = i;
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
            let ident = &flat[start..i];
            let is_path = flat[i..].starts_with("::");
            if is_path && ident.starts_with(|c: char| c.is_ascii_lowercase() || c == '_') {
                i += 2;
                continue;
            }
            out.push_str(ident);
            continue;
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// `norm`-alised type text with every `Arc<X>` replaced by `X`.
///
/// serde serializes an `Arc<T>` exactly as the `T` it points to, so a command
/// returning a typed cache entry (`Result<Arc<Vec<Row>>, UiError>`, a refcount
/// clone rather than a deep copy) puts the same bytes on the wire as one
/// returning `Result<Vec<Row>, UiError>`, and its binding decodes the plain
/// type. Applied to the backend side only: the frontend has no reason to ask
/// for an `Arc`.
fn strip_arc(norm: &str) -> String {
    let mut out = norm.to_string();
    while let Some(at) = out
        .match_indices("Arc<")
        .map(|(at, _)| at)
        .find(|&at| at == 0 || !is_ident(out.as_bytes()[at - 1]))
    {
        let open = at + "Arc".len();
        let mut depth = 0usize;
        let mut close = None;
        for (i, b) in out.bytes().enumerate().skip(open) {
            match b {
                b'<' => depth += 1,
                b'>' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            break;
        };
        out = format!(
            "{}{}{}",
            &out[..at],
            &out[open + 1..close],
            &out[close + 1..]
        );
    }
    out
}

#[test]
fn strip_arc_unwraps_every_arc_and_nothing_else() {
    assert_eq!(
        strip_arc("Result<Arc<Vec<X>>,UiError>"),
        "Result<Vec<X>,UiError>"
    );
    assert_eq!(
        strip_arc("Result<Option<Arc<Run>>,UiError>"),
        "Result<Option<Run>,UiError>"
    );
    assert_eq!(strip_arc("(Arc<A>,Arc<B<C>>)"), "(A,B<C>)");
    assert_eq!(strip_arc("MyArc<X>"), "MyArc<X>");
    assert_eq!(strip_arc("Vec<X>"), "Vec<X>");
}

/// One `invoke*("command", args)` call site in a binding file.
#[derive(Debug, Clone, PartialEq)]
struct Call {
    command: String,
    /// The argument expression, trimmed, trailing comma dropped.
    args: String,
    /// `invoke_result` (true) or the infallible `invoke` (false).
    fallible: bool,
    /// The enclosing binding fn's declared return type (empty for `()`).
    ret: String,
}

/// Whether byte `at` sits on a line that is a `//` comment.
fn in_comment_line(src: &str, at: usize) -> bool {
    let line_start = src[..at].rfind('\n').map_or(0, |n| n + 1);
    src[line_start..at].trim_start().starts_with("//")
}

/// The declared return type of the nearest `fn` header before `at`.
fn enclosing_fn_ret(src: &str, at: usize) -> String {
    let bytes = src.as_bytes();
    let mut search_end = at;
    let fn_at = loop {
        let Some(hit) = src[..search_end].rfind("fn ") else {
            return String::new();
        };
        if hit == 0 || !is_ident(bytes[hit - 1]) {
            break hit;
        }
        search_end = hit;
    };
    let Some(open) = src[fn_at..].find('(').map(|p| fn_at + p) else {
        return String::new();
    };
    let Some(close) = balance(src, open) else {
        return String::new();
    };
    let Some(body) = src[close..].find('{').map(|p| close + p) else {
        return String::new();
    };
    let sig = src[close + 1..body].trim();
    let sig = sig.split(" where").next().unwrap_or(sig);
    sig.trim_start_matches("->").trim().to_string()
}

/// Every `invoke(` / `invoke_result(` / `invoke::<…>(` call in `src` whose
/// first argument is the command's string literal.
fn binding_calls(file: &str, src: &str) -> Vec<Call> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(hit) = src[from..].find("invoke") {
        let at = from + hit;
        from = at + "invoke".len();
        if at > 0 && is_ident(bytes[at - 1]) {
            continue;
        }
        let mut i = at;
        while i < bytes.len() && is_ident(bytes[i]) {
            i += 1;
        }
        let fallible = match &src[at..i] {
            "invoke_result" => true,
            "invoke" => false,
            _ => continue,
        };
        if in_comment_line(src, at) {
            continue;
        }
        if src[i..].starts_with("::<") {
            let Some(close) = balance(src, i + 2) else {
                continue;
            };
            i = close + 1;
        }
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if bytes.get(i) != Some(&b'(') {
            // An import, a doc mention, a path — not a call.
            continue;
        }
        let open = i;
        let close =
            balance(src, open).unwrap_or_else(|| panic!("{file}: unbalanced call at byte {at}"));
        let inner = src[open + 1..close].trim_start();
        let Some(lit) = inner.strip_prefix('"') else {
            panic!(
                "{file}: `{}` is called with a non-literal command name — name the command \
                 with a string literal so the IPC contract can be checked (only \
                 `bindings/{IPC_MODULE}` forwards a variable)",
                &src[at..close + 1]
            );
        };
        let end = lit.find('"').expect("unterminated command literal");
        let command = lit[..end].to_string();
        let rest = lit[end + 1..].trim_start();
        let rest = rest.strip_prefix(',').unwrap_or(rest).trim();
        let args = rest.trim_end_matches(',').trim().to_string();
        out.push(Call {
            command,
            args,
            fallible,
            ret: enclosing_fn_ret(src, at),
        });
        from = close;
    }
    out
}

/// The wire keys of argument struct `name`, looked up in `file`'s source and
/// then in `common.rs`: field names, camelCased when the struct carries
/// `rename_all = "camelCase"`.
fn struct_wire_keys(name: &str, own: &str, common: &str) -> Option<BTreeSet<String>> {
    for src in [own, common] {
        let mut from = 0usize;
        let needle = format!("struct {name}");
        while let Some(hit) = src[from..].find(&needle) {
            let at = from + hit;
            from = at + needle.len();
            let after = src.as_bytes().get(from).copied().unwrap_or(b' ');
            if is_ident(after) || (at > 0 && is_ident(src.as_bytes()[at - 1])) {
                continue;
            }
            // The attribute lines directly above the declaration.
            let decl_line = src[..at].rfind('\n').map_or(0, |n| n + 1);
            let mut camel_case = false;
            for line in src[..decl_line].lines().rev() {
                let line = line.trim();
                if line.starts_with("#[") {
                    if line.contains("rename_all") {
                        assert!(
                            line.contains("rename_all = \"camelCase\""),
                            "struct `{name}` uses `{line}` — the IPC rule only understands \
                             `rename_all = \"camelCase\"`; extend `repo_invariants/ipc.rs`"
                        );
                        camel_case = true;
                    }
                } else if !line.starts_with("//") {
                    break;
                }
            }
            let open = from + src[from..].find('{').expect("struct body");
            let close = balance(src, open).expect("balanced struct body");
            let body: String = src[open + 1..close]
                .lines()
                .map(|l| l.split("//").next().unwrap_or(""))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                !body.contains("#[serde("),
                "struct `{name}` carries a field-level `#[serde(..)]` — the IPC rule reads wire \
                 keys from field names; extend `repo_invariants/ipc.rs` before renaming a field \
                 on the wire"
            );
            let keys = split_top_level(&body, ',')
                .into_iter()
                .filter_map(|f| {
                    let (field, _) = f.split_once(':')?;
                    let field = field.trim();
                    let field = field
                        .strip_prefix("pub(crate) ")
                        .or_else(|| field.strip_prefix("pub "))
                        .unwrap_or(field)
                        .trim();
                    Some(if camel_case {
                        camel(field)
                    } else {
                        field.to_string()
                    })
                })
                .collect();
            return Some(keys);
        }
    }
    None
}

/// The struct name of a `Name { .. }` / `&Name { .. }` literal.
fn struct_literal_name(args: &str) -> Option<&str> {
    let a = args.strip_prefix('&').unwrap_or(args).trim_start();
    let brace = a.find('{')?;
    if !a.ends_with('}') {
        return None;
    }
    let name = a[..brace].trim();
    (!name.is_empty() && name.bytes().all(is_ident)).then_some(name)
}

/// The names of the private (non-`pub`) named-field structs declared in `src`:
/// the local argument structs a binding file defines for itself.
fn local_struct_names(src: &str) -> Vec<&str> {
    src.lines()
        .filter_map(|line| {
            let rest = line.trim_start().strip_prefix("struct ")?;
            let end = rest.bytes().position(|b| !is_ident(b))?;
            let (name, tail) = rest.split_at(end);
            (!name.is_empty() && (tail.starts_with('<') || tail.starts_with(" {"))).then_some(name)
        })
        .collect()
}

/// Every binding call outside the wrapper module, as (file, call).
fn all_calls() -> Vec<(String, Call)> {
    binding_files()
        .into_iter()
        .filter(|(f, _)| f != IPC_MODULE)
        .flat_map(|(f, src)| {
            binding_calls(&f, &src)
                .into_iter()
                .map(move |c| (f.clone(), c))
        })
        .collect()
}

fn commands_by_name() -> BTreeMap<String, Command> {
    sources::commands()
        .into_iter()
        .map(|c| (c.name.clone(), c))
        .collect()
}

// ---------------------------------------------------------------- rules

/// Every `#[tauri::command]` is in `generate_handler![]` exactly once, and
/// every registration is a command.
///
/// A command that is declared but never registered rejects at runtime with
/// "command not found"; the compiler cannot see it, because the attribute's
/// generated items are only referenced by the macro.
#[test]
fn every_command_is_registered_and_every_registration_is_a_command() {
    let declared: Vec<String> = sources::commands().into_iter().map(|c| c.name).collect();
    let registered = registered();

    let mut seen = BTreeSet::new();
    for name in &declared {
        assert!(
            seen.insert(name),
            "two `#[tauri::command]` fns are both named `{name}` — Tauri keys commands by fn \
             name alone, so one shadows the other at runtime; rename one"
        );
    }
    let mut seen_reg = BTreeSet::new();
    for name in &registered {
        assert!(
            seen_reg.insert(name),
            "`{name}` is listed twice in `generate_handler![]` (src/lib.rs); drop the duplicate"
        );
    }
    let unregistered: Vec<_> = seen.difference(&seen_reg).collect();
    assert!(
        unregistered.is_empty(),
        "{unregistered:?} are `#[tauri::command]`s missing from `generate_handler![]` \
         (src/lib.rs) — every binding call to them rejects with \"command not found\"; register \
         them"
    );
    let stale: Vec<_> = seen_reg.difference(&seen).collect();
    assert!(
        stale.is_empty(),
        "`generate_handler![]` registers {stale:?}, which no `#[tauri::command]` under \
         src/commands declares — remove the stale entries or restore the commands"
    );
    assert!(
        declared.len() >= 150,
        "only {} commands compared — the scan is broken, and a parity rule over nothing \
         passes vacuously",
        declared.len()
    );
}

/// Every command has a typed binding, and every binding names a real command.
#[test]
fn every_command_has_a_binding_and_every_binding_names_a_command() {
    let commands = commands_by_name();
    let calls = all_calls();
    let bound: BTreeSet<&str> = calls.iter().map(|(_, c)| c.command.as_str()).collect();
    for (file, call) in &calls {
        assert!(
            commands.contains_key(&call.command),
            "bindings/{file} invokes \"{}\", which no `#[tauri::command]` declares — a misspelt \
             or removed command rejects at runtime; fix the literal",
            call.command
        );
    }
    for name in commands.keys() {
        assert!(
            bound.contains(name.as_str()),
            "`#[tauri::command] {name}` has no typed binding under web-rs/src/bindings — add one \
             that calls `invoke_result(\"{name}\", ..)` (AGENTS.md: New Tauri command, step 3)"
        );
    }
    assert!(
        calls.len() >= 150,
        "found only {} binding calls — the scan is broken",
        calls.len()
    );
}

/// The keys a binding sends are exactly the parameters the command reads.
///
/// Tauri deserializes each parameter from the top-level args object under its
/// camelCase name; a renamed parameter or field rejects with "invalid args
/// `tenantId` for command …" and nothing else notices.
#[test]
fn binding_arg_keys_match_command_parameters() {
    let commands = commands_by_name();
    let files: BTreeMap<String, String> = binding_files().into_iter().collect();
    let common = files.get("common.rs").expect("bindings/common.rs");
    let mut compared = 0usize;
    for (file, call) in all_calls() {
        let Some(cmd) = commands.get(&call.command) else {
            continue; // reported by the binding-existence rule
        };
        let want: BTreeSet<String> = command_args(&cmd.params).iter().map(|p| camel(p)).collect();
        let got: BTreeSet<String> = if call.args == "()" {
            BTreeSet::new()
        } else {
            let Some(name) = struct_literal_name(&call.args) else {
                panic!(
                    "bindings/{file}: \"{}\" is invoked with `{}` — bind args through a named \
                     struct literal (`Name {{ .. }}`) or `()`, so the wire keys can be checked \
                     against the command's parameters",
                    call.command, call.args
                );
            };
            struct_wire_keys(name, &files[&file], common).unwrap_or_else(|| {
                panic!(
                    "bindings/{file}: argument struct `{name}` for \"{}\" is defined neither in \
                     that file nor in bindings/common.rs — define it there so the rule can read \
                     its fields",
                    call.command
                )
            })
        };
        assert_eq!(
            got, want,
            "bindings/{file}: \"{}\" sends keys {got:?} but `{}::{}` reads {want:?} — a key \
             mismatch rejects with \"invalid args\" at runtime; rename the field (Tauri camelCases \
             parameter names) or the parameter",
            call.command, cmd.module, cmd.name
        );
        compared += 1;
    }
    assert!(
        compared >= 150,
        "compared only {compared} arg sets — the scan is broken"
    );
}

/// A binding decodes the type its command returns, and a fallible command is
/// never bound through the infallible `invoke`.
#[test]
fn binding_return_types_match_their_commands() {
    let commands = commands_by_name();
    let mut compared = 0usize;
    for (file, call) in all_calls() {
        let Some(cmd) = commands.get(&call.command) else {
            continue;
        };
        let backend = strip_arc(&norm_type(&cmd.ret));
        let binding = match norm_type(&call.ret) {
            t if t.is_empty() => "()".to_string(),
            t => t,
        };
        if backend.starts_with("Result<") {
            assert!(
                call.fallible,
                "bindings/{file}: \"{}\" is fallible (`{}`) but bound through the infallible \
                 `invoke`, which panics the window on an Err — use `invoke_result` from \
                 `bindings::ipc`",
                call.command, cmd.ret
            );
            assert_eq!(
                binding, backend,
                "bindings/{file}: \"{}\" returns `{}` on the backend but its binding decodes \
                 `{}` — a shape mismatch fails only at runtime; make them the same type",
                call.command, cmd.ret, call.ret
            );
        } else {
            let t = if backend.is_empty() {
                "()".to_string()
            } else {
                backend.clone()
            };
            let ok = binding == t || binding == format!("Result<{t},UiError>");
            assert!(
                ok,
                "bindings/{file}: \"{}\" returns `{t}` (infallible) on the backend but its \
                 binding declares `{}` — return `{t}` or `Result<{t}, UiError>`",
                call.command, call.ret
            );
        }
        compared += 1;
    }
    assert!(
        compared >= 150,
        "compared only {compared} return types — the scan is broken"
    );
}

/// `bindings/ipc.rs` is the only door to `tauri_sys::core`'s invoke functions.
///
/// Upstream `invoke_result` `unwrap`s the rejection into a `UiError`; Tauri
/// rejects with a plain string for invalid args, an unknown command or a denied
/// permission, so a direct import turns any of those into a panic that freezes
/// the window with no message. `tauri_sys::core::is_tauri()` and
/// `tauri_sys::event` are not IPC calls and stay allowed.
#[test]
fn bindings_reach_tauri_sys_only_through_the_ipc_module() {
    let root = web_src();
    let wrapper = root.join("bindings").join(IPC_MODULE);
    let wrapper_src = std::fs::read_to_string(&wrapper).unwrap_or_else(|e| {
        panic!(
            "{} is missing ({e}) — it is the single IPC door that maps a non-UiError rejection \
             to code `ipc`",
            wrapper.display()
        )
    });
    assert!(
        wrapper_src.contains("tauri_sys::core::invoke_result"),
        "bindings/{IPC_MODULE} no longer calls `tauri_sys::core::invoke_result` — the wrapper \
         this rule protects has moved; update the rule"
    );

    let mut offenders = Vec::new();
    let mut scanned = 0usize;
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|f| f != "target") {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") || path == wrapper {
                continue;
            }
            let Ok(src) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            for (n, line) in src.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                if t.contains("tauri_sys::core") && (t.contains("invoke") || t.contains('*')) {
                    offenders.push(format!("{}:{}: {}", path.display(), n + 1, t));
                }
            }
        }
    }
    assert!(
        scanned > 50,
        "scanned only {scanned} files under web-rs/src"
    );
    assert!(
        offenders.is_empty(),
        "these reach `tauri_sys::core`'s invoke functions directly — import `invoke_result` \
         (or the infallible `invoke`) from `bindings::ipc` instead, which maps a rejection that \
         is not a `UiError` to code `ipc` rather than panicking:\n{}",
        offenders.join("\n")
    );
}

/// The bindings keep the compiler's dead-code lint, and a local argument
/// struct never restates a shape `bindings/common.rs` already defines.
///
/// A module-wide `#![allow(dead_code)]` once sat on `bindings/mod.rs`, and
/// behind it the argument structs of removed commands (`kv_set_secret`,
/// `resolve_permission`, `update_required_resource_access`, the
/// `export_audit_csv` registration) outlived them, along with a dozen
/// field-for-field copies of `TenantArg` / `ObjectIdArgs` / `AppIdArgs`.
/// `pub` items are exempt from the lint anyway, so the allow only ever hid
/// private leftovers.
#[test]
fn bindings_keep_the_dead_code_lint_and_reuse_the_common_arg_shapes() {
    let files = binding_files();
    let mut allows = Vec::new();
    for (file, src) in &files {
        for (n, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if !t.starts_with("//") && t.contains("allow(dead_code)") {
                allows.push(format!("bindings/{file}:{}: {t}", n + 1));
            }
        }
    }
    assert!(
        allows.is_empty(),
        "`allow(dead_code)` in the bindings hid the argument structs of removed commands \
         (`kv_set_secret`, `resolve_permission`, ...) — delete the leftover instead of allowing \
         it:\n{}",
        allows.join("\n")
    );

    let common = &files
        .iter()
        .find(|(f, _)| f == "common.rs")
        .expect("bindings/common.rs")
        .1;
    let shapes: Vec<(&str, BTreeSet<String>)> = common
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("pub struct "))
        .filter_map(|rest| {
            rest.split(|c: char| !c.is_alphanumeric() && c != '_')
                .next()
        })
        .map(|name| {
            let keys = struct_wire_keys(name, common, "")
                .unwrap_or_else(|| panic!("common.rs: cannot read `{name}`"));
            (name, keys)
        })
        .collect();
    assert!(
        shapes.len() >= 5,
        "read only {} shapes from bindings/common.rs — the scan is broken",
        shapes.len()
    );

    let mut compared = 0usize;
    let mut duplicates = Vec::new();
    for (file, src) in files.iter().filter(|(f, _)| f != "common.rs") {
        for name in local_struct_names(src) {
            let keys = struct_wire_keys(name, src, "")
                .unwrap_or_else(|| panic!("bindings/{file}: cannot read struct `{name}`"));
            if let Some((shared, _)) = shapes.iter().find(|(_, k)| *k == keys) {
                duplicates.push(format!(
                    "bindings/{file}: `{name}` sends {keys:?} — use `crate::bindings::{shared}`"
                ));
            }
            compared += 1;
        }
    }
    assert!(
        compared >= 40,
        "compared only {compared} local argument structs — the scan is broken"
    );
    assert!(
        duplicates.is_empty(),
        "these argument structs restate a shape bindings/common.rs defines — reuse the shared \
         struct so the wire format has one definition:\n{}",
        duplicates.join("\n")
    );
}

/// The regression guard for the guard: each shape below exists in the tree.
#[test]
fn the_ipc_scanners_read_the_shapes_the_tree_uses() {
    // A turbofish with `()` inside, wrapped the way rustfmt wraps it.
    let src = "pub async fn f() -> Result<(), UiError> {\n    invoke::<()>(\n        \"x\",\n        S { a },\n    )\n    .await\n}\n";
    assert_eq!(
        binding_calls("t.rs", src),
        vec![Call {
            command: "x".into(),
            args: "S { a }".into(),
            fallible: false,
            ret: "Result<(), UiError>".into(),
        }]
    );
    // A borrowed struct literal, an import line and a doc mention.
    let src = "use super::ipc::{invoke, invoke_result};\n/// calls invoke_result(\"doc\", ..)\npub async fn g(t: &str) -> Result<Vec<crate::X>, UiError> {\n    invoke_result(\"y\", &S { t }).await\n}\n";
    let calls = binding_calls("t.rs", src);
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].command, "y");
    assert_eq!(struct_literal_name(&calls[0].args), Some("S"));
    assert!(calls[0].fallible);
    assert_eq!(norm_type(&calls[0].ret), "Result<Vec<X>,UiError>");
    assert_eq!(struct_literal_name("()"), None);
    assert_eq!(struct_literal_name("args"), None);

    assert_eq!(
        command_args("state: State<'_, AppState>, ids: Vec<(String, u32)>, mut s: String"),
        vec!["ids".to_string(), "s".to_string()]
    );
    assert_eq!(
        command_args("mut tenant_id: String, app: AppHandle"),
        vec!["tenant_id".to_string()],
        "`mut ` must be stripped as a prefix, not as a character set"
    );
    assert_eq!(
        norm_type("Result<crate::dto::X, UiError>"),
        "Result<X,UiError>"
    );
    assert_eq!(
        norm_type("Result<Vec<azapptoolkit_core::models::Application>, crate::dto::UiError>"),
        "Result<Vec<Application>,UiError>"
    );
    assert_eq!(camel("service_principal_id"), "servicePrincipalId");
    assert_eq!(camel("tenant_id"), "tenantId");

    let common = "#[derive(Serialize)]\n#[serde(rename_all = \"camelCase\")]\npub struct S<'a> {\n    /// doc\n    pub tenant_id: &'a str,\n    pub ids: Vec<(String, u32)>,\n}\n";
    assert_eq!(
        struct_wire_keys("S", "", common),
        Some(BTreeSet::from(["tenantId".to_string(), "ids".to_string()]))
    );
    assert_eq!(struct_wire_keys("Missing", "", common), None);

    // Only private named-field structs are local argument structs.
    let decls = "#[derive(Serialize)]\nstruct A<'a> {\n    t: &'a str,\n}\nstruct B {\n}\npub struct C {}\npub struct D(pub String);\nstruct Ab;\n";
    assert_eq!(local_struct_names(decls), vec!["A", "B"]);

    // A doc comment that mentions the attribute is not a command.
    let doc = "/// behind a #[tauri::command] wrapper\nfn helper() {}\n    #[tauri::command]\nasync fn real() {}\n";
    let mention = doc.find("#[tauri::command]").expect("mention");
    let real = doc.rfind("#[tauri::command]").expect("real");
    assert!(!sources::command_attribute_at_line_start(doc, mention));
    assert!(sources::command_attribute_at_line_start(doc, real));
}

/// The GUI tests' throttled fixture is the message the backend really sends.
///
/// They used to mock "Too many requests", a string no client ever produced,
/// so nothing could see the real Display leak "retry after Some(30)s" into
/// the UI. Built through the real `UiError::from` path so a change to the
/// Display (or to how `ui_error_from!` copies it) fails here, not in front of an
/// operator.
#[test]
fn the_throttled_gui_fixture_is_the_backend_message() {
    let ui = azapptoolkit_dto::UiError::from(azapptoolkit_graph::GraphError::Throttled {
        retry_after_secs: Some(30),
    });
    assert_eq!(ui.code, "throttled");
    assert!(ui.retryable, "a throttle is retryable");
    let fixtures_rs = web_src().join("ipc_mock/fixtures.rs");
    let fixtures = std::fs::read_to_string(&fixtures_rs)
        .unwrap_or_else(|e| panic!("{}: {e}", fixtures_rs.display()));
    assert!(
        fixtures.contains(&format!("\"{}\"", ui.message)),
        "ipc_mock/fixtures.rs THROTTLED_MESSAGE must be the backend's throttled message \
         verbatim: {:?}",
        ui.message
    );
}
