//! Pins the demo's load-bearing invariant: every **infallible** `invoke()` /
//! `invoke::<()>()` in `src/bindings/` must have a fixture registered in
//! `demo::register_fixtures`.
//!
//! Why it matters: the mock IPC bridge answers an unregistered route with a
//! *rejected* promise. `invoke_result` turns that into an `Err` the UI renders,
//! but the infallible form has nowhere to put it and panics — taking down the
//! whole published GitHub Pages page, not just one widget. AGENTS.md states the
//! rule and `demo/mod.rs` repeats it in a doc comment; nothing enforced it, so
//! the failure only showed up by loading the deployed demo and watching it die.
//!
//! Runs natively under `just web-test` (no WASM, no browser) — it only reads
//! source text. Gated OFF for wasm32, the mirror of the `tests/gui_*.rs`
//! shards' `#![cfg(target_arch = "wasm32")]`: this reads the filesystem, which
//! does not exist in the browser, and `just web-itest` builds every test target.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Commands that are deliberately NOT mocked, with the reason they cannot reach
/// the demo. Keep this list short and justified — every entry is a page-crash
/// waiting to happen if the reasoning stops holding.
///
/// Empty today, and that is the healthy state: every infallible invoke in the
/// bindings currently has a fixture. The mechanism stays for the case where a
/// command genuinely cannot be reached.
const NOT_DEMO_REACHABLE: &[(&str, &str)] = &[];

/// Extracts the command name from every infallible `invoke` call in `src`.
///
/// `invoke_result(...)` is excluded by construction: the scan requires the
/// character right after `invoke` to start a turbofish or an argument list.
fn infallible_invoked_commands(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let bytes = src.as_bytes();
    let mut from = 0;
    while let Some(rel) = src[from..].find("invoke") {
        let start = from + rel;
        from = start + "invoke".len();

        // `invoke_result` / `invoked` / an identifier ending in `invoke`.
        let next = bytes.get(from).copied().unwrap_or(b' ');
        if next != b'(' && next != b':' {
            continue;
        }
        if start > 0 {
            let prev = bytes[start - 1];
            if prev.is_ascii_alphanumeric() || prev == b'_' {
                continue;
            }
        }
        // First string literal after the call opens is the command name.
        let tail = &src[from..];
        let Some(open) = tail.find('"') else { continue };
        // Guard against running past the call into unrelated code.
        if tail[..open].contains(';') {
            continue;
        }
        let after = &tail[open + 1..];
        let Some(close) = after.find('"') else {
            continue;
        };
        out.insert(after[..close].to_string());
    }
    out
}

fn read_dir_sources(dir: &Path) -> String {
    let mut all = String::new();
    let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.extension().is_some_and(|e| e == "rs") {
            all.push_str(&fs::read_to_string(&path).expect("read binding source"));
            all.push('\n');
        }
    }
    all
}

#[test]
fn every_infallible_invoke_has_a_demo_fixture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bindings = read_dir_sources(&root.join("src/bindings"));
    let demo = fs::read_to_string(root.join("src/demo/mod.rs")).expect("read demo/mod.rs");

    let commands = infallible_invoked_commands(&bindings);
    assert!(
        commands.len() >= 5,
        "the scan found only {} infallible invokes — it is broken, not the demo",
        commands.len()
    );

    let exempt: BTreeSet<&str> = NOT_DEMO_REACHABLE.iter().map(|(c, _)| *c).collect();
    let missing: Vec<&String> = commands
        .iter()
        .filter(|c| !exempt.contains(c.as_str()))
        // A registration names the command in a `mock_*("name", ...)` call.
        .filter(|c| !demo.contains(&format!("\"{c}\"")))
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
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let bindings = read_dir_sources(&root.join("src/bindings"));
    let demo = fs::read_to_string(root.join("src/demo/mod.rs")).expect("read demo/mod.rs");
    let commands = infallible_invoked_commands(&bindings);

    for (command, reason) in NOT_DEMO_REACHABLE {
        assert!(
            commands.contains(*command),
            "`{command}` is exempted (\"{reason}\") but is no longer an \
             infallible invoke — drop the entry"
        );
        assert!(
            !demo.contains(&format!("\"{command}\"")),
            "`{command}` is exempted as unreachable but IS registered in \
             register_fixtures — drop the exemption so the fixture is actually \
             required"
        );
    }
}

#[test]
fn the_scan_ignores_the_fallible_wrapper() {
    // `invoke_result` returns Err on a rejected promise, so it is safe
    // unregistered — and it must not inflate the required-fixture set.
    let src = r#"
        pub async fn a() -> Result<X, UiError> { invoke_result("safe_command", ()).await }
        pub async fn b() -> Y { invoke("must_be_mocked", ()).await }
        pub async fn c() { invoke::<()>("also_mocked", ()).await }
    "#;
    let got = infallible_invoked_commands(src);
    assert!(got.contains("must_be_mocked"));
    assert!(got.contains("also_mocked"));
    assert!(!got.contains("safe_command"), "got: {got:?}");
}
