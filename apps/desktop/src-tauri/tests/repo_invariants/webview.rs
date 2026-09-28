//! What the webview is granted: nothing it does not use.
//!
//! Every Graph, login, Key Vault, ARM, Exchange and Log Analytics call is
//! backend reqwest, and every updater or dialog use is a Rust API on the
//! `AppHandle` — neither is governed by the webview's CSP or its capability
//! file. So a remote `connect-src` origin or a plugin permission is a grant
//! nothing in the app uses, and it is exactly what a webview-side script bug
//! would reach for. Both are pinned here so they cannot quietly regrow.

/// Tauri's IPC transport. Tauri does **not** append these to `connect-src`
/// itself; without them its IPC script falls back to `postMessage`, which is
/// how invokes run today. Adding them later (to use the custom protocol) is
/// allowed; any other source is not.
const ALLOWED_CONNECT_SOURCES: &[&str] = &["'self'", "ipc:", "http://ipc.localhost"];

/// The sources of a CSP's `connect-src` directive, or `None` when it has none.
fn connect_src(csp: &str) -> Option<Vec<&str>> {
    csp.split(';').find_map(|directive| {
        let mut parts = directive.split_whitespace();
        (parts.next() == Some("connect-src")).then(|| parts.collect())
    })
}

/// Why a `connect-src` source list is rejected, or `None` when it is allowed.
fn connect_src_violation(sources: &[&str]) -> Option<String> {
    if !sources.contains(&"'self'") {
        return Some(format!("connect-src {sources:?} lacks 'self'"));
    }
    let extra: Vec<&&str> = sources
        .iter()
        .filter(|s| !ALLOWED_CONNECT_SOURCES.contains(s))
        .collect();
    (!extra.is_empty()).then(|| format!("connect-src grants {extra:?}"))
}

fn check_csp(which: &str, csp: &str) {
    let sources =
        connect_src(csp).unwrap_or_else(|| panic!("{which} has no connect-src directive: {csp}"));
    if let Some(why) = connect_src_violation(&sources) {
        panic!(
            "{which}: {why}. The WASM frontend has no HTTP client; every Graph, login, Key \
             Vault, ARM, Exchange and Log Analytics call is backend reqwest. The CSP governs \
             only the webview, so a remote origin here is a grant nothing uses. The only \
             allowed additions are `ipc: http://ipc.localhost` — Tauri's IPC transport, which \
             Tauri does not append itself."
        );
    }
}

#[test]
fn the_webview_csp_connects_to_nothing_remote() {
    let conf: serde_json::Value = serde_json::from_str(include_str!("../../tauri.conf.json"))
        .expect("tauri.conf.json is not JSON");
    let security = &conf["app"]["security"];
    let csp = security["csp"]
        .as_str()
        .expect("tauri.conf.json app.security.csp must be a string");
    check_csp("app.security.csp", csp);
    // A dev CSP must not bring the list back through the side door.
    match &security["devCsp"] {
        serde_json::Value::Null => {}
        serde_json::Value::String(dev) => check_csp("app.security.devCsp", dev),
        other => panic!("app.security.devCsp must be a string when set, got {other}"),
    }
}

#[test]
fn the_webview_capability_grants_only_core_default() {
    let cap: serde_json::Value =
        serde_json::from_str(include_str!("../../capabilities/default.json"))
            .expect("capabilities/default.json is not JSON");
    assert_eq!(
        cap["permissions"],
        serde_json::json!(["core:default"]),
        "capabilities/default.json must grant exactly [\"core:default\"]. Backend plugin use \
         (`app.updater()`, `app.dialog()`) is not capability-gated, so a plugin permission \
         here only lets webview script call the plugin directly — and `updater:*` in \
         particular exposes `download_and_install`, bypassing the interactive \
         `UpdateSplash`, the silent-install path AGENTS.md forbids."
    );

    // A second capability file would be merged in and could grant `updater:*`
    // past the exact-list check above.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities");
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|entry| entry.expect("capabilities entry").file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    files.sort();
    assert_eq!(
        files,
        vec!["default.json".to_string()],
        "capabilities/ must hold only default.json; any other capability file widens the \
         webview's grants past the check above"
    );
}

/// The regression guard for the guard: the extractor finds the directive in
/// the shapes a CSP takes, and the rule rejects a remote origin while
/// accepting Tauri's IPC transport — so the tests above cannot pass vacuously.
#[test]
fn the_connect_src_scanner_reads_real_csp_shapes() {
    let remote =
        "default-src 'self'; connect-src 'self' https://graph.microsoft.com; img-src 'self'";
    let sources = connect_src(remote).expect("connect-src present");
    assert_eq!(sources, vec!["'self'", "https://graph.microsoft.com"]);
    assert!(connect_src_violation(&sources).is_some());

    let ipc = "default-src 'self';connect-src 'self' ipc: http://ipc.localhost";
    let sources = connect_src(ipc).expect("connect-src present");
    assert_eq!(sources, vec!["'self'", "ipc:", "http://ipc.localhost"]);
    assert_eq!(connect_src_violation(&sources), None);

    assert!(
        connect_src_violation(&["ipc:"]).is_some(),
        "'self' is required"
    );
    assert_eq!(connect_src("default-src 'self'; img-src data:"), None);
    // A directive whose name merely starts with `connect-src` is not it.
    assert_eq!(connect_src("connect-srcx 'self'"), None);
}
