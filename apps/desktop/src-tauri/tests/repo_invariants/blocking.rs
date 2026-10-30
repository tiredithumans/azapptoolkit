//! Blocking work stays off the tokio workers and the main thread: the
//! `settings.json` writer.
//!
//! `UserSettings::mutate` holds a process-wide mutex while it waits on the
//! cross-process lock on `settings.lock`, which a second app instance or a hung
//! network mount can hold for as long as it likes, and then writes and fsyncs
//! the file. Run inline in async code, that wait parks a tokio worker and every
//! task queued on it; run in a synchronous command, which Tauri executes on the
//! main thread, it freezes the UI. Through the mutex either one stalls every
//! other settings writer too. The Key Vault rotation's vault binding, the
//! sign-in, restore and sign-out account pointer and the two Settings saves all
//! ran it that way. The OS keyring has the same shape and the same pin
//! (`keyring_calls_stay_on_the_blocking_pool`, in the auth crate).

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::path::{Path, PathBuf};

use super::sources::{calls, code_mask, functions_in, strip_tests};

/// The blocking settings writer as the rule's seeds spell a call to it: by
/// path, and as `Self::mutate` from a wrapper inside `impl UserSettings`. The
/// bare `Self::` form is unambiguous only while `UserSettings::mutate` is the
/// tree's one `fn mutate`, which [`settings_writes_run_on_the_blocking_pool`]
/// asserts. Every plain sync `fn` that runs a seed inline is a writer too,
/// derived to a fixpoint by [`scan`].
const SETTINGS_WRITERS: [&str; 2] = ["UserSettings::mutate", "Self::mutate"];

/// The helper every settings writer awaits instead of running `mutate`.
const OFF_WORKER_HELPER: &str = "mutate_settings_off_worker";

/// The async contexts that await [`OFF_WORKER_HELPER`]: the Key Vault
/// rotation's binding, the two account-pointer writers and the two Settings
/// commands. A floor, not the set.
const HELPER_CALLERS_FLOOR: usize = 5;

/// `src` with every comment and string or char literal blanked (newlines
/// kept), so prose or a message that names the writer is never read as a call.
fn code_only(src: &str) -> String {
    let mask = code_mask(src);
    src.char_indices()
        .map(|(i, c)| if mask[i] || c == '\n' { c } else { ' ' })
        .collect()
}

/// The index of the `)` or `}` that closes the delimiter at `open`, in code
/// whose comments and literals are already blanked.
fn closing(code: &str, open: usize) -> Option<usize> {
    let bytes = code.as_bytes();
    let (opener, closer) = match bytes.get(open)? {
        b'(' => (b'(', b')'),
        b'{' => (b'{', b'}'),
        _ => return None,
    };
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        if b == opener {
            depth += 1;
        } else if b == closer {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}

/// `code` with every byte in `spans` turned into a space, newlines kept.
fn blank(code: &str, spans: &[Range<usize>]) -> String {
    let mut bytes = code.as_bytes().to_vec();
    for span in spans {
        for b in &mut bytes[span.clone()] {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    }
    // Every span starts and ends at an ASCII delimiter and is blanked whole.
    String::from_utf8(bytes).expect("blanked code stays UTF-8")
}

/// The argument list of every `spawn_blocking(…)` call in `code`, whichever
/// runtime's (`tokio::task::`, `tauri::async_runtime::`, a handle's): what runs
/// inside one runs on the blocking pool.
fn blocking_pool_spans(code: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    for (at, name) in code.match_indices("spawn_blocking") {
        if code[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            continue;
        }
        let after = &code[at + name.len()..];
        let open = at + name.len() + (after.len() - after.trim_start().len());
        if code.as_bytes().get(open) != Some(&b'(') {
            continue;
        }
        if let Some(close) = closing(code, open) {
            out.push(open + 1..close);
        }
    }
    out
}

/// The `{ … }` body of every `async` block and every async closure with a
/// block body in `code`. Not `async fn` items: [`functions_in`] reports those
/// as functions of their own.
fn async_block_spans(code: &str) -> Vec<Range<usize>> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = Vec::new();
    for (at, keyword) in code.match_indices("async") {
        let after = &code[at + keyword.len()..];
        if code[..at].chars().next_back().is_some_and(ident) || after.starts_with(ident) {
            continue;
        }
        let mut rest = after.trim_start();
        if let Some(moved) = rest.strip_prefix("move") {
            if moved.starts_with(ident) {
                continue;
            }
            rest = moved.trim_start();
        }
        if let Some(params) = rest.strip_prefix('|') {
            let Some(end) = params.find('|') else {
                continue;
            };
            rest = params[end + 1..].trim_start();
        }
        // `async fn`, or a closure whose body is a bare expression.
        if !rest.starts_with('{') {
            continue;
        }
        let open = code.len() - rest.len();
        if let Some(close) = closing(code, open) {
            out.push(open..close + 1);
        }
    }
    out
}

/// Every `#[tauri::command]` in `code`, by function name, and whether its
/// attribute asks for the async runtime. Tauri runs a sync command on the main
/// thread, unless it is marked `#[tauri::command(async)]`: then it calls the
/// body inside an `async` block on a tokio worker, as for an `async fn`.
fn commands_in(code: &str) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    for (at, attr) in code.match_indices("#[tauri::command") {
        let rest = &code[at + attr.len()..];
        let runtime = rest.starts_with('(')
            && rest.find(')').is_some_and(|end| {
                rest[1..end]
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .any(|word| word == "async")
            });
        let Some(fn_at) = rest.find("fn ") else {
            continue;
        };
        let name = rest[fn_at + 3..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        out.insert(name, runtime);
    }
    out
}

/// Where a function's body runs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RunsOn {
    /// An `async fn` or a `#[tauri::command(async)]`: on a tokio worker.
    Worker,
    /// Any other `#[tauri::command]`: on the main thread, which also runs the
    /// webview, so a wait there freezes the UI.
    MainThread,
    /// Any other sync `fn`: on whichever thread calls it.
    Caller,
}

/// Whether `file`'s parent module mounts it test-only: `#[cfg(test)]` on the
/// line right above its `mod` declaration. [`strip_tests`] cannot see a cfg
/// that sits in another file.
fn mounted_test_only(file: &Path) -> bool {
    let (Some(dir), Some(stem)) = (file.parent(), file.file_stem().and_then(|s| s.to_str())) else {
        return false;
    };
    if matches!(stem, "mod" | "lib" | "main") {
        return false;
    }
    let decls =
        ["mod", "pub mod", "pub(crate) mod", "pub(super) mod"].map(|v| format!("{v} {stem};"));
    [
        dir.join("mod.rs"),
        dir.join("lib.rs"),
        dir.with_extension("rs"),
    ]
    .iter()
    .filter_map(|p| std::fs::read_to_string(p).ok())
    .any(|parent| {
        let lines: Vec<&str> = parent.lines().map(str::trim).collect();
        lines
            .windows(2)
            .any(|w| w[0] == "#[cfg(test)]" && decls.iter().any(|d| w[1] == d))
    })
}

/// Every production `.rs` file of the desktop backend and of each shared
/// crate's `src`, as (path from the repo root, code with test items stripped
/// and comments and literals blanked). A `tests/` directory and a file mounted
/// test-only ([`mounted_test_only`]) are skipped. An unreadable directory
/// fails the walk rather than shrinking it.
fn backend_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("apps/desktop/src-tauri → repo root")
        .to_path_buf();
    let mut stack: Vec<PathBuf> = vec![root.join("apps/desktop/src-tauri/src")];
    let crates = std::fs::read_dir(root.join("crates"))
        .unwrap_or_else(|e| panic!("read {}: {e}", root.join("crates").display()));
    for entry in crates.flatten() {
        if entry.path().is_dir() {
            stack.push(entry.path().join("src"));
        }
    }
    let mut out = Vec::new();
    while let Some(dir) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_none_or(|n| n != "tests") {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") || mounted_test_only(&path) {
                continue;
            }
            let src = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            let name = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .display()
                .to_string();
            out.push((name.replace('\\', "/"), code_only(&strip_tests(&src))));
        }
    }
    out.sort();
    assert!(
        out.len() > 100,
        "walked only {} backend sources under {} — the walk is broken, and a rule that scans \
         nothing passes vacuously",
        out.len(),
        root.display()
    );
    out
}

/// What [`scan`] derived and found.
struct Findings {
    /// [`SETTINGS_WRITERS`] plus every plain sync `fn` (not a command) that
    /// runs a writer inline (outside `spawn_blocking` and outside an `async`
    /// block), to a fixpoint.
    writers: BTreeSet<String>,
    /// Every async context or sync command that runs a writer inline, as
    /// `file: what`.
    offenders: Vec<String>,
    /// Every async context that calls [`OFF_WORKER_HELPER`], as `file: what`.
    helper_callers: Vec<String>,
}

/// Derives the writers from `files` (code-only sources, as
/// [`backend_sources`] returns them) and finds every body that calls one
/// outside a `spawn_blocking(…)` argument list while it runs on a tokio worker
/// (an `async fn`, a `#[tauri::command(async)]`, an `async` block in a sync
/// `fn`) or on the main thread (a sync `#[tauri::command]`).
fn scan(files: &[(String, String)]) -> Findings {
    // (file, fn name, where it runs, body with the pooled calls blanked)
    let mut units: Vec<(&str, String, RunsOn, String)> = Vec::new();
    for (file, code) in files {
        let commands = commands_in(code);
        for f in functions_in(code) {
            let runs = match (f.is_async, commands.get(&f.name)) {
                (true, _) | (false, Some(true)) => RunsOn::Worker,
                (false, Some(false)) => RunsOn::MainThread,
                (false, None) => RunsOn::Caller,
            };
            let body = blank(&f.body, &blocking_pool_spans(&f.body));
            units.push((file, f.name, runs, body));
        }
    }

    let mut writers: BTreeSet<String> = SETTINGS_WRITERS.iter().map(|w| (*w).to_string()).collect();
    loop {
        let before = writers.len();
        for (_, name, runs, body) in &units {
            if *runs != RunsOn::Caller || writers.contains(name) {
                continue;
            }
            let inline = blank(body, &async_block_spans(body));
            if writers.iter().any(|w| calls(&inline, w)) {
                writers.insert(name.clone());
            }
        }
        if writers.len() == before {
            break;
        }
    }

    let (mut offenders, mut helper_callers) = (Vec::new(), Vec::new());
    for (file, name, runs, body) in &units {
        let contexts: Vec<(&str, &str)> = match runs {
            RunsOn::Worker => vec![("", body.as_str())],
            RunsOn::MainThread => vec![(" (a sync command, on the main thread)", body.as_str())],
            RunsOn::Caller => async_block_spans(body)
                .into_iter()
                .map(|span| (" (an async block)", &body[span]))
                .collect(),
        };
        for (what, code) in contexts {
            if let Some(writer) = writers.iter().find(|w| calls(code, w)) {
                offenders.push(format!("{file}: `{name}`{what} runs `{writer}` inline"));
            }
            if *runs != RunsOn::MainThread && calls(code, OFF_WORKER_HELPER) {
                helper_callers.push(format!("{file}: `{name}`{what}"));
            }
        }
    }
    offenders.sort();
    offenders.dedup();
    helper_callers.sort();
    helper_callers.dedup();
    Findings {
        writers,
        offenders,
        helper_callers,
    }
}

/// Settings writes run on the blocking pool, never inline on a tokio worker or
/// on the main thread.
///
/// Derived from the source rather than listed: the subjects are every `async
/// fn`, every `#[tauri::command(async)]` and every `async` block (a tokio
/// worker) and every sync `#[tauri::command]` (the main thread, which Tauri
/// runs them on) in the desktop backend and the shared crates. The writers are
/// [`SETTINGS_WRITERS`] plus every plain sync `fn` that runs one inline, to a
/// fixpoint, so a sync helper around the write (`AppState::remember_account`
/// was one) cannot hide it from its callers. A call inside a
/// `spawn_blocking(…)` argument list runs on the pool, which
/// `state::mutate_settings_off_worker` does for every writer.
///
/// Blind spots: a wrapper is followed by name, not by type, so two functions
/// that share its name are both treated as writers; and the `.setup(…)`
/// closure in `lib.rs` also runs on the main thread but is a closure, not a
/// command, so it is not scanned.
#[test]
fn settings_writes_run_on_the_blocking_pool() {
    let files = backend_sources();
    let found = scan(&files);
    assert!(
        found.offenders.is_empty(),
        "the blocking settings writer runs inline on a tokio worker or the main thread. It waits \
         on the cross-process `settings.lock` while holding the process mutex: on a worker that \
         parks every task queued on it, and in a sync command it freezes the UI, for as long as \
         another instance or a hung mount holds the lock. Await \
         `state::mutate_settings_off_worker` from an `async` fn or command instead, and make a \
         sync wrapper `async` around it. If this lists functions that never touch settings.json, \
         a wrapper's name collides with one they call (the scan matches by name, not by type): \
         rename the wrapper.\n  {}\n(writers: {:?})",
        found.offenders.join("\n  "),
        found.writers
    );

    // `Self::mutate` is a seed only because no other type has a `fn mutate`.
    let mutates = files
        .iter()
        .flat_map(|(_, code)| functions_in(code))
        .filter(|f| f.name == "mutate")
        .count();
    assert_eq!(
        mutates, 1,
        "found {mutates} `fn mutate` definitions; the scan expects exactly one, \
         `UserSettings::mutate`. None: the writer was renamed, so update `SETTINGS_WRITERS`. More: \
         a bare `Self::mutate(` could now mean another type's method, so limit that seed to \
         `impl UserSettings`"
    );

    // The floors: a scan that sees no pooled write, or fewer awaiting writers
    // than the tree has, passes vacuously.
    let call = format!("{}(", SETTINGS_WRITERS[0]);
    let pooled: usize = files
        .iter()
        .map(|(_, code)| {
            let inline = blank(code, &blocking_pool_spans(code));
            code.matches(&call).count() - inline.matches(&call).count()
        })
        .sum();
    assert!(
        pooled >= 1,
        "found no `{call}` inside a `spawn_blocking(…)` — the off-worker helper moved, the writer \
         was renamed, or the scan is broken"
    );
    assert!(
        found.helper_callers.len() >= HELPER_CALLERS_FLOOR,
        "found {} async contexts awaiting `{OFF_WORKER_HELPER}`, expected at least \
         {HELPER_CALLERS_FLOOR} — a writer moved off the helper, the helper was renamed, or the \
         scan is broken:\n  {}",
        found.helper_callers.len(),
        found.helper_callers.join("\n  ")
    );
}

/// The rule follows a wrapper through another wrapper (declared below its
/// caller, so one pass in source order is not enough), sees an `async` block or
/// async closure in a sync `fn`, a `#[tauri::command(async)]` body, a sync
/// command and a wrapper inside `impl UserSettings` that calls `Self::mutate`,
/// counts the async callers of the off-worker helper, and is satisfied by
/// `spawn_blocking`, by a plain sync helper (only where it is called from
/// counts), and by prose or a literal naming the writer.
#[test]
fn the_settings_writer_rule_follows_wrappers_and_async_blocks() {
    let src = r#"
pub async fn inline_in_async(dir: PathBuf) {
    let _ = UserSettings::mutate(&dir, |s| s.client_id = None);
}
pub async fn through_wrappers(state: State<'_, AppState>) {
    state.outer_wrapper();
}
impl AppState {
    pub fn outer_wrapper(&self) {
        inner_wrapper(&self.dir);
    }
}
fn inner_wrapper(dir: &Path) {
    let _ = azapptoolkit_core::settings::UserSettings::mutate(dir, |_| ());
}
pub async fn pooled(dir: PathBuf) {
    let _ = tauri::async_runtime::spawn_blocking(move || {
        UserSettings::mutate(&dir, |_| ())
    })
    .await;
    let _ = tokio::task::spawn_blocking(move || inner_wrapper(&dir)).await;
}
#[tauri::command]
pub fn sync_command(dir: PathBuf) {
    // Tauri runs this on the main thread: UserSettings::mutate( freezes the UI.
    let _ = UserSettings::mutate(&dir, |_| ());
}
#[tauri::command(async)]
pub fn runtime_command(dir: PathBuf) {
    let _ = UserSettings::mutate(&dir, |_| ());
}
fn spawns_a_task(dir: PathBuf) {
    tauri::async_runtime::spawn(async move {
        inner_wrapper(&dir);
    });
}
fn builds_an_async_closure(dir: PathBuf) -> impl AsyncFnOnce(u8) {
    async move |_n: u8| {
        inner_wrapper(&dir);
    }
}
pub async fn names_it_only() {
    tracing::info!("UserSettings::mutate(&dir, f) holds the lock");
}
impl UserSettings {
    pub fn set_flag(dir: &Path) -> std::io::Result<()> {
        Self::mutate(dir, |s| s.auto_update = false).map(|_| ())
    }
}
pub async fn through_a_settings_method(dir: PathBuf) {
    let _ = UserSettings::set_flag(&dir);
}
pub async fn awaits_the_helper(dir: PathBuf) {
    let _ = crate::state::mutate_settings_off_worker(dir, |_| ()).await;
}
"#;
    let found = scan(&[("x.rs".to_string(), code_only(src))]);
    assert_eq!(
        found.writers.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "Self::mutate",
            "UserSettings::mutate",
            "inner_wrapper",
            "outer_wrapper",
            "set_flag"
        ],
        "a plain sync wrapper is a writer, to a fixpoint; an async block and a command are not"
    );
    assert_eq!(
        found.offenders,
        [
            "x.rs: `builds_an_async_closure` (an async block) runs `inner_wrapper` inline",
            "x.rs: `inline_in_async` runs `UserSettings::mutate` inline",
            "x.rs: `runtime_command` runs `UserSettings::mutate` inline",
            "x.rs: `spawns_a_task` (an async block) runs `inner_wrapper` inline",
            "x.rs: `sync_command` (a sync command, on the main thread) runs \
             `UserSettings::mutate` inline",
            "x.rs: `through_a_settings_method` runs `set_flag` inline",
            "x.rs: `through_wrappers` runs `outer_wrapper` inline",
        ],
    );
    assert_eq!(found.helper_callers, ["x.rs: `awaits_the_helper`"]);
}
