//! Repo dependency-policy checks that no compiler or linter can express.
//!
//! Lives here rather than in a shared crate because these files govern the
//! dependency graph of the thing that actually ships — the desktop app.

/// The RUSTSEC advisory ids inside an `ignore = [ ... ]` array.
///
/// Deliberately a small hand-rolled scan rather than a TOML dependency: this
/// runs in `just test` on every platform, and pulling a parser in for two
/// string arrays would be the kind of dependency AGENTS.md tells us to avoid.
fn ignored_advisories(toml_src: &str) -> Vec<&str> {
    let Some(start) = toml_src.find("ignore = [") else {
        return Vec::new();
    };
    let rest = &toml_src[start..];
    let end = rest.find(']').map(|i| start + i).unwrap_or(toml_src.len());
    let mut out: Vec<&str> = toml_src[start..end]
        .lines()
        // Skip commented-out ids so the rationale prose above each entry (which
        // quotes ids freely) can't be mistaken for an active ignore.
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let open = line.find('"')?;
            let after = &line[open + 1..];
            let close = after.find('"')?;
            Some(&after[..close])
        })
        .filter(|id| id.starts_with("RUSTSEC-"))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// `cargo audit` reads `.cargo/audit.toml`; `cargo deny check advisories` reads
/// `deny.toml`. Both run as required CI checks over the same dependency graph,
/// so an id suppressed in one and not the other means a gate fails on a risk the
/// other already accepted — and the two files carry only a "keep this in sync"
/// comment to prevent it. This is that comment, enforced.
///
/// Adding an ignore? Put it in BOTH files with the same rationale + drop
/// condition. Dropping one? Remove it from both.
#[test]
fn the_two_advisory_ignore_lists_stay_in_sync() {
    let deny = ignored_advisories(include_str!("../../../../deny.toml"));
    let audit = ignored_advisories(include_str!("../../../../.cargo/audit.toml"));

    assert!(
        !deny.is_empty(),
        "parsed no ignores out of deny.toml — the scan broke, not the policy"
    );
    assert_eq!(
        deny, audit,
        "deny.toml and .cargo/audit.toml ignore different advisory sets.\n  \
         deny.toml:        {deny:?}\n  .cargo/audit.toml: {audit:?}"
    );
}

/// The `[advisories]` block in `deny.toml` is only worth maintaining if the
/// recipe that reads it actually asks for the check. It did not for a long time:
/// both recipes ran `check bans licenses sources`, so `yanked = "deny"` was
/// enforced by nothing and the ignore list read as load-bearing when only
/// `cargo audit` consulted it.
#[test]
fn both_deny_recipes_run_the_advisories_check() {
    let justfile = include_str!("../../../../justfile");
    let recipes: Vec<&str> = justfile
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("cargo deny"))
        .collect();

    assert_eq!(
        recipes.len(),
        2,
        "expected exactly the `deny` and `web-deny` recipes: {recipes:?}"
    );
    for recipe in recipes {
        assert!(
            recipe.contains("advisories"),
            "`{recipe}` does not run the advisories check, so deny.toml's \
             [advisories] block is config nobody executes"
        );
    }
}

/// `just machete` (verify-full + the CI `deny` job) fails on a declared-but-unused
/// dependency, and `[package.metadata.cargo-machete] ignored` is its escape hatch.
/// The only legitimate entry today is `thiserror` in a crate that invokes
/// `azapptoolkit_core::http_error_enum!`: the macro's expansion names
/// `::thiserror::Error`, which cargo-machete cannot see. Anything else in that
/// list is a dead dependency hidden from the gate, so this keeps the hatch from
/// becoming a dumping ground.
#[test]
fn machete_ignores_are_only_the_macro_expanded_thiserror() {
    use std::path::{Path, PathBuf};

    fn mentions_macro(dir: &Path) -> bool {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let path = entry.path();
            if path.is_dir() {
                mentions_macro(&path)
            } else {
                path.extension().is_some_and(|ext| ext == "rs")
                    && std::fs::read_to_string(&path)
                        .is_ok_and(|src| src.contains("http_error_enum!"))
            }
        })
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut crate_dirs: Vec<PathBuf> = std::fs::read_dir(root.join("crates"))
        .expect("read crates/")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.join("Cargo.toml").is_file())
        .collect();
    crate_dirs.push(root.join("apps/desktop/src-tauri"));
    crate_dirs.push(root.join("apps/desktop/web-rs"));

    let mut with_ignores = Vec::new();
    for dir in crate_dirs {
        let manifest = std::fs::read_to_string(dir.join("Cargo.toml"))
            .unwrap_or_else(|e| panic!("read {}: {e}", dir.join("Cargo.toml").display()));
        let Some(start) = manifest.find("[package.metadata.cargo-machete]") else {
            continue;
        };
        let ignored: Vec<&str> = manifest[start..]
            .lines()
            .skip(1)
            .take_while(|line| !line.trim_start().starts_with('['))
            .map(str::trim)
            .filter(|line| line.starts_with("ignored"))
            .collect();
        assert_eq!(
            ignored,
            [r#"ignored = ["thiserror"]"#],
            "{}: only the macro-expanded `thiserror` may be hidden from `just machete`; \
             any other ignored dependency is dead — remove it instead",
            dir.display()
        );
        assert!(
            mentions_macro(&dir.join("src")),
            "{} ignores `thiserror` for cargo-machete but never invokes \
             `http_error_enum!`, so nothing uses it — remove the dependency and the ignore",
            dir.display()
        );
        with_ignores.push(dir);
    }

    assert!(
        with_ignores.len() >= 3,
        "expected the arm/graph/keyvault ignores; found {with_ignores:?} — the scan broke"
    );
}

/// The synchronous-lock spellings [`sync_locks_are_parking_lot`] rejects, found
/// in one source text: a path through `std::sync::` naming `Mutex` / `RwLock`
/// (and their guards), or a `use std::sync::{…}` group importing one.
fn std_sync_locks_in(src: &str) -> Vec<String> {
    const LOCKS: [&str; 5] = [
        "Mutex",
        "MutexGuard",
        "RwLock",
        "RwLockReadGuard",
        "RwLockWriteGuard",
    ];
    let mut out = Vec::new();
    for token in [
        "std::sync::Mutex",
        "std::sync::RwLock",
        "std::sync::MutexGuard",
    ] {
        if src.contains(token) {
            out.push(token.to_string());
        }
    }
    let mut rest = src;
    while let Some(at) = rest.find("std::sync::{") {
        let group = &rest[at + "std::sync::{".len()..];
        // Balanced to the group's own `}` (a nested `atomic::{…}` is allowed).
        let mut depth = 1usize;
        let end = group
            .char_indices()
            .find(|&(_, c)| {
                match c {
                    '{' => depth += 1,
                    '}' => depth -= 1,
                    _ => {}
                }
                depth == 0
            })
            .map_or(group.len(), |(i, _)| i);
        let items = &group[..end];
        if items
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|ident| LOCKS.contains(&ident))
        {
            out.push(format!("use std::sync::{{{items}}}"));
        }
        rest = &group[end..];
    }
    out
}

#[test]
fn the_std_lock_detector_sees_the_import_forms() {
    assert!(!std_sync_locks_in("use std::sync::{Arc, Mutex};").is_empty());
    assert!(!std_sync_locks_in("use std::sync::{\n    Arc,\n    RwLock,\n};").is_empty());
    assert!(!std_sync_locks_in("static L: std::sync::Mutex<()> = todo!();").is_empty());
    assert!(
        !std_sync_locks_in("use std::sync::{atomic::{AtomicUsize, Ordering}, Mutex as M};")
            .is_empty()
    );
    // Not a lock, or not std's.
    assert!(std_sync_locks_in("use std::sync::{Arc, OnceLock};").is_empty());
    assert!(std_sync_locks_in("use std::sync::{atomic::{AtomicBool, Ordering}, Arc};").is_empty());
    assert!(std_sync_locks_in("use tokio::sync::{Mutex, RwLock};").is_empty());
    assert!(std_sync_locks_in("use parking_lot::{Mutex, RwLock};").is_empty());
}

/// Synchronous locks are `parking_lot` (no poisoning, a const `new` for
/// statics); a lock held across `.await` is `tokio::sync`. The std pair used to
/// sit beside `parking_lot` in the same files, each with a paragraph of
/// poison-recovery code `parking_lot` makes moot. Production code only: each
/// file is cut at its first `#[cfg(test)]`, and `tests.rs` files are skipped.
/// `web-rs` (wasm, its own lockfile) is out of scope.
#[test]
fn sync_locks_are_parking_lot() {
    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path.file_name().is_some_and(|n| n != "tests.rs")
            {
                out.push(path);
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root");
    let mut files = Vec::new();
    let crates = std::fs::read_dir(root.join("crates")).expect("crates/ is readable");
    for krate in crates.flatten() {
        rust_files(&krate.path().join("src"), &mut files);
    }
    rust_files(&root.join("apps/desktop/src-tauri/src"), &mut files);
    files.sort();

    let mut offenders = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("source is readable");
        let production = src.split("#[cfg(test)]").next().unwrap_or(&src);
        for hit in std_sync_locks_in(production) {
            offenders.push(format!(
                "{}: {hit}",
                path.strip_prefix(&root).unwrap_or(path).display()
            ));
        }
    }

    assert!(
        files.len() > 50,
        "the walk found only {} .rs files — the root is wrong and the rule passes vacuously",
        files.len()
    );
    assert!(
        offenders.is_empty(),
        "use `parking_lot::Mutex` / `RwLock` for a synchronous lock (no poisoning, const \
         `new`), or `tokio::sync` for one held across `.await`:\n  {}",
        offenders.join("\n  ")
    );
}
