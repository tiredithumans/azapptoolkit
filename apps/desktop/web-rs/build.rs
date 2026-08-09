//! Bakes the running build's own `CHANGELOG.md` section into the wasm bundle,
//! so "What's new" (`components/release_notes.rs`) can show the release notes
//! for the version the user is *on* — not just the one they're about to install.
//!
//! Until now the notes existed in exactly one place at runtime: the updater
//! manifest of a *pending* update. Once the update installed, the splash was
//! gone and there was nothing left to re-read. Baking the section at compile
//! time makes it available offline, forever, with no IPC call (so it also works
//! in the GitHub Pages demo, where an unfixtured infallible `invoke()` would
//! take the whole page down).
//!
//! The extraction mirrors `release.yml`'s notes step exactly — lines between
//! this version's `## [X.Y.Z]` header and the next `## [` header — so both
//! surfaces show the same text. A version with no matching section bakes an
//! empty string and the dialog degrades to a link to the changelog on GitHub.

use std::path::{Path, PathBuf};

// The pure parser lives in its own file so `src/lib.rs` can mount the same
// source under `#[cfg(test)]` — a build script is compiled into no test target.
include!("build_support.rs");

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let changelog = repo_root(&manifest).join("CHANGELOG.md");
    println!("cargo:rerun-if-changed={}", changelog.display());
    println!("cargo:rerun-if-changed=build.rs");

    let version = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let notes = std::fs::read_to_string(&changelog)
        .ok()
        .and_then(|text| section_for(&text, &version))
        .unwrap_or_default();

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("release_notes.md");
    std::fs::write(&out, notes).expect("write baked release notes");
}

/// `apps/desktop/web-rs` → repo root.
fn repo_root(manifest: &Path) -> PathBuf {
    manifest
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| manifest.to_path_buf())
}
