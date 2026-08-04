//! "What's new" — the release notes for the version currently running, opened
//! from the version line in the account menu.
//!
//! The update splash shows a *pending* release's notes and then it's gone:
//! after the update installs there was no way back to what changed. The notes
//! here are the running build's own `CHANGELOG.md` section, baked in by
//! `build.rs` (see there for why compile-time and not an IPC call), so the
//! dialog works offline, on first launch, and in the Pages demo. It renders
//! through the same [`ChangelogNotes`] component as the splash, so both read
//! identically — condensed by default, technical detail one click away.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::components::changelog_notes::ChangelogNotes;
use crate::components::modal_shell::ModalShell;

/// This build's `CHANGELOG.md` section, baked by `build.rs`. Empty when the
/// version has no section — a local build whose manifest was bumped ahead of
/// the changelog — in which case the dialog links out instead.
pub const CURRENT_RELEASE_NOTES: &str = include_str!(concat!(env!("OUT_DIR"), "/release_notes.md"));

/// The running version. The release bumps `web-rs` in lockstep with the other
/// two manifests, so `CARGO_PKG_VERSION` is the shipped one (same source as the
/// version line this dialog opens from).
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

const CHANGELOG_URL: &str = "https://github.com/tiredithumans/azapptoolkit/blob/main/CHANGELOG.md";

#[component]
pub fn ReleaseNotesDialog(open: RwSignal<bool>) -> impl IntoView {
    let title = Signal::derive(|| format!("What's new in v{CURRENT_VERSION}"));

    view! {
        <ModalShell
            open=open
            title=title
            on_close=Callback::new(move |()| open.set(false))
            wide=true
        >
            <div class="update-splash">
                {if CURRENT_RELEASE_NOTES.trim().is_empty() {
                    view! {
                        <div class="changelog">
                            <p>
                                "Release notes for this version aren't bundled with this build."
                            </p>
                        </div>
                    }
                        .into_any()
                } else {
                    view! { <ChangelogNotes notes=CURRENT_RELEASE_NOTES.to_string() /> }.into_any()
                }}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| open.set(false))
                    >
                        "Close"
                    </Button>
                    <a
                        class="link-btn"
                        href=CHANGELOG_URL
                        target="_blank"
                        rel="noopener noreferrer"
                    >
                        "Full changelog on GitHub"
                    </a>
                </div>
            </div>
        </ModalShell>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the `build.rs` ↔ `CHANGELOG.md` contract end-to-end: this build's
    /// version must have a section, and what gets baked must be the section
    /// *body* — not the `## [X.Y.Z]` header, and not the next release's entries.
    /// A failure here means the manifest version was bumped without finalizing
    /// `## [Unreleased]` (see the `release` skill), which would also ship an
    /// empty in-app "What's new".
    #[test]
    fn the_running_versions_changelog_section_is_baked_in() {
        assert!(
            !CURRENT_RELEASE_NOTES.trim().is_empty(),
            "CHANGELOG.md has no `## [{CURRENT_VERSION}]` section — finalize [Unreleased] for \
             this version, or the in-app What's new ships blank"
        );
        assert!(
            !CURRENT_RELEASE_NOTES.contains("## ["),
            "baked notes must stop at the next version header, got:\n{CURRENT_RELEASE_NOTES}"
        );
    }
}
