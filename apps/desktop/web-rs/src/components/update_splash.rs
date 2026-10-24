//! Changelog splash for a pending app update. Shows the new version's release
//! notes (from the updater manifest) with an "Update & restart" action that
//! downloads, installs, and relaunches — streaming download progress. Opened
//! from the launch-check toast or the nav "Check for updates" button.
//!
//! A failure a retry cannot clear — an update whose signature did not verify,
//! an install that failed — disables "Update & restart" and points at the
//! manual install (the Releases page) and the log folder instead of offering
//! the same failing click again.

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use azapptoolkit_dto::UiError;

use crate::bindings::events;
use crate::bindings::updater::{self, UpdateInfo, UpdateProgress};
use crate::components::changelog_notes::ChangelogNotes;
use crate::components::modal_shell::ModalShell;
use crate::components::support_paths::SupportPathsBlock;
use crate::components::ui::{Callout, ProgressBar};
use crate::hooks::use_progress_stream::use_progress_stream;

/// Where a release can be downloaded and installed by hand.
const RELEASES_URL: &str = "https://github.com/tiredithumans/azapptoolkit/releases";

/// Whether `e` leaves only the manual install: not retryable, and not the
/// "updates are off for this install" refusal, whose own message already says
/// who updates it.
fn needs_manual_install(e: &UiError) -> bool {
    !e.retryable && e.code != "updates_disabled"
}

#[component]
pub fn UpdateSplash(open: RwSignal<bool>, info: RwSignal<Option<UpdateInfo>>) -> impl IntoView {
    let updating = RwSignal::new(false);
    let error: RwSignal<Option<UiError>> = RwSignal::new(None);
    let progress: RwSignal<Option<UpdateProgress>> = RwSignal::new(None);
    use_progress_stream(progress, events::updater_progress);
    // A failure a retry cannot clear keeps Update & restart off: clicking it
    // again would download the same unverifiable bytes, or fail the same way.
    let blocked = move || error.with(|e| e.as_ref().is_some_and(|e| !e.retryable));
    // A later check that found a newer release is a different download: the
    // last failure no longer applies to it.
    Effect::new(move |seen: Option<Option<String>>| {
        let version = info.with(|i| i.as_ref().map(|i| i.version.clone()));
        if seen.is_some_and(|seen| seen != version) {
            error.set(None);
        }
        version
    });

    let do_update = move |_| {
        if updating.get() || blocked() {
            return;
        }
        updating.set(true);
        error.set(None);
        progress.set(None);
        leptos::task::spawn_local(async move {
            // `perform_update` relaunches into the new version on success and
            // never returns. We only get here on an error, or in the rare no-op
            // case where the update vanished between check and install — either
            // way, stop the spinner (and close on the benign no-op).
            match updater::perform_update().await {
                Ok(()) => {
                    updating.set(false);
                    open.set(false);
                }
                Err(e) => {
                    error.set(Some(e));
                    updating.set(false);
                }
            }
        });
    };

    let title = Signal::derive(move || {
        info.with(|i| {
            i.as_ref()
                .map(|i| format!("Update available — v{}", i.version))
                .unwrap_or_else(|| "Update".to_string())
        })
    });

    view! {
        <ModalShell
            open=open
            title=title
            busy=Signal::derive(move || updating.get())
            on_close=Callback::new(move |()| open.set(false))
            wide=true
        >
            {move || {
                info.get()
                    .map(|i| {
                        let notes = if i.notes.trim().is_empty() {
                            "See the release notes on GitHub for what's new in this version."
                                .to_string()
                        } else {
                            i.notes.clone()
                        };
                        view! {
                            <div class="update-splash">
                                <span class="ui-text update-splash__meta">
                                    {format!(
                                        "You're on v{}. v{} is ready to install.",
                                        i.current_version,
                                        i.version,
                                    )}
                                </span>
                                <ChangelogNotes notes=notes />
                                {move || {
                                    progress
                                        .get()
                                        .map(|p| {
                                            let frac = p
                                                .total
                                                .filter(|t| *t > 0)
                                                .map(|t| p.downloaded as f64 / t as f64);
                                            let mb = p.downloaded as f64 / 1_048_576.0;
                                            view! {
                                                <div class="update-splash__progress">
                                                    {frac
                                                        .map(|f| {
                                                            view! { <ProgressBar value=Signal::derive(move || f) /> }
                                                        })}
                                                    <span class="ui-text">{format!("Downloading… {mb:.1} MB")}</span>
                                                </div>
                                            }
                                        })
                                }}
                                {move || {
                                    error
                                        .get()
                                        .map(|e| {
                                            let manual = needs_manual_install(&e);
                                            // A signature that did not verify means the bytes
                                            // that arrived are not the ones that were signed:
                                            // fetching the same payload by hand over the same
                                            // path proves nothing, so the advice is a fresh copy
                                            // from the release page, ideally over another network.
                                            let (before, after) = if e.code == "update_unverified" {
                                                (
                                                    "The download may have been altered or corrupted on the way, so it wasn't installed. Get the release from the ",
                                                    " in a browser — ideally from another network — and install it from there. The log folder below has the details.",
                                                )
                                            } else {
                                                (
                                                    "Update & restart can't get past this. Download the new version from the ",
                                                    " and run its installer instead. The log folder below has the details.",
                                                )
                                            };
                                            view! {
                                                <Callout tone="warn" role="alert">
                                                    <span class="ui-text">{e.message}</span>
                                                    {manual
                                                        .then(|| {
                                                            view! {
                                                                <span class="ui-text update-splash__manual">
                                                                    {before}
                                                                    <a
                                                                        class="link-btn"
                                                                        href=RELEASES_URL
                                                                        target="_blank"
                                                                        rel="noopener noreferrer"
                                                                    >
                                                                        "Releases page"
                                                                    </a>
                                                                    {after}
                                                                </span>
                                                                <SupportPathsBlock settings_file=false />
                                                            }
                                                        })}
                                                </Callout>
                                            }
                                        })
                                }}
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(do_update)
                                        disabled=Signal::derive(move || updating.get() || blocked())
                                    >
                                        {move || if updating.get() { "Updating…" } else { "Update & restart" }}
                                    </Button>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                        on_click=Box::new(move |_| open.set(false))
                                        disabled=Signal::derive(move || updating.get())
                                    >
                                        "Later"
                                    </Button>
                                </div>
                            </div>
                        }
                    })
            }}
        </ModalShell>
    }
}
