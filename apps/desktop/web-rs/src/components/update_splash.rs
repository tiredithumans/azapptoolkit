//! Changelog splash for a pending app update. Shows the new version's release
//! notes (from the updater manifest) with an "Update & restart" action that
//! downloads, installs, and relaunches — streaming download progress. Opened
//! from the launch-check toast or the nav "Check for updates" button.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, ProgressBar};

use crate::bindings::events;
use crate::bindings::updater::{self, UpdateInfo, UpdateProgress};
use crate::components::modal_shell::ModalShell;
use crate::hooks::use_progress_stream::use_progress_stream;

#[component]
pub fn UpdateSplash(open: RwSignal<bool>, info: RwSignal<Option<UpdateInfo>>) -> impl IntoView {
    let updating = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let progress: RwSignal<Option<UpdateProgress>> = RwSignal::new(None);
    use_progress_stream(progress, events::updater_progress);

    let do_update = move |_| {
        if updating.get() {
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
                    error.set(Some(e.message));
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
                                <Body1 class="update-splash__meta">
                                    {format!(
                                        "You're on v{}. v{} is ready to install.",
                                        i.current_version,
                                        i.version,
                                    )}
                                </Body1>
                                <pre class="update-splash__notes">{notes}</pre>
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
                                                    <Body1>{format!("Downloading… {mb:.1} MB")}</Body1>
                                                </div>
                                            }
                                        })
                                }}
                                {move || {
                                    error.get().map(|e| view! { <div class="alert alert--warn">{e}</div> })
                                }}
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(do_update)
                                        disabled=Signal::derive(move || updating.get())
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
