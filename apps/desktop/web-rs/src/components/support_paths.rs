//! The two paths support asks for — the log folder and `settings.json` — each
//! in a [`CopyBlock`], from `get_support_paths`.
//!
//! "Check the log" and "fix settings.json" are only advice if the operator can
//! find the files, and the folders differ per OS (README "Logs"). Rendered in
//! Settings → Tenant connection and under the surfaces that fail before
//! Settings is reachable: the config screen, the sign-in card and the update
//! splash.

use leptos::prelude::*;

use crate::bindings::diagnostics::{self, SupportPaths};
use crate::components::ui::CopyBlock;

#[component]
pub fn SupportPathsBlock(
    /// Show the settings file as well as the log folder. Off where only the
    /// log helps (a failed update).
    #[prop(default = true)]
    settings_file: bool,
) -> impl IntoView {
    let paths = RwSignal::new(None::<SupportPaths>);
    leptos::task::spawn_local(async move {
        // A failure shows nothing: the paths sit beside an error that already
        // says what to do, and must not become a second error.
        if let Ok(found) = diagnostics::get_support_paths().await {
            paths.set(Some(found));
        }
    });
    move || {
        paths.get().map(|p| {
            view! {
                <div class="support-paths">
                    <CopyBlock
                        label="Logs folder"
                        value=p.log_dir
                        hint="One file per day, named azapptoolkit.YYYY-MM-DD.log."
                    />
                    {settings_file
                        .then(|| view! { <CopyBlock label="Settings file" value=p.settings_file /> })}
                </div>
            }
        })
    }
}
