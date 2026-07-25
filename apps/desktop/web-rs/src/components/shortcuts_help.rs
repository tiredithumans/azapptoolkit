//! The keyboard-shortcut sheet (`?`).
//!
//! Reads its rows from [`crate::hooks::use_shortcuts::SHORTCUTS`], which sits
//! beside the handler that implements them, so the documented bindings and the
//! live ones can't drift.

use leptos::prelude::*;

use crate::components::modal_shell::ModalShell;
use crate::hooks::use_shortcuts::SHORTCUTS;

#[component]
pub fn ShortcutsHelp(open: RwSignal<bool>) -> impl IntoView {
    view! {
        <ModalShell
            open=open
            title="Keyboard shortcuts".to_string()
            on_close=Callback::new(move |_| open.set(false))
        >
            <dl class="shortcuts">
                {SHORTCUTS
                    .iter()
                    .map(|(keys, what)| {
                        view! {
                            <div class="shortcuts__row">
                                <dt class="shortcuts__keys">
                                    <kbd>{*keys}</kbd>
                                </dt>
                                <dd class="shortcuts__what">{*what}</dd>
                            </div>
                        }
                    })
                    .collect_view()}
            </dl>
        </ModalShell>
    }
}
