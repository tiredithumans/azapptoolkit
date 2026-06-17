//! Reveals a freshly-minted client secret with a copy-to-clipboard control.

use leptos::html;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};
use wasm_bindgen_futures::JsFuture;

use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;

#[component]
pub fn SecretRevealDialog(
    #[prop(into)] secret_text: String,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    let copied = RwSignal::new(false);
    let secret_for_copy = secret_text.clone();
    let copy = move |_| {
        let value = secret_for_copy.clone();
        copied.set(false);
        leptos::task::spawn_local(async move {
            if let Some(win) = web_sys::window() {
                let nav = win.navigator();
                let clipboard = nav.clipboard();
                let promise = clipboard.write_text(&value);
                let _ = JsFuture::from(promise).await;
                copied.set(true);
            }
        });
    };

    use_escape(|| true, move || on_close.run(()));
    let modal_ref: NodeRef<html::Div> = NodeRef::new();
    // This dialog is mounted only while visible, so it's always "active".
    use_focus_trap(modal_ref, Signal::derive(|| true));

    view! {
        <div
            class="modal-backdrop"
            role="dialog"
            aria-modal="true"
            aria-labelledby="secret-reveal-dialog-title"
        >
            <div class="modal modal--wide" node_ref=modal_ref>
                <h3 id="secret-reveal-dialog-title">"New client secret"</h3>
                <Body1>
                    "Copy the secret now — it can never be retrieved again. The Microsoft Graph API only returns the value at creation time."
                </Body1>
                <pre class="secret-reveal">{secret_text}</pre>
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(copy)
                    >
                        {move || {
                            if copied.get() {
                                "Copied"
                            } else {
                                "Copy to clipboard"
                            }
                        }}
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| on_close.run(()))
                    >
                        "Done"
                    </Button>
                </div>
            </div>
        </div>
    }
}
