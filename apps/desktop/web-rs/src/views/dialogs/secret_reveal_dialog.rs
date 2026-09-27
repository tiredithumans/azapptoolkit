//! Reveals a freshly-minted client secret with a copy-to-clipboard control.

use leptos::html;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::components::ui::Callout;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::util::write_clipboard;

#[component]
pub fn SecretRevealDialog(
    #[prop(into)] secret_text: String,
    #[prop(into)] on_close: Callback<()>,
) -> impl IntoView {
    // `None` until a copy has been attempted; then whether the clipboard
    // actually took it. `writeText` can reject (no focus, permission denied in
    // some webviews), and "Copied" on a failed write is the one lie this dialog
    // cannot afford: once it closes the value is gone for good.
    let copy_result: RwSignal<Option<bool>> = RwSignal::new(None);
    let secret_for_copy = secret_text.clone();
    let copy = move |_| {
        let value = secret_for_copy.clone();
        copy_result.set(None);
        leptos::task::spawn_local(async move {
            copy_result.set(Some(write_clipboard(&value).await));
        });
    };

    // Deliberately no close-on-Escape. Dismissing releases the deferred detail
    // reload (the credentials tab's `on_close`), which unmounts this dialog and
    // with it the only copy of the secret — so a reflex Escape after a copy that
    // silently failed would lose it. Only the explicit Done button closes it.
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
                {move || {
                    (copy_result.get() == Some(false))
                        .then(|| {
                            view! {
                                <Callout tone="warn" role="alert">
                                    "Couldn't copy to the clipboard. Select the secret above and copy it manually before you close this dialog."
                                </Callout>
                            }
                        })
                }}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(copy)
                    >
                        {move || {
                            if copy_result.get() == Some(true) {
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
