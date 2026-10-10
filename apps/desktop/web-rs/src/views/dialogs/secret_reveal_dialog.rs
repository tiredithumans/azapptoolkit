//! Reveals a freshly-minted client secret with a copy-to-clipboard control.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::components::modal_shell::ModalShell;
use crate::components::ui::Callout;
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
    // Stored (Copy) so the shell's re-callable children can both show and copy
    // it.
    let secret = StoredValue::new(secret_text);
    let copy = move |_| {
        let value = secret.get_value();
        copy_result.set(None);
        leptos::task::spawn_local(async move {
            copy_result.set(Some(write_clipboard(&value).await));
        });
    };

    // Deliberately no close-on-Escape. Dismissing releases the deferred detail
    // reload (the credentials tab's `on_close`), which unmounts this dialog and
    // with it the only copy of the secret — so a reflex Escape after a copy that
    // silently failed would lose it. Only the explicit Done button closes it.
    // Mounted only while visible, so the shell is always open.
    view! {
        <ModalShell
            open=Signal::derive(|| true)
            title="New client secret"
            on_close=on_close
            wide=true
            close_on_escape=false
        >
            <Body1>
                "Copy the secret now — it can never be retrieved again. The Microsoft Graph API only returns the value at creation time."
            </Body1>
            <pre class="secret-reveal">{secret.get_value()}</pre>
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
        </ModalShell>
    }
}
