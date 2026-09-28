use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::components::ui::Callout;
use crate::util::write_clipboard;

/// A large copyable value — a certificate or a one-time secret — shown as a
/// label, an optional hint, a monospace `pre.secret-reveal` block and a Copy
/// button. The one primitive for this pattern: don't hand-roll a `pre` plus a
/// clipboard call for a new reveal.
///
/// The Copy button reports what the clipboard actually did. `writeText` can
/// reject (no focus, permission denied in some webviews), and "Copied" on a
/// failed write is exactly the lie a show-once value can't afford — so a
/// failure says so and tells the operator to copy the text by hand.
#[component]
pub fn CopyBlock(
    #[prop(into)] label: String,
    #[prop(into)] value: String,
    #[prop(into, optional)] hint: String,
) -> impl IntoView {
    // `None` until a copy has been attempted; then whether the write landed.
    let copied: RwSignal<Option<bool>> = RwSignal::new(None);
    let copy_value = value.clone();
    let copy = move |_| {
        let v = copy_value.clone();
        copied.set(None);
        leptos::task::spawn_local(async move {
            copied.set(Some(write_clipboard(&v).await));
        });
    };
    view! {
        <div class="copy-block">
            <span class="copy-block__label">{label}</span>
            {(!hint.is_empty()).then(|| view! { <Body1 class="hint">{hint}</Body1> })}
            <pre class="secret-reveal">{value}</pre>
            {move || {
                (copied.get() == Some(false))
                    .then(|| {
                        view! {
                            <Callout tone="warn" role="alert">
                                "Couldn't copy to the clipboard. Select the text above and copy it manually."
                            </Callout>
                        }
                    })
            }}
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(copy)
            >
                {move || if copied.get() == Some(true) { "Copied" } else { "Copy" }}
            </Button>
        </div>
    }
}
