use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;

use crate::components::icon::IconName;
use crate::components::ui::IconButton;
use crate::util::copy_text;

/// How long the transient "Copied" badge stays visible.
const COPIED_BADGE_MS: i32 = 1500;

/// Copy-to-clipboard icon button with a transient "Copied" confirmation badge —
/// the single home of the copy-feedback behavior. Every icon-button copy
/// affordance (`CopyableId`, the detail-header app id, the SSO summary fields)
/// renders this so the confirmation is uniform; don't wire a raw
/// `IconButton` + `copy_text` for a new copy button.
#[component]
pub fn CopyIconButton(
    /// Value to copy, read at click time (so live-updating fields copy fresh).
    #[prop(into)]
    value: Signal<String>,
    #[prop(into)] aria_label: String,
) -> impl IntoView {
    // Confirms the (fire-and-forget async) copy actually happened — a transient
    // badge next to the button rather than a reactive IconButton prop, since
    // those are non-reactive and rebuilding the button would drop focus.
    let copied = RwSignal::new(false);
    let on_copy = move |_| {
        copy_text(value.get());
        copied.set(true);
        // Schedule the badge reset (the toast timer idiom). Repeated clicks:
        // the earliest pending timeout wins, so a re-click's badge can clear up
        // to COPIED_BADGE_MS early — fine for a hint. `try_set` because the
        // timeout can outlive the component (table re-renders unmount rows).
        if let Some(win) = web_sys::window() {
            let cb = Closure::once_into_js(move || {
                let _ = copied.try_set(false);
            });
            let _ = win.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.unchecked_ref(),
                COPIED_BADGE_MS,
            );
        }
    };
    view! {
        <IconButton
            icon=IconName::Copy
            aria_label=aria_label
            title="Copy".to_string()
            on_click=Callback::new(on_copy)
        />
        {move || {
            copied
                .get()
                .then(|| view! { <span class="copyable-id__copied">"Copied"</span> })
        }}
    }
}
