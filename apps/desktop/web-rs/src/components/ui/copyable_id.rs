use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;

use crate::components::icon::IconName;
use crate::components::ui::IconButton;
use crate::util::copy_text;

/// How long the transient "Copied" badge stays visible.
const COPIED_BADGE_MS: i32 = 1500;

/// A GUID/identifier with a copy-to-clipboard button. By default the text is
/// truncated to 8 chars + `…` (full value on hover) — for table cells where a
/// full GUID would crowd the row (Secret ID / Certificate ID). Pass `full` to
/// render the whole value, for a detail-pane property field where the GUID is
/// the thing the operator came to copy.
#[component]
pub fn CopyableId(
    #[prop(into)] value: String,
    #[prop(into)] label: String,
    #[prop(optional)] full: bool,
) -> impl IntoView {
    let shown = if full {
        value.clone()
    } else {
        format!("{}…", value.chars().take(8).collect::<String>())
    };
    let copy_value = value.clone();
    // Confirms the (fire-and-forget async) copy actually happened — a transient
    // badge next to the button rather than a reactive IconButton prop, since
    // those are non-reactive and rebuilding the button would drop focus.
    let copied = RwSignal::new(false);
    let on_copy = move |_| {
        copy_text(copy_value.clone());
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
        <span class="copyable-id">
            <span class="mono" title=value.clone()>
                {shown}
            </span>
            <IconButton
                icon=IconName::Copy
                aria_label=format!("Copy {label}")
                title="Copy".to_string()
                on_click=Callback::new(on_copy)
            />
            {move || {
                copied
                    .get()
                    .then(|| view! { <span class="copyable-id__copied">"Copied"</span> })
            }}
        </span>
    }
}
