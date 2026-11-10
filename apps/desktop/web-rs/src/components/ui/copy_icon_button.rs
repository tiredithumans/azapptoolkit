use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;

use crate::components::icon::IconName;
use crate::components::ui::IconButton;
use crate::util::write_clipboard;

/// How long the transient "Copied" / "Copy failed" badge stays visible.
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
    // Reports what the clipboard write actually did — `Some(true)` copied,
    // `Some(false)` rejected (the webview lost focus, permission denied). It
    // used to show "Copied" unconditionally, so a failed copy of an app id read
    // as done and the operator pasted whatever was on the clipboard before.
    // A transient badge next to the button rather than a reactive IconButton
    // prop, since those are non-reactive and rebuilding the button would drop
    // focus.
    let copied: RwSignal<Option<bool>> = RwSignal::new(None);
    let on_copy = move |_| {
        let text = value.get();
        leptos::task::spawn_local(async move {
            let ok = write_clipboard(&text).await;
            // `try_set`: the row can unmount while the write is in flight.
            let _ = copied.try_set(Some(ok));
        });
        // Schedule the badge reset (the toast timer idiom). Repeated clicks:
        // the earliest pending timeout wins, so a re-click's badge can clear up
        // to COPIED_BADGE_MS early — fine for a hint. `try_set` because the
        // timeout can outlive the component (table re-renders unmount rows).
        if let Some(win) = web_sys::window() {
            let cb = Closure::once_into_js(move || {
                let _ = copied.try_set(None);
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
                .map(|ok| {
                    if ok {
                        view! {
                            <span class="copyable-id__copied" role="status">
                                "Copied"
                            </span>
                        }
                            .into_any()
                    } else {
                        view! {
                            <span
                                class="copyable-id__copied copyable-id__copied--failed"
                                role="alert"
                            >
                                "Copy failed"
                            </span>
                        }
                            .into_any()
                    }
                })
        }}
    }
}
