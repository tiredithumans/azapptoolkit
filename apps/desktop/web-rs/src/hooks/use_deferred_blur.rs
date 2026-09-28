//! Deferred-close blur handler for typeahead dropdowns.

use leptos::prelude::*;
use wasm_bindgen::JsCast;

/// How long a typeahead keeps its results open after the input blurs. A click
/// on a result fires *after* the input's blur, so closing synchronously would
/// unmount the row before its click lands.
pub const BLUR_CLOSE_DELAY_MS: i32 = 150;

/// Returns an `on:blur` handler that sets `focused` to `false` after
/// [`BLUR_CLOSE_DELAY_MS`]. The one copy of the timer interop that GlobalSearch
/// and the permission tester's identity picker each used to hand-roll.
pub fn use_deferred_blur(
    focused: RwSignal<bool>,
) -> impl Fn(leptos::ev::FocusEvent) + Copy + 'static {
    move |_| {
        if let Some(w) = web_sys::window() {
            let cb = wasm_bindgen::closure::Closure::once_into_js(move || focused.set(false));
            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.unchecked_ref::<js_sys::Function>(),
                BLUR_CLOSE_DELAY_MS,
            );
        }
    }
}
