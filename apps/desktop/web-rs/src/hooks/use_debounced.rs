//! Debounce a string signal.

use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

/// Returns a `Signal<String>` that lags `source` by `delay_ms`. Each new value
/// cancels the pending timeout and starts a fresh one.
pub fn use_debounced(source: Signal<String>, delay_ms: i32) -> Signal<String> {
    let out = RwSignal::new(source.get_untracked());
    // The pending `setTimeout` handle lives in a `StoredValue` rather than an
    // `Rc<RefCell<..>>` so the same `Copy` handle reaches both the `Effect` and
    // the `on_cleanup` closure (which requires `Send + Sync`, ruling out `Rc`).
    let pending: StoredValue<Option<i32>> = StoredValue::new(None);

    let clear_pending = move || {
        if let Some(handle) = pending.try_get_value().flatten() {
            if let Some(win) = web_sys::window() {
                win.clear_timeout_with_handle(handle);
            }
            pending.set_value(None);
        }
    };

    Effect::new(move |_| {
        let next = source.get();
        let win = match web_sys::window() {
            Some(w) => w,
            None => return,
        };

        // Cancel any in-flight timer.
        clear_pending();

        let cb = Closure::once_into_js(move || {
            out.set(next);
            pending.set_value(None);
        });
        let cb_fn = cb.unchecked_ref::<js_sys::Function>();

        if let Ok(handle) =
            win.set_timeout_with_callback_and_timeout_and_arguments_0(cb_fn, delay_ms)
        {
            pending.set_value(Some(handle));
        }
    });

    // On unmount, cancel any still-pending timer so its closure can't fire
    // after the owning component (and `out`) has been disposed.
    on_cleanup(clear_pending);

    out.into()
}
