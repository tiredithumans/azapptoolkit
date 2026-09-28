//! Debounce a string signal.

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

/// Returns a `Signal<String>` that lags `source` by `delay_ms`. Each new value
/// cancels the pending timeout and starts a fresh one.
///
/// The timer's JS callback is an owned `Closure`, not `Closure::once_into_js`:
/// wasm-bindgen frees a `once_into_js` closure only when JS calls it — "If the
/// JavaScript function is never called then the FnOnce and everything it
/// closes over will leak" — and a debounce cancels its timer on nearly every
/// keystroke, so each one leaked a boxed closure plus the captured `String`
/// for the life of a keep-alive list. Owning it lets a cancel drop it.
pub fn use_debounced(source: Signal<String>, delay_ms: i32) -> Signal<String> {
    let out = RwSignal::new(source.get_untracked());
    // The pending `setTimeout` handle and its callback live in `StoredValue`s
    // rather than an `Rc<RefCell<..>>` so the same `Copy` handles reach both the
    // `Effect` and the `on_cleanup` closure (which requires `Send + Sync`,
    // ruling out `Rc`). The `Closure` is `!Send`, hence local storage — the
    // handle itself stays `Send + Sync`.
    let pending: StoredValue<Option<i32>> = StoredValue::new(None);
    let cb: StoredValue<Option<Closure<dyn FnMut()>>, LocalStorage> = StoredValue::new_local(None);

    // Cancel the pending timer and drop its callback (freeing the Rust box and
    // invalidating the JS function). At most one callback lives per hook.
    let clear_pending = move || {
        if let Some(handle) = pending.try_get_value().flatten() {
            if let Some(win) = web_sys::window() {
                win.clear_timeout_with_handle(handle);
            }
            pending.set_value(None);
        }
        cb.try_update_value(|c| *c = None);
    };

    Effect::new(move |_| {
        let next = source.get();
        let win = match web_sys::window() {
            Some(w) => w,
            None => return,
        };

        // Cancel any in-flight timer (and drop its callback).
        clear_pending();

        // The callback must never touch `cb`: dropping a `Closure` while it is
        // running is invalid. A fired callback stays stored until the next
        // change or unmount drops it.
        let mut next = Some(next);
        let closure = Closure::<dyn FnMut()>::new(move || {
            if let Some(v) = next.take() {
                out.set(v);
            }
            pending.set_value(None);
        });

        if let Ok(handle) = win.set_timeout_with_callback_and_timeout_and_arguments_0(
            closure.as_ref().unchecked_ref(),
            delay_ms,
        ) {
            pending.set_value(Some(handle));
            cb.set_value(Some(closure));
        }
    });

    // On unmount, cancel any still-pending timer so its closure can't fire
    // after the owning component (and `out`) has been disposed, and free it.
    on_cleanup(clear_pending);

    out.into()
}
