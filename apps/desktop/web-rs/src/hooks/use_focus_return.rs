//! Record-and-restore focus around a surface that takes over the page.
//!
//! Split out of [`super::use_focus_trap`], where this half was welded to the
//! Tab-cycling half and so could not serve the open-items workspace. That
//! overlay is not a dialog — it has no trap, because once it is up the panes
//! *are* the page — but it has the identical focus problem, and worse: it
//! marks `.shell__content` `inert`, which is where the row button that opened
//! it lives, so the browser blurs the trigger and focus lands on `<body>`.
//! Reaching the pane then costs ~13 Tab presses past the nav rail, and Escape
//! (which collapses the overlay) leaves focus on `<body>` too — losing the
//! operator's place in a four-thousand-row list.
//!
//! The trap now calls this and adds cycling on top, so "where did focus come
//! from, and where does it go back to" has exactly one implementation.

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::HtmlElement;

/// Records the focused element on the false→true edge of `active` and restores
/// it on the true→false edge (or on teardown while still active).
///
/// `place_focus` runs on every reactive pass while `active` is true and focus
/// has not yet been placed. It moves focus into the freshly-opened surface and
/// returns whether it managed to: `false` means "the surface isn't in the DOM
/// yet", so nothing is recorded, nothing is latched, and the next pass tries
/// again. Read the signal that will resolve (the container `NodeRef`, the
/// open-items list) *inside* the closure and that retry is automatic.
///
/// **Call this before any effect that makes the trigger unreachable.** Marking
/// a container `inert` blurs whatever is focused inside it, and what we must
/// record is the trigger, not the `<body>` the browser falls back to — Leptos
/// runs effects in creation order, so ordering the calls orders the two.
pub fn use_focus_return(active: Signal<bool>, place_focus: impl Fn() -> bool + 'static) {
    // The element focused before the surface opened, to restore on close. Not
    // Send/Sync, so local storage.
    let prev = StoredValue::new_local(None::<HtmlElement>);
    // Latches the per-open placement so re-runs (a ref resolving, a title
    // correcting) don't re-grab focus mid-interaction.
    let grabbed = StoredValue::new(false);

    Effect::new(move |_| {
        if active.get() {
            if grabbed.get_value() {
                return;
            }
            // Read the outgoing element *before* `place_focus` moves focus.
            let outgoing = document()
                .active_element()
                .and_then(|e| e.dyn_into::<HtmlElement>().ok());
            if place_focus() {
                prev.set_value(outgoing);
                grabbed.set_value(true);
            }
        } else if grabbed.get_value() {
            if let Some(el) = prev.get_value() {
                let _ = el.focus();
            }
            prev.set_value(None);
            grabbed.set_value(false);
        }
    });

    // Restore focus if the surface is torn down while still open — covers the
    // dialogs that are mounted only while visible (so `active` never flips to
    // false). `try_*` since the StoredValues may already be disposing.
    on_cleanup(move || {
        if grabbed.try_get_value().unwrap_or(false)
            && let Some(el) = prev.try_get_value().flatten()
        {
            let _ = el.focus();
        }
    });
}
