//! Close-on-Escape for modal dialogs.

use leptos::ev;
use leptos::prelude::*;

/// Calls `on_escape` whenever the Escape key is pressed while `active` returns
/// true. Registers one window-level `keydown` listener and detaches it when the
/// calling component is cleaned up.
///
/// Window-level (rather than a backdrop `on:keydown`) so it fires no matter
/// which element inside the modal currently holds focus. `active` is a plain
/// closure so each caller encodes its own gate: an always-mounted, `Show`-gated
/// dialog passes `move || open.get_untracked() && !busy.get_untracked()` so it
/// mirrors its (busy-disabled) Cancel button, while a dialog that is only in the
/// DOM while visible can pass `|| true`. Signals are read untracked — this fires
/// outside any reactive scope.
pub fn use_escape(active: impl Fn() -> bool + 'static, on_escape: impl Fn() + 'static) {
    let handle = window_event_listener(ev::keydown, move |ev| {
        if ev.key() == "Escape" && active() {
            on_escape();
        }
    });
    on_cleanup(move || handle.remove());
}
