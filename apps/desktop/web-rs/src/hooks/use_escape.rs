//! Close-on-Escape for modal dialogs, and the workspace's gentler variant.

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

/// [`use_escape`] for a surface that is NOT a dialog — the open-items
/// workspace, which sits under everything else on the page.
///
/// Escape there used to hide the pane whenever no modal was open, so pressing
/// it to leave the global search, close the account menu or dismiss a picker
/// inside the pane also threw the pane the operator was working in off screen.
/// This variant stands down when the key was typed into a text field (the same
/// `is_text_entry` predicate the bare-key shortcuts use), when a menu is open,
/// and when a nearer handler already claimed the event.
pub fn use_escape_outside_entry(
    active: impl Fn() -> bool + 'static,
    on_escape: impl Fn() + 'static,
) {
    let handle = window_event_listener(ev::keydown, move |ev| {
        if ev.key() != "Escape" || ev.default_prevented() || crate::hooks::is_text_entry(&ev) {
            return;
        }
        let menu_open = document()
            .query_selector("[role=\"menu\"]")
            .ok()
            .flatten()
            .is_some();
        if !menu_open && active() {
            on_escape();
        }
    });
    on_cleanup(move || handle.remove());
}
