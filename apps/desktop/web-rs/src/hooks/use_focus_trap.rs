//! Focus management for modal dialogs.
//!
//! Our dialogs are hand-rolled `<div role="dialog" aria-modal="true">`s gated
//! by `<Show>`. `aria-modal="true"` *asserts* a focus trap, but nothing
//! enforced it: focus stayed on the trigger behind the backdrop, Tab could walk
//! out into the obscured page, and closing never restored focus. This hook
//! makes the assertion true — focus the dialog on open, cycle Tab within it,
//! and restore focus to the trigger on close. Pairs with [`super::use_escape`]
//! (close-on-Escape) to complete the modal contract.

use leptos::ev;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Element, HtmlElement};

/// Tab-reachable elements, in DOM order. Excludes `tabindex="-1"` (programmatic
/// focus only — e.g. the search-clear ×) and disabled controls.
const FOCUSABLE: &str = "a[href], button:not([disabled]), input:not([disabled]), \
     select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex=\"-1\"])";

fn focusable_in(container: &Element) -> Vec<HtmlElement> {
    let mut out = Vec::new();
    if let Ok(list) = container.query_selector_all(FOCUSABLE) {
        for i in 0..list.length() {
            if let Some(el) = list.item(i).and_then(|n| n.dyn_into::<HtmlElement>().ok()) {
                out.push(el);
            }
        }
    }
    out
}

fn is_active(el: &HtmlElement) -> bool {
    document()
        .active_element()
        .map(|a| a == *el.unchecked_ref::<Element>())
        .unwrap_or(false)
}

/// Traps focus inside `container` while `active` is true.
///
/// On the open transition it records the previously-focused element and moves
/// focus to the dialog's first focusable control; while open, Tab / Shift-Tab
/// wrap at the edges; on close it restores focus to the recorded element. The
/// container ref is read reactively, so the focus-in still fires if the dialog
/// mounts a tick after `active` flips (the `<Show>` case).
pub fn use_focus_trap(container: NodeRef<html::Div>, active: Signal<bool>) {
    // The element focused before the dialog opened, to restore on close. Not
    // Send/Sync, so local storage.
    let prev = StoredValue::new_local(None::<HtmlElement>);
    // Latches the per-open focus-in so re-runs (e.g. the ref resolving) don't
    // re-grab focus mid-interaction.
    let grabbed = StoredValue::new(false);

    Effect::new(move |_| {
        let now = active.get();
        let node = container.get();
        if now {
            if let Some(c) = node {
                if !grabbed.get_value() {
                    prev.set_value(
                        document()
                            .active_element()
                            .and_then(|e| e.dyn_into::<HtmlElement>().ok()),
                    );
                    if let Some(first) = focusable_in(&c).first() {
                        let _ = first.focus();
                    }
                    grabbed.set_value(true);
                }
            }
        } else if grabbed.get_value() {
            if let Some(el) = prev.get_value() {
                let _ = el.focus();
            }
            prev.set_value(None);
            grabbed.set_value(false);
        }
    });

    // Restore focus if the dialog is torn down while still open — covers the
    // dialogs that are mounted only while visible (so `active` never flips to
    // false). `try_*` since the StoredValues may already be disposing.
    on_cleanup(move || {
        if grabbed.try_get_value().unwrap_or(false) {
            if let Some(el) = prev.try_get_value().flatten() {
                let _ = el.focus();
            }
        }
    });

    let handle = window_event_listener(ev::keydown, move |ev| {
        if ev.key() != "Tab" || !active.get_untracked() {
            return;
        }
        let Some(c) = container.get_untracked() else {
            return;
        };
        let els = focusable_in(&c);
        let (Some(first), Some(last)) = (els.first(), els.last()) else {
            return;
        };
        // Cycle at the edges; let the browser handle Tab in the interior.
        if ev.shift_key() {
            if is_active(first) {
                ev.prevent_default();
                let _ = last.focus();
            }
        } else if is_active(last) {
            ev.prevent_default();
            let _ = first.focus();
        }
    });
    on_cleanup(move || handle.remove());
}
