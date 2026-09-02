//! Focus management for modal dialogs.
//!
//! Our dialogs are hand-rolled `<div role="dialog" aria-modal="true">`s gated
//! by `<Show>`. `aria-modal="true"` *asserts* a focus trap, but nothing
//! enforced it: focus stayed on the trigger behind the backdrop, Tab could walk
//! out into the obscured page, and closing never restored focus. This hook
//! makes the assertion true — focus the dialog on open, cycle Tab within it,
//! and restore focus to the trigger on close. Pairs with [`super::use_escape`]
//! (close-on-Escape) to complete the modal contract.
//!
//! The record-and-restore half lives in [`super::use_focus_return`], because
//! the open-items workspace needs it without the trap; this hook is that hook
//! plus Tab cycling.

use leptos::ev;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Element, HtmlElement};

use super::use_focus_return::use_focus_return;

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
    // Record-and-restore is the shared half (see the module doc). Reading the
    // container ref inside the closure is what drives the retry when the dialog
    // mounts a tick after `active` flips; a dialog with no focusable control at
    // all still counts as placed, so closing it still restores the trigger.
    use_focus_return(active, move || {
        let Some(c) = container.get() else {
            return false;
        };
        if let Some(first) = focusable_in(&c).first() {
            let _ = first.focus();
        }
        true
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
