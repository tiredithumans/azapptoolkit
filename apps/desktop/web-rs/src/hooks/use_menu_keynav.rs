//! The keyboard contract of `role="menu"`, for the plain-DOM dropdowns.
//!
//! `role="menu"` switches a screen reader into menu mode, where the operator
//! expects focus to land on the first item when the menu opens, Arrow Up/Down
//! and Home/End to move between items, and Escape to close it and put focus
//! back on the button that opened it. Announcing the role without that
//! behaviour is worse than not announcing it. **A `role="menu"` panel must wire
//! this hook.**
//!
//! Our dropdowns (the account menu, `ExportMenu`) are plain-DOM disclosures,
//! not a Thaw `Menu`: an export opens the native "Save file" dialog, and doing
//! that from inside a teleported Thaw overlay froze the webview on WebView2 as
//! the overlay tore down (see the `export_menu` module doc). So the contract
//! Thaw would have provided is provided here, once, for both.
//!
//! Escape itself stays with the caller's [`super::use_escape`]; this hook adds
//! the focus-in, the arrow roving, and the focus return (through
//! [`super::use_focus_return`], the single record-and-restore implementation),
//! which runs however the menu closes — Escape, an item click, or an outside
//! mousedown.
//!
//! Tab is deliberately not handled (and items keep their natural tab stops):
//! closing the menu on Tab would race the focus return against the browser's
//! own Tab move.

use leptos::ev::KeyboardEvent;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Element, HtmlElement};

use super::use_focus_return::use_focus_return;

/// The items the keys move between: enabled `role="menuitem"`s, in DOM order.
const ITEMS: &str = "[role=menuitem]:not([disabled])";

fn items(panel: &Element) -> Vec<HtmlElement> {
    let mut out = Vec::new();
    if let Ok(list) = panel.query_selector_all(ITEMS) {
        for i in 0..list.length() {
            if let Some(el) = list.item(i).and_then(|n| n.dyn_into::<HtmlElement>().ok()) {
                out.push(el);
            }
        }
    }
    out
}

/// Wires the menu keyboard contract onto `panel` (the `role="menu"` element,
/// mounted while `open`) and returns the `keydown` handler to bind on it with
/// `on:keydown`.
///
/// On the open edge focus moves to the first enabled item (retried until the
/// `<Show>` has mounted the panel); on the close edge it returns to whatever was
/// focused before — the trigger. An item that opens a dialog must close the
/// menu *before* opening the dialog, so this restore runs before the dialog's
/// focus trap records and places focus.
pub fn use_menu_keynav(
    panel: NodeRef<html::Div>,
    open: Signal<bool>,
) -> impl Fn(KeyboardEvent) + Clone + 'static {
    use_focus_return(open, move || {
        let Some(p) = panel.get() else {
            return false;
        };
        if let Some(first) = items(&p).first() {
            let _ = first.focus();
        }
        true
    });

    move |ev: KeyboardEvent| {
        let Some(p) = panel.get_untracked() else {
            return;
        };
        let list = items(&p);
        let n = list.len();
        if n == 0 {
            return;
        }
        let active = document().active_element();
        let current = active.and_then(|a| {
            list.iter()
                .position(|el| *el.unchecked_ref::<Element>() == a)
        });
        let next = match ev.key().as_str() {
            "ArrowDown" => current.map_or(0, |i| (i + 1) % n),
            "ArrowUp" => current.map_or(n - 1, |i| (i + n - 1) % n),
            "Home" => 0,
            "End" => n - 1,
            _ => return,
        };
        ev.prevent_default();
        let _ = list[next].focus();
    }
}
