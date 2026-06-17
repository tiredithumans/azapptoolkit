//! Roving-tabindex keyboard navigation for a data table's body rows.
//!
//! Applies the WAI-ARIA grid pattern to a `<tbody>`: exactly one row is in the
//! tab order at a time, Arrow Up/Down move focus between rows, Home/End jump to
//! the ends, and Enter on a focused row activates its first `<button>` (the
//! row's "Open" deep-link). Tab still reaches the in-row buttons natively, and
//! Enter on a button is left to the browser so activation never double-fires.

use leptos::ev::KeyboardEvent;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Element, HtmlElement, NodeList};

fn rows_of(tbody: &Element) -> Option<NodeList> {
    tbody.query_selector_all("tr").ok()
}

fn row_at(rows: &NodeList, i: u32) -> Option<HtmlElement> {
    rows.item(i).and_then(|n| n.dyn_into::<HtmlElement>().ok())
}

/// Makes row `target` the sole tab stop and focuses it. With no target
/// (`None`) it just seeds row 0 as focusable without stealing focus — used to
/// (re)initialize the roving tabindex after a re-render.
fn set_roving(rows: &NodeList, target: Option<u32>) {
    let focusable = target.unwrap_or(0);
    for i in 0..rows.length() {
        if let Some(tr) = row_at(rows, i) {
            let _ = tr.set_attribute("tabindex", if i == focusable { "0" } else { "-1" });
        }
    }
    if let Some(t) = target {
        if let Some(tr) = row_at(rows, t) {
            let _ = tr.focus();
        }
    }
}

/// Wires keyboard navigation onto `tbody`'s rows and returns the `keydown`
/// handler to bind with `on:keydown`. `rerender` is read inside an effect so
/// the roving tabindex is reapplied whenever the rendered row set changes
/// (filter/search/data updates).
pub fn use_grid_keynav(
    tbody: NodeRef<html::Tbody>,
    rerender: impl Fn() + 'static,
) -> impl Fn(KeyboardEvent) + Clone + 'static {
    // Reseed the roving tabindex after each render of the row set. Effects run
    // post-render, so `query_selector_all` sees the current rows.
    Effect::new(move |_| {
        rerender();
        if let Some(body) = tbody.get() {
            if let Some(rows) = rows_of(&body) {
                set_roving(&rows, None);
            }
        }
    });

    move |ev: KeyboardEvent| {
        let Some(body) = tbody.get() else { return };
        let Some(rows) = rows_of(&body) else { return };
        let n = rows.length();
        if n == 0 {
            return;
        }
        let active = web_sys::window()
            .and_then(|w| w.document())
            .and_then(|d| d.active_element())
            .map(|e| e.unchecked_into::<web_sys::Node>());

        // `contains` is the row holding focus (a focused in-row button counts);
        // `exact` is the row element itself being focused (for Enter).
        let mut contains: Option<u32> = None;
        let mut exact: Option<u32> = None;
        for i in 0..n {
            if let Some(tr) = row_at(&rows, i) {
                if tr.is_same_node(active.as_ref()) {
                    exact = Some(i);
                }
                if tr.contains(active.as_ref()) {
                    contains = Some(i);
                }
            }
        }

        let target = match ev.key().as_str() {
            "ArrowDown" => contains.map(|c| (c + 1).min(n - 1)).unwrap_or(0),
            "ArrowUp" => contains.map(|c| c.saturating_sub(1)).unwrap_or(0),
            "Home" => 0,
            "End" => n - 1,
            "Enter" => {
                // Only when the row itself is focused — a focused button keeps
                // its native Enter so activation can't fire twice.
                if let Some(c) = exact {
                    if let Some(tr) = row_at(&rows, c) {
                        if let Ok(Some(btn)) = tr.query_selector("button") {
                            if let Ok(btn) = btn.dyn_into::<HtmlElement>() {
                                ev.prevent_default();
                                btn.click();
                            }
                        }
                    }
                }
                return;
            }
            _ => return,
        };
        ev.prevent_default();
        set_roving(&rows, Some(target));
    }
}
