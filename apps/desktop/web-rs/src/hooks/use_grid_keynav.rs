//! Roving-tabindex keyboard navigation for a container of list rows.
//!
//! Applies the WAI-ARIA grid pattern: exactly one row is in the tab order at a
//! time, Arrow Up/Down move focus between rows, Home/End jump to the ends, and
//! Enter on a focused row activates its first `<button>` (the row's "Open"
//! deep-link). Tab still reaches the in-row buttons natively, and Enter on a
//! button is left to the browser so activation never double-fires.
//!
//! Two shapes of row set exist, and they differ in exactly one place — whether
//! the row you are navigating *to* is in the DOM yet:
//!
//! * [`RowSource::Complete`] — a `<tbody>`: every row is rendered, so any target
//!   can be focused on the spot. [`use_grid_keynav`] is this case.
//! * [`RowSource::Windowed`] — a [`VirtualList`](crate::components::virtual_list)
//!   scroller: only the rows around the viewport exist. A one-row arrow step
//!   stays inside the rendered window (the list's overscan keeps the neighbour
//!   materialized), but Home/End address rows that are not rendered at all, so
//!   they scroll the container first and take focus once the window has been
//!   rebuilt around the target.

use leptos::ev::KeyboardEvent;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Element, HtmlElement, HtmlInputElement, NodeList};

/// Whether the container holds every row, or only a scrolled window of them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RowSource {
    /// Every row is in the DOM (a `<tbody>`, a short static list).
    Complete,
    /// Only the rows around the scroll viewport are (a `VirtualList` scroller).
    Windowed,
}

/// The end of the list a deferred Home/End is heading for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Edge {
    First,
    Last,
}

fn rows_of(root: &Element, selector: &str) -> Option<NodeList> {
    root.query_selector_all(selector).ok()
}

fn row_at(rows: &NodeList, i: u32) -> Option<HtmlElement> {
    rows.item(i).and_then(|n| n.dyn_into::<HtmlElement>().ok())
}

/// `(row holding focus, row that *is* focused)`. The first counts a focused
/// in-row button (so arrows work from anywhere in the row); the second is the
/// row element itself, which is what Enter acts on.
fn focused_rows(rows: &NodeList) -> (Option<u32>, Option<u32>) {
    let active = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element())
        .map(|e| e.unchecked_into::<web_sys::Node>());

    let (mut contains, mut exact) = (None, None);
    for i in 0..rows.length() {
        if let Some(row) = row_at(rows, i) {
            if row.is_same_node(active.as_ref()) {
                exact = Some(i);
            }
            if row.contains(active.as_ref()) {
                contains = Some(i);
            }
        }
    }
    (contains, exact)
}

/// Makes row `target` the sole tab stop and focuses it. With no target
/// (`None`) it re-seeds the tab stop without stealing focus — used after a
/// re-render — keeping it on whichever row still holds focus, so scrolling a
/// windowed list (which rebuilds the window on every step) doesn't silently
/// reset the roving position to the top of the rendered slice.
fn set_roving(rows: &NodeList, target: Option<u32>) {
    let focusable = target.or_else(|| focused_rows(rows).0).unwrap_or(0);
    for i in 0..rows.length() {
        if let Some(row) = row_at(rows, i) {
            let _ = row.set_attribute("tabindex", if i == focusable { "0" } else { "-1" });
        }
    }
    if let Some(t) = target
        && let Some(row) = row_at(rows, t)
    {
        let _ = row.focus();
    }
}

/// True when the keystroke came from a text-entry control, where a bare arrow
/// key belongs to the caret and not to the grid.
///
/// The surface-local twin of the window-level check in `use_shortcuts` — that
/// module is deliberately scoped to *window* bindings and a surface hook must
/// not reach into it. A row's bulk-select checkbox is explicitly not a text
/// field: arrowing off it is exactly what a keyboard user expects.
fn in_text_field(ev: &KeyboardEvent) -> bool {
    let Some(el) = ev.target().and_then(|t| t.dyn_into::<HtmlElement>().ok()) else {
        return false;
    };
    if el.is_content_editable() {
        return true;
    }
    match el.tag_name().to_ascii_lowercase().as_str() {
        "textarea" | "select" => true,
        "input" => !matches!(
            el.unchecked_ref::<HtmlInputElement>().type_().as_str(),
            "checkbox" | "radio" | "button" | "submit" | "reset"
        ),
        _ => false,
    }
}

/// Wires keyboard navigation onto the rows `row_selector` matches inside
/// `container`, and returns the `keydown` handler to bind with `on:keydown`.
///
/// `rerender` is read inside an effect so the roving tabindex is reapplied
/// whenever the rendered row set changes (filter/search/data updates, and for a
/// windowed list every scroll step).
pub fn use_row_keynav(
    container: impl Fn() -> Option<Element> + Copy + 'static,
    row_selector: &'static str,
    source: RowSource,
    rerender: impl Fn() + 'static,
) -> impl Fn(KeyboardEvent) + Clone + 'static {
    // A Home/End over a windowed list addresses a row that isn't rendered: the
    // scroll is issued immediately and the focus is parked here until a render
    // brings the row into existence. The `i32` is the `scrollTop` that was
    // actually taken (the browser clamps it) — if the container has since moved
    // somewhere else the jump was superseded, and is dropped rather than
    // yanking focus back when the window finally settles.
    let pending: RwSignal<Option<(Edge, i32)>> = RwSignal::new(None);

    // Reseed the roving tabindex after each render of the row set. Effects run
    // post-render, so `query_selector_all` sees the current rows.
    Effect::new(move |_| {
        rerender();
        let want = pending.get();
        let Some(root) = container() else { return };
        let Some(rows) = rows_of(&root, row_selector) else {
            return;
        };
        let n = rows.length();
        let Some((edge, at)) = want else {
            set_roving(&rows, None);
            return;
        };
        if n == 0 {
            return;
        }

        // The rendered window may still be the pre-scroll one, whose first/last
        // row is not the list's. Rows are absolutely positioned inside the
        // full-height sizer, so `offsetTop` is a row's offset in the *whole*
        // list and `scrollHeight` is that list's height — which is what makes
        // "is this really the edge?" answerable from geometry alone, without
        // this hook knowing the row height or the row count.
        let (idx, arrived) = match edge {
            Edge::First => (0, row_at(&rows, 0).is_some_and(|r| r.offset_top() <= 0)),
            Edge::Last => (
                n - 1,
                row_at(&rows, n - 1)
                    .is_some_and(|r| r.offset_top() + r.offset_height() >= root.scroll_height()),
            ),
        };
        if arrived {
            pending.set(None);
            set_roving(&rows, Some(idx));
        } else if root.scroll_top() != at {
            pending.set(None);
        }
    });

    move |ev: KeyboardEvent| {
        if in_text_field(&ev) {
            return;
        }
        let Some(root) = container() else { return };
        let Some(rows) = rows_of(&root, row_selector) else {
            return;
        };
        let n = rows.length();
        if n == 0 {
            return;
        }
        let (contains, exact) = focused_rows(&rows);

        let target = match ev.key().as_str() {
            // One step is always inside the rendered window: a windowed list
            // renders `overscan` rows beyond the viewport in both directions,
            // so the neighbour of a row the user can see already exists.
            // Focusing it scrolls it into view natively.
            "ArrowDown" => contains.map(|c| (c + 1).min(n - 1)).unwrap_or(0),
            "ArrowUp" => contains.map(|c| c.saturating_sub(1)).unwrap_or(0),
            key @ ("Home" | "End") if source == RowSource::Windowed => {
                // The list's first/last row is usually not rendered at all.
                // Scroll to the end that holds it and let the effect above take
                // focus once the window has been rebuilt around it.
                ev.prevent_default();
                let (edge, top) = match key {
                    "Home" => (Edge::First, 0),
                    _ => (Edge::Last, root.scroll_height()),
                };
                root.set_scroll_top(top);
                pending.set(Some((edge, root.scroll_top())));
                return;
            }
            "Home" => 0,
            "End" => n - 1,
            "Enter" => {
                // Only when the row itself is focused — a focused button keeps
                // its native Enter so activation can't fire twice.
                if let Some(c) = exact
                    && let Some(row) = row_at(&rows, c)
                    && let Ok(Some(btn)) = row.query_selector("button")
                    && let Ok(btn) = btn.dyn_into::<HtmlElement>()
                {
                    ev.prevent_default();
                    btn.click();
                }
                return;
            }
            _ => return,
        };
        ev.prevent_default();
        // An arrow supersedes a Home/End still waiting for its window.
        if pending.get_untracked().is_some() {
            pending.set(None);
        }
        set_roving(&rows, Some(target));
    }
}

/// [`use_row_keynav`] for a `<tbody>` whose every row is rendered — the shape
/// every `DataTable` in the app has.
pub fn use_grid_keynav(
    tbody: NodeRef<html::Tbody>,
    rerender: impl Fn() + 'static,
) -> impl Fn(KeyboardEvent) + Clone + 'static {
    use_row_keynav(
        move || tbody.get().map(Element::from),
        "tr",
        RowSource::Complete,
        rerender,
    )
}
