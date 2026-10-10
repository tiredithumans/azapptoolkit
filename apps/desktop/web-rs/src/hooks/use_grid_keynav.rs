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
//!   scroller: only the rows around the viewport exist, plus the focused row
//!   wherever it is (the list keeps it rendered after it scrolls away, so focus
//!   survives). Rows are found by GEOMETRY, not DOM order — their place in the
//!   list, measured against the full-height sizer they sit in — because the DOM
//!   neighbour of a focused row the window has left is the far edge of the
//!   window. An arrow steps to the row one row-height away: when it is rendered
//!   (the usual case, the overscan keeps it materialized) it is focused on the
//!   spot; when it is not (the focused row was scrolled out of view), the
//!   container scrolls it into view first and focus follows once the window has
//!   been rebuilt around it. Home/End address rows that are usually not
//!   rendered at all, so they take that deferred path too. A scroll that cannot
//!   move (a list shorter than the view, or already at that end) brings no
//!   render, so the target is then focused on the spot or not at all — never
//!   parked.

use leptos::ev::KeyboardEvent;
use leptos::html;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{Element, HtmlElement, NodeList};

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

/// What a deferred move on a windowed list is waiting for the window to
/// render.
#[derive(Clone, Copy, PartialEq)]
enum Goal {
    /// The list's first or last row (Home/End).
    Edge(Edge),
    /// The row whose top sits at this offset in the whole list — the neighbour
    /// of a focused row the window has scrolled away from (an arrow step).
    RowAt(f64),
}

/// Rows a pixel apart are the same row: geometry comes back fractional under
/// zoom.
const SAME_PX: f64 = 0.5;

fn rows_of(root: &Element, selector: &str) -> Option<NodeList> {
    root.query_selector_all(selector).ok()
}

fn row_at(rows: &NodeList, i: u32) -> Option<HtmlElement> {
    rows.item(i).and_then(|n| n.dyn_into::<HtmlElement>().ok())
}

/// A windowed row's `(top, height)` in the whole list, and the list's height —
/// measured against the row's parent, the full-height sizer a `VirtualList`
/// positions its rows in. That holds whatever the rows' CSS is (absolutely
/// positioned in the app, stacked in a GUI test that loads no stylesheet), and
/// never reads the scroller's own height, which a list shorter than the view
/// does not fill.
fn list_box(row: &Element) -> Option<(f64, f64, f64)> {
    let sizer = row.parent_element()?.get_bounding_client_rect();
    let r = row.get_bounding_client_rect();
    Some((r.top() - sizer.top(), r.height(), sizer.height()))
}

/// The rendered row whose top sits at `top` in the whole list, if any.
fn row_index_at(rows: &NodeList, top: f64) -> Option<u32> {
    (0..rows.length()).find(|&i| {
        row_at(rows, i)
            .and_then(|r| list_box(&r))
            .is_some_and(|(t, _, _)| (t - top).abs() < SAME_PX)
    })
}

/// The rendered row a deferred goal is waiting for, if the window has
/// rendered it. The window may still be the pre-scroll one, whose first/last
/// row is not the list's — which only the geometry can tell, since this hook
/// knows neither the row height nor the row count.
fn resolve(goal: Goal, rows: &NodeList) -> Option<u32> {
    let n = rows.length();
    if n == 0 {
        return None;
    }
    let edge_box = |i| row_at(rows, i).and_then(|r| list_box(&r));
    match goal {
        Goal::Edge(Edge::First) => edge_box(0).filter(|(top, _, _)| *top < SAME_PX).map(|_| 0),
        Goal::Edge(Edge::Last) => edge_box(n - 1)
            .filter(|(top, h, list_h)| top + h > list_h - SAME_PX)
            .map(|_| n - 1),
        Goal::RowAt(top) => row_index_at(rows, top),
    }
}

/// `(row holding focus, row that *is* focused)`. The first counts a focused
/// in-row button (so arrows work from anywhere in the row); the second is the
/// row element itself, which is what Enter acts on.
fn focused_rows(rows: &NodeList) -> (Option<u32>, Option<u32>) {
    let active = active_node();
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

fn active_node() -> Option<web_sys::Node> {
    web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.active_element())
        .map(|e| e.unchecked_into::<web_sys::Node>())
}

/// Whether the operator has moved focus to something outside `root` — another
/// control, not `<body>`. Focus on `<body>` is what a DOM move of the focused
/// row leaves behind (the list puts it back), not a decision to leave.
fn focus_moved_away(root: &Element) -> bool {
    let body = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.body());
    active_node().is_some_and(|a| {
        !root.contains(Some(&a)) && !body.as_ref().is_some_and(|b| b.is_same_node(Some(&a)))
    })
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

/// Re-seeds the roving tab stop on whichever row of `root` holds focus,
/// without moving focus — for a caller that has just put focus back on a row
/// (the windowed list, after a render moved the focused row's node).
pub(crate) fn reseed(root: &Element, row_selector: &str) {
    if let Some(rows) = rows_of(root, row_selector) {
        set_roving(&rows, None);
    }
}

/// Scrolls a windowed `root` to `top` for a `goal` that is not rendered yet,
/// and returns what to park: the goal plus the `scrollTop` actually taken (the
/// browser clamps it). A scroll that does not move brings no render, so the
/// goal is settled on the spot instead — focused if it is rendered after all,
/// dropped if not — and nothing is parked: a parked goal nothing will resolve
/// would steal focus the next time the list happened to grow.
fn scroll_toward(root: &Element, rows: &NodeList, goal: Goal, top: i32) -> Option<(Goal, i32)> {
    let before = root.scroll_top();
    root.set_scroll_top(top.max(0));
    let taken = root.scroll_top();
    if taken != before {
        return Some((goal, taken));
    }
    if let Some(i) = resolve(goal, rows) {
        set_roving(rows, Some(i));
    }
    None
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
    // A Home/End — or an arrow from a row scrolled out of view — over a
    // windowed list addresses a row that isn't rendered: the scroll is issued
    // immediately and the focus is parked here until a render brings the row
    // into existence. The `i32` is the `scrollTop` that was actually taken — if
    // the container has since moved somewhere else the jump was superseded,
    // and is dropped rather than yanking focus back when the window settles.
    let pending: RwSignal<Option<(Goal, i32)>> = RwSignal::new(None);

    // Reseed the roving tabindex — and settle a parked goal — after each render
    // of the row set.
    Effect::new(move |_| {
        rerender();
        pending.track();
        // Read (and tracked) here, so a first run that precedes the mount
        // re-runs on it; the element is handed to the deferred pass, since a
        // NodeRef read outside a reactive context warns in debug builds.
        let Some(root) = container() else { return };
        // The DOM pass waits for the end of this tick. This effect and the
        // keyed `<For>` that renders the rows are woken by the same signals in
        // subscription order, which is not render order (a `<For>` re-run on
        // its own — a focus change re-running a windowed list's — moves it
        // behind this effect). Run here, the pass could read the pre-render
        // rows: a parked goal missed its row, and a freshly rendered row got
        // no tabindex, so a click on it could not focus it.
        queue_microtask(move || {
            // The list can be gone by now (a remount, a tenant switch).
            let Some(want) = pending.try_get_untracked() else {
                return;
            };
            let Some(rows) = rows_of(&root, row_selector) else {
                return;
            };
            let Some((goal, at)) = want else {
                set_roving(&rows, None);
                return;
            };
            // A goal only ever moves focus that is still with this list:
            // once the operator has moved on (the search box, another pane),
            // it is dropped instead of pulling focus back.
            if focus_moved_away(&root) {
                let _ = pending.try_set(None);
                return;
            }
            if let Some(idx) = resolve(goal, &rows) {
                let _ = pending.try_set(None);
                set_roving(&rows, Some(idx));
            } else if root.scroll_top() != at {
                let _ = pending.try_set(None);
            }
        });
    });

    move |ev: KeyboardEvent| {
        // The shared predicate (`hooks::is_text_entry`), not a surface-local
        // twin: a row's bulk-select checkbox is explicitly not a text field —
        // arrowing off it is exactly what a keyboard user expects.
        if super::is_text_entry(&ev) {
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
        // A move this key makes supersedes a goal parked by an earlier one.
        let park = |goal: Option<(Goal, i32)>| {
            if goal.is_some() || pending.get_untracked().is_some() {
                pending.set(goal);
            }
        };

        let target = match ev.key().as_str() {
            key @ ("ArrowDown" | "ArrowUp")
                if source == RowSource::Windowed && contains.is_some() =>
            {
                ev.prevent_default();
                let Some((top, h, list_h)) = contains
                    .and_then(|c| row_at(&rows, c))
                    .and_then(|r| list_box(&r))
                else {
                    return;
                };
                // The neighbour by geometry: one row-height above or below.
                let want = if key == "ArrowDown" { top + h } else { top - h };
                if want < -SAME_PX || want + h > list_h + SAME_PX {
                    return; // already the list's first/last row
                }
                if let Some(i) = row_index_at(&rows, want) {
                    // Rendered: focusing it scrolls it into view natively.
                    i
                } else {
                    // Not rendered: the focused row was scrolled out of view.
                    // Bring the neighbour to the nearest edge of the viewport
                    // (the sizer's offset in the scroller turns its list top
                    // into a scroll position) and focus it once it exists.
                    let Some(sizer) = row_at(&rows, 0).and_then(|r| r.parent_element()) else {
                        return;
                    };
                    let origin = sizer.get_bounding_client_rect().top()
                        - root.get_bounding_client_rect().top()
                        - f64::from(root.client_top())
                        + f64::from(root.scroll_top());
                    let at = origin + want;
                    let scroll = if at < f64::from(root.scroll_top()) {
                        at
                    } else {
                        at + h - f64::from(root.client_height())
                    };
                    park(scroll_toward(
                        &root,
                        &rows,
                        Goal::RowAt(want),
                        scroll.round() as i32,
                    ));
                    return;
                }
            }
            "ArrowDown" => contains.map(|c| (c + 1).min(n - 1)).unwrap_or(0),
            "ArrowUp" => contains.map(|c| c.saturating_sub(1)).unwrap_or(0),
            key @ ("Home" | "End") if source == RowSource::Windowed => {
                // The list's first/last row is usually not rendered at all.
                // Scroll to the end that holds it and take focus once the
                // window has been rebuilt around it.
                ev.prevent_default();
                let (edge, top) = match key {
                    "Home" => (Edge::First, 0),
                    _ => (Edge::Last, root.scroll_height()),
                };
                park(scroll_toward(&root, &rows, Goal::Edge(edge), top));
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
        park(None);
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
