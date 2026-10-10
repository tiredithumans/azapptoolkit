//! Generic fixed-row virtual-scroll windowing, extracted from the app and
//! enterprise lists. Renders only the rows in the visible window (plus an
//! overscan margin), absolutely positioned inside a full-height sizer. The
//! per-row markup and the surrounding empty-state / footer stay caller-side
//! (they differ between lists); this component owns ONLY the scroll/measure
//! bookkeeping and the sizer + positioned-row plumbing.
//!
//! `items` is reactive, so a search/filter change updates the window in place
//! (no remount), and the window is rendered through a keyed `<For>` — a
//! one-row scroll step reuses the DOM of every still-visible row and only
//! creates/drops the edge rows.
//!
//! Keyboard row navigation lives here rather than in the three list views
//! because the element a Home/End has to move before an off-window row can
//! exist — the scroller — is this component's, and so is the signal that says
//! the window has caught up.

use std::hash::Hash;
use std::sync::Arc;

use leptos::ev;
use leptos::html::Div;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{Element, HtmlElement, ResizeObserver};

use crate::hooks::use_grid_keynav::{RowSource, use_row_keynav};

/// The caller half of [`VirtualList`]'s `scroll_offset`: zero the carried
/// offset whenever `items` changes, from a scope that outlives the list.
///
/// `VirtualList` snaps to the top itself on a row-set change — but only while it
/// is mounted. The App Registrations / Enterprise lists wrap it in a
/// `<Show when=non-empty>`, so a search that matches nothing unmounts it before
/// its snap runs; without this, the next non-empty result would remount it at
/// the offset of the old, unrelated row set. The first run is skipped: a fresh
/// caller (a refetch remount) is exactly where the carried offset must survive.
pub fn reset_scroll_offset_on_change<T>(items: Memo<Arc<Vec<T>>>, offset: RwSignal<f64>)
where
    T: Send + Sync + 'static,
{
    Effect::new(move |prev: Option<()>| {
        items.track();
        if prev.is_some() {
            offset.set(0.0);
        }
    });
}

#[component]
pub fn VirtualList<T, K, KF, R>(
    /// All rows, reactively. Only the visible window is rendered; when the
    /// row set changes within this instance the scroller snaps back to the top
    /// (the old offset pointed into a different list). A parent that remounts
    /// the list instead (a refetch) carries the offset via `scroll_offset`.
    #[prop(into)]
    items: Signal<Arc<Vec<T>>>,
    /// Fixed row height in pixels (e.g. `52.0`).
    row_height: f64,
    /// Extra rows rendered above/below the viewport (e.g. `8`).
    overscan: usize,
    /// Class for the scrolling container (the element with the `on:scroll`).
    #[prop(into)]
    scroller_class: String,
    /// Class for the full-height inner sizer the rows are positioned in.
    #[prop(into)]
    sizer_class: String,
    /// Selector matching the row roots `render_row` produces (e.g.
    /// `".app-list__row"`), which gives them the roving-tabindex Arrow/Home/End
    /// navigation every `DataTable` already has. Required rather than optional:
    /// a windowed list is exactly the case where crossing it by Tab alone is
    /// unusable, so opting out would only ever be an oversight.
    row_selector: &'static str,
    /// Stable per-row key (e.g. the object id). Combined with the row's
    /// absolute index — a scroll step keeps every (index, id) pair so DOM is
    /// reused; a filter change that moves a row to a new offset rebuilds it
    /// (its absolutely-positioned `top` is baked in at render time).
    key: KF,
    /// Builds one row. Must set the row's own `style:top` / `style:height`.
    render_row: R,
    /// Caller-owned scroll offset. When given, the offset outlives this
    /// instance, so a parent that remounts the list on a refetch (the
    /// `<Suspense>` bodies of the App Registrations / Enterprise lists) lands
    /// back where the operator was; a row-set change within one instance still
    /// snaps to the top. A caller that can unmount this list while the row set
    /// changes (an empty-state `<Show>`) must also call
    /// [`reset_scroll_offset_on_change`], or the offset outlives the row set it
    /// pointed into.
    #[prop(optional)]
    scroll_offset: Option<RwSignal<f64>>,
) -> impl IntoView
where
    T: Clone + Send + Sync + 'static,
    K: Eq + Hash + 'static,
    KF: Fn(&T) -> K + 'static,
    R: Fn(usize, T) -> AnyView + 'static,
{
    // `LocalStorage` (single-threaded) so the generic closures need not be
    // `Send + Sync` — they never are for these CSR-only callers (the row
    // renderer captures non-`Send` `Session`/signal handles). The `StoredValue`
    // *handles* are `Copy + Send`, which is what keeps the `<For>` closures
    // below (which must be `Send`) happy.
    let render_row: StoredValue<R, LocalStorage> = StoredValue::new_local(render_row);
    let key: StoredValue<KF, LocalStorage> = StoredValue::new_local(key);

    // Writing through to the caller's signal (when given) is what carries the
    // offset across a remount — and `visible_range` renders the carried window
    // straight away, before the DOM scroller has caught up.
    let scroll_top = scroll_offset.unwrap_or_else(|| RwSignal::new(0.0_f64));
    let viewport_height = RwSignal::new(600.0_f64);
    let scroll_ref: NodeRef<Div> = NodeRef::new();

    // A carried offset still has to be replayed into the DOM: a fresh scroller
    // starts at `scrollTop` 0. And it can only land once the scroller has
    // layout — a list remounted while its view is hidden (`keep_alive`'s
    // `display:none`, e.g. a bulk delete run from the Bulk Actions page)
    // ignores `scrollTop` — so this is retried from the ResizeObserver, which
    // fires on the hidden → shown transition.
    //
    // The value replayed is the signal's CURRENT one, not a snapshot taken at
    // construction: the caller's `reset_scroll_offset_on_change` may zero it
    // after this instance was built for the new row set, and that reset wins.
    let pending_restore = StoredValue::new(scroll_offset.is_some_and(|s| s.get_untracked() > 0.0));
    let apply_pending = move |el: &HtmlElement| {
        if el.client_height() > 0 && pending_restore.get_value() {
            pending_restore.set_value(false);
            let v = scroll_top.get_untracked();
            if v > 0.0 {
                el.set_scroll_top(v.round() as i32);
                // Read back: the browser clamps to the (possibly shrunk) list,
                // and a clamp to 0 fires no scroll event — without this the
                // window would stay at a stale offset.
                scroll_top.set(el.scroll_top() as f64);
            }
        }
    };

    // Measure height and update the signal. Handles `scroll_ref` being None
    // (e.g. during SSR or before first frame) by returning early.
    let measure_height = move || {
        if let Some(el) = scroll_ref.get() {
            let h = el.client_height() as f64;
            if h > 0.0 {
                viewport_height.set(h);
            }
            apply_pending(&el);
        }
    };

    // Observe resize events so the viewport height stays correct when the
    // window or a sibling pane changes size without triggering `scroll`.
    Effect::new(move |_| {
        measure_height(); // initial measurement on mount

        if let Some(el) = scroll_ref.get() {
            let observer_fn = Closure::wrap(Box::new({
                // Clone the element into the closure so we own it.
                let el_clone: HtmlElement = el.clone().unchecked_into();
                move |_: Vec<web_sys::ResizeObserverEntry>| {
                    let h = el_clone.client_height() as f64;
                    if h > 0.0 {
                        viewport_height.set(h);
                    }
                    apply_pending(&el_clone);
                }
            })
                as Box<dyn FnMut(Vec<web_sys::ResizeObserverEntry>)>);

            // ResizeObserver keeps the viewport height in sync with layout
            // changes. If the API is unavailable, fall back to the initial
            // `measure_height` plus the on-scroll measure rather than crashing
            // the whole list on an `unwrap`.
            if let Ok(observer) = ResizeObserver::new(observer_fn.as_ref().unchecked_ref()) {
                // Observe uses the original `el` reference (still alive since this is a
                // sync setup block), while the closure owns its own `el_clone` copy.
                observer.observe(&el);

                // Keep the closure alive while observing (the observer holds a raw
                // pointer to it), then on unmount disconnect the observer and drop
                // the closure — instead of leaking both via `forget()`. The lists
                // remount on every refetch (their `<Suspense>` bodies re-run), so
                // this fires once per reload, not once per session.
                let closure_store = StoredValue::new_local(Some(observer_fn));
                let observer_for_cleanup = observer.clone();
                on_cleanup(move || {
                    observer_for_cleanup.disconnect();
                    closure_store.set_value(None);
                });
            }
        }
    });

    // The row that has keyboard focus, by absolute index, so the window keeps
    // rendering it after it scrolls out of view. The keyed `<For>` used to
    // drop that row's node with the rest of the overscan: focus fell to
    // <body>, the arrow keys (bound on the scroller) went dead, and the roving
    // tab stop reseeded to the first rendered row. A row's absolute index is
    // its `top` over the row height — the positioning contract every
    // `render_row` keeps. Cleared when focus leaves the scroller altogether,
    // and when the row set changes (the pin indexed the old one).
    let focused_row: RwSignal<Option<usize>> = RwSignal::new(None);

    // Snap back to the top whenever the row set changes within this instance
    // (search keystroke, facet click, sort) — skipping the first run, where
    // the scroller is at 0 or at the carried offset. A refetch never reaches
    // this: it remounts the instance (the callers' `<Suspense>` bodies), and
    // the caller's `scroll_offset` carries the position across that. Setting
    // `scrollTop` re-fires `on_scroll`, which is idempotent here.
    Effect::new(move |prev: Option<()>| {
        items.track();
        if prev.is_some() {
            // A carried offset pointed into the old row set too; don't let a
            // later visibility change jump back to it.
            pending_restore.set_value(false);
            // Nor the pin: its node leaves with the old row set, and no
            // focusout fires for a removed node, so a stale index would
            // render whatever row now sits there — invisible, outside the
            // window, and the arrow keys' next target.
            focused_row.set(None);
            if let Some(el) = scroll_ref.get_untracked() {
                el.set_scroll_top(0);
            }
            scroll_top.set(0.0);
        }
    });

    let on_scroll = move |ev: ev::Event| {
        if let Some(target) = ev.current_target()
            && let Ok(el) = target.dyn_into::<HtmlElement>()
        {
            scroll_top.set(el.scroll_top() as f64);
            let h = el.client_height() as f64;
            if h > 0.0 {
                viewport_height.set(h);
            }
        }
    };

    let visible_range = Memo::new(move |_| {
        let total = items.with(|all| all.len());
        visible_window(
            scroll_top.get(),
            viewport_height.get(),
            row_height,
            total,
            overscan,
        )
    });

    let on_focusin = move |ev: ev::FocusEvent| {
        let row = ev
            .target()
            .and_then(|t| t.dyn_into::<Element>().ok())
            .and_then(|t| t.closest(row_selector).ok().flatten())
            .and_then(|r| r.dyn_into::<HtmlElement>().ok());
        let idx = row.map(|r| (f64::from(r.offset_top()) / row_height).round() as usize);
        // Tab between a row's buttons re-fires this for the same row; an
        // unchanged write would still re-run `each` (every rendered row cloned).
        if focused_row.get_untracked() != idx {
            focused_row.set(idx);
        }
    };
    let on_focusout = move |ev: ev::FocusEvent| {
        // Alt-tab, a native dialog or the re-auth window blur the focused
        // element with no related target. The row is still the one to come
        // back to, so keep it rendered; focusin re-pins it on return anyway.
        if !leptos::prelude::document().has_focus().unwrap_or(true) {
            return;
        }
        let stays_inside = ev
            .related_target()
            .and_then(|t| t.dyn_into::<web_sys::Node>().ok())
            .is_some_and(|n| {
                scroll_ref
                    .get_untracked()
                    .is_some_and(|root| root.contains(Some(&n)))
            });
        if !stays_inside {
            focused_row.set(None);
        }
    };

    // Keyboard row navigation over the *rendered* window. `visible_range` is the
    // rerender trigger the hook waits on: a Home/End scrolls first and can only
    // take focus once the window has been rebuilt around the target row, and
    // this is the signal that says it has. `items` is tracked too — a re-sort
    // leaves the range untouched while replacing every row in it.
    let on_keydown = use_row_keynav(
        move || scroll_ref.get().map(Element::from),
        row_selector,
        RowSource::Windowed,
        move || {
            items.track();
            visible_range.track();
        },
    );

    view! {
        <div
            class=scroller_class
            node_ref=scroll_ref
            on:scroll=on_scroll
            on:keydown=on_keydown
            on:focusin=on_focusin
            on:focusout=on_focusout
        >
            <div
                class=sizer_class
                style:height=move || {
                    format!("{}px", items.with(|all| all.len()) as f64 * row_height)
                }
            >
                <For
                    each=move || {
                        let (start, end) = visible_range.get();
                        // The focused row rides along outside the window, IN
                        // INDEX ORDER: its (index, key) is unchanged, so the
                        // keyed diff keeps its node — but only if it never has
                        // to move it. A move is `insertBefore`, which the DOM
                        // runs as remove + insert, and a removed node loses
                        // focus. Appended last, a row pinned above the window
                        // was moved on every scroll down.
                        let pinned = focused_row.get().filter(|f| !(start..end).contains(f));
                        let above = pinned.filter(|f| *f < start);
                        let below = pinned.filter(|f| *f >= end);
                        items
                            .with(|all| {
                                above
                                    .into_iter()
                                    .chain(start..end)
                                    .chain(below)
                                    .filter_map(|i| all.get(i).cloned().map(|item| (i, item)))
                                    .collect::<Vec<_>>()
                            })
                    }
                    key=move |(i, item)| (*i, key.with_value(|k| k(item)))
                    children=move |(i, item)| render_row.with_value(|f| f(i, item))
                />
            </div>
        </div>
    }
}

/// The `(start, end)` slice of rows to render for a scroller at `scroll_top`
/// with `viewport_h` of visible height: the rows under the viewport plus
/// `overscan` on each side, clamped to `total`. Pure, so the arithmetic every
/// list's window rides on has tests of its own.
pub(crate) fn visible_window(
    scroll_top: f64,
    viewport_h: f64,
    row_h: f64,
    total: usize,
    overscan: usize,
) -> (usize, usize) {
    debug_assert!(row_h > 0.0, "a zero row height makes the window infinite");
    // A rubber-band scroll reports a negative offset for a frame.
    let st = scroll_top.max(0.0);
    let start = ((st / row_h).floor() as usize).saturating_sub(overscan);
    let end = (((st + viewport_h) / row_h).ceil() as usize)
        .saturating_add(overscan)
        .min(total);
    // `start` can exceed `total` for one tick when a filter shrinks the list
    // before the scroll reset lands; clamp so the slice stays valid.
    (start.min(end), end)
}

#[cfg(test)]
mod tests {
    use super::visible_window;

    #[test]
    fn the_window_covers_the_viewport_plus_overscan_and_clamps() {
        assert_eq!(visible_window(0.0, 600.0, 52.0, 1000, 8), (0, 20));
        assert_eq!(visible_window(5200.0, 600.0, 52.0, 1000, 8), (92, 120));
        assert_eq!(
            visible_window(5000.0, 600.0, 52.0, 100, 8),
            (88, 100),
            "the end clamps to the row count"
        );
        assert_eq!(
            visible_window(5200.0, 600.0, 52.0, 3, 8),
            (3, 3),
            "a list that shrank under the scroll offset clamps the start too"
        );
        assert_eq!(visible_window(0.0, 600.0, 52.0, 0, 8), (0, 0));
        assert_eq!(
            visible_window(-40.0, 600.0, 52.0, 1000, 8),
            (0, 20),
            "a rubber-band offset reads as the top"
        );
    }
}
