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

use std::hash::Hash;
use std::sync::Arc;

use leptos::ev;
use leptos::html::Div;
use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen::closure::Closure;
use web_sys::{HtmlElement, ResizeObserver};

#[component]
pub fn VirtualList<T, K, KF, R>(
    /// All rows, reactively. Only the visible window is rendered; when the
    /// row set changes the scroller snaps back to the top (the old offset
    /// pointed into a different list).
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
    /// Stable per-row key (e.g. the object id). Combined with the row's
    /// absolute index — a scroll step keeps every (index, id) pair so DOM is
    /// reused; a filter change that moves a row to a new offset rebuilds it
    /// (its absolutely-positioned `top` is baked in at render time).
    key: KF,
    /// Builds one row. Must set the row's own `style:top` / `style:height`.
    render_row: R,
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

    let scroll_top = RwSignal::new(0.0_f64);
    let viewport_height = RwSignal::new(600.0_f64);
    let scroll_ref: NodeRef<Div> = NodeRef::new();

    // Measure height and update the signal. Handles `scroll_ref` being None
    // (e.g. during SSR or before first frame) by returning early.
    let measure_height = move || {
        if let Some(el) = scroll_ref.get() {
            let h = el.client_height() as f64;
            if h > 0.0 {
                viewport_height.set(h);
            }
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
                // the closure — instead of leaking both via `forget()`. The three
                // lists are keep-alive panes so this fires ~once per session today,
                // but it makes `VirtualList` leak-free for any remounting caller too.
                let closure_store = StoredValue::new_local(Some(observer_fn));
                let observer_for_cleanup = observer.clone();
                on_cleanup(move || {
                    observer_for_cleanup.disconnect();
                    closure_store.set_value(None);
                });
            }
        }
    });

    // Snap back to the top whenever the row set changes (search keystroke,
    // facet click, refetch) — skipping the first run, where the scroller is
    // already at 0. Setting `scrollTop` re-fires `on_scroll`, which is
    // idempotent here.
    Effect::new(move |prev: Option<()>| {
        items.track();
        if prev.is_some() {
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
        let st = scroll_top.get();
        let vh = viewport_height.get();
        let start = ((st / row_height).floor() as usize).saturating_sub(overscan);
        let end = (((st + vh) / row_height).ceil() as usize + overscan).min(total);
        // `start` can exceed `total` for one tick when a filter shrinks the
        // list before the scroll reset lands; clamp so the slice stays valid.
        (start.min(end), end)
    });

    view! {
        <div class=scroller_class node_ref=scroll_ref on:scroll=on_scroll>
            <div
                class=sizer_class
                style:height=move || {
                    format!("{}px", items.with(|all| all.len()) as f64 * row_height)
                }
            >
                <For
                    each=move || {
                        let (start, end) = visible_range.get();
                        items
                            .with(|all| {
                                (start..end)
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
