//! A single list-filter chip: a labeled, count-bearing toggle used by the App
//! Registration / Enterprise Application / Managed Identity list filter bars.
//! Models the audit view's posture-card pattern — a plain `<button>` rather than
//! a Thaw `Tab`, which takes only `class` / `value` / `children` and so cannot
//! carry the count badge or the zero-count `disabled` state below.
//!
//! (This previously claimed a dynamic Thaw `TabList` "pulls `uuid-v4` on wasm, a
//! known no-go". Both halves were false: `thaw::tab_list` contains no `uuid`
//! reference at all — a tab's identity is the caller's `value` string — and
//! `ConfigProvider` mints a `Uuid::new_v4()` on wasm at root mount on every
//! single boot, so uuid-on-wasm cannot be a no-go or this app would not start.
//! Three of the six `TabList` call sites were already dynamic. The real reason
//! to keep this a `<button>` is the API-capability one above.)
//!
//! Clicking sets the host view's `facet` signal to this chip's `value`. The chip
//! mutes + disables at a zero count *unless* it is the active selection, so a user
//! can't navigate into an empty filter but can always click away from one.

use leptos::prelude::*;

/// One filter chip. `value` is written into `facet` on click; the chip renders
/// active when `facet` already equals `value`. `count` is the number of loaded
/// rows this chip would show — a zero count mutes + disables the chip (unless it
/// is the active one). `class`, `disabled`, and the count are all reactive so
/// the chip restyles and re-counts itself **without the parent re-rendering**.
///
/// `count` is a `Signal`, not a `usize`, on purpose: taking it by value forced
/// every caller to unwrap `use_filtered_list`'s reactive counts with `.get()`
/// inside the closure that builds the chip row, which tore down and rebuilt the
/// whole bar on every keystroke and facet click — defeating the hook's memoized
/// counts.
#[component]
pub fn FilterChip(
    label: &'static str,
    value: &'static str,
    #[prop(into)] count: Signal<usize>,
    facet: RwSignal<String>,
) -> impl IntoView {
    let class = move || {
        let mut c = String::from("filter-chip");
        if facet.with(|f| f == value) {
            c.push_str(" filter-chip--active");
        }
        c
    };
    let disabled = move || count.get() == 0 && facet.with(|f| f != value);
    view! {
        <button
            class=class
            type="button"
            prop:disabled=disabled
            on:click=move |_| facet.set(value.to_string())
        >
            <span class="filter-chip__label">{label}</span>
            <span class="filter-chip__count">{move || count.get()}</span>
        </button>
    }
}
