//! A single list-filter chip: a labeled, count-bearing toggle used by the App
//! Registration / Enterprise Application / Managed Identity list filter bars.
//! Models the audit view's posture-card pattern — a plain `<button>`, **never** a
//! dynamic Thaw `TabList` (those pull `uuid-v4` on wasm, a known no-go).
//!
//! Clicking sets the host view's `facet` signal to this chip's `value`. The chip
//! mutes + disables at a zero count *unless* it is the active selection, so a user
//! can't navigate into an empty filter but can always click away from one.

use leptos::prelude::*;

/// One filter chip. `value` is written into `facet` on click; the chip renders
/// active when `facet` already equals `value`. `count` is the number of loaded
/// rows this chip would show — a zero count mutes + disables the chip (unless it
/// is the active one). Both `class` and `disabled` are reactive closures so the
/// chip restyles itself when `facet` changes without the parent re-rendering.
#[component]
pub fn FilterChip(
    label: &'static str,
    value: &'static str,
    count: usize,
    facet: RwSignal<String>,
) -> impl IntoView {
    let class = move || {
        let mut c = String::from("filter-chip");
        if facet.with(|f| f == value) {
            c.push_str(" filter-chip--active");
        }
        c
    };
    let disabled = move || count == 0 && facet.with(|f| f != value);
    view! {
        <button
            class=class
            type="button"
            prop:disabled=disabled
            on:click=move |_| facet.set(value.to_string())
        >
            <span class="filter-chip__label">{label}</span>
            <span class="filter-chip__count">{count}</span>
        </button>
    }
}
