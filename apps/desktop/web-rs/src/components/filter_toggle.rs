//! Collapsible-filters toggle for the list views. A compact button that expands
//! / collapses the advanced filter drawer (saved views, created-on range, facet
//! chips), with an active-filter count badge so a filter hidden behind a
//! collapsed drawer is still discoverable. Search stays outside the drawer
//! (always visible).

use leptos::prelude::*;

use crate::components::icon::{Icon, IconName};

#[component]
pub fn FilterToggle(
    /// Drawer open/closed state, owned by the list view and shared with the
    /// loaded body so the facet chips collapse with everything else.
    open: RwSignal<bool>,
    /// Count of currently-active filters, shown as a badge when non-zero.
    #[prop(into)]
    active_count: Signal<usize>,
) -> impl IntoView {
    view! {
        <button
            class="filter-toggle"
            type="button"
            // A *string*, never a bare `bool`: Leptos renders a bool as a
            // boolean attribute, and neither `aria-expanded=""` nor an absent
            // one is a valid ARIA value.
            aria-expanded=move || open.get().to_string()
            on:click=move |_| open.update(|o| *o = !*o)
        >
            <Icon name=IconName::Filter size=16 />
            <span class="filter-toggle__label">"Filters"</span>
            {move || {
                let c = active_count.get();
                (c > 0).then(|| view! { <span class="filter-toggle__badge">{c}</span> })
            }}
            <span class="filter-toggle__chevron">
                {move || {
                    if open.get() {
                        view! { <Icon name=IconName::ChevronDown size=14 /> }
                    } else {
                        view! { <Icon name=IconName::ChevronRight size=14 /> }
                    }
                }}
            </span>
        </button>
    }
}
