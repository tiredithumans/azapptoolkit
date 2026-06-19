//! Shared chrome for the tenant list views (App Registrations, Enterprise
//! Applications): the header (title + an actions slot), the always-visible
//! search box, the collapsible filter drawer (saved views + an extra-filter
//! slot), and a body slot for the loaded rows.
//!
//! The facet chips and the virtualized rows depend on loaded data, so they live
//! in the body (`children`) — typically a `Suspense` whose loaded body uses
//! [`use_filtered_list`](crate::hooks::use_filtered_list). The scaffold owns
//! only the data-independent chrome.

use leptos::prelude::*;

use crate::components::filter_toggle::FilterToggle;
use crate::components::saved_views::SavedViews;
use crate::components::ui::SearchInput;

#[component]
pub fn ListScaffold(
    /// Header title, e.g. `"App Registrations"`.
    title: &'static str,
    /// Filter query, lifted to the session so global search can seed it. Shared
    /// with `SavedViews` and the view's own debounce.
    search: RwSignal<String>,
    #[prop(into)] search_placeholder: String,
    /// Saved-views storage key (per list).
    saved_view_key: &'static str,
    /// Active facet value, shared with `SavedViews` and the facet chips.
    facet: RwSignal<String>,
    /// Drawer open/closed state, shared with the loaded body so the facet chips
    /// collapse with the rest of the drawer.
    filters_open: RwSignal<bool>,
    /// Count of active filters, badged on the toggle.
    #[prop(into)]
    active_filters: Signal<usize>,
    /// Header action buttons (export, refresh, …).
    #[prop(optional, into)]
    actions: ViewFn,
    /// Extra filter controls inside the drawer (date range, …).
    #[prop(optional, into)]
    drawer: ViewFn,
    /// The loaded body — usually a `Suspense` wrapping the rows.
    children: Children,
) -> impl IntoView {
    view! {
        <section class="app-list">
            <header class="app-list__header">
                <strong>{title}</strong>
                <div class="list-header-actions">{actions.run()}</div>
            </header>
            <SearchInput value=search placeholder=search_placeholder />
            <FilterToggle open=filters_open active_count=active_filters />
            <Show when=move || filters_open.get()>
                <SavedViews view_key=saved_view_key facet=facet search=search />
                {drawer.run()}
            </Show>
            {children()}
        </section>
    }
}
