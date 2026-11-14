//! Shared chrome for the tenant list views (App Registrations, Enterprise
//! Applications): the always-visible search box, the collapsible filter drawer
//! (saved views + an extra-filter slot), and a body slot for the loaded rows.
//!
//! The card starts with ONE toolbar row: the search box, the Filters toggle
//! and the page's actions (`actions`: Export, Refresh, New…). Those used to be
//! three stacked bands — a page header carrying the title and the actions, then
//! the search box, then the toggle on a line of its own — before the count and
//! sort rows, so at the default 1280×800 window the App Registrations list
//! began 340px down and showed nine rows. The page's name is the top bar's.
//!
//! The facet chips and the virtualized rows depend on loaded data, so they live
//! in the body (`children`) — typically a `Suspense` whose loaded body uses
//! [`use_filtered_list`](crate::hooks::use_filtered_list). The scaffold owns
//! only the data-independent chrome.

use leptos::prelude::*;

use chrono::NaiveDate;

use crate::components::filter_toggle::FilterToggle;
use crate::components::saved_views::SavedViews;
use crate::components::ui::SearchInput;

#[component]
pub fn ListScaffold(
    /// Filter query, lifted to the session so global search can seed it. Shared
    /// with `SavedViews` and the view's own debounce.
    search: RwSignal<String>,
    /// Short, since the box shares its row with the page's actions ("Filter by
    /// name or app ID…"). Starts with "Filter" — `/` finds the box by that.
    #[prop(into)]
    search_placeholder: String,
    /// The box's accessible name, which says WHICH list it filters; the
    /// placeholder no longer does.
    #[prop(into)]
    search_label: String,
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
    /// Extra filter controls inside the drawer (date range, …).
    #[prop(optional, into)]
    drawer: ViewFn,
    /// The page's actions, drawn at the end of the toolbar row (the "Updated …
    /// ago" stamp, Export, Refresh, New …).
    #[prop(optional, into)]
    actions: ViewFn,
    /// The drawer's created-on window (F369), forwarded to `SavedViews` so a
    /// saved view carries and restores it along with facet + search.
    #[prop(optional_no_strip)]
    after: Option<RwSignal<Option<NaiveDate>>>,
    #[prop(optional_no_strip)] before: Option<RwSignal<Option<NaiveDate>>>,
    /// The loaded body — usually a `Suspense` wrapping the rows.
    children: Children,
) -> impl IntoView {
    view! {
        <section class="app-list">
            <div class="app-list__toolbar">
                <div class="app-list__toolbar-search">
                    <SearchInput
                        value=search
                        placeholder=search_placeholder
                        label=search_label
                    />
                </div>
                <FilterToggle open=filters_open active_count=active_filters />
                <div class="app-list__toolbar-actions">{actions.run()}</div>
            </div>
            <Show when=move || filters_open.get()>
                <SavedViews
                    view_key=saved_view_key
                    facet=facet
                    search=search
                    after=after
                    before=before
                />
                {drawer.run()}
            </Show>
            {children()}
        </section>
    }
}
