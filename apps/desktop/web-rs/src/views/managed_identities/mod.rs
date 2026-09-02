//! Managed Identities view: discover managed identities and grant them
//! application permissions (the RBAC equivalent of `Grant-AzManagedIdentityPermission`).
//! Full-width master list; opening a row adds it to the shell's open-items
//! workspace, where each identity's detail lives in a self-contained
//! [`ManagedIdentityDetailWindow`].

mod detail_window;
mod row;

pub(crate) use row::chip_kind_for;

pub use detail_window::ManagedIdentityDetailWindow;

use std::sync::Arc;

use leptos::prelude::*;
use thaw::Body1;

use crate::components::icon::IconName;
use crate::components::list_scaffold::ListScaffold;
use crate::components::ui::{DetailLoadError, EmptyState, IconButton, SectionHeader, SkeletonList};
use crate::components::virtual_list::VirtualList;

use crate::bindings::diagnostics::{self, ListCacheKindDto};
use crate::bindings::managed_identity::{self, ManagedIdentityDto, MiSubtype};
use crate::components::export_menu::ExportMenu;
use crate::components::filter_chip::FilterChip;
use crate::components::index_cap_notice::IndexCapNotice;
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_filtered_list::{Facet, FilteredListSpec, use_filtered_list};
use crate::hooks::use_list_export::use_list_export;
use crate::state::use_session;
use crate::util::contains_ignore_case;

use row::render_row;

use crate::util::no_tenant;

/// Whether a managed identity matches the active facet chip. `all` (and any
/// unknown value) matches everything. Drives the `use_filtered_list` facet
/// predicates (per-facet counts come from the hook).
fn matches_mi_facet(mi: &ManagedIdentityDto, facet: &str) -> bool {
    match facet {
        "system" => matches!(mi.mi_subtype, MiSubtype::SystemAssigned),
        "user" => matches!(mi.mi_subtype, MiSubtype::UserAssigned),
        "enabled" => mi.account_enabled == Some(true),
        "disabled" => mi.account_enabled == Some(false),
        _ => true,
    }
}

#[component]
pub fn ManagedIdentitiesView() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // "Filter this list" query, lifted to the session so the top-bar Global
    // Search can seed it (picking a Managed Identity there lands the user here
    // with the list pre-filtered to that name). Mirrors the App Registration /
    // Enterprise Application lists.
    let raw_search = session.tenant_ui.mi_search;
    let search = use_debounced(raw_search.into(), LIST_FILTER_DEBOUNCE_MS);
    // Facet chip over the loaded list (all | system | user | enabled | disabled),
    // lifted to the session (like the search above) so the Home dashboard's
    // Managed Identities metrics can seed it.
    let mi_filter = session.tenant_ui.mi_facet;

    // Collapsible filter drawer, matching the two sibling lists (this view had
    // neither the drawer nor the active-filter badge).
    let filters_open = RwSignal::new(false);
    let active_filters = Signal::derive(move || (mi_filter.get() != "all") as usize);

    // Bumped by the Refresh button to force the identities list to re-evaluate.
    let list_reload = RwSignal::new(0_u32);
    // Drives the refresh button's busy spinner. Without it, refreshing this list
    // gave no feedback at all — the other two lists both show one.
    let refreshing = RwSignal::new(false);

    // Rows currently shown (after every filter) — captured for the inventory
    // export so "what you see is what you export" (the backend serializes these
    // passed rows; filters live here). Kept in step by an Effect in
    // `LoadedManagedIdentities`; the `Arc` makes each snapshot a pointer copy.
    let (export_rows, exporting, do_export) = use_list_export(
        |rows: Arc<Vec<ManagedIdentityDto>>, format| async move {
            managed_identity::save_managed_identities_to_file(&rows, format).await
        },
        "managed identities",
    );

    let identities = LocalResource::new(move || {
        let tenant = tenant.get();
        let _ = list_reload.get();
        async move {
            let Some(t) = tenant else {
                refreshing.set(false);
                return Err(no_tenant());
            };
            let result = managed_identity::list_managed_identities(&t.tenant_id).await;
            refreshing.set(false);
            result
        }
    });

    let on_refresh_list = move |_| {
        let Some(t) = tenant.get() else {
            return;
        };
        refreshing.set(true);
        leptos::task::spawn_local(async move {
            diagnostics::invalidate_list_cache(
                t.tenant_id.clone(),
                ListCacheKindDto::ManagedIdentities,
            )
            .await;
            list_reload.update(|n| *n = n.wrapping_add(1));
        });
    };

    view! {
        <div class="mi-view">
            <div>
                <SectionHeader title="Managed Identities".to_string() crumb="Inventory".to_string()>
                    <div class="list-header-actions">
                        <ExportMenu
                            disabled=Signal::derive(move || exporting.get())
                            on_select=Callback::new(do_export)
                            options=vec![("csv", "Export as CSV…"), ("json", "Export as JSON…")]
                        />
                        <IconButton
                            icon=IconName::Refresh
                            aria_label="Refresh managed identities".to_string()
                            title="Refresh".to_string()
                            on_click=Callback::new(on_refresh_list)
                            busy=Signal::derive(move || refreshing.get())
                        />
                    </div>
                </SectionHeader>
                <Body1 class="mi-view__intro">
                    "Grant Microsoft Graph (or another resource) application permissions to a managed identity. Permissions you list (e.g. Mail.Read) are assigned to the selected identity's service principal."
                </Body1>
            </div>
            <div class="mi-view__body">
                <div class="mi-view__list">
                    // Was a hand-rolled search box + SavedViews pair, so this
                    // list had no filter drawer and no active-filter badge while
                    // both sibling lists did.
                    <ListScaffold
                        search=raw_search
                        search_placeholder="Filter Managed Identities by name or appId…"
                        saved_view_key="mi"
                        facet=mi_filter
                        filters_open=filters_open
                        active_filters=active_filters
                    >
                    <Suspense fallback=move || view! { <SkeletonList rows=6 /> }>
                        {move || {
                            // Re-runs only on an actual refetch; the search and
                            // facet are read inside `LoadedManagedIdentities`'
                            // memos, not here.
                            Suspend::new(async move {
                                match identities.await {
                                    Ok(list) if list.is_empty() => {
                                        view! {
                                            <EmptyState
                                                icon=IconName::Server
                                                title="No managed identities yet".to_string()
                                                body="This tenant has no managed identities. Azure creates them when you enable a system- or user-assigned identity on a resource."
                                                    .to_string()
                                            />
                                        }
                                            .into_any()
                                    }
                                    Ok(list) => {
                                        view! {
                                            <LoadedManagedIdentities
                                                list=list
                                                search=search
                                                mi_filter=mi_filter
                                                filters_open=filters_open
                                                export_rows=export_rows
                                            />
                                        }
                                            .into_any()
                                    }
                                    Err(e) => {
                                        // A list load can fail transiently (429 /
                                        // network); offer an in-context Retry through the
                                        // shared load-failure primitive (the App
                                        // Registrations list does the same). Plain reload —
                                        // the header Refresh keeps the cache-busting job.
                                        view! {
                                            <DetailLoadError
                                                error=e
                                                on_retry=Callback::new(move |_| {
                                                    list_reload.update(|n| *n = n.wrapping_add(1))
                                                })
                                                class="app-list__error".to_string()
                                            />
                                        }
                                            .into_any()
                                    }
                                }
                            })
                        }}
                    </Suspense>
                    </ListScaffold>
                </div>
            </div>
        </div>
    }
}

/// The loaded managed-identity list: layered filter memos feeding the facet
/// chips and the virtualized rows, so a keystroke or chip click re-filters in
/// memory without rebuilding this subtree.
#[component]
fn LoadedManagedIdentities(
    list: Vec<ManagedIdentityDto>,
    search: Signal<String>,
    mi_filter: RwSignal<String>,
    /// Drawer state, so the facet chips collapse with the rest of the drawer —
    /// matching the two sibling lists.
    filters_open: RwSignal<bool>,
    export_rows: StoredValue<Arc<Vec<ManagedIdentityDto>>>,
) -> impl IntoView {
    let list = use_filtered_list(FilteredListSpec {
        items: list,
        search,
        // Name OR appId, like the two sibling lists — a managed identity is
        // just as likely to arrive from a log line as from a name.
        search_match: |mi: &ManagedIdentityDto, needle: &str| {
            contains_ignore_case(&mi.display_name, needle)
                || contains_ignore_case(&mi.app_id, needle)
        },
        // No date range or other extra filter on this list — search only.
        extra_active: Signal::derive(|| false),
        extra: |_mi: &ManagedIdentityDto| true,
        facet: mi_filter,
        facet_any: "all",
        facets: vec![
            Facet::new("System", "system", |mi: &ManagedIdentityDto| {
                matches_mi_facet(mi, "system")
            }),
            Facet::new("User", "user", |mi: &ManagedIdentityDto| {
                matches_mi_facet(mi, "user")
            }),
            Facet::new("Enabled", "enabled", |mi: &ManagedIdentityDto| {
                matches_mi_facet(mi, "enabled")
            }),
            Facet::new("Disabled", "disabled", |mi: &ManagedIdentityDto| {
                matches_mi_facet(mi, "disabled")
            }),
        ],
        export_rows: Some(export_rows),
    });

    let filtered = list.shown;
    let total = list.total;
    let shown_total = list.shown_total();
    let base_total = list.base_total();
    let system = list.count_of("system");
    let user = list.count_of("user");
    let enabled = list.count_of("enabled");
    let disabled = list.count_of("disabled");

    view! {
        <Show when=move || filters_open.get()>
            <div class="filter-chips">
                <FilterChip label="All" value="all" count=base_total facet=mi_filter />
                <FilterChip label="System" value="system" count=system facet=mi_filter />
                <FilterChip label="User" value="user" count=user facet=mi_filter />
                <FilterChip label="Enabled" value="enabled" count=enabled facet=mi_filter />
                <FilterChip label="Disabled" value="disabled" count=disabled facet=mi_filter />
            </div>
        </Show>
        <IndexCapNotice noun="managed identity" />
        // Both sibling lists print "N of M"; this one printed nothing, so a
        // filtered view gave no sense of how much it was hiding.
        <div class="app-list__selectbar">
            <span class="app-list__count">
                {move || {
                    let shown_n = shown_total.get();
                    if shown_n == total {
                        format!("{total} managed identities")
                    } else {
                        format!("{shown_n} of {total} managed identities")
                    }
                }}
            </span>
        </div>
        <Show
            when=move || filtered.with(|v| !v.is_empty())
            fallback=|| {
                view! {
                    <EmptyState
                        icon=IconName::Server
                        title="No matches".to_string()
                        body="No managed identities match your filter.".to_string()
                    />
                }
            }
        >
            <VirtualList
                items=filtered
                row_height=ROW_HEIGHT
                overscan=OVERSCAN
                scroller_class="app-list__scroller"
                sizer_class="app-list__sizer"
                row_selector=".app-list__row"
                key=|mi: &ManagedIdentityDto| mi.id.clone()
                render_row=move |idx, mi| { render_row(idx, mi).into_any() }
            />
        </Show>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_mi(subtype: MiSubtype, enabled: Option<bool>) -> ManagedIdentityDto {
        ManagedIdentityDto {
            id: "sp-1".to_string(),
            app_id: "app-1".to_string(),
            display_name: "mi".to_string(),
            account_enabled: enabled,
            mi_subtype: subtype,
        }
    }

    #[test]
    fn matches_mi_facet_filters_by_subtype_and_state() {
        let sys_on = mk_mi(MiSubtype::SystemAssigned, Some(true));
        let usr_off = mk_mi(MiSubtype::UserAssigned, Some(false));
        assert!(matches_mi_facet(&sys_on, "system"));
        assert!(!matches_mi_facet(&sys_on, "user"));
        assert!(matches_mi_facet(&sys_on, "enabled"));
        assert!(matches_mi_facet(&usr_off, "disabled"));
        assert!(!matches_mi_facet(&usr_off, "enabled"));
        // An unknown facet (e.g. the "all" chip) matches everything.
        assert!(matches_mi_facet(&sys_on, "all"));
    }
}
