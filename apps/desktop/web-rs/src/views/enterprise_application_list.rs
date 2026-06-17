//! Virtualized list of Enterprise Application service principals — every SP
//! in the tenant that is **not** a managed identity. Mirrors the App
//! Registration list's pattern: search + virtualized rows, with a type chip,
//! foreign-tenant pill, and pairing arrow per row. Filtering runs through
//! layered memos over the loaded rows, so a keystroke or chip click never
//! rebuilds the loaded subtree.

use std::sync::Arc;

use chrono::NaiveDate;
use leptos::ev;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::bindings::diagnostics::{self, ListCacheKindDto};
use crate::bindings::enterprise_application::{self, EnterpriseApplicationDto};
use crate::components::date_range_filter::DateRangeFilter;
use crate::components::filter_chip::FilterChip;
use crate::components::filter_toggle::FilterToggle;
use crate::components::icon::IconName;
use crate::components::saved_views::SavedViews;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{EmptyState, IconButton, SearchInput, SkeletonList};
use crate::components::virtual_list::VirtualList;
use crate::hooks::use_debounced::{use_debounced, LIST_FILTER_DEBOUNCE_MS};
use crate::state::use_session;
use crate::util::created_in_range;
use crate::views::pairing::jump_to_paired_app;

const ROW_HEIGHT: f64 = 52.0;

const OVERSCAN: usize = 8;

#[component]
pub fn EnterpriseApplicationList() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let _selected_enterprise_app_id = session.selected_enterprise_app_id;

    // "Filter this list" query, lifted to the session so the top-bar Global
    // Search can seed it (picking an Enterprise Application there lands the user
    // here with the list pre-filtered to that name).
    let raw_search = session.enterprise_search;
    let search = use_debounced(raw_search.into(), LIST_FILTER_DEBOUNCE_MS);

    // Client-side facet over the loaded page: all | enabled | disabled | foreign
    // | assignment (assignment-required). Credential status is the App
    // Registration lens, not the enterprise-app lens, so it's not offered here.
    let ent_filter = RwSignal::new("all".to_string());
    // Unset date picker (None) leaves that side of the creation-date range open;
    // together they bound creation date to an inclusive window.
    let created_after: RwSignal<Option<NaiveDate>> = RwSignal::new(None);
    let created_before: RwSignal<Option<NaiveDate>> = RwSignal::new(None);

    // Collapsible advanced-filter drawer (saved views + created-on range + facet
    // chips); search stays outside it. Default collapsed to reclaim list space,
    // with the active-filter count badged on the toggle.
    let filters_open = RwSignal::new(false);
    let active_filters = Signal::derive(move || {
        (ent_filter.get() != "all") as usize
            + created_after.get().is_some() as usize
            + created_before.get().is_some() as usize
    });

    // Refresh tick — bumped by the Refresh button and session.
    let reload = RwSignal::new(0_u64);
    // True while a Refresh-triggered refetch is in flight, so the Refresh
    // button can show a spinner. Cleared when the resource fetcher resolves.
    let refreshing = RwSignal::new(false);

    // Rows currently shown (after every filter) — captured for the inventory
    // export so "what you see is what you export". Kept in step by an Effect
    // in `LoadedEnterpriseApps`; the `Arc` makes each snapshot a pointer copy.
    let export_rows: StoredValue<Arc<Vec<EnterpriseApplicationDto>>> =
        StoredValue::new(Arc::new(Vec::new()));
    let exporting = RwSignal::new(false);
    let do_export = move |format: &'static str| {
        if exporting.get_untracked() {
            return;
        }
        let rows = export_rows.get_value();
        if rows.is_empty() {
            return;
        }
        exporting.set(true);
        leptos::task::spawn_local(async move {
            let count = rows.len();
            match enterprise_application::save_enterprise_applications_to_file(&rows, format).await
            {
                Ok(Some(path)) => {
                    session.toast_success(format!(
                        "Exported {count} enterprise applications to {path}"
                    ));
                }
                Ok(None) => {}
                Err(e) => {
                    session.toast_error(e.message, None);
                }
            }
            exporting.set(false);
        });
    };

    let sps = LocalResource::new(move || {
        let tenant = tenant.get();
        let _ = reload.get();
        // Bump from session for enterprise-app-specific refetch.
        let _ = session.enterprise_apps_reload.get();
        async move {
            let Some(t) = tenant else {
                refreshing.set(false);
                return Ok(Vec::new());
            };
            let result = enterprise_application::list_enterprise_applications(&t.tenant_id).await;
            refreshing.set(false);
            result
        }
    });

    let on_refresh = move |_| {
        let Some(t) = tenant.get() else {
            return;
        };
        refreshing.set(true);
        // Bump immediately so the resource refetches on next tick.
        reload.update(|n| *n = n.wrapping_add(1));
        leptos::task::spawn_local(async move {
            let _ = diagnostics::invalidate_list_cache(
                t.tenant_id.clone(),
                ListCacheKindDto::Enterprise,
            )
            .await;
        });
    };

    view! {
        <section class="app-list">
            <header class="app-list__header">
                <strong>"Enterprise Applications"</strong>
                <div class="list-header-actions">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                        disabled=Signal::derive(move || exporting.get())
                        on_click=Box::new(move |_| do_export("csv"))
                    >
                        "Export CSV"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                        disabled=Signal::derive(move || exporting.get())
                        on_click=Box::new(move |_| do_export("json"))
                    >
                        "Export JSON"
                    </Button>
                    <IconButton
                        icon=IconName::Refresh
                        aria_label="Refresh Enterprise Applications".to_string()
                        title="Refresh".to_string()
                        on_click=Callback::new(on_refresh)
                        busy=Signal::derive(move || refreshing.get())
                    />
                </div>
            </header>
            <SearchInput value=raw_search placeholder="Filter Enterprise Apps…" />
            <FilterToggle open=filters_open active_count=active_filters />
            <Show when=move || filters_open.get()>
                <SavedViews view_key="enterprise" facet=ent_filter search=raw_search />
                <DateRangeFilter
                    after=created_after
                    before=created_before
                    noun="enterprise applications"
                />
            </Show>
            <Suspense fallback=move || view! { <SkeletonList rows=8 /> }>
                {move || {
                    // Re-runs only on an actual refetch; the filters are read
                    // inside `LoadedEnterpriseApps`' memos, not here.
                    Suspend::new(async move {
                        match sps.await {
                            Ok(items) => {
                                view! {
                                    <LoadedEnterpriseApps
                                        items=items
                                        search=search
                                        ent_filter=ent_filter
                                        created_after=created_after
                                        created_before=created_before
                                        filters_open=filters_open
                                        export_rows=export_rows
                                    />
                                }
                                    .into_any()
                            }
                            Err(err) => {
                                view! {
                                    <Body1 class="app-list__error">
                                        {format!("Failed to load: {}", err.message)}
                                    </Body1>
                                }
                                    .into_any()
                            }
                        }
                    })
                }}
            </Suspense>
        </section>
    }
}

/// The loaded-list body: layered filter memos feeding the facet chips, the
/// result count, and the virtualized rows.
#[component]
fn LoadedEnterpriseApps(
    items: Vec<EnterpriseApplicationDto>,
    search: Signal<String>,
    ent_filter: RwSignal<String>,
    created_after: RwSignal<Option<NaiveDate>>,
    created_before: RwSignal<Option<NaiveDate>>,
    /// Shared with the list view's filter toggle — the facet chips collapse with
    /// the rest of the drawer.
    filters_open: RwSignal<bool>,
    export_rows: StoredValue<Arc<Vec<EnterpriseApplicationDto>>>,
) -> impl IntoView {
    // Count before filtering (for the "N of M" footer).
    let total = items.len();
    let all = Arc::new(items);

    // Name + creation-date range define the base set; the facet chips partition
    // that base (their counts are over it).
    let base = Memo::new(move |_| {
        let needle = search.with(|s| s.trim().to_lowercase());
        let after = created_after.get();
        let before = created_before.get();
        if needle.is_empty() && after.is_none() && before.is_none() {
            return Arc::clone(&all);
        }
        Arc::new(
            all.iter()
                .filter(|sp| {
                    let name_ok =
                        needle.is_empty() || sp.display_name.to_lowercase().contains(&needle);
                    name_ok && created_in_range(sp.created_date_time, after, before)
                })
                .cloned()
                .collect::<Vec<_>>(),
        )
    });
    let counts = Memo::new(move |_| ent_counts(&base.get()));
    let shown = Memo::new(move |_| {
        let facet = ent_filter.get();
        let base = base.get();
        if facet == "all" {
            return base;
        }
        Arc::new(
            base.iter()
                .filter(|sp| matches_ent_facet(sp, &facet))
                .cloned()
                .collect::<Vec<_>>(),
        )
    });

    // Keep the export snapshot in step with what's shown (a pointer copy).
    Effect::new(move |_| export_rows.set_value(shown.get()));

    // No bulk-selection bar: there is no SP-targeted bulk operation (the bulk
    // dialog acts on app registrations), so the list shows only the result
    // count, not a select-all / Bulk-actions control that would act on nothing.
    view! {
        <Show when=move || filters_open.get()>
        {move || {
            let counts = counts.get();
            let base_total = base.with(|b| b.len());
            view! {
                <div class="filter-chips">
                    <FilterChip label="All" value="all" count=base_total facet=ent_filter />
                    <FilterChip
                        label="Enabled"
                        value="enabled"
                        count=counts.enabled
                        facet=ent_filter
                    />
                    <FilterChip
                        label="Disabled"
                        value="disabled"
                        count=counts.disabled
                        facet=ent_filter
                    />
                    <FilterChip
                        label="Foreign"
                        value="foreign"
                        count=counts.foreign
                        facet=ent_filter
                    />
                </div>
            }
        }}
        </Show>
        {move || {
            let shown_n = shown.with(|s| s.len());
            let count_label = if shown_n == total {
                format!("{total} enterprise applications")
            } else {
                format!("{shown_n} of {total} enterprise applications")
            };
            view! {
                <div class="app-list__selectbar">
                    <span class="app-list__count">{count_label}</span>
                </div>
            }
        }}
        <VirtualRows items=shown />
    }
}

/// Per-facet counts over the loaded rows, powering the filter chips. (No
/// assignment-required facet: the shared SP list index doesn't `$select`
/// `appRoleAssignmentRequired`, so it's only known on the detail pane.)
#[derive(Clone, Copy, PartialEq, Eq)]
struct EntCounts {
    enabled: usize,
    disabled: usize,
    foreign: usize,
}

fn ent_counts(items: &[EnterpriseApplicationDto]) -> EntCounts {
    let mut c = EntCounts {
        enabled: 0,
        disabled: 0,
        foreign: 0,
    };
    for sp in items {
        match sp.account_enabled {
            Some(true) => c.enabled += 1,
            Some(false) => c.disabled += 1,
            None => {}
        }
        if sp.is_foreign_tenant {
            c.foreign += 1;
        }
    }
    c
}

/// Whether a service principal matches the active facet chip. `all` (and any
/// unknown value) matches everything.
fn matches_ent_facet(sp: &EnterpriseApplicationDto, facet: &str) -> bool {
    match facet {
        "enabled" => sp.account_enabled == Some(true),
        "disabled" => sp.account_enabled == Some(false),
        "foreign" => sp.is_foreign_tenant,
        _ => true,
    }
}

/// Reactive wrapper around the shared `VirtualList`: the empty state when
/// every row is filtered out, otherwise the keyed virtualized window.
#[component]
fn VirtualRows(items: Memo<Arc<Vec<EnterpriseApplicationDto>>>) -> impl IntoView {
    let session = use_session();
    view! {
        <Show
            when=move || items.with(|v| !v.is_empty())
            fallback=|| {
                view! {
                    <EmptyState
                        icon=IconName::Search
                        title="No matching enterprise applications".to_string()
                        body="Try a broader search term or clear the filters.".to_string()
                    />
                }
            }
        >
            <VirtualList
                items=items
                row_height=ROW_HEIGHT
                overscan=OVERSCAN
                scroller_class="app-list__scroller"
                sizer_class="app-list__sizer"
                key=|sp: &EnterpriseApplicationDto| sp.id.clone()
                render_row=move |idx, sp| view_row(idx, sp, session).into_any()
            />
        </Show>
    }
}

fn view_row(
    idx: usize,
    sp: EnterpriseApplicationDto,
    session: crate::state::Session,
) -> impl IntoView {
    // One shared allocation for the row id; the per-handler captures below are
    // refcount bumps instead of String clones.
    let id: Arc<str> = sp.id.into();
    let id_click = Arc::clone(&id);
    let id_key = Arc::clone(&id);
    let row_class = move || {
        let mut c = String::from("app-list__row");
        if session
            .selected_enterprise_app_id
            .with(|s| s.as_deref() == Some(&*id))
        {
            c.push_str(" app-list__row--selected");
        }
        c
    };
    let top = idx as f64 * ROW_HEIGHT;
    let display_name = if sp.display_name.is_empty() {
        sp.app_id.clone()
    } else {
        sp.display_name
    };
    let title_name = display_name.clone();
    let app_id_string = sp.app_id;
    let is_foreign = sp.is_foreign_tenant;
    let paired_app_id = sp.paired_app_registration_id.clone();

    // Descriptive per-row label so the row button announces which enterprise
    // application it opens.
    let row_label = format!("{display_name} ({app_id_string})");

    view! {
        <div
            class=row_class
            style:top=format!("{top}px")
            style:height=format!("{ROW_HEIGHT}px")
        >
            <button
                class="app-list__row-btn"
                type="button"
                aria-label=row_label
                on:click=move |_| {
                    let s = session;
                    s.set_selected_enterprise_app(Some(id_click.to_string()));
                }
                on:keydown=move |ev: ev::KeyboardEvent| {
                    let s = session;
                    if ev.key() == "Enter" {
                        s.set_selected_enterprise_app(Some(id_key.to_string()));
                    }
                }
            >
                <span class="row-meta">
                    <TypeChip kind=AppKind::EnterpriseApp compact=true />
                    <span class="app-list__row-title" title=title_name>{display_name}</span>
                    {is_foreign
                        .then(|| {
                            view! {
                                <span class="badge badge--warning" title="Foreign tenant — app registered in a different tenant; consented locally.">
                                    "Foreign"
                                </span>
                            }
                        })}
                    {paired_app_id
                        .map(|app_id| {
                            let app_id_clone = app_id.clone();
                            let s_ref = session;
                            let on_pair = move |ev: ev::MouseEvent| {
                                ev.stop_propagation();
                                jump_to_paired_app(s_ref, app_id_clone.clone());
                            };
                            view! {
                                <button
                                    class="pair-arrow"
                                    type="button"
                                    title="Jump to paired App Registration"
                                    aria-label="Jump to paired App Registration"
                                    on:click=on_pair
                                >
                                    "↔"
                                </button>
                            }
                        })}
                </span>
                <span class="app-list__row-appid">{app_id_string}</span>
            </button>
        </div>
    }
}
