//! Searchable, virtualized list of app registrations. Mirrors
//! `apps/desktop/web/src/views/ApplicationList.tsx`. Hand-rolled fixed-row
//! windowing replaces `@tanstack/react-virtual` (no Rust port exists).
//!
//! All filtering (search, creation-date range, credential facet) runs **in
//! memory** over the loaded rows through layered memos — a keystroke or chip
//! click re-filters the cached list without refetching or rebuilding the subtree.

use std::sync::Arc;

use azapptoolkit_core::audit::ListCredentialStatus;
use chrono::NaiveDate;
use leptos::ev;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::bindings::applications::{self, ApplicationListRowDto};
use crate::bindings::diagnostics::{self, ListCacheKindDto};
use crate::components::date_range_filter::DateRangeFilter;
use crate::components::filter_chip::FilterChip;
use crate::components::filter_toggle::FilterToggle;
use crate::components::icon::IconName;
use crate::components::saved_views::SavedViews;
use crate::components::select_all_bar::SelectAllBar;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{EmptyState, IconButton, SearchInput, SkeletonList};
use crate::components::virtual_list::VirtualList;
use crate::hooks::use_debounced::{use_debounced, LIST_FILTER_DEBOUNCE_MS};
use crate::state::use_session;
use crate::util::created_in_range;
use crate::views::pairing::jump_to_paired_enterprise;

const ROW_HEIGHT: f64 = 52.0;
const OVERSCAN: usize = 8;
/// Backend safety cap on apps materialized for this list (see `APPS_MAX` in
/// `commands/applications.rs`). Only when the tenant exceeds this do we show a
/// truncation notice — real tenants stay well under it.
const APPS_HARD_CAP: usize = 10_000;

#[component]
pub fn ApplicationList() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let selected = session.selected_app_object_id;

    // "Filter this list" query, lifted to the session so the top-bar Global
    // Search can seed it (picking an App Registration there lands the user here
    // with the list pre-filtered to that name). Debounced, then applied in
    // memory over the loaded rows — like the other two lists, a keystroke
    // never re-enters Graph.
    let raw_search = session.apps_search;
    let search = use_debounced(raw_search.into(), LIST_FILTER_DEBOUNCE_MS);

    // Client-side filters over the loaded rows. "any" disables the credential
    // filter; an unset date picker (None) leaves that side of the creation-date
    // range open — together they bound creation date to an inclusive window.
    let cred_filter = RwSignal::new("any".to_string());
    let created_after: RwSignal<Option<NaiveDate>> = RwSignal::new(None);
    let created_before: RwSignal<Option<NaiveDate>> = RwSignal::new(None);

    // Collapsible advanced-filter drawer (saved views + created-on range + the
    // facet chips). Search stays outside it (always visible). Default collapsed
    // to reclaim list space; the toggle badges the active-filter count so a
    // filter hidden behind it stays discoverable.
    let filters_open = RwSignal::new(false);
    let active_filters = Signal::derive(move || {
        (cred_filter.get() != "any") as usize
            + created_after.get().is_some() as usize
            + created_before.get().is_some() as usize
    });

    // Refresh tick — bumped by the Refresh button to force the resource to
    // re-evaluate after the backend cache for this list has been dropped.
    let reload = RwSignal::new(0_u64);
    // True while a Refresh-triggered refetch is in flight, so the Refresh
    // button can show a spinner. Cleared when the resource fetcher resolves.
    let refreshing = RwSignal::new(false);

    // Rows currently shown (after every filter) — captured for the inventory
    // export so "what you see is what you export". Kept in step by an Effect
    // in `LoadedApps`; the `Arc` makes each snapshot a pointer copy, not a
    // row-by-row clone of the filtered list.
    let export_rows: StoredValue<Arc<Vec<ApplicationListRowDto>>> =
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
            match applications::save_applications_to_file(&rows, format).await {
                Ok(Some(path)) => {
                    session.toast_success(format!("Exported {count} app registrations to {path}"));
                }
                Ok(None) => {}
                Err(e) => {
                    session.toast_error(e.message, None);
                }
            }
            exporting.set(false);
        });
    };

    let apps = LocalResource::new(move || {
        let tenant = tenant.get();
        let _ = reload.get();
        // Bulk delete / remove-expired bump this to force a refetch after the
        // backend cache for this list has been invalidated.
        let _ = session.apps_reload.get();
        async move {
            let Some(t) = tenant else {
                refreshing.set(false);
                return Ok(Vec::new());
            };
            let result = applications::list_applications_with_pairing(&t.tenant_id).await;
            refreshing.set(false);
            result
        }
    });

    let on_refresh = move |_| {
        let Some(t) = tenant.get() else {
            return;
        };
        refreshing.set(true);
        // Bump immediately *before* awaiting so the resource refetches on
        // the next tick (after the backend has had a chance to drop its cache).
        reload.update(|n| *n = n.wrapping_add(1));
        leptos::task::spawn_local(async move {
            let _ = diagnostics::invalidate_list_cache(t.tenant_id.clone(), ListCacheKindDto::Apps)
                .await;
        });
    };

    view! {
        <section class="app-list">
            <header class="app-list__header">
                <strong>"App Registrations"</strong>
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
                        aria_label="Refresh App Registrations".to_string()
                        title="Refresh".to_string()
                        on_click=Callback::new(on_refresh)
                        busy=Signal::derive(move || refreshing.get())
                    />
                </div>
            </header>
            <SearchInput value=raw_search placeholder="Filter App Registrations…" />
            <FilterToggle open=filters_open active_count=active_filters />
            <Show when=move || filters_open.get()>
                <SavedViews view_key="apps" facet=cred_filter search=raw_search />
                <DateRangeFilter after=created_after before=created_before noun="apps" />
            </Show>
            <Suspense fallback=move || view! { <SkeletonList rows=8 /> }>
                {move || {
                    // Re-runs only on an actual refetch (tenant switch / reload
                    // bump): the filters are read inside `LoadedApps`' memos,
                    // not here, so typing or a chip click never tears the
                    // loaded subtree down.
                    Suspend::new(async move {
                        match apps.await {
                            Ok(items) => {
                                view! {
                                    <LoadedApps
                                        items=items
                                        search=search
                                        cred_filter=cred_filter
                                        created_after=created_after
                                        created_before=created_before
                                        filters_open=filters_open
                                        export_rows=export_rows
                                        selected=selected
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

/// The loaded-list body: layered filter memos feeding the chips, the select
/// bar, and the virtualized rows. Built once per fetch; every filter
/// interaction flows through the memos, so each stage rescans only when its
/// own inputs change and downstream subtrees update independently.
#[component]
fn LoadedApps(
    items: Vec<ApplicationListRowDto>,
    search: Signal<String>,
    cred_filter: RwSignal<String>,
    created_after: RwSignal<Option<NaiveDate>>,
    created_before: RwSignal<Option<NaiveDate>>,
    /// Shared with the list view's filter toggle — the facet chips collapse with
    /// the rest of the drawer.
    filters_open: RwSignal<bool>,
    export_rows: StoredValue<Arc<Vec<ApplicationListRowDto>>>,
    selected: RwSignal<Option<String>>,
) -> impl IntoView {
    let session = use_session();
    // The backend paginates to completion (bounded by APPS_HARD_CAP). `total`
    // is the full tenant count, taken before client-side filters shrink the view.
    let total = items.len();
    let capped = total >= APPS_HARD_CAP;
    let all = Arc::new(items);

    // The search + creation-date range define the base set; the credential
    // chips partition that base, so each chip's count agrees with what
    // clicking it shows.
    let base = Memo::new(move |_| {
        let needle = search.with(|s| s.trim().to_lowercase());
        let after = created_after.get();
        let before = created_before.get();
        if needle.is_empty() && after.is_none() && before.is_none() {
            return Arc::clone(&all);
        }
        Arc::new(
            all.iter()
                .filter(|row| {
                    let name_ok =
                        needle.is_empty() || row.display_name.to_lowercase().contains(&needle);
                    name_ok && created_in_range(row.created_date_time, after, before)
                })
                .cloned()
                .collect::<Vec<_>>(),
        )
    });
    let counts = Memo::new(move |_| cred_counts(&base.get()));
    let shown = Memo::new(move |_| {
        let facet = cred_filter.get();
        let base = base.get();
        if facet == "any" {
            return base;
        }
        Arc::new(
            base.iter()
                .filter(|row| row.credential_status.as_facet() == facet)
                .cloned()
                .collect::<Vec<_>>(),
        )
    });

    // Keep the export snapshot in step with what's shown (a pointer copy).
    Effect::new(move |_| export_rows.set_value(shown.get()));

    view! {
        <Show when=move || filters_open.get()>
        {move || {
            let counts = counts.get();
            let base_total = base.with(|b| b.len());
            view! {
                <div class="filter-chips">
                    <FilterChip label="All" value="any" count=base_total facet=cred_filter />
                    <FilterChip
                        label="Active"
                        value="active"
                        count=counts.active
                        facet=cred_filter
                    />
                    <FilterChip
                        label="Expiring"
                        value="expiring"
                        count=counts.expiring
                        facet=cred_filter
                    />
                    <FilterChip
                        label="Expired"
                        value="expired"
                        count=counts.expired
                        facet=cred_filter
                    />
                    <FilterChip
                        label="No creds"
                        value="none"
                        count=counts.none
                        facet=cred_filter
                    />
                </div>
            }
        }}
        </Show>
        {move || {
            let items = shown.get();
            let shown_n = items.len();
            let count_label = if shown_n == total {
                format!("{total} app registrations")
            } else {
                format!("{shown_n} of {total} app registrations")
            };
            let visible_ids: Vec<String> = items.iter().map(|r| r.id.clone()).collect();
            view! {
                <SelectAllBar
                    count_label=count_label
                    visible_ids=visible_ids
                    selected=session.selected_app_ids
                />
            }
        }}
        {capped
            .then(|| {
                view! {
                    <div class="alert alert--warn app-list__cap-notice">
                        {format!(
                            "Loaded the first {APPS_HARD_CAP} apps — search and filters apply within this set.",
                        )}
                    </div>
                }
            })}
        <VirtualRows items=shown selected=selected />
    }
}

/// Per-credential-status counts over the loaded rows, powering the filter
/// chips. Mirrors the four backend-classified buckets the credential filter
/// keys off.
#[derive(Clone, Copy, PartialEq, Eq)]
struct CredCounts {
    active: usize,
    expiring: usize,
    expired: usize,
    none: usize,
}

fn cred_counts(items: &[ApplicationListRowDto]) -> CredCounts {
    let mut c = CredCounts {
        active: 0,
        expiring: 0,
        expired: 0,
        none: 0,
    };
    for row in items {
        match row.credential_status {
            ListCredentialStatus::Active => c.active += 1,
            ListCredentialStatus::Expiring => c.expiring += 1,
            ListCredentialStatus::Expired => c.expired += 1,
            ListCredentialStatus::None => c.none += 1,
        }
    }
    c
}

/// Reactive wrapper around the shared `VirtualList`: the empty state when
/// every row is filtered out, otherwise the keyed virtualized window.
#[component]
fn VirtualRows(
    items: Memo<Arc<Vec<ApplicationListRowDto>>>,
    selected: RwSignal<Option<String>>,
) -> impl IntoView {
    let session = use_session();
    view! {
        <Show
            when=move || items.with(|v| !v.is_empty())
            fallback=|| {
                view! {
                    <EmptyState
                        icon=IconName::Search
                        title="No matching apps".to_string()
                        body="Adjust your search or filters to widen the result set.".to_string()
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
                key=|row: &ApplicationListRowDto| row.id.clone()
                render_row=move |idx, row| view_row(idx, row, selected, session).into_any()
            />
        </Show>
    }
}

fn view_row(
    idx: usize,
    row: ApplicationListRowDto,
    selected: RwSignal<Option<String>>,
    session: crate::state::Session,
) -> impl IntoView {
    let paired_sp_id = row.paired_service_principal_id;
    // One shared allocation for the row id; the per-handler captures below are
    // refcount bumps instead of String clones.
    let id: Arc<str> = row.id.into();
    let id_class = Arc::clone(&id);
    let id_click = Arc::clone(&id);
    let id_key = Arc::clone(&id);
    let id_check = Arc::clone(&id);
    let row_class = move || {
        let mut c = String::from("app-list__row");
        if selected.with(|s| s.as_deref() == Some(&*id_class)) {
            c.push_str(" app-list__row--selected");
        }
        c
    };
    let top = idx as f64 * ROW_HEIGHT;
    let display_name = if row.display_name.is_empty() {
        row.app_id.clone()
    } else {
        row.display_name
    };
    let title_name = display_name.clone();
    let app_id_string = row.app_id;
    // Descriptive per-row label for the bulk-select checkbox: the row's
    // display name plus its appId, so screen-reader users can tell rows apart
    // instead of hearing "Select for bulk actions" repeated.
    let check_label = format!("Select {display_name} ({app_id_string}) for bulk actions");
    view! {
        <div
            class=row_class
            style:top=format!("{top}px")
            style:height=format!("{ROW_HEIGHT}px")
        >
            <input
                type="checkbox"
                class="app-list__check"
                aria-label=check_label
                prop:checked=move || session.is_app_selected(&id_check)
                on:change=move |_| session.toggle_app_selected(id.to_string())
            />
            <button
                class="app-list__row-btn"
                type="button"
                on:click=move |_| { session.set_selected_app(Some(id_click.to_string())) }
                on:keydown=move |ev: ev::KeyboardEvent| {
                    if ev.key() == "Enter" {
                        session.set_selected_app(Some(id_key.to_string()));
                    }
                }
            >
                <span class="row-meta">
                    <TypeChip kind=AppKind::AppRegistration compact=true />
                    <span class="app-list__row-title" title=title_name>{display_name}</span>
                    {paired_sp_id
                        .map(|sp_id| {
                            let on_pair = move |ev: ev::MouseEvent| {
                                ev.stop_propagation();
                                jump_to_paired_enterprise(session, sp_id.clone());
                            };
                            view! {
                                <button
                                    class="pair-arrow"
                                    type="button"
                                    title="Jump to paired Enterprise Application"
                                    aria-label="Jump to paired Enterprise Application"
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
