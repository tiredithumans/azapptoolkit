//! Searchable, virtualized list of app registrations. Mirrors
//! `apps/desktop/web/src/views/ApplicationList.tsx`. Hand-rolled fixed-row
//! windowing replaces `@tanstack/react-virtual` (no Rust port exists).
//!
//! All filtering (search, creation-date range, credential facet) runs **in
//! memory** over the loaded rows through the shared [`use_filtered_list`] memos
//! — a keystroke or chip click re-filters the cached list without refetching or
//! rebuilding the subtree. The chrome (header, search, filter drawer) is the
//! shared [`ListScaffold`].

use std::sync::Arc;

use chrono::NaiveDate;
use leptos::ev;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::applications::{self, ApplicationListRowDto};
use crate::bindings::diagnostics::{self, ListCacheKindDto};
use crate::components::bulk_action_bar::{BulkAction, BulkActionBar};
use crate::components::date_range_filter::DateRangeFilter;
use crate::components::export_menu::ExportMenu;
use crate::components::filter_chip::FilterChip;
use crate::components::icon::{Icon, IconName};
use crate::components::list_scaffold::ListScaffold;
use crate::components::select_all_bar::SelectAllBar;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{DetailLoadError, EmptyState, IconButton, SectionHeader, SkeletonList};
use crate::components::virtual_list::VirtualList;
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_filtered_list::{Facet, FilteredListSpec, use_filtered_list};
use crate::hooks::use_list_export::use_list_export;
use crate::state::{ActiveView, OpenItemKind, use_session};
use crate::util::created_in_range;
use crate::views::pairing::jump_to_paired_enterprise;

#[component]
pub fn ApplicationList() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // "Filter this list" query, lifted to the session so the top-bar Global
    // Search can seed it (picking an App Registration there lands the user here
    // with the list pre-filtered to that name). Debounced, then applied in
    // memory over the loaded rows — like the other two lists, a keystroke
    // never re-enters Graph.
    let raw_search = session.tenant_ui.apps_search;
    let search = use_debounced(raw_search.into(), LIST_FILTER_DEBOUNCE_MS);

    // Client-side filters over the loaded rows. "any" disables the credential
    // filter; an unset date picker (None) leaves that side of the creation-date
    // range open — together they bound creation date to an inclusive window.
    // (Local, not lifted: no Home metric drills into the apps credential facet —
    // the Credential Health card drills into the per-credential Security surface.)
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
    // export so "what you see is what you export". Kept in step by the
    // `use_filtered_list` export hook; the `Arc` makes each snapshot a pointer
    // copy, not a row-by-row clone of the filtered list.
    let (export_rows, exporting, do_export) = use_list_export(
        |rows: Arc<Vec<ApplicationListRowDto>>, format| async move {
            applications::save_applications_to_file(&rows, format).await
        },
        "app registrations",
    );

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
        <div class="apps-view">
            <SectionHeader title="App Registrations".to_string() crumb="Inventory".to_string()>
                {move || {
                    let n = session.tenant_ui.selected_app_ids.with(|s| s.len());
                    (n > 0)
                        .then(|| {
                            view! {
                                <span class="selection-bar">
                                    <span class="selection-bar__count">{format!("{n} selected")}</span>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                        on_click=Box::new(move |_| session.set_view(ActiveView::BulkActions))
                                    >
                                        "Bulk Actions…"
                                    </Button>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                        on_click=Box::new(move |_| session.clear_app_selection())
                                    >
                                        "Clear"
                                    </Button>
                                </span>
                            }
                        })
                }}
                <ExportMenu
                    disabled=Signal::derive(move || exporting.get())
                    on_select=Callback::new(do_export)
                    options=vec![("csv", "Export as CSV…"), ("json", "Export as JSON…")]
                />
                <IconButton
                    icon=IconName::Refresh
                    aria_label="Refresh App Registrations".to_string()
                    title="Refresh".to_string()
                    on_click=Callback::new(on_refresh)
                    busy=Signal::derive(move || refreshing.get())
                />
                <Button
                    class="btn-icon-label"
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| session.open_create_app())
                >
                    <Icon name=IconName::Plus size=16 />
                    "New app"
                </Button>
            </SectionHeader>
            <div class="apps-view__body">
                <ListScaffold
                    search=raw_search
                    search_placeholder="Filter App Registrations…"
                    saved_view_key="apps"
                    facet=cred_filter
                    filters_open=filters_open
                    active_filters=active_filters
                    drawer=move || {
                        view! {
                            <DateRangeFilter after=created_after before=created_before noun="apps" />
                        }
                    }
                >
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
                                            />
                                        }
                                            .into_any()
                                    }
                                    Err(err) => {
                                        // A list load can fail transiently (429 / network);
                                        // offer an in-context Retry through the shared
                                        // load-failure primitive (same as the detail panes
                                        // and dashboard cards).
                                        view! {
                                            <DetailLoadError
                                                error=err
                                                on_retry=Callback::new(move |_| {
                                                    reload.update(|n| *n = n.wrapping_add(1))
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
    }
}

/// The loaded-list body: the shared filter memos feeding the chips, the select
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
) -> impl IntoView {
    let session = use_session();

    let list = use_filtered_list(FilteredListSpec {
        items,
        search,
        search_match: |row: &ApplicationListRowDto, needle: &str| {
            row.display_name.to_lowercase().contains(needle)
        },
        extra_active: Signal::derive(move || {
            created_after.get().is_some() || created_before.get().is_some()
        }),
        extra: move |row: &ApplicationListRowDto| {
            created_in_range(
                row.created_date_time,
                created_after.get(),
                created_before.get(),
            )
        },
        facet: cred_filter,
        facet_any: "any",
        // The credential chips partition the base set; each chip's predicate is
        // the same `as_facet` test the count and the partition share, so a
        // chip's count always agrees with what clicking it shows.
        facets: vec![
            Facet::new("Active", "active", |row: &ApplicationListRowDto| {
                row.credential_status.as_facet() == "active"
            }),
            Facet::new("Expiring", "expiring", |row: &ApplicationListRowDto| {
                row.credential_status.as_facet() == "expiring"
            }),
            Facet::new("Expired", "expired", |row: &ApplicationListRowDto| {
                row.credential_status.as_facet() == "expired"
            }),
            Facet::new("No creds", "none", |row: &ApplicationListRowDto| {
                row.credential_status.as_facet() == "none"
            }),
        ],
        export_rows: Some(export_rows),
    });

    // The backend paginates to completion (bounded by APPS_HARD_CAP). `total`
    // is the full tenant count, taken before client-side filters shrink the view.
    let total = list.total;
    let capped = total >= APPS_HARD_CAP;
    let shown = list.shown;
    let base_total = list.base_total();
    let active = list.count_of("active");
    let expiring = list.count_of("expiring");
    let expired = list.count_of("expired");
    let none = list.count_of("none");

    view! {
        <Show when=move || filters_open.get()>
            {move || {
                view! {
                    <div class="filter-chips">
                        <FilterChip
                            label="All"
                            value="any"
                            count=base_total.get()
                            facet=cred_filter
                        />
                        <FilterChip
                            label="Active"
                            value="active"
                            count=active.get()
                            facet=cred_filter
                        />
                        <FilterChip
                            label="Expiring"
                            value="expiring"
                            count=expiring.get()
                            facet=cred_filter
                        />
                        <FilterChip
                            label="Expired"
                            value="expired"
                            count=expired.get()
                            facet=cred_filter
                        />
                        <FilterChip
                            label="No creds"
                            value="none"
                            count=none.get()
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
                    selected=session.tenant_ui.selected_app_ids
                />
            }
        }}
        // Inline bulk-action bar — self-gating: appears once ≥1 app is checked
        // (and stays to show the run summary), so the user can grant consent /
        // remove expired creds / delete without leaving the list (the separate
        // Bulk Actions page remains for Create-apps).
        <BulkActionBar
            selection=session.tenant_ui.selected_app_ids
            actions=Signal::derive(|| {
                vec![BulkAction::Grant, BulkAction::RemoveExpired, BulkAction::Delete]
            })
            on_done=Callback::new(move |_| session.bump_apps_reload())
        />
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
        <VirtualRows items=shown total=total />
    }
}

/// Reactive wrapper around the shared `VirtualList`: the empty state when
/// every row is filtered out, otherwise the keyed virtualized window.
#[component]
fn VirtualRows(
    items: Memo<Arc<Vec<ApplicationListRowDto>>>,
    // The pre-filter tenant count, so an empty tenant gets an onboarding CTA
    // rather than the "adjust your filters" copy meant for a filtered-empty list.
    total: usize,
) -> impl IntoView {
    let session = use_session();
    view! {
        <Show
            when=move || items.with(|v| !v.is_empty())
            fallback=move || {
                if total == 0 {
                    view! {
                        <EmptyState
                            icon=IconName::AppWindow
                            title="No app registrations yet".to_string()
                            body="Create your first app registration to get started.".to_string()
                        >
                            <Button
                                class="btn-icon-label"
                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                on_click=Box::new(move |_| session.open_create_app())
                            >
                                <Icon name=IconName::Plus size=16 />
                                "New app"
                            </Button>
                        </EmptyState>
                    }
                        .into_any()
                } else {
                    view! {
                        <EmptyState
                            icon=IconName::Search
                            title="No matching apps".to_string()
                            body="Adjust your search or filters to widen the result set.".to_string()
                        />
                    }
                        .into_any()
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
                render_row=move |idx, row| view_row(idx, row, session).into_any()
            />
        </Show>
    }
}

fn view_row(
    idx: usize,
    row: ApplicationListRowDto,
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
    // Highlight every row that's open in the workspace (the working set), not a
    // single selection. Class name stays `--selected` so `pairing.rs`'s
    // scroll-settle selector keeps matching.
    let row_class = move || {
        let mut c = String::from("app-list__row");
        if session.is_open(OpenItemKind::AppReg, &id_class).is_some() {
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
    // Owned name copies for the open handlers (the open chip's label).
    let name_click = display_name.clone();
    let name_key = display_name.clone();
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
                on:click=move |_| {
                    session.open_item(OpenItemKind::AppReg, id_click.to_string(), name_click.clone());
                }
                on:keydown=move |ev: ev::KeyboardEvent| {
                    if ev.key() == "Enter" {
                        session.open_item(OpenItemKind::AppReg, id_key.to_string(), name_key.clone());
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
