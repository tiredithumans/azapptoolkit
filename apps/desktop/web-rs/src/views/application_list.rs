//! Searchable, virtualized list of app registrations. Mirrors
//! `apps/desktop/web/src/views/ApplicationList.tsx`. Hand-rolled fixed-row
//! windowing replaces `@tanstack/react-virtual` (no Rust port exists).
//!
//! All filtering (search, creation-date range, credential facet) runs **in
//! memory** over the loaded rows through the shared [`use_filtered_list`] memos
//! — a keystroke or chip click re-filters the cached list without refetching or
//! rebuilding the subtree. The chrome (header, search, filter drawer) is the
//! shared [`ListScaffold`].

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use azapptoolkit_core::audit::ListCredentialStatus;
use chrono::{DateTime, NaiveDate, Utc};
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
use crate::components::ui::{
    Badge, Callout, DetailLoadError, EmptyState, IconButton, SectionHeader, SkeletonList,
};
use crate::components::virtual_list::VirtualList;
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_filtered_list::{Facet, FilteredListSpec, use_filtered_list};
use crate::hooks::use_list_export::use_list_export;
use crate::state::{ActiveView, OpenItemKind, use_session};
use crate::util::{contains_ignore_case, created_in_range, relative_time};
use crate::views::pairing::jump_to_paired_enterprise;

/// A sortable App Registrations column.
///
/// The order Graph returned is the unsorted default — the list command sends no
/// `$orderby` precisely because ordering happens here — and clicking a column
/// cycles default-direction → reverse → back to unsorted, so that original
/// order is always recoverable. Modelled on the audit table's `SortCol`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AppSortCol {
    Name,
    Expiry,
    Created,
}

impl AppSortCol {
    /// First-click direction: names A→Z, soonest expiry first (the triage
    /// need), newest apps first.
    fn default_desc(self) -> bool {
        matches!(self, AppSortCol::Created)
    }

    fn label(self) -> &'static str {
        match self {
            AppSortCol::Name => "Name",
            AppSortCol::Expiry => "Soonest expiry",
            AppSortCol::Created => "Created",
        }
    }
}

/// Orders two optional column values, keeping the rows that *have* no value at
/// the bottom in **both** directions. Reversing them along with everything else
/// would head the descending view with "no credentials" / "creation date
/// unknown" — the one thing the column cannot rank.
fn cmp_missing_last<T: Ord>(a: Option<&T>, b: Option<&T>, desc: bool) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => {
            let ord = x.cmp(y);
            if desc { ord.reverse() } else { ord }
        }
    }
}

/// Orders the filtered rows by `col`. Pure so the column semantics — above all
/// where a missing value lands — are pinned by tests rather than by eyeballing
/// a 5 000-app tenant.
fn sort_rows(rows: &mut [ApplicationListRowDto], col: AppSortCol, desc: bool) {
    match col {
        AppSortCol::Name => {
            // Lowercase ONCE per row (`sort_by_cached_key`) instead of twice per
            // comparison: the comparator runs O(n log n) times, and at the
            // 10 000-row list ceiling allocating inside it dominates the sort.
            // `reverse()` afterwards rather than a reversing comparator keeps
            // that single allocation; the only difference is the relative order
            // of rows sharing one name exactly.
            rows.sort_by_cached_key(|r| r.display_name.to_lowercase());
            if desc {
                rows.reverse();
            }
        }
        AppSortCol::Expiry => rows.sort_by(|a, b| {
            cmp_missing_last(
                a.soonest_credential_expiry.as_ref(),
                b.soonest_credential_expiry.as_ref(),
                desc,
            )
        }),
        AppSortCol::Created => rows.sort_by(|a, b| {
            cmp_missing_last(
                a.created_date_time.as_ref(),
                b.created_date_time.as_ref(),
                desc,
            )
        }),
    }
}

/// One row's credential cell: the state badge plus the relative expiry beside
/// it.
///
/// Tones are the Credential-expiry dashboard's `status_badge` vocabulary
/// (`danger` / `warning` / `ok` / `unknown`), because a row and that dashboard
/// describe the same credential — two colour languages for one fact is how an
/// operator learns to trust neither.
struct CredentialMeta {
    label: &'static str,
    tone: &'static str,
    /// `"12d left"` / `"3 days ago"`. `None` when nothing on the app carries an
    /// end date, where the badge already says all there is to say.
    expiry: Option<String>,
    /// The expiry date itself, hovered on the relative phrase — a relative
    /// phrase alone is unciteable in a change ticket.
    exact: Option<String>,
}

fn credential_meta(
    status: ListCredentialStatus,
    soonest: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> CredentialMeta {
    let (label, tone) = match status {
        ListCredentialStatus::Active => ("Active", "ok"),
        ListCredentialStatus::Expiring => ("Expiring", "warning"),
        ListCredentialStatus::Expired => ("Expired", "danger"),
        ListCredentialStatus::None => ("No creds", "unknown"),
    };
    CredentialMeta {
        label,
        tone,
        expiry: soonest.map(|end| {
            if end <= now {
                // Already gone: `relative_time` is the app's one past-tense phrase.
                relative_time(now, end)
            } else {
                // Still to come, in the Credential-expiry dashboard's own words.
                format!("{}d left", (end - now).num_days())
            }
        }),
        exact: soonest.map(|end| end.date_naive().to_string()),
    }
}

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

    // Row order. `None` keeps the order Graph returned. Local rather than
    // lifted to `TenantScopedUi` for the same reason as `cred_filter`: nothing
    // outside this view seeds it, and it lives above `LoadedApps` so a Refresh
    // doesn't silently drop the operator back into Graph order.
    let sort: RwSignal<Option<(AppSortCol, bool)>> = RwSignal::new(None);

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
                    search_placeholder="Filter App Registrations by name or appId…"
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
                                                sort=sort
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
    /// Active `(column, descending)`, or `None` for the order Graph returned.
    sort: RwSignal<Option<(AppSortCol, bool)>>,
    export_rows: StoredValue<Arc<Vec<ApplicationListRowDto>>>,
) -> impl IntoView {
    let session = use_session();

    // `object_id -> display name` so a bulk failure names the app instead of
    // printing its GUID. Built once per fetch from the rows the selection is
    // made from; the bar falls back to the id for anything missing.
    let names: Signal<Arc<HashMap<String, String>>> = {
        let map: Arc<HashMap<String, String>> = Arc::new(
            items
                .iter()
                .map(|r| (r.id.clone(), r.display_name.clone()))
                .collect(),
        );
        // Publish for the standalone Bulk Actions page, which operates on this
        // same selection but owns no rows to build the map from — without it its
        // failure list is a column of raw GUIDs.
        session.tenant_ui.app_names.set(Arc::clone(&map));
        Signal::stored(map)
    };

    let list = use_filtered_list(FilteredListSpec {
        items,
        search,
        // Name OR appId — an appId is what a sign-in log, a ticket, and a
        // Conditional Access policy name an app by, and it is printed on every
        // row here. Same two fields the audit and credential searches match.
        search_match: |row: &ApplicationListRowDto, needle: &str| {
            contains_ignore_case(&row.display_name, needle)
                || contains_ignore_case(&row.app_id, needle)
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
        // The export snapshot is taken from `sorted` below instead, so what you
        // export matches what you see down to the row order.
        export_rows: None,
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

    // The sort sits BETWEEN the filtered set and the `VirtualList`: the scroller
    // is handed an already-ordered `Arc<Vec<_>>` exactly as it is handed the
    // filtered one, so virtualization never learns that sorting exists.
    let sorted: Memo<Arc<Vec<ApplicationListRowDto>>> = Memo::new(move |_| {
        let Some((col, desc)) = sort.get() else {
            // Unsorted: a pointer copy of the filtered set, not a row-by-row
            // clone of it (the same short-circuit `use_filtered_list` makes).
            return shown.get();
        };
        // One clone of the *filtered* set to own an order. `base` already clones
        // its matches whenever a search is active, so this adds a second pass
        // over a set that is usually much smaller than the tenant — and only
        // while a sort is actually held.
        let mut rows = shown.with(|s| s.as_ref().clone());
        sort_rows(&mut rows, col, desc);
        Arc::new(rows)
    });

    // "What you see is what you export", order included. `use_filtered_list` was
    // given no `export_rows`, so this is the snapshot's single writer.
    Effect::new(move |_| export_rows.set_value(sorted.get()));

    // Derived ONCE, outside the render closures: each is memoized, so a
    // keystroke updates the count text and the selection bar in place instead of
    // rebuilding the chip row and re-materializing every visible id.
    let visible_ids: Memo<Arc<Vec<String>>> = Memo::new(move |_| {
        Arc::new(shown.with(|items| items.iter().map(|r| r.id.clone()).collect()))
    });
    // `object_id -> display name` so a bulk failure names the app instead of
    // printing its GUID. Derived from the loaded rows the selection came from.
    let count_label = Signal::derive(move || {
        let shown_n = shown.with(|items| items.len());
        if shown_n == total {
            format!("{total} app registrations")
        } else {
            format!("{shown_n} of {total} app registrations")
        }
    });

    // Click a column: cycle default-direction → reverse → unsorted, so the
    // order Graph returned is always one more click away (the audit table's
    // contract).
    let toggle_sort = move |col: AppSortCol| {
        sort.update(|s| {
            *s = match *s {
                Some((c, desc)) if c == col => {
                    if desc == col.default_desc() {
                        Some((col, !desc))
                    } else {
                        None
                    }
                }
                _ => Some((col, col.default_desc())),
            };
        });
    };
    let sort_buttons = [AppSortCol::Name, AppSortCol::Expiry, AppSortCol::Created]
        .into_iter()
        .map(|col| {
            let active = move || sort.get().is_some_and(|(c, _)| c == col);
            view! {
                <button
                    type="button"
                    class=move || {
                        if active() {
                            "app-list__sort app-list__sort--active"
                        } else {
                            "app-list__sort"
                        }
                    }
                    // A *string*, never a bare `bool`: Leptos renders a bool as
                    // a boolean attribute, and neither `aria-pressed=""` nor an
                    // absent one is a valid ARIA value.
                    aria-pressed=move || active().to_string()
                    on:click=move |_| toggle_sort(col)
                >
                    {col.label()}
                    {move || match sort.get() {
                        Some((c, desc)) if c == col => {
                            if desc { " ↓" } else { " ↑" }
                        }
                        _ => "",
                    }}
                </button>
            }
        })
        .collect_view();

    view! {
        <Show when=move || filters_open.get()>
            <div class="filter-chips">
                <FilterChip label="All" value="any" count=base_total facet=cred_filter />
                <FilterChip label="Active" value="active" count=active facet=cred_filter />
                <FilterChip label="Expiring" value="expiring" count=expiring facet=cred_filter />
                <FilterChip label="Expired" value="expired" count=expired facet=cred_filter />
                <FilterChip label="No creds" value="none" count=none facet=cred_filter />
            </div>
        </Show>
        <SelectAllBar
            count_label=count_label
            visible_ids=visible_ids
            selected=session.tenant_ui.selected_app_ids
        />
        // Inline bulk-action bar — self-gating: appears once ≥1 app is checked
        // (and stays to show the run summary), so the user can grant consent /
        // remove expired creds / delete without leaving the list (the separate
        // Bulk Actions page remains for Create-apps).
        <BulkActionBar
            names=names
            selection=session.tenant_ui.selected_app_ids
            actions=Signal::derive(|| {
                vec![BulkAction::Grant, BulkAction::RemoveExpired, BulkAction::Delete]
            })
            on_done=Callback::new(move |_| session.bump_apps_reload())
        />
        {capped
            .then(|| {
                view! {
                    <Callout tone="warn" class="app-list__cap-notice">
                        {format!(
                            "Loaded the first {APPS_HARD_CAP} apps — search and filters apply within this set.",
                        )}
                    </Callout>
                }
            })}
        // Sits directly above the rows it reorders, outside the collapsed
        // filter drawer: a sort an operator cannot see is a sort they will not
        // use, and it is not a filter — it never changes the result count.
        // Suppressed only for a tenant with no apps at all, where the onboarding
        // empty state is the whole message; a filtered-empty list keeps it so
        // the chrome doesn't jump as the operator widens the search back out.
        {(total > 0)
            .then(|| {
                view! {
                    <div
                        class="app-list__sortbar"
                        role="group"
                        aria-label="Sort app registrations"
                    >
                        <span class="app-list__sortbar-label">"Sort"</span>
                        {sort_buttons}
                    </div>
                }
            })}
        <VirtualRows items=sorted total=total />
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
    // One clock for the whole window rather than one per row: the backend
    // classified `credential_status` at fetch time, so a row's relative expiry
    // is already a snapshot of that moment — re-reading the clock per row would
    // only let neighbouring rows disagree about "today".
    let now = Utc::now();
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
                row_selector=".app-list__row"
                key=|row: &ApplicationListRowDto| row.id.clone()
                render_row=move |idx, row| view_row(idx, row, session, now).into_any()
            />
        </Show>
    }
}

fn view_row(
    idx: usize,
    row: ApplicationListRowDto,
    session: crate::state::Session,
    now: DateTime<Utc>,
) -> impl IntoView {
    let paired_sp_id = row.paired_service_principal_id;
    // One shared allocation for the row id; the per-handler captures below are
    // refcount bumps instead of String clones.
    let id: Arc<str> = row.id.into();
    let id_class = Arc::clone(&id);
    let id_click = Arc::clone(&id);
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
    let app_id_string = row.app_id;
    // Descriptive per-row label for the bulk-select checkbox: the row's
    // display name plus its appId, so screen-reader users can tell rows apart
    // instead of hearing "Select for bulk actions" repeated.
    let check_label = format!("Select {display_name} ({app_id_string}) for bulk actions");

    // The credential state the list already filters on but never showed — so
    // "Expiring" narrowed the set without saying which credential expires when.
    let CredentialMeta {
        label: cred_label,
        tone: cred_tone,
        expiry: cred_expiry,
        exact: cred_exact,
    } = credential_meta(row.credential_status, row.soonest_credential_expiry, now);
    // Spelled out rather than left to the browser's name computation: the row
    // button's accessible name would otherwise be the concatenation of a type
    // chip, a truncated title, a badge and a monospace GUID.
    let row_label = match &cred_expiry {
        Some(expiry) => format!("{display_name} ({app_id_string}) — {cred_label}, {expiry}"),
        None => format!("{display_name} ({app_id_string}) — {cred_label}"),
    };

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
                aria-label=row_label
                on:click=move |_| {
                    session.open_item(OpenItemKind::AppReg, id_click.to_string(), name_click.clone());
                }
            >
                <span class="row-meta">
                    <TypeChip kind=AppKind::AppRegistration compact=true />
                    <span class="app-list__row-title" title=title_name>{display_name}</span>
                    <Badge label=cred_label tone=cred_tone />
                    {cred_expiry
                        .map(|expiry| {
                            view! {
                                <span class="app-list__row-expiry" title=cred_exact>
                                    {expiry}
                                </span>
                            }
                        })}
                </span>
                <span class="app-list__row-appid">{app_id_string}</span>
            </button>
            // A SIBLING of the row button, never nested inside it: nested
            // interactive content is invalid HTML, and Leptos builds the DOM
            // node-by-node so the parser never corrects it — the arrow's label
            // ended up spliced into the middle of the row's accessible name,
            // and Tab stopped on it between the name and the appId.
            {paired_sp_id
                .map(|sp_id| {
                    view! {
                        <button
                            class="pair-arrow"
                            type="button"
                            title="Jump to paired Enterprise Application"
                            aria-label="Jump to paired Enterprise Application"
                            on:click=move |_| jump_to_paired_enterprise(session, sp_id.clone())
                        >
                            "↔"
                        </button>
                    }
                })}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn at(days: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 2, 12, 0, 0).unwrap() + Duration::days(days)
    }

    fn row(name: &str, expiry: Option<i64>, created: Option<i64>) -> ApplicationListRowDto {
        ApplicationListRowDto {
            id: name.to_string(),
            app_id: format!("{name}-appid"),
            display_name: name.to_string(),
            sign_in_audience: None,
            publisher_domain: None,
            created_date_time: created.map(at),
            password_credential_count: 0,
            key_credential_count: 0,
            soonest_credential_expiry: expiry.map(at),
            credential_status: ListCredentialStatus::None,
            paired_service_principal_id: None,
        }
    }

    fn names(rows: &[ApplicationListRowDto]) -> Vec<&str> {
        rows.iter().map(|r| r.display_name.as_str()).collect()
    }

    #[test]
    fn name_sort_is_case_insensitive_in_both_directions() {
        let mut rows = vec![row("beta", None, None), row("Alpha", None, None)];
        sort_rows(&mut rows, AppSortCol::Name, false);
        assert_eq!(names(&rows), ["Alpha", "beta"]);
        sort_rows(&mut rows, AppSortCol::Name, true);
        assert_eq!(names(&rows), ["beta", "Alpha"]);
    }

    #[test]
    fn expiry_sort_puts_the_soonest_first_by_default() {
        let mut rows = vec![
            row("far", Some(90), None),
            row("soon", Some(3), None),
            row("gone", Some(-10), None),
        ];
        let desc = AppSortCol::Expiry.default_desc();
        sort_rows(&mut rows, AppSortCol::Expiry, desc);
        assert_eq!(names(&rows), ["gone", "soon", "far"]);
    }

    #[test]
    fn created_sort_puts_the_newest_first_by_default() {
        let mut rows = vec![row("old", None, Some(-400)), row("new", None, Some(-2))];
        let desc = AppSortCol::Created.default_desc();
        sort_rows(&mut rows, AppSortCol::Created, desc);
        assert_eq!(names(&rows), ["new", "old"]);
    }

    /// A row the column cannot rank belongs at the bottom whichever way the
    /// column points — heading the descending view with "no credentials" would
    /// bury the very rows the sort was reached for.
    #[test]
    fn a_missing_value_sorts_last_in_both_directions() {
        let mut rows = vec![
            row("none", None, None),
            row("far", Some(90), None),
            row("soon", Some(3), None),
        ];
        sort_rows(&mut rows, AppSortCol::Expiry, false);
        assert_eq!(names(&rows), ["soon", "far", "none"]);
        sort_rows(&mut rows, AppSortCol::Expiry, true);
        assert_eq!(names(&rows), ["far", "soon", "none"]);
    }

    #[test]
    fn credential_meta_reuses_the_dashboard_badge_vocabulary() {
        let tone = |s| credential_meta(s, None, at(0)).tone;
        assert_eq!(tone(ListCredentialStatus::Active), "ok");
        assert_eq!(tone(ListCredentialStatus::Expiring), "warning");
        assert_eq!(tone(ListCredentialStatus::Expired), "danger");
        assert_eq!(tone(ListCredentialStatus::None), "unknown");
    }

    #[test]
    fn credential_meta_reads_forward_to_an_expiry_and_back_from_a_lapse() {
        let now = at(0);
        let soon = credential_meta(ListCredentialStatus::Expiring, Some(at(12)), now);
        assert_eq!(soon.expiry.as_deref(), Some("12d left"));
        // The relative phrase is unciteable on its own, so the exact date rides
        // along as the hover title.
        assert_eq!(soon.exact.as_deref(), Some("2026-09-14"));

        let lapsed = credential_meta(ListCredentialStatus::Expired, Some(at(-3)), now);
        assert_eq!(lapsed.expiry.as_deref(), Some("3 days ago"));

        // Nothing with an end date: the badge alone carries the state.
        let bare = credential_meta(ListCredentialStatus::None, None, now);
        assert!(bare.expiry.is_none() && bare.exact.is_none());
    }
}
