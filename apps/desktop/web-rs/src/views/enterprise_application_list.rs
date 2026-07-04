//! Virtualized list of Enterprise Application service principals — every SP
//! in the tenant that is **not** a managed identity. Mirrors the App
//! Registration list's pattern: search + virtualized rows, with a type chip,
//! foreign-tenant pill, and pairing arrow per row. Filtering runs through the
//! shared [`use_filtered_list`] memos over the loaded rows, so a keystroke or
//! chip click never rebuilds the loaded subtree. The chrome (header, search,
//! filter drawer) is the shared [`ListScaffold`].

use std::sync::Arc;

use chrono::NaiveDate;
use leptos::ev;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::diagnostics::{self, ListCacheKindDto};
use crate::bindings::enterprise_application::{self, EnterpriseApplicationDto};
use crate::components::date_range_filter::DateRangeFilter;
use crate::components::filter_chip::FilterChip;
use crate::components::icon::{Icon, IconName};
use crate::components::list_scaffold::ListScaffold;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{DetailLoadError, EmptyState, IconButton, SectionHeader, SkeletonList};
use crate::components::virtual_list::VirtualList;
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_filtered_list::{Facet, FilteredListSpec, use_filtered_list};
use crate::hooks::use_list_export::use_list_export;
use crate::state::{OpenItemKind, use_session};
use crate::util::created_in_range;
use crate::views::pairing::jump_to_paired_app;

#[component]
pub fn EnterpriseApplicationList() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // "Filter this list" query, lifted to the session so the top-bar Global
    // Search can seed it (picking an Enterprise Application there lands the user
    // here with the list pre-filtered to that name).
    let raw_search = session.tenant_ui.enterprise_search;
    let search = use_debounced(raw_search.into(), LIST_FILTER_DEBOUNCE_MS);

    // Facet over the loaded page (all | enabled | disabled | foreign), lifted to
    // the session (like the search above) so the Home dashboard's Enterprise
    // metrics can seed it. Credential status is the App Registration lens, not
    // the enterprise-app lens, so it's not offered here.
    let ent_filter = session.tenant_ui.enterprise_facet;
    // Unset date picker (None) leaves that side of the creation-date range open;
    // together they bound creation date to an inclusive window.
    let created_after: RwSignal<Option<NaiveDate>> = RwSignal::new(None);
    let created_before: RwSignal<Option<NaiveDate>> = RwSignal::new(None);

    // Collapsible advanced-filter drawer (saved views + created-on range + facet
    // chips); search stays outside it. Default collapsed to reclaim list space,
    // with the active-filter count badged on the toggle.
    let filters_open = RwSignal::new(false);
    // A Home dashboard drill (open_enterprise_with_facet) lands here pre-filtered
    // but with the drawer collapsed, hiding the active facet chip. Consume the
    // one-shot flag to expand the drawer once so the chip is visible (this is the
    // sole consumer, so no view-guard is needed).
    Effect::new(move |_| {
        if session.tenant_ui.pending_open_filters.get() {
            filters_open.set(true);
            session.tenant_ui.pending_open_filters.set(false);
        }
    });
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
    // export so "what you see is what you export". Kept in step by the
    // `use_filtered_list` export hook; the `Arc` makes each snapshot a pointer
    // copy.
    let (export_rows, exporting, do_export) = use_list_export(
        |rows: Arc<Vec<EnterpriseApplicationDto>>, format| async move {
            enterprise_application::save_enterprise_applications_to_file(&rows, format).await
        },
        "enterprise applications",
    );

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
        <div class="apps-view">
            <SectionHeader
                title="Enterprise Applications".to_string()
                crumb="Inventory".to_string()
            >
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
                <Button
                    class="btn-icon-label"
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| session.tenant_ui.sso_wizard_open.set(true))
                >
                    <Icon name=IconName::Plus size=16 />
                    "New SSO application"
                </Button>
            </SectionHeader>
            <div class="apps-view__body">
                <ListScaffold
                    search=raw_search
                    search_placeholder="Filter Enterprise Apps…"
                    saved_view_key="enterprise"
                    facet=ent_filter
                    filters_open=filters_open
                    active_filters=active_filters
                    drawer=move || {
                        view! {
                            <DateRangeFilter
                                after=created_after
                                before=created_before
                                noun="enterprise applications"
                            />
                        }
                    }
                >
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
                                        // Transient (429 / network) loads get an in-context
                                        // Retry through the shared load-failure primitive —
                                        // parity with the detail panes and dashboard cards.
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

/// The loaded-list body: the shared filter memos feeding the facet chips, the
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
    let list = use_filtered_list(FilteredListSpec {
        items,
        search,
        search_match: |sp: &EnterpriseApplicationDto, needle: &str| {
            sp.display_name.to_lowercase().contains(needle)
        },
        extra_active: Signal::derive(move || {
            created_after.get().is_some() || created_before.get().is_some()
        }),
        extra: move |sp: &EnterpriseApplicationDto| {
            created_in_range(
                sp.created_date_time,
                created_after.get(),
                created_before.get(),
            )
        },
        facet: ent_filter,
        facet_any: "all",
        // No assignment-required facet: the shared SP list index doesn't
        // `$select` `appRoleAssignmentRequired`, so it's only known on the
        // detail pane.
        facets: vec![
            Facet::new("Enabled", "enabled", |sp: &EnterpriseApplicationDto| {
                sp.account_enabled == Some(true)
            }),
            Facet::new("Disabled", "disabled", |sp: &EnterpriseApplicationDto| {
                sp.account_enabled == Some(false)
            }),
            Facet::new("Foreign", "foreign", |sp: &EnterpriseApplicationDto| {
                sp.is_foreign_tenant
            }),
        ],
        export_rows: Some(export_rows),
    });

    let total = list.total;
    let shown = list.shown;
    let base_total = list.base_total();
    let enabled = list.count_of("enabled");
    let disabled = list.count_of("disabled");
    let foreign = list.count_of("foreign");
    let shown_total = list.shown_total();

    // No bulk-selection bar: there is no SP-targeted bulk operation (the bulk
    // dialog acts on app registrations), so the list shows only the result
    // count, not a select-all / Bulk-actions control that would act on nothing.
    view! {
        <Show when=move || filters_open.get()>
            {move || {
                view! {
                    <div class="filter-chips">
                        <FilterChip
                            label="All"
                            value="all"
                            count=base_total.get()
                            facet=ent_filter
                        />
                        <FilterChip
                            label="Enabled"
                            value="enabled"
                            count=enabled.get()
                            facet=ent_filter
                        />
                        <FilterChip
                            label="Disabled"
                            value="disabled"
                            count=disabled.get()
                            facet=ent_filter
                        />
                        <FilterChip
                            label="Foreign"
                            value="foreign"
                            count=foreign.get()
                            facet=ent_filter
                        />
                    </div>
                }
            }}
        </Show>
        {move || {
            let shown_n = shown_total.get();
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
        <VirtualRows items=shown total=total />
    }
}

/// Reactive wrapper around the shared `VirtualList`: the empty state when
/// every row is filtered out, otherwise the keyed virtualized window.
#[component]
fn VirtualRows(
    items: Memo<Arc<Vec<EnterpriseApplicationDto>>>,
    // Pre-filter tenant count: 0 ⇒ no enterprise apps at all (onboarding CTA)
    // rather than a filtered-empty list ("broaden your search").
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
                            icon=IconName::Building
                            title="No enterprise applications yet".to_string()
                            body="Add one from the gallery in the portal, or start a new SSO application here."
                                .to_string()
                        >
                            <Button
                                class="btn-icon-label"
                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                on_click=Box::new(move |_| session.tenant_ui.sso_wizard_open.set(true))
                            >
                                <Icon name=IconName::Plus size=16 />
                                "New SSO application"
                            </Button>
                        </EmptyState>
                    }
                        .into_any()
                } else {
                    view! {
                        <EmptyState
                            icon=IconName::Search
                            title="No matching enterprise applications".to_string()
                            body="Try a broader search term or clear the filters.".to_string()
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
    // Highlight every row open in the workspace (the working set). Class name
    // stays `--selected` so `pairing.rs`'s scroll-settle selector keeps matching.
    let row_class = move || {
        let mut c = String::from("app-list__row");
        if session.is_open(OpenItemKind::Enterprise, &id).is_some() {
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
    // Owned name copies for the open handlers (the open chip's label).
    let name_click = display_name.clone();
    let name_key = display_name.clone();
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
                    session.open_item(OpenItemKind::Enterprise, id_click.to_string(), name_click.clone());
                }
                on:keydown=move |ev: ev::KeyboardEvent| {
                    if ev.key() == "Enter" {
                        session.open_item(OpenItemKind::Enterprise, id_key.to_string(), name_key.clone());
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
