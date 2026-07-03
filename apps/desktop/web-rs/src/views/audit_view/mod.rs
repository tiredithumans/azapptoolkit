//! Security audit — the findings-first workbench's data modules and the
//! "All apps" pane.
//!
//! The workbench shell ([`crate::views::security_view::SecurityView`]) owns
//! the run lifecycle via [`AuditController`] (posture strip: run / cancel /
//! export / progress / consent) and hosts two audit panes over the same scan:
//! [`FindingsPane`] (grouped by finding, remediation-centric — the default)
//! and [`AuditAppsPane`] (this file: the ranked per-app table for search /
//! score triage, filtered by ONE severity control).

mod controller;
mod filter;
mod findings;
mod groups;
pub mod posture;
mod row;
mod sort;

pub(crate) use controller::AuditController;
pub(crate) use findings::FindingsPane;

use azapptoolkit_core::audit::{AuditItem, AuditPrincipalKind, RiskLevel};
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::components::bulk_action_bar::{BulkAction, BulkActionBar};
use crate::components::select_all_bar::SelectAllBar;
use crate::components::ui::{SearchInput, TabBar, TabBarItem};
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_grid_keynav::use_grid_keynav;
use crate::state::use_session;

use filter::filter_indices;
use row::AuditRowActions;
use sort::SortCol;

/// The ranked per-app audit table. Reads the shared scan from the
/// [`AuditController`] context; its one filter dimension is the severity
/// TabBar (`Session.audit_severity`, so Home's Critical/High/Medium drills
/// seed it) intersected with the name/appId search. Finding-shaped filtering
/// and remediation grouping live in the Findings pane — this table's bulk bar
/// offers only the management set (Remove expired / Delete).
#[component]
pub fn AuditAppsPane() -> impl IntoView {
    let session = use_session();
    let ctrl = expect_context::<AuditController>();
    let result = ctrl.result;

    let severity = session.audit_severity;
    let selection = session.selected_audit_ids;
    let search = RwSignal::new(String::new());
    // Column sort: `None` keeps the backend's risk-ranked order. `Some((col,
    // desc))` sorts the filtered indices by that column.
    let sort: RwSignal<Option<(SortCol, bool)>> = RwSignal::new(None);

    let search_debounced = use_debounced(search.into(), LIST_FILTER_DEBOUNCE_MS);
    let total_items = ctrl.total_items;
    // Filter to row INDICES, not cloned items: a keystroke/facet click rescans
    // to a `Vec<usize>` (no `AuditItem` clones), and the renderer below clones
    // only the rows it actually draws.
    let filtered = Memo::new(move |_| {
        let sev = severity.get();
        let q = search_debounced.get().to_lowercase();
        let srt = sort.get();
        result.with(|r| {
            r.as_ref()
                .map(|r| {
                    let mut idx = filter_indices(&r.items, &sev, "all", &q);
                    if let Some((col, desc)) = srt {
                        // Stable sort over indices — reads the column value from
                        // the items by index, never cloning a row.
                        idx.sort_by(|&a, &b| {
                            let (ia, ib) = (&r.items[a], &r.items[b]);
                            let ord = match col {
                                SortCol::Name => ia
                                    .application_name
                                    .to_lowercase()
                                    .cmp(&ib.application_name.to_lowercase()),
                                SortCol::Score => ia.risk_score.cmp(&ib.risk_score),
                                SortCol::LastSignIn => ia.last_sign_in.cmp(&ib.last_sign_in),
                            };
                            if desc { ord.reverse() } else { ord }
                        });
                    }
                    idx
                })
                .unwrap_or_default()
        })
    });

    // Click a sortable header: cycle default-direction → reverse → unsorted.
    let toggle_sort = move |col: SortCol| {
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
    // Sort-direction glyph for a header (empty when that column isn't the sort).
    let sort_glyph = move |col: SortCol| -> &'static str {
        match sort.get() {
            Some((c, desc)) if c == col => {
                if desc {
                    " ↓"
                } else {
                    " ↑"
                }
            }
            _ => "",
        }
    };

    // Render window. This table is the one view guaranteed to hold every app
    // in the tenant; rendering all matched rows at once builds ~15 nodes ×
    // 10k rows = a multi-second main-thread stall. Draw the first page and grow
    // on demand, keeping the DOM bounded and the keyed table/keyboard-nav intact.
    let render_limit = RwSignal::new(RENDER_PAGE);
    // Reset the window to the first page whenever the filter changes or a new
    // scan lands a different item set. Tracks facet/search/total — an in-place
    // remediation changes none of those, so an expanded window survives a Fix.
    Effect::new(move |prev: Option<()>| {
        severity.track();
        search_debounced.track();
        total_items.track();
        sort.track();
        if prev.is_some() {
            render_limit.set(RENDER_PAGE);
        }
    });

    // Roving-tabindex keyboard navigation for the results table — Arrow/Home/End
    // move between rows and Enter activates the row's first button (its "Open"
    // deep-link), matching the lens tables (which get it via AuditDashboard).
    let tbody_ref: NodeRef<leptos::html::Tbody> = NodeRef::new();
    let on_grid_key = use_grid_keynav(tbody_ref, move || {
        // Reseed on the rendered row set: filter changes AND window growth
        // (Show more) both add/remove navigable rows.
        let _ = filtered.with(|f| f.len());
        let _ = render_limit.get();
    });

    view! {
        <div class="audit-apps-pane">
            // The ONE severity filter control (the old scorecard-as-filter and
            // finding-chip drawer are gone — findings live in their own pane).
            <TabBar
                selected=severity
                items=vec![
                    TabBarItem { value: "all", label: "All" },
                    TabBarItem { value: "critical", label: "Critical" },
                    TabBarItem { value: "high", label: "High" },
                    TabBarItem { value: "medium", label: "Medium" },
                    TabBarItem { value: "low", label: "Low" },
                ]
            />
            <SearchInput value=search placeholder="Filter by name or appId…" />
            {move || {
                if total_items.get().is_none() {
                    return view! { <Body1>"Run an audit to populate this view."</Body1> }
                        .into_any();
                }
                // The table shell renders once per scan; the count line and the
                // keyed <For> below react to filter changes on their own, so a
                // facet click or keystroke diffs rows by key instead of tearing
                // down the whole <tbody>.
                view! {
                    <div>
                        // Inline bulk-action bar — the management set only.
                        // Finding-paired fixes (scope/redundant/owner/disable)
                        // live on the Findings pane's per-group bars.
                        <BulkActionBar
                            selection=selection
                            actions=Signal::derive(|| vec![
                                BulkAction::RemoveExpired,
                                BulkAction::Delete,
                            ])
                            on_done=ctrl.on_bulk_done
                        />
                        // Tri-state select-all + result count. `visible_ids` is the
                        // object_ids of every row matching the active filters (not
                        // just the rendered window), so "select all visible" covers
                        // the whole filtered set. SP-only rows are excluded — the
                        // bulk commands loop app-registration cores, which have
                        // nothing to resolve for a principal without a local app.
                        {move || {
                            let (count_label, visible_ids) = filtered
                                .with(|idx| {
                                    let label = format!(
                                        "{} of {} apps match",
                                        idx.len(),
                                        total_items.get().unwrap_or(0),
                                    );
                                    let ids = result
                                        .with(|r| {
                                            r.as_ref()
                                                .map(|r| {
                                                    idx.iter()
                                                        .filter_map(|&i| r.items.get(i))
                                                        .filter(|it| {
                                                            it.principal_kind
                                                                == AuditPrincipalKind::Application
                                                        })
                                                        .map(|it| it.object_id.clone())
                                                        .collect::<Vec<_>>()
                                                })
                                                .unwrap_or_default()
                                        });
                                    (label, ids)
                                });
                            view! {
                                <SelectAllBar
                                    count_label=count_label
                                    visible_ids=visible_ids
                                    selected=selection
                                />
                            }
                        }}
                        {move || {
                            filtered
                                .with(|f| f.is_empty())
                                .then(|| {
                                    view! {
                                        <div class="alert">
                                            "No applications match this filter."
                                        </div>
                                    }
                                })
                        }}
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th class="data-table__check" aria-label="Select"></th>
                                    <th>
                                        <button
                                            class="th-sort"
                                            type="button"
                                            on:click=move |_| toggle_sort(SortCol::Name)
                                        >
                                            "Application"
                                            {move || sort_glyph(SortCol::Name)}
                                        </button>
                                    </th>
                                    <th>"AppId"</th>
                                    <th>
                                        <button
                                            class="th-sort"
                                            type="button"
                                            title="Sort by risk score"
                                            on:click=move |_| toggle_sort(SortCol::Score)
                                        >
                                            "Risk"
                                        </button>
                                    </th>
                                    <th>
                                        <button
                                            class="th-sort"
                                            type="button"
                                            on:click=move |_| toggle_sort(SortCol::Score)
                                        >
                                            "Score"
                                            {move || sort_glyph(SortCol::Score)}
                                        </button>
                                    </th>
                                    <th>"Status"</th>
                                    <th>
                                        <button
                                            class="th-sort"
                                            type="button"
                                            on:click=move |_| toggle_sort(SortCol::LastSignIn)
                                        >
                                            "Last sign-in"
                                            {move || sort_glyph(SortCol::LastSignIn)}
                                        </button>
                                    </th>
                                    <th>"Issues"</th>
                                    <th>"Actions"</th>
                                </tr>
                            </thead>
                            <tbody node_ref=tbody_ref on:keydown=on_grid_key.clone()>
                                // Window over filtered INDICES: clone only the
                                // rows actually drawn (the first `render_limit`
                                // matches), not the whole matched set. Key carries
                                // the remediation count so a keyed row re-renders
                                // only when its key changes — the one in-place
                                // mutation this view performs is `on_remediated`
                                // clearing an item's remediations (Fix must vanish).
                                <For
                                    each=move || {
                                        let limit = render_limit.get();
                                        filtered.with(|idx| {
                                            result
                                                .with(|r| {
                                                    r.as_ref()
                                                        .map(|r| {
                                                            idx.iter()
                                                                .take(limit)
                                                                .filter_map(|&i| {
                                                                    r.items.get(i).map(|it| (i, it.clone()))
                                                                })
                                                                .collect::<Vec<_>>()
                                                        })
                                                        .unwrap_or_default()
                                                })
                                        })
                                    }
                                    key=|(_, i)| (i.object_id.clone(), i.remediations.len())
                                    children=move |(_, i)| {
                                        let oid = i.object_id.clone();
                                        let oid_change = oid.clone();
                                        let check_label = format!(
                                            "Select {} for bulk actions",
                                            i.application_name,
                                        );
                                        // SP-only rows can't join the bulk selection (the
                                        // bulk commands target app registrations) and have
                                        // no local credentials to report a status for.
                                        let is_app_reg = i.principal_kind
                                            == AuditPrincipalKind::Application;
                                        view! {
                                            <tr>
                                                <td class="data-table__check">
                                                    {if is_app_reg {
                                                        view! {
                                                            <input
                                                                type="checkbox"
                                                                aria-label=check_label
                                                                prop:checked=move || session.is_audit_selected(&oid)
                                                                on:change=move |_| {
                                                                    session.toggle_audit_selected(oid_change.clone())
                                                                }
                                                            />
                                                        }
                                                            .into_any()
                                                    } else {
                                                        view! {
                                                            <span
                                                                class="muted"
                                                                title="Bulk actions target app registrations — this principal has no local one"
                                                            >
                                                                "—"
                                                            </span>
                                                        }
                                                            .into_any()
                                                    }}
                                                </td>
                                                <td>{i.application_name.clone()}</td>
                                                <td class="mono">{i.app_id.clone()}</td>
                                                <td>
                                                    <span class=format!(
                                                        "badge {}",
                                                        risk_class(&i.risk_level),
                                                    )>{i.risk_level.as_str()}</span>
                                                </td>
                                                <td>{i.risk_score}</td>
                                                <td>
                                                    {if is_app_reg {
                                                        view! { {i.credential_status.as_str()} }.into_any()
                                                    } else {
                                                        view! {
                                                            <span
                                                                class="muted"
                                                                title="Credentials live on the application in its home tenant"
                                                            >
                                                                "—"
                                                            </span>
                                                        }
                                                            .into_any()
                                                    }}
                                                </td>
                                                <td>{last_sign_in_cell(&i)}</td>
                                                <td>
                                                    <ul class="issues">
                                                        {i.issues
                                                            .iter()
                                                            .take(ISSUES_INLINE)
                                                            .map(|issue| view! { <li>{issue.clone()}</li> })
                                                            .collect_view()}
                                                        {(i.issues.len() > ISSUES_INLINE)
                                                            .then(|| {
                                                                let more = i.issues.len() - ISSUES_INLINE;
                                                                view! {
                                                                    <li class="issues__more">
                                                                        {format!("+{more} more — open to see all")}
                                                                    </li>
                                                                }
                                                            })}
                                                    </ul>
                                                </td>
                                                <td>
                                                    <AuditRowActions item=i.clone() on_done=ctrl.on_remediated />
                                                </td>
                                            </tr>
                                        }
                                    }
                                />
                            </tbody>
                        </table>
                        // "Show more" grows the render window a page at a time.
                        // Shown only when matches exceed what's drawn.
                        {move || {
                            let matched = filtered.with(|f| f.len());
                            let limit = render_limit.get();
                            (matched > limit)
                                .then(|| {
                                    let remaining = matched - limit;
                                    let next = RENDER_PAGE.min(remaining);
                                    view! {
                                        <div class="audit-show-more">
                                            <Body1>
                                                {format!("Showing {limit} of {matched} matching rows")}
                                            </Body1>
                                            <Button
                                                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                                on_click=Box::new(move |_| {
                                                    render_limit.update(|n| *n += RENDER_PAGE)
                                                })
                                            >
                                                {format!("Show {next} more")}
                                            </Button>
                                        </div>
                                    }
                                })
                        }}
                    </div>
                }
                    .into_any()
            }}
        </div>
    }
}

fn risk_class(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "badge--critical",
        RiskLevel::High => "badge--danger",
        RiskLevel::Medium => "badge--warning",
        RiskLevel::Low => "badge--ok",
    }
}

/// "Last sign-in" cell. Distinguishes never-signed-in from an unavailable report
/// (no `AuditLog.Read.All` / no Entra ID P1-P2) so an empty value isn't read as
/// "never used".
fn last_sign_in_cell(i: &AuditItem) -> AnyView {
    if !i.sign_in_report_available {
        return view! { <span class="muted" title="Sign-in report unavailable">"—"</span> }
            .into_any();
    }
    match i.last_sign_in {
        Some(dt) => view! { <span>{dt.format("%Y-%m-%d").to_string()}</span> }.into_any(),
        None => view! { <span class="muted">"Never"</span> }.into_any(),
    }
}
