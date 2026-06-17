//! Security audit dashboard.
//! CSV export goes through the OS save dialog (backend `tauri-plugin-dialog`)
//! rather than the React-side `Blob`/`URL.createObjectURL` path.

use crate::hooks::use_progress_stream::use_progress_stream;
use azapptoolkit_core::audit::{issue, AuditItem, RemediationAction, RemediationKind, RiskLevel};
use leptos::prelude::*;
use thaw::{
    Body1, Button, ButtonAppearance, Menu, MenuItem, MenuPosition, MenuTrigger, ProgressBar,
    Spinner, SpinnerSize, Tab, TabList,
};

use crate::bindings::audit::{self, AuditProgress, AuditRunResult};
use crate::bindings::events;
use crate::bindings::{auth, remediation};
use crate::components::saved_views::SavedViews;
use crate::components::ui::{SearchInput, SectionHeader};
use crate::hooks::use_debounced::{use_debounced, LIST_FILTER_DEBOUNCE_MS};
use crate::hooks::use_grid_keynav::use_grid_keynav;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::dialogs::scope_remediation::{ScopeMailboxButton, ScopeSharePointButton};

/// How many audit rows to draw per render page. The table windows to this many
/// at a time with a "Show more" control, so a 10k-app tenant's DOM stays bounded
/// instead of materializing every matched row at once.
const RENDER_PAGE: usize = 200;

/// How many of a row's issues to show inline before collapsing the rest to a
/// "+N more" hint (the full list lives in the detail pane the row deep-links to).
const ISSUES_INLINE: usize = 2;

/// A sortable audit-table column. The backend's original order (risk-ranked) is
/// the unsorted default; clicking a header cycles default-direction → reverse →
/// back to unsorted so that default order is always recoverable.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SortCol {
    Name,
    Score,
    LastSignIn,
}

impl SortCol {
    /// First-click direction: highest score / most-recent sign-in first (the
    /// triage need), names A→Z.
    fn default_desc(self) -> bool {
        !matches!(self, SortCol::Name)
    }
}

#[component]
pub fn AuditView() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let result: RwSignal<Option<AuditRunResult>> = RwSignal::new(None);
    // When a row's remediation succeeds, drop that item's remediations so the
    // "Fix" button is gone for good (the audit cache is already busted
    // server-side; scores refresh on the next manual re-run).
    let on_remediated = Callback::new(move |object_id: String| {
        result.update(|opt| {
            if let Some(r) = opt.as_mut() {
                if let Some(item) = r.items.iter_mut().find(|i| i.object_id == object_id) {
                    item.remediations.clear();
                }
            }
        });
    });
    let scanning = RwSignal::new(false);
    let progress: RwSignal<Option<AuditProgress>> = RwSignal::new(None);
    let scan_error: RwSignal<Option<String>> = RwSignal::new(None);
    let facet = RwSignal::new(String::from("all"));
    let search = RwSignal::new(String::new());
    // Column sort: `None` keeps the backend's risk-ranked order. `Some((col,
    // desc))` sorts the filtered indices by that column.
    let sort: RwSignal<Option<(SortCol, bool)>> = RwSignal::new(None);
    let exporting = RwSignal::new(false);
    let export_msg: RwSignal<Option<String>> = RwSignal::new(None);

    // Derived views of the result, computed with `.with()` so the multi-MB
    // `AuditRunResult` is never cloned wholesale — previously every keystroke
    // deep-cloned it for the table, and the posture/consent closures cloned it
    // again for a handful of integers.
    let search_debounced = use_debounced(search.into(), LIST_FILTER_DEBOUNCE_MS);
    let posture_counts = Memo::new(move |_| {
        result.with(|r| {
            r.as_ref().map(|r| {
                let items = &r.items;
                (
                    count_level(items, RiskLevel::Critical),
                    count_level(items, RiskLevel::High),
                    count_expiring(items),
                    items.iter().filter(|i| i.unused).count(),
                    count_issue_prefix(items, issue::ORG_WIDE_MAILBOX),
                    count_issue_prefix(items, issue::ORG_WIDE_SHAREPOINT),
                )
            })
        })
    });
    let consent_needed =
        Memo::new(move |_| result.with(|r| r.as_ref().is_some_and(|r| r.sign_in_consent_required)));
    let total_items = Memo::new(move |_| result.with(|r| r.as_ref().map(|r| r.items.len())));
    let report_available =
        Memo::new(move |_| result.with(|r| r.as_ref().is_some_and(|r| r.sign_in_report_available)));
    // Filter to row INDICES, not cloned items: a keystroke/facet click rescans
    // to a `Vec<usize>` (no `AuditItem` clones), and the renderer below clones
    // only the rows it actually draws. Previously this memo deep-cloned every
    // matching item, and the `<For>` cloned the whole `Vec` again — twice the
    // multi-MB set per keystroke on a large tenant.
    let filtered = Memo::new(move |_| {
        let f = facet.get();
        let q = search_debounced.get().to_lowercase();
        let srt = sort.get();
        result.with(|r| {
            r.as_ref()
                .map(|r| {
                    let mut idx = filter_indices(&r.items, &f, &q);
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
                            if desc {
                                ord.reverse()
                            } else {
                                ord
                            }
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

    // Render window. The audit table is the one view guaranteed to hold every
    // app in the tenant; rendering all matched rows at once builds ~15 nodes ×
    // 10k rows = a multi-second main-thread stall. Draw the first page and grow
    // on demand, keeping the DOM bounded and the keyed table/keyboard-nav intact.
    let render_limit = RwSignal::new(RENDER_PAGE);
    // Reset the window to the first page whenever the filter changes or a new
    // scan lands a different item set. Tracks facet/search/total — an in-place
    // remediation changes none of those, so an expanded window survives a Fix.
    Effect::new(move |prev: Option<()>| {
        facet.track();
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
    // Reseeded whenever the filtered row set changes (covers facet, search, and
    // scan-result changes).
    let tbody_ref: NodeRef<leptos::html::Tbody> = NodeRef::new();
    let on_grid_key = use_grid_keynav(tbody_ref, move || {
        // Reseed on the rendered row set: filter changes AND window growth
        // (Show more) both add/remove navigable rows.
        let _ = filtered.with(|f| f.len());
        let _ = render_limit.get();
    });

    // Subscribe to audit-progress events for this view's lifetime, and abort
    // the stream task on unmount so it doesn't leak or race a remount's task.
    use_progress_stream(progress, events::audit_progress);

    // Hydrate from cache when tenant changes. Clear stale state synchronously so
    // the previous tenant's table never lingers, then guard the async write
    // against a tenant-changed race: if the user switches tenants (or two cache
    // loads resolve out of order) while `get_cached_audit` is in flight, drop
    // the late result instead of clobbering the now-active tenant's view.
    Effect::new(move |_| {
        let t = tenant.get();
        // Reset transient per-tenant state up front (tracked read above, plain
        // writes here — Effect re-runs only on `tenant` changing).
        result.set(None);
        scan_error.set(None);
        progress.set(None);
        let Some(t) = t else { return };
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            let cached = audit::get_cached_audit(&tenant_id).await;
            // Only apply if this tenant is still the active one.
            let still_active = tenant
                .get_untracked()
                .map(|t| t.tenant_id == tenant_id)
                .unwrap_or(false);
            if still_active {
                result.set(cached);
            }
        });
    });

    // Zero-arg so it drives both the "Run audit" button and the post-consent
    // re-run (after enabling the sign-in report) without the event arg leaking.
    let do_run = move || {
        if scanning.get() {
            return;
        }
        scanning.set(true);
        scan_error.set(None);
        progress.set(Some(AuditProgress {
            done: 0,
            total: 0,
            current_app: None,
            in_flight_cap: 8,
            cancelled: false,
        }));
        let t = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = t else {
                scanning.set(false);
                return;
            };
            match audit::run_audit(&t.tenant_id).await {
                Ok(r) => {
                    result.set(Some(r));
                    // Refresh the Home dashboard's "Security Posture" tile: it
                    // keeps its cached-audit resource alive across view switches
                    // (keep-alive panes), so it only refetches when this bumps.
                    session.bump_audit_reload();
                }
                Err(e) => scan_error.set(Some(e.message)),
            }
            scanning.set(false);
            progress.set(None);
        });
    };

    // Grants AuditLog.Read.All (the sign-in activity report behind the Unused
    // tab), then re-runs the audit so unused apps populate.
    let grant_reports_consent = move |_| {
        if scanning.get() {
            return;
        }
        let Some(t) = tenant.get() else { return };
        scan_error.set(None);
        leptos::task::spawn_local(async move {
            match auth::request_scope_consent(&t.tenant_id, "audit_log").await {
                Ok(()) => do_run(),
                Err(e) => scan_error.set(Some(e.message)),
            }
        });
    };

    let cancel = move |_| {
        leptos::task::spawn_local(async move {
            audit::cancel_audit().await;
        });
    };

    let export = move |format: &'static str| {
        if exporting.get() {
            return;
        }
        let Some(t) = tenant.get() else { return };
        // Export by reference: the backend serves its own cached run, so the
        // item vector doesn't round-trip the IPC bridge. Only a CANCELLED run
        // (never cached backend-side) ships its items along.
        let (empty, cancelled_items) = result.with(|r| match r.as_ref() {
            Some(r) => (r.items.is_empty(), r.cancelled.then(|| r.items.clone())),
            None => (true, None),
        });
        if empty {
            return;
        }
        exporting.set(true);
        export_msg.set(None);
        leptos::task::spawn_local(async move {
            match audit::save_audit_to_file(&t.tenant_id, cancelled_items.as_deref(), format).await
            {
                Ok(Some(path)) => export_msg.set(Some(format!("Saved to {path}"))),
                Ok(None) => {} // user cancelled
                Err(e) => export_msg.set(Some(format!("Export failed: {}", e.message))),
            }
            exporting.set(false);
        });
    };

    view! {
        <main class="audit-view">
            <SectionHeader title="Security audit".to_string() crumb="Tenant health".to_string()>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| do_run())
                    disabled=Signal::derive(move || scanning.get())
                >
                    {move || {
                        if scanning.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                .into_any()
                        } else {
                            view! { "Run audit" }.into_any()
                        }
                    }}
                </Button>
                <Show when=move || scanning.get() fallback=|| view! { <></> }>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(cancel)
                    >
                        "Cancel"
                    </Button>
                </Show>
                <Menu
                    position=MenuPosition::BottomEnd
                    on_select=move |fmt: String| {
                        match fmt.as_str() {
                            "csv" => export("csv"),
                            "json" => export("json"),
                            "html" => export("html"),
                            _ => {}
                        }
                    }
                >
                    <MenuTrigger slot>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                            disabled=Signal::derive(move || {
                                exporting.get() || result.with(|r| r.is_none())
                            })
                        >
                            "Export ▾"
                        </Button>
                    </MenuTrigger>
                    <MenuItem value="csv".to_string()>"Export as CSV…"</MenuItem>
                    <MenuItem value="json".to_string()>"Export as JSON…"</MenuItem>
                    <MenuItem value="html".to_string()>"Export as HTML…"</MenuItem>
                </Menu>
            </SectionHeader>
            {move || {
                progress
                    .get()
                    .map(|p| {
                        let pct = if p.total > 0 {
                            (p.done as f64) / (p.total as f64)
                        } else {
                            0.0
                        };
                        view! {
                            <div class="audit-progress">
                                <ProgressBar value=Signal::derive(move || pct) />
                                <Body1>
                                    {format!(
                                        "{} / {} apps  (cap: {}{})",
                                        p.done,
                                        p.total,
                                        p.in_flight_cap,
                                        if p.cancelled { ", cancelled" } else { "" },
                                    )}
                                </Body1>
                                {p.current_app.map(|n| view! { <Body1>{n}</Body1> })}
                            </div>
                        }
                    })
            }}
            {move || {
                scan_error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
            }}
            {move || {
                export_msg.get().map(|m| view! { <div class="alert alert--ok">{m}</div> })
            }}
            <TabList selected_value=facet>
                <Tab value="all">"All"</Tab>
                <Tab value="critical">"Critical"</Tab>
                <Tab value="high">"High"</Tab>
                <Tab value="medium">"Medium"</Tab>
                <Tab value="low">"Low"</Tab>
                <Tab value="expiring">"Expiring/Expired"</Tab>
                <Tab value="high_risk_perms">"High-risk app"</Tab>
                <Tab value="high_risk_delegated">"High-risk delegated"</Tab>
                <Tab value="orgwide_mailbox">"Org-wide mailbox"</Tab>
                <Tab value="scoped_mailbox">"Scoped mailbox"</Tab>
                <Tab value="orgwide_sharepoint">"Org-wide SharePoint"</Tab>
                <Tab value="scoped_sites">"Scoped sites"</Tab>
                <Tab value="ownership">"Ownership"</Tab>
                <Tab value="unused">"Unused"</Tab>
            </TabList>
            <SearchInput value=search placeholder="Filter by name or appId…" />
            <SavedViews view_key="audit" facet=facet search=search />
            // Posture cards — clickable summary counts that jump to the matching
            // facet. Shown once an audit has populated `result`.
            {move || {
                posture_counts
                    .get()
                    .map(|(crit, high, expiring, unused, owm, ows)| {
                        view! {
                            <div class="dash-metrics audit-cards">
                                {posture_card("Critical", crit, "danger", "critical", facet)}
                                {posture_card("High", high, "danger", "high", facet)}
                                {posture_card("Expiring", expiring, "warning", "expiring", facet)}
                                {posture_card("Unused", unused, "warning", "unused", facet)}
                                {posture_card(
                                    "Org-wide mailbox",
                                    owm,
                                    "warning",
                                    "orgwide_mailbox",
                                    facet,
                                )}
                                {posture_card(
                                    "Org-wide SharePoint",
                                    ows,
                                    "warning",
                                    "orgwide_sharepoint",
                                    facet,
                                )}
                            </div>
                        }
                    })
            }}
            // AuditLog.Read.All consent prompt — the sign-in activity report
            // (behind the Unused tab) needs it. Offered when the last run found it
            // un-consented; granting re-runs the audit.
            {move || {
                consent_needed
                    .get()
                    .then(|| {
                        view! {
                            <div class="alert alert--warn">
                                "Unused-app detection needs the AuditLog.Read.All permission (it reads each app's last sign-in). Grant consent to enable it — requires a Global Reader / Security Reader / Reports Reader role and Entra ID P1 or P2."
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(grant_reports_consent)
                                        disabled=Signal::derive(move || scanning.get())
                                    >
                                        "Grant consent & re-run"
                                    </Button>
                                </div>
                            </div>
                        }
                    })
            }}
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
                        <Body1>
                            {move || {
                                format!(
                                    "{} of {} apps match",
                                    filtered.with(|f| f.len()),
                                    total_items.get().unwrap_or(0),
                                )
                            }}
                        </Body1>
                        {move || {
                            filtered
                                .with(|f| f.is_empty())
                                .then(|| {
                                    let msg = empty_facet_message(
                                        &facet.get(),
                                        report_available.get(),
                                    );
                                    view! { <div class="alert">{msg}</div> }
                                })
                        }}
                        <table class="data-table">
                            <thead>
                                <tr>
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
                                        view! {
                                            <tr>
                                                <td>{i.application_name.clone()}</td>
                                                <td class="mono">{i.app_id.clone()}</td>
                                                <td>
                                                    <span class=format!(
                                                        "badge {}",
                                                        risk_class(&i.risk_level),
                                                    )>{i.risk_level.as_str()}</span>
                                                </td>
                                                <td>{i.risk_score}</td>
                                                <td>{i.credential_status.as_str()}</td>
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
                                                    <AuditRowActions item=i.clone() on_done=on_remediated />
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
        </main>
    }
}

/// The audit table's filter, as a pure function over the item set: returns the
/// indices (in original order) of items matching both the facet and the
/// already-lowercased name/appId query. Extracted so the facet × search
/// interplay is pinned by tests, and so the perf rewrite can window over these
/// indices and clone only the rows it renders — instead of deep-cloning the
/// whole multi-MB matching set on every keystroke. `query_lower` must already
/// be lowercased (the caller lowercases once); an empty query matches all.
fn filter_indices(items: &[AuditItem], facet: &str, query_lower: &str) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter(|(_, i)| matches_facet(i, facet))
        .filter(|(_, i)| {
            query_lower.is_empty()
                || i.application_name.to_lowercase().contains(query_lower)
                || i.app_id.to_lowercase().contains(query_lower)
        })
        .map(|(idx, _)| idx)
        .collect()
}

fn matches_facet(i: &AuditItem, facet: &str) -> bool {
    match facet {
        "all" => true,
        "critical" => matches!(i.risk_level, RiskLevel::Critical),
        "high" => matches!(i.risk_level, RiskLevel::High),
        "medium" => matches!(i.risk_level, RiskLevel::Medium),
        "low" => matches!(i.risk_level, RiskLevel::Low),
        "expiring" => {
            use azapptoolkit_core::audit::CredentialStatus;
            matches!(
                i.credential_status,
                CredentialStatus::ExpiringSoon | CredentialStatus::Expired
            )
        }
        "high_risk_perms" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::HIGH_RISK_APP_PERMS)),
        "high_risk_delegated" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::HIGH_RISK_DELEGATED_PERMS)),
        // Effective mailbox scoping facets. Scoping is resolved on every run, but
        // degrades to org-wide when the signed-in user lacks Exchange-admin rights.
        "orgwide_mailbox" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::ORG_WIDE_MAILBOX)),
        "scoped_mailbox" => i.issues.iter().any(|x| x.contains(issue::SCOPED_VIA_RBAC)),
        "orgwide_sharepoint" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::ORG_WIDE_SHAREPOINT)),
        "scoped_sites" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::SCOPED_SHAREPOINT)),
        "ownership" => i
            .issues
            .iter()
            .any(|x| x.starts_with(issue::NO_OWNERS) || x.starts_with(issue::SINGLE_OWNER)),
        // Structured flag set by the audit runner from the sign-in activity
        // report — no longer parsed from the issue text.
        "unused" => i.unused,
        _ => true,
    }
}

fn risk_class(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical => "badge--danger",
        RiskLevel::High => "badge--danger",
        RiskLevel::Medium => "badge--warning",
        RiskLevel::Low => "badge--ok",
    }
}

fn count_level(items: &[AuditItem], level: RiskLevel) -> usize {
    items.iter().filter(|i| i.risk_level == level).count()
}

fn count_expiring(items: &[AuditItem]) -> usize {
    use azapptoolkit_core::audit::CredentialStatus;
    items
        .iter()
        .filter(|i| {
            matches!(
                i.credential_status,
                CredentialStatus::ExpiringSoon | CredentialStatus::Expired
            )
        })
        .count()
}

fn count_issue_prefix(items: &[AuditItem], prefix: &str) -> usize {
    items
        .iter()
        .filter(|i| i.issues.iter().any(|x| x.starts_with(prefix)))
        .count()
}

/// One clickable posture card. Zero counts render muted; non-zero use the tone
/// colour. Clicking jumps the table to the matching facet.
fn posture_card(
    label: &'static str,
    n: usize,
    tone: &'static str,
    target: &'static str,
    facet: RwSignal<String>,
) -> impl IntoView {
    let num_class = if n == 0 {
        "dash-metric__num".to_string()
    } else {
        format!("dash-metric__num dash-metric__num--{tone}")
    };
    view! {
        <button
            class="dash-metric audit-card"
            type="button"
            on:click=move |_| facet.set(target.to_string())
        >
            <span class=num_class>{n}</span>
            <span class="dash-metric__label">{label}</span>
        </button>
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

/// Contextual message when a facet yields no rows — most importantly explaining
/// why the Unused tab is empty when the sign-in report wasn't available.
fn empty_facet_message(facet: &str, sign_in_report_available: bool) -> &'static str {
    if facet == "unused" && !sign_in_report_available {
        "No unused apps to show: the sign-in activity report wasn't available. It needs the AuditLog.Read.All permission and Entra ID P1 or P2 — grant consent above and re-run to enable unused-app detection."
    } else {
        "No applications match this filter."
    }
}

/// Picks the most actionable detail-pane tab for an audit finding, so the row's
/// "Open" deep-link lands where the operator can act on it (mailbox/site
/// scoping and risky perms → Permissions, which hosts the Exchange/SharePoint
/// scoping sections; ownership → Owners; expiry → Credentials), falling back to
/// Overview. The audit only enumerates app registrations and `object_id` is the
/// app-registration object id, so the target always resolves in the Apps pane.
fn target_tab(item: &AuditItem) -> &'static str {
    use azapptoolkit_core::audit::CredentialStatus;
    let has = |p: &str| item.issues.iter().any(|x| x.starts_with(p));
    if has(issue::ORG_WIDE_MAILBOX)
        || item
            .issues
            .iter()
            .any(|x| x.contains(issue::SCOPED_VIA_RBAC))
        || has(issue::ORG_WIDE_SHAREPOINT)
        || has(issue::SCOPED_SHAREPOINT)
        || has(issue::HIGH_RISK_APP_PERMS)
        || has(issue::HIGH_RISK_DELEGATED_PERMS)
        || has(issue::REDUNDANT_APP_PERMS)
    {
        "permissions"
    } else if has(issue::NO_OWNERS) || has(issue::SINGLE_OWNER) {
        "owners"
    } else if matches!(
        item.credential_status,
        CredentialStatus::ExpiringSoon | CredentialStatus::Expired
    ) {
        "credentials"
    } else {
        "overview"
    }
}

/// Per-row actions for an audit finding. Always renders an "Open" deep-link into
/// the app's detail pane on the most actionable tab (turning the audit from a
/// dead-end table into a launchpad), followed by any one-click remediation the
/// scorer attached: remove-expired-credentials (a static confirm dialog) and the
/// scoping fixes (guided group/site modals). On success each fires `on_done` so
/// the parent clears this item's remediations — the buttons disappear for good
/// (surviving facet/search changes) and the audit cache is busted server-side,
/// so a re-run reflects the new scores.
#[component]
fn AuditRowActions(item: AuditItem, #[prop(into)] on_done: Callback<String>) -> impl IntoView {
    let session = use_session();
    let find = |k: RemediationKind| item.remediations.iter().find(|r| r.kind == k).cloned();
    let expired = find(RemediationKind::RemoveExpiredCredentials);
    let redundant = find(RemediationKind::RemoveRedundantPermissions);
    let mailbox = find(RemediationKind::ScopeMailboxAccess);
    let sharepoint = find(RemediationKind::ScopeSharePointAccess);

    let tab = target_tab(&item);
    let object_id = item.object_id.clone();
    let oid_open = object_id.clone();
    let oid_r = object_id.clone();
    let oid_m = object_id.clone();
    let oid_s = object_id.clone();
    view! {
        <div class="audit-actions-stack">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                on_click=Box::new(move |_| session.open_app_on_tab(oid_open.clone(), tab))
            >
                "Open"
            </Button>
            {expired
                .map(|action| {
                    view! {
                        <ExpiredCredsAction object_id=object_id.clone() action=action on_done=on_done />
                    }
                })}
            {redundant
                .map(|action| {
                    view! {
                        <RedundantPermsAction object_id=oid_r.clone() action=action on_done=on_done />
                    }
                })}
            {mailbox
                .map(|action| {
                    view! { <ScopeMailboxButton object_id=oid_m.clone() action=action on_done=on_done /> }
                })}
            {sharepoint
                .map(|action| {
                    view! {
                        <ScopeSharePointButton object_id=oid_s.clone() action=action on_done=on_done />
                    }
                })}
        </div>
    }
}

/// The remove-redundant-permissions fix: a button gated by a static confirm
/// dialog (the narrower permissions are previewed in-row and the covering
/// broader ones listed under Issues). The backend re-plans against the live
/// manifest + grants, so the toast reports what was actually removed/skipped.
#[component]
fn RedundantPermsAction(
    object_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let confirm = move |()| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let object_id = object_id.clone();
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match remediation::remediate_remove_redundant_permissions(&t.tenant_id, &object_id)
                .await
            {
                Ok(outcome) => {
                    open.set(false);
                    let n = outcome.removed.len();
                    let mut msg = format!(
                        "Removed {n} redundant permission{}",
                        if n == 1 { "" } else { "s" }
                    );
                    if !outcome.skipped.is_empty() {
                        msg.push_str(&format!(
                            "; skipped {} (covering grant no longer present)",
                            outcome.skipped.join(", ")
                        ));
                    }
                    msg.push_str(" — re-run the audit to refresh scores.");
                    session.toast_success(&msg);
                    on_done.run(object_id);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let label = action.label.clone();
    let detail = action.detail.clone();

    view! {
        <div class="audit-actions">
            <Button
                class="button--danger"
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| open.set(true))
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <ConfirmDialog
                open=Signal::derive(move || open.get())
                title="Remove redundant permissions?"
                body="Removes the narrower permissions listed under Issues — a broader permission this app also holds already grants the same access, so its calls keep working. Each removal is re-checked against the live grants first; a permission whose covering grant has since been revoked or scoped is skipped. Re-run the audit afterward to refresh scores."
                confirm_label="Remove"
                busy=Signal::derive(move || busy.get())
                error=Signal::derive(move || error.get())
                on_confirm=Callback::new(confirm)
                on_close=Callback::new(move |()| open.set(false))
            />
        </div>
    }
        .into_any()
}

/// The remove-expired-credentials fix: a button gated by a static confirm dialog
/// (the specific credentials are previewed in-row and listed under Issues).
#[component]
fn ExpiredCredsAction(
    object_id: String,
    action: RemediationAction,
    #[prop(into)] on_done: Callback<String>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let open = RwSignal::new(false);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let confirm = move |()| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let object_id = object_id.clone();
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match remediation::remediate_remove_expired_credentials(&t.tenant_id, &object_id).await
            {
                Ok(outcome) => {
                    open.set(false);
                    let n = outcome.removed_secrets + outcome.removed_certificates;
                    session.toast_success(
                        format!(
                            "Removed {n} expired credential{} — re-run the audit to refresh scores.",
                            if n == 1 { "" } else { "s" }
                        )
                        .as_str(),
                    );
                    // Parent drops this item's remediations → button replaced by
                    // "—", and the state can't be lost by a re-render.
                    on_done.run(object_id);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let label = action.label.clone();
    let detail = action.detail.clone();

    view! {
        <div class="audit-actions">
            <Button
                class="button--danger"
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(move |_| open.set(true))
            >
                {label}
            </Button>
            <div class="audit-actions__preview">{detail}</div>
            <ConfirmDialog
                open=Signal::derive(move || open.get())
                title="Remove expired credentials?"
                body="Permanently removes this app's expired secrets and certificates (listed under Issues). Expired credentials can't authenticate, so removing them won't disrupt a working sign-in — you can add a new credential anytime. Re-run the audit afterward to refresh scores."
                confirm_label="Remove"
                busy=Signal::derive(move || busy.get())
                error=Signal::derive(move || error.get())
                on_confirm=Callback::new(confirm)
                on_close=Callback::new(move |()| open.set(false))
            />
        </div>
    }
        .into_any()
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::audit::CredentialStatus;

    fn blank() -> AuditItem {
        AuditItem {
            application_name: "App".into(),
            app_id: "app-1".into(),
            object_id: "obj-1".into(),
            created_date: None,
            publisher: None,
            sign_in_audience: None,
            risk_score: 0,
            risk_level: RiskLevel::Low,
            issues: vec![],
            recommendations: vec![],
            remediations: vec![],
            credential_status: CredentialStatus::Active,
            permission_count: 0,
            service_principal_enabled: None,
            days_since_created: None,
            certificates: vec![],
            secrets: vec![],
            last_sign_in: None,
            unused: false,
            sign_in_report_available: false,
        }
    }

    fn with_issue(text: String) -> AuditItem {
        AuditItem {
            issues: vec![text],
            ..blank()
        }
    }

    fn named(name: &str, app_id: &str, level: RiskLevel) -> AuditItem {
        AuditItem {
            application_name: name.into(),
            app_id: app_id.into(),
            risk_level: level,
            ..blank()
        }
    }

    // ---- filter_indices characterization (T-M7) ----------------------------
    // These pin the facet × search interplay before the at-scale perf rewrite
    // (windowed, index-based rendering) so the rewrite is provably
    // behavior-preserving. The query is passed already-lowercased, mirroring
    // the call site (`search_debounced.get().to_lowercase()`).

    #[test]
    fn filter_indices_empty_query_keeps_facet_matches_in_order() {
        let items = vec![
            named("Alpha", "aaa", RiskLevel::Critical),
            named("Beta", "bbb", RiskLevel::Low),
            named("Gamma", "ccc", RiskLevel::Critical),
        ];
        // "all" facet, empty query → every index, original order.
        assert_eq!(filter_indices(&items, "all", ""), vec![0, 1, 2]);
        // A risk facet keeps only its matches, preserving order.
        assert_eq!(filter_indices(&items, "critical", ""), vec![0, 2]);
        assert_eq!(filter_indices(&items, "low", ""), vec![1]);
    }

    #[test]
    fn filter_indices_query_matches_name_or_appid_case_insensitively() {
        let items = vec![
            named("Payroll API", "1111-aaaa", RiskLevel::Low),
            named("HR Sync", "2222-bbbb", RiskLevel::Low),
        ];
        // Name substring (caller lowercases the query; data is lowercased here).
        assert_eq!(filter_indices(&items, "all", "payroll"), vec![0]);
        // AppId substring also matches.
        assert_eq!(filter_indices(&items, "all", "2222"), vec![1]);
        // No match → empty.
        assert!(filter_indices(&items, "all", "zzz").is_empty());
    }

    #[test]
    fn filter_indices_combines_facet_and_query_as_intersection() {
        let items = vec![
            named("Critical Payroll", "aaa", RiskLevel::Critical),
            named("Low Payroll", "bbb", RiskLevel::Low),
            named("Critical Other", "ccc", RiskLevel::Critical),
        ];
        // Both predicates must hold: critical AND name contains "payroll".
        assert_eq!(filter_indices(&items, "critical", "payroll"), vec![0]);
        // Facet excludes the matching-name low-risk row.
        assert_eq!(
            filter_indices(&items, "high", "payroll"),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn filter_indices_indices_address_the_original_slice() {
        // The rewrite renders `items[idx]`, so every returned index must be a
        // valid, correct address into the *unfiltered* slice.
        let items = vec![
            named("keep me", "aaa", RiskLevel::Low),
            named("skip", "bbb", RiskLevel::Low),
            named("keep me too", "ccc", RiskLevel::Low),
        ];
        let idx = filter_indices(&items, "all", "keep");
        assert_eq!(idx, vec![0, 2]);
        for i in idx {
            assert!(items[i].application_name.contains("keep"));
        }
    }

    // Consumer half of the structured-signals invariant: the producer side is
    // pinned by core's `emitted_issue_markers_are_stable`; this pins that each
    // marker-driven facet matches exactly its own marker and no sibling's.
    #[test]
    fn issue_marker_facets_match_exactly_their_facet() {
        let cases = [
            (
                format!("{} something", issue::HIGH_RISK_APP_PERMS),
                "high_risk_perms",
            ),
            (
                format!("{} something", issue::HIGH_RISK_DELEGATED_PERMS),
                "high_risk_delegated",
            ),
            (
                format!("{} something", issue::ORG_WIDE_MAILBOX),
                "orgwide_mailbox",
            ),
            (
                format!("{} something", issue::ORG_WIDE_SHAREPOINT),
                "orgwide_sharepoint",
            ),
            (
                format!("{} something", issue::SCOPED_SHAREPOINT),
                "scoped_sites",
            ),
            (format!("{} something", issue::NO_OWNERS), "ownership"),
        ];
        let marker_facets = [
            "high_risk_perms",
            "high_risk_delegated",
            "orgwide_mailbox",
            "scoped_mailbox",
            "orgwide_sharepoint",
            "scoped_sites",
            "ownership",
        ];
        for (text, expect) in &cases {
            let item = with_issue(text.clone());
            for f in marker_facets {
                assert_eq!(
                    matches_facet(&item, f),
                    f == *expect,
                    "issue {text:?} vs facet {f}"
                );
            }
        }
    }

    #[test]
    fn scoped_mailbox_facet_matches_the_mid_string_marker() {
        // SCOPED_VIA_RBAC is deliberately matched with `.contains` — the
        // scorer embeds it mid-issue ("Mail.Read scoped via Exchange RBAC…"),
        // not as a prefix like every sibling marker. Load-bearing asymmetry:
        // a well-meaning "make them all starts_with" sweep would silently
        // empty the Scoped-mailbox facet.
        let item = with_issue(format!("Mail.Read {} (Sales Team)", issue::SCOPED_VIA_RBAC));
        assert!(matches_facet(&item, "scoped_mailbox"));
        assert!(!matches_facet(&item, "orgwide_mailbox"));
    }

    #[test]
    fn target_tab_routes_each_marker_to_its_detail_tab() {
        let tab = |text: String| target_tab(&with_issue(text));
        // Mailbox/site scoping findings land on Permissions, which hosts the
        // Exchange/SharePoint scoping sections (the dedicated tabs are gone).
        assert_eq!(tab(format!("{} x", issue::ORG_WIDE_MAILBOX)), "permissions");
        assert_eq!(
            tab(format!("Mail.Read {} (Sales)", issue::SCOPED_VIA_RBAC)),
            "permissions"
        );
        assert_eq!(
            tab(format!("{} x", issue::ORG_WIDE_SHAREPOINT)),
            "permissions"
        );
        assert_eq!(
            tab(format!("{} x", issue::REDUNDANT_APP_PERMS)),
            "permissions"
        );
        assert_eq!(tab(format!("{} x", issue::NO_OWNERS)), "owners");
        let expired = AuditItem {
            credential_status: CredentialStatus::Expired,
            ..blank()
        };
        assert_eq!(target_tab(&expired), "credentials");
        assert_eq!(target_tab(&blank()), "overview");
    }
}
