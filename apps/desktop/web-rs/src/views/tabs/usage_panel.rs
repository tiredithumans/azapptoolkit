//! "Observed Graph activity" — the granted-vs-used lens for the Permissions tab.
//! Loads on demand (the workspace discovery + KQL query cost a few round trips,
//! so it never runs on tab open): summarizes the app's actual Graph calls over
//! the last 90 days from MicrosoftGraphActivityLogs, so an admin can compare
//! what the app *does* against its declared permissions (e.g. `Mail.ReadWrite`
//! granted but only GETs observed → the Downgrade… action applies). Degrades to
//! setup guidance (`usage_unavailable`) or a consent button — never breaks the
//! tab.

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::bindings::applications::ApplicationDetail;
use crate::bindings::auth;
use crate::bindings::usage;
use crate::state::use_session;

#[component]
pub fn UsagePanel(#[prop(into)] detail: Signal<Arc<ApplicationDetail>>) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let result: RwSignal<Option<usage::GraphUsageResult>> = RwSignal::new(None);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let consent_needed = RwSignal::new(false);
    let unavailable = RwSignal::new(false);

    // Stale-usage guard: a different app's detail in the same pane must not
    // show the previous app's call patterns.
    Effect::new(move |_| {
        let _ = detail.with(|d| d.application.app_id.clone());
        result.set(None);
        error.set(None);
        consent_needed.set(false);
        unavailable.set(false);
    });

    let do_load = move || {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        consent_needed.set(false);
        unavailable.set(false);
        let tenant = tenant.get();
        let app_id = detail.with(|d| d.application.app_id.clone());
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match usage::get_app_graph_usage(&t.tenant_id, &app_id, 90).await {
                Ok(r) => result.set(Some(r)),
                Err(e) => {
                    consent_needed.set(e.code == "consent_required");
                    unavailable.set(e.code == "usage_unavailable");
                    error.set(Some(e.message));
                }
            }
            busy.set(false);
        });
    };

    let grant_consent = move |_| {
        let Some(t) = tenant.get() else { return };
        error.set(None);
        leptos::task::spawn_local(async move {
            match auth::request_scope_consent(&t.tenant_id, "log_analytics").await {
                Ok(()) => do_load(),
                Err(e) => error.set(Some(e.message)),
            }
        });
    };

    view! {
        <div class="permissions-tab__usage">
            <h3>"Observed Graph activity"</h3>
            <Body1>
                "What this app actually called over the last 90 days (from MicrosoftGraphActivityLogs) — compare against the permissions above to spot unused or over-broad grants."
            </Body1>
            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| do_load())
                >
                    {move || {
                        if busy.get() {
                            "Loading…"
                        } else if result.with(|r| r.is_some()) {
                            "Refresh observed usage"
                        } else {
                            "Check observed usage (90d)"
                        }
                    }}
                </Button>
            </div>
            {move || {
                error
                    .get()
                    .map(|e| {
                        let class = if unavailable.get() { "alert" } else { "alert alert--warn" };
                        view! {
                            <div class=class>
                                <Body1>{e}</Body1>
                                {consent_needed
                                    .get()
                                    .then(|| {
                                        view! {
                                            <div class="actions-row">
                                                <Button
                                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                    on_click=Box::new(grant_consent)
                                                >
                                                    "Grant consent & retry"
                                                </Button>
                                            </div>
                                        }
                                    })}
                            </div>
                        }
                    })
            }}
            {move || {
                result
                    .get()
                    .map(|r| {
                        let summary = format!(
                            "{} call pattern{} over {} days (workspace: {}){}{}",
                            r.rows.len(),
                            if r.rows.len() == 1 { "" } else { "s" },
                            r.days,
                            r.workspace_name,
                            if r.truncated { " — long tail truncated" } else { "" },
                            if r.rows.is_empty() {
                                " — no Graph calls observed; if this persists, the app may not need its Graph permissions at all"
                            } else {
                                ""
                            },
                        );
                        view! {
                            <Body1 class="page__summary">{summary}</Body1>
                            {(!r.rows.is_empty())
                                .then(|| {
                                    view! {
                                        <table class="data-table">
                                            <thead>
                                                <tr>
                                                    <th>"Method"</th>
                                                    <th>"Path"</th>
                                                    <th>"Calls"</th>
                                                    <th>"Last seen"</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {r
                                                    .rows
                                                    .into_iter()
                                                    .map(|row| {
                                                        view! {
                                                            <tr>
                                                                <td class="cell-mid">{row.method}</td>
                                                                <td class="mono">{row.path}</td>
                                                                <td class="cell-mid">{row.count}</td>
                                                                <td class="cell-mid">
                                                                    {row.last_seen.unwrap_or_default()}
                                                                </td>
                                                            </tr>
                                                        }
                                                    })
                                                    .collect_view()}
                                            </tbody>
                                        </table>
                                    }
                                })}
                        }
                    })
            }}
        </div>
    }
}
