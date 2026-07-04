//! Mailboxes panel — probes every candidate application against one target
//! mailbox (the Entra ∪ Exchange-RBAC union) to answer "who can read this
//! mailbox?".

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, ProgressBar};

use crate::bindings::events;
use crate::bindings::permission_tester::{
    self, MailboxProbeProgress, MailboxReacherRow, MailboxReachersResult,
};
use crate::bindings::sharepoint;
use crate::constants::*;
use crate::hooks::use_grid_keynav::use_grid_keynav;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::use_session;

use super::verdict_badge;

#[component]
pub(super) fn MailboxesPanel() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let result: RwSignal<Option<MailboxReachersResult>> = RwSignal::new(None);
    let probing = RwSignal::new(false);
    let progress: RwSignal<Option<MailboxProbeProgress>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let mailbox = RwSignal::new(String::new());
    // Render window for the reachers table — bounded DOM on a large result.
    let render_limit = RwSignal::new(RENDER_PAGE);
    let tbody_ref: NodeRef<leptos::html::Tbody> = NodeRef::new();
    let on_grid_key = use_grid_keynav(tbody_ref, move || {
        let _ = render_limit.get();
        let _ = result.with(|r| r.as_ref().map(|x| x.rows.len()));
    });
    Effect::new(move |prev: Option<()>| {
        result.track();
        if prev.is_some() {
            render_limit.set(RENDER_PAGE);
        }
    });

    use_progress_stream(progress, events::mailbox_probe_progress);

    // A probe result is mailbox- and tenant-specific: clear it on tenant switch
    // so another tenant's verdicts can never linger (cross-tenant leakage).
    Effect::new(move |_| {
        let _ = tenant.get();
        result.set(None);
        error.set(None);
        progress.set(None);
        mailbox.set(String::new());
    });

    let do_probe = move || {
        if probing.get() {
            return;
        }
        let mb = mailbox.get().trim().to_string();
        if mb.is_empty() {
            error.set(Some(
                "Enter a mailbox address (e.g. shared@contoso.com).".into(),
            ));
            return;
        }
        probing.set(true);
        error.set(None);
        progress.set(Some(MailboxProbeProgress {
            done: 0,
            total: 0,
            current_app: None,
            cancelled: false,
        }));
        let t = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = t else {
                probing.set(false);
                return;
            };
            match permission_tester::find_mailbox_reachers(&t.tenant_id, &mb).await {
                Ok(r) => result.set(Some(r)),
                Err(e) => error.set(Some(e.message)),
            }
            probing.set(false);
            progress.set(None);
        });
    };

    let cancel = move |_| {
        leptos::task::spawn_local(async move {
            let _ = sharepoint::cancel_resource_sweep().await;
        });
    };

    view! {
        <Body1>
            "Lists every application holding a mail-scopable Graph permission and tests each against one mailbox via Exchange's authoritative authorization check — \"who can read this mailbox?\"."
        </Body1>
        <div class="actions-row">
            <div class="page__search">
                <Input value=mailbox placeholder="Mailbox address (e.g. shared@contoso.com)…" />
            </div>
            {move || {
                if probing.get() {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(cancel)
                        >
                            "Cancel"
                        </Button>
                    }
                        .into_any()
                } else {
                    view! {
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(move |_| do_probe())
                        >
                            "Check mailbox"
                        </Button>
                    }
                        .into_any()
                }
            }}
        </div>
        {move || {
            progress
                .get()
                .filter(|_| probing.get())
                .map(|p| {
                    let pct = if p.total == 0 {
                        0.0
                    } else {
                        p.done as f64 / p.total as f64
                    };
                    view! {
                        <div class="audit-progress">
                            <ProgressBar value=Signal::derive(move || pct) />
                            <Body1>
                                {format!(
                                    "{} / {} candidate apps{}{}",
                                    p.done,
                                    p.total,
                                    p.current_app.as_deref().map(|s| format!(" — {s}")).unwrap_or_default(),
                                    if p.cancelled { " (cancelling…)" } else { "" },
                                )}
                            </Body1>
                        </div>
                    }
                })
        }}
        {move || {
            error
                .get()
                .map(|e| view! { <div class="alert alert--warn"><Body1>{e}</Body1></div> })
        }}
        {move || {
            let Some(r) = result.get() else {
                return ().into_any();
            };
            let reachers = r
                .rows
                .iter()
                .filter(|x| x.verdict == "org_wide" || x.verdict == "scoped")
                .count();
            let summary = format!(
                "{} of {} candidate app{} can reach “{}”{}{}",
                reachers,
                r.total_candidates,
                if r.total_candidates == 1 { "" } else { "s" },
                r.mailbox,
                if r.exchange_available {
                    ""
                } else {
                    " — Exchange was unavailable, so verdicts derive from the Entra grants alone (org-wide unless scoped; never under-reported)"
                },
                if r.cancelled { " — probe was cancelled early" } else { "" },
            );
            view! {
                <Body1 class="page__summary">{summary}</Body1>
                {if r.rows.is_empty() {
                    view! {
                        <Body1>
                            "No application in this tenant holds a mail-scopable Graph application permission or an Exchange RBAC-for-Applications registration — nothing can read mailboxes app-only via Graph."
                        </Body1>
                    }
                        .into_any()
                } else {
                    let total = r.rows.len();
                    let limit = render_limit.get();
                    let rows: Vec<MailboxReacherRow> =
                        r.rows.iter().take(limit).cloned().collect();
                    view! {
                        <table class="data-table">
                            <thead>
                                <tr>
                                    <th>"Application"</th>
                                    <th>"Holds"</th>
                                    <th>"Verdict"</th>
                                    <th>"Detail"</th>
                                </tr>
                            </thead>
                            <tbody node_ref=tbody_ref on:keydown=on_grid_key.clone()>
                                {rows
                                    .into_iter()
                                    .map(|row| {
                                        let (badge_class, badge_label) = verdict_badge(&row.verdict);
                                        let app_primary = row
                                            .display_name
                                            .clone()
                                            .unwrap_or_else(|| row.app_id.clone());
                                        let roles = if row.roles.is_empty() {
                                            String::new()
                                        } else {
                                            format!(" — via {}", row.roles.join(", "))
                                        };
                                        view! {
                                            <tr>
                                                <td class="permission-cell">
                                                    <div class="permissions-cell__primary">{app_primary}</div>
                                                    <div class="permissions-cell__secondary mono">{row.app_id}</div>
                                                </td>
                                                <td class="cell-mid">{row.held_permissions.join(", ")}</td>
                                                <td class="cell-mid">
                                                    <span class=badge_class>{badge_label}</span>
                                                </td>
                                                <td>{format!("{}{roles}", row.detail.unwrap_or_default())}</td>
                                            </tr>
                                        }
                                    })
                                    .collect_view()}
                            </tbody>
                        </table>
                        {(total > limit)
                            .then(|| {
                                let remaining = total - limit;
                                let next = RENDER_PAGE.min(remaining);
                                view! {
                                    <div class="audit-show-more">
                                        <Body1>
                                            {format!("Showing {limit} of {total} apps")}
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
                            })}
                    }
                        .into_any()
                }}
            }
                .into_any()
        }}
    }
}
