//! Mailboxes panel — probes every candidate application against one target
//! mailbox (the Entra ∪ Exchange-RBAC union) to answer "who can read this
//! mailbox?".

use std::sync::Arc;

use azapptoolkit_core::audit::AuditPrincipalKind;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, ProgressBar};

use crate::bindings::events;
use crate::bindings::permission_tester::{
    self, AccessVerdict, MailboxProbeProgress, MailboxReacherRow, MailboxReachersResult,
};
use crate::components::export_menu::ExportMenu;
use crate::components::ui::{Badge, Callout, ShowMore};
use crate::constants::*;
use crate::hooks::use_grid_keynav::use_grid_keynav;
use crate::hooks::use_list_export::use_list_export;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::{Session, use_session};
use crate::util::plural;

use super::{verdict_badge, verdict_tooltip};

/// The panel's headline sentence for one probe result.
///
/// A free function rather than prose built inline, because the export ships it
/// verbatim: an `unknown` verdict means an Exchange RBAC check could not be
/// evaluated, and an Exchange outage leaves every verdict deriving from the
/// Entra grants alone. An unread Exchange SP store means apps granted access
/// only through Exchange RBAC were never candidates at all. Every caveat is
/// stated on screen, and a file that dropped one would read as an audited
/// all-clear.
fn summary_line(r: &MailboxReachersResult) -> String {
    let reachers = r.rows.iter().filter(|x| x.verdict.reaches()).count();
    let unknowns = r
        .rows
        .iter()
        .filter(|x| x.verdict == AccessVerdict::Unknown)
        .count();
    let mut summary = format!(
        "{} of {} candidate app{} can reach “{}”",
        reachers,
        r.total_candidates,
        plural(r.total_candidates),
        r.mailbox,
    );
    if unknowns > 0 {
        // An Unknown row means a path (usually the Exchange RBAC check)
        // couldn't be evaluated — treat as possible access, not noise.
        summary.push_str(&format!(
            " · {unknowns} couldn’t be confirmed (need Exchange admin rights)"
        ));
    }
    if !r.exchange_available {
        summary.push_str(
            " — Exchange was unavailable, so verdicts derive from the Entra grants alone (org-wide unless scoped; never under-reported); apps granted access only through Exchange RBAC could not be listed",
        );
    } else if !r.exchange_sp_store_read {
        summary.push_str(
            " — Exchange's service-principal list couldn't be read, so apps granted access only through Exchange RBAC may be missing",
        );
    }
    if r.cancelled {
        summary.push_str(" — probe was cancelled early");
    }
    summary
}

/// Routes a reacher row's "Open" affordance to the right detail pane — the audit
/// view's `principal_kind` routing (App Registration / enterprise / managed
/// identity), landing on the Permissions tab where the grant can be reviewed and
/// revoked. `object_id` is the application object id for a local registration,
/// otherwise the service-principal object id.
fn open_reacher(session: Session, kind: AuditPrincipalKind, object_id: &str) {
    match kind {
        AuditPrincipalKind::Application => {
            session.open_app_on_tab(object_id.to_string(), "permissions")
        }
        AuditPrincipalKind::ServicePrincipal => {
            session.open_enterprise_on_tab(object_id.to_string(), "permissions")
        }
        AuditPrincipalKind::ManagedIdentity => {
            session.open_managed_identity_on_tab(object_id.to_string(), "permissions")
        }
    }
}

#[component]
pub(super) fn MailboxesPanel() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    let result: RwSignal<Option<MailboxReachersResult>> = RwSignal::new(None);
    let probing = RwSignal::new(false);
    let progress: RwSignal<Option<MailboxProbeProgress>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let mailbox = RwSignal::new(String::new());
    // Confirmed "No access" rows are noise for "who can reach this?" — hidden by
    // default, revealed by the toggle below.
    let show_no_access = RwSignal::new(false);
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
            show_no_access.set(false);
        }
    });

    use_progress_stream(progress, events::mailbox_probe_progress);

    let summary: Memo<Option<String>> =
        Memo::new(move |_| result.with(|r| r.as_ref().map(summary_line)));

    // What the panel is answering with: confirmed "No access" is noise for "who
    // can reach this?" and is hidden by default. THIS, not the render window
    // below, is what the export writes — the window is a DOM budget, not a
    // filter. A `Signal` rather than a `Memo` because `MailboxReacherRow` is an
    // IPC DTO with no `PartialEq` to memoize on.
    let visible_rows: Signal<Vec<MailboxReacherRow>> = Signal::derive(move || {
        let show_na = show_no_access.get();
        result.with(|r| {
            r.as_ref()
                .map(|r| {
                    r.rows
                        .iter()
                        .filter(|x| show_na || x.verdict != AccessVerdict::NoAccess)
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
    });

    // "Which apps can read this mailbox?" is the answer an operator is asked to
    // put in writing after an incident; before this the only way out of the app
    // was a screenshot. Reuses the inventory lists' export handle (snapshot +
    // double-submit guard + toast) and ships `summary` with the rows so the
    // probe's caveats travel with the data.
    let (export_rows, exporting, do_export) = use_list_export(
        move |rows: Arc<Vec<MailboxReacherRow>>, format| async move {
            let coverage = summary.get_untracked().unwrap_or_default();
            permission_tester::save_mailbox_reachers_to_file(&rows, &coverage, format).await
        },
        "candidate apps",
    );
    Effect::new(move |_| export_rows.set_value(Arc::new(visible_rows.get())));

    // A probe result is mailbox- and tenant-specific: clear it on tenant switch
    // so another tenant's verdicts can never linger (cross-tenant leakage).
    Effect::new(move |_| {
        let _ = tenant.get();
        result.set(None);
        error.set(None);
        progress.set(None);
        mailbox.set(String::new());
        show_no_access.set(false);
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
        // A probe is per-target: a table for a *different* mailbox must not sit
        // under the progress bar (or beneath an error) while this one runs.
        // Re-checking the same mailbox keeps it until the new result lands.
        if result.with_untracked(|r| {
            r.as_ref()
                .is_some_and(|r| !r.mailbox.eq_ignore_ascii_case(&mb))
        }) {
            result.set(None);
        }
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
                // This panel has no consent / step-up button of its own, so it
                // takes the shared sink's whole ladder (dead session, rejected
                // token, Exchange consent, step-up) before the inline line.
                Err(e) => {
                    if !session.report_recovery_action(&e, "exchange") {
                        error.set(Some(e.message));
                    }
                }
            }
            probing.set(false);
            progress.set(None);
        });
    };

    let cancel = move |_| {
        leptos::task::spawn_local(async move {
            let _ = permission_tester::cancel_mailbox_probe().await;
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
            <ExportMenu
                disabled=Signal::derive(move || {
                    exporting.get() || visible_rows.with(Vec::is_empty)
                })
                on_select=Callback::new(do_export)
                options=vec![("csv", "Export as CSV…"), ("json", "Export as JSON…")]
            />
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
                .map(|e| view! { <Callout tone="warn"><Body1>{e}</Body1></Callout> })
        }}
        {move || {
            let Some(r) = result.get() else {
                return ().into_any();
            };
            let no_access = r.rows.iter().filter(|x| x.verdict == AccessVerdict::NoAccess).count();
            // From the same memo the export reads, so the sentence on screen and
            // the one in the file are one string, not two that can drift apart.
            let summary = summary.get().unwrap_or_default();
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
                    let show_na = show_no_access.get();
                    // Hide confirmed "No access" by default — the answer to "who
                    // can reach this?" is the reachers plus the couldn't-confirms.
                    // ONE definition of "visible", shared with the export; the
                    // render window below is a DOM budget layered on top of it,
                    // not a second filter, so the file and the table agree.
                    let visible = visible_rows.get();
                    let visible_total = visible.len();
                    let limit = render_limit.get();
                    let rows: Vec<MailboxReacherRow> =
                        visible.into_iter().take(limit).collect();
                    view! {
                        {if rows.is_empty() {
                            // Everything was confirmed no-access (all hidden).
                            view! {
                                <Body1 class="page__summary">
                                    {format!(
                                        "No application can reach “{}” — all {} candidate{} were checked and have no access.",
                                        r.mailbox,
                                        no_access,
                                        plural(no_access),
                                    )}
                                </Body1>
                            }
                                .into_any()
                        } else {
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
                                                let (badge_tone, badge_label) = verdict_badge(row.verdict);
                                                let badge_title = verdict_tooltip(row.verdict);
                                                let app_primary = row
                                                    .display_name
                                                    .clone()
                                                    .unwrap_or_else(|| row.app_id.clone());
                                                let roles = if row.roles.is_empty() {
                                                    String::new()
                                                } else {
                                                    format!(" — via {}", row.roles.join(", "))
                                                };
                                                let kind = row.principal_kind;
                                                let object_id = row.object_id.clone();
                                                let has_target = !object_id.is_empty();
                                                view! {
                                                    <tr>
                                                        <td class="permission-cell">
                                                            <div class="permissions-cell__primary">{app_primary}</div>
                                                            <div class="permissions-cell__secondary mono">{row.app_id}</div>
                                                            {has_target
                                                                .then(|| {
                                                                    view! {
                                                                        <button
                                                                            type="button"
                                                                            class="link-btn"
                                                                            on:click=move |_| open_reacher(session, kind, &object_id)
                                                                        >
                                                                            "Open for investigation ↗"
                                                                        </button>
                                                                    }
                                                                })}
                                                        </td>
                                                        <td class="cell-mid">{row.held_permissions.join(", ")}</td>
                                                        <td class="cell-mid">
                                                            <Badge label=badge_label tone=badge_tone title=badge_title />
                                                        </td>
                                                        <td>{format!("{}{roles}", row.detail.unwrap_or_default())}</td>
                                                    </tr>
                                                }
                                            })
                                            .collect_view()}
                                    </tbody>
                                </table>
                                <ShowMore
                                    total=visible_total
                                    limit=limit
                                    render_limit=render_limit
                                    noun="apps"
                                />
                            }
                                .into_any()
                        }}
                        {(no_access > 0)
                            .then(|| {
                                let label = if show_na {
                                    "Hide apps with no access".to_string()
                                } else {
                                    format!("Show {no_access} with no access")
                                };
                                view! {
                                    <div class="show-more">
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                            on_click=Box::new(move |_| {
                                                render_limit.set(RENDER_PAGE);
                                                show_no_access.update(|s| *s = !*s);
                                            })
                                        >
                                            {label}
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

#[cfg(test)]
mod tests {
    use super::*;

    fn result(exchange_available: bool, exchange_sp_store_read: bool) -> MailboxReachersResult {
        MailboxReachersResult {
            tenant_id: "t".into(),
            mailbox: "shared@contoso.com".into(),
            total_candidates: 0,
            rows: Vec::new(),
            exchange_available,
            exchange_sp_store_read,
            cancelled: false,
        }
    }

    // The caveat travels with the export verbatim, so a probe that could not
    // enumerate the RBAC-only principals must say so in this one sentence.
    #[test]
    fn summary_flags_unavailable_exchange() {
        let s = summary_line(&result(false, false));
        assert!(s.contains("Exchange was unavailable"));
        assert!(s.contains("only through Exchange RBAC could not be listed"));
        // One caveat, not two stacked versions of the same gap.
        assert!(!s.contains("service-principal list"));
    }

    #[test]
    fn summary_flags_an_unread_exchange_sp_store() {
        let s = summary_line(&result(true, false));
        assert!(s.contains("Exchange's service-principal list couldn't be read"));
        assert!(s.contains("may be missing"));
        assert!(!s.contains("Exchange was unavailable"));
    }

    #[test]
    fn a_fully_covered_probe_has_no_coverage_caveat() {
        let s = summary_line(&result(true, true));
        assert_eq!(s, "0 of 0 candidate apps can reach “shared@contoso.com”");
    }
}
