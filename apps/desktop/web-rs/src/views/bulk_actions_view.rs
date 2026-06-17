//! Bulk actions page. A tabbed surface over the bulk-operation commands.
//! The grant / remove-expired / delete tabs operate on the apps the user has
//! checked in the App Registrations list (`session.selected_app_ids`); the
//! create tab takes a JSON array and ignores the selection. Destructive tabs
//! gate behind a typed confirmation, and successful destructive runs bump
//! `apps_reload` so the list refetches.
//!
//! Promoted from a modal to a page: the modal used to cover the very App
//! Registrations selection it operates on. The selection persists in the
//! session, so checking apps in the list and then opening this page works.

use crate::hooks::use_progress_stream::use_progress_stream;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Spinner, SpinnerSize, Textarea};

use crate::bindings::bulk;
use crate::bindings::events;
use crate::components::icon::IconName;
use crate::components::ui::{EmptyState, SectionHeader, TabBar, TabBarItem};
use crate::state::use_session;

/// One failed item from a bulk run, surfaced below the aggregate summary so the
/// user can see *which* app failed and *why* (the counts alone hid this).
#[derive(Clone)]
struct BulkFailure {
    label: String,
    reason: String,
}

#[component]
pub fn BulkActionsView() -> impl IntoView {
    let session = use_session();
    let tab = RwSignal::new(String::from("grant"));
    let busy = RwSignal::new(false);
    let summary: RwSignal<Option<String>> = RwSignal::new(None);
    // Per-item failures from the last run (label + reason). Drives the failure
    // list and tones the summary alert warn-vs-ok.
    let failures: RwSignal<Vec<BulkFailure>> = RwSignal::new(Vec::new());
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    // Live per-app progress emitted by the backend bulk loop ("bulk-progress").
    let progress: RwSignal<Option<bulk::BulkProgress>> = RwSignal::new(None);
    use_progress_stream(progress, events::bulk_progress);

    let create_json = RwSignal::new(String::new());

    // Destructive-action confirmation gates. Each tab keeps its own confirm
    // text so switching tabs never leaves a stale confirmation armed. The gate
    // opens only when the user types the tab's exact keyword (case-sensitive),
    // deliberately requiring the user to reproduce the literal word shown.
    let remove_confirm = RwSignal::new(String::new());
    let delete_confirm = RwSignal::new(String::new());
    let confirm_ok = |typed: String, keyword: &str| typed.trim() == keyword;
    let remove_ok = Memo::new(move |_| confirm_ok(remove_confirm.get(), "REMOVE"));
    let delete_ok = Memo::new(move |_| confirm_ok(delete_confirm.get(), "DELETE"));

    // Clear any prior result/error when the active tab changes so messages
    // don't bleed from one operation into another.
    Effect::new(move |_| {
        let _ = tab.get();
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        progress.set(None);
    });

    let do_grant = move |_| {
        if busy.get() {
            return;
        }
        let ids: Vec<String> = session.selected_app_ids.get().into_iter().collect();
        if ids.is_empty() {
            return;
        }
        busy.set(true);
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        let tenant = session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match bulk::bulk_grant_permissions(&t.tenant_id, &ids).await {
                Ok(r) => {
                    let fails: Vec<BulkFailure> = r
                        .outcomes
                        .iter()
                        .filter_map(|o| {
                            o.error.as_ref().map(|e| BulkFailure {
                                label: o.object_id.clone(),
                                reason: e.clone(),
                            })
                        })
                        .collect();
                    summary.set(Some(format!(
                        "Granted consent to {} app(s); {} with errors{}.",
                        r.outcomes.len(),
                        fails.len(),
                        if r.cancelled { " (cancelled)" } else { "" }
                    )));
                    failures.set(fails);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let do_remove = move |_| {
        if busy.get() || !remove_ok.get() {
            return;
        }
        let ids: Vec<String> = session.selected_app_ids.get().into_iter().collect();
        if ids.is_empty() {
            return;
        }
        busy.set(true);
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        let tenant = session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match bulk::bulk_remove_expired_credentials(&t.tenant_id, Some(&ids)).await {
                Ok(r) => {
                    // A per-app failure is either a hard error or some key(s)
                    // that couldn't be removed.
                    let fails: Vec<BulkFailure> = r
                        .summaries
                        .iter()
                        .filter_map(|s| {
                            let reason = if let Some(e) = &s.error {
                                Some(e.clone())
                            } else if !s.failed_key_ids.is_empty() {
                                Some(format!(
                                    "{} credential(s) could not be removed",
                                    s.failed_key_ids.len()
                                ))
                            } else {
                                None
                            };
                            reason.map(|reason| BulkFailure {
                                label: s.display_name.clone(),
                                reason,
                            })
                        })
                        .collect();
                    let removed = r
                        .summaries
                        .iter()
                        .filter(|s| !s.removed_key_ids.is_empty())
                        .count();
                    summary.set(Some(format!(
                        "Scanned {} app(s); {} had expired creds removed{}.",
                        r.apps_scanned,
                        removed,
                        if r.cancelled { " (cancelled)" } else { "" }
                    )));
                    failures.set(fails);
                    remove_confirm.set(String::new());
                    session.bump_apps_reload();
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let do_delete = move |_| {
        if busy.get() || !delete_ok.get() {
            return;
        }
        let ids: Vec<String> = session.selected_app_ids.get().into_iter().collect();
        if ids.is_empty() {
            return;
        }
        busy.set(true);
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        let tenant = session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match bulk::bulk_delete_applications(&t.tenant_id, &ids).await {
                Ok(r) => {
                    let fails: Vec<BulkFailure> = r
                        .failed
                        .iter()
                        .map(|f| BulkFailure {
                            label: f.object_id.clone(),
                            reason: f.message.clone(),
                        })
                        .collect();
                    summary.set(Some(format!(
                        "Deleted {} app(s); {} failed{}.",
                        r.deleted.len(),
                        fails.len(),
                        if r.cancelled { " (cancelled)" } else { "" }
                    )));
                    failures.set(fails);
                    delete_confirm.set(String::new());
                    session.clear_app_selection();
                    session.bump_apps_reload();
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let do_create = move |validate_only: bool| {
        if busy.get() {
            return;
        }
        let specs: Vec<bulk::BulkCreateSpec> = match serde_json::from_str(&create_json.get()) {
            Ok(s) => s,
            Err(e) => {
                error.set(Some(format!("Invalid JSON: {e}")));
                return;
            }
        };
        if specs.is_empty() {
            error.set(Some("JSON array is empty.".into()));
            return;
        }
        busy.set(true);
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        let tenant = session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match bulk::bulk_create_applications(&t.tenant_id, &specs, validate_only).await {
                Ok(r) => {
                    let fails: Vec<BulkFailure> = r
                        .outcomes
                        .iter()
                        .filter(|o| o.status != "created" && o.status != "valid")
                        .map(|o| BulkFailure {
                            label: o.display_name.clone(),
                            reason: o.message.clone().unwrap_or_else(|| o.status.clone()),
                        })
                        .collect();
                    let ok = r.outcomes.len() - fails.len();
                    summary.set(Some(format!(
                        "{}: {ok} ok, {} problem(s){}.",
                        if r.validate_only {
                            "Validated"
                        } else {
                            "Created"
                        },
                        fails.len(),
                        if r.cancelled { " (cancelled)" } else { "" }
                    )));
                    failures.set(fails);
                    if !r.validate_only && !r.cancelled {
                        session.bump_apps_reload();
                    }
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    // Empty-state shown by the selection-driven tabs when nothing is checked.
    let no_selection = move |body: &'static str| {
        view! {
            <EmptyState
                icon=IconName::AppWindow
                title="No apps selected".to_string()
                body=body.to_string()
            />
        }
    };

    view! {
        <main class="tool-page">
            <SectionHeader
                title="Bulk Actions".to_string()
                crumb="Operate on the App Registrations you've selected".to_string()
            />
            <TabBar
                items=vec![
                    TabBarItem { value: "grant", label: "Grant consent" },
                    TabBarItem { value: "remove", label: "Remove expired" },
                    TabBarItem { value: "delete", label: "Delete selected" },
                    TabBarItem { value: "create", label: "Create apps" },
                ]
                selected=tab
            />
            <div class="bulk-tab">
                {move || match tab.get().as_str() {
                    "grant" => {
                        if session.selected_app_ids.with(|s| s.is_empty()) {
                            no_selection(
                                    "Check one or more apps in App Registrations, then return here to grant admin consent.",
                                )
                                .into_any()
                        } else {
                            view! {
                                <div class="bulk-action">
                                    <Body1>
                                        {move || {
                                            format!(
                                                "Grant admin consent to the {} selected app(s).",
                                                session.selected_app_ids.with(|s| s.len()),
                                            )
                                        }}
                                    </Body1>
                                    <div class="actions-row">
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                                            on_click=Box::new(do_grant)
                                            disabled=Signal::derive(move || busy.get())
                                        >
                                            "Grant consent to selected apps"
                                        </Button>
                                    </div>
                                </div>
                            }
                                .into_any()
                        }
                    }
                    "remove" => {
                        if session.selected_app_ids.with(|s| s.is_empty()) {
                            no_selection(
                                    "Check one or more apps in App Registrations to sweep their expired password credentials.",
                                )
                                .into_any()
                        } else {
                            view! {
                                <div class="bulk-action">
                                    <Body1 class="bulk-action__danger">
                                        {move || {
                                            format!(
                                                "Remove every expired password credential from the {} selected app(s). This is irreversible.",
                                                session.selected_app_ids.with(|s| s.len()),
                                            )
                                        }}
                                    </Body1>
                                    <div class="confirm-gate">
                                        <Body1 class="confirm-gate__label">
                                            "Type "<strong>"REMOVE"</strong>" to confirm."
                                        </Body1>
                                        <Input value=remove_confirm placeholder="REMOVE" />
                                    </div>
                                    <div class="actions-row">
                                        <Button
                                            class="button--danger"
                                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                                            on_click=Box::new(do_remove)
                                            disabled=Signal::derive(move || busy.get() || !remove_ok.get())
                                        >
                                            "Remove expired from selected apps"
                                        </Button>
                                    </div>
                                </div>
                            }
                                .into_any()
                        }
                    }
                    "delete" => {
                        if session.selected_app_ids.with(|s| s.is_empty()) {
                            no_selection(
                                    "Check one or more apps in App Registrations to delete them here.",
                                )
                                .into_any()
                        } else {
                            view! {
                                <div class="bulk-action">
                                    <Body1 class="bulk-action__danger">
                                        {move || {
                                            format!(
                                                "Permanently delete the {} selected app registration(s). This cannot be undone.",
                                                session.selected_app_ids.with(|s| s.len()),
                                            )
                                        }}
                                    </Body1>
                                    <div class="confirm-gate">
                                        <Body1 class="confirm-gate__label">
                                            "Type "<strong>"DELETE"</strong>" to confirm."
                                        </Body1>
                                        <Input value=delete_confirm placeholder="DELETE" />
                                    </div>
                                    <div class="actions-row">
                                        <Button
                                            class="button--danger"
                                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                                            on_click=Box::new(do_delete)
                                            disabled=Signal::derive(move || busy.get() || !delete_ok.get())
                                        >
                                            "Delete selected apps"
                                        </Button>
                                    </div>
                                </div>
                            }
                                .into_any()
                        }
                    }
                    _ => {
                        view! {
                            <div class="bulk-action">
                                <Body1>
                                    "Create apps from a JSON array, e.g. [{\"displayName\":\"App A\",\"signInAudience\":\"AzureADMyOrg\"}]. Validate first to check inputs without creating anything."
                                </Body1>
                                <Textarea value=create_json />
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                        on_click=Box::new(move |_| do_create(true))
                                        disabled=Signal::derive(move || busy.get())
                                    >
                                        "Validate"
                                    </Button>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(move |_| do_create(false))
                                        disabled=Signal::derive(move || busy.get())
                                    >
                                        "Create apps"
                                    </Button>
                                </div>
                            </div>
                        }
                            .into_any()
                    }
                }}
            </div>
            {move || {
                busy.get()
                    .then(|| {
                        view! {
                            <div class="actions-row">
                                <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                <Body1>
                                    {move || match progress.get() {
                                        Some(p) if p.total > 0 => {
                                            format!("Working… ({}/{})", p.done, p.total)
                                        }
                                        _ => "Working…".to_string(),
                                    }}
                                </Body1>
                            </div>
                        }
                    })
            }}
            {move || {
                summary
                    .get()
                    .map(|s| {
                        // Warn-tone the summary when any item failed, so a
                        // partial success doesn't read as all-green.
                        let cls = if failures.with(|f| f.is_empty()) {
                            "alert alert--ok"
                        } else {
                            "alert alert--warn"
                        };
                        view! { <div class=cls>{s}</div> }
                    })
            }}
            {move || {
                let fs = failures.get();
                (!fs.is_empty())
                    .then(|| {
                        view! {
                            <div class="bulk-failures">
                                <Body1 class="bulk-failures__title">
                                    {format!("{} item(s) failed:", fs.len())}
                                </Body1>
                                <ul class="bulk-failures__list">
                                    {fs
                                        .into_iter()
                                        .map(|f| {
                                            view! {
                                                <li>
                                                    <span class="mono">{f.label}</span>
                                                    " — "
                                                    {f.reason}
                                                </li>
                                            }
                                        })
                                        .collect_view()}
                                </ul>
                            </div>
                        }
                    })
            }}
            {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
        </main>
    }
}
