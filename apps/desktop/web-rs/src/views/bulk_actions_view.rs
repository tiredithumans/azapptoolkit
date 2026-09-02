//! Bulk actions page. Two sections behind a sub-tab bar:
//!
//! - **Selected apps** — the shared [`BulkActionBar`] (Grant consent / Remove
//!   expired credentials / Delete) over the apps checked in the App
//!   Registrations list (`session.tenant_ui.selected_app_ids`). The bar is the single home
//!   of the bulk command-calling logic; this page just hosts it. It reviews the
//!   selection by name too — that disclosure started here and moved into the
//!   bar, where the other four hosts get it as well.
//! - **Create apps** — a JSON form that ignores the selection.
//!
//! Promoted from a modal to a page: the modal used to cover the very App
//! Registrations selection it operates on. The selection persists in the
//! session, so checking apps in the list and then opening this page works.

use crate::hooks::use_progress_stream::use_progress_stream;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Textarea};

use crate::bindings::bulk;
use crate::bindings::events;
use crate::components::bulk_action_bar::{BulkAction, BulkActionBar, BulkFailure, BulkProgressRow};
use crate::components::icon::IconName;
use crate::components::ui::{Callout, EmptyState, SectionHeader, TabBar, TabBarItem};
use crate::state::use_session;

#[component]
pub fn BulkActionsView() -> impl IntoView {
    let session = use_session();
    let tab = RwSignal::new(String::from("selected"));

    // After a successful selection-driven run, refetch the App Registrations
    // list (a delete / remove-expired sweep invalidates the backend cache). The
    // bar drops the ids a delete actually removed from the selection itself, so
    // the host only refreshes.
    let on_done = Callback::new(move |_| session.bump_apps_reload());

    // ---- Create-apps flow state (the only non-selection action) -------------
    let busy = RwSignal::new(false);
    let summary: RwSignal<Option<String>> = RwSignal::new(None);
    let failures: RwSignal<Vec<BulkFailure>> = RwSignal::new(Vec::new());
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    // Live per-app progress emitted by the backend bulk loop ("bulk-progress").
    let progress: RwSignal<Option<bulk::BulkProgress>> = RwSignal::new(None);
    use_progress_stream(progress, events::bulk_progress);

    let create_json = RwSignal::new(String::new());

    // Clear any prior create result/error when the active tab changes so
    // messages don't bleed across sections.
    Effect::new(move |_| {
        let _ = tab.get();
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        progress.set(None);
    });

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
                            // The apps this flow reports on were never created,
                            // so there is no object id to re-select — the only
                            // shape in the app where that is true.
                            object_id: None,
                            // `None` for a validation rejection (`invalid`),
                            // which never reached the backend and so says
                            // nothing about the session.
                            code: o.error.as_ref().map(|e| e.code.clone()),
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

    view! {
        <main class="tool-page">
            <SectionHeader
                title="Bulk Actions".to_string()
                crumb="Act on the App Registrations you've selected, or create apps in bulk"
                    .to_string()
            />
            <TabBar
                items=vec![
                    TabBarItem { value: "selected", label: "Selected apps" },
                    TabBarItem { value: "create", label: "Create apps" },
                ]
                selected=tab
            />
            <div class="bulk-tab">
                {move || match tab.get().as_str() {
                    "create" => {
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
                                {move || {
                                    busy.get()
                                        .then(|| {
                                            // The bar's row, verbatim: these apps
                                            // don't exist yet, so `current_app`
                                            // is already a display name and there
                                            // is no id map to resolve it against.
                                            view! { <BulkProgressRow progress=progress names=None /> }
                                        })
                                }}
                                {move || {
                                    summary
                                        .get()
                                        .map(|s| {
                                            let tone = if failures.with(|f| f.is_empty()) {
                                                "ok"
                                            } else {
                                                "warn"
                                            };
                                            view! { <Callout tone=tone>{s}</Callout> }
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
                            </div>
                        }
                            .into_any()
                    }
                    _ => {
                        // The bar self-gates (visible while there's a selection or
                        // a result on screen); the hint shows whenever nothing is
                        // checked, including right after a run clears the selection.
                        view! {
                            // WHAT is selected is reviewed in the bar's armed
                            // panel now — one implementation, and it reads the
                            // same on the four hosts that never had it.
                            <BulkActionBar
                                names=Signal::derive(move || session.tenant_ui.app_names.get())
                                selection=session.tenant_ui.selected_app_ids
                                actions=Signal::derive(|| {
                                    vec![
                                        BulkAction::Grant,
                                        BulkAction::RemoveExpired,
                                        BulkAction::Delete,
                                    ]
                                })
                                on_done=on_done
                            />
                            <Show when=move || session.tenant_ui.selected_app_ids.with(|s| s.is_empty()) fallback=|| ()>
                                <EmptyState
                                    icon=IconName::AppWindow
                                    title="No apps selected".to_string()
                                    body="Check one or more apps in App Registrations, then return here (or use the inline bar on the list) to grant consent, remove expired credentials, or delete them."
                                        .to_string()
                                />
                            </Show>
                        }
                            .into_any()
                    }
                }}
            </div>
        </main>
    }
}
