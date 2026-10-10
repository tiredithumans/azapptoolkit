//! Bulk actions page. Two sections behind a sub-tab bar:
//!
//! - **Selected apps** — the shared [`BulkActionBar`] (Grant consent / Remove
//!   expired credentials / Delete) over the apps checked in the App
//!   Registrations list (`session.tenant_ui.selected_app_ids`). The bar is the single home
//!   of the bulk command-calling logic; this page just hosts it. It reviews the
//!   selection by name too — that disclosure started here and moved into the
//!   bar, where the other four hosts get it as well.
//! - **Create apps** — a JSON form that ignores the selection. "Load from
//!   file…" fills it from a CSV inventory or a JSON array (F283); the textarea
//!   stays the review surface, so a loaded file is validated and run exactly
//!   like a pasted one.
//!
//! Promoted from a modal to a page: the modal used to cover the very App
//! Registrations selection it operates on. The selection persists in the
//! session, so checking apps in the list and then opening this page works.

use crate::hooks::use_progress_stream::use_progress_stream;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Textarea};

use crate::bindings::bulk;
use crate::bindings::bulk::BulkCreateStatus;
use crate::bindings::events;
use crate::components::bulk_action_bar::{
    BulkAction, BulkActionBar, BulkFailure, BulkProgressRow, session_dead_error,
};
use crate::components::icon::IconName;
use crate::components::ui::{
    Callout, EmptyState, FormError, SectionHeader, TabBar, TabBarItem, tab_id,
};
use crate::state::use_session;
use crate::util::count_noun;

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
    // Shared with every `BulkActionBar`: a create shares the backend's one
    // bulk cancel flag with the bars' runs, so only one bulk run is in flight
    // at a time (see `TenantScopedUi::bulk_running`).
    let bulk_running = session.tenant_ui.bulk_running;
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

    // Its own flag, not `busy`: `busy` also shows the run's progress row, and
    // the file dialog is not a run.
    let loading = RwSignal::new(false);
    let load_file = move || {
        if busy.get() || loading.get() {
            return;
        }
        loading.set(true);
        leptos::task::spawn_local(async move {
            match bulk::load_bulk_create_specs_from_file().await {
                Ok(Some(specs)) => {
                    summary.set(None);
                    failures.set(Vec::new());
                    error.set(None);
                    // Pretty JSON so the operator can read (and edit) every row
                    // the file produced before validating it.
                    match serde_json::to_string_pretty(&specs) {
                        Ok(json) => create_json.set(json),
                        Err(e) => error.set(Some(e.to_string())),
                    }
                }
                Ok(None) => {}
                Err(e) => error.set(Some(e.message)),
            }
            loading.set(false);
        });
    };

    let do_create = move |validate_only: bool| {
        if busy.get() || loading.get() || bulk_running.get() {
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
        // Declaring a permission is not consenting to it; say so after a run
        // that declared any, so nobody reads "created" as "has access".
        let declares = specs.iter().any(|s| !s.permissions.is_empty());
        busy.set(true);
        bulk_running.set(true);
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        let tenant = session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                bulk_running.set(false);
                return;
            };
            let res = bulk::bulk_create_applications(&t.tenant_id, &specs, validate_only).await;
            // Land nothing for a tenant that is no longer active: the page
            // shows another tenant (or none), and the in-flight flag this run
            // would clear is that tenant's.
            if !session.is_active_tenant(&t.tenant_id) {
                busy.set(false);
                return;
            }
            match res {
                Ok(r) => {
                    let fails: Vec<BulkFailure> = r
                        .outcomes
                        .iter()
                        // A created row with a message is a partial success
                        // (an owner not added, a later step failed): the app
                        // exists, but not as the input described it.
                        .filter(|o| {
                            !matches!(
                                o.status,
                                BulkCreateStatus::Created | BulkCreateStatus::Valid
                            ) || o.message.is_some()
                        })
                        .map(|o| BulkFailure {
                            label: o.display_name.clone(),
                            reason: o
                                .message
                                .clone()
                                .unwrap_or_else(|| o.status.as_str().to_string()),
                            // The apps this flow reports on were never created,
                            // so there is no object id to re-select — the only
                            // shape in the app where that is true.
                            object_id: None,
                            // `None` for a rejection (`invalid`), which
                            // created nothing and says nothing about the
                            // session.
                            code: o.error.as_ref().map(|e| e.code.clone()),
                        })
                        .collect();
                    let ok = r.outcomes.len() - fails.len();
                    let consent_note = if declares
                        && !r.validate_only
                        && r.outcomes
                            .iter()
                            .any(|o| o.status == BulkCreateStatus::Created)
                    {
                        " Declared permissions are not consented yet — select the new apps in App Registrations and use Grant consent."
                    } else {
                        ""
                    };
                    summary.set(Some(format!(
                        "{}: {ok} ok, {}{}.{consent_note}",
                        if r.validate_only {
                            "Validated"
                        } else {
                            "Created"
                        },
                        count_noun(fails.len(), "problem", "problems"),
                        if r.cancelled { " (cancelled)" } else { "" }
                    )));
                    // A row that failed because the session died is the
                    // run stopping, not that app being broken: offer
                    // Re-authenticate like the bulk bar does.
                    if let Some(dead) = session_dead_error(&fails) {
                        session.report_if_session_dead(&dead);
                    }
                    failures.set(fails);
                    if !r.validate_only && !r.cancelled {
                        session.bump_apps_reload();
                    }
                }
                Err(e) => session.fail_inline(&e, "write", error),
            }
            busy.set(false);
            bulk_running.set(false);
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
                label="Bulk actions sections"
                panel_id="bulk-tab"
                items=vec![
                    TabBarItem { value: "selected", label: "Selected apps" },
                    TabBarItem { value: "create", label: "Create apps" },
                ]
                selected=tab
            />
            <div
                class="bulk-tab"
                id="bulk-tab"
                role="tabpanel"
                aria-labelledby=move || tab_id("bulk-tab", &tab.get())
            >
                {move || match tab.get().as_str() {
                    "create" => {
                        view! {
                            <div class="bulk-action">
                                <Body1>
                                    "Create apps from a JSON array, e.g. [{\"displayName\":\"App A\",\"signInAudience\":\"AzureADMyOrg\"}], or load a CSV inventory (DisplayName, SignInAudience, Description, Owners, Permissions). Owners are UPNs; permissions are declared, not consented. Validate first to check every name against the tenant without creating anything."
                                </Body1>
                                <Textarea value=create_json />
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                        on_click=Box::new(move |_| load_file())
                                        disabled=Signal::derive(move || busy.get() || loading.get())
                                    >
                                        "Load from file…"
                                    </Button>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                        on_click=Box::new(move |_| do_create(true))
                                        disabled=Signal::derive(move || {
                                            busy.get() || loading.get() || bulk_running.get()
                                        })
                                    >
                                        "Validate"
                                    </Button>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(move |_| do_create(false))
                                        disabled=Signal::derive(move || {
                                            busy.get() || loading.get() || bulk_running.get()
                                        })
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
                                                        {format!("{} failed:", count_noun(fs.len(), "item", "items"))}
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
                                {move || error.get().map(|e| view! { <FormError>{e}</FormError> })}
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
