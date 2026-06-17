//! Activity / change-log tab — recent directory audit entries for a directory
//! object (an app registration or an enterprise application) and, optionally, a
//! second related object id (its paired SP / app registration). Read-only;
//! degrades gracefully when AuditLog.Read.All is un-consented or the tenant
//! lacks an Entra ID P1/P2 license.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::bindings::activity::{self, ActivityLogItem};
use crate::bindings::applications::ApplicationDetail;
use crate::bindings::auth;
use crate::components::ui::DataTable;
use crate::state::use_session;

use crate::util::no_tenant;

/// App-registration Activity tab: changes to the app object and its paired SP.
#[component]
pub fn ActivityTab(#[prop(into)] detail: Signal<ApplicationDetail>) -> impl IntoView {
    let app_id = Signal::derive(move || detail.with(|d| d.application.app_id.clone()));
    let primary = Signal::derive(move || detail.with(|d| d.application.id.clone()));
    let secondary = Signal::derive(move || {
        detail.with(|d| d.service_principal.as_ref().map(|sp| sp.id.clone()))
    });
    view! { <ActivityPanel app_id=app_id primary_id=primary secondary_id=secondary /> }
}

/// Core activity feed for one or two related directory-object ids. Shared by the
/// app-registration and enterprise-application detail panes.
#[component]
pub fn ActivityPanel(
    #[prop(into)] app_id: Signal<String>,
    #[prop(into)] primary_id: Signal<String>,
    #[prop(into)] secondary_id: Signal<Option<String>>,
) -> impl IntoView {
    let session = use_session();
    let reload = RwSignal::new(0_u32);

    let logs = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let primary = primary_id.get();
        let secondary = secondary_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            activity::list_directory_audits_for_app(&t.tenant_id, &primary, secondary.as_deref())
                .await
        }
    });

    view! {
        <div class="activity-tab">
            <SignInSummary app_id=app_id />
            <header class="row-between">
                <strong>"Recent directory changes"</strong>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| reload.update(|n| *n += 1))
                >
                    "Refresh"
                </Button>
            </header>
            <Body1>
                "Administrative changes recorded in the Entra ID audit log for this application (and its paired object, when present). Requires AuditLog.Read.All consent and an Entra ID P1/P2 license; retained for 30 days."
            </Body1>

            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" /> }
            }>
                {move || Suspend::new(async move {
                    match logs.await {
                        Ok(list) => activity_table(list).into_any(),
                        // Graceful degradation: the backend tags missing
                        // consent/license as "activity_unavailable".
                        Err(e) if e.code == "activity_unavailable" => {
                            view! { <div class="alert alert--warn">{e.message}</div> }.into_any()
                        }
                        Err(e) => view! { <Body1 class="form-error">{e.message}</Body1> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

/// Per-app sign-in summary above the change log: the SP's most recent recorded
/// sign-in, so an admin can gauge "is this still used?" before disabling or
/// deleting. Read-only; degrades gracefully (missing scope/license ⇒ a notice,
/// missing consent ⇒ a "Grant consent & retry" button) and never blocks the
/// change log below — the backend always returns a populated DTO.
#[component]
fn SignInSummary(#[prop(into)] app_id: Signal<String>) -> impl IntoView {
    let session = use_session();
    let reload = RwSignal::new(0_u32);

    let activity = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let app_id = app_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            activity::get_app_sign_in_activity(&t.tenant_id, &app_id).await
        }
    });

    view! {
        <div class="signin-summary">
            <strong>"Sign-in activity"</strong>
            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" /> }
            }>
                {move || Suspend::new(async move {
                    match activity.await {
                        Ok(dto) if dto.available => {
                            let text = match dto.last_sign_in_date_time {
                                Some(d) => {
                                    format!("Last recorded sign-in: {}", d.format("%Y-%m-%d %H:%M UTC"))
                                }
                                None => "No sign-in recorded in the reporting window.".to_string(),
                            };
                            view! { <Body1>{text}</Body1> }.into_any()
                        }
                        Ok(dto) if dto.consent_required => {
                            let msg = dto.message.unwrap_or_default();
                            let grant = move |_| {
                                leptos::task::spawn_local(async move {
                                    let Some(t) = session.active_tenant.get_untracked() else {
                                        return;
                                    };
                                    match auth::request_scope_consent(&t.tenant_id, "audit_log")
                                        .await
                                    {
                                        Ok(()) => reload.update(|n| *n += 1),
                                        Err(e) => {
                                            session.toast_error(e.message, None);
                                        }
                                    }
                                });
                            };
                            view! {
                                <div class="alert alert--warn">
                                    {msg}
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(grant)
                                    >
                                        "Grant consent & retry"
                                    </Button>
                                </div>
                            }
                                .into_any()
                        }
                        Ok(dto) => {
                            view! {
                                <div class="alert alert--warn">{dto.message.unwrap_or_default()}</div>
                            }
                                .into_any()
                        }
                        Err(e) => view! { <Body1 class="form-error">{e.message}</Body1> }.into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

fn activity_table(list: Vec<ActivityLogItem>) -> impl IntoView {
    view! {
        <DataTable
            headers=vec!["When", "Activity", "Initiated by", "Target", "Result"]
            rows=list
            empty_message="No recent changes recorded in the audit window."
            row=|item| activity_row(item).into_any()
        />
    }
}

fn activity_row(item: ActivityLogItem) -> impl IntoView {
    let when = item
        .activity_date_time
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| "—".into());
    let result = item.result.unwrap_or_else(|| "—".into());
    let result_class = match result.as_str() {
        "success" => "badge badge--ok",
        "failure" => "badge badge--danger",
        _ => "badge",
    };
    let changed: Vec<String> = item
        .modified_properties
        .into_iter()
        .filter_map(|p| (!p.name.is_empty()).then_some(p.name))
        .collect();
    view! {
        <tr>
            <td class="mono">{when}</td>
            <td>
                <div class="permissions-cell__primary">{item.activity}</div>
                {(!changed.is_empty())
                    .then(|| {
                        view! {
                            <div class="permissions-cell__secondary">
                                {format!("Changed: {}", changed.join(", "))}
                            </div>
                        }
                    })}
            </td>
            <td>{item.initiated_by}</td>
            <td>{item.target_summary}</td>
            <td>
                <span class=result_class>{result}</span>
            </td>
        </tr>
    }
}
