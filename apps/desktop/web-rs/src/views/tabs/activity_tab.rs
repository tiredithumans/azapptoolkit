//! Activity / change-log tab — recent directory audit entries for a directory
//! object (an app registration or an enterprise application) and, optionally, a
//! second related object id (its paired SP / app registration). Read-only;
//! degrades gracefully when the tenant lacks an Entra ID P1/P2 license or the
//! account a reporting role, and offers the lever for every other failure
//! (Grant consent for AuditLog.Read.All, Verify identity, Re-authenticate).

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::activity::{self, ActivityLogItem};
use crate::bindings::applications::ApplicationDetail;
use crate::components::feature_load_error::FeatureLoadError;
use crate::components::ui::{Badge, BadgeTone, Callout, DataTable, Skeleton, SkeletonList};
use crate::state::use_session;

use crate::util::{fmt_datetime, no_tenant};

/// App-registration Activity tab: changes to the app object and its paired SP.
#[component]
pub fn ActivityTab(#[prop(into)] detail: Signal<Arc<ApplicationDetail>>) -> impl IntoView {
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
            <SignInSummary app_id=app_id reload=reload />
            <header class="row-between">
                <strong>"Recent directory changes"</strong>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| reload.update(|n| *n += 1))
                >
                    "Refresh"
                </Button>
            </header>
            <span class="ui-text">
                "Administrative changes recorded in the Entra ID audit log for this application (and its paired object, when present). Requires AuditLog.Read.All consent and an Entra ID P1/P2 license; retained for 30 days."
            </span>

            <Suspense fallback=move || view! { <SkeletonList rows=5 /> }>
                {move || Suspend::new(async move {
                    match logs.await {
                        Ok(list) => activity_table(list).into_any(),
                        // Every failure gets its lever: consent, step-up, the
                        // session's toast, the backend's "activity_unavailable"
                        // notice (license / role / transient), or Retry.
                        Err(e) => activity_error(e, reload).into_any(),
                    }
                })}
            </Suspense>
        </div>
    }
}

/// Per-app sign-in summary above the change log: the SP's most recent recorded
/// sign-in, so an admin can gauge "is this still used?" before disabling or
/// deleting. Read-only; degrades gracefully (missing license/role ⇒ a notice)
/// and never blocks the change log below.
///
/// Holds **no lever of its own**: both halves read on the one
/// `AuditLog.Read.All` token, so a missing consent, a step-up or a dead session
/// fails the change log the same way, and its `FeatureLoadError` is the one
/// place offering the fix — this half only names the cause in a muted line.
/// It shares the panel's `reload`, so that fix (or the header's Refresh)
/// re-runs both halves.
#[component]
fn SignInSummary(#[prop(into)] app_id: Signal<String>, reload: RwSignal<u32>) -> impl IntoView {
    let session = use_session();

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
                view! { <Skeleton width="50%".to_string() height="14px".to_string() /> }
            }>
                {move || Suspend::new(async move {
                    match activity.await {
                        Ok(dto) if dto.available => {
                            let text = match dto.last_sign_in_date_time {
                                Some(d) => {
                                    format!("Last recorded sign-in: {}", fmt_datetime(d))
                                }
                                None => "No sign-in recorded in the reporting window.".to_string(),
                            };
                            view! { <span class="ui-text">{text}</span> }.into_any()
                        }
                        // The change log below reads on the same token and
                        // fails the same way, so its `FeatureLoadError` holds
                        // the one lever; this half only says why it's empty.
                        Ok(dto) if dto.consent_required => {
                            view! {
                                <span class="ui-text muted">
                                    "Needs AuditLog.Read.All consent — grant it below."
                                </span>
                            }
                                .into_any()
                        }
                        Ok(dto) => {
                            view! {
                                <Callout tone="warn">{dto.message.unwrap_or_default()}</Callout>
                            }
                                .into_any()
                        }
                        Err(e) => {
                            view! { <span class="ui-text muted">{sign_in_summary_note(&e)}</span> }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

/// The sign-in summary's muted line for a failed read — the cause only; the
/// change log's `FeatureLoadError` (or the session's toast) carries the lever.
fn sign_in_summary_note(e: &azapptoolkit_dto::UiError) -> &'static str {
    if e.is_interaction_required() {
        "Needs identity verification — verify it below."
    } else if e.is_reauth_fatal() || e.is_unauthorized() {
        "Unavailable until your session is renewed — see the notice."
    } else if e.is_consent_required() {
        "Needs AuditLog.Read.All consent — grant it below."
    } else {
        "Couldn't read sign-in activity just now — use Refresh."
    }
}

/// The change log's load failure — the Activity tab's one lever surface (the
/// sign-in summary above reads on the same `audit_log` token and defers to it).
fn activity_error(e: azapptoolkit_dto::UiError, reload: RwSignal<u32>) -> impl IntoView {
    view! {
        <FeatureLoadError
            error=e
            consent_feature="audit_log"
            step_up_features=&["audit_log"]
            consent_text="The activity log needs admin consent to AuditLog.Read.All."
            unavailable_code="activity_unavailable"
            on_retry=Callback::new(move |()| reload.update(|n| *n += 1))
        />
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
        .map(fmt_datetime)
        .unwrap_or_else(|| "—".into());
    let result = item.result.unwrap_or_else(|| "—".into());
    let result_tone = match result.as_str() {
        "success" => BadgeTone::Ok,
        "failure" => BadgeTone::Danger,
        _ => BadgeTone::Neutral,
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
                <Badge label=result tone=result_tone />
            </td>
        </tr>
    }
}
