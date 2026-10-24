//! The load-failure surface of a detail-pane tab that reads a premium Graph
//! surface on its own on-demand scope (Activity, Conditional Access) — one
//! lever per failure class, so none is a dead end.
//!
//! The backend pre-acquires the tab's token, so a missing consent arrives
//! typed (`consent_required`) and gets the grant round trip here, a
//! Conditional Access step-up (`interaction_required`) gets "Verify identity &
//! retry", the feature's own `*_unavailable` code (no license, no role, a
//! transient read failure — worded by the backend) a notice, and anything else
//! `DetailLoadError` with Retry. A dead session or a rejected token needs the
//! session's lever, not an inline one: the tab raises it right after its
//! await (`Session::report_if_session_lost`), where it can check the tenant.
//! The same split as the Provisioning tab, which grew it first.

use azapptoolkit_dto::UiError;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::auth;
use crate::components::ui::{Callout, DetailLoadError};
use crate::components::verify_identity_button::{VERIFY_IDENTITY_MESSAGE, VerifyIdentityButton};
use crate::state::use_session;

#[component]
pub fn FeatureLoadError(
    error: UiError,
    /// The consent feature whose scope the tab reads (`"audit_log"`,
    /// `"policy"`) — what "Grant consent & retry" requests.
    consent_feature: &'static str,
    /// The same feature as a step-up list, for `VerifyIdentityButton`.
    step_up_features: &'static [&'static str],
    /// The tab's graceful-degradation code (`"activity_unavailable"`,
    /// `"ca_unavailable"`), whose message the backend already worded.
    unavailable_code: &'static str,
    /// What the tab says when its scope is not consented yet.
    consent_text: &'static str,
    /// Re-run the tab's load (after a grant, a step-up or a Retry click).
    #[prop(into)]
    on_retry: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let consenting = RwSignal::new(false);
    let on_consent = move |_| {
        // One browser round trip at a time: a double click must not open two.
        if consenting.get_untracked() {
            return;
        }
        let Some(t) = session.active_tenant.get_untracked() else {
            return;
        };
        consenting.set(true);
        leptos::task::spawn_local(async move {
            let res = auth::request_scope_consent(&t.tenant_id, consent_feature).await;
            // The consent prompt is answered minutes later, perhaps after a
            // sign-out: a toast then would surface at the next sign-in.
            if !session.is_active_tenant(&t.tenant_id) {
                return;
            }
            match res {
                Ok(()) => {
                    on_retry.try_run(());
                }
                Err(e) => session.report_command_error_for(&e, consent_feature),
            }
            consenting.set(false);
        });
    };

    if error.is_consent_required() {
        view! {
            <Callout tone="warn">
                <span class="ui-text">{consent_text}</span>
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(on_consent)
                        disabled=Signal::derive(move || consenting.get())
                    >
                        "Grant consent & retry"
                    </Button>
                </div>
            </Callout>
        }
        .into_any()
    } else if error.is_interaction_required() {
        // Our wording, not the AADSTS text, and the step-up as its lever.
        view! {
            <Callout tone="warn">
                <span class="ui-text">{VERIFY_IDENTITY_MESSAGE}</span>
                <VerifyIdentityButton features=step_up_features on_verified=on_retry />
            </Callout>
        }
        .into_any()
    } else if error.code == unavailable_code {
        view! { <Callout tone="warn">{error.message}</Callout> }.into_any()
    } else {
        view! { <DetailLoadError error=error on_retry=on_retry /> }.into_any()
    }
}
