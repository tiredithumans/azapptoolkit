//! The load-failure surface of a detail-pane tab that reads on its own
//! on-demand scope (Activity, Conditional Access, Provisioning) — one lever per
//! failure class, so none is a dead end. The primitive for that pattern, as
//! `DetailLoadError` is for a plain load failure (which it falls back to).
//!
//! The backend pre-acquires the tab's token, so a missing consent arrives
//! typed (`consent_required`) and gets the grant round trip here, a
//! Conditional Access step-up (`interaction_required`) gets "Verify identity &
//! retry", the feature's own `*_unavailable` code (worded by the backend) or a
//! 403 with a `forbidden_lead` a notice, and anything else `DetailLoadError`
//! with Retry.
//!
//! **The session levers are raised here, not by the caller.** A dead session
//! or a rejected token needs the session's toast (`Session::report_if_session_lost`),
//! which no inline button can offer; this component raises it once per mount
//! (the toast dedupes by key, so a tab re-rendering it stacks nothing) and
//! never while signed out, when it would surface at the next sign-in — the
//! `ScopeUnavailableBanner` contract. A caller only renders it from its `Err`
//! arm and passes the reload.

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
    /// `"policy"`, `"sync"`) — what "Grant consent & retry" requests.
    consent_feature: &'static str,
    /// The same feature as a step-up list, for `VerifyIdentityButton`.
    step_up_features: &'static [&'static str],
    /// What the tab says when its scope is not consented yet.
    consent_text: &'static str,
    /// The tab's graceful-degradation code (`"activity_unavailable"`,
    /// `"ca_unavailable"`), whose message the backend already worded.
    #[prop(optional)]
    unavailable_code: Option<&'static str>,
    /// When set, a `forbidden` (403) error is a role / license notice: this
    /// sentence, then the backend's message (which carries the catalog
    /// remediation) — for a tab whose backend does not fold the 403 into an
    /// `*_unavailable` code.
    #[prop(optional)]
    forbidden_lead: Option<&'static str>,
    /// Re-run the tab's load (after a grant, a step-up or a Retry click).
    #[prop(into)]
    on_retry: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    if session.active_tenant.with_untracked(Option::is_some) {
        session.report_if_session_lost(&error);
    }
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
    } else if unavailable_code == Some(error.code.as_str()) {
        view! { <Callout tone="warn">{error.message}</Callout> }.into_any()
    } else if let Some(lead) = forbidden_lead.filter(|_| error.code == "forbidden") {
        view! {
            <Callout tone="warn">
                <span class="ui-text">{lead}</span>
                <span class="ui-text">{error.message}</span>
            </Callout>
        }
        .into_any()
    } else {
        view! { <DetailLoadError error=error on_retry=on_retry /> }.into_any()
    }
}
