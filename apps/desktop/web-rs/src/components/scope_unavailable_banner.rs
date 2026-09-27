//! Banner shown when effective mailbox scoping (the held-permissions "Scope"
//! column) couldn't be resolved — a genuine 403 / consent gap, e.g. the
//! signed-in user holds the Entra Exchange-administrator role but lacks the
//! effective EXO "Role Management" RBAC role, or `Exchange.ManageAsApp` isn't
//! consented. Offers "Grant consent & retry" when the failure is
//! `consent_required`, "Verify identity & retry" when it is
//! `interaction_required` (an Exchange MFA policy), plus a plain Retry. Shared by the managed-identity and
//! enterprise-app held-permission views so the affordance stays identical.

use azapptoolkit_dto::UiError;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::bindings::auth;
use crate::components::ui::Callout;
use crate::components::verify_identity_button::{VERIFY_IDENTITY_MESSAGE, VerifyIdentityButton};
use crate::hooks::use_command::use_command;

#[component]
pub fn ScopeUnavailableBanner(
    /// The resolution error that drives the banner.
    error: UiError,
    /// Re-run the scope resolution (the caller bumps its reload). Invoked after a
    /// successful consent grant and by the explicit Retry button.
    #[prop(into)]
    on_retry: Callback<()>,
) -> impl IntoView {
    // The feature key is stated once: it is both what this banner's button
    // consents and what `cmd.run`'s own recovery toast would offer.
    let cmd = use_command().with_consent_feature("exchange");
    let needs_consent = error.is_consent_required();
    // A Conditional Access step-up for Exchange (`interaction_required`): our
    // wording, not the AADSTS text, and the Exchange step-up as its lever.
    let needs_step_up = error.is_interaction_required();
    let message = if needs_step_up {
        VERIFY_IDENTITY_MESSAGE.to_string()
    } else {
        error.message.clone()
    };

    let on_consent = move |_| {
        cmd.run(
            move |()| on_retry.run(()),
            move |tenant_id| async move {
                auth::request_scope_consent(&tenant_id, cmd.consent_feature).await
            },
        );
    };
    let on_retry_click = move |_| on_retry.run(());

    view! {
        // `role="status"` so the banner — inserted after an async scope
        // resolution fails — is announced to assistive tech, not silently shown.
        <Callout tone="warn" role="status">
            <Body1>
                {format!("Mailbox scoping (Scope column) unavailable — {message}")}
            </Body1>
            <div class="actions-row">
                {needs_consent
                    .then(|| {
                        view! {
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                on_click=Box::new(on_consent)
                                disabled=Signal::derive(move || cmd.busy.get())
                            >
                                "Grant consent & retry"
                            </Button>
                        }
                    })}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(on_retry_click)
                >
                    "Retry"
                </Button>
            </div>
            {needs_step_up
                .then(|| {
                    view! { <VerifyIdentityButton features=&["exchange"] on_verified=on_retry /> }
                })}
            {move || {
                cmd.error.get().map(|m| view! { <Body1 class="form-error">{m}</Body1> })
            }}
        </Callout>
    }
}
