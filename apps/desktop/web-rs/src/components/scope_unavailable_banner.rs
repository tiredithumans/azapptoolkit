//! Banner shown when effective mailbox scoping (the held-permissions "Scope"
//! column) couldn't be resolved — a genuine 403 / consent gap, e.g. the
//! signed-in user holds the Entra Exchange-administrator role but lacks the
//! effective EXO "Role Management" RBAC role, or `Exchange.ManageAsApp` isn't
//! consented. Offers "Grant consent & retry" when the failure is
//! `consent_required`, plus a plain Retry. Shared by the managed-identity and
//! enterprise-app held-permission views so the affordance stays identical.

use azapptoolkit_dto::UiError;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::bindings::auth;
use crate::state::use_session;

#[component]
pub fn ScopeUnavailableBanner(
    /// The resolution error that drives the banner.
    error: UiError,
    /// Re-run the scope resolution (the caller bumps its reload). Invoked after a
    /// successful consent grant and by the explicit Retry button.
    #[prop(into)]
    on_retry: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let consenting = RwSignal::new(false);
    let consent_error: RwSignal<Option<String>> = RwSignal::new(None);
    let needs_consent = error.code == "consent_required";
    let message = error.message.clone();

    let on_consent = move |_| {
        if consenting.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        consenting.set(true);
        consent_error.set(None);
        leptos::task::spawn_local(async move {
            match auth::request_scope_consent(&t.tenant_id, "exchange").await {
                Ok(()) => on_retry.run(()),
                Err(e) => consent_error.set(Some(e.message)),
            }
            consenting.set(false);
        });
    };
    let on_retry_click = move |_| on_retry.run(());

    view! {
        // `role="status"` so the banner — inserted after an async scope
        // resolution fails — is announced to assistive tech, not silently shown.
        <div class="alert alert--warn" role="status">
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
                                disabled=Signal::derive(move || consenting.get())
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
            {move || {
                consent_error.get().map(|m| view! { <Body1 class="form-error">{m}</Body1> })
            }}
        </div>
    }
}
