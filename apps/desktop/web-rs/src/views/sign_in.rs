//! Entra ID sign-in.
//! Single-tenant: the OAuth authority is built from `AZAPPTOOLKIT_TENANT_ID` on
//! the backend, so there is no tenant input to render here.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::bindings::auth;
use crate::components::ui::Card;
use crate::state::use_session;

#[component]
pub fn SignInScreen() -> impl IntoView {
    let session = use_session();
    let busy = RwSignal::new(false);
    // (message, hint): the hint translates the machine error code into a
    // recovery step, since "error [keyring]" means nothing to most users.
    let error: RwSignal<Option<(String, &'static str)>> = RwSignal::new(None);

    let on_sign_in = move |_| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let session = session;
        leptos::task::spawn_local(async move {
            match auth::sign_in().await {
                Ok(outcome) => session.set_active_tenant(Some(outcome.tenant)),
                // Surface the error code alongside the message (matches the
                // detail-pane `error [code]: message` convention) so failures
                // are diagnosable.
                Err(err) => error.set(Some((
                    format!("error [{}]: {}", err.code, err.message),
                    recovery_hint(&err.code),
                ))),
            }
            busy.set(false);
        });
    };

    view! {
        <main class="signin-shell">
            <Card elevation=4 class="signin-card".to_string()>
                <div class="signin-card__brand">
                    <span class="shell__brand-mark">"a"</span>
                    <span>"azapptoolkit"</span>
                </div>
                <h1 class="signin-card__title">"Sign in to your tenant"</h1>
                <Body1>
                    "Use Entra ID to manage App Registrations, permissions, and run security audits."
                </Body1>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(on_sign_in)
                    disabled=Signal::derive(move || busy.get())
                >
                    {move || {
                        if busy.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                .into_any()
                        } else {
                            view! { "Sign in with Entra ID" }.into_any()
                        }
                    }}
                </Button>
                {move || {
                    error
                        .get()
                        .map(|(msg, hint)| {
                            view! {
                                <Body1 class="signin-error">
                                    {format!("Sign-in failed: {msg}")}
                                </Body1>
                                <Body1 class="signin-hint">{hint}</Body1>
                            }
                        })
                }}
            </Card>
        </main>
    }
}

/// One actionable recovery step per `UiError.code` (codes from
/// `azapptoolkit-dto`'s `AuthError` mapping).
fn recovery_hint(code: &str) -> &'static str {
    match code {
        "network" => "Check your network connection, then select Sign in to retry.",
        "keyring" => {
            "The OS credential store couldn't be reached — unlock your \
             keychain/credential manager, then retry."
        }
        "authorization" | "consent_required" => {
            "The sign-in was declined. An administrator may need to grant the app \
             consent in this tenant before you can sign in."
        }
        "token_exchange" => {
            "Entra ID rejected the token exchange — verify the app's client and \
             tenant IDs are configured for this tenant, then retry."
        }
        "cancelled" => "The browser sign-in was closed before completing — retry when ready.",
        _ => "Check your network and try again — selecting Sign in retries.",
    }
}
