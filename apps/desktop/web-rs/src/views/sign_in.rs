//! Entra ID sign-in.
//! Single-tenant: the OAuth authority is built from `AZAPPTOOLKIT_TENANT_ID` on
//! the backend, so there is no tenant input to render here — the card *names*
//! the tenant it is about to redirect to, and links back to the config form for
//! when that name is the thing that is wrong.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use crate::bindings::auth;
use crate::components::ui::Card;
use crate::state::use_session;

#[component]
pub fn SignInScreen(
    /// The tenant this build authenticates against — the domain or GUID
    /// currently configured. Named on the card because it is the last moment a
    /// wrong one is cheap: after the button, a well-formed but wrong id costs a
    /// browser round trip and comes back as an opaque `token_exchange` failure.
    tenant: String,
    /// Reopens the (prefilled) config form. The escape hatch for an install
    /// pointed at the wrong tenant, which can reach no other surface: sign-in is
    /// all it has, and Settings → Tenant connection is behind the sign-in it
    /// can never complete.
    #[prop(into)]
    on_reconfigure: Callback<()>,
) -> impl IntoView {
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
                    recovery_hint(&err.code, &err.message),
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
                {(!tenant.is_empty())
                    .then(|| {
                        view! {
                            <Body1 class="signin-hint">
                                {format!("Signing in to {tenant} · ")}
                                <button
                                    type="button"
                                    class="link-btn"
                                    on:click=move |_| on_reconfigure.run(())
                                >
                                    "Change"
                                </button>
                            </Body1>
                        }
                    })}
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

/// The launch placeholder shown while the backend tries to revive the previous
/// session from the OS keyring (`bindings::auth::restore_session`).
///
/// It exists to hold the sign-in card back for the fraction of a second that
/// takes. Painting the card first and swapping it for the shell mid-blink is
/// worse than a brief wait: the operator reads "sign in" and reaches for it, and
/// a click that lands just as the restore completes hits whatever replaced the
/// button. Deliberately the same card shell as [`SignInScreen`] so the two are
/// one surface changing its message, not two screens flickering past each other.
#[component]
pub fn RestoringSession() -> impl IntoView {
    view! {
        <main class="signin-shell">
            <Card elevation=4 class="signin-card".to_string()>
                <div class="signin-card__brand">
                    <span class="shell__brand-mark">"a"</span>
                    <span>"azapptoolkit"</span>
                </div>
                <h1 class="signin-card__title">"Restoring your session"</h1>
                <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
            </Card>
        </main>
    }
}

/// One actionable recovery step per `UiError.code` (codes from
/// `azapptoolkit-dto`'s `AuthError` mapping), refined by the `AADSTSnnnnn` code
/// Entra embeds in the message whenever it sent one.
///
/// The code-level arms below are broad by necessity: `token_exchange` alone
/// covers every rejection Entra can hand back at the exchange — wrong tenant,
/// unknown client id, unregistered redirect URI, a Conditional Access block.
/// The AADSTS number is the part that says *which*, and the app was already
/// holding it: `azapptoolkit-auth`'s `redacted_aad_error` deliberately keeps
/// that number while dropping the tenant/user GUIDs, correlation ids and client
/// IPs around it. Until now the operator read the number on screen and had to
/// leave the app to search it.
fn recovery_hint(code: &str, message: &str) -> &'static str {
    if let Some(specific) = aadsts_hint(message) {
        return specific;
    }
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

/// The `AADSTSnnnnn` codes an operator actually hits at sign-in, each translated
/// into the step that clears it.
///
/// Deliberately a short list. A confidently wrong instruction is worse than the
/// generic one, so anything not listed here falls back to the code-level hint
/// rather than guessing — and the raw code stays on the error line above the
/// hint either way, for anyone filing a ticket.
fn aadsts_hint(message: &str) -> Option<&'static str> {
    let idx = message.find("AADSTS")?;
    let digits: String = message[idx + "AADSTS".len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    Some(match digits.as_str() {
        // The two "you are pointed at the wrong directory" shapes. A well-formed
        // but wrong tenant GUID fails exactly like this, which is why the hint
        // names Settings: the ids are editable there.
        "90002" | "900023" => {
            "That tenant doesn't resolve. Check the tenant ID under Settings → \
             Tenant connection — a well-formed but wrong GUID fails exactly this way."
        }
        "700016" | "700054" => {
            "No app registration with this client ID exists in the configured \
             tenant. Check the client ID under Settings → Tenant connection, or \
             that you're pointed at the right tenant."
        }
        // Right tenant, wrong account.
        "50020" | "50034" | "500011" => {
            "Your account isn't in this tenant (or is a guest without access here). \
             Sign in with an account from the configured tenant."
        }
        "50105" => {
            "Your account isn't assigned to this application. An administrator has \
             to assign you, or turn off the assignment requirement on it."
        }
        "50126" => "That username or password was rejected — retry, or reset your password.",
        // Consent. Distinct from a decline: one needs an admin, the other needs
        // the same operator to accept the prompt.
        "65001" => {
            "An administrator needs to grant this app consent in the tenant before \
             anyone can sign in to it."
        }
        "65004" => {
            "Consent was declined. Select Sign in again and accept the permissions \
             prompt to continue."
        }
        // Policy interrupts: retrying alone will not clear a CA block.
        "53003" => {
            "A Conditional Access policy blocked this sign-in. You may need a \
             compliant or joined device, or your identity admin has to allow this \
             app in the policy."
        }
        "50076" | "50079" | "50158" => {
            "Entra needs additional verification. Select Sign in again and complete \
             the multi-factor prompt."
        }
        "50011" => {
            "Entra rejected the redirect URI. This build's app registration needs a \
             loopback (http://localhost) redirect URI under Mobile and desktop \
             applications."
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{aadsts_hint, recovery_hint};

    #[test]
    fn an_aadsts_code_beats_the_generic_code_hint() {
        // `token_exchange` is the catch-all for every exchange rejection, so
        // without the number it can only say "verify the ids". With it, the
        // hint names the actual cause.
        let hint = recovery_hint("token_exchange", "invalid_request (AADSTS90002)");
        assert!(hint.contains("tenant doesn't resolve"), "{hint}");
    }

    #[test]
    fn an_unmapped_or_absent_code_falls_back_rather_than_guessing() {
        assert!(aadsts_hint("invalid_request (AADSTS99999)").is_none());
        assert!(aadsts_hint("invalid_request").is_none());
        // "AADSTS" with no digits after it yields no code (mirrors the
        // extractor in azapptoolkit-auth's `wire.rs`).
        assert!(aadsts_hint("AADSTS: malformed").is_none());
        assert_eq!(
            recovery_hint("network", "connection refused"),
            "Check your network connection, then select Sign in to retry.",
        );
    }

    #[test]
    fn consent_needed_and_consent_declined_do_not_share_a_hint() {
        // Load-bearing split: 65001 needs an administrator, 65004 needs this
        // same operator to accept the prompt. One hint for both sends half the
        // people to the wrong place.
        let needed = aadsts_hint("invalid_grant (AADSTS65001)").unwrap();
        let declined = aadsts_hint("invalid_grant (AADSTS65004)").unwrap();
        assert!(needed.contains("administrator"), "{needed}");
        assert!(
            declined.contains("accept the permissions prompt"),
            "{declined}"
        );
        assert_ne!(needed, declined);
    }
}
