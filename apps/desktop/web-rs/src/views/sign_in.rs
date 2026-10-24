//! Entra ID sign-in.
//! Single-tenant: the OAuth authority is built from `AZAPPTOOLKIT_TENANT_ID` on
//! the backend, so there is no tenant input to render here — the card *names*
//! the tenant it is about to redirect to, and links back to the config form for
//! when that name is the thing that is wrong.

use std::time::Duration;

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::TenantContext;
use crate::bindings::auth;
use crate::components::ui::{Callout, Card, Spinner};
use crate::state::auth_hints::recovery_hint;
use crate::state::{Session, use_session};
use azapptoolkit_dto::UiError;

/// How long the launch restore may run before its card admits it is slow and
/// offers to stop waiting. A restore normally takes a fraction of a second; an
/// unreachable or throttled token endpoint can hold it for a minute or more
/// (connect timeouts and the token retry budget).
pub const SLOW_RESTORE_AFTER: Duration = Duration::from_secs(5);

/// One silent attempt at reviving the previous session — the launch restore in
/// `Root` and the offline card's Retry are this same call. A restored session
/// replaces the sign-in card; a token endpoint that gave no verdict on the
/// stored token (unreachable, answered by a proxy or portal, or throttled /
/// down — the only cases the backend returns as an error) raises `unreachable`
/// so the card offers a Retry; every other outcome is the plain card. The
/// error message is never shown: its cause chain can carry the token URL.
///
/// `generation` fences a late answer: the attempt lands only if it has not
/// moved since the attempt began. The operator choosing to sign in ("Sign in
/// instead" on the restoring card, or the card's own Sign in) moves it, so a
/// restore that completes behind a browser sign-in never signs a session in
/// under it, nor repaints the offline callout.
pub(crate) async fn attempt_restore(
    session: Session,
    unreachable: RwSignal<bool>,
    generation: RwSignal<u64>,
) {
    let Some(started) = generation.try_get_untracked() else {
        return;
    };
    let result = auth::restore_session().await;
    land_restore(session, unreachable, generation, started, result);
}

/// [`attempt_restore`]'s landing, apart from the IPC so the generation fence is
/// testable natively.
fn land_restore(
    session: Session,
    unreachable: RwSignal<bool>,
    generation: RwSignal<u64>,
    started: u64,
    result: Result<Option<TenantContext>, UiError>,
) {
    if generation.try_get_untracked() != Some(started) {
        return;
    }
    match result {
        Ok(Some(tenant)) => {
            unreachable.set(false);
            session.set_active_tenant(Some(tenant));
        }
        Err(_) => unreachable.set(true),
        Ok(None) => unreachable.set(false),
    }
}

/// Moves a restore generation: every attempt already in flight lands nothing.
pub(crate) fn abandon_restore(generation: RwSignal<u64>) {
    generation.update(|g| *g = g.wrapping_add(1));
}

#[component]
pub fn SignInScreen(
    /// The tenant this build authenticates against — the GUID currently
    /// configured. Named on the card because it is the last moment a
    /// wrong one is cheap: after the button, a well-formed but wrong id costs a
    /// browser round trip and comes back as an opaque `token_exchange` failure.
    tenant: String,
    /// Reopens the (prefilled) config form. The escape hatch for an install
    /// pointed at the wrong tenant, which can reach no other surface: sign-in is
    /// all it has, and Settings → Tenant connection is behind the sign-in it
    /// can never complete.
    #[prop(into)]
    on_reconfigure: Callback<()>,
    /// Set when the launch restore could not reach Entra ID: the stored
    /// session is intact, so the card offers a Retry of the silent restore
    /// instead of only a browser sign-in that can't load either. Owned by
    /// `Root`, which runs the launch attempt.
    #[prop(optional)]
    restore_unreachable: RwSignal<bool>,
    /// The restore fence (see `attempt_restore`), owned by `Root`: the card's
    /// Retry runs under it, and its Sign in moves it, so a Retry still in
    /// flight cannot land behind the browser sign-in.
    #[prop(optional)]
    restore_generation: RwSignal<u64>,
) -> impl IntoView {
    let session = use_session();
    let busy = RwSignal::new(false);
    let retrying = RwSignal::new(false);
    let on_retry = move |_| {
        if retrying.get() {
            return;
        }
        retrying.set(true);
        leptos::task::spawn_local(async move {
            attempt_restore(session, restore_unreachable, restore_generation).await;
            retrying.set(false);
        });
    };
    // (message, code, hint): the hint translates the machine error code into a
    // recovery step, since a bare `[keyring]` means nothing to most users.
    let error: RwSignal<Option<(String, String, &'static str)>> = RwSignal::new(None);

    let on_sign_in = move |_| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        abandon_restore(restore_generation);
        let session = session;
        leptos::task::spawn_local(async move {
            match auth::sign_in().await {
                Ok(outcome) => {
                    // So a later sign-out doesn't repaint a stale offline callout.
                    restore_unreachable.set(false);
                    session.set_active_tenant(Some(outcome.tenant));
                }
                // Message first, with the machine code muted after it — the
                // same shape as `DetailLoadError` — so a failure stays
                // diagnosable without leading with the wire code.
                Err(err) => {
                    let hint = recovery_hint(&err.code, &err.message);
                    error.set(Some((err.message, err.code, hint)));
                }
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
                <span class="ui-text">
                    "Use Entra ID to manage App Registrations, permissions, and run security audits."
                </span>
                {move || {
                    restore_unreachable
                        .get()
                        .then(|| {
                            view! {
                                <Callout tone="warn" role="status">
                                    <span class="ui-text">
                                        "Couldn't reach Entra ID to restore your session — check your network connection, then retry."
                                    </span>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                        class="signin-restore-retry"
                                        on_click=Box::new(on_retry)
                                        disabled=Signal::derive(move || retrying.get())
                                    >
                                        {move || {
                                            if retrying.get() {
                                                view! {
                                                    <Spinner />
                                                }
                                                    .into_any()
                                            } else {
                                                view! { "Retry" }.into_any()
                                            }
                                        }}
                                    </Button>
                                </Callout>
                            }
                        })
                }}
                {(!tenant.is_empty())
                    .then(|| {
                        view! {
                            <span class="ui-text signin-hint">
                                {format!("Signing in to {tenant} · ")}
                                <button
                                    type="button"
                                    class="link-btn"
                                    on:click=move |_| on_reconfigure.run(())
                                >
                                    "Change"
                                </button>
                            </span>
                        }
                    })}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(on_sign_in)
                    disabled=Signal::derive(move || busy.get())
                >
                    {move || {
                        if busy.get() {
                            view! { <Spinner /> }
                                .into_any()
                        } else {
                            view! { "Sign in with Entra ID" }.into_any()
                        }
                    }}
                </Button>
                {move || {
                    error
                        .get()
                        .map(|(msg, code, hint)| {
                            view! {
                                <span class="ui-text signin-error">
                                    {format!("Sign-in failed: {msg}")}
                                </span>
                                {(!code.is_empty())
                                    .then(|| {
                                        view! {
                                            <span class="ui-load-error__code">
                                                {format!("[{code}]")}
                                            </span>
                                        }
                                    })}
                                <span class="ui-text signin-hint">{hint}</span>
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
///
/// The hold is bounded by the operator, not the network: an unreachable or
/// throttled token endpoint can keep the restore going for a minute or more,
/// so after `slow_after` the card says so and offers "Sign in instead", which
/// ends the wait (`Root` moves the restore fence, so the late answer lands
/// nothing).
#[component]
pub fn RestoringSession(
    /// Stop waiting and show the sign-in card.
    #[prop(into)]
    on_sign_in_instead: Callback<()>,
    /// How long before the card admits the restore is slow
    /// ([`SLOW_RESTORE_AFTER`]); a prop so a test need not wait it out.
    #[prop(default = SLOW_RESTORE_AFTER)]
    slow_after: Duration,
) -> impl IntoView {
    let slow = RwSignal::new(false);
    if let Ok(timer) = set_timeout_with_handle(move || slow.set(true), slow_after) {
        on_cleanup(move || timer.clear());
    }
    view! {
        <main class="signin-shell">
            <Card elevation=4 class="signin-card".to_string()>
                <div class="signin-card__brand">
                    <span class="shell__brand-mark">"a"</span>
                    <span>"azapptoolkit"</span>
                </div>
                <h1 class="signin-card__title">"Restoring your session"</h1>
                <Spinner />
                {move || {
                    slow.get()
                        .then(|| {
                            view! {
                                <Callout role="status">
                                    <span class="ui-text">"Still trying to reach Entra ID…"</span>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                        class="signin-restore-skip"
                                        on_click=Box::new(move |_| on_sign_in_instead.run(()))
                                    >
                                        "Sign in instead"
                                    </Button>
                                </Callout>
                            }
                        })
                }}
            </Card>
        </main>
    }
}

#[cfg(test)]
mod tests {
    use super::{abandon_restore, land_restore};
    use crate::bindings::TenantContext;
    use crate::state::{provide_session, use_session};
    use azapptoolkit_dto::UiError;
    use leptos::prelude::*;

    fn tenant() -> TenantContext {
        TenantContext {
            tenant_id: "restore-fence".into(),
            account_oid: "oid".into(),
            username: None,
            display_name: None,
        }
    }

    #[test]
    fn a_restore_answer_after_the_operator_chose_to_sign_in_lands_nothing() {
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            let (unreachable, generation) = (RwSignal::new(false), RwSignal::new(0u64));
            let started = generation.get_untracked();
            // "Sign in instead" (or the card's Sign in) while the restore runs.
            abandon_restore(generation);

            land_restore(
                session,
                unreachable,
                generation,
                started,
                Ok(Some(tenant())),
            );
            assert!(
                session.active_tenant.get_untracked().is_none(),
                "a late restore must not sign in under the operator's browser sign-in"
            );
            land_restore(
                session,
                unreachable,
                generation,
                started,
                Err(UiError::new("network", "offline", true)),
            );
            assert!(
                !unreachable.get_untracked(),
                "nor repaint the offline callout"
            );
        });
    }

    #[test]
    fn a_current_restore_answer_lands() {
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            let (unreachable, generation) = (RwSignal::new(false), RwSignal::new(0u64));
            let started = generation.get_untracked();

            land_restore(
                session,
                unreachable,
                generation,
                started,
                Err(UiError::new("unexpected_responder", "proxy", true)),
            );
            assert!(
                unreachable.get_untracked(),
                "any restore error offers Retry"
            );
            land_restore(
                session,
                unreachable,
                generation,
                started,
                Ok(Some(tenant())),
            );
            assert!(!unreachable.get_untracked());
            assert_eq!(
                session
                    .active_tenant
                    .get_untracked()
                    .map(|t| t.tenant_id)
                    .as_deref(),
                Some("restore-fence")
            );
        });
    }
}
