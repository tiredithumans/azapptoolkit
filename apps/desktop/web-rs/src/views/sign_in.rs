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
use crate::components::support_paths::SupportPathsBlock;
use crate::components::ui::{Callout, Card, Spinner};
use crate::state::auth_hints::recovery_hint;
use crate::state::{Session, use_session};
use crate::views::config_screen::SettingsErrorCallout;
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
/// down — the only cases the backend returns as an error) sets `failure` to
/// the error's code so the card offers a Retry and says which; every other
/// outcome is the plain card. The error message is never shown: its cause
/// chain can carry the token URL.
///
/// `generation` fences a late answer: the attempt lands only if it has not
/// moved since the attempt began. The operator choosing to sign in ("Sign in
/// instead" on the restoring card, or the card's own Sign in) moves it, so a
/// restore that completes behind a browser sign-in never signs a session in
/// under it, nor repaints the offline callout.
pub(crate) async fn attempt_restore(
    session: Session,
    failure: RwSignal<Option<String>>,
    generation: RwSignal<u64>,
) {
    let Some(started) = generation.try_get_untracked() else {
        return;
    };
    let result = auth::restore_session().await;
    land_restore(session, failure, generation, started, result);
}

/// [`attempt_restore`]'s landing, apart from the IPC so the generation fence is
/// testable natively.
fn land_restore(
    session: Session,
    failure: RwSignal<Option<String>>,
    generation: RwSignal<u64>,
    started: u64,
    result: Result<Option<TenantContext>, UiError>,
) {
    if generation.try_get_untracked() != Some(started) {
        return;
    }
    match result {
        Ok(Some(tenant)) => {
            failure.set(None);
            session.set_active_tenant(Some(tenant));
        }
        Err(e) => failure.set(Some(e.code)),
        Ok(None) => failure.set(None),
    }
}

/// Moves a restore generation: every attempt already in flight lands nothing.
pub(crate) fn abandon_restore(generation: RwSignal<u64>) {
    generation.update(|g| *g = g.wrapping_add(1));
}

/// The restoring card's "Sign in instead" (`Root`'s handler): stop holding the
/// sign-in card back, and fence off the launch attempt still in flight so its
/// late answer lands nothing.
pub(crate) fn stop_waiting_for_restore(restoring: RwSignal<bool>, generation: RwSignal<u64>) {
    abandon_restore(generation);
    restoring.set(false);
}

/// The card's "Signing in to …" line: the tenant, and the cloud when the
/// backend named one, so a sovereign-cloud operator sees which login it is
/// about to open before the browser does. Not in parentheses: the cloud names
/// carry their own ("US Gov (GCC High)").
fn signing_in_to(tenant: &str, cloud: &str) -> String {
    if cloud.is_empty() {
        format!("Signing in to {tenant} · ")
    } else {
        format!("Signing in to {tenant} on the {cloud} cloud · ")
    }
}

/// What the launch callout says about a restore that got no verdict, by its
/// code: the shared hint for a foreign responder or an unavailable endpoint
/// (checking the network would not help there), else the reachability line
/// (`network`, or the IPC call itself failing).
fn restore_failure_text(code: &str) -> String {
    match code {
        "unexpected_responder" | "service_unavailable" => {
            format!("Couldn't restore your session. {}", recovery_hint(code, ""))
        }
        _ => "Couldn't reach Entra ID to restore your session — check your network \
              connection, then retry."
            .to_string(),
    }
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
    /// The code of a launch restore that got no verdict from Entra ID
    /// (`network`, `unexpected_responder`, `service_unavailable`): the stored
    /// session is intact, so the card offers a Retry of the silent restore
    /// instead of only a browser sign-in that can't get through either, and
    /// says which. Owned by `Root`, which runs the launch attempt.
    #[prop(optional)]
    restore_failure: RwSignal<Option<String>>,
    /// The restore fence (see `attempt_restore`), owned by `Root`: the card's
    /// Retry runs under it, and its Sign in moves it, so a Retry still in
    /// flight cannot land behind the browser sign-in.
    #[prop(optional)]
    restore_generation: RwSignal<u64>,
    /// The cloud sign-in targets (`AuthConfigStatus::cloud`), named beside the
    /// tenant. Empty from an older backend, which leaves the line as it was.
    #[prop(optional, into)]
    cloud: String,
    /// `AuthConfigStatus::cloud_warning`: an `AZAPPTOOLKIT_CLOUD` value that
    /// was ignored, with the valid ones.
    #[prop(optional_no_strip)]
    cloud_warning: Option<String>,
    /// `AuthConfigStatus::settings_error`: a `settings.json` the app could not
    /// read at startup (Settings, where it would otherwise be fixed, is behind
    /// this sign-in).
    #[prop(optional_no_strip)]
    settings_error: Option<String>,
) -> impl IntoView {
    let session = use_session();
    let busy = RwSignal::new(false);
    let retrying = RwSignal::new(false);
    // Not while the browser sign-in is open either: its Sign in moved the
    // fence, and a Retry started after it would run under the new generation
    // and could land behind the sign-in.
    let on_retry = move |_| {
        if retrying.get() || busy.get() {
            return;
        }
        retrying.set(true);
        leptos::task::spawn_local(async move {
            attempt_restore(session, restore_failure, restore_generation).await;
            retrying.set(false);
        });
    };
    // (message, code, hint): the hint translates the machine error code into a
    // recovery step, since a bare `[keyring]` means nothing to most users.
    let error: RwSignal<Option<(String, String, &'static str)>> = RwSignal::new(None);
    // The settings callout carries the paths already; otherwise a failed
    // sign-in shows them, since the log is where its detail is.
    let has_settings_error = settings_error.is_some();

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
                    restore_failure.set(None);
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
                {settings_error.map(|message| view! { <SettingsErrorCallout message=message /> })}
                {cloud_warning
                    .map(|warning| {
                        view! {
                            <Callout tone="warn" role="status" class="signin-cloud-warning">
                                <span class="ui-text">{warning}</span>
                            </Callout>
                        }
                    })}
                {move || {
                    restore_failure
                        .get()
                        .map(|code| {
                            view! {
                                <Callout tone="warn" role="status">
                                    <span class="ui-text">{restore_failure_text(&code)}</span>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                        class="signin-restore-retry"
                                        on_click=Box::new(on_retry)
                                        disabled=Signal::derive(move || retrying.get() || busy.get())
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
                                {signing_in_to(&tenant, &cloud)}
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
                                {(!has_settings_error).then(|| view! { <SupportPathsBlock /> })}
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
                                    <span class="ui-text">"Still restoring your session…"</span>
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
    use super::{
        abandon_restore, land_restore, restore_failure_text, signing_in_to,
        stop_waiting_for_restore,
    };
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
            let (failure, generation) = (RwSignal::new(None::<String>), RwSignal::new(0u64));
            let restoring = RwSignal::new(true);
            let started = generation.get_untracked();
            // "Sign in instead" while the restore runs — Root's handler.
            stop_waiting_for_restore(restoring, generation);
            assert!(!restoring.get_untracked(), "the sign-in card shows");
            assert_ne!(generation.get_untracked(), started, "the fence moved");

            land_restore(session, failure, generation, started, Ok(Some(tenant())));
            assert!(
                session.active_tenant.get_untracked().is_none(),
                "a late restore must not sign in under the operator's browser sign-in"
            );
            land_restore(
                session,
                failure,
                generation,
                started,
                Err(UiError::new("network", "offline", true)),
            );
            assert!(
                failure.get_untracked().is_none(),
                "nor repaint the offline callout"
            );
            // The card's own Sign in moves it again, for a Retry in flight.
            let retry_started = generation.get_untracked();
            abandon_restore(generation);
            assert_ne!(generation.get_untracked(), retry_started);
        });
    }

    #[test]
    fn a_current_restore_answer_lands() {
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            let (failure, generation) = (RwSignal::new(None::<String>), RwSignal::new(0u64));
            let started = generation.get_untracked();

            land_restore(
                session,
                failure,
                generation,
                started,
                Err(UiError::new("unexpected_responder", "proxy", true)),
            );
            assert_eq!(
                failure.get_untracked().as_deref(),
                Some("unexpected_responder"),
                "any restore error offers Retry, and keeps its code"
            );
            land_restore(session, failure, generation, started, Ok(Some(tenant())));
            assert!(failure.get_untracked().is_none());
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

    #[test]
    fn the_card_names_the_cloud_beside_the_tenant_when_it_has_one() {
        assert_eq!(
            signing_in_to("t-1", "US Gov (GCC High)"),
            "Signing in to t-1 on the US Gov (GCC High) cloud · "
        );
        // An older backend sends no cloud: the line reads as it always did.
        assert_eq!(signing_in_to("t-1", ""), "Signing in to t-1 · ");
    }

    #[test]
    fn the_launch_callout_says_why_the_restore_got_no_verdict() {
        // Checking the network does not help when a proxy answered, or Entra
        // (or a gateway) is down: the callout says what the sign-in hint says.
        let proxy = restore_failure_text("unexpected_responder");
        assert!(proxy.contains("proxy"), "{proxy}");
        assert!(proxy.contains("login.microsoftonline.com"), "{proxy}");
        assert!(!proxy.contains("network connection"), "{proxy}");
        let busy = restore_failure_text("service_unavailable");
        assert!(busy.contains("wait a minute"), "{busy}");
        for reachability in ["network", "ipc"] {
            assert!(
                restore_failure_text(reachability).starts_with("Couldn't reach Entra ID"),
                "{reachability}"
            );
        }
    }
}
