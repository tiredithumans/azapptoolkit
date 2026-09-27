//! "Verify identity & retry" — the inline lever for a Conditional Access
//! step-up (`interaction_required`: MFA, registration or an external challenge
//! a policy demands for one resource) on a surface that shows its own error
//! instead of routing through the shared toast sink
//! (`Session::report_recovery_action`). The inline twin of the toast's
//! "Verify identity" action, as the hand-rolled "Grant consent & retry"
//! buttons are of its "Grant consent" one.
//!
//! The session is fine — the refresh token still serves every other audience
//! — so this is never Re-authenticate: it runs `request_scope_step_up` for the
//! failed surface's feature(s), then re-runs the surface.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};

use crate::bindings::auth;
use crate::state::use_session;

/// What an `interaction_required` surface says instead of `e.message`, which
/// carries an AADSTS code the operator cannot act on. Shared with the toast
/// (`Session::report_interaction_required`).
pub const VERIFY_IDENTITY_MESSAGE: &str = "Microsoft Entra needs you to verify your identity \
     (for example, multi-factor authentication) for this action.";

/// The button (plus its own failure line) that completes the step-up for
/// `features`, then calls `on_verified`.
#[component]
pub fn VerifyIdentityButton(
    /// The consent-feature keys (`"arm"`, `"log_analytics"`, `"exchange"`, …)
    /// of every audience the failed command acquires, in the order it acquires
    /// them. Nothing in the error names the audience that raised it, so a
    /// surface whose command touches two lists both: the backend opens the
    /// browser only for an audience whose silent acquisition still needs the
    /// step-up, so the one that is fine costs nothing.
    features: &'static [&'static str],
    /// Re-run the failed surface once every step-up succeeded.
    #[prop(into)]
    on_verified: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let on_click = move |_| {
        if busy.get_untracked() {
            return;
        }
        let Some(tenant) = session.active_tenant.get_untracked() else {
            return;
        };
        busy.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            for feature in features {
                if let Err(e) = auth::request_scope_step_up(&tenant.tenant_id, feature).await {
                    error.set(Some(format!(
                        "Couldn't complete verification: {}",
                        e.message
                    )));
                    busy.set(false);
                    return;
                }
            }
            busy.set(false);
            on_verified.run(());
        });
    };

    view! {
        <div class="actions-row">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Primary)
                on_click=Box::new(on_click)
                disabled=Signal::derive(move || busy.get())
            >
                "Verify identity & retry"
            </Button>
        </div>
        {move || error.get().map(|m| view! { <Body1 class="form-error">{m}</Body1> })}
    }
}
