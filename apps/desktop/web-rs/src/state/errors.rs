//! Command-error reporting, in-place re-authentication, and incremental consent.
//!
//! Three failures reach this sink that the message alone can never resolve,
//! and each has exactly one in-place lever:
//!
//! - a **dead session** is re-authenticated in place, never signed out (signing
//!   out would drop every data cache along with the session);
//! - a **rejected access token** (`unauthorized`, a 401) is re-minted in place
//!   by the same "Refresh token" lever the top bar offers, falling back to
//!   re-authentication when the session turns out to be dead;
//! - a **missing admin consent** is granted incrementally, because a silent
//!   `refresh_token` grant can only *use* consent, never obtain it.
//!
//! Each gets a toast action rather than a red line, so none is a dead end.
//! [`Session::report_recovery_action`] is the one ordering of the three, shared
//! by the toast surfaces and the inline-error ones (`CommandState::run`).

use super::*;

impl Session {
    /// Interactively re-authenticate the signed-in account in place — one browser
    /// round trip — when the session has gone dead, so the user skips the manual
    /// Sign Out → Sign In (which would also wipe the cached lists + audit run).
    /// The tenant id is unchanged (the backend validates the returned identity
    /// matches), so this deliberately does **not** call `set_active_tenant`:
    /// re-setting it would needlessly reset the user's filters and selection.
    /// Used by the smart Refresh button's fallback and the
    /// [`Self::report_command_error`] "Re-authenticate" toast action.
    pub fn spawn_reauth(&self) {
        let session = *self;
        leptos::task::spawn_local(async move {
            let Some(tenant) = session.active_tenant.get_untracked() else {
                return;
            };
            match crate::bindings::auth::reauthenticate(&tenant).await {
                Ok(_) => {
                    session.toast_success("Re-authenticated — retry the action that failed.");
                }
                Err(e) => {
                    session.toast_error(format!("Couldn't re-authenticate: {}", e.message), None);
                }
            }
        });
    }

    /// When `e` means the **session is dead** — the refresh token
    /// expired/revoked (`refresh_missing`) or there's no session at all
    /// (`not_signed_in`) — show the persistent error toast whose action
    /// re-authenticates in place (see [`Self::spawn_reauth`]) and return
    /// `true`; otherwise show nothing and return `false`. Surfaces with their
    /// own error affordance (an inline banner, a contextual toast) call this
    /// first so a dead session still gets the recovery action instead of a
    /// dead-end message, without growing another copy of the code set.
    ///
    /// The code set is [`azapptoolkit_dto::UiError::is_reauth_fatal`] — the one
    /// definition, shared with the backend. It used to be a `matches!` here AND
    /// one in `shell.rs`, which AGENTS.md flagged as a footgun ("a new
    /// re-auth-fatal code must extend BOTH sets").
    pub fn report_if_session_dead(&self, e: &azapptoolkit_dto::UiError) -> bool {
        if !e.is_reauth_fatal() {
            return false;
        }
        let session = *self;
        self.push_toast(
            ToastKind::Error,
            "Your session has expired — re-authenticate to continue.",
            Some("Re-authenticate".to_string()),
            Some(std::rc::Rc::new(move || session.spawn_reauth())),
        );
        true
    }

    /// Run interactive incremental consent for `feature`'s scopes — the one
    /// round trip a silent grant cannot make — then tell the user the action is
    /// theirs to repeat. The sibling of [`Self::spawn_reauth`], down to the
    /// "retry" wording: this sink only ever receives the `UiError`, never the
    /// closure that produced it, so it cannot replay the failed operation.
    /// Call sites that *do* hold a re-runnable operation (the per-feature
    /// banners, the scope wizard) keep replaying it themselves.
    ///
    /// `feature` is a key the backend's `AppState::consent_scopes_for` accepts
    /// (`"write"`, `"exchange"`, `"sharepoint"`, `"arm"`, …).
    pub fn spawn_scope_consent(&self, feature: &'static str) {
        let session = *self;
        leptos::task::spawn_local(async move {
            let Some(tenant) = session.active_tenant.get_untracked() else {
                return;
            };
            match crate::bindings::auth::request_scope_consent(&tenant.tenant_id, feature).await {
                Ok(()) => {
                    session.toast_success("Consent granted — retry the action that failed.");
                }
                Err(e) => {
                    session.toast_error(format!("Couldn't grant consent: {}", e.message), None);
                }
            }
        });
    }

    /// Re-mint the session's tokens in place (no sign-out) so a rejected or
    /// stale token — or a role activated since sign-in — is replaced. Tries the
    /// silent `refresh_session` first; if the session is dead (an
    /// expired/revoked or missing refresh token, surfaced as
    /// `refresh_missing`/`not_signed_in`), falls back to ONE interactive
    /// `reauthenticate` — still no sign-out, so the cached lists + audit run
    /// survive. `token_reauthing` is held true while the browser flow is open.
    ///
    /// Only [`Self::spawn_refresh_token`] calls this, after claiming the
    /// in-flight flag.
    async fn refresh_token_in_place(self, tenant: TenantContext) {
        let session = self;
        match crate::bindings::auth::refresh_session(&tenant.tenant_id).await {
            Ok(()) => {
                // Re-applied roles may change access, so re-run a mounted
                // Access Readiness checklist (this is its only re-check).
                session.bump_readiness_reload();
                session.toast_success(
                    "Token refreshed — roles activated since sign-in now apply. \
                     Retry the action that failed.",
                );
            }
            Err(e) if e.is_reauth_fatal() => {
                // Silent re-mint can't fix a dead refresh token; re-auth
                // interactively in place rather than dumping the user to the
                // sign-in screen.
                session.token_reauthing.set(true);
                match crate::bindings::auth::reauthenticate(&tenant).await {
                    Ok(_) => {
                        session.bump_readiness_reload();
                        session.toast_success("Re-authenticated — retry the action that failed.")
                    }
                    Err(e) => session
                        .toast_error(format!("Couldn't re-authenticate: {}", e.message), None),
                };
                session.token_reauthing.set(false);
            }
            Err(e) => {
                session.toast_error(format!("Couldn't refresh token: {}", e.message), None);
            }
        }
    }

    /// Start the one in-place token refresh for the active tenant (see
    /// [`Self::refresh_token_in_place`]) — the single entry behind both the
    /// top-bar "Refresh token" button and the 401 toast's action
    /// ([`Self::report_if_token_rejected`]).
    ///
    /// A no-op while one is already in flight: the flag lives on the session
    /// (`token_refreshing`), not on either trigger, so a double-click, several
    /// 401 toasts from parallel loads, or the top bar and a toast together
    /// can't race concurrent refreshes — or, on a dead session, concurrent
    /// interactive re-auth browser flows.
    pub fn spawn_refresh_token(&self) {
        let session = *self;
        if session.token_refreshing.get_untracked() {
            return;
        }
        let Some(tenant) = session.active_tenant.get_untracked() else {
            return;
        };
        session.token_refreshing.set(true);
        leptos::task::spawn_local(async move {
            session.refresh_token_in_place(tenant).await;
            session.token_refreshing.set(false);
        });
    }

    /// When `e` is a rejected access token (`unauthorized` — a client 401: a
    /// revoked token, or a Continuous Access Evaluation claims challenge the
    /// silent re-mint couldn't satisfy), show the persistent error toast whose
    /// action re-mints it in place (see [`Self::spawn_refresh_token`]) and
    /// return `true`; otherwise show nothing and return `false`.
    ///
    /// Deliberately NOT a re-auth-fatal code (`core::reauth::REAUTH_FATAL_CODES`):
    /// one 401 does not prove the session is dead, so a fan-out keeps going
    /// (pinned by `an_operation_level_failure_is_not_a_dead_session`). But the
    /// operator still needs the lever — the bare "unauthorized (401)" names
    /// nothing to do — and the right lever is the same one the top bar offers,
    /// which itself falls back to re-authentication when the session IS dead.
    ///
    /// Unlike [`Self::report_consent_required`], the text is ours only for a
    /// bare status line: Exchange, Key Vault and ARM append their own curated
    /// guidance (`ui_hint`) — which already names "Refresh token" and says what
    /// to check if the 401 persists — so that text is shown as-is
    /// ([`azapptoolkit_dto::UiError::unauthorized_guidance`]). Dropping it
    /// would turn a persistent 401 into a refresh loop with nothing to go on.
    pub fn report_if_token_rejected(&self, e: &azapptoolkit_dto::UiError) -> bool {
        if !e.is_unauthorized() {
            return false;
        }
        let message = e.unauthorized_guidance().map_or_else(
            || "Your access token was rejected — refresh it, then retry the action.".to_string(),
            str::to_string,
        );
        let session = *self;
        self.push_toast(
            ToastKind::Error,
            message,
            Some("Refresh token".to_string()),
            Some(std::rc::Rc::new(move || session.spawn_refresh_token())),
        );
        true
    }

    /// When `e` means the tenant has never consented to the scopes the command
    /// needed (`consent_required`), show the persistent error toast whose action
    /// grants them (see [`Self::spawn_scope_consent`]) and return `true`;
    /// otherwise show nothing and return `false`.
    ///
    /// The structural twin of [`Self::report_if_session_dead`], for the same
    /// reason: write scopes are consented on **first use**, so any mutation can
    /// hit this in a tenant that hasn't pre-granted admin consent — and the
    /// scope is obtainable from nowhere else in the app, so a message without
    /// this action is a dead end. (`consent_required` is deliberately NOT
    /// `invalid_grant`: the refresh token is still valid and must not be
    /// purged — see `core::reauth` and the auth deep-dive.)
    ///
    /// The wording is ours, not `e.message`: AAD's text is
    /// `consent required for the requested permissions (AADSTS65001)`, which
    /// names a diagnostic code the operator cannot act on. The label says
    /// "Grant consent", not "…& retry", because nothing here re-runs the call.
    pub fn report_consent_required(
        &self,
        e: &azapptoolkit_dto::UiError,
        feature: &'static str,
    ) -> bool {
        if !e.is_consent_required() {
            return false;
        }
        let session = *self;
        self.push_toast(
            ToastKind::Error,
            "This tenant hasn't consented to the permissions this action needs.",
            Some("Grant consent".to_string()),
            Some(std::rc::Rc::new(move || {
                session.spawn_scope_consent(feature)
            })),
        );
        true
    }

    /// Surface a failed command with the Graph **write** scopes as the consent
    /// recovery — see [`Self::report_command_error_for`], which this delegates
    /// to. Write scopes are the right default because every mutating command
    /// needs them, they are consented lazily on first write, and until now
    /// nothing in the UI offered a grant path for them at all (the hand-rolled
    /// consent buttons all cover on-demand feature scopes instead).
    pub fn report_command_error(&self, e: &azapptoolkit_dto::UiError) {
        self.report_command_error_for(e, "write");
    }

    /// The recovery actions a message alone can never provide, in priority
    /// order: dead session ([`Self::report_if_session_dead`]) → rejected token
    /// ([`Self::report_if_token_rejected`]) → missing consent
    /// ([`Self::report_consent_required`]). Raises at most one toast and returns
    /// `true` when it did. A dead session outranks the rest because it can
    /// neither refresh nor consent to anything.
    ///
    /// The one ordering, shared by the toast surfaces
    /// ([`Self::report_command_error_for`]) and the inline-error ones
    /// (`CommandState::run`, which keeps its own inline text).
    pub fn report_recovery_action(
        &self,
        e: &azapptoolkit_dto::UiError,
        consent_feature: &'static str,
    ) -> bool {
        self.report_if_session_dead(e)
            || self.report_if_token_rejected(e)
            || self.report_consent_required(e, consent_feature)
    }

    /// Surface a failed command: the recovery toast when one applies (see
    /// [`Self::report_recovery_action`]), else a plain `toast_error`. This is
    /// the central error sink `use_command` routes through.
    ///
    /// `consent_feature` is declared by the caller because **nothing in a
    /// `consent_required` error says which scope set was missing** — a component
    /// whose commands ride an on-demand scope passes its own feature via
    /// `use_command().with_consent_feature(..)`, or the offered grant consents
    /// scopes that cannot fix the failure the operator just saw.
    pub fn report_command_error_for(
        &self,
        e: &azapptoolkit_dto::UiError,
        consent_feature: &'static str,
    ) {
        if self.report_recovery_action(e, consent_feature) {
            return;
        }
        self.toast_error(e.message.clone(), None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_dto::UiError;

    #[test]
    fn a_missing_consent_gets_a_grant_action_not_a_dead_end() {
        // The FR-02 regression: `consent_required` fell through to the plain
        // error toast, so the one interactive round trip that fixes it was
        // reachable from nowhere.
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.report_command_error(&UiError::new(
                "consent_required",
                "consent required for the requested permissions (AADSTS65001)",
                false,
            ));
            session.toasts.with_untracked(|list| {
                assert_eq!(list.len(), 1);
                let t = &list[0];
                assert!(matches!(t.kind, ToastKind::Error));
                assert_eq!(t.action_label.as_deref(), Some("Grant consent"));
                assert!(t.action.is_some(), "the grant action is the whole point");
                assert!(
                    !t.message.contains("AADSTS"),
                    "AAD's text names a code the operator can't act on"
                );
            });
        });
    }

    #[test]
    fn a_dead_session_still_wins_over_the_consent_branch() {
        // Ordering matters: a dead session cannot consent to anything, so
        // re-auth must be offered first even though both codes are "auth-ish".
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.report_command_error(&UiError::new("refresh_missing", "gone", false));
            session.toasts.with_untracked(|list| {
                assert_eq!(list[0].action_label.as_deref(), Some("Re-authenticate"));
            });
        });
    }

    #[test]
    fn a_rejected_token_offers_refresh_not_sign_out() {
        // A 401 used to be a bare "unauthorized (401)" toast; the lever it
        // needs is the in-place token refresh, never a sign-out.
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.report_command_error(&UiError::new(
                "unauthorized",
                "unauthorized (401)",
                false,
            ));
            session.toasts.with_untracked(|list| {
                assert_eq!(list.len(), 1);
                let t = &list[0];
                assert!(matches!(t.kind, ToastKind::Error));
                assert_eq!(t.action_label.as_deref(), Some("Refresh token"));
                assert!(t.action.is_some(), "the refresh action is the whole point");
                assert!(
                    !t.message.contains("Sign out and back in"),
                    "signing out would drop every data cache: {}",
                    t.message
                );
                assert!(
                    !t.message.contains("unauthorized (401)"),
                    "a bare status line names nothing to do: {}",
                    t.message
                );
            });
        });
    }

    #[test]
    fn a_rejected_token_keeps_the_clients_curated_guidance() {
        // Exchange / Key Vault / ARM append a `ui_hint` to their 401 — the only
        // advice for a 401 that survives a refresh. Replacing it with fixed text
        // turned a persistent 401 into a refresh loop with nothing to go on.
        let hinted = "unauthorized (401)\n\nYour Key Vault token was rejected. Use \
                      \"Refresh token\" (next to Sign out), then retry; if it persists, \
                      confirm the app has consented the vault.azure.net scope.";
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.report_command_error(&UiError::new("unauthorized", hinted, false));
            session.toasts.with_untracked(|list| {
                assert_eq!(list.len(), 1);
                let t = &list[0];
                assert_eq!(t.action_label.as_deref(), Some("Refresh token"));
                assert!(
                    t.message.contains("if it persists") && t.message.contains("vault.azure.net"),
                    "the curated guidance must reach the toast: {}",
                    t.message
                );
                assert!(
                    !t.message.starts_with("unauthorized (401)"),
                    "the bare status line adds nothing: {}",
                    t.message
                );
            });
        });
    }

    #[test]
    fn a_dead_session_outranks_a_rejected_token() {
        // Ordering: a dead session can't refresh anything, so its code gets
        // Re-authenticate, and only a 401 gets Refresh token.
        let label_for = |code: &str| {
            Owner::new().with(|| {
                provide_session();
                let session = use_session();
                session.report_command_error(&UiError::new(code, "m", false));
                session
                    .toasts
                    .with_untracked(|list| list[0].action_label.clone())
            })
        };
        assert_eq!(
            label_for("refresh_missing").as_deref(),
            Some("Re-authenticate")
        );
        assert_eq!(
            label_for("not_signed_in").as_deref(),
            Some("Re-authenticate")
        );
        assert_eq!(label_for("unauthorized").as_deref(), Some("Refresh token"));
    }
}
