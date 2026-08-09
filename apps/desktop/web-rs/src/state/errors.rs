//! Command-error reporting and in-place re-authentication.
//!
//! A dead session is re-authenticated in place, never signed out: signing out
//! would drop every data cache along with the session.

use leptos::prelude::*;

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

    /// Surface a failed command: the dead-session recovery toast when it
    /// applies (see [`Self::report_if_session_dead`]), else a plain
    /// `toast_error`. This is the central error sink `use_command` routes
    /// through.
    pub fn report_command_error(&self, e: &azapptoolkit_dto::UiError) {
        if !self.report_if_session_dead(e) {
            self.toast_error(e.message.clone(), None);
        }
    }
}
