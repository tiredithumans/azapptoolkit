//! Command-error reporting, in-place re-authentication, and incremental consent.
//!
//! Two failures reach this sink that the message alone can never resolve, and
//! both are fixed by exactly one interactive browser round trip:
//!
//! - a **dead session** is re-authenticated in place, never signed out (signing
//!   out would drop every data cache along with the session);
//! - a **missing admin consent** is granted incrementally, because a silent
//!   `refresh_token` grant can only *use* consent, never obtain it.
//!
//! Each gets a toast action rather than a red line, so neither is a dead end.

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
        if e.code != "consent_required" {
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

    /// Surface a failed command: the dead-session recovery toast when it applies
    /// (see [`Self::report_if_session_dead`]), then the consent toast (see
    /// [`Self::report_consent_required`]), else a plain `toast_error`. This is
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
        if self.report_if_session_dead(e) || self.report_consent_required(e, consent_feature) {
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
}
