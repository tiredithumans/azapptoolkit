//! Transient notifications.

use super::*;

/// The most toasts the stack shows at once, so a burst of failures (e.g. a
/// tight mutation loop) can't paper the screen.
pub(crate) const MAX_TOASTS: usize = 5;

impl Session {
    /// Push a toast and return its id. `action_label` + `action` render an
    /// inline button (Retry, …). The id lets a caller dismiss the toast later.
    ///
    /// Over `MAX_TOASTS` the oldest toast that is not sticky
    /// ([`Toast::is_sticky`]) is dropped first — a burst of successes never
    /// pushes a waiting Re-authenticate or Retry off the screen — and only
    /// then the oldest sticky one. The toast just pushed is never the one
    /// dropped. Never merges: a recovery lever that must show once goes
    /// through [`Self::push_recovery_toast`].
    pub fn push_toast(
        &self,
        kind: ToastKind,
        message: impl Into<String>,
        action_label: Option<String>,
        action: Option<ToastAction>,
    ) -> u64 {
        self.push(kind, message.into(), action_label, action, None)
    }

    /// Push the sticky error toast of a recovery lever (Re-authenticate,
    /// Refresh token, Grant consent, Verify identity) unless one with the same
    /// `key` is already showing — then return that toast's id and change
    /// nothing. A dead session fails every in-flight command at once; each
    /// failure reports it, and the operator needs one lever, not a stack of
    /// identical copies crowding out everything else.
    ///
    /// `key` names the lever and what it recovers (`"reauth"`,
    /// `"consent:exchange"`, …), never just the text: the consent toast's
    /// wording is the same for every feature, and granting Exchange does not
    /// fix a missing SharePoint consent.
    pub fn push_recovery_toast(
        &self,
        key: String,
        message: impl Into<String>,
        label: &str,
        action: ToastAction,
    ) -> u64 {
        self.push(
            ToastKind::Error,
            message.into(),
            Some(label.to_string()),
            Some(action),
            Some(key),
        )
    }

    fn push(
        &self,
        kind: ToastKind,
        message: String,
        action_label: Option<String>,
        action: Option<ToastAction>,
        dedupe_key: Option<String>,
    ) -> u64 {
        if let Some(key) = dedupe_key.as_deref() {
            let showing = self.toasts.with_untracked(|list| {
                list.iter()
                    .find(|t| t.dedupe_key.as_deref() == Some(key))
                    .map(|t| t.id)
            });
            if let Some(id) = showing {
                return id;
            }
        }
        let id = self.toast_seq.get_untracked();
        self.toast_seq.set(id.wrapping_add(1));
        self.toasts.update(|list| {
            list.push(Toast {
                id,
                kind,
                message,
                action_label,
                action,
                dedupe_key,
            });
            while list.len() > MAX_TOASTS {
                // Never the toast just pushed (the last one): transient
                // toasts go oldest-first, and only then the oldest sticky.
                let victim = list[..list.len() - 1]
                    .iter()
                    .position(|t| !t.is_sticky())
                    .unwrap_or(0);
                list.remove(victim);
            }
        });
        id
    }

    /// Convenience: a success toast (auto-dismisses).
    pub fn toast_success(&self, message: impl Into<String>) -> u64 {
        self.push_toast(ToastKind::Success, message, None, None)
    }

    /// Convenience: an error toast. With `retry: Some(..)` the toast gains a
    /// "Retry" button and stays until acted on / dismissed.
    pub fn toast_error(&self, message: impl Into<String>, retry: Option<ToastAction>) -> u64 {
        let label = retry.as_ref().map(|_| "Retry".to_string());
        self.push_toast(ToastKind::Error, message, label, retry)
    }

    /// Remove the toast with `id` (no-op if already gone).
    pub fn dismiss_toast(&self, id: u64) {
        self.toasts.update(|list| list.retain(|t| t.id != id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_dto::UiError;

    fn with_session<R>(f: impl FnOnce(Session) -> R) -> R {
        Owner::new().with(|| {
            provide_session();
            f(use_session())
        })
    }

    fn messages(session: Session) -> Vec<String> {
        session
            .toasts
            .with_untracked(|list| list.iter().map(|t| t.message.clone()).collect())
    }

    fn noop() -> ToastAction {
        std::rc::Rc::new(|| {})
    }

    #[test]
    fn a_repeated_session_expiry_raises_one_toast() {
        // A dead session fails every in-flight command at once, and each
        // failure reports it: one lever, not a stack of identical copies.
        with_session(|session| {
            let dead = UiError::new("refresh_missing", "gone", false);
            assert!(session.report_if_session_dead(&dead));
            assert!(
                session.report_if_session_dead(&dead),
                "a merged report is still a handled failure"
            );
            session.report_command_error(&UiError::new("not_signed_in", "none", false));
            session.toasts.with_untracked(|list| {
                assert_eq!(list.len(), 1, "{:?}", messages(session));
                assert_eq!(list[0].action_label.as_deref(), Some("Re-authenticate"));
            });
        });
    }

    #[test]
    fn consent_toasts_for_different_features_both_stay() {
        // The consent wording is the same for every feature; the lever is not.
        let consent = UiError::new("consent_required", "AADSTS65001", false);
        with_session(|session| {
            session.report_consent_required(&consent, "exchange");
            session.report_consent_required(&consent, "sharepoint");
            assert_eq!(session.toasts.with_untracked(Vec::len), 2);
        });
        with_session(|session| {
            session.report_consent_required(&consent, "exchange");
            session.report_consent_required(&consent, "exchange");
            assert_eq!(session.toasts.with_untracked(Vec::len), 1);
        });
    }

    #[test]
    fn identical_retry_toasts_are_not_merged() {
        // Two operations failing with the same text each keep their own Retry.
        with_session(|session| {
            session.toast_error("same", Some(noop()));
            session.toast_error("same", Some(noop()));
            assert_eq!(session.toasts.with_untracked(Vec::len), 2);
        });
    }

    #[test]
    fn the_cap_evicts_transient_toasts_before_sticky_ones() {
        with_session(|session| {
            session.report_if_session_dead(&UiError::new("refresh_missing", "gone", false));
            for i in 0..MAX_TOASTS {
                session.toast_success(format!("s{i}"));
            }
            let shown = messages(session);
            assert_eq!(shown.len(), MAX_TOASTS);
            assert!(
                session.toasts.with_untracked(|l| l
                    .iter()
                    .any(|t| t.action_label.as_deref() == Some("Re-authenticate"))),
                "a burst of successes pushed the lever off the screen: {shown:?}"
            );
            assert!(!shown.contains(&"s0".to_string()), "{shown:?}");
            assert!(shown.contains(&"s4".to_string()), "{shown:?}");
        });
    }

    #[test]
    fn a_full_sticky_stack_drops_its_oldest() {
        with_session(|session| {
            for i in 0..=MAX_TOASTS {
                session.toast_error(format!("e{i}"), Some(noop()));
            }
            let shown = messages(session);
            assert_eq!(shown.len(), MAX_TOASTS);
            assert!(!shown.contains(&"e0".to_string()), "{shown:?}");
            assert!(shown.contains(&"e5".to_string()), "{shown:?}");
        });
    }

    #[test]
    fn a_new_toast_is_never_the_one_evicted() {
        with_session(|session| {
            for i in 0..MAX_TOASTS {
                session.toast_error(format!("e{i}"), Some(noop()));
            }
            session.toast_success("saved");
            let shown = messages(session);
            assert_eq!(shown.len(), MAX_TOASTS);
            assert!(shown.contains(&"saved".to_string()), "{shown:?}");
            assert!(!shown.contains(&"e0".to_string()), "{shown:?}");
        });
    }
}
