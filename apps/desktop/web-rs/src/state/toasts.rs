//! Transient notifications.

use leptos::prelude::*;

use super::*;

impl Session {
    /// Push a toast and return its id. `action_label` + `action` render an
    /// inline button (used for Retry on retryable errors). The id lets a
    /// caller dismiss the toast later.
    pub fn push_toast(
        &self,
        kind: ToastKind,
        message: impl Into<String>,
        action_label: Option<String>,
        action: Option<ToastAction>,
    ) -> u64 {
        let id = self.toast_seq.get_untracked();
        self.toast_seq.set(id.wrapping_add(1));
        self.toasts.update(|list| {
            list.push(Toast {
                id,
                kind,
                message: message.into(),
                action_label,
                action,
            });
            // Cap the visible stack so a burst of failures (e.g. a tight
            // mutation loop) can't paper the screen — drop the oldest.
            const MAX_TOASTS: usize = 5;
            let overflow = list.len().saturating_sub(MAX_TOASTS);
            if overflow > 0 {
                list.drain(0..overflow);
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
