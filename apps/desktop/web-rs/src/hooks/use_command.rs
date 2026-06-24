//! Reactive hook for tenant-scoped Tauri command mutations. Generalizes the
//! `spawn_mutation` pattern repeated across views/components into one hook: a
//! double-submit guard, error reset on start, active-tenant resolution, and
//! `busy` cleared on completion.
//!
//! ```ignore
//! let cmd = use_command();
//! // in an event handler:
//! cmd.run(move |_| on_changed.run(()), move |tenant_id| async move {
//!     applications::delete_application(&tenant_id, &id).await
//! });
//! // read `cmd.busy` to disable a button, `cmd.error` to surface the message.
//! ```

use leptos::prelude::*;

use crate::state::{Session, use_session};

/// Busy/error state plus a runner for tenant-scoped command mutations. `Copy`,
/// so a component creates one and reuses the handle for every mutation.
#[derive(Clone, Copy)]
pub struct CommandState {
    /// True while a command is in flight (drives spinners / disabled buttons).
    pub busy: RwSignal<bool>,
    /// Message from the last failed command, if any.
    pub error: RwSignal<Option<String>>,
    session: Session,
}

impl CommandState {
    /// The general runner behind the double-submit guard. Bails if already busy;
    /// otherwise sets `busy`, resolves the active tenant, and spawns
    /// `op(tenant_id)`. On `Ok` runs `on_ok(value)`; on `Err` runs `on_err(e)`.
    /// `busy` is always cleared. No-op (busy cleared) when no tenant is active.
    /// [`run`](Self::run) and [`run_toast_err`](Self::run_toast_err) are the
    /// common wrappers; use this directly only when a handler needs custom error
    /// handling (e.g. branching on `e.code`).
    ///
    /// The future is intentionally **not** `Send`: `tauri_sys` IPC futures hold
    /// JS values and are `!Send`, and run on the single wasm thread via
    /// `spawn_local`.
    pub fn run_with<T, Fut>(
        &self,
        on_ok: impl FnOnce(T) + 'static,
        on_err: impl FnOnce(azapptoolkit_dto::UiError) + 'static,
        op: impl FnOnce(String) -> Fut + 'static,
    ) where
        Fut: std::future::Future<Output = Result<T, azapptoolkit_dto::UiError>> + 'static,
        T: 'static,
    {
        if self.busy.get_untracked() {
            return;
        }
        let busy = self.busy;
        let tenant_id = self
            .session
            .active_tenant
            .get_untracked()
            .map(|t| t.tenant_id);
        busy.set(true);
        leptos::task::spawn_local(async move {
            let Some(tenant_id) = tenant_id else {
                busy.set(false);
                return;
            };
            match op(tenant_id).await {
                Ok(value) => on_ok(value),
                Err(e) => on_err(e),
            }
            busy.set(false);
        });
    }

    /// Run a mutating command, storing any error message in `error` (cleared at
    /// start). On `Ok` runs `on_ok(value)`. The common case.
    pub fn run<T, Fut>(
        &self,
        on_ok: impl FnOnce(T) + 'static,
        op: impl FnOnce(String) -> Fut + 'static,
    ) where
        Fut: std::future::Future<Output = Result<T, azapptoolkit_dto::UiError>> + 'static,
        T: 'static,
    {
        let error = self.error;
        error.set(None);
        self.run_with(on_ok, move |e| error.set(Some(e.message)), op);
    }

    /// Like [`run`](Self::run) but reports failures via a `toast_error` instead
    /// of the `error` signal — for handlers that surface errors as toasts and
    /// keep no inline error signal (so this never touches `self.error`).
    pub fn run_toast_err<T, Fut>(
        &self,
        on_ok: impl FnOnce(T) + 'static,
        op: impl FnOnce(String) -> Fut + 'static,
    ) where
        Fut: std::future::Future<Output = Result<T, azapptoolkit_dto::UiError>> + 'static,
        T: 'static,
    {
        let session = self.session;
        self.run_with(
            on_ok,
            move |e| {
                session.toast_error(e.message, None);
            },
            op,
        );
    }
}

/// Create command state. Call once per component during setup (where the
/// `Session` context is available); reuse the returned `Copy` handle for every
/// mutation in that component.
pub fn use_command() -> CommandState {
    CommandState {
        busy: RwSignal::new(false),
        error: RwSignal::new(None),
        session: use_session(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::provide_session;

    #[test]
    fn use_command_starts_idle() {
        // `use_command` reads the `Session` from context, so the test needs a
        // reactive owner with a provided session.
        Owner::new().with(|| {
            provide_session();
            let cmd = use_command();
            assert!(!cmd.busy.get_untracked());
            assert!(cmd.error.with_untracked(|e| e.is_none()));
        });
    }
}
