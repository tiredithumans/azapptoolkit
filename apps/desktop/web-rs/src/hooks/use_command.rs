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

use std::rc::Rc;

use leptos::prelude::*;

use crate::components::toast::{ToastAction, ToastKind};
use crate::state::{Session, use_session};

/// Busy/error state plus a runner for tenant-scoped command mutations. `Copy`,
/// so a component creates one and reuses the handle for every mutation.
#[derive(Clone, Copy)]
pub struct CommandState {
    /// True while a command is in flight (drives spinners / disabled buttons).
    pub busy: RwSignal<bool>,
    /// Message from the last failed command, if any.
    pub error: RwSignal<Option<String>>,
    /// Which scope set to offer consent for when a command fails with
    /// `consent_required` — see [`with_consent_feature`](Self::with_consent_feature).
    pub consent_feature: &'static str,
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
        // `try_`: a handle whose owning component is gone (a sticky Retry
        // toast outlives the pane that made it) reads as busy, never panics.
        if self.busy.try_get_untracked().unwrap_or(true) {
            return;
        }
        let this = *self;
        let tenant_id = self
            .session
            .active_tenant
            .get_untracked()
            .map(|t| t.tenant_id);
        self.busy.set(true);
        leptos::task::spawn_local(async move {
            let Some(tenant_id) = tenant_id else {
                this.busy.set(false);
                return;
            };
            let result = op(tenant_id.clone()).await;
            this.land(&tenant_id, result, on_ok, on_err);
        });
    }

    /// Where a [`run_with`](Self::run_with) result lands once its command
    /// returns — the call outlives what started it, two ways:
    ///
    /// - **The tenant it ran for is no longer active** (a switch, or sign-out,
    ///   which clears the tenant and unmounts the shell). Nothing lands: the
    ///   view shows another tenant or none, and a toast pushed onto the
    ///   shell-root `Session` would surface in the next sign-in.
    /// - **Same tenant, but the owning component was unmounted** (its pane
    ///   closed mid-save). `on_ok` / `on_err` read and run that component's
    ///   signals and callbacks, which panic once disposed, so neither runs. A
    ///   success needs no further word; a failure goes to the session's sink so
    ///   a write that failed is never silent.
    ///
    /// `busy` is always cleared (a no-op on a disposed handle). Synchronous so
    /// it is testable without spawning.
    pub(crate) fn land<T>(
        self,
        started_for: &str,
        result: Result<T, azapptoolkit_dto::UiError>,
        on_ok: impl FnOnce(T),
        on_err: impl FnOnce(azapptoolkit_dto::UiError),
    ) {
        if !self.session.is_active_tenant(started_for) {
            self.busy.set(false);
            return;
        }
        if self.busy.is_disposed() {
            if let Err(e) = result {
                self.session
                    .report_command_error_for(&e, self.consent_feature);
            }
            return;
        }
        match result {
            Ok(value) => on_ok(value),
            Err(e) => on_err(e),
        }
        self.busy.set(false);
    }

    /// Run a mutating command, storing any error message in `error` (cleared at
    /// start). On `Ok` runs `on_ok(value)`. The common case.
    ///
    /// Three failures additionally raise the shared sink's recovery toast
    /// (`Session::report_recovery_action`): a dead session ("Re-authenticate"),
    /// a rejected token ("Refresh token") and a missing admin consent ("Grant
    /// consent"). The inline message can never resolve any of them — each needs
    /// an out-of-band round trip — so leaving them as `error` text alone is a
    /// dead end, which is exactly what every expired session and write-scope
    /// failure used to be here. It follows the sink's own rule
    /// (`report_if_session_dead`: surfaces with their own error affordance call
    /// it first). See `fail_inline`.
    pub fn run<T, Fut>(
        &self,
        on_ok: impl FnOnce(T) + 'static,
        op: impl FnOnce(String) -> Fut + 'static,
    ) where
        Fut: std::future::Future<Output = Result<T, azapptoolkit_dto::UiError>> + 'static,
        T: 'static,
    {
        let this = *self;
        self.error.set(None);
        self.run_with(on_ok, move |e| this.fail_inline(e), op);
    }

    /// The inline-error failure path of [`run`](Self::run): the recovery toast
    /// (dead session → rejected token → consent) when one applies — never a
    /// plain toast, the inline `error` IS this surface's message — and always
    /// the inline text. Synchronous so it is testable without spawning.
    pub(crate) fn fail_inline(self, e: azapptoolkit_dto::UiError) {
        self.session
            .report_recovery_action(&e, self.consent_feature);
        self.error.set(Some(e.message));
    }

    /// Like [`run`](Self::run) but reports failures via a toast instead of the
    /// `error` signal — for handlers that surface errors as toasts and keep no
    /// inline error signal (so this never touches `self.error`).
    ///
    /// A failure goes through the central sink: a recovery lever when one
    /// applies (Re-authenticate, Refresh token, Grant consent, Verify
    /// identity), else an error toast that — when the backend marks the
    /// failure transient (`UiError::retryable`: throttled, a 5xx, a network
    /// error) — carries a sticky **Retry** that re-runs this same call. That is
    /// why `on_ok` and `op` are `Clone`: every run, the first and each retry,
    /// consumes a fresh clone. See `fail_toast`.
    ///
    /// A retry goes through this runner again, so it resolves the tenant anew
    /// (pinned to the one the call first ran for), and it is refused — with an
    /// info toast saying why — while the same handle is busy or once the
    /// component that owns it is gone (see `fail_toast`). An op
    /// that reads a signal when called (the enterprise-app notes text) retries
    /// with the value current at the click, not the one that failed.
    pub fn run_toast_err<T, Fut>(
        &self,
        on_ok: impl FnOnce(T) + Clone + 'static,
        op: impl FnOnce(String) -> Fut + Clone + 'static,
    ) where
        Fut: std::future::Future<Output = Result<T, azapptoolkit_dto::UiError>> + 'static,
        T: 'static,
    {
        let this = *self;
        let started_for = self
            .session
            .active_tenant
            .get_untracked()
            .map(|t| t.tenant_id);
        let (again_ok, again_op) = (on_ok.clone(), op.clone());
        self.run_with(
            on_ok,
            move |e| {
                this.fail_toast(e, started_for, move || {
                    this.run_toast_err(again_ok.clone(), again_op.clone())
                });
            },
            op,
        );
    }

    /// The toast failure path of [`run_toast_err`](Self::run_toast_err), the
    /// twin of [`fail_inline`](Self::fail_inline): hands `rerun` to
    /// `Session::report_command_error_with_retry`, which offers it as Retry
    /// only for a transient failure with no recovery lever to use first.
    ///
    /// The Retry is **pinned to `started_for`**, the tenant the failed call ran
    /// for. Toasts survive a tenant switch, and a re-run resolves the tenant
    /// active at the click — so without the pin a Retry clicked after a switch
    /// would send tenant A's captured object ids to tenant B. After a switch it
    /// says so instead.
    ///
    /// It is also **bounded by the owning component's lifetime**. The toast
    /// lives on the shell's `Session` and, being sticky, outlives the detail
    /// pane that raised it (closing the dock chip, "Close all", a tenant
    /// A → B → A switch all dispose the pane), while `rerun` reads that pane's
    /// signals and stored values — reading a disposed one panics the app. So a
    /// Retry whose handle is disposed says the view was closed instead, and one
    /// clicked while the same handle is still busy (another action on that pane
    /// is in flight) says so rather than vanishing silently. Synchronous so it
    /// is testable without spawning.
    pub(crate) fn fail_toast(
        self,
        e: azapptoolkit_dto::UiError,
        started_for: Option<String>,
        rerun: impl Fn() + 'static,
    ) {
        let (session, busy) = (self.session, self.busy);
        let retry: ToastAction = Rc::new(move || {
            let not_retried = if busy.is_disposed() {
                "That view was closed, so the action wasn't retried."
            } else if session.active_tenant.get_untracked().map(|t| t.tenant_id) != started_for {
                "You switched tenants, so that action wasn't retried."
            } else if busy.try_get_untracked().unwrap_or(true) {
                "Another action is still running there, so that one wasn't retried. \
                 Try again when it finishes."
            } else {
                rerun();
                return;
            };
            session.push_toast(ToastKind::Info, not_retried, None, None);
        });
        session.report_command_error_with_retry(&e, self.consent_feature, Some(retry));
    }

    /// Point this handle's consent recovery at a feature other than the Graph
    /// write scopes — `"exchange"`, `"sharepoint"`, `"arm"`, … (the keys the
    /// backend's `AppState::consent_scopes_for` accepts).
    ///
    /// Nothing in a `consent_required` error says which scope set was missing,
    /// so a component whose commands ride an on-demand scope must declare it;
    /// otherwise the offered grant consents scopes that cannot fix the failure
    /// the operator just saw. (That mis-mapping is a real bug this repo has
    /// shipped once: the scope wizard consented Exchange for an org-wide Graph
    /// grant.)
    #[must_use]
    pub fn with_consent_feature(mut self, feature: &'static str) -> Self {
        self.consent_feature = feature;
        self
    }
}

/// Create command state. Call once per component during setup (where the
/// `Session` context is available); reuse the returned `Copy` handle for every
/// mutation in that component.
pub fn use_command() -> CommandState {
    CommandState {
        busy: RwSignal::new(false),
        error: RwSignal::new(None),
        // Graph write scopes: what every mutating command needs, consented
        // lazily on the first write, and — unlike the on-demand feature scopes
        // — never offered a grant path anywhere in the UI. Override per
        // component with `with_consent_feature`.
        consent_feature: "write",
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

    #[test]
    fn the_consent_recovery_defaults_to_the_graph_write_scopes() {
        // The default is load-bearing: a mutation that fails on the lazily
        // consented write scopes is the case no per-feature consent button
        // covers, so it is the one the shared sink must get right unaided.
        Owner::new().with(|| {
            provide_session();
            assert_eq!(use_command().consent_feature, "write");
            assert_eq!(
                use_command()
                    .with_consent_feature("exchange")
                    .consent_feature,
                "exchange"
            );
        });
    }

    fn inline_failure(
        code: &str,
        cmd: impl FnOnce() -> CommandState,
    ) -> (Vec<Option<String>>, Option<String>) {
        Owner::new().with(|| {
            provide_session();
            let cmd = cmd();
            cmd.fail_inline(azapptoolkit_dto::UiError::new(code, "gone", false));
            let labels = use_session()
                .toasts
                .with_untracked(|list| list.iter().map(|t| t.action_label.clone()).collect());
            (labels, cmd.error.get_untracked())
        })
    }

    #[test]
    fn an_inline_failure_on_a_dead_session_offers_reauthenticate() {
        let (labels, error) = inline_failure("refresh_missing", use_command);
        assert_eq!(labels, vec![Some("Re-authenticate".to_string())]);
        assert_eq!(error.as_deref(), Some("gone"), "the inline text stays");
    }

    #[test]
    fn an_inline_failure_on_a_rejected_token_offers_refresh() {
        let (labels, error) = inline_failure("unauthorized", use_command);
        assert_eq!(labels, vec![Some("Refresh token".to_string())]);
        assert_eq!(error.as_deref(), Some("gone"));
    }

    #[test]
    fn an_inline_consent_failure_uses_the_handles_feature() {
        let (labels, error) = inline_failure("consent_required", || {
            use_command().with_consent_feature("exchange")
        });
        assert_eq!(labels, vec![Some("Grant consent".to_string())]);
        assert_eq!(error.as_deref(), Some("gone"));
    }

    fn tenant(id: &str) -> crate::bindings::TenantContext {
        crate::bindings::TenantContext {
            tenant_id: id.to_string(),
            account_oid: "00000000-0000-0000-0000-000000000001".to_string(),
            username: None,
            display_name: None,
        }
    }

    fn forbidden() -> azapptoolkit_dto::UiError {
        azapptoolkit_dto::UiError::new("forbidden", "no rights", false)
    }

    fn messages(session: Session) -> Vec<String> {
        session
            .toasts
            .with_untracked(|list| list.iter().map(|t| t.message.clone()).collect())
    }

    #[test]
    fn a_live_result_runs_its_handlers_and_clears_busy() {
        Owner::new().with(|| {
            provide_session();
            use_session().set_active_tenant(Some(tenant("tenant-a")));
            let cmd = use_command();
            cmd.busy.set(true);
            let ran = Rc::new(std::cell::Cell::new(false));
            let r = ran.clone();
            cmd.land(
                "tenant-a",
                Ok(()),
                move |()| r.set(true),
                |_| panic!("on_err"),
            );
            assert!(ran.get());
            assert!(!cmd.busy.get_untracked());
        });
    }

    #[test]
    fn a_result_after_a_tenant_switch_or_sign_out_lands_nowhere() {
        // Sign-out clears the tenant (and unmounts the shell), so both reach
        // the same branch: no handler, no toast carried into the next tenant.
        for next in [Some(tenant("tenant-b")), None] {
            Owner::new().with(|| {
                provide_session();
                let session = use_session();
                session.set_active_tenant(Some(tenant("tenant-a")));
                let cmd = use_command();
                cmd.busy.set(true);
                session.set_active_tenant(next.clone());
                cmd.land(
                    "tenant-a",
                    Ok(()),
                    |()| panic!("on_ok"),
                    |_| panic!("on_err"),
                );
                cmd.land(
                    "tenant-a",
                    Err(forbidden()),
                    |()| panic!("on_ok"),
                    |_| panic!("on_err"),
                );
                assert!(messages(session).is_empty(), "{:?}", messages(session));
                assert!(
                    !cmd.busy.get_untracked(),
                    "the handle gets its controls back"
                );
            });
        }
    }

    #[test]
    fn a_result_after_its_view_closed_never_runs_its_handlers() {
        // The pane closed mid-save: its handlers read disposed signals and
        // callbacks (a panic), so they are skipped — but a failed write still
        // reaches the session's sink rather than vanishing.
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.set_active_tenant(Some(tenant("tenant-a")));
            let pane = Owner::new();
            let cmd = pane.with(use_command);
            pane.cleanup();
            cmd.land(
                "tenant-a",
                Ok(()),
                |()| panic!("on_ok"),
                |_| panic!("on_err"),
            );
            assert!(messages(session).is_empty(), "a success needs no word");
            cmd.land(
                "tenant-a",
                Err(forbidden()),
                |()| panic!("on_ok"),
                |_| panic!("on_err"),
            );
            assert!(
                messages(session).iter().any(|m| m.contains("no rights")),
                "{:?}",
                messages(session)
            );
        });
    }

    /// `fail_toast` for `e` with a counting re-run, then click the toast's
    /// action after `between` ran. Returns (re-runs, toast messages).
    fn click_retry(
        e: azapptoolkit_dto::UiError,
        between: impl FnOnce(Session),
    ) -> (u32, Vec<String>) {
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.set_active_tenant(Some(tenant("tenant-a")));
            let runs = Rc::new(std::cell::Cell::new(0));
            let count = runs.clone();
            use_command().fail_toast(e, Some("tenant-a".to_string()), move || {
                count.set(count.get() + 1)
            });
            let action = session.toasts.with_untracked(|list| {
                assert_eq!(list[0].action_label.as_deref(), Some("Retry"));
                list[0].action.clone().expect("a retry action")
            });
            between(session);
            action();
            let messages = session
                .toasts
                .with_untracked(|list| list.iter().map(|t| t.message.clone()).collect());
            (runs.get(), messages)
        })
    }

    #[test]
    fn a_transient_toast_failure_retries_the_same_op() {
        let (runs, _) = click_retry(
            azapptoolkit_dto::UiError::new("network_error", "offline", true),
            |_| {},
        );
        assert_eq!(runs, 1);
    }

    #[test]
    fn a_retry_never_crosses_tenants() {
        // Toasts survive a tenant switch; the re-run would resolve the new
        // tenant and send the old one's object ids to it.
        let (runs, messages) = click_retry(
            azapptoolkit_dto::UiError::new("throttled", "slow down", true),
            |session| session.set_active_tenant(Some(tenant("tenant-b"))),
        );
        assert_eq!(runs, 0, "a retry ran against another tenant");
        assert!(
            messages.iter().any(|m| m.contains("switched tenants")),
            "{messages:?}"
        );
    }

    #[test]
    fn a_retry_after_its_view_closed_never_runs() {
        // The sticky toast outlives the pane that owns the handle; the re-run
        // reads that pane's (now disposed) signals, which would panic.
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.set_active_tenant(Some(tenant("tenant-a")));
            let pane = Owner::new();
            let cmd = pane.with(use_command);
            cmd.fail_toast(
                azapptoolkit_dto::UiError::new("throttled", "slow down", true),
                Some("tenant-a".to_string()),
                || panic!("a retry ran for a closed view"),
            );
            let action = session
                .toasts
                .with_untracked(|list| list[0].action.clone().expect("a retry action"));
            pane.cleanup();
            assert!(cmd.busy.is_disposed());
            action();
            let messages: Vec<String> = session
                .toasts
                .with_untracked(|list| list.iter().map(|t| t.message.clone()).collect());
            assert!(
                messages.iter().any(|m| m.contains("view was closed")),
                "{messages:?}"
            );
            // The runner's own guard is disposal-safe too: no panic, no spawn.
            cmd.run_with(
                |()| panic!("ran"),
                |_| panic!("ran"),
                |_| async { Err(azapptoolkit_dto::UiError::new("x", "ran", false)) },
            );
        });
    }

    #[test]
    fn a_retry_while_the_handle_is_busy_says_so() {
        // The runner's guard drops a click on a busy handle (sso_tab shares
        // one handle across five actions); the operator must hear why.
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            let cmd = use_command();
            cmd.fail_toast(
                azapptoolkit_dto::UiError::new("server_error", "try later", true),
                None,
                || panic!("a busy handle re-ran"),
            );
            let action = session
                .toasts
                .with_untracked(|list| list[0].action.clone().expect("a retry action"));
            cmd.busy.set(true);
            action();
            session.toasts.with_untracked(|list| {
                assert!(
                    list.iter().any(|t| t.message.contains("still running")),
                    "the lever vanished silently"
                );
            });
        });
    }

    #[test]
    fn an_ordinary_toast_failure_has_no_retry() {
        Owner::new().with(|| {
            provide_session();
            use_command().fail_toast(
                azapptoolkit_dto::UiError::new("forbidden", "denied", false),
                None,
                || panic!("never re-run"),
            );
            use_session().toasts.with_untracked(|list| {
                assert_eq!(list.len(), 1);
                assert!(list[0].action.is_none());
            });
        });
    }

    #[test]
    fn an_ordinary_inline_failure_raises_no_toast() {
        // The inline `error` is this surface's message: an ordinary failure
        // must not also be reported as a toast.
        let (labels, error) = inline_failure("forbidden", use_command);
        assert!(labels.is_empty(), "no double report: {labels:?}");
        assert_eq!(error.as_deref(), Some("gone"));
    }
}
