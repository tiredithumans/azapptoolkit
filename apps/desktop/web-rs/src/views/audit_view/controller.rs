//! Shared audit run state for the Security workbench.
//!
//! The posture strip, the Findings pane, and the All-apps pane all read one
//! scan: `AuditController` bundles the run/progress/export signals, the derived
//! memos, and the run/cancel/export/consent actions. Constructed **once** in
//! `SecurityView` (which lives for the app's lifetime under the shell's
//! keep-alive routing) and provided via context; panes `expect_context` it.
//! All fields are arena-backed handles, so the struct is `Copy` and closures
//! capture it wholesale.

use std::collections::HashMap;
use std::sync::Arc;

use azapptoolkit_core::audit::{PostureCounts, RemediationKind, posture_counts};
use leptos::prelude::*;

use crate::bindings::audit::{self, AuditExportCoverage, AuditProgress, AuditRunResult};
use crate::bindings::auth;
use crate::bindings::events;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::Session;

#[derive(Clone, Copy)]
pub(crate) struct AuditController {
    session: Session,
    pub result: RwSignal<Option<AuditRunResult>>,
    pub scanning: RwSignal<bool>,
    pub progress: RwSignal<Option<AuditProgress>>,
    /// High-water concurrency cap. When the live cap later drops below this
    /// peak, Graph is throttling and the scan is backing off — surfaced so a
    /// slow audit reads as expected, not stalled. Monotonic within a run;
    /// reset when a new run clears `progress`. The placeholder `run` seeds
    /// carries cap 0, so the peak only ever tracks the backend's own events.
    pub peak_cap: RwSignal<usize>,
    pub scan_error: RwSignal<Option<String>>,
    pub exporting: RwSignal<bool>,
    /// Per-bucket counts for the posture strip, computed once per scan (never
    /// per keystroke) without cloning the multi-MB run — by core's
    /// `posture_counts`, the same function the backend runs for the Home
    /// card's summary, so the two surfaces can't disagree.
    pub posture: Memo<Option<PostureCounts>>,
    pub consent_needed: Memo<bool>,
    pub total_items: Memo<Option<usize>>,
    /// `object_id -> application name`, so a bulk failure names the app instead
    /// of printing its GUID. Built ONCE per scan here because it was previously
    /// rebuilt independently by every finding group and again by the All-apps
    /// pane — a full-tenant HashMap per reader per render.
    pub names: Memo<Arc<HashMap<String, String>>>,
    pub report_available: Memo<bool>,
    /// `false` when the run couldn't check some mail permission against
    /// Exchange mailbox scoping — the org-wide mailbox group then says its
    /// findings may already be confined. `true` with no run (nothing to caveat).
    pub mailbox_scoping_resolved: Memo<bool>,
    /// The per-kind `Callback<String>` wrappers the row Fixes report through
    /// (see [`Self::done_for`]). When a row's remediation succeeds, the wrapper
    /// drops **that one kind** from the item so its "Fix" button is gone for
    /// good (the audit cache is already busted server-side; scores refresh on
    /// the next manual re-run). Only that kind: an item scored under several
    /// rules carries a Fix per rule, and clearing the whole set made one
    /// section's success erase another section's still-unfixed button.
    ///
    /// Built ONCE here (SecurityView's ownership) rather than per row: a
    /// wrapper the row owned died with the row, and a Fix whose row was
    /// rebuilt mid-flight — a scan landing re-groups every row — then found
    /// `try_run` a no-op, so the result was never patched and the Fix button
    /// came back for a finding already fixed.
    row_done: RowDone,
    /// The row to hand keyboard focus to once a Fix lands. A landed Fix
    /// re-keys its row (the key carries the remediation count), so the `<tr>`
    /// is rebuilt and the focus that was on its Fix button fell to `<body>`.
    /// Set by `on_remediated`; the rebuilt row's action stack claims it from
    /// its own effect and clears it (the `UriListEditor` `focus_key` hand-over).
    pub focus_row: RwSignal<Option<String>>,
    /// After a successful inline bulk run, refetch the App Registrations list
    /// (a delete / remove-expired sweep busts its backend cache). The audit's
    /// own scan is a point-in-time snapshot — deleted rows linger until the
    /// next manual re-run, matching how the audit cache already works.
    pub on_bulk_done: Callback<()>,
}

/// One `Callback<String>` per remediation kind, each reporting `(row, kind)`
/// to `on_remediated`. See [`AuditController::row_done`].
#[derive(Clone, Copy)]
struct RowDone {
    expired: Callback<String>,
    redundant: Callback<String>,
    mailbox: Callback<String>,
    migrate: Callback<String>,
    sharepoint: Callback<String>,
    add_owner: Callback<String>,
    disable: Callback<String>,
}

impl AuditController {
    /// Sets up the signals, memos, cached-run hydration, and the
    /// `audit-progress` subscription in the calling component's reactive
    /// ownership — call once from `SecurityView`.
    pub(crate) fn new(session: Session) -> Self {
        let result: RwSignal<Option<AuditRunResult>> = RwSignal::new(None);
        let scanning = RwSignal::new(false);
        let progress: RwSignal<Option<AuditProgress>> = RwSignal::new(None);
        let peak_cap = RwSignal::new(0usize);
        Effect::new(move |_| match progress.get() {
            Some(p) => peak_cap.update(|peak| *peak = (*peak).max(p.in_flight_cap)),
            None => peak_cap.set(0),
        });
        let scan_error: RwSignal<Option<String>> = RwSignal::new(None);
        let exporting = RwSignal::new(false);

        let posture =
            Memo::new(move |_| result.with(|r| r.as_ref().map(|r| posture_counts(&r.items))));
        let consent_needed = Memo::new(move |_| {
            result.with(|r| r.as_ref().is_some_and(|r| r.sign_in_consent_required))
        });
        let total_items = Memo::new(move |_| result.with(|r| r.as_ref().map(|r| r.items.len())));
        let names: Memo<Arc<HashMap<String, String>>> = Memo::new(move |_| {
            Arc::new(result.with(|r| {
                r.as_ref()
                    .map(|r| {
                        r.items
                            .iter()
                            .map(|i| (i.object_id.clone(), i.application_name.clone()))
                            .collect()
                    })
                    .unwrap_or_default()
            }))
        });
        let report_available = Memo::new(move |_| {
            result.with(|r| r.as_ref().is_some_and(|r| r.sign_in_report_available))
        });
        let mailbox_scoping_resolved = Memo::new(move |_| {
            result.with(|r| r.as_ref().is_none_or(|r| r.mailbox_scoping_resolved))
        });

        let focus_row: RwSignal<Option<String>> = RwSignal::new(None);
        let on_remediated = Callback::new(move |(object_id, kind): (String, RemediationKind)| {
            let mut rekeyed = false;
            result.update(|opt| {
                if let Some(r) = opt.as_mut()
                    && let Some(item) = r.items.iter_mut().find(|i| i.object_id == object_id)
                {
                    let before = item.remediations.len();
                    item.remediations.retain(|a| a.kind != kind);
                    rekeyed = item.remediations.len() != before;
                }
            });
            // Only a row whose key changed is rebuilt and loses focus; a
            // no-op (the scan that landed mid-Fix already lacked this kind, or
            // the item is gone) hands over nothing — and clears a stale one,
            // so a later remount of that app's row can't steal focus.
            focus_row.set(rekeyed.then_some(object_id));
        });
        let done = |kind: RemediationKind| {
            Callback::new(move |row_id: String| on_remediated.run((row_id, kind)))
        };
        let row_done = RowDone {
            expired: done(RemediationKind::RemoveExpiredCredentials),
            redundant: done(RemediationKind::RemoveRedundantPermissions),
            mailbox: done(RemediationKind::ScopeMailboxAccess),
            migrate: done(RemediationKind::MigrateApplicationAccessPolicy),
            sharepoint: done(RemediationKind::ScopeSharePointAccess),
            add_owner: done(RemediationKind::AddOwner),
            disable: done(RemediationKind::DisableSignIn),
        };
        let on_bulk_done = Callback::new(move |_| session.bump_apps_reload());

        // Subscribe to audit-progress events for the owner's lifetime; the
        // stream task aborts on cleanup so it can't leak or race a remount.
        use_progress_stream(progress, events::audit_progress);

        // Hydrate from cache when tenant changes. Clear stale state
        // synchronously so the previous tenant's data never lingers, then
        // guard the async write against a tenant-changed race: if the user
        // switches tenants (or two cache loads resolve out of order) while
        // `get_cached_audit` is in flight, drop the late result instead of
        // clobbering the now-active tenant's view.
        let tenant = session.active_tenant;
        Effect::new(move |_| {
            let t = tenant.get();
            result.set(None);
            scan_error.set(None);
            progress.set(None);
            let Some(t) = t else { return };
            let tenant_id = t.tenant_id.clone();
            leptos::task::spawn_local(async move {
                // A failed hydrate reads as "no cached run" (the operator can
                // still run the audit), but says so in the console.
                let cached = match audit::get_cached_audit(&tenant_id).await {
                    Ok(cached) => cached,
                    Err(err) => {
                        leptos::logging::warn!(
                            "get_cached_audit failed ({}): {}",
                            err.code,
                            err.message
                        );
                        None
                    }
                };
                // Only onto an empty slot: a Run that finished while this
                // read was in flight (Home's call to action starts one at
                // construction) is fresher than the cache, and a cancelled
                // or partial run must not be replaced by an older complete
                // one wearing no caveats.
                if session.is_active_tenant(&tenant_id)
                    && result.try_with_untracked(Option::is_none).unwrap_or(false)
                {
                    focus_row.set(None);
                    result.set(cached);
                }
            });
        });

        let ctrl = Self {
            session,
            result,
            scanning,
            progress,
            peak_cap,
            scan_error,
            exporting,
            posture,
            consent_needed,
            total_items,
            names,
            report_available,
            mailbox_scoping_resolved,
            row_done,
            focus_row,
            on_bulk_done,
        };

        // Home's "Run a security audit" call to action used to only NAVIGATE
        // here, leaving the operator to find and press "Run audit" a second
        // time. It now trips the one-shot flag and this consumes it, so one
        // click both navigates and scans. An Effect rather than a read at
        // construction because this workbench is keep-alive: after its first
        // visit it never mounts again, and a mount-time read would make the
        // button work exactly once per session. Clearing the flag *before*
        // running is what makes it one-shot — this effect also sees the signals
        // `run()` touches, and every re-run then finds it false and does
        // nothing.
        Effect::new(move |_| {
            if session.tenant_ui.pending_audit_run.get() {
                session.tenant_ui.pending_audit_run.set(false);
                ctrl.run();
            }
        });

        ctrl
    }

    /// Starts a scan (no-op while one runs). Zero-arg so it drives both the
    /// "Run audit" button and the post-consent re-run.
    pub(crate) fn run(self) {
        if self.scanning.get() {
            return;
        }
        self.scanning.set(true);
        self.scan_error.set(None);
        self.progress.set(Some(AuditProgress {
            done: 0,
            total: 0,
            current_app: None,
            // 0, not the backend's INITIAL_CONCURRENCY: `peak_cap` is a
            // high-water mark of the BACKEND's live cap, and a re-spelled 8
            // made the rate-limit notice fire on a healthy scan if the backend
            // constant ever dropped.
            in_flight_cap: 0,
            cancelled: false,
        }));
        let t = self.session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = t else {
                self.scanning.set(false);
                return;
            };
            let res = audit::run_audit(&t.tenant_id).await;
            // Sign-out disposes this controller with the shell: the result
            // then belongs to nobody on screen, and the Home tile's bump
            // would refetch for the next sign-in. `is_disposed` covers a
            // sign-out and sign-in back to the same tenant mid-scan, where
            // the tenant check alone would land this on a rebuilt shell.
            if self.scanning.is_disposed() || !self.session.is_active_tenant(&t.tenant_id) {
                self.scanning.set(false);
                self.progress.set(None);
                return;
            }
            match res {
                Ok(r) => {
                    // A new run re-keys nothing in particular; a pending
                    // focus hand-over from a Fix is stale against it.
                    self.focus_row.set(None);
                    self.result.set(Some(r));
                    // Refresh the Home dashboard's "Security Posture" tile: it
                    // keeps its cached-audit resource alive across view
                    // switches, so it only refetches when this bumps.
                    self.session.bump_audit_reload();
                }
                Err(e) => self.fail(e),
            }
            self.scanning.set(false);
            self.progress.set(None);
        });
    }

    /// The strip's inline error is this surface's message — plus the recovery
    /// lever when one applies (`CommandState::fail_inline`'s rule): a session
    /// that dies mid-scan needs Re-authenticate, not a red line saying "sign
    /// in again", which here means a sign-out that drops every cache.
    fn fail(self, e: azapptoolkit_dto::UiError) {
        self.session.report_recovery_action(&e, "audit_log");
        self.scan_error.set(Some(e.message));
    }

    /// Receiver-shaped with the rest of the controller surface; the cancel
    /// itself is a backend call, so there is no controller state to read.
    #[allow(clippy::unused_self)]
    pub(crate) fn cancel(self) {
        leptos::task::spawn_local(async move {
            audit::cancel_audit().await;
        });
    }

    /// Grants AuditLog.Read.All (the sign-in activity report behind the Unused
    /// finding), then re-runs the audit so unused apps populate.
    pub(crate) fn grant_reports_consent(self) {
        if self.scanning.get() {
            return;
        }
        let Some(t) = self.session.active_tenant.get() else {
            return;
        };
        self.scan_error.set(None);
        leptos::task::spawn_local(async move {
            let res = auth::request_scope_consent(&t.tenant_id, "audit_log").await;
            // The consent round trip is a browser prompt answered minutes
            // later, perhaps after a sign-out: the shell is gone by then and
            // so is this controller — `run` reads `scanning`, which panics
            // once disposed — and a toast would surface at the next sign-in.
            if self.scanning.is_disposed() || !self.session.is_active_tenant(&t.tenant_id) {
                return;
            }
            match res {
                Ok(()) => self.run(),
                Err(e) => self.fail(e),
            }
        });
    }

    /// The `Callback<String>` a row Fix of `kind` reports through; see
    /// [`Self::row_done`].
    pub(crate) fn done_for(self, kind: RemediationKind) -> Callback<String> {
        match kind {
            RemediationKind::RemoveExpiredCredentials => self.row_done.expired,
            RemediationKind::RemoveRedundantPermissions => self.row_done.redundant,
            RemediationKind::ScopeMailboxAccess => self.row_done.mailbox,
            RemediationKind::MigrateApplicationAccessPolicy => self.row_done.migrate,
            RemediationKind::ScopeSharePointAccess => self.row_done.sharepoint,
            RemediationKind::AddOwner => self.row_done.add_owner,
            RemediationKind::DisableSignIn => self.row_done.disable,
        }
    }

    /// Exports by reference: the backend serves its own cached run, so the
    /// item vector doesn't round-trip the IPC bridge. Any run the backend did
    /// not cache (cancelled, truncated or degraded) ships its items along: the
    /// cache holds nothing for it — or an EARLIER complete run, which would be
    /// written out in its place and labelled complete.
    ///
    /// The run's coverage always rides along, cached path included: the file
    /// leaving the app has to carry the same caveats this workbench refuses to
    /// omit on screen, and an incomplete run — the one that ships its items
    /// here — is exactly the one with something to disclose.
    pub(crate) fn export(self, format: &'static str) {
        if self.exporting.get() {
            return;
        }
        let Some(t) = self.session.active_tenant.get() else {
            return;
        };
        let (empty, uncached_items, coverage) = self.result.with(|r| match r.as_ref() {
            Some(r) => {
                // `is_complete` is the same conjunction as the backend's cache
                // guard, so "incomplete" here means "not in the cache".
                let coverage = r.coverage();
                (
                    r.items.is_empty(),
                    (!coverage.is_complete()).then(|| r.items.clone()),
                    coverage,
                )
            }
            None => (true, None, AuditExportCoverage::default()),
        });
        if empty {
            return;
        }
        self.exporting.set(true);
        leptos::task::spawn_local(async move {
            match audit::save_audit_to_file(
                &t.tenant_id,
                uncached_items.as_deref(),
                coverage,
                format,
            )
            .await
            {
                // Success + failure both surface through the shared bottom-right
                // toast system (matching the list-view exports), not a
                // persistent inline banner.
                Ok(Some(path)) => {
                    self.session.toast_success(format!("Saved audit to {path}"));
                }
                Ok(None) => {} // user cancelled
                Err(e) => self.session.report_command_error(&e),
            }
            self.exporting.set(false);
        });
    }
}
