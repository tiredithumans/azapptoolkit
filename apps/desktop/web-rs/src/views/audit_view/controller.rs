//! Shared audit run state for the Security workbench.
//!
//! The posture strip, the Findings pane, and the All-apps pane all read one
//! scan: `AuditController` bundles the run/progress/export signals, the derived
//! memos, and the run/cancel/export/consent actions. Constructed **once** in
//! `SecurityView` (which lives for the app's lifetime under the shell's
//! keep-alive routing) and provided via context; panes `expect_context` it.
//! All fields are arena-backed handles, so the struct is `Copy` and closures
//! capture it wholesale.

use leptos::prelude::*;

use crate::bindings::audit::{self, AuditProgress, AuditRunResult};
use crate::bindings::auth;
use crate::bindings::events;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::Session;

use super::posture::{PostureCounts, posture_counts};

#[derive(Clone, Copy)]
pub(crate) struct AuditController {
    session: Session,
    pub result: RwSignal<Option<AuditRunResult>>,
    pub scanning: RwSignal<bool>,
    pub progress: RwSignal<Option<AuditProgress>>,
    /// High-water concurrency cap. When the live cap later drops below this
    /// peak, Graph is throttling and the scan is backing off — surfaced so a
    /// slow audit reads as expected, not stalled. Monotonic within a run;
    /// reset when a new run clears `progress`.
    pub peak_cap: RwSignal<usize>,
    pub scan_error: RwSignal<Option<String>>,
    pub exporting: RwSignal<bool>,
    pub export_msg: RwSignal<Option<String>>,
    /// Per-bucket counts for the posture strip + Home card, computed once per
    /// scan (never per keystroke) without cloning the multi-MB run.
    pub posture: Memo<Option<PostureCounts>>,
    pub consent_needed: Memo<bool>,
    pub total_items: Memo<Option<usize>>,
    pub report_available: Memo<bool>,
    /// When a row's remediation succeeds, drops that item's remediations so
    /// the "Fix" button is gone for good (the audit cache is already busted
    /// server-side; scores refresh on the next manual re-run).
    pub on_remediated: Callback<String>,
    /// After a successful inline bulk run, refetch the App Registrations list
    /// (a delete / remove-expired sweep busts its backend cache). The audit's
    /// own scan is a point-in-time snapshot — deleted rows linger until the
    /// next manual re-run, matching how the audit cache already works.
    pub on_bulk_done: Callback<()>,
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
        let export_msg: RwSignal<Option<String>> = RwSignal::new(None);

        let posture =
            Memo::new(move |_| result.with(|r| r.as_ref().map(|r| posture_counts(&r.items))));
        let consent_needed = Memo::new(move |_| {
            result.with(|r| r.as_ref().is_some_and(|r| r.sign_in_consent_required))
        });
        let total_items = Memo::new(move |_| result.with(|r| r.as_ref().map(|r| r.items.len())));
        let report_available = Memo::new(move |_| {
            result.with(|r| r.as_ref().is_some_and(|r| r.sign_in_report_available))
        });

        let on_remediated = Callback::new(move |object_id: String| {
            result.update(|opt| {
                if let Some(r) = opt.as_mut()
                    && let Some(item) = r.items.iter_mut().find(|i| i.object_id == object_id)
                {
                    item.remediations.clear();
                }
            });
        });
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
                let cached = audit::get_cached_audit(&tenant_id).await;
                let still_active = tenant
                    .get_untracked()
                    .map(|t| t.tenant_id == tenant_id)
                    .unwrap_or(false);
                if still_active {
                    result.set(cached);
                }
            });
        });

        Self {
            session,
            result,
            scanning,
            progress,
            peak_cap,
            scan_error,
            exporting,
            export_msg,
            posture,
            consent_needed,
            total_items,
            report_available,
            on_remediated,
            on_bulk_done,
        }
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
            in_flight_cap: 8,
            cancelled: false,
        }));
        let t = self.session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = t else {
                self.scanning.set(false);
                return;
            };
            match audit::run_audit(&t.tenant_id).await {
                Ok(r) => {
                    self.result.set(Some(r));
                    // Refresh the Home dashboard's "Security Posture" tile: it
                    // keeps its cached-audit resource alive across view
                    // switches, so it only refetches when this bumps.
                    self.session.bump_audit_reload();
                }
                Err(e) => self.scan_error.set(Some(e.message)),
            }
            self.scanning.set(false);
            self.progress.set(None);
        });
    }

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
            match auth::request_scope_consent(&t.tenant_id, "audit_log").await {
                Ok(()) => self.run(),
                Err(e) => self.scan_error.set(Some(e.message)),
            }
        });
    }

    /// Exports by reference: the backend serves its own cached run, so the
    /// item vector doesn't round-trip the IPC bridge. Only a CANCELLED run
    /// (never cached backend-side) ships its items along.
    pub(crate) fn export(self, format: &'static str) {
        if self.exporting.get() {
            return;
        }
        let Some(t) = self.session.active_tenant.get() else {
            return;
        };
        let (empty, cancelled_items) = self.result.with(|r| match r.as_ref() {
            Some(r) => (r.items.is_empty(), r.cancelled.then(|| r.items.clone())),
            None => (true, None),
        });
        if empty {
            return;
        }
        self.exporting.set(true);
        self.export_msg.set(None);
        leptos::task::spawn_local(async move {
            match audit::save_audit_to_file(&t.tenant_id, cancelled_items.as_deref(), format).await
            {
                Ok(Some(path)) => self.export_msg.set(Some(format!("Saved to {path}"))),
                Ok(None) => {} // user cancelled
                Err(e) => self
                    .export_msg
                    .set(Some(format!("Export failed: {}", e.message))),
            }
            self.exporting.set(false);
        });
    }
}
