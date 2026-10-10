//! Inline bulk-action bar over a multi-selected set of app-registration object
//! ids.
//!
//! The **single home** of the selection-driven bulk command-calling logic: the
//! Security workbench (one bar per expanded Findings group + the All-apps
//! pane), the App Registrations list, and the Bulk Actions page all mount this
//! same component. The offered actions are configurable (the `actions` signal)
//! so each host shows the right set — a Findings group offers exactly the fix
//! paired with its rule (no bulk admin consent on audit surfaces), while the App
//! Registrations list / Bulk Actions page show the management set.
//!
//! Each action arms an inline panel before running. The panel opens by naming
//! the apps the run is about to touch, then gates on that action's own
//! requirement: destructive ones (Remove expired, Delete) behind a typed
//! REMOVE/DELETE confirmation, the scoping ones behind a small target form
//! (mailbox groups / site URLs) reusing the same shapes as the per-row "Scope…"
//! fixes, Add-owner behind a directory-search picker, and Disable-sign-in behind
//! a plain confirm (reversible). A live progress row naming the app being
//! mutated + Cancel, and a tone-coded summary that reports the apps a stopped
//! run never reached, mirror the former tab-per-action page.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, ProgressBar, Textarea};

use crate::bindings::applications;
use crate::bindings::bulk;
use crate::bindings::events;
use crate::components::group_autocomplete::MailboxGroupsField;
use crate::components::ui::{Callout, FormError};
use crate::constants::RENDER_PAGE;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::{Session, use_session};
use crate::util::{count_noun, parse_lines};

/// One failed item from a bulk run, surfaced below the aggregate summary so the
/// user can see *which* app failed and *why*. Public so the Bulk Actions page's
/// Create flow can reuse the same shape.
#[derive(Clone)]
pub struct BulkFailure {
    pub label: String,
    pub reason: String,
    /// The object id this failure belongs to, so the bar can hand the operator
    /// the failed set back as a selection. Re-checking six failures out of a
    /// 200-row list by hand is precisely the work this bar exists to avoid, and
    /// the summary's "re-run to finish" is an empty instruction without it.
    ///
    /// `None` only where no id exists: the Bulk Actions page's Create flow
    /// reports apps that were never created.
    pub object_id: Option<String>,
    /// The backend wire code, when this failure came from a command call.
    /// `None` for failures the frontend synthesizes (e.g. "3 credentials could
    /// not be removed", derived from counts rather than an error).
    ///
    /// Kept because flattening the error to its message alone loses the one bit
    /// the UI must act on: a mid-run `refresh_missing` means the SESSION died,
    /// not that this app failed, and it needs a re-auth prompt rather than a
    /// line in a failure list.
    pub code: Option<String>,
}

/// One bulk outcome's failure, if any — the shape every per-item outcome DTO
/// shares. A local trait over foreign types so the seven `parse_*` helpers can
/// share one collector instead of repeating the same
/// filter_map-over-outcomes/build-BulkFailure skeleton.
trait BulkRow {
    fn object_id(&self) -> &str;
    fn error(&self) -> Option<&bulk::BulkError>;
}

macro_rules! bulk_row {
    ($($ty:ty),+ $(,)?) => {$(
        impl BulkRow for $ty {
            fn object_id(&self) -> &str { &self.object_id }
            fn error(&self) -> Option<&bulk::BulkError> { self.error.as_ref() }
        }
    )+};
}

bulk_row!(
    bulk::BulkGrantOutcome,
    bulk::BulkRemoveRedundantOutcome,
    bulk::BulkScopeOutcome,
    bulk::BulkOwnerOutcome,
    bulk::BulkDisableOutcome,
    bulk::BulkStageCertOutcome,
    bulk::BulkRestoreOutcome,
);

/// The failed rows of a bulk run, labelled for display.
fn failures_of<T: BulkRow>(outcomes: &[T], label_for: impl Fn(&str) -> String) -> Vec<BulkFailure> {
    outcomes
        .iter()
        .filter_map(|o| {
            o.error().map(|e| BulkFailure {
                label: label_for(o.object_id()),
                reason: e.message.clone(),
                object_id: Some(o.object_id().to_string()),
                code: Some(e.code.clone()),
            })
        })
        .collect()
}

/// The first failure that means the session died rather than the item failing.
/// The backend already stops the run on one of these, so at most the tail of the
/// selection is unprocessed — the UI's job is to offer re-auth instead of
/// presenting it as N app-level failures.
pub fn session_dead_error(failures: &[BulkFailure]) -> Option<azapptoolkit_dto::UiError> {
    failures
        .iter()
        .find(|f| {
            f.code
                .as_deref()
                .is_some_and(|c| azapptoolkit_dto::UiError::new(c, "", false).is_reauth_fatal())
        })
        .map(|f| {
            azapptoolkit_dto::UiError::new(f.code.clone().unwrap_or_default(), &f.reason, false)
        })
}

/// One bulk result, read into everything the bar has to render.
struct Parsed {
    summary: String,
    failures: Vec<BulkFailure>,
    /// How many of the attempted ids the run produced an outcome for, when the
    /// result makes that knowable.
    ///
    /// `run_bulk_seq` **breaks out of its loop** on Cancel or a dead session and
    /// returns only the outcomes it produced; the `dispatch_capped` commands
    /// simply never dispatch the tail. A short count is therefore the only
    /// evidence in the result that the rest of the selection was never touched
    /// — and counting successes as `outcomes.len() - failures.len()` and
    /// stopping there is what let a Cancel at item 12 of 40 read as a finished
    /// run over 12 apps, with the 28 untouched ones unmentioned.
    ///
    /// `None` where reach is genuinely not derivable — see
    /// [`parse_remove_expired`].
    reached: Option<usize>,
    /// Object ids that no longer exist and must leave the selection. Delete
    /// only, and only the ids Graph confirmed gone.
    deleted: Vec<String>,
    /// Stopped by the operator's Cancel (the summary already says so).
    cancelled: bool,
}

impl Parsed {
    /// A run whose outcome count *is* its reach — every command but the
    /// credential sweep — and which strands no ids.
    fn new(summary: String, failures: Vec<BulkFailure>, reached: usize, cancelled: bool) -> Self {
        Parsed {
            summary,
            failures,
            reached: Some(reached),
            deleted: Vec::new(),
            cancelled,
        }
    }

    /// Whether the run did everything it was asked: nothing failed, nothing
    /// was cancelled, and it reached every one of the `attempted` ids (a reach
    /// that is not knowable counts as complete — a note that guesses is worse
    /// than none).
    fn is_clean(&self, attempted: usize) -> bool {
        self.failures.is_empty() && !self.cancelled && self.reached.is_none_or(|r| r >= attempted)
    }
}

/// Names the tail a stopped run never reached, appended to every summary.
///
/// A cancelled or session-killed run used to report only what it produced, so
/// "Scoped mailbox access on 11 app(s); 1 failed (cancelled)" was the whole
/// story of a 40-app run and the operator's only way to find the other 28 was
/// to diff the report against the tenant. Same failure mode and same voice as
/// the AAP migration report's `unattempted` disclosure. Empty when the run
/// reached everything, or when its reach is not knowable — a note that guesses
/// is worse than none.
///
/// `still_selected`: the mounted bar can promise the tail is still checked
/// (the selection is the host's and the run touched only the deleted ids); a
/// bar that is gone cannot — collapsing a Findings group clears that
/// selection — so its toast says only what was not attempted.
fn unattempted_note(attempted: usize, reached: Option<usize>, still_selected: bool) -> String {
    match (
        reached.map_or(0, |r| attempted.saturating_sub(r)),
        still_selected,
    ) {
        (0, _) => String::new(),
        (1, true) => " — 1 app was never attempted and is still selected; re-run to finish.".into(),
        (1, false) => " — 1 app was never attempted; select it again to finish.".into(),
        (n, true) => {
            format!(" — {n} apps were never attempted and are still selected; re-run to finish.")
        }
        (n, false) => format!(" — {n} apps were never attempted; select them again to finish."),
    }
}

/// Resolve an object id to the host-supplied display name, falling back to the
/// id itself. One definition, because the failure labels and the progress row
/// resolve the same ids out of the same map.
///
/// `try_`: a run's results are labelled after its await, and by then the host
/// that derived `names` may be gone (sign-out unmounts the shell mid-run). A
/// disposed map falls back to the id rather than panicking.
fn label_with(names: Option<Signal<Arc<HashMap<String, String>>>>, key: &str) -> String {
    names
        .and_then(|n| n.try_with(|m| m.get(key).cloned()).flatten())
        .unwrap_or_else(|| key.to_string())
}

/// Everything a bulk run touches once its command returns, and the rules for
/// touching it.
///
/// A run outlives the bar that started it, two ways:
///
/// - **The tenant it ran for is no longer active** (a switch, or sign-out,
///   which clears the tenant and unmounts the whole authed shell). The result
///   belongs to nobody on screen, and a toast pushed onto the shell-root
///   `Session` would surface in the next sign-in — so the run lands nowhere.
/// - **Same tenant, but the bar was unmounted** (the operator navigated away,
///   or a Findings group collapsed). The bar's own signals are disposed, but
///   the run's session-level effects still matter: its toasts and re-auth
///   prompt, the confirmed-deleted ids leaving the session-owned selection, a
///   failure that would otherwise be silent, and the host's refresh. Only the
///   bar-local writes are skipped.
///
/// The decisions live here, synchronously, so the native tests drive the very
/// code the spawned tasks run.
#[derive(Clone, Copy)]
struct Landing {
    session: Session,
    selection: RwSignal<HashSet<String>>,
    names: Option<Signal<Arc<HashMap<String, String>>>>,
    /// Run through `try_run` and NOT gated on the bar: a host can outlive its
    /// bar (the audit's per-group bars share the workbench's refresh), and a
    /// host that is gone simply skips it.
    on_done: Option<Callback<()>>,
    busy: RwSignal<bool>,
    summary: RwSignal<Option<String>>,
    failures: RwSignal<Vec<BulkFailure>>,
    error: RwSignal<Option<String>>,
    armed: RwSignal<Option<BulkAction>>,
    undo_ids: RwSignal<Vec<String>>,
}

impl Landing {
    /// Whether the bar's own signals are still live. `busy` stands in for the
    /// set: they are created together, so they are disposed together.
    fn bar_mounted(self) -> bool {
        !self.busy.is_disposed()
    }

    fn done(self) {
        if let Some(cb) = self.on_done {
            cb.try_run(());
        }
    }

    /// Land one action's result. `attempted` is the selection size the run
    /// started from; every summary is measured against it.
    fn finish_action(
        self,
        started_for: &str,
        action: BulkAction,
        attempted: usize,
        parsed: Result<Parsed, azapptoolkit_dto::UiError>,
    ) {
        if !self.session.is_active_tenant(started_for) {
            // A no-op on a disposed bar; a live one just needs its controls.
            self.busy.set(false);
            return;
        }
        let mounted = self.bar_mounted();
        match parsed {
            Ok(p) => {
                // A failure carrying a re-auth-fatal code means the session
                // died mid-run, not that these apps are broken. The backend
                // already halted the loop; surface the recovery action so
                // the operator re-authenticates in place (never a sign-out —
                // that drops every data cache) instead of reading a list of
                // failures with no obvious cause.
                if let Some(dead) = session_dead_error(&p.failures) {
                    self.session.report_if_session_dead(&dead);
                }
                if mounted {
                    self.summary.set(Some(format!(
                        "{}{}",
                        p.summary,
                        unattempted_note(attempted, p.reached, true)
                    )));
                    self.failures.set(p.failures);
                    self.armed.set(None);
                    // A completed delete leaves its confirmed-gone ids on hand
                    // for one Undo run (recycle-bin restore).
                    if matches!(action, BulkAction::Delete) {
                        self.undo_ids.set(p.deleted.clone());
                    }
                } else {
                    // The bar is gone (a Findings group collapsed, the Bulk
                    // Actions tab switched) but the run's outcome is not: a
                    // failure or a stopped run nobody sees is one the operator
                    // rediscovers on the next scan. The summary lands as a
                    // toast — red unless the run did everything it was asked.
                    let summary = format!(
                        "{}{}",
                        p.summary,
                        unattempted_note(attempted, p.reached, false)
                    );
                    if p.is_clean(attempted) {
                        self.session.toast_success(summary);
                    } else {
                        self.session.toast_error(summary, None);
                    }
                }
                // ONLY the ids the backend confirmed gone leave the
                // selection. Clearing the whole set — what a bare
                // "clears-selection" flag did — threw away the apps a
                // cancelled delete never reached along with the ones it
                // deleted, destroying the operator's work queue at the exact
                // moment the summary was telling them to re-run. Not gated on
                // the bar: the selection is the host's (usually the
                // session's), and a deleted id left in it is a dangling one —
                // in the host's set and in every other session set alike.
                if !p.deleted.is_empty() {
                    let gone: HashSet<String> = p.deleted.into_iter().collect();
                    self.selection
                        .try_update(|s| s.retain(|id| !gone.contains(id)));
                    for id in &gone {
                        self.session.deselect_object(id);
                    }
                }
                self.done();
            }
            // The bar's inline error is this surface's message — plus the
            // recovery lever (Re-authenticate / Refresh token / Grant consent)
            // when the failure needs one, exactly as `CommandState::fail_inline`
            // does. A dead session mid-run used to be a red line saying "sign
            // in again", which here means a sign-out that drops every cache.
            // With the bar gone, the session's sink is the only place it can
            // still be read.
            Err(e) if mounted => {
                self.session
                    .report_recovery_action(&e, action.consent_feature());
                self.error.set(Some(e.message));
            }
            Err(e) => self
                .session
                .report_command_error_for(&e, action.consent_feature()),
        }
        self.busy.set(false);
        self.session.tenant_ui.bulk_running.set(false);
    }

    /// Land an Undo (recycle-bin restore) result.
    fn finish_undo(
        self,
        started_for: &str,
        attempted: usize,
        res: Result<bulk::BulkRestoreResult, azapptoolkit_dto::UiError>,
    ) {
        if !self.session.is_active_tenant(started_for) {
            self.busy.set(false);
            return;
        }
        let mounted = self.bar_mounted();
        match res {
            Ok(r) => {
                let reached = r.outcomes.len();
                let restored = r.outcomes.iter().filter(|o| o.restored).count();
                let fails = failures_of(&r.outcomes, |id| label_with(self.names, id));
                if let Some(dead) = session_dead_error(&fails) {
                    self.session.report_if_session_dead(&dead);
                }
                // Read before `failures.set(fails)` moves the vec.
                let clean = fails.is_empty();
                let summary = format!(
                    "Restored {restored} of {}.{}",
                    count_noun(attempted, "deleted app", "deleted apps"),
                    unattempted_note(attempted, Some(reached), mounted)
                );
                if mounted {
                    self.summary.set(Some(summary.clone()));
                    self.failures.set(fails);
                }
                if !r.cancelled && restored > 0 && clean {
                    self.session
                        .toast_success(format!("Restored {restored} of {attempted} deleted apps."));
                } else if !mounted {
                    // Same rule as `finish_action`: a restore that failed or
                    // stopped while its bar was gone is not silent.
                    self.session.toast_error(summary, None);
                }
                self.done();
            }
            // The lever when one applies, and the inline text as the message;
            // the full sink (which also toasts an ordinary failure) only when
            // the bar is gone and the inline text has nowhere to show.
            Err(e) if mounted => {
                self.session.report_recovery_action(&e, "write");
                self.error.set(Some(e.message));
            }
            Err(e) => self.session.report_command_error(&e),
        }
        self.busy.set(false);
        self.session.tenant_ui.bulk_running.set(false);
    }
}

/// The live progress row for an in-flight bulk run: a determinate bar, the
/// counter, the app being mutated *right now*, and Cancel.
///
/// Shared by the bar and the Bulk Actions page's Create flow so the two cannot
/// describe the same run differently. It replaces a bare spinner that dropped
/// `BulkProgress.current_app` on the floor: the read-only audit scan
/// has always shown n/m plus the app it is reading, while the operator deciding
/// whether to Cancel a 40-app scope-and-strip — the run that is actually
/// mutating things — saw "Working… (12/40)" and could not tell what was
/// mid-mutation.
///
/// Mount it only while the run is in flight (`busy.get().then(…)`): `cancelling`
/// lives here, so each run gets a fresh Cancel rather than one still reading
/// "Cancelling…" from the last one.
#[component]
pub fn BulkProgressRow(
    /// Stream-driven progress. `None` (or `total == 0`) until the first event,
    /// which the bar renders as an empty bar rather than as nothing — the row
    /// appearing is itself the signal that the run started.
    progress: RwSignal<Option<bulk::BulkProgress>>,
    /// `object_id -> display name`, as passed to [`BulkActionBar`].
    /// `run_bulk_seq` labels its progress events with the object id it was
    /// handed, so without this the row would name the app by GUID; the fan-out
    /// commands and the Create flow already send a display name, which passes
    /// through unchanged. Not `#[prop(optional)]` — both hosts state what they
    /// have, and the Create flow's `None` is a fact about it, not an omission.
    names: Option<Signal<Arc<HashMap<String, String>>>>,
) -> impl IntoView {
    let cancelling = RwSignal::new(false);
    let do_cancel = move |_| {
        if cancelling.get() {
            return;
        }
        cancelling.set(true);
        leptos::task::spawn_local(async move {
            bulk::cancel_bulk().await;
        });
    };
    let fraction = Signal::derive(move || {
        progress.with(|p| match p {
            Some(p) if p.total > 0 => p.done as f64 / p.total as f64,
            _ => 0.0,
        })
    });

    view! {
        <ProgressBar value=fraction />
        <div class="actions-row">
            <Body1>
                {move || match progress.get() {
                    Some(p) if p.total > 0 => {
                        // "Working… (12/40) — Contoso API", the DR restore's
                        // shape. The name is what makes Cancel a decision
                        // rather than a guess.
                        let current = p
                            .current_app
                            .map(|a| format!(" — {}", label_with(names, &a)))
                            .unwrap_or_default();
                        format!("Working… ({}/{}){current}", p.done, p.total)
                    }
                    _ => "Working…".to_string(),
                }}
            </Body1>
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                on_click=Box::new(do_cancel)
                disabled=Signal::derive(move || cancelling.get())
            >
                {move || if cancelling.get() { "Cancelling…" } else { "Cancel" }}
            </Button>
        </div>
    }
}

/// The bulk operations a bar can offer. Hosts pass the subset they support.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkAction {
    Grant,
    RemoveExpired,
    RemoveRedundant,
    ScopeMailbox,
    ScopeSharePoint,
    AddOwner,
    DisableSignIn,
    /// Stage a fresh SAML signing certificate on each selected app WITHOUT
    /// activating it. Takes service-principal ids, not app-registration object
    /// ids — signing certificates live on the SP.
    StageSsoCertificate,
    Delete,
}

/// What the confirm step requires before an armed action may run.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Confirm {
    /// Type this exact word. Irreversible, tenant-wide, or both.
    Keyword(&'static str),
    /// At least one mailbox group line.
    Groups,
    /// At least one site URL line.
    Sites,
    /// An owner picked from the directory.
    Owner,
    /// A plain click suffices — reversible, or self-evidently safe.
    Click,
}

/// Everything the bar needs to know about one action, in one place.
///
/// This was three parallel per-action `match`es — `label`, `is_destructive`, and
/// the `confirm_ok` memo — plus a fourth deciding the confirm input's
/// placeholder. Adding an action meant editing all four and hoping; and the two
/// keyword tables had no relationship to each other, so a disagreement between
/// them would show the operator one word and require another, leaving the
/// confirm button disabled with nothing on screen explaining why. The armed
/// panel's confirm-button text and description moved here too, so the panel
/// has no per-action `match` left; the only per-action dispatch that remains is
/// the runner in `run`, which is necessarily per-command.
struct Spec {
    label: &'static str,
    /// Destroys or revokes something, so it must render red wherever it is
    /// offered. Used by BOTH the arming chip and the confirm button — they
    /// disagreed before, and "Remove expired credentials" armed as an ordinary
    /// button while deleting credentials across the whole selection.
    ///
    /// `DisableSignIn` is excluded deliberately: it is reversible (re-enable
    /// flips it back), and reserving red for the irreversible keeps the signal
    /// worth reading. `Grant` is not destructive either, but it still requires a
    /// typed keyword on its own high-privilege grounds — which is exactly why
    /// "is it red" and "how is it confirmed" are separate fields rather than one
    /// flag doing double duty.
    ///
    /// `RemoveRedundant` is the one destructive action confirmed by a click:
    /// the backend re-resolves each app live and removes only permissions
    /// strictly covered by a broader grant the app keeps, so load-bearing
    /// grants survive and effective access is unchanged.
    destructive: bool,
    confirm: Confirm,
    /// The armed panel's point-of-no-return button text.
    confirm_label: &'static str,
    /// The armed panel's sentence, given the selected count.
    description: fn(usize) -> String,
}

impl BulkAction {
    /// Every action, in declaration order. Adding a variant: list it here and
    /// give it a slot in `tests::slot` (an exhaustive match that won't compile
    /// until you do).
    #[cfg(test)]
    pub(crate) const ALL: [BulkAction; 9] = [
        BulkAction::Grant,
        BulkAction::RemoveExpired,
        BulkAction::RemoveRedundant,
        BulkAction::ScopeMailbox,
        BulkAction::ScopeSharePoint,
        BulkAction::AddOwner,
        BulkAction::DisableSignIn,
        BulkAction::StageSsoCertificate,
        BulkAction::Delete,
    ];

    fn spec(self) -> Spec {
        match self {
            BulkAction::Grant => Spec {
                label: "Grant consent",
                destructive: false,
                confirm: Confirm::Keyword("GRANT"),
                confirm_label: "Grant consent",
                description: |n| {
                    format!(
                        "Grant admin consent to the {} — this consents every permission each app requests, tenant-wide, on behalf of all users. Consent stays in place until revoked per app.",
                        count_noun(n, "selected app", "selected apps")
                    )
                },
            },
            BulkAction::RemoveExpired => Spec {
                label: "Remove expired credentials",
                destructive: true,
                confirm: Confirm::Keyword("REMOVE"),
                confirm_label: "Remove expired",
                description: |n| {
                    format!(
                        "Remove every expired password credential from the {}. This is irreversible.",
                        count_noun(n, "selected app", "selected apps")
                    )
                },
            },
            // Red because it deletes grants, but a click suffices: the backend
            // re-resolves each app live and removes only permissions strictly
            // covered by a broader grant the app keeps, so effective access is
            // unchanged. Pinned by `tests::CLICK_CONFIRMED_DESTRUCTIVE`.
            BulkAction::RemoveRedundant => Spec {
                label: "Remove redundant permissions",
                destructive: true,
                confirm: Confirm::Click,
                confirm_label: "Remove redundant",
                description: |n| {
                    format!(
                        "Remove redundant application permissions (narrower ones already covered by a broader grant) from the {}. Re-resolved live per app; load-bearing grants are kept.",
                        count_noun(n, "selected app", "selected apps")
                    )
                },
            },
            BulkAction::ScopeMailbox => Spec {
                label: "Scope mailbox access",
                destructive: false,
                confirm: Confirm::Groups,
                confirm_label: "Scope mailbox",
                description: |n| {
                    format!(
                        "Confine the mailbox permissions of the {} to the groups below via Exchange RBAC (every mail permission each app holds is scoped). Needs Exchange admin rights.",
                        count_noun(n, "selected app", "selected apps")
                    )
                },
            },
            BulkAction::ScopeSharePoint => Spec {
                label: "Scope SharePoint access",
                destructive: false,
                confirm: Confirm::Sites,
                confirm_label: "Scope SharePoint",
                description: |n| {
                    format!(
                        "Convert the org-wide SharePoint access of the {} to Sites.Selected on the sites below.",
                        count_noun(n, "selected app", "selected apps")
                    )
                },
            },
            BulkAction::AddOwner => Spec {
                label: "Add owner",
                destructive: false,
                confirm: Confirm::Owner,
                confirm_label: "Add owner",
                description: |n| {
                    format!(
                        "Add one user as an owner of the {}. Purely additive — apps that already have this owner are skipped.",
                        count_noun(n, "selected app", "selected apps")
                    )
                },
            },
            BulkAction::DisableSignIn => Spec {
                label: "Disable sign-in",
                destructive: false,
                confirm: Confirm::Click,
                confirm_label: "Disable sign-in",
                description: |n| {
                    format!(
                        "Disable sign-in for the {} by disabling their service principals. Reversible — re-enable anytime from the enterprise app's Overview.",
                        count_noun(n, "selected app", "selected apps")
                    )
                },
            },
            // Additive and inactive: the new certificate signs nothing until it
            // is activated per app, so this is neither destructive nor worth a
            // typed keyword. The risk it carries is the opposite of the usual
            // one — doing nothing is what breaks sign-in.
            BulkAction::StageSsoCertificate => Spec {
                label: "Stage signing certificates",
                destructive: false,
                confirm: Confirm::Click,
                confirm_label: "Stage certificates",
                description: |n| {
                    format!(
                        "Generate a new SAML signing certificate on the {} and leave it INACTIVE. Nothing changes for users: each app keeps signing with its current certificate until you activate the new one from its SSO tab. Apps that already have a replacement staged are skipped.",
                        count_noun(n, "selected app", "selected apps")
                    )
                },
            },
            // Entra soft-deletes app registrations for 30 days, so the copy
            // must not call this permanent (the single-app dialog says the
            // same), and since F266 the undo is IN-app: the bar's own Undo
            // button right after the run, then the "Recently deleted" view.
            BulkAction::Delete => Spec {
                label: "Delete",
                destructive: true,
                confirm: Confirm::Keyword("DELETE"),
                confirm_label: "Delete",
                description: |n| {
                    format!(
                        "Delete the {}. Their service principals' permission grants are revoked and any credentials stop working immediately. The apps stay recoverable for 30 days — undo below right after the run, or restore them from \"Recently deleted…\".",
                        count_noun(n, "selected app registration", "selected app registrations")
                    )
                },
            },
        }
    }

    /// Which consent set a `consent_required` failure of this action can be
    /// fixed by — the key `AppState::consent_scopes_for` accepts. The scoping
    /// actions ride their resource's on-demand scopes; everything else is a
    /// Graph write.
    fn consent_feature(self) -> &'static str {
        match self {
            BulkAction::ScopeMailbox => "exchange",
            BulkAction::ScopeSharePoint => "sharepoint",
            _ => "write",
        }
    }

    fn label(self) -> &'static str {
        self.spec().label
    }

    fn is_destructive(self) -> bool {
        self.spec().destructive
    }
}

#[component]
pub fn BulkActionBar(
    /// The selection set this bar operates on (app-registration object ids).
    ///
    /// The bar writes to it twice: a Delete drops the ids the backend confirmed
    /// gone (only those — a cancelled run's untouched tail stays checked), and
    /// "Select only the N failed" narrows it to the failures so the operator can
    /// re-run without rebuilding the set by hand.
    selection: RwSignal<HashSet<String>>,
    /// The actions to offer, in display order. Reactive so the audit can derive
    /// it from the active finding filter; static hosts pass a constant.
    actions: Signal<Vec<BulkAction>>,
    /// Fired after any successful run so the host can refetch its list(s).
    #[prop(optional, into)]
    on_done: Option<Callback<()>>,
    /// `object_id -> display name` for the selectable rows, used to label
    /// failures.
    ///
    /// The bulk commands take object ids, so their outcomes carry only ids —
    /// which meant a failure list after (say) a 200-app delete was a column of
    /// raw GUIDs with no way to tell WHICH app failed. The host already has the
    /// names (the selection was made from its list), so it supplies them here.
    /// Empty map ⇒ fall back to the id, the previous behaviour.
    #[prop(optional, into)]
    names: Option<Signal<Arc<HashMap<String, String>>>>,
) -> impl IntoView {
    let session = use_session();
    // Resolve an object id to its display name for failure labels.
    let label_for = move |object_id: &str| -> String { label_with(names, object_id) };

    let busy = RwSignal::new(false);
    // A run started from ANY bar (or the Bulk Actions page's Create) blocks
    // this one: the bars share their selection and the backend's one cancel
    // flag, and the App Registrations list and the Bulk Actions page both stay
    // mounted, so a second Delete on the very same ids was one click away.
    let bulk_running = session.tenant_ui.bulk_running;
    let blocked = Memo::new(move |_| busy.get() || bulk_running.get());
    let summary: RwSignal<Option<String>> = RwSignal::new(None);
    let failures: RwSignal<Vec<BulkFailure>> = RwSignal::new(Vec::new());
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let progress: RwSignal<Option<bulk::BulkProgress>> = RwSignal::new(None);
    use_progress_stream(progress, events::bulk_progress);

    // The delete run's confirmed-gone ids, kept for exactly one follow-up:
    // "Undo (restore N deleted)" replays them through the recycle bin. Cleared
    // when any new run starts, so it can only ever name the LAST run.
    let undo_ids: RwSignal<Vec<String>> = RwSignal::new(Vec::new());
    let armed: RwSignal<Option<BulkAction>> = RwSignal::new(None);
    let landing = Landing {
        session,
        selection,
        names,
        on_done,
        busy,
        summary,
        failures,
        error,
        armed,
        undo_ids,
    };

    // Sequential restore over the deleted ids — the same `bulk_*` shape as
    // every action here: one busy flag, summary + per-item failures, and a
    // toast because the host's `on_done` refetch may re-mount the bar before
    // the summary is read.
    let undo = Callback::new(move |ids: Vec<String>| {
        if blocked.get() || ids.is_empty() {
            return;
        }
        undo_ids.set(Vec::new());
        busy.set(true);
        bulk_running.set(true);
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        progress.set(None);
        let attempted = ids.len();
        let tenant = session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                bulk_running.set(false);
                return;
            };
            let tid = &t.tenant_id;
            let res = bulk::bulk_restore_deleted(tid, &ids).await;
            landing.finish_undo(tid, attempted, res);
        });
    });

    // Arming: every action except Grant reveals an inline panel (a typed
    // confirmation for the destructive ones, a target form for the scoping ones)
    // before running. `armed` holds which action's panel is open; the input
    // fields reset whenever it changes, and `armed` itself clears when the
    // offered action set changes (e.g. the audit's finding filter switches).
    let confirm_text = RwSignal::new(String::new());
    let groups_text = RwSignal::new(String::new());
    let sites_text = RwSignal::new(String::new());
    let sp_write = RwSignal::new(false);
    // Add-owner picker state: a debounced directory search + the single picked
    // principal `(id, label)`. Created here (not in the armed panel, which is
    // rebuilt per arming) so the resource lives once per bar.
    let owner_query = RwSignal::new(String::new());
    let owner_pick: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let owner_query_debounced = use_debounced(owner_query.into(), 300);
    let owner_candidates = LocalResource::new(move || {
        let q = owner_query_debounced.get();
        let tenant = session.active_tenant.get();
        async move {
            let q = q.trim().to_string();
            if q.len() < 2 {
                return Ok::<Vec<DirectoryObject>, String>(Vec::new());
            }
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            applications::search_users(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
        }
    });
    Effect::new(move |_| {
        let _ = armed.get();
        confirm_text.set(String::new());
        groups_text.set(String::new());
        sites_text.set(String::new());
        sp_write.set(false);
        owner_query.set(String::new());
        owner_pick.set(None);
    });
    Effect::new(move |_| {
        let _ = actions.get();
        armed.set(None);
    });

    // The armed action's confirm button is enabled only when its inputs are
    // valid: the exact keyword typed (destructive), or ≥1 target line (scoping).
    let confirm_ok = Memo::new(move |_| match armed.get().map(BulkAction::spec) {
        Some(spec) => match spec.confirm {
            Confirm::Keyword(word) => confirm_text.get().trim() == word,
            Confirm::Groups => !parse_lines(&groups_text.get()).is_empty(),
            Confirm::Sites => !parse_lines(&sites_text.get()).is_empty(),
            Confirm::Owner => owner_pick.with(Option::is_some),
            Confirm::Click => true,
        },
        None => false,
    });

    // The one runner for every action: snapshots the selection + any target
    // input, fires the matching bulk command, parses its result into a summary +
    // per-item failures, and on success clears the armed panel (Delete also
    // drops the ids it deleted from the selection) and fires `on_done`.
    let run = move |action: BulkAction| {
        if blocked.get() {
            return;
        }
        let ids: Vec<String> = selection.get().into_iter().collect();
        if ids.is_empty() {
            return;
        }
        // Snapshotted before the run because every summary is measured against
        // what the operator SELECTED, never against the outcomes a stopped run
        // happened to produce.
        let attempted = ids.len();
        let groups = parse_lines(&groups_text.get());
        let sites = parse_lines(&sites_text.get());
        match action {
            BulkAction::ScopeMailbox if groups.is_empty() => {
                error.set(Some(
                    "Enter at least one mailbox group (one per line).".into(),
                ));
                return;
            }
            BulkAction::ScopeSharePoint if sites.is_empty() => {
                error.set(Some("Enter at least one site URL (one per line).".into()));
                return;
            }
            _ => {}
        }
        let role = if sp_write.get() { "write" } else { "read" }.to_string();
        let principal_id = owner_pick.get().map(|(id, _)| id);
        if action == BulkAction::AddOwner && principal_id.is_none() {
            error.set(Some("Pick a user to add as owner.".into()));
            return;
        }
        busy.set(true);
        bulk_running.set(true);
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        undo_ids.set(Vec::new());
        // The last run's terminal event is still in place (a full bar for a
        // completed run); leaving it opens the new run on a stale bar.
        progress.set(None);
        let tenant = session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                bulk_running.set(false);
                return;
            };
            let tid = &t.tenant_id;
            // Each arm reads its own result shape into the one `Parsed`.
            let parsed: Result<Parsed, azapptoolkit_dto::UiError> = match action {
                BulkAction::Grant => bulk::bulk_grant_permissions(tid, &ids)
                    .await
                    .map(|r| parse_grant(r, label_for)),
                BulkAction::RemoveExpired => bulk::bulk_remove_expired_credentials(tid, Some(&ids))
                    .await
                    .map(parse_remove_expired),
                BulkAction::RemoveRedundant => bulk::bulk_remove_redundant_permissions(tid, &ids)
                    .await
                    .map(|r| parse_redundant(r, label_for)),
                BulkAction::ScopeMailbox => bulk::bulk_scope_mailbox_access(tid, &ids, &groups)
                    .await
                    .map(|r| parse_scope("mailbox", r, label_for)),
                BulkAction::ScopeSharePoint => {
                    bulk::bulk_scope_sharepoint_access(tid, &ids, &sites, &role)
                        .await
                        .map(|r| parse_scope("SharePoint", r, label_for))
                }
                BulkAction::AddOwner => {
                    // Guarded non-None above; unwrap_or_default is unreachable.
                    let principal_id = principal_id.unwrap_or_default();
                    bulk::bulk_add_owner(tid, &ids, &principal_id)
                        .await
                        .map(|r| parse_add_owner(r, label_for))
                }
                // Subject empty => the backend defaults to `CN=SSO`; lifetime
                // `None` => Entra's default. A bulk run is not the place to
                // hand-tune either, and both are per-app editable afterwards.
                BulkAction::StageSsoCertificate => {
                    bulk::bulk_stage_sso_certificates(tid, &ids, "", None)
                        .await
                        .map(|r| parse_stage_certs(r, label_for))
                }
                BulkAction::DisableSignIn => bulk::bulk_disable_sign_in(tid, &ids)
                    .await
                    .map(|r| parse_disable(r, label_for)),
                BulkAction::Delete => bulk::bulk_delete_applications(tid, &ids)
                    .await
                    .map(|r| parse_delete(r, label_for)),
            };
            landing.finish_action(tid, action, attempted, parsed);
        });
    };

    let has_result = move || {
        summary.with(Option::is_some)
            || error.with(Option::is_some)
            || failures.with(|f| !f.is_empty())
    };
    let has_selection = move || selection.with(|s| !s.is_empty());
    let show_bar = move || busy.get() || has_selection() || has_result();

    view! {
        <Show when=show_bar fallback=|| ()>
            <div class="bulk-action-bar">
                <Show when=has_selection fallback=|| ()>
                    <div class="bulk-action-bar__actions">
                        <Body1 class="bulk-action-bar__count">
                            {move || format!("{} selected", selection.with(HashSet::len))}
                        </Body1>
                        {move || {
                            actions
                                .get()
                                .into_iter()
                                .map(|a| {
                                    let cls = if a.is_destructive() { "button--danger" } else { "" };
                                    view! {
                                        <Button
                                            class=cls
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| armed.set(Some(a)))
                                            disabled=Signal::derive(move || blocked.get())
                                        >
                                            {a.label()}
                                        </Button>
                                    }
                                })
                                .collect_view()
                        }}
                        {move || {
                            (!busy.get() && bulk_running.get())
                                .then(|| {
                                    view! {
                                        <Body1 class="muted">
                                            "Another bulk action is still running — wait for it to finish."
                                        </Body1>
                                    }
                                })
                        }}
                    </div>
                </Show>
                // Inline panel for the armed action — typed confirmation or target form.
                {move || armed.get().map(|action| armed_panel(action, ArmedPanel {
                    selection,
                    names,
                    confirm_text,
                    groups_text,
                    sites_text,
                    sp_write,
                    owner_query,
                    owner_pick,
                    owner_candidates,
                    confirm_ok,
                    armed,
                    busy,
                    blocked,
                    run,
                }))}
                {move || {
                    busy.get().then(|| view! { <BulkProgressRow progress=progress names=names /> })
                }}
                {move || {
                    summary
                        .get()
                        .map(|s| {
                            // `role="status"` so the outcome of a bulk mutation is
                            // ANNOUNCED — a screen-reader user otherwise got no
                            // signal that a 200-app delete had finished, or how.
                            let tone = if failures.with(|f| f.is_empty()) { "ok" } else { "warn" };
                            view! { <Callout tone=tone role="status">{s}</Callout> }
                        })
                }}
                {move || {
                    let fs = failures.get();
                    (!fs.is_empty())
                        .then(|| {
                            // Narrowing the selection to the failures is the
                            // whole retry loop: "re-run to finish" is an empty
                            // instruction while re-checking six rows out of two
                            // hundred is manual work. Absent only when the run's
                            // failures carry no ids to select (the Create flow).
                            let retry: Vec<String> = fs
                                .iter()
                                .filter_map(|f| f.object_id.clone())
                                .collect();
                            let retry_n = retry.len();
                            view! {
                                <div class="bulk-failures">
                                    <Body1 class="bulk-failures__title">
                                        {format!("{} failed:", count_noun(fs.len(), "item", "items"))}
                                    </Body1>
                                    <ul class="bulk-failures__list">
                                        {fs
                                            .into_iter()
                                            .map(|f| {
                                                view! {
                                                    <li>
                                                        <span class="mono">{f.label}</span>
                                                        " — "
                                                        {f.reason}
                                                    </li>
                                                }
                                            })
                                            .collect_view()}
                                    </ul>
                                    {(retry_n > 0)
                                        .then(|| {
                                            view! {
                                                <div class="actions-row">
                                                    <Button
                                                        appearance=Signal::derive(|| {
                                                            ButtonAppearance::Secondary
                                                        })
                                                        on_click=Box::new(move |_| {
                                                            selection.set(retry.iter().cloned().collect())
                                                        })
                                                    >
                                                        {format!("Select only the {retry_n} failed")}
                                                    </Button>
                                                </div>
                                            }
                                        })}
                                </div>
                            }
                        })
                }}
                {move || {
                    // Undo for the last delete: the run's confirmed-gone ids,
                    // replayed through the recycle bin. Sits above the error
                    // slot and disappears as soon as a new run starts, so a
                    // second Undo can never target a stale id set.
                    let ids = undo_ids.get();
                    let is_busy = busy.get();
                    (!ids.is_empty() && !is_busy)
                        .then(move || {
                            let n = ids.len();
                            view! {
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                        on_click=Box::new(move |_| undo.run(ids.clone()))
                                        disabled=Signal::derive(move || blocked.get())
                                    >
                                        {format!("Undo (restore {n} deleted)")}
                                    </Button>
                                </div>
                            }
                        })
                }}
                {move || error.get().map(|e| view! { <FormError>{e}</FormError> })}
            </div>
        </Show>
    }
}

/// Signals the armed panel needs — bundled so the runner closure and inputs
/// thread through one struct instead of a dozen positional args.
#[derive(Clone, Copy)]
struct ArmedPanel<R: Fn(BulkAction) + Copy + Send + Sync + 'static> {
    selection: RwSignal<HashSet<String>>,
    names: Option<Signal<Arc<HashMap<String, String>>>>,
    confirm_text: RwSignal<String>,
    groups_text: RwSignal<String>,
    sites_text: RwSignal<String>,
    sp_write: RwSignal<bool>,
    owner_query: RwSignal<String>,
    owner_pick: RwSignal<Option<(String, String)>>,
    owner_candidates: LocalResource<Result<Vec<DirectoryObject>, String>>,
    confirm_ok: Memo<bool>,
    armed: RwSignal<Option<BulkAction>>,
    busy: RwSignal<bool>,
    /// `busy` OR a run in flight from another bar: the point-of-no-return
    /// button waits on both, while Cancel (un-arming) waits only on this bar.
    blocked: Memo<bool>,
    run: R,
}

/// The inline panel for whichever action is armed: the selection under review,
/// a description, the per-action input (typed keyword / mailbox groups / site
/// URLs), and confirm + cancel.
fn armed_panel<R: Fn(BulkAction) + Copy + Send + Sync + 'static>(
    action: BulkAction,
    p: ArmedPanel<R>,
) -> AnyView {
    let n = move || p.selection.with(HashSet::len);
    let selection = p.selection;
    let names = p.names;
    let ArmedPanel {
        confirm_text,
        groups_text,
        sites_text,
        sp_write,
        owner_query,
        owner_pick,
        owner_candidates,
        confirm_ok,
        armed,
        busy,
        blocked,
        run,
        ..
    } = p;

    // Destructive actions plus `Grant`, which is additive but tenant-wide and
    // keeps its red emphasis on the point-of-no-return button.
    let danger = action.is_destructive() || matches!(action, BulkAction::Grant);

    // WHICH apps this is about to hit, not just how many. The panel used to say
    // "the 40 selected app(s)" and nothing else, which is unreviewable exactly
    // where it matters most: the operator often did not build the set by hand.
    // The Findings pane's "Fix all N" seeds the selection in one click, and the
    // App Registrations list deliberately keeps rows selected after the filter
    // that revealed them changes. The Bulk Actions page solved this for itself
    // and only itself; this is that block, moved into the bar so all five hosts
    // get it and there is one implementation.
    //
    // Open on the point-of-no-return actions, where reviewing the set IS the
    // gate; collapsed elsewhere, where it is reference an operator opens if they
    // want it. Deliberately free of buttons and inputs: the GUI tests drive the
    // confirm through this panel's first `input` / `button`, so a control in
    // here would silently retarget them.
    let review = move || {
        let ids = selection.get();
        (!ids.is_empty()).then(|| {
            let total = ids.len();
            let mut labels: Vec<String> = ids.iter().map(|id| label_with(names, id)).collect();
            // Sorted so the same selection always reads the same way — the set
            // arrives as a HashSet, whose order changes between renders.
            labels.sort_unstable();
            // Past a few hundred names a scrolling list stops being review, and
            // the App Registrations list can hand this bar the whole tenant.
            let overflow = total.saturating_sub(RENDER_PAGE);
            labels.truncate(RENDER_PAGE);
            view! {
                <details class="bulk-selection" open=danger>
                    <summary>{format!("{} selected", count_noun(total, "app", "apps"))}</summary>
                    <ul class="bulk-selection__list">
                        {labels.into_iter().map(|l| view! { <li>{l}</li> }).collect_view()}
                        {(overflow > 0)
                            .then(|| {
                                view! { <li class="muted">{format!("…and {overflow} more")}</li> }
                            })}
                    </ul>
                </details>
            }
        })
    };

    let spec = action.spec();
    let describe = spec.description;
    // The description reads as a warning exactly where the operator must type
    // a keyword.
    let desc_cls = if matches!(spec.confirm, Confirm::Keyword(_)) {
        "bulk-action__danger"
    } else {
        ""
    };
    let description = view! { <Body1 class=desc_cls>{move || describe(n())}</Body1> };

    // Driven by the action's `Confirm` requirement, not by naming the actions
    // that happen to have one today: an action added with `Confirm::Keyword`
    // gets the typed gate automatically, and cannot end up gated by `confirm_ok`
    // while rendering no input to satisfy it.
    let input: AnyView = match spec.confirm {
        Confirm::Keyword(keyword) => view! {
            <div class="confirm-gate">
                <Body1 class="confirm-gate__label">
                    "Type "<strong>{keyword}</strong>" to confirm."
                </Body1>
                <Input value=confirm_text placeholder=keyword />
            </div>
        }
        .into_any(),
        Confirm::Groups => view! {
            <div class="bulk-action-bar__scope-form">
                <MailboxGroupsField value=groups_text />
            </div>
        }
        .into_any(),
        Confirm::Sites => view! {
            <div class="bulk-action-bar__scope-form">
                <Textarea value=sites_text placeholder="https://contoso.sharepoint.com/sites/Marketing — one per line" />
                <label class="bulk-action-bar__check">
                    <input
                        type="checkbox"
                        prop:checked=move || sp_write.get()
                        on:change=move |_| sp_write.update(|w| *w = !*w)
                    />
                    "Grant write access (default: read)"
                </label>
            </div>
        }.into_any(),
        Confirm::Owner => {
            // Debounced directory search; clicking a candidate picks them (one
            // owner per run) and shows a "picked" line in place of the list.
            view! {
                <div class="bulk-action-bar__scope-form">
                    {move || match owner_pick.get() {
                        Some((_, label)) => view! {
                            <div class="actions-row">
                                <Body1>"Adding: "<strong>{label}</strong></Body1>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                    on_click=Box::new(move |_| owner_pick.set(None))
                                >
                                    "Change"
                                </Button>
                            </div>
                        }
                            .into_any(),
                        None => view! {
                            <Input value=owner_query placeholder="Search users by name or UPN (min 2 chars)" />
                            {move || {
                                owner_candidates
                                    .get()
                                    .map(|res| match res {
                                        Ok(users) if users.is_empty() => ().into_any(),
                                        Ok(users) => view! {
                                            <ul class="add-owner-candidates">
                                                {users
                                                    .into_iter()
                                                    .map(|u| {
                                                        let name = u
                                                            .display_name
                                                            .clone()
                                                            .unwrap_or_else(|| "—".to_string());
                                                        let upn = u.user_principal_name.clone().unwrap_or_default();
                                                        let label = if upn.is_empty() {
                                                            name.clone()
                                                        } else {
                                                            format!("{name} ({upn})")
                                                        };
                                                        let id = u.id.clone();
                                                        view! {
                                                            <li class="add-owner-candidates__row">
                                                                <Button
                                                                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                    on_click=Box::new(move |_| {
                                                                        owner_pick.set(Some((id.clone(), label.clone())))
                                                                    })
                                                                >
                                                                    {name} " " <span class="muted">{upn}</span>
                                                                </Button>
                                                            </li>
                                                        }
                                                    })
                                                    .collect_view()}
                                            </ul>
                                        }
                                            .into_any(),
                                        Err(e) => {
                                            view! { <FormError>{e}</FormError> }.into_any()
                                        }
                                    })
                            }}
                        }
                            .into_any(),
                    }}
                </div>
            }
            .into_any()
        }
        // Nothing to type or pick — the description plus the confirm button is
        // the whole gate.
        Confirm::Click => ().into_any(),
    };

    let confirm_label = spec.confirm_label;
    let confirm_cls = if danger { "button--danger" } else { "" };

    view! {
        <div class="bulk-action-bar__confirm">
            {review}
            {description}
            {input}
            <div class="actions-row">
                <Button
                    class=confirm_cls
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| run(action))
                    disabled=Signal::derive(move || blocked.get() || !confirm_ok.get())
                >
                    {confirm_label}
                </Button>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    on_click=Box::new(move |_| armed.set(None))
                    disabled=Signal::derive(move || busy.get())
                >
                    "Cancel"
                </Button>
            </div>
        </div>
    }
    .into_any()
}

fn cancelled_suffix(cancelled: bool) -> &'static str {
    if cancelled { " (cancelled)" } else { "" }
}

fn parse_grant(r: bulk::BulkGrantResult, label_for: impl Fn(&str) -> String) -> Parsed {
    let fails = failures_of(&r.outcomes, label_for);
    let reached = r.outcomes.len();
    // Successes by subtraction, like every sibling summary: an outcome with an
    // error (a failed OR partial grant) was not "granted consent". Counting
    // every reached app read "Granted consent to 5 apps; 5 with errors" for a
    // run that consented nothing.
    let granted = reached - fails.len();
    Parsed::new(
        format!(
            "Granted consent to {}; {} with errors{}.",
            count_noun(granted, "app", "apps"),
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
        reached,
        r.cancelled,
    )
}

/// Summarises a credential sweep. The only parse with **no derivable reach**:
/// `summaries` holds just the apps that had something to remove or that failed,
/// so a short list is the healthy case ("nothing expired"), not a stopped run —
/// and `apps_scanned` is the whole filtered set whether or not the fan-out
/// dispatched it. Claiming an unattempted tail from those two numbers would be
/// a guess, so this leans on `(cancelled)` and, for a run the session killed,
/// on the fatal code the failure list carries, until the backend reports what
/// it dispatched.
fn parse_remove_expired(r: bulk::BulkRemoveExpiredResult) -> Parsed {
    let fails: Vec<BulkFailure> = r
        .summaries
        .iter()
        .filter_map(|s| {
            let (reason, code) = match (&s.error, s.failed_key_ids.is_empty()) {
                (Some(e), _) => (Some(e.message.clone()), Some(e.code.clone())),
                // Synthesized from counts, so there is no wire code to carry.
                (None, false) => (
                    Some(format!(
                        "{} could not be removed",
                        count_noun(s.failed_key_ids.len(), "credential", "credentials")
                    )),
                    None,
                ),
                (None, true) => (None, None),
            };
            reason.map(|reason| BulkFailure {
                label: s.display_name.clone(),
                reason,
                object_id: Some(s.object_id.clone()),
                code,
            })
        })
        .collect();
    let removed = r
        .summaries
        .iter()
        .filter(|s| !s.removed_key_ids.is_empty())
        .count();
    // With no reach to count, a run the session killed would otherwise read
    // as a complete sweep: say it stopped, beside the re-auth prompt the
    // failure's code raises.
    let stopped = if session_dead_error(&fails).is_some() {
        " Stopped when the session expired; the remaining apps were not checked."
    } else {
        ""
    };
    Parsed {
        summary: format!(
            "Scanned {}; {} had expired creds removed{}.{stopped}",
            count_noun(r.apps_scanned, "app", "apps"),
            removed,
            cancelled_suffix(r.cancelled)
        ),
        failures: fails,
        reached: None,
        deleted: Vec::new(),
        cancelled: r.cancelled,
    }
}

fn parse_redundant(
    r: bulk::BulkRemoveRedundantResult,
    label_for: impl Fn(&str) -> String,
) -> Parsed {
    let fails = failures_of(&r.outcomes, label_for);
    let removed_total: usize = r.outcomes.iter().map(|o| o.removed.len()).sum();
    let apps_changed = r.outcomes.iter().filter(|o| !o.removed.is_empty()).count();
    let reached = r.outcomes.len();
    Parsed::new(
        format!(
            "Removed {} across {}; {} failed{}.",
            count_noun(
                removed_total,
                "redundant permission",
                "redundant permissions"
            ),
            count_noun(apps_changed, "app", "apps"),
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
        reached,
        r.cancelled,
    )
}

fn parse_scope(noun: &str, r: bulk::BulkScopeResult, label_for: impl Fn(&str) -> String) -> Parsed {
    let fails = failures_of(&r.outcomes, label_for);
    let reached = r.outcomes.len();
    let scoped = reached - fails.len();
    Parsed::new(
        format!(
            "Scoped {noun} access on {}; {} failed{}.",
            count_noun(scoped, "app", "apps"),
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
        reached,
        r.cancelled,
    )
}

fn parse_add_owner(r: bulk::BulkAddOwnerResult, label_for: impl Fn(&str) -> String) -> Parsed {
    let fails = failures_of(&r.outcomes, label_for);
    let added = r.outcomes.iter().filter(|o| o.added).count();
    let skipped = r.outcomes.iter().filter(|o| o.skipped).count();
    let reached = r.outcomes.len();
    Parsed::new(
        format!(
            "Added the owner to {}; {skipped} already had them; {} failed{}.",
            count_noun(added, "app", "apps"),
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
        reached,
        r.cancelled,
    )
}

fn parse_disable(r: bulk::BulkDisableSignInResult, label_for: impl Fn(&str) -> String) -> Parsed {
    let fails = failures_of(&r.outcomes, label_for);
    let reached = r.outcomes.len();
    let disabled = reached - fails.len();
    Parsed::new(
        format!(
            "Disabled sign-in for {}; {} failed{}. Re-enable anytime from the enterprise app's Overview.",
            count_noun(disabled, "app", "apps"),
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
        reached,
        r.cancelled,
    )
}

/// Summarises a staging run. Reports **staged** and **already prepared**
/// separately: a re-run over a work-queue filter legitimately skips the apps it
/// prepared last time, and folding those into "staged" would claim work that
/// didn't happen. Names the next step, because a staged certificate that nobody
/// activates is not a finished rollover.
fn parse_stage_certs(r: bulk::BulkStageCertResult, label_for: impl Fn(&str) -> String) -> Parsed {
    let fails = failures_of(&r.outcomes, label_for);
    let staged = r.outcomes.iter().filter(|o| o.thumbprint.is_some()).count();
    let skipped = r.outcomes.iter().filter(|o| o.skipped).count();
    let skipped_note = if skipped > 0 {
        format!("; {skipped} already had one staged")
    } else {
        String::new()
    };
    let reached = r.outcomes.len();
    Parsed::new(
        format!(
            "Staged a new signing certificate on {}{skipped_note}; {} failed{}. \
             Nothing has changed for users yet — activate each app from its SSO tab once the \
             application has picked the new certificate up.",
            count_noun(staged, "app", "apps"),
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
        reached,
        r.cancelled,
    )
}

/// Summarises a delete run and reports **which** object ids are gone.
///
/// Not a "clears the selection" flag: a cancelled delete leaves most of the
/// selection alive, and wiping the whole set destroyed the operator's work queue
/// along with the apps it actually deleted.
fn parse_delete(r: bulk::BulkDeleteResult, label_for: impl Fn(&str) -> String) -> Parsed {
    let fails: Vec<BulkFailure> = r
        .failed
        .iter()
        .map(|f| BulkFailure {
            label: label_for(&f.object_id),
            reason: f.message.clone(),
            object_id: Some(f.object_id.clone()),
            // The wire code when the backend had one: a delete that failed
            // because the session died carries `refresh_missing`, and that is
            // what `session_dead_error` reads to prompt re-authentication
            // instead of listing the stopped run as app-level failures.
            code: f.code.clone(),
        })
        .collect();
    // The fan-out never dispatches the tail of a cancelled run, so what it
    // reported on — deleted plus failed — is exactly what it reached.
    let reached = r.deleted.len() + fails.len();
    Parsed {
        summary: format!(
            "Deleted {}; {} failed{}.",
            count_noun(r.deleted.len(), "app", "apps"),
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        failures: fails,
        reached: Some(reached),
        deleted: r.deleted,
        cancelled: r.cancelled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::toast::ToastKind;
    use crate::state::provide_session;

    fn tenant(id: &str) -> crate::bindings::TenantContext {
        crate::bindings::TenantContext {
            tenant_id: id.to_string(),
            account_oid: "00000000-0000-0000-0000-000000000001".to_string(),
            username: None,
            display_name: None,
        }
    }

    /// A bar's worth of signals plus a host-owned `on_done` counter, built
    /// the way `BulkActionBar` builds them: the bar's signals under `bar`, the
    /// selection on the session, `on_done` and `names` under the host.
    fn landing_in(bar: &Owner) -> (Landing, RwSignal<u32>) {
        let session = use_session();
        let done = RwSignal::new(0u32);
        let map = RwSignal::new(Arc::new(HashMap::from([(
            "a".to_string(),
            "Contoso API".to_string(),
        )])));
        let names = Some(Signal::derive(move || map.get()));
        let on_done = Some(Callback::new(move |()| done.update(|n| *n += 1)));
        let landing = bar.with(|| Landing {
            session,
            selection: session.tenant_ui.selected_app_ids,
            names,
            on_done,
            busy: RwSignal::new(true),
            summary: RwSignal::new(None),
            failures: RwSignal::new(Vec::new()),
            error: RwSignal::new(None),
            armed: RwSignal::new(Some(BulkAction::Delete)),
            undo_ids: RwSignal::new(Vec::new()),
        });
        (landing, done)
    }

    fn select(session: Session, ids: &[&str]) {
        session
            .tenant_ui
            .selected_app_ids
            .set(ids.iter().map(|s| s.to_string()).collect());
    }

    fn selected(session: Session) -> Vec<String> {
        let mut v: Vec<String> = session
            .tenant_ui
            .selected_app_ids
            .get_untracked()
            .into_iter()
            .collect();
        v.sort();
        v
    }

    fn toast_messages(session: Session) -> Vec<String> {
        session
            .toasts
            .with_untracked(|l| l.iter().map(|t| t.message.clone()).collect())
    }

    /// A delete of a,b out of a,b,c whose run also hit a dead session — the
    /// shape the backend returns for it (the deletes that landed, plus the
    /// failure that latched the dead session, carrying its code), read through
    /// the real parser so the test cannot drift from the wire.
    fn a_dead_delete() -> Parsed {
        parse_delete(
            bulk::BulkDeleteResult {
                deleted: vec!["a".into(), "b".into()],
                failed: vec![bulk::BulkDeleteFailure {
                    object_id: "c".into(),
                    message: "session expired".into(),
                    code: Some("refresh_missing".into()),
                }],
                cancelled: false,
            },
            |id| id.to_string(),
        )
    }

    fn toast_action_labels(session: Session) -> Vec<Option<String>> {
        session
            .toasts
            .with_untracked(|l| l.iter().map(|t| t.action_label.clone()).collect())
    }

    /// A whole-command failure on a mounted bar keeps the inline message AND
    /// raises the recovery lever when one applies: a dead session mid-run used
    /// to be a red line saying "sign in again", which here means a sign-out
    /// that drops every cache. An ordinary failure is the inline text alone —
    /// no second toast, for a run or for an Undo.
    #[test]
    fn a_mounted_bar_offers_recovery_for_a_dead_session_error() {
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.set_active_tenant(Some(tenant("tenant-a")));
            let bar = Owner::new();
            let (l, done) = landing_in(&bar);
            let dead = || azapptoolkit_dto::UiError::new("refresh_missing", "gone", false);
            let plain = || azapptoolkit_dto::UiError::new("forbidden", "no rights", false);
            l.finish_action("tenant-a", BulkAction::Delete, 3, Err(dead()));
            assert_eq!(l.error.get_untracked().as_deref(), Some("gone"));
            assert_eq!(
                toast_action_labels(session),
                vec![Some("Re-authenticate".to_string())]
            );
            assert_eq!(done.get_untracked(), 0, "a failed run refetches nothing");
            l.finish_action("tenant-a", BulkAction::Grant, 3, Err(plain()));
            assert_eq!(l.error.get_untracked().as_deref(), Some("no rights"));
            assert_eq!(session.toasts.with_untracked(Vec::len), 1, "inline only");
            l.finish_undo("tenant-a", 1, Err(plain()));
            assert_eq!(l.error.get_untracked().as_deref(), Some("no rights"));
            assert_eq!(session.toasts.with_untracked(Vec::len), 1, "inline only");
        });
    }

    /// A bar unmounted mid-run (navigation, a collapsed Findings group) still
    /// reports how the run ended: the summary arrives as a toast, an error
    /// one when anything failed or was never reached.
    #[test]
    fn a_run_whose_bar_unmounted_toasts_its_summary() {
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.set_active_tenant(Some(tenant("tenant-a")));
            let bar = Owner::new();
            let (l, _) = landing_in(&bar);
            bar.cleanup();
            let failure = BulkFailure {
                label: "c".into(),
                reason: "no rights".into(),
                object_id: Some("c".into()),
                code: Some("forbidden".into()),
            };
            l.finish_action(
                "tenant-a",
                BulkAction::Grant,
                3,
                Ok(Parsed::new(
                    "Granted 2; 1 failed.".into(),
                    vec![failure],
                    3,
                    false,
                )),
            );
            l.finish_action(
                "tenant-a",
                BulkAction::Grant,
                3,
                Ok(Parsed::new(
                    "Granted 2; 0 failed (cancelled).".into(),
                    vec![],
                    2,
                    true,
                )),
            );
            l.finish_action(
                "tenant-a",
                BulkAction::Grant,
                2,
                Ok(Parsed::new("Granted 2; 0 failed.".into(), vec![], 2, false)),
            );
            let toasts: Vec<(ToastKind, String)> = session
                .toasts
                .with_untracked(|l| l.iter().map(|t| (t.kind, t.message.clone())).collect());
            assert_eq!(toasts.len(), 3, "{toasts:?}");
            assert_eq!(toasts[0].0, ToastKind::Error);
            assert!(
                toasts[0].1.starts_with("Granted 2; 1 failed."),
                "{toasts:?}"
            );
            assert_eq!(toasts[1].0, ToastKind::Error, "a stopped run is not clean");
            assert!(
                toasts[1].1.contains("never attempted; select"),
                "{toasts:?}"
            );
            assert_eq!(
                toasts[2],
                (ToastKind::Success, "Granted 2; 0 failed.".into())
            );
        });
    }

    /// A landed run or Undo releases the session-wide "a bulk action is
    /// running" flag that keeps a second bar from starting one on the same
    /// ids — on every exit, a failure included.
    #[test]
    fn a_landed_run_releases_the_session_bulk_flag() {
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.set_active_tenant(Some(tenant("tenant-a")));
            let bar = Owner::new();
            let (l, _) = landing_in(&bar);
            let flag = session.tenant_ui.bulk_running;
            flag.set(true);
            l.finish_action(
                "tenant-a",
                BulkAction::Grant,
                1,
                Ok(Parsed::new("ok".into(), vec![], 1, false)),
            );
            assert!(!flag.get_untracked());
            flag.set(true);
            l.finish_undo(
                "tenant-a",
                1,
                Err(azapptoolkit_dto::UiError::new("forbidden", "no", false)),
            );
            assert!(!flag.get_untracked());
        });
    }

    /// The consent summary counts successes by subtraction like its siblings:
    /// an app whose grant errored was not "granted consent".
    #[test]
    fn the_grant_summary_counts_successes_by_subtraction() {
        let outcome = |id: &str, error: Option<bulk::BulkError>| bulk::BulkGrantOutcome {
            object_id: id.into(),
            granted: 0,
            skipped: 0,
            failed: 0,
            error,
        };
        let p = parse_grant(
            bulk::BulkGrantResult {
                outcomes: vec![
                    outcome("a", None),
                    outcome("b", Some(err("forbidden"))),
                    outcome("c", Some(err("forbidden"))),
                ],
                cancelled: false,
            },
            upper,
        );
        assert!(
            p.summary
                .starts_with("Granted consent to 1 app; 2 with errors"),
            "{}",
            p.summary
        );
        assert_eq!(p.reached, Some(3));
    }

    /// A delete failure keeps its wire code, so a run the session killed is
    /// recognised as one (and prompts re-auth) rather than read as N apps
    /// that happened to fail.
    #[test]
    fn a_delete_failure_keeps_its_wire_code() {
        let p = a_dead_delete();
        assert_eq!(p.failures[0].code.as_deref(), Some("refresh_missing"));
        assert!(session_dead_error(&p.failures).is_some());
        assert_eq!(p.deleted, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn a_live_run_lands_in_the_bar_and_the_session() {
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.set_active_tenant(Some(tenant("tenant-a")));
            select(session, &["a", "b", "c"]);
            let bar = Owner::new();
            let (l, done) = landing_in(&bar);
            l.finish_action("tenant-a", BulkAction::Delete, 3, Ok(a_dead_delete()));
            assert_eq!(selected(session), vec!["c".to_string()]);
            assert!(l.summary.get_untracked().is_some());
            assert_eq!(l.armed.get_untracked(), None);
            assert_eq!(l.undo_ids.get_untracked().len(), 2);
            assert!(!l.busy.get_untracked());
            assert_eq!(done.get_untracked(), 1);
            assert_eq!(
                session.toasts.with_untracked(Vec::len),
                1,
                "the re-auth prompt"
            );
        });
    }

    /// Navigating away (same tenant) unmounts the bar mid-run. Its own signals
    /// are gone — and reading or running them used to panic the window — but
    /// the run's session-level effects must still land.
    #[test]
    fn a_run_whose_bar_unmounted_still_lands_its_session_effects() {
        Owner::new().with(|| {
            provide_session();
            let session = use_session();
            session.set_active_tenant(Some(tenant("tenant-a")));
            select(session, &["a", "b", "c"]);
            let bar = Owner::new();
            let (l, done) = landing_in(&bar);
            bar.cleanup();
            assert!(!l.bar_mounted());
            l.finish_action("tenant-a", BulkAction::Delete, 3, Ok(a_dead_delete()));
            assert_eq!(
                selected(session),
                vec!["c".to_string()],
                "deleted ids dangle"
            );
            // The re-auth prompt, plus the summary the bar can no longer show.
            assert_eq!(
                toast_action_labels(session),
                vec![Some("Re-authenticate".to_string()), None]
            );
            assert!(
                toast_messages(session)[1].starts_with("Deleted 2 apps; 1 failed."),
                "{:?}",
                toast_messages(session)
            );
            assert_eq!(done.get_untracked(), 1, "the host outlives its bar");
            // A failure with no inline error left to show goes to the sink.
            l.finish_action(
                "tenant-a",
                BulkAction::Grant,
                3,
                Err(azapptoolkit_dto::UiError::new(
                    "forbidden",
                    "no rights",
                    false,
                )),
            );
            assert!(
                toast_messages(session)
                    .iter()
                    .any(|m| m.contains("no rights")),
                "{:?}",
                toast_messages(session)
            );
        });
    }

    /// Results are labelled after the await, when sign-out may already have
    /// disposed the host's `names` map: the id stands in rather than a panic.
    #[test]
    fn a_disposed_names_map_labels_by_id() {
        Owner::new().with(|| {
            let host = Owner::new();
            let names = host.with(|| {
                Some(Signal::derive(|| {
                    Arc::new(HashMap::from([(
                        "a".to_string(),
                        "Contoso API".to_string(),
                    )]))
                }))
            });
            assert_eq!(label_with(names, "a"), "Contoso API");
            host.cleanup();
            assert_eq!(label_with(names, "a"), "a");
        });
    }

    /// Sign-out (tenant cleared, shell unmounted) or a tenant switch: the run
    /// belongs to nobody on screen. Nothing lands — not the other tenant's
    /// selection, not a toast that would carry into the next sign-in.
    #[test]
    fn a_run_whose_tenant_is_gone_lands_nowhere() {
        for signed_out in [false, true] {
            Owner::new().with(|| {
                provide_session();
                let session = use_session();
                session.set_active_tenant(Some(tenant("tenant-a")));
                let bar = Owner::new();
                let (l, done) = landing_in(&bar);
                if signed_out {
                    session.set_active_tenant(None);
                    bar.cleanup();
                } else {
                    session.set_active_tenant(Some(tenant("tenant-b")));
                }
                select(session, &["a", "b", "c"]);
                l.finish_action("tenant-a", BulkAction::Delete, 3, Ok(a_dead_delete()));
                l.finish_action(
                    "tenant-a",
                    BulkAction::Grant,
                    3,
                    Err(azapptoolkit_dto::UiError::new(
                        "forbidden",
                        "no rights",
                        false,
                    )),
                );
                l.finish_undo(
                    "tenant-a",
                    1,
                    Ok(bulk::BulkRestoreResult {
                        outcomes: vec![bulk::BulkRestoreOutcome {
                            object_id: "a".into(),
                            restored: true,
                            sp_restored: true,
                            error: None,
                        }],
                        cancelled: false,
                    }),
                );
                assert_eq!(selected(session).len(), 3, "signed_out={signed_out}");
                assert!(
                    toast_messages(session).is_empty(),
                    "signed_out={signed_out}"
                );
                assert_eq!(done.get_untracked(), 0, "signed_out={signed_out}");
                if !signed_out {
                    assert!(l.summary.get_untracked().is_none());
                    assert!(!l.busy.get_untracked(), "the bar gets its controls back");
                }
            });
        }
    }

    /// The one destructive action confirmed by a plain click. Why: the backend
    /// re-resolves each app live and removes only permissions strictly covered
    /// by a broader grant the app keeps, so effective access is unchanged.
    const CLICK_CONFIRMED_DESTRUCTIVE: [BulkAction; 1] = [BulkAction::RemoveRedundant];

    /// A slot per variant. Exhaustive with no wildcard, so a new variant won't
    /// compile until it gets one — the groups.rs "won't compile until listed"
    /// pattern, tightened with a slot match (full compile-time exhaustiveness of
    /// `ALL` would need a derive crate, and dependencies are a cost).
    fn slot(a: BulkAction) -> usize {
        match a {
            BulkAction::Grant => 0,
            BulkAction::RemoveExpired => 1,
            BulkAction::RemoveRedundant => 2,
            BulkAction::ScopeMailbox => 3,
            BulkAction::ScopeSharePoint => 4,
            BulkAction::AddOwner => 5,
            BulkAction::DisableSignIn => 6,
            BulkAction::StageSsoCertificate => 7,
            BulkAction::Delete => 8,
        }
    }

    /// `BulkAction::ALL` lists every variant exactly once, in declaration
    /// order, so the spec tests below iterate every action by construction.
    #[test]
    fn all_lists_every_action_once() {
        assert_eq!(
            BulkAction::ALL.len(),
            9,
            "a variant was added: list it in `BulkAction::ALL` and give it a `slot`"
        );
        let mut hits = [0u8; BulkAction::ALL.len()];
        for a in BulkAction::ALL {
            hits[slot(a)] += 1;
        }
        assert!(
            hits.iter().all(|&h| h == 1),
            "`ALL` has a gap or duplicate: {hits:?}"
        );
        assert!(
            BulkAction::ALL
                .iter()
                .enumerate()
                .all(|(i, a)| *a as usize == i),
            "`ALL` is out of declaration order"
        );
    }

    /// Bulk delete must not tell the operator the apps are gone for good:
    /// Entra soft-deletes app registrations for 30 days.
    #[test]
    fn a_bulk_delete_says_it_can_be_restored() {
        let d = (BulkAction::Delete.spec().description)(3);
        assert!(d.contains("30 days"), "{d}");
        assert!(!d.contains("cannot be undone"), "{d}");
    }

    /// Every action's spec is coherent, and the confirm keywords are distinct.
    ///
    /// The spec table replaced three parallel per-action matches plus a fourth
    /// choosing the confirm placeholder. Two of those held keyword lists with no
    /// relationship to each other, so they could disagree — showing the operator
    /// one word while requiring another, leaving the confirm button disabled
    /// with nothing on screen explaining why. One table makes that unrepresentable;
    /// this pins the rest.
    #[test]
    fn every_action_has_a_coherent_spec() {
        let mut keywords: Vec<&str> = Vec::new();
        for action in BulkAction::ALL {
            let spec = action.spec();
            assert!(!spec.label.is_empty(), "{action:?} has no label");
            assert!(
                !spec.confirm_label.is_empty(),
                "{action:?} has no confirm label"
            );
            let d = (spec.description)(7);
            assert!(
                d.contains('7'),
                "{action:?}'s description must state the selected count"
            );
            if let Confirm::Keyword(word) = spec.confirm {
                assert!(
                    word.chars().all(|c| c.is_ascii_uppercase()),
                    "{action:?}'s keyword {word:?} must be typed exactly, so it is uppercase"
                );
                assert!(
                    !keywords.contains(&word),
                    "{action:?} reuses the confirm keyword {word:?}; typing it must mean one thing"
                );
                keywords.push(word);
            }
        }
    }

    /// Anything irreversible is gated on a typed keyword, and anything gated on
    /// a keyword renders the input that accepts it.
    ///
    /// `Grant` is the deliberate asymmetry: additive, so not red, but tenant-wide
    /// and high-privilege, so still keyword-gated. That is why `destructive` and
    /// `confirm` are separate fields rather than one flag doing both jobs.
    #[test]
    fn destructive_actions_are_keyword_gated() {
        let click_confirmed: Vec<BulkAction> = BulkAction::ALL
            .into_iter()
            .filter(|a| {
                let spec = a.spec();
                spec.destructive && !matches!(spec.confirm, Confirm::Keyword(_))
            })
            .collect();
        assert_eq!(
            click_confirmed, CLICK_CONFIRMED_DESTRUCTIVE,
            "a destructive action confirms on a plain click; gate it on a keyword \
             or justify it in CLICK_CONFIRMED_DESTRUCTIVE"
        );
        // Reversible actions must NOT be red — red reserved for the
        // irreversible is what keeps it worth reading.
        assert!(!BulkAction::DisableSignIn.spec().destructive);
        assert!(!BulkAction::Grant.spec().destructive);
        assert!(matches!(
            BulkAction::Grant.spec().confirm,
            Confirm::Keyword("GRANT")
        ));
    }

    fn err(code: &str) -> bulk::BulkError {
        bulk::BulkError {
            code: code.to_string(),
            message: format!("{code} happened"),
            retryable: false,
        }
    }

    fn scope_outcome(id: &str, error: Option<bulk::BulkError>) -> bulk::BulkScopeOutcome {
        bulk::BulkScopeOutcome {
            object_id: id.to_string(),
            error,
        }
    }

    fn owner_outcome(
        id: &str,
        added: bool,
        skipped: bool,
        error: Option<bulk::BulkError>,
    ) -> bulk::BulkOwnerOutcome {
        bulk::BulkOwnerOutcome {
            object_id: id.to_string(),
            added,
            skipped,
            error,
        }
    }

    fn upper(id: &str) -> String {
        id.to_uppercase()
    }

    #[test]
    fn only_failed_rows_become_failures_and_they_keep_their_wire_code() {
        let fails = failures_of(
            &[
                scope_outcome("a", None),
                scope_outcome("b", Some(err("forbidden"))),
                scope_outcome("c", None),
            ],
            upper,
        );
        assert_eq!(fails.len(), 1);
        assert_eq!(fails[0].label, "B", "the label goes through label_for");
        assert_eq!(
            fails[0].code.as_deref(),
            Some("forbidden"),
            "the code is what lets the bar tell a dead session from a failed app"
        );
        assert_eq!(
            fails[0].object_id.as_deref(),
            Some("b"),
            "the raw id, not the label, is what 'Select only the N failed' \
             puts back into the selection"
        );
    }

    /// The distinction the whole `code` field exists for.
    ///
    /// A mid-run `refresh_missing` does not mean this app failed — it means the
    /// SESSION died, the backend stopped the run, and the tail of the selection
    /// was never attempted. Rendering it as N app-level failures tells the
    /// operator to go fix N apps that are fine, and hides the one action that
    /// would actually help.
    #[test]
    fn a_dead_session_is_detected_among_ordinary_failures() {
        let fails = failures_of(
            &[
                scope_outcome("a", Some(err("forbidden"))),
                scope_outcome("b", Some(err("refresh_missing"))),
            ],
            upper,
        );
        let dead = session_dead_error(&fails).expect("the session death must surface");
        assert_eq!(dead.code, "refresh_missing");
        assert!(dead.is_reauth_fatal());
    }

    #[test]
    fn ordinary_failures_alone_are_not_a_dead_session() {
        let fails = failures_of(
            &[
                scope_outcome("a", Some(err("forbidden"))),
                scope_outcome("b", Some(err("throttled"))),
                scope_outcome("c", Some(err("not_found"))),
            ],
            upper,
        );
        assert!(
            session_dead_error(&fails).is_none(),
            "these are per-app failures; prompting for re-auth would be wrong"
        );
    }

    #[test]
    fn a_synthesized_failure_with_no_code_never_reads_as_a_dead_session() {
        // Failures derived from counts rather than an error carry `code: None`
        // — but they still name a real app, so they keep their `object_id` and
        // stay re-selectable. The two fields answer different questions.
        let fails = vec![BulkFailure {
            label: "app".into(),
            reason: "3 credentials could not be removed".into(),
            object_id: Some("obj-app".into()),
            code: None,
        }];
        assert!(session_dead_error(&fails).is_none());
    }

    #[test]
    fn every_reauth_fatal_code_is_recognised() {
        // Reads the shared set, so a code added there cannot reach the backend
        // without also being understood here.
        for code in azapptoolkit_core::reauth::REAUTH_FATAL_CODES {
            let fails = failures_of(&[scope_outcome("a", Some(err(code)))], upper);
            assert!(
                session_dead_error(&fails).is_some(),
                "{code} must trigger the re-auth prompt"
            );
        }
    }

    #[test]
    fn the_scope_summary_counts_successes_by_subtraction() {
        let p = parse_scope(
            "mailbox",
            bulk::BulkScopeResult {
                outcomes: vec![
                    scope_outcome("a", None),
                    scope_outcome("b", None),
                    scope_outcome("c", Some(err("forbidden"))),
                ],
                cancelled: false,
            },
            upper,
        );
        let summary = &p.summary;
        assert_eq!(p.failures.len(), 1);
        assert!(
            summary.contains("on 2 apps;"),
            "scoped count must exclude failures: {summary}"
        );
        assert!(summary.contains("1 failed"), "{summary}");
        assert!(
            !summary.contains("cancelled"),
            "a completed run must not claim it was cancelled: {summary}"
        );
        assert_eq!(p.reached, Some(3));
    }

    #[test]
    fn a_cancelled_run_says_so_in_its_summary() {
        // A partial run that reads as complete is the failure mode; the suffix
        // is the only thing distinguishing them in the summary line.
        let p = parse_scope(
            "mailbox",
            bulk::BulkScopeResult {
                outcomes: vec![scope_outcome("a", None)],
                cancelled: true,
            },
            upper,
        );
        assert!(
            p.summary.contains(cancelled_suffix(true).trim()),
            "{}",
            p.summary
        );
        assert_eq!(cancelled_suffix(false), "");
    }

    #[test]
    fn the_add_owner_summary_separates_added_from_already_present() {
        // `skipped` means the owner was already there — reporting it as "added"
        // overstates what the run changed, and as "failed" understates success.
        let p = parse_add_owner(
            bulk::BulkAddOwnerResult {
                outcomes: vec![
                    owner_outcome("a", true, false, None),
                    owner_outcome("b", false, true, None),
                    owner_outcome("c", false, false, Some(err("forbidden"))),
                ],
                cancelled: false,
            },
            upper,
        );
        let summary = &p.summary;
        assert_eq!(p.failures.len(), 1);
        assert!(summary.contains("to 1 app;"), "{summary}");
        assert!(summary.contains("1 already had them"), "{summary}");
        assert!(summary.contains("1 failed"), "{summary}");
    }

    /// The whole point of `reached`: a stopped run must name the tail it never
    /// touched, in the summary the operator is already reading.
    ///
    /// `run_bulk_seq` breaks out of its loop on Cancel or a dead session and
    /// returns only the outcomes it produced, so a Cancel at item 12 of 40
    /// summarised as "11 scoped; 1 failed (cancelled)" — true, and silent about
    /// the 28 apps still holding org-wide access.
    #[test]
    fn a_stopped_run_names_the_apps_it_never_attempted() {
        let p = parse_scope(
            "mailbox",
            bulk::BulkScopeResult {
                outcomes: (0..12)
                    .map(|i| scope_outcome(&format!("a{i}"), None))
                    .collect(),
                cancelled: true,
            },
            upper,
        );
        let note = unattempted_note(40, p.reached, true);
        assert!(note.contains("28 apps were never attempted"), "{note}");
        assert!(
            note.contains("still selected"),
            "the tail survives the run, so say so — it is what makes 're-run to \
             finish' actionable: {note}"
        );
    }

    #[test]
    fn a_single_unattempted_app_reads_in_the_singular() {
        let note = unattempted_note(2, Some(1), true);
        assert!(
            note.contains("1 app was never attempted and is still selected"),
            "{note}"
        );
    }

    #[test]
    fn a_run_that_reached_everything_adds_no_note() {
        assert_eq!(unattempted_note(40, Some(40), true), "");
        // A backend that somehow reports more outcomes than were attempted must
        // not underflow into a nonsense count.
        assert_eq!(unattempted_note(40, Some(41), true), "");
    }

    /// The credential sweep reports only the apps that HAD expired credentials,
    /// so a short summary list is the healthy case. Deriving an unattempted
    /// count from it would invent skipped apps on every clean sweep.
    #[test]
    fn an_underivable_reach_never_claims_apps_were_skipped() {
        let p = parse_remove_expired(bulk::BulkRemoveExpiredResult {
            apps_scanned: 40,
            summaries: Vec::new(),
            cancelled: true,
        });
        assert_eq!(p.reached, None);
        assert_eq!(unattempted_note(40, p.reached, true), "");
        assert!(
            p.summary.contains(cancelled_suffix(true).trim()),
            "the cancel suffix is the only partial-run signal this shape \
             supports, so it has to be there: {}",
            p.summary
        );
    }

    /// A cancelled delete must strand nothing: only the ids Graph confirmed
    /// gone leave the selection, so the apps it never reached — and the ones
    /// that failed — are still checked and can be re-run.
    #[test]
    fn a_cancelled_delete_surrenders_only_the_ids_it_deleted() {
        let p = parse_delete(
            bulk::BulkDeleteResult {
                deleted: vec!["a".into(), "b".into()],
                failed: vec![bulk::BulkDeleteFailure {
                    object_id: "c".into(),
                    message: "insufficient privileges".into(),
                    code: Some("forbidden".into()),
                }],
                cancelled: true,
            },
            upper,
        );
        assert_eq!(p.deleted, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(
            p.reached,
            Some(3),
            "deleted + failed is exactly what the fan-out dispatched"
        );
        let note = unattempted_note(10, p.reached, true);
        assert!(
            note.contains("7 apps were never attempted and are still selected"),
            "{note}"
        );
        let note = unattempted_note(10, p.reached, false);
        assert!(
            note.contains("7 apps were never attempted; select them again"),
            "{note}"
        );
        assert_eq!(
            p.failures[0].object_id.as_deref(),
            Some("c"),
            "a delete failure is re-selectable like any other"
        );
    }
}
