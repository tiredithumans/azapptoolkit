//! Inline bulk-action bar over a multi-selected set of app-registration object
//! ids.
//!
//! The **single home** of the selection-driven bulk command-calling logic: the
//! Security workbench (one bar per expanded Findings group + the All-apps
//! pane), the App Registrations list, and the Bulk Actions page all mount this
//! same component. The offered actions are configurable (the `actions` signal)
//! so each host shows the right set — a Findings group offers exactly the fix
//! paired with its rule (no Grant consent on audit surfaces), while the App
//! Registrations list / Bulk Actions page show the management set.
//!
//! Each action arms an inline panel before running: destructive ones (Remove
//! expired, Delete) behind a typed REMOVE/DELETE confirmation, the scoping ones
//! behind a small target form (mailbox groups / site URLs) reusing the same
//! shapes as the per-row "Scope…" fixes, Add-owner behind a directory-search
//! picker, and Disable-sign-in behind a plain confirm (reversible). A live
//! progress row + Cancel and a tone-coded result summary mirror the former
//! tab-per-action page.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Spinner, SpinnerSize, Textarea};

use crate::bindings::applications;
use crate::bindings::bulk;
use crate::bindings::events;
use crate::components::ui::Callout;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::use_session;
use crate::util::parse_lines;

/// One failed item from a bulk run, surfaced below the aggregate summary so the
/// user can see *which* app failed and *why*. Public so the Bulk Actions page's
/// Create flow can reuse the same shape.
#[derive(Clone)]
pub struct BulkFailure {
    pub label: String,
    pub reason: String,
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
);

/// The failed rows of a bulk run, labelled for display.
fn failures_of<T: BulkRow>(outcomes: &[T], label_for: impl Fn(&str) -> String) -> Vec<BulkFailure> {
    outcomes
        .iter()
        .filter_map(|o| {
            o.error().map(|e| BulkFailure {
                label: label_for(o.object_id()),
                reason: e.message.clone(),
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
/// confirm button disabled with nothing on screen explaining why.
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
    destructive: bool,
    confirm: Confirm,
}

impl BulkAction {
    fn spec(self) -> Spec {
        let (label, destructive, confirm) = match self {
            BulkAction::Grant => ("Grant consent", false, Confirm::Keyword("GRANT")),
            BulkAction::RemoveExpired => (
                "Remove expired credentials",
                true,
                Confirm::Keyword("REMOVE"),
            ),
            BulkAction::RemoveRedundant => ("Remove redundant permissions", true, Confirm::Click),
            BulkAction::ScopeMailbox => ("Scope mailbox access", false, Confirm::Groups),
            BulkAction::ScopeSharePoint => ("Scope SharePoint access", false, Confirm::Sites),
            BulkAction::AddOwner => ("Add owner", false, Confirm::Owner),
            BulkAction::DisableSignIn => ("Disable sign-in", false, Confirm::Click),
            BulkAction::Delete => ("Delete", true, Confirm::Keyword("DELETE")),
        };
        Spec {
            label,
            destructive,
            confirm,
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
    /// Cleared by the bar after a successful Delete (those object ids are gone).
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
    let label_for = move |object_id: &str| -> String {
        names
            .and_then(|n| n.with(|m| m.get(object_id).cloned()))
            .unwrap_or_else(|| object_id.to_string())
    };

    let busy = RwSignal::new(false);
    let summary: RwSignal<Option<String>> = RwSignal::new(None);
    let failures: RwSignal<Vec<BulkFailure>> = RwSignal::new(Vec::new());
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let progress: RwSignal<Option<bulk::BulkProgress>> = RwSignal::new(None);
    use_progress_stream(progress, events::bulk_progress);

    let cancelling = RwSignal::new(false);
    Effect::new(move |_| {
        if !busy.get() {
            cancelling.set(false);
        }
    });
    let do_cancel = move |_| {
        if cancelling.get() {
            return;
        }
        cancelling.set(true);
        leptos::task::spawn_local(async move {
            bulk::cancel_bulk().await;
        });
    };

    // Arming: every action except Grant reveals an inline panel (a typed
    // confirmation for the destructive ones, a target form for the scoping ones)
    // before running. `armed` holds which action's panel is open; the input
    // fields reset whenever it changes, and `armed` itself clears when the
    // offered action set changes (e.g. the audit's finding filter switches).
    let armed: RwSignal<Option<BulkAction>> = RwSignal::new(None);
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
    // clears the selection) and fires `on_done`.
    let run = move |action: BulkAction| {
        if busy.get() {
            return;
        }
        let ids: Vec<String> = selection.get().into_iter().collect();
        if ids.is_empty() {
            return;
        }
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
        summary.set(None);
        failures.set(Vec::new());
        error.set(None);
        let tenant = session.active_tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            let tid = &t.tenant_id;
            // Each arm parses its own result into (summary, failures, clears-selection).
            let parsed: Result<(String, Vec<BulkFailure>, bool), String> = match action {
                BulkAction::Grant => bulk::bulk_grant_permissions(tid, &ids)
                    .await
                    .map(|r| (parse_grant(r, label_for), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::RemoveExpired => bulk::bulk_remove_expired_credentials(tid, Some(&ids))
                    .await
                    .map(|r| (parse_remove_expired(r), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::RemoveRedundant => bulk::bulk_remove_redundant_permissions(tid, &ids)
                    .await
                    .map(|r| (parse_redundant(r, label_for), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::ScopeMailbox => bulk::bulk_scope_mailbox_access(tid, &ids, &groups)
                    .await
                    .map(|r| (parse_scope("mailbox", r, label_for), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::ScopeSharePoint => {
                    bulk::bulk_scope_sharepoint_access(tid, &ids, &sites, &role)
                        .await
                        .map(|r| (parse_scope("SharePoint", r, label_for), false))
                        .map(|((s, f), c)| (s, f, c))
                        .map_err(|e| e.message)
                }
                BulkAction::AddOwner => {
                    // Guarded non-None above; unwrap_or_default is unreachable.
                    let principal_id = principal_id.unwrap_or_default();
                    bulk::bulk_add_owner(tid, &ids, &principal_id)
                        .await
                        .map(|r| (parse_add_owner(r, label_for), false))
                        .map(|((s, f), c)| (s, f, c))
                        .map_err(|e| e.message)
                }
                BulkAction::DisableSignIn => bulk::bulk_disable_sign_in(tid, &ids)
                    .await
                    .map(|r| (parse_disable(r, label_for), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::Delete => bulk::bulk_delete_applications(tid, &ids)
                    .await
                    .map(|r| (parse_delete(r, label_for), true))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
            };
            match parsed {
                Ok((s, f, clear_sel)) => {
                    // A failure carrying a re-auth-fatal code means the session
                    // died mid-run, not that these apps are broken. The backend
                    // already halted the loop; surface the recovery action so
                    // the operator re-authenticates in place (never a sign-out —
                    // that drops every data cache) instead of reading a list of
                    // failures with no obvious cause.
                    if let Some(dead) = session_dead_error(&f) {
                        session.report_if_session_dead(&dead);
                    }
                    summary.set(Some(s));
                    failures.set(f);
                    armed.set(None);
                    if clear_sel {
                        selection.update(HashSet::clear);
                    }
                    if let Some(cb) = on_done {
                        cb.run(());
                    }
                }
                Err(msg) => error.set(Some(msg)),
            }
            busy.set(false);
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
                                            disabled=Signal::derive(move || busy.get())
                                        >
                                            {a.label()}
                                        </Button>
                                    }
                                })
                                .collect_view()
                        }}
                    </div>
                </Show>
                // Inline panel for the armed action — typed confirmation or target form.
                {move || armed.get().map(|action| armed_panel(action, ArmedPanel {
                    selection,
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
                    run,
                }))}
                {move || {
                    busy.get()
                        .then(|| {
                            view! {
                                <div class="actions-row">
                                    <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                    <Body1>
                                        {move || match progress.get() {
                                            Some(p) if p.total > 0 => {
                                                format!("Working… ({}/{})", p.done, p.total)
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
                        })
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
                            view! {
                                <div class="bulk-failures">
                                    <Body1 class="bulk-failures__title">
                                        {format!("{} item(s) failed:", fs.len())}
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
                                </div>
                            }
                        })
                }}
                {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
            </div>
        </Show>
    }
}

/// Signals the armed panel needs — bundled so the runner closure and inputs
/// thread through one struct instead of a dozen positional args.
#[derive(Clone, Copy)]
struct ArmedPanel<R: Fn(BulkAction) + Copy + Send + Sync + 'static> {
    selection: RwSignal<HashSet<String>>,
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
    run: R,
}

/// The inline panel for whichever action is armed: a description, the per-action
/// input (typed keyword / mailbox groups / site URLs), and confirm + cancel.
fn armed_panel<R: Fn(BulkAction) + Copy + Send + Sync + 'static>(
    action: BulkAction,
    p: ArmedPanel<R>,
) -> AnyView {
    let n = move || p.selection.with(HashSet::len);
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
        run,
        ..
    } = p;

    // Destructive actions plus `Grant`, which is additive but tenant-wide and
    // keeps its red emphasis on the point-of-no-return button.
    let danger = action.is_destructive() || matches!(action, BulkAction::Grant);
    let description: AnyView = match action {
        BulkAction::RemoveExpired => view! {
            <Body1 class="bulk-action__danger">
                {move || format!("Remove every expired password credential from the {} selected app(s). This is irreversible.", n())}
            </Body1>
        }.into_any(),
        BulkAction::Delete => view! {
            <Body1 class="bulk-action__danger">
                {move || format!("Permanently delete the {} selected app registration(s). This cannot be undone.", n())}
            </Body1>
        }.into_any(),
        BulkAction::RemoveRedundant => view! {
            <Body1>
                {move || format!("Remove redundant application permissions (narrower ones already covered by a broader grant) from the {} selected app(s). Re-resolved live per app; load-bearing grants are kept.", n())}
            </Body1>
        }.into_any(),
        BulkAction::ScopeMailbox => view! {
            <Body1>
                {move || format!("Confine the {} selected app(s)' mailbox permissions to the groups below via Exchange RBAC (every mail permission each app holds is scoped). Needs Exchange admin rights.", n())}
            </Body1>
        }.into_any(),
        BulkAction::ScopeSharePoint => view! {
            <Body1>
                {move || format!("Convert the {} selected app(s)' org-wide SharePoint access to Sites.Selected on the sites below.", n())}
            </Body1>
        }.into_any(),
        BulkAction::AddOwner => view! {
            <Body1>
                {move || format!("Add one user as an owner of the {} selected app(s). Purely additive — apps that already have this owner are skipped.", n())}
            </Body1>
        }.into_any(),
        BulkAction::DisableSignIn => view! {
            <Body1>
                {move || format!("Disable sign-in for the {} selected app(s) by disabling their service principals. Reversible — re-enable anytime from the enterprise app's Overview.", n())}
            </Body1>
        }.into_any(),
        BulkAction::Grant => view! {
            <Body1 class="bulk-action__danger">
                {move || format!("Grant admin consent to the {} selected app(s) — this consents every permission each app requests, tenant-wide, on behalf of all users. Consent stays in place until revoked per app.", n())}
            </Body1>
        }.into_any(),
    };

    // Driven by the action's `Confirm` requirement, not by naming the actions
    // that happen to have one today: an action added with `Confirm::Keyword`
    // gets the typed gate automatically, and cannot end up gated by `confirm_ok`
    // while rendering no input to satisfy it.
    let input: AnyView = match action.spec().confirm {
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
            <Textarea value=groups_text placeholder="Mailbox groups (name, address, or object id) — one per line" />
        }.into_any(),
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
                                            view! { <Body1 class="form-error">{e}</Body1> }.into_any()
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

    let confirm_label = match action {
        BulkAction::RemoveExpired => "Remove expired",
        BulkAction::RemoveRedundant => "Remove redundant",
        BulkAction::ScopeMailbox => "Scope mailbox",
        BulkAction::ScopeSharePoint => "Scope SharePoint",
        BulkAction::AddOwner => "Add owner",
        BulkAction::DisableSignIn => "Disable sign-in",
        BulkAction::Delete => "Delete",
        BulkAction::Grant => "Grant consent",
    };
    let confirm_cls = if danger { "button--danger" } else { "" };

    view! {
        <div class="bulk-action-bar__confirm">
            {description}
            {input}
            <div class="actions-row">
                <Button
                    class=confirm_cls
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| run(action))
                    disabled=Signal::derive(move || busy.get() || !confirm_ok.get())
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

fn parse_grant(
    r: bulk::BulkGrantResult,
    label_for: impl Fn(&str) -> String,
) -> (String, Vec<BulkFailure>) {
    let fails = failures_of(&r.outcomes, label_for);
    (
        format!(
            "Granted consent to {} app(s); {} with errors{}.",
            r.outcomes.len(),
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
    )
}

fn parse_remove_expired(r: bulk::BulkRemoveExpiredResult) -> (String, Vec<BulkFailure>) {
    let fails: Vec<BulkFailure> = r
        .summaries
        .iter()
        .filter_map(|s| {
            let (reason, code) = match (&s.error, s.failed_key_ids.is_empty()) {
                (Some(e), _) => (Some(e.message.clone()), Some(e.code.clone())),
                // Synthesized from counts, so there is no wire code to carry.
                (None, false) => (
                    Some(format!(
                        "{} credential(s) could not be removed",
                        s.failed_key_ids.len()
                    )),
                    None,
                ),
                (None, true) => (None, None),
            };
            reason.map(|reason| BulkFailure {
                label: s.display_name.clone(),
                reason,
                code,
            })
        })
        .collect();
    let removed = r
        .summaries
        .iter()
        .filter(|s| !s.removed_key_ids.is_empty())
        .count();
    (
        format!(
            "Scanned {} app(s); {} had expired creds removed{}.",
            r.apps_scanned,
            removed,
            cancelled_suffix(r.cancelled)
        ),
        fails,
    )
}

fn parse_redundant(
    r: bulk::BulkRemoveRedundantResult,
    label_for: impl Fn(&str) -> String,
) -> (String, Vec<BulkFailure>) {
    let fails = failures_of(&r.outcomes, label_for);
    let removed_total: usize = r.outcomes.iter().map(|o| o.removed.len()).sum();
    let apps_changed = r.outcomes.iter().filter(|o| !o.removed.is_empty()).count();
    (
        format!(
            "Removed {removed_total} redundant permission(s) across {apps_changed} app(s); {} failed{}.",
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
    )
}

fn parse_scope(
    noun: &str,
    r: bulk::BulkScopeResult,
    label_for: impl Fn(&str) -> String,
) -> (String, Vec<BulkFailure>) {
    let fails = failures_of(&r.outcomes, label_for);
    let scoped = r.outcomes.len() - fails.len();
    (
        format!(
            "Scoped {noun} access on {scoped} app(s); {} failed{}.",
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
    )
}

fn parse_add_owner(
    r: bulk::BulkAddOwnerResult,
    label_for: impl Fn(&str) -> String,
) -> (String, Vec<BulkFailure>) {
    let fails = failures_of(&r.outcomes, label_for);
    let added = r.outcomes.iter().filter(|o| o.added).count();
    let skipped = r.outcomes.iter().filter(|o| o.skipped).count();
    (
        format!(
            "Added the owner to {added} app(s); {skipped} already had them; {} failed{}.",
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
    )
}

fn parse_disable(
    r: bulk::BulkDisableSignInResult,
    label_for: impl Fn(&str) -> String,
) -> (String, Vec<BulkFailure>) {
    let fails = failures_of(&r.outcomes, label_for);
    let disabled = r.outcomes.len() - fails.len();
    (
        format!(
            "Disabled sign-in for {disabled} app(s); {} failed{}. Re-enable anytime from the enterprise app's Overview.",
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
    )
}

fn parse_delete(
    r: bulk::BulkDeleteResult,
    label_for: impl Fn(&str) -> String,
) -> (String, Vec<BulkFailure>) {
    let fails: Vec<BulkFailure> = r
        .failed
        .iter()
        .map(|f| BulkFailure {
            label: label_for(&f.object_id),
            reason: f.message.clone(),
            // BulkDeleteFailure predates the structured error and carries only
            // a message; delete failures are per-object (not-found, insufficient
            // privileges), never session-level.
            code: None,
        })
        .collect();
    (
        format!(
            "Deleted {} app(s); {} failed{}.",
            r.deleted.len(),
            fails.len(),
            cancelled_suffix(r.cancelled)
        ),
        fails,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_ACTIONS: [BulkAction; 8] = [
        BulkAction::Grant,
        BulkAction::RemoveExpired,
        BulkAction::RemoveRedundant,
        BulkAction::ScopeMailbox,
        BulkAction::ScopeSharePoint,
        BulkAction::AddOwner,
        BulkAction::DisableSignIn,
        BulkAction::Delete,
    ];

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
        for action in ALL_ACTIONS {
            let spec = action.spec();
            assert!(!spec.label.is_empty(), "{action:?} has no label");
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
        for action in ALL_ACTIONS {
            let spec = action.spec();
            if spec.destructive && action != BulkAction::RemoveRedundant {
                assert!(
                    matches!(spec.confirm, Confirm::Keyword(_)),
                    "{action:?} is destructive but confirms on a plain click"
                );
            }
        }
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
        // Failures derived from counts rather than an error carry `code: None`.
        let fails = vec![BulkFailure {
            label: "app".into(),
            reason: "3 credential(s) could not be removed".into(),
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
        let (summary, fails) = parse_scope(
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
        assert_eq!(fails.len(), 1);
        assert!(
            summary.contains("2 app(s)"),
            "scoped count must exclude failures: {summary}"
        );
        assert!(summary.contains("1 failed"), "{summary}");
        assert!(
            !summary.contains("cancelled"),
            "a completed run must not claim it was cancelled: {summary}"
        );
    }

    #[test]
    fn a_cancelled_run_says_so_in_its_summary() {
        // A partial run that reads as complete is the failure mode; the suffix
        // is the only thing distinguishing them in the summary line.
        let (summary, _) = parse_scope(
            "mailbox",
            bulk::BulkScopeResult {
                outcomes: vec![scope_outcome("a", None)],
                cancelled: true,
            },
            upper,
        );
        assert!(summary.contains(cancelled_suffix(true).trim()), "{summary}");
        assert_eq!(cancelled_suffix(false), "");
    }

    #[test]
    fn the_add_owner_summary_separates_added_from_already_present() {
        // `skipped` means the owner was already there — reporting it as "added"
        // overstates what the run changed, and as "failed" understates success.
        let (summary, fails) = parse_add_owner(
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
        assert_eq!(fails.len(), 1);
        assert!(summary.contains("to 1 app(s)"), "{summary}");
        assert!(summary.contains("1 already had them"), "{summary}");
        assert!(summary.contains("1 failed"), "{summary}");
    }
}
