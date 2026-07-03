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

use std::collections::HashSet;

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Spinner, SpinnerSize, Textarea};

use crate::bindings::applications;
use crate::bindings::bulk;
use crate::bindings::events;
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

impl BulkAction {
    fn label(self) -> &'static str {
        match self {
            BulkAction::Grant => "Grant consent",
            BulkAction::RemoveExpired => "Remove expired credentials",
            BulkAction::RemoveRedundant => "Remove redundant permissions",
            BulkAction::ScopeMailbox => "Scope mailbox access",
            BulkAction::ScopeSharePoint => "Scope SharePoint access",
            BulkAction::AddOwner => "Add owner",
            BulkAction::DisableSignIn => "Disable sign-in",
            BulkAction::Delete => "Delete",
        }
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
) -> impl IntoView {
    let session = use_session();

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
    let confirm_ok = Memo::new(move |_| match armed.get() {
        Some(BulkAction::RemoveExpired) => confirm_text.get().trim() == "REMOVE",
        Some(BulkAction::Delete) => confirm_text.get().trim() == "DELETE",
        Some(BulkAction::RemoveRedundant) => true,
        // Reversible (accountEnabled toggles back), so a plain confirm suffices.
        Some(BulkAction::DisableSignIn) => true,
        Some(BulkAction::ScopeMailbox) => !parse_lines(&groups_text.get()).is_empty(),
        Some(BulkAction::ScopeSharePoint) => !parse_lines(&sites_text.get()).is_empty(),
        Some(BulkAction::AddOwner) => owner_pick.with(Option::is_some),
        Some(BulkAction::Grant) | None => false,
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
                    .map(|r| (parse_grant(r), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::RemoveExpired => bulk::bulk_remove_expired_credentials(tid, Some(&ids))
                    .await
                    .map(|r| (parse_remove_expired(r), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::RemoveRedundant => bulk::bulk_remove_redundant_permissions(tid, &ids)
                    .await
                    .map(|r| (parse_redundant(r), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::ScopeMailbox => bulk::bulk_scope_mailbox_access(tid, &ids, &groups)
                    .await
                    .map(|r| (parse_scope("mailbox", r), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::ScopeSharePoint => {
                    bulk::bulk_scope_sharepoint_access(tid, &ids, &sites, &role)
                        .await
                        .map(|r| (parse_scope("SharePoint", r), false))
                        .map(|((s, f), c)| (s, f, c))
                        .map_err(|e| e.message)
                }
                BulkAction::AddOwner => {
                    // Guarded non-None above; unwrap_or_default is unreachable.
                    let principal_id = principal_id.unwrap_or_default();
                    bulk::bulk_add_owner(tid, &ids, &principal_id)
                        .await
                        .map(|r| (parse_add_owner(r), false))
                        .map(|((s, f), c)| (s, f, c))
                        .map_err(|e| e.message)
                }
                BulkAction::DisableSignIn => bulk::bulk_disable_sign_in(tid, &ids)
                    .await
                    .map(|r| (parse_disable(r), false))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
                BulkAction::Delete => bulk::bulk_delete_applications(tid, &ids)
                    .await
                    .map(|r| (parse_delete(r), true))
                    .map(|((s, f), c)| (s, f, c))
                    .map_err(|e| e.message),
            };
            match parsed {
                Ok((s, f, clear_sel)) => {
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
                                    let cls = if a == BulkAction::Delete { "button--danger" } else { "" };
                                    view! {
                                        <Button
                                            class=cls
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            on_click=Box::new(move |_| {
                                                if a == BulkAction::Grant {
                                                    run(a);
                                                } else {
                                                    armed.set(Some(a));
                                                }
                                            })
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
                            let cls = if failures.with(|f| f.is_empty()) {
                                "alert alert--ok"
                            } else {
                                "alert alert--warn"
                            };
                            view! { <div class=cls>{s}</div> }
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

    let danger = matches!(action, BulkAction::RemoveExpired | BulkAction::Delete);
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
        BulkAction::Grant => ().into_any(),
    };

    let input: AnyView = match action {
        BulkAction::RemoveExpired | BulkAction::Delete => {
            let keyword = if matches!(action, BulkAction::Delete) { "DELETE" } else { "REMOVE" };
            view! {
                <div class="confirm-gate">
                    <Body1 class="confirm-gate__label">
                        "Type "<strong>{keyword}</strong>" to confirm."
                    </Body1>
                    <Input value=confirm_text placeholder=keyword />
                </div>
            }
            .into_any()
        }
        BulkAction::ScopeMailbox => view! {
            <Textarea value=groups_text placeholder="Mailbox groups (name, address, or object id) — one per line" />
        }.into_any(),
        BulkAction::ScopeSharePoint => view! {
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
        BulkAction::AddOwner => {
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
        BulkAction::RemoveRedundant | BulkAction::DisableSignIn | BulkAction::Grant => {
            ().into_any()
        }
    };

    let confirm_label = match action {
        BulkAction::RemoveExpired => "Remove expired",
        BulkAction::RemoveRedundant => "Remove redundant",
        BulkAction::ScopeMailbox => "Scope mailbox",
        BulkAction::ScopeSharePoint => "Scope SharePoint",
        BulkAction::AddOwner => "Add owner",
        BulkAction::DisableSignIn => "Disable sign-in",
        BulkAction::Delete => "Delete",
        BulkAction::Grant => "Confirm",
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

fn parse_grant(r: bulk::BulkGrantResult) -> (String, Vec<BulkFailure>) {
    let fails: Vec<BulkFailure> = r
        .outcomes
        .iter()
        .filter_map(|o| {
            o.error.as_ref().map(|e| BulkFailure {
                label: o.object_id.clone(),
                reason: e.clone(),
            })
        })
        .collect();
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
            let reason = if let Some(e) = &s.error {
                Some(e.clone())
            } else if !s.failed_key_ids.is_empty() {
                Some(format!(
                    "{} credential(s) could not be removed",
                    s.failed_key_ids.len()
                ))
            } else {
                None
            };
            reason.map(|reason| BulkFailure {
                label: s.display_name.clone(),
                reason,
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

fn parse_redundant(r: bulk::BulkRemoveRedundantResult) -> (String, Vec<BulkFailure>) {
    let fails: Vec<BulkFailure> = r
        .outcomes
        .iter()
        .filter_map(|o| {
            o.error.as_ref().map(|e| BulkFailure {
                label: o.object_id.clone(),
                reason: e.clone(),
            })
        })
        .collect();
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

fn parse_scope(noun: &str, r: bulk::BulkScopeResult) -> (String, Vec<BulkFailure>) {
    let fails: Vec<BulkFailure> = r
        .outcomes
        .iter()
        .filter_map(|o| {
            o.error.as_ref().map(|e| BulkFailure {
                label: o.object_id.clone(),
                reason: e.clone(),
            })
        })
        .collect();
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

fn parse_add_owner(r: bulk::BulkAddOwnerResult) -> (String, Vec<BulkFailure>) {
    let fails: Vec<BulkFailure> = r
        .outcomes
        .iter()
        .filter_map(|o| {
            o.error.as_ref().map(|e| BulkFailure {
                label: o.object_id.clone(),
                reason: e.clone(),
            })
        })
        .collect();
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

fn parse_disable(r: bulk::BulkDisableSignInResult) -> (String, Vec<BulkFailure>) {
    let fails: Vec<BulkFailure> = r
        .outcomes
        .iter()
        .filter_map(|o| {
            o.error.as_ref().map(|e| BulkFailure {
                label: o.object_id.clone(),
                reason: e.clone(),
            })
        })
        .collect();
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

fn parse_delete(r: bulk::BulkDeleteResult) -> (String, Vec<BulkFailure>) {
    let fails: Vec<BulkFailure> = r
        .failed
        .iter()
        .map(|f| BulkFailure {
            label: f.object_id.clone(),
            reason: f.message.clone(),
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
