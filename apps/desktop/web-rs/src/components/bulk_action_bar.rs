//! Inline bulk-action bar — Grant consent / Remove expired credentials / Delete
//! over a multi-selected set of app-registration object ids.
//!
//! This is the **single home** of the selection-driven bulk command-calling
//! logic: the Security Audit table, the App Registrations list, and the Bulk
//! Actions page all mount this same component, passing their own selection set.
//! Destructive actions arm an inline typed confirmation (REMOVE / DELETE) before
//! running; a live progress row + Cancel and a tone-coded result summary mirror
//! the former tab-per-action Bulk Actions page.

use std::collections::HashSet;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input, Spinner, SpinnerSize};

use crate::bindings::bulk;
use crate::bindings::events;
use crate::hooks::use_progress_stream::use_progress_stream;
use crate::state::use_session;

/// One failed item from a bulk run, surfaced below the aggregate summary so the
/// user can see *which* app failed and *why* (the counts alone hid this).
/// Public so the Bulk Actions page's Create flow can reuse the same shape.
#[derive(Clone)]
pub struct BulkFailure {
    pub label: String,
    pub reason: String,
}

/// The three selection-driven bulk operations. Grant runs immediately; the two
/// destructive ones arm an inline typed-confirmation gate first.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BulkAction {
    RemoveExpired,
    Delete,
}

#[component]
pub fn BulkActionBar(
    /// The selection set this bar operates on (app-registration object ids).
    /// The bar clears it after a successful Delete (those object ids are gone).
    selection: RwSignal<HashSet<String>>,
    /// Fired after any successful run so the host can refetch its list(s)
    /// (e.g. `bump_apps_reload`). The bar handles selection-clearing on Delete
    /// itself, so the host only needs to refresh. Pass a `Callback` directly or
    /// omit it.
    #[prop(optional, into)]
    on_done: Option<Callback<()>>,
) -> impl IntoView {
    let session = use_session();

    let busy = RwSignal::new(false);
    let summary: RwSignal<Option<String>> = RwSignal::new(None);
    // Per-item failures from the last run (label + reason). Drives the failure
    // list and tones the summary alert warn-vs-ok.
    let failures: RwSignal<Vec<BulkFailure>> = RwSignal::new(Vec::new());
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    // Live per-app progress emitted by the backend bulk loop ("bulk-progress").
    let progress: RwSignal<Option<bulk::BulkProgress>> = RwSignal::new(None);
    use_progress_stream(progress, events::bulk_progress);

    // Cancel an in-flight run. The backend bulk loops poll the shared cancel
    // flag and stop at the next item boundary (the run still returns its partial
    // result, tagged `cancelled`). `cancelling` disables the button until the
    // run actually ends; reset whenever `busy` clears.
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

    // Destructive-action arming: clicking Remove/Delete reveals an inline typed
    // confirmation rather than running immediately. `armed` holds which action
    // awaits confirmation; `confirm_text` resets whenever it changes so a stale
    // keyword can never leave the next action armed.
    let armed: RwSignal<Option<BulkAction>> = RwSignal::new(None);
    let confirm_text = RwSignal::new(String::new());
    Effect::new(move |_| {
        let _ = armed.get();
        confirm_text.set(String::new());
    });
    // Confirm opens only when the typed text exactly matches the armed action's
    // keyword (case-sensitive, trimmed) — deliberately reproducing the literal
    // word shown, matching the former Bulk Actions page.
    let confirm_ok = Memo::new(move |_| match armed.get() {
        Some(BulkAction::RemoveExpired) => confirm_text.get().trim() == "REMOVE",
        Some(BulkAction::Delete) => confirm_text.get().trim() == "DELETE",
        None => false,
    });

    let do_grant = move |_| {
        if busy.get() {
            return;
        }
        let ids: Vec<String> = selection.get().into_iter().collect();
        if ids.is_empty() {
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
            match bulk::bulk_grant_permissions(&t.tenant_id, &ids).await {
                Ok(r) => {
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
                    summary.set(Some(format!(
                        "Granted consent to {} app(s); {} with errors{}.",
                        r.outcomes.len(),
                        fails.len(),
                        if r.cancelled { " (cancelled)" } else { "" }
                    )));
                    failures.set(fails);
                    if let Some(cb) = on_done {
                        cb.run(());
                    }
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let do_remove = move || {
        if busy.get() || !confirm_ok.get() {
            return;
        }
        let ids: Vec<String> = selection.get().into_iter().collect();
        if ids.is_empty() {
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
            match bulk::bulk_remove_expired_credentials(&t.tenant_id, Some(&ids)).await {
                Ok(r) => {
                    // A per-app failure is either a hard error or some key(s)
                    // that couldn't be removed.
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
                    summary.set(Some(format!(
                        "Scanned {} app(s); {} had expired creds removed{}.",
                        r.apps_scanned,
                        removed,
                        if r.cancelled { " (cancelled)" } else { "" }
                    )));
                    failures.set(fails);
                    armed.set(None);
                    if let Some(cb) = on_done {
                        cb.run(());
                    }
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let do_delete = move || {
        if busy.get() || !confirm_ok.get() {
            return;
        }
        let ids: Vec<String> = selection.get().into_iter().collect();
        if ids.is_empty() {
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
            match bulk::bulk_delete_applications(&t.tenant_id, &ids).await {
                Ok(r) => {
                    let fails: Vec<BulkFailure> = r
                        .failed
                        .iter()
                        .map(|f| BulkFailure {
                            label: f.object_id.clone(),
                            reason: f.message.clone(),
                        })
                        .collect();
                    summary.set(Some(format!(
                        "Deleted {} app(s); {} failed{}.",
                        r.deleted.len(),
                        fails.len(),
                        if r.cancelled { " (cancelled)" } else { "" }
                    )));
                    failures.set(fails);
                    armed.set(None);
                    // The deleted object ids no longer exist — drop them from the
                    // host's selection set (mirrors the former page's behaviour).
                    selection.update(HashSet::clear);
                    if let Some(cb) = on_done {
                        cb.run(());
                    }
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    // The bar is self-gating: it shows while there's a selection, a run in
    // flight, or a result still on screen. This keeps the post-run summary
    // visible even after a successful Delete clears the selection (the host
    // mounts the bar unconditionally and lets it decide its own visibility).
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
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(do_grant)
                    disabled=Signal::derive(move || busy.get())
                >
                    "Grant consent"
                </Button>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| armed.set(Some(BulkAction::RemoveExpired)))
                    disabled=Signal::derive(move || busy.get())
                >
                    "Remove expired credentials"
                </Button>
                <Button
                    class="button--danger"
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| armed.set(Some(BulkAction::Delete)))
                    disabled=Signal::derive(move || busy.get())
                >
                    "Delete"
                </Button>
            </div>
            </Show>
            // Inline typed-confirmation gate for whichever destructive action is armed.
            {move || {
                armed
                    .get()
                    .map(|action| {
                        let (keyword, danger, confirm_label) = match action {
                            BulkAction::RemoveExpired => {
                                (
                                    "REMOVE",
                                    "Remove every expired password credential from the selected app(s). This is irreversible.",
                                    "Remove expired",
                                )
                            }
                            BulkAction::Delete => {
                                (
                                    "DELETE",
                                    "Permanently delete the selected app registration(s). This cannot be undone.",
                                    "Delete",
                                )
                            }
                        };
                        view! {
                            <div class="bulk-action-bar__confirm">
                                <Body1 class="bulk-action__danger">{danger}</Body1>
                                <div class="confirm-gate">
                                    <Body1 class="confirm-gate__label">
                                        "Type "<strong>{keyword}</strong>" to confirm."
                                    </Body1>
                                    <Input value=confirm_text placeholder=keyword />
                                </div>
                                <div class="actions-row">
                                    <Button
                                        class="button--danger"
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(move |_| match action {
                                            BulkAction::RemoveExpired => do_remove(),
                                            BulkAction::Delete => do_delete(),
                                        })
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
                    })
            }}
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
                        // Warn-tone the summary when any item failed, so a partial
                        // success doesn't read as all-green.
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
