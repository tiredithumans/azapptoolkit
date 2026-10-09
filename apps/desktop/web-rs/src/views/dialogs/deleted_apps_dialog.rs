//! "Recently deleted" dialog — the tenant recycle bin.
//!
//! Deleted app registrations stay recoverable for ~30 days; until now the app
//! delete was presented as irreversible and the bin was invisible. This dialog
//! lists it and offers the two exits: **Restore** (which carries the paired
//! enterprise app along — see `commands::bulk::bulk_restore_deleted`) and a
//! two-step **Delete forever** that skips the window.
//!
//! Mounted once by the shell under the App Registrations view, gated on
//! `TenantScopedUi::deleted_open`, so it re-mounts per open and fetches fresh
//! each time — the bin is never cached (see `commands::applications::deleted`).

use leptos::prelude::*;
use thaw::{Button, ButtonAppearance};

use crate::bindings::{applications, bulk};
use crate::components::icon::IconName;
use crate::components::modal_shell::ModalShell;
use crate::components::ui::{Callout, DataTable, DetailLoadError, EmptyState, SkeletonList};
use crate::state::use_session;
use crate::util::{expiry_label, floored_days_until, relative_time};

use azapptoolkit_dto::applications::{DeletedAppDto, DeletedAppsDto};
use chrono::{Duration, Utc};

/// The recycle-bin window Graph documents; the dialog shows how much of it is
/// left per row so "expires in 2d" is a fact, not a guess.
const DELETED_WINDOW_DAYS: i64 = 30;

#[component]
pub fn DeletedAppsDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] on_close: Callback<()>,
    /// Fired when a restore succeeded, so the App Registrations list refetches
    /// and the restored app comes back on it.
    #[prop(into)]
    on_mutated: Callback<()>,
) -> impl IntoView {
    let session = use_session();

    // `None` = the first fetch hasn't landed (skeleton); `Some` = loaded or
    // refetched. Errors replace the whole body through `DetailLoadError`.
    let rows: RwSignal<Option<DeletedAppsDto>> = RwSignal::new(None);
    let loading = RwSignal::new(false);
    let error: RwSignal<Option<azapptoolkit_dto::UiError>> = RwSignal::new(None);
    let reload = RwSignal::new(0_u32);
    // One mutation at a time across the whole dialog (a restore and a purge
    // both change what the next row read would show); holds the object id of
    // the row being acted on so its buttons read busy.
    let busy_row: RwSignal<Option<String>> = RwSignal::new(None);
    // First "Delete forever" click only arms the row; the same button then
    // reads "Confirm permanent delete". Arming is per-row and sticky until a
    // click, so an accidental first tap never chains into a second-target
    // accidental confirm.
    let purge_armed: RwSignal<Option<String>> = RwSignal::new(None);

    // Fetch on mount and on every reload bump. Tenant-race guarded like the
    // audit dashboard: a late response must not write into a switched tenant.
    Effect::new(move |_| {
        let t = session.active_tenant.get();
        let _ = reload.get();
        let Some(t) = t else { return };
        loading.set(true);
        error.set(None);
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            let result = applications::list_recently_deleted(&tenant_id).await;
            let still_active = session
                .active_tenant
                .get_untracked()
                .map(|t| t.tenant_id == tenant_id)
                .unwrap_or(false);
            if still_active {
                match result {
                    Ok(d) => rows.set(Some(d)),
                    Err(e) => error.set(Some(e)),
                }
                loading.set(false);
            }
        });
    });

    // `Callback<()>` rather than a bare closure: the retry button takes a
    // `Callback<()>` and the footer Refresh takes `Fn(MouseEvent)` — one
    // closure cannot serve both, and `Callback` is `Copy`.
    let refetch = Callback::new(move |_: ()| reload.update(|n| *n = n.wrapping_add(1)));

    let on_restore = Callback::new(move |object_id: String| {
        if busy_row.get_untracked().is_some() {
            return;
        }
        let name = rows
            .get_untracked()
            .and_then(|d| {
                d.apps
                    .iter()
                    .find(|a| a.object_id == object_id)
                    .and_then(|a| a.display_name.clone())
            })
            .unwrap_or_else(|| object_id.clone());
        busy_row.set(Some(object_id.clone()));
        let Some(t) = session.active_tenant.get_untracked() else {
            busy_row.set(None);
            return;
        };
        let tenant_id = t.tenant_id;
        let session = session;
        leptos::task::spawn_local(async move {
            let result = bulk::bulk_restore_deleted(&tenant_id, &[object_id]).await;
            // Land nothing on a switched or signed-out tenant: the task outlives
            // the dialog (`frontend-workspace.md`), and a toast here would
            // surface in whatever tenant is active now.
            if !session.is_active_tenant(&tenant_id) {
                busy_row.set(None);
                return;
            }
            match result {
                Ok(res) => {
                    let outcome = res.outcomes.first();
                    let fatal = outcome.and_then(|o| o.error.as_ref());
                    let restored = outcome.is_some_and(|o| o.restored);
                    if restored && fatal.is_none() {
                        let sp_note = if outcome.is_some_and(|o| o.sp_restored) {
                            " + its enterprise app"
                        } else {
                            ""
                        };
                        session.toast_success(format!("Restored {name}{sp_note}."));
                        on_mutated.try_run(());
                        reload.update(|n| *n = n.wrapping_add(1));
                    } else if restored {
                        // App came back but a paired SP failed — say so rather
                        // than claiming a clean restore.
                        let msg = fatal.map(|e| e.message.clone()).unwrap_or_default();
                        session.toast_error(
                            format!("App restored, but its enterprise app was not: {msg}"),
                            None,
                        );
                        on_mutated.try_run(());
                        reload.update(|n| *n = n.wrapping_add(1));
                    } else if let Some(e) = fatal {
                        // Per-row failures arrive as `BulkError`; the session
                        // reporter takes `UiError` (its code drives the
                        // re-auth classification).
                        session.report_command_error(&azapptoolkit_dto::UiError::new(
                            e.code.clone(),
                            e.message.clone(),
                            e.retryable,
                        ));
                    } else {
                        session.toast_error("Restore was cancelled.", None);
                    }
                }
                Err(e) => session.report_command_error(&e),
            }
            busy_row.set(None);
        });
    });

    let on_purge = Callback::new(move |object_id: String| {
        // Two-step: arm first, confirm second.
        if purge_armed.get_untracked().as_deref() != Some(object_id.as_str()) {
            purge_armed.set(Some(object_id));
            return;
        }
        if busy_row.get_untracked().is_some() {
            return;
        }
        let name = rows
            .get_untracked()
            .and_then(|d| {
                d.apps
                    .iter()
                    .find(|a| a.object_id == object_id)
                    .and_then(|a| a.display_name.clone())
            })
            .unwrap_or_else(|| object_id.clone());
        purge_armed.set(None);
        busy_row.set(Some(object_id.clone()));
        let Some(t) = session.active_tenant.get_untracked() else {
            busy_row.set(None);
            return;
        };
        let tenant_id = t.tenant_id;
        let session = session;
        leptos::task::spawn_local(async move {
            let purged = applications::purge_deleted_application(&tenant_id, &object_id).await;
            if !session.is_active_tenant(&tenant_id) {
                busy_row.set(None);
                return;
            }
            match purged {
                Ok(()) => {
                    session.toast_success(format!("Deleted {name} permanently."));
                    reload.update(|n| *n = n.wrapping_add(1));
                }
                Err(e) => session.report_command_error(&e),
            }
            busy_row.set(None);
        });
    });

    view! {
        <ModalShell
            open
            title="Recently deleted apps".to_string()
            busy=Signal::derive(move || busy_row.get().is_some())
            on_close
            wide=true
        >
            <Callout tone="info">
                "Deleted apps stay in the recycle bin for 30 days. Restoring an app also restores its paired enterprise application; permanent deletion skips the window and cannot be undone."
            </Callout>
            {move || {
                error
                    .get()
                    .map(|e| {
                        view! {
                            <DetailLoadError
                                error=e
                                on_retry=Callback::new(move |_| refetch.run(()))
                                class="app-list__error"
                            />
                        }
                    })
            }}
            {move || {
                if loading.get() && rows.get().is_none() {
                    return view! { <SkeletonList rows=5 /> }.into_any();
                }
                let Some(data) = rows.get() else {
                    return ().into_any();
                };
                if data.apps.is_empty() {
                    return view! {
                        <EmptyState
                            icon=IconName::Trash
                            title="Recycle bin is empty"
                            body="App registrations deleted in the last 30 days appear here."
                        />
                    }
                        .into_any();
                }
                let truncated = data.truncated;
                view! {
                    <>
                        {truncated.then(|| {
                            view! {
                                <Callout tone="warn">
                                    "The recycle-bin read hit its row cap, so this list is partial — deleted apps beyond the cap are not shown."
                                </Callout>
                            }
                        })}
                        // Re-rendered when a row goes busy / armed so the
                        // buttons flip; the table is dialog-scale, so a full
                        // rebuild per interaction is fine.
                        {
                            let busy = busy_row.get();
                            let armed = purge_armed.get();
                            view! {
                                <DataTable
                                    headers=vec!["App", "Deleted", ""]
                                    rows=data.apps
                                    empty_message="".to_string()
                                    row=move |row: DeletedAppDto| {
                                        let pending = busy.as_deref() == Some(row.object_id.as_str());
                                        let is_armed =
                                            armed.as_deref() == Some(row.object_id.as_str());
                                        let name = row
                                            .display_name
                                            .clone()
                                            .unwrap_or_else(|| "(limited info)".to_string());
                                        let deleted_line = row.deleted_date_time.map_or_else(
                                            || "unknown".to_string(),
                                            |d| {
                                                let now = Utc::now();
                                                let rel = relative_time(now, d);
                                                let window_end =
                                                    d + Duration::days(DELETED_WINDOW_DAYS);
                                                let left =
                                                    expiry_label(floored_days_until(window_end, now));
                                                format!("{rel} · {left}")
                                            },
                                        );
                                        let id_for_restore = row.object_id.clone();
                                        let id_for_purge = row.object_id.clone();
                                        view! {
                                            <tr>
                                                <td>
                                                    <div class="permissions-cell__primary">{name}</div>
                                                    <div class="permissions-cell__secondary">
                                                        {row.app_id.clone().unwrap_or_else(|| row.object_id.clone())}
                                                    </div>
                                                </td>
                                                <td>{deleted_line}</td>
                                                <td>
                                                    <Button
                                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                        disabled=Signal::derive(move || pending)
                                                        on_click=Box::new(move |_| {
                                                            on_restore.run(id_for_restore.clone())
                                                        })
                                                    >
                                                        "Restore"
                                                    </Button>
                                                    <Button
                                                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                                        disabled=Signal::derive(move || pending)
                                                        on_click=Box::new(move |_| {
                                                            on_purge.run(id_for_purge.clone())
                                                        })
                                                    >
                                                        {if is_armed {
                                                            "Confirm permanent delete"
                                                        } else {
                                                            "Delete forever"
                                                        }}
                                                    </Button>
                                                </td>
                                            </tr>
                                        }
                                            .into_any()
                                    }
                                />
                            }
                                .into_any()
                                }
                    }
                        .into_any()
            }}
            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| refetch.run(()))
                    disabled=Signal::derive(move || loading.get())
                >
                    "Refresh"
                </Button>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| on_close.run(()))
                >
                    "Close"
                </Button>
            </div>
        </ModalShell>
    }
}
