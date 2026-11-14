//! Detail pane for a selected application: header (name + delete), the
//! `AppTab` `TabBar`, and the active tab body.

use std::rc::Rc;
use std::sync::Arc;

use azapptoolkit_dto::UiError;
use leptos::html;
use leptos::prelude::*;

use crate::bindings::applications::{self, ApplicationDetail};
use crate::bindings::bulk;
use crate::components::detail_header::DetailHeader;
use crate::components::toast::ToastKind;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{
    Badge, BadgeTone, DetailLoadError, DetailSkeleton, TabBar, TabBarItem,
};
use crate::hooks::pane_tabs::{PaneTabs, Reload};
use crate::hooks::use_command::use_command;
use crate::state::{OpenItemKind, Session, use_session};
use crate::util::no_tenant;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::pairing::jump_to_paired_enterprise;
use crate::views::tabs::{
    AppTab, activity_tab::ActivityTab, authentication_tab::AuthenticationTab,
    conditional_access_tab::ConditionalAccessTab, credentials_tab::CredentialsTab,
    expose_api_tab::ExposeApiTab, overview_tab::OverviewTab, owners_tab::OwnersTab,
    permissions_tab::PermissionsTab,
};

#[component]
pub fn ApplicationDetailPane(
    #[prop(into)] object_id: Signal<String>,
    // Reports the resolved display name to the dock chip once the detail loads
    // (the workspace passes a setter). `None` for standalone uses (e.g. tests).
    #[prop(optional)] on_title: Option<Callback<String>>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // `reload` increments to force the resource to re-fetch.
    let reload = RwSignal::new(0_u32);

    // Each fetch is numbered so the effect below can tell a fresh result from
    // the previous one: the resource notifies when a refetch STARTS as well as
    // when it lands, and still holds the old value in between.
    let fetch_seq = StoredValue::new(0_u64);
    let detail = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = object_id.get();
        let _ = reload.get();
        let seq = fetch_seq.get_value() + 1;
        fetch_seq.set_value(seq);
        async move {
            let result = match tenant {
                Some(t) => applications::get_application_detail(&t.tenant_id, &id).await,
                None => Err(no_tenant()),
            };
            (seq, id, result)
        }
    });

    // The last detail that loaded. The pane body renders from this signal and
    // stays mounted across a reload, so fresh data arrives under the tabs
    // instead of replacing the pane with a skeleton — which rebuilt every tab
    // and threw away unsaved edits on tabs that had nothing to do with the
    // reload (`hooks::pane_tabs`).
    let loaded: RwSignal<Option<Arc<ApplicationDetail>>> = RwSignal::new(None);
    // A failed FIRST load (nothing to show yet). A failed reload keeps the
    // pane and reports through the session instead.
    let load_error: RwSignal<Option<UiError>> = RwSignal::new(None);
    // True from a reload request until its result lands; spins the header's
    // Refresh so a reload that no longer blanks the pane still shows.
    let reloading = RwSignal::new(false);

    // Open on the deep-link target tab if one was set (e.g. the credential
    // dashboard's "Open" action sets "credentials"); otherwise restore the
    // last-viewed tab so the workflow tab survives switching apps. The deep-link
    // is consumed once so a later in-app selection doesn't re-trigger it.
    let initial_tab = session
        .tenant_ui
        .pending_app_tab
        .get_untracked()
        .unwrap_or_else(|| session.last_app_tab.get_untracked());
    session.tenant_ui.pending_app_tab.set(None);
    // `TabBar` is string-keyed and two-way bound, so the active tab stays a
    // `String`; `AppTab` is only the bridge that clamps stale values and names
    // each slot below.
    let tabs = PaneTabs::new(
        AppTab::from_str(&initial_tab).value().to_string(),
        AppTab::ALL.iter().map(|tab| tab.value()),
    );
    let active_tab = tabs.active;
    // Persist the active tab for the next app opened.
    Effect::new(move |_| session.last_app_tab.set(active_tab.get()));

    let pane_ref: NodeRef<html::Div> = NodeRef::new();
    let landed_seq = StoredValue::new(0_u64);
    let landed_id: StoredValue<Option<String>> = StoredValue::new(None);
    Effect::new(move |_| {
        let Some((seq, id, result)) = detail.get() else {
            return;
        };
        if seq <= landed_seq.get_value() {
            return;
        }
        landed_seq.set_value(seq);
        reloading.set(false);
        match result {
            Ok(d) => {
                if let Some(cb) = on_title {
                    cb.run(d.application.display_name.clone());
                }
                // A different object in the same pane: nothing on screen
                // belongs to it, unsaved edits included.
                if landed_id.get_value().is_some_and(|prev| prev != id) {
                    tabs.request(Reload::DiscardAll);
                }
                landed_id.set_value(Some(id));
                let first = loaded.with_untracked(Option::is_none);
                load_error.set(None);
                // The new detail first, so a tab rebuilt by `land` reads it.
                loaded.set(Some(Arc::new(d)));
                if !first {
                    let scope = pane_ref.get_untracked();
                    tabs.land(scope.as_deref().map(|el| el as &web_sys::Element));
                }
            }
            Err(e) => {
                if loaded.with_untracked(Option::is_some) {
                    // The pane keeps showing what it had; say the refresh failed.
                    session.report_command_error(&e);
                } else {
                    load_error.set(Some(e));
                }
            }
        }
    });

    // A tab's `on_changed` after its own mutation: refetch, rebuild that tab,
    // keep unsaved edits on the others.
    let reload_from = move |tab: AppTab| {
        Callback::new(move |()| {
            tabs.request(Reload::From(tab.value()));
            reloading.set(true);
            reload.update(|n| *n = n.wrapping_add(1));
        })
    };

    // Detail-pane Refresh: bust this app's server-side detail cache, then
    // re-run the resource so it re-fetches from Graph (a plain reload would hit
    // the cache and show stale data). It rebuilds every tab, so with unsaved
    // edits in the pane it asks first (`confirm_refresh`).
    let refresh_now = move || {
        if reloading.get_untracked() {
            return;
        }
        let Some(t) = tenant.get_untracked() else {
            return;
        };
        let id = object_id.get_untracked();
        tabs.request(Reload::DiscardAll);
        reloading.set(true);
        leptos::task::spawn_local(async move {
            let _ = applications::invalidate_application_detail(&t.tenant_id, &id).await;
            reload.update(|n| *n = n.wrapping_add(1));
        });
    };
    let confirm_refresh = RwSignal::new(false);
    let on_refresh = Callback::new(move |()| {
        if tabs.any_dirty() {
            confirm_refresh.set(true);
        } else {
            refresh_now();
        }
    });

    let delete_open = RwSignal::new(false);
    // `use_command` owns the busy/error signals and the double-submit guard,
    // tenant resolution, and spawn boilerplate this handler used to inline.
    let delete_cmd = use_command();

    let do_delete = move || {
        delete_cmd.run(
            move |()| {
                delete_open.set(false);
                let id = object_id.get_untracked();
                // Read before the close below disposes this pane.
                let name = loaded
                    .with_untracked(|d| d.as_ref().map(|d| d.application.display_name.clone()))
                    .unwrap_or_else(|| id.clone());
                // Out of every bulk selection: a deleted id left in one is a
                // dangling one ("N selected" counts it; the Bulk Actions page
                // shows it as a raw GUID once its name leaves the list).
                session.deselect_object(&id);
                session.close_item_by_entity(OpenItemKind::AppReg, &id);
                // Graph deletes the app's service principal with it.
                session.bump_app_and_enterprise_reload();
                // A deleted app registration stays restorable for 30 days, so
                // the confirmation carries the way back while the operator is
                // still looking at it. The bulk delete has always had Undo; a
                // single delete sent them to "Recently deleted…" instead.
                match session.active_tenant.get_untracked() {
                    Some(t) => toast_deleted_with_undo(session, t.tenant_id, id, name),
                    None => {
                        session.toast_success("App registration deleted.");
                    }
                }
            },
            move |tenant_id| {
                let id = object_id.get();
                async move { applications::delete_application(&tenant_id, &id).await }
            },
        );
    };

    // The pane's phase, memoized so the body below is built once when the
    // first detail lands — not again on every reload (`loaded` changes then).
    let phase = Memo::new(move |_| {
        if loaded.with(Option::is_some) {
            Phase::Ready
        } else if load_error.with(Option::is_some) {
            Phase::Failed
        } else {
            Phase::Loading
        }
    });
    // What the tabs read. `expect`: only the `Phase::Ready` body holds this
    // signal, and `loaded` is never cleared once set.
    let detail_signal: Signal<Arc<ApplicationDetail>> = Signal::derive(move || {
        loaded
            .get()
            .expect("the pane body renders only once a detail has loaded")
    });

    view! {
        <div class="app-detail" node_ref=pane_ref>
            {move || match phase.get() {
                Phase::Loading => {
                    view! {
                        <div class="app-detail__body">
                            <DetailSkeleton />
                        </div>
                    }
                        .into_any()
                }
                Phase::Failed => {
                    view! {
                        {move || {
                            load_error
                                .get()
                                .map(|err| {
                                    view! {
                                        <DetailLoadError
                                            error=err
                                            on_retry=Callback::new(move |_| {
                                                // Back to the skeleton while the retry runs.
                                                load_error.set(None);
                                                reload.update(|n| *n = n.wrapping_add(1))
                                            })
                                            class="app-detail__body".to_string()
                                        />
                                    }
                                })
                        }}
                    }
                        .into_any()
                }
                Phase::Ready => {
                    view! {
                        <div class="app-detail__body">
                            <DetailHeader
                                kind=AppKind::AppRegistration
                                title=Signal::derive(move || detail_signal.with(|d| d.application.display_name.clone()))
                                app_id=Signal::derive(move || detail_signal.with(|d| d.application.app_id.clone()))
                                on_refresh=on_refresh
                                refreshing=Signal::derive(move || reloading.get())
                                on_delete=Callback::new(move |()| delete_open.set(true))
                            >
                                {move || {
                                    // Microsoft's own "malicious" flag —
                                    // shown before the pairing link so it
                                    // is the first thing on a disabled app.
                                    detail_signal
                                        .with(|d| d.application.disabled_by_microsoft_status.clone())
                                        .filter(|s| !s.is_empty())
                                        .map(|status| {
                                            view! {
                                                <Badge
                                                    label="Disabled by Microsoft"
                                                    tone=BadgeTone::Critical
                                                    title=format!(
                                                        "Microsoft disabled this application for a Services Agreement violation ({status}); sign-ins and token issuance are blocked"
                                                    )
                                                />
                                            }
                                        })
                                }}
                                {move || {
                                    detail_signal
                                        .with(|d| d.service_principal.clone())
                                        .map(|sp| {
                                            let sp_id = sp.id.clone();
                                            let sp_name = sp.display_name.clone();
                                            let on_jump = move |_| {
                                                jump_to_paired_enterprise(session, sp_id.clone());
                                            };
                                            view! {
                                                <span class="detail-header__pairing">
                                                    "Paired with"
                                                    <TypeChip kind=AppKind::EnterpriseApp compact=true />
                                                    <button type="button" on:click=on_jump>
                                                        {sp_name}
                                                    </button>
                                                </span>
                                            }
                                        })
                                }}
                            </DetailHeader>
                            <TabBar
                                label="Application sections"
                                items={
                                    AppTab::ALL
                                        .iter()
                                        .map(|tab| TabBarItem {
                                            value: tab.value(),
                                            label: tab.label(),
                                        })
                                        .collect::<Vec<_>>()
                                }
                                selected=active_tab
                            />
                            <div class="app-detail__pane">
                                {tabs.slot(AppTab::Overview.value(), move || {
                                    view! {
                                        <OverviewTab
                                            detail=detail_signal
                                            on_changed=reload_from(AppTab::Overview)
                                        />
                                    }
                                })}
                                {tabs.slot(AppTab::Credentials.value(), move || {
                                    view! {
                                        <CredentialsTab
                                            detail=detail_signal
                                            on_changed=reload_from(AppTab::Credentials)
                                        />
                                    }
                                })}
                                {tabs.slot(AppTab::Authentication.value(), move || {
                                    view! {
                                        <AuthenticationTab
                                            detail=detail_signal
                                            on_changed=reload_from(AppTab::Authentication)
                                        />
                                    }
                                })}
                                {tabs.slot(AppTab::Owners.value(), move || {
                                    view! {
                                        <OwnersTab
                                            detail=detail_signal
                                            on_changed=reload_from(AppTab::Owners)
                                        />
                                    }
                                })}
                                {tabs.slot(AppTab::Permissions.value(), move || {
                                    view! {
                                        <PermissionsTab
                                            detail=detail_signal
                                            on_changed=reload_from(AppTab::Permissions)
                                        />
                                    }
                                })}
                                {tabs.slot(AppTab::ExposeApi.value(), move || {
                                    view! {
                                        <ExposeApiTab
                                            detail=detail_signal
                                            on_changed=reload_from(AppTab::ExposeApi)
                                        />
                                    }
                                })}
                                {tabs.slot(AppTab::ConditionalAccess.value(), move || {
                                    view! { <ConditionalAccessTab detail=detail_signal /> }
                                })}
                                {tabs.slot(AppTab::Activity.value(), move || {
                                    view! { <ActivityTab detail=detail_signal /> }
                                })}
                            </div>
                            <ConfirmDialog
                                open=Signal::derive(move || delete_open.get())
                                title="Delete this app registration?"
                                body="This deletes the app registration. Permission grants on its service principal are revoked and its credentials stop working immediately. It stays recoverable for 30 days — use Undo on the confirmation, or \"Recently deleted…\" on the App Registrations view."
                                // Several app windows can be open at once and the
                                // modal covers all of them, so it names the app it
                                // will delete instead of relying on the header it
                                // is sitting on top of.
                                subject=Signal::derive(move || detail_signal
                                    .with(|d| d.application.display_name.clone()))
                                confirm_label="Delete"
                                require_keyword="DELETE"
                                busy=Signal::derive(move || delete_cmd.busy.get())
                                error=Signal::derive(move || delete_cmd.error.get())
                                on_confirm=Callback::new(move |()| do_delete())
                                on_close=Callback::new(move |()| delete_open.set(false))
                            />
                            // Refresh rebuilds every tab from Graph, so with
                            // unsaved edits in the pane it asks first — the
                            // same question closing the item asks.
                            <ConfirmDialog
                                open=confirm_refresh
                                title="Discard unsaved changes and refresh?"
                                body="This item has edits that were not saved. Refreshing reloads it from Microsoft Entra and discards them."
                                subject=Signal::derive(move || detail_signal
                                    .with(|d| d.application.display_name.clone()))
                                confirm_label="Discard and refresh"
                                cancel_label="Keep editing"
                                on_confirm=Callback::new(move |()| {
                                    confirm_refresh.set(false);
                                    refresh_now();
                                })
                                on_close=Callback::new(move |()| confirm_refresh.set(false))
                            />
                        </div>
                    }
                        .into_any()
                }
            }}
        </div>
    }
}

/// What the pane is showing: nothing yet, a failed first load, or a detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Loading,
    Failed,
    Ready,
}

/// The delete confirmation, with an Undo that restores the app registration
/// (and its paired enterprise application) from the recycle bin — the same
/// `bulk_restore_deleted` the bulk bar's Undo and the "Recently deleted…" dialog
/// use. Session-level by design: the pane that started the delete is closed by
/// the time this shows.
fn toast_deleted_with_undo(session: Session, tenant_id: String, object_id: String, name: String) {
    let undo = move || {
        let tenant_id = tenant_id.clone();
        let object_id = object_id.clone();
        leptos::task::spawn_local(async move {
            let result = bulk::bulk_restore_deleted(&tenant_id, &[object_id]).await;
            // Switched tenant or signed out since: land nothing there.
            if !session.is_active_tenant(&tenant_id) {
                return;
            }
            match result {
                Ok(res) => {
                    let outcome = res.outcomes.first();
                    let fatal = outcome.and_then(|o| o.error.as_ref());
                    if outcome.is_some_and(|o| o.restored) {
                        session.bump_app_and_enterprise_reload();
                        match fatal {
                            None => {
                                session.toast_success("App registration restored.");
                            }
                            // The app came back but its paired SP did not —
                            // say so rather than claim a clean restore.
                            Some(e) => {
                                session.toast_error(
                                    format!(
                                        "App restored, but its enterprise app was not: {}",
                                        e.message
                                    ),
                                    None,
                                );
                            }
                        }
                    } else if let Some(e) = fatal {
                        session.report_command_error(&UiError::new(
                            e.code.clone(),
                            e.message.clone(),
                            e.retryable,
                        ));
                    } else {
                        session.toast_error("The restore did not run.", None);
                    }
                }
                Err(e) => session.report_command_error(&e),
            }
        });
    };
    session.push_toast(
        ToastKind::Success,
        format!("Deleted “{name}”. It stays recoverable for 30 days."),
        Some("Undo".to_string()),
        Some(Rc::new(undo)),
    );
}
