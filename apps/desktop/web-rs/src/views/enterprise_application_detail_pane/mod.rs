#![allow(clippy::unnecessary_wraps)]

//! Detail pane for a selected enterprise application service principal: header
//! strip, then the tab bar (the tab list is `views::tabs::EnterpriseTab::ALL`)
//! with per-tab content. Mirrors the App Registrations detail pane structure.

use std::collections::HashSet;
use std::sync::Arc;

use azapptoolkit_core::models::DirectoryObject;
use azapptoolkit_dto::UiError;
use leptos::html;
use leptos::prelude::*;
use thaw::{Button, ButtonAppearance, Field, Input, Textarea};

use crate::bindings::auth;
use crate::bindings::enterprise_application::{self, EnterpriseApplicationDetail};
use crate::bindings::sso::{self, SsoConfigDto, SsoMode, SsoSummary};
use crate::components::claims_editor::{ClaimsEditor, ClaimsEditorState};
use crate::components::detail_header::DetailHeader;
use crate::components::directory_search::{DirectoryScope, DirectorySearch};
use crate::components::requires_role::RequiresRole;
use crate::components::sso_summary::{OidcSummaryView, SamlSummaryView};
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{
    Badge, BadgeTone, DataTable, DetailLoadError, DetailSkeleton, SkeletonList, Spinner, TabBar,
    TabBarItem,
};
use crate::components::uri_list_editor::{UriListEditor, UriListState, redirect_uri_reason};
use crate::hooks::pane_tabs::{PaneTabs, Reload};
use crate::hooks::use_command::use_command;
use crate::hooks::use_debounced::use_debounced;
use crate::state::{OpenItemKind, use_session};
use crate::util::{fmt_date, no_tenant};
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::pairing::jump_to_paired_app;
use crate::views::tabs::EnterpriseTab;
use crate::views::tabs::activity_tab::ActivityPanel;
use crate::views::tabs::conditional_access_tab::ConditionalAccessPanel;

// `pub` for the same reason as `panels`: the GUI tests mount the Access tab
// directly to drive its failed-load Retry.
pub mod access;
mod app_roles;
mod credentials;
mod overview;
mod owners;
// `pub` for the same reason as `sso_tab`: the GUI tests mount the Provisioning
// tab directly to drive its consent round trip.
pub mod panels;
mod permissions;
// `pub` so the GUI tests can mount the SSO tab (and its rollover panel)
// directly, the same way `AuthenticationTab` is mounted — driving the pane to a
// non-default tab from a test needs machinery this behaviour doesn't warrant.
pub mod sso_tab;

use access::AccessContent;
use app_roles::AppRolesContent;
use credentials::CredentialsContent;
use overview::OverviewContent;
use owners::OwnersContent;
use panels::{ActivityContent, CaContent, ProvisioningContent};
use permissions::PermissionsContent;
use sso_tab::SsoContent;

/// Entra's "default access" app-role id (no specific role).
const DEFAULT_ACCESS_ROLE: &str = "00000000-0000-0000-0000-000000000000";

#[component]
pub fn EnterpriseApplicationDetailPane(
    #[prop(into)] service_principal_id: Signal<String>,
    // Reports the resolved display name to the dock chip once the detail loads
    // (the workspace passes a setter). `None` for standalone uses.
    #[prop(optional)] on_title: Option<Callback<String>>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // Bumped to re-fetch. The enterprise detail is not server-cached, so
    // re-running the resource is enough — no cache bust needed (unlike the App
    // Registrations pane).
    let reload = RwSignal::new(0_u32);

    // Each fetch is numbered so the effect below can tell a fresh result from
    // the previous one: the resource notifies when a refetch STARTS as well as
    // when it lands, and still holds the old value in between.
    let fetch_seq = StoredValue::new(0_u64);
    let detail = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = service_principal_id.get();
        let _ = reload.get();
        let seq = fetch_seq.get_value() + 1;
        fetch_seq.set_value(seq);
        async move {
            let result = match tenant {
                Some(t) => {
                    enterprise_application::get_enterprise_application_detail(&t.tenant_id, &id)
                        .await
                }
                None => Err(no_tenant()),
            };
            (seq, id, result)
        }
    });

    // The last detail that loaded; the panel renders from it and stays mounted
    // across a reload, so a tab's unsaved edits survive another tab's mutation
    // (`hooks::pane_tabs`, and `ApplicationDetailPane` for the same shape). It
    // is written from the effect below, never from inside a render: a signal
    // write inside the old `Suspend` body fed back into its scope and looped.
    let loaded: RwSignal<Option<Arc<EnterpriseApplicationDetail>>> = RwSignal::new(None);
    let load_error: RwSignal<Option<UiError>> = RwSignal::new(None);
    let reloading = RwSignal::new(false);

    // Restore the last-viewed tab so it survives switching between enterprise
    // apps. A deep-link (e.g. a consent-grant "Open") sets
    // `pending_enterprise_tab` and overrides it; consumed once so it doesn't
    // pin every later visit. Clamped through the typed enum, so a stale
    // persisted value (the former merged "insights") lands on a live tab.
    let restored = session
        .tenant_ui
        .pending_enterprise_tab
        .get_untracked()
        .unwrap_or_else(|| session.last_enterprise_tab.get_untracked());
    session.tenant_ui.pending_enterprise_tab.set(None);
    let tabs = PaneTabs::new(
        EnterpriseTab::from_str(&restored).value().to_string(),
        EnterpriseTab::ALL.iter().map(|tab| tab.value()),
    );
    let active_tab = tabs.active;
    Effect::new(move |_| session.last_enterprise_tab.set(active_tab.get()));

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
                    cb.run(d.service_principal.display_name.clone());
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

    // A tab's own mutation (an owner added, a role edited): refetch, rebuild
    // that tab, keep unsaved edits on the others.
    let reload_from = move |tab: EnterpriseTab| {
        Callback::new(move |()| {
            tabs.request(Reload::From(tab.value()));
            reloading.set(true);
            reload.update(|n| *n = n.wrapping_add(1));
        })
    };
    // The header's Refresh rebuilds every tab, so with unsaved edits in the
    // pane it asks first (`confirm_refresh`).
    let refresh_now = move || {
        tabs.request(Reload::DiscardAll);
        reloading.set(true);
        reload.update(|n| *n = n.wrapping_add(1));
    };
    let confirm_refresh = RwSignal::new(false);
    let on_refresh = Callback::new(move |()| {
        if tabs.any_dirty() {
            confirm_refresh.set(true);
        } else {
            refresh_now();
        }
    });

    // Memoized so the panel is built once when the first detail lands, not
    // again on every reload.
    let phase = Memo::new(move |_| {
        if loaded.with(Option::is_some) {
            Phase::Ready
        } else if load_error.with(Option::is_some) {
            Phase::Failed
        } else {
            Phase::Loading
        }
    });
    // `expect`: only the `Phase::Ready` panel holds this signal, and `loaded`
    // is never cleared once set.
    let detail_signal: Signal<Arc<EnterpriseApplicationDetail>> = Signal::derive(move || {
        loaded
            .get()
            .expect("the panel renders only once a detail has loaded")
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
                        <EnterpriseAppPanel
                            detail_signal=detail_signal
                            tabs=tabs
                            on_refresh=on_refresh
                            refreshing=Signal::derive(move || reloading.get())
                            reload_owners=reload_from(EnterpriseTab::Owners)
                            reload_app_roles=reload_from(EnterpriseTab::AppRoles)
                        />
                        // Refresh rebuilds every tab from Graph, so with unsaved
                        // edits in the pane it asks first — the same question
                        // closing the item asks.
                        <ConfirmDialog
                            open=confirm_refresh
                            title="Discard unsaved changes and refresh?"
                            body="This item has edits that were not saved. Refreshing reloads it from Microsoft Entra and discards them."
                            subject=Signal::derive(move || detail_signal
                                .with(|d| d.service_principal.display_name.clone()))
                            confirm_label="Discard and refresh"
                            cancel_label="Keep editing"
                            on_confirm=Callback::new(move |()| {
                                confirm_refresh.set(false);
                                refresh_now();
                            })
                            on_close=Callback::new(move |()| confirm_refresh.set(false))
                        />
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

#[component]
fn EnterpriseAppPanel(
    detail_signal: Signal<Arc<EnterpriseApplicationDetail>>,
    /// The pane's tab bookkeeping, owned by the pane so a reload can decide
    /// which tabs to rebuild.
    tabs: PaneTabs,
    /// The header's Refresh (asks first when a tab holds unsaved edits).
    #[prop(into)]
    on_refresh: Callback<()>,
    #[prop(into)] refreshing: Signal<bool>,
    /// The Owners and App roles tabs' "reload after my own mutation".
    #[prop(into)]
    reload_owners: Callback<()>,
    #[prop(into)] reload_app_roles: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let active_tab = tabs.active;
    // Derive a read-only signal from the RwSignal for easier access.
    let ro_signal = Signal::derive(move || detail_signal.get());

    // Deleting a service principal is destructive and has no app-reg equivalent
    // for managed identities (their lifecycle is owned by the Azure resource), so
    // this lives only on the enterprise detail. Foreign-tenant / first-party SPs
    // get a louder warning AND a typed-"DELETE" confirmation (the dangerous case);
    // an ordinary in-tenant SP uses the plain one-click confirm.
    let delete_open = RwSignal::new(false);
    let deleting = RwSignal::new(false);
    let delete_error: RwSignal<Option<String>> = RwSignal::new(None);

    let do_delete = move || {
        if deleting.get() {
            return;
        }
        deleting.set(true);
        delete_error.set(None);
        let tenant = session.active_tenant.get();
        let id = ro_signal.with(|d| d.service_principal.id.clone());
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                deleting.set(false);
                return;
            };
            let res =
                enterprise_application::delete_enterprise_application(&t.tenant_id, &id).await;
            // Sign-out mid-delete: nothing to close, and the toast would
            // surface at the next sign-in.
            if !session.is_active_tenant(&t.tenant_id) {
                deleting.set(false);
                return;
            }
            match res {
                Ok(()) => {
                    delete_open.set(false);
                    // The SSO-certificate board selects by SP id: a deleted
                    // one left there is a dangling "N selected".
                    session.deselect_object(&id);
                    session.close_item_by_entity(OpenItemKind::Enterprise, &id);
                    session.bump_enterprise_apps_reload();
                    session.toast_success("Enterprise application deleted.");
                }
                Err(e) => session.fail_inline(&e, "write", delete_error),
            }
            deleting.set(false);
        });
    };

    view! {
        <div class="app-detail__body">
            <DetailHeader
                kind=AppKind::EnterpriseApp
                title=Signal::derive(move || ro_signal.with(|d| d.service_principal.display_name.clone()))
                app_id=Signal::derive(move || ro_signal.with(|d| d.service_principal.app_id.clone()))
                on_refresh=on_refresh
                refreshing=refreshing
                on_delete=Callback::new(move |()| delete_open.set(true))
            >
                {move || {
                    // Microsoft's own "malicious" flag, ahead of the foreign
                    // badge: a disabled SP is already blocked at sign-in.
                    ro_signal
                        .with(|d| d.service_principal.disabled_by_microsoft_status.clone())
                        .filter(|s| !s.is_empty())
                        .map(|status| {
                            view! {
                                <Badge
                                    label="Disabled by Microsoft"
                                    tone=BadgeTone::Critical
                                    title=format!(
                                        "Microsoft disabled this service principal for a Services Agreement violation ({status}); sign-ins and token issuance are blocked"
                                    )
                                />
                            }
                        })
                }}
                {move || {
                    ro_signal
                        .with(|d| d.service_principal.is_foreign_tenant)
                        .then(|| view! { <Badge label="Foreign tenant" tone=BadgeTone::Warning /> })
                }}
                {move || {
                    ro_signal
                        .with(|d| d.service_principal.paired_app_registration_id.clone())
                        .map(|app_obj_id| {
                            let on_jump = move |_| {
                                jump_to_paired_app(session, app_obj_id.clone());
                            };
                            view! {
                                <span class="detail-header__pairing">
                                    "Paired with"
                                    <TypeChip kind=AppKind::AppRegistration compact=true />
                                    <button type="button" on:click=on_jump>
                                        "App Registration"
                                    </button>
                                </span>
                            }
                        })
                }}
            </DetailHeader>
            <TabBar
                label="Enterprise application sections"
                items={
                    EnterpriseTab::ALL
                        .iter()
                        .map(|t| TabBarItem { value: t.value(), label: t.label() })
                        .collect::<Vec<_>>()
                }
                selected=active_tab
            />
            <div class="app-detail__pane">
                {tabs.slot(EnterpriseTab::Overview.value(), move || {
                    view! { <OverviewContent signal=ro_signal /> }
                })}
                {tabs.slot(EnterpriseTab::Sso.value(), move || {
                    view! { <SsoContent signal=ro_signal /> }
                })}
                {tabs.slot(EnterpriseTab::Credentials.value(), move || {
                    view! { <CredentialsContent signal=ro_signal /> }
                })}
                {tabs.slot(EnterpriseTab::Owners.value(), move || {
                    view! { <OwnersContent signal=ro_signal on_refresh=reload_owners /> }
                })}
                {tabs.slot(EnterpriseTab::Permissions.value(), move || {
                    view! { <PermissionsContent signal=ro_signal /> }
                })}
                {tabs.slot(EnterpriseTab::AppRoles.value(), move || {
                    view! { <AppRolesContent signal=ro_signal on_refresh=reload_app_roles /> }
                })}
                {tabs.slot(EnterpriseTab::Access.value(), move || {
                    view! { <AccessContent signal=ro_signal /> }
                })}
                {tabs.slot(EnterpriseTab::Provisioning.value(), move || {
                    view! { <ProvisioningContent signal=ro_signal /> }
                })}
                {tabs.slot(EnterpriseTab::ConditionalAccess.value(), move || {
                    view! { <CaContent signal=ro_signal /> }
                })}
                {tabs.slot(EnterpriseTab::Activity.value(), move || {
                    view! { <ActivityContent signal=ro_signal /> }
                })}
            </div>
            {move || {
                // A foreign-tenant / first-party SP (owned outside this tenant)
                // is the dangerous deletion case — deleting it can break
                // tenant-wide sign-in or orphan consent, so warn louder.
                let foreign = ro_signal.with(|d| d.service_principal.is_foreign_tenant);
                let body = if foreign {
                    "Delete this service principal? This app is owned outside your tenant (a Microsoft first-party or a foreign-tenant app you consented to). Deleting its service principal removes it from your tenant and can break tenant-wide sign-in or orphan existing consent. Only proceed if you are certain. It can be restored from the Entra admin center within 30 days."
                } else {
                    "Delete this enterprise application's service principal? This removes the app from your tenant — sign-ins stop and its permission/consent grants are revoked immediately. It can be restored from the Entra admin center within 30 days."
                };
                // Foreign-tenant / first-party SPs are the dangerous case
                // (deleting one can break tenant-wide sign-in), so require a typed
                // "DELETE" confirmation — matching the bulk-delete guard. An
                // ordinary in-tenant SP keeps the one-click confirm.
                let require_keyword = if foreign { "DELETE" } else { "" };
                // Several detail windows can be open at once and the modal covers
                // all of them, so it names the service principal it will delete
                // rather than leaving "this enterprise application" to the header
                // underneath it.
                let subject = ro_signal.with(|d| d.service_principal.display_name.clone());
                view! {
                    <ConfirmDialog
                        open=Signal::derive(move || delete_open.get())
                        title="Delete this enterprise application?"
                        body=body
                        subject=subject
                        confirm_label="Delete"
                        require_keyword=require_keyword
                        busy=Signal::derive(move || deleting.get())
                        error=Signal::derive(move || delete_error.get())
                        on_confirm=Callback::new(move |()| do_delete())
                        on_close=Callback::new(move |()| delete_open.set(false))
                    />
                }
            }}
        </div>
    }
}
