#![allow(clippy::unnecessary_wraps)]

//! Detail pane for a selected enterprise application service principal.
//! Header strip + tab list (Overview, Credentials, Owners, Permissions) with
//! per-tab content. Mirrors the App Registrations detail pane structure.

use std::sync::Arc;

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{
    Body1, Button, ButtonAppearance, Card, Field, Input, Spinner, SpinnerSize, Tab, TabList,
    Textarea,
};

use crate::bindings::applications;
use crate::bindings::auth;
use crate::bindings::enterprise_application::{self, EnterpriseApplicationDetail};
use crate::bindings::sso::{self, OidcSsoSummary, SamlSsoSummary, SsoConfigDto};
use crate::components::claims_editor::{ClaimsEditor, ClaimsEditorState};
use crate::components::detail_header::DetailHeader;
use crate::components::requires_role::RequiresRole;
use crate::components::sso_summary::{OidcSummaryView, SamlSummaryView};
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{DataTable, DetailLoadError, DetailSkeleton};
use crate::hooks::use_command::use_command;
use crate::hooks::use_debounced::use_debounced;
use crate::state::{OpenItemKind, use_session};
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::pairing::jump_to_paired_app;
use crate::views::tabs::EnterpriseTab;
use crate::views::tabs::activity_tab::ActivityPanel;
use crate::views::tabs::conditional_access_tab::ConditionalAccessPanel;

mod access;
mod app_roles;
mod credentials;
mod overview;
mod owners;
mod panels;
mod permissions;
mod sso_tab;

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

/// Expiry label + badge class for a credential end date. Mirrors the per-app
/// Credentials tab so enterprise-app credentials (incl. SAML signing certs) show
/// the same urgency colours.
fn cred_status(end: Option<chrono::DateTime<chrono::Utc>>) -> (String, &'static str) {
    match end {
        None => ("No expiry".to_string(), "badge"),
        Some(e) => {
            let days = (e - chrono::Utc::now()).num_days();
            if days < 0 {
                ("Expired".to_string(), "badge badge--danger")
            } else if days <= 7 {
                (format!("{days}d left"), "badge badge--danger")
            } else if days <= 30 {
                (format!("{days}d left"), "badge badge--warning")
            } else {
                (format!("{days}d left"), "badge badge--ok")
            }
        }
    }
}

fn fmt_date(d: Option<chrono::DateTime<chrono::Utc>>) -> String {
    d.map(|d| d.date_naive().to_string())
        .unwrap_or_else(|| "—".to_string())
}

#[component]
pub fn EnterpriseApplicationDetailPane(
    #[prop(into)] service_principal_id: Signal<String>,
    // Reports the resolved display name to the dock chip once the detail loads
    // (the workspace passes a setter). `None` for standalone uses.
    #[prop(optional)] on_title: Option<Callback<String>>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // Bumped by the detail-pane Refresh button to re-fetch. The enterprise
    // detail is not server-cached, so re-running the resource is enough — no
    // cache bust needed (unlike the App Registrations pane). The Suspense
    // fallback covers the re-fetch, so no separate busy flag is needed.
    let reload = RwSignal::new(0_u32);

    let detail = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = service_principal_id.get();
        let _ = reload.get();
        async move {
            if let Some(t) = tenant {
                enterprise_application::get_enterprise_application_detail(&t.tenant_id, &id).await
            } else {
                Err(azapptoolkit_dto::UiError {
                    code: "no_tenant".into(),
                    message: "tenant missing".into(),
                    retryable: false,
                })
            }
        }
    });

    let on_refresh = Callback::new(move |()| reload.update(|n| *n += 1));

    view! {
        <Card class="app-detail">
            <Suspense fallback=move || {
                view! {
                    <div class="app-detail__body">
                        <DetailSkeleton />
                    </div>
                }
            }>
                {move || Suspend::new(async move {
                    match detail.await {
                        Ok(d) => {
                            if let Some(cb) = on_title {
                                cb.run(d.service_principal.display_name.clone());
                            }
                            // Derive the child's signal from the resolved value — do
                            // NOT write a container signal here. A signal write inside
                            // this Suspend render fed back into the scope and looped
                            // (the pane refetched forever, then froze); the App
                            // Registrations pane derives the same way.
                            //
                            // Wrap in `Arc` first so the (non-memoized) derive clones a
                            // refcount, not the whole detail struct, on every tab read.
                            let d = std::sync::Arc::new(d);
                            let detail_signal = Signal::derive(move || d.clone());
                            view! {
                                <EnterpriseAppPanel
                                    detail_signal=detail_signal
                                    on_refresh=on_refresh
                                />
                            }
                                .into_any()
                        }
                        Err(err) => {
                            view! { <DetailLoadError error=err reload=reload /> }.into_any()
                        }
                    }
                })}
            </Suspense>
        </Card>
    }
}

#[component]
fn EnterpriseAppPanel(
    detail_signal: Signal<Arc<EnterpriseApplicationDetail>>,
    #[prop(into)] on_refresh: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    // Restore the last-viewed tab so it survives switching between enterprise
    // apps, and persist changes. The former merged "Insights" tab was split back
    // into separate Conditional Access + Activity tabs; clamp a stale persisted
    // "insights" value so it doesn't fall through to the "Unknown tab" arm.
    // A deep-link (e.g. a consent-grant "Open") sets `pending_enterprise_tab`
    // and overrides the restored last-tab; consume it once so it doesn't pin
    // every later visit.
    let restored = session
        .tenant_ui
        .pending_enterprise_tab
        .get_untracked()
        .unwrap_or_else(|| session.last_enterprise_tab.get_untracked());
    session.tenant_ui.pending_enterprise_tab.set(None);
    // Clamp a stale persisted/deep-linked value to a live tab (e.g. the former
    // merged "insights" → Conditional Access) via the typed enum.
    let active_tab = RwSignal::new(EnterpriseTab::from_str(&restored).value().to_string());
    Effect::new(move |_| session.last_enterprise_tab.set(active_tab.get()));

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
            match enterprise_application::delete_enterprise_application(&t.tenant_id, &id).await {
                Ok(()) => {
                    delete_open.set(false);
                    session.close_item_by_entity(OpenItemKind::Enterprise, &id);
                    session.enterprise_apps_reload.update(|n| *n += 1);
                    session.toast_success("Enterprise application deleted.");
                }
                Err(e) => delete_error.set(Some(e.message)),
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
                on_delete=Callback::new(move |()| delete_open.set(true))
            >
                {move || {
                    ro_signal
                        .with(|d| d.service_principal.is_foreign_tenant)
                        .then(|| view! { <span class="badge badge--warning">"Foreign tenant"</span> })
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
            <TabList selected_value=active_tab>
                {EnterpriseTab::ALL
                    .iter()
                    .map(|t| view! { <Tab value=t.value()>{t.label()}</Tab> })
                    .collect_view()}
            </TabList>
            <div class="app-detail__pane">
                {move || match EnterpriseTab::from_str(&active_tab.get()) {
                    EnterpriseTab::Overview => {
                        view! { <OverviewContent signal=ro_signal /> }.into_any()
                    }
                    EnterpriseTab::Sso => view! { <SsoContent signal=ro_signal /> }.into_any(),
                    EnterpriseTab::Credentials => {
                        view! { <CredentialsContent signal=ro_signal /> }.into_any()
                    }
                    EnterpriseTab::Owners => {
                        view! { <OwnersContent signal=ro_signal on_refresh=on_refresh /> }
                            .into_any()
                    }
                    EnterpriseTab::Permissions => {
                        view! { <PermissionsContent signal=ro_signal /> }.into_any()
                    }
                    EnterpriseTab::AppRoles => {
                        view! { <AppRolesContent signal=ro_signal on_refresh=on_refresh /> }
                            .into_any()
                    }
                    EnterpriseTab::Access => view! { <AccessContent signal=ro_signal /> }.into_any(),
                    EnterpriseTab::Provisioning => {
                        view! { <ProvisioningContent signal=ro_signal /> }.into_any()
                    }
                    EnterpriseTab::ConditionalAccess => {
                        view! { <CaContent signal=ro_signal /> }.into_any()
                    }
                    EnterpriseTab::Activity => {
                        view! { <ActivityContent signal=ro_signal /> }.into_any()
                    }
                }}
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
                view! {
                    <ConfirmDialog
                        open=Signal::derive(move || delete_open.get())
                        title="Delete this enterprise application?"
                        body=body
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
