//! Detail pane for a selected application: header (name + delete) + tab list
//! + active tab body. Mirrors
//!   `apps/desktop/web/src/views/ApplicationDetailPane.tsx`.

use leptos::prelude::*;
use thaw::{Card, Tab, TabList};

use crate::bindings::applications;
use crate::components::detail_header::DetailHeader;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::DetailSkeleton;
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::pairing::jump_to_paired_enterprise;
use crate::views::tabs::{
    activity_tab::ActivityTab, authentication_tab::AuthenticationTab,
    conditional_access_tab::ConditionalAccessTab, credentials_tab::CredentialsTab,
    expose_api_tab::ExposeApiTab, overview_tab::OverviewTab, owners_tab::OwnersTab,
    permissions_tab::PermissionsTab, AppTab,
};

#[component]
pub fn ApplicationDetailPane(#[prop(into)] object_id: Signal<String>) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // `reload` increments to force the resource to re-fetch.
    let reload = RwSignal::new(0_u32);

    let detail = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = object_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(azapptoolkit_dto::UiError {
                    code: "no_tenant".into(),
                    message: "tenant missing".into(),
                    retryable: false,
                });
            };
            applications::get_application_detail(&t.tenant_id, &id).await
        }
    });

    let bump_reload = Callback::new(move |()| reload.update(|n| *n += 1));

    // Detail-pane Refresh: bust this app's server-side detail cache, then
    // re-run the resource so it re-fetches from Graph (a plain reload would hit
    // the cache and show stale data).
    let refreshing = RwSignal::new(false);
    let on_refresh = Callback::new(move |()| {
        if refreshing.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        let id = object_id.get();
        refreshing.set(true);
        leptos::task::spawn_local(async move {
            let _ = applications::invalidate_application_detail(&t.tenant_id, &id).await;
            reload.update(|n| *n += 1);
            refreshing.set(false);
        });
    });

    // Open on the deep-link target tab if one was set (e.g. the credential
    // dashboard's "Open" action sets "credentials"); otherwise restore the
    // last-viewed tab so the workflow tab survives switching apps. The deep-link
    // is consumed once so a later in-app selection doesn't re-trigger it.
    let initial_tab = session
        .pending_app_tab
        .get_untracked()
        .unwrap_or_else(|| session.last_app_tab.get_untracked());
    session.pending_app_tab.set(None);
    // Thaw's `TabList` is string-keyed and two-way bound, so the active tab stays
    // a `String`; `AppTab` is only the bridge that clamps stale values and drives
    // the exhaustive match below.
    let active_tab = RwSignal::new(AppTab::from_str(&initial_tab).value().to_string());
    // Persist the active tab for the next app opened.
    Effect::new(move |_| session.last_app_tab.set(active_tab.get()));

    let delete_open = RwSignal::new(false);
    // `use_command` owns the busy/error signals and the double-submit guard,
    // tenant resolution, and spawn boilerplate this handler used to inline.
    let delete_cmd = use_command();

    let do_delete = move || {
        delete_cmd.run(
            move |()| {
                delete_open.set(false);
                session.set_selected_app(None);
                session.toast_success("Application deleted.");
            },
            move |tenant_id| {
                let id = object_id.get();
                async move { applications::delete_application(&tenant_id, &id).await }
            },
        );
    };

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
                            // Wrap in `Arc` so the (non-memoized) derive's per-read
                            // clone is a refcount bump, not a deep clone of the whole
                            // detail struct — every tab read of `detail_signal`
                            // otherwise deep-cloned Application + ServicePrincipal +
                            // owners + grants + resolved permissions.
                            let d = std::sync::Arc::new(d);
                            let detail_signal = Signal::derive(move || d.clone());
                            view! {
                                <div class="app-detail__body">
                                    <DetailHeader
                                        kind=AppKind::AppRegistration
                                        title=Signal::derive(move || detail_signal.with(|d| d.application.display_name.clone()))
                                        app_id=Signal::derive(move || detail_signal.with(|d| d.application.app_id.clone()))
                                        on_refresh=on_refresh
                                        refreshing=Signal::derive(move || refreshing.get())
                                        on_delete=Callback::new(move |()| delete_open.set(true))
                                    >
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
                                    <TabList selected_value=active_tab>
                                        {AppTab::ALL
                                            .iter()
                                            .map(|tab| {
                                                view! { <Tab value=tab.value()>{tab.label()}</Tab> }
                                            })
                                            .collect::<Vec<_>>()}
                                    </TabList>
                                    <div class="app-detail__pane">
                                        {move || match AppTab::from_str(&active_tab.get()) {
                                            AppTab::Overview => {
                                                view! {
                                                    <OverviewTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            AppTab::Credentials => {
                                                view! {
                                                    <CredentialsTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            AppTab::Authentication => {
                                                view! {
                                                    <AuthenticationTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            AppTab::Owners => {
                                                view! {
                                                    <OwnersTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            AppTab::Permissions => {
                                                view! {
                                                    <PermissionsTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            AppTab::ExposeApi => {
                                                view! {
                                                    <ExposeApiTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            AppTab::ConditionalAccess => {
                                                view! {
                                                    <ConditionalAccessTab detail=detail_signal />
                                                }
                                                    .into_any()
                                            }
                                            AppTab::Activity => {
                                                view! { <ActivityTab detail=detail_signal /> }.into_any()
                                            }
                                        }}
                                    </div>
                                    <ConfirmDialog
                                        open=Signal::derive(move || delete_open.get())
                                        title="Delete this app registration?"
                                        body="This removes the application. Permission grants on the service principal are revoked; any credentials become invalid immediately. Deletion can be undone from the Entra admin center within 30 days."
                                        confirm_label="Delete"
                                        busy=Signal::derive(move || delete_cmd.busy.get())
                                        error=Signal::derive(move || delete_cmd.error.get())
                                        on_confirm=Callback::new(move |()| do_delete())
                                        on_close=Callback::new(move |()| delete_open.set(false))
                                    />
                                </div>
                            }
                                .into_any()
                        }
                        Err(err) => {
                            view! {
                                <div class="app-detail__body">
                                    <span style="color: var(--tauri-accent-color);">
                                        {format!("error [{}]: {}", err.code, err.message)}
                                    </span>
                                </div>
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
        </Card>
    }
}
