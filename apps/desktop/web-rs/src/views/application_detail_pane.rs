//! Detail pane for a selected application: header (name + delete) + tab list
//! + active tab body. Mirrors
//! `apps/desktop/web/src/views/ApplicationDetailPane.tsx`.

use leptos::prelude::*;
use thaw::{Body1, Card, Tab, TabList};

use crate::bindings::applications;
use crate::components::detail_header::DetailHeader;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::DetailSkeleton;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::pairing::jump_to_paired_enterprise;
use crate::views::tabs::{
    activity_tab::ActivityTab, authentication_tab::AuthenticationTab,
    conditional_access_tab::ConditionalAccessTab, credentials_tab::CredentialsTab,
    expose_api_tab::ExposeApiTab, overview_tab::OverviewTab, owners_tab::OwnersTab,
    permissions_tab::PermissionsTab,
};

/// Clamps stale persisted/deep-linked tab values from merged or removed tabs
/// so they don't fall through to the "Unknown tab" arm: Federated →
/// Credentials, the former merged "Insights" tab → Conditional Access
/// (Activity is its own tab again, so it stays as-is), and the former
/// Exchange/SharePoint access tabs → Permissions (now sections below the
/// permissions table).
fn normalize_app_tab(tab: &str) -> &str {
    match tab {
        "federated" => "credentials",
        "insights" => "conditionalAccess",
        "exchange" | "sharepoint" => "permissions",
        other => other,
    }
}

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
    let initial_tab = normalize_app_tab(&initial_tab).to_string();
    let active_tab = RwSignal::new(initial_tab);
    // Persist the active tab for the next app opened.
    Effect::new(move |_| session.last_app_tab.set(active_tab.get()));

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
        let id = object_id.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                deleting.set(false);
                return;
            };
            match applications::delete_application(&t.tenant_id, &id).await {
                Ok(()) => {
                    delete_open.set(false);
                    session.set_selected_app(None);
                    session.toast_success("Application deleted.");
                }
                Err(e) => delete_error.set(Some(e.message)),
            }
            deleting.set(false);
        });
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
                                        <Tab value="overview">"Overview"</Tab>
                                        <Tab value="credentials">"Credentials"</Tab>
                                        <Tab value="authentication">"Authentication"</Tab>
                                        <Tab value="owners">"Owners"</Tab>
                                        <Tab value="permissions">"Permissions"</Tab>
                                        <Tab value="exposeApi">"Expose an API"</Tab>
                                        <Tab value="conditionalAccess">"Conditional Access"</Tab>
                                        <Tab value="activity">"Activity"</Tab>
                                    </TabList>
                                    <div class="app-detail__pane">
                                        {move || match active_tab.get().as_str() {
                                            "overview" => {
                                                view! {
                                                    <OverviewTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            "credentials" => {
                                                view! {
                                                    <CredentialsTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            "authentication" => {
                                                view! {
                                                    <AuthenticationTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            "owners" => {
                                                view! {
                                                    <OwnersTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            "permissions" => {
                                                view! {
                                                    <PermissionsTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            "exposeApi" => {
                                                view! {
                                                    <ExposeApiTab detail=detail_signal on_changed=bump_reload />
                                                }
                                                    .into_any()
                                            }
                                            "conditionalAccess" => {
                                                view! {
                                                    <ConditionalAccessTab detail=detail_signal />
                                                }
                                                    .into_any()
                                            }
                                            "activity" => {
                                                view! {
                                                    <ActivityTab detail=detail_signal />
                                                }
                                                    .into_any()
                                            }
                                            _ => view! { <Body1>"Unknown tab"</Body1> }.into_any(),
                                        }}
                                    </div>
                                    <ConfirmDialog
                                        open=Signal::derive(move || delete_open.get())
                                        title="Delete this app registration?"
                                        body="This removes the application. Permission grants on the service principal are revoked; any credentials become invalid immediately. Deletion can be undone from the Entra admin center within 30 days."
                                        confirm_label="Delete"
                                        busy=Signal::derive(move || deleting.get())
                                        error=Signal::derive(move || delete_error.get())
                                        on_confirm=Callback::new(move |()| do_delete())
                                        on_close=Callback::new(move |()| delete_open.set(false))
                                    />
                                </div>
                            }
                                .into_any()
                        }
                        Err(err) => {
                            view! {
                                <Body1 class="app-detail__error">
                                    {format!("error [{}]: {}", err.code, err.message)}
                                </Body1>
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
        </Card>
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_app_tab;

    #[test]
    fn normalize_app_tab_clamps_stale_values_to_live_tabs() {
        // (persisted/deep-linked value, tab it must land on)
        let cases = [
            ("federated", "credentials"),
            ("insights", "conditionalAccess"),
            ("exchange", "permissions"),
            ("sharepoint", "permissions"),
            ("permissions", "permissions"),
            ("overview", "overview"),
        ];
        for (input, expected) in cases {
            assert_eq!(normalize_app_tab(input), expected, "for input {input:?}");
        }
    }
}
