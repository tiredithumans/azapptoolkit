//! Self-contained managed-identity detail window for the open-items workspace.
//! Keyed off a single `mi_id`, it owns everything `ManagedIdentitiesView` used
//! to own for the selected identity — the resources (the MI itself, held
//! permissions, mail scoping, Azure RBAC roles) and the grant/revoke/refresh
//! state — so multiple identities can be open at once, independently. Mirrors
//! the self-contained App Registration / Enterprise Application detail panes;
//! `ManagedIdentityDetailPane` stays a pure presenter that this window feeds.

use std::collections::HashMap;

use leptos::prelude::*;
use thaw::{Spinner, SpinnerSize};

use azapptoolkit_core::audit::MailPermissionScope;

use crate::bindings::diagnostics::{self, ListCacheKindDto};
use crate::bindings::exchange as exchange_bindings;
use crate::bindings::graph_roles;
use crate::bindings::managed_identity;
use crate::bindings::permissions as permissions_bindings;
use crate::components::icon::IconName;
use crate::components::scope_badge::is_exchange_scopable;
use crate::components::ui::EmptyState;
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::managed_identity_detail_pane::ManagedIdentityDetailPane;

#[component]
pub fn ManagedIdentityDetailWindow(
    #[prop(into)] mi_id: Signal<String>,
    // Reports the resolved display name to the dock chip once the identity
    // resolves (the workspace passes a setter). `None` for standalone uses.
    #[prop(optional)] on_title: Option<Callback<String>>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // One shared command runner for every grant/revoke/scope mutation (only one
    // runs at a time; one busy + error surface), mirroring the old parent view.
    let cmd = use_command();
    let pending_revoke: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    // Bumped after a grant/revoke (and by Refresh) to re-read the held list, the
    // mail scoping, and the identity header. Azure roles ride `arm_reload` since
    // grants don't change them.
    let reload = RwSignal::new(0_u32);
    let arm_reload = RwSignal::new(0_u32);
    let consenting = RwSignal::new(false);
    let consent_error: RwSignal<Option<String>> = RwSignal::new(None);
    let refreshing = RwSignal::new(false);

    // Resolve this window's identity from the (server-cached) list — the same
    // lookup the old parent did, so it's a cache hit. Depends on `reload` so the
    // header status/subtype refresh after a Refresh busts the list cache.
    let mi_resource = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = mi_id.get();
        let _ = reload.get();
        async move {
            let t = tenant?;
            managed_identity::list_managed_identities(&t.tenant_id)
                .await
                .ok()
                .and_then(|list| list.into_iter().find(|m| m.id == id))
        }
    });

    let permissions = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = mi_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            graph_roles::list_held_app_role_grants(&t.tenant_id, &id).await
        }
    });

    // Effective Exchange mailbox scoping for this identity's mail permissions.
    // Resolves the identity's `app_id` from the cached list (keyed on `mi_id`),
    // then the held mail values; empty when it holds no scopable mail permission.
    // Its own resource so the non-Send binding runs on the local executor.
    let mail_scopes = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = mi_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Ok(HashMap::<String, MailPermissionScope>::new());
            };
            let app_id = managed_identity::list_managed_identities(&t.tenant_id)
                .await
                .ok()
                .and_then(|list| list.into_iter().find(|m| m.id == id).map(|m| m.app_id));
            let Some(app_id) = app_id else {
                return Ok(HashMap::new());
            };
            let mail_values: Vec<String> = permissions
                .await
                .unwrap_or_default()
                .iter()
                .filter_map(|p| p.app_role_value.clone())
                .filter(|v| is_exchange_scopable(v))
                .collect();
            if mail_values.is_empty() {
                return Ok(HashMap::new());
            }
            exchange_bindings::get_mail_scopes_for_principal(&t.tenant_id, &app_id, &mail_values)
                .await
                .map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| (e.graph_permission, e.scope))
                        .collect()
                })
        }
    });

    // Azure RBAC roles (via ARM) — independent of `reload` (grants don't change
    // Azure roles); refetches on `arm_reload` after interactive ARM consent.
    let azure_roles = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = mi_id.get();
        let _ = arm_reload.get();
        async move {
            let Some(t) = tenant else {
                return Ok(managed_identity::AzureRolesResult::default());
            };
            managed_identity::list_managed_identity_azure_roles(&t.tenant_id, &id).await
        }
    });

    let do_revoke = move |assignment_id: String, sp_id: String| {
        cmd.run(
            move |()| {
                reload.update(|n| *n += 1);
                pending_revoke.set(None);
            },
            move |tenant_id| async move {
                permissions_bindings::revoke_app_role_assignment(&tenant_id, &sp_id, &assignment_id)
                    .await
            },
        );
    };

    // Refresh: bust the (cached) identity list — which backs the header's
    // status/subtype — then re-read the held permissions, scoping, and Azure
    // roles. Captures only Copy signals, so it stays Copy across re-renders.
    let on_refresh_detail = move |_| {
        if refreshing.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        refreshing.set(true);
        leptos::task::spawn_local(async move {
            diagnostics::invalidate_list_cache(
                t.tenant_id.clone(),
                ListCacheKindDto::ManagedIdentities,
            )
            .await;
            reload.update(|n| *n += 1);
            arm_reload.update(|n| *n += 1);
            refreshing.set(false);
        });
    };

    view! {
        <ConfirmDialog
            open=Signal::derive(move || pending_revoke.with(|p| p.is_some()))
            title="Revoke permission?"
            body="Remove this managed identity's held app-role assignment. The identity loses that permission until it's granted again; the live grant is re-checked before removal."
            confirm_label="Revoke"
            busy=cmd.busy
            error=cmd.error
            on_confirm=Callback::new(move |()| {
                if let Some((aid, sp)) = pending_revoke.get() {
                    do_revoke(aid, sp);
                }
            })
            on_close=Callback::new(move |()| {
                pending_revoke.set(None);
                cmd.error.set(None);
            })
        />
        <div class="mi-window">
            <Suspense fallback=move || {
                view! {
                    <div class="centered-pad">
                        <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" />
                    </div>
                }
            }>
                {move || Suspend::new(async move {
                    match mi_resource.await {
                        None => {
                            view! {
                                <EmptyState
                                    icon=IconName::Server
                                    title="Identity not found".to_string()
                                    body="This managed identity is no longer in the tenant — it may have been deleted."
                                        .to_string()
                                />
                            }
                                .into_any()
                        }
                        Some(mi) => {
                            if let Some(cb) = on_title {
                                cb.run(mi.display_name.clone());
                            }
                            view! {
                                <ManagedIdentityDetailPane
                                    mi=mi
                                    permissions=permissions
                                    mail_scopes=mail_scopes
                                    azure_roles=azure_roles
                                    busy=cmd.busy
                                    refreshing=refreshing
                                    consenting=consenting
                                    consent_error=consent_error
                                    reload=reload
                                    arm_reload=arm_reload
                                    tenant=tenant
                                    principal_id=Signal::derive(move || Some(mi_id.get()))
                                    on_revoke=Callback::new(move |(aid, sp): (String, String)| {
                                        cmd.error.set(None);
                                        pending_revoke.set(Some((aid, sp)));
                                    })
                                    on_refresh=Callback::new(move |()| on_refresh_detail(()))
                                />
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}
