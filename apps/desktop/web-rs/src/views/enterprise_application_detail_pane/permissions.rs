use super::*;
use crate::bindings::exchange as exchange_bindings;
use crate::bindings::graph_roles;
use crate::bindings::permissions as permissions_bindings;
use crate::components::exchange_scoping_section::{ExchangeScopeTarget, ExchangeScopingSection};
use crate::components::held_permissions_panel::HeldPermissionsPanel;
use crate::components::permission_picker::PickerSelection;
use crate::components::scope_badge::{is_exchange_scopable, is_sharepoint_orgwide};
use crate::components::scope_unavailable_banner::ScopeUnavailableBanner;
use crate::components::scope_wizard::{ScopeTarget, ScopeWizard};
use crate::components::sharepoint_sites_section::SharePointSitesSection;
use crate::hooks::use_command::use_command;
use azapptoolkit_core::audit::MailPermissionScope;
use std::collections::HashMap;

#[component]
pub(super) fn PermissionsContent(
    signal: Signal<Arc<EnterpriseApplicationDetail>>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let sp_id = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));
    let app_id = Signal::derive(move || signal.with(|d| d.service_principal.app_id.clone()));

    // Bumped after a revoke (or a consent/retry on the scope banner) to refresh.
    let reload = RwSignal::new(0_u32);
    let revoke_cmd = use_command();

    // What the service principal has been **granted** (the permissions it
    // HOLDS), fetched live. This is the same held-permission view the app-reg
    // and managed-identity details show — so an enterprise app finally surfaces
    // its own privilege + over-privilege risk, instead of only the roles it
    // EXPOSES (rendered below).
    let granted = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = sp_id.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => graph_roles::list_held_app_role_grants(&t.tenant_id, &id).await,
                None => Ok(Vec::new()),
            }
        }
    });

    // Effective Exchange mailbox scoping for this SP's mail permissions, resolved
    // by app id (no manifest needed — an enterprise app's SP is a service
    // principal like a managed identity). Awaits `granted` to know which values
    // are mail-scopable, so it reuses that fetch. A genuine 403/consent failure
    // surfaces via the shared banner; otherwise the empty map paints cells
    // accurately. Empty when the SP holds no scopable mail permission.
    let mail_scopes = LocalResource::new(move || {
        let tenant = tenant.get();
        let app = app_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Ok(HashMap::<String, MailPermissionScope>::new());
            };
            let mail_values: Vec<String> = granted
                .await
                .unwrap_or_default()
                .iter()
                .filter_map(|p| p.app_role_value.clone())
                .filter(|v| is_exchange_scopable(v))
                .collect();
            if mail_values.is_empty() {
                return Ok(HashMap::new());
            }
            exchange_bindings::get_mail_scopes_for_principal(&t.tenant_id, &app, &mail_values)
                .await
                .map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| (e.graph_permission, e.scope))
                        .collect()
                })
        }
    });

    // Revoke a held app-role grant — the same generic delete the managed-identity
    // view uses (an enterprise app's SP is a service principal too). Staged behind
    // a confirmation dialog (parity with the managed-identity pane, which gates the
    // identical action): the panel's revoke icon sets `pending_revoke`, and
    // confirming runs `do_revoke`. On success clear the selection and re-fetch.
    let pending_revoke: RwSignal<Option<String>> = RwSignal::new(None);
    let do_revoke = move |assignment_id: String| {
        let id = sp_id.get();
        revoke_cmd.run(
            move |()| {
                pending_revoke.set(None);
                reload.update(|n| *n += 1);
            },
            move |tenant_id| async move {
                permissions_bindings::revoke_app_role_assignment(&tenant_id, &id, &assignment_id)
                    .await
            },
        );
    };
    let on_revoke = Callback::new(move |assignment_id: String| {
        revoke_cmd.error.set(None);
        pending_revoke.set(Some(assignment_id));
    });

    let display_name =
        Signal::derive(move || signal.with(|d| d.service_principal.display_name.clone()));

    // The unified "Grant access" wizard — always reachable, so a bare SP can be
    // granted/scoped from the start (the Exchange section below only appears once
    // the SP already holds a mail permission). A row's "Scope…" opens it
    // pre-selected to that permission (`wizard_preseed`); the header button opens
    // it blank.
    let wizard_open = RwSignal::new(false);
    let wizard_preseed: RwSignal<Option<PickerSelection>> = RwSignal::new(None);
    let wizard_target = Signal::derive(move || ScopeTarget {
        object_id: None,
        sp_object_id: sp_id.get(),
        app_id: app_id.get(),
        display_name: display_name.get(),
        is_managed_identity: false,
    });

    let on_scope = Callback::new(move |sel: PickerSelection| {
        wizard_preseed.set(Some(sel));
        wizard_open.set(true);
    });

    // App-role *definitions* this app exposes are managed on the dedicated
    // "App roles" tab (add/edit/enable/delete); this tab keeps the held
    // permissions + the delegated scopes the app publishes.
    let scopes = signal.with(|d| d.service_principal.oauth2_permission_scopes.clone());

    let scopes_view = view! {
        <DataTable
            headers=vec!["Scope", "Admin consent name", "Type"]
            rows=scopes
            empty_message="No delegated permission scopes exposed."
            row=move |s: azapptoolkit_core::models::OAuth2PermissionScope| {
                view! {
                    <tr>
                        <td class="mono">{s.value.clone()}</td>
                        <td>
                            {s.admin_consent_display_name.clone().unwrap_or_else(|| "—".into())}
                        </td>
                        <td>{s.r#type.clone().unwrap_or_else(|| "—".into())}</td>
                    </tr>
                }
                    .into_any()
            }
        />
    };

    view! {
        <section>
            <header class="row-between">
                <h4>"Granted permissions"</h4>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| wizard_open.set(true))
                >
                    "Grant access"
                </Button>
            </header>
            <p class="muted">
                "Application permissions this app has been granted — what it can do as a client."
            </p>
            <ScopeWizard
                open=wizard_open
                target=wizard_target
                preseed=wizard_preseed
                on_close=Callback::new(move |()| {
                    wizard_open.set(false);
                    wizard_preseed.set(None);
                })
                on_changed=Callback::new(move |()| reload.update(|n| *n += 1))
            />
            <Suspense fallback=move || {
                view! {
                    <div class="centered-pad">
                        <Spinner
                            size=Signal::derive(|| SpinnerSize::Tiny)
                            label="Loading granted permissions…"
                        />
                    </div>
                }
            }>
                {move || Suspend::new(async move {
                    match granted.await {
                        Err(e) => {
                            view! { <Body1 class="form-error">{e.message}</Body1> }.into_any()
                        }
                        Ok(list) => {
                            // Same held-permission table as the managed-identity view
                            // (both are service principals): risk badges, the effective
                            // mailbox-scope column, and per-row revoke. A genuine
                            // 403/consent gap resolving scopes drives the shared banner.
                            let scope_result = mail_scopes.await;
                            let scope_error = scope_result.as_ref().err().cloned();
                            let scope_map = scope_result.unwrap_or_default();
                            let scope_banner = scope_error.map(|e| {
                                view! {
                                    <ScopeUnavailableBanner
                                        error=e
                                        on_retry=Callback::new(move |()| reload.update(|n| *n += 1))
                                    />
                                }
                            });
                            // Same Exchange/SharePoint scoping sections the app-reg
                            // Permissions tab hosts, keyed off the *held* grants (an
                            // SP has no manifest). The local `reload` bump refetches
                            // the held list + scope verdicts after a coarse grant.
                            let mail_values: Vec<String> = list
                                .iter()
                                .filter_map(|p| p.app_role_value.clone())
                                .filter(|v| is_exchange_scopable(v))
                                .collect();
                            let has_sites = list.iter().any(|p| {
                                p.app_role_value
                                    .as_deref()
                                    .is_some_and(|v| {
                                        v == "Sites.Selected" || is_sharepoint_orgwide(v)
                                    })
                            });
                            let exchange_section = (!mail_values.is_empty()).then(|| {
                                view! {
                                    <ExchangeScopingSection
                                        app_id=app_id
                                        target=Signal::derive(move || {
                                            ExchangeScopeTarget::ServicePrincipal {
                                                sp_object_id: sp_id.get(),
                                                display_name: display_name.get(),
                                                mail_permissions: mail_values.clone(),
                                                is_managed_identity: false,
                                            }
                                        })
                                        on_changed=Callback::new(move |()| {
                                            reload.update(|n| *n += 1)
                                        })
                                    />
                                }
                            });
                            let sharepoint_section = has_sites.then(|| {
                                view! {
                                    <SharePointSitesSection
                                        app_id=app_id
                                        app_display_name=display_name
                                    />
                                }
                            });
                            view! {
                                {scope_banner}
                                <HeldPermissionsPanel
                                    permissions=list
                                    scope_map=scope_map
                                    show_scope_column=true
                                    on_revoke=on_revoke
                                    on_scope=on_scope
                                    busy=Signal::derive(move || revoke_cmd.busy.get())
                                />
                                {exchange_section}
                                {sharepoint_section}
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
            <ConfirmDialog
                open=Signal::derive(move || pending_revoke.with(|p| p.is_some()))
                title="Revoke permission?"
                body="Remove this app's held app-role assignment. The app loses that permission until it's granted again; the live grant is re-checked before removal."
                confirm_label="Revoke"
                busy=revoke_cmd.busy
                error=revoke_cmd.error
                on_confirm=Callback::new(move |()| {
                    if let Some(aid) = pending_revoke.get() {
                        do_revoke(aid);
                    }
                })
                on_close=Callback::new(move |()| {
                    pending_revoke.set(None);
                    revoke_cmd.error.set(None);
                })
            />
            <h4>"Delegated scopes exposed"</h4>
            <p class="muted">
                "Delegated scopes this app publishes for users and clients to consent to."
            </p>
            {scopes_view}
        </section>
    }
    .into_any()
}
