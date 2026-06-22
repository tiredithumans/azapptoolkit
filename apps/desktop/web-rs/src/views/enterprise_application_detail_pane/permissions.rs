use super::*;
use crate::bindings::exchange as exchange_bindings;
use crate::bindings::graph_roles;
use crate::bindings::permissions as permissions_bindings;
use crate::bindings::sharepoint;
use crate::components::exchange_scoping_section::{ExchangeScopeTarget, ExchangeScopingSection};
use crate::components::held_permissions_panel::HeldPermissionsPanel;
use crate::components::scope_badge::{is_exchange_scopable, is_sharepoint_orgwide};
use crate::components::scope_panel::{ScopeKind, ScopePanel};
use crate::components::scope_unavailable_banner::ScopeUnavailableBanner;
use crate::components::sharepoint_sites_section::SharePointSitesSection;
use crate::hooks::use_command::use_command;
use crate::util::parse_lines;
use azapptoolkit_core::audit::MailPermissionScope;
use std::collections::HashMap;

#[component]
pub(super) fn PermissionsContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
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

    // In-place "Scope…" for an already-held org-wide permission. The enterprise
    // app's SP is a service principal like any other, so this reuses the same
    // SP-generic backend cores the managed-identity view uses (scoped Exchange
    // grant / convert-to-Sites.Selected) — confine the held permission, then the
    // org-wide grant is stripped and the held list refetches. `pending_scope`
    // holds the picked permission until the admin supplies groups / a site URL.
    let display_name =
        Signal::derive(move || signal.with(|d| d.service_principal.display_name.clone()));
    let pending_scope: RwSignal<Option<(String, ScopeKind)>> = RwSignal::new(None);
    let scope_groups_text = RwSignal::new(String::new());
    let scope_site_url = RwSignal::new(String::new());
    let scope_cmd = use_command();
    let scope_note: RwSignal<Option<String>> = RwSignal::new(None);

    let on_scope = Callback::new(move |value: String| {
        // Restrict-after-the-fact classifier: org-wide Sites.* → SharePoint. Mail
        // is excluded — Exchange RBAC scoping is app-wide, driven by the "Exchange
        // scoping" section below, not a per-row button. (This is the only call
        // site, so it lives inline.)
        let kind = is_sharepoint_orgwide(&value).then_some(ScopeKind::SharePoint);
        if let Some(kind) = kind {
            scope_groups_text.set(String::new());
            scope_site_url.set(String::new());
            scope_cmd.error.set(None);
            scope_note.set(None);
            pending_scope.set(Some((value, kind)));
        }
    });

    let cancel_scope = move || {
        pending_scope.set(None);
        scope_cmd.error.set(None);
    };

    // Retained only to satisfy the shared `ScopePanel`'s mandatory Exchange
    // callback. Now unreachable for this pane: mail no longer opens a per-row
    // scope panel (Exchange scoping is app-wide — see the "Exchange scoping"
    // section below), so `pending_scope` here is always SharePoint.
    let submit_exchange = move || {
        let Some((value, _)) = pending_scope.get() else {
            return;
        };
        if scope_cmd.busy.get() {
            return;
        }
        let groups = parse_lines(&scope_groups_text.get());
        if groups.is_empty() {
            scope_cmd.error.set(Some(
                "Enter at least one group or mailbox identifier.".into(),
            ));
            return;
        }
        scope_note.set(None);
        let (sp, app, name) = (sp_id.get(), app_id.get(), display_name.get());
        let value_for_op = value.clone();
        scope_cmd.run(
            move |r: exchange_bindings::ExchangeAccessResult| {
                scope_note.set(Some(format!(
                    "Scoped {} via “{}” — {} role(s) assigned, {} org-wide grant(s) removed.",
                    value,
                    r.scope_name,
                    r.roles_assigned.len(),
                    r.removed_entra_grants.len(),
                )));
                pending_scope.set(None);
                reload.update(|n| *n += 1);
            },
            move |tenant_id| async move {
                exchange_bindings::grant_managed_identity_scoped_exchange_access(
                    &tenant_id,
                    &sp,
                    &app,
                    &name,
                    &[value_for_op],
                    &groups,
                    true,
                )
                .await
            },
        );
    };

    let submit_sharepoint = move |role: &'static str| {
        if pending_scope.get().is_none() || scope_cmd.busy.get() {
            return;
        }
        let url = scope_site_url.get().trim().to_string();
        if url.is_empty() {
            scope_cmd
                .error
                .set(Some("Enter a SharePoint site URL.".into()));
            return;
        }
        scope_note.set(None);
        let (sp, app, name) = (sp_id.get(), app_id.get(), display_name.get());
        let url_for_op = url.clone();
        scope_cmd.run(
            move |r: sharepoint::SiteScopeResult| {
                let site = r
                    .sites_granted
                    .first()
                    .and_then(|s| s.site_display_name.clone())
                    .unwrap_or(url);
                let mut note = format!("Granted {role} access to {site}.");
                if !r.removed_orgwide_grants.is_empty() {
                    note.push_str(&format!(
                        " Removed org-wide grant(s): {}.",
                        r.removed_orgwide_grants.join(", ")
                    ));
                }
                scope_note.set(Some(note));
                pending_scope.set(None);
                reload.update(|n| *n += 1);
            },
            move |tenant_id| async move {
                sharepoint::convert_site_access_to_selected(
                    &tenant_id,
                    &sp,
                    &app,
                    &name,
                    &[url_for_op],
                    role,
                    true,
                )
                .await
            },
        );
    };

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
            <h4>"Granted permissions"</h4>
            <p class="muted">
                "Application permissions this app has been granted — what it can do as a client."
            </p>
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
            {move || {
                pending_scope
                    .get()
                    .map(|(value, kind)| {
                        view! {
                            <ScopePanel
                                kind=kind
                                permission_value=value
                                groups_text=scope_groups_text
                                site_url=scope_site_url
                                busy=Signal::derive(move || scope_cmd.busy.get())
                                on_submit_exchange=Callback::new(move |()| submit_exchange())
                                on_submit_sharepoint=Callback::new(move |w: bool| {
                                    submit_sharepoint(if w { "write" } else { "read" })
                                })
                                on_cancel=Callback::new(move |()| cancel_scope())
                            />
                        }
                    })
            }}
            {move || scope_note.get().map(|m| view! { <div class="alert alert--ok">{m}</div> })}
            {move || scope_cmd.error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
            <h4>"Delegated scopes exposed"</h4>
            <p class="muted">
                "Delegated scopes this app publishes for users and clients to consent to."
            </p>
            {scopes_view}
        </section>
    }
    .into_any()
}
