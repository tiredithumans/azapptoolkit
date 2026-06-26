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
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::pairing::jump_to_paired_app;
use crate::views::tabs::EnterpriseTab;
use crate::views::tabs::activity_tab::ActivityPanel;
use crate::views::tabs::conditional_access_tab::ConditionalAccessPanel;

mod access;
mod app_roles;
mod permissions;
mod sso_tab;

use access::AccessContent;
use app_roles::AppRolesContent;
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
        .pending_enterprise_tab
        .get_untracked()
        .unwrap_or_else(|| session.last_enterprise_tab.get_untracked());
    session.pending_enterprise_tab.set(None);
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
                    session.set_selected_enterprise_app(None);
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

#[component]
fn OverviewContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let session = use_session();
    let sp = signal.with(|d| d.service_principal.clone());

    // My Apps portal visibility (the `HideApp` tag). Toggled optimistically so
    // the row reflects the change without re-fetching the whole detail.
    let sp_id = sp.id.clone();
    let initial_hidden = sp.tags.iter().any(|t| t == "HideApp");
    let hidden_override: RwSignal<Option<bool>> = RwSignal::new(None);
    let toggling = RwSignal::new(false);
    let toggle_visibility = move |_| {
        if toggling.get() {
            return;
        }
        let new_hidden = !hidden_override.get_untracked().unwrap_or(initial_hidden);
        toggling.set(true);
        let tenant = session.active_tenant.get();
        let sp_id = sp_id.clone();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                toggling.set(false);
                return;
            };
            match enterprise_application::set_enterprise_app_visibility(
                &t.tenant_id,
                &sp_id,
                new_hidden,
            )
            .await
            {
                Ok(()) => {
                    hidden_override.set(Some(new_hidden));
                    session.toast_success(if new_hidden {
                        "Hidden from the My Apps portal."
                    } else {
                        "Visible on the My Apps portal."
                    });
                }
                Err(e) => {
                    session.report_command_error(&e);
                }
            }
            toggling.set(false);
        });
    };

    // ---- "Enabled for users to sign in?" toggle (accountEnabled). Optimistic
    // local override (like the My Apps visibility toggle); the backend busts the
    // list caches so the list reflects it on next load. ----
    let initial_enabled = sp.account_enabled;
    let enabled_override: RwSignal<Option<bool>> = RwSignal::new(None);
    let enabled_cmd = use_command();
    let sp_id_enabled = StoredValue::new(sp.id.clone());
    let toggle_enabled = move |_| {
        let next = !enabled_override
            .get_untracked()
            .or(initial_enabled)
            .unwrap_or(true);
        enabled_cmd.run_toast_err(
            move |()| {
                enabled_override.set(Some(next));
                session.toast_success(if next {
                    "Users can sign in to this application."
                } else {
                    "Sign-in disabled — no tokens will be issued for this application."
                });
            },
            move |tenant_id| {
                let id = sp_id_enabled.get_value();
                async move {
                    enterprise_application::set_enterprise_app_account_enabled(
                        &tenant_id, &id, next,
                    )
                    .await
                }
            },
        );
    };

    // ---- "Assignment required?" toggle (appRoleAssignmentRequired). ----
    let initial_assign = sp.app_role_assignment_required;
    let assign_override: RwSignal<Option<bool>> = RwSignal::new(None);
    let assign_cmd = use_command();
    let sp_id_assign = StoredValue::new(sp.id.clone());
    let toggle_assign = move |_| {
        let next = !assign_override
            .get_untracked()
            .or(initial_assign)
            .unwrap_or(false);
        assign_cmd.run_toast_err(
            move |()| {
                assign_override.set(Some(next));
                session.toast_success(if next {
                    "Assignment now required — only assigned users/services can get a token."
                } else {
                    "Assignment no longer required."
                });
            },
            move |tenant_id| {
                let id = sp_id_assign.get_value();
                async move {
                    enterprise_application::set_enterprise_app_assignment_required(
                        &tenant_id, &id, next,
                    )
                    .await
                }
            },
        );
    };

    // ---- Free-text management notes editor. ----
    let notes_text = RwSignal::new(sp.notes.clone().unwrap_or_default());
    let notes_cmd = use_command();
    let sp_id_notes = StoredValue::new(sp.id.clone());
    let save_notes = move |_| {
        notes_cmd.run_toast_err(
            move |()| {
                session.toast_success("Notes saved.");
            },
            move |tenant_id| {
                let id = sp_id_notes.get_value();
                let n = notes_text.get_untracked();
                async move {
                    enterprise_application::set_enterprise_app_notes(&tenant_id, &id, &n).await
                }
            },
        );
    };

    let sp_type = sp
        .service_principal_type
        .clone()
        .unwrap_or_else(|| "—".to_string());
    let created = fmt_date(sp.created_date_time);
    let owner_org = sp
        .app_owner_organization_id
        .clone()
        .unwrap_or_else(|| "—".to_string());

    view! {
        <dl class="read-field">
            <dt>"Service principal id"</dt>
            <dd class="mono">{sp.id.clone()}</dd>
            <dt>"Application id"</dt>
            <dd class="mono">{sp.app_id.clone()}</dd>
            <dt>"Type"</dt>
            <dd>{sp_type}</dd>
            <dt>"Enabled for sign-in"</dt>
            <dd class="row-meta">
                {move || {
                    let eff = enabled_override.get().or(initial_enabled);
                    let (label, cls) = match eff {
                        Some(true) => ("Enabled", "badge badge--ok"),
                        Some(false) => ("Disabled", "badge badge--danger"),
                        None => ("Unknown", "badge"),
                    };
                    view! { <span class=cls>{label}</span> }
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    disabled=Signal::derive(move || enabled_cmd.busy.get())
                    on_click=Box::new(toggle_enabled)
                >
                    {move || {
                        if enabled_override.get().or(initial_enabled).unwrap_or(true) {
                            "Disable sign-in"
                        } else {
                            "Enable sign-in"
                        }
                    }}
                </Button>
            </dd>
            <dt>"Assignment required"</dt>
            <dd class="row-meta">
                {move || {
                    let eff = assign_override.get().or(initial_assign);
                    let (label, cls) = match eff {
                        Some(true) => ("Required", "badge badge--ok"),
                        Some(false) => ("Not required", "badge badge--warning"),
                        None => ("Unknown", "badge"),
                    };
                    view! { <span class=cls>{label}</span> }
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    disabled=Signal::derive(move || assign_cmd.busy.get())
                    on_click=Box::new(toggle_assign)
                >
                    {move || {
                        if assign_override.get().or(initial_assign).unwrap_or(false) {
                            "Make optional"
                        } else {
                            "Require assignment"
                        }
                    }}
                </Button>
            </dd>
            <dt>"Created"</dt>
            <dd>{created}</dd>
            <dt>"Owner tenant"</dt>
            <dd class="mono">{owner_org}</dd>
            <dt>"My Apps visibility"</dt>
            <dd class="row-meta">
                {move || {
                    let hidden = hidden_override.get().unwrap_or(initial_hidden);
                    let (label, cls) = if hidden {
                        ("Hidden", "badge badge--warning")
                    } else {
                        ("Visible", "badge badge--ok")
                    };
                    view! { <span class=cls>{label}</span> }
                }}
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Subtle)
                    disabled=Signal::derive(move || toggling.get())
                    on_click=Box::new(toggle_visibility)
                >
                    {move || {
                        if hidden_override.get().unwrap_or(initial_hidden) {
                            "Show on My Apps"
                        } else {
                            "Hide from My Apps"
                        }
                    }}
                </Button>
            </dd>
        </dl>
        <h4>"Notes"</h4>
        <Field label="Management notes (max 1024 characters)">
            <Textarea value=notes_text />
        </Field>
        <Button
            appearance=Signal::derive(|| ButtonAppearance::Primary)
            disabled=Signal::derive(move || notes_cmd.busy.get())
            on_click=Box::new(save_notes)
        >
            "Save notes"
        </Button>
    }
}

#[component]
fn CredentialsContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let secrets = signal.with(|d| d.service_principal.password_credentials.clone());
    let certs = signal.with(|d| d.service_principal.key_credentials.clone());

    let secrets_view = view! {
        <DataTable
            headers=vec!["Description", "Expires", "Status"]
            rows=secrets
            empty_message="No client secrets."
            row=|s: azapptoolkit_core::models::PasswordCredential| {
                let (label, cls) = cred_status(s.end_date_time);
                view! {
                    <tr>
                        <td>{s.display_name.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{fmt_date(s.end_date_time)}</td>
                        <td>
                            <span class=cls>{label}</span>
                        </td>
                    </tr>
                }
                    .into_any()
            }
        />
    };

    let certs_view = view! {
        <DataTable
            headers=vec!["Name", "Usage", "Expires", "Status"]
            rows=certs
            empty_message="No certificates."
            row=|c: azapptoolkit_core::models::KeyCredential| {
                let (label, cls) = cred_status(c.end_date_time);
                view! {
                    <tr>
                        <td>{c.display_name.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{c.usage.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{fmt_date(c.end_date_time)}</td>
                        <td>
                            <span class=cls>{label}</span>
                        </td>
                    </tr>
                }
                    .into_any()
            }
        />
    };

    view! {
        <section class="ent-creds">
            <h4>"Client secrets"</h4>
            {secrets_view}
            <h4>"Certificates"</h4>
            <Body1 class="mi-view__intro">
                "For SAML single sign-on apps these are the token-signing certificates — watch the expiry to avoid SSO outages."
            </Body1>
            {certs_view}
        </section>
    }
    .into_any()
}

/// Owners tab — lists current owners and lets you add/remove them. Only **users**
/// can own a service principal (Graph rejects groups), so the search targets
/// users only. An owner can manage this app's SSO, provisioning, and user
/// assignments. Mutations bump the detail `on_refresh` so the owners list
/// refetches.
#[component]
fn OwnersContent(
    signal: Signal<Arc<EnterpriseApplicationDetail>>,
    #[prop(into)] on_refresh: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let sp_id = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));

    // The principal id currently being added/removed (drives per-row disabling).
    let busy: RwSignal<Option<String>> = RwSignal::new(None);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 300);
    let pending_remove: RwSignal<Option<String>> = RwSignal::new(None);

    let candidates = LocalResource::new(move || {
        let q = query.get();
        let tenant = tenant.get();
        async move {
            let q = q.trim().to_string();
            if q.len() < 2 {
                return Ok::<Vec<DirectoryObject>, String>(Vec::new());
            }
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            applications::search_users(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
        }
    });

    let mutate = move |add: bool, principal_id: String| {
        if busy.get().is_some() {
            return;
        }
        busy.set(Some(principal_id.clone()));
        error.set(None);
        let tenant = tenant.get();
        let sp = sp_id.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(None);
                return;
            };
            let result = if add {
                enterprise_application::add_enterprise_app_owner(&t.tenant_id, &sp, &principal_id)
                    .await
            } else {
                enterprise_application::remove_enterprise_app_owner(
                    &t.tenant_id,
                    &sp,
                    &principal_id,
                )
                .await
            };
            match result {
                Ok(()) => {
                    session.toast_success(if add {
                        "Owner added."
                    } else {
                        "Owner removed."
                    });
                    // Reloads the detail (refetches owners) and tears this
                    // component down — do it last and skip resetting `busy`.
                    on_refresh.run(());
                }
                Err(e) => {
                    error.set(Some(e.message));
                    busy.set(None);
                }
            }
        });
    };

    view! {
        <div class="ent-owners">
            {move || {
                let owners = signal.with(|d| d.owners.clone());
                let empty = owners.is_empty();
                view! {
                    <h4>"Owners (" {owners.len()} ")"</h4>
                    {empty
                        .then(|| {
                            view! {
                                <div class="alert alert--warn">
                                    "No owners assigned — no one is accountable for this enterprise application. Only Application Administrators can manage it."
                                </div>
                            }
                        })}
                    <ul class="candidates">
                        {owners
                            .into_iter()
                            .map(|o| {
                                let name = o.display_name.clone().unwrap_or_else(|| o.id.clone());
                                let sub = o
                                    .user_principal_name
                                    .clone()
                                    .unwrap_or_else(|| o.id.clone());
                                let id_click = o.id.clone();
                                let id_busy = o.id.clone();
                                view! {
                                    <li>
                                        <div>
                                            <div>{name}</div>
                                            <div class="mono small">{sub}</div>
                                        </div>
                                        <Button
                                            class="button--danger"
                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                            disabled=Signal::derive(move || {
                                                busy.with(|b| b.as_deref() == Some(id_busy.as_str()))
                                            })
                                            on_click=Box::new(move |_| {
                                                pending_remove.set(Some(id_click.clone()))
                                            })
                                        >
                                            "Remove"
                                        </Button>
                                    </li>
                                }
                            })
                            .collect_view()}
                    </ul>
                }
            }}

            <h4>"Add an owner"</h4>
            <p class="muted">
                "Only users can own a service principal. An owner can manage this app's single sign-on, provisioning, and user assignments."
            </p>
            <Field label="Search users by name or UPN (2+ chars)">
                <Input value=raw_query placeholder="alice@contoso.com" />
            </Field>
            {move || {
                if raw_query.get().trim().len() < 2 {
                    return ().into_any();
                }
                view! {
                    <Suspense fallback=move || {
                        view! {
                            <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Searching…" />
                        }
                    }>
                        {move || Suspend::new(async move {
                            match candidates.await {
                                Err(msg) => {
                                    view! {
                                        <Body1 class="app-detail__error">
                                            {format!("Search failed: {msg}")}
                                        </Body1>
                                    }
                                        .into_any()
                                }
                                Ok(users) => {
                                    let existing: std::collections::HashSet<String> = signal
                                        .with_untracked(|d| {
                                            d.owners.iter().map(|o| o.id.clone()).collect()
                                        });
                                    let filtered: Vec<DirectoryObject> = users
                                        .into_iter()
                                        .filter(|u| !existing.contains(&u.id))
                                        .collect();
                                    if filtered.is_empty() {
                                        return view! { <Body1>"No matches."</Body1> }.into_any();
                                    }
                                    view! {
                                        <ul class="candidates">
                                            {filtered
                                                .into_iter()
                                                .map(|u| {
                                                    let id_click = u.id.clone();
                                                    let id_busy = u.id.clone();
                                                    let display = u
                                                        .display_name
                                                        .clone()
                                                        .unwrap_or_else(|| u.id.clone());
                                                    let upn = u
                                                        .user_principal_name
                                                        .clone()
                                                        .unwrap_or_else(|| u.id.clone());
                                                    view! {
                                                        <li>
                                                            <div>
                                                                <div>{display}</div>
                                                                <div class="mono small">{upn}</div>
                                                            </div>
                                                            <Button
                                                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                                disabled=Signal::derive(move || {
                                                                    busy.with(|b| b.as_deref() == Some(id_busy.as_str()))
                                                                })
                                                                on_click=Box::new(move |_| {
                                                                    mutate(true, id_click.clone())
                                                                })
                                                            >
                                                                "Add"
                                                            </Button>
                                                        </li>
                                                    }
                                                })
                                                .collect_view()}
                                        </ul>
                                    }
                                        .into_any()
                                }
                            }
                        })}
                    </Suspense>
                }
                    .into_any()
            }}
            {move || error.get().map(|e| view! { <Body1 class="app-detail__error">{e}</Body1> })}
            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove this owner?"
                body="The owner loses the ability to manage this enterprise application. You can re-add them later."
                confirm_label="Remove"
                busy=Signal::derive(move || busy.with(|b| b.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_remove.get() {
                        pending_remove.set(None);
                        mutate(false, id);
                    }
                })
                on_close=Callback::new(move |()| pending_remove.set(None))
            />
        </div>
    }
}

#[component]
fn ProvisioningContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let sp_id = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));

    let jobs = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = sp_id.get();
        async move {
            match tenant {
                Some(t) => {
                    enterprise_application::get_enterprise_app_provisioning(&t.tenant_id, &id).await
                }
                None => Ok(Vec::new()),
            }
        }
    });

    view! {
        <Suspense fallback=move || {
            view! {
                <div class="centered-pad">
                    <Spinner
                        size=Signal::derive(|| SpinnerSize::Tiny)
                        label="Loading provisioning…"
                    />
                </div>
            }
        }>
            {move || Suspend::new(async move {
                match jobs.await {
                    Err(_) => {
                        view! {
                            <div class="alert alert--warn">
                                "Provisioning status is unavailable. It needs admin consent to Synchronization.Read.All and an Entra ID P1/P2 license."
                            </div>
                        }
                            .into_any()
                    }
                    Ok(list) if list.is_empty() => {
                        view! {
                            <Body1>"This application has no SCIM provisioning configured."</Body1>
                        }
                            .into_any()
                    }
                    Ok(list) => {
                        view! {
                            <div>
                                {list
                                    .into_iter()
                                    .map(|j| {
                                        let (label, cls) = match j.status_code.as_deref() {
                                            Some("Active") => ("Active".to_string(), "badge badge--ok"),
                                            Some("Quarantine") => {
                                                ("Quarantine".to_string(), "badge badge--danger")
                                            }
                                            Some(other) => (other.to_string(), "badge badge--warning"),
                                            None => ("Unknown".to_string(), "badge"),
                                        };
                                        let last = match (j.last_state.clone(), j.last_run.clone()) {
                                            (Some(s), Some(t)) => format!("{s} — {t}"),
                                            (Some(s), None) => s,
                                            _ => "—".to_string(),
                                        };
                                        let title = j
                                            .template_id
                                            .clone()
                                            .unwrap_or_else(|| j.id.clone());
                                        view! {
                                            <div class="prov-job">
                                                <div class="row-between">
                                                    <strong>{title}</strong>
                                                    <span class=cls>{label}</span>
                                                </div>
                                                <dl class="read-field">
                                                    <dt>"Last run"</dt>
                                                    <dd>{last}</dd>
                                                    {j.quarantine_reason
                                                        .clone()
                                                        .map(|r| {
                                                            view! {
                                                                <dt>"Quarantine reason"</dt>
                                                                <dd>{r}</dd>
                                                            }
                                                        })}
                                                </dl>
                                            </div>
                                        }
                                    })
                                    .collect_view()}
                            </div>
                        }
                            .into_any()
                    }
                }
            })}
        </Suspense>
    }
}

/// Activity / change-log for the enterprise app — directory audit entries
/// targeting the service principal and its paired app registration (if any).
#[component]
fn ActivityContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let app_id = Signal::derive(move || signal.with(|d| d.service_principal.app_id.clone()));
    let primary = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));
    let secondary = Signal::derive(move || {
        signal.with(|d| d.service_principal.paired_app_registration_id.clone())
    });
    view! { <ActivityPanel app_id=app_id primary_id=primary secondary_id=secondary /> }
}

/// Conditional Access for the enterprise app — policies that target its appId.
#[component]
fn CaContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let app_id = Signal::derive(move || signal.with(|d| d.service_principal.app_id.clone()));
    view! { <ConditionalAccessPanel app_id=app_id /> }
}
