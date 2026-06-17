#![allow(clippy::unnecessary_wraps)]

//! Detail pane for a selected enterprise application service principal.
//! Header strip + tab list (Overview, Credentials, Owners, Permissions) with
//! per-tab content. Mirrors the App Registrations detail pane structure.

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
use crate::components::ui::{DataTable, DetailSkeleton};
use crate::hooks::use_debounced::use_debounced;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::pairing::jump_to_paired_app;
use crate::views::tabs::activity_tab::ActivityPanel;
use crate::views::tabs::conditional_access_tab::ConditionalAccessPanel;

mod access;
mod permissions;
mod sso_tab;

use access::AccessContent;
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

#[component]
fn EnterpriseAppPanel(
    detail_signal: Signal<EnterpriseApplicationDetail>,
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
    let restored = match restored.as_str() {
        "insights" => "conditionalAccess".to_string(),
        _ => restored,
    };
    let active_tab = RwSignal::new(restored);
    Effect::new(move |_| session.last_enterprise_tab.set(active_tab.get()));

    // Derive a read-only signal from the RwSignal for easier access.
    let ro_signal = Signal::derive(move || detail_signal.get());

    // Deleting a service principal is destructive and has no app-reg equivalent
    // for managed identities (their lifecycle is owned by the Azure resource),
    // so this lives only on the enterprise detail and is gated behind a typed
    // confirmation with an extra warning for foreign-tenant / first-party SPs.
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
                <Tab value="overview">"Overview"</Tab>
                <Tab value="sso">"SSO"</Tab>
                <Tab value="credentials">"Credentials"</Tab>
                <Tab value="owners">"Owners"</Tab>
                <Tab value="permissions">"Permissions"</Tab>
                <Tab value="access">"Access"</Tab>
                <Tab value="provisioning">"Provisioning"</Tab>
                <Tab value="conditionalAccess">"Conditional Access"</Tab>
                <Tab value="activity">"Activity"</Tab>
            </TabList>
            <div class="app-detail__pane">
                {move || match active_tab.get().as_str() {
                    "overview" => view! { <OverviewContent signal=ro_signal /> }.into_any(),
                    "sso" => view! { <SsoContent signal=ro_signal /> }.into_any(),
                    "credentials" => view! { <CredentialsContent signal=ro_signal /> }.into_any(),
                    "owners" => view! { <OwnersContent signal=ro_signal /> }.into_any(),
                    "permissions" => view! { <PermissionsContent signal=ro_signal /> }.into_any(),
                    "access" => view! { <AccessContent signal=ro_signal /> }.into_any(),
                    "provisioning" => {
                        view! { <ProvisioningContent signal=ro_signal /> }.into_any()
                    }
                    "conditionalAccess" => view! { <CaContent signal=ro_signal /> }.into_any(),
                    "activity" => view! { <ActivityContent signal=ro_signal /> }.into_any(),
                    _ => view! { <Body1>"Unknown tab"</Body1> }.into_any(),
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
                view! {
                    <ConfirmDialog
                        open=Signal::derive(move || delete_open.get())
                        title="Delete this enterprise application?"
                        body=body
                        confirm_label="Delete"
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
fn OverviewContent(signal: Signal<EnterpriseApplicationDetail>) -> impl IntoView {
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
                    session.toast_error(e.message, None);
                }
            }
            toggling.set(false);
        });
    };

    let (status_label, status_class) = match sp.account_enabled {
        Some(true) => ("Enabled", "badge badge--ok"),
        Some(false) => ("Disabled", "badge badge--danger"),
        None => ("Unknown", "badge"),
    };
    // `appRoleAssignmentRequired` governs whether users must be explicitly
    // assigned before the app is usable / visible on My Apps.
    let (assign_label, assign_class) = match sp.app_role_assignment_required {
        Some(true) => ("Required", "badge badge--ok"),
        Some(false) => ("Not required", "badge badge--warning"),
        None => ("Unknown", "badge"),
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
            <dt>"Status"</dt>
            <dd>
                <span class=status_class>{status_label}</span>
            </dd>
            <dt>"User assignment"</dt>
            <dd>
                <span class=assign_class>{assign_label}</span>
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
    }
}

#[component]
fn CredentialsContent(signal: Signal<EnterpriseApplicationDetail>) -> impl IntoView {
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

#[component]
fn OwnersContent(signal: Signal<EnterpriseApplicationDetail>) -> impl IntoView {
    let owners = signal.with(|d| d.owners.clone());
    if owners.is_empty() {
        view! {
            <div class="alert alert--warn">
                "No owners assigned — no one is accountable for this enterprise application."
            </div>
        }
        .into_any()
    } else {
        view! {
            <ul class="owner-list">
                {owners
                    .into_iter()
                    .map(|o| {
                        let name = o.display_name.clone().unwrap_or_else(|| o.id.clone());
                        let upn = o.user_principal_name.clone();
                        view! {
                            <li>
                                <span>{name}</span>
                                {upn.map(|u| view! { <span class="row-meta mono">{u}</span> })}
                            </li>
                        }
                    })
                    .collect_view()}
            </ul>
        }
        .into_any()
    }
}

#[component]
fn ProvisioningContent(signal: Signal<EnterpriseApplicationDetail>) -> impl IntoView {
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
fn ActivityContent(signal: Signal<EnterpriseApplicationDetail>) -> impl IntoView {
    let app_id = Signal::derive(move || signal.with(|d| d.service_principal.app_id.clone()));
    let primary = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));
    let secondary = Signal::derive(move || {
        signal.with(|d| d.service_principal.paired_app_registration_id.clone())
    });
    view! { <ActivityPanel app_id=app_id primary_id=primary secondary_id=secondary /> }
}

/// Conditional Access for the enterprise app — policies that target its appId.
#[component]
fn CaContent(signal: Signal<EnterpriseApplicationDetail>) -> impl IntoView {
    let app_id = Signal::derive(move || signal.with(|d| d.service_principal.app_id.clone()));
    view! { <ConditionalAccessPanel app_id=app_id /> }
}
