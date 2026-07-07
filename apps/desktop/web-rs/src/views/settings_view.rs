//! Settings page — per-tenant operator defaults.
//!
//! Edits the defaults persisted by `get_tenant_defaults` / `set_tenant_defaults`:
//! default owners for app registrations and enterprise applications, the SSO
//! notification-email seed, and the legacy-AAP management-scope-name pattern.
//! These are reused elsewhere (the "Add Default Owners" buttons in the owner
//! tabs, the SSO field prefill, the migration default) so the operator configures
//! them once.
//!
//! Loads via a tenant-keyed resource, then mounts an editor seeded from the
//! loaded values — so a tenant switch refetches and remounts a fresh editor
//! rather than leaking the prior tenant's directory objects.

use std::collections::HashSet;

use azapptoolkit_core::models::DirectoryObject;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize, Textarea};

use crate::bindings::applications;
use crate::bindings::defaults::{
    self, AppRegistrationDefaults, EnterpriseApplicationDefaults, StoredPrincipal, TenantDefaults,
};
use crate::components::owner_picker::OwnerPicker;
use crate::components::ui::{Callout, SectionHeader};
use crate::hooks::use_debounced::use_debounced;
use crate::state::use_session;
use crate::util::parse_lines;

fn to_stored(o: &DirectoryObject) -> StoredPrincipal {
    StoredPrincipal {
        id: o.id.clone(),
        display_name: o.display_name.clone(),
        user_principal_name: o.user_principal_name.clone(),
        odata_type: o.odata_type.clone(),
    }
}

#[component]
pub fn SettingsView() -> impl IntoView {
    let session = use_session();
    // Keyed on the active tenant: switching tenants refetches (and remounts the
    // editor with fresh initial values).
    let loaded = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        async move {
            match tenant {
                Some(t) => Some((
                    t.tenant_id.clone(),
                    defaults::get_tenant_defaults(&t.tenant_id).await,
                )),
                None => None,
            }
        }
    });

    view! {
        <div class="settings-view">
            <SectionHeader title="Settings" crumb="Account" />
            <Body1 class="hint">
                "Operator defaults for this tenant — stored locally and reused so you don't re-enter \
                 them each time. They apply only when you choose to (e.g. the \"Add Default Owners\" \
                 button); nothing here changes an app on its own."
            </Body1>
            <Suspense fallback=move || {
                view! {
                    <Spinner
                        size=Signal::derive(|| SpinnerSize::Medium)
                        label="Loading settings…"
                    />
                }
            }>
                {move || Suspend::new(async move {
                    match loaded.await {
                        Some((tenant_id, initial)) => {
                            view! { <SettingsEditor tenant_id=tenant_id initial=initial /> }
                                .into_any()
                        }
                        None => {
                            view! {
                                <Callout tone="info">
                                    "Sign in and select a tenant to configure its defaults."
                                </Callout>
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn SettingsEditor(tenant_id: String, initial: TenantDefaults) -> impl IntoView {
    let session = use_session();

    let app_owners = RwSignal::new(initial.app_registration.default_owners.clone());
    let ent_owners = RwSignal::new(initial.enterprise_application.default_owners.clone());
    let emails = RwSignal::new(
        initial
            .enterprise_application
            .default_notification_emails
            .join("\n"),
    );
    let pattern = RwSignal::new(initial.scope_name_pattern.clone().unwrap_or_default());
    let group_pattern = RwSignal::new(initial.group_name_pattern.clone().unwrap_or_default());
    let secret_pattern = RwSignal::new(initial.secret_name_pattern.clone().unwrap_or_default());

    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let app_exclude = Signal::derive(move || {
        app_owners
            .get()
            .iter()
            .map(|p| p.id.clone())
            .collect::<HashSet<_>>()
    });
    let ent_exclude = Signal::derive(move || {
        ent_owners
            .get()
            .iter()
            .map(|p| p.id.clone())
            .collect::<HashSet<_>>()
    });

    let add_app = Callback::new(move |o: DirectoryObject| {
        app_owners.update(|v| {
            if !v.iter().any(|p| p.id == o.id) {
                v.push(to_stored(&o));
            }
        });
    });
    let add_ent = Callback::new(move |o: DirectoryObject| {
        ent_owners.update(|v| {
            if !v.iter().any(|p| p.id == o.id) {
                v.push(to_stored(&o));
            }
        });
    });
    // Appends a distribution list's address to the notification-email textarea
    // (deduped, case-insensitive).
    let add_dl_email = Callback::new(move |email: String| {
        emails.update(|cur| {
            let mut lines: Vec<String> = cur
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            if !lines.iter().any(|l| l.eq_ignore_ascii_case(&email)) {
                lines.push(email);
            }
            *cur = lines.join("\n");
        });
    });

    let on_save = {
        let tenant_id = tenant_id.clone();
        move |_| {
            if busy.get() {
                return;
            }
            busy.set(true);
            error.set(None);
            let tenant_id = tenant_id.clone();
            let payload = TenantDefaults {
                app_registration: AppRegistrationDefaults {
                    default_owners: app_owners.get(),
                },
                enterprise_application: EnterpriseApplicationDefaults {
                    default_owners: ent_owners.get(),
                    default_notification_emails: parse_lines(&emails.get()),
                },
                scope_name_pattern: {
                    let p = pattern.get().trim().to_string();
                    (!p.is_empty()).then_some(p)
                },
                group_name_pattern: {
                    let p = group_pattern.get().trim().to_string();
                    (!p.is_empty()).then_some(p)
                },
                secret_name_pattern: {
                    let p = secret_pattern.get().trim().to_string();
                    (!p.is_empty()).then_some(p)
                },
                ..Default::default()
            };
            leptos::task::spawn_local(async move {
                match defaults::set_tenant_defaults(&tenant_id, &payload).await {
                    Ok(()) => {
                        session.toast_success("Settings saved.");
                    }
                    Err(e) => error.set(Some(e.message)),
                }
                busy.set(false);
            });
        }
    };

    view! {
        <div class="settings-editor">
            <section class="settings-section">
                <h3>"App Registration defaults"</h3>
                <Body1 class="hint">
                    "Default owners to add with one click from an app registration's Owners tab."
                </Body1>
                {owner_list(app_owners)}
                <OwnerPicker on_pick=add_app exclude=app_exclude />
            </section>

            <section class="settings-section">
                <h3>"Enterprise Application defaults"</h3>
                <Body1 class="hint">
                    "Default owners (users only — Entra rejects groups as service-principal owners) \
                     and the notification email addresses seeded into a new SAML SSO configuration."
                </Body1>
                {owner_list(ent_owners)}
                <OwnerPicker on_pick=add_ent exclude=ent_exclude />
                <Field label="Default SSO notification emails (one per line, max 5)">
                    <Textarea value=emails />
                </Field>
                <Body1 class="hint">
                    "Or search a distribution list / mail-enabled group to add its address:"
                </Body1>
                <DlEmailPicker on_pick=add_dl_email />
            </section>

            <section class="settings-section">
                <h3>"Key Vault"</h3>
                <Body1 class="hint">
                    "Naming pattern for the Key Vault secret created when rotating a credential. \
                     Use "
                    <code>"{appId}"</code>
                    " as the app's client id. Blank uses the built-in "
                    <code>"secret-{appId}"</code>
                    " (Key Vault secret names allow only letters, digits, and dashes — no underscores)."
                </Body1>
                <Field label="Secret name pattern">
                    <Input value=secret_pattern placeholder="secret-{appId}" />
                </Field>
            </section>

            <section class="settings-section">
                <h3>"Management scope naming"</h3>
                <Body1 class="hint">
                    "Naming pattern for the Exchange management scope this toolkit creates for any \
                     scoped-mailbox grant (and when migrating a legacy Application Access Policy). \
                     Use "
                    <code>"{appId}"</code>
                    " as the app's client id. Blank uses the built-in "
                    <code>"app_scope_{appId}"</code>
                    "."
                </Body1>
                <Field label="Management scope name pattern">
                    <Input value=pattern placeholder="app_scope_{appId}" />
                </Field>
            </section>

            <section class="settings-section">
                <h3>"Mail-enabled security group naming"</h3>
                <Body1 class="hint">
                    "Naming pattern for the toolkit-managed mail-enabled security group whose \
                     membership defines which mailboxes a scoped app can reach. Use "
                    <code>"{appId}"</code>
                    " as the app's client id. Blank uses the built-in "
                    <code>"app_scope_group_{appId}"</code>
                    "."
                </Body1>
                <Field label="Mail-enabled group name pattern">
                    <Input value=group_pattern placeholder="app_scope_group_{appId}" />
                </Field>
            </section>

            {move || {
                error.get().map(|e| view! { <Callout tone="danger">{e}</Callout> })
            }}
            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(on_save)
                    disabled=Signal::derive(move || busy.get())
                >
                    {move || {
                        if busy.get() {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                .into_any()
                        } else {
                            view! { "Save defaults" }.into_any()
                        }
                    }}
                </Button>
            </div>
        </div>
    }
}

/// Renders the current default-owner list with per-row remove. Shared by both
/// the app-registration and enterprise-application editors.
fn owner_list(owners: RwSignal<Vec<StoredPrincipal>>) -> impl IntoView {
    view! {
        {move || {
            let items = owners.get();
            if items.is_empty() {
                view! { <Body1 class="hint">"No default owners set."</Body1> }.into_any()
            } else {
                view! {
                    <ul class="candidates">
                        {items
                            .into_iter()
                            .map(|p| {
                                let id = p.id.clone();
                                let display = p.display_name.clone().unwrap_or_else(|| p.id.clone());
                                let upn = p
                                    .user_principal_name
                                    .clone()
                                    .unwrap_or_else(|| p.id.clone());
                                view! {
                                    <li>
                                        <div>
                                            <div>{display}</div>
                                            <div class="mono small">{upn}</div>
                                        </div>
                                        <Button
                                            class="button--danger"
                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                            on_click=Box::new(move |_| {
                                                let id = id.clone();
                                                owners.update(|v| v.retain(|x| x.id != id));
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
                    .into_any()
            }
        }}
    }
}

/// Distribution-list / mail-enabled-group search that emits the selected group's
/// mail address — for seeding the SSO notification-email default without typing.
#[component]
fn DlEmailPicker(on_pick: Callback<String>) -> impl IntoView {
    let session = use_session();
    let raw_query = RwSignal::new(String::new());
    let query = use_debounced(raw_query.into(), 300);

    let candidates = LocalResource::new(move || {
        let q = query.get();
        let tenant = session.active_tenant.get();
        async move {
            let q = q.trim().to_string();
            if q.len() < 2 {
                return Ok::<Vec<DirectoryObject>, String>(Vec::new());
            }
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            applications::search_distribution_lists(&t.tenant_id, &q)
                .await
                .map_err(|e| e.message)
        }
    });

    view! {
        <div class="owner-picker">
            <Field label="Search distribution lists (2+ chars)">
                <Input value=raw_query placeholder="sso-alerts" />
            </Field>
            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Searching…" /> }
            }>
                {move || Suspend::new(async move {
                    let dls = match candidates.await {
                        Ok(d) => d,
                        Err(msg) => {
                            return view! {
                                <Body1 class="form-error">{format!("Search failed: {msg}")}</Body1>
                            }
                                .into_any();
                        }
                    };
                    if dls.is_empty() {
                        return view! { <Body1>"No matches."</Body1> }.into_any();
                    }
                    view! {
                        <ul class="candidates">
                            {dls
                                .into_iter()
                                .filter_map(|d| {
                                    let mail = d.mail.clone()?;
                                    let display = d
                                        .display_name
                                        .clone()
                                        .unwrap_or_else(|| mail.clone());
                                    let pick = mail.clone();
                                    Some(
                                        view! {
                                            <li>
                                                <div>
                                                    <div>{display}</div>
                                                    <div class="mono small">{mail}</div>
                                                </div>
                                                <Button
                                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                    on_click=Box::new(move |_| {
                                                        on_pick.run(pick.clone());
                                                        raw_query.set(String::new());
                                                    })
                                                >
                                                    "Add"
                                                </Button>
                                            </li>
                                        },
                                    )
                                })
                                .collect_view()}
                        </ul>
                    }
                        .into_any()
                })}
            </Suspense>
        </div>
    }
}
