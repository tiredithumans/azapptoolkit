//! Overview tab. Read mode + edit mode for display name / sign-in audience /
//! description.

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Select, Spinner, SpinnerSize, Textarea};

use crate::bindings::applications::{self, ApplicationDetail, UpdateApplicationInput};
use crate::hooks::use_command::use_command;

const SIGN_IN_AUDIENCES: &[(&str, &str)] = &[
    ("AzureADMyOrg", "Single tenant (this directory only)"),
    (
        "AzureADMultipleOrgs",
        "Multitenant (any Microsoft Entra directory)",
    ),
    (
        "AzureADandPersonalMicrosoftAccount",
        "Multitenant + personal Microsoft accounts",
    ),
    (
        "PersonalMicrosoftAccount",
        "Personal Microsoft accounts only",
    ),
];

fn audience_label(value: Option<&str>) -> String {
    match value {
        None => "—".into(),
        Some(v) => SIGN_IN_AUDIENCES
            .iter()
            .find(|(k, _)| *k == v)
            .map(|(_, l)| (*l).to_string())
            .unwrap_or_else(|| v.to_string()),
    }
}

#[component]
pub fn OverviewTab(
    #[prop(into)] detail: Signal<Arc<ApplicationDetail>>,
    #[prop(into)] on_changed: Callback<()>,
) -> impl IntoView {
    let editing = RwSignal::new(false);
    let cmd = use_command();

    let initial_app = detail.with_untracked(|d| d.application.clone());
    let display_name = RwSignal::new(initial_app.display_name.clone());
    let audience = RwSignal::new(
        initial_app
            .sign_in_audience
            .clone()
            .unwrap_or_else(|| "AzureADMyOrg".into()),
    );
    let description = RwSignal::new(initial_app.description.clone().unwrap_or_default());
    let notes = RwSignal::new(initial_app.notes.clone().unwrap_or_default());

    // Reset form when underlying detail changes (mirrors React's useEffect).
    Effect::new(move |_| {
        let app = detail.with(|d| d.application.clone());
        display_name.set(app.display_name);
        audience.set(
            app.sign_in_audience
                .clone()
                .unwrap_or_else(|| "AzureADMyOrg".into()),
        );
        description.set(app.description.clone().unwrap_or_default());
        notes.set(app.notes.clone().unwrap_or_default());
    });

    let save = move |_| {
        let app = detail.with(|d| d.application.clone());
        let dn = display_name.get();
        let aud = audience.get();
        let desc = description.get();
        let notes_val = notes.get();
        let on_changed_cb = on_changed;
        cmd.run(
            move |()| {
                editing.set(false);
                on_changed_cb.run(());
            },
            move |tenant_id| {
                let mut patch = UpdateApplicationInput::default();
                let dn_t = dn.trim();
                if dn_t != app.display_name {
                    patch.display_name = Some(dn_t.to_string());
                }
                if aud != app.sign_in_audience.clone().unwrap_or_default() {
                    patch.sign_in_audience = Some(aud);
                }
                let desc_t = desc.trim();
                let desc_opt = if desc_t.is_empty() {
                    None
                } else {
                    Some(desc_t.to_string())
                };
                if desc_opt != app.description {
                    patch.description = desc_opt;
                }
                // Notes: send the trimmed value (empty string included) whenever it
                // changed, so clearing actually reaches Graph. Unlike `description`
                // above, an empty edit sends `Some("")` rather than omitting.
                let notes_t = notes_val.trim();
                if notes_t != app.notes.clone().unwrap_or_default() {
                    patch.notes = Some(notes_t.to_string());
                }
                async move { applications::update_application(&tenant_id, &app.id, &patch).await }
            },
        );
    };

    let cancel = move |_| {
        editing.set(false);
        cmd.error.set(None);
    };
    let start_edit = move |_| editing.set(true);

    view! {
        <div class="overview-tab">
            <Show
                when=move || !editing.get()
                fallback=move || {
                    let save = save;
                    let cancel = cancel;
                    view! {
                        <div class="form-grid">
                            <Field label="Display name">
                                <Input value=display_name />
                            </Field>
                            <Field label="Sign-in audience">
                                <Select value=audience>
                                    {SIGN_IN_AUDIENCES
                                        .iter()
                                        .map(|(value, label)| {
                                            view! { <option value=*value>{*label}</option> }
                                        })
                                        .collect_view()}
                                </Select>
                            </Field>
                            <Field label="Description">
                                <Textarea value=description />
                            </Field>
                            <Field label="Internal notes (max 1024 characters)">
                                <Textarea value=notes />
                            </Field>
                            {move || {
                                cmd.error
                                    .get()
                                    .map(|e| {
                                        view! { <Body1 class="form-error">{e}</Body1> }
                                    })
                            }}
                            <div class="actions-row">
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                    on_click=Box::new(save)
                                    disabled=Signal::derive(move || cmd.busy.get())
                                >
                                    {move || {
                                        if cmd.busy.get() {
                                            view! {
                                                <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                            }
                                                .into_any()
                                        } else {
                                            view! { "Save" }.into_any()
                                        }
                                    }}
                                </Button>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(cancel)
                                    disabled=Signal::derive(move || cmd.busy.get())
                                >
                                    "Cancel"
                                </Button>
                            </div>
                        </div>
                    }
                }
            >
                {move || {
                    let app = detail.with(|d| d.application.clone());
                    let sp = detail.with(|d| d.service_principal.clone());
                    let sp_text = match sp.as_ref() {
                        Some(sp) => {
                            format!(
                                "{} · {}",
                                sp.display_name,
                                if sp.account_enabled.unwrap_or(false) {
                                    "enabled"
                                } else {
                                    "disabled"
                                },
                            )
                        }
                        None => "No service principal — grant admin consent to provision one."
                            .to_string(),
                    };
                    // Microsoft trust/hardening signals (Tier-2 best-practices surfacing).
                    let verified_text = match app
                        .verified_publisher
                        .as_ref()
                        .and_then(|v| v.display_name.as_deref())
                    {
                        Some(name) if !name.is_empty() => format!("Verified — {name}"),
                        _ => "Not verified".to_string(),
                    };
                    let lock_text = match app.service_principal_lock_configuration.as_ref() {
                        None => "Not configured".to_string(),
                        Some(l) if l.is_fully_locked() => {
                            "Enabled (all sensitive properties)".to_string()
                        }
                        Some(_) => {
                            "Partially enabled — not all sensitive properties locked".to_string()
                        }
                    };
                    let is_public_client = app.is_fallback_public_client == Some(true);
                    view! {
                        <div class="form-grid">
                            <ReadField label="Object ID" value=app.id.clone() mono=true />
                            <ReadField label="App ID" value=app.app_id.clone() mono=true />
                            <ReadField label="Display name" value=app.display_name.clone() mono=false />
                            <ReadField
                                label="Sign-in audience"
                                value=audience_label(app.sign_in_audience.as_deref())
                                mono=false
                            />
                            <ReadField
                                label="Publisher domain"
                                value=app.publisher_domain.clone().unwrap_or_else(|| "—".into())
                                mono=false
                            />
                            <ReadField
                                label="Publisher verification"
                                value=verified_text
                                mono=false
                            />
                            <ReadField label="Instance lock" value=lock_text mono=false />
                            {is_public_client
                                .then(|| {
                                    view! {
                                        <ReadField
                                            label="Public client flows"
                                            value="Enabled — if used only as a public/installed client, it should not hold credentials"
                                                .to_string()
                                            mono=false
                                        />
                                    }
                                })}
                            <ReadField
                                label="Created"
                                value=app
                                    .created_date_time
                                    .map(|d| d.to_rfc3339())
                                    .unwrap_or_else(|| "—".into())
                                mono=false
                            />
                            <ReadField label="Service principal" value=sp_text mono=false />
                            {app
                                .description
                                .as_ref()
                                .map(|d| {
                                    view! {
                                        <ReadField label="Description" value=d.clone() mono=false />
                                    }
                                })}
                            <ReadField
                                label="Internal notes"
                                value=app
                                    .notes
                                    .clone()
                                    .filter(|n| !n.is_empty())
                                    .unwrap_or_else(|| "—".into())
                                mono=false
                            />
                            <div>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(start_edit)
                                >
                                    "Edit"
                                </Button>
                            </div>
                        </div>
                    }
                }}
            </Show>
        </div>
    }
}

#[component]
fn ReadField(label: &'static str, value: String, mono: bool) -> impl IntoView {
    let class = if mono {
        "read-field mono"
    } else {
        "read-field"
    };
    view! {
        <div class=class>
            <strong>{label}</strong>
            <div>{value}</div>
        </div>
    }
}
