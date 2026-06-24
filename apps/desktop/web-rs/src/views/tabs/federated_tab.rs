//! Federated identity credentials tab — workload identity federation (GitHub
//! Actions, Kubernetes, …). Lets an external OIDC workload authenticate as the
//! app with no client secret. Mirrors the portal's "Add a credential" pane: a
//! scenario picker with structured per-scenario fields that auto-build the
//! issuer/subject, plus in-place editing (everything but the immutable name).

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Select, Spinner, SpinnerSize};

use crate::bindings::applications::{
    self, AddFederatedCredentialInput, ApplicationDetail, FederatedCredentialDto,
    UpdateFederatedCredentialInput,
};
use crate::bindings::managed_identity;
use crate::components::ui::DataTable;
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::tabs::federated_scenarios::{
    DEFAULT_AUDIENCE, GITHUB_ISSUER, GithubEntity, entra_issuer, github_subject, k8s_subject,
};

/// The portal's "Federated credential scenario" choices (key, label).
const SCENARIOS: &[(&str, &str)] = &[
    ("github", "GitHub Actions deploying Azure resources"),
    ("kubernetes", "Kubernetes accessing Azure resources"),
    ("cmk", "Customer managed keys"),
    ("managed_identity", "Managed identity"),
    ("other", "Other issuer"),
];

const GITHUB_ENTITIES: &[(&str, &str)] = &[
    ("environment", "Environment"),
    ("branch", "Branch"),
    ("pull_request", "Pull request"),
    ("tag", "Tag"),
];

#[component]
pub fn FederatedTab(#[prop(into)] detail: Signal<Arc<ApplicationDetail>>) -> impl IntoView {
    let session = use_session();
    let object_id = Signal::derive(move || detail.with(|d| d.application.id.clone()));
    let tenant_id = Signal::derive(move || {
        session
            .active_tenant
            .get()
            .map(|t| t.tenant_id)
            .unwrap_or_default()
    });

    let reload = RwSignal::new(0_u32);
    let add_open = RwSignal::new(false);
    let cmd = use_command();
    let pending_remove: RwSignal<Option<(String, String)>> = RwSignal::new(None);

    // ---- Add form state ----
    let scenario = RwSignal::new("github".to_string());
    let name = RwSignal::new(String::new());
    let description = RwSignal::new(String::new());
    // GitHub Actions
    let gh_org = RwSignal::new(String::new());
    let gh_repo = RwSignal::new(String::new());
    let gh_entity = RwSignal::new("environment".to_string());
    let gh_value = RwSignal::new(String::new());
    // Kubernetes
    let k8s_issuer = RwSignal::new(String::new());
    let k8s_namespace = RwSignal::new(String::new());
    let k8s_sa = RwSignal::new(String::new());
    // Customer managed keys / Managed identity (same trust shape: the MI's
    // SP object id, issued by this tenant)
    let mi_selected = RwSignal::new(String::new());
    // Other issuer
    let other_issuer = RwSignal::new(String::new());
    let other_subject = RwSignal::new(String::new());
    let other_audience = RwSignal::new(DEFAULT_AUDIENCE.to_string());

    // ---- Edit state (raw fields; name is immutable in Graph) ----
    let editing: RwSignal<Option<FederatedCredentialDto>> = RwSignal::new(None);
    let edit_issuer = RwSignal::new(String::new());
    let edit_subject = RwSignal::new(String::new());
    let edit_description = RwSignal::new(String::new());
    let edit_audience = RwSignal::new(DEFAULT_AUDIENCE.to_string());

    let creds = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let id = object_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            applications::list_federated_credentials(&t.tenant_id, &id).await
        }
    });

    // The MI scenarios need the managed-identity list; fetch it only once one
    // of them is selected (Memo so toggling between the two doesn't refetch).
    let mi_needed = Memo::new(move |_| {
        add_open.get() && matches!(scenario.get().as_str(), "cmk" | "managed_identity")
    });
    let mis = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let needed = mi_needed.get();
        async move {
            if !needed {
                return Ok(Vec::new());
            }
            let Some(t) = tenant else {
                return Ok(Vec::new());
            };
            managed_identity::list_managed_identities(&t.tenant_id).await
        }
    });

    // What the chosen scenario resolves to on submit; also drives the
    // read-only Issuer/Subject preview, like the portal's auto-filled fields.
    let derived_issuer = Signal::derive(move || match scenario.get().as_str() {
        "github" => GITHUB_ISSUER.to_string(),
        "kubernetes" => k8s_issuer.get().trim().to_string(),
        "cmk" | "managed_identity" => entra_issuer(tenant_id.get().trim()),
        _ => other_issuer.get().trim().to_string(),
    });
    let derived_subject = Signal::derive(move || match scenario.get().as_str() {
        "github" => {
            let org = gh_org.get().trim().to_string();
            let repo = gh_repo.get().trim().to_string();
            if org.is_empty() || repo.is_empty() {
                return String::new();
            }
            let entity = GithubEntity::from_key(&gh_entity.get());
            let value = gh_value.get().trim().to_string();
            if entity.value_label().is_some() && value.is_empty() {
                return String::new();
            }
            github_subject(&org, &repo, entity, &value)
        }
        "kubernetes" => {
            let ns = k8s_namespace.get().trim().to_string();
            let sa = k8s_sa.get().trim().to_string();
            if ns.is_empty() || sa.is_empty() {
                String::new()
            } else {
                k8s_subject(&ns, &sa)
            }
        }
        "cmk" | "managed_identity" => mi_selected.get().trim().to_string(),
        _ => other_subject.get().trim().to_string(),
    });

    let submit = move |_| {
        let n = name.get().trim().to_string();
        if n.is_empty() {
            cmd.error.set(Some(
                "Name is required (it cannot be changed later).".into(),
            ));
            return;
        }
        let iss = derived_issuer.get();
        let sub = derived_subject.get();
        if iss.is_empty() || sub.is_empty() {
            let msg = match scenario.get().as_str() {
                "github" => "Organization, repository, and the entity value are required.",
                "kubernetes" => "Cluster issuer URL, namespace, and service account are required.",
                "cmk" | "managed_identity" => {
                    "Select (or paste the object ID of) a managed identity."
                }
                _ => "Issuer and subject identifier are required.",
            };
            cmd.error.set(Some(msg.into()));
            return;
        }
        // Only the Other-issuer scenario may override the audience; the
        // backend falls back to the default for None.
        let aud = other_audience.get().trim().to_string();
        let audiences = (scenario.get() == "other" && !aud.is_empty() && aud != DEFAULT_AUDIENCE)
            .then(|| vec![aud]);
        let desc = description.get().trim().to_string();
        let id = object_id.get();
        cmd.run(
            move |_| {
                name.set(String::new());
                description.set(String::new());
                gh_org.set(String::new());
                gh_repo.set(String::new());
                gh_value.set(String::new());
                k8s_issuer.set(String::new());
                k8s_namespace.set(String::new());
                k8s_sa.set(String::new());
                mi_selected.set(String::new());
                other_issuer.set(String::new());
                other_subject.set(String::new());
                other_audience.set(DEFAULT_AUDIENCE.to_string());
                add_open.set(false);
                session.toast_success("Federated credential added.");
                reload.update(|n| *n += 1);
            },
            move |tenant_id| {
                let input = AddFederatedCredentialInput {
                    name: n,
                    issuer: iss,
                    subject: sub,
                    description: (!desc.is_empty()).then_some(desc),
                    audiences,
                };
                async move { applications::add_federated_credential(&tenant_id, &id, &input).await }
            },
        );
    };

    let start_edit = move |c: FederatedCredentialDto| {
        edit_issuer.set(c.issuer.clone());
        edit_subject.set(c.subject.clone());
        edit_description.set(c.description.clone().unwrap_or_default());
        edit_audience.set(
            c.audiences
                .first()
                .cloned()
                .unwrap_or_else(|| DEFAULT_AUDIENCE.to_string()),
        );
        editing.set(Some(c));
        add_open.set(false);
        cmd.error.set(None);
    };

    let submit_edit = move |_| {
        let Some(cred) = editing.get() else {
            return;
        };
        let iss = edit_issuer.get().trim().to_string();
        let sub = edit_subject.get().trim().to_string();
        if iss.is_empty() || sub.is_empty() {
            cmd.error
                .set(Some("Issuer and subject are both required.".into()));
            return;
        }
        let aud = edit_audience.get().trim().to_string();
        let audiences = (!aud.is_empty()).then(|| vec![aud]);
        let desc = edit_description.get().trim().to_string();
        let id = object_id.get();
        cmd.run(
            move |()| {
                editing.set(None);
                session.toast_success("Federated credential updated.");
                reload.update(|n| *n += 1);
            },
            move |tenant_id| {
                let input = UpdateFederatedCredentialInput {
                    issuer: iss,
                    subject: sub,
                    description: (!desc.is_empty()).then_some(desc),
                    audiences,
                };
                async move {
                    applications::update_federated_credential(&tenant_id, &id, &cred.id, &input)
                        .await
                }
            },
        );
    };

    let do_remove = move |credential_id: String| {
        let id = object_id.get();
        cmd.run(
            move |()| {
                session.toast_success("Federated credential removed.");
                reload.update(|n| *n += 1);
            },
            move |tenant_id| async move {
                applications::remove_federated_credential(&tenant_id, &id, &credential_id).await
            },
        );
    };

    let preview_line = move |label: &'static str, value: String| {
        view! { <Body1 class="row-meta mono">{format!("{label}: {value}")}</Body1> }
    };

    view! {
        <div class="federated-tab">
            <header class="row-between">
                <strong>"Federated credentials"</strong>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| {
                        editing.set(None);
                        add_open.update(|v| *v = !*v);
                    })
                >
                    {move || if add_open.get() { "Cancel" } else { "+ Add federated credential" }}
                </Button>
            </header>
            <Body1 class="mi-view__intro">
                "Lets an external OIDC workload (GitHub Actions, Kubernetes, …) authenticate as this app with no client secret. Up to 20 per app."
            </Body1>

            <Show when=move || add_open.get() fallback=|| view! { <></> }>
                <section class="federated-tab__add">
                    <Field label="Federated credential scenario">
                        <Select value=scenario>
                            {SCENARIOS
                                .iter()
                                .map(|(value, label)| {
                                    view! { <option value=*value>{*label}</option> }
                                })
                                .collect_view()}
                        </Select>
                    </Field>

                    <Show when=move || scenario.get() == "github" fallback=|| view! { <></> }>
                        <Field label="Organization">
                            <Input value=gh_org placeholder="contoso" />
                        </Field>
                        <Field label="Repository">
                            <Input value=gh_repo placeholder="contoso-app" />
                        </Field>
                        <Field label="Entity type">
                            <Select value=gh_entity>
                                {GITHUB_ENTITIES
                                    .iter()
                                    .map(|(value, label)| {
                                        view! { <option value=*value>{*label}</option> }
                                    })
                                    .collect_view()}
                            </Select>
                        </Field>
                        {move || {
                            GithubEntity::from_key(&gh_entity.get())
                                .value_label()
                                .map(|label| {
                                    view! {
                                        <Field label=label>
                                            <Input value=gh_value />
                                        </Field>
                                    }
                                })
                        }}
                        <Body1 class="hint">
                            "Values must exactly match the GitHub workflow configuration — pattern matching is not supported."
                        </Body1>
                    </Show>

                    <Show when=move || scenario.get() == "kubernetes" fallback=|| view! { <></> }>
                        <Field label="Cluster issuer URL">
                            <Input value=k8s_issuer placeholder="https://oidc.prod-aks.azure.com/…" />
                        </Field>
                        <Field label="Namespace">
                            <Input value=k8s_namespace placeholder="default" />
                        </Field>
                        <Field label="Service account name">
                            <Input value=k8s_sa placeholder="workload-sa" />
                        </Field>
                    </Show>

                    <Show
                        when=move || matches!(scenario.get().as_str(), "cmk" | "managed_identity")
                        fallback=|| view! { <></> }
                    >
                        <Suspense fallback=move || {
                            view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading managed identities…" /> }
                        }>
                            {move || Suspend::new(async move {
                                match mis.await {
                                    Ok(list) if !list.is_empty() => {
                                        view! {
                                            <Field label="Managed identity">
                                                <Select value=mi_selected>
                                                    <option value="">"Select a managed identity…"</option>
                                                    {list
                                                        .into_iter()
                                                        .map(|mi| {
                                                            view! {
                                                                <option value=mi.id.clone()>{mi.display_name.clone()}</option>
                                                            }
                                                        })
                                                        .collect_view()}
                                                </Select>
                                            </Field>
                                        }
                                            .into_any()
                                    }
                                    // No MIs visible (none exist, or the read needs a
                                    // role this user lacks) — degrade to a free-text
                                    // object id, never block the form.
                                    _ => {
                                        view! {
                                            <Field label="Managed identity object (principal) ID">
                                                <Input value=mi_selected placeholder="00000000-0000-0000-0000-000000000000" />
                                            </Field>
                                            <Body1 class="hint">
                                                "Couldn't list managed identities — paste the identity's object (principal) ID instead."
                                            </Body1>
                                        }
                                            .into_any()
                                    }
                                }
                            })}
                        </Suspense>
                    </Show>

                    <Show when=move || scenario.get() == "other" fallback=|| view! { <></> }>
                        <Field label="Issuer (OIDC issuer URL)">
                            <Input value=other_issuer placeholder="https://accounts.google.com" />
                        </Field>
                        <Field label="Subject identifier (must match the token's sub claim exactly)">
                            <Input value=other_subject />
                        </Field>
                        <Field label="Audience">
                            <Input value=other_audience />
                        </Field>
                        <Body1 class="hint">
                            "Microsoft recommends keeping the default audience api://AzureADTokenExchange — only change it if the external provider requires another value."
                        </Body1>
                    </Show>

                    <Field label="Name (unique on this app; cannot be changed later)">
                        <Input value=name placeholder="github-actions-prod" />
                    </Field>
                    <Field label="Description (optional)">
                        <Input value=description />
                    </Field>

                    // Read-only preview of what will be written — the portal
                    // shows the same auto-populated issuer/subject/audience.
                    <Show when=move || scenario.get() != "other" fallback=|| view! { <></> }>
                        {move || preview_line("Issuer", {
                            let v = derived_issuer.get();
                            if v.is_empty() { "—".into() } else { v }
                        })}
                        {move || preview_line("Subject", {
                            let v = derived_subject.get();
                            if v.is_empty() { "—".into() } else { v }
                        })}
                        {move || preview_line("Audience", DEFAULT_AUDIENCE.to_string())}
                    </Show>

                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(submit)
                            disabled=Signal::derive(move || cmd.busy.get())
                        >
                            {move || {
                                if cmd.busy.get() {
                                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                        .into_any()
                                } else {
                                    view! { "Add" }.into_any()
                                }
                            }}
                        </Button>
                    </div>
                </section>
            </Show>

            <Show when=move || editing.get().is_some() fallback=|| view! { <></> }>
                <section class="federated-tab__add">
                    <strong>
                        {move || {
                            editing
                                .get()
                                .map(|c| format!("Edit “{}”", c.name))
                                .unwrap_or_default()
                        }}
                    </strong>
                    <Body1 class="hint">
                        "The name is immutable — to rename, remove the credential and add a new one."
                    </Body1>
                    <Field label="Issuer (OIDC issuer URL)">
                        <Input value=edit_issuer />
                    </Field>
                    <Field label="Subject (must match the token's sub claim exactly)">
                        <Input value=edit_subject />
                    </Field>
                    <Field label="Audience">
                        <Input value=edit_audience />
                    </Field>
                    <Field label="Description (optional)">
                        <Input value=edit_description />
                    </Field>
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| editing.set(None))
                            disabled=Signal::derive(move || cmd.busy.get())
                        >
                            "Cancel"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(submit_edit)
                            disabled=Signal::derive(move || cmd.busy.get())
                        >
                            {move || {
                                if cmd.busy.get() {
                                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                        .into_any()
                                } else {
                                    view! { "Save" }.into_any()
                                }
                            }}
                        </Button>
                    </div>
                </section>
            </Show>

            {move || cmd.error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}

            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" /> }
            }>
                {move || Suspend::new(async move {
                    match creds.await {
                        Ok(list) => {
                            view! {
                                <DataTable
                                    headers=vec!["Name", "Issuer", "Subject", ""]
                                    rows=list
                                    empty_message="No federated credentials."
                                    row=move |c: FederatedCredentialDto| {
                                        let cid = c.id.clone();
                                        let cname = c.name.clone();
                                        let edit_cred = c.clone();
                                        view! {
                                            <tr>
                                                <td>{c.name.clone()}</td>
                                                <td class="mono">{c.issuer.clone()}</td>
                                                <td class="mono">{c.subject.clone()}</td>
                                                <td>
                                                    <div class="actions-row">
                                                        <Button
                                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                            on_click=Box::new(move |_| {
                                                                start_edit(edit_cred.clone())
                                                            })
                                                        >
                                                            "Edit"
                                                        </Button>
                                                        <Button
                                                            class="button--danger"
                                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                            on_click=Box::new(move |_| {
                                                                pending_remove.set(Some((cid.clone(), cname.clone())))
                                                            })
                                                        >
                                                            "Remove"
                                                        </Button>
                                                    </div>
                                                </td>
                                            </tr>
                                        }
                                            .into_any()
                                    }
                                />
                            }
                                .into_any()
                        }
                        Err(e) => {
                            view! { <Body1 class="form-error">{e.message}</Body1> }.into_any()
                        }
                    }
                })}
            </Suspense>

            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove this federated credential?"
                body="Any workload using this issuer/subject will stop being able to authenticate as the app. This cannot be undone."
                confirm_label="Remove"
                busy=Signal::derive(move || cmd.busy.get())
                on_confirm=Callback::new(move |()| {
                    if let Some((id, _)) = pending_remove.get() {
                        pending_remove.set(None);
                        do_remove(id);
                    }
                })
                on_close=Callback::new(move |()| pending_remove.set(None))
            />
        </div>
    }
}
