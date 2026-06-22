//! App roles tab for an enterprise application — manage the **exposed** app-role
//! definitions the app publishes: add, edit, enable/disable, and delete. This is
//! the Entra "App roles" blade. Assigning a role to users/groups lives in the
//! Access tab.
//!
//! Loads live via `list_enterprise_app_roles` — an authoritative read against the
//! canonical target (the paired application when one exists, else the SP), so the
//! list is correct immediately after a write with no app→SP replication lag. Each
//! mutation re-reads live state on the backend (Graph full-replaces `appRoles`);
//! on success the tab refetches and bumps the parent detail (the Access tab's role
//! picker reads the SP's mirrored roles).

use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize, Textarea};

use crate::bindings::enterprise_application::{
    self, AppRoleInput, AppRolesView, EnterpriseApplicationDetail,
};
use crate::components::modal_shell::ModalShell;
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;

use azapptoolkit_core::models::AppRole;

/// Portal wording for an app role's `allowedMemberTypes`.
fn member_types_label(types: &[String]) -> String {
    let labels: Vec<&str> = types
        .iter()
        .map(|t| match t.as_str() {
            "User" => "Users/Groups",
            "Application" => "Applications",
            other => other,
        })
        .collect();
    if labels.is_empty() {
        "—".to_string()
    } else {
        labels.join(", ")
    }
}

#[component]
pub(super) fn AppRolesContent(
    signal: Signal<Arc<EnterpriseApplicationDetail>>,
    on_refresh: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let sp_id = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));
    let app_id = Signal::derive(move || signal.with(|d| d.service_principal.app_id.clone()));

    // Bumped after every successful mutation to refetch the live list.
    let reload = RwSignal::new(0_u32);
    let roles_res = LocalResource::new(move || {
        let tenant = tenant.get();
        let sp = sp_id.get();
        let app = app_id.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => {
                    enterprise_application::list_enterprise_app_roles(&t.tenant_id, &sp, &app).await
                }
                None => Ok(AppRolesView {
                    target_kind: "servicePrincipal".into(),
                    roles: Vec::new(),
                }),
            }
        }
    });

    // ---- Add / edit dialog ----
    let dialog_open = RwSignal::new(false);
    let editing_id: RwSignal<Option<String>> = RwSignal::new(None);
    let f_display = RwSignal::new(String::new());
    let f_value = RwSignal::new(String::new());
    let f_desc = RwSignal::new(String::new());
    let f_member_user = RwSignal::new(true);
    let f_member_app = RwSignal::new(false);
    let f_enabled = RwSignal::new(true);
    let upsert_cmd = use_command();

    let open_add = move || {
        editing_id.set(None);
        f_display.set(String::new());
        f_value.set(String::new());
        f_desc.set(String::new());
        f_member_user.set(true);
        f_member_app.set(false);
        f_enabled.set(true);
        upsert_cmd.error.set(None);
        dialog_open.set(true);
    };

    let open_edit = move |r: AppRole| {
        editing_id.set(Some(r.id));
        f_display.set(r.display_name);
        f_value.set(r.value);
        f_desc.set(r.description.unwrap_or_default());
        f_member_user.set(r.allowed_member_types.iter().any(|t| t == "User"));
        f_member_app.set(r.allowed_member_types.iter().any(|t| t == "Application"));
        f_enabled.set(r.is_enabled.unwrap_or(true));
        upsert_cmd.error.set(None);
        dialog_open.set(true);
    };

    let save = move |_| {
        let display = f_display.get().trim().to_string();
        let value = f_value.get().trim().to_string();
        let mut types = Vec::new();
        if f_member_user.get() {
            types.push("User".to_string());
        }
        if f_member_app.get() {
            types.push("Application".to_string());
        }
        if display.is_empty() || value.is_empty() {
            upsert_cmd
                .error
                .set(Some("Display name and value are required.".into()));
            return;
        }
        if types.is_empty() {
            upsert_cmd
                .error
                .set(Some("Select at least one allowed member type.".into()));
            return;
        }
        let desc = {
            let d = f_desc.get().trim().to_string();
            (!d.is_empty()).then_some(d)
        };
        let input = AppRoleInput {
            id: editing_id.get(),
            display_name: display,
            value,
            description: desc,
            allowed_member_types: types,
            is_enabled: f_enabled.get(),
        };
        let created = input.id.is_none();
        let (sp, app) = (sp_id.get(), app_id.get());
        upsert_cmd.run(
            move |()| {
                dialog_open.set(false);
                session.toast_success(if created {
                    "App role added."
                } else {
                    "App role updated."
                });
                reload.update(|n| *n += 1);
                on_refresh.run(());
            },
            move |tenant_id| async move {
                enterprise_application::upsert_enterprise_app_role(&tenant_id, &sp, &app, &input)
                    .await
            },
        );
    };

    // ---- Enable/disable toggle (reuses the upsert with the role's live fields) ----
    let toggle_cmd = use_command();
    let toggle = move |r: AppRole| {
        let (sp, app) = (sp_id.get(), app_id.get());
        let now_enabled = !r.is_enabled.unwrap_or(true);
        let input = AppRoleInput {
            id: Some(r.id.clone()),
            display_name: r.display_name.clone(),
            value: r.value.clone(),
            description: r.description.clone(),
            allowed_member_types: r.allowed_member_types.clone(),
            is_enabled: now_enabled,
        };
        toggle_cmd.run_toast_err(
            move |()| {
                session.toast_success(if now_enabled {
                    "App role enabled."
                } else {
                    "App role disabled."
                });
                reload.update(|n| *n += 1);
                on_refresh.run(());
            },
            move |tenant_id| async move {
                enterprise_application::upsert_enterprise_app_role(&tenant_id, &sp, &app, &input)
                    .await
            },
        );
    };

    // ---- Delete (backend disables an enabled role first) ----
    let delete_cmd = use_command();
    let pending_delete: RwSignal<Option<String>> = RwSignal::new(None);
    let do_delete = move || {
        let Some(id) = pending_delete.get() else {
            return;
        };
        let (sp, app) = (sp_id.get(), app_id.get());
        delete_cmd.run_with(
            move |()| {
                pending_delete.set(None);
                session.toast_success("App role deleted.");
                reload.update(|n| *n += 1);
                on_refresh.run(());
            },
            move |e| {
                pending_delete.set(None);
                session.toast_error(e.message, None);
            },
            move |tenant_id| async move {
                enterprise_application::delete_enterprise_app_role(&tenant_id, &sp, &app, &id).await
            },
        );
    };

    let busy_any = Signal::derive(move || {
        upsert_cmd.busy.get() || toggle_cmd.busy.get() || delete_cmd.busy.get()
    });

    view! {
        <section>
            <header class="row-between">
                <div>
                    <h4>"App roles"</h4>
                    <p class="muted">
                        {move || {
                            roles_res
                                .get()
                                .and_then(|r| r.ok())
                                .map(|v| {
                                    if v.target_kind == "application" {
                                        "Roles are defined on the linked app registration and apply to this enterprise application."
                                    } else {
                                        "Roles this app exposes for users and apps to be assigned to."
                                    }
                                })
                                .unwrap_or(
                                    "Roles this app exposes for users and apps to be assigned to.",
                                )
                        }}
                    </p>
                </div>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| open_add())
                >
                    "+ Add role"
                </Button>
            </header>

            <Suspense fallback=move || {
                view! {
                    <div class="centered-pad">
                        <Spinner
                            size=Signal::derive(|| SpinnerSize::Tiny)
                            label="Loading app roles…"
                        />
                    </div>
                }
            }>
                {move || Suspend::new(async move {
                    match roles_res.await {
                        Err(e) => view! { <Body1 class="form-error">{e.message}</Body1> }.into_any(),
                        Ok(view_model) => {
                            let roles = view_model.roles;
                            if roles.is_empty() {
                                return view! {
                                    <Body1>"No app roles defined. Add one to publish a role."</Body1>
                                }
                                    .into_any();
                            }
                            view! {
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>"Display name"</th>
                                            <th>"Value"</th>
                                            <th>"Allowed members"</th>
                                            <th>"State"</th>
                                            <th></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {roles
                                            .into_iter()
                                            .map(|r| {
                                                let enabled = r.is_enabled.unwrap_or(true);
                                                // A value-less role is the built-in SAML default
                                                // (msiam_access) — surfaced read-only.
                                                let builtin = r.value.trim().is_empty();
                                                let (state_label, badge_class) = if enabled {
                                                    ("Enabled", "badge--ok")
                                                } else {
                                                    ("Disabled", "badge--unknown")
                                                };
                                                let edit_role = r.clone();
                                                let toggle_role = r.clone();
                                                let delete_id = r.id.clone();
                                                let actions = if builtin {
                                                    view! { <span class="muted">"Built-in"</span> }
                                                        .into_any()
                                                } else {
                                                    view! {
                                                        <div class="actions-row">
                                                            <Button
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                disabled=busy_any
                                                                on_click=Box::new(move |_| open_edit(
                                                                    edit_role.clone(),
                                                                ))
                                                            >
                                                                "Edit"
                                                            </Button>
                                                            <Button
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                disabled=busy_any
                                                                on_click=Box::new(move |_| toggle(
                                                                    toggle_role.clone(),
                                                                ))
                                                            >
                                                                {if enabled { "Disable" } else { "Enable" }}
                                                            </Button>
                                                            <Button
                                                                class="button--danger"
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                disabled=busy_any
                                                                on_click=Box::new(move |_| {
                                                                    pending_delete.set(Some(delete_id.clone()))
                                                                })
                                                            >
                                                                "Delete"
                                                            </Button>
                                                        </div>
                                                    }
                                                        .into_any()
                                                };
                                                view! {
                                                    <tr>
                                                        <td>{r.display_name.clone()}</td>
                                                        <td class="mono">{r.value.clone()}</td>
                                                        <td>{member_types_label(&r.allowed_member_types)}</td>
                                                        <td>
                                                            <span class=format!(
                                                                "badge {badge_class}",
                                                            )>{state_label}</span>
                                                        </td>
                                                        <td>{actions}</td>
                                                    </tr>
                                                }
                                            })
                                            .collect_view()}
                                    </tbody>
                                </table>
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>

            // ---- Add/edit dialog ----
            <ModalShell
                open=Signal::derive(move || dialog_open.get())
                title=Signal::derive(move || {
                    if editing_id.get().is_some() {
                        "Edit app role".to_string()
                    } else {
                        "Add an app role".to_string()
                    }
                })
                busy=Signal::derive(move || upsert_cmd.busy.get())
                on_close=Callback::new(move |()| dialog_open.set(false))
                wide=true
            >
                <Field label="Display name">
                    <Input value=f_display placeholder="e.g. Task writers" />
                </Field>
                <Field label="Value">
                    <Input value=f_value placeholder="e.g. Task.Write" />
                </Field>
                <Body1 class="hint">
                    "The value appears in the roles claim. No spaces; it must be unique for this app."
                </Body1>
                <Field label="Description">
                    <Textarea value=f_desc />
                </Field>
                <Field label="Allowed member types">
                    <label class="checkbox-row">
                        <input
                            type="checkbox"
                            prop:checked=move || f_member_user.get()
                            on:change=move |ev| f_member_user.set(event_target_checked(&ev))
                        />
                        " Users/Groups"
                    </label>
                    <label class="checkbox-row">
                        <input
                            type="checkbox"
                            prop:checked=move || f_member_app.get()
                            on:change=move |ev| f_member_app.set(event_target_checked(&ev))
                        />
                        " Applications"
                    </label>
                </Field>
                <label class="checkbox-row">
                    <input
                        type="checkbox"
                        prop:checked=move || f_enabled.get()
                        on:change=move |ev| f_enabled.set(event_target_checked(&ev))
                    />
                    " Enabled — the role can be assigned and appears in tokens"
                </label>
                {move || {
                    upsert_cmd.error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                }}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| dialog_open.set(false))
                        disabled=Signal::derive(move || upsert_cmd.busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(save)
                        disabled=Signal::derive(move || upsert_cmd.busy.get())
                    >
                        {move || {
                            if upsert_cmd.busy.get() {
                                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                    .into_any()
                            } else {
                                view! { "Save" }.into_any()
                            }
                        }}
                    </Button>
                </div>
            </ModalShell>

            // ---- Delete confirm ----
            <ConfirmDialog
                open=Signal::derive(move || pending_delete.with(|p| p.is_some()))
                title="Delete this app role?"
                body="Any users, groups, or apps currently assigned this role lose it, and tokens stop carrying its value. An enabled role is disabled first, then removed."
                confirm_label="Delete"
                busy=Signal::derive(move || delete_cmd.busy.get())
                on_confirm=Callback::new(move |()| do_delete())
                on_close=Callback::new(move |()| pending_delete.set(None))
            />
        </section>
    }
    .into_any()
}
