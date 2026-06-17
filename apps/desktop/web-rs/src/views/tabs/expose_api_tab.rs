//! Expose an API tab — the portal blade for an app registration acting as a
//! resource API: the Application ID URI(s), the delegated scopes the API
//! defines, and the client applications pre-authorized to use them without a
//! consent prompt.
//!
//! Loads live state via `get_expose_api` (these fields aren't on the cached
//! list shape), then each mutation goes through its own command; the backend
//! re-reads live state before every write because Graph full-replaces the
//! `api` arrays. After a successful save the tab refetches itself and bumps
//! the parent detail (the paired SP mirrors the scope list).

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Select, Spinner, SpinnerSize, Textarea};

use crate::bindings::applications::ApplicationDetail;
use crate::bindings::expose_api::{
    self, ExposeApiDto, SetPreAuthorizedAppInput, UpsertApiScopeInput,
};
use crate::components::modal_shell::ModalShell;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;

use azapptoolkit_core::models::OAuth2PermissionScope;

use crate::util::no_tenant;

/// Portal wording for Graph's `permissionScope.type`.
fn consent_label(scope_type: Option<&str>) -> &'static str {
    match scope_type {
        Some("Admin") => "Admins only",
        _ => "Admins and users",
    }
}

#[component]
pub fn ExposeApiTab(
    #[prop(into)] detail: Signal<ApplicationDetail>,
    #[prop(into)] on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let object_id = Signal::derive(move || detail.with(|d| d.application.id.clone()));
    let app_id = Signal::derive(move || detail.with(|d| d.application.app_id.clone()));
    let reload = RwSignal::new(0_u32);

    let state = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let id = object_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            expose_api::get_expose_api(&t.tenant_id, &id).await
        }
    });

    // After a successful save, refresh this tab's own fetch and the parent
    // detail (the paired SP's oauth2PermissionScopes mirror the scope list).
    let on_saved = Callback::new(move |()| {
        reload.update(|n| *n += 1);
        on_changed.run(());
    });

    view! {
        <div class="expose-api-tab">
            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" /> }
            }>
                {move || Suspend::new(async move {
                    match state.await {
                        Ok(dto) => {
                            let id = object_id.get_untracked();
                            let app = app_id.get_untracked();
                            view! {
                                <ExposeApiLoaded object_id=id app_id=app dto=dto on_saved=on_saved />
                            }
                                .into_any()
                        }
                        Err(e) => {
                            view! { <Body1 class="form-error">{e.message}</Body1> }.into_any()
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

#[component]
fn ExposeApiLoaded(
    object_id: String,
    app_id: String,
    dto: ExposeApiDto,
    #[prop(into)] on_saved: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let object_id = StoredValue::new(object_id);
    let uris = StoredValue::new(dto.identifier_uris.clone());
    let scopes = StoredValue::new(dto.scopes.clone());

    // ---- Application ID URI ----
    let uri_open = RwSignal::new(false);
    // Prefill the portal default the first time an App ID URI is set.
    let uri_value = RwSignal::new(if dto.identifier_uris.is_empty() {
        format!("api://{app_id}")
    } else {
        String::new()
    });
    let uri_busy = RwSignal::new(false);
    let uri_error: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_remove_uri: RwSignal<Option<String>> = RwSignal::new(None);
    let uri_removing = RwSignal::new(false);

    let save_uris = move |new_uris: Vec<String>, busy: RwSignal<bool>, done: Callback<()>| {
        if busy.get() {
            return;
        }
        busy.set(true);
        uri_error.set(None);
        let tenant = session.active_tenant.get();
        let id = object_id.get_value();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match expose_api::set_identifier_uris(&t.tenant_id, &id, &new_uris).await {
                Ok(()) => {
                    busy.set(false);
                    session.toast_success("Application ID URIs updated.");
                    done.run(());
                    on_saved.run(());
                }
                Err(e) => {
                    busy.set(false);
                    uri_error.set(Some(e.message));
                }
            }
        });
    };

    let add_uri = move |_| {
        let v = uri_value.get().trim().to_string();
        if v.is_empty() {
            uri_error.set(Some("Enter a URI.".into()));
            return;
        }
        let mut list = uris.get_value();
        if list.iter().any(|u| u.eq_ignore_ascii_case(&v)) {
            uri_error.set(Some("That URI is already set.".into()));
            return;
        }
        list.push(v);
        save_uris(list, uri_busy, Callback::new(move |()| uri_open.set(false)));
    };

    let remove_uri = move |uri: String| {
        let list: Vec<String> = uris.get_value().into_iter().filter(|u| u != &uri).collect();
        save_uris(
            list,
            uri_removing,
            Callback::new(move |()| pending_remove_uri.set(None)),
        );
    };

    // ---- Scopes ----
    let scope_open = RwSignal::new(false);
    let scope_editing_id: RwSignal<Option<String>> = RwSignal::new(None);
    let scope_value = RwSignal::new(String::new());
    let scope_type = RwSignal::new("User".to_string());
    let admin_dn = RwSignal::new(String::new());
    let admin_desc = RwSignal::new(String::new());
    let user_dn = RwSignal::new(String::new());
    let user_desc = RwSignal::new(String::new());
    let scope_enabled = RwSignal::new(true);
    let scope_busy = RwSignal::new(false);
    let scope_error: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_delete_scope: RwSignal<Option<String>> = RwSignal::new(None);
    let deleting_scope = RwSignal::new(false);

    let open_add_scope = move || {
        scope_editing_id.set(None);
        scope_value.set(String::new());
        scope_type.set("User".into());
        admin_dn.set(String::new());
        admin_desc.set(String::new());
        user_dn.set(String::new());
        user_desc.set(String::new());
        scope_enabled.set(true);
        scope_error.set(None);
        scope_open.set(true);
    };

    let open_edit_scope = move |s: OAuth2PermissionScope| {
        scope_editing_id.set(Some(s.id));
        scope_value.set(s.value);
        scope_type.set(s.r#type.unwrap_or_else(|| "User".into()));
        admin_dn.set(s.admin_consent_display_name.unwrap_or_default());
        admin_desc.set(s.admin_consent_description.unwrap_or_default());
        user_dn.set(s.user_consent_display_name.unwrap_or_default());
        user_desc.set(s.user_consent_description.unwrap_or_default());
        scope_enabled.set(s.is_enabled.unwrap_or(true));
        scope_error.set(None);
        scope_open.set(true);
    };

    let save_scope = move |_| {
        if scope_busy.get() {
            return;
        }
        let value = scope_value.get().trim().to_string();
        let dn = admin_dn.get().trim().to_string();
        let desc = admin_desc.get().trim().to_string();
        if value.is_empty() || dn.is_empty() || desc.is_empty() {
            scope_error.set(Some(
                "Scope name, admin consent display name and description are required.".into(),
            ));
            return;
        }
        scope_busy.set(true);
        scope_error.set(None);
        let tenant = session.active_tenant.get();
        let id = object_id.get_value();
        let opt = |sig: RwSignal<String>| {
            let v = sig.get().trim().to_string();
            (!v.is_empty()).then_some(v)
        };
        let input = UpsertApiScopeInput {
            id: scope_editing_id.get(),
            value,
            scope_type: scope_type.get(),
            admin_consent_display_name: dn,
            admin_consent_description: desc,
            user_consent_display_name: opt(user_dn),
            user_consent_description: opt(user_desc),
            is_enabled: scope_enabled.get(),
        };
        let created = input.id.is_none();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                scope_busy.set(false);
                return;
            };
            match expose_api::upsert_api_scope(&t.tenant_id, &id, &input).await {
                Ok(()) => {
                    scope_busy.set(false);
                    scope_open.set(false);
                    session.toast_success(if created {
                        "Scope added."
                    } else {
                        "Scope updated."
                    });
                    on_saved.run(());
                }
                Err(e) => {
                    scope_busy.set(false);
                    scope_error.set(Some(e.message));
                }
            }
        });
    };

    let delete_scope = move |scope_id: String| {
        if deleting_scope.get() {
            return;
        }
        deleting_scope.set(true);
        let tenant = session.active_tenant.get();
        let id = object_id.get_value();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                deleting_scope.set(false);
                return;
            };
            match expose_api::delete_api_scope(&t.tenant_id, &id, &scope_id).await {
                Ok(()) => {
                    deleting_scope.set(false);
                    pending_delete_scope.set(None);
                    session.toast_success("Scope deleted.");
                    on_saved.run(());
                }
                Err(e) => {
                    deleting_scope.set(false);
                    pending_delete_scope.set(None);
                    session.toast_error(e.message, None);
                }
            }
        });
    };

    // ---- Pre-authorized client applications ----
    let pre_open = RwSignal::new(false);
    let pre_editing = RwSignal::new(false);
    let pre_client_id = RwSignal::new(String::new());
    let pre_selected: RwSignal<Vec<String>> = RwSignal::new(Vec::new());
    let pre_busy = RwSignal::new(false);
    let pre_error: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_remove_pre: RwSignal<Option<String>> = RwSignal::new(None);
    let removing_pre = RwSignal::new(false);

    let open_add_pre = move || {
        pre_editing.set(false);
        pre_client_id.set(String::new());
        pre_selected.set(Vec::new());
        pre_error.set(None);
        pre_open.set(true);
    };

    let open_edit_pre = move |client_app_id: String, scope_ids: Vec<String>| {
        pre_editing.set(true);
        pre_client_id.set(client_app_id);
        pre_selected.set(scope_ids);
        pre_error.set(None);
        pre_open.set(true);
    };

    let save_pre = move |_| {
        if pre_busy.get() {
            return;
        }
        let client_app_id = pre_client_id.get().trim().to_string();
        let scope_ids = pre_selected.get();
        if client_app_id.is_empty() {
            pre_error.set(Some("Client ID is required.".into()));
            return;
        }
        if scope_ids.is_empty() {
            pre_error.set(Some("Select at least one scope to authorize.".into()));
            return;
        }
        pre_busy.set(true);
        pre_error.set(None);
        let tenant = session.active_tenant.get();
        let id = object_id.get_value();
        let input = SetPreAuthorizedAppInput {
            client_app_id,
            scope_ids,
        };
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                pre_busy.set(false);
                return;
            };
            match expose_api::set_pre_authorized_app(&t.tenant_id, &id, &input).await {
                Ok(()) => {
                    pre_busy.set(false);
                    pre_open.set(false);
                    session.toast_success("Authorized client application saved.");
                    on_saved.run(());
                }
                Err(e) => {
                    pre_busy.set(false);
                    pre_error.set(Some(e.message));
                }
            }
        });
    };

    let remove_pre = move |client_app_id: String| {
        if removing_pre.get() {
            return;
        }
        removing_pre.set(true);
        let tenant = session.active_tenant.get();
        let id = object_id.get_value();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                removing_pre.set(false);
                return;
            };
            match expose_api::remove_pre_authorized_app(&t.tenant_id, &id, &client_app_id).await {
                Ok(()) => {
                    removing_pre.set(false);
                    pending_remove_pre.set(None);
                    session.toast_success("Authorized client application removed.");
                    on_saved.run(());
                }
                Err(e) => {
                    removing_pre.set(false);
                    pending_remove_pre.set(None);
                    session.toast_error(e.message, None);
                }
            }
        });
    };

    let first_uri = dto.identifier_uris.first().cloned();
    let scope_name_hint_uri = first_uri
        .clone()
        .unwrap_or_else(|| format!("api://{app_id}"));

    view! {
        <div class="expose-api">
            <section>
                <header class="row-between">
                    <strong>"Application ID URI"</strong>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| {
                            uri_error.set(None);
                            uri_open.set(true);
                        })
                    >
                        "+ Add URI"
                    </Button>
                </header>
                <Body1 class="hint">
                    "The globally unique URI clients use to request tokens for this API (the audience). Usually api://{client-id}."
                </Body1>
                {
                    let list = dto.identifier_uris.clone();
                    if list.is_empty() {
                        view! {
                            <Body1>
                                "No Application ID URI is set — clients can't request tokens for this API's scopes until one is added."
                            </Body1>
                        }
                            .into_any()
                    } else {
                        view! {
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>"URI"</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {list
                                        .into_iter()
                                        .map(|uri| {
                                            let uri_click = uri.clone();
                                            view! {
                                                <tr>
                                                    <td class="mono">{uri.clone()}</td>
                                                    <td>
                                                        <Button
                                                            class="button--danger"
                                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                            on_click=Box::new(move |_| {
                                                                uri_error.set(None);
                                                                pending_remove_uri.set(Some(uri_click.clone()))
                                                            })
                                                        >
                                                            "Remove"
                                                        </Button>
                                                    </td>
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
            </section>
            <section>
                <header class="row-between">
                    <strong>
                        {format!("Scopes defined by this API ({})", dto.scopes.len())}
                    </strong>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| open_add_scope())
                    >
                        "+ Add a scope"
                    </Button>
                </header>
                <Body1 class="hint">
                    "Delegated permissions client applications can request when calling this API on a signed-in user's behalf."
                </Body1>
                {
                    let list = dto.scopes.clone();
                    if list.is_empty() {
                        view! { <Body1>"No scopes defined."</Body1> }.into_any()
                    } else {
                        view! {
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>"Scope name"</th>
                                        <th>"Who can consent"</th>
                                        <th>"Admin consent display name"</th>
                                        <th>"State"</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {list
                                        .into_iter()
                                        .map(|s| {
                                            let enabled = s.is_enabled.unwrap_or(true);
                                            let (state_label, badge_class) = if enabled {
                                                ("Enabled", "badge--ok")
                                            } else {
                                                ("Disabled", "badge--unknown")
                                            };
                                            let edit_scope = s.clone();
                                            let delete_id = s.id.clone();
                                            view! {
                                                <tr>
                                                    <td class="mono">{s.value.clone()}</td>
                                                    <td>{consent_label(s.r#type.as_deref())}</td>
                                                    <td>
                                                        {s
                                                            .admin_consent_display_name
                                                            .clone()
                                                            .unwrap_or_else(|| "—".into())}
                                                    </td>
                                                    <td>
                                                        <span class=format!(
                                                            "badge {badge_class}",
                                                        )>{state_label}</span>
                                                    </td>
                                                    <td>
                                                        <div class="actions-row">
                                                            <Button
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                on_click=Box::new(move |_| open_edit_scope(
                                                                    edit_scope.clone(),
                                                                ))
                                                            >
                                                                "Edit"
                                                            </Button>
                                                            <Button
                                                                class="button--danger"
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                on_click=Box::new(move |_| {
                                                                    pending_delete_scope.set(Some(delete_id.clone()))
                                                                })
                                                            >
                                                                "Delete"
                                                            </Button>
                                                        </div>
                                                    </td>
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
            </section>
            <section>
                <header class="row-between">
                    <strong>
                        {format!(
                            "Authorized client applications ({})",
                            dto.pre_authorized_applications.len(),
                        )}
                    </strong>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        disabled=Signal::derive(move || scopes.get_value().is_empty())
                        on_click=Box::new(move |_| open_add_pre())
                    >
                        "+ Add a client application"
                    </Button>
                </header>
                <Body1 class="hint">
                    "Pre-authorized clients can request the selected scopes without the user being asked to consent. Only authorize clients you trust."
                </Body1>
                {
                    let list = dto.pre_authorized_applications.clone();
                    let by_id: std::collections::HashMap<String, String> = dto
                        .scopes
                        .iter()
                        .map(|s| (s.id.clone(), s.value.clone()))
                        .collect();
                    if list.is_empty() {
                        view! { <Body1>"No authorized client applications."</Body1> }.into_any()
                    } else {
                        view! {
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>"Client ID"</th>
                                        <th>"Authorized scopes"</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {list
                                        .into_iter()
                                        .map(|p| {
                                            let scope_names = p
                                                .delegated_permission_ids
                                                .iter()
                                                .map(|id| {
                                                    by_id
                                                        .get(id)
                                                        .cloned()
                                                        .unwrap_or_else(|| format!(
                                                            "{}…",
                                                            id.chars().take(8).collect::<String>(),
                                                        ))
                                                })
                                                .collect::<Vec<_>>()
                                                .join(", ");
                                            let edit_id = p.app_id.clone();
                                            let edit_scopes = p.delegated_permission_ids.clone();
                                            let remove_id = p.app_id.clone();
                                            view! {
                                                <tr>
                                                    <td class="mono">{p.app_id.clone()}</td>
                                                    <td>{scope_names}</td>
                                                    <td>
                                                        <div class="actions-row">
                                                            <Button
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                on_click=Box::new(move |_| open_edit_pre(
                                                                    edit_id.clone(),
                                                                    edit_scopes.clone(),
                                                                ))
                                                            >
                                                                "Edit"
                                                            </Button>
                                                            <Button
                                                                class="button--danger"
                                                                appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                on_click=Box::new(move |_| {
                                                                    pending_remove_pre.set(Some(remove_id.clone()))
                                                                })
                                                            >
                                                                "Remove"
                                                            </Button>
                                                        </div>
                                                    </td>
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
            </section>

            // ---- Add-URI dialog ----
            <ModalShell
                open=Signal::derive(move || uri_open.get())
                title="Add an Application ID URI"
                busy=Signal::derive(move || uri_busy.get())
                on_close=Callback::new(move |()| uri_open.set(false))
            >
                <Body1 class="hint">
                    "Use api://{client-id} (always accepted), or an https URI on a verified domain of this tenant."
                </Body1>
                <Field label="Application ID URI">
                    <Input value=uri_value />
                </Field>
                {move || {
                    uri_error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                }}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| uri_open.set(false))
                        disabled=Signal::derive(move || uri_busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(add_uri)
                        disabled=Signal::derive(move || uri_busy.get())
                    >
                        {move || {
                            if uri_busy.get() {
                                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                    .into_any()
                            } else {
                                view! { "Save" }.into_any()
                            }
                        }}
                    </Button>
                </div>
            </ModalShell>

            // ---- Add/edit scope dialog ----
            <ModalShell
                open=Signal::derive(move || scope_open.get())
                title=Signal::derive(move || {
                    if scope_editing_id.get().is_some() {
                        "Edit scope".to_string()
                    } else {
                        "Add a scope".to_string()
                    }
                })
                busy=Signal::derive(move || scope_busy.get())
                on_close=Callback::new(move |()| scope_open.set(false))
                wide=true
            >
                <Field label="Scope name">
                    <Input value=scope_value placeholder="e.g. Files.Read" />
                </Field>
                {
                    let hint_uri = scope_name_hint_uri.clone();
                    view! {
                        <Body1 class="hint mono">
                            {move || format!("{hint_uri}/{}", scope_value.get())}
                        </Body1>
                    }
                }
                <Field label="Who can consent">
                    <Select value=scope_type>
                        <option value="User">"Admins and users"</option>
                        <option value="Admin">"Admins only"</option>
                    </Select>
                </Field>
                <Field label="Admin consent display name">
                    <Input value=admin_dn placeholder="e.g. Read files" />
                </Field>
                <Field label="Admin consent description">
                    <Textarea value=admin_desc />
                </Field>
                <Field label="User consent display name (optional)">
                    <Input value=user_dn />
                </Field>
                <Field label="User consent description (optional)">
                    <Textarea value=user_desc />
                </Field>
                <label class="checkbox-row">
                    <input
                        type="checkbox"
                        prop:checked=move || scope_enabled.get()
                        on:change=move |ev| scope_enabled.set(event_target_checked(&ev))
                    />
                    " Enabled — clients can request this scope"
                </label>
                {move || {
                    scope_error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                }}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| scope_open.set(false))
                        disabled=Signal::derive(move || scope_busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(save_scope)
                        disabled=Signal::derive(move || scope_busy.get())
                    >
                        {move || {
                            if scope_busy.get() {
                                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                    .into_any()
                            } else {
                                view! { "Save" }.into_any()
                            }
                        }}
                    </Button>
                </div>
            </ModalShell>

            // ---- Add/edit pre-authorized client dialog ----
            <ModalShell
                open=Signal::derive(move || pre_open.get())
                title=Signal::derive(move || {
                    if pre_editing.get() {
                        "Edit authorized client application".to_string()
                    } else {
                        "Add an authorized client application".to_string()
                    }
                })
                busy=Signal::derive(move || pre_busy.get())
                on_close=Callback::new(move |()| pre_open.set(false))
            >
                {move || {
                    if pre_editing.get() {
                        view! { <Body1 class="mono">{pre_client_id.get()}</Body1> }.into_any()
                    } else {
                        view! {
                            <Field label="Client ID (application ID of the client app)">
                                <Input
                                    value=pre_client_id
                                    placeholder="00000000-0000-0000-0000-000000000000"
                                />
                            </Field>
                        }
                            .into_any()
                    }
                }}
                <strong>"Authorized scopes"</strong>
                {scopes
                    .get_value()
                    .into_iter()
                    .map(|s| {
                        let id_checked = s.id.clone();
                        let id_toggle = s.id.clone();
                        let label = if s.is_enabled.unwrap_or(true) {
                            s.value.clone()
                        } else {
                            format!("{} (disabled)", s.value)
                        };
                        view! {
                            <label class="checkbox-row">
                                <input
                                    type="checkbox"
                                    prop:checked=move || {
                                        pre_selected.with(|sel| sel.contains(&id_checked))
                                    }
                                    on:change=move |_| {
                                        pre_selected
                                            .update(|sel| {
                                                if let Some(pos) = sel.iter().position(|x| x == &id_toggle) {
                                                    sel.remove(pos);
                                                } else {
                                                    sel.push(id_toggle.clone());
                                                }
                                            })
                                    }
                                />
                                " "
                                <span class="mono">{label}</span>
                            </label>
                        }
                    })
                    .collect_view()}
                {move || {
                    pre_error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                }}
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| pre_open.set(false))
                        disabled=Signal::derive(move || pre_busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(save_pre)
                        disabled=Signal::derive(move || pre_busy.get())
                    >
                        {move || {
                            if pre_busy.get() {
                                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                    .into_any()
                            } else {
                                view! { "Save" }.into_any()
                            }
                        }}
                    </Button>
                </div>
            </ModalShell>

            <ConfirmDialog
                open=Signal::derive(move || pending_remove_uri.with(|p| p.is_some()))
                title="Remove this Application ID URI?"
                body="Clients requesting tokens with this URI as the audience will start failing immediately."
                confirm_label="Remove"
                busy=Signal::derive(move || uri_removing.get())
                error=Signal::derive(move || uri_error.get())
                on_confirm=Callback::new(move |()| {
                    if let Some(uri) = pending_remove_uri.get() {
                        remove_uri(uri);
                    }
                })
                on_close=Callback::new(move |()| pending_remove_uri.set(None))
            />
            <ConfirmDialog
                open=Signal::derive(move || pending_delete_scope.with(|p| p.is_some()))
                title="Delete this scope?"
                body="Any client or consent grant using this scope breaks immediately. The scope is disabled first, then removed, and it is stripped from authorized client applications. This cannot be undone."
                confirm_label="Delete"
                busy=Signal::derive(move || deleting_scope.get())
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_delete_scope.get() {
                        delete_scope(id);
                    }
                })
                on_close=Callback::new(move |()| pending_delete_scope.set(None))
            />
            <ConfirmDialog
                open=Signal::derive(move || pending_remove_pre.with(|p| p.is_some()))
                title="Remove this authorized client application?"
                body="The client can still request these scopes, but users will be prompted to consent again."
                confirm_label="Remove"
                busy=Signal::derive(move || removing_pre.get())
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_remove_pre.get() {
                        remove_pre(id);
                    }
                })
                on_close=Callback::new(move |()| pending_remove_pre.set(None))
            />
        </div>
    }
}
