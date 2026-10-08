//! Collapsible "SharePoint item access" section: the libraries, folders and
//! files an app was granted under a `*.SelectedOperations.Selected` permission,
//! each with what SharePoint says about it now, plus add, remove and track.
//!
//! Graph can't list an app's item grants (only who holds access to one
//! resource), so the list is the app's own record: one tag per grant on the app
//! registration, written whenever a grant lands through azapptoolkit. The copy
//! says so, and a row whose status can't be read is never shown as "not
//! granted". Callers render this only for an app registration (the record lives
//! on it) that declares or holds a permission
//! `azapptoolkit_core::scoping::is_scoped_sharepoint_item_resource_permission`
//! accepts.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::sharepoint::{AppItemScopeDto, ItemScopeRef, ItemScopeStatus};
use crate::bindings::{auth, sharepoint};
use crate::components::collapsible_scoping_section::CollapsibleScopingSection;
use crate::components::ui::{Callout, DataTable, DetailLoadError, FormError};
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::util::no_tenant;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use azapptoolkit_core::scoping::{
    MICROSOFT_GRAPH_APP_ID, SelectedScopeLevel, selected_scope_accepts, selected_scope_level_for,
};

/// What a row's type column says.
fn type_label(entry: &AppItemScopeDto) -> &'static str {
    match entry.scope.level {
        SelectedScopeLevel::List => "Library or list",
        SelectedScopeLevel::File if entry.is_folder => "Folder",
        SelectedScopeLevel::File => "File",
        SelectedScopeLevel::ListItem => "List item",
        SelectedScopeLevel::Site => "Site",
    }
}

/// What a row's access column says.
fn status_label(status: &ItemScopeStatus) -> String {
    match status {
        ItemScopeStatus::Granted { roles, .. } => roles.join(", "),
        ItemScopeStatus::NotGranted => "Not granted (removed outside azapptoolkit)".into(),
        ItemScopeStatus::Missing => "Not found (deleted, or moved to another library)".into(),
        ItemScopeStatus::Unreadable { message } => format!("Couldn't check: {message}"),
    }
}

#[component]
pub fn SharePointItemScopesSection(
    /// The app registration's object id: the record lives in its tags.
    #[prop(into)]
    object_id: Signal<String>,
    /// The paired service principal's object id; empty when the app has none
    /// in this tenant, which leaves nothing to grant the access to.
    #[prop(into)]
    sp_object_id: Signal<String>,
    /// appId (client id): the grants' `grantedToV2.application.id`.
    #[prop(into)]
    app_id: Signal<String>,
    #[prop(into)] app_display_name: Signal<String>,
    /// The item-level Selected permissions the app declares or holds. A grant
    /// rides the first one whose level accepts the URL; the backend checks.
    #[prop(into)]
    permission_values: Signal<Vec<String>>,
    /// Called when a grant also had to declare or assign the permission, which
    /// changes the permissions table above.
    on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let open = RwSignal::new(false);
    let url = RwSignal::new(String::new());
    let cmd = use_command().with_consent_feature("sharepoint");
    let reload = RwSignal::new(0_u32);
    let needs_consent = RwSignal::new(false);
    let warnings: RwSignal<Vec<String>> = RwSignal::new(Vec::new());
    let done: RwSignal<Option<String>> = RwSignal::new(None);
    // (scope, permission id, label) of the grant awaiting the revoke confirm.
    let pending_remove: RwSignal<Option<(ItemScopeRef, String, String)>> = RwSignal::new(None);

    // Loads only while open: collapsed, the section costs no Graph call.
    let scopes = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let is_open = open.get();
        let _ = reload.get();
        let object_id = object_id.get();
        let app_id = app_id.get();
        async move {
            if !is_open {
                return Ok(None);
            }
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            let r = sharepoint::list_app_item_scopes(&t.tenant_id, &object_id, &app_id).await;
            match &r {
                Ok(_) => needs_consent.set(false),
                Err(e) if e.is_consent_required() => needs_consent.set(true),
                Err(_) => {}
            }
            r.map(Some)
        }
    });

    let fail = move |e: azapptoolkit_dto::UiError| {
        if e.is_consent_required() {
            needs_consent.set(true);
        }
        cmd.error.set(Some(e.message));
    };

    let grant_consent = move |_| {
        cmd.run(
            move |()| {
                needs_consent.set(false);
                reload.update(|n| *n += 1);
            },
            move |tenant_id| async move {
                auth::request_scope_consent(&tenant_id, "sharepoint").await
            },
        );
    };

    let take_url = move || {
        let target = url.get().trim().to_string();
        if target.is_empty() {
            cmd.error.set(Some(
                "Enter the URL of a SharePoint library, folder or file.".into(),
            ));
            return None;
        }
        cmd.error.set(None);
        warnings.set(Vec::new());
        done.set(None);
        Some(target)
    };

    let do_grant = move |role: &'static str| {
        let Some(target) = take_url() else {
            return;
        };
        let sp_object_id = sp_object_id.get();
        if sp_object_id.is_empty() {
            cmd.error.set(Some(
                "This app has no enterprise application (service principal) in this tenant, so there is nothing to grant the access to.".into(),
            ));
            return;
        }
        let values = permission_values.get();
        if values.is_empty() {
            return;
        }
        let (object_id, app_id, app_name) = (object_id.get(), app_id.get(), app_display_name.get());
        cmd.run_with(
            move |r: sharepoint::SelectedItemScopeResult| {
                needs_consent.set(false);
                url.set(String::new());
                let changed_table = r.declared_permission || r.granted_role_added;
                let granted = r.granted.len();
                warnings.set(r.warnings);
                if granted > 0 {
                    done.set(Some(format!("Granted {role} access.")));
                }
                if changed_table {
                    // The table above changes, and its reload rebuilds this
                    // section, so the outcome also goes out as a toast.
                    if granted > 0 {
                        session.toast_success(format!("Granted {role} access."));
                    }
                    on_changed.try_run(());
                } else {
                    reload.update(|n| *n += 1);
                }
            },
            fail,
            move |tenant_id| async move {
                // Resolve first, so the grant rides the permission whose level
                // reaches this URL when the app holds more than one.
                let resolved = sharepoint::resolve_sharepoint_resource(&tenant_id, &target).await?;
                let permission_value = values
                    .iter()
                    .find(|v| {
                        selected_scope_level_for(Some(MICROSOFT_GRAPH_APP_ID), v)
                            .is_some_and(|level| selected_scope_accepts(level, resolved.level))
                    })
                    .unwrap_or(&values[0])
                    .clone();
                sharepoint::grant_selected_item_access(
                    &tenant_id,
                    &sp_object_id,
                    Some(&object_id),
                    &app_id,
                    &app_name,
                    &permission_value,
                    &[target],
                    role,
                )
                .await
            },
        );
    };

    let do_track = move |_| {
        let Some(target) = take_url() else {
            return;
        };
        let object_id = object_id.get();
        cmd.run_with(
            move |_| {
                url.set(String::new());
                done.set(Some(
                    "Added to the list. Its access is checked below.".into(),
                ));
                reload.update(|n| *n += 1);
            },
            fail,
            move |tenant_id| async move {
                sharepoint::track_app_item_scope(&tenant_id, &object_id, &target).await
            },
        );
    };

    // Revokes (with a permission id) or just forgets (without one) a record.
    let do_remove = move |scope: ItemScopeRef, permission_id: Option<String>| {
        cmd.error.set(None);
        done.set(None);
        let (object_id, app_id) = (object_id.get(), app_id.get());
        cmd.run_with(
            move |()| reload.update(|n| *n += 1),
            fail,
            move |tenant_id| async move {
                sharepoint::remove_app_item_scope(
                    &tenant_id,
                    &object_id,
                    &app_id,
                    &scope,
                    permission_id.as_deref(),
                )
                .await
            },
        );
    };

    view! {
        <CollapsibleScopingSection
            title="SharePoint item access"
            capability_key="sharepoint_selected_items"
            open=open
        >
            <Body1>
                "The libraries, folders and files this app can reach under a Lists, ListItems or Files .SelectedOperations.Selected permission, with what SharePoint says about each now. SharePoint can't list an app's item grants, so only grants made through azapptoolkit, or tracked below, appear here."
            </Body1>
            {move || {
                needs_consent
                    .get()
                    .then(|| {
                        view! {
                            <Callout tone="warn">
                                "Managing item access needs the Sites.FullControl.All admin permission. Grant consent to continue (you must be a SharePoint or Global administrator)."
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(grant_consent)
                                        disabled=Signal::derive(move || cmd.busy.get())
                                    >
                                        "Grant consent"
                                    </Button>
                                </div>
                            </Callout>
                        }
                    })
            }}
            <Suspense fallback=move || {
                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" /> }
            }>
                {move || Suspend::new(async move {
                    match scopes.await {
                        Ok(None) => ().into_any(),
                        Ok(Some(list)) => {
                            let malformed = list.malformed;
                            view! {
                                <DataTable
                                    headers=vec!["Resource", "Type", "Access", ""]
                                    rows=list.entries
                                    empty_message="No libraries, folders or files recorded for this app. Grants made before this version, in the Permission Tester or outside azapptoolkit aren't listed until you track them below."
                                    row=move |entry: AppItemScopeDto| {
                                        let kind = type_label(&entry);
                                        let access = status_label(&entry.status);
                                        let name = entry
                                            .name
                                            .clone()
                                            .unwrap_or_else(|| "Unnamed".to_string());
                                        let location = entry.web_url.clone();
                                        let scope = entry.scope.clone();
                                        let action = match entry.status {
                                            ItemScopeStatus::Granted { permission_id, .. } => {
                                                let label = format!("{name} ({access})");
                                                let aria = format!("Remove access to {name}");
                                                view! {
                                                    <Button
                                                        class="button--danger"
                                                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                        attr:aria-label=aria
                                                        disabled=Signal::derive(move || cmd.busy.get())
                                                        on_click=Box::new(move |_| {
                                                            pending_remove
                                                                .set(
                                                                    Some((
                                                                        scope.clone(),
                                                                        permission_id.clone(),
                                                                        label.clone(),
                                                                    )),
                                                                )
                                                        })
                                                    >
                                                        "Remove"
                                                    </Button>
                                                }
                                                    .into_any()
                                            }
                                            _ => {
                                                let aria = format!("Forget {name}");
                                                view! {
                                                    <Button
                                                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                        attr:aria-label=aria
                                                        disabled=Signal::derive(move || cmd.busy.get())
                                                        on_click=Box::new(move |_| do_remove(scope.clone(), None))
                                                    >
                                                        "Forget"
                                                    </Button>
                                                }
                                                    .into_any()
                                            }
                                        };
                                        view! {
                                            <tr>
                                                <td class="permission-cell">
                                                    <div>{name}</div>
                                                    {location
                                                        .map(|l| view! { <div class="mono muted">{l}</div> })}
                                                </td>
                                                <td class="cell-mid">{kind}</td>
                                                <td class="cell-mid">{access}</td>
                                                <td class="cell-mid">{action}</td>
                                            </tr>
                                        }
                                            .into_any()
                                    }
                                />
                                {(malformed > 0)
                                    .then(|| {
                                        view! {
                                            <Body1 class="hint">
                                                {format!(
                                                    "{malformed} record tag(s) on this app are not valid and were ignored.",
                                                )}
                                            </Body1>
                                        }
                                    })}
                            }
                                .into_any()
                        }
                        // Consent is surfaced by the banner above.
                        Err(e) if e.is_consent_required() => ().into_any(),
                        Err(e) => {
                            view! {
                                <DetailLoadError
                                    error=e
                                    on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                />
                            }
                                .into_any()
                        }
                    }
                })}
            </Suspense>
            <hr />
            <strong>"Add a library, folder or file"</strong>
            <Field label="SharePoint URL">
                <Input
                    value=url
                    placeholder="https://contoso.sharepoint.com/sites/Finance/Shared Documents/2026"
                />
            </Field>
            <div class="actions-row">
                // Read is the Primary, last of the grant pair: the emphasized
                // default must not be the broader role.
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(move |_| do_grant("write"))
                    disabled=Signal::derive(move || cmd.busy.get())
                >
                    "Grant write"
                </Button>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| do_grant("read"))
                    disabled=Signal::derive(move || cmd.busy.get())
                >
                    "Grant read"
                </Button>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(do_track)
                    disabled=Signal::derive(move || cmd.busy.get())
                >
                    "Track existing grant"
                </Button>
                {move || {
                    cmd.busy
                        .get()
                        .then(|| view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> })
                }}
            </div>
            {move || cmd.error.get().map(|e| view! { <FormError>{e}</FormError> })}
            {move || done.get().map(|d| view! { <Callout tone="ok">{d}</Callout> })}
            {move || {
                let list = warnings.get();
                (!list.is_empty())
                    .then(|| {
                        view! {
                            <Callout tone="warn">
                                <ul>
                                    {list.into_iter().map(|w| view! { <li>{w}</li> }).collect_view()}
                                </ul>
                            </Callout>
                        }
                    })
            }}
            <Body1 class="hint">
                "Granting breaks permission inheritance on the target. To change a role, remove the access and grant it again with the other role."
            </Body1>
            <ConfirmDialog
                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                title="Remove this access?"
                body="This app immediately loses its access to this library, folder or file, and it leaves this list. The access can be granted again from this section."
                subject=Signal::derive(move || {
                    pending_remove
                        .with(|p| p.as_ref().map(|(_, _, label)| label.clone()))
                        .unwrap_or_default()
                })
                confirm_label="Remove"
                busy=cmd.busy
                on_confirm=Callback::new(move |()| {
                    if let Some((scope, permission_id, _)) = pending_remove.get() {
                        pending_remove.set(None);
                        do_remove(scope, Some(permission_id));
                    }
                })
                on_close=Callback::new(move |()| pending_remove.set(None))
            />
        </CollapsibleScopingSection>
    }
}
