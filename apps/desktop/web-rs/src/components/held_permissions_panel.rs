//! Shared rendering of the application permissions a service principal **holds**
//! — its granted `appRoleAssignments`. A managed identity and an enterprise
//! application's service principal are both service principals with the same
//! `AppRoleGrantDto` grants, so the table, the over-privilege banner, the risk
//! badges, and the effective-scope column are identical; only the data fetch and
//! the revoke / scope flows differ, and those are the caller's via callbacks.
//!
//! This is **pure presentation**: the caller resolves the grants and the
//! effective mailbox-scope map and passes them in, so this never re-decides
//! scope resolution (the [`MailPermissionScope`] arrives already resolved). It
//! does **not** own the inline scope panel — in the managed-identity view that
//! panel is shared with the grant flow — so a row's "Scope…" action just emits
//! a [`PickerSelection`] for the permission and the caller opens its own panel.

use std::collections::HashMap;

use azapptoolkit_core::audit::{classify_app_permission_risk, MailPermissionScope};
use azapptoolkit_dto::managed_identity::AppRoleGrantDto;
use azapptoolkit_dto::permissions::PermissionKind;
use leptos::prelude::*;

use crate::components::icon::IconName;
use crate::components::permission_picker::{PickerSelection, MICROSOFT_GRAPH_APP_ID};
use crate::components::scope_badge::{
    app_permission_risk_badge, is_sharepoint_orgwide, permission_scope_cell,
};
use crate::components::ui::{DataTable, IconButton};

/// Whether an already-held permission can be restricted in place *per row* (and so
/// should offer a "Scope…" action): an org-wide `Sites.*` (excluding
/// `Sites.Selected`, which is already scoped). Mail/calendar/contacts are
/// deliberately excluded — Exchange RBAC scoping is **app-wide** (a single
/// management scope binds the whole principal's mail roles, not one permission),
/// so it's driven by the app-wide "Exchange scoping" section, never a per-row
/// button. Mirrors the per-row `existing_scope_kind_for` / `row_scope_kind`
/// restrict classifiers.
fn is_held_scopable(value: &str) -> bool {
    is_sharepoint_orgwide(value)
}

#[component]
pub fn HeldPermissionsPanel(
    /// The resolved held grants (the caller awaits its own resource).
    permissions: Vec<AppRoleGrantDto>,
    /// Effective mailbox scope per permission value, resolved by the caller.
    /// Empty when scoping wasn't resolved; only consulted if `show_scope_column`.
    #[prop(optional)]
    scope_map: HashMap<String, MailPermissionScope>,
    /// Show the "Scope" column. Off where the caller hasn't resolved scoping.
    #[prop(optional)]
    show_scope_column: bool,
    /// Revoke a held grant by its `assignment_id`. When set, a revoke action is
    /// rendered per row.
    #[prop(optional, into)]
    on_revoke: Option<Callback<String>>,
    /// Restrict an already-held org-wide permission. When set, a "Scope…" action
    /// is rendered for held-scopable permissions; the caller opens its own scope
    /// panel for the emitted [`PickerSelection`] (a held-scopable permission is
    /// always a Microsoft Graph `Sites.*` application role).
    #[prop(optional, into)]
    on_scope: Option<Callback<PickerSelection>>,
    /// When true, the per-row revoke/scope actions are disabled — the caller
    /// sets this while a mutation it owns is in flight, so a second click can't
    /// fire a duplicate revoke/scope (and the greyed buttons signal "in
    /// progress" instead of silently no-op'ing). Defaults to a never-busy
    /// signal when the caller renders the panel read-only.
    #[prop(optional, into)]
    busy: Signal<bool>,
) -> impl IntoView {
    // Over-privilege banner over the granted values.
    let values: Vec<String> = permissions
        .iter()
        .filter_map(|p| p.app_role_value.clone())
        .collect();
    let (high, medium) = classify_app_permission_risk(&values);
    let banner = (!high.is_empty() || !medium.is_empty()).then(|| {
        let (cls, msg) = if !high.is_empty() {
            (
                "alert alert--warn",
                format!(
                    "Holds {} high-risk application permission(s): {}",
                    high.len(),
                    high.join(", "),
                ),
            )
        } else {
            (
                "alert",
                format!(
                    "Holds {} medium-risk application permission(s): {}",
                    medium.len(),
                    medium.join(", "),
                ),
            )
        };
        view! { <div class=cls>{msg}</div> }
    });

    let has_actions = on_revoke.is_some() || on_scope.is_some();
    let mut headers = vec!["Resource", "Permission"];
    if show_scope_column {
        headers.push("Scope");
    }
    if has_actions {
        headers.push("");
    }

    let row = move |p: AppRoleGrantDto| -> AnyView {
        let res = p
            .resource_display_name
            .unwrap_or_else(|| p.resource_id.clone());
        let app_role_id = p.app_role_id.clone();
        let value = p.app_role_value.clone();
        let perm = value.clone().unwrap_or_else(|| app_role_id.clone());
        let risk = value.as_deref().map(app_permission_risk_badge);
        let scope = value.as_deref().and_then(|v| scope_map.get(v).cloned());
        let scope_value = value.clone();
        let assignment_id = p.assignment_id.clone();
        let scope_btn = on_scope.and_then(|cb| {
            let v = value.clone()?;
            is_held_scopable(&v).then(|| {
                // Held-scopable ⇒ a Microsoft Graph `Sites.*` application role,
                // so the selection is fully determined here.
                let sel = PickerSelection {
                    resource_app_id: MICROSOFT_GRAPH_APP_ID.to_string(),
                    kind: PermissionKind::Application,
                    permission_id: app_role_id.clone(),
                    permission_value: v.clone(),
                };
                view! {
                    <IconButton
                        icon=IconName::Filter
                        aria_label="Scope this permission".to_string()
                        title="Scope…".to_string()
                        disabled=busy
                        on_click=Callback::new(move |_| cb.run(sel.clone()))
                    />
                }
            })
        });
        let revoke_btn = on_revoke.map(|cb| {
            let aid = assignment_id.clone();
            view! {
                <IconButton
                    icon=IconName::Trash
                    aria_label="Revoke permission".to_string()
                    title="Revoke".to_string()
                    class="button--danger".to_string()
                    disabled=busy
                    on_click=Callback::new(move |_| cb.run(aid.clone()))
                />
            }
        });
        view! {
            <tr>
                <td>{res}</td>
                <td>
                    <span class="mono">{perm}</span>
                    {risk}
                </td>
                {show_scope_column
                    .then(|| {
                        view! {
                            <td class="cell-mid">
                                // This panel only receives the resolved map, so it can't
                                // distinguish in-flight from failed — no loading state here.
                                {permission_scope_cell(scope_value.as_deref(), scope, true, false)}
                            </td>
                        }
                    })}
                {has_actions
                    .then(|| {
                        view! {
                            <td class="cell-mid">
                                <div class="cell-actions">{scope_btn}{revoke_btn}</div>
                            </td>
                        }
                    })}
            </tr>
        }
        .into_any()
    };

    view! {
        {banner}
        <DataTable
            headers=headers
            rows=permissions
            empty_message="This identity holds no application permissions."
            row=row
        />
    }
    .into_any()
}
