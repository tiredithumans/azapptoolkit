//! Searchable picker for selecting one or more Application or Delegated
//! permissions. The resource dropdown is the bundled directory (`appId` +
//! name); the permissions for the selected resource — and the per-resource
//! counts shown in the dropdown — are resolved live from Microsoft Graph. The
//! picker is presentation-only — the parent owns the selection (the "cart")
//! and the eventual Tauri grant call: each row is a checkbox that emits a
//! toggle, and the parent renders the running cart and the Grant action.

use std::collections::HashMap;

use azapptoolkit_core::audit::{
    downgrade_alternatives, is_risky_delegated_scope, least_privilege_alternative_for,
};
use azapptoolkit_core::scoping::{
    SP_FILES_SELECTED, SP_LIST_ITEMS_SELECTED, SP_LISTS_SELECTED, SP_SITES_SELECTED,
    is_sharepoint_orgwide,
};
use leptos::prelude::*;
use thaw::{Body1, Input};

use crate::bindings::permissions::{
    self, CatalogResourceSummary, PermissionKind, ResourcePermissions,
};
use crate::components::scope_badge::app_permission_risk_badge;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{Badge, Card, DetailLoadError, TabBar, TabBarItem};
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;

// Microsoft Graph's first-party app id — the natural default for both the App
// Registration and Managed Identity grant flows. Re-exported from its one
// definition in `azapptoolkit_core::scoping`, never re-spelled here.
pub use azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerMode {
    /// Managed identities only support Application permissions. Hides the
    /// Application/Delegated tab strip and filters to `app_roles` whose
    /// `allowed_member_types` contain `"Application"`.
    ApplicationOnly,
    /// App Registrations grant both kinds — show the tab strip.
    AppAndDelegated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PickerSelection {
    pub resource_app_id: String,
    pub kind: PermissionKind,
    pub permission_id: String,
    pub permission_value: String,
}

#[component]
pub fn PermissionPicker(
    #[prop(into)] tenant_id: Signal<Option<String>>,
    mode: PickerMode,
    /// The current selection ("cart"), owned by the parent. A row renders
    /// checked when it appears here.
    #[prop(into)]
    selected: Signal<Vec<PickerSelection>>,
    /// Add/remove a permission from the selection (the parent flips it).
    on_toggle: Callback<PickerSelection>,
) -> impl IntoView {
    let resource_app_id = RwSignal::new(MICROSOFT_GRAPH_APP_ID.to_string());
    let filter = RwSignal::new(String::new());
    // Debounce the filter that drives the (heavy) permission-list rebuild.
    // Microsoft Graph alone exposes ~400 application + ~200 delegated
    // permissions, so re-running the Suspense closure on every keystroke
    // rebuilt that entire `<li>` list (with per-row risk/scope/downgrade hints)
    // each character. The raw `filter` still backs the responsive <Input>;
    // only the list re-renders on the settled value — same 300ms the App Reg /
    // Enterprise / MI / Audit list filters use.
    let filter_debounced = use_debounced(filter.into(), LIST_FILTER_DEBOUNCE_MS);
    let active_kind = RwSignal::new("application".to_string());

    let resources: RwSignal<Vec<CatalogResourceSummary>> = RwSignal::new(Vec::new());
    Effect::new(move |_| {
        leptos::task::spawn_local(async move {
            // A failed catalog load leaves the picker empty instead of panicking
            // the whole WASM frontend; reopening the picker retries.
            if let Ok(list) = permissions::list_catalog_resources().await {
                resources.set(list);
            }
        });
    });

    // Live per-resource (app, delegated) counts for the dropdown labels,
    // keyed by appId. Fetched once the tenant is known (each resource SP is
    // resolved server-side in parallel and cached), folded into the label
    // when present so names render instantly and counts fill in after.
    let counts: RwSignal<HashMap<String, (usize, usize)>> = RwSignal::new(HashMap::new());
    Effect::new(move |_| {
        let Some(tenant) = tenant_id.get() else {
            return;
        };
        leptos::task::spawn_local(async move {
            if let Ok(list) = permissions::list_resource_permission_counts(&tenant).await {
                counts.set(
                    list.into_iter()
                        .map(|r| (r.app_id, (r.role_count, r.scope_count)))
                        .collect(),
                );
            }
        });
    });

    // The tenant's own app registrations / SPs that expose Application app roles
    // (the org's custom APIs), shown as a second resource group below the
    // bundled Microsoft APIs. Loaded once the tenant is known; selecting one
    // reuses the existing `list_resource_permissions` resolve + grant path
    // unchanged (`PickerSelection.resource_app_id` carries the appId). A failed
    // load leaves the group empty rather than panicking the frontend. Local to
    // this picker (re-created per wizard open) and re-derived from `tenant_id`,
    // so there's nothing to reset on tenant switch.
    let tenant_resources: RwSignal<Vec<CatalogResourceSummary>> = RwSignal::new(Vec::new());
    Effect::new(move |_| {
        let Some(tenant) = tenant_id.get() else {
            return;
        };
        leptos::task::spawn_local(async move {
            if let Ok(list) = permissions::list_app_role_resources(&tenant).await {
                tenant_resources.set(list);
            }
        });
    });

    // Bumped by the load-failure Retry to re-run the same resource's read.
    let reload = RwSignal::new(0_u32);
    let permissions_res = LocalResource::new(move || {
        let tenant = tenant_id.get();
        let resource = resource_app_id.get();
        let _ = reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(azapptoolkit_dto::UiError {
                    code: "no_tenant".into(),
                    message: "tenant missing".into(),
                    retryable: false,
                });
            };
            permissions::list_resource_permissions(&t, &resource).await
        }
    });

    let on_pick_resource = move |ev: leptos::ev::Event| {
        resource_app_id.set(event_target_value(&ev));
        filter.set(String::new());
    };

    let tabs = vec![
        TabBarItem {
            value: "application",
            label: "Application",
        },
        TabBarItem {
            value: "delegated",
            label: "Delegated",
        },
    ];

    view! {
        <Card class="permission-picker".to_string()>
            <div class="permission-picker__row">
                <label class="permission-picker__field">
                    <span class="permission-picker__label">"Resource"</span>
                    <select
                        class="permission-picker__select"
                        prop:value=move || resource_app_id.get()
                        on:change=on_pick_resource
                    >
                        {move || {
                            resources
                                .get()
                                .into_iter()
                                .map(|r: CatalogResourceSummary| {
                                    let label = counts
                                        .with(|c| c.get(&r.app_id).copied())
                                        .map(|(roles, scopes)| {
                                            format!(
                                                "{} ({} app / {} delegated)",
                                                r.display_name, roles, scopes,
                                            )
                                        })
                                        .unwrap_or_else(|| r.display_name.clone());
                                    view! { <option value=r.app_id.clone()>{label}</option> }
                                })
                                .collect_view()
                        }}
                        {move || {
                            let apps = tenant_resources.get();
                            (!apps.is_empty())
                                .then(|| {
                                    view! {
                                        <optgroup label="Tenant app registrations">
                                            {apps
                                                .into_iter()
                                                .map(|r: CatalogResourceSummary| {
                                                    let label = if r.role_count == 1 {
                                                        format!("{} (1 app role)", r.display_name)
                                                    } else {
                                                        format!(
                                                            "{} ({} app roles)",
                                                            r.display_name,
                                                            r.role_count,
                                                        )
                                                    };
                                                    view! {
                                                        <option value=r.app_id.clone()>{label}</option>
                                                    }
                                                })
                                                .collect_view()}
                                        </optgroup>
                                    }
                                })
                        }}
                    </select>
                </label>
                <label class="permission-picker__field permission-picker__field--grow">
                    <span class="permission-picker__label">"Filter"</span>
                    <Input value=filter placeholder="Search by name or value…" />
                </label>
            </div>
            {(matches!(mode, PickerMode::AppAndDelegated))
                .then(|| view! { <TabBar items=tabs.clone() selected=active_kind /> })}
            <Suspense fallback=|| view! { <Body1>"Loading permissions…"</Body1> }>
                {move || {
                    let needle = filter_debounced.get().to_lowercase();
                    let kind = active_kind.get();
                    // Track the resource so picking a new one re-renders the list
                    // immediately — the filter clear that used to trigger this is
                    // now debounced.
                    let _ = resource_app_id.get();
                    Suspend::new(async move {
                        match permissions_res.await {
                            Ok(perms) => view! {
                                <PermissionList
                                    perms=perms
                                    mode=mode
                                    active_kind=kind
                                    filter=needle
                                    selected=selected
                                    on_toggle=on_toggle
                                />
                            }
                                .into_any(),
                            Err(err) => view! {
                                <DetailLoadError
                                    error=err
                                    on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                                />
                            }
                                .into_any(),
                        }
                    })
                }}
            </Suspense>
        </Card>
    }
}

/// The text of the contextual least-privilege note shown under an application
/// permission at grant time, as `(scoped, text)`: `scoped` picks the "ok" tone,
/// otherwise it is a warning. Flags tenant-wide reach and points at the scoped
/// alternative (Rule 11/12) — only where that alternative exists on this
/// `resource_app_id` (Office 365 Exchange Online's mail appRoles cannot be
/// confined by RBAC for Applications). `None` when there is nothing to say.
fn scope_hint_note(resource_app_id: &str, value: &str) -> Option<(bool, String)> {
    if value == SP_SITES_SELECTED {
        return Some((
            true,
            "Scoped — per-site access (least privilege)".to_string(),
        ));
    }
    // The sub-site Selected family. Named individually rather than by prefix so
    // the note can say which securable each one confines to — "Selected" alone
    // tells an operator nothing about whether they are picking a library or a
    // file, and picking the wrong one is the mistake this whole flow guards.
    if let Some(target) = match value {
        SP_LISTS_SELECTED => Some("one list or document library"),
        SP_LIST_ITEMS_SELECTED => Some("individual list items, folders and files"),
        SP_FILES_SELECTED => Some("individual files and library folders"),
        _ => None,
    } {
        return Some((
            true,
            format!("Scoped — grants nothing until you pick {target} (least privilege)"),
        ));
    }
    let alt = least_privilege_alternative_for(Some(resource_app_id), value)?;
    // Worded off the helper's own answer, so the two can never disagree.
    let note = if alt == SP_SITES_SELECTED {
        format!("Org-wide — reaches every site. Prefer {alt}.")
    } else {
        // Exchange-scopable mail/calendar/contacts.
        format!("Org-wide — tenant-wide reach. {alt}.")
    };
    Some((false, note))
}

/// Contextual least-privilege note shown under an application permission at
/// grant time (see [`scope_hint_note`]). Advisory only — the Grant button is
/// never blocked.
fn scope_hint(resource_app_id: &str, value: &str) -> AnyView {
    match scope_hint_note(resource_app_id, value) {
        Some((true, note)) => view! {
            <span class="permission-picker__row-note permission-picker__row-note--ok">{note}</span>
        }
        .into_any(),
        Some((false, note)) => view! {
            <span class="permission-picker__row-note permission-picker__row-note--warn">{note}</span>
        }
        .into_any(),
        None => ().into_any(),
    }
}

/// Grant-time downgrade pointer for an application permission: names the
/// closest documented narrower alternative (e.g. `Mail.ReadWrite` → "needs
/// only read? Mail.Read suffices"), so the least-privilege choice is visible
/// *before* the broad grant lands. Advisory only; sourced from the same
/// coverage table as audit Rule 18 and the Downgrade… action.
fn downgrade_hint(value: &str) -> AnyView {
    let alts = downgrade_alternatives(value);
    let Some(closest) = alts.first() else {
        return ().into_any();
    };
    let note = format!("Narrower alternative: {closest}, if the full capability isn't needed.");
    view! { <span class="permission-picker__row-note permission-picker__row-note--warn">{note}</span> }
        .into_any()
}

/// Risk badge for a delegated scope. Broad delegated scopes (mail/files/
/// directory/sites/…) get a lighter "Broad scope" warning than an application
/// permission — delegated runs as the signed-in user, not app-only — nudging
/// admins toward the narrowest scope and user consent. Reuses the same
/// `is_risky_delegated_scope` classifier the consent audit uses.
fn delegated_risk_badge(value: &str) -> AnyView {
    if is_risky_delegated_scope(value) {
        view! {
            <Badge
                label="Broad scope"
                tone="warning"
                title="Broad delegated scope — prefer the narrowest scope and user consent where possible"
            />
        }
        .into_any()
    } else {
        ().into_any()
    }
}

/// SharePoint least-privilege note for a delegated scope. (The Exchange-RBAC
/// mailbox-scoping pointer is application-permission-only, so it is not shown
/// for delegated scopes — only the name-based `Sites.Selected` guidance is.)
fn delegated_scope_hint(value: &str) -> AnyView {
    if value == SP_SITES_SELECTED {
        return view! {
            <span class="permission-picker__row-note permission-picker__row-note--ok">
                "Scoped — per-site access (least privilege)"
            </span>
        }
        .into_any();
    }
    if is_sharepoint_orgwide(value) {
        return view! {
            <span class="permission-picker__row-note permission-picker__row-note--warn">
                "Org-wide — reaches every site. Prefer Sites.Selected."
            </span>
        }
        .into_any();
    }
    ().into_any()
}

#[component]
fn PermissionList(
    perms: ResourcePermissions,
    mode: PickerMode,
    active_kind: String,
    filter: String,
    selected: Signal<Vec<PickerSelection>>,
    on_toggle: Callback<PickerSelection>,
) -> impl IntoView {
    let resource_app_id = perms.app_id;
    let want_delegated = matches!(mode, PickerMode::AppAndDelegated) && active_kind == "delegated";

    let app_only_filter = matches!(mode, PickerMode::ApplicationOnly);
    let matches = |hay: &str| filter.is_empty() || hay.to_lowercase().contains(&filter);

    if want_delegated {
        let rows: Vec<_> = perms
            .oauth2_permission_scopes
            .into_iter()
            .filter(|s| {
                matches(&s.value)
                    || s.admin_consent_display_name
                        .as_deref()
                        .map(matches)
                        .unwrap_or(false)
            })
            .map(|s| {
                let resource_app_id = resource_app_id.clone();
                let display = s
                    .admin_consent_display_name
                    .clone()
                    .unwrap_or_else(|| s.value.clone());
                let payload_id = s.id.clone();
                let payload_value = s.value.clone();
                // Delegated grant-time hints (advisory). Computed before s.value moves.
                let drisk = delegated_risk_badge(&s.value);
                // One name per row: ~400 Graph permissions all announcing
                // "Select permission" left the list unusable by screen reader.
                let check_label = format!("Select {}", s.value);
                let dhint = delegated_scope_hint(&s.value);
                let sel = PickerSelection {
                    resource_app_id,
                    kind: PermissionKind::Delegated,
                    permission_id: payload_id,
                    permission_value: payload_value,
                };
                let sel_checked = sel.clone();
                let checked = move || selected.with(|v| v.contains(&sel_checked));
                let on_change = move |_| on_toggle.run(sel.clone());
                view! {
                    <li class="permission-picker__row">
                        <span class="permission-picker__row-chip">
                            <TypeChip kind=AppKind::PermissionDelegated compact=true />
                        </span>
                        <span class="permission-picker__row-text">
                            <span class="permission-picker__row-head">
                                <strong>{s.value}</strong>
                                {drisk}
                            </span>
                            <span class="permission-picker__row-sub">{display}</span>
                            {dhint}
                        </span>
                        <input
                            type="checkbox"
                            class="permission-picker__check"
                            aria-label=check_label
                            prop:checked=checked
                            on:change=on_change
                        />
                    </li>
                }
            })
            .collect();
        view! { <ul class="permission-picker__list">{rows}</ul> }.into_any()
    } else {
        let rows: Vec<_> = perms
            .app_roles
            .into_iter()
            .filter(|r| {
                !app_only_filter
                    || r.allowed_member_types.is_empty()
                    || r.allowed_member_types
                        .iter()
                        .any(|t| t.eq_ignore_ascii_case("Application"))
            })
            .filter(|r| matches(&r.value) || matches(&r.display_name))
            .map(|r| {
                let resource_app_id = resource_app_id.clone();
                let payload_id = r.id.clone();
                let payload_value = r.value.clone();
                // Grant-time least-privilege hints (advisory; the Grant button is
                // never blocked). Computed before `r.value` is moved below.
                let risk = app_permission_risk_badge(&r.value);
                let check_label = format!("Select {}", r.value);
                let hint = scope_hint(&resource_app_id, &r.value);
                let downgrade = downgrade_hint(&r.value);
                let sel = PickerSelection {
                    resource_app_id,
                    kind: PermissionKind::Application,
                    permission_id: payload_id,
                    permission_value: payload_value,
                };
                let sel_checked = sel.clone();
                let checked = move || selected.with(|v| v.contains(&sel_checked));
                let on_change = move |_| on_toggle.run(sel.clone());
                view! {
                    <li class="permission-picker__row">
                        <span class="permission-picker__row-chip">
                            <TypeChip kind=AppKind::PermissionApplication compact=true />
                        </span>
                        <span class="permission-picker__row-text">
                            <span class="permission-picker__row-head">
                                <strong>{r.value}</strong>
                                {risk}
                            </span>
                            <span class="permission-picker__row-sub">{r.display_name}</span>
                            {hint}
                            {downgrade}
                        </span>
                        <input
                            type="checkbox"
                            class="permission-picker__check"
                            aria-label=check_label
                            prop:checked=checked
                            on:change=on_change
                        />
                    </li>
                }
            })
            .collect();
        view! { <ul class="permission-picker__list">{rows}</ul> }.into_any()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::scoping::{MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID};

    #[test]
    fn scope_hint_offers_mailbox_scoping_only_where_rbac_applies() {
        let (scoped, text) =
            scope_hint_note(MICROSOFT_GRAPH_APP_ID, "Mail.Read").expect("Graph mail is scopable");
        assert!(!scoped);
        assert!(text.contains("Exchange RBAC"), "{text}");
        // Office 365 Exchange Online's identically-named appRole cannot be
        // confined by RBAC for Applications: no advice it cannot follow.
        assert_eq!(
            scope_hint_note(OFFICE365_EXCHANGE_ONLINE_APP_ID, "Mail.Read"),
            None
        );
    }

    #[test]
    fn scope_hint_points_broad_sites_at_sites_selected() {
        assert_eq!(
            scope_hint_note(MICROSOFT_GRAPH_APP_ID, "Sites.ReadWrite.All"),
            Some((
                false,
                "Org-wide — reaches every site. Prefer Sites.Selected.".to_string()
            ))
        );
        let (scoped, _) = scope_hint_note(MICROSOFT_GRAPH_APP_ID, SP_SITES_SELECTED)
            .expect("Sites.Selected gets the scoped note");
        assert!(scoped);
    }
}
