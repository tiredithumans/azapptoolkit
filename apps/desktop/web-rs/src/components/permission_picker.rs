//! Searchable picker for granting a single Application or Delegated
//! permission. The resource dropdown is the bundled directory (`appId` +
//! name); the permissions for the selected resource — and the per-resource
//! counts shown in the dropdown — are resolved live from Microsoft Graph. The
//! picker is presentation-only — the parent owns the actual Tauri grant call
//! and the busy flag.

use std::collections::HashMap;

use azapptoolkit_core::audit::{
    downgrade_alternatives, is_risky_delegated_scope, least_privilege_alternative,
};
use azapptoolkit_core::scoping::is_sharepoint_orgwide;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Input};

use crate::bindings::permissions::{
    self, CatalogResourceSummary, PermissionKind, ResourcePermissions,
};
use crate::components::scope_badge::app_permission_risk_badge;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{Card, TabBar, TabBarItem};
use crate::constants::*;
use crate::hooks::use_debounced::use_debounced;

/// Microsoft Graph's first-party app id — the natural default for both
/// the App Registration and Managed Identity grant flows.
pub const MICROSOFT_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerMode {
    /// Managed identities only support Application permissions. Hides the
    /// Application/Delegated tab strip and filters to `app_roles` whose
    /// `allowed_member_types` contain `"Application"`.
    ApplicationOnly,
    /// App Registrations grant both kinds — show the tab strip.
    AppAndDelegated,
}

#[derive(Debug, Clone)]
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
    on_grant: Callback<PickerSelection>,
    #[prop(into)] busy: Signal<bool>,
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

    let permissions_res = LocalResource::new(move || {
        let tenant = tenant_id.get();
        let resource = resource_app_id.get();
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
                                        .get()
                                        .get(&r.app_id)
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
                                    busy=busy
                                    on_grant=on_grant
                                />
                            }
                                .into_any(),
                            Err(err) => view! {
                                <Body1 class="form-error">
                                    {format!("Failed to load: {}", err.message)}
                                </Body1>
                            }
                                .into_any(),
                        }
                    })
                }}
            </Suspense>
        </Card>
    }
}

/// Contextual least-privilege note shown under an application permission at
/// grant time: flags tenant-wide reach and points at the scoped alternative
/// (Rule 11/12). Advisory only — the Grant button is never blocked.
fn scope_hint(value: &str) -> AnyView {
    if value == "Sites.Selected" {
        return view! {
            <span class="permission-picker__row-note permission-picker__row-note--ok">
                "Scoped — per-site access (least privilege)"
            </span>
        }
        .into_any();
    }
    let Some(alt) = least_privilege_alternative(value) else {
        return ().into_any();
    };
    let note = if is_sharepoint_orgwide(value) {
        format!("Org-wide — reaches every site. Prefer {alt}.")
    } else {
        // Exchange-scopable mail/calendar/contacts.
        format!("Org-wide — tenant-wide reach. {alt}.")
    };
    view! {
        <span class="permission-picker__row-note permission-picker__row-note--warn">{note}</span>
    }
    .into_any()
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
            <span
                class="badge badge--warning"
                title="Broad delegated scope — prefer the narrowest scope and user consent where possible"
            >
                "Broad scope"
            </span>
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
    if value == "Sites.Selected" {
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
    busy: Signal<bool>,
    on_grant: Callback<PickerSelection>,
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
                let dhint = delegated_scope_hint(&s.value);
                let on_click = move |_| {
                    on_grant.run(PickerSelection {
                        resource_app_id: resource_app_id.clone(),
                        kind: PermissionKind::Delegated,
                        permission_id: payload_id.clone(),
                        permission_value: payload_value.clone(),
                    });
                };
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
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(on_click)
                            disabled=busy
                        >
                            "Grant"
                        </Button>
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
                let hint = scope_hint(&r.value);
                let downgrade = downgrade_hint(&r.value);
                let on_click = move |_| {
                    on_grant.run(PickerSelection {
                        resource_app_id: resource_app_id.clone(),
                        kind: PermissionKind::Application,
                        permission_id: payload_id.clone(),
                        permission_value: payload_value.clone(),
                    });
                };
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
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(on_click)
                            disabled=busy
                        >
                            "Grant"
                        </Button>
                    </li>
                }
            })
            .collect();
        view! { <ul class="permission-picker__list">{rows}</ul> }.into_any()
    }
}
