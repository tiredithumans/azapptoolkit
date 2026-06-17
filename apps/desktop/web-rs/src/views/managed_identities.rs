//! Managed Identities view: discover managed identities and grant them
//! application permissions (the RBAC equivalent of `Grant-AzManagedIdentityPermission`).
//! Master list on the left, selected-identity properties + grant form on the right.

use std::collections::HashMap;
use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use azapptoolkit_core::audit::MailPermissionScope;

use crate::components::icon::IconName;
use crate::components::permission_picker::PickerSelection;
use crate::components::scope_badge::{is_exchange_scopable, is_sharepoint_orgwide};
use crate::components::scope_panel::ScopeKind;
use crate::components::ui::{EmptyState, IconButton, SearchInput, SectionHeader, SkeletonList};
use crate::components::virtual_list::VirtualList;
use crate::util::parse_lines;

use crate::bindings::diagnostics::{self, ListCacheKindDto};
use crate::bindings::exchange as exchange_bindings;
use crate::bindings::graph_roles;
use crate::bindings::managed_identity::{
    self, GrantManagedIdentityResult, ManagedIdentityDto, MiSubtype,
};
use crate::bindings::permissions as permissions_bindings;
use crate::bindings::sharepoint;
use crate::components::filter_chip::FilterChip;
use crate::components::saved_views::SavedViews;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::hooks::use_debounced::{use_debounced, LIST_FILTER_DEBOUNCE_MS};
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::managed_identity_detail_pane::ManagedIdentityDetailPane;

/// Microsoft Graph's first-party app id — mail/calendar/contacts and
/// `Sites.Selected` application permissions live on this resource, so scoping
/// only applies when the picked permission's resource matches.
pub(crate) const MICROSOFT_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// Fixed MI row height (px) + overscan for the virtualized list. Matches the
/// App Registration / Enterprise Application lists so all three look alike and
/// the managed-identity list no longer renders every row for large fleets.
const MI_ROW_HEIGHT: f64 = 52.0;
const MI_OVERSCAN: usize = 8;

/// A permission the user picked that can be scoped to a resource before being
/// granted to the managed identity. Captured when the picker emits a scopable
/// selection so the inline panel can collect the resource (groups / site URL).
#[derive(Clone)]
pub(crate) struct PendingScope {
    /// The managed identity's service-principal object id (assignment target).
    pub(crate) sp_object_id: String,
    /// The managed identity's app id (Exchange SP pointer / site permission).
    pub(crate) app_id: String,
    pub(crate) display_name: String,
    pub(crate) resource_app_id: String,
    pub(crate) permission_value: String,
    pub(crate) kind: ScopeKind,
}

/// Classifies whether a picked Graph permission can be resource-scoped.
fn scope_kind_for(resource_app_id: &str, permission_value: &str) -> Option<ScopeKind> {
    if resource_app_id != MICROSOFT_GRAPH_APP_ID {
        return None;
    }
    if is_exchange_scopable(permission_value) {
        Some(ScopeKind::Exchange)
    } else if permission_value == "Sites.Selected" {
        Some(ScopeKind::SharePoint)
    } else {
        None
    }
}

/// Classifies whether an **already-held** permission can be restricted *per row*
/// after the fact: a broad `Sites.*` grant is SharePoint-scopable — the convert-to-
/// `Sites.Selected` case. Mail/calendar/contacts are excluded — Exchange RBAC
/// scoping is **app-wide** (one management scope binds the whole principal's mail
/// roles), so it's driven by the app-wide "Exchange scoping" section, not a per-row
/// button. Unlike [`scope_kind_for`] (the new-grant picker path) this still treats
/// a broad `Sites.*` as scopable. `app_role_value` is only populated for Microsoft
/// Graph permissions, so a `Some(value)` already implies the Graph resource.
pub(crate) fn existing_scope_kind_for(permission_value: &str) -> Option<ScopeKind> {
    is_sharepoint_orgwide(permission_value).then_some(ScopeKind::SharePoint)
}

pub(crate) fn chip_kind_for(subtype: MiSubtype) -> AppKind {
    match subtype {
        MiSubtype::SystemAssigned => AppKind::ManagedIdentitySystem,
        MiSubtype::UserAssigned => AppKind::ManagedIdentityUser,
        MiSubtype::Unknown => AppKind::ManagedIdentityUnknown,
    }
}

use crate::util::no_tenant;

/// Per-facet counts over the loaded managed identities, powering the filter
/// chips (subtype + account-enabled state).
#[derive(Clone, Copy, PartialEq, Eq)]
struct MiCounts {
    system: usize,
    user: usize,
    enabled: usize,
    disabled: usize,
}

fn mi_counts(items: &[ManagedIdentityDto]) -> MiCounts {
    let mut c = MiCounts {
        system: 0,
        user: 0,
        enabled: 0,
        disabled: 0,
    };
    for mi in items {
        match mi.mi_subtype {
            MiSubtype::SystemAssigned => c.system += 1,
            MiSubtype::UserAssigned => c.user += 1,
            MiSubtype::Unknown => {}
        }
        match mi.account_enabled {
            Some(true) => c.enabled += 1,
            Some(false) => c.disabled += 1,
            None => {}
        }
    }
    c
}

/// Whether a managed identity matches the active facet chip. `all` (and any
/// unknown value) matches everything.
fn matches_mi_facet(mi: &ManagedIdentityDto, facet: &str) -> bool {
    match facet {
        "system" => matches!(mi.mi_subtype, MiSubtype::SystemAssigned),
        "user" => matches!(mi.mi_subtype, MiSubtype::UserAssigned),
        "enabled" => mi.account_enabled == Some(true),
        "disabled" => mi.account_enabled == Some(false),
        _ => true,
    }
}

#[component]
pub fn ManagedIdentitiesView() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let selected_id = session.selected_managed_identity_id;

    // "Filter this list" query, lifted to the session so the top-bar Global
    // Search can seed it (picking a Managed Identity there lands the user here
    // with the list pre-filtered to that name). Mirrors the App Registration /
    // Enterprise Application lists.
    let raw_search = session.mi_search;
    let search = use_debounced(raw_search.into(), LIST_FILTER_DEBOUNCE_MS);
    // Facet chip over the loaded list: all | system | user | enabled | disabled.
    let mi_filter = RwSignal::new(String::from("all"));

    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    // Confirmation gate for revoking a held app-role grant — a destructive,
    // irreversible server mutation. Holds (assignment_id, sp_id) while open.
    let pending_revoke: RwSignal<Option<(String, String)>> = RwSignal::new(None);
    let result: RwSignal<Option<GrantManagedIdentityResult>> = RwSignal::new(None);
    // Bumped after a grant or revoke to refresh the permissions list.
    let reload = RwSignal::new(0_u32);
    // Bumped by the Refresh button to force the identities list to re-evaluate.
    let list_reload = RwSignal::new(0_u32);
    // Bumped after interactive ARM consent succeeds, to re-run the Azure-RBAC
    // resource now that the scope is consented.
    let arm_reload = RwSignal::new(0_u32);
    // Interactive ARM-consent flow state (browser round trip in flight; error).
    let consenting = RwSignal::new(false);
    let consent_error: RwSignal<Option<String>> = RwSignal::new(None);
    // Detail-pane Refresh: re-fetch the selected identity's permissions, Azure
    // roles, and list-derived header in one go.
    let refreshing = RwSignal::new(false);

    // Rows currently shown (after every filter) — captured for the inventory
    // export so "what you see is what you export" (the backend serializes these
    // passed rows; filters live here). Kept in step by an Effect in
    // `LoadedManagedIdentities`; the `Arc` makes each snapshot a pointer copy.
    let export_rows: StoredValue<Arc<Vec<ManagedIdentityDto>>> =
        StoredValue::new(Arc::new(Vec::new()));
    let exporting = RwSignal::new(false);
    let do_export = move |format: &'static str| {
        if exporting.get_untracked() {
            return;
        }
        let rows = export_rows.get_value();
        if rows.is_empty() {
            return;
        }
        exporting.set(true);
        leptos::task::spawn_local(async move {
            let count = rows.len();
            match managed_identity::save_managed_identities_to_file(&rows, format).await {
                Ok(Some(path)) => {
                    session.toast_success(format!("Exported {count} managed identities to {path}"));
                }
                Ok(None) => {}
                Err(e) => {
                    session.toast_error(e.message, None);
                }
            }
            exporting.set(false);
        });
    };

    // Inline resource-scoping for a scopable permission picked in the grant
    // form. `pending_scope` holds the picked permission until the user supplies
    // a scope (mailbox groups / site URL) or grants it org-wide.
    let pending_scope: RwSignal<Option<PendingScope>> = RwSignal::new(None);
    let scope_groups_text = RwSignal::new(String::new());
    let scope_site_url = RwSignal::new(String::new());
    let scope_note: RwSignal<Option<String>> = RwSignal::new(None);

    let identities = LocalResource::new(move || {
        let tenant = tenant.get();
        let _ = list_reload.get();
        async move {
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            managed_identity::list_managed_identities(&t.tenant_id).await
        }
    });

    let on_refresh_list = move |_| {
        let Some(t) = tenant.get() else {
            return;
        };
        leptos::task::spawn_local(async move {
            diagnostics::invalidate_list_cache(
                t.tenant_id.clone(),
                ListCacheKindDto::ManagedIdentities,
            )
            .await;
            list_reload.update(|n| *n = n.wrapping_add(1));
        });
    };

    let permissions = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = selected_id.get();
        let _ = reload.get();
        async move {
            let (Some(t), Some(id)) = (tenant, id) else {
                return Ok(Vec::new());
            };
            graph_roles::list_held_app_role_grants(&t.tenant_id, &id).await
        }
    });

    // Effective Exchange mailbox scoping for the selected identity's mail
    // permissions. Its own resource so the non-Send tauri-sys binding runs on
    // the local executor (awaiting it inside the detail Suspend stays Send).
    // Awaits the shared `identities`/`permissions` resources, so it reuses their
    // data (no extra Graph calls) and refetches when a grant/revoke bumps
    // `reload`. Empty when the identity holds no scopable mail permission.
    let mail_scopes = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = selected_id.get();
        let _ = reload.get();
        async move {
            let (Some(t), Some(id)) = (tenant, id) else {
                return Ok(HashMap::<String, MailPermissionScope>::new());
            };
            let app_id = identities.await.ok().and_then(|list| {
                list.iter()
                    .find(|mi| mi.id == id)
                    .map(|mi| mi.app_id.clone())
            });
            let Some(app_id) = app_id else {
                return Ok(HashMap::new());
            };
            let mail_values: Vec<String> = permissions
                .await
                .unwrap_or_default()
                .iter()
                .filter_map(|p| p.app_role_value.clone())
                .filter(|v| is_exchange_scopable(v))
                .collect();
            if mail_values.is_empty() {
                return Ok(HashMap::new());
            }
            // Surface the error (don't swallow): a genuine 403/consent failure
            // drives a "Grant consent & retry" banner, mirroring the app-reg
            // Permissions tab. After the backend fix an AAP-confined permission
            // resolves to Scoped(legacy) and an unresolvable principal to
            // org-wide, so this `Err` is reserved for real unavailability.
            exchange_bindings::get_mail_scopes_for_principal(&t.tenant_id, &app_id, &mail_values)
                .await
                .map(|entries| {
                    entries
                        .into_iter()
                        .map(|e| (e.graph_permission, e.scope))
                        .collect()
                })
        }
    });

    // Azure RBAC roles (via ARM) — the Azure-resource side of the identity's
    // privilege. Independent of `reload` (grants don't change Azure roles).
    let azure_roles = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = selected_id.get();
        let _ = arm_reload.get();
        async move {
            let (Some(t), Some(id)) = (tenant, id) else {
                return Ok(managed_identity::AzureRolesResult::default());
            };
            managed_identity::list_managed_identity_azure_roles(&t.tenant_id, &id).await
        }
    });

    let do_grant = Callback::new(move |sel: PickerSelection| {
        if busy.get() {
            return;
        }
        let Some(id) = selected_id.get() else {
            return;
        };
        error.set(None);
        result.set(None);
        scope_note.set(None);

        // A scopable permission (mail or Sites.Selected) opens the inline scope
        // panel instead of granting immediately. We need the MI's app_id +
        // display name (for the Exchange SP pointer / site grant), resolved from
        // the loaded identities list.
        if let Some(kind) = scope_kind_for(&sel.resource_app_id, &sel.permission_value) {
            let mi = identities
                .get()
                .and_then(|r| r.ok())
                .and_then(|list| list.into_iter().find(|m| m.id == id));
            if let Some(mi) = mi {
                scope_groups_text.set(String::new());
                scope_site_url.set(String::new());
                pending_scope.set(Some(PendingScope {
                    sp_object_id: mi.id,
                    app_id: mi.app_id,
                    display_name: mi.display_name,
                    resource_app_id: sel.resource_app_id,
                    permission_value: sel.permission_value,
                    kind,
                }));
                return;
            }
            // Couldn't resolve the MI — fall through to an org-wide grant.
        }

        busy.set(true);
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match managed_identity::grant_managed_identity_permission(
                &t.tenant_id,
                &id,
                &sel.resource_app_id,
                &[sel.permission_value.clone()],
            )
            .await
            {
                Ok(r) => {
                    result.set(Some(r));
                    reload.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    });

    // Cancel the pending scope panel without granting.
    let cancel_scope = move |_| {
        pending_scope.set(None);
        error.set(None);
    };

    // Grant the pending permission org-wide (the panel's fallback button).
    let submit_orgwide = move |_| {
        let Some(p) = pending_scope.get() else {
            return;
        };
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match managed_identity::grant_managed_identity_permission(
                &t.tenant_id,
                &p.sp_object_id,
                &p.resource_app_id,
                &[p.permission_value.clone()],
            )
            .await
            {
                Ok(r) => {
                    result.set(Some(r));
                    pending_scope.set(None);
                    reload.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    // Grant the pending mail permission scoped to mailbox group(s) via RBAC.
    let submit_exchange = move |_| {
        let Some(p) = pending_scope.get() else {
            return;
        };
        if busy.get() {
            return;
        }
        let groups = parse_lines(&scope_groups_text.get());
        if groups.is_empty() {
            error.set(Some(
                "Enter at least one group or mailbox identifier.".into(),
            ));
            return;
        }
        busy.set(true);
        error.set(None);
        scope_note.set(None);
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match exchange_bindings::grant_managed_identity_scoped_exchange_access(
                &t.tenant_id,
                &p.sp_object_id,
                &p.app_id,
                &p.display_name,
                &[p.permission_value.clone()],
                &groups,
                true,
            )
            .await
            {
                Ok(r) => {
                    let mut note = format!(
                        "Scoped {} via “{}” — {} role(s) assigned, {} org-wide grant(s) removed.",
                        p.permission_value,
                        r.scope_name,
                        r.roles_assigned.len(),
                        r.removed_entra_grants.len(),
                    );
                    if !r.warnings.is_empty() {
                        note.push_str(&format!(" Warnings: {}", r.warnings.join("; ")));
                    }
                    scope_note.set(Some(note));
                    pending_scope.set(None);
                    reload.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    // Restrict SharePoint access to one site via the Sites.Selected model.
    // `role` is "read" or "write". One command grants Sites.Selected (idempotent),
    // grants the site permission, and — when the identity already held a broad
    // `Sites.*` grant — strips it. Safe for both the new-grant picker path (no
    // broad grant to remove) and the per-row "restrict existing" path. Copy
    // (captures only Copy signals) so both site buttons can reuse it.
    let submit_sharepoint = move |role: &'static str| {
        let Some(p) = pending_scope.get() else {
            return;
        };
        if busy.get() {
            return;
        }
        let url = scope_site_url.get().trim().to_string();
        if url.is_empty() {
            error.set(Some("Enter a SharePoint site URL.".into()));
            return;
        }
        busy.set(true);
        error.set(None);
        scope_note.set(None);
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            match sharepoint::convert_site_access_to_selected(
                &t.tenant_id,
                &p.sp_object_id,
                &p.app_id,
                &p.display_name,
                &[url.clone()],
                role,
                true,
            )
            .await
            {
                Ok(r) => {
                    let site = r
                        .sites_granted
                        .first()
                        .and_then(|s| s.site_display_name.clone())
                        .unwrap_or(url.clone());
                    let mut note = format!("Granted {role} access to {site}.");
                    if !r.removed_orgwide_grants.is_empty() {
                        note.push_str(&format!(
                            " Removed org-wide grant(s): {}.",
                            r.removed_orgwide_grants.join(", ")
                        ));
                    }
                    if !r.warnings.is_empty() {
                        note.push_str(&format!(" Warnings: {}", r.warnings.join("; ")));
                    }
                    scope_note.set(Some(note));
                    pending_scope.set(None);
                    reload.update(|n| *n += 1);
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    let do_revoke = move |assignment_id: String, sp_id: String| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let tenant = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            if let Err(e) = permissions_bindings::revoke_app_role_assignment(
                &t.tenant_id,
                &sp_id,
                &assignment_id,
            )
            .await
            {
                error.set(Some(e.message));
            } else {
                reload.update(|n| *n += 1);
                pending_revoke.set(None);
            }
            busy.set(false);
        });
    };

    // Detail-pane Refresh for the selected identity. Permissions and Azure-role
    // views aren't server-cached, so bumping their reloads re-fetches them; the
    // identity list IS cached (it backs the header's status/subtype), so bust it
    // too. Captures only Copy signals, so the closure stays Copy for reuse
    // across Suspense re-renders.
    let on_refresh_detail = move |_| {
        if refreshing.get() {
            return;
        }
        let Some(t) = tenant.get() else {
            return;
        };
        refreshing.set(true);
        leptos::task::spawn_local(async move {
            diagnostics::invalidate_list_cache(
                t.tenant_id.clone(),
                ListCacheKindDto::ManagedIdentities,
            )
            .await;
            list_reload.update(|n| *n = n.wrapping_add(1));
            reload.update(|n| *n += 1);
            arm_reload.update(|n| *n += 1);
            refreshing.set(false);
        });
    };

    let tenant_for_picker: Signal<Option<String>> =
        Signal::derive(move || tenant.get().map(|t| t.tenant_id.clone()));

    view! {
        <div class="mi-view">
            <ConfirmDialog
                open=Signal::derive(move || pending_revoke.with(|p| p.is_some()))
                title="Revoke permission?"
                body="Remove this managed identity's held app-role assignment. The identity loses that permission until it's granted again; the live grant is re-checked before removal."
                confirm_label="Revoke"
                busy=busy
                error=error
                on_confirm=Callback::new(move |()| {
                    if let Some((aid, sp)) = pending_revoke.get() {
                        do_revoke(aid, sp);
                    }
                })
                on_close=Callback::new(move |()| {
                    pending_revoke.set(None);
                    error.set(None);
                })
            />
            <div>
                <SectionHeader title="Managed Identities".to_string() crumb="Identities".to_string()>
                    <div class="list-header-actions">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                            disabled=Signal::derive(move || exporting.get())
                            on_click=Box::new(move |_| do_export("csv"))
                        >
                            "Export CSV"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                            disabled=Signal::derive(move || exporting.get())
                            on_click=Box::new(move |_| do_export("json"))
                        >
                            "Export JSON"
                        </Button>
                        <IconButton
                            icon=IconName::Refresh
                            aria_label="Refresh managed identities".to_string()
                            title="Refresh".to_string()
                            on_click=Callback::new(on_refresh_list)
                        />
                    </div>
                </SectionHeader>
                <Body1 class="mi-view__intro">
                    "Grant Microsoft Graph (or another resource) application permissions to a managed identity. Permissions you list (e.g. Mail.Read) are assigned to the selected identity's service principal."
                </Body1>
            </div>
            <div class="mi-view__body">
                <div class="mi-view__list">
                    <SearchInput value=raw_search placeholder="Filter Managed Identities…" />
                    <SavedViews view_key="mi" facet=mi_filter search=raw_search />
                    <Suspense fallback=move || view! { <SkeletonList rows=6 /> }>
                        {move || {
                            // Re-runs only on an actual refetch; the search and
                            // facet are read inside `LoadedManagedIdentities`'
                            // memos, not here.
                            Suspend::new(async move {
                                match identities.await {
                                    Ok(list) if list.is_empty() => {
                                        view! {
                                            <EmptyState
                                                icon=IconName::Server
                                                title="No managed identities".to_string()
                                                body="No managed identities found in this tenant.".to_string()
                                            />
                                        }
                                            .into_any()
                                    }
                                    Ok(list) => {
                                        view! {
                                            <LoadedManagedIdentities
                                                list=list
                                                search=search
                                                mi_filter=mi_filter
                                                export_rows=export_rows
                                                selected_id=selected_id
                                                result=result
                                                error=error
                                            />
                                        }
                                            .into_any()
                                    }
                                    Err(e) => {
                                        view! { <Body1 class="form-error">{e.message}</Body1> }
                                            .into_any()
                                    }
                                }
                            })
                        }}
                    </Suspense>
                </div>
                <div class="mi-view__detail">
                    <Suspense fallback=move || {
                        view! {
                            <div class="centered-pad">
                                <Spinner
                                    size=Signal::derive(|| SpinnerSize::Tiny)
                                    label="Loading…"
                                />
                            </div>
                        }
                    }>
                        {move || Suspend::new(async move {
                            let list = identities.await.ok().unwrap_or_default();
                            let id = selected_id.get();
                            let selected = id
                                .as_ref()
                                .and_then(|id| {
                                    list.iter().find(|mi| &mi.id == id).cloned()
                                });
                            match selected {
                                None => {
                                    view! {
                                        <EmptyState
                                            icon=IconName::Server
                                            title="No identity selected".to_string()
                                            body="Pick a managed identity from the list to view details and grant permissions.".to_string()
                                        />
                                    }
                                        .into_any()
                                }
                                Some(mi) => {
                                    view! {
                                        <ManagedIdentityDetailPane
                                            mi=mi
                                            permissions=permissions
                                            mail_scopes=mail_scopes
                                            azure_roles=azure_roles
                                            busy=busy
                                            error=error
                                            result=result
                                            refreshing=refreshing
                                            pending_scope=pending_scope
                                            scope_groups_text=scope_groups_text
                                            scope_site_url=scope_site_url
                                            scope_note=scope_note
                                            consenting=consenting
                                            consent_error=consent_error
                                            reload=reload
                                            arm_reload=arm_reload
                                            tenant=tenant
                                            selected_id=selected_id
                                            tenant_for_picker=tenant_for_picker
                                            on_grant=do_grant
                                            on_revoke=Callback::new(move |(aid, sp): (String, String)| {
                                                error.set(None);
                                                pending_revoke.set(Some((aid, sp)))
                                            })
                                            on_refresh=Callback::new(move |()| on_refresh_detail(()))
                                            on_cancel_scope=Callback::new(move |()| cancel_scope(()))
                                            on_submit_orgwide=Callback::new(move |()| submit_orgwide(()))
                                            on_submit_exchange=Callback::new(move |()| submit_exchange(()))
                                            on_submit_sharepoint=Callback::new(move |role: &'static str| {
                                                submit_sharepoint(role)
                                            })
                                        />
                                    }
                                        .into_any()
                                }
                            }
                        })}
                    </Suspense>
                </div>
            </div>
        </div>
    }
}

/// The loaded managed-identity list: layered filter memos feeding the facet
/// chips and the virtualized rows, so a keystroke or chip click re-filters in
/// memory without rebuilding this subtree.
#[component]
fn LoadedManagedIdentities(
    list: Vec<ManagedIdentityDto>,
    search: Signal<String>,
    mi_filter: RwSignal<String>,
    export_rows: StoredValue<Arc<Vec<ManagedIdentityDto>>>,
    selected_id: RwSignal<Option<String>>,
    result: RwSignal<Option<GrantManagedIdentityResult>>,
    error: RwSignal<Option<String>>,
) -> impl IntoView {
    let all = Arc::new(list);

    // Name defines the base set; the facet chips partition it (counts are
    // over the base).
    let base = Memo::new(move |_| {
        let needle = search.with(|s| s.trim().to_lowercase());
        if needle.is_empty() {
            return Arc::clone(&all);
        }
        Arc::new(
            all.iter()
                .filter(|mi| mi.display_name.to_lowercase().contains(&needle))
                .cloned()
                .collect::<Vec<_>>(),
        )
    });
    let counts = Memo::new(move |_| mi_counts(&base.get()));
    let filtered = Memo::new(move |_| {
        let kind = mi_filter.get();
        let base = base.get();
        if kind == "all" {
            return base;
        }
        Arc::new(
            base.iter()
                .filter(|mi| matches_mi_facet(mi, &kind))
                .cloned()
                .collect::<Vec<_>>(),
        )
    });

    // Keep the export snapshot in step with what's shown (a pointer copy).
    Effect::new(move |_| export_rows.set_value(filtered.get()));

    view! {
        {move || {
            let counts = counts.get();
            let base_total = base.with(|b| b.len());
            view! {
                <div class="filter-chips">
                    <FilterChip label="All" value="all" count=base_total facet=mi_filter />
                    <FilterChip
                        label="System"
                        value="system"
                        count=counts.system
                        facet=mi_filter
                    />
                    <FilterChip label="User" value="user" count=counts.user facet=mi_filter />
                    <FilterChip
                        label="Enabled"
                        value="enabled"
                        count=counts.enabled
                        facet=mi_filter
                    />
                    <FilterChip
                        label="Disabled"
                        value="disabled"
                        count=counts.disabled
                        facet=mi_filter
                    />
                </div>
            }
        }}
        <Show
            when=move || filtered.with(|v| !v.is_empty())
            fallback=|| {
                view! {
                    <EmptyState
                        icon=IconName::Server
                        title="No matches".to_string()
                        body="No managed identities match your filter.".to_string()
                    />
                }
            }
        >
            <VirtualList
                items=filtered
                row_height=MI_ROW_HEIGHT
                overscan=MI_OVERSCAN
                scroller_class="app-list__scroller"
                sizer_class="app-list__sizer"
                key=|mi: &ManagedIdentityDto| mi.id.clone()
                render_row=move |idx, mi| {
                    render_row(idx, mi, selected_id, result, error).into_any()
                }
            />
        </Show>
    }
}

// Reuses the shared `app-list__*` row classes (and the VirtualList scroller)
// so the managed-identity list matches the App Registration / Enterprise
// Application lists exactly. Rows are absolutely positioned inside the sizer.
fn render_row(
    idx: usize,
    mi: ManagedIdentityDto,
    selected_id: RwSignal<Option<String>>,
    result: RwSignal<Option<GrantManagedIdentityResult>>,
    error: RwSignal<Option<String>>,
) -> impl IntoView {
    let session = use_session();
    // One shared allocation for the row id; the per-handler captures below are
    // refcount bumps instead of String clones.
    let id: Arc<str> = mi.id.into();
    let id_for_click = Arc::clone(&id);
    let row_class = move || {
        let mut c = String::from("app-list__row");
        if selected_id.with(|s| s.as_deref() == Some(&*id)) {
            c.push_str(" app-list__row--selected");
        }
        c
    };
    let chip_kind = chip_kind_for(mi.mi_subtype);
    let top = idx as f64 * MI_ROW_HEIGHT;
    let display_name = if mi.display_name.is_empty() {
        mi.app_id.clone()
    } else {
        mi.display_name
    };
    let title_name = display_name.clone();
    let app_id = mi.app_id;
    view! {
        <div
            class=row_class
            style:top=format!("{top}px")
            style:height=format!("{MI_ROW_HEIGHT}px")
        >
            <button
                class="app-list__row-btn"
                type="button"
                on:click=move |_| {
                    session.set_selected_managed_identity(Some(id_for_click.to_string()));
                    result.set(None);
                    error.set(None);
                }
            >
                <span class="row-meta">
                    <TypeChip kind=chip_kind compact=true />
                    <span class="app-list__row-title" title=title_name>{display_name}</span>
                </span>
                <span class="app-list__row-appid">{app_id}</span>
            </button>
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_mi(subtype: MiSubtype, enabled: Option<bool>) -> ManagedIdentityDto {
        ManagedIdentityDto {
            id: "sp-1".to_string(),
            app_id: "app-1".to_string(),
            display_name: "mi".to_string(),
            account_enabled: enabled,
            mi_subtype: subtype,
        }
    }

    #[test]
    fn scope_kind_for_only_classifies_graph_scopable_grants() {
        assert_eq!(
            scope_kind_for(MICROSOFT_GRAPH_APP_ID, "Mail.Read"),
            Some(ScopeKind::Exchange)
        );
        assert_eq!(
            scope_kind_for(MICROSOFT_GRAPH_APP_ID, "Sites.Selected"),
            Some(ScopeKind::SharePoint)
        );
        assert_eq!(scope_kind_for(MICROSOFT_GRAPH_APP_ID, "User.Read"), None);
        // A non-Graph resource is never Exchange/SharePoint-scopable here.
        assert_eq!(
            scope_kind_for("00000002-0000-0ff1-ce00-000000000000", "Mail.Read"),
            None
        );
    }

    #[test]
    fn existing_scope_kind_for_is_sharepoint_orgwide_only() {
        // Mail/calendar/contacts no longer offer a per-row Scope… — Exchange RBAC
        // scoping is app-wide, driven by the "Exchange scoping" section.
        assert_eq!(existing_scope_kind_for("Mail.Read"), None);
        assert_eq!(
            existing_scope_kind_for("Sites.Read.All"),
            Some(ScopeKind::SharePoint)
        );
        // Sites.Selected is already per-site, so it can't be *re*-scoped.
        assert_eq!(existing_scope_kind_for("Sites.Selected"), None);
        assert_eq!(existing_scope_kind_for("User.Read"), None);
    }

    #[test]
    fn chip_kind_for_maps_each_subtype() {
        assert_eq!(
            chip_kind_for(MiSubtype::SystemAssigned),
            AppKind::ManagedIdentitySystem
        );
        assert_eq!(
            chip_kind_for(MiSubtype::UserAssigned),
            AppKind::ManagedIdentityUser
        );
        assert_eq!(
            chip_kind_for(MiSubtype::Unknown),
            AppKind::ManagedIdentityUnknown
        );
    }

    #[test]
    fn mi_counts_tallies_subtype_and_enabled_state() {
        let items = vec![
            mk_mi(MiSubtype::SystemAssigned, Some(true)),
            mk_mi(MiSubtype::UserAssigned, Some(true)),
            mk_mi(MiSubtype::UserAssigned, Some(false)),
            mk_mi(MiSubtype::Unknown, None),
        ];
        let c = mi_counts(&items);
        assert_eq!(c.system, 1);
        assert_eq!(c.user, 2);
        assert_eq!(c.enabled, 2);
        assert_eq!(c.disabled, 1);
    }

    #[test]
    fn matches_mi_facet_filters_by_subtype_and_state() {
        let sys_on = mk_mi(MiSubtype::SystemAssigned, Some(true));
        let usr_off = mk_mi(MiSubtype::UserAssigned, Some(false));
        assert!(matches_mi_facet(&sys_on, "system"));
        assert!(!matches_mi_facet(&sys_on, "user"));
        assert!(matches_mi_facet(&sys_on, "enabled"));
        assert!(matches_mi_facet(&usr_off, "disabled"));
        assert!(!matches_mi_facet(&usr_off, "enabled"));
        // An unknown facet (e.g. the "all" chip) matches everything.
        assert!(matches_mi_facet(&sys_on, "all"));
    }
}
