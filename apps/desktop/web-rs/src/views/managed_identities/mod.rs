//! Managed Identities view: discover managed identities and grant them
//! application permissions (the RBAC equivalent of `Grant-AzManagedIdentityPermission`).
//! Master list on the left, selected-identity properties + grant form on the right.

mod row;
mod scoping;

pub(crate) use row::chip_kind_for;
pub(crate) use scoping::{existing_scope_kind_for, PendingScope};

use std::collections::HashMap;
use std::sync::Arc;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Spinner, SpinnerSize};

use azapptoolkit_core::audit::MailPermissionScope;

use crate::components::icon::IconName;
use crate::components::permission_picker::PickerSelection;
use crate::components::scope_badge::is_exchange_scopable;
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
use crate::constants::*;
use crate::hooks::use_command::use_command;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_filtered_list::{use_filtered_list, Facet, FilteredListSpec};
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::managed_identity_detail_pane::ManagedIdentityDetailPane;

use row::render_row;
use scoping::scope_kind_for;

/// Microsoft Graph's first-party app id — mail/calendar/contacts and
/// `Sites.Selected` application permissions live on this resource, so scoping
/// only applies when the picked permission's resource matches.
pub(crate) const MICROSOFT_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

use crate::util::no_tenant;

/// Whether a managed identity matches the active facet chip. `all` (and any
/// unknown value) matches everything. Drives the `use_filtered_list` facet
/// predicates (per-facet counts come from the hook).
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

    // One shared command runner for every grant/revoke/scope mutation below —
    // they share a single busy + error (only one runs at a time; one error
    // surface). `cmd.busy`/`cmd.error` flow to the detail pane and confirm dialog.
    let cmd = use_command();
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
        if cmd.busy.get() {
            return;
        }
        let Some(id) = selected_id.get() else {
            return;
        };
        cmd.error.set(None);
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

        cmd.run(
            move |r| {
                result.set(Some(r));
                reload.update(|n| *n += 1);
            },
            move |tenant_id| async move {
                managed_identity::grant_managed_identity_permission(
                    &tenant_id,
                    &id,
                    &sel.resource_app_id,
                    &[sel.permission_value.clone()],
                )
                .await
            },
        );
    });

    // Cancel the pending scope panel without granting.
    let cancel_scope = move |_| {
        pending_scope.set(None);
        cmd.error.set(None);
    };

    // Grant the pending permission org-wide (the panel's fallback button).
    let submit_orgwide = move |_| {
        let Some(p) = pending_scope.get() else {
            return;
        };
        cmd.run(
            move |r| {
                result.set(Some(r));
                pending_scope.set(None);
                reload.update(|n| *n += 1);
            },
            move |tenant_id| async move {
                managed_identity::grant_managed_identity_permission(
                    &tenant_id,
                    &p.sp_object_id,
                    &p.resource_app_id,
                    &[p.permission_value.clone()],
                )
                .await
            },
        );
    };

    // Grant the pending mail permission scoped to mailbox group(s) via RBAC.
    let submit_exchange = move |_| {
        let Some(p) = pending_scope.get() else {
            return;
        };
        if cmd.busy.get() {
            return;
        }
        let groups = parse_lines(&scope_groups_text.get());
        if groups.is_empty() {
            cmd.error.set(Some(
                "Enter at least one group or mailbox identifier.".into(),
            ));
            return;
        }
        scope_note.set(None);
        // `p` feeds both the op (sp/app/name) and the success note (its
        // permission value), so pull the note's part out before `p` moves.
        let perm_value = p.permission_value.clone();
        cmd.run(
            move |r: exchange_bindings::ExchangeAccessResult| {
                let mut note = format!(
                    "Scoped {} via “{}” — {} role(s) assigned, {} org-wide grant(s) removed.",
                    perm_value,
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
            },
            move |tenant_id| async move {
                exchange_bindings::grant_managed_identity_scoped_exchange_access(
                    &tenant_id,
                    &p.sp_object_id,
                    &p.app_id,
                    &p.display_name,
                    &[p.permission_value.clone()],
                    &groups,
                    true,
                )
                .await
            },
        );
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
        if cmd.busy.get() {
            return;
        }
        let url = scope_site_url.get().trim().to_string();
        if url.is_empty() {
            cmd.error.set(Some("Enter a SharePoint site URL.".into()));
            return;
        }
        scope_note.set(None);
        let url_op = url.clone();
        cmd.run(
            move |r: sharepoint::SiteScopeResult| {
                let site = r
                    .sites_granted
                    .first()
                    .and_then(|s| s.site_display_name.clone())
                    .unwrap_or(url);
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
            },
            move |tenant_id| async move {
                sharepoint::convert_site_access_to_selected(
                    &tenant_id,
                    &p.sp_object_id,
                    &p.app_id,
                    &p.display_name,
                    &[url_op],
                    role,
                    true,
                )
                .await
            },
        );
    };

    let do_revoke = move |assignment_id: String, sp_id: String| {
        cmd.run(
            move |()| {
                reload.update(|n| *n += 1);
                pending_revoke.set(None);
            },
            move |tenant_id| async move {
                permissions_bindings::revoke_app_role_assignment(&tenant_id, &sp_id, &assignment_id)
                    .await
            },
        );
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
                busy=cmd.busy
                error=cmd.error
                on_confirm=Callback::new(move |()| {
                    if let Some((aid, sp)) = pending_revoke.get() {
                        do_revoke(aid, sp);
                    }
                })
                on_close=Callback::new(move |()| {
                    pending_revoke.set(None);
                    cmd.error.set(None);
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
                                                error=cmd.error
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
                                            busy=cmd.busy
                                            error=cmd.error
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
                                                cmd.error.set(None);
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
    let list = use_filtered_list(FilteredListSpec {
        items: list,
        search,
        search_match: |mi: &ManagedIdentityDto, needle: &str| {
            mi.display_name.to_lowercase().contains(needle)
        },
        // No date range or other extra filter on this list — search only.
        extra_active: Signal::derive(|| false),
        extra: |_mi: &ManagedIdentityDto| true,
        facet: mi_filter,
        facet_any: "all",
        facets: vec![
            Facet::new("System", "system", |mi: &ManagedIdentityDto| {
                matches_mi_facet(mi, "system")
            }),
            Facet::new("User", "user", |mi: &ManagedIdentityDto| {
                matches_mi_facet(mi, "user")
            }),
            Facet::new("Enabled", "enabled", |mi: &ManagedIdentityDto| {
                matches_mi_facet(mi, "enabled")
            }),
            Facet::new("Disabled", "disabled", |mi: &ManagedIdentityDto| {
                matches_mi_facet(mi, "disabled")
            }),
        ],
        export_rows: Some(export_rows),
    });

    let filtered = list.shown;
    let base_total = list.base_total();
    let system = list.count_of("system");
    let user = list.count_of("user");
    let enabled = list.count_of("enabled");
    let disabled = list.count_of("disabled");

    view! {
        {move || {
            view! {
                <div class="filter-chips">
                    <FilterChip label="All" value="all" count=base_total.get() facet=mi_filter />
                    <FilterChip
                        label="System"
                        value="system"
                        count=system.get()
                        facet=mi_filter
                    />
                    <FilterChip label="User" value="user" count=user.get() facet=mi_filter />
                    <FilterChip
                        label="Enabled"
                        value="enabled"
                        count=enabled.get()
                        facet=mi_filter
                    />
                    <FilterChip
                        label="Disabled"
                        value="disabled"
                        count=disabled.get()
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
                row_height=ROW_HEIGHT
                overscan=OVERSCAN
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
