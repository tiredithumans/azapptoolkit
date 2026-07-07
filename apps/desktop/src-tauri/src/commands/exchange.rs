//! Exchange Online RBAC-for-Applications commands.
//!
//! These replace the deprecated Application Access Policy flow: instead of a
//! single mail-enabled security group scoped via `New-ApplicationAccessPolicy`,
//! an app's mailbox access is scoped with an Exchange management scope
//! (`MemberOfGroup` recipient filter) plus per-role management role
//! assignments (`New-ManagementRoleAssignment -App ... -CustomResourceScope`).
//!
//! Because RBAC grants union with Microsoft Entra ID consents, scoping is only
//! effective once the org-wide Entra app-role assignment for the same
//! permission is removed — these commands do that explicitly.

use std::collections::{HashMap, HashSet};

use tauri::State;

use azapptoolkit_core::audit::{MailPermissionScope, ScopeMechanism};
use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{AppRoleAssignment, Application};
use azapptoolkit_core::scoping::is_scopable_exchange_permission;
use azapptoolkit_exchange::models::{ExoApplicationAccessPolicy, ExoAuthorizationResult};
use azapptoolkit_exchange::{
    ExchangeClient, ExchangeError, exchange_role_for_graph_permission, member_of_group_filter,
};
use azapptoolkit_graph::GraphClient;

use crate::commands::applications::invalidate_app_lists;
use crate::commands::graph_roles::{MICROSOFT_GRAPH_APP_ID, graph_role_index};
use crate::dto::UiError;
use crate::dto::exchange::{
    AapMigrationItem, AapMigrationReport, ExchangeAccessRemovalResult, ExchangeAccessResult,
    ExchangeGroupMemberDto, ExchangeGroupRef, ExchangeMemberFailure, ExchangeMemberMutationResult,
    ExchangeRoleAssignmentDto, ExchangeScopeGroupDto, MailScopeEntry,
};
use crate::state::AppState;
use azapptoolkit_core::defaults::TenantDefaults;
use azapptoolkit_core::settings::UserSettings;

/// Loads this tenant's operator defaults from `settings.json` (an empty set if
/// none). It is the source of the configurable Exchange naming patterns —
/// [`TenantDefaults::scope_name_for`] (management scope, default
/// `app_scope_<app_id>`) and [`TenantDefaults::group_name_for`] (mail-enabled
/// scope group, default `app_scope_group_<app_id>`). The two defaults are kept
/// distinct so a scope and its backing group never collide on name; both apply
/// to every Exchange scoping path (fresh grants and legacy-AAP migration).
fn load_tenant_defaults(tenant_id: &str) -> TenantDefaults {
    UserSettings::stored(&crate::config_directory()).defaults_for(tenant_id)
}

/// Exchange aliases allow only a restricted character set and cap at 64 chars.
/// An appId GUID is already alias-safe; this only guards against anything
/// unexpected in `app_id` by dropping disallowed characters and truncating.
fn sanitize_alias(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(64)
        .collect()
}

/// Resolves the signed-in admin's UPN and returns a ready Exchange client. The
/// UPN is mandatory — it is the `X-AnchorMailbox` routing hint for every Admin
/// API call.
pub(crate) fn exchange_client(
    state: &AppState,
    tenant_id: &str,
) -> Result<std::sync::Arc<ExchangeClient>, UiError> {
    let tenant = state.auth.tenant_context(tenant_id).ok_or_else(|| {
        UiError::validation(
            "not_signed_in",
            format!("not signed in to tenant {tenant_id}"),
        )
    })?;
    let upn = tenant.username.ok_or_else(|| {
        UiError::validation(
            "no_anchor_mailbox",
            "signed-in account has no UPN; cannot set the Exchange X-AnchorMailbox",
        )
    })?;
    Ok(state.exchange_for(tenant_id, &upn))
}

/// Like [`exchange_client`] but first pre-acquires the `Exchange.Manage` token
/// with a typed call, so a not-yet-consented Exchange scope surfaces as the
/// typed `consent_required` (the UI offers a "Grant consent" button) instead of
/// being flattened to a generic `token_error` deep inside the admin-API call.
/// Mirrors the SharePoint/ARM/audit `ensure_*_token` pre-acquire pattern. A
/// *consented-but-RBAC-blocked* user passes this and instead gets an actionable
/// 403 from the admin API (see `ExchangeError::ui_hint`).
pub(crate) async fn exchange_client_checked(
    state: &AppState,
    tenant_id: &str,
) -> Result<std::sync::Arc<ExchangeClient>, UiError> {
    state.ensure_exchange_token(tenant_id).await?;
    exchange_client(state, tenant_id)
}

/// An Exchange permission the app declares/holds, paired with its Exchange
/// application role and the Graph appRole id that backs it (used to remove the
/// unscoped Entra grant).
#[derive(Clone)]
struct ExchangeTarget {
    graph_value: String,
    exchange_role: &'static str,
    app_role_id: String,
}

/// Builds an [`ExchangeTarget`] for a Graph permission value, or `None` when the
/// value isn't one of the Exchange-scopable mail/calendar/contacts permissions.
/// The single construction point shared by all three target-derivation paths
/// (declared perms, granted assignments, and the managed-identity value list),
/// so the `ExchangeTarget` shape and the scopability check live in one place.
fn exchange_target(app_role_id: String, graph_value: String) -> Option<ExchangeTarget> {
    exchange_role_for_graph_permission(&graph_value).map(|exchange_role| ExchangeTarget {
        graph_value,
        exchange_role,
        app_role_id,
    })
}

/// Targets derived from the app's *declared* permissions (`requiredResourceAccess`).
fn targets_from_declared(
    app: &Application,
    role_value_by_id: &HashMap<String, String>,
) -> Vec<ExchangeTarget> {
    let mut out = Vec::new();
    for resource in &app.required_resource_access {
        if resource.resource_app_id != MICROSOFT_GRAPH_APP_ID {
            continue;
        }
        for access in &resource.resource_access {
            if access.r#type != "Role" {
                continue;
            }
            if let Some(value) = role_value_by_id.get(&access.id)
                && let Some(t) = exchange_target(access.id.clone(), value.clone())
            {
                out.push(t);
            }
        }
    }
    out
}

/// Extracts the set of group DistinguishedNames quoted in a `MemberOfGroup`
/// OPATH filter (`… -eq 'CN=a,DC=x' -or …`). Lets us compare a stored scope
/// filter to a freshly-built one by group *set*, without depending on Exchange's
/// exact whitespace/paren formatting. Handles OPATH's doubled-quote escaping
/// (`''` → `'`).
fn group_dns_in_filter(filter: &str) -> std::collections::HashSet<&str> {
    let mut out = std::collections::HashSet::new();
    let bytes = filter.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\'' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        while j < bytes.len() {
            if bytes[j] == b'\'' {
                // A doubled '' is an escaped quote inside the value, not a close.
                if bytes.get(j + 1) == Some(&b'\'') {
                    j += 2;
                    continue;
                }
                break;
            }
            j += 1;
        }
        // Only record values with no embedded escaped quote — DNs never contain
        // apostrophes, so a clean slice is the common (and only relevant) case.
        if !filter[start..j].contains("''") {
            out.insert(&filter[start..j]);
        }
        i = j + 1;
    }
    out
}

/// Narrows `targets` to the requested permission values. `None` keeps every
/// target (scope all declared mail permissions); `Some` keeps only those whose
/// `graph_value` is listed — the per-permission "scope this one permission"
/// path. An empty `Some` list therefore retains nothing.
fn filter_targets_by_value(
    targets: Vec<ExchangeTarget>,
    only: Option<&[String]>,
) -> Vec<ExchangeTarget> {
    match only {
        None => targets,
        Some(values) => {
            let set: std::collections::HashSet<&str> = values.iter().map(String::as_str).collect();
            targets
                .into_iter()
                .filter(|t| set.contains(t.graph_value.as_str()))
                .collect()
        }
    }
}

/// Targets derived from the app's *granted* Entra app-role assignments. Used
/// during migration, where the app already holds org-wide grants.
fn targets_from_grants(
    assignments: &[AppRoleAssignment],
    graph_resource_sp_id: &str,
    role_value_by_id: &HashMap<String, String>,
) -> Vec<ExchangeTarget> {
    let mut out = Vec::new();
    for a in assignments {
        if a.resource_id != graph_resource_sp_id {
            continue;
        }
        if let Some(value) = role_value_by_id.get(&a.app_role_id)
            && let Some(t) = exchange_target(a.app_role_id.clone(), value.clone())
        {
            out.push(t);
        }
    }
    out
}

/// Removes the org-wide Entra app-role assignments for `targets` from the
/// service principal, so the scoped Exchange grant is not unioned away.
/// Returns the permission values actually removed; appends any failures to
/// `warnings`.
async fn remove_unscoped_grants(
    client: &GraphClient,
    sp_id: &str,
    graph_resource_sp_id: &str,
    targets: &[ExchangeTarget],
    warnings: &mut Vec<String>,
) -> Vec<String> {
    let assignments = match client.list_app_role_assignments(sp_id).await {
        Ok(a) => a,
        Err(err) => {
            warnings.push(format!("could not list Entra app-role assignments: {err}"));
            return Vec::new();
        }
    };
    let mut removed = Vec::new();
    for t in targets {
        let found = assignments
            .iter()
            .find(|a| a.resource_id == graph_resource_sp_id && a.app_role_id == t.app_role_id);
        if let Some(a) = found {
            match client.remove_app_role_assignment(sp_id, &a.id).await {
                Ok(()) => removed.push(t.graph_value.clone()),
                Err(err) => warnings.push(format!(
                    "failed to remove unscoped grant {}: {err}",
                    t.graph_value
                )),
            }
        }
    }
    removed
}

/// Given each target paired with whether its scoped Exchange role is now in place
/// (newly assigned **or** already present), returns the subset whose org-wide
/// Entra grant is safe to strip. A target whose scoped role assignment *failed*
/// is excluded, so the broad grant is never removed out from under a principal
/// that has no scoped replacement — the Exchange analogue of SharePoint's
/// `should_remove_orgwide` grant-before-strip guard.
fn targets_safe_to_strip(scoped: Vec<(ExchangeTarget, bool)>) -> Vec<ExchangeTarget> {
    scoped
        .into_iter()
        .filter_map(|(t, role_in_place)| role_in_place.then_some(t))
        .collect()
}

/// Inputs to [`apply_exchange_mailbox_scope`], grouped so each is named at the
/// call site. Several are `&str` (tenant/app/sp ids), where a long positional
/// list is easy to transpose — hence a struct rather than 12 bare arguments.
struct ApplyExchangeMailboxScopeParams<'a> {
    state: &'a AppState,
    graph: &'a GraphClient,
    exo: &'a ExchangeClient,
    tenant_id: &'a str,
    app_id: &'a str,
    sp_object_id: &'a str,
    display_name: &'a str,
    graph_resource_sp_id: &'a str,
    targets: &'a [ExchangeTarget],
    groups: &'a [String],
    remove_unscoped: bool,
    warnings: Vec<String>,
}

/// Assigns each target's Exchange role scoped to `scope_name` (idempotent),
/// recording per-target whether the scoped role ended up in place — so the
/// caller strips a target's org-wide Entra grant only once its scoped
/// replacement actually landed (a failed assignment keeps its broad grant;
/// never strand the app). Returns `(roles_assigned, roles_skipped, scoped)`;
/// `roles_skipped` lists targets whose scoped role already existed. Shared by
/// `apply_exchange_mailbox_scope` and the AAP-migration path so the
/// strand-guard tracking lives in one place.
async fn assign_scoped_roles(
    exo: &ExchangeClient,
    app_id: &str,
    scope_name: &str,
    targets: &[ExchangeTarget],
    warnings: &mut Vec<String>,
) -> (Vec<String>, Vec<String>, Vec<(ExchangeTarget, bool)>) {
    let existing = exo.get_role_assignments(app_id).await.unwrap_or_default();
    let mut roles_assigned = Vec::new();
    let mut roles_skipped = Vec::new();
    let mut scoped: Vec<(ExchangeTarget, bool)> = Vec::new();
    for t in targets {
        let already = existing.iter().any(|a| {
            a.role.as_deref() == Some(t.exchange_role)
                && a.custom_resource_scope.as_deref() == Some(scope_name)
        });
        let role_in_place = if already {
            roles_skipped.push(t.exchange_role.to_string());
            true
        } else {
            match exo
                .new_role_assignment(app_id, t.exchange_role, Some(scope_name))
                .await
            {
                Ok(_) => {
                    roles_assigned.push(t.exchange_role.to_string());
                    true
                }
                Err(err) => {
                    warnings.push(format!("failed to assign {}: {err}", t.exchange_role));
                    false
                }
            }
        };
        scoped.push((t.clone(), role_in_place));
    }
    (roles_assigned, roles_skipped, scoped)
}

/// Shared core of a scoped-mailbox grant: register the Exchange service-principal
/// pointer, resolve `groups` into a management scope, assign each target's
/// Exchange role scoped to it (idempotent), and — when `remove_unscoped` — strip
/// the org-wide Entra grants so the scope is actually effective. The two callers
/// differ only in how `targets` are derived: from an app registration's manifest
/// (`targets_from_declared`) or from the permission being granted to a managed
/// identity. `warnings` is seeded by the caller and extended here.
async fn apply_exchange_mailbox_scope(
    params: ApplyExchangeMailboxScopeParams<'_>,
) -> Result<ExchangeAccessResult, UiError> {
    let ApplyExchangeMailboxScopeParams {
        state,
        graph,
        exo,
        tenant_id,
        app_id,
        sp_object_id,
        display_name,
        graph_resource_sp_id,
        targets,
        groups,
        remove_unscoped,
        mut warnings,
    } = params;
    // Register the Exchange service-principal pointer to the Entra SP.
    exo.ensure_service_principal(app_id, sp_object_id, display_name)
        .await?;

    // Resolve each group to its DistinguishedName for the MemberOfGroup filter.
    let mut group_refs = Vec::new();
    let mut dns = Vec::new();
    for identifier in groups {
        match exo.get_group(identifier).await {
            Ok(Some(g)) => {
                let dn = g.distinguished_name.clone();
                if let Some(dn) = &dn {
                    dns.push(dn.clone());
                } else {
                    warnings.push(format!("group '{identifier}' has no distinguished name"));
                }
                group_refs.push(ExchangeGroupRef {
                    identifier: identifier.clone(),
                    distinguished_name: dn,
                });
            }
            Ok(None) => {
                warnings.push(format!("group '{identifier}' not found in Exchange"));
                group_refs.push(ExchangeGroupRef {
                    identifier: identifier.clone(),
                    distinguished_name: None,
                });
            }
            Err(err) => return Err(err.into()),
        }
    }

    if dns.is_empty() {
        return Err(UiError::validation(
            "no_scope_group",
            "none of the supplied groups resolved to a distinguished name; cannot build a management scope",
        ));
    }

    // The management-scope name follows this tenant's configured pattern (blank ⇒
    // the built-in `app_scope_<app_id>`), so a fresh scoped grant and the
    // legacy-AAP migration name their scopes identically. See
    // `TenantDefaults::scope_name_for`.
    let scope_name = load_tenant_defaults(tenant_id).scope_name_for(app_id);
    let scope_filter = member_of_group_filter(&dns);
    // There is exactly one management scope per app (its resolved `scope_name`),
    // and `ensure_management_scope` keeps an EXISTING scope as-is rather than
    // rewriting its filter. So if a different permission was already scoped to a
    // different group set, the groups requested *here* silently won't apply —
    // warn instead of misleading the user into thinking they took effect.
    if let Ok(Some(existing)) = exo.get_management_scope(&scope_name).await
        && let Some(existing_filter) = existing.recipient_filter.as_deref()
    {
        let wanted: std::collections::HashSet<&str> = dns.iter().map(String::as_str).collect();
        let have = group_dns_in_filter(existing_filter);
        if have != wanted {
            warnings.push(format!(
                    "a management scope “{scope_name}” already exists for this app with a different group set — \
                     Exchange keeps the existing scope, so the groups requested here were NOT applied to it. \
                     Edit or remove the scope in Exchange to change which mailboxes this app can reach."
                ));
        }
    }
    exo.ensure_management_scope(&scope_name, &scope_filter)
        .await?;

    // Assign each Exchange role scoped to the management scope (idempotent),
    // tracking per target whether its scoped role ended up in place so we only
    // strip the org-wide grant for permissions that actually got a scoped
    // replacement (a failed assignment must keep its broad grant).
    let (roles_assigned, roles_skipped, scoped) =
        assign_scoped_roles(exo, app_id, &scope_name, targets, &mut warnings).await;

    let removed_entra_grants = if remove_unscoped {
        remove_unscoped_grants(
            graph,
            sp_object_id,
            graph_resource_sp_id,
            &targets_safe_to_strip(scoped),
            &mut warnings,
        )
        .await
    } else {
        warnings.push(
            "unscoped Entra grants were left in place; scoping is NOT effective until they are removed".into(),
        );
        Vec::new()
    };

    // `ensure_service_principal` above may have created/registered an SP, adding
    // a pairing the cached App Registrations / Enterprise Apps lists (and the
    // shared SP index) must reflect. Invalidate only on this success path.
    invalidate_app_lists(&state.cache, tenant_id);

    Ok(ExchangeAccessResult {
        app_id: app_id.to_string(),
        service_principal_object_id: Some(sp_object_id.to_string()),
        scope_name,
        scope_filter,
        groups: group_refs,
        roles_assigned,
        roles_skipped,
        removed_entra_grants,
        warnings,
    })
}

// ---------------- Grant scoped mailbox access ----------------

/// Scopes an application's mailbox access to the members of one or more groups
/// using Exchange RBAC. Roles are derived from the app's declared Microsoft
/// Graph mail/calendar/contacts permissions. When `permissions` is `Some`, only
/// the listed permission values are scoped (the per-permission "scope this one"
/// path); `None` scopes every declared mail permission (the coarse Exchange-scoping-section
/// action).
#[tauri::command]
pub async fn grant_exchange_mailbox_access(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    permissions: Option<Vec<String>>,
    groups: Vec<String>,
    remove_unscoped_entra_grants: bool,
) -> Result<ExchangeAccessResult, UiError> {
    let graph = state.graph_for(&tenant_id);
    let exo = exchange_client_checked(&state, &tenant_id).await?;

    let app = graph.get_application(&object_id).await?;
    // The list caches are busted unconditionally on success below (line ~450),
    // so the `created` flag isn't needed here.
    let (entra_sp, _created) = graph.ensure_service_principal(&app.app_id).await?;
    let (graph_resource_sp_id, role_value_by_id) = graph_role_index(&graph).await?;

    let targets = filter_targets_by_value(
        targets_from_declared(&app, &role_value_by_id),
        permissions.as_deref(),
    );
    let mut warnings = Vec::new();
    if targets.is_empty() {
        warnings.push(
            "application declares no Exchange-scopable Graph permissions (Mail/Calendars/Contacts) matching the request; nothing to scope".into(),
        );
    }

    apply_exchange_mailbox_scope(ApplyExchangeMailboxScopeParams {
        state: &state,
        graph: &graph,
        exo: &exo,
        tenant_id: &tenant_id,
        app_id: &app.app_id,
        sp_object_id: &entra_sp.id,
        display_name: &app.display_name,
        graph_resource_sp_id: &graph_resource_sp_id,
        targets: &targets,
        groups: &groups,
        remove_unscoped: remove_unscoped_entra_grants,
        warnings,
    })
    .await
}

/// Scopes a **managed identity's** mailbox access to one or more groups via
/// Exchange RBAC. Unlike [`grant_exchange_mailbox_access`], the targets come
/// from the `mail_permissions` being granted (a managed identity has no app
/// registration manifest), and the SP object id is the managed identity itself.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn grant_managed_identity_scoped_exchange_access(
    state: State<'_, AppState>,
    tenant_id: String,
    managed_identity_id: String,
    app_id: String,
    app_display_name: String,
    mail_permissions: Vec<String>,
    groups: Vec<String>,
    remove_unscoped_entra_grants: bool,
) -> Result<ExchangeAccessResult, UiError> {
    let graph = state.graph_for(&tenant_id);
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let (graph_resource_sp_id, role_value_by_id) = graph_role_index(&graph).await?;

    // value -> appRole id, so `remove_unscoped_grants` can find the org-wide
    // assignment for each permission to strip.
    let id_by_value: HashMap<&str, &str> = role_value_by_id
        .iter()
        .map(|(id, value)| (value.as_str(), id.as_str()))
        .collect();

    let mut warnings = Vec::new();
    let mut targets = Vec::new();
    for perm in &mail_permissions {
        let app_role_id = id_by_value
            .get(perm.as_str())
            .map(|id| id.to_string())
            .unwrap_or_default();
        match exchange_target(app_role_id, perm.clone()) {
            Some(t) => targets.push(t),
            None => warnings.push(format!(
                "{perm} is not an Exchange-scopable permission; skipped"
            )),
        }
    }
    if targets.is_empty() {
        return Err(UiError::validation(
            "no_scopable_permission",
            "none of the selected permissions can be scoped via Exchange RBAC for Applications",
        ));
    }

    apply_exchange_mailbox_scope(ApplyExchangeMailboxScopeParams {
        state: &state,
        graph: &graph,
        exo: &exo,
        tenant_id: &tenant_id,
        app_id: &app_id,
        sp_object_id: &managed_identity_id,
        display_name: &app_display_name,
        graph_resource_sp_id: &graph_resource_sp_id,
        targets: &targets,
        groups: &groups,
        remove_unscoped: remove_unscoped_entra_grants,
        warnings,
    })
    .await
}

// ---------------- List / remove ----------------

#[tauri::command]
pub async fn list_exchange_role_assignments(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<Vec<ExchangeRoleAssignmentDto>, UiError> {
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let assignments = exo.get_role_assignments(&app_id).await?;
    Ok(assignments
        .into_iter()
        .map(|a| ExchangeRoleAssignmentDto {
            name: a.name,
            role: a.role,
            custom_resource_scope: a.custom_resource_scope,
            identity: a.identity,
        })
        .collect())
}

// ---------------- Effective mailbox scoping (read-only) ----------------

/// True when a `Test-ServicePrincipalAuthorization` row is *not* confined to a
/// recipient scope — i.e. the grant reaches every mailbox in the tenant. The
/// `ScopeType` enum returned by EXO uses values like `OrganizationConfig` /
/// `NotApplicable` for org-wide; a custom management scope reports its name in
/// `AllowedResourceScope` with a `*RecipientScope` type. We treat an empty /
/// "Not Applicable" `AllowedResourceScope` as org-wide too, and default to
/// org-wide (the conservative, never-under-report choice) when unsure.
pub(crate) fn is_org_wide_auth_row(r: &ExoAuthorizationResult) -> bool {
    let allowed = r.allowed_resource_scope.as_deref().unwrap_or("").trim();
    if allowed.is_empty() || allowed.eq_ignore_ascii_case("Not Applicable") {
        return true;
    }
    matches!(
        r.scope_type
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "" | "notapplicable" | "organizationconfig" | "organizationscope" | "organization"
    )
}

/// Folds the authorization rows for one Exchange role into a single verdict:
/// no row → `OrgWide` (queried OK, no scoped restriction); any org-wide row →
/// `OrgWide` (it unions to tenant-wide reach); otherwise `Scoped` to the named
/// management scope.
fn verdict_from_rows(rows: &[&ExoAuthorizationResult]) -> MailPermissionScope {
    if rows.is_empty() || rows.iter().any(|r| is_org_wide_auth_row(r)) {
        return MailPermissionScope::OrgWide;
    }
    let scope_name = rows
        .iter()
        .find_map(|r| r.allowed_resource_scope.clone())
        .filter(|s| !s.trim().is_empty());
    MailPermissionScope::Scoped {
        scope_name,
        recipient_filter: None,
        group_count: None,
        mechanism: ScopeMechanism::Rbac,
    }
}

/// Resolves whether a legacy Application Access Policy confines `app_id`'s
/// mailbox access. An AAP applies to the whole application (not per-permission),
/// so a single lookup covers every permission. Only a `RestrictAccess` policy
/// *scopes* access to its group; a `DenyAccess` policy is a blocklist (access to
/// everything *except* the group), which is still effectively org-wide, so it is
/// not reported as scoped. Returns `None` on any Exchange error (the RBAC
/// verdict — org-wide — then stands, never under-reporting risk).
async fn legacy_aap_scope(exo: &ExchangeClient, app_id: &str) -> Option<MailPermissionScope> {
    let policies = exo.get_application_access_policies().await.ok()?;
    aap_verdict_for(&policies, app_id)
}

/// Pure decision behind [`legacy_aap_scope`]: does any legacy Application Access
/// Policy *confine* `app_id`'s mailbox access? Only a `RestrictAccess` policy
/// scopes access to its group; a `DenyAccess` policy is a blocklist (access to
/// everything *except* the group), which is still effectively org-wide, so it is
/// not reported as scoped.
pub(crate) fn aap_verdict_for(
    policies: &[ExoApplicationAccessPolicy],
    app_id: &str,
) -> Option<MailPermissionScope> {
    let policy = policies.iter().find(|p| {
        p.app_id.as_deref() == Some(app_id)
            && p.access_right
                .as_deref()
                .is_some_and(|r| r.eq_ignore_ascii_case("RestrictAccess"))
    })?;
    Some(MailPermissionScope::Scoped {
        scope_name: policy
            .scope_name
            .clone()
            .or_else(|| policy.scope_identity.clone()),
        recipient_filter: policy.description.clone(),
        group_count: None,
        mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
    })
}

/// Per-app mailbox-scope fallback when `Test-ServicePrincipalAuthorization`
/// itself fails (detail/enrich path only). An AAP confines the *whole* app (see
/// [`legacy_aap_scope`]), so the verdict applies to every scopable permission.
/// A `RestrictAccess` AAP keyed on this exact appId is stronger evidence than a
/// failed probe, so it wins even over a 403. A principal Exchange can't resolve
/// (the managed-identity case — it isn't in Exchange's SP store) has no RBAC
/// scope, so absent an AAP its org-wide Graph grant reaches every mailbox =>
/// `OrgWide`. Any other failure (403/401/network) is genuinely indeterminate and
/// is surfaced to the caller so the UI can explain *why*.
fn scope_from_rbac_error(
    err: ExchangeError,
    aap: Option<MailPermissionScope>,
) -> Result<MailPermissionScope, ExchangeError> {
    if let Some(scoped) = aap {
        return Ok(scoped);
    }
    if err.is_missing_object() {
        return Ok(MailPermissionScope::OrgWide);
    }
    Err(err)
}

/// Counts `MemberOfGroup` clauses in an OPATH recipient filter (the number of
/// groups a management scope confines access to).
fn count_member_of_group(filter: &str) -> usize {
    filter.to_ascii_lowercase().matches("memberofgroup").count()
}

/// Reconciles one permission's scope verdict against the org-wide Entra grants
/// the principal still holds. A scoped **RBAC** verdict for a permission whose
/// org-wide grant was never removed unions to tenant-wide reach, so it becomes
/// `OrgWide` (what `Test-ServicePrincipalAuthorization` alone misses — it can't
/// see Entra grants). A legacy Application Access Policy is exempt: it genuinely
/// confines an org-wide grant. Org-wide / unknown verdicts pass through.
fn reconcile_orgwide_grant(
    verdict: MailPermissionScope,
    perm: &str,
    orgwide_granted: &HashSet<String>,
) -> MailPermissionScope {
    let scoped_via_rbac = matches!(
        verdict,
        MailPermissionScope::Scoped {
            mechanism: ScopeMechanism::Rbac,
            ..
        }
    );
    if scoped_via_rbac && orgwide_granted.contains(perm) {
        MailPermissionScope::OrgWide
    } else {
        verdict
    }
}

/// Mail/calendar/contacts Graph permission **values** that `sp_object_id` holds
/// as **org-wide Entra app-role grants** (appRoleAssignments on the Microsoft
/// Graph resource). `Test-ServicePrincipalAuthorization` deliberately *excludes*
/// these — it reports only the Exchange RBAC layer — so a scoped RBAC verdict
/// must be reconciled against them: per Microsoft's RBAC-for-Applications
/// guidance, an un-stripped org-wide grant *unions* with the scoped role to
/// reach every mailbox ("remove the assignment … in Microsoft Entra ID.
/// Otherwise, the union … results in no effective resource scoping"). A legacy
/// Application Access Policy, by contrast, genuinely confines an org-wide grant,
/// so it is *not* reconciled away (see [`verdict_from_rows`] / [`aap_verdict_for`]).
///
/// Best-effort: any read failure yields an empty set (no reconciliation) rather
/// than fabricating an org-wide verdict from a transient error.
pub(crate) async fn held_orgwide_mail_grants(
    graph: &GraphClient,
    sp_object_id: &str,
) -> HashSet<String> {
    let Ok((graph_sp_id, role_value_by_id)) = graph_role_index(graph).await else {
        return HashSet::new();
    };
    let Ok(assignments) = graph.list_app_role_assignments(sp_object_id).await else {
        return HashSet::new();
    };
    assignments
        .iter()
        // Only Microsoft Graph appRole ids resolve to mail permission values;
        // guard on the resource so an id collision on another API can't match.
        .filter(|a| a.resource_id == graph_sp_id)
        .filter_map(|a| role_value_by_id.get(&a.app_role_id))
        .filter(|v| is_scopable_exchange_permission(v))
        .cloned()
        .collect()
}

/// Resolves the effective Exchange mailbox scoping for each Exchange-scopable
/// permission in `graph_perms`. Primary source: `Test-ServicePrincipalAuthorization`,
/// which reports the **Exchange RBAC layer only** — it deliberately *excludes*
/// permissions granted separately in Microsoft Entra ID. A scoped RBAC verdict is
/// therefore reconciled against `orgwide_granted` (the mail permissions the
/// principal still holds as org-wide Entra app-role grants — see
/// [`held_orgwide_mail_grants`]): an un-stripped org-wide grant *unions* with the
/// scoped role to reach every mailbox, so that permission is reported `OrgWide`,
/// which is what actually catches "scope created but org-wide grant never removed".
/// When the probe *fails*, the verdict depends on why: a
/// principal Exchange can't resolve (a managed identity isn't in its SP store)
/// has no RBAC scope, so it resolves to `OrgWide` — or to `Scoped` if a legacy
/// Application Access Policy confines it; only a genuine 403/consent failure
/// degrades to a propagated error (caller surfaces `Unknown` + a reason). When
/// `enrich` is set, a `Scoped` verdict is augmented with the scope's recipient
/// filter + group count via `Get-ManagementScope` (cached per distinct scope),
/// and the legacy-AAP fallback is consulted; the audit path leaves both off
/// since only the org-wide/scoped distinction affects the score (and `OrgWide`
/// scores identically to a propagated/`Unknown` failure there).
pub(crate) async fn resolve_mail_scopes(
    exo: &ExchangeClient,
    app_id: &str,
    graph_perms: &[String],
    orgwide_granted: &HashSet<String>,
    enrich: bool,
) -> Result<HashMap<String, MailPermissionScope>, ExchangeError> {
    let scopable: Vec<(&String, &'static str)> = graph_perms
        .iter()
        .filter_map(|p| exchange_role_for_graph_permission(p).map(|role| (p, role)))
        .collect();
    if scopable.is_empty() {
        return Ok(HashMap::new());
    }

    // Resolve the legacy Application Access Policy up front (detail views only).
    // It serves two roles: the org-wide override on the Ok path below, AND — keyed
    // only on appId, via an independent cmdlet — the authoritative fallback when
    // the probe can't resolve the principal (the managed-identity case). One
    // lookup per app covers every permission; the bulk audit (`enrich == false`)
    // skips it to avoid an extra admin-API call per app.
    let aap_override = if enrich {
        legacy_aap_scope(exo, app_id).await
    } else {
        None
    };

    // Authoritative RBAC-for-Applications verdict.
    let rows = match exo.test_service_principal_authorization(app_id, None).await {
        Ok(rows) => rows,
        Err(err) => {
            // Log a concise code, not the raw body — an Exchange 403 can return a
            // NUL-padded blob that otherwise floods the log.
            tracing::info!(%app_id, code = err.ui_code(), "exchange scoping unavailable");
            // Audit path: propagate so the caller's `unwrap_or_default` scores
            // org-wide (never under-reporting) — byte-for-byte the prior behavior.
            if !enrich {
                return Err(err);
            }
            // Detail path: a legacy AAP can still answer, and a principal Exchange
            // can't resolve simply has no RBAC scope (=> org-wide). Only a genuine
            // 403/consent failure propagates so the UI can offer "Grant consent".
            let fallback = scope_from_rbac_error(err, aap_override)?;
            return Ok(scopable
                .into_iter()
                .map(|(perm, _role)| (perm.clone(), fallback.clone()))
                .collect());
        }
    };

    let mut out = HashMap::new();
    // scope name → (group_count, recipient_filter); `None` = unresolved scope.
    let mut scope_cache: HashMap<String, Option<(u32, String)>> = HashMap::new();
    for (perm, role) in scopable {
        let matching: Vec<&ExoAuthorizationResult> = rows
            .iter()
            .filter(|r| r.role_name.as_deref() == Some(role))
            .collect();
        let mut verdict = verdict_from_rows(&matching);
        // Apply the legacy-AAP fallback only when RBAC shows org-wide.
        if matches!(verdict, MailPermissionScope::OrgWide)
            && let Some(aap) = &aap_override
        {
            verdict = aap.clone();
        }
        // Reconcile a scoped RBAC verdict against an un-stripped org-wide Entra
        // grant (the probe can't see Entra grants).
        verdict = reconcile_orgwide_grant(verdict, perm, orgwide_granted);
        // Enrich an RBAC management scope with its recipient filter + group
        // count (display only). Legacy-AAP scopes carry no management scope, so
        // they are matched out here.
        if enrich
            && let MailPermissionScope::Scoped {
                scope_name: Some(name),
                mechanism: ScopeMechanism::Rbac,
                ..
            } = &verdict
        {
            let name = name.clone();
            let resolved = match scope_cache.get(&name) {
                Some(hit) => hit.clone(),
                None => {
                    let r = exo
                        .get_management_scope(&name)
                        .await
                        .ok()
                        .flatten()
                        .and_then(|s| s.recipient_filter)
                        .map(|f| (count_member_of_group(&f) as u32, f));
                    scope_cache.insert(name.clone(), r.clone());
                    r
                }
            };
            if let Some((count, filter)) = resolved {
                verdict = MailPermissionScope::Scoped {
                    scope_name: Some(name),
                    recipient_filter: Some(filter),
                    group_count: Some(count),
                    mechanism: ScopeMechanism::Rbac,
                };
            }
        }
        out.insert(perm.clone(), verdict);
    }
    Ok(out)
}

/// Cached, lean (audit-path) mailbox-scope resolution: the same probe as
/// `resolve_mail_scopes(..., enrich=false)` but memoized under a distinct
/// `audit|{app_id}|{perms}` discriminator, so a security-audit **re-run**
/// within the cache TTL skips the per-app `Test-ServicePrincipalAuthorization`
/// round trip (1–5s each — minutes across a mail-heavy tenant).
///
/// The key is intentionally **separate** from the Permissions tab's `held|` /
/// `declared|` verdicts. The lean (`enrich=false`) probe skips the legacy-AAP
/// override, so a permission confined *only* by a legacy Application Access
/// Policy resolves org-wide here but scoped on the enriched detail path —
/// sharing one key would make either surface's verdict depend on the other's
/// cache warmth. Both live under the `{tenant}|mail_scopes|` prefix, so a
/// single `invalidate_app_details` sweep drops them together. Errors are never
/// cached (the audit trips its Exchange breaker on an auth failure, and a
/// transient failure must not pin org-wide for the TTL).
pub(crate) async fn resolve_mail_scopes_audit_cached(
    cache: &Cache,
    tenant_id: &str,
    exo: &ExchangeClient,
    app_id: &str,
    graph_perms: &[String],
    orgwide_granted: &HashSet<String>,
) -> Result<HashMap<String, MailPermissionScope>, ExchangeError> {
    // Nothing scopable ⇒ no probe and no cache entry (matches
    // `resolve_mail_scopes` and the Permissions-tab commands).
    let mut scopable: Vec<&str> = graph_perms
        .iter()
        .filter(|p| exchange_role_for_graph_permission(p).is_some())
        .map(String::as_str)
        .collect();
    if scopable.is_empty() {
        return Ok(HashMap::new());
    }
    scopable.sort_unstable();
    let key = mail_scopes_key(tenant_id, &format!("audit|{app_id}|{}", scopable.join(",")));
    if let Some(hit) = cache.get::<HashMap<String, MailPermissionScope>>(CacheKind::Lists, &key) {
        return Ok(hit);
    }
    let scopes = resolve_mail_scopes(exo, app_id, graph_perms, orgwide_granted, false).await?;
    cache.put(CacheKind::Lists, key, &scopes);
    Ok(scopes)
}

/// Cache key for a principal's resolved per-permission mailbox scopes:
/// `{tenant}|mail_scopes|{discriminator}`. The discriminator carries
/// `declared|{object_id}` (Permissions tab, manifest), `held|{app_id}|{perms}`
/// (Permissions tab, bare principal), and `audit|{app_id}|{perms}` (the lean
/// security-audit verdict) so the three surfaces never collide. The whole
/// `{tenant}|mail_scopes|` prefix is dropped by
/// `applications::invalidate_app_details`.
pub(crate) fn mail_scopes_key(tenant_id: &str, discriminator: &str) -> String {
    format!("{tenant_id}|mail_scopes|{discriminator}")
}

/// Per-permission effective mailbox scoping for an app's declared
/// mail/calendar/contacts permissions. Drives the Permissions-tab "Scope"
/// column. Degrades gracefully:
/// when the caller is not an Exchange admin (or `Exchange.Manage` is not
/// consented) every entry is `Unknown` rather than a hard error.
#[tauri::command]
pub async fn get_mail_permission_scopes(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<Vec<MailScopeEntry>, UiError> {
    // Resolution rides several Exchange admin-API cmdlets (each a proxied
    // PowerShell invocation, seconds apiece), so successful verdicts are
    // cached — otherwise every Permissions-tab visit re-pays the full round
    // trip. Busted by `invalidate_app_details` (any app/scope mutation) and
    // the TTL; errors are never cached.
    let cache_key = mail_scopes_key(&tenant_id, &format!("declared|{object_id}"));
    if let Some(cached) = state
        .cache
        .get::<Vec<MailScopeEntry>>(CacheKind::Lists, &cache_key)
    {
        return Ok(cached);
    }
    let graph = state.graph_for(&tenant_id);
    // The app manifest read and the Graph role index are independent — overlap
    // them instead of paying two serial round trips on a cold Permissions tab.
    let (app, (_, role_value_by_id)) = futures::future::try_join(
        async {
            graph
                .get_application(&object_id)
                .await
                .map_err(UiError::from)
        },
        graph_role_index(&graph),
    )
    .await?;

    // Declared, Exchange-scopable Graph permissions on this app.
    let scopable: Vec<String> = targets_from_declared(&app, &role_value_by_id)
        .into_iter()
        .map(|t| t.graph_value)
        .collect();
    if scopable.is_empty() {
        state
            .cache
            .put(CacheKind::Lists, cache_key, &Vec::<MailScopeEntry>::new());
        return Ok(Vec::new());
    }

    // Mail permissions the SP still holds as org-wide Entra grants — used to
    // reconcile a scoped RBAC verdict (the probe can't see Entra grants).
    // Best-effort: a lookup miss leaves the set empty (no reconciliation).
    let orgwide = match graph.get_service_principal_by_app_id(&app.app_id).await {
        Ok(Some(sp)) => held_orgwide_mail_grants(&graph, &sp.id).await,
        _ => HashSet::new(),
    };

    // Propagate Exchange failures (consent_required / 403 / …) so the UI can
    // show an actionable banner + "Grant consent" button, rather than silently
    // painting every row "Unknown" with no explanation.
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let scopes = resolve_mail_scopes(&exo, &app.app_id, &scopable, &orgwide, true).await?;

    let entries: Vec<MailScopeEntry> = scopable
        .into_iter()
        .filter_map(|p| {
            let role = exchange_role_for_graph_permission(&p)?;
            let scope = scopes
                .get(&p)
                .cloned()
                .unwrap_or(MailPermissionScope::Unknown);
            Some(MailScopeEntry {
                graph_permission: p,
                exchange_role: role.to_string(),
                scope,
            })
        })
        .collect();
    state.cache.put(CacheKind::Lists, cache_key, &entries);
    Ok(entries)
}

/// Effective mailbox scoping for an arbitrary service principal identified by
/// its `app_id`, given the Graph permission values it holds. Unlike
/// [`get_mail_permission_scopes`] this takes the permissions directly rather
/// than reading an app registration's manifest, so it works for principals with
/// no `Application` object — notably **managed identities**, whose mail
/// permissions are *granted* app-role assignments. Same graceful degradation:
/// `Unknown` (never under-reported) when Exchange is unavailable.
#[tauri::command]
pub async fn get_mail_scopes_for_principal(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    permissions: Vec<String>,
) -> Result<Vec<MailScopeEntry>, UiError> {
    // Nothing scopable ⇒ no Exchange call (and no needless consent prompt).
    if !permissions
        .iter()
        .any(|p| exchange_role_for_graph_permission(p).is_some())
    {
        return Ok(Vec::new());
    }

    // Same cache as `get_mail_permission_scopes`, keyed on the *held*
    // permission set (caller-supplied), so the same app viewed as an app
    // registration (declared manifest) and as a bare principal can't collide.
    let cache_key = {
        let mut sorted = permissions.clone();
        sorted.sort();
        mail_scopes_key(&tenant_id, &format!("held|{app_id}|{}", sorted.join(",")))
    };
    if let Some(cached) = state
        .cache
        .get::<Vec<MailScopeEntry>>(CacheKind::Lists, &cache_key)
    {
        return Ok(cached);
    }

    // Reconcile a scoped RBAC verdict against the principal's un-stripped
    // org-wide Entra grants (best-effort; empty set ⇒ no reconciliation).
    let graph = state.graph_for(&tenant_id);
    let orgwide = match graph.get_service_principal_by_app_id(&app_id).await {
        Ok(Some(sp)) => held_orgwide_mail_grants(&graph, &sp.id).await,
        _ => HashSet::new(),
    };

    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let scopes = resolve_mail_scopes(&exo, &app_id, &permissions, &orgwide, true).await?;

    let entries: Vec<MailScopeEntry> = permissions
        .into_iter()
        .filter_map(|p| {
            let role = exchange_role_for_graph_permission(&p)?;
            let scope = scopes
                .get(&p)
                .cloned()
                .unwrap_or(MailPermissionScope::Unknown);
            Some(MailScopeEntry {
                graph_permission: p,
                exchange_role: role.to_string(),
                scope,
            })
        })
        .collect();
    state.cache.put(CacheKind::Lists, cache_key, &entries);
    Ok(entries)
}

#[tauri::command]
pub async fn remove_exchange_mailbox_access(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<ExchangeAccessRemovalResult, UiError> {
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let assignments = exo.get_role_assignments(&app_id).await?;
    let mut removed = Vec::new();
    let mut warnings = Vec::new();
    for a in assignments {
        let Some(identity) = a.identity.clone() else {
            continue;
        };
        match exo.remove_role_assignment(&identity).await {
            Ok(()) => removed.push(a.role.unwrap_or(identity)),
            Err(err) => warnings.push(format!("failed to remove assignment {identity}: {err}")),
        }
    }
    warnings.push(
        "the management scope and Exchange service-principal pointer were left in place".into(),
    );
    // Assignments were really removed (even on partial success), changing the
    // cached per-permission scope verdicts and audit-relevant state — same
    // rule as the audit remediations: invalidate because state really changed.
    if !removed.is_empty() {
        invalidate_app_lists(&state.cache, &tenant_id);
    }
    Ok(ExchangeAccessRemovalResult {
        app_id,
        removed_assignments: removed,
        warnings,
    })
}

// ---------------- Managed scope group (create + membership) ----------------
//
// The toolkit-managed mail-enabled security group `azapptoolkit_<app_id>` is
// the recommended scope source: a scoped grant points its management scope at
// this group's stable DN, so callers adjust *who* is in scope by editing the
// group's membership here — never by rewriting the (immutable) management-scope
// filter. These three commands create the group on first use, list its members,
// and add/remove members.
//
// None of them invalidate caches: membership changes don't alter the cached
// scope verdict (it keys off the scope name / MemberOfGroup-clause count, not
// the member set), the member list is fetched live, and a distribution group is
// absent from the app/SP pairing + name indexes. The grant command that wires
// the scope to this group is the one that mutates pairing, and it already calls
// `invalidate_app_lists`.

/// State of the managed scope group for `app_id` — whether it exists, how to
/// reference it, and its current direct members. Degrades like the other
/// Exchange reads: a not-yet-admin caller surfaces `consent_required` / a 403
/// hint rather than crashing the view.
#[tauri::command]
pub async fn list_exchange_scope_group(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<ExchangeScopeGroupDto, UiError> {
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let group_name = load_tenant_defaults(&tenant_id).group_name_for(&app_id);
    let Some(group) = exo.get_distribution_group(&group_name).await? else {
        return Ok(ExchangeScopeGroupDto {
            group_name,
            exists: false,
            primary_smtp_address: None,
            distinguished_name: None,
            members: Vec::new(),
        });
    };
    let members = exo
        .list_group_members(&group_name)
        .await?
        .into_iter()
        .map(|m| ExchangeGroupMemberDto {
            display_name: m.display_name,
            primary_smtp_address: m.primary_smtp_address,
            recipient_type: m.recipient_type,
        })
        .collect();
    Ok(ExchangeScopeGroupDto {
        group_name,
        exists: true,
        primary_smtp_address: group.primary_smtp_address,
        distinguished_name: group.distinguished_name,
        members,
    })
}

/// Adds one or more mailboxes to the managed scope group, creating the group
/// (mail-enabled security) on first use. Per-mailbox failures are collected so
/// one bad identifier never aborts the batch. Adding an existing member is a
/// no-op success.
#[tauri::command]
pub async fn add_exchange_scope_group_members(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    mailboxes: Vec<String>,
) -> Result<ExchangeMemberMutationResult, UiError> {
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let group_name = load_tenant_defaults(&tenant_id).group_name_for(&app_id);
    let group_created = exo.get_distribution_group(&group_name).await?.is_none();
    exo.ensure_security_group(&group_name, &sanitize_alias(&group_name))
        .await?;

    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    for mailbox in &mailboxes {
        let mailbox = mailbox.trim();
        if mailbox.is_empty() {
            continue;
        }
        match exo.add_group_member(&group_name, mailbox).await {
            Ok(()) => succeeded.push(mailbox.to_string()),
            Err(err) => failed.push(ExchangeMemberFailure {
                mailbox: mailbox.to_string(),
                reason: err.to_string(),
            }),
        }
    }
    Ok(ExchangeMemberMutationResult {
        group_name,
        group_created,
        succeeded,
        failed,
    })
}

/// Removes one or more mailboxes from the managed scope group. Removing a
/// non-member is a no-op success; per-mailbox failures are collected.
#[tauri::command]
pub async fn remove_exchange_scope_group_members(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    mailboxes: Vec<String>,
) -> Result<ExchangeMemberMutationResult, UiError> {
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let group_name = load_tenant_defaults(&tenant_id).group_name_for(&app_id);

    let mut succeeded = Vec::new();
    let mut failed = Vec::new();
    for mailbox in &mailboxes {
        let mailbox = mailbox.trim();
        if mailbox.is_empty() {
            continue;
        }
        match exo.remove_group_member(&group_name, mailbox).await {
            Ok(()) => succeeded.push(mailbox.to_string()),
            Err(err) => failed.push(ExchangeMemberFailure {
                mailbox: mailbox.to_string(),
                reason: err.to_string(),
            }),
        }
    }
    Ok(ExchangeMemberMutationResult {
        group_name,
        group_created: false,
        succeeded,
        failed,
    })
}

// ---------------- Migrate legacy Application Access Policies ----------------

/// Migrates legacy Application Access Policies to RBAC for Applications,
/// following the Microsoft-documented steps: create a management scope from the
/// policy's scoping group, register the service principal, assign the scoped
/// roles, remove the unscoped Entra consent, then remove the policy. `dry_run`
/// reports the plan without mutating anything. When `app_id` is `None`, every
/// policy in the tenant is processed.
///
/// `scope_name` optionally overrides the management-scope name for this
/// migration; when `None` (or blank) it defaults to the tenant's configured
/// pattern (see [`TenantDefaults::scope_name_for`], built-in
/// `app_scope_<AppId GUID>`). The override is honored only for a single-app
/// migration (`app_id` is `Some`) — a whole-tenant run always derives a distinct
/// per-app name so the scopes can't collide.
#[tauri::command]
pub async fn migrate_application_access_policies(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: Option<String>,
    scope_name: Option<String>,
    dry_run: bool,
) -> Result<AapMigrationReport, UiError> {
    let graph = state.graph_for(&tenant_id);
    let exo = exchange_client_checked(&state, &tenant_id).await?;

    let (graph_resource_sp_id, role_value_by_id) = graph_role_index(&graph).await?;

    let mut policies = exo.get_application_access_policies().await?;
    if let Some(filter_app) = &app_id {
        policies.retain(|p| p.app_id.as_deref() == Some(filter_app.as_str()));
    }

    // A blank override is treated as "no override"; a whole-tenant run ignores it
    // entirely (one name can't scope every app), falling back to the per-app default.
    let scope_override = scope_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && app_id.is_some());

    // The per-app default follows the tenant's configured scope-name pattern
    // (blank ⇒ the built-in `app_scope_<appId>`), set from the Settings page —
    // the same pattern fresh scoped grants use.
    let tenant_defaults = load_tenant_defaults(&tenant_id);

    let mut items = Vec::new();
    let mut failures = Vec::new();

    for policy in policies {
        let Some(policy_app_id) = policy.app_id.clone() else {
            failures.push("policy without an AppId skipped".into());
            continue;
        };
        match migrate_one(
            &graph,
            &exo,
            &policy,
            &graph_resource_sp_id,
            &role_value_by_id,
            scope_override.as_deref(),
            &tenant_defaults,
            dry_run,
        )
        .await
        {
            Ok(item) => items.push(item),
            Err(msg) => failures.push(format!("{policy_app_id}: {msg}")),
        }
    }

    Ok(AapMigrationReport {
        dry_run,
        items,
        failures,
    })
}

#[allow(clippy::too_many_arguments)]
async fn migrate_one(
    graph: &GraphClient,
    exo: &ExchangeClient,
    policy: &azapptoolkit_exchange::models::ExoApplicationAccessPolicy,
    graph_resource_sp_id: &str,
    role_value_by_id: &HashMap<String, String>,
    scope_override: Option<&str>,
    tenant_defaults: &TenantDefaults,
    dry_run: bool,
) -> Result<AapMigrationItem, String> {
    let app_id = policy.app_id.clone().ok_or("policy has no AppId")?;
    let scope_group = policy
        .scope_name
        .clone()
        .ok_or("policy has no scope group (ScopeName)")?;

    let mut warnings = Vec::new();

    // Resolve the Entra service principal (needed for the EXO pointer ObjectId
    // and to remove the unscoped grants).
    let entra_sp = graph
        .get_service_principal_by_app_id(&app_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no Entra service principal for this app")?;

    // Resolve the scope group to its distinguished name for MemberOfGroup.
    let group = exo
        .get_group(&scope_group)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("scope group '{scope_group}' not found"))?;
    let dn = group
        .distinguished_name
        .ok_or_else(|| format!("scope group '{scope_group}' has no distinguished name"))?;

    let scope_name = scope_override
        .map(str::to_string)
        .unwrap_or_else(|| tenant_defaults.scope_name_for(&app_id));
    let scope_filter = member_of_group_filter(&[dn]);

    // Roles come from what the app actually holds today.
    let assignments = graph
        .list_app_role_assignments(&entra_sp.id)
        .await
        .map_err(|e| e.to_string())?;
    let targets = targets_from_grants(&assignments, graph_resource_sp_id, role_value_by_id);
    if targets.is_empty() {
        warnings.push(
            "app holds no Exchange-scopable Graph permissions; only the policy is removed".into(),
        );
    }

    if dry_run {
        return Ok(AapMigrationItem {
            app_id,
            source_policy_identity: policy.identity.clone(),
            scope_name: Some(scope_name),
            scope_filter: Some(scope_filter),
            roles_assigned: targets
                .iter()
                .map(|t| t.exchange_role.to_string())
                .collect(),
            removed_entra_grants: targets.iter().map(|t| t.graph_value.clone()).collect(),
            removed_policy: false,
            status: "planned".into(),
            warnings,
        });
    }

    // 1. management scope, 2. service principal pointer.
    exo.ensure_management_scope(&scope_name, &scope_filter)
        .await
        .map_err(|e| e.to_string())?;
    exo.ensure_service_principal(&app_id, &entra_sp.id, &entra_sp.display_name)
        .await
        .map_err(|e| e.to_string())?;

    // 3. scoped role assignments (idempotent). Track which targets ended up
    //    scoped so step 4 only strips the org-wide grant for those.
    let (roles_assigned, _roles_skipped, scoped) =
        assign_scoped_roles(exo, &app_id, &scope_name, &targets, &mut warnings).await;

    // 4. remove the unscoped Entra grants so scoping is effective — but only for
    //    permissions whose scoped role actually landed (never strand the app).
    let removed_entra_grants = remove_unscoped_grants(
        graph,
        &entra_sp.id,
        graph_resource_sp_id,
        &targets_safe_to_strip(scoped),
        &mut warnings,
    )
    .await;

    // 5. remove the legacy policy.
    let mut removed_policy = false;
    if let Some(identity) = &policy.identity {
        match exo.remove_application_access_policy(identity).await {
            Ok(()) => removed_policy = true,
            Err(err) => warnings.push(format!("failed to remove legacy policy: {err}")),
        }
    }

    Ok(AapMigrationItem {
        app_id,
        source_policy_identity: policy.identity.clone(),
        scope_name: Some(scope_name),
        scope_filter: Some(scope_filter),
        roles_assigned,
        removed_entra_grants,
        removed_policy,
        status: "migrated".into(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(value: &str) -> ExchangeTarget {
        ExchangeTarget {
            graph_value: value.to_string(),
            exchange_role: "Application Mail.Read",
            app_role_id: "role-id".to_string(),
        }
    }

    fn values(targets: &[ExchangeTarget]) -> Vec<&str> {
        targets.iter().map(|t| t.graph_value.as_str()).collect()
    }

    #[test]
    fn filter_none_keeps_every_target() {
        // The coarse Exchange-scoping-section path scopes all declared mail permissions.
        let targets = vec![target("Mail.Read"), target("Mail.Send")];
        let out = filter_targets_by_value(targets, None);
        assert_eq!(values(&out), ["Mail.Read", "Mail.Send"]);
    }

    #[test]
    fn scope_and_group_names_follow_distinct_conventions() {
        let app = "71487acd-ec93-476d-bd0e-6c8b31831053";
        // The management scope and its backing mail-group are deliberately named
        // apart so they never collide: scope = `app_scope_<app>`,
        // group = `app_scope_group_<app>`. Both defaults are user-overridable via
        // the Settings naming patterns (resolved by `TenantDefaults`).
        let d = TenantDefaults::default();
        assert_eq!(d.scope_name_for(app), format!("app_scope_{app}"));
        assert_eq!(d.group_name_for(app), format!("app_scope_group_{app}"));
        assert_ne!(d.scope_name_for(app), d.group_name_for(app));
    }

    #[test]
    fn alias_is_safe_and_bounded() {
        let app = "71487acd-ec93-476d-bd0e-6c8b31831053";
        let alias = sanitize_alias(&TenantDefaults::default().group_name_for(app));
        // A GUID-based name is already alias-safe and well under the 64 cap.
        assert_eq!(alias, format!("app_scope_group_{app}"));
        assert!(alias.len() <= 64);
        // Disallowed characters are dropped; length is capped.
        let messy = sanitize_alias(&format!("azapptoolkit_a b@c!{}", "x".repeat(80)));
        assert!(
            messy
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        );
        assert_eq!(messy.len(), 64);
    }

    #[test]
    fn filter_some_keeps_only_requested() {
        // The per-permission "Scope this one" path narrows to a single value.
        let targets = vec![
            target("Mail.Read"),
            target("Mail.Send"),
            target("Calendars.Read"),
        ];
        let out = filter_targets_by_value(targets, Some(&["Mail.Send".to_string()]));
        assert_eq!(values(&out), ["Mail.Send"]);
    }

    fn rbac_scope() -> MailPermissionScope {
        MailPermissionScope::Scoped {
            scope_name: Some("azapptoolkit_x".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::Rbac,
        }
    }

    #[tokio::test]
    async fn audit_cached_scopes_skip_probe_and_cache_for_nonmail_perms() {
        // A non-mail permission set must short-circuit before any Exchange call
        // (the base points nowhere) AND leave no cache entry — otherwise the
        // audit would create a useless entry per non-mail app, bloating the
        // cache it's meant to reuse.
        use azapptoolkit_core::token::StaticTokenProvider;
        let cache = Cache::new();
        let exo = ExchangeClient::with_base_url(
            StaticTokenProvider::new("t"),
            "tenant-1",
            "admin@contoso.com",
            "http://127.0.0.1:9".to_string(),
        );
        let out = resolve_mail_scopes_audit_cached(
            &cache,
            "tenant-1",
            &exo,
            "app-1",
            &["User.Read.All".to_string()],
            &HashSet::new(),
        )
        .await
        .unwrap();
        assert!(out.is_empty());
        // The whole audit discriminator for this app is absent (empty perm set).
        let key = mail_scopes_key("tenant-1", "audit|app-1|");
        assert!(
            cache
                .get::<HashMap<String, MailPermissionScope>>(CacheKind::Lists, &key)
                .is_none()
        );
    }

    #[test]
    fn reconcile_downgrades_rbac_scope_when_orgwide_grant_remains() {
        let granted: HashSet<String> = ["Mail.Read".to_string()].into_iter().collect();
        // Test-ServicePrincipalAuthorization can't see the Entra grant, so a scoped
        // RBAC role coexisting with the un-stripped org-wide grant unions to org-wide.
        assert!(matches!(
            reconcile_orgwide_grant(rbac_scope(), "Mail.Read", &granted),
            MailPermissionScope::OrgWide
        ));
    }

    #[test]
    fn reconcile_keeps_rbac_scope_when_no_residual_grant() {
        // Properly stripped: scoped RBAC with no org-wide grant stays scoped.
        assert!(matches!(
            reconcile_orgwide_grant(rbac_scope(), "Mail.Read", &HashSet::new()),
            MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::Rbac,
                ..
            }
        ));
        // A grant for a *different* permission must not affect this one.
        let other: HashSet<String> = ["Calendars.ReadWrite".to_string()].into_iter().collect();
        assert!(matches!(
            reconcile_orgwide_grant(rbac_scope(), "Mail.Read", &other),
            MailPermissionScope::Scoped { .. }
        ));
    }

    #[test]
    fn reconcile_never_downgrades_legacy_aap_scope() {
        // A RestrictAccess AAP genuinely confines an org-wide grant — exempt.
        let granted: HashSet<String> = ["Mail.Read".to_string()].into_iter().collect();
        let aap = MailPermissionScope::Scoped {
            scope_name: Some("Policy-X".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
        };
        assert!(matches!(
            reconcile_orgwide_grant(aap, "Mail.Read", &granted),
            MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
                ..
            }
        ));
    }

    #[test]
    fn filter_empty_list_keeps_nothing() {
        let targets = vec![target("Mail.Read")];
        let out = filter_targets_by_value(targets, Some(&[]));
        assert!(out.is_empty());
    }

    #[test]
    fn org_wide_strip_skips_targets_whose_scoped_role_failed() {
        // Mirrors sharepoint::org_wide_removal_requires_a_landed_site_grant: a
        // target whose scoped Exchange role did NOT land keeps its org-wide grant,
        // so a partial assignment failure never strands the principal with no
        // mailbox access. Only the landed/already-present ones are stripped.
        let scoped = vec![
            (target("Mail.Read"), true),  // assigned or already present → strip
            (target("Mail.Send"), false), // assignment failed → keep org-wide grant
        ];
        let out = targets_safe_to_strip(scoped);
        assert_eq!(values(&out), ["Mail.Read"]);
    }

    #[test]
    fn org_wide_strip_keeps_nothing_when_all_assignments_fail() {
        let scoped = vec![(target("Mail.Read"), false), (target("Mail.Send"), false)];
        assert!(targets_safe_to_strip(scoped).is_empty());
    }

    #[test]
    fn group_dns_in_filter_extracts_the_dn_set() {
        // Round-trips what `member_of_group_filter` produces, set-wise.
        let dns = ["CN=a,DC=x".to_string(), "CN=b,DC=y".to_string()];
        let filter = member_of_group_filter(&dns);
        let got = group_dns_in_filter(&filter);
        assert_eq!(got, ["CN=a,DC=x", "CN=b,DC=y"].into_iter().collect());
    }

    #[test]
    fn group_dns_in_filter_is_formatting_agnostic() {
        // Exchange may echo the filter with extra parens/whitespace; the group
        // *set* is what we compare, so those differences don't trip the warning.
        let same = group_dns_in_filter("(MemberOfGroup  -eq  'CN=a,DC=x')")
            == group_dns_in_filter("MemberOfGroup -eq 'CN=a,DC=x'");
        assert!(same);
        // A genuinely different group set is detected.
        assert_ne!(
            group_dns_in_filter("MemberOfGroup -eq 'CN=a,DC=x'"),
            group_dns_in_filter("MemberOfGroup -eq 'CN=b,DC=y'"),
        );
    }

    fn auth_row(
        role: &str,
        allowed_scope: Option<&str>,
        scope_type: &str,
    ) -> ExoAuthorizationResult {
        ExoAuthorizationResult {
            role_name: Some(role.to_string()),
            granted_permissions: None,
            allowed_resource_scope: allowed_scope.map(str::to_string),
            scope_type: Some(scope_type.to_string()),
            in_scope: None,
        }
    }

    #[test]
    fn verdict_from_rows_tags_rbac_mechanism() {
        // A row confined to a custom recipient scope is RBAC-scoped.
        let row = auth_row(
            "Application Mail.Read",
            Some("azapptoolkit_app-1"),
            "CustomRecipientScope",
        );
        assert!(matches!(
            verdict_from_rows(&[&row]),
            MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::Rbac,
                ..
            }
        ));
    }

    fn aap(app_id: &str, access_right: &str, scope: Option<&str>) -> ExoApplicationAccessPolicy {
        ExoApplicationAccessPolicy {
            identity: Some("policy-1".into()),
            app_id: Some(app_id.into()),
            scope_name: scope.map(str::to_string),
            scope_identity: None,
            access_right: Some(access_right.into()),
            description: None,
        }
    }

    #[test]
    fn aap_restrict_access_is_scoped_via_legacy_mechanism() {
        // The legacy fallback only fires when RBAC reports org-wide; a
        // RestrictAccess policy then confines the app to its scope group.
        let policies = [aap("app-1", "RestrictAccess", Some("Sales"))];
        match aap_verdict_for(&policies, "app-1").expect("should be scoped") {
            MailPermissionScope::Scoped {
                mechanism,
                scope_name,
                ..
            } => {
                assert_eq!(mechanism, ScopeMechanism::LegacyApplicationAccessPolicy);
                assert_eq!(scope_name.as_deref(), Some("Sales"));
            }
            other => panic!("expected Scoped, got {other:?}"),
        }
    }

    #[test]
    fn aap_deny_access_is_not_scoped() {
        // DenyAccess is a blocklist (everything *except* the group) — still
        // effectively org-wide, so it must NOT be reported as scoped.
        let policies = [aap("app-1", "DenyAccess", Some("Execs"))];
        assert!(aap_verdict_for(&policies, "app-1").is_none());
    }

    #[test]
    fn aap_ignores_policies_for_other_apps() {
        let policies = [aap("other-app", "RestrictAccess", Some("Sales"))];
        assert!(aap_verdict_for(&policies, "app-1").is_none());
    }

    #[test]
    fn rbac_error_restrict_access_aap_wins_even_over_forbidden() {
        // A RestrictAccess AAP keyed on this appId is authoritative regardless of
        // why the probe failed — it confines the whole app.
        let aap = aap_verdict_for(&[aap("app-1", "RestrictAccess", Some("Sales"))], "app-1");
        match scope_from_rbac_error(
            ExchangeError::Forbidden {
                detail: "nope".into(),
                had_diagnostics: false,
            },
            aap,
        )
        .expect("AAP should resolve the verdict")
        {
            MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
                ..
            } => {}
            other => panic!("expected legacy-AAP Scoped, got {other:?}"),
        }
    }

    #[test]
    fn rbac_missing_object_without_aap_is_org_wide() {
        // The managed-identity case: the principal isn't in Exchange's SP store,
        // so it has no RBAC scope — its org-wide Graph grant reaches every mailbox.
        for err in [
            ExchangeError::NotFound("object couldn't be found".into()),
            ExchangeError::Api {
                status: 400,
                body: "[Test-ServicePrincipalAuthorization] couldn't be found".into(),
            },
        ] {
            assert_eq!(
                scope_from_rbac_error(err, None).expect("missing object => org-wide"),
                MailPermissionScope::OrgWide,
            );
        }
    }

    #[test]
    fn rbac_genuine_forbidden_without_aap_propagates() {
        // Not a missing object — the caller can't run the cmdlet, so scoping is
        // genuinely indeterminate. Surface it (caller shows a consent/403 banner).
        let err = scope_from_rbac_error(
            ExchangeError::Forbidden {
                detail: "RBAC denied".into(),
                had_diagnostics: true,
            },
            None,
        )
        .expect_err("genuine 403 must propagate");
        assert!(matches!(err, ExchangeError::Forbidden { .. }));
    }
}
