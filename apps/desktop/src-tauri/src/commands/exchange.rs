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
use azapptoolkit_core::scoping::{is_blanket_mailbox_grant, is_scopable_exchange_permission};
use azapptoolkit_exchange::models::{
    ExoApplicationAccessPolicy, ExoAuthorizationResult, ExoRoleAssignment,
};
use azapptoolkit_exchange::targets::{
    ExchangeTarget, count_member_of_group, exchange_target, filter_targets_by_value,
    group_dns_in_filter, mailbox_resources_complete, policies_safe_to_remove,
    require_scopable_targets, scope_dns_after_consolidation, targets_from_declared,
    targets_from_grants, targets_safe_to_strip,
};
use azapptoolkit_exchange::{
    ExchangeClient, ExchangeError, exchange_role_for_permission, member_of_group_filter,
};
use azapptoolkit_graph::GraphClient;

use crate::commands::applications::{invalidate_app_detail_state, invalidate_app_lists};
use crate::commands::graph_roles::{
    ResourceRoles, mailbox_resource_roles, resolve_grant, resolve_value,
};
use crate::dto::UiError;
use crate::dto::exchange::{
    AapMigrationItem, AapMigrationReport, ExchangeAccessRemovalResult, ExchangeAccessResult,
    ExchangeGroupMemberDto, ExchangeGroupRef, ExchangeMemberFailure, ExchangeMemberMutationResult,
    ExchangeRoleAssignmentDto, ExchangeScopeConsolidationResult, ExchangeScopeGroupDto,
    MailScopeEntry,
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

/// Removes the org-wide Entra app-role assignments for `targets` from the
/// service principal, so the scoped Exchange grant is not unioned away.
/// Returns the permission values actually removed; appends any failures to
/// `warnings`.
///
/// Each target names its own resource service principal, so a grant is matched
/// on `(resource, appRole)` — never on the appRole id alone, which two resources
/// can legitimately share.
async fn remove_unscoped_grants(
    client: &GraphClient,
    sp_id: &str,
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
            .find(|a| a.resource_id == t.resource_sp_object_id && a.app_role_id == t.app_role_id);
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
    targets: &'a [ExchangeTarget],
    groups: &'a [String],
    remove_unscoped: bool,
    warnings: Vec<String>,
}

/// The Exchange roles already assigned to this app **and confined to
/// `scope_name`**. Seeds the dedupe set in [`assign_scoped_roles`]; pure so the
/// scope filter is unit-testable (an assignment on a *different* scope, or with
/// no scope at all, must not count as in place).
fn roles_already_scoped<'a>(
    existing: &'a [ExoRoleAssignment],
    scope_name: &str,
) -> std::collections::HashSet<&'a str> {
    existing
        .iter()
        .filter(|a| a.custom_resource_scope.as_deref() == Some(scope_name))
        .filter_map(|a| a.role.as_deref())
        .collect()
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
    // Roles already scoped to THIS management scope. Seeded from the live
    // snapshot and **extended as the loop assigns**, because several permission
    // values legitimately map to ONE Exchange role — `Mail.ReadBasic` and
    // `Mail.ReadBasic.All` both map to `Application Mail.ReadBasic`
    // (`scoping::graph_mail_role`). Re-reading the pre-loop snapshot made the
    // second such target's `New-RoleAssignment` a duplicate; its `Err` marked the
    // target unsafe to strip, so `targets_safe_to_strip` excluded it and its
    // org-wide Entra grant survived — leaving the grant unioned with the scope,
    // i.e. the scoping silently did not take effect, permanently (every re-run
    // repeated the same failure).
    let mut in_place = roles_already_scoped(&existing, scope_name);
    let mut roles_assigned = Vec::new();
    let mut roles_skipped = Vec::new();
    let mut scoped: Vec<(ExchangeTarget, bool)> = Vec::new();
    for t in targets {
        let role_in_place = if in_place.contains(t.exchange_role) {
            roles_skipped.push(t.exchange_role.to_string());
            true
        } else {
            match exo
                .new_role_assignment(app_id, t.exchange_role, Some(scope_name))
                .await
            {
                Ok(_) => {
                    roles_assigned.push(t.exchange_role.to_string());
                    in_place.insert(t.exchange_role);
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
                     Repointing a scope changes what every role assignment using it reaches, so it is a \
                     deliberate action, not a side effect of granting: use “Move to managed group” to \
                     consolidate onto the toolkit-managed group, or edit the scope in Exchange."
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
    let resources = mailbox_resource_roles(&graph).await?;

    let targets = filter_targets_by_value(
        targets_from_declared(&app, &resources),
        permissions.as_deref(),
    );
    let warnings = Vec::new();
    require_scopable_targets(&targets).map_err(|_| {
        UiError::validation(
            "no_scopable_permission",
            "application declares no Exchange-scopable permissions (Mail/Calendars/Contacts, \
             or the EWS full_access_as_app scope) matching the request; nothing to scope",
        )
    })?;

    apply_exchange_mailbox_scope(ApplyExchangeMailboxScopeParams {
        state: &state,
        graph: &graph,
        exo: &exo,
        tenant_id: &tenant_id,
        app_id: &app.app_id,
        sp_object_id: &entra_sp.id,
        display_name: &app.display_name,
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
    let resources = mailbox_resource_roles(&graph).await?;

    let mut warnings = Vec::new();
    let mut targets = Vec::new();
    for perm in &mail_permissions {
        // The caller sends bare permission values, so resolve each to the
        // resource that exposes it (Graph for mail/calendar/contacts, Office 365
        // Exchange Online for the EWS scope) — `remove_unscoped_grants` then has
        // the exact `(resource, appRole)` pair to strip.
        let target = resolve_value(&resources, perm).and_then(
            |(resource_app_id, resource_sp_id, app_role_id)| {
                exchange_target(
                    resource_app_id,
                    resource_sp_id,
                    app_role_id.to_string(),
                    perm.clone(),
                )
            },
        );
        match target {
            Some(t) => targets.push(t),
            None => warnings.push(format!(
                "{perm} is not an Exchange-scopable permission; skipped"
            )),
        }
    }
    require_scopable_targets(&targets).map_err(|_| {
        UiError::validation(
            "no_scopable_permission",
            "none of the selected permissions can be scoped via Exchange RBAC for Applications",
        )
    })?;

    apply_exchange_mailbox_scope(ApplyExchangeMailboxScopeParams {
        state: &state,
        graph: &graph,
        exo: &exo,
        tenant_id: &tenant_id,
        app_id: &app_id,
        sp_object_id: &managed_identity_id,
        display_name: &app_display_name,
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

/// True when a `Test-ServicePrincipalAuthorization` row confers `value` — either
/// because it *is* that permission's dedicated role, or because it's one of the
/// **composite** roles that bundle several permissions (`Application Mail Full
/// Access` → `Mail.ReadWrite` + `Mail.Send`; `Application Exchange Full Access`
/// → five permissions).
///
/// Matching `RoleName` alone missed every composite role, so a correctly scoped
/// app produced no matching row and read `OrgWide`. The cmdlet reports the
/// bundle in `GrantedPermissions`, so that is the authoritative field; the
/// role-name check stays as the fast path and as a fallback for a row that omits
/// the list.
fn row_grants_permission(row: &ExoAuthorizationResult, role: &str, value: &str) -> bool {
    if row.role_name.as_deref() == Some(role) {
        return true;
    }
    row.granted_permissions
        .as_deref()
        .is_some_and(|granted| granted.split(',').any(|g| g.trim() == value))
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

/// Reconciles one permission's scope verdict against the org-wide Entra grants
/// the principal still holds. A scoped **RBAC** verdict for a permission whose
/// org-wide grant was never removed unions to tenant-wide reach, so it becomes
/// `OrgWide` (what `Test-ServicePrincipalAuthorization` alone misses — it can't
/// see Entra grants). A legacy Application Access Policy is exempt: it genuinely
/// confines an org-wide grant. Org-wide / unknown verdicts pass through.
///
/// A **blanket** grant (the EWS `full_access_as_app` scope) vetoes the scope of
/// *every* permission, not just its own name: it reaches every mailbox with full
/// access, so a `Mail.Read` confined to one group is still effectively org-wide
/// while it survives.
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
    let defeated = orgwide_granted.contains(perm)
        || orgwide_granted.iter().any(|g| is_blanket_mailbox_grant(g));
    if scoped_via_rbac && defeated {
        MailPermissionScope::OrgWide
    } else {
        verdict
    }
}

/// Mailbox permission **values** that `sp_object_id` holds as **org-wide Entra
/// app-role grants** — across Microsoft Graph (mail/calendar/contacts) *and* the
/// legacy Office 365 Exchange Online resource (the EWS `full_access_as_app`
/// scope). `Test-ServicePrincipalAuthorization` deliberately *excludes* these —
/// it reports only the Exchange RBAC layer — so a scoped RBAC verdict must be
/// reconciled against them: per Microsoft's RBAC-for-Applications guidance, an
/// un-stripped org-wide grant *unions* with the scoped role to reach every
/// mailbox ("remove the assignment … in Microsoft Entra ID. Otherwise, the union
/// … results in no effective resource scoping"). A legacy Application Access
/// Policy, by contrast, genuinely confines an org-wide grant, so it is *not*
/// reconciled away (see [`verdict_from_rows`] / [`aap_verdict_for`]).
///
/// Reading Graph alone here was an under-report: a surviving org-wide EWS grant
/// reaches every mailbox, but the verdict still read `Scoped`.
///
/// Best-effort: any read failure yields an empty set (no reconciliation) rather
/// than fabricating an org-wide verdict from a transient error.
pub(crate) async fn held_orgwide_mail_grants(
    graph: &GraphClient,
    sp_object_id: &str,
) -> HashSet<String> {
    let Ok(resources) = mailbox_resource_roles(graph).await else {
        return HashSet::new();
    };
    let Ok(assignments) = graph.list_app_role_assignments(sp_object_id).await else {
        return HashSet::new();
    };
    assignments
        .iter()
        // Resolve each grant against the resource it was made on, so an appRole
        // id collision across APIs can't match the wrong permission.
        .filter_map(|a| {
            resolve_grant(&resources, &a.resource_id, &a.app_role_id).map(|(_, _, value)| value)
        })
        .filter(|v| is_scopable_exchange_permission(v))
        .map(str::to_string)
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
        .filter_map(|p| exchange_role_for_permission(p).map(|role| (p, role)))
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
        // A composite role (`Application Mail Full Access`, `Application Exchange
        // Full Access`) confers this permission without carrying its role name,
        // so match the granted-permission list too.
        let matching: Vec<&ExoAuthorizationResult> = rows
            .iter()
            .filter(|r| row_grants_permission(r, role, perm))
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
        .filter(|p| exchange_role_for_permission(p).is_some())
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
    // The app manifest read and the resource role indexes are independent —
    // overlap them instead of paying serial round trips on a cold Permissions tab.
    let (app, resources) = futures::future::try_join(
        async {
            graph
                .get_application(&object_id)
                .await
                .map_err(UiError::from)
        },
        mailbox_resource_roles(&graph),
    )
    .await?;

    // Declared, Exchange-scopable permissions on this app (Graph mail/calendar/
    // contacts plus the EWS `full_access_as_app` scope).
    let scopable: Vec<String> = targets_from_declared(&app, &resources)
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
            let role = exchange_role_for_permission(&p)?;
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
        .any(|p| exchange_role_for_permission(p).is_some())
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
            let role = exchange_role_for_permission(&p)?;
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
// The toolkit-managed mail-enabled security group (the tenant's
// `group_name_pattern`, default `app_scope_group_<app_id>` — resolved via
// `TenantDefaults::group_name_for`, never hardcoded) is the recommended scope
// source: a scoped grant points its management scope at
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

// ---------------- Consolidate a scope source onto the managed group ---------
//
// One core, two callers: the legacy-AAP migration (source = the policies'
// groups) and `move_exchange_scope_to_managed_group` (source = the groups the
// app's existing management scope already references). Both end at the same
// place — the scope's `MemberOfGroup` filter naming the toolkit-managed group
// alone — so an operator adjusts reach by editing ONE group's membership.
//
// The whole design point is fail-closed. Everything here exists so a
// consolidation that can't be *proved* complete leaves the scope on its
// original groups instead of narrowing what the app can reach: an integration
// that silently stops seeing a mailbox reports "not found", not "denied", which
// is the hardest kind of outage to trace back to a permission change.

/// A member of a source group, as identified for copy + verification.
/// `identity` is what `Add-DistributionGroupMember` is given; `key` is the
/// case-folded value the post-copy membership check compares on.
struct SourceMember {
    identity: String,
    key: String,
}

fn source_member(m: &azapptoolkit_exchange::models::ExoGroupMember) -> Option<SourceMember> {
    // Primary SMTP first (stable and what the members list shows), GUID as the
    // fallback for a mail-less recipient. A member with neither can't be copied
    // *or* verified, so it isn't one — the caller counts it as unverifiable.
    let identity = m
        .primary_smtp_address
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            m.guid
                .as_deref()
                .map(str::trim)
                .filter(|s: &&str| !s.is_empty())
        })?;
    Some(SourceMember {
        identity: identity.to_string(),
        key: identity.to_ascii_lowercase(),
    })
}

/// Outcome of consolidating `source_dns`' membership onto the managed group.
struct ScopeGroupConsolidation {
    group_name: String,
    /// Mailboxes copied in (dry run: that *would* be copied).
    copied: Vec<String>,
    /// Source members that could not be verified present in the managed group.
    /// Non-empty ⇒ the scope stays on its source groups.
    unverified: Vec<String>,
    /// The group DNs the scope filter should reference — the managed group's DN
    /// alone on a fully-verified copy, else `source_dns` unchanged.
    scope_dns: Vec<String>,
    /// `true` when `scope_dns` is the managed group (i.e. the move is on).
    consolidated: bool,
}

/// Copies every member of `source_dns`' groups into the toolkit-managed group
/// and decides — fail-closed — which DNs the scope filter should name.
/// `dry_run` reads only: it enumerates and reports, and creates/copies nothing.
async fn consolidate_scope_group(
    exo: &ExchangeClient,
    app_id: &str,
    source_dns: &[String],
    tenant_defaults: &TenantDefaults,
    dry_run: bool,
    warnings: &mut Vec<String>,
) -> ScopeGroupConsolidation {
    let group_name = tenant_defaults.group_name_for(app_id);
    let keep_source = |warnings: &mut Vec<String>, why: String| {
        warnings.push(format!(
            "{why} — the management scope was left pointing at its current group(s); \
             nothing this app can reach has changed."
        ));
    };

    // 1. Enumerate the source membership. An EMPTY source group is treated as
    //    unreadable, not as "no mailboxes": `Get-DistributionGroupMember` also
    //    returns nothing for a Microsoft 365 group (its members need
    //    `Get-UnifiedGroupLinks`), and consolidating that onto an empty managed
    //    group would cut the app off from every mailbox at once.
    let mut members: Vec<SourceMember> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut unreadable = Vec::new();
    for dn in source_dns {
        match exo.list_group_members(dn).await {
            Ok(list) if !list.is_empty() => {
                let mut unidentifiable = 0_usize;
                for m in &list {
                    match source_member(m) {
                        Some(sm) if seen.insert(sm.key.clone()) => members.push(sm),
                        Some(_) => {}
                        None => unidentifiable += 1,
                    }
                }
                if unidentifiable > 0 {
                    unreadable.push(format!(
                        "{dn} ({unidentifiable} member(s) with no address or GUID to copy)"
                    ));
                }
            }
            Ok(_) => unreadable.push(format!("{dn} (no readable members)")),
            Err(err) => unreadable.push(format!("{dn} ({err})")),
        }
    }
    if !unreadable.is_empty() {
        keep_source(
            warnings,
            format!(
                "could not read the full membership of {}",
                unreadable.join("; ")
            ),
        );
        return ScopeGroupConsolidation {
            group_name,
            copied: Vec::new(),
            unverified: Vec::new(),
            scope_dns: source_dns.to_vec(),
            consolidated: false,
        };
    }

    let copied: Vec<String> = members.iter().map(|m| m.identity.clone()).collect();
    if dry_run {
        return ScopeGroupConsolidation {
            group_name,
            copied,
            unverified: Vec::new(),
            // A plan mutates nothing, so the live filter is still the source's.
            scope_dns: source_dns.to_vec(),
            consolidated: false,
        };
    }

    // 2. Create the managed group if needed and copy the membership in.
    //    Individual failures are collected, not fatal — step 3 is what decides.
    let managed_dn = match exo
        .ensure_security_group(&group_name, &sanitize_alias(&group_name))
        .await
    {
        Ok(g) => g.distinguished_name,
        Err(err) => {
            keep_source(warnings, format!("could not create '{group_name}' ({err})"));
            return ScopeGroupConsolidation {
                group_name,
                copied: Vec::new(),
                unverified: copied,
                scope_dns: source_dns.to_vec(),
                consolidated: false,
            };
        }
    };
    for m in &members {
        if let Err(err) = exo.add_group_member(&group_name, &m.identity).await {
            warnings.push(format!(
                "could not add {} to {group_name}: {err}",
                m.identity
            ));
        }
    }

    // 3. Verify against the group's ACTUAL membership rather than trusting the
    //    adds: EXO accepts some recipient types and then doesn't list them.
    let present: HashSet<String> = match exo.list_group_members(&group_name).await {
        Ok(list) => list
            .iter()
            .filter_map(source_member)
            .map(|m| m.key)
            .collect(),
        Err(err) => {
            keep_source(
                warnings,
                format!("could not re-read '{group_name}' to verify the copy ({err})"),
            );
            return ScopeGroupConsolidation {
                group_name,
                copied: Vec::new(),
                unverified: copied,
                scope_dns: source_dns.to_vec(),
                consolidated: false,
            };
        }
    };
    let unverified: Vec<String> = members
        .iter()
        .filter(|m| !present.contains(&m.key))
        .map(|m| m.identity.clone())
        .collect();

    let scope_dns =
        scope_dns_after_consolidation(source_dns, managed_dn.as_deref(), unverified.len());
    let consolidated = managed_dn.is_some_and(|dn| scope_dns == vec![dn]);
    if !consolidated {
        keep_source(
            warnings,
            if unverified.is_empty() {
                format!("'{group_name}' has no distinguished name to build a filter from")
            } else {
                format!(
                    "{} of {} mailbox(es) could not be verified in '{group_name}' ({})",
                    unverified.len(),
                    members.len(),
                    unverified.join(", ")
                )
            },
        );
    }
    ScopeGroupConsolidation {
        group_name,
        copied: members
            .iter()
            .filter(|m| present.contains(&m.key))
            .map(|m| m.identity.clone())
            .collect(),
        unverified,
        scope_dns,
        consolidated,
    }
}

/// Points an existing management scope at `wanted_filter` when its current
/// filter names a different group set. A no-op when the scope is already right
/// (or doesn't exist yet — the caller's `ensure_management_scope` just made it
/// with this filter). Never fatal: a failed repoint leaves the scope as it was,
/// which is the wider-or-equal side, so it warns rather than erroring out
/// mid-flow.
async fn repoint_scope_if_stale(
    exo: &ExchangeClient,
    scope_name: &str,
    wanted_filter: &str,
    warnings: &mut Vec<String>,
) {
    let existing = match exo.get_management_scope(scope_name).await {
        Ok(Some(scope)) => scope,
        Ok(None) => return,
        Err(err) => {
            warnings.push(format!(
                "could not read management scope '{scope_name}' to check its filter ({err})"
            ));
            return;
        }
    };
    let Some(current) = existing.recipient_filter.as_deref() else {
        return;
    };
    if group_dns_in_filter(current) == group_dns_in_filter(wanted_filter) {
        return;
    }
    match exo
        .set_management_scope_filter(scope_name, wanted_filter)
        .await
    {
        Ok(_) => warnings.push(format!(
            "management scope '{scope_name}' already existed and pointed at a different group set; \
             it now points at the toolkit-managed group. Exchange applies this to every role \
             assignment using the scope, and can take 30 min–2 h to propagate."
        )),
        Err(err) => warnings.push(format!(
            "management scope '{scope_name}' still points at its previous group set — the repoint \
             failed ({err}). Nothing this app can reach has changed."
        )),
    }
}

/// Moves an already-scoped app onto the toolkit-managed group: copies the
/// mailboxes its management scope reaches today into `app_scope_group_<appId>`
/// and repoints the scope at that group.
///
/// The counterpart to the legacy-AAP migration for apps that have already
/// migrated (their policy is gone, so the migration has nothing to find) or
/// that were scoped to a hand-made group. Same fail-closed core: unless every
/// mailbox is verified present in the managed group, the scope keeps its
/// current filter.
///
/// `dry_run` reads only — it reports the mailboxes it would copy and changes
/// nothing.
#[tauri::command]
pub async fn move_exchange_scope_to_managed_group(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    dry_run: bool,
) -> Result<ExchangeScopeConsolidationResult, UiError> {
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let defaults = load_tenant_defaults(&tenant_id);
    let scope_name = defaults.scope_name_for(&app_id);
    let group_name = defaults.group_name_for(&app_id);
    let mut warnings = Vec::new();

    let Some(scope) = exo.get_management_scope(&scope_name).await? else {
        return Err(UiError::validation(
            "no_management_scope",
            format!(
                "no management scope named '{scope_name}' exists for this app, so there is \
                 nothing to move. Use “Grant scoped access” to scope it to the managed group."
            ),
        ));
    };
    let previous_filter = scope.recipient_filter.clone();
    let Some(current_filter) = previous_filter.as_deref() else {
        return Err(UiError::validation(
            "no_scope_filter",
            format!(
                "management scope '{scope_name}' has no recipient filter to read, so the \
                 mailboxes it covers can't be determined."
            ),
        ));
    };
    let source_dns: Vec<String> = group_dns_in_filter(current_filter)
        .into_iter()
        .map(str::to_string)
        .collect();
    if source_dns.is_empty() {
        return Err(UiError::validation(
            "no_scope_group",
            format!(
                "management scope '{scope_name}' isn't built from group membership \
                 (filter: {current_filter}), so its mailboxes can't be copied into a group."
            ),
        ));
    }

    // Already on the managed group: nothing to do. Resolving the group by name
    // (rather than trusting the filter's DN) keeps this honest if the group was
    // recreated and its DN changed.
    if let Ok(Some(managed)) = exo.get_distribution_group(&group_name).await
        && let Some(dn) = managed.distinguished_name.as_deref()
        && source_dns.len() == 1
        && source_dns[0] == dn
    {
        return Ok(ExchangeScopeConsolidationResult {
            app_id,
            scope_name,
            group_name,
            previous_filter: previous_filter.clone(),
            scope_filter: previous_filter,
            members_copied: Vec::new(),
            members_unverified: Vec::new(),
            repointed: false,
            dry_run,
            warnings: vec!["already scoped to the toolkit-managed group".into()],
        });
    }

    let consolidation = consolidate_scope_group(
        &exo,
        &app_id,
        &source_dns,
        &defaults,
        dry_run,
        &mut warnings,
    )
    .await;

    if dry_run || !consolidation.consolidated {
        return Ok(ExchangeScopeConsolidationResult {
            app_id,
            scope_name,
            group_name: consolidation.group_name,
            previous_filter: previous_filter.clone(),
            scope_filter: previous_filter,
            members_copied: consolidation.copied,
            members_unverified: consolidation.unverified,
            repointed: false,
            dry_run,
            warnings,
        });
    }

    let wanted_filter = member_of_group_filter(&consolidation.scope_dns);
    exo.set_management_scope_filter(&scope_name, &wanted_filter)
        .await?;
    warnings.push(
        "the previous group is no longer referenced by this app's scope and can be cleaned up. \
         Exchange can take 30 min–2 h to apply the change (the permission tester bypasses that \
         cache)."
            .into(),
    );
    // The scope's group set (and so the resolved verdict, its filter and its
    // group count) really changed — detail + audit state, not the app/SP set.
    invalidate_app_detail_state(&state.cache, &tenant_id);

    Ok(ExchangeScopeConsolidationResult {
        app_id,
        scope_name,
        group_name: consolidation.group_name,
        previous_filter,
        scope_filter: Some(wanted_filter),
        members_copied: consolidation.copied,
        members_unverified: consolidation.unverified,
        repointed: true,
        dry_run,
        warnings,
    })
}

// ---------------- Migrate legacy Application Access Policies ----------------

/// Groups the tenant's policies into the per-application batches a migration
/// runs on, dropping the ones that must not be migrated. Pure, so the two
/// exclusion rules are unit-testable without Exchange.
///
/// Two rules, both load-bearing:
/// - **`RestrictAccess` only.** A `DenyAccess` policy is a *blocklist* (every
///   mailbox EXCEPT its group), while an RBAC management scope is an allow-list.
///   Rebuilding one as the other inverts the policy — the app would gain exactly
///   the mailboxes it was denied and lose the rest — so those are reported, never
///   migrated. A policy with no readable `AccessRight` is equally unsafe to guess
///   at, so it is excluded too.
/// - **One batch per application.** Several `RestrictAccess` policies on one app
///   grant access to the *union* of their groups (`New-ApplicationAccessPolicy`
///   evaluation rule 3), and an app gets exactly one management scope. Migrating
///   them one at a time meant the second policy's group was silently dropped —
///   `ensure_management_scope` keeps the existing scope — after which both
///   policies were deleted and those mailboxes lost access.
fn group_policies_for_migration(
    policies: Vec<ExoApplicationAccessPolicy>,
) -> (Vec<(String, Vec<ExoApplicationAccessPolicy>)>, Vec<String>) {
    let mut batches: Vec<(String, Vec<ExoApplicationAccessPolicy>)> = Vec::new();
    let mut excluded = Vec::new();
    for policy in policies {
        let Some(policy_app_id) = policy.app_id.clone() else {
            excluded.push("policy without an AppId skipped".to_string());
            continue;
        };
        match policy.access_right.as_deref().map(str::trim) {
            Some(right) if right.eq_ignore_ascii_case("RestrictAccess") => {}
            Some(right) => {
                excluded.push(format!(
                    "{policy_app_id}: skipped a {right} policy — only RestrictAccess policies are \
                     migratable. A DenyAccess policy blocks its group and allows every other \
                     mailbox, whereas an RBAC management scope allows only what it names, so \
                     migrating it would invert the policy. Re-express the exclusion as a \
                     management-scope recipient filter instead."
                ));
                continue;
            }
            None => {
                excluded.push(format!(
                    "{policy_app_id}: skipped a policy with no readable AccessRight — \
                     RestrictAccess and DenyAccess migrate to opposite scopes, so it can't be \
                     guessed."
                ));
                continue;
            }
        }
        match batches.iter_mut().find(|(a, _)| *a == policy_app_id) {
            Some((_, batch)) => batch.push(policy),
            None => batches.push((policy_app_id, vec![policy])),
        }
    }
    (batches, excluded)
}

/// Migrates legacy Application Access Policies to RBAC for Applications,
/// following the Microsoft-documented steps: create a management scope from the
/// policies' scoping groups, register the service principal, assign the scoped
/// roles, remove the unscoped Entra consent, then remove the policies. `dry_run`
/// reports the plan without mutating anything. When `app_id` is `None`, every
/// policy in the tenant is processed.
///
/// Migration is **per application**, not per policy, and only `RestrictAccess`
/// policies qualify — see [`group_policies_for_migration`]. The legacy policies
/// are deleted only once every org-wide grant they were constraining has actually
/// been re-scoped; see [`migrate_one`].
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

    let resources = mailbox_resource_roles(&graph).await?;

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

    let (batches, mut failures) = group_policies_for_migration(policies);

    let mut items = Vec::new();
    for (policy_app_id, batch) in batches {
        match migrate_one(
            &graph,
            &exo,
            &policy_app_id,
            &batch,
            &resources,
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
    app_id: &str,
    policies: &[ExoApplicationAccessPolicy],
    resources: &[ResourceRoles],
    scope_override: Option<&str>,
    tenant_defaults: &TenantDefaults,
    dry_run: bool,
) -> Result<AapMigrationItem, String> {
    let identities: Vec<String> = policies.iter().filter_map(|p| p.identity.clone()).collect();
    let mut warnings = Vec::new();

    // Resolve the Entra service principal (needed for the EXO pointer ObjectId
    // and to remove the unscoped grants).
    let entra_sp = graph
        .get_service_principal_by_app_id(app_id)
        .await
        .map_err(|e| e.to_string())?
        .ok_or("no Entra service principal for this app")?;

    // Resolve EVERY policy's scoping group to its DistinguishedName: the app's
    // one management scope has to span all of them, because that union is what
    // the policies granted. A group we can't resolve aborts the app's migration
    // before anything is mutated — building a scope that silently omits it would
    // cut those mailboxes off.
    let mut dns: Vec<String> = Vec::new();
    for policy in policies {
        let scope_group = policy
            .scope_name
            .clone()
            .or_else(|| policy.scope_identity.clone())
            .ok_or("policy has no scope group (ScopeName)")?;
        let group = exo
            .get_group(&scope_group)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("scope group '{scope_group}' not found"))?;
        let dn = group
            .distinguished_name
            .ok_or_else(|| format!("scope group '{scope_group}' has no distinguished name"))?;
        if !dns.contains(&dn) {
            dns.push(dn);
        }
    }
    if policies.len() > 1 {
        warnings.push(format!(
            "folded {} RestrictAccess policies into one management scope spanning {} group(s) — \
             their combined effect was access to the union of those groups",
            policies.len(),
            dns.len()
        ));
    }

    let scope_name = scope_override
        .map(str::to_string)
        .unwrap_or_else(|| tenant_defaults.scope_name_for(app_id));

    // Consolidate onto the toolkit-managed group: copy the legacy group(s)'
    // membership into `app_scope_group_<appId>` and scope to THAT, so the old
    // group can be retired and every app's reach is edited in one predictable
    // place. Fail-closed — a copy that can't be verified leaves the filter on
    // the legacy groups (see `consolidate_scope_group`), which is exactly the
    // pre-consolidation behavior, never a narrower one.
    let consolidation =
        consolidate_scope_group(exo, app_id, &dns, tenant_defaults, dry_run, &mut warnings).await;
    let scope_filter = member_of_group_filter(&consolidation.scope_dns);

    // Roles come from what the app actually holds today — across Microsoft Graph
    // AND Office 365 Exchange Online, so a policy confining the EWS
    // `full_access_as_app` scope migrates to `Application EWS.AccessAsApp`
    // instead of being silently dropped.
    let assignments = graph
        .list_app_role_assignments(&entra_sp.id)
        .await
        .map_err(|e| e.to_string())?;
    let targets = targets_from_grants(&assignments, resources);
    // An empty target set only means "this policy governs nothing" if we
    // actually looked at every resource an AAP can constrain. See
    // `policies_safe_to_remove`.
    let resources_complete = mailbox_resources_complete(resources);
    if targets.is_empty() {
        if resources_complete {
            warnings.push(
                "app holds none of the permissions an Application Access Policy can constrain \
                 (Graph Mail/Calendars/Contacts, or the EWS full_access_as_app scope), so the \
                 policy governs no effective access"
                    .into(),
            );
        } else {
            warnings.push(
                "could not resolve the Office 365 Exchange Online service principal, so the \
                 app's EWS grants could not be inspected. Treating the empty target set as \
                 UNKNOWN rather than empty: the legacy policy is kept, because deleting it \
                 while an unseen full_access_as_app grant survives would give this app access \
                 to every mailbox in the tenant."
                    .into(),
            );
        }
    }

    if dry_run {
        let removable = policies_safe_to_remove(targets.len(), targets.len(), resources_complete);
        if !removable {
            warnings.push(
                "the legacy policy would be kept until every org-wide grant is re-scoped".into(),
            );
        }
        return Ok(AapMigrationItem {
            app_id: app_id.to_string(),
            source_policy_identities: identities.clone(),
            scope_name: Some(scope_name),
            // A plan mutates nothing, so this is the filter as it stands today.
            scope_filter: Some(scope_filter),
            managed_group_name: Some(consolidation.group_name),
            members_copied: consolidation.copied,
            members_unverified: consolidation.unverified,
            roles_assigned: targets
                .iter()
                .map(|t| t.exchange_role.to_string())
                .collect(),
            removed_entra_grants: targets.iter().map(|t| t.graph_value.clone()).collect(),
            removed_policies: if removable { identities } else { Vec::new() },
            status: "planned".into(),
            warnings,
        });
    }

    // 1. management scope, 2. service principal pointer.
    exo.ensure_management_scope(&scope_name, &scope_filter)
        .await
        .map_err(|e| e.to_string())?;
    // `ensure_management_scope` is create-only, so a RE-RUN (or a scope left by
    // an earlier partial migration) would keep an old filter and silently drop
    // the consolidation. Repoint it — but only a scope this tenant's pattern
    // names for THIS app: an operator-supplied `scope_override` may be shared
    // with other apps, and rewriting that would change their reach too.
    if consolidation.consolidated && scope_override.is_none() {
        repoint_scope_if_stale(exo, &scope_name, &scope_filter, &mut warnings).await;
    }
    exo.ensure_service_principal(app_id, &entra_sp.id, &entra_sp.display_name)
        .await
        .map_err(|e| e.to_string())?;

    // 3. scoped role assignments (idempotent). Track which targets ended up
    //    scoped so step 4 only strips the org-wide grant for those.
    let (roles_assigned, _roles_skipped, scoped) =
        assign_scoped_roles(exo, app_id, &scope_name, &targets, &mut warnings).await;

    // 4. remove the unscoped Entra grants so scoping is effective — but only for
    //    permissions whose scoped role actually landed (never strand the app).
    let removed_entra_grants = remove_unscoped_grants(
        graph,
        &entra_sp.id,
        &targets_safe_to_strip(scoped),
        &mut warnings,
    )
    .await;

    // 5. remove the legacy policies — ONLY once nothing they were constraining is
    //    still granted org-wide (see `policies_safe_to_remove`).
    let mut removed_policies = Vec::new();
    let mut status = "migrated";
    if policies_safe_to_remove(
        targets.len(),
        removed_entra_grants.len(),
        resources_complete,
    ) {
        for identity in &identities {
            match exo.remove_application_access_policy(identity).await {
                Ok(()) => removed_policies.push(identity.clone()),
                Err(err) => {
                    warnings.push(format!("failed to remove legacy policy {identity}: {err}"));
                    status = "partial";
                }
            }
        }
    } else {
        let kept: Vec<&str> = targets
            .iter()
            .map(|t| t.graph_value.as_str())
            .filter(|v| !removed_entra_grants.iter().any(|r| r == v))
            .collect();
        if kept.is_empty() {
            warnings.push(
                "KEPT the legacy policy: the mailbox resources could not be fully resolved, so \
                 whether any grant still needs it is UNKNOWN. Re-run once Exchange is reachable."
                    .into(),
            );
        } else {
            warnings.push(format!(
                "KEPT the legacy policy: {} still granted organization-wide in Microsoft Entra \
                 ID. The policy is the only thing confining {} today, so removing it would give \
                 this app access to every mailbox. Re-run once the grant(s) are scoped.",
                kept.join(", "),
                if kept.len() == 1 { "it" } else { "them" }
            ));
        }
        status = "partial";
    }

    Ok(AapMigrationItem {
        app_id: app_id.to_string(),
        source_policy_identities: identities,
        scope_name: Some(scope_name),
        scope_filter: Some(scope_filter),
        managed_group_name: Some(consolidation.group_name),
        members_copied: consolidation.copied,
        members_unverified: consolidation.unverified,
        roles_assigned,
        removed_entra_grants,
        removed_policies,
        status: status.into(),
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use azapptoolkit_core::models::{
        AppRoleAssignment, Application, RequiredResourceAccess, ResourceAccess,
    };
    use azapptoolkit_core::scoping::{
        EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
        exchange_role_for_resource_permission,
    };

    fn target(value: &str) -> ExchangeTarget {
        ExchangeTarget {
            graph_value: value.to_string(),
            exchange_role: "Application Mail.Read",
            app_role_id: "role-id".to_string(),
            resource_sp_object_id: "graph-sp".to_string(),
        }
    }

    fn values(targets: &[ExchangeTarget]) -> Vec<&str> {
        targets.iter().map(|t| t.graph_value.as_str()).collect()
    }

    /// The two mailbox resources as they resolve in a tenant, with one appRole
    /// each keyed `role-<value>`.
    fn mailbox_resources() -> Vec<ResourceRoles> {
        let index = |values: &[&str]| -> HashMap<String, String> {
            values
                .iter()
                .map(|v| (format!("role-{v}"), v.to_string()))
                .collect()
        };
        vec![
            ResourceRoles {
                app_id: MICROSOFT_GRAPH_APP_ID,
                sp_object_id: "graph-sp".to_string(),
                role_value_by_id: index(&["Mail.Read", "Mail.Send", "User.Read.All"]),
            },
            ResourceRoles {
                app_id: OFFICE365_EXCHANGE_ONLINE_APP_ID,
                sp_object_id: "exo-sp".to_string(),
                // The legacy resource exposes the EWS scope AND its own
                // Outlook-REST `Mail.Read` appRole (a different GUID).
                role_value_by_id: [
                    (
                        format!("exo-role-{EWS_FULL_ACCESS_AS_APP}"),
                        EWS_FULL_ACCESS_AS_APP.to_string(),
                    ),
                    ("exo-role-Mail.Read".to_string(), "Mail.Read".to_string()),
                ]
                .into(),
            },
        ]
    }

    fn declared(resource_app_id: &str, role_ids: &[&str]) -> RequiredResourceAccess {
        RequiredResourceAccess {
            resource_app_id: resource_app_id.to_string(),
            resource_access: role_ids
                .iter()
                .map(|id| ResourceAccess {
                    id: id.to_string(),
                    r#type: "Role".to_string(),
                })
                .collect(),
        }
    }

    fn grant(resource_sp_id: &str, app_role_id: &str) -> AppRoleAssignment {
        AppRoleAssignment {
            id: format!("assign-{app_role_id}"),
            resource_id: resource_sp_id.to_string(),
            app_role_id: app_role_id.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn declared_targets_span_graph_and_the_legacy_ews_scope() {
        // The EWS `full_access_as_app` scope is the one non-Graph permission an
        // Application Access Policy could confine. Deriving targets from Microsoft
        // Graph alone made it invisible: no `Application EWS.AccessAsApp` was ever
        // assigned and its org-wide grant was never stripped.
        let app = Application {
            required_resource_access: vec![
                declared(
                    MICROSOFT_GRAPH_APP_ID,
                    &["role-Mail.Read", "role-User.Read.All"],
                ),
                declared(
                    OFFICE365_EXCHANGE_ONLINE_APP_ID,
                    &[&format!("exo-role-{EWS_FULL_ACCESS_AS_APP}")],
                ),
            ],
            ..Default::default()
        };
        let targets = targets_from_declared(&app, &mailbox_resources());
        assert_eq!(values(&targets), ["Mail.Read", EWS_FULL_ACCESS_AS_APP]);
        // Each target carries the resource SP its grant lives on, so the strip
        // can't hit the wrong resource.
        assert_eq!(targets[0].resource_sp_object_id, "graph-sp");
        assert_eq!(targets[1].resource_sp_object_id, "exo-sp");
        assert_eq!(targets[1].exchange_role, "Application EWS.AccessAsApp");
    }

    #[test]
    fn declared_targets_skip_exchange_onlines_own_mail_roles() {
        // Office 365 Exchange Online's `Mail.Read` (retired Outlook REST) has no
        // RBAC-for-Applications counterpart, so it must not become a target —
        // stripping it would leave the app with no scoped replacement.
        let app = Application {
            required_resource_access: vec![declared(
                OFFICE365_EXCHANGE_ONLINE_APP_ID,
                &["exo-role-Mail.Read"],
            )],
            ..Default::default()
        };
        assert!(targets_from_declared(&app, &mailbox_resources()).is_empty());
    }

    #[test]
    fn granted_targets_span_both_resources_and_keep_resources_apart() {
        // Migration derives its targets from held grants. Both resources expose an
        // appRole named `Mail.Read`; each target must point at the resource its own
        // grant was made on.
        let assignments = vec![
            grant("graph-sp", "role-Mail.Send"),
            grant("exo-sp", &format!("exo-role-{EWS_FULL_ACCESS_AS_APP}")),
            grant("exo-sp", "exo-role-Mail.Read"), // not RBAC-scopable
            grant("other-sp", "role-Mail.Read"),   // unrelated resource
        ];
        let targets = targets_from_grants(&assignments, &mailbox_resources());
        assert_eq!(values(&targets), ["Mail.Send", EWS_FULL_ACCESS_AS_APP]);
        assert_eq!(targets[0].resource_sp_object_id, "graph-sp");
        assert_eq!(targets[1].resource_sp_object_id, "exo-sp");
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
    fn reconcile_lets_a_surviving_ews_grant_defeat_every_scope() {
        // `full_access_as_app` reaches every mailbox with full access, so while it
        // survives org-wide, a `Mail.Read` confined to one group is still org-wide
        // in effect — even though the granted set never names `Mail.Read`.
        let granted: HashSet<String> = [EWS_FULL_ACCESS_AS_APP.to_string()].into_iter().collect();
        assert!(matches!(
            reconcile_orgwide_grant(rbac_scope(), "Mail.Read", &granted),
            MailPermissionScope::OrgWide
        ));
        assert!(matches!(
            reconcile_orgwide_grant(rbac_scope(), "Calendars.ReadWrite", &granted),
            MailPermissionScope::OrgWide
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

    fn exo_member(
        smtp: Option<&str>,
        guid: Option<&str>,
    ) -> azapptoolkit_exchange::models::ExoGroupMember {
        azapptoolkit_exchange::models::ExoGroupMember {
            display_name: Some("Someone".into()),
            primary_smtp_address: smtp.map(str::to_string),
            recipient_type: Some("UserMailbox".into()),
            guid: guid.map(str::to_string),
        }
    }

    #[test]
    fn source_member_prefers_smtp_and_folds_case_for_verification() {
        // The verification key must match regardless of how EXO cases the
        // address on the way back out, or a copied mailbox reads as missing and
        // the consolidation fails closed for no reason.
        let m = source_member(&exo_member(Some("Sales@Contoso.com"), Some("guid-1"))).unwrap();
        assert_eq!(m.identity, "Sales@Contoso.com");
        assert_eq!(m.key, "sales@contoso.com");
    }

    #[test]
    fn source_member_falls_back_to_guid_then_gives_up() {
        // A mail-less recipient is still copyable by GUID...
        let by_guid = source_member(&exo_member(None, Some("guid-1"))).unwrap();
        assert_eq!(by_guid.identity, "guid-1");
        // ...but one with neither can be neither copied nor verified, so it must
        // NOT silently drop out of the count — `None` makes the caller treat the
        // whole source group as unreadable and keep the existing scope.
        assert!(source_member(&exo_member(None, None)).is_none());
        assert!(source_member(&exo_member(Some("  "), None)).is_none());
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

    #[test]
    fn composite_roles_confer_each_bundled_permission() {
        // `Application Mail Full Access` grants Mail.ReadWrite + Mail.Send without
        // carrying either permission's role name. Matching RoleName alone found no
        // row for `Mail.Send`, so a correctly scoped app read org-wide.
        let mut row = auth_row(
            "Application Mail Full Access",
            Some("azapptoolkit_app-1"),
            "CustomRecipientScope",
        );
        row.granted_permissions = Some("Mail.ReadWrite, Mail.Send".to_string());
        assert!(row_grants_permission(
            &row,
            "Application Mail.Send",
            "Mail.Send"
        ));
        assert!(row_grants_permission(
            &row,
            "Application Mail.ReadWrite",
            "Mail.ReadWrite"
        ));
        // A permission the composite does NOT bundle still doesn't match.
        assert!(!row_grants_permission(
            &row,
            "Application Calendars.Read",
            "Calendars.Read"
        ));
        // ...and a permission substring must not match a longer value.
        let mut basic = auth_row("Application Mail.ReadBasic", None, "CustomRecipientScope");
        basic.granted_permissions = Some("Mail.ReadBasic".to_string());
        assert!(!row_grants_permission(
            &basic,
            "Application Mail.Read",
            "Mail.Read"
        ));
    }

    #[test]
    fn dedicated_role_name_still_matches_without_a_permission_list() {
        // The fast path / fallback: a row that omits GrantedPermissions is still
        // matched by its role name.
        let row = auth_row("Application Mail.Read", None, "CustomRecipientScope");
        assert!(row_grants_permission(
            &row,
            "Application Mail.Read",
            "Mail.Read"
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
    fn migration_never_converts_a_deny_access_policy() {
        // A DenyAccess policy blocks its group and allows every other mailbox; a
        // management scope allows only what it names. Migrating one would invert
        // it — the app would gain exactly the mailboxes it was denied. It must be
        // reported, never batched.
        let (batches, excluded) =
            group_policies_for_migration(vec![aap("app-1", "DenyAccess", Some("Execs"))]);
        assert!(batches.is_empty(), "DenyAccess must never be migrated");
        assert_eq!(excluded.len(), 1);
        assert!(excluded[0].contains("DenyAccess"));
        assert!(excluded[0].contains("invert"));
    }

    #[test]
    fn migration_skips_a_policy_with_no_readable_access_right() {
        // RestrictAccess and DenyAccess migrate to opposite scopes, so an absent
        // AccessRight can't be guessed.
        let mut policy = aap("app-1", "RestrictAccess", Some("Sales"));
        policy.access_right = None;
        let (batches, excluded) = group_policies_for_migration(vec![policy]);
        assert!(batches.is_empty());
        assert_eq!(excluded.len(), 1);
    }

    #[test]
    fn migration_batches_every_policy_of_one_app_together() {
        // Two RestrictAccess policies on one app grant access to the UNION of
        // their groups, and an app gets exactly one management scope. Migrating
        // them separately dropped the second group (ensure_management_scope keeps
        // the existing scope) and then deleted both policies.
        let (batches, excluded) = group_policies_for_migration(vec![
            aap("app-1", "RestrictAccess", Some("Sales")),
            aap("app-2", "RestrictAccess", Some("Support")),
            aap("app-1", "RestrictAccess", Some("Finance")),
        ]);
        assert!(excluded.is_empty());
        assert_eq!(batches.len(), 2, "one batch per application");
        assert_eq!(batches[0].0, "app-1");
        assert_eq!(batches[0].1.len(), 2, "both of app-1's policies");
        assert_eq!(batches[1].0, "app-2");
        assert_eq!(batches[1].1.len(), 1);
    }

    #[test]
    fn migration_keeps_the_policy_while_any_grant_is_still_org_wide() {
        // The policy is the ONLY thing constraining a surviving org-wide grant, so
        // deleting it widens the app's reach to every mailbox — the regression that
        // shipped when an EWS-confining policy was deleted with nothing re-scoped.
        assert!(
            !policies_safe_to_remove(2, 1, true),
            "one of two grants stripped ⇒ keep the policy"
        );
        assert!(
            !policies_safe_to_remove(1, 0, true),
            "nothing stripped ⇒ keep the policy"
        );
        // Fully re-scoped ⇒ the documented step 5 runs.
        assert!(policies_safe_to_remove(2, 2, true));
        // No constrainable grant at all ⇒ the policy governs nothing.
        assert!(policies_safe_to_remove(0, 0, true));
    }

    #[test]
    fn two_permission_values_can_share_one_exchange_role() {
        // The precondition that made `assign_scoped_roles` strand a grant: the
        // role map is many-to-one, so an app declaring BOTH of these emits two
        // targets carrying the SAME Exchange role. The second assignment is then a
        // duplicate, and before the in-loop dedupe its Err marked the target
        // unsafe to strip — so its org-wide grant survived the scoping, forever.
        assert_eq!(
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "Mail.ReadBasic"),
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "Mail.ReadBasic.All"),
        );
        assert!(
            exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "Mail.ReadBasic")
                .is_some()
        );
    }

    #[test]
    fn roles_already_scoped_counts_only_this_scope() {
        let assignment = |role: &str, scope: Option<&str>| ExoRoleAssignment {
            name: None,
            role: Some(role.into()),
            role_assignee_name: None,
            custom_resource_scope: scope.map(str::to_string),
            identity: None,
        };
        let existing = vec![
            assignment("Application Mail.Read", Some("app_scope_a")),
            // A different app's scope, and an org-wide (unscoped) assignment:
            // neither means this app's role is confined to `app_scope_a`, and
            // counting them would skip an assignment that must actually happen.
            assignment("Application Mail.Send", Some("app_scope_b")),
            assignment("Application Calendars.Read", None),
        ];
        let got = roles_already_scoped(&existing, "app_scope_a");
        assert_eq!(got.len(), 1);
        assert!(got.contains("Application Mail.Read"));
    }

    #[test]
    fn an_incomplete_resource_view_never_authorizes_deleting_a_policy() {
        // `mailbox_resource_roles` resolves Office 365 Exchange Online
        // best-effort, so a transient failure yields ZERO targets for an app whose
        // full_access_as_app grant is live. The old "no targets ⇒ delete" branch
        // then removed the only thing confining it — widening the app to every
        // mailbox in the tenant, which is strictly worse than misreporting.
        assert!(
            !policies_safe_to_remove(0, 0, false),
            "an unverifiable empty target set must never authorize deletion"
        );
        // ...and the guard is absolute: even a "fully re-scoped" count is not
        // trustworthy when the target set it was derived from may be incomplete.
        assert!(!policies_safe_to_remove(2, 2, false));
    }

    #[test]
    fn resource_completeness_requires_both_mailbox_resources() {
        let roles = |app_id: &'static str| ResourceRoles {
            app_id,
            sp_object_id: "sp".into(),
            role_value_by_id: HashMap::new(),
        };
        assert!(mailbox_resources_complete(&[
            roles(MICROSOFT_GRAPH_APP_ID),
            roles(OFFICE365_EXCHANGE_ONLINE_APP_ID),
        ]));
        // Graph alone is the exact shape a swallowed Exchange Online lookup
        // produces — the case that must read as incomplete.
        assert!(!mailbox_resources_complete(&[roles(
            MICROSOFT_GRAPH_APP_ID
        )]));
        assert!(!mailbox_resources_complete(&[]));
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
