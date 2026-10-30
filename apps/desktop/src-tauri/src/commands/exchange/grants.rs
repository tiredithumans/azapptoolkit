//! Grant, list and remove scoped mailbox access: the shared
//! `apply_exchange_mailbox_scope` core (scoped roles assigned BEFORE the
//! org-wide Entra grants are stripped, so a failure never strands the
//! principal) and the commands that drive it.

use super::*;

use crate::commands::sharepoint::require_same_app;

/// Whether assignment `a` is the org-wide Entra grant target `t` names.
///
/// Each target names its own resource service principal, so a grant is matched
/// on `(resource, appRole)` — never on the appRole id alone, which two resources
/// can legitimately share.
fn grants_target(a: &AppRoleAssignment, t: &ExchangeTarget) -> bool {
    a.resource_id == t.resource_sp_object_id && a.app_role_id == t.app_role_id
}

/// The permission value `a` grants when it is the org-wide grant of one of
/// `targets`, `None` when it is not one to strip.
fn unscoped_grant_value(targets: &[ExchangeTarget], a: &AppRoleAssignment) -> Option<String> {
    targets
        .iter()
        .find(|t| grants_target(a, t))
        .map(|t| t.graph_value.clone())
}

/// What [`remove_unscoped_grants`] did, and what it left org-wide.
pub(super) struct UnscopedStrip {
    /// Values whose org-wide Entra grant was removed.
    pub(super) removed: Vec<String>,
    /// Target values the principal STILL holds org-wide after the strip (its
    /// scoped role failed to land, or the removal failed), read from the live
    /// assignments — never from the targets alone, which may be declared but
    /// never granted. `None` when the assignments could not be read at all.
    pub(super) still_orgwide: Option<Vec<String>>,
}

/// Removes the org-wide Entra app-role assignments for the targets in `scoped`
/// whose scoped Exchange role landed, so the scoped grant is not unioned away.
/// Appends any failures to `warnings`.
///
/// The strand guard lives here: `scoped` is `assign_scoped_roles`' per-target
/// outcome, and only a target whose scoped role is in place is stripped
/// (`targets_safe_to_strip`) — a failed assignment keeps its broad grant, so
/// the principal is never left with neither. The removal loop itself is the
/// shared `graph_roles::strip_app_role_grants`, also used by the SharePoint
/// `Sites.Selected` conversion.
pub(super) async fn remove_unscoped_grants(
    client: &GraphClient,
    sp_id: &str,
    scoped: &[(ExchangeTarget, bool)],
    warnings: &mut Vec<String>,
) -> UnscopedStrip {
    let safe = targets_safe_to_strip(scoped.to_vec());
    let assignments = match client.list_app_role_assignments(sp_id).await {
        Ok(a) => a,
        Err(err) => {
            warnings.push(format!(
                "could not list Entra app-role assignments, so no org-wide grant was removed \
                 and scoping may NOT be effective: {err}"
            ));
            return UnscopedStrip {
                removed: Vec::new(),
                still_orgwide: None,
            };
        }
    };
    let removed = strip_app_role_grants(
        client,
        sp_id,
        &assignments,
        |a| unscoped_grant_value(&safe, a),
        warnings,
    )
    .await;
    let still_orgwide = still_held_orgwide(scoped.iter().map(|(t, _)| t), &assignments, &removed);
    UnscopedStrip {
        removed,
        still_orgwide: Some(still_orgwide),
    }
}

/// The values of `targets` the principal still holds org-wide: some live
/// assignment grants the target (matched on `(resource, appRole)`) and its
/// removal is not in `removed`. A target the app only DECLARES — the wizard
/// declares each permission before scoping it — has no assignment and is not
/// listed, so it is never reported as reaching every mailbox. Deduplicated, in
/// target order.
pub(super) fn still_held_orgwide<'a>(
    targets: impl IntoIterator<Item = &'a ExchangeTarget>,
    assignments: &[AppRoleAssignment],
    removed: &[String],
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for t in targets {
        let held = assignments.iter().any(|a| grants_target(a, t));
        if held && !removed.contains(&t.graph_value) && !out.contains(&t.graph_value) {
            out.push(t.graph_value.clone());
        }
    }
    out
}

/// "{a, b} still granted organization-wide in Microsoft Entra ID" — the one
/// phrasing of what an unstripped grant means, shared by the scoped grant and
/// the legacy-policy migration so the two callers of the Exchange core say it
/// the same way.
pub(super) fn still_granted_orgwide(kept: &[&str]) -> String {
    format!(
        "{} still granted organization-wide in Microsoft Entra ID",
        kept.join(", ")
    )
}

/// One "Scoping is NOT effective" line per org-wide Exchange role assignment
/// that already grants a role this run is scoping (see
/// `targets::orgwide_role_assignments`). Same voice as the
/// `still_granted_orgwide` warning: RBAC unions, so the scoped assignment added
/// beside it confines nothing. Reported, never removed — an org-wide assignment
/// may be deliberate, and taking access away is the operator's call.
pub(super) fn orgwide_assignment_warnings(
    existing: &[azapptoolkit_exchange::models::ExoRoleAssignment],
    targets: &[ExchangeTarget],
) -> Vec<String> {
    orgwide_role_assignments(existing, targets)
        .into_iter()
        .map(|(role, identity)| {
            format!(
                "Scoping is NOT effective for {role}: an org-wide Exchange assignment {identity} \
                 remains, and Exchange RBAC adds to that assignment rather than replacing it, so \
                 the app still reaches every mailbox with it. Remove that assignment in Exchange \
                 if the app should be confined."
            )
        })
        .collect()
}

/// "it" for one permission, "them" for several.
pub(super) fn it_or_them(n: usize) -> &'static str {
    if n == 1 { "it" } else { "them" }
}

/// Inputs to [`apply_exchange_mailbox_scope`], grouped so each is named at the
/// call site. Several are `&str` (tenant/app/sp ids), where a long positional
/// list is easy to transpose — hence a struct rather than 12 bare arguments.
pub(super) struct ApplyExchangeMailboxScopeParams<'a> {
    state: &'a AppState,
    graph: &'a GraphClient,
    exo: &'a ExchangeClient,
    tenant_id: &'a str,
    /// This tenant's naming patterns (`load_tenant_defaults`), read by the
    /// caller so the core reads no settings file of its own.
    tenant_defaults: &'a TenantDefaults,
    app_id: &'a str,
    sp_object_id: &'a str,
    display_name: &'a str,
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
///
/// The live snapshot is read **here and propagated on failure**. It used to be
/// `get_role_assignments(..).unwrap_or_default()`, which turned an unreadable
/// snapshot into "this app has no scoped roles": every role was re-assigned,
/// every duplicate `New-RoleAssignment` failed, every target was recorded as not
/// in place, and `targets_safe_to_strip` therefore stripped nothing — so the app
/// ended up with neither a working scope nor a removed org-wide grant, and every
/// re-run repeated it. What to do about an unreadable snapshot is a decision, so
/// it is now an error rather than a default.
///
/// The ordering rules (already-scoped, first assigner, and the several-values-to-
/// one-role case) live in `azapptoolkit_exchange::targets::plan_role_assignments`,
/// which is pure and unit-tested; this function is the I/O around that plan.
pub(super) async fn assign_scoped_roles(
    exo: &ExchangeClient,
    app_id: &str,
    scope_name: &str,
    targets: &[ExchangeTarget],
    warnings: &mut Vec<String>,
) -> Result<(Vec<String>, Vec<String>, Vec<(ExchangeTarget, bool)>), UiError> {
    let existing = exo.get_role_assignments(app_id).await?;
    let plan = plan_role_assignments(&existing, scope_name, targets);
    // A scoped role beside an org-wide assignment of the same role confines
    // nothing; say so rather than report a scoping that has no effect.
    warnings.extend(orgwide_assignment_warnings(&existing, targets));

    let mut roles_assigned = Vec::new();
    let mut roles_skipped = Vec::new();
    let mut scoped: Vec<(ExchangeTarget, bool)> = Vec::new();
    for (t, step) in targets.iter().zip(plan) {
        let role_in_place = match step {
            RoleStep::AlreadyScoped => {
                roles_skipped.push(t.exchange_role.to_string());
                true
            }
            // Shares an Exchange role with an earlier target in this batch, so
            // it inherits that assignment's outcome instead of issuing a
            // duplicate that would fail and block the strip.
            RoleStep::SameRoleAs { mirrors } => scoped[mirrors].1,
            RoleStep::Assign => {
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
            }
        };
        scoped.push((t.clone(), role_in_place));
    }
    Ok((roles_assigned, roles_skipped, scoped))
}

/// What a grant onto an existing scope that confines nothing would do: the
/// grant's half of the shared `scope_filter_unreadable` refusal
/// (`existing_scope_filter_checked`).
pub(super) const GRANT_ONTO_UNRESTRICTED_SCOPE: &str = "Assigning roles against it and removing \
     the org-wide grants would change what this app reaches in a way that was not asked for.";

/// The grant's refusal when this app's existing scope does not prove exactly
/// the requested groups (`scope_filter_agrees`): the groups asked for would not
/// apply, and repointing the scope is not a side effect a grant may have.
fn scope_group_mismatch(scope_name: &str) -> UiError {
    UiError::validation(
        "scope_group_mismatch",
        format!(
            "a management scope “{scope_name}” already exists for this app and either confines a \
             different group set or has a filter that does more than name these groups, and \
             Exchange keeps the existing scope — so the groups requested here would NOT have been \
             applied, while the org-wide grants were removed. Nothing was changed. Repointing a scope \
             changes what every role assignment using it reaches, so it is a deliberate action, not a \
             side effect of granting: use “Move to managed group” to consolidate onto the \
             toolkit-managed group, or edit the scope in Exchange, then grant again."
        ),
    )
}

/// Shared core of a scoped-mailbox grant: register the Exchange service-principal
/// pointer, resolve `groups` into a management scope, assign each target's
/// Exchange role scoped to it (idempotent), and — when `remove_unscoped` — strip
/// the org-wide Entra grants so the scope is actually effective. The two callers
/// differ only in how `targets` are derived: from an app registration's manifest
/// (`targets_from_declared`) or from the permission being granted to a managed
/// identity. `warnings` is seeded by the caller and extended here.
pub(super) async fn apply_exchange_mailbox_scope(
    params: ApplyExchangeMailboxScopeParams<'_>,
) -> Result<ExchangeAccessResult, UiError> {
    let ApplyExchangeMailboxScopeParams {
        state,
        graph,
        exo,
        tenant_id,
        tenant_defaults,
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
    let scope_name = tenant_defaults.scope_name_for(app_id);
    let scope_filter = member_of_group_filter(&dns);
    // One management scope per app, and `ensure_management_scope` keeps an
    // existing one as it is: refuse unless that scope already confines exactly
    // these groups, while nothing access-affecting has happened yet (only the
    // pointer registration above). The migration's guard, shared:
    // `existing_scope_filter_checked`, then `scope_filter_agrees`.
    if let Some(existing) =
        existing_scope_filter_checked(exo, &scope_name, GRANT_ONTO_UNRESTRICTED_SCOPE).await?
        && !scope_filter_agrees(&existing, &scope_filter)
    {
        return Err(scope_group_mismatch(&scope_name));
    }
    exo.ensure_management_scope(&scope_name, &scope_filter)
        .await?;

    // Assign each Exchange role scoped to the management scope (idempotent),
    // tracking per target whether its scoped role ended up in place so we only
    // strip the org-wide grant for permissions that actually got a scoped
    // replacement (a failed assignment must keep its broad grant).
    let (roles_assigned, roles_skipped, scoped) =
        assign_scoped_roles(exo, app_id, &scope_name, targets, &mut warnings).await?;

    let removed_entra_grants = if remove_unscoped {
        let strip = remove_unscoped_grants(graph, sp_object_id, &scoped, &mut warnings).await;
        // The per-item lines above say what failed; this says what it MEANS,
        // once — the same consequence `migrate_one` states when it keeps a
        // legacy policy. Built from the live assignments, so a permission the
        // app only declares is never reported as reaching every mailbox.
        if let Some(kept) = strip.still_orgwide.filter(|k| !k.is_empty()) {
            let kept: Vec<&str> = kept.iter().map(String::as_str).collect();
            warnings.push(format!(
                "Scoping is NOT effective for {}: {}, and Exchange RBAC adds to that grant \
                 rather than replacing it, so the app still reaches every mailbox with {}. \
                 Re-run once the problems above are fixed.",
                kept.join(", "),
                still_granted_orgwide(&kept),
                it_or_them(kept.len())
            ));
        }
        strip.removed
    } else {
        warnings.push(
            "unscoped Entra grants were left in place; scoping is NOT effective until they are removed".into(),
        );
        Vec::new()
    };

    // Scoping changes the per-permission verdicts, the detail payloads and the
    // audit's findings, never the app/SP set: `ensure_service_principal` above
    // registers Exchange's pointer to an Entra SP that already exists. The one
    // caller that may have created that SP busts the list tier itself
    // (`grant_exchange_mailbox_access`'s `sp_created`). Only on this success path.
    invalidate_app_detail_state(&state.cache, tenant_id);

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
    let resources = mailbox_resource_roles(&graph).await?;

    // Validate BEFORE creating anything: the targets need only the manifest and
    // the resource indexes, and `ensure_service_principal` below is a directory
    // write (it adds an enterprise app when the app has none). Creating it first
    // meant a "nothing to scope" refusal still left a new enterprise app behind.
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

    // A new enterprise app is a set change the cached lists must show, whether
    // or not the scope step then succeeds (`sp_created` below); the scoping
    // itself busts the detail tier inside `apply_exchange_mailbox_scope`.
    let (entra_sp, sp_created) = graph.ensure_service_principal(&app.app_id).await?;

    let result = apply_exchange_mailbox_scope(ApplyExchangeMailboxScopeParams {
        state: &state,
        graph: &graph,
        exo: &exo,
        tenant_id: &tenant_id,
        tenant_defaults: &load_tenant_defaults(&tenant_id),
        app_id: &app.app_id,
        sp_object_id: &entra_sp.id,
        display_name: &app.display_name,
        targets: &targets,
        groups: &groups,
        remove_unscoped: remove_unscoped_entra_grants,
        warnings,
    })
    .await;
    // Not a failed write being invalidated: the SP POST above LANDED, even when
    // the scope step then refused (no_scope_group, scope_group_mismatch, an
    // Exchange error). That is a brand-new Enterprise App row the cached lists
    // must show — the `invalidate_after_grant` / `GrantRun.sp_created` precedent.
    if sp_created {
        invalidate_app_lists(&state.cache, &tenant_id);
    }
    result
}

/// Scopes a **managed identity's** mailbox access to one or more groups via
/// Exchange RBAC. Unlike [`grant_exchange_mailbox_access`], the targets come
/// from the `mail_permissions` being granted (a managed identity has no app
/// registration manifest), and the SP object id is the managed identity itself.
/// A thin wrapper: the clients and this tenant's naming patterns, then
/// [`grant_managed_identity_scope`]. `app_display_name` is part of the IPC
/// contract but unread: the Exchange pointer takes the name Graph returns with
/// the service principal.
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
    let _ = app_display_name;
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    grant_managed_identity_scope(
        &state,
        &exo,
        &tenant_id,
        &load_tenant_defaults(&tenant_id),
        ManagedIdentityScope {
            managed_identity_id: &managed_identity_id,
            app_id: &app_id,
            mail_permissions: &mail_permissions,
            groups: &groups,
            remove_unscoped: remove_unscoped_entra_grants,
        },
    )
    .await
}

/// A managed identity's scoped grant as the webview sent it. `app_id` and
/// `managed_identity_id` are two separate arguments, and the Exchange core
/// assigns roles to the first and strips org-wide grants from the second, so
/// [`grant_managed_identity_scope`] proves they name one principal first.
pub(super) struct ManagedIdentityScope<'a> {
    pub(super) managed_identity_id: &'a str,
    pub(super) app_id: &'a str,
    pub(super) mail_permissions: &'a [String],
    pub(super) groups: &'a [String],
    pub(super) remove_unscoped: bool,
}

/// The body of [`grant_managed_identity_scoped_exchange_access`], over the
/// clients the command builds.
///
/// Before anything else, the service principal is read by its object id and
/// must carry `app_id` (`principal_mismatch` otherwise), as the SharePoint
/// grant paths check (`sharepoint::require_same_app`). Trusting the pairing
/// let a transposed or stale pair assign one app's scoped roles, strip another
/// principal's org-wide mail grants, and report the scoping as done.
pub(super) async fn grant_managed_identity_scope(
    state: &AppState,
    exo: &ExchangeClient,
    tenant_id: &str,
    tenant_defaults: &TenantDefaults,
    request: ManagedIdentityScope<'_>,
) -> Result<ExchangeAccessResult, UiError> {
    let ManagedIdentityScope {
        managed_identity_id,
        app_id,
        mail_permissions,
        groups,
        remove_unscoped,
    } = request;
    let graph = state.graph_for(tenant_id);
    let sp = graph
        .get_service_principal_by_object_id(managed_identity_id)
        .await?
        .ok_or_else(|| UiError::not_found("service_principal", "Service principal not found."))?;
    require_same_app(&sp.app_id, app_id, "service principal")?;
    let resources = mailbox_resource_roles(&graph).await?;

    let mut warnings = Vec::new();
    let mut targets = Vec::new();
    for perm in mail_permissions {
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

    // Graph's own ids and name from here on: the ids equal the webview's, as
    // just proven.
    apply_exchange_mailbox_scope(ApplyExchangeMailboxScopeParams {
        state,
        graph: &graph,
        exo,
        tenant_id,
        tenant_defaults,
        app_id: &sp.app_id,
        sp_object_id: &sp.id,
        display_name: &sp.display_name,
        targets: &targets,
        groups,
        remove_unscoped,
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
            recipient_write_scope: a.recipient_write_scope,
            custom_recipient_write_scope: a.custom_recipient_write_scope,
            recipient_administrative_unit_scope: a.recipient_administrative_unit_scope,
        })
        .collect())
}

/// The label a removal result names an assignment by: its role, else its
/// identity, else its name.
fn assignment_label(a: &azapptoolkit_exchange::models::ExoRoleAssignment) -> String {
    a.role
        .clone()
        .or_else(|| a.identity.clone())
        .or_else(|| a.name.clone())
        .unwrap_or_else(|| "(unnamed assignment)".to_string())
}

/// The failure an assignment with no `Identity` becomes. It cannot be removed
/// (the cmdlet needs the identity), so it is still in place — skipping it
/// silently let "Removed 2" read as complete while a third role still granted
/// mailbox access.
pub(super) fn identityless_failure(
    a: &azapptoolkit_exchange::models::ExoRoleAssignment,
) -> ExchangeAssignmentFailure {
    ExchangeAssignmentFailure {
        assignment: assignment_label(a),
        reason: "Exchange returned this assignment without an identity, so it could not be \
                 removed — remove it in Exchange"
            .to_string(),
    }
}

/// Whether a removal run failed outright: nothing came off and something is
/// still in place. `first_error` carries the first rejection's classification
/// (so a dead session still reads as one); an identity-less-only failure is a
/// validation error. `None` ⇒ return the (possibly partial) result.
pub(super) fn removal_failed_outright(
    removed: &[String],
    failed: &[ExchangeAssignmentFailure],
    first_error: Option<UiError>,
) -> Option<UiError> {
    if !removed.is_empty() || failed.is_empty() {
        return None;
    }
    let list = failed
        .iter()
        .map(|f| format!("{} ({})", f.assignment, f.reason))
        .collect::<Vec<_>>()
        .join("; ");
    let message = format!(
        "no Exchange role assignment was removed, so this principal's mailbox scoping is \
         unchanged: {list}"
    );
    Some(match first_error {
        Some(err) => UiError::new(err.code, message, err.retryable),
        None => UiError::validation("exchange_assignment_unremovable", message),
    })
}

#[tauri::command]
pub async fn remove_exchange_mailbox_access(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
) -> Result<ExchangeAccessRemovalResult, UiError> {
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let assignments = exo.get_role_assignments(&app_id).await?;
    let (result, removed_any) = remove_role_assignments(&exo, app_id, assignments).await;
    // Assignments were really removed (even on partial success, and even when
    // the run then reports failure), changing the cached per-permission scope
    // verdicts and audit-relevant state — invalidate because state really
    // changed. No app or SP was added or removed, so the detail tier (details +
    // audit run) is the one that changed.
    if removed_any {
        invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    result
}

/// The removal loop behind [`remove_exchange_mailbox_access`]: removes every
/// assignment it can, counts the rest as `failed` (an identity-less row is a
/// failure, never a silent skip), and fails outright when nothing came off and
/// something is still assigned (see [`removal_failed_outright`]). Returns the
/// result and whether any removal landed — the caller's invalidation flag.
pub(super) async fn remove_role_assignments(
    exo: &ExchangeClient,
    app_id: String,
    assignments: Vec<azapptoolkit_exchange::models::ExoRoleAssignment>,
) -> (Result<ExchangeAccessRemovalResult, UiError>, bool) {
    let mut removed = Vec::new();
    let mut failed = Vec::new();
    let mut first_error: Option<UiError> = None;
    for a in assignments {
        let Some(identity) = a.identity.clone() else {
            failed.push(identityless_failure(&a));
            continue;
        };
        match exo.remove_role_assignment(&identity).await {
            Ok(()) => removed.push(a.role.unwrap_or(identity)),
            Err(err) => {
                failed.push(ExchangeAssignmentFailure {
                    assignment: assignment_label(&a),
                    reason: err.to_string(),
                });
                first_error.get_or_insert_with(|| err.into());
            }
        }
    }
    let removed_any = !removed.is_empty();
    if let Some(err) = removal_failed_outright(&removed, &failed, first_error) {
        return (Err(err), removed_any);
    }
    (
        Ok(ExchangeAccessRemovalResult {
            app_id,
            removed_assignments: removed,
            failed,
            warnings: vec![
                "the management scope and Exchange service-principal pointer were left in place"
                    .into(),
            ],
        }),
        removed_any,
    )
}
