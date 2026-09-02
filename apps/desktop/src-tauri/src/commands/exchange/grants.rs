//! Grant, list and remove scoped mailbox access: the shared
//! `apply_exchange_mailbox_scope` core (scoped roles assigned BEFORE the
//! org-wide Entra grants are stripped, so a failure never strands the
//! principal) and the commands that drive it.

use super::*;

/// Removes the org-wide Entra app-role assignments for `targets` from the
/// service principal, so the scoped Exchange grant is not unioned away.
/// Returns the permission values actually removed; appends any failures to
/// `warnings`.
///
/// Each target names its own resource service principal, so a grant is matched
/// on `(resource, appRole)` — never on the appRole id alone, which two resources
/// can legitimately share.
pub(super) async fn remove_unscoped_grants(
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
pub(super) struct ApplyExchangeMailboxScopeParams<'a> {
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
    // FAIL CLOSED, not warn-and-proceed. This used to push a warning and fall
    // through — but the fall-through then assigned roles against the EXISTING
    // scope and stripped the org-wide Entra grants, so the app ended up confined
    // to a group set the operator never asked for while its broad access was
    // removed. When the existing groups are a superset of the request that is an
    // access-WIDENING outcome delivered behind a warning; when they are a subset
    // the app silently loses reach it was just granted. Either way the mutation
    // did not do what was asked.
    //
    // Refusing here is safe precisely because nothing access-affecting has
    // happened yet: only `ensure_service_principal` (an idempotent pointer
    // registration) has run, so the app is left exactly as it was — org-wide,
    // which is the status quo the operator was trying to improve, not a
    // half-applied state. Repointing is a deliberate action with its own
    // command; see AGENTS.md, "Repointing a management scope is an explicit
    // action, and fail-closed".
    //
    // Matched exhaustively rather than `if let Ok(Some(..))`: that form let BOTH
    // an `Err` read and a scope with no `RecipientRestrictionFilter` skip the
    // guard entirely and fall through to assign-then-strip — the exact outcome
    // the paragraph above says must never happen. An unrestricted or custom
    // scope carrying this app's name is precisely the case where confining the
    // app to it, and then removing its org-wide grants, is least likely to be
    // what the operator meant.
    match exo.get_management_scope(&scope_name).await {
        Ok(Some(existing)) => {
            let Some(existing_filter) = existing.recipient_filter.as_deref() else {
                return Err(UiError::validation(
                    "scope_filter_unreadable",
                    format!(
                        "a management scope “{scope_name}” already exists for this app but has no recipient \
                         restriction filter, so it does not confine anything to the groups requested here — \
                         and Exchange keeps the existing scope rather than replacing it. Assigning roles \
                         against it and removing the org-wide grants would change what this app reaches in a \
                         way that was not asked for, so nothing was changed. Review the scope in Exchange, or \
                         use “Move to managed group” to consolidate onto the toolkit-managed group."
                    ),
                ));
            };
            let wanted: std::collections::HashSet<String> = dns.iter().cloned().collect();
            let have = group_dns_in_filter(existing_filter);
            if have != wanted {
                return Err(UiError::validation(
                    "scope_group_mismatch",
                    format!(
                        "a management scope “{scope_name}” already exists for this app with a different group set, \
                         and Exchange keeps the existing scope — so the groups requested here would NOT have been \
                         applied, while the org-wide grants were removed. Nothing was changed. Repointing a scope \
                         changes what every role assignment using it reaches, so it is a deliberate action, not a \
                         side effect of granting: use “Move to managed group” to consolidate onto the \
                         toolkit-managed group, or edit the scope in Exchange, then grant again."
                    ),
                ));
            }
        }
        // No scope yet — `ensure_management_scope` creates it below with exactly
        // the requested filter, which is the clean path this guard protects.
        Ok(None) => {}
        // Refuse rather than proceed blind. `ensure_management_scope` re-reads
        // with `?` and so aborts on a *persistent* failure anyway; this closes
        // the transient case, where the first read errs, the second succeeds,
        // and the pre-existing scope is never compared at all.
        Err(err) => return Err(err.into()),
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
