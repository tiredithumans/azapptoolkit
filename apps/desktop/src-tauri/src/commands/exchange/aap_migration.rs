//! Migration of legacy Application Access Policies onto RBAC for
//! Applications — guarded, one batch per app, fail-closed (see
//! docs/architecture/exchange-scoping.md).

use super::*;

// ---------------- Migrate legacy Application Access Policies ----------------

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
    // This loop runs once per APP IN THE TENANT, each iteration doing several
    // multi-second Exchange and Entra round trips — the same shape as the audit
    // and DR fan-outs, and it had neither of their stop conditions. The operator
    // could not stop a whole-tenant migration once started, and a session that
    // died on the first app still burned through every remaining one, producing
    // an identical "failed" line per app that read as a tenant rejecting the
    // writes. Shares `audit_cancel` with the security audit and bulk actions
    // (AGENTS.md), claimed ONCE so a cancel can't be lost at a boundary.
    //
    // Claimed BEFORE the three tenant-wide reads below, not after them — the
    // same rule and the same reason as `run_audit`: `claim()` takes a fresh
    // generation and `cancel()` stamps whatever generation is current when it
    // runs, so a token claimed after a long read carries a HIGHER generation
    // than the cancel the operator issued during it, and `is_cancelled()`
    // (`cancelled >= generation`) never sees it. `get_application_access_policies`
    // walks every policy in the tenant, so pressing Cancel while it ran was both
    // likely and, until this moved, silently discarded.
    let cancel = state.audit_cancel.claim();
    let session = SessionDead::new();
    let mut cancelled = false;

    let graph = state.graph_for(&tenant_id);
    let exo = exchange_client_checked(&state, &tenant_id).await?;

    let resources = mailbox_resource_roles(&graph).await?;

    let mut policies = exo.get_application_access_policies().await?;
    if let Some(filter_app) = &app_id {
        // Casefolded: Exchange echoes the AppId back in whatever case it stored,
        // and a GUID differing only in case is the same application. A
        // case-sensitive filter here silently produced an empty migration plan
        // for a tenant whose policies were created with an upper-case GUID.
        policies.retain(|p| {
            p.app_id
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(filter_app))
        });
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
    // Drained rather than consumed by `for`, so a stop can name the apps it
    // never reached. A cancelled run previously reported only `incomplete: true`
    // and dropped the remaining batches, leaving the operator to diff the report
    // against the tenant to find out which apps are still on legacy policies —
    // the same "a partial run is never presented as a complete one" rule the
    // flag exists for, applied to the apps rather than to the run.
    let mut remaining = batches.into_iter();
    let mut unattempted: Vec<String> = Vec::new();
    while let Some((policy_app_id, batch)) = remaining.next() {
        if cancel.is_cancelled() || session.is_dead() {
            // A dead session makes every remaining app fail identically. Stop
            // and report what was already migrated rather than manufacturing N
            // failures.
            cancelled = true;
            unattempted.push(policy_app_id);
            unattempted.extend(remaining.map(|(id, _)| id));
            break;
        }
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
            Err(err) => {
                // `note_code` keeps `UiError::is_reauth_fatal` the single
                // definition of which codes end the run.
                session.note_code(&err.code);
                failures.push(format!("{policy_app_id}: {}", err.message));
            }
        }
    }

    // A real run assigns Exchange roles and removes org-wide Entra grants, which
    // changes the app/SP lists, every detail payload, the mailbox-scope verdicts
    // AND the audit's scoping findings — `invalidate_app_lists` reaches all four.
    // A dry run mutated nothing, so it must not bust anything. Same exception the
    // credential remediation makes: a **partial** migration is still a real write,
    // so invalidate whenever any app produced an item rather than only on a clean
    // sweep (`migrate_one` reports its own failures inside the item's warnings).
    if !dry_run && !items.is_empty() {
        invalidate_app_lists(&state.cache, &tenant_id);
    }

    Ok(AapMigrationReport {
        dry_run,
        items,
        failures,
        incomplete: cancelled,
        unattempted,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn migrate_one(
    graph: &GraphClient,
    exo: &ExchangeClient,
    app_id: &str,
    policies: &[ExoApplicationAccessPolicy],
    resources: &[ResourceRoles],
    scope_override: Option<&str>,
    tenant_defaults: &TenantDefaults,
    dry_run: bool,
) -> Result<AapMigrationItem, UiError> {
    let identities: Vec<String> = policies.iter().filter_map(|p| p.identity.clone()).collect();
    let mut warnings = Vec::new();

    // Resolve the Entra service principal (needed for the EXO pointer ObjectId
    // and to remove the unscoped grants).
    //
    // `UiError`, not `String`: this is the boundary AGENTS.md says must carry
    // the auth classification. Flattening a GraphError/ExchangeError into a
    // formatted string destroyed the `refresh_missing` / `not_signed_in` /
    // `consent_required` code, so the caller's `SessionDead` latch could never
    // fire and a dead session looked like N independent per-app failures.
    let entra_sp = graph
        .get_service_principal_by_app_id(app_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "service_principal_not_found",
                "no Entra service principal for this app",
            )
        })?;

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
            .ok_or_else(|| {
                UiError::validation("no_scope_group", "policy has no scope group (ScopeName)")
            })?;
        let group = exo.get_group(&scope_group).await?.ok_or_else(|| {
            UiError::not_found(
                "scope_group_not_found",
                format!("scope group '{scope_group}' not found"),
            )
        })?;
        let dn = group.distinguished_name.ok_or_else(|| {
            UiError::validation(
                "scope_group_no_dn",
                format!("scope group '{scope_group}' has no distinguished name"),
            )
        })?;
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

    // Read the scope BEFORE anything is mutated, and refuse an unrestricted one.
    // Unconditional on purpose: the repoint below only runs for a consolidated
    // run without an operator-supplied scope name, so gating the check on it
    // left the other branches — an unconsolidated migration, and an explicit
    // `scope_override` — reaching assign-then-strip against a scope that
    // confines nothing. A dry run checks too, so the plan shows the refusal
    // instead of promising a migration that would fail.
    let existing_filter = existing_scope_filter_checked(exo, &scope_name).await?;

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
    let assignments = graph.list_app_role_assignments(&entra_sp.id).await?;
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
        // Say so when a scope ALREADY exists and confines something else.
        // The plan reports the filter this run computed; `ensure_management_scope`
        // is create-only, so on a real run that computed filter may never be
        // applied. Without this the plan promised a confinement the migration
        // would then refuse (or, before the refusal existed, silently not
        // deliver) — an operator approving the plan could not see the difference.
        if let Some(current) = existing_filter.as_deref() {
            let current_groups = scope_groups_in_filter(current);
            let wanted_dns = group_dns_in_filter(&scope_filter);
            // Case-FOLDED, like the post-write proof in `rbac.rs`: Exchange
            // returns DNs in its own casing, so a raw comparison warns about a
            // scope that in fact already confines exactly the wanted groups.
            let wanted_folded: std::collections::HashSet<String> =
                wanted_dns.iter().map(|d| d.to_ascii_lowercase()).collect();
            if !current_groups.complete || current_groups.folded_dns() != wanted_folded {
                warnings.push(format!(
                    "a management scope “{scope_name}” already exists and confines access to a \
                     different set of groups than this plan computed. Its filter is ({current}). \
                     Exchange keeps an existing scope rather than replacing it, so the migration \
                     will repoint it only if the group consolidation verifies and no explicit \
                     scope name was supplied — otherwise it will refuse this app and change \
                     nothing."
                ));
            }
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
            // A plan repoints nothing, so no group is retired yet.
            retired_groups: Vec::new(),
            status: "planned".into(),
            warnings,
        });
    }

    // 1. management scope, 2. service principal pointer.
    exo.ensure_management_scope(&scope_name, &scope_filter)
        .await?;
    // `ensure_management_scope` is create-only, so a RE-RUN (or a scope left by
    // an earlier partial migration) keeps an OLD filter. Establish what Exchange
    // actually has before assigning any role against it — and refuse the app
    // outright when that is not what this migration computed and we are not
    // permitted to repoint it.
    let live_filter = reconcile_scope_filter(
        exo,
        &scope_name,
        existing_filter.as_deref(),
        &scope_filter,
        consolidation.consolidated && scope_override.is_none(),
        &mut warnings,
    )
    .await?;
    exo.ensure_service_principal(app_id, &entra_sp.id, &entra_sp.display_name)
        .await?;

    // 3. scoped role assignments (idempotent). Track which targets ended up
    //    scoped so step 4 only strips the org-wide grant for those.
    let (roles_assigned, _roles_skipped, scoped) =
        assign_scoped_roles(exo, app_id, &scope_name, &targets, &mut warnings).await?;

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

    // 6. Name the legacy group(s) the new scope no longer points at, so "the
    //    policy group is left in place for you to clean up" says WHICH one. Only
    //    when the consolidation actually repointed: otherwise the scope still
    //    references them and they are in use by definition. A KEPT policy still
    //    names its group, so it shows up as a live reference — which is exactly
    //    right, and stops the operator deleting the group out from under it.
    let retired_groups = if consolidation.consolidated {
        retired_scope_groups(exo, &dns).await
    } else {
        Vec::new()
    };
    if !retired_groups.is_empty() {
        warnings.push(format!(
            "{} The toolkit can only check Exchange management scopes and policies — not mail \
             flow, transport rules, or anything outside Exchange.",
            retired_groups_note(&retired_groups),
        ));
    }

    Ok(AapMigrationItem {
        app_id: app_id.to_string(),
        source_policy_identities: identities,
        scope_name: Some(scope_name),
        // The filter Exchange ACTUALLY has, not the one this run computed.
        // `ensure_management_scope` is create-only, so the two can differ — and
        // reporting the computed one told the operator the app was confined to
        // groups it was not. `reconcile_scope_filter` has already refused the
        // app outright if the divergence could not be corrected, so by here this
        // is both live and correct.
        scope_filter: Some(live_filter),
        managed_group_name: Some(consolidation.group_name),
        members_copied: consolidation.copied,
        members_unverified: consolidation.unverified,
        roles_assigned,
        removed_entra_grants,
        removed_policies,
        retired_groups,
        status: status.into(),
        warnings,
    })
}
