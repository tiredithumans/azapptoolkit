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
    // writes. The migration has its own flag, `migration_cancel`, stopped only
    // by `cancel_aap_migration` — an audit or bulk Cancel can no longer stop it
    // — and is claimed ONCE so a cancel can't be lost at a boundary.
    //
    // Claimed BEFORE the three tenant-wide reads below, not after them — the
    // same rule and the same reason as `run_audit`: `claim()` takes a fresh
    // generation and `cancel()` stamps whatever generation is current when it
    // runs, so a token claimed after a long read carries a HIGHER generation
    // than the cancel the operator issued during it, and `is_cancelled()`
    // (`cancelled >= generation`) never sees it. `get_application_access_policies`
    // walks every policy in the tenant, so pressing Cancel while it ran was both
    // likely and, until this moved, silently discarded.
    let cancel = state.migration_cancel.claim();
    let session = SessionDead::new();

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

    let ctx = MigrationContext {
        graph: &graph,
        exo: &exo,
        resources: &resources,
        scope_override: scope_override.as_deref(),
        tenant_defaults: &tenant_defaults,
        dry_run,
        cancel: &cancel,
    };
    let run = run_migration_batches(
        batches,
        &cancel,
        &session,
        |policy_app_id, batch| async move { migrate_one(ctx, &policy_app_id, &batch).await },
    )
    .await;

    // A real run assigns Exchange roles and removes org-wide Entra grants, which
    // changes the app/SP lists, every detail payload, the mailbox-scope verdicts
    // AND the audit's scoping findings — `invalidate_app_lists` reaches all four.
    // A dry run mutated nothing, so it must not bust anything. Same exception the
    // credential remediation makes: a **partial** migration is still a real write,
    // so invalidate whenever any app was ATTEMPTED rather than only on a clean
    // sweep. Keying it on `items` missed the `Err` returns that follow a landed
    // write — a role-snapshot read, a scope re-read or the service-principal
    // pointer can fail after the management scope and member copy went in — and
    // left a single-app run's caches stale after Exchange really changed.
    if run.should_invalidate(dry_run) {
        invalidate_app_lists(&state.cache, &tenant_id);
    }

    failures.extend(run.failures);
    Ok(AapMigrationReport {
        dry_run,
        items: run.items,
        failures,
        incomplete: run.cancelled,
        unattempted: run.unattempted,
    })
}

/// One application's migration outcome: the report item, and whether Cancel or
/// a dead session stopped it partway (its member copy) — which makes the whole
/// run `incomplete` even when it was the only or last application.
pub(super) struct MigratedApp {
    pub(super) item: AapMigrationItem,
    pub(super) stopped: bool,
}

/// What [`run_migration_batches`] did across the run.
pub(super) struct MigrationRun {
    pub(super) items: Vec<AapMigrationItem>,
    pub(super) failures: Vec<String>,
    /// Stopped by Cancel or a dead session — between apps, or inside one.
    pub(super) cancelled: bool,
    /// Apps the run never reached.
    pub(super) unattempted: Vec<String>,
    /// Any app reached `migrate`, success or not.
    pub(super) attempted: bool,
}

impl MigrationRun {
    /// See [`migration_should_invalidate`].
    pub(super) fn should_invalidate(&self, dry_run: bool) -> bool {
        migration_should_invalidate(dry_run, self.attempted)
    }
}

/// The per-application loop of [`migrate_application_access_policies`], with
/// the per-app step passed in so the stop rules are testable without a live
/// tenant.
///
/// Checks Cancel and the dead-session latch BEFORE each app; an app already
/// started runs to its own stopping point (`migrate_one` stops before any
/// scope/role/grant/policy write when its member copy was cancelled, and says
/// so through [`MigratedApp::stopped`]). Drained rather than consumed by `for`,
/// so a stop can name the apps it never reached. A cancelled run previously
/// reported only `incomplete: true` and dropped the remaining batches, leaving
/// the operator to diff the report against the tenant to find out which apps
/// are still on legacy policies.
pub(super) async fn run_migration_batches<F, Fut>(
    batches: Vec<(String, Vec<ExoApplicationAccessPolicy>)>,
    cancel: &CancelToken,
    session: &SessionDead,
    mut migrate: F,
) -> MigrationRun
where
    F: FnMut(String, Vec<ExoApplicationAccessPolicy>) -> Fut,
    Fut: std::future::Future<Output = Result<MigratedApp, UiError>>,
{
    let mut run = MigrationRun {
        items: Vec::new(),
        failures: Vec::new(),
        cancelled: false,
        unattempted: Vec::new(),
        attempted: false,
    };
    let mut remaining = batches.into_iter();
    while let Some((policy_app_id, batch)) = remaining.next() {
        if cancel.is_cancelled() || session.is_dead() {
            // A dead session makes every remaining app fail identically. Stop
            // and report what was already migrated rather than manufacturing N
            // failures.
            run.cancelled = true;
            run.unattempted.push(policy_app_id);
            run.unattempted.extend(remaining.map(|(id, _)| id));
            break;
        }
        run.attempted = true;
        match migrate(policy_app_id.clone(), batch).await {
            Ok(MigratedApp { item, stopped }) => {
                run.cancelled |= stopped;
                run.items.push(item);
            }
            Err(err) => {
                // `note_code` keeps `UiError::is_reauth_fatal` the single
                // definition of which codes end the run.
                session.note_code(&err.code);
                run.failures
                    .push(format!("{policy_app_id}: {}", err.message));
            }
        }
    }
    run
}

/// Whether a migration run must bust the app caches: any real (non-dry) run that
/// reached [`migrate_one`] for at least one app. `migrate_one` can return `Err`
/// after its first write landed, so "some app produced an item" under-counts —
/// over-invalidating after a refusal that wrote nothing costs one re-read, while
/// under-invalidating shows a stale verdict for the cache TTL. The same
/// landed-write rule as `create_application_core` / `GrantRun`.
pub(super) fn migration_should_invalidate(dry_run: bool, attempted: bool) -> bool {
    !dry_run && attempted
}

/// Signals an in-progress [`migrate_application_access_policies`] run to stop.
/// The run checks before each application, and inside one at the member copy
/// into the toolkit-managed group: a Cancel that lands during that copy stops
/// the application before any management-scope, role, Entra-grant or policy
/// write — the app stays on its legacy policy, reported `partial`. Once the
/// copy is done the application finishes, because [`migrate_one`]'s later
/// steps are ordered never to leave it half-scoped. A stopped run reports
/// `incomplete` (even for a single-app run) and names the applications it
/// never reached in `unattempted`.
#[tauri::command]
pub fn cancel_aap_migration(state: State<'_, AppState>) {
    state.migration_cancel.cancel();
}

/// What stays the same for every application in one migration run, grouped so
/// each per-app [`migrate_one`] call names only what varies (the app and its
/// policies) — the same reasoning as `ApplyExchangeMailboxScopeParams`.
#[derive(Clone, Copy)]
pub(super) struct MigrationContext<'a> {
    pub(super) graph: &'a GraphClient,
    pub(super) exo: &'a ExchangeClient,
    pub(super) resources: &'a [ResourceRoles],
    pub(super) scope_override: Option<&'a str>,
    pub(super) tenant_defaults: &'a TenantDefaults,
    pub(super) dry_run: bool,
    /// The run's one token, so the member copy inside an app's consolidation
    /// stops on the same Cancel as the per-app loop.
    pub(super) cancel: &'a CancelToken,
}

pub(super) async fn migrate_one(
    ctx: MigrationContext<'_>,
    app_id: &str,
    policies: &[ExoApplicationAccessPolicy],
) -> Result<MigratedApp, UiError> {
    let MigrationContext {
        graph,
        exo,
        resources,
        scope_override,
        tenant_defaults,
        dry_run,
        cancel,
    } = ctx;
    // The AppId as Exchange stored it on the policy may be upper-case, while
    // every other path (fresh grants, "Move to managed group", the Settings
    // preview) names the scope and group from Entra's lower-case appId. Fold it
    // once here so `scope_name_for` / `group_name_for` produce the same names
    // for the same app, and the role snapshot recognises the scope it already
    // holds (see `targets::roles_already_scoped`).
    let app_id = &app_id.to_ascii_lowercase();
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
                "service_principal",
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
                "scope_group",
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
    let consolidation = consolidate_scope_group(
        ConsolidateParams {
            exo,
            app_id,
            source_dns: &dns,
            tenant_defaults,
            dry_run,
            live_filter: existing_filter.as_deref(),
            cancel,
        },
        &mut warnings,
    )
    .await;
    let scope_filter = member_of_group_filter(&consolidation.scope_dns);

    // Cancel (or a dead session) stopped the member copy. Stop THIS app here,
    // before its first scope/role/grant/policy write: carrying on would build
    // the scope over the legacy groups and strip grants after the operator
    // asked the run to stop. The app stays exactly as it was — on its legacy
    // policy — and the run is reported incomplete.
    if consolidation.incomplete {
        warnings.push(
            "STOPPED before this app's management scope, role assignments, Entra grants or \
             legacy policy were changed: the run was cancelled (or the session ended) while \
             copying mailboxes into the toolkit-managed group. The app is still confined by \
             its legacy policy. Run the migration again to finish it."
                .into(),
        );
        return Ok(MigratedApp {
            item: AapMigrationItem {
                app_id: app_id.to_string(),
                source_policy_identities: identities,
                scope_name: Some(scope_name),
                // Nothing was written to the scope: report what is live.
                scope_filter: existing_filter,
                managed_group_name: Some(consolidation.group_name),
                members_copied: consolidation.copied,
                members_unverified: consolidation.unverified,
                roles_assigned: Vec::new(),
                removed_entra_grants: Vec::new(),
                removed_policies: Vec::new(),
                retired_groups: Vec::new(),
                status: "partial".into(),
                warnings,
            },
            stopped: true,
        });
    }

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
            // The same proof the real run uses (`scope_filter_agrees`): case-
            // folded, and never agreement for a filter that is not a pure
            // OR-chain of exactly the wanted groups. A filter the run could
            // never rewrite gets the promise it can keep — a refusal — rather
            // than "will repoint if…".
            if !scope_filter_agrees(current, &scope_filter) {
                warnings.push(match rewritable_scope_dns(current) {
                    Err(why) => format!(
                        "a management scope “{scope_name}” already exists and its filter \
                         ({current}) can't be verified or rewritten: {why}. Exchange keeps an \
                         existing scope rather than replacing it, so the migration will refuse \
                         this app and change nothing."
                    ),
                    Ok(_) => format!(
                        "a management scope “{scope_name}” already exists and confines access to a \
                         different set of groups than this plan computed. Its filter is ({current}). \
                         Exchange keeps an existing scope rather than replacing it, so the migration \
                         will repoint it only if the group consolidation verifies and no explicit \
                         scope name was supplied — otherwise it will refuse this app and change \
                         nothing."
                    ),
                });
            }
        }
        return Ok(MigratedApp {
            stopped: false,
            item: AapMigrationItem {
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
            },
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
    //    `still_orgwide` is deliberately not consulted: whether the policies go
    //    stays `policies_safe_to_remove`'s decision, below.
    let removed_entra_grants = remove_unscoped_grants(graph, &entra_sp.id, &scoped, &mut warnings)
        .await
        .removed;

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
                "KEPT the legacy policy: {}. The policy is the only thing confining {} today, so \
                 removing it would give this app access to every mailbox. Re-run once the \
                 grant(s) are scoped.",
                still_granted_orgwide(&kept),
                it_or_them(kept.len())
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

    Ok(MigratedApp {
        stopped: false,
        item: AapMigrationItem {
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
        },
    })
}
