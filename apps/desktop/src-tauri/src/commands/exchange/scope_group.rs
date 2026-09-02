//! The toolkit-managed scope group: create + membership commands, consolidating
//! a scope source onto it, and the fail-closed management-scope repoint.

use super::*;

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

/// Outcome of consolidating `source_dns`' membership onto the managed group.
pub(super) struct ScopeGroupConsolidation {
    pub(super) group_name: String,
    /// Mailboxes copied in (dry run: that *would* be copied).
    pub(super) copied: Vec<String>,
    /// Source members that could not be verified present in the managed group.
    /// Non-empty ⇒ the scope stays on its source groups.
    pub(super) unverified: Vec<String>,
    /// The group DNs the scope filter should reference — the managed group's DN
    /// alone on a fully-verified copy, else `source_dns` unchanged.
    pub(super) scope_dns: Vec<String>,
    /// `true` when `scope_dns` is the managed group (i.e. the move is on).
    pub(super) consolidated: bool,
}

/// Copies every member of `source_dns`' groups into the toolkit-managed group
/// and decides — fail-closed — which DNs the scope filter should name.
/// `dry_run` reads only: it enumerates and reports, and creates/copies nothing.
pub(super) async fn consolidate_scope_group(
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
    //    Fetch, then plan: the enumeration is the only part that needs a client,
    //    and `plan_source_membership` owns every rule about what the results
    //    mean — including the load-bearing "an empty list is unreadable, not
    //    empty" one — so those rules are unit-testable without a session.
    let mut reads: Vec<(&String, Result<Vec<ExoGroupMember>, String>)> =
        Vec::with_capacity(source_dns.len());
    for dn in source_dns {
        let result = exo
            .list_group_members(dn)
            .await
            .map_err(|err| err.to_string());
        reads.push((dn, result));
    }
    let planned = plan_source_membership(
        &reads
            .iter()
            .map(|(dn, result)| SourceGroupRead {
                dn: dn.as_str(),
                members: match result {
                    Ok(list) => Ok(list.as_slice()),
                    Err(err) => Err(err.clone()),
                },
            })
            .collect::<Vec<_>>(),
    );
    let members = match planned {
        Ok(members) => members,
        Err(unreadable) => {
            keep_source(
                warnings,
                Refusal::UnreadableSourceGroups(unreadable).to_string(),
            );
            return ScopeGroupConsolidation {
                group_name,
                copied: Vec::new(),
                unverified: Vec::new(),
                scope_dns: source_dns.to_vec(),
                consolidated: false,
            };
        }
    };

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
    let present: Vec<String> = match exo.list_group_members(&group_name).await {
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
    let unverified = unverified_members(&members, &present);

    // 4. The decision itself is pure and lives in `azapptoolkit-exchange`, where
    //    it is unit-testable without a signed-in session. It re-parses the
    //    filter it is about to replace, so the plan can never disagree with what
    //    gets overwritten. Sources were proved readable above, hence `&[]`.
    let source_filter = member_of_group_filter(source_dns);
    let plan = plan_consolidation(&source_filter, managed_dn.as_deref(), &[], unverified.len());
    let (scope_dns, consolidated) = match plan {
        Ok(plan) => (plan.scope_dns, true),
        Err(why) => {
            keep_source(
                warnings,
                match why {
                    // Name the mailboxes: this is the refusal an operator can act on.
                    Refusal::UnverifiedMembers(n) => format!(
                        "{n} of {} mailbox(es) could not be verified in '{group_name}' ({})",
                        members.len(),
                        unverified.join(", ")
                    ),
                    other => other.to_string(),
                },
            );
            (source_dns.to_vec(), false)
        }
    };
    ScopeGroupConsolidation {
        group_name,
        copied: members
            .iter()
            .filter(|m| present.iter().any(|k| k == &m.key))
            .map(|m| m.identity.clone())
            .collect(),
        unverified,
        scope_dns,
        consolidated,
    }
}

/// Resolves the groups a repoint left behind and reports what still references
/// them, so the result can name the cleanup candidate instead of saying "the
/// previous group".
///
/// Best-effort by design: a group that no longer resolves, or a reference read
/// that fails, yields `reference_check_complete: false` — the operator still
/// sees the DN (which is what they need to find it), but no delete affordance
/// is offered on an unknown.
pub(super) async fn retired_scope_groups(
    exo: &ExchangeClient,
    source_dns: &[String],
) -> Vec<RetiredScopeGroupDto> {
    if source_dns.is_empty() {
        return Vec::new();
    }
    // Both reads are org-wide and independent of the per-group loop below.
    let (scopes, policies) = futures::join!(
        exo.list_management_scopes(),
        exo.get_application_access_policies(),
    );
    let readable = scopes.is_ok() && policies.is_ok();
    let scopes = scopes.unwrap_or_default();
    let policies = policies.unwrap_or_default();

    let mut out = Vec::new();
    for dn in source_dns {
        let resolved = exo.get_group(dn).await.ok().flatten();
        let group = GroupIdentity {
            distinguished_name: dn.clone(),
            name: resolved.as_ref().and_then(|g| g.name.clone()),
            primary_smtp_address: resolved
                .as_ref()
                .and_then(|g| g.primary_smtp_address.clone()),
        };
        let still_referenced_by = references_to_group(&group, &scopes, &policies);
        out.push(RetiredScopeGroupDto {
            display_name: group.name.clone(),
            primary_smtp_address: group.primary_smtp_address.clone(),
            distinguished_name: group.distinguished_name,
            still_referenced_by,
            // A group we couldn't resolve can't be matched by name either, so
            // its policy check is unreliable — report the whole check as
            // incomplete rather than a clean bill of health.
            reference_check_complete: readable && resolved.is_some(),
        });
    }
    out
}

/// Deletes a group a consolidation retired — the explicit, separately confirmed
/// cleanup step, never a side effect of the move.
///
/// **`Remove-DistributionGroup` is not reversible**, so every guard is re-checked
/// against live state here rather than trusted from the caller's snapshot:
///
/// 1. the group must still exist *as a distribution / mail-enabled security
///    group* (so a mistyped identity can't match something else);
/// 2. it must not be this app's toolkit-managed scope group — that is the group
///    the scope was just repointed *onto*, and deleting it would cut the app off
///    from every mailbox;
/// 3. nothing the toolkit can enumerate may still reference it, and that check
///    must have completed — an unknown is refused, not assumed clean.
///
/// The residual risk the toolkit cannot check for (mail flow, transport rules,
/// nesting, non-Exchange consumers) is stated in the UI; this command is the
/// last gate, not the only one.
#[tauri::command]
pub async fn delete_exchange_scope_group(
    state: State<'_, AppState>,
    tenant_id: String,
    app_id: String,
    group_identity: String,
) -> Result<(), UiError> {
    let exo = exchange_client_checked(&state, &tenant_id).await?;
    let defaults = load_tenant_defaults(&tenant_id);

    let Some(group) = exo.get_distribution_group(&group_identity).await? else {
        return Err(UiError::not_found(
            "group_not_found",
            format!(
                "no distribution or mail-enabled security group matches '{group_identity}' — it \
                 may already have been deleted."
            ),
        ));
    };
    let identity = GroupIdentity {
        distinguished_name: group
            .distinguished_name
            .clone()
            .unwrap_or_else(|| group_identity.clone()),
        name: group.name.clone(),
        primary_smtp_address: group.primary_smtp_address.clone(),
    };

    let managed = defaults.group_name_for(&app_id);
    if identity.matches(&managed) {
        return Err(UiError::validation(
            "managed_group",
            format!(
                "'{managed}' is the toolkit-managed scope group this app's management scope now \
                 points at. Deleting it would remove the app's mailbox access entirely."
            ),
        ));
    }

    // Re-check references live; the caller's snapshot is advisory.
    let scopes = exo.list_management_scopes().await?;
    let policies = exo.get_application_access_policies().await?;
    let references = references_to_group(&identity, &scopes, &policies);
    if !references.is_empty() {
        return Err(UiError::validation(
            "group_in_use",
            format!(
                "'{}' is still referenced by {}. Repoint or remove those first.",
                identity
                    .name
                    .as_deref()
                    .unwrap_or(&identity.distinguished_name),
                references.join(", ")
            ),
        ));
    }

    exo.remove_distribution_group(&identity.distinguished_name)
        .await?;
    // Nothing to invalidate: a distribution group is absent from the app/SP
    // pairing + name indexes, and both the scope-group listing and the scope
    // verdict are read live (the verdict keys off the scope's own filter, which
    // this doesn't touch) — the same reasoning as the membership mutators.
    Ok(())
}

/// Reads this app's management scope and refuses the migration unless what is
/// there is something the migration can reason about.
///
/// Returns the existing recipient filter, or `None` when no scope exists yet —
/// the clean path, where the caller's `ensure_management_scope` creates it with
/// exactly the filter this migration computed.
///
/// FAIL CLOSED on a scope that exists with **no** `RecipientRestrictionFilter`.
/// Such a scope confines nothing, and `ensure_management_scope` is create-only,
/// so it is kept rather than replaced. Proceeding assigns this app's roles
/// against an unrestricted scope, then strips its org-wide Entra grants and
/// deletes the legacy policy — leaving the app reaching every mailbox in the
/// tenant while the report says it was confined. That is strictly worse than
/// the legacy policy it replaced, and it is the one outcome this whole flow
/// exists to prevent.
///
/// This is the same guard `apply_exchange_mailbox_scope` applies to the same
/// state (`scope_filter_unreadable`, see its comment block); the migration path
/// reached the identical assign-then-strip sequence through
/// `repoint_scope_if_stale`, which returned silently on `None`, and through the
/// branches that never called it at all. Refusing is safe precisely because the
/// caller runs this BEFORE the first mutation, so the app is left exactly as it
/// was — on its legacy policy, which is the status quo, not a half-applied
/// state. AGENTS.md: "Repointing a management scope is an explicit action, and
/// fail-closed."
pub(super) async fn existing_scope_filter_checked(
    exo: &ExchangeClient,
    scope_name: &str,
) -> Result<Option<String>, UiError> {
    // Refuse rather than proceed blind on a read error — the same reasoning as
    // the grant path: `ensure_management_scope` re-reads and aborts on a
    // *persistent* failure anyway, so this closes the transient case where the
    // first read errs, the second succeeds, and the pre-existing scope is never
    // compared at all.
    let read = exo.get_management_scope(scope_name).await?;
    scope_filter_decision(read, scope_name)
}

/// The decision half of [`existing_scope_filter_checked`], split out so the
/// fail-closed rule is unit-testable without an Exchange round trip.
pub(super) fn scope_filter_decision(
    read: Option<ExoManagementScope>,
    scope_name: &str,
) -> Result<Option<String>, UiError> {
    match read {
        None => Ok(None),
        Some(scope) => match scope.recipient_filter {
            Some(filter) => Ok(Some(filter)),
            None => Err(UiError::validation(
                "scope_filter_unreadable",
                format!(
                    "a management scope “{scope_name}” already exists for this app but has no \
                     recipient restriction filter, so it confines nothing — and Exchange keeps the \
                     existing scope rather than replacing it. Migrating onto it would assign this \
                     app's roles against an unrestricted scope and then remove the org-wide grants \
                     and the legacy policy, leaving the app able to reach every mailbox in the \
                     tenant. Nothing was changed. Review the scope in Exchange, or use “Move to \
                     managed group” to consolidate onto the toolkit-managed group."
                ),
            )),
        },
    }
}

/// Whether `current` confines access to exactly the groups `wanted` names.
///
/// Compares group DN **sets**, not raw strings: Exchange normalizes OPATH
/// whitespace, quoting and parenthesization, so a byte comparison would call an
/// identical filter divergent. A `current` this parser cannot fully read is
/// NEVER agreement — an unstatable reach cannot be asserted equal to an intended
/// one, and treating "cannot read" as "matches" is exactly how a stale scope
/// would slip past the guard below.
pub(super) fn scope_filter_agrees(current: &str, wanted: &str) -> bool {
    let g = scope_groups_in_filter(current);
    g.complete && g.dns == group_dns_in_filter(wanted)
}

/// Establishes the recipient filter Exchange **actually has** on `scope_name`,
/// repointing it when permitted, and refusing when it diverges and we may not.
///
/// This is the guard that makes the migration fail closed on a stale scope.
/// `ensure_management_scope` is create-only, so a scope left by an earlier
/// partial migration — or made by hand — keeps its own filter. Previously the
/// repoint was gated on `consolidated && scope_override.is_none()`, and when
/// that gate was false the flow simply carried on: `assign_scoped_roles` bound
/// the app's Exchange roles to that stale scope, `remove_unscoped_grants`
/// stripped its org-wide Entra grants, and the legacy policy was deleted. The
/// app's live mailbox reach silently became whatever the stale scope covered —
/// wider, narrower or simply *different* — while the report printed the filter
/// this run had computed. A migration that reports success while redirecting an
/// application's mailbox access is the exact outcome this product exists to
/// prevent, so a divergence we cannot correct is fatal for that app.
///
/// Returns the filter in force, which the caller reports instead of its own.
pub(super) async fn reconcile_scope_filter(
    exo: &ExchangeClient,
    scope_name: &str,
    existing_filter: Option<&str>,
    wanted_filter: &str,
    may_repoint: bool,
    warnings: &mut Vec<String>,
) -> Result<String, UiError> {
    // No pre-existing scope: `ensure_management_scope` just created it with
    // exactly this filter, so that is what is live.
    let Some(current) = existing_filter else {
        return Ok(wanted_filter.to_string());
    };

    // Compare the group DN SETS, not the raw strings: Exchange normalizes OPATH
    // whitespace, quoting and parenthesization, so a byte comparison would call
    // an identical filter divergent. An unreadable current filter is treated as
    // divergent — we cannot claim it confines what we intend.
    if scope_filter_agrees(current, wanted_filter) {
        return Ok(current.to_string());
    }

    if !may_repoint {
        return Err(UiError::validation(
            "scope_filter_mismatch",
            format!(
                "a management scope “{scope_name}” already exists for this app and confines access \
                 to a different set of groups than this migration computed. Exchange keeps the \
                 existing scope rather than replacing it, and this run is not permitted to repoint \
                 it — either the group consolidation could not be verified, or an explicit scope \
                 name was supplied that may be shared with other applications. Assigning roles \
                 against it and then removing the org-wide grants would change what this app \
                 reaches in a way that was not asked for, so nothing was changed. Review the scope \
                 in Exchange, or use “Move to managed group” to consolidate onto the \
                 toolkit-managed group."
            ),
        ));
    }

    repoint_scope_if_stale(exo, scope_name, current, wanted_filter, warnings).await;

    // PROVE the repoint landed. `repoint_scope_if_stale` is documented as never
    // fatal — it warns and leaves the scope as it was, which is the safe
    // direction for a caller that stops there. This caller does not stop: it
    // goes on to assign roles and strip grants, so a warning is not enough.
    let after = exo
        .get_management_scope(scope_name)
        .await?
        .and_then(|s| s.recipient_filter);
    match after.as_deref() {
        Some(f) if scope_filter_agrees(f, wanted_filter) => Ok(f.to_string()),
        _ => Err(UiError::validation(
            "scope_filter_mismatch",
            format!(
                "management scope “{scope_name}” still does not confine access to the groups this \
                 migration computed after attempting to repoint it, so the app's roles were NOT \
                 assigned and its org-wide grants were left in place. Nothing this app can reach \
                 has changed. Inspect the scope in Exchange."
            ),
        )),
    }
}

/// Points an existing management scope at `wanted_filter` when its current
/// filter names a different group set. A no-op when the scope is already right.
/// Never fatal: a failed repoint leaves the scope as it was, which is the
/// wider-or-equal side, so it warns rather than erroring out mid-flow.
///
/// `current` comes from [`existing_scope_filter_checked`], which the caller has
/// already run — so by the time this is reached the scope is known to exist and
/// to carry a filter. It is deliberately not re-read here: the unfiltered case
/// is fatal and belongs to that guard, not to a function documented as never
/// fatal.
pub(super) async fn repoint_scope_if_stale(
    exo: &ExchangeClient,
    scope_name: &str,
    current: &str,
    wanted_filter: &str,
    warnings: &mut Vec<String>,
) {
    // Refuse to overwrite a filter a rebuild would not reproduce: Exchange
    // applies a scope's filter to EVERY role assignment on it, so dropping an
    // `-and` restriction or a `-not` exclusion here widens mailbox reach
    // silently. Leaving the scope alone is the safe direction — the app keeps
    // exactly the access it has.
    let current_dns = match rewritable_scope_dns(current) {
        Ok(dns) => dns,
        Err(why) => {
            warnings.push(format!(
                "management scope '{scope_name}' was left as it is: {why}. Its filter is \
                 ({current}) — repoint it in Exchange if this app should use the \
                 toolkit-managed group."
            ));
            return;
        }
    };
    if current_dns.iter().cloned().collect::<HashSet<_>>() == group_dns_in_filter(wanted_filter) {
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
    // The move rewrites this filter from a DN list, so it may only proceed when
    // a rebuild would reproduce the filter exactly. A clause we can't reproduce
    // — an `-and` recipient-type restriction, a `-not` exclusion — would be
    // dropped by the rewrite and widen what every role assignment on this scope
    // reaches. Refusing is the outcome, not a fallback.
    let source_dns = rewritable_scope_dns(current_filter).map_err(|why| {
        UiError::validation(
            match why {
                UnrewritableFilter::NoGroupClauses => "no_scope_group",
                _ => "unsupported_scope_filter",
            },
            format!(
                "management scope '{scope_name}' can't be moved onto the toolkit-managed \
                 group because {why} (filter: {current_filter}). Nothing was changed — edit \
                 the scope in Exchange if this app should use the managed group."
            ),
        )
    })?;

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
            retired_groups: Vec::new(),
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
            // The scope still points at these groups, so nothing is retired —
            // reporting a cleanup candidate here would invite deleting a group
            // the app is still scoped to.
            retired_groups: Vec::new(),
            dry_run,
            warnings,
        });
    }

    let wanted_filter = member_of_group_filter(&consolidation.scope_dns);
    exo.set_management_scope_filter(&scope_name, &wanted_filter)
        .await?;
    // Resolved AFTER the repoint, so this app's own scope is read in its new
    // state rather than assumed to have moved.
    let retired_groups = retired_scope_groups(&exo, &source_dns).await;
    warnings.push(format!(
        "{} Exchange can take 30 min–2 h to apply the change (the permission tester bypasses \
         that cache).",
        retired_groups_note(&retired_groups),
    ));
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
        retired_groups,
        dry_run,
        warnings,
    })
}

/// The warning line for the group(s) a repoint retired — **named**, because "the
/// previous group can be cleaned up" left operators hunting through Exchange for
/// which one it meant. Falls back to the DN when a group no longer resolves by
/// name, since that is still enough to find it.
///
/// The claim tracks the check: "can be cleaned up" only when every group came
/// back with no reference *and* a completed check. Anything else says review,
/// because a scope the migration deliberately did not repoint (an operator-set
/// `scope_name` override that other apps may share) still points here.
pub(crate) fn retired_groups_note(groups: &[RetiredScopeGroupDto]) -> String {
    if groups.is_empty() {
        return "The previous group(s) are no longer this app's scope source.".to_string();
    }
    let names: Vec<&str> = groups
        .iter()
        .map(|g| {
            g.display_name
                .as_deref()
                .or(g.primary_smtp_address.as_deref())
                .unwrap_or(&g.distinguished_name)
        })
        .collect();
    let list = format!("'{}'", names.join("', '"));
    let verb = if names.len() == 1 { "is" } else { "are" };
    let clean = groups
        .iter()
        .all(|g| g.reference_check_complete && g.still_referenced_by.is_empty());
    if clean {
        format!(
            "{list} {verb} no longer referenced by any management scope or Application Access \
             Policy the toolkit can see, and can be cleaned up."
        )
    } else {
        format!(
            "{list} {verb} this app's previous scope source — review the notes before deleting."
        )
    }
}
