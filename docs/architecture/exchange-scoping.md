# Exchange mailbox scoping (RBAC for Applications)

Deep-dive companion to the Exchange scoping gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `azapptoolkit-core::scoping`, `azapptoolkit-exchange`, `commands::exchange`, or the Exchange
scoping sections/badges in the frontend. How the resulting verdicts are *scored* is in
[audit-findings-and-remediation.md](./audit-findings-and-remediation.md); the SharePoint sibling is
[sharepoint-selected.md](./sharepoint-selected.md).

## Mailbox permissions live on two resources

Mail/calendar/contacts application permissions are scopable via Exchange RBAC for Applications, so
their *effective* risk depends on whether they're confined to specific mailboxes.

**Two resources carry mailbox permissions, not one.** `azapptoolkit-core::scoping` maps every
Microsoft Graph mailbox permission that [RBAC for
Applications](https://learn.microsoft.com/exchange/permissions-exo/application-rbac#supported-application-roles)
exposes a dedicated role for — the eleven `Mail.*`/`MailboxSettings.*`/`Calendars.*`/`Contacts.*` values
a legacy Application Access Policy could confine **plus** the RBAC-only `MailboxFolder.*`,
`MailboxItem.*`, `MailboxConfigItem.*`, `MailTips.ReadBasic.All` and `Mail-Advanced.ReadWrite.All` —
**and** the EWS `full_access_as_app` scope, which is an appRole on the legacy **Office 365 Exchange
Online** resource (`00000002-…`). Its RBAC counterpart is `Application EWS.AccessAsApp`. The subset an
[Application Access
Policy](https://learn.microsoft.com/exchange/permissions-exo/application-access-policies) governed is
a separate gate, `is_aap_confinable_permission` (see below). Consequences to preserve:

- **Every path that names a concrete Entra grant resolves it through
  `graph_roles::mailbox_resource_roles`** (both resource SPs + their appRole indexes), never
  `graph_role_index` alone. `ExchangeTarget` carries `resource_sp_object_id`, so a strip matches on
  `(resource, appRole)` — both resources expose an appRole literally named `Mail.Read`, so a
  value-only or id-only match hits the wrong grant. This was a real regression: Graph-only filters
  meant a policy confining `full_access_as_app` migrated to *nothing* — no scoped role, no consent
  revoked (the symptom: admin consent still granted), policy deleted anyway.
- **Office 365 Exchange Online's own `Mail.Read`-style appRoles deliberately do NOT map.** They
  authorize the retired Outlook REST API; RBAC for Applications supports MS Graph and EWS only, so
  `exchange_role_for_resource_permission` returns `None` for them. Mapping them would strip a grant
  that has no scoped replacement. Use `exchange_role_for_resource_permission` /
  `is_scopable_exchange_resource_permission` everywhere, including the probe and badge paths: the
  value-only forms were **deleted**, and
  `repo_invariants/commands.rs::the_resource_blind_mailbox_gates_are_not_reintroduced` fails the
  build if any of the old names (including the Graph-defaulting `least_privilege_alternative(value)`
  the picker once used) reappears in any `.rs` file. A path that needs a role for a value whose
  resource it no longer holds (the verdict resolver) receives the `(value, role)` pair from the
  caller that did the resource-aware lookup, rather than re-deriving it.
- **`full_access_as_app` is a blanket grant.** `is_blanket_mailbox_grant` marks it, and
  `reconcile_orgwide_grant` lets a surviving one force `OrgWide` for **every** permission on that
  principal — it reaches all mailboxes with full access, so a `Mail.Read` confined to one group is
  still org-wide in effect. The audit picks these up from its tenant-wide Office 365 grant read
  (`prefetch_office365_role_grants`, every Exchange Online and SharePoint Online role with its
  resource), kept **separate** from the Graph `appRoleAssignedTo` matrix; `ews_full_access_holders`
  derives the blanket-grant set from it, resource-checked.
- **Composite roles confer permissions without carrying their names.** `Application Mail Full Access`
  and `Application Exchange Full Access` bundle several permissions, so `verdict_from_rows` matches
  rows via `row_grants_permission`, which reads `GrantedPermissions` as well as `RoleName`, and falls
  back to the static bundle table `roles::composite_role_confers` only when that list is absent or
  blank (an explicit list is authoritative, so a scoped composite row that excludes the value can't
  turn a no-row `OrgWide` into `Scoped`). Every comparison is case-insensitive. Matching role names alone reported a
  correctly scoped app as org-wide; dropping a list-less **org-wide** composite row beside a scoped
  dedicated one reported an org-wide app as scoped. `targets::orgwide_role_assignments` reads the same
  table, so an org-wide composite assignment raises the "Scoping is NOT effective" warning too.
- **A `Test-ServicePrincipalAuthorization` row is confined only by a known `ScopeType`.**
  `is_org_wide_auth_row` allowlists the confining types (`CustomRecipientScope`, `RecipientScope`
  and the administrative-unit spellings, case-insensitive); a blank/"Not Applicable"
  `AllowedResourceScope` or any other type is org-wide, and an unrecognised type is logged (type
  only, never the scope name; once per distinct type per process). A denylist of org-level
  spellings read an unknown type as confined.
- **The legacy-AAP override reaches only `is_aap_confinable_permission` values.** On both the audit
  fold (`apply_legacy_policy_verdict`) and the detail path (`resolve_mail_scopes`' `aap_override`
  and its probe-failure fallback), a policy answers only for what it governed. Each
  `ScopableMailPermission` carries `aap_confinable`, decided where the resource is known
  (`ScopableMailPermission::on_resource`, or `ExchangeTarget.aap_confinable` from
  `exchange_target`). An RBAC-only value on a policy-confined app keeps its RBAC verdict: org-wide
  when the probe found no scope or could not resolve the principal, `Unknown` after any other probe
  failure, never "Scoped (legacy)". Such a failure-derived `Unknown` is never cached
  (`verdicts_are_cacheable`). The permission tester's `entra_reach` applies the same gate to
  resource-carrying held grants (`try_held_orgwide_mail_permissions`): an ungoverned grant is
  `EntraReach::OrgWide` before any policy is consulted.

**Two role sets, two gates.** The ten RBAC-only Graph roles (`MailboxFolder.*`, `MailboxItem.*`,
`MailboxConfigItem.*`, `MailTips.ReadBasic.All`, `Mail-Advanced.ReadWrite.All`) are mapped like the
AAP-era eleven: scopable (`is_scopable_exchange_resource_permission`), members of the audit's
org-wide mailbox advisory with the one-click Scope fix, offered by the Grant-access wizard, and shown
in the Permissions-tab Scope column. `MailboxItem.ReadWrite.All` and `Mail-Advanced.ReadWrite.All`
read, write and delete every item in every mailbox, so leaving them unmapped scored them zero. Two
things stay deliberately narrower:

- **`SMTP.SendAsApp` is not mapped.** Learn files it under protocol "MS Graph", but the appRole is on
  Office 365 Exchange Online and backs live SMTP client submission; mapping it would make
  `is_unscopable_legacy_exchange_permission` tell an operator to remove it. Pinned by
  `smtp_send_as_app_is_mapped_on_neither_resource` and
  `unscopable_legacy_exchange_spares_the_live_protocol_roles`.
- **The AAP migration targets only `is_aap_confinable_permission`** (the eleven + EWS), never the
  whole scopable set. The migration scopes a grant and then *strips* it; a grant RBAC can scope but no
  policy ever governed is org-wide today and must stay org-wide when the policy goes, or the migration
  silently narrows live access. `targets_from_grants` applies that gate;
  `targets_from_declared` (Grant access / Scope fix) does not, because there the operator chose the
  permission. Pinned by `aap_confinable_is_a_strict_subset_of_scopable` and
  `granted_targets_span_both_resources_and_keep_resources_apart`.

Widening either gate shifts the audit's scoped-mail weighting, so it needs a CHANGELOG note.
`-RecipientAdministrativeUnitScope` is a read-only capability here: an AU-scoped assignment is *read*
correctly (`is_org_wide_auth_row` won't call it org-wide; the enrich step simply finds no management
scope), but the grant paths only build `MemberOfGroup` management scopes. The role-assignment list
(`list_exchange_role_assignments`) labels such an assignment "Administrative unit <id>" rather than
"(org-wide)"; `roles_already_scoped` and `plan_role_assignments` stay keyed on `CustomResourceScope`,
because an AU scope is not the toolkit's group scope. The AU wire keys (`RecipientWriteScope`,
`CustomRecipientWriteScope`, `RecipientAdministrativeUnitScope`) are read tolerantly, each its own
field, pending a captured AU-scoped envelope.

## Migrating a legacy Application Access Policy

**Migrating a legacy AAP is not a mechanical rewrite.** `migrate_application_access_policies` +
`migrate_one` follow Microsoft's five documented steps (scope → SP pointer → scoped roles → remove
Entra consent → remove policy), with three guards that the doc's happy path doesn't mention and whose
absence each caused a real widening of access:

Before the scope is built, the policy's groups are **consolidated onto the toolkit-managed group**
(see below) so a migrated app lands on the naming standard rather than pinned to a legacy group.
`ensure_management_scope` is create-only, so a re-run repoints via `repoint_scope_if_stale` — but
**only** when the scope name came from the tenant pattern, never from a `scope_name` override, which
may be shared with other apps whose reach must not change as a side effect.

- **`RestrictAccess` only** (`group_policies_for_migration`, pure + tested). A `DenyAccess` policy is
  a *blocklist* — every mailbox except its group — and a management scope is an allow-list, so
  converting one inverts it: the app gains exactly what it was denied and loses the rest. `DenyAccess`
  (and an unreadable `AccessRight`) is reported, never migrated. Note `aap_verdict_for` has always
  got this distinction right for *verdicts*; it was only the migration that didn't consult it.
- **One batch per application.** Several `RestrictAccess` policies on one app grant the *union* of
  their groups (`New-ApplicationAccessPolicy` evaluation rule 3) and an app gets exactly one
  management scope, so they migrate into one scope spanning every group. Migrating them one at a time
  silently dropped all but the first (`ensure_management_scope` keeps an existing scope) and then
  deleted every policy. `AapMigrationItem` is therefore per **app**, with
  `source_policy_identities` / `removed_policies` as vectors.
- **The policy outlives an un-stripped grant** (`policies_safe_to_remove`, pure + tested). Step 5 runs
  only when every target's org-wide grant was actually removed, or when there were no constrainable
  targets at all (the policy then governs nothing). A partial strip **keeps** every policy and reports
  `partial` naming the blockers — the policy is the only thing still confining them.

A real run busts `invalidate_app_lists` once it has **attempted** any app
(`migration_should_invalidate`), not only when an app produced an item: `migrate_one` can return
`Err` after the scope, the member copy or the SP pointer landed.

## Surfaces and resource-aware rendering

The verdict resolver itself (`resolve_mail_scopes`, bulk vs. detail resolution, org-wide-grant
reconciliation and the legacy-AAP fold) is described in
[audit-findings-and-remediation.md](./audit-findings-and-remediation.md#scope-aware-audit-risk).

**Surfaces.** The per-app detail uses the resolver via the `get_mail_permission_scopes` command
(the Permissions-tab "Scope" column). **Managed identities** are
service principals too, so the same verdict applies — but they have no app registration manifest,
so the MI detail view uses `get_mail_scopes_for_principal(tenant_id, app_id, permissions)` (keyed
on the SP's app id + its *granted* app-role values) instead of `get_mail_permission_scopes` (which
reads a manifest). A detail-path verdict is enriched with the scope's filter and group
count only when the matching rows name exactly **one** scope (`verdict::distinct_scope_names`):
several scopes produce the joined display name "A, B", which names no scope, so it is never looked
up as one. The badge rendering for all three surfaces lives in one place —
`web-rs/components/scope_badge.rs` (`permission_scope_cell` / `mailbox_scope_badge` /
`is_exchange_scopable`).

**The frontend is resource-aware too, and has to be.** `AppRoleGrantDto` carries
`resource_app_id` (`None` for a resource the backend doesn't resolve, whose row still renders
id-only), because a *value* alone can't answer scopability once two resources are in play. Every
held-permission surface (MI detail + window, enterprise Permissions tab, `OrgwideScopeCallout`,
`permission_scope_cell`) uses **`is_exchange_scopable_on(resource, value)`**, and the app-reg
Permissions tab passes `ResolvedPermission::resource_app_id`. Two things break if a surface reverts
to the value-only `is_exchange_scopable`: Exchange Online's un-scopable `Mail.Read` gains a "Scope…"
action the backend correctly refuses to honour (and an alarming "Unknown" verdict that will never
arrive), and a `full_access_as_app` row seeds the wizard with Microsoft Graph — a resource that
doesn't expose it. `resolve_app_role_grants` resolves both resources so the EWS scope reads as
itself instead of a bare GUID; the callout additionally names it as a **blanket** grant that
overrides per-permission mailbox scopes, mirroring `reconcile_orgwide_grant` so the two surfaces
can't appear to contradict each other. Pinned by `orgwide_scope_callout` unit + GUI tests.

**The scope *verdict* is resource-gated too, not just the actions.** `mail_scopes` is keyed on
permission value alone, so `permission_scope_cell` (via the pure `scope_cell_for`) consumes a verdict
**only** when the row is an Application permission *and* `is_exchange_scopable_on(resource, value)`.
Without that gate an app declaring `Mail.ReadWrite` on both resources paints Exchange Online's
un-scopable row with Graph's badge — "Org-wide" on a row that was never scopable reads as a scoping
failure — and a delegated `Mail.Read` inherits the application verdict. Pinned by `scope_badge` unit
tests; both call sites (`permissions_tab`, `held_permissions_panel`) route through the one function.

**Legacy Exchange Online mail grants are unscopable, and are called out rather than reconciled.**
Office 365 Exchange Online's own `Mail.*`/`Calendars.*`/`Contacts.*`/`MailboxSettings.*` appRoles
(retired Outlook REST) have no RBAC role. `held_orgwide_mail_grants` filters with the resource-aware
`is_scopable_exchange_resource_permission`, so those grants are **excluded** from the org-wide
reconciliation set — `reconcile_orgwide_grant` only ever sees confinable grants (Graph's mail family
and the EWS scope), and a surviving legacy grant does not flip the identically named *Graph*
permission's verdict. They still reach every mailbox, and nothing confines them once the AAP is gone,
so they are surfaced as their own thing: `LegacyExchangeGrantsCallout` names them on the app-reg
Permissions tab and in `HeldPermissionsPanel`, and the audit raises `UNSCOPABLE_LEGACY_MAILBOX` (its
own finding group `unscopable_legacy_mailbox`, no Scope fix). They are unfixable from any scoping surface — `targets_from_declared`
never targets them, so `remove_unscoped_grants` never strips them — and the only remedy is removing
the grant. The predicate everywhere is `core::scoping::is_unscopable_legacy_exchange_permission` —
the resource's mail-named roles **only**. Never widen it to the whole resource: `full_access_as_app`
is scopable, and `EWS.AccessAsApp` / `Exchange.ManageAsApp` / `IMAP`/`POP`/`SMTP.*AsApp` back live
protocols, so naming them would tell an operator to break a working integration.

`full_access_as_app` **is** in the audit's high-risk list (`audit/permissions.rs`): it is the
broadest mailbox grant there is, and it carries the reduced scoped weight once
`Application EWS.AccessAsApp` confines it — the resolver keys its verdict under the value like any
Graph row.

**Error-body hygiene.** Exchange error bodies are sanitized by the shared
`azapptoolkit_core::http_error::sanitize_error_body` (Graph, ARM and Key Vault bodies go through
the same helper) because a 403 can return a NUL-padded blob; log the `ui_code`, never the raw body.

## Scoped grants reuse one Exchange core

The scoped-mailbox grant body (register Exchange SP → management scope from groups → scoped role
assignment → strip org-wide Entra grant → `invalidate_app_lists`) lives in
`commands::exchange::apply_exchange_mailbox_scope`; the two callers differ only in how
`ExchangeTarget`s are derived:

- `grant_exchange_mailbox_access` reads an app registration manifest (`targets_from_declared`). It
  takes an optional `permissions` filter so it can scope **one** declared mail permission (the
  per-permission "Scope…" action) or all of them (`None`, the coarse "scope all" action in the Permissions tab's Exchange scoping section).
- `grant_managed_identity_scoped_exchange_access` builds them from the permission values being
  granted (managed identities have no manifest).

The MI grant form opens an inline scope panel for a scopable permission; non-scopable ones grant
org-wide as before.

`remove_unscoped_grants` strips only targets whose scoped role landed, through the shared
`graph_roles::strip_app_role_grants`, and reports what is still held org-wide from the **live
assignments**, never from the targets (the wizard declares a permission before scoping it, so a
target is routinely declared but not held); the core names those permissions in one "Scoping is NOT
effective" warning, phrased by the same `still_granted_orgwide` the AAP migration's KEPT note uses.
RBAC grants union in Exchange too: `assign_scoped_roles` (both callers) reads the role snapshot and,
via the pure `targets::orgwide_role_assignments`, adds one "Scoping is NOT effective for <role>"
warning per **org-wide Exchange assignment** of a role being scoped (no management scope, AU or
custom write scope). It never removes that assignment — it may be deliberate. `roles_already_scoped`
compares the scope name case-insensitively, and `migrate_one` lower-cases the policy's AppId
before naming the scope and group, so a policy stored with an upper-case GUID recognises the scope
it already holds instead of re-assigning (and failing) on every re-run.

`remove_exchange_mailbox_access` reports what it could not remove in `failed` (a rejected removal,
or a row with no `Identity`, which is never skipped silently), and returns `Err` when nothing came
off and something is still assigned — the UI shows a partial removal as an error toast naming the
leftovers, never as "Removed N".
`grant_exchange_mailbox_access` validates its targets before `ensure_service_principal`, and a
newly created SP busts the list tier even when the scope step then fails.

### Toolkit-managed scope group (default `app_scope_group_<app_id>`)

The recommended scope source is a **toolkit-managed mail-enabled security group**, named by
`TenantDefaults::group_name_for` (default `app_scope_group_<app_id>`) — exactly one managed group per
app. The management **scope** built over it is named separately by `TenantDefaults::scope_name_for`
(default `app_scope_<app_id>`), deliberately distinct from the group so a scope and its backing group
never collide on name. **Both** names resolve from the tenant's configurable Settings patterns
(`scope_name_pattern` / `group_name_pattern`, `{appId}`-templated, blank ⇒ the built-in default) and
apply to **every** Exchange scoping path — fresh scoped grants and the legacy-AAP migration alike;
commands load them through the `load_tenant_defaults(tenant_id)` helper rather than a hardcoded prefix.
The legacy-AAP-migration command additionally accepts an optional `scope_name` override for a
single-app run (blank ⇒ the pattern default; a whole-tenant run always derives the per-app default so
scopes can't clash). Three commands manage the group, all in `commands::exchange`:

- `list_exchange_scope_group` — `Get-DistributionGroup` + `Get-DistributionGroupMember`; returns
  whether the group exists, its SMTP/DN, and its members.
- `add_exchange_scope_group_members` — `New-DistributionGroup -Type Security -IgnoreNamingPolicy`
  on first use (idempotent), then `Add-DistributionGroupMember` per mailbox; per-mailbox failures
  are collected, not fatal. Adding an existing member is a no-op (the client swallows the EXO
  "already a member" 400).
- `remove_exchange_scope_group_members` — `Remove-DistributionGroupMember`
  `-BypassSecurityGroupManagerCheck` (removing a non-member is a no-op).

#### Consolidating an existing scope onto the managed group

`consolidate_scope_group` (`commands::exchange`) is the shared core behind two callers: the AAP
migration (source = the policies' groups) and the `move_exchange_scope_to_managed_group` command
(source = the groups the app's live management scope already references — the path for an app that
already migrated, whose policy is gone, or one scoped to a hand-made group). Both end with the
scope's `MemberOfGroup` filter naming the managed group alone, so reach is edited in one place.
Invariants, each of which exists because its absence *narrows* access silently:

- **Fail closed on anything unproved.** The pure `plan_consolidation`
  (`azapptoolkit-exchange::targets`) returns the managed group's DN only when its DN resolved,
  zero source members are unverified AND the managed group holds nothing the source does not;
  otherwise the scope keeps the source DNs unchanged. A mailbox an integration can no longer read
  fails as "not found", not "denied", so narrowing is the quiet risk — but widening is a risk too.
- **The managed group must equal the source, not merely contain it.** An existing managed group is
  NOT reused as-is: `aap::extra_members` (case-folded keys, an unidentifiable member counts) names
  every member the source lacks, and `Refusal::ExtraManagedMembers` refuses the repoint. The path
  that made this real: an AAP run copies G1 and refuses, the policy is changed to G2, the re-run
  copies G2, verifies every G2 member present and repoints — reach G1 ∪ G2. The dry run reads the
  managed group and names the extras (capped at `MAX_LISTED_MEMBERS`, then "and N more"), and
  `ExchangeScopeConsolidationResult.refused` makes the plan say it would be refused instead of
  offering "Move now"; a real run refuses before copying anything, and the post-copy re-read checks
  again. **Exception:** when the app's live scope already names the managed group alone
  (`targets::filter_names_only_group`), its members ARE the app's current reach, so nothing can
  widen and the check is skipped — otherwise every re-run after an operator edited the managed
  group was refused.
- **Member reads are complete.** `list_group_members` sends `ResultSize: Unlimited`;
  `Get-DistributionGroupMember` otherwise stops at 1000 *silently*, which made a truncated source
  read look complete and the repoint narrow. No other list cmdlet the client sends takes
  `-ResultSize`.
- **The copy is cancellable and bounded.** Adds run `MEMBER_COPY_CONCURRENCY` (4) at a time, each
  gated on the caller's `CancelToken` and a `SessionDead` latch — the migration passes its
  `migration_cancel` token, `move_exchange_scope_to_managed_group` claims `scope_move_cancel`
  (stopped by `cancel_scope_move`). A failed add is retried once, serially, under the same gates
  (concurrent adds to one group can hit Exchange's "object modified" conflict). A stopped copy
  keeps the source and reports `incomplete`; in the migration, `migrate_one` then stops that app
  **before** any scope, role, Entra-grant or policy write (status `partial`, policy kept) and the
  run is reported `incomplete` even when it was the only app.
- **Verification re-reads the group; it does not trust the adds.** EXO accepts some recipient types
  and then doesn't list them. Comparison is on `source_member`'s case-folded key (primary SMTP,
  else GUID); a member with neither is unidentifiable, so its source group counts as unreadable.
- **An empty source group is unreadable, not empty.** `Get-DistributionGroupMember` returns nothing
  for a Microsoft 365 group (its members need `Get-UnifiedGroupLinks`), so treating "no members" as
  "no mailboxes" would repoint the scope at an empty group and cut the app off from everything.
- **Repointing is never a side effect.** `set_management_scope_filter` (`Set-ManagementScope`) is the
  only mutator of an existing scope's filter, and Exchange applies it to **every** role assignment
  using that scope. `apply_exchange_mailbox_scope` therefore still only *warns* on a group-set
  mismatch — a grant must not rewrite a scope other permissions depend on; the operator chooses the
  move explicitly, from a dry-run plan listing the mailboxes.
- **Invalidation:** the repoint changes the resolved verdict's filter and group count but not the
  app/SP set ⇒ `invalidate_app_detail_state`, not `invalidate_app_lists`.

#### Retiring the group the scope left behind

A consolidation ends with a group nothing points at, so both callers report it (`retired_groups` on
`ExchangeScopeConsolidationResult` / `AapMigrationItem`, rendered by
`components::retired_scope_groups`) instead of the old anonymous "the previous group can be cleaned
up". `retired_scope_groups` resolves each source DN to its name/SMTP and runs the pure
`references_to_group` over **two enumerable authorities** — management scopes' `MemberOfGroup`
filters (matched on DN) and legacy AAPs (matched on `ScopeName`/`ScopeIdentity`, which carry the
group *name*, so a DN-only match misses them). Populated **only when the repoint actually happened**:
while the consolidation is a plan or fails closed, the scope still points at the group and nothing is
retired. A kept policy still names its group and so shows up as a live reference — exactly right, and
it stops the group being deleted out from under it.

**The app's own scope is deliberately NOT excluded from the check.** It is read after the repoint,
so normally it no longer names the group — but the AAP migration skips its repoint when an
operator-supplied `scope_name` override may be shared with other apps, and `ensure_management_scope`
is create-only, so a pre-existing scope can still point at the legacy group. Excluding it by name
reported that group as unreferenced and offered to delete a group the app was still scoped to;
reporting a scope that hasn't caught up only *withholds* the delete, which is the safe direction.
`retired_groups_note` follows the same rule — it claims "can be cleaned up" only when every group
came back with no reference **and** a completed check.

`delete_exchange_scope_group` is the cleanup, and it is **offered, never automatic**:
`Remove-DistributionGroup` has no undo (the address starts bouncing), and the checks above cannot see
transport rules, DLP/retention, nesting, or anyone who simply mails the group. So the UI states that
limit and takes a typed confirmation, and the command re-verifies every guard against live state
before acting: the group must still resolve *as a distribution/mail-enabled security group*, must not
be this app's managed scope group (deleting that removes the app's access entirely), and must have
**zero** references from a check that **completed** — `reference_check_complete: false` is an unknown
and is refused, never read as clean. Both org-wide reads behind it (`list_management_scopes`,
`get_application_access_policies`) fail on any rejection rather than reading "not found" as an empty
list — only an `-Identity` lookup goes through `invoke_optional`. No invalidation: a distribution group is absent from the app/SP
and name indexes, and both the group listing and the scope verdict are read live.

The grant flow is **unchanged**: the UI passes the managed group's identifier in the existing
`groups` list, so `apply_exchange_mailbox_scope` resolves its DN and builds the `MemberOfGroup`
filter as it does for any group. The win is that the group's DN is **stable**, so scoping is
adjusted by editing the group's *membership* — the (immutable) management-scope filter never has to
change. **No cache invalidation** on add/remove: membership doesn't change the cached scope verdict
(it keys off the scope name / `MemberOfGroup`-clause count), the member list is fetched live, and a
distribution group is absent from the app/SP pairing + name indexes. Caveats (surfaced in the UI):
only **direct** members are in scope (nested groups are ignored), and RBAC changes take 30 min–2 h
to propagate (`Test-ServicePrincipalAuthorization` bypasses that cache). Creating/populating the
group needs the Exchange **Distribution Groups** role (Recipient Management / Organization
Management — all covered by **Exchange Administrator**).

## Repointing a management scope (fail-closed)

`ensure_management_scope` is **create-only**. `set_management_scope_filter` is
the sole filter mutator, and Exchange applies a filter change to **every** role
assignment on that scope — so repointing is never incidental to another
operation.

A filter may only be rewritten once `targets::rewritable_scope_dns` proves it a
pure `MemberOfGroup` OR-chain; anything it cannot fully read is unrewritable.
`plan_consolidation` owns the rest of the decision. Both refuse rather than fall
back: a scope that cannot be *proved* safe to narrow keeps its original groups,
because an integration that silently stops seeing a mailbox reports "not found",
not "denied" — the hardest kind of outage to trace to a permission change.

## Transport: the InvokeCommand gateway

Every Exchange cmdlet rides `POST {base}/adminapi/beta/{tenant}/InvokeCommand` with a `CmdletInput`
envelope (`azapptoolkit-exchange::client`). That is the ExchangeOnlineManagement PowerShell module's
own REST transport, exercised against live tenants but **not a contract Microsoft publishes for
third parties**. The documented Admin API is the preview `adminapi/v2.0/{tenant}/{Endpoint}` surface
with `Exchange.ManageV2`; its six endpoints (AcceptedDomain, Mailbox, MailboxFolderPermission,
OrganizationConfig, DistributionGroupMember, DynamicDistributionGroupMember) cover none of the
RBAC-for-Applications cmdlets, and the gateway rejects a `ManageV2` token, so the app requests the
classic `Exchange.Manage` scope (`core::constants::EXCHANGE_SCOPES`). The support risk is that
Microsoft can change the gateway without notice. Migration trigger: once the role-assignment,
management-scope, service-principal and `Test-ServicePrincipalAuthorization` cmdlets appear under
`adminapi/v2.0`, move to that surface and to `Exchange.ManageV2`.

## Name the resource in operator-facing text

Wherever a mailbox or SharePoint permission is shown to an operator — a finding, a Fix's preview, a
scope badge, a CSV column — say which **resource** exposes it, not just the value. `Mail.Read` on
Microsoft Graph and `Mail.Read` on Office 365 Exchange Online are different permissions with
different reach, and only Graph's can be confined. Text that shows the bare value asks the operator
to make a scoping decision on information that cannot answer it, and reads as though the two rows
were duplicates of one grant.
