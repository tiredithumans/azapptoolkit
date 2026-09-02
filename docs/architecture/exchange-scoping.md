# Exchange mailbox scoping (RBAC for Applications)

Deep-dive companion to the Exchange scoping gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `azapptoolkit-core::scoping`, `azapptoolkit-exchange`, `commands::exchange`, or the Exchange
scoping sections/badges in the frontend. How the resulting verdicts are *scored* is in
[audit-findings-and-remediation.md](./audit-findings-and-remediation.md); the SharePoint sibling is
[sharepoint-selected.md](./sharepoint-selected.md).

## Mailbox permissions live on two resources

Mail/calendar/contacts application permissions are scopable via Exchange RBAC for Applications, so
their *effective* risk depends on whether they're confined to specific mailboxes.

**Two resources carry mailbox permissions, not one.** `azapptoolkit-core::scoping` maps the eleven
Microsoft Graph mail/calendar/contacts values **and** the EWS `full_access_as_app` scope, which is an
appRole on the legacy **Office 365 Exchange Online** resource (`00000002-…`) — exactly the set
Microsoft documents an [Application Access
Policy](https://learn.microsoft.com/exchange/permissions-exo/application-access-policies) as able to
confine, so an AAP migration can always map what a policy was restricting. Its RBAC counterpart is
`Application EWS.AccessAsApp`. Consequences to preserve:

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
  that has no scoped replacement. Use the resource-aware function wherever the resource is known;
  the value-only `exchange_role_for_permission` exists for the probe/badge paths and is unambiguous
  only because the two resources share no *mapped* value names.
- **`full_access_as_app` is a blanket grant.** `is_blanket_mailbox_grant` marks it, and
  `reconcile_orgwide_grant` lets a surviving one force `OrgWide` for **every** permission on that
  principal — it reaches all mailboxes with full access, so a `Mail.Read` confined to one group is
  still org-wide in effect. The audit picks these up from one extra tenant-wide read
  (`prefetch_ews_full_access_grants`), kept **separate** from the Graph `appRoleAssignedTo` matrix so
  the SP-only phase's candidate rule ("holds a Graph application grant") is unchanged.
- **Composite roles confer permissions without carrying their names.** `Application Mail Full Access`
  and `Application Exchange Full Access` bundle several permissions, so `verdict_from_rows` matches
  rows via `row_grants_permission`, which reads `GrantedPermissions` as well as `RoleName`. Matching
  role names alone reported a correctly scoped app as org-wide.

Not mapped, on purpose: the rest of the ~22 supported application roles (`MailboxFolder.*`,
`MailboxItem.*`, `SMTP.SendAsApp`, `MailboxConfigItem.*`, `MailTips.ReadBasic.All`). They are
RBAC-scopable today but were never AAP-scopable, so they don't affect migration parity — adding one
is additive, but it widens `is_scopable_exchange_permission` and therefore the audit's scoped-mail
weighting, which needs a CHANGELOG note. `-RecipientAdministrativeUnitScope` is likewise a read-only
capability here: an AU-scoped assignment is *read* correctly (`is_org_wide_auth_row` won't call it
org-wide; the enrich step simply finds no management scope), but the grant paths only build
`MemberOfGroup` management scopes.

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

## Surfaces and resource-aware rendering

The verdict resolver itself (`resolve_mail_scopes`, bulk vs. detail resolution, org-wide-grant
reconciliation and the legacy-AAP fold) is described in
[audit-findings-and-remediation.md](./audit-findings-and-remediation.md#scope-aware-audit-risk).

**Surfaces.** The per-app detail uses the resolver via the `get_mail_permission_scopes` command
(the Permissions-tab "Scope" column). **Managed identities** are
service principals too, so the same verdict applies — but they have no app registration manifest,
so the MI detail view uses `get_mail_scopes_for_principal(tenant_id, app_id, permissions)` (keyed
on the SP's app id + its *granted* app-role values) instead of `get_mail_permission_scopes` (which
reads a manifest). The badge rendering for all three surfaces lives in one place —
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

**Legacy Exchange Online mail grants are the "scoped app still reads Org-wide" trap.** Office 365
Exchange Online's own `Mail.*`/`Calendars.*`/`Contacts.*`/`MailboxSettings.*` appRoles (retired
Outlook REST) have no RBAC role, yet `held_orgwide_mail_grants` filters with the **value-only**
`is_scopable_exchange_permission`, so a surviving grant enters the org-wide set and
`reconcile_orgwide_grant` flips the identically named *Graph* permission to `OrgWide`. That is
correct (never under-report — nothing confines those grants once the AAP is gone), but it is
unfixable from any scoping surface: `targets_from_declared` never targets them, so
`remove_unscoped_grants` never strips them and re-running the scope flow changes nothing. Only
removing the grant helps, so `LegacyExchangeGrantsCallout` names them on the app-reg Permissions tab
and in `HeldPermissionsPanel`. Its predicate is `core::scoping::is_unscopable_legacy_exchange_permission`
— the resource's mail-named roles **only**. Never widen it to the whole resource:
`full_access_as_app` is scopable, and `EWS.AccessAsApp` / `Exchange.ManageAsApp` /
`IMAP`/`POP`/`SMTP.*AsApp` back live protocols, so naming them would tell an operator to break a
working integration.

**Known display gap:** `full_access_as_app` is not in the audit's high/medium risk lists, so it
shows no risk badge even though it is the broadest mailbox grant there is. Adding it would shift
audit ranking (an operator-visible change needing a CHANGELOG note), so it is deliberately left
alone here rather than folded into a correctness fix.

**Error-body hygiene.** Exchange error bodies are sanitized (`client.rs::sanitize_error_body`)
because a 403 can return a NUL-padded blob; log the `ui_code`, never the raw body.

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

- **Fail closed on anything unproved.** The pure `scope_dns_after_consolidation`
  (`azapptoolkit-exchange::targets`) returns the managed group's DN only when its DN resolved AND
  zero source members are unverified; otherwise it returns the source DNs unchanged. Narrowing is
  the risk here, not widening — the managed group is built from the source membership — and a
  mailbox an integration can no longer read fails as "not found", not "denied".
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
and is refused, never read as clean. No invalidation: a distribution group is absent from the app/SP
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

## Name the resource in operator-facing text

Wherever a mailbox or SharePoint permission is shown to an operator — a finding, a Fix's preview, a
scope badge, a CSV column — say which **resource** exposes it, not just the value. `Mail.Read` on
Microsoft Graph and `Mail.Read` on Office 365 Exchange Online are different permissions with
different reach, and only Graph's can be confined. Text that shows the bare value asks the operator
to make a scoping decision on information that cannot answer it, and reads as though the two rows
were duplicates of one grant.
