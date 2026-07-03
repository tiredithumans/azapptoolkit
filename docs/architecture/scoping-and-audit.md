# Exchange/SharePoint scoping & the security audit

Deep-dive companion to the scoping/audit gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `azapptoolkit-core::audit`, `commands::exchange`, `commands::sharepoint`,
`commands::remediation`, or the scope badges/panels in the frontend.

## Scope-aware audit risk

Mail/calendar/contacts application permissions are scopable via Exchange RBAC for Applications, so
their *effective* risk depends on whether they're confined to specific mailboxes.

**The `mail_scopes` map.** `score_application` reads `AppPermissions.mail_scopes` (a
`value → MailPermissionScope` map in `azapptoolkit-core::audit`): a permission confirmed `Scoped`
earns a reduced weight (high 10→3, medium 5→2) and a positive Rule-11 note instead of the org-wide
advisory. An **empty** map (the default) means scoping wasn't resolved — every mail permission
scores at its full org-wide weight, i.e. byte-for-byte the pre-scope behavior, so the non-mail
rules keep PowerShell parity.

**Bulk vs. detail resolution.** `run_audit` resolves the map on **every** run (best-effort — it
degrades to the empty-map org-wide scoring when the signed-in user lacks Exchange-admin rights, so
no toggle is needed). The resolver (`commands::exchange::resolve_mail_scopes`, authoritative via
`Test-ServicePrincipalAuthorization`) **returns `Result`**:

- The bulk-audit caller (`enrich == false`) swallows any error (empty map → scored org-wide,
  never under-reported). An **auth** failure (401/403) additionally trips a run-wide circuit
  breaker — it would recur for every remaining mail app, each a doomed 1-5s cmdlet POST — so the
  rest of the run skips the probes; scoring is identical to the swallowed-error path, and the
  next run probes afresh ("resolved on every run" still holds).
- The per-app detail commands (`get_mail_permission_scopes` / `get_mail_scopes_for_principal`,
  `enrich == true`) instead *resolve* most probe failures rather than propagating them: a
  **missing-principal** error (a managed identity — or any SP never registered in Exchange RBAC —
  isn't in Exchange's SP store, so the cmdlet can't resolve it) means the SP has no RBAC scope ⇒
  `OrgWide`, unless a `RestrictAccess` legacy AAP confines it ⇒
  `Scoped { LegacyApplicationAccessPolicy }`. Only a *genuine* 403/consent failure (the user holds
  the Entra Exchange-Admin role but lacks the effective EXO "Role Management" RBAC role — see
  `ExchangeError::ui_hint`) **propagates**, so the UI shows the reason + a "Grant consent / Retry"
  affordance (the app-reg Permissions tab **and** the MI detail view) instead of silently painting
  every row "Unknown".

**Org-wide-grant reconciliation.** `Test-ServicePrincipalAuthorization` sees **only the Exchange
RBAC layer** — it deliberately excludes app-role grants made in Entra. A scoped RBAC verdict
coexisting with an un-stripped org-wide Entra grant still reaches every mailbox, so verdicts are
reconciled against `held_orgwide_mail_grants` (`reconcile_orgwide_grant` in
`commands::exchange`): scoped-RBAC + surviving org-wide grant ⇒ `OrgWide`. The one exemption is a
legacy AAP, which genuinely confines an org-wide grant. This is what catches "scope created but
org-wide grant never removed".

**Legacy Application Access Policies (AAP).** The detail path resolves the legacy AAP up front
(`enrich`-gated, so the bulk audit never pays the extra call) — keyed only on appId via an
independent cmdlet, so it overrides an org-wide RBAC verdict **and** answers when the probe itself
errors (the MI case, where the old code propagated before the AAP was ever read). A
`RestrictAccess` AAP yields `Scoped { mechanism: LegacyApplicationAccessPolicy }` (`DenyAccess` is
a blocklist → still org-wide). The missing-principal→`OrgWide` vs. propagate decision is the pure
`scope_from_rbac_error`, with `ExchangeError::is_missing_object` distinguishing the two failure
modes. `MailPermissionScope::Scoped` carries a `ScopeMechanism`
(`Rbac` | `LegacyApplicationAccessPolicy`) so the badge can label legacy scopes and nudge
migration.

**Surfaces.** The per-app detail uses the resolver via the `get_mail_permission_scopes` command
(the Permissions-tab "Scope" column). **Managed identities** are
service principals too, so the same verdict applies — but they have no app registration manifest,
so the MI detail view uses `get_mail_scopes_for_principal(tenant_id, app_id, permissions)` (keyed
on the SP's app id + its *granted* app-role values) instead of `get_mail_permission_scopes` (which
reads a manifest). The badge rendering for all three surfaces lives in one place —
`web-rs/components/scope_badge.rs` (`permission_scope_cell` / `mailbox_scope_badge` /
`is_exchange_scopable`).

**Error-body hygiene.** Exchange error bodies are sanitized (`client.rs::sanitize_error_body`)
because a 403 can return a NUL-padded blob; log the `ui_code`, never the raw body.

**SharePoint is the simpler sibling.** Its scoping is encoded by the permission *name*
(`Sites.Selected` = scoped to individually-granted sites; every other `Sites.*` = org-wide), so the
verdict needs no live call and no `mail_scopes`-style map — Rule 12 derives it directly, and the
Permissions-tab "Scope" column / audit facets reuse the same name check. Graph has **no reverse
`appId → sites` lookup**, so the named sites can't be enumerated (only per-site via the SharePoint site
access section on the Permissions tab). `Sites.ReadWrite.All` is scored high-risk (a deliberate net-new deviation from the PowerShell
source, alongside `Sites.FullControl.All`).

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

### Toolkit-managed scope group (`azapptoolkit_<app_id>`)

The recommended scope source is a **toolkit-managed mail-enabled security group**, named
`azapptoolkit_<app_id>` by `group_name_for` (the same convention as `scope_name_for`'s management
scope — exactly one managed group per app). Three commands manage it, all in `commands::exchange`:

- `list_exchange_scope_group` — `Get-DistributionGroup` + `Get-DistributionGroupMember`; returns
  whether the group exists, its SMTP/DN, and its members.
- `add_exchange_scope_group_members` — `New-DistributionGroup -Type Security -IgnoreNamingPolicy`
  on first use (idempotent), then `Add-DistributionGroupMember` per mailbox; per-mailbox failures
  are collected, not fatal. Adding an existing member is a no-op (the client swallows the EXO
  "already a member" 400).
- `remove_exchange_scope_group_members` — `Remove-DistributionGroupMember`
  `-BypassSecurityGroupManagerCheck` (removing a non-member is a no-op).

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

## The scope registry + the mechanism-dispatched wizard

Scoping is a **family of independent authorities**, unified behind one classifier and one UI shell:

- **Registry** (`azapptoolkit-core::scoping`): `ScopeKind` (Exchange / SharePoint, room to grow) +
  `scope_kind(value) -> Option<ScopeKind>` (the single "what mechanism, if any?" decision) + metadata
  (`target_noun` / `capability_key` / `admin_applicable`). `admin_applicable() == false` is the seam
  for future owner-consented mechanisms (Teams/Chat RSC) — the UI renders guidance, not an apply.
- **Wizard** (`web-rs/components/scope_wizard.rs`, the "Grant scoped access…" button on every
  principal's Permissions surface; a held org-wide row's **"Scope…"** opens it *pre-seeded* to that
  permission). Uniform shell — pick permissions → choose targets → review & grant — that **dispatches
  Step 2's target panel and Step 3's apply by `ScopeKind`**. **One mechanism per run** (picking a
  permission locks the checklist to its mechanism). A de-emphasized **org-wide** option falls back to
  `grant_single_permission` / `grant_managed_identity_permission`.

Per-mechanism apply (each does grant-before-strip, so a failure never strands the principal):

- **Exchange** — declare-only: `declare_app_permission` per permission (manifest only, no runtime
  grant) then `grant_exchange_mailbox_access(Some([…]))` /
  `grant_managed_identity_scoped_exchange_access` with `remove_unscoped=true`. Targets:
  `ManagedScopeGroupPanel` (mailbox group membership) or existing groups.
- **SharePoint** — `commands::sharepoint::convert_site_access_to_selected` (works for an app SP *and*
  an MI — caller passes the SP object id + app id): grant `Sites.Selected` (idempotent) → grant
  per-site access → **only if ≥1 site grant landed** strip the broad `Sites.*` grant
  (`should_remove_orgwide`). Targets: `SiteSelectionPanel` (site URLs + read/write). Graph has **no
  reverse `appId → sites` lookup**, so the site URL(s) are user-supplied.

Graph appRole id↔value resolution lives in `commands::graph_roles::graph_role_index` (shared by
exchange + sharepoint); SharePoint org-wide detection is name-based (`is_sharepoint_orgwide`, defined
once in `azapptoolkit-core::scoping`). **To teach the app a new mechanism**: add a `ScopeKind` variant
+ a target panel + a Step-3 apply arm — nothing else branches on the concrete mechanism.

**Discoverability**: the enterprise-app and managed-identity Permissions tabs render the shared
`OrgwideScopeCallout` (`web-rs/components/orgwide_scope_callout.rs`) above the held-permissions
table when the principal holds org-wide access — a scopable mail value whose verdict is not
`Scoped` (unresolved counts, never-under-report) or any broad `Sites.*`. It names the values and
its "Scope…" opens the wizard pre-seeded to the first one, same contract as a held row's "Scope…".
This is the front door for scoping a **foreign-tenant** enterprise app (no local app registration
⇒ no App Registrations surface, and the scoping sections only render further down the tab).

## Audit remediations (one-click "Fix")

Only for findings whose fix maps to a **safe, existing** mutation. Add a `RemediationKind` variant
in `azapptoolkit-core::audit` and populate a `RemediationAction` in `score_application` from the
same data the issue uses (so the button appears exactly when the finding does). Each kind maps 1:1
to a `commands/remediation.rs` handler that **re-resolves live state** before acting — the audit
snapshot is advisory, never the source of truth for what gets mutated (e.g. remove-expired
recomputes the expired set from a fresh `get_application` using the *same* whole-day rule the
scorer uses — `azapptoolkit_core::audit::is_expired`, the single definition shared by the scorer,
the one-click remediation, the per-app `remove_expired_passwords`, and the bulk sweep, so no
removal path can delete a credential the audit never flagged).

On success the command busts caches (`invalidate_app_lists`) — and, unlike most mutations, a
**partial** success still invalidates, because credentials were really removed. The audit view's
`result` signal is a snapshot; clear the item's `remediations` on success (button gone) and re-run
for fresh scores.

Two kinds vary the pattern:

- **`AddOwner`** (Rule 14 ownership gap) has **no dedicated handler** — the guided user-picker
  modal (`views/dialogs/add_owner.rs`) calls the existing `add_application_owner`, which already
  busts the detail + audit caches. Safe because it's purely additive. `build_remediations` takes
  the owner count (`app.owners.as_ref().map(Vec::len)` — the same data Rule 14 keys off); `None`
  (owners not fetched, incl. every SP-only row) attaches nothing.
- **`DisableSignIn`** (unused app) is attached by the **audit runner's sign-in post-pass**, not
  `score_application` — `unused` is a post-pass flag (the sign-in report is fetched after scoring),
  and it's skipped when the SP is already disabled. Safe because it's reversible: the handler
  (`remediate_disable_sign_in`) re-resolves the SP from the live application and sets
  `accountEnabled: false`; the enterprise app's Overview toggle re-enables. SP-only unused rows
  don't get it (their Open lands on the enterprise/MI detail, which has the toggle).

## Redundant application permissions (Rule 18)

`subsuming_app_permissions` in `azapptoolkit-core::audit` is the table of "broader permission
fully covers narrower one" relationships (transitive closure flattened, e.g. `Sites.Read.All` →
all three broader `Sites.*` tiers). Rule 18 flags a held narrower permission whose broader sibling
is also held — advisory, **no score** (the broader permission already carries the risk weight).
Constraints baked into the table; keep them when extending it:

- **Application permissions only.** Graph authorizes app-only calls by the union of `roles` in the
  token (a client-credentials token always carries every granted role), so a covered narrower role
  is pure surface area and removing it can never break a call. Delegated scopes are matched
  *literally* in token requests — removing a narrower consented scope can break an app that
  requests it by name — so delegated redundancy is deliberately not flagged.
- **Only documented full-coverage pairs.** `Mail.Send` is not covered by `Mail.ReadWrite`;
  `Directory.ReadWrite.All` does not cover `User.ReadWrite.All`/`Group.ReadWrite.All` (no user
  delete / password reset).
- **`Sites.Selected` is never the narrower value** — it's the least-privilege model Rule 12 pushes
  *toward*; calling it redundant would invert that guidance.
- **A scoped broader doesn't cover.** `score_application` vetoes a broader mail permission whose
  `mail_scopes` verdict is `Scoped` — confined `Mail.ReadWrite` no longer reaches everything an
  org-wide `Mail.Read` does, so the pair isn't redundant.

The one-click fix (`RemediationKind::RemoveRedundantPermissions` →
`commands::remediation::remediate_remove_redundant_permissions`) re-plans from a fresh manifest +
live `appRoleAssignments` (`plan_redundant_removals`, pure + unit-tested), with two rules
**stricter than the scorer** (which flattens values across resources):

- The covering broader permission must be declared on the **same resource** (Graph's
  `Mail.ReadWrite` doesn't cover Exchange Online's `Mail.Read` appRole of the same name).
- A **granted** narrower permission is removed only while a covering broader **grant** is live;
  if the broader grant has since been revoked or scoped away (Exchange RBAC strips the org-wide
  Entra grant), the value is reported `skipped`, never removed. An ungranted declaration is
  removable whenever the broader is declared — declarations authorize nothing.

Per removal: revoke the narrower `appRoleAssignment` (when granted), then drop all affected
declarations in **one** trailing `requiredResourceAccess` patch. A revocation error stops further
revocations but already-revoked grants still get their declarations patched out (a revoked grant
with a lingering declaration is the inconsistent state to avoid), and caches are busted on any
partial success — the same exception remove-expired-credentials makes.

## Least-privilege downgrades (the inverse direction)

`downgrade_alternatives` is the **inverse scan of the same coverage table** (broader → narrowers,
ordered closest-tier-first by subsumer count), so Rule 18 and the downgrade suggestions can never
disagree about what covers what. It drives three surfaces:

- the permission picker's grant-time "Narrower alternative: …" note (closest tier only);
- an audit *recommendation* (never an issue, never a score) naming concrete swaps for
  risk-flagged application permissions, capped at three alternatives;
- the Permissions tab's per-row **"Downgrade…"** action →
  `commands::permissions::downgrade_application_permission`.

**A downgrade is NOT safe by construction** — the narrower permission only suffices if the app
genuinely never uses the broader capability — so it is *never* offered as a one-click audit
remediation; every surface presents it as an admin-judged choice. The command re-validates the
pair against the table, then swaps non-strandingly: grant the narrower `appRoleAssignment`
**before** revoking the broad one (grant-before-strip, matching the Exchange/SharePoint scoping
cores), then swap the declaration in one `requiredResourceAccess` patch (`swap_declared_role`,
pure — note `remove_declared_access` prunes an emptied resource entry, so a broad-only resource is
recreated to carry the narrow role). Idempotent: a broad permission already gone is a no-op
success with every `DowngradeOutcome` flag `false`.

## Structured audit signals over issue-text parsing

The audit view's facets/cards key off structured `AuditItem` fields (`risk_level`,
`credential_status`, `unused`, `last_sign_in`, `sign_in_report_available`) rather than
`starts_with(...)` on free-text issues — `score_one` populates the sign-in fields after
`score_application` (which stays sign-in-agnostic, defaulting them). When adding a new facet/card,
prefer a structured flag on `AuditItem` over matching an advisory string.

## SP-only principals in the audit (no local application)

The audit run has **two phases**. Phase 1 scores every `/applications` entry
(`score_application`). Phase 2 scores service principals with **no local application object** —
foreign-tenant (OIDC/multi-tenant) enterprise apps, managed identities, orphaned SPs — via
`score_service_principal`, from their *granted* state instead of a manifest.

- **Candidates** (`sp_audit_candidates`, pure + unit-tested): shared `{tenant}|sp_index` rows whose
  `appId` joins to no scanned application AND that hold ≥1 **Microsoft Graph** application grant in
  the tenant-wide `appRoleAssignedTo` matrix. The grant requirement is the noise filter (grantless
  first-party Microsoft SPs vanish); disabled SPs stay in (Rule 4). Known limitation: roles held
  only on non-Graph resources (e.g. legacy Office 365 Exchange Online `full_access_as_app`) aren't
  in the matrix, so such an SP isn't scored.
- **Zero extra per-item Graph traffic.** Phase 2 reuses the run's tenant-wide reads — the Graph
  `appRoleAssignedTo` matrix (now fetched regardless of Exchange availability; its mail-scopable
  subset still feeds `score_one`'s reconciliation) and the `oauth2PermissionGrants` read (which now
  also keeps AllPrincipals scope strings per client for Rule 13). Scoring is pure CPU — a plain
  sequential loop, no `dispatch_capped` fan-out.
- **Applicable rules only**: permission risk (1 & 2), admin consent (3), disabled SP (4),
  mailbox/SharePoint advisories (11, 12), high-risk delegated (13), plus the sign-in post-pass.
  Credential rules (5–9) and manifest rules (10, 14–18, downgrades) are deliberately absent —
  those objects live in the app's home tenant. `mail_scopes` stays **empty on purpose**: a held
  mail value here IS an un-stripped org-wide Entra grant, so the reconciliation would force
  `OrgWide` regardless of any RBAC probe — empty scores identically without the 1–5s Exchange
  probe per SP. (A properly scoped principal no longer holds the grant and drops out of the
  candidate set; its RBAC-only access is not surfaced — under-reporting an advisory, never risk.)
- **Wire shape**: one additive field, `AuditItem.principal_kind`
  (`application` | `service_principal` | `managed_identity`, `#[serde(default)]` so pre-field
  cached runs deserialize as `Application`). For SP rows `object_id` is the **SP object id**.
- **Frontend routing keys off `principal_kind`** (structured-signals rule): the `no_local_app`
  finding chip; Open → enterprise / MI detail (`open_enterprise_on_tab` /
  `open_managed_identity_on_tab`); scope Fixes carry a `ScopeFixTarget` — `AppReg` rows call the
  `remediation::remediate_scope_*` wrappers (which `get_application` first), SP rows call the
  SP-only cores (`grant_managed_identity_scoped_exchange_access` /
  `convert_site_access_to_selected`) that a foreign principal needs. **SP rows are non-selectable**
  — the bulk commands loop app-registration cores and would 404 on an SP object id.
- **Invalidation**: the SP-only scoping/revoke paths already bust the audit transitively
  (`invalidate_app_lists` / `invalidate_app_detail_state`); `grant_managed_identity_permission`
  busts it explicitly (its old "audit scans only app registrations" rationale died with this).

## Resource Access — the resource → identities reverse lookups

The Resource Access page (`ActiveView::ResourceAccess`) answers the inverted question the
Permission tester can't: not "can this app reach that resource?" but "**who** can reach this
resource?". One tab per resource plane; both long-running operations poll the shared
`AppState.sweep_cancel` atomic — NOT `audit_cancel` — so the page's Cancel can never abort a
concurrent audit/bulk run (and vice versa); `cancel_resource_sweep` flips it. All four long-running
fan-out loops (audit, site sweep, mailbox probe, bulk credential sweep) ride
`commands::dispatch::dispatch_capped`, which delivers **every** completed task to the collector and
returns an early-stop latch — callers report cancellation from that latch rather than re-reading a
shared cancel flag a concurrent command may have reset.

**Sites tab (`sweep_site_permissions`).** Graph offers no `appId → sites` lookup, so the per-site
grants behind `Sites.Selected` are invisible from the app side. The sweep builds the index the
other way: `GraphClient::list_all_sites` enumerates the tenant's sites via `GET /sites?search=*`
(team/communication sites — the delegated search endpoint does not return personal OneDrive sites,
and `/sites/getAllSites` is application-permission-only, out of reach by design), then reads each
site's `/sites/{id}/permissions` with bounded concurrency (6) on the SharePoint scope. One
searchable table answers both directions: filter by app → its granted sites; filter by site → the
apps that can touch it. Invariants:

- **Coverage is never overstated.** The per-site read rides the client's retrying transport, so a
  transient 429 is absorbed with `Retry-After` honored; a *persistently* failing site increments
  `sites_failed` (surfaced as "scanned X of Y (Z failed — coverage is partial)") instead of
  silently reading as "no grants". A cancelled **or partially-failed** run is returned but
  **never cached** — the promise extends to the cache. `list_site_permissions` follows `nextLink`,
  so a site whose grant list spans pages is fully counted. Progress streams as
  `site-sweep-progress` events; the run ends with one `site sweep complete` summary log line.
- **Org-wide holders don't appear.** Only `Sites.Selected`-model grants create per-site rows; an
  app holding org-wide `Sites.*` reaches every site without appearing here — the view says so and
  points at the audit (Rule 12), which owns that finding.
- The completed result is cached under the tenant-prefixed `{tenant}|site_sweep` key
  (`CacheKind::Audit`, 60-minute TTL) so revisiting the view rehydrates without re-scanning.

**Mailboxes tab (`find_mailbox_reachers`).** Candidates come from two sources, merged by SP
object id: ONE paged Graph call — `appRoleAssignedTo` on the Microsoft Graph resource SP is the
whole tenant's principal → Graph-app-role matrix — filtered to service principals holding a
mail-scopable application permission; **plus the Exchange SP store** (`Get-ServicePrincipal`),
the only place a principal granted access *solely* through Exchange RBAC (no Entra grant) is
visible — those enter with empty `held_permissions` and their verdict can only come from the RBAC
layer. Each candidate is then evaluated with the **same two-layer union the Permission tester
uses** (see below; the AAP list is fetched once for the whole run; concurrency 4; progress
streams as `mailbox-probe-progress`). Degradation follows the audit's never-under-report posture:
when Exchange is unavailable, a candidate's held org-wide Graph mail grant reaches every mailbox
via Graph anyway — the row reads `org_wide` with the legacy-AAP caveat, never a silent "no
access" (the Exchange-only candidate source is necessarily absent then; the
`exchange_available = false` summary flags the partial coverage). Results are mailbox-specific
and not cached.

## Permission tester (`commands::permission_tester`)

A standalone Tools page (`ActiveView::PermissionTester`) that answers "identity → resource":
whether a chosen principal actually reaches a specific Exchange mailbox (`test_mailbox_access`) or
SharePoint site (`test_site_access`, unioning an org-wide `Sites.*` app-role grant with the site's
per-app permission list).

**The mailbox verdict is a two-layer union** — mirroring how Exchange actually authorizes an
app-only call (per Microsoft's RBAC-for-Applications guidance, the two authorities union; neither
restricts the other):

1. **Entra layer** (`EntraReach`) — the SP's org-wide Graph mail app-role grants
   (`orgwide_mailbox_grant`) reach every mailbox, constrained **only** by a legacy Application
   Access Policy, evaluated live via `ExchangeClient::test_application_access_policy`
   (`Test-ApplicationAccessPolicy`; the call is made only when a policy actually names the app). A
   `RestrictAccess` grant reads `scoped`; an unreadable AAP gate degrades to org-wide *with a
   caveat* (never under-reported).
2. **Exchange RBAC layer** (`RbacReach`) — `Test-ServicePrincipalAuthorization -Resource`,
   **honoring the per-row `InScope` flag**: the cmdlet returns one row per role assignment whether
   or not the mailbox is covered, so a row with `InScope = false` means "permission held but NOT
   over this mailbox" — it must never read as access. A missing-object error means the principal
   isn't in Exchange's SP store (the managed-identity case) ⇒ definitively no RBAC layer; other
   failures leave the layer indeterminate (verdict `unknown` only if the Entra layer grants
   nothing).

`synthesize` folds the layers (org-wide > scoped > unknown > no-access) and the detail names which
layer decided — including the headline finding "scoped RBAC + un-stripped org-wide Entra grant ⇒
the scope is ineffective, remove the Entra permission" (the same union `reconcile_orgwide_grant`
catches in the Scope-column resolver).

Both commands are keyed on the principal's **appId** and resolve the SP via
`get_service_principal_by_app_id`, so they work for **any** service-principal type — the picker
reuses `global_search` to span app registrations, enterprise apps, and managed identities (deduped
by appId, tagged with `TypeChip`). It exercises the same live primitives the grant/scope flows use
— no new caches, scopes, or CSP origins — and **degrades gracefully** when the signed-in user
lacks Exchange-admin rights: the Entra layer answers alone (with the AAP caveat) before falling
back to an `unknown` verdict (never a hard error); SharePoint reuses the `sharepoint` consent
flow.
