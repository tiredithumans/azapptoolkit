# Resource Access & the permission tester

Deep-dive companion to the resource-lookup gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `commands::sharepoint::sweep_site_permissions`, `commands::keyvault_rbac::sweep_key_vault_access`,
`commands::permission_tester` (incl. `find_mailbox_reachers`), or the Resource Access / Permission
tester views. The scoping
mechanisms these tools observe are in [exchange-scoping.md](./exchange-scoping.md) and
[sharepoint-selected.md](./sharepoint-selected.md).

## Resource Access — the resource → identities reverse lookups

The Resource Access page (`ActiveView::ResourceAccess`) answers the inverted question the
Permission tester can't: not "can this app reach that resource?" but "**who** can reach this
resource?". One tab per resource plane. The panels stay mounted across tab switches and can run at
the same time, so each long-running operation has its own cancel flag and command: the site sweep
`site_sweep_cancel` / `cancel_site_sweep` (shared by the Sites tab and the per-app site panel — same
sweep), the Key Vault sweep `key_vault_sweep_cancel` / `cancel_key_vault_sweep`, and the mailbox
probe `mailbox_probe_cancel` / `cancel_mailbox_probe`. One panel's Cancel never aborts another
panel's scan, nor an audit/bulk run (and vice versa). Every long-running fan-out — the audit, the
site sweep, the mailbox probe, the vault sweep, the `bulk.rs` app-list fan-outs and the DR backup —
rides `commands::dispatch::dispatch_capped` (`repo_invariants/fanout.rs` finds the call sites
itself; this list is illustrative), which delivers **every** completed task to the collector and
returns an early-stop latch — callers report cancellation from that latch rather than re-reading the
token afterwards.

**Sites tab (`sweep_site_permissions`).** Graph offers no `appId → sites` lookup, so the per-site
grants behind `Sites.Selected` are invisible from the app side. The sweep builds the index the
other way: `GraphClient::list_all_sites` enumerates the tenant's sites via `GET /sites?search=*`
(team/communication sites — the delegated search endpoint does not return personal OneDrive sites,
and `/sites/getAllSites` is application-permission-only, out of reach by design), then reads each
site's `/sites/{id}/permissions` on the SharePoint scope — in `$batch` chunks of `SWEEP_BATCH` sites
under an adaptive cap of `SWEEP_CONCURRENCY` chunk tasks (`ConcurrencyThrottle`, halved on 429s).
One searchable table answers both directions: filter by app → its granted sites; filter by site →
the apps that can touch it. Invariants:

- **Coverage is never overstated.** The per-site read rides the client's retrying transport, so a
  transient 429 is absorbed with `Retry-After` honored; a *persistently* failing site increments
  `sites_failed` (surfaced as "scanned X of Y (Z failed — coverage is partial)") instead of
  silently reading as "no grants". A cancelled **or partially-failed** run is returned but
  **never cached** — the promise extends to the cache. Site enumeration is capped at
  `MAX_SITES_PER_SWEEP` (5000); hitting it sets `SiteSweepResult::truncated` (the graph client's
  `list_all_sites` returns `(sites, truncated)` like every other capped walk), which
  `AppSiteAccessDto::is_complete()` folds and both surfaces render as a cap caveat — in the summary
  line, hence in the CSV/JSON coverage line, and as a callout. A capped run **is** cached, *with*
  the flag (the cap is deterministic, so re-sweeping 5000 sites buys the same prefix), and is
  therefore never served as complete; `sweep_is_cacheable` + its table test pin the split.
  `list_site_permissions` follows `nextLink`, so a site whose grant list spans pages is fully
  counted. Progress streams as `site-sweep-progress` events (one per chunk); the run ends with
  one `site sweep complete` summary log line.
- **Org-wide holders don't appear.** Only `Sites.Selected`-model grants create per-site rows; an
  app holding org-wide `Sites.*` reaches every site without appearing here — the view says so and
  points at the audit (Rule 12), which owns that finding.
- **The index has a second consumer: the per-app panel.** `components::app_site_access_panel`
  ("Sites this app can reach", on the app-reg + enterprise Permissions tabs and the MI pane) answers
  the `Sites.Selected` blind spot *per principal*, so an operator never has to know a site URL to see
  what an app reaches. `get_app_site_access` projects one app's rows out of the **cached** sweep
  backend-side — a tenant sweep holds up to 5000 sites' grants, and shipping all of them so one
  collapsible panel could keep a handful would put a multi-MB payload on every Permissions tab. When
  nothing is cached the panel runs the same sweep and projects the result **client-side**, because a
  partial or cancelled sweep is deliberately never cached and re-reading would discard it. Both paths
  call the one pure `AppSiteAccessDto::from_sweep`, so they cannot disagree about what "this app's
  sites" means, and `is_complete()` gates the empty state: "no per-site grants" is only claimed when
  every enumerable site was actually read **and** the enumeration was not capped. The cap sentence
  itself has one home, `app_site_access_panel::site_sweep_cap_message`, shared with the Sites tab.
- The completed result is cached under the tenant-prefixed `{tenant}|site_sweep` key
  (`CacheKind::Audit`, 60-minute TTL) so revisiting the view rehydrates without re-scanning.

**Vault access tab (`sweep_key_vault_access`).** ARM-plane, answering "who can touch this vault?"
(and, filtered by principal, "which vaults can this identity reach?"). The command proves the
session (`prove_tenant_session`), claims `key_vault_sweep_cancel` before the first await, and
pre-acquires the ARM token via `ensure_arm_token`, so the UI can offer the `arm` consent. It lists
the subscriptions (a failure there is fatal), then `list_key_vaults` per subscription at
`ARM_CONCURRENCY` (8), and reads each vault's `atScope()` role assignments through
`dispatch_capped` — direct **and** inherited (resource group / subscription / management group).
Rows carry `inherited` (the "Inherited" badge; `is_inherited` compares the assignment scope to the
vault id case-insensitively); role-definition ids resolve to names through
`arm_roles::resolve_role_names_cached` — one fetch per role GUID (via the first absolute id ARM
returned for it, never the tenant-level path, which 404s for custom roles), cached under
`CacheKind::Permissions` as `{tenant}|arm_roledef|{guid}` and shared with the managed-identity
Azure-roles view — and principal ids to display names. Rows are flagged `high_privilege` by
`azure_roles::is_high_privilege_role(_, RoleContext::KeyVault)`. Progress streams as
`keyvault-sweep-progress`.

- **Coverage, the same rule as the site sweep.** A per-vault read failure increments
  `vaults_failed` — never read as "no access" — and the panel renders "scanned X of Y (Z failed —
  coverage is partial)". The CSV/JSON export (`save_key_vault_access_to_file`) leads with that
  coverage line, because a failed vault contributes no rows.
- Only a run that was not cancelled **and** has `vaults_failed == 0` is cached, under
  `{tenant}|keyvault_sweep` (`CacheKind::Audit`, audit TTL); `get_cached_key_vault_access`
  rehydrates it and proves the session first. Invalidation (an in-app Azure role assignment busts
  it on `Ok`) is in [caching-and-search.md](./caching-and-search.md).
- **Known gaps** (the coverage line does not yet say so): a subscription whose vault enumeration
  fails is logged and skipped, not counted in `vaults_failed`; and enumeration is silently capped
  at `MAX_VAULTS_PER_SWEEP` (2000) — `KeyVaultSweepResult` has no `truncated` flag, unlike the site
  sweep's.

**Mailboxes tab (`find_mailbox_reachers`).** Candidates come from two sources, merged by SP
object id: the paged `appRoleAssignedTo` on **both** mailbox-bearing resource SPs
(`mailbox_resource_roles`: Microsoft Graph, plus Office 365 Exchange Online when the tenant has it,
so an app whose only grant is the EWS `full_access_as_app` scope appears — as org-wide) — together
the whole tenant's principal → mailbox-app-role matrix — filtered by the pure `mailbox_candidates`
to service principals holding a mail-scopable application permission, each grant resolved against
its own resource and gated with the resource-carrying `is_scopable_exchange_resource_permission`
(the retired Outlook REST `Mail.*` roles on Exchange Online do not count); **plus the Exchange SP
store** (`Get-ServicePrincipal`),
the only place a principal granted access *solely* through Exchange RBAC (no Entra grant) is
visible — those enter with empty `held_permissions` and their verdict can only come from the RBAC
layer. Each candidate is then evaluated with the **same two-layer union the Permission tester
uses** (see below; the AAP list is fetched once for the whole run; concurrency 4; progress
streams as `mailbox-probe-progress`). Degradation follows the audit's never-under-report posture:
when Exchange is unavailable, a candidate's held org-wide Graph mail grant reaches every mailbox
via Graph anyway — the row reads `org_wide` with the legacy-AAP caveat, never a silent "no
access" (the Exchange-only candidate source is necessarily absent then; the
`exchange_available = false` summary flags the partial coverage). `exchange_available` follows a
**pre-acquired Exchange.Manage token** (`ensure_exchange_token`), not just a buildable client — a
missing consent or admin right used to leave it `true`. When Exchange answered but its SP store
couldn't be listed, `exchange_sp_store_read = false` says the RBAC-only principals are missing.
Both caveats are appended to the panel's summary sentence, which the CSV/JSON export ships
verbatim. Results are mailbox-specific and not cached.

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
   caveat* (never under-reported). `orgwide_mailbox_grant` returns `Result`: an app with **no
   service principal** holds nothing (`NotHeld`), but a failed SP lookup, role index or
   assignment read is `EntraReach::Unreadable`, scored `unknown` — never `NotHeld`, which would
   let a transient Graph failure answer a definite "No access" with a sentence claiming no grant
   exists.
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

**The SharePoint verdict is the pure `site_verdict(held, hit, label)`** — `held` is `None` when
`sharepoint_grants_held` failed to read the app's assignments (an absent SP is `Some` of the empty
default), `hit` the nearest permission entry on the target or an ancestor:

| held | entry | verdict |
|---|---|---|
| org-wide `Sites.*` | any | `org_wide` (the chain walk is skipped) |
| unreadable | none | `unknown` — never the "holds no organization-wide grant" sentence |
| readable (or no SP) | none | `no_access` |
| unreadable | found | `unknown` |
| Selected scope reaching the entry's level | found | `scoped` |
| no such scope | found | `no_access`, naming the scope to grant (`required_scope_for`) |

A re-auth-fatal read error on either tester returns the error (the dead-session re-auth path)
instead of an `unknown` verdict.

Both commands are keyed on the principal's **appId** and resolve the SP via
`get_service_principal_by_app_id`, so they work for **any** service-principal type — the picker
reuses `global_search` to span app registrations, enterprise apps, and managed identities (deduped
by appId, tagged with `TypeChip`). It exercises the same live primitives the grant/scope flows use
— no new caches, scopes, or CSP origins — and **degrades gracefully** when the signed-in user
lacks Exchange-admin rights: the Entra layer answers alone (with the AAP caveat) before falling
back to an `unknown` verdict (never a hard error); SharePoint reuses the `sharepoint` consent
flow.
