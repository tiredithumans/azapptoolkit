# Resource Access & the permission tester

Deep-dive companion to the resource-lookup gotchas in [AGENTS.md](../../AGENTS.md). Read this before
editing `commands::sharepoint::sweep_site_permissions`, `commands::exchange::find_mailbox_reachers`,
`commands::permission_tester`, or the Resource Access / Permission tester views. The scoping
mechanisms these tools observe are in [exchange-scoping.md](./exchange-scoping.md) and
[sharepoint-selected.md](./sharepoint-selected.md).

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
  every enumerable site was actually read.
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
