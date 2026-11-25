# Design — Project B: safeguards you can apply

## Context
Project A (merged as #428/#429) made Microsoft Graph permissions with no built-in scoping visible:
- audit Rule 24;
- `AuditItem::unscopable_grants`, each with a Conditional Access `NetworkLock` verdict;
- the "No built-in scoping" Security-tab group and its checklist;
- the permission-row badge.

Project B lets the operator act on what A shows. It is three independent parts, each its own PR, in this order:
- **B1. Usage per permission.** Whether each unscopable grant is actually used, from Microsoft Graph
  activity logs.
- **B2. Network lock.** Create, enable and remove a per-app Conditional Access policy that blocks
  the app's sign-ins outside trusted locations.
- **B3. Expiring grants.** Put an expiry date on a grant, and flag and revoke it once the date
  passes.

Project-wide context (spec of A, still binding): `docs/superpowers/specs/2026-11-25-no-builtin-scoping-visibility-design.md`.
Projects C (more Microsoft-enforced scoping) and D (broker) follow, separately designed.

## Decisions made with the user
| Decision | Choice |
|---|---|
| Scope | All three parts. The lock is built even where the tenant lacks the licence; the toolkit detects that and says so |
| Lock layout | One Conditional Access policy per locked app |
| Usage check | During the audit run: one Graph-activity-log query per run, not on demand |

Calls I proposed that the user didn't object to:
- Order B1 → B2 → B3.
- The lock is created report-only, and "Turn on" is a separate confirmed step.
- Expiry is stored as a tag on the service principal and enforced by an audit finding plus a one-click
  Revoke. There is no background job and no automatic revoke.

## Goals
1. Every unscopable grant shows when a call it could authorize was last seen, and a grant with no such
   call in the log window is called out.
2. An operator can lock an in-house app's sign-ins to trusted locations from the toolkit, safely:
   report-only first, verifiable, reversible.
3. An operator can grant (or mark) a permission with an expiry, and the audit surfaces, and revokes on
   request, any grant past its date.

## Non-goals
- Automatic revocation or any background or scheduled job. The app runs nothing unattended, and an
  Azure-side job would itself need a tier-0 grant.
- Locks for vendor or multi-tenant apps, managed identities, or service principals without a local
  app registration: Microsoft's Conditional Access for workload identities can't target them.
- Bulk lock or bulk expiry.
- Usage mapping for directory permissions (`Directory.*`, `User.*`, `RoleManagement.*`, …): their
  request paths overlap so broadly that "last used" would be noise.

## Anti-goals
- A lock that is created enforced, or that is shown as ✓ while report-only.
- Deleting or changing a Conditional Access policy the toolkit didn't create, or one that no longer
  has the exact lock shape for this service principal.
- Revoking a grant whose expiry was removed or moved since the audit ran.
- Copy implying a "seen" call proves this permission was the one used. Only "not seen" is sound
  evidence.
- A trusted location of `0.0.0.0/0` or `::/0`, which makes the lock meaningless.

## Approaches considered
- **Lock layout.**
  - Per-app policy (chosen): independent locations and switch-on per app, undo by deleting one policy,
    one of the tenant's 195 policy slots per app.
  - Rejected: one shared policy, where switching on affects every app at once and every app shares
    one set of locations.
- **Usage.**
  - Tenant-wide query in the audit (chosen): finds unused grants across the tenant.
  - Rejected: an on-demand per-app query, which can't find them.
- **Expiry storage.**
  - Service-principal tag (chosen): tenant-visible, shared by every operator, works for vendor SPs,
    and reuses the `azapptoolkit:spItem:` tag pattern.
  - Rejected: local `settings.json`, which isn't shared.
  - Rejected: application tags, which vendor apps don't have.

## Design

### B1. Usage per permission
- **Core table** (`crates/azapptoolkit-core/src/audit/usage.rs`, pure): `USAGE_FAMILIES`, a list of
  `(family_key, permission values, path regex)` for the communications permissions only:
  - `call_records`: `CallRecords.Read.All`, `CallRecord-PstnCalls.Read.All` → `/communications/callrecords`
  - `online_meetings`: `OnlineMeetings.*` → `/(users/[^/]+|me|communications)/onlinemeetings`
  - `meeting_transcripts`: `OnlineMeetingTranscript.Read.All` → `…/transcripts|gettalltranscripts`
  - `meeting_recordings`: `OnlineMeetingRecording.Read.All` → `…/recordings|getallrecordings`
  - `meeting_artifacts`: `OnlineMeetingArtifact.Read.All` → `…/attendancereports`
  - `channel_messages`: `ChannelMessage.Read.All` → `/teams/[^/]+/channels/[^/]+/messages|/teams/getallmessages`
  - `chats`: `Chat.Read.All`, `Chat.ReadWrite.All` → `/chats|/users/[^/]+/chats`
  - `calls`: `Calls.AccessMedia.All` → `/communications/calls`

  Paths are matched lower-cased with the `/v1.0` or `/beta` prefix stripped. The builder confirms each
  path against the Graph reference.
  - `fn families_for(value) -> &[&str]`.
  - `fn usage_kql() -> String`, built only from the static table, with no user input in the query.
  - A grant whose value has no family is `NotTracked`.
- **KQL** (one query, 90 days), roughly:
  `MicrosoftGraphActivityLogs | where TimeGenerated > ago(90d) | extend P = <normalized lower path> | extend Family = case(...) | where Family != "" | summarize LastSeen = max(TimeGenerated) by AppId, Family`.
  A second tiny query, `summarize Since = min(TimeGenerated)`, gives the real window, because workspace
  retention can be shorter than 90 days.
- **Prefetch** `prefetch_graph_usage` in `commands/audit/prefetch.rs`. It reuses `commands::usage`:
  - `discover_workspace` (made `pub(crate)`; already cached per tenant for 60 minutes, including "no
    workspace");
  - `ensure_log_analytics_token`;
  - `LogAnalyticsClient::query`.

  Its outcome follows `sign_in_activity_outcome`:
  - **Unavailable** (no consent, no workspace, a non-retryable error): every usage is `Unknown`, and
    there is no gap.
  - **Transient failure**: a new `AuditCoverageGap::GraphActivity`.
- **Wire.** `UnscopableGrant` gains `#[serde(default)] last_used: GrantUsage`, an internally tagged
  enum:
  - `Seen { at }`
  - `NotSeen { since }`
  - `NotTracked`
  - `#[default] Unknown`

  It is filled by the runner's post-pass next to `apply_network_locks`, keyed by appId and family; the
  latest `LastSeen` across a permission's families wins.
- **Checklist line.**
  - Seen: "· Last call it could authorize: 3 days ago".
  - NotSeen: "✗ No call it could authorize since <since> — consider removing it".
  - NotTracked: "· Usage not tracked for this permission".
  - Unknown: "· Usage unknown — needs Microsoft Graph activity logs in a Log Analytics workspace you
    can read".
- No Fix: removal stays admin-judged on the Permissions tab.
- Capability: the existing `graph_activity_usage`.

### B2. Network lock
- **Graph client** (`azapptoolkit-graph`): every id spliced into a path is shape-checked, and every
  call uses the shared retry and body caps.
  - `list_named_locations()`
  - `create_ip_named_location(display_name, cidrs)`, trusted
  - `create_ca_policy(&body)`
  - `get_ca_policy(id)`
  - `set_ca_policy_state(id, state)`
  - `delete_ca_policy(id)`
- **Auth.**
  - A new `ConsentFeature::ConditionalAccessWrite`, with scopes `Policy.Read.All` +
    `Policy.ReadWrite.ConditionalAccess` (delegated, consented on demand).
  - A new capability `conditional_access_lock`, for Conditional Access Administrator or Security
    Administrator.
- **Policy body.**
  - `state: "enabledForReportingButNotEnforced"`
  - `displayName: "azapptoolkit network lock — <app display name>"`
  - `conditions.applications.includeApplications: ["All"]`
  - `conditions.clientApplications.includeServicePrincipals: [<sp id>]`
  - `conditions.locations: { includeLocations: ["All"], excludeLocations: [<chosen named location ids>] }`
  - `grantControls: { operator: "OR", builtInControls: ["block"] }`

  `network_lock_for` on exactly this body must answer `ReportOnly`/`Enforced`. That is a test.
- **Commands** (all `#[tauri::command] async fn … -> Result<_, UiError>`, `prove_tenant_session`,
  invalidate the audit run with `invalidate_app_detail_state` on `Ok`):
  - `list_named_locations(tenant_id)` returns id, name, kind (ip or country), trusted, and range count.
  - `create_network_lock(tenant_id, app_id, named_location_ids, new_location: Option<{ name, cidrs }>)`
    re-resolves everything live:
    - the SP is resolved by appId;
    - the principal must be eligible (`lock_ineligibility_for_app` is `None`; `NotPossible` refuses);
    - no existing lock for this SP (refuse `lock_exists`);
    - at least one excluded location.

    CIDRs are validated (parsed IPv4/IPv6; `/0` refused). It creates the named location first if
    asked, then the report-only policy, and returns the policy id. If the policy create fails after
    the location was created, the location stays and is reported; it is harmless and reusable.
  - `enable_network_lock(tenant_id, app_id, policy_id)` re-reads the policy. It must be the lock shape
    for this app's SP, report-only, and named with the toolkit prefix. Otherwise it refuses
    (`not_a_toolkit_lock`). Then it PATCHes `state: "enabled"`.
  - `remove_network_lock(tenant_id, app_id, policy_id)` runs the same verification, then DELETEs.
  - **Licence:** a create or patch refused for a missing Workload Identities Premium licence maps to
    `workload_identity_license_required`, with a plain message. The builder finds Graph's exact error
    code or body and pins it in a test.
- **Wire.** `NetworkLock::ReportOnly` becomes `ReportOnly { policy_ids }`, so the UI can name the
  policy to switch on. This is unreleased, so the change is allowed.
- **UI: on the app registration's Conditional Access tab**, which already reads policies live. The
  audit's advisory group keeps offering no row Fix. A "Network lock" section heads the tab:
  - **None** (eligible): explains the lock. "Lock to trusted locations…" opens a `ModalShell` where
    you pick trusted named locations and/or paste CIDRs plus a name for a new one. It states that the
    lock is created report-only.
  - **ReportOnly**: "Turn on lock". The confirm names the app: "Sign-ins by <app> from outside these
    locations will be blocked". There is also "Remove".
  - **Enforced**: "Remove lock", with a confirm naming the app.
  - **NotPossible / MayApply / Unknown**: an explanation, and no button.

  Confirmation tier: click-confirm naming the object, because the action is narrow and reversible.
  - The audit checklist's lock line links to this tab: "Set up on the Conditional Access tab".
- Docs: the deep-dive and rules file gain the lock invariants (create report-only, verify-before-write,
  shape check).

### B3. Expiring grants
- **Tag** on the service principal: `azapptoolkit:grantExpiry:v1|<resourceAppId>|<appRoleId>|<YYYY-MM-DD>`
  (at most 256 chars).
  - Parsed as untrusted input: GUID shapes and a valid date, else ignored with a warn.
  - Written full-collection under a per-SP `single_flight`, mirroring
    `commands::sharepoint_item_scopes::remember/forget`.
  - A date means the end of that day, UTC.
- **SP index** selects `tags` (`SP_INDEX_SELECT` + `sp_index_row`), so the audit reads every
  principal's expiries with no extra call.
  - A tag write patches the cached index row (a new idempotent patch helper beside
    `record_renamed_app`) instead of dropping the list tier.
  - The builder confirms the cache rules (`repo_invariants/cache.rs`) accept it.
- **Commands.**
  - `set_grant_expiry(tenant_id, sp_object_id, resource_app_id, app_role_id, expires_on: Option<String>)`
    writes the tag; `None` clears it. It checks the SP holds that assignment.
  - `revoke_expired_grants(tenant_id, sp_object_id)` re-reads the SP's tags and `appRoleAssignments`
    live. It removes only assignments whose tag is still past its date, then clears those tags.
    It returns what it revoked and what it skipped.
- **Grant time.** In the Grant access wizard's org-wide path, an "Expires" `Select` (never / 7 / 30 /
  90 days). After each grant lands, it calls `set_grant_expiry`. A failed tag write is a warning on the
  result, not a failed grant.
- **Existing grants.** An "Expiry…" action on granted application-permission rows of the Permissions
  tab (both the app-registration tab and the held-permissions panel).
- **Audit Rule 25** (advisory, no score) runs on app and SP-only rows: a held grant whose expiry date
  has passed. It adds:
  - an `issue::GRANT_EXPIRED` line, "Grants past their expiry: CallRecords.Read.All (expired 2026-11-01)";
  - `RemediationKind::RevokeExpiredGrants` (Fix: `revoke_expired_grants`, confirm naming app and
    permissions);
  - a new finding group, "Grants past their expiry" (Actionable), which owns the kind.

  SP-only rows get the Fix too, because it acts on the SP and never on `remediate_scope_*`.
- `UnscopableGrant` gains `#[serde(default)] expires_on: Option<jiff::civil::Date>` for the checklist
  line ("· Expires 2026-12-24" / "✗ Expired 2026-11-01").

## Left to the builder
- Exact path regexes (confirmed against Graph docs) and the KQL text.
- The licence error's exact Graph shape.
- Patch-helper naming.
- Modal layout and copy, within the anti-goals.
- Whether `create_network_lock` takes the app's display name from live state or the request (live
  preferred).

## Delivery
Three PRs, each with its own CHANGELOG line, deep-dive and rules updates, and tests:
`feat/usage-per-permission` → `feat/network-lock` → `feat/expiring-grants`, each branched off `main`
after the previous one merges.

## Verification
- **B1:**
  - Table tests (each family's regex hits and misses sample paths; `/v1.0`, `/beta` and case handled).
  - KQL contains no interpolated input.
  - Outcome unavailable vs gap.
  - Post-pass mapping, including the latest of several families, `NotSeen` with `since`, and
    `NotTracked`.
- **B2:**
  - The body built by the command passes `network_lock_for` (`ReportOnly`, then `Enforced` after enable).
  - CIDR validation (valid v4/v6, `/0` refused, junk refused).
  - Verify-before-write refuses a foreign or changed policy.
  - Ineligible principal refused.
  - Licence error mapped.
  - wiremock tests for the client calls.
  - GUI test of the tab's three states and the confirm.
- **B3:**
  - Tag round-trip and untrusted parse.
  - Rule 25 table test (expired / today / future / malformed).
  - `revoke_expired_grants` revokes only still-expired ones (wiremock).
  - Index patch keeps tags.
  - GUI test of the group and Fix confirm.
  - Wizard expiry select.
- Each PR: `just verify`, all four GUI shards, `audit`/`deny`/`machete`, a fresh whole-branch review.
- **Manual (user, `just dev`, test tenant):**
  - an app calling call records;
  - lock create, then enable (with a Workload ID Premium tenant, and without one to see the message),
    then remove;
  - a 1-day expiry revoked next day.

## Builder-check resolutions (my calls — these override the sections above where they differ)
1. **Toolkit-owned lock vs any lock (B2).**
   - A core `toolkit_lock_for(policies, sp_object_id)` finds the toolkit's own policy, in any state
     including `disabled`. It must match all three:
     - displayName prefix `azapptoolkit network lock — `;
     - `includeServicePrincipals` exactly `[sp]`;
     - the lock shape (`includeApplications: ["All"]`, `includeLocations: ["All"]`, `block`, no risk
       gate).
   - The tab shows the toolkit lock's state with its actions:
     - report-only → Turn on / Remove;
     - enabled → Remove;
     - disabled in the portal → "Turned off outside the toolkit" with Turn on / Remove.
   - With no toolkit lock, the tab shows the general verdict (`network_lock_for` against the Graph
     resource), read-only:
     - another policy enforcing → "Locked by <policy name> — not managed here", no Create;
     - report-only or may-apply elsewhere → info, Create still offered;
     - none → Create.
   - `create_network_lock` refuses `lock_exists` only when a toolkit lock for this SP already exists
     (any state). Enable and remove act only on `toolkit_lock_for`'s policy.
   - `ReportOnly { policy_ids }` is not needed for the UI and stays a unit variant.
2. **Named locations are created UNTRUSTED (B2).** A trusted range joins `AllTrusted`, which relaxes
   user MFA policies and Identity Protection risk for anyone signing in from it. The picker lists IP
   named locations whether trusted or not; country locations are not offered. Remove leaves the named
   location in place, since it may be shared, and says so.
3. **Usage never blocks or degrades the audit (B1).**
   - The query runs alongside scoring: it is spawned before the fan-out and awaited after it.
   - `last_used` is filled in a final pass over the collected items, not inside `score_one`.
   - It has a 60 s budget (`tokio::time::timeout`) on top of the client's retries.
   - Any failure (timeout, partial result, no workspace, no consent) leaves every usage `Unknown`, with
     a reason the checklist shows. There is **no** `AuditCoverageGap::GraphActivity`: usage is advisory
     evidence, and `Unknown` claims nothing.
4. **Rule 25 fires on the tag alone (B3).**
   - An SP whose tags carry a passed expiry is admitted to the SP-only candidate set, like the risky
     admission path, so a vendor whose only expiring grant is on a custom API still gets a row.
   - The issue reads "Expiry passed for: <value> on <resource> (expired <date>)".
   - The Fix's live re-check revokes what is still held, and clears the tag for what is already gone
     (reported as "already removed").
5. **"Verifiable" includes a report-only readout (B2).**
   - While the toolkit lock is report-only, the tab reads the SP's recent sign-ins:
     `auditLogs/signIns` filtered to service-principal sign-ins of this app, with the existing
     `AuditLog.Read.All` consent and capability.
   - It counts those where this policy's applied result is `reportOnlyFailure` ("would have been
     blocked"), over the last 7 days, with the source IPs.
   - "Turn on lock" shows that count in its confirm. If the read is unavailable, the confirm says the
     outcome couldn't be checked.
6. **Revoking an expired grant also removes its declaration on app-registration rows (B3).**
   - Otherwise the portal's "Grant admin consent" brings it back with no expiry.
   - SP-only rows revoke the grant only, since they have no manifest.
   - The confirm says both, and the declaration removal reuses the existing permission-removal core.
