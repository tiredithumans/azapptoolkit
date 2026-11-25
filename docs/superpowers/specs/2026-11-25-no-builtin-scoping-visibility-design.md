# Design — Project A: "No built-in scoping" visibility

## Context
Some highly privileged Microsoft Graph application permissions have no Microsoft-provided way to narrow
them. `CallRecords.Read.All` is the example: Microsoft's call-records FAQ says it is tenant-wide by design.
The user wants the toolkit to handle this class of permission for both in-house and vendor apps, at both
moments: apps that already hold one (Security audit) and new requests (permission picker / Grant access
wizard).

The work is split into four projects, agreed order **A → B → C → D**, each designed separately:
- **A. Visibility (this doc).** Find, classify, score and explain. Read-only.
- B. Apply safeguards: expiring grants, Conditional Access network lock, mapping observed calls to permissions.
- C. More Microsoft-enforced scoping: admin-unit-limited Entra roles, Teams per-team consent, Teams meeting
  access policies.
- D. A broker service in Azure for in-house apps.

Today `CallRecords.*`, `OnlineMeeting*` and `Calls.*` are in no risk tier, so the audit scores them 0, and
nothing tells an operator that a permission cannot be narrowed.

## Goals
1. A single pure classifier, in core, that decides whether a held/requested app permission has no
   built-in scoping.
2. A tier sweep that adds the missing privileged permissions to the risk tiers so they score.
3. A new advisory audit finding per principal (app registrations **and** SP-only rows, which is where
   vendor apps live) listing each unscopable grant plus a safeguards checklist.
4. The same classification as a badge on the Permissions tab / held-permissions panel and as a warning in
   the permission picker and Grant access wizard.

## Non-goals
- Applying any safeguard (Project B). No new write paths, no new Fix buttons.
- Linking observed Graph activity to permissions (B).
- Teams / admin-unit mechanisms (C), broker (D).

## Anti-goals (would be a failure even if it technically works)
- Any wording that implies a safeguard narrows data reach. Never "scoped", "confined" or "limited to" for
  safeguards: a network lock limits where a token can be used, not what it reads.
- Flagging nearly every app (hence the directory-read exclusion).
- Showing "✗ no network lock" when the Conditional Access read failed or is unavailable. That is
  "unknown", and a failed read is a coverage gap.
- Value-only gates for the classifier where a resource is known (AGENTS.md: carry the resource).

## Decisions made with the user
| Decision | Choice |
|---|---|
| Whose apps | Both in-house and vendor |
| Which moment | Existing grants and new requests, equally |
| Project order | A → B → C → D |
| Scoring | The permission's tier sets the score. Safeguards are an advisory checklist and never move it |
| Approach | A new rule in the tenant-wide audit (not a separate page, not per-app only) |
| Coverage | Every risk tier, except the read-only directory permissions |

## Approaches considered
1. **New audit rule (chosen).** Reuses the audit's tenant-wide loading; the badge and picker share the
   classifier; SP-only rows cover vendor apps.
2. Separate "Privileged permissions" page. Rejected: duplicates the audit's loading and adds a third
   filtering home on the Security tab (AGENTS.md allows exactly two).
3. Per-app only. Rejected: cannot find existing grants across the tenant.

## Design

### 1. Classifier (core, pure, compiles for WASM)
New module, e.g. `crates/azapptoolkit-core/src/audit/unscopable.rs` (re-exported from `audit`).

```rust
pub enum NativeScoping {
    Managed(ScopeKind),                 // scoping::scope_kind_for → Some
    Swappable(&'static str),            // audit::least_privilege_alternative_for → Some
    MicrosoftUnmanaged(UnmanagedMechanism), // curated table, Graph resource only
    None,
}
pub enum UnmanagedMechanism { TeamsMeetingAccessPolicy, ResourceSpecificConsent, AdministrativeUnitRole }

pub fn native_scoping_for(resource_app_id: Option<&str>, value: &str) -> NativeScoping;
pub fn is_unscopable_privileged(resource_app_id: Option<&str>, value: &str) -> bool;
```

- `is_unscopable_privileged` = `risk_level_for_app_permission(value).is_some()`
  AND value not in `DIRECTORY_READ_EXCLUSIONS`
  AND `native_scoping_for` is `None` or `MicrosoftUnmanaged`.
- `DIRECTORY_READ_EXCLUSIONS` (the user's "skip directory reads"): `User.Read.All`, `Group.Read.All`,
  `GroupMember.Read.All`, `Device.Read.All`, `Application.Read.All`, `Directory.Read.All`,
  `RoleManagement.Read.Directory`.
- Risk tiers stay value-matched, as they are today (over-reporting is the safe direction). The curated
  `MicrosoftUnmanaged` table requires the Graph resource id.
- **Leave grants to the findings that already own them** *(my call)*. Skip any grant Rules 11/12 already
  speak for: mailbox-reaching (`scoping::is_mailbox_reaching_permission`, so the legacy Office 365
  Exchange Online mail roles stay with `unscopable_legacy_mailbox`), SharePoint site access, and org-wide
  Files. A grant with `resource_app_id: None` is checked against those families as if it were on Graph,
  so an unresolved `Mail.Read` is skipped rather than called unnarrowable. Reason: no duplicate rows with
  conflicting advice, and no false "Microsoft offers no way to narrow it".
- Curated table seed. The builder checks each entry against Microsoft's docs; only list a mechanism
  Microsoft documents for **app-only** access:
  - `OnlineMeetings.*`, `OnlineMeetingTranscript.Read.All`, `OnlineMeetingRecording.Read.All`,
    `OnlineMeetingArtifact.Read.All` → `TeamsMeetingAccessPolicy`.
  - `ChannelMessage.Read.All`, `Chat.Read.All`, `Chat.ReadWrite.All` → `ResourceSpecificConsent`.
  - `User.ReadWrite.All`, `Group.ReadWrite.All`, `Device.ReadWrite.All` → `AdministrativeUnitRole`.
- `CallRecords.*` deliberately has no entry. It falls through to `None`.

### 2. Tier sweep (`crates/azapptoolkit-core/src/audit/permissions.rs`)
- Add the missing communications-family permissions, following the file's existing convention:
  tenant-wide read → MEDIUM, write/act → HIGH, each marked "Net-new" with a one-line reason.
- Seed list. The builder confirms each value exists in the Graph permissions reference and drops any
  that don't:
  - MEDIUM: `CallRecords.Read.All`, `CallRecord-PstnCalls.Read.All`, `OnlineMeetings.Read.All`,
    `OnlineMeetingTranscript.Read.All`, `OnlineMeetingRecording.Read.All`,
    `OnlineMeetingArtifact.Read.All`, `ChannelMessage.Read.All`.
  - HIGH: `OnlineMeetings.ReadWrite.All`, `Calls.AccessMedia.All`.
- This shifts rankings, so it needs a CHANGELOG line under `[Unreleased]`.
- The existing disjointness and family tests must keep passing.

### 3. Audit rule (advisory, no score)
- **Rule 24, `rule_unscopable_privileged`**, in `audit/scoring.rs`.
  - Score: none. The weight already lands through Rules 1/2.
  - Runs for app rows **and** SP-only rows: add it to the SP-only rule set beside Rules 1–4, 11–13, 21–22.
  - Reads **held** grants, i.e. `app_role_grants` after the Rule 23 merge, not `declared_view()`. It has
    no Fix to re-plan, so undeclared grants count.
- **Structured output on `AuditItem`** (crosses IPC as-is, so the fields are additive with
  `#[serde(default)]`):
  - `unscopable_grants: Vec<UnscopableGrant>`, where
    `UnscopableGrant { permission: ResourcePermission, risk: RiskLevel, microsoft_mechanism: Option<UnmanagedMechanism>, network_lock: NetworkLock }`.
    The network lock is **per grant**, because a policy can cover one resource and not another
    *(my call; fixing this later would change the wire format)*.
  - `safeguards: Option<Safeguards>`, present only when `unscopable_grants` is non-empty.
- **`Safeguards`** (per principal):
  - Credentials: cert-only / has a secret / none / not applicable for SP-only rows.
  - Owners count (app rows).
  - Instance lock (app rows).
  - Last sign-in.
  - Reuse what the scorer already computes (credential status, ownership, `INSTANCE_LOCK_DISABLED`,
    sign-in post-pass). Builder's call whether `Safeguards` copies those or points at existing fields.
    The sign-in value arrives in a runner post-pass, so its slot must be filled there.
- **Wiring** (touch points from `docs/architecture/audit-findings-and-remediation.md`):
  - An `issue::UNSCOPABLE_PRIVILEGED` marker.
  - Finding key `unscopable_privileged` in `audit/finding.rs`.
  - An entry in `POSTURE_FINDING_KEYS` (`audit/posture.rs:44`).
  - A `GROUP_CATALOG` entry in `web-rs/src/views/audit_view/groups.rs`.
  - No `RemediationKind`.

### 4. Network-lock verdict
- **Preliminary fix, its own small PR first** *(my call)*. The CA tab's `ALL_WORKLOAD_TOKENS`
  (`conditional_access.rs:261`) is missing `ServicePrincipalsInMyTenant`, which Graph documents as the
  all-service-principals value of `includeServicePrincipals` (confirm against the Graph reference). So
  the tab hides the most common workload-identity lock policy today, and the audit would show a false
  "✗". Ship it as `fix(desktop): …` with a CHANGELOG line and a test, before Project A's move.
- **Move the pure Conditional Access client-axis logic** (`client_axis`, `client_includes_sp`,
  `ALL_WORKLOAD_TOKENS`, and `applies` / `resource_reason` for the tab) from
  `apps/desktop/src-tauri/src/commands/conditional_access.rs` into core (e.g.
  `azapptoolkit-core::conditional_access`). The tab's behaviour is unchanged beyond the preliminary fix,
  and its tests move with the code.
- **The lock evaluator is its own function, not `applies()`.** `applies()` checks excluded resources
  against the app's own appId (the app as the thing being called), which is the wrong question here. The
  lock evaluator takes the SP plus the grant's resource appId. The policy covers the grant only when its
  `includeApplications` holds `All` or that resource appId, and `excludeApplications` doesn't hold it.
  `Office365` or an application filter yields `MayApply`.
- **Add `locations`** to `CaConditions` (`crates/azapptoolkit-core/src/models.rs:804`):
  `Option<CaLocations { include_locations: Vec<String>, exclude_locations: Vec<String> }>`, using the
  existing `null_to_default` tolerance.
- **`NetworkLock`** values:
  - `Enforced { policy_ids }`: some policy has state `enabled`, a client axis that names this SP
    (directly or through an all-workload token), a resource axis that covers the grant's resource, a
    locations condition with a non-empty include, and `block` in its built-in grant controls.
    Named-location contents are not evaluated.
  - `ReportOnly`: the same, but state `enabledForReportingButNotEnforced`.
  - `MayApply`: only a client attribute filter could match.
  - `None`: the CA read succeeded and nothing matched.
  - `NotPossible { reason }`: Microsoft only covers single-tenant service principals registered in this
    tenant. Reasons:
    - a managed identity (`servicePrincipalType`);
    - an app owned by another tenant (`appOwnerOrganizationId` ≠ tenant);
    - a multi-tenant audience.
    The builder confirms the exact rule against the Microsoft Learn workload-identity page.
  - `Unknown`: the CA read is unavailable or failed.
- **Prefetch.** A new `prefetch_conditional_access` in `commands/audit/prefetch.rs` reads policies once
  per run through the existing `GraphClient::list_conditional_access_policies`. Its outcome function
  follows `sign_in_activity_outcome` (`prefetch.rs:444-498`), not the risky-SP one *(my call)*:
  - "Unavailable": `Unknown` everywhere, and not a gap. This covers no token or consent, a tenant without
    a licence, **or an operator without a role that can read CA**. Reason: the repo's precedent is that a
    permanent banner trains operators to ignore it, and a degraded run would never be cached, which
    breaks Home's posture card for that operator.
  - Any other read failure after the token is in hand → a new `AuditCoverageGap::ConditionalAccess`
    variant (`crates/azapptoolkit-dto/src/audit.rs:257`), so the run is degraded and never cached as
    all-clear.
  - The checklist copy for `Unknown` says why: "couldn't read Conditional Access (needs Security Reader
    or similar)".
  - It always runs: one paged read is cheap, and skipping it would need an ordering dependency on the
    grant matrices.

### 5. Surfaces
- **Security workbench.** A "No built-in scoping" group. A row's detail shows the checklist:
  ```
  ⚠ No built-in scoping · CallRecords.Read.All (Medium)
    Reads every Teams call record in the tenant. Microsoft offers no way to narrow it.
    ✗ Network lock      no Conditional Access policy targets this app
    ✓ Credentials       certificate only
    ✓ Owners            2
    · Last sign-in      3 days ago
  ```
  - Vendor rows read "Network lock: not possible for an app owned by another tenant".
  - A `MicrosoftUnmanaged` grant adds "Microsoft can narrow this with <mechanism>; this toolkit doesn't
    manage it yet."
- **Permissions tab** (`views/tabs/permissions_tab.rs`) and **held-permissions panel**
  (`components/held_permissions_panel.rs`): a "No built-in scoping" badge on qualifying rows. It is
  classifier-only: no safeguards and no new IPC.
- **Permission picker** (`components/permission_picker.rs`, beside `downgrade_hint` / `scope_hint`) and
  **Grant access wizard** (`components/scope_wizard.rs`, review step): a non-blocking `Callout` when a
  selected Application permission is unscopable.
- **Reuse the UI primitives** (`Callout`, `SectionHeader`, the badge component). Don't build new ones.

### 6. Docs
- CHANGELOG `[Unreleased]`: one line for the new finding, and one for the tier additions (a ranking
  change).
- `docs/architecture/audit-findings-and-remediation.md`: a Rule 24 row, plus a short "No built-in scoping"
  section (classifier, exclusions, network-lock verdict).
- `.claude/rules/scoping-and-audit.md`: one line.
- AGENTS.md: one sentence under *Audit & remediation*, only if it fits the 18 000-byte budget.

## Left to the builder
- Final membership of the tier sweep and the curated table, using the rules above.
- Type names and module placement.
- Whether `Safeguards` copies or references existing `AuditItem` fields.
- How `Exchange.ManageAsApp` (high; its reach comes from an Exchange role) is classified. State the call
  in the PR.
- Exact copy, within the anti-goals.

## Calls I made (check these while reading)
1. Grants Rules 11/12 already own are left to them, and an unresolved resource is checked as Graph
   (section 1).
2. The network lock is per grant and checks the policy's resource side (sections 3–4).
3. An operator who can't read Conditional Access gets "unknown", not a degraded run (section 4).
4. The CA tab's missing `ServicePrincipalsInMyTenant` token gets fixed first, in its own small PR
   (section 4).
5. The tier sweep follows the file's read = Medium / write = High rule, so `CallRecords.Read.All` lands
   at Medium (section 2).

## After approval
1. On branch `fix/ca-all-tenant-workload-token`: the preliminary CA-tab fix (TDD, `just verify`, its own PR).
2. Save this design to `docs/superpowers/specs/2026-11-25-no-builtin-scoping-visibility-design.md` on
   branch `feat/no-builtin-scoping-visibility`.
3. Run `superpowers:writing-plans` to produce the task-level implementation plan, then implement with TDD.

## Verification
- **Core tests (table-driven):**
  - Classifier: every `NativeScoping` arm; the resource is carried (a non-Graph resource never hits the
    curated table); directory reads are excluded; `CallRecords.Read.All` → unscopable.
  - Network-lock verdict: enabled, report-only, no `block`, exclude wins, all-workload token
    (`ServicePrincipalsInMyTenant` included), client filter, resource axis covers / misses / excludes
    the grant's resource, `Office365` → `MayApply`, managed identity, foreign-owned app, multi-tenant.
  - Classifier skips: a legacy Exchange Online `Mail.ReadWrite`, a `None`-resource `Mail.Read`,
    `Files.Read.All`, and `Sites.Read.All` are never flagged.
  - Tier disjointness.
- **Moved Conditional Access tests:** still pass, unchanged.
- **Prefetch outcome tests:** unavailable vs gap, mirroring `risky_service_principals_outcome`.
- **GUI tests** (`web-rs/tests/gui_N.rs`, mocked IPC): the finding group renders the checklist, the badge
  shows on the Permissions tab, and the picker shows the warning. Update `demo::register_fixtures` if the
  audit fixtures change.
- `just verify`, then `just verify-full`.
- **Manual (`just dev`, test tenant):** an app holding `CallRecords.Read.All` with and without a
  workload-identity CA block policy, plus one vendor (multi-tenant) app holding it.

## Planning amendments (2026-11-25, made while writing the implementation plan)
- The classifier flags **Microsoft Graph grants only** (or unresolved `None` resources). The user asked
  about Graph permissions, and this settles the "left to the builder" `Exchange.ManageAsApp` case: it is
  out of scope, along with the legacy Exchange Online / SharePoint Online roles that Rules 11/12 own.
- **No separate `Safeguards` struct.** `AuditItem` already carries credentials (`certificates`/`secrets`),
  owner markers, `last_sign_in` and `sign_in_audience`. The checklist reads those, and the only new data
  is each grant's `network_lock`.
- `unscopable_privileged` is **not a posture bucket**. It is an advisory sibling of `high_risk_perms`,
  like `granted_undeclared`. That avoids changing Home's posture strip.
- Checklist copy is generic ("reaches the whole tenant"), not per permission. Permission descriptions
  are resolved live elsewhere.
