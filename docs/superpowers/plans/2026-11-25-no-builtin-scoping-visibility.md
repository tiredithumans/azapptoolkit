# "No built-in scoping" Visibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Find, score and explain Microsoft Graph application permissions that Microsoft gives no way to narrow
(e.g. `CallRecords.Read.All`). That covers a new audit finding with a per-permission network-lock check, a
badge on permission rows, and a warning at grant time.

**Architecture:**
- **Core:** a pure classifier (`audit::unscopable`) plus a pure Conditional Access evaluator
  (`conditional_access`, moved out of the command file).
- **Audit:** a no-score Rule 24 lists unscopable grants on `AuditItem`. The audit runner then fills each
  grant's network-lock verdict from one tenant-wide Conditional Access read.
- **Frontend:** it reads the classifier directly for badges and warnings, and the finding's structured
  field for the checklist.

**Tech Stack:** Rust 2024, Tauri 2 backend, Leptos 0.8 WASM frontend, Microsoft Graph v1.0.

**Spec:** `docs/superpowers/specs/2026-11-25-no-builtin-scoping-visibility-design.md`

## Global Constraints

- Safeguards never move the score. Rule 24 adds 0 points; only the new tier entries (Task 1) change scores.
- Copy never says "scoped", "confined" or "limited to" about a safeguard. A network lock limits where a
  token is used, not what it reads.
- "Couldn't read Conditional Access" is `NetworkLock::Unknown`, never `None` (✗). Only a retryable read
  failure is a coverage gap.
- The classifier flags only Microsoft Graph grants, or grants whose resource is unresolved (`None`), and
  carries the resource everywhere. Graph appId is `scoping::MICROSOFT_GRAPH_APP_ID`, compared
  case-insensitively.
- Directory reads are never flagged: `User.Read.All`, `Group.Read.All`, `GroupMember.Read.All`,
  `Device.Read.All`, `Application.Read.All`, `Directory.Read.All`, `RoleManagement.Read.Directory`.
- `AuditItem` crosses IPC and the cache as-is. New fields are `#[serde(default)]` and additive, and old
  cached runs must still deserialize.
- CHANGELOG entries: one line, ≤ 120 chars, the app's own words, under `[Unreleased]`.
- Conventional Commits with scope `core` or `desktop` only.
- Gate every commit with `just verify`. Format web-rs with `cargo fmt` run inside `apps/desktop/web-rs`.

## Review Focus

1. **An audit run cached before this change** (no `unscopable_grants`) must load and render with no
   checklist. Test in Task 5.
2. **A Conditional Access policy with `locations: null`, only `excludeLocations`, or no client axis** must
   parse and must not count as a lock. Tests in Tasks 3 and 4.
3. **The same unscopable permission both declared and granted** shows once. Test in Task 5 (`deduped()`
   runs first).
4. **An operator whose Conditional Access read is refused (403)** sees "couldn't read" on every grant, and
   the run isn't degraded. Test in Task 7.
5. **A Graph resource id in upper case** (`00000003-0000-0000-C000-000000000000`) still classifies. Test
   in Task 2.

---

### Task 1: Weight the missing communications permissions

**Files:**
- Modify: `crates/azapptoolkit-core/src/audit/permissions.rs` (`HIGH_RISK_APP_PERMISSIONS` :156, `MEDIUM_RISK_APP_PERMISSIONS` :243)
- Modify: `CHANGELOG.md`
- Test: `crates/azapptoolkit-core/src/audit/permissions.rs` (its `tests` module)

**Interfaces:**
- Produces: `risk_level_for_app_permission` answers for the values below.

- [ ] **Step 1: Confirm each value exists** in Microsoft's Graph permissions reference
  (learn.microsoft.com/graph/permissions-reference). Drop any value that doesn't exist from both the
  test and the code.
- [ ] **Step 2: Write the failing test**

```rust
#[test]
fn communications_permissions_carry_a_risk_weight() {
    for v in ["CallRecords.Read.All", "CallRecord-PstnCalls.Read.All", "OnlineMeetings.Read.All",
              "OnlineMeetingTranscript.Read.All", "OnlineMeetingRecording.Read.All",
              "OnlineMeetingArtifact.Read.All", "ChannelMessage.Read.All"] {
        assert_eq!(risk_level_for_app_permission(v), Some(RiskLevel::Medium), "{v}");
    }
    for v in ["OnlineMeetings.ReadWrite.All", "Calls.AccessMedia.All"] {
        assert_eq!(risk_level_for_app_permission(v), Some(RiskLevel::High), "{v}");
    }
}
```

- [ ] **Step 3: Run it.** `just test-crate azapptoolkit-core -- communications_permissions` fails with
  `left: None`.
- [ ] **Step 4: Add the values to the lists.**
  - Medium: the seven reads, under one `// Net-new: tenant-wide Teams communications reads (call records,
    meeting content, channel messages) — read = medium` comment.
  - High: the two writes / live-media entries, under one `// Net-new: …` comment.
- [ ] **Step 5: Run the core suite.** `just test-crate azapptoolkit-core` passes, including
  `tier0_high_and_medium_lists_are_disjoint`.
- [ ] **Step 6: Add a CHANGELOG line** under `[Unreleased]` → `### Changed`:
  `- The security audit now scores Teams call-record, meeting and channel-message permissions.`
- [ ] **Step 7: Commit** `feat(core): weight Teams communications permissions in the audit`.

### Task 2: The "no built-in scoping" classifier

**Files:**
- Create: `crates/azapptoolkit-core/src/audit/unscopable.rs`
- Modify: `crates/azapptoolkit-core/src/audit/mod.rs` (declare the module + `pub use unscopable::*;`)

**Interfaces:**
- Produces:
  - `pub enum NativeScoping { Managed(ScopeKind), Swappable(&'static str), MicrosoftUnmanaged(UnmanagedMechanism), None }`
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "snake_case")] pub enum UnmanagedMechanism { TeamsMeetingAccessPolicy, ResourceSpecificConsent, AdministrativeUnitRole }`,
    with `pub fn label(self) -> &'static str` returning "a Teams meeting access policy" / "per-team
    (resource-specific) consent" / "an admin role limited to an administrative unit".
  - `pub fn native_scoping_for(resource_app_id: Option<&str>, value: &str) -> NativeScoping`
  - `pub fn is_unscopable_privileged(resource_app_id: Option<&str>, value: &str) -> bool`
  - `pub fn unmanaged_mechanism_for(resource_app_id: Option<&str>, value: &str) -> Option<UnmanagedMechanism>`
  - `pub const DIRECTORY_READ_EXCLUSIONS: &[&str]` (the seven values in Global Constraints).

- [ ] **Step 1: Write the failing table test** `unscopable_classification_table`. Each row asserts
  `is_unscopable_privileged`, with `G = Some(MICROSOFT_GRAPH_APP_ID)`:

| resource | value | expected | why |
|---|---|---|---|
| G | `CallRecords.Read.All` | true | no mechanism |
| `Some("00000003-0000-0000-C000-000000000000")` | `CallRecords.Read.All` | true | case-insensitive Graph |
| None | `CallRecords.Read.All` | true | unresolved is treated as Graph |
| G | `Chat.Read.All` | true | `MicrosoftUnmanaged(ResourceSpecificConsent)` still flags |
| G | `User.Read.All` | false | directory read |
| G | `Directory.Read.All` | false | directory read |
| G | `Mail.Read` | false | Managed(Exchange) |
| None | `Mail.Read` | false | Rule 11 owns mailbox-reaching values |
| `Some(OFFICE365_EXCHANGE_ONLINE_APP_ID)` | `Mail.ReadWrite` | false | not Graph |
| `Some(OFFICE365_EXCHANGE_ONLINE_APP_ID)` | `Exchange.ManageAsApp` | false | not Graph |
| G | `Files.Read.All` | false | Swappable |
| G | `Sites.Read.All` | false | Managed(SharePoint) |
| G | `RoleManagement.ReadWrite.Directory` | true | tier-0, no mechanism |
| G | `Organization.Read.All` | false | in no tier |

  Plus a second test, `unmanaged_mechanisms_are_graph_only`:
  - `unmanaged_mechanism_for(G, "OnlineMeetings.Read.All") == Some(TeamsMeetingAccessPolicy)`
  - `== Some(AdministrativeUnitRole)` for `User.ReadWrite.All`
  - `None` for the same value on `Some(OFFICE365_EXCHANGE_ONLINE_APP_ID)`.
- [ ] **Step 2: Run it.** `just test-crate azapptoolkit-core -- unscopable` fails to compile (missing items).
- [ ] **Step 3: Implement** in `unscopable.rs`:
  - `native_scoping_for` checks, in order: `scoping::scope_kind_for` → `least_privilege_alternative_for`
    → the curated table (Graph only) → `None`.
  - `is_unscopable_privileged` returns false unless the resource is Graph or `None`, the value has a risk
    tier, the value isn't in the exclusions, and the value isn't mailbox-reaching / SharePoint site access
    / org-wide Files (`scoping::is_mailbox_reaching_permission`, `is_sharepoint_site_access_permission`,
    `is_files_orgwide_permission`, each called with the Graph id when the resource is `None`). It then
    answers true for `NativeScoping::None | MicrosoftUnmanaged(_)`.
  - Curated table seed: confirm each entry against Microsoft's docs for **app-only** access and drop any
    that isn't documented:
    - `OnlineMeetings.Read.All`, `OnlineMeetings.ReadWrite.All`, `OnlineMeetingTranscript.Read.All`,
      `OnlineMeetingRecording.Read.All`, `OnlineMeetingArtifact.Read.All` → `TeamsMeetingAccessPolicy`.
    - `ChannelMessage.Read.All`, `Chat.Read.All`, `Chat.ReadWrite.All` → `ResourceSpecificConsent`.
    - `User.ReadWrite.All`, `Group.ReadWrite.All`, `Device.ReadWrite.All` → `AdministrativeUnitRole`.
- [ ] **Step 4: Run it.** `just test-crate azapptoolkit-core -- unscopable` passes.
- [ ] **Step 5: Commit** `feat(core): classify Graph permissions with no built-in scoping`.

### Task 3: Move the Conditional Access logic to core and read `locations`

Pure refactor plus one model field. Builds on the preliminary `ServicePrincipalsInMyTenant` fix.

**Files:**
- Create: `crates/azapptoolkit-core/src/conditional_access.rs` (+ `pub mod conditional_access;` in `lib.rs`)
- Modify: `apps/desktop/src-tauri/src/commands/conditional_access.rs`
- Modify: `crates/azapptoolkit-core/src/models.rs:804` (`CaConditions`)

**Interfaces:**
- Produces:
  - `pub fn applies(conditions: &CaConditions, app_id: &str, sp_id: Option<&str>) -> Option<(&'static str, bool)>`
    (unchanged behaviour).
  - `pub(crate) fn client_axis` / `ClientAxis` / `ALL_WORKLOAD_TOKENS` for Task 4.
  - `CaConditions.locations: Option<CaLocations>`, where
    `pub struct CaLocations { include_locations: Vec<String>, exclude_locations: Vec<String> }`
    (camelCase serde, `null_to_default`).

- [ ] **Step 1: Write the failing model test** in `models.rs`, `ca_policy_reads_locations_and_tolerates_null`:
  - Deserialize a policy with
    `"locations": {"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}` and assert both vecs.
  - Deserialize one with `"locations": null` and assert `locations.is_none()`.
  - Deserialize one with `"locations": {"includeLocations": null, "excludeLocations": ["x"]}` and assert
    the include is empty.
- [ ] **Step 2: Run it.** `just test-crate azapptoolkit-core -- ca_policy_reads_locations` fails to compile.
- [ ] **Step 3: Add `CaLocations` and the field.** Then fix every `CaConditions { … }` literal the
  compiler names (add `locations: None`).
- [ ] **Step 4: Move the pure functions and their tests.** Move `applies`, `resource_reason`,
  `client_includes_sp`, `client_filter_is_exclude`, `ALL_WORKLOAD_TOKENS`, `ClientAxis`, `client_axis` and
  the whole `tests` module, except `ca_err_is_body_safe_and_classified` and `reason_ranks_…`, which stay
  with `map_ca_err` / `reason_rank`. The command file imports `azapptoolkit_core::conditional_access::applies`.
- [ ] **Step 5: Run the moved tests.** `just test-crate azapptoolkit-core -- conditional_access` passes,
  with the same test names as before plus the preliminary fix's test, and
  `just test-crate desktop --lib -- conditional_access` passes.
- [ ] **Step 6: Commit** `refactor(core): move Conditional Access applicability to core`.

### Task 4: Network-lock verdict

**Files:**
- Modify: `crates/azapptoolkit-core/src/conditional_access.rs`

**Interfaces:**
- Consumes: Task 3's `client_axis`, `CaLocations`.
- Produces:
  - `#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)] #[serde(tag = "state", rename_all = "snake_case")] pub enum NetworkLock { Enforced { policy_ids: Vec<String> }, ReportOnly, MayApply, None, NotPossible { reason: LockIneligible }, #[default] Unknown }`
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "snake_case")] pub enum LockIneligible { ManagedIdentity, OtherTenant, MultiTenantApp, NoServicePrincipal }`
  - `pub fn network_lock_for(policies: &[ConditionalAccessPolicy], sp_object_id: &str, resource_app_id: &str) -> NetworkLock`.
    The read succeeded, so this never returns `Unknown` or `NotPossible`.
  - `pub fn lock_ineligibility_for_app(sign_in_audience: Option<&str>, has_service_principal: bool) -> Option<LockIneligible>`
  - `pub fn lock_ineligibility_for_sp(service_principal_type: Option<&str>, app_owner_organization_id: Option<&str>, tenant_id: &str) -> Option<LockIneligible>`

- [ ] **Step 1: Write the failing tests.** A builder `lock_policy(state, clients, include_apps, exclude_apps, locations, controls)`.
  Cases, with `G` = Graph appId:

| test | policy | expected |
|---|---|---|
| `enforced_when_enabled_block_with_locations_names_sp` | enabled, clients `[SP]`, apps `["All"]`, locations include `["All"]`, `block` | `Enforced{policy_ids:[id]}` |
| `tenant_token_counts` | clients `["ServicePrincipalsInMyTenant"]` | `Enforced` |
| `report_only` | state `enabledForReportingButNotEnforced` | `ReportOnly` |
| `disabled_is_none` | state `disabled` | `None` |
| `no_block_is_none` | controls `["mfa"]` | `None` |
| `no_locations_is_none` | `locations: None` | `None` |
| `exclude_only_locations_is_none` | include `[]`, exclude `["AllTrusted"]` | `None` |
| `client_exclude_wins` | clients include `["ServicePrincipalsInMyTenant"]`, exclude `[SP]` | `None` |
| `other_sp_only_is_none` | clients `[OTHER_SP]` | `None` |
| `no_client_axis_is_none` | `client_applications: None` (a user policy) | `None` |
| `resource_excluded_is_none` | apps `["All"]`, exclude `[G]` | `None` |
| `other_resource_only_is_none` | apps `[OTHER_APP]` | `None` |
| `office365_or_app_filter_may_apply` | apps `["Office365"]` / application_filter set | `MayApply` |
| `client_filter_may_apply` | `service_principal_filter` only | `MayApply` |
| `enforced_beats_report_only` | one enabled + one report-only | `Enforced` with only the enabled id |

  Ineligibility:
  - `lock_ineligibility_for_app(Some("AzureADMultipleOrgs"), true) == Some(MultiTenantApp)`
  - `(Some("AzureADMyOrg"), false) == Some(NoServicePrincipal)`
  - `(Some("AzureADMyOrg"), true) == None`
  - `lock_ineligibility_for_sp(Some("ManagedIdentity"), _, T) == Some(ManagedIdentity)`
  - other owner org → `OtherTenant`
  - owner org == T in a different case → `None`
  - owner org `None` → `None`
  - Serde: `NetworkLock::NotPossible{reason: OtherTenant}` serializes to
    `{"state":"not_possible","reason":"other_tenant"}`.
- [ ] **Step 2: Run them.** `just test-crate azapptoolkit-core -- conditional_access` fails to compile.
- [ ] **Step 3: Implement.** For each policy whose state isn't `disabled`:
  1. **Client axis:** a policy with no client axis (or an empty one) is skipped. `Hidden` → skip,
     `Matched` → match, `MayApply` → may.
  2. **Resource axis:** `exclude_applications` holds the resource (case-insensitive) → skip. Include
     holds `All` or the resource → covered. `Office365` / `application_filter` → may. Otherwise skip.
  3. **Lock shape:** `locations` include is non-empty and `built_in_controls` contains `block`;
     otherwise skip.

  An enabled policy that matches on both axes goes into `Enforced`. An enabled policy with a "may" on
  either axis contributes `MayApply`. A report-only policy contributes `ReportOnly`. Precedence:
  Enforced > MayApply > ReportOnly > None.
- [ ] **Step 4: Run them.** `just test-crate azapptoolkit-core -- conditional_access` passes.
- [ ] **Step 5: Commit** `feat(core): network-lock verdict from Conditional Access policies`.

### Task 5: Rule 24 and the `AuditItem` field

**Files:**
- Modify: `crates/azapptoolkit-core/src/audit/types.rs` (`AuditItem` :598, `issue` :668)
- Modify: `crates/azapptoolkit-core/src/audit/unscopable.rs` (`UnscopableGrant`)
- Modify: `crates/azapptoolkit-core/src/audit/scoring.rs` (`score_application` :1024, `score_service_principal` :1216)
- Modify: every `AuditItem { … }` literal the compiler names (~10, in core, dto, desktop and web-rs tests)
- Test: `crates/azapptoolkit-core/src/audit/scoring/tests.rs`, `types.rs` tests

**Interfaces:**
- Consumes: Task 2's classifier, Task 4's `NetworkLock`.
- Produces:
  - `#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)] pub struct UnscopableGrant { pub permission: ResourcePermission, pub risk: RiskLevel, pub microsoft_mechanism: Option<UnmanagedMechanism>, #[serde(default)] pub network_lock: NetworkLock }`
  - `AuditItem.unscopable_grants: Vec<UnscopableGrant>` (`#[serde(default)]`)
  - `issue::UNSCOPABLE_PRIVILEGED = "No built-in scoping:"`

- [ ] **Step 1: Write the failing tests** in `scoring/tests.rs`:
  - `rule24_lists_unscopable_grants_without_score`: an app whose `app_role_grants` are Graph
    `CallRecords.Read.All` and Graph `Mail.Read`.
    - `unscopable_grants` has exactly one entry (CallRecords, `RiskLevel::Medium`, mechanism `None`,
      lock `Unknown`).
    - One issue starts with `issue::UNSCOPABLE_PRIVILEGED` and names `CallRecords.Read.All` but not
      `Mail.Read`.
    - `risk_score` equals the score of the same app without the CallRecords grant, plus
      `PTS_MEDIUM_RISK_APP_PERM` (the Task 1 weight alone; Rule 24 adds nothing).
  - `rule24_counts_undeclared_grants_once`: CallRecords declared AND in `undeclared_grants` (merged
    twice) gives one entry.
  - `rule24_runs_on_sp_only_rows`: `score_service_principal` with a Graph `Chat.Read.All` grant gives one
    entry, mechanism `Some(ResourceSpecificConsent)`.
  - Add `issue::UNSCOPABLE_PRIVILEGED` to `emitted_issue_markers_are_stable`.
  - In `types.rs` tests, `audit_item_without_unscopable_grants_deserializes`: an `AuditItem` JSON without
    the field deserializes with an empty vec. Extend `audit_item_enum_wire_spellings_are_pinned` with the
    `NetworkLock` / `UnmanagedMechanism` spellings.
- [ ] **Step 2: Run them.** `just test-crate azapptoolkit-core -- rule24` fails to compile.
- [ ] **Step 3: Implement** `fn rule_unscopable_privileged(perms: &AppPermissions) -> (RuleContribution, Vec<UnscopableGrant>)`.
  - Score 0. It reads the full deduped `perms.app_role_grants`, not `declared_view()`.
  - Issue copy: `"{UNSCOPABLE_PRIVILEGED} {values} — Microsoft offers no way to narrow these, so each reaches the whole tenant"`.
  - Recommendation copy: `"Remove any the app doesn't need; for the rest, review the safeguards around it (a Conditional Access network lock, certificate-only credentials, owners)"`.
  - Fold it after Rule 23 in `score_application`, and after Rule 13 in `score_service_principal`. Set
    the field on both `AuditItem` literals.
- [ ] **Step 4: Run the suites.** `just test-crate azapptoolkit-core` passes, then `just check`.
- [ ] **Step 5: Commit** `feat(core): audit Rule 24 lists permissions with no built-in scoping`.

### Task 6: Conditional Access read in the audit run

**Files:**
- Modify: `crates/azapptoolkit-dto/src/audit.rs:257` (`AuditCoverageGap::ConditionalAccess` + its message arm :393)
- Modify: `apps/desktop/src-tauri/src/commands/audit/prefetch.rs`
- Modify: `apps/desktop/src-tauri/src/commands/audit/mod.rs` (`ScoreCtx` :75)
- Modify: `apps/desktop/src-tauri/src/commands/audit/run.rs` (`futures::join!` :122, `degraded` :217, `ScoreCtx` literal :274)
- Modify: `apps/desktop/src-tauri/src/commands/audit/score.rs` (`score_one` post-pass :496, `score_sp_only` :216)
- Test: `apps/desktop/src-tauri/src/commands/audit/tests.rs`

**Interfaces:**
- Consumes: Task 4 (`network_lock_for`, `lock_ineligibility_for_*`), Task 5 (`unscopable_grants`).
- Produces:
  - `pub(crate) type CaPrefetch = (bool, Arc<Vec<ConditionalAccessPolicy>>, Option<AuditCoverageGap>)`
  - `pub(crate) async fn prefetch_conditional_access(state: &AppState, client: &GraphClient, tenant_id: &str) -> CaPrefetch`
  - `pub(crate) fn ca_pre_acquire_outcome(ui: &UiError) -> CaPrefetch`
  - `pub(crate) fn conditional_access_outcome(read: azapptoolkit_graph::Result<Vec<ConditionalAccessPolicy>>) -> CaPrefetch`
  - `ScoreCtx { ca_available: bool, ca_policies: Arc<Vec<ConditionalAccessPolicy>>, .. }`
  - `pub(crate) fn apply_network_locks(item: &mut AuditItem, ctx: &ScoreCtx, sp_object_id: Option<&str>, ineligible: Option<LockIneligible>)`

- [ ] **Step 1: Write the failing tests** in `tests.rs`, mirroring the existing
  `risky_service_principals_outcome` / `sign_in_activity_outcome` tests:
  - `ca_outcome_ok_is_available`: `Ok(vec![policy])` → `(true, len 1, None)`.
  - `ca_outcome_forbidden_is_unavailable_not_a_gap`: a 403 `GraphError` → `(false, empty, None)`.
  - `ca_outcome_throttled_is_a_gap`: a retryable error → `(false, empty, Some(AuditCoverageGap::ConditionalAccess))`.
  - `ca_pre_acquire_network_is_a_gap_consent_is_not`: codes `network` → gap; `consent_required` → no gap.
  - `network_locks_unknown_when_ca_unavailable` / `…_not_possible_when_ineligible` /
    `…_evaluated_per_grant`: build an item with two unscopable grants (Graph, and a second resource
    covered by no policy) and a ctx holding one Graph-only lock policy. Assert `Enforced` on the first
    and `None` on the second.
- [ ] **Step 2: Run them.** `just test-crate desktop --lib -- ca_outcome network_locks` fails to compile.
- [ ] **Step 3: Implement.**
  - The prefetch pre-acquires with `state.ensure_feature_token(tenant_id, ConsentFeature::Policy)`.
    Transient token codes (`network` | `service_unavailable` | `unexpected_responder`) are a gap; any
    other token error is unavailable. The read goes through `client.list_conditional_access_policies()`:
    `is_retryable()` → gap, any other error → unavailable.
  - Add it as the 11th future in the `join!`, push its gap into `degraded`, and fill the new `ScoreCtx`
    fields.
  - `apply_network_locks` sets each grant's lock:
    - CA unavailable → `Unknown`;
    - ineligible → `NotPossible { reason }`;
    - otherwise `network_lock_for(&ctx.ca_policies, sp_id, resource)`, where a `None` resource is
      evaluated as Graph.
  - In `score_one`, call it after the risky pass with
    `lock_ineligibility_for_app(app.sign_in_audience.as_deref(), sp.is_some())`.
  - In `score_sp_only`, call it with
    `lock_ineligibility_for_sp(sp.service_principal_type.as_deref(), sp.app_owner_organization_id.as_deref(), &ctx.tenant_id)`.
- [ ] **Step 4: Run the suites.** `just test-crate desktop --lib` passes, then `just check`.
- [ ] **Step 5: Commit** `feat(desktop): check each unscopable grant for a Conditional Access network lock`.

### Task 7: The Security workbench group and checklist

**Files:**
- Modify: `crates/azapptoolkit-core/src/audit/finding.rs` (`finding_issue_marker` :20 and the key list below it)
- Modify: `apps/desktop/web-rs/src/views/audit_view/groups.rs` (`GROUP_CATALOG`, after `granted_undeclared`)
- Create: `apps/desktop/web-rs/src/views/audit_view/unscopable_checklist.rs`
- Modify: `apps/desktop/web-rs/src/views/audit_view/findings.rs:515` (the Detail cell)
- Modify: `apps/desktop/web-rs/src/styles.css` (only if a new class is needed; reuse `.issues` / `.read-grid` first)
- Test: core `finding.rs` tests, `groups.rs` tests, a GUI shard (`apps/desktop/web-rs/tests/gui_N.rs`, the shard that holds the audit-view tests)

**Interfaces:**
- Consumes: `AuditItem.unscopable_grants`, `NetworkLock`, `UnmanagedMechanism::label`.
- Produces:
  - Finding key `"unscopable_privileged"`. Not a posture bucket: like `granted_undeclared`, it's an
    advisory sibling of `high_risk_perms`.
  - `pub(super) fn network_lock_line(lock: &NetworkLock) -> (&'static str /*✓ ✗ · */, String)`
  - `#[component] pub(super) fn UnscopableChecklist(item: AuditItem) -> impl IntoView`

- [ ] **Step 1: Write the failing tests.**
  - Core: `matches_finding(item_with_marker, "unscopable_privileged")` is true.
  - web-rs unit test `network_lock_lines`:
    - `Enforced` → `("✓", "Conditional Access blocks sign-in from outside named locations")`
    - `ReportOnly` → `("·", "Conditional Access policy is report-only — it doesn't block yet")`
    - `MayApply` → `("·", "a Conditional Access policy may cover this app (filter or app group)")`
    - `None` → `("✗", "no Conditional Access policy locks this app to named locations")`
    - `NotPossible{OtherTenant}` → `("·", "not possible — Conditional Access can't target an app owned by another tenant")`
    - `MultiTenantApp` → `"…a multi-tenant app"`
    - `ManagedIdentity` → `"…a managed identity"`
    - `NoServicePrincipal` → `"…an app with no service principal"`
    - `Unknown` → `("·", "unknown — couldn't read Conditional Access (needs Security Reader or similar)")`
    - Assert that no line contains "scoped", "confined" or "limited to".
  - GUI test `unscopable_group_renders_checklist`: a mocked audit run with one SP-only row holding
    `CallRecords.Read.All` with lock `NotPossible{OtherTenant}`. Expanding "No built-in scoping" shows
    the permission and the "not possible" line.
- [ ] **Step 2: Run them.** `just test-crate azapptoolkit-core -- finding` and `just web-test` fail.
- [ ] **Step 3: Implement.**
  - The marker arm.
  - The `GroupSpec`: title `"No built-in scoping"`, tab `"permissions"`, `GroupSection::Actionable`.
    Blurb: `"Application permissions Microsoft offers no way to narrow (e.g. CallRecords.Read.All), so each reaches the whole tenant. Each row lists the safeguards around the app; none of them narrows what it can read."`
  - The checklist renders one line per grant: the value, a risk `Badge`, the lock line, and
    `"Microsoft can narrow this with {label}; this toolkit doesn't manage it yet."` when the grant has a
    mechanism. Then, per row:
    - credentials (certificate only / uses a secret / none) for Application rows;
    - owners (from the `NO_OWNERS` / `SINGLE_OWNER` markers) for Application rows;
    - last sign-in, reusing `last_sign_in_cell`.
  - The Detail cell uses the checklist when `key == "unscopable_privileged"`, and `issue_lines_for`
    otherwise.
- [ ] **Step 4: Run the gates.** `just test-crate azapptoolkit-core`, `just web-test`, and the audit GUI
  shard all pass.
- [ ] **Step 5: Commit** `feat(desktop): Security workbench group for permissions with no built-in scoping`.

### Task 8: Permission-row badge, picker note, wizard warning

**Files:**
- Modify: `apps/desktop/web-rs/src/components/scope_badge.rs` (`ScopeCell` :79, `scope_cell_for` :109, `permission_scope_cell` :147)
- Modify: `apps/desktop/web-rs/src/components/permission_picker.rs` (`scope_hint_note` :262)
- Modify: `apps/desktop/web-rs/src/components/scope_wizard.rs` (review step, beside `strip_warning` :1084)
- Test: the unit tests in those files, plus a GUI test in the shard holding the permissions-tab / wizard tests

**Interfaces:**
- Consumes: `is_unscopable_privileged`, `unmanaged_mechanism_for`, `UnmanagedMechanism::label`.
- Produces: `ScopeCell::NoBuiltInScoping(Option<UnmanagedMechanism>)`.

- [ ] **Step 1: Write the failing tests.**
  - `scope_cell_for(Some("CallRecords.Read.All"), Some(G), None, true, false) == ScopeCell::NoBuiltInScoping(None)`.
  - The same value with `is_application = false` gives `NotApplicable`.
  - `Chat.Read.All` gives `NoBuiltInScoping(Some(ResourceSpecificConsent))`.
  - `permission_scope_reach_is_unstated` stays false for it.
  - `scope_hint_note(G, "CallRecords.Read.All") == Some((false, "Tenant-wide — Microsoft offers no way to narrow this permission.".into()))`.
  - `scope_hint_note(G, "Chat.Read.All")` ends with `"Microsoft can narrow it with per-team (resource-specific) consent; this toolkit doesn't manage that yet."`.
  - GUI test: the wizard review step with `CallRecords.Read.All` in the cart shows a warn `Callout`
    containing `"Microsoft offers no way to narrow"`.
- [ ] **Step 2: Run them.** `just web-test` fails.
- [ ] **Step 3: Implement.**
  - The new arm runs before `NotApplicable`. Badge: label `"No built-in scoping"`, `BadgeTone::Warning`,
    title `"Microsoft offers no way to narrow this permission — it reaches the whole tenant"` plus the
    mechanism sentence when there is one.
  - The `scope_hint_note` arm comes after the `least_privilege_alternative_for` miss. That needs the `?`
    early return there restructured.
  - The wizard warning lists the cart's Application items for which `is_unscopable_privileged` is true.
    Copy: `"{values}: Microsoft offers no way to narrow these, so the app will reach the whole tenant with each."`
- [ ] **Step 4: Run the gates.** `just web-test` and the shard pass.
- [ ] **Step 5: Commit** `feat(desktop): flag permissions with no built-in scoping on rows and at grant time`.

### Task 9: Docs and the full gate

**Files:**
- Modify: `docs/architecture/audit-findings-and-remediation.md`: a Rule 24 row in the table at :16, plus a
  "No built-in scoping" section covering the classifier, exclusions, network-lock verdict and the
  unavailable-vs-gap split.
- Modify: `.claude/rules/scoping-and-audit.md`: one bullet.
- Modify: `AGENTS.md`: one sentence under *Audit & remediation*, only if `repo_invariants/release.rs`
  keeps it under 18 000 bytes.
- Modify: `CHANGELOG.md`, `[Unreleased]` → `### Added`:
  `- The Security tab flags permissions Microsoft offers no way to narrow, with each app's safeguards.`

- [ ] **Step 1: Write the docs.** `just test-crate desktop --test repo_invariants` passes (AGENTS.md size,
  CHANGELOG format).
- [ ] **Step 2: Run `just verify`.** Every stage passes.
- [ ] **Step 3: Run the CI gates in pieces.** `just _verify-core audit web-audit deny web-deny machete`,
  then all four GUI shards with the matching chromedriver (see memory), then `just web-itest-size`.
- [ ] **Step 4: Commit** `docs: no built-in scoping finding`.
- [ ] **Step 5: Manual check (user).** In `just dev` against a test tenant:
  - an app holding `CallRecords.Read.All`, with and without a workload-identity block policy;
  - a vendor (multi-tenant) app holding it.
