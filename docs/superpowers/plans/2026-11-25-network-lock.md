# Network Lock (B2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** From an app registration's Conditional Access tab, an operator can:
- create a report-only policy that blocks the app's sign-ins outside chosen named locations;
- see what it would have blocked;
- turn it on, or remove it.

**Architecture:**
- **Core** (pure): builds the lock body, identifies the toolkit's own lock, validates CIDRs.
- **Graph client:** gains a Conditional Access write token and six calls, plus a beta service-principal
  sign-in read.
- **Commands:** five commands that re-resolve everything live and verify before each write.
- **UI:** a "Network lock" section heads the Conditional Access tab.

**Tech Stack:** Rust 2024, Tauri 2, Leptos 0.8, Microsoft Graph v1.0 (+ beta for sign-ins).

**Spec:** `docs/superpowers/specs/2026-11-25-safeguards-design.md` (B2, plus resolutions 1, 2, 5)

## Global Constraints

- **Writes.** The lock is always created `enabledForReportingButNotEnforced`. Enable and remove act
  only on `toolkit_lock_for`'s policy: prefix `azapptoolkit network lock — `, `includeServicePrincipals`
  exactly `[sp]`, the exact lock shape. Otherwise refuse with `not_a_toolkit_lock`.
- **Named locations** the toolkit creates are `isTrusted: false`. CIDRs with prefix length 0 are refused.
- **Eligibility.** Single-tenant app registrations with a service principal only
  (`lock_ineligibility_for_app` is `None`); anything else is refused (`lock_not_possible`).
- **Policy body** (Microsoft Learn workload-identity sample, plus the documented required
  `clientAppTypes`):

  ```json
  {"displayName":"azapptoolkit network lock — <app>","state":"enabledForReportingButNotEnforced",
   "conditions":{"applications":{"includeApplications":["All"]},
     "clientApplications":{"includeServicePrincipals":["<sp object id>"]},
     "clientAppTypes":["all"],
     "locations":{"includeLocations":["All"],"excludeLocations":["<named location ids>"]}},
   "grantControls":{"operator":"OR","builtInControls":["block"]}}
  ```

  The user's manual test confirms Graph accepts it.
- **Missing Workload Identities Premium licence:** a Graph 400/403 whose body mentions "workload
  identit" maps to `workload_identity_license_required`, with the message "Creating or changing a
  Conditional Access policy for an app needs a Microsoft Entra Workload ID Premium licence." The exact
  error isn't documented; the user's manual test confirms it.
- **Scopes and roles.** New `ConsentFeature::ConditionalAccessWrite` (wire key
  `conditional_access_write`) = `Policy.Read.All` + `Policy.ReadWrite.ConditionalAccess`. New capability
  `conditional_access_lock`: Conditional Access Administrator, then Security Administrator, then
  Global Administrator.
- **Report-only readout:** beta `auditLogs/signIns` filtered to this app's service-principal sign-ins
  over 7 days, with header `Prefer: include-unknown-enum-members`. It counts sign-ins whose
  `appliedConditionalAccessPolicies` entry for the lock's id has `result == "reportOnlyFailure"`, plus
  up to 5 distinct `ipAddress`es. Uses the `audit_log` feature. If it is unavailable, the readout is
  `None` and the confirm says so.
- **Cache.** Every write calls `invalidate_app_detail_state` on `Ok` only.
- **Conventions.** CHANGELOG ≤ 120 chars. Commits use scope `core` / `graph` / `auth` / `desktop`.
  Format web-rs with `cargo fmt` inside it.

## Review Focus

1. Another policy already locks the app (tenant-wide `ServicePrincipalsInMyTenant`): the tab offers
   no Create, Turn on or Remove for it. Test in Task 5.
2. The toolkit lock was set to `disabled` in the portal: the tab shows "turned off outside the
   toolkit" with Turn on / Remove, never Create. Test in Task 5.
3. Someone edited the toolkit lock in the portal, adding a second service principal: enable and remove
   refuse. Test in Task 1.
4. A named location id in the request that doesn't exist, or isn't a GUID: refused before any write.
   Test in Task 4.
5. The named location got created but the policy create failed: the result names the created location
   and returns the error. Test in Task 4.

---

### Task 1: Core — lock body, toolkit-lock identity, CIDR validation

**Files:** `crates/azapptoolkit-core/src/conditional_access.rs`

**Interfaces (produces):**
- `pub const TOOLKIT_LOCK_PREFIX: &str = "azapptoolkit network lock — ";`
- `pub fn lock_display_name(app_display_name: &str) -> String`: prefix + name, cut at 256 chars on a
  char boundary.
- `pub fn lock_policy_body(display_name: &str, sp_object_id: &str, excluded_location_ids: &[String]) -> serde_json::Value`
  (the Global Constraints body).
- `pub fn toolkit_lock_for<'a>(policies: &'a [ConditionalAccessPolicy], sp_object_id: &str) -> Option<&'a ConditionalAccessPolicy>`:
  any state (enabled, report-only, disabled). It requires:
  - the prefix;
  - `include_service_principals` is exactly one entry, equal to sp case-insensitively;
  - `include_applications == ["All"]`;
  - `include_locations` contains `All` and `exclude_locations` is non-empty;
  - `block`;
  - no risk levels.
- `pub fn parse_cidr(s: &str) -> Result<(bool /*ipv6*/, String /*canonical text*/), CidrError>`:
  trims, splits on `/`, parses the address with `std::net::IpAddr` and the prefix as `u8` (v4 ≤ 32,
  v6 ≤ 128), refuses prefix 0. `pub enum CidrError { Malformed, PrefixZero }`.

- [ ] **Step 1: Write the failing tests.**
  - `lock_body_round_trips_as_a_report_only_lock`: deserialize `lock_policy_body(..)` into
    `ConditionalAccessPolicy`. Then:
    - `network_lock_for(&[p], SP, GRAPH)` gives `ReportOnly`;
    - setting `state = "enabled"` gives `Enforced`;
    - `toolkit_lock_for` finds it in every state, including `disabled`.
  - `toolkit_lock_for_refuses_foreign_or_changed_policies`: each of these is `None`:
    - no prefix;
    - two service principals;
    - `ServicePrincipalsInMyTenant`;
    - `includeLocations` without `All`;
    - no `block`;
    - risk levels set.
  - `parse_cidr_table`:

    | input | result |
    |---|---|
    | `"10.0.0.0/8"` | `Ok((false,"10.0.0.0/8"))` |
    | `" 2001:db8::/32 "` | `Ok((true,"2001:db8::/32"))` |
    | `"0.0.0.0/0"` | `PrefixZero` |
    | `"::/0"` | `PrefixZero` |
    | `"10.0.0.0/33"` | `Malformed` |
    | `"10.0.0.0"` | `Malformed` |
    | `"nope/8"` | `Malformed` |

  - `lock_display_name_caps_at_256`.
- [ ] **Step 2: Run them.** `just test-crate azapptoolkit-core -- conditional_access` fails to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** `just test-crate azapptoolkit-core` passes.
- [ ] **Step 5: Commit** `feat(core): Conditional Access network-lock body and toolkit-lock identity`.

### Task 2: Graph client — CA write token, policy and named-location calls, SP sign-ins

**Files:**
- `crates/azapptoolkit-graph/src/client.rs`: token field `conditional_access_write`,
  `with_conditional_access_write_token`, accessor `conditional_access_write_token()`, `None` init.
- `crates/azapptoolkit-graph/src/client/conditional_access.rs`: new, plus `mod` in `client.rs`.
- `crates/azapptoolkit-core/src/models.rs`: `NamedLocation`, `IpRange`, `SignIn`,
  `AppliedConditionalAccessPolicy`.
- Tests: `crates/azapptoolkit-graph/src/client/tests/conditional_access.rs` (+ mod).

**Interfaces (produces), all `pub async fn` on `GraphClient`:**
- `list_named_locations(&self) -> Result<Vec<NamedLocation>>`: `policy_token`, `$top`, paged via
  `collect_pages_from`.
- `create_ip_named_location(&self, display_name: &str, cidrs: &[(bool, String)]) -> Result<NamedLocation>`:
  `isTrusted: false`; each range is `@odata.type` `#microsoft.graph.iPv4CidrRange` or `iPv6CidrRange`.
- `get_ca_policy(&self, id: &str) -> Result<ConditionalAccessPolicy>`
- `create_ca_policy(&self, body: &serde_json::Value) -> Result<ConditionalAccessPolicy>`
- `set_ca_policy_state(&self, id: &str, state: &str) -> Result<()>`
- `delete_ca_policy(&self, id: &str) -> Result<()>`
  - The last four use `conditional_access_write_token()` and run `require_path_segment("policy id", id)?`.
- `list_service_principal_sign_ins(&self, app_id: &str, since: Timestamp) -> Result<Vec<SignIn>>`:
  - `{beta}/auditLogs/signIns`;
  - `$filter=appId eq '<escaped>' and createdDateTime ge <since> and signInEventTypes/any(t: t eq 'servicePrincipal')`;
  - `$top`, header `Prefer: include-unknown-enum-members`, `audit_log_token`;
  - paged, capped at 1 000 rows.

  A GET that needs the `Prefer` header may require a small transport addition next to `scoped_get_retried`.

**Models:**
- `NamedLocation { id: Option<String>, display_name: Option<String>, #[serde(rename="@odata.type")] odata_type: Option<String>, is_trusted: Option<bool>, ip_ranges: Vec<IpRange> }`
- `IpRange { cidr_address: Option<String> }`
- `SignIn { created_date_time: Option<Timestamp>, ip_address: Option<String>, applied_conditional_access_policies: Vec<AppliedConditionalAccessPolicy> }`
- `AppliedConditionalAccessPolicy { id: Option<String>, display_name: Option<String>, result: Option<String> }`

All camelCase, `null_to_default` on the vectors.

- [ ] **Step 1: Write the failing wiremock tests.**
  - `create_ca_policy_posts_the_body_with_the_ca_write_token`
  - `set_ca_policy_state_patches_state_only`
  - `delete_ca_policy_deletes`
  - `policy_id_is_shape_checked`: `"a/b"` → `Protocol`, with no request sent.
  - `create_ip_named_location_is_untrusted_with_typed_ranges`
  - `list_named_locations_pages_with_top`
  - `sp_sign_ins_filter_and_prefer_header`: asserts the query contains `signInEventTypes/any` and
    `appId eq`, and the `Prefer` header.
- [ ] **Step 2: Run them.** `just test-crate azapptoolkit-graph -- conditional_access` fails.
- [ ] **Step 3: Implement.** Mirror `client/policies.rs`. `repo_invariants/trust.rs` (path splices) and
  `fanout.rs` (`$top`) must stay green.
- [ ] **Step 4: Run them.** `just test-crate azapptoolkit-graph` and
  `just test-crate desktop --test repo_invariants` pass.
- [ ] **Step 5: Commit** `feat(graph): Conditional Access policy, named-location and SP sign-in calls`.

### Task 3: Auth — consent feature, token wiring, capability

**Files:**
- `crates/azapptoolkit-auth/src/service/scopes.rs`: `default_graph_conditional_access_write_scopes()`,
  plus its pinning test.
- `apps/desktop/src-tauri/src/state.rs`:
  - a `ConditionalAccessWrite` variant, `ALL` = 13;
  - `as_str`/`parse` key `conditional_access_write`;
  - a `feature_scopes` arm;
  - `ensure_conditional_access_write_token`;
  - `graph_for` wiring with `.with_conditional_access_write_token(...)` (CAE adapter like the policy
    token).
- `crates/azapptoolkit-core/src/capabilities.rs`: `conditional_access_lock` right after
  `conditional_access`:
  - plane `EntraDirectory`; roles as in Global Constraints, with template ids;
  - scopes `Policy.Read.All`, `Policy.ReadWrite.ConditionalAccess`;
    `scope_feature: Some("conditional_access_write")`;
  - remediation: "Locking an app to named locations needs the Policy.ReadWrite.ConditionalAccess scope, the Conditional Access Administrator role and a Microsoft Entra Workload ID Premium licence."
- Docs: `docs/architecture/auth-and-consent.md` (scope table, token list),
  `docs/operator-rbac/OPERATOR-ROLES.md` (role and scope lists).

- [ ] **Step 1: Write the failing test.** Extend `consent_feature_keys_round_trip` for the new key. The
  existing `every_consent_feature_has_a_catalog_row` will then fail until the catalog row exists.
- [ ] **Step 2: Run it.** `just test-crate desktop --lib -- consent_feature` fails to compile.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** `just test-crate azapptoolkit-auth`, `just test-crate azapptoolkit-core`
  and `just test-crate desktop --lib` pass.
- [ ] **Step 5: Commit** `feat(auth): Conditional Access write consent and lock capability`.

### Task 4: Commands — read status, list locations, create / enable / remove

**Files:**
- `apps/desktop/src-tauri/src/commands/network_lock.rs` (new, + `commands/mod.rs`)
- `lib.rs` `generate_handler![]`
- `crates/azapptoolkit-dto/src/conditional_access.rs`
- `apps/desktop/web-rs/src/bindings/conditional_access.rs`
- `apps/desktop/web-rs/src/demo/mod.rs` (+ `ipc_mock/fixtures.rs`) for the two reads

**Interfaces (produces):**
- DTOs:
  - `NamedLocationDto { id, display_name, is_trusted: bool, range_count: u32 }`
  - `ToolkitLockDto { policy_id, state: String, excluded_locations: Vec<NamedLocationDto> }`
  - `ReportOnlyReadout { would_block: u32, sample_ips: Vec<String>, window_days: u32 }`
  - `NetworkLockStatus { ineligible: Option<LockIneligible>, toolkit_lock: Option<ToolkitLockDto>, other: NetworkLock, other_policy_name: Option<String>, readout: Option<ReportOnlyReadout> }`
  - `NewLocationArgs { name, cidrs: Vec<String> }`
  - `CreatedLock { policy_id, created_location_id: Option<String> }`
- Commands:
  - `get_network_lock(tenant_id, app_id) -> Result<NetworkLockStatus, UiError>`
  - `list_named_locations(tenant_id) -> Result<Vec<NamedLocationDto>, UiError>` (IP locations only)
  - `create_network_lock(tenant_id, app_id, named_location_ids: Vec<String>, new_location: Option<NewLocationArgs>) -> Result<CreatedLock, UiError>`
  - `enable_network_lock(tenant_id, app_id, policy_id) -> Result<(), UiError>`
  - `remove_network_lock(tenant_id, app_id, policy_id) -> Result<(), UiError>`
- Pure helpers:
  - `fn readout_from(sign_ins: &[SignIn], policy_id: &str) -> ReportOnlyReadout`
  - `fn map_lock_write_err(err: GraphError) -> UiError`

Every command runs, in order:
1. `require_app_id`
2. `prove_tenant_session`
3. `ensure_feature_token(.., Policy)` for reads, `ConditionalAccessWrite` for writes
4. live SP (`get_service_principal_by_app_id`)
5. live app (`find_application_by_app_id`) → eligibility
6. live policies → `toolkit_lock_for`

On top of that:
- **`create`:**
  - refuses `lock_exists` when a toolkit lock exists;
  - refuses `no_locations` when no ids and no new location are given;
  - validates each id as a GUID (`invalid_location_id`);
  - checks each id exists among the live IP named locations (`unknown_location`);
  - `parse_cidr`s every new CIDR (`invalid_cidr` names the line);
  - creates the location first, then the policy.

  If the policy create fails after the location was created, it returns the mapped error, with the
  message naming the created location so the operator can reuse or delete it.
- **`enable` / `remove`:** refuse `not_a_toolkit_lock` unless `policy_id ==
  toolkit_lock_for(..).id`. Remove deletes the policy only, and the named location stays.
- **The `get` readout:** only when the toolkit lock is report-only. `ensure_audit_log_token` plus the
  sign-in read; any failure → `None`.

- [ ] **Step 1: Write the failing tests** (pure, `#[cfg(test)]` in `network_lock.rs`).
  - `readout_counts_report_only_failures_for_this_policy`: other policies' results and
    `reportOnlySuccess` are ignored; the IPs are distinct, at most 5.
  - `lock_write_licence_error_is_typed`: a `Forbidden` body containing "Workload Identities" →
    `workload_identity_license_required`. Other 403s pass through to `graph_err` mapping.
  - `create_validation_refuses_bad_input`, a pure `validate_create(ids, new_location, live_locations)`:
    - non-GUID id;
    - unknown id;
    - `0.0.0.0/0`;
    - empty input.
- [ ] **Step 2: Run them.** `just test-crate desktop --lib -- network_lock` fails to compile.
- [ ] **Step 3: Implement** the commands, register them, add bindings, add DTOs, and add demo fixtures
  for `get_network_lock` and `list_named_locations`. `repo_invariants` (`ipc`, `trust`, `cache`,
  `commands`) must stay green.
- [ ] **Step 4: Run them.** `just test-crate desktop`, `just web-test`, `just check`.
- [ ] **Step 5: Commit** `feat(desktop): commands to create, enable and remove a network lock`.

### Task 5: UI — Network lock section on the Conditional Access tab

**Files:**
- `apps/desktop/web-rs/src/views/tabs/conditional_access_tab.rs`: a `NetworkLockSection` inside
  `ConditionalAccessTab`, above the panel; the panel gains an optional `reload` signal.
- `apps/desktop/web-rs/src/views/dialogs/network_lock_dialog.rs`: new, the create modal.
- `apps/desktop/web-rs/tests/confirmation_tiers.rs`: rows for the Turn on / Remove confirms.
- `apps/desktop/web-rs/src/views/audit_view/unscopable_checklist.rs`: the `None` lock line appends
  " — set one up on the app's Conditional Access tab".
- GUI test: `apps/desktop/web-rs/tests/gui/network_lock.rs` (+ `gui_3.rs` mod).

**Behaviour** (states from `NetworkLockStatus`):

| state | shows |
|---|---|
| `ineligible = Some(r)` | the `NotPossible` reason text from the checklist, no buttons |
| `toolkit_lock` report-only | "Report-only — not blocking yet"; readout line "In the last 7 days, N sign-ins would have been blocked (from: ips…)" or "Couldn't check what it would have blocked"; buttons **Turn on lock**, **Remove** |
| `toolkit_lock` enabled | "Blocking sign-ins from outside: <locations>"; **Remove lock** |
| `toolkit_lock` disabled | "Turned off outside the toolkit"; **Turn on lock**, **Remove** |
| no toolkit lock, `other == Enforced` | "Locked by <other_policy_name> — not managed here", no buttons |
| no toolkit lock, otherwise | explanation; **Lock to trusted locations…** |

- **The create modal** (`ModalShell`):
  - a checkbox list of IP named locations (`.checkbox-row`);
  - optional "New named location" name `Input` plus a CIDR `Textarea` (`parse_lines`);
  - the note "Created report-only: nothing is blocked until you turn it on. New locations are created
    untrusted.";
  - `FormError`, and a Create button with `Spinner`.
- **The confirms** (`ConfirmDialog`, click-confirm):
  - Turn on: subject "<app>: <readout line>", body "Sign-ins by this app from outside the chosen
    locations will be blocked.";
  - Remove: subject "<app>", body "Deletes the toolkit's lock policy. The named locations stay.".
- Each write runs through `use_command().with_consent_feature("conditional_access_write")`, then bumps
  the shared reload and re-reads status.

- [ ] **Step 1: Write the failing GUI tests** (mocked IPC), one per Review Focus 1 and 2 plus the flows:
  - `none_offers_create_and_creates_report_only`: the modal posts the chosen ids.
  - `report_only_shows_the_readout_in_the_turn_on_confirm`.
  - `a_foreign_lock_offers_no_buttons`.
  - `a_lock_turned_off_in_the_portal_offers_turn_on_and_remove`.

  Plus a unit test for the checklist line change.
- [ ] **Step 2: Run them.** `just web-test` fails, and so does the gui_3 shard.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** `just web-test`, `confirmation_tiers`, `demo_fixture_coverage`, the gui_3 shard.
- [ ] **Step 5: Commit** `feat(desktop): Network lock section on the Conditional Access tab`.

### Task 6: Docs and the full gate

- **Docs:**
  - `docs/architecture/audit-findings-and-remediation.md` (Rule 24: the lock is set up from the tab);
  - `docs/architecture/auth-and-consent.md` (already in Task 3);
  - a new short section "Network lock (B2)" in `docs/architecture/audit-findings-and-remediation.md`:
    toolkit-lock identity, verify-before-write, report-only first, untrusted locations, readout;
  - `.claude/rules/scoping-and-audit.md`: one line.
- **CHANGELOG** `### Added`: `- The Conditional Access tab can lock an app to named locations: report-only first, then turn it on.`
- **Gates:** `just verify`, all four GUI shards, `just audit web-audit deny web-deny machete`,
  `just web-itest-size`.
- [ ] **Commit** `docs: network lock`.
