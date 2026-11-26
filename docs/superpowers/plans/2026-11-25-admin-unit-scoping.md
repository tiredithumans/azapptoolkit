# Admin-unit scoping (C1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator replace a tenant-wide `User/Group/Device.ReadWrite.All` grant with the matching Entra admin role limited to an administrative unit, from the Grant access wizard and the audit, and see the result.

**Architecture:** A new `ScopeKind::AdministrativeUnit` mechanism. Core holds one curated mapping table (permission → role, tenant-wide read, object kind, disclosures). The Graph client gains admin-unit and directory-role reads/writes (writes on a new on-demand consent feature). One backend core applies "assign role at unit scope → ensure tenant-wide read → strip tenant-wide write (gated)" for app registrations and SP-only principals. The audit reads direct, active role assignments once per run and adds Rule 26 (org-wide directory write + Scope fix; healthy limited write, reduced weight). The frontend adds an admin-unit target panel to the wizard, a Directory roles section, and a Scope fix dialog.

**Tech Stack:** Rust 2024; Tauri 2 backend; Leptos 0.8 WASM frontend; Microsoft Graph v1.0; wiremock; wasm-bindgen-test.

**Spec:** `docs/superpowers/specs/2026-11-25-admin-unit-scoping-design.md`

## Global Constraints

- Microsoft Graph resource only: every mapping lookup carries the resource (`MICROSOFT_GRAPH_APP_ID`); a value on another resource never matches.
- Grant first, strip last, fail closed: never remove the tenant-wide permission unless the role assignment and tenant-wide read both landed, the unit wasn't created in this run, and it has members of the permission's object type (dynamic units: processing `On`).
- Never assign at tenant scope: role assignments are built only as `directoryScopeId: "/administrativeUnits/{id}"`; Remove refuses a non-unit scope.
- One permission per wizard run for this mechanism.
- The review always shows the role's "also allows" and "no longer able to" lines.
- Direct, active role assignments only; group-inherited and PIM-eligible are a documented limitation.
- Writes use a new on-demand consent feature `admin_unit_roles` (`RoleManagement.ReadWrite.Directory` + `AdministrativeUnit.ReadWrite.All`, the builder confirms the least set); reads use the sign-in `Directory.Read.All` token and degrade to unknown on 403.
- Capability key `admin_unit_roles` → Privileged Role Administrator (`TID_PRIVILEGED_ROLE_ADMIN`).
- Repo rules (AGENTS.md): tenant-scoped caches invalidated only on `Ok`; every id spliced into a Graph path is shape-checked; commands → `generate_handler!` + typed binding; `DetailLoadError` for load failures; `ConfirmDialog` tiers pinned; demo fixtures for every read; Conventional Commits; CHANGELOG ≤ 120 chars per line.
- AGENTS.md is at its byte budget: no additions there.

## Review Focus

1. **Partial landing** — the role lands but the read grant fails: nothing is stripped, the result says so, and a rerun is idempotent. Test in Task 3 (`a_failed_read_grant_strips_nothing`, `an_existing_assignment_is_idempotent`).
2. **A unit with no members of the right type, or a paused rule** — the tenant-wide permission is kept with the reason. Test in Task 3 (`a_unit_without_members_of_the_type_keeps_tenant_wide`, `a_paused_rule_keeps_tenant_wide`).
3. **A covering tenant-scope role** (same role or Global Administrator) — the result warns; the audit never shows it healthy. Tests in Task 3 (`a_covering_tenant_role_is_reported`) and Task 4 (`a_covering_tenant_role_is_not_healthy`).
4. **Role assignments unreadable during the audit** — unknown, never all-clear: the org-wide finding still shows, no healthy finding. Test in Task 4 (`unreadable_roles_never_read_as_limited`).
5. **A tenant-scope assignment id sent to Remove** — refused (`not_admin_unit_scoped`). Test in Task 3 (`remove_refuses_a_tenant_scope_assignment`).

---

### Task 1: Core — the mapping, the mechanism, the capability

**Files:**
- Create: `crates/azapptoolkit-core/src/scoping/admin_unit.rs` (if `scoping.rs` is a single file, add the module as `scoping/admin_unit.rs` with `#[path]` or convert to `scoping/mod.rs`; either is fine)
- Modify: `crates/azapptoolkit-core/src/scoping.rs` (`ScopeKind::AdministrativeUnit`, `capability_key`, `admin_applicable`, `scope_kind_for`)
- Modify: `crates/azapptoolkit-core/src/audit/unscopable.rs` (drop the three `AdministrativeUnitRole` entries and the variant)
- Modify: `crates/azapptoolkit-core/src/capabilities.rs` (entry `admin_unit_roles`)

**Interfaces — Produces:**
```rust
pub enum AdminUnitMemberKind { User, Group, Device }
pub struct DirectoryWriteMapping {
    pub permission: &'static str,
    pub role_name: &'static str,
    pub role_template_id: &'static str,
    pub read_permission: &'static str,
    pub member_kind: AdminUnitMemberKind,
    pub also_allows: &'static [&'static str],
    pub no_longer: &'static [&'static str],
}
pub const DIRECTORY_WRITE_MAPPINGS: &[DirectoryWriteMapping];
pub const GLOBAL_ADMIN_ROLE_TEMPLATE_ID: &str = "62e90394-69f5-4237-9190-012177145e10";
pub fn directory_write_mapping(resource_app_id: Option<&str>, value: &str) -> Option<&'static DirectoryWriteMapping>;
pub fn is_scopable_directory_write_resource_permission(resource_app_id: Option<&str>, value: &str) -> bool;
/// The reads that satisfy `mapping`'s tenant-wide read: its own, Directory.Read.All, Directory.ReadWrite.All (Graph only).
pub fn satisfies_tenant_read(mapping: &DirectoryWriteMapping, resource_app_id: Option<&str>, value: &str) -> bool;
/// A tenant-scope role that voids a unit limit for `mapping`: the same role or Global Administrator.
pub fn covers_tenant_wide(mapping: &DirectoryWriteMapping, held_role_template_id: &str) -> bool;
/// The membership rule "users whose `attribute` equals `value`", quoting `value`.
pub fn user_rule(attribute: UserRuleAttribute, value: &str) -> String;
pub enum UserRuleAttribute { Department, CompanyName, OfficeLocation, Country, JobTitle, EmployeeType }
```
Values: User.ReadWrite.All → User Administrator `fe930be7-5e62-47db-91af-98c3a49a38b1`, read `User.Read.All`, User; Group.ReadWrite.All → Groups Administrator `fdd7a751-b60b-444a-984c-02652fe8fa1c`, read `Group.Read.All`, Group; Device.ReadWrite.All → Cloud Device Administrator `7698a772-787b-4ac8-901f-60d6b08affd2`, read `Device.Read.All`, Device. The `also_allows` / `no_longer` lines start from the spec's table; verify each line and id against Microsoft's built-in roles reference and cite it in a doc comment.

- [ ] **Step 1: Write the failing tests** (in `admin_unit.rs`):
  - `mapping_carries_the_resource`: Graph `User.ReadWrite.All` maps to User Administrator; the same value with `OFFICE365_EXCHANGE_ONLINE_APP_ID` or `None` → `None`.
  - `every_mapping_discloses_both_ways`: each entry has non-empty `also_allows` and `no_longer`, and a GUID role id.
  - `tenant_read_accepts_broader_reads`: `User.Read.All`, `Directory.Read.All`, `Directory.ReadWrite.All` on Graph satisfy User's mapping; `Group.Read.All` doesn't; a Graph value on another resource doesn't.
  - `covering_roles`: the mapping's own role and Global Administrator cover; Helpdesk Administrator doesn't.
  - `user_rule_quotes`: `user_rule(Department, "Finance")` == `(user.department -eq "Finance")`; a value with `"` is escaped (`\"`).
  - In `scoping.rs` tests: `scope_kind_for(Some(GRAPH), "User.ReadWrite.All") == Some(ScopeKind::AdministrativeUnit)`; `ScopeKind::AdministrativeUnit.capability_key() == "admin_unit_roles"`.
  - In `unscopable.rs` tests: `native_scoping_for(Some(GRAPH), "User.ReadWrite.All")` is `Managed(AdministrativeUnit)` and `is_unscopable_privileged` is false for the three.
  - In `capabilities.rs` tests: the `admin_unit_roles` entry exists, names Privileged Role Administrator, `scope_feature: Some("admin_unit_roles")`.
- [ ] **Step 2: Run** `just test-crate azapptoolkit-core -- admin_unit scoping unscopable capabilities`. Expected: FAIL (missing items).
- [ ] **Step 3: Implement** the items above. `admin_applicable` → `true`.
- [ ] **Step 4: Run** `just test-crate azapptoolkit-core`. Expected: PASS. Then `just check`: the compiler names every exhaustive `ScopeKind` match in web-rs. Keep web-rs compiling with the real mode row (`mode_options` → `&[(ScopeMode::AdminUnit, "Specific admin unit")]`, `default_mode` → `ScopeMode::AdminUnit`) and, for the mode's panel/plan arms, a minimal arm that sets the wizard error "Not available yet" (filled in Task 5). Ledger it as a ruling.
- [ ] **Step 5: Commit** `feat(core): admin-unit scope mechanism and the directory-write mapping`.

### Task 2: Graph client — admin units and directory roles

**Files:**
- Create: `crates/azapptoolkit-graph/src/client/admin_units.rs`, `crates/azapptoolkit-graph/src/client/tests/admin_units.rs`
- Modify: `crates/azapptoolkit-graph/src/client.rs` (module, `admin_unit_roles_token` field + `with_admin_unit_roles_token` + accessor, mirroring `conditional_access_write_token`)
- Modify: `crates/azapptoolkit-core/src/models.rs` (models below)
- Modify: `crates/azapptoolkit-auth/src/service/scopes.rs` (`default_graph_admin_unit_roles_scopes`), `apps/desktop/src-tauri/src/state.rs` (`ConsentFeature::AdminUnitRoles` = `"admin_unit_roles"`, `ALL`, `feature_scopes`, `graph_for` wiring)

**Interfaces — Produces:**
```rust
// models.rs (Graph camelCase, no serde rename)
pub struct AdministrativeUnit { pub id: String, pub display_name: Option<String>, pub membership_type: Option<String>, pub membership_rule: Option<String>, pub membership_rule_processing_state: Option<String>, pub is_member_management_restricted: Option<bool> }
pub struct DirectoryRoleAssignment { pub id: String, pub principal_id: String, pub role_definition_id: String, pub directory_scope_id: String, pub role_definition: Option<DirectoryRoleDefinition> }
pub struct DirectoryRoleDefinition { pub id: String, pub display_name: Option<String>, pub template_id: Option<String> }

// GraphClient
pub async fn list_admin_units(&self) -> Result<Vec<AdministrativeUnit>>;
pub async fn get_admin_unit(&self, id: &str) -> Result<AdministrativeUnit>;
pub async fn create_dynamic_admin_unit(&self, display_name: &str, membership_rule: &str) -> Result<AdministrativeUnit>; // admin_unit_roles token
pub async fn admin_unit_has_members(&self, id: &str, kind: AdminUnitMemberKind) -> Result<bool>; // members/microsoft.graph.{user|group|device}?$top=1&$select=id
pub async fn list_role_assignments_for_principal(&self, principal_id: &str) -> Result<Vec<DirectoryRoleAssignment>>; // $filter=principalId eq '…'&$expand=roleDefinition
pub async fn list_unit_scoped_role_assignments(&self) -> Result<Vec<DirectoryRoleAssignment>>; // tenant read; fallback documented in the builder note below
pub async fn assign_role_at_admin_unit(&self, principal_id: &str, role_template_id: &str, admin_unit_id: &str) -> Result<DirectoryRoleAssignment>; // admin_unit_roles token; builds the scope itself
pub async fn delete_role_assignment(&self, assignment_id: &str) -> Result<()>; // admin_unit_roles token
```
Builder notes: confirm the `$filter`/`$expand` support on v1.0 (`roleManagement/directory/roleAssignments`); if a tenant-wide filter on `directoryScopeId` isn't supported, `list_unit_scoped_role_assignments` lists all assignments (paged, `$top`) and keeps those whose scope starts with `/administrativeUnits/`. Every id spliced into a path runs `validate::require_path_segment`; GUIDs in `$filter` are `escape_odata`d. Every paged read sends `$top`. Writes invalidate nothing in the client caches (no cached kind is affected).

- [ ] **Step 1: Write the failing tests** (wiremock, `tests/admin_units.rs`): one per method asserting method, path, the `$select`/`$filter`/`$expand`/`$top` params and parsing; `assign_role_at_admin_unit_scopes_to_the_unit` asserts the body `{ principalId, roleDefinitionId, directoryScopeId: "/administrativeUnits/{id}" }`; `create_dynamic_admin_unit_body` asserts `membershipType: "Dynamic"`, `membershipRule`, `membershipRuleProcessingState: "On"`; path-splice refusals (`"a/b"` → `GraphError::Protocol`) for `get_admin_unit`, `admin_unit_has_members`, `delete_role_assignment`; writes refuse without the token (`require_token`). In `state.rs` tests: `consent_feature_keys_round_trip` covers `admin_unit_roles`.
- [ ] **Step 2: Run** `just test-crate azapptoolkit-graph -- admin_units`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `just test-crate azapptoolkit-graph`, `just test-crate desktop -- consent_feature`, and `just test-crate desktop --test repo_invariants` (path splices, page sizes, read-throughs). Expected: PASS.
- [ ] **Step 5: Commit** `feat(graph): admin units and directory role assignments`.

### Task 3: Backend commands — apply, list, create, remove

**Files:**
- Create: `apps/desktop/src-tauri/src/commands/admin_units.rs`, `crates/azapptoolkit-dto/src/admin_units.rs`
- Modify: `apps/desktop/src-tauri/src/commands/mod.rs`, `apps/desktop/src-tauri/src/lib.rs` (`generate_handler!`), `crates/azapptoolkit-dto/src/lib.rs`
- Modify: `apps/desktop/web-rs/src/bindings/` (new `admin_units.rs` + `mod.rs`)

**Interfaces — Produces:**
```rust
// dto (serde camelCase)
pub struct AdminUnitDto { pub id: String, pub display_name: String, pub dynamic: bool, pub membership_rule: Option<String>, pub rule_processing_on: bool, pub restricted: bool }
pub enum DirectoryRoleScopeDto { Tenant, AdminUnit { id: String, name: String } } // serde tag = "kind"
pub struct DirectoryRoleDto { pub assignment_id: String, pub role_template_id: String, pub role_name: String, pub scope: DirectoryRoleScopeDto }
pub struct DirectoryWriteScopeResult { pub role_assigned: bool, pub role_already_held: bool, pub read_granted: bool, pub read_already_held: bool, pub orgwide_removed: bool, pub kept_reason: Option<String>, pub covering_role: Option<String>, pub warnings: Vec<String> }

// commands (all prove the session where cache-only; GUID-check every id)
pub async fn list_admin_units(state, tenant_id) -> Result<Vec<AdminUnitDto>, UiError>;
pub async fn create_admin_unit_by_rule(state, tenant_id, display_name: String, membership_rule: String) -> Result<AdminUnitDto, UiError>; // name 1..=256 trimmed, rule 1..=3072
pub async fn list_directory_roles(state, tenant_id, sp_object_id) -> Result<Vec<DirectoryRoleDto>, UiError>; // names AU scopes via get_admin_unit (unreadable name → the id)
pub async fn remove_admin_unit_role(state, tenant_id, sp_object_id, assignment_id) -> Result<(), UiError>; // re-reads the principal's assignments; `not_admin_unit_scoped` unless the scope starts with /administrativeUnits/
pub async fn scope_directory_write(state, tenant_id, sp_object_id, object_id: Option<String>, app_id: String, permission_value: String, admin_unit_id: String, created_now: bool) -> Result<DirectoryWriteScopeResult, UiError>;
pub(crate) async fn scope_directory_write_core(client: &GraphClient, cache: &Cache, principal: &GraphRolePrincipal<'_>, mapping: &DirectoryWriteMapping, admin_unit_id: &str, created_now: bool) -> Result<DirectoryWriteScopeResult, UiError>;
```
`GraphRolePrincipal` (today private in `commands/sharepoint.rs`) becomes `pub(crate)` so both mechanisms share it; `require_same_app` already is.
The core's order is the spec's section 3: re-read (SP pairs with `app_id` via `require_same_app`; app grants; direct assignments; the unit) → assign (an existing identical assignment = `role_already_held`) → ensure read (`satisfies_tenant_read` over held grants; else `grant_app_role` of the mapped read, and on an app registration also declare it, reusing `declare_graph_role` / `graph_role_index`) → strip (`strip_app_role_grants` + declaration removal) only when the gate passes; `kept_reason` copy per cause (just created; no members of the type — for groups: "add groups to the unit in the Entra portal, then Scope… again"; rule paused). `covering_role` names a held tenant-scope covering role. Cache: `invalidate_app_detail_state` on any landed write. 403s splice `forbidden_remediation(&ui, "admin_unit_roles")`. Error mapping for licence / invalid rule / restricted unit: map Graph's message to `admin_unit_licence_required` / `invalid_membership_rule` / `admin_unit_restricted` where recognisable, else pass through.

- [ ] **Step 1: Write the failing tests** (wiremock, in `admin_units.rs`; pattern: `sharepoint_item_scopes.rs` tests with `AppState::for_test` / `mock_graph`):
  - `grant_then_read_then_strip_in_order` (records request order: role POST, read grant, then the strip DELETE and manifest PATCH).
  - `a_failed_role_assignment_strips_nothing`, `a_failed_read_grant_strips_nothing`.
  - `an_existing_assignment_is_idempotent` (`role_already_held`, no POST).
  - `a_held_directory_read_satisfies_the_read` (`Directory.Read.All` held → no read grant).
  - `a_just_created_unit_keeps_tenant_wide`, `a_unit_without_members_of_the_type_keeps_tenant_wide`, `a_paused_rule_keeps_tenant_wide` (each: no strip, `kept_reason` set).
  - `a_covering_tenant_role_is_reported` (`covering_role == Some("User Administrator")`, strip still runs).
  - `an_sp_only_principal_never_touches_a_manifest`.
  - `remove_refuses_a_tenant_scope_assignment`, `remove_refuses_another_principals_assignment`.
  - `create_admin_unit_validates_name_and_rule`.
- [ ] **Step 2: Run** `just test-crate desktop --lib -- admin_units`. Expected: FAIL.
- [ ] **Step 3: Implement** commands, DTOs, bindings (`invoke_result`, camelCase args).
- [ ] **Step 4: Run** `just test-crate desktop` (incl. `repo_invariants` — IPC pins, trust, cache). Expected: PASS.
- [ ] **Step 5: Commit** `feat(desktop): limit directory writes to an admin unit`.

### Task 4: Audit — Rule 26

**Files:**
- Modify: `crates/azapptoolkit-core/src/audit/types.rs` (`AppPermissions.directory_roles: Option<Vec<HeldDirectoryRole>>`, `issue::ORG_WIDE_DIRECTORY_WRITE`, `issue::SCOPED_DIRECTORY_WRITE`, `RemediationKind::ScopeDirectoryWrite`), `audit/scoring.rs` (Rule 26 in both rule sets; remediation attached like `ScopeSharePointAccess`), `audit/finding.rs` (keys), `audit/permissions.rs` (`PTS_SCOPED_HIGH_RISK` = 3, or reuse the mail constant renamed), `audit/mod.rs`
- Modify: `apps/desktop/src-tauri/src/commands/audit/{prefetch,run,score}.rs` (one read per run, joined per principal)
- Test: `audit/scoring/tests.rs`, `commands/audit/tests.rs`

**Interfaces — Produces:**
```rust
pub struct HeldDirectoryRole { pub role_template_id: String, pub admin_unit: Option<(String, String)> } // None = tenant scope; (id, name)
pub const issue::ORG_WIDE_DIRECTORY_WRITE: &str = "Organization-wide directory write:";
pub const issue::SCOPED_DIRECTORY_WRITE: &str = "Directory writes limited to admin units:";
pub enum RemediationKind { …, ScopeDirectoryWrite } // targets = the org-wide values
```
Rule 26 (`rule_directory_write`, net-new, no PowerShell citation): org-wide holders (`is_scopable_directory_write_resource_permission`) → `ORG_WIDE_DIRECTORY_WRITE: <values>` + the Fix, no extra score; for each mapping whose role is held at a unit scope, the permission not held tenant-wide, `directory_roles` is `Some`, and no covering tenant role → `SCOPED_DIRECTORY_WRITE: User Administrator (Finance)` + `PTS_SCOPED_HIGH_RISK` per role. `None` roles → no healthy line. Finding keys `orgwide_directory_write` (actionable) and `scoped_directory_write` (healthy, a posture bucket like `scoped_sites` if that one is).

- [ ] **Step 1: Write the failing tests** (table-driven, `scoring/tests.rs`): org-wide holder → issue + one `ScopeDirectoryWrite` remediation + no extra score; limited (role at unit, no permission) → healthy issue + 3 points; `a_covering_tenant_role_is_not_healthy`; `unreadable_roles_never_read_as_limited` (`directory_roles: None` + permission held → org-wide finding, no healthy); SP-only rule set includes Rule 26; finding-marker exclusivity rows for both keys. In `commands/audit/tests.rs`: the prefetch joins assignments to principals by SP object id, and an unreadable read leaves every row `None` (no gap added).
- [ ] **Step 2: Run** `just test-crate azapptoolkit-core -- audit` and `just test-crate desktop --lib -- audit`. Expected: FAIL.
- [ ] **Step 3: Implement.** The prefetch uses `list_unit_scoped_role_assignments` plus the tenant-scope assignments needed for the covering check (one combined read if Task 2's fallback lists all; else two). Spawned after the audit watch capture, like the usage prefetch.
- [ ] **Step 4: Run** both suites in full. Expected: PASS.
- [ ] **Step 5: Commit** `feat(core): audit Rule 26 — org-wide directory writes and admin-unit limits`.

### Task 5: Frontend — wizard mechanism and the row gates

**Files:**
- Create: `apps/desktop/web-rs/src/components/admin_unit_panel.rs` (pick or create; used by the wizard and Task 6's Fix)
- Modify: `components/scope_wizard.rs` (`ScopeMode::AdminUnit`, `mode_options`, `default_mode`, `consent_scope` → `"admin_unit_roles"`, `mode_panel`, the `Plan` arm calling `scope_directory_write`, `targets_label` / `review_targets` / `strip_warning` / `review_line`, `cart_mechanism` single-item gate for this kind, reset), `views/tabs/permissions_tab.rs` (`row_scope_kind`), `components/held_permissions_panel.rs` (`is_held_scopable`), `components/mod.rs`
- Test: `web-rs/tests/gui/scope_wizard.rs` (gui_3), unit tests in `scope_wizard.rs`

**Interfaces — Consumes:** Task 1 mapping (WASM-safe core), Task 3 bindings. **Produces:** `AdminUnitPanel { member_kind: AdminUnitMemberKind, selected: RwSignal<Option<AdminUnitDto>>, created_now: RwSignal<bool> }`.

Panel behaviour: lists units (`list_admin_units`, `DetailLoadError` on failure, skeleton while loading); a group permission disables dynamic units with "dynamic rules can't add groups"; "Create by rule" — users: attribute `Select` + value → `user_rule`, plus "Advanced rule"; devices: advanced only; groups: no create, a line pointing to the Entra portal; Create calls `create_admin_unit_by_rule` (consent feature `admin_unit_roles` via `use_command().with_consent_feature`), selects the new unit and sets `created_now`. Copy: membership takes a while to calculate; needs Entra ID P1 per member.

Review lines: the role, the unit, the tenant-wide read, each `also_allows` and `no_longer` line, and either "Removes the tenant-wide <permission>" or why it will be kept.

- [ ] **Step 1: Write the failing tests:** unit — `cart_mechanism` returns `Some(AdministrativeUnit)` for a single `User.ReadWrite.All` and `None` for `User.ReadWrite.All` + `Group.ReadWrite.All`; `mode_options(AdministrativeUnit)` is non-empty and its modes are unique to it (the existing pin). GUI (`scope_wizard.rs`, gui_3): `admin_unit_path_assigns_then_reports_kept_or_removed` (pick an existing unit → review shows the disclosures → apply calls `scope_directory_write` with `adminUnitId`, `permissionValue`, `createdNow: false`); `create_by_rule_builds_the_rule_and_keeps_tenant_wide` (attribute + value → `create_admin_unit_by_rule` receives `(user.department -eq "Finance")`; apply sends `createdNow: true`; the kept reason is shown); `a_group_permission_disables_dynamic_units`.
- [ ] **Step 2: Run** the gui_3 filter `scope_wizard` and `just web-test`. Expected: FAIL.
- [ ] **Step 3: Implement.** Demo fixtures for `list_admin_units` (two units, one dynamic).
- [ ] **Step 4: Run** `just web-test`, `just web-clippy`, gui_3 in full, `just web-itest-size`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(desktop): limit writes to an admin unit from the Grant access wizard`.

### Task 6: Frontend — Directory roles section and the audit Fix

**Files:**
- Create: `apps/desktop/web-rs/src/components/directory_roles_section.rs`
- Modify: `views/tabs/permissions_tab.rs`, `views/enterprise_application_detail_pane/permissions.rs`, `views/managed_identity_detail_pane.rs` (mount the section), `views/dialogs/scope_remediation.rs` (`ScopeDirectoryWriteButton`), `views/audit_view/{groups,row,controller}.rs` (group specs `orgwide_directory_write` Actionable + `scoped_directory_write` Healthy, `group_remediation_kinds`, the exhaustive-kind test list, the row arm, `RowDone`), `web-rs/tests/confirmation_tiers.rs`, demo fixtures (`list_directory_roles`)
- Test: `web-rs/tests/gui/directory_roles.rs` (new, in gui_3 with the permissions tab cluster), `tests/gui/security_findings.rs` (gui_2)

**Interfaces — Consumes:** Task 3 bindings, Task 5 `AdminUnitPanel`.

Plan decision (spec §4 badge): the "Writes limited to <unit>" indicator lives in this section, not on the permission row — once limited, the tenant-wide permission row is gone, and while it is held the row is org-wide by definition, so the row keeps the existing org-wide badge plus **Scope…** (Task 5's gates).

Section: a `DataTable` of the principal's direct, active roles — role name, scope ("Tenant" or the unit's name), and for unit-scoped rows **Remove** (`ConfirmDialog` click-confirm, `confirm_label="Remove role"`, subject `"<role> — <unit>"`; when the principal no longer holds the mapped tenant-wide permission the body adds that its writes to the unit stop). Under it, one line per mapped role held at unit scope: "Writes limited to <unit>", or "Not limited: also holds <role> tenant-wide". Load failure → `DetailLoadError`. Fix dialog: a permission `Select` when the action has more than one target, `AdminUnitPanel`, the same review lines, apply via `scope_directory_write`; SP-only rows pass `object_id: None`.

- [ ] **Step 1: Write the failing tests:** GUI `the_directory_roles_section_lists_and_removes_a_unit_role` (tenant row has no Remove; unit row's Remove confirms with the subject, calls `remove_admin_unit_role` with the assignment id), `a_covering_tenant_role_says_not_limited`; GUI (security_findings) `orgwide_directory_write_group_offers_the_scope_fix` (Fix opens the dialog, apply calls `scope_directory_write`); `confirmation_tiers.rs` row for `confirm_label="Remove role"`; `groups.rs` exhaustive-kind list includes `ScopeDirectoryWrite`.
- [ ] **Step 2: Run** gui_2 `security_findings`, gui_3 `directory_roles`, `just web-test`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `just web-test`, `just web-clippy`, gui_2 and gui_3 in full, `just web-itest-size`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(desktop): directory roles section and the admin-unit Scope fix`.

### Task 7: Docs and the full gate

- `docs/architecture/audit-findings-and-remediation.md`: Rule 26 catalog row; an "Admin-unit scoping (C1)" section (mapping, order, gates, covering role, limitation); the mechanism appears in "To teach the app a new mechanism" examples if useful.
- `.claude/rules/scoping-and-audit.md`: one line.
- CHANGELOG `[Unreleased]`: `### Added` — `- The Grant access wizard can limit an app's user, group or device writes to an administrative unit.`; `### Changed` — `- Apps whose directory writes are limited to an admin unit now score a small amount instead of nothing.`
- [ ] **Gates:** `just verify`, all four GUI shards, `just audit web-audit deny web-deny machete`, `just web-itest-size`.
- [ ] **Commit** `docs: admin-unit scoping`.
