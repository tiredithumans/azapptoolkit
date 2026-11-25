# Expiring Grants (B3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An operator can put an expiry date on an application-permission grant. The audit then flags
any grant past its date, and a one-click Fix revokes it, and on app registrations also removes it from
the declared API permissions.

**Architecture:**
- The expiry is a tag on the service principal (`azapptoolkit:grantExpiry:v1|<resourceAppId>|<appRoleId>|<YYYY-MM-DD>`).
  Its codec lives in core, so the backend and the WASM frontend share it.
- The SP index selects `tags`, so the audit reads every principal's expiries with no extra call. Tag
  writes go through one per-SP gate, which the HideApp toggle joins.
- A run post-pass adds Rule 25 and its Fix.
- The UI sets expiries in three places: the wizard's org-wide path, the Permissions tab, and the
  held-permissions panel.

**Tech Stack:** Rust 2024, Tauri 2, Leptos 0.8, jiff `civil::Date`.

**Spec:** `docs/superpowers/specs/2026-11-25-safeguards-design.md` (B3, plus resolutions 4 and 6)

## Global Constraints

- **Tag format.** Exactly `azapptoolkit:grantExpiry:v1|<resourceAppId GUID>|<appRoleId GUID>|<YYYY-MM-DD>`,
  at most 256 chars. Decoded as untrusted input: a malformed tag of our family is ignored, never fatal.
- **When an expiry has passed:** `today_utc > expires_on`. A date means the end of that day, UTC.
- **Every service-principal tag write** (expiry set/clear, revoke cleanup, HideApp) runs under
  `state.single_flight("{tenant}|sp_tags|{sp_object_id}")`. It re-reads tags live, edits, writes the
  full set, then calls `record_sp_tags` on `Ok`.
- **Rule 25** fires on the tag alone; the Fix's live re-check decides what is still held. An SP with a
  passed expiry is admitted to the SP-only candidate set. No score.
- **The Fix:**
  - revokes every still-held assignment whose tag is still past its date;
  - on Application rows, removes those declarations in one manifest PATCH;
  - clears the processed tags.

  The confirm names the app and the permissions. Not a bulk action.
- **A failed tag write after a successful grant** is a warning on the wizard result, never a failed grant.
- **Wire changes** (`AuditItem` / `UnscopableGrant` / DTO additions) are `#[serde(default)]`.
- **Cache.** Invalidate only on `Ok`; tags patch the SP index row (they no longer drop the list tier).
- **Conventions.** CHANGELOG ≤ 120 chars. Commits use scope `core` / `graph` / `desktop`. Format
  web-rs with `cargo fmt` inside it. Run `repo_invariants`, `doc`, `web-doc` and both clippies after
  each task that touches their trees.

## Review Focus

1. **HideApp toggled while an expiry is being set:** neither tag is lost (shared gate). Test in Task 3.
2. **A tag on a deleted resource, or a role id the resource no longer defines:** the audit still caches
   (no `PermissionResolution` gap), and the issue shows the GUID. Test in Task 4.
3. **The expiry date is today:** not expired yet. Tomorrow: expired. Test in Task 1.
4. **The Fix runs twice, or someone already revoked the grant by hand:** the tag is cleared and the
   result says "already removed". Test in Task 3.
5. **An app whose SP is past the index cap:** no expiry check, documented, not an error (code review).

---

### Task 1: Core codec

**Files:**
- `crates/azapptoolkit-core/src/audit/grant_expiry.rs` (new)
- `audit/mod.rs` re-exports

**Interfaces (produces):**
- `pub const GRANT_EXPIRY_TAG_FAMILY: &str = "azapptoolkit:grantExpiry:"`
- `pub struct GrantExpiry { pub resource_app_id: String, pub app_role_id: String, pub expires_on: jiff::civil::Date }`
  (Debug, Clone, PartialEq, Eq, Serialize, Deserialize)
- `pub fn encode_expiry_tag(e: &GrantExpiry) -> Option<String>`: `None` when either id isn't a GUID.
  GUIDs are lower-cased.
- `pub fn decode_expiry_tag(tag: &str) -> Option<Option<GrantExpiry>>`: outer `None` = not ours.
- `pub fn expiries_in(tags: &[String]) -> Vec<GrantExpiry>`: the valid ones only.
- `pub fn expiry_has_passed(expires_on: Date, now: Timestamp) -> bool`
- `pub fn with_expiry(tags: &[String], resource_app_id: &str, app_role_id: &str, expires_on: Option<Date>) -> Option<Vec<String>>`:
  removes every tag of our family for this `(resource, role)`, case-insensitively, then adds the new
  one if `Some`. `None` only when the ids aren't GUIDs. Other tags are kept in order.

- [ ] **Step 1: Write the failing tests:**
  - round-trip;
  - upper-case GUIDs normalised;
  - malformed date or GUID → `Some(None)`;
  - a foreign tag (`HideApp`) → `None`;
  - `expiry_has_passed`: date today → false, yesterday → true;
  - `with_expiry`: replace, clear, keeps `HideApp`, and drops a duplicate of the same `(resource, role)`
    in different case.
- [ ] **Step 2: Run them.** `just test-crate azapptoolkit-core -- grant_expiry` fails.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** `just test-crate azapptoolkit-core` passes.
- [ ] **Step 5: Commit** `feat(core): grant-expiry tag codec`.

### Task 2: Graph — SP tag read, SP index carries tags

**Files:**
- `crates/azapptoolkit-graph/src/client/service_principals.rs`:
  - `get_service_principal_tags(sp_id) -> Result<Vec<String>>` (`$select=id,tags`, path-checked,
    uncached);
  - `SP_INDEX_SELECT` + `"tags"`;
  - `sp_index_row` copies `tags`.
- The tests that pin the select and the projection (`client/tests/service_principals.rs:198-205`,
  `:792`) are updated to include tags.
- The desktop test `a_clean_create_is_patched_into_the_warm_lists_without_a_rescan`
  (`commands/applications/mod.rs:1602`) is updated: the patched row now carries the created SP's tags.

- [ ] **Step 1: Write the failing tests.**
  - `get_service_principal_tags_selects_tags` (wiremock).
  - Update the select pin to expect `,tags`.
- [ ] **Step 2: Run them.** They fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** `just test-crate azapptoolkit-graph`, `just test-crate desktop`, `repo_invariants`.
- [ ] **Step 5: Commit** `feat(graph): service-principal tag read; the SP index carries tags`.

### Task 3: Commands — set expiry, revoke expired, the shared tag gate

**Files:**
- `apps/desktop/src-tauri/src/commands/grant_expiry.rs` (new; + `commands/mod.rs`, `lib.rs`)
- `commands/applications/cache.rs` (`record_sp_tags`)
- `commands/enterprise_application.rs` (HideApp under the gate + `record_sp_tags`)
- DTOs in `crates/azapptoolkit-dto/src/permissions.rs`
- Bindings in `web-rs/src/bindings/permissions.rs`

**Interfaces (produces):**
- `pub(crate) fn sp_tags_gate_key(tenant_id: &str, sp_object_id: &str) -> String` → `"{tenant}|sp_tags|{sp}"`
- `pub(crate) fn record_sp_tags(cache: &Cache, tenant_id: &str, sp_object_id: &str, tags: &[String])`:
  patches the cached `sp_index` row (`Patch::Keep` when absent or equal), drops the enterprise list
  entry (its rows carry tags), and calls `invalidate_app_detail_state`.
- `#[tauri::command] set_grant_expiry(tenant_id, sp_object_id, resource_app_id, app_role_id, expires_on: Option<String>) -> Result<(), UiError>`
  - Validation: GUIDs (`invalid_id`); date `YYYY-MM-DD` not in the past (`invalid_date`).
  - `prove_tenant_session`, then:
    1. under the gate: `get_service_principal_tags` → `with_expiry` → `set_service_principal_tags`;
    2. `record_sp_tags` on `Ok`.

  It doesn't check the SP holds the grant (ruling: the wizard writes right after the grant and would
  race replication; Rule 25's live Fix decides).
- `#[tauri::command] remediate_revoke_expired_grants(tenant_id, object_id, principal_kind: AuditPrincipalKind) -> Result<RevokeExpiredResult, UiError>`
  - Resolve the SP: Application → `get_application(object_id)` → `get_service_principal_by_app_id`;
    otherwise `object_id` is the SP.
  - Under the gate, read tags live and take the passed expiries. For each:
    - `resolve_resource_sp(resource_app_id)` (`Ok(None)` → nothing to revoke);
    - `list_app_role_assignments(sp)` once, matching
      `resource_id == res.id && app_role_id == role` → `remove_app_role_assignment`, where `NotFound`
      counts as already gone;
    - name = `res.app_roles` value for the role, else the role id.
  - On Application rows, one manifest PATCH with `remove_declared_access` for the revoked roles
    (`Role` kind).
  - Then `with_expiry(.., None)` for every processed expiry → `set_service_principal_tags` →
    `record_sp_tags`.
  - Returns `RevokeExpiredResult { revoked: Vec<String>, already_gone: Vec<String>, failed: Vec<String> }`
    (permission names) and invalidates on any landed write.
  - Pure helper `fn plan_revocations(expiries, assignments, resource_ids: &HashMap<String /*appId*/, String /*sp id*/>) -> (Vec<(assignment_id, expiry)>, Vec<expiry /*gone*/>)`.
- HideApp (`set_enterprise_app_visibility`) moves under `sp_tags_gate_key` and calls `record_sp_tags`.

- [ ] **Step 1: Write the failing tests** (pure).
  - `plan_revocations_matches_resource_and_role`: an expiry for a role no longer assigned → gone; a
    held one → revoke.
  - `set_grant_expiry_validation`: a past date refused, today accepted, a non-GUID refused.
  - `record_sp_tags_patches_the_index_row_and_keeps_others`: an in-memory `Cache` with an `sp_index`
    entry.
- [ ] **Step 2: Run them.** `just test-crate desktop --lib -- grant_expiry` fails.
- [ ] **Step 3: Implement**, registering the commands and adding bindings. `repo_invariants`
  (`cache`, `ipc`, `trust`, `blocking`) must stay green.
- [ ] **Step 4: Run them.** `just test-crate desktop`, `just web-test`, `just check`.
- [ ] **Step 5: Commit** `feat(desktop): set grant expiries and revoke expired grants`.

### Task 4: Audit Rule 25

**Files:**
- `core/audit/types.rs`:
  - `issue::GRANT_EXPIRED = "Grants past their expiry:"`;
  - `RemediationKind::RevokeExpiredGrants`;
  - `AuditItem.expired_grants: Vec<String>` (names, `#[serde(default)]`).
- `core/audit/unscopable.rs`: `UnscopableGrant.expires_on: Option<Date>` (`#[serde(default)]`).
- `core/audit/finding.rs`: key `expired_grants`.
- `src-tauri/.../audit/score.rs`:
  - `sp_audit_candidates` admission `|| has_passed_expiry`;
  - a run post-pass `apply_grant_expiries(items, ctx, now)` that:
    - reads each row's SP tags from the run SP index;
    - resolves names via `client.resolve_resource_sp`, cached, never through `ResourceResolver`, and on
      any failure falls back to the role GUID, so no gap;
    - pushes the issue + Fix;
    - fills `UnscopableGrant.expires_on` by `(resource_app_id, value)`.
- `run.rs` calls it before `apply_graph_usage`.

- [ ] **Step 1: Write the failing tests.**
  - `sp_audit_candidates_admits_a_passed_expiry`.
  - `grant_expiries_post_pass_flags_and_names`: one tag on Graph `CallRecords.Read.All` past its date, and
    one future.
    - The issue names `CallRecords.Read.All`, and there is one `RevokeExpiredGrants` remediation.
    - The future one only sets `expires_on`.
    - An unresolvable resource names the GUID.
  - Finding-marker exclusivity (core).
- [ ] **Step 2: Run them.** They fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** `just test-crate azapptoolkit-core`, `just test-crate desktop`.
- [ ] **Step 5: Commit** `feat(desktop): audit Rule 25 flags grants past their expiry`.

### Task 5: UI — finding group + Fix, checklist line, set-expiry actions, wizard select

**Files:**
- `web-rs/src/views/audit_view/groups.rs`: `GroupSpec` key `expired_grants`, title "Grants past their
  expiry", tab `permissions`, Actionable; `group_remediation_kinds` arm; the exhaustive-kind test list.
- `web-rs/src/views/audit_view/row.rs` + `controller.rs`: `RevokeExpiredGrantsAction` (`ConfirmDialog`,
  click-confirm, `confirm_label="Revoke"`, subject `"<app>: <names>"`), passing
  `object_id + principal_kind`; `RowDone` arm.
- `web-rs/tests/confirmation_tiers.rs`: a row.
- `web-rs/src/views/audit_view/unscopable_checklist.rs`: under each grant, "· Expires <date>" /
  "✗ Expired <date>" from `expires_on`.
- `web-rs/src/views/dialogs/grant_expiry_dialog.rs` (new): `ModalShell` with a `DateInput` + **Save** /
  **Clear expiry**, calling `set_grant_expiry`.
- `permissions_tab.rs` `view_resolved_row`: an **Expiry…** button on granted Application rows (SP from
  `detail.service_principal`, current expiry from its tags via `expiries_in`).
- `held_permissions_panel.rs`: optional `on_expiry` callback; the enterprise-app permissions caller
  passes it (`resource_app_id` from the row, or omitted when `None`).
- `components/scope_wizard.rs`:
  - an "Expires" `Select` (Never / 7 / 30 / 90 days) shown in the org-wide path;
  - `apply_orgwide` calls `set_grant_expiry` per granted Application item (SP id from
    `GrantResult.client_service_principal_id`, or `target.sp_object_id` on the bare-SP path);
  - a failure becomes a warning.
- Demo fixtures for any new infallible read (none expected).

- [ ] **Step 1: Write the failing tests.**
  - GUI `expired_grants_group_offers_revoke_with_a_named_confirm` (gui_2 security_findings).
  - GUI `the_expiry_dialog_sets_and_clears` (gui_3).
  - The wizard: `orgwide_with_expiry_sets_it_after_granting` (gui_3 scope_wizard).
  - Unit: the checklist expiry line.
- [ ] **Step 2: Run them.** They fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run them.** `just web-test`, `web-clippy`, the gui_2 and gui_3 shards, `repo_invariants`.
- [ ] **Step 5: Commit** `feat(desktop): set grant expiries and revoke expired ones from the Security tab`.

### Task 6: Docs and the full gate

- `docs/architecture/audit-findings-and-remediation.md`: Rule 25 row + "Expiring grants (B3)" section.
- `docs/architecture/caching-and-search.md`: the SP index now selects tags; tag writes patch the row.
- `.claude/rules/backend-commands-and-caches.md`: the tags line.
- `.claude/rules/scoping-and-audit.md`: one line.
- CHANGELOG `### Added`: `- Application-permission grants can be given an expiry date; the Security tab flags and revokes expired ones.`
- Gates: `just verify`, all four GUI shards, `audit`/`deny`/`machete`, `web-itest-size`.
- [ ] **Commit** `docs: expiring grants`.
