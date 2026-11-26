# Teams meeting access policy script (C3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate the exact Teams PowerShell that scopes an app's online-meeting permissions to chosen users or one group, from a "Meeting policy…" action.

**Architecture:** A pure, WASM-safe generator in core builds the script from a typed request (injection-safe quoting, GUID checks); a frontend dialog collects the request (reusing `ModalShell`, `DirectorySearch`, `CopyBlock`) and shows the script live. No backend command, no Graph call.

**Tech Stack:** Rust 2024; Leptos 0.8 WASM; wasm-bindgen-test.

**Spec:** `docs/superpowers/specs/2026-11-25-teams-meeting-policy-script-design.md`

## Global Constraints

- Every value lands in a single-quoted PowerShell literal with `'` doubled; comment text has control characters (newlines included) stripped; ids are GUIDs.
- Never generate a `-Global` grant.
- The six gated permissions (Graph only): `OnlineMeetings.Read.All`, `OnlineMeetings.ReadWrite.All`, `OnlineMeetingArtifact.Read.All`, `OnlineMeetingTranscript.Read.All`, `OnlineMeetingRecording.Read.All`, `VirtualEvent.Read.All`.
- Repo rules: one primitive per UI pattern; `ConfirmDialog`-free (nothing is mutated); CHANGELOG ≤ 120 chars.

## Review Focus

1. **A vendor display name containing `'`, a newline or `#>`** — the script stays one statement per line with the name inert. Test in Task 1 (`hostile_names_stay_inert`).
2. **A new policy with no targets** — refused with a message (an unused policy grants nothing); add-to-existing with no targets is allowed. Test in Task 1 (`targets_rules_per_mode`).
3. **A pasted non-GUID object id** — refused, never emitted. Test in Task 1 (`ids_are_guids`).
4. **The operator expects `-Global`** — the dialog says why it isn't offered. Test in Task 2 (`the_dialog_builds_a_users_script_and_never_global`).
5. **A user who already holds another policy** — the new-policy mode warns and points at add-to-existing. Test in Task 2 (same test asserts the warning).

---

### Task 1: Core generator

**Files:** Create `crates/azapptoolkit-core/src/teams_meeting_policy.rs`; modify `crates/azapptoolkit-core/src/lib.rs`.

**Produces:**
```rust
pub const MEETING_POLICY_PERMISSIONS: [&str; 6];
pub fn is_meeting_policy_permission(resource_app_id: Option<&str>, value: &str) -> bool; // Graph, any case
pub enum PolicyMode { New, AddToExisting }
pub enum PolicyTargets { Users(Vec<String>), Group { id: String, rank: Option<u32> } }
pub struct PolicyRequest { pub app_id: String, pub app_name: String, pub policy_name: String, pub mode: PolicyMode, pub targets: PolicyTargets }
pub enum PolicyScriptError { InvalidAppId, InvalidPolicyName, InvalidTarget(String), NoTargets } // + Display
pub fn ps_quote(s: &str) -> String;                 // 'x' with ' doubled
pub fn default_policy_name(app_name: &str) -> String; // "azapptoolkit-" + [A-Za-z0-9-] (spaces → '-'), ≤ 64 chars
pub fn script(req: &PolicyRequest) -> Result<String, PolicyScriptError>;
```
Script shape: comment header (app name sanitised), `Connect-MicrosoftTeams`, then `New-CsApplicationAccessPolicy -Identity '<n>' -AppIds '<id>' -Description 'Created by azapptoolkit for <app>'` or `Set-CsApplicationAccessPolicy -Identity '<n>' -AppIds @{Add='<id>'}`, then one `Grant-CsApplicationAccessPolicy -PolicyName '<n>' -Identity '<guid>'` per user or `… -Group '<guid>' [-Rank n]`, then the checks (`Get-CsApplicationAccessPolicy | Where-Object { $_.AppIds -contains '<id>' } | Format-List Identity, AppIds` and `(Get-CsApplicationAccessPolicy -Identity 'Global').AppIds -contains '<id>'` with a comment that `True` means every user without their own policy is covered) and a note that changes take up to 30 minutes. Policy names: 1–64 of `[A-Za-z0-9 ._-]`.

- [ ] **Step 1: Failing tests:** `quoting_doubles_single_quotes`; `hostile_names_stay_inert` (name `O'Brien\nRemove-Item C:\ #>` → no line starts with `Remove-Item`, the description literal is well-formed); `ids_are_guids` (bad app id, bad user id, bad group id each refused); `targets_rules_per_mode` (New + no users → `NoTargets`; AddToExisting + no users → Ok without any Grant line); `users_and_group_scripts` (exact Grant lines; `-Rank 2` present only when given); `never_a_global_grant` (no line contains `Grant-` and `-Global`); `default_names` (`"Contoso Recorder!"` → `azapptoolkit-Contoso-Recorder`, length cap); `the_six_permissions` (Graph only, any case).
- [ ] **Step 2: Run** `just test-crate azapptoolkit-core -- teams_meeting_policy` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `just test-crate azapptoolkit-core` → PASS.
- [ ] **Step 5: Commit** `feat(core): Teams meeting access policy script generator`.

### Task 2: Dialog and entry points

**Files:** Create `apps/desktop/web-rs/src/views/dialogs/meeting_policy_dialog.rs`; modify `views/dialogs/mod.rs`, `views/tabs/permissions_tab.rs` (row button on a meeting-policy permission), `components/held_permissions_panel.rs` (optional `on_meeting_policy: Callback<()>` rendering the same button), the enterprise and managed-identity panes (pass it, mount the dialog), `views/audit_view/unscopable_checklist.rs` (the TeamsMeetingAccessPolicy line points at the action); test `web-rs/tests/gui/meeting_policy.rs` (gui_3).

**Consumes:** Task 1. **Produces:** `MeetingPolicyDialog { open: Signal<bool>, app_id: Signal<String>, app_name: Signal<String>, on_close: Callback<()> }`.

Dialog: mode radios (New policy / Add to an existing policy), policy name `Input` (prefilled with `default_policy_name`), target radios (Specific users / One group), `DirectorySearch` (Users or Groups scope) — picked users listed with remove buttons, a picked group shown with an optional rank `Input`; in New mode a warn `Callout`: "A user holds one application access policy; granting this one replaces theirs — use Add to an existing policy for users who already have one." A muted line: "-Global isn't offered: it covers every user without their own policy." Output: `CopyBlock` with the script, or `FormError` with the generator's error. Row button: `IconButton` `IconName::UserCheck`, aria-label `Meeting policy for <perm>`, title `Meeting policy…`.

- [ ] **Step 1: Failing GUI tests:** `the_dialog_builds_a_users_script_and_never_global` (mount the dialog; pick two users via mocked `search_users`; script contains both Grant lines and no `-Global` grant; the one-policy warning shows; the -Global note shows); `the_group_mode_builds_one_grant_with_rank`; `the_permissions_tab_offers_meeting_policy_on_online_meetings_rows` (a granted `OnlineMeetings.Read.All` row has the button; a `User.Read.All` row doesn't).
- [ ] **Step 2: Run** gui_3 filter `meeting_policy` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `just web-test`, `just web-clippy`, gui_3 and gui_2 in full, `just web-itest-size` → PASS.
- [ ] **Step 5: Commit** `feat(desktop): generate a Teams meeting access policy script`.

### Task 3: Docs and the gate

- `docs/architecture/audit-findings-and-remediation.md`: a short "Teams meeting access policy (C3)" paragraph under the No-built-in-scoping section.
- `.claude/rules/scoping-and-audit.md`: one sentence appended to the Rule 24 line.
- CHANGELOG `### Added`: `- Online-meeting permissions get a Meeting policy… action that writes the Teams PowerShell to scope them.`
- [ ] **Gates:** `just verify`, all four GUI shards, `just audit web-audit deny web-deny machete`, `just web-itest-size`.
- [ ] **Commit** `docs: Teams meeting access policy script`.
