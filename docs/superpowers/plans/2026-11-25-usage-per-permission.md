# Usage per Permission (B1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Each "No built-in scoping" grant shows when a Graph call it could authorize was last seen in
Microsoft Graph activity logs, and calls out a grant with no such call in the log window.

**Architecture:**
- A pure core table of path families per communications permission. It renders one static KQL query
  and matches paths in Rust from the same patterns.
- The audit spawns the query alongside scoring, with a 60 s budget, and fills `UnscopableGrant::last_used`
  in a final pass.
- Failures leave usage `Unknown` with a reason and never degrade the run.

**Tech Stack:** Rust 2024, Tauri 2, Leptos 0.8, Azure Monitor Logs (KQL).

**Spec:** `docs/superpowers/specs/2026-11-25-safeguards-design.md` (B1, plus resolution 3)

## Global Constraints

- Usage never blocks scoring and never adds an `AuditCoverageGap`. Every failure becomes `GrantUsage::Unknown { reason }`.
- The KQL text contains no interpolated input: it is built only from the static family table.
- Only "not seen" is sound evidence. Copy for a seen call says "a call it could authorize", never "used".
- Only communications permissions are tracked. Every other unscopable grant is `NotTracked`.
- `AuditItem` / `UnscopableGrant` wire additions are `#[serde(default)]`.
- CHANGELOG: one line, ≤ 120 chars. Commits use scope `core` / `desktop`. Format web-rs with `cargo fmt` inside `apps/desktop/web-rs`.

## Review Focus

1. A path with the `/beta` prefix, mixed case, or a query string or function-call parentheses
   (`getAllTranscripts(meetingOrganizerUserId='x')`) still maps to its family. Test in Task 1.
2. A transcripts call must not count as an `OnlineMeetings.Read.All` call: the most specific family
   wins. Test in Task 1.
3. A workspace whose retention is shorter than 90 days: `NotSeen` carries the real `since`, not
   "90 days ago". Test in Task 3.
4. A cancelled audit doesn't leave the usage task running. Abort it in Task 3 (code review).
5. An app id in the logs whose case differs from `AuditItem::app_id` still matches. Test in Task 3.

---

### Task 1: Core path families, KQL and matcher

**Files:**
- Create: `crates/azapptoolkit-core/src/audit/usage.rs` (+ `mod usage;` and re-exports in `audit/mod.rs`)

**Interfaces:**
- Produces:
  - `pub fn family_for_path(path: &str) -> Option<&'static str>`: strips `/v1.0` or `/beta`, lower-cases,
    drops the query string, then returns the first family in table order whose segment pattern prefixes
    the path.
  - `pub fn families_for_permission(value: &str) -> &'static [&'static str]`
  - `pub fn graph_usage_kql() -> String`
  - `pub fn graph_usage_since_kql() -> String`
  - `pub const USAGE_WINDOW_DAYS: u32 = 90`
  - `pub enum GrantUsage { Seen { at: Timestamp }, NotSeen { since: Timestamp }, NotTracked, Unknown { reason: UsageUnknownReason } }`
    (serde `tag = "state"`, snake_case; `Default` = `Unknown { reason: NotChecked }`)
  - `pub enum UsageUnknownReason { NotChecked, NoConsent, NoWorkspace, TimedOut, Failed }`
    (serde snake_case)
  - `pub fn grant_usage(value: &str, app_last_seen: &HashMap<&'static str, Timestamp>, since: Timestamp) -> GrantUsage`:
    `NotTracked` if the value has no family; the latest `Seen` across its families; else `NotSeen { since }`.

The family table is ordered most-specific first. A segment pattern `*` matches any one segment; a
pattern segment `p` matches a path segment equal to `p` or starting with `p(`.

| family | permissions | segment patterns |
|---|---|---|
| `meeting_transcripts` | `OnlineMeetingTranscript.Read.All` | `users/*/onlinemeetings/*/transcripts`, `users/*/onlinemeetings/getalltranscripts`, `communications/onlinemeetings/*/transcripts` |
| `meeting_recordings` | `OnlineMeetingRecording.Read.All` | `users/*/onlinemeetings/*/recordings`, `users/*/onlinemeetings/getallrecordings`, `communications/onlinemeetings/*/recordings` |
| `meeting_artifacts` | `OnlineMeetingArtifact.Read.All` | `users/*/onlinemeetings/*/attendancereports` |
| `online_meetings` | `OnlineMeetings.Read.All`, `OnlineMeetings.ReadWrite.All` | `users/*/onlinemeetings`, `me/onlinemeetings`, `communications/onlinemeetings` |
| `call_records` | `CallRecords.Read.All`, `CallRecord-PstnCalls.Read.All` | `communications/callrecords` |
| `calls` | `Calls.AccessMedia.All` | `communications/calls` |
| `channel_messages` | `ChannelMessage.Read.All` | `teams/*/channels/*/messages`, `teams/getallmessages` |
| `chats` | `Chat.Read.All`, `Chat.ReadWrite.All` | `chats`, `users/*/chats` |

- [ ] **Step 1: Write the failing tests.**
  - `family_for_path_table`:

    | path | expected |
    |---|---|
    | `/v1.0/communications/callRecords/abc` | `call_records` |
    | `/beta/communications/callRecords/getPstnCalls(fromDateTime=2026-01-01)` | `call_records` |
    | `/v1.0/users/u1/onlineMeetings/m1/transcripts/t1/content` | `meeting_transcripts` |
    | `/v1.0/users/u1/onlineMeetings/getAllTranscripts(meetingOrganizerUserId='u1')` | `meeting_transcripts` |
    | `/v1.0/users/u1/onlineMeetings/m1` | `online_meetings` |
    | `/v1.0/teams/t1/channels/c1/messages?$top=5` | `channel_messages` |
    | `/v1.0/users/u1/chats` | `chats` |
    | `/v1.0/users/u1/messages` | `None` |
    | `/v1.0/communicationsx/callrecords` | `None` |

  - `every_family_has_a_permission_and_every_tracked_permission_is_risk_weighted`: every table
    permission returns `Some` from `risk_level_for_app_permission`.
  - `graph_usage_kql_is_static_and_names_every_family`: the KQL contains each family key,
    `ago(90d)`, and `summarize LastSeen = max(TimeGenerated) by AppId, Family`, and contains no `{`.
  - `grant_usage_picks_latest_seen_else_not_seen_else_not_tracked`.
- [ ] **Step 2: Run them.** `just test-crate azapptoolkit-core -- audit::usage` fails to compile.
- [ ] **Step 3: Implement `audit/usage.rs`.** The KQL regex for each pattern is generated from its
  segments: `^/(v1\.0|beta)/` + segments joined by `/`, where `*` becomes `[^/]+`, then
  `(/|\(|$)` at the end. The `case()` arms follow table order.
  - Normalized path in KQL: `tolower(tostring(parse_url(RequestUri).Path))`.
- [ ] **Step 4: Run them.** `just test-crate azapptoolkit-core` passes.
- [ ] **Step 5: Commit** `feat(core): Graph activity path families for unscopable permissions`.

### Task 2: Rule 24 carries usage

**Files:**
- Modify: `crates/azapptoolkit-core/src/audit/unscopable.rs` (`UnscopableGrant`)
- Modify: `crates/azapptoolkit-core/src/audit/scoring.rs` (`rule_unscopable_privileged`)
- Test: `crates/azapptoolkit-core/src/audit/scoring/tests.rs`, `types.rs` tests

**Interfaces:**
- Consumes: Task 1 `GrantUsage`, `families_for_permission`.
- Produces: `UnscopableGrant.last_used: GrantUsage` (`#[serde(default)]`). Rule 24 sets `NotTracked`
  for a value with no family, else `Unknown { reason: NotChecked }`.

- [ ] **Step 1: Write the failing tests.**
  - Extend `rule24_lists_unscopable_grants_without_score`: CallRecords → `Unknown { NotChecked }`.
  - Add `rule24_marks_directory_permissions_not_tracked`: `RoleManagement.ReadWrite.Directory` → `NotTracked`.
  - The old-run JSON without `last_used` deserializes to the default.
  - Update the `unscopable()` test helper.
- [ ] **Step 2: Run them.** `just test-crate azapptoolkit-core -- rule24` fails.
- [ ] **Step 3: Implement.** Fix every `UnscopableGrant { … }` literal the compiler names (core, the
  desktop audit tests, the web-rs GUI test).
- [ ] **Step 4: Run them.** `just test-crate azapptoolkit-core` passes, then `just check`.
- [ ] **Step 5: Commit** `feat(core): unscopable grants carry their observed usage`.

### Task 3: Usage prefetch alongside scoring, and the final pass

**Files:**
- Modify: `apps/desktop/src-tauri/src/commands/usage.rs` (`discover_workspace` → `pub(crate)`)
- Modify: `apps/desktop/src-tauri/src/commands/audit/prefetch.rs`
- Modify: `apps/desktop/src-tauri/src/commands/audit/score.rs`
- Modify: `apps/desktop/src-tauri/src/commands/audit/run.rs`
- Test: `apps/desktop/src-tauri/src/commands/audit/tests.rs`

**Interfaces:**
- Consumes: Task 1 (`graph_usage_kql`, `graph_usage_since_kql`, `grant_usage`, `families_for_permission`), Task 2.
- Produces:
  - `pub(crate) struct GraphUsage { since: Timestamp, by_app: HashMap<String /* lower-case appId */, HashMap<&'static str, Timestamp>> }`
  - `pub(crate) type UsagePrefetch = Result<GraphUsage, UsageUnknownReason>`
  - `pub(crate) async fn prefetch_graph_usage(state: &AppState, tenant_id: &str) -> UsagePrefetch`
  - `pub(crate) fn graph_usage_from_tables(rows: &LogsQueryTable, since: &LogsQueryTable, now: Timestamp) -> GraphUsage`.
    Columns are found by name (`AppId`, `Family`, `LastSeen`; `Since`). An unknown family string is
    dropped. A missing `Since` falls back to `now - 90 days`.
  - `pub(crate) fn apply_graph_usage(items: &mut [AuditItem], usage: &UsagePrefetch)`

- [ ] **Step 1: Write the failing tests.**
  - `graph_usage_from_tables_maps_by_column_name`: reordered columns, an unknown family, upper-case appId.
  - `apply_graph_usage_sets_seen_not_seen_and_unknown`:
    - an item holding CallRecords and `RoleManagement.ReadWrite.Directory`, with usage `Ok` showing
      the app's `call_records` seen → `Seen` and `NotTracked`;
    - a different app → `NotSeen { since }`, where `since` is the table's, not `now - 90d`;
    - `Err(TimedOut)` → `Unknown { TimedOut }`, with `NotTracked` left alone.
  - `apply_graph_usage_matches_app_id_case_insensitively`.
- [ ] **Step 2: Run them.** `just test-crate desktop --lib -- graph_usage` fails to compile.
- [ ] **Step 3: Implement.**
  - **The prefetch:**
    - `ensure_log_analytics_token` failing → `NoConsent` when `is_consent_required()`, else `Failed`;
    - `discover_workspace`: `Ok(None)` → `NoWorkspace`, `Err` → `Failed`;
    - both queries run under one `tokio::time::timeout(Duration::from_secs(60), …)`, and `Elapsed` → `TimedOut`;
    - a query `Err` → `Failed`.
  - **In `run_audit`**, before the fan-out:
    - spawn `tokio::spawn(async move { let state = handle.state::<AppState>(); prefetch_graph_usage(&state, &tenant).await })`
      with a cloned `AppHandle`;
    - after phase 2, await it if not cancelled (abort on cancel, and a join error → `Err(Failed)`);
    - then `apply_graph_usage(&mut items, &usage)` before the sort.
  - Not in the `join!`, and no gap.
- [ ] **Step 4: Run them.** `just test-crate desktop --lib` passes, then `just check`.
- [ ] **Step 5: Commit** `feat(desktop): check unscopable grants against Graph activity logs during the audit`.

### Task 4: Checklist usage line

**Files:**
- Modify: `apps/desktop/web-rs/src/views/audit_view/unscopable_checklist.rs`
- Modify: `apps/desktop/web-rs/tests/gui/security_findings.rs` (`unscopable_group_renders_checklist`)

**Interfaces:**
- Produces: `pub(super) fn usage_line(usage: &GrantUsage, now: Timestamp) -> (&'static str, String)`

| usage | mark | text |
|---|---|---|
| `Seen{at}` | `·` | `Last call it could authorize: {fmt_day(at)}` |
| `NotSeen{since}` | `✗` | `No call it could authorize since {fmt_day(since)} — consider removing it` |
| `NotTracked` | `·` | `Usage not tracked for this permission` |
| `Unknown{NoWorkspace}` | `·` | `Usage unknown — no Log Analytics workspace with Microsoft Graph activity logs` |
| `Unknown{NoConsent}` | `·` | `Usage unknown — grant the Log Analytics consent on the Observed Graph activity panel` |
| `Unknown{TimedOut}` | `·` | `Usage unknown — the Graph activity query took too long; re-run the audit` |
| `Unknown{Failed}` / `Unknown{NotChecked}` | `·` | `Usage unknown — couldn't read Microsoft Graph activity logs` |

- [ ] **Step 1: Write the failing tests.** The `usage_lines` unit test covers the table above; no line
  contains "used it" or "scoped". The GUI test's vendor grant gets `last_used: NotSeen { since }`,
  and the test asserts `No call it could authorize since`.
- [ ] **Step 2: Run them.** `just web-test` fails.
- [ ] **Step 3: Implement.** Render under each grant's lock line. Reuse `super::fmt_day` (check it
  exists; otherwise the date helper `last_sign_in_cell` uses).
- [ ] **Step 4: Run them.** `just web-test` and the `gui_2` shard pass.
- [ ] **Step 5: Commit** `feat(desktop): show each unscopable grant's last observed call`.

### Task 5: Docs and the full gate

**Files:**
- `docs/architecture/audit-findings-and-remediation.md` (Rule 24 section: usage bullet)
- `.claude/rules/scoping-and-audit.md` (append to the Rule 24 bullet)
- `CHANGELOG.md` `[Unreleased]` → `### Added`:
  `- The Security tab shows when each unnarrowable permission was last used, from Graph activity logs.`

- [ ] **Step 1: Run the repo invariants.** `just test-crate desktop --test repo_invariants` passes.
- [ ] **Step 2: Run the gates.** `just verify`, all four GUI shards, `just audit web-audit deny web-deny machete`, `just web-itest-size`.
- [ ] **Step 3: Commit** `docs: usage per permission`.
