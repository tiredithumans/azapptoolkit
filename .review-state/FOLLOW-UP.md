# Review follow-up — items not yet implemented

Remaining work from the 2026-09-26 review (`azapptoolkit-review-2026-09-26.md`) after #281 merged.

## Tier 3 — DONE on `chore/review-follow-up` (2026-10-02)
- F230 tokio feature trim → `fb53f42` (+ web-rs lockfile sync `6958df9`)
- F299 hand-mirrored tauri-cli version literal → `d5c0e12`
- F285 updater signing key scoped to the bundle step → `9f081ef`
- F300 intra-doc-link rustdoc gate → `4a29b5a`
- F216 six low-FP clippy lints + pedantic recipes → `0d8def0`
- F309 `just bump` recipe → `bbaf469`
- F232 reqwest HTTP/2 re-enabled (perf effect **unmeasured** — operator's call) → `910cb10`
- F094 permission tester lists/revokes the tested resource's Selected entries → `3103bc4`

## Module splits — DONE
- F016 `commands/permissions.rs` → directory module → `e2c67c7`
- F028 `commands/audit.rs` → directory module → `9ef935b`
- F076 `commands/sso/mod.rs` → directory module → `d482f56`

## Tier 4 — Enhancements & feature opportunities (in progress)

The per-item set IS defined: the review doc's **"## Enhancements and feature
opportunities"** section (108 findings / 106 entries after the F042+F428 and
F264+F276 merges; 30 medium + 78 low; 58 S / 45 M / 5 L). The "8 enhancement
packages" label is the separate **"## Strategic projects"** list — those span
buckets (Idempotent DR restore pulls from Bugs; Run identity from gap slices),
so it is not the per-item enhancement set.

Already done from this bucket: **F094** → `3103bc4` (permission tester
lists/revokes Selected entries; its ship-together partner F073 — the dead
"(capped)" branch — remains open). **F309** → `bbaf469` (`just bump`).

Remaining 31 entries by area (read the section for each item's Problem +
Proposal; #### items are full entries, one-liners are bullets):

- **Audit & remediation (9)** — **all closed 2026-10-02.** F125 · F129 · F027
  (+ its UI Callout) · F034 · F035 · F127 + F402 (+ F393) verified already
  implemented on main (unconfinable-reach markers have their groups + posture
  counts; preparatory progress and unconditional caveat strips exist). F133
  shipped as the dedicated `AuditItem.app_owner_organization_id` column (SP rows
  keep `publisher: None`), not a publisher rewrite. F138 implemented:
  `issue::ORG_WIDE_FILES` advisory in Rule 12 (no remediation) + the
  `least_privilege_alternative_for` Files arm, so picker hint, audit
  recommendation and item wizard agree.
- **Scoping (Exchange/SharePoint) & resource access (9)** — closed 2026-10-02
  except **F174 · F263** (below). F060 · F406 · F407 · F439 verified already
  implemented on main (consolidated "Scoping is NOT effective" warning through a
  helper shared with `aap_migration`; `is_held_scopable` carries the resource,
  comment fixed; Grant write is Secondary with read Primary last; `do_probe`
  clears a stale result when the target changes). F069 step 1 (tester reads BOTH
  SP resources, labels SPO grants) shipped with F094; step 2 (converter strips
  the SPO copy + widened `is_scopable_sharepoint_resource_permission`) is
  **declined after review** — the design now deliberately keeps per-row Scope
  actions Graph-only because the conversion's grant and strip targets Microsoft
  Graph (F406 documents it; the picker hint agrees by omission). F436's
  display-name substitution verified implemented; its remaining tab reset landed
  with F197. F197 implemented: `enableRbacAuthorization` reaches
  `KeyVaultSweepResult.vaults_access_policy_mode`, so access-policy vaults are
  named in the sweep summary + export instead of reading as all-clear.
  **Open — F174:** the decommission teardown is a real gap (no
  `Remove-ManagementScope`/`Remove-ServicePrincipal` anywhere); it needs
  prove-zero-references + separately-confirmed design modelled on
  `delete_exchange_scope_group`'s live re-checks. **Blocked — F263:** parsing
  `RecipientAdministrativeUnitScope` requires the real wire key confirmed from a
  live role-assignment envelope before code exists; guessing the key is the
  failure mode the entry warns about.
- **Credentials & SSO (13)** — **all closed 2026-10-02.** Verified already
  implemented on main: F075 (create.rs pushes `warnings` for the best-effort
  claims/email steps) · F085 (every create step runs through
  `with_replication_retry`) · F190 (removers return `NotFound` without a PATCH
  and remediation treats `NotFound` as removed; the aggregators propagate the
  error) · F200 (the stale `SetArgs`/`delete_secret` residues are gone) · F338
  ("Rotate & remove {n} existing" behind a ConfirmDialog) · F373
  (pending-retire removal behind a ConfirmDialog) · F374 (CopyBlock is shared
  and the reveal paths use the warn Callout; only the optional "Save as .cer"
  button remains) · F381 (gallery dialog and wizard both offer "Open
  application"). Implemented on this branch: F196 (certificate-backed
  `managed` secrets are badged in the browser) · F079 (rotation stamps
  provenance tags and refuses to overwrite a secret tagged to another app —
  built on `get_secret`'s documented per-secret tags rather than the proposed
  new `list_secret_versions` endpoint, the check needs no new wire surface) ·
  F385 (claims-editor `problems()` advisory panel, in the SSO tab and the
  wizard alike) · F382 (wizard lifetime fields gate Next on the real
  1..=1095/1..=730 bounds instead of `parse().ok()` defaulting). **F392 stays
  open as a product-gap idea** (same spirit as the Product-gap bucket below).
- **App-reg editing: auth / Expose an API / federation (5)** — **all closed
  2026-10-02.** Verified already implemented on main: F017
  (`validate_authentication_input` runs `redirect::validate_logout_url` on the
  logout URL before any mutation, pinned by
  `the_logout_url_is_validated_before_the_patch`) · F158 (redirect.rs drops the
  `::1` IPv6 loopback with the Microsoft citation and caps URIs at 256 chars,
  both mirrored in the frontend's row hints) · F162 (federation.rs rejects
  `len() > 1` audiences; `rejects_more_than_one_audience` pins it) · F350
  (expose_api_tab's add is a DirectorySearch typeahead over apps + SPs, and
  rows resolve client display names via `client_display_names`). F342
  implemented here: both forms gate Save on a real diff (Authentication via
  `UriListState::same_as`, Overview via a shared `overview_patch` helper whose
  result is compared to default), Authentication gained Reset, and
  `update_application` treats an all-default patch as a no-op (no round trip,
  no list-cache bust). Deviation from the proposal: a clean form disables Save
  rather than firing a toast, and Cancel on Overview now re-seeds instead of
  parking edits.
- **Enterprise apps & managed identities (5)** — **all closed 2026-10-02,
  verified against current main.** F377 (`AppAssignmentDto.principal_id` exists
  with its per-role doc; the Access tab derives `exclude` from assignments
  holding the *selected* role and has a debounced filter `SearchInput`;
  ShowMore deliberately not revisited — no stall evidence). F378
  (`assignable_to_users_and_groups` gates the picker; Application-only roles
  render disabled "(applications only)"). F391 (the `Synchronization.Read.All`
  capability entry is in `core::capabilities` with its role list and
  remediation, `AppState::ensure_sync_token` pre-acquires and
  `get_enterprise_app_provisioning` calls it, and the Provisioning Callout has
  "Grant consent & retry"). F389 (the MI Azure role form has the "Custom role
  definition id…" GUID option and the "Grant consent to Azure" label). F206 (a
  409 `RoleAssignmentExists` maps to `UiError` code `already_assigned` without
  leaking the JSON blob, unit-tested in `managed_identity.rs`).
- **Operator tooling: search, DR, settings, readiness (18)** — 16 closed
  2026-10-02 (verified against main unless noted): F009 (GUID probes set
  `lookup_degraded`; an unanswered probe never reads as a miss) · F012
  (`index_truncated` covers both caps, `APPS_MAX == SP_INDEX_MAX` asserted) ·
  F040 (per-item `appRoleAssignedTo`/`memberOf` failures push
  `enterpriseAppAssignments`/`enterpriseAppGroups` SkippedObjects) ·
  F042+F428 (`schema_too_new` is a dry-run blocker behind `plan_blocked()`,
  the four new RestorePlan counts render, and same-tenant restore warns about
  duplicates) · F049 (one `csv_bytes` sink adds the UTF-8 BOM, tested) ·
  F053 (`ConfigSource` + settings-view source note + build.rs warning for an
  empty/mistyped `.env` value) · F024+F163 (`claims_policy_write` +
  `provisioning_read` catalog rows, `ensure_sync_token`, the Grant-consent-&-
  retry Callout, and `forbidden_remediation` spliced into both claims-save
  paths — the readiness feature set now derives from CAPABILITIES) · F262
  (admin_consent lists Application/Cloud Application Administrator, remediation
  reworded) · F157 (placeholder scopes expanded per cloud in `scope_detail_text`
  + a no-literal-host test) · F153 (`AZAPPTOOLKIT_BUILD_CLOUD` baked, runtime
  var still wins) · F149 (`settings.lock` via `File::lock` inside the process
  mutex, cross-instance test) · F390 (both created-on pairs live on
  `TenantScopedUi` + the credential-facet clear-on-switch rule) · F432 (Clear
  per kind + reactive Disable/Enable label) · F434 (Home's With-secrets/
  With-certs metrics drill through `open_apps_with_facet` into the two new
  chips) · F369 **implemented here**
  (`16bc3df`: saved views carry + apply the date window, clear included).
  **Open — F258:** custom-Entra-role detection (`required_actions` + a
  roleAssignments/roleDefinitions read path) and **F271:** PIM eligibility
  (`Verdict::Eligible` via `roleEligibilityScheduleInstances` needs a new
  consent scope + a sovereign-aware `portal_root()`); both are design-level,
  not drop-in.
- **Auth, sign-in & network resilience (9)** — **all closed 2026-10-02,
  verified against current code.** F110 (`PASSTHROUGH_NON_FATAL_CODES` =
  `consent_required` + `network_error` + `interaction_required` flows through
  `passthrough_code`, `is_consent_required` keys on it, and the reauth.rs docs
  tell the pass-through story — no `String`-boundary residue in
  auth-and-consent.md or `state.rs`). F112 (README + DEVELOPMENT.md state the
  Linux Secret Service requirement, `token_cache.rs` calls it a hard
  requirement, and sign_in.rs splits `keyring` (locked) from
  `keyring_unavailable` (no store) hints, test-asserted). F181
  (`scoped_send_core` runs through `send_core_url_with` with
  `retry_class_for(&method)`, so scoped writes replay on 429/5xx and DELETEs
  stay idempotent-replayable). F183 (`retried_sub_status` = 429 or any 5xx
  re-batches under budget; the throttle observer is notified for 429 only).
  F427 (permission_tester, resource-access sites/keyvault/mailboxes and
  key_vault_view route `Err(e)` through `report_if_session_dead` or the shared
  `report_recovery_action` ladder; global_search reports in its resource).
  F114 (`components::browser_fallback_notice` renders the copy-the-link
  banner when the browser launch fails). F113 (timeout and code-less
  `access_denied` map to `AuthError::Cancelled` → UiError code `cancelled`
  with a live sign-in hint; unit-tested). F354 (both pre-sign-in hints point
  at the card's **Change** link; the pinning test asserts no hint mentions
  Settings). F018 (`KeyFailure`/`OwnerChangeFailure` carry the `code`,
  `is_reauth_fatal` keys on it, and both credential loops and both owner
  loops `break` on a fatal code, flagged in the result).
- **Frontend consistency & polish (8)** — **all closed 2026-10-02, verified
  against current code.** F341 (every named hand-rolled red-text site now
  renders `DetailLoadError` with `on_retry`: all five app tabs,
  permission_picker and sharepoint_sites_section in `components/`, and the
  enterprise pane's permissions/app_roles/sso/access/panels). F357 (scroll
  offsets are lifted to `TenantScopedUi` — `apps_scroll_top` +
  `enterprise_scroll_top` — carried across the refetch remount via
  `reset_scroll_offset_on_change`, and the `virtual_list.rs` comment tells the
  remount story). F355 (`push_toast` takes a `dedupe_key` collapsing identical
  toasts, and the cap evicts non-sticky toasts first with two host tests).
  F322 (`util::plural` is `pub` and `count_noun` exists with its pairing test;
  the operator-facing `(s)` literals are gone — the three remaining grep hits
  are a doc comment, a fixture and a test assertion). F321 (`fmt_date`,
  `fmt_datetime` and `expiry_label` live in util.rs with host tests; the SSO
  tab calls `expiry_label` and the pane's private `fmt_date` copy is deleted).
  F327 (all eight action `<td>`s carry `cell-mid`). F325 (Settings falls back
  to `DetailSkeleton`; the three plain-"Loading…" text sites are gone).
  F326 (table-level empties route through DataTable's `empty_message`, e.g.
  credentials_tab's secrets/certs tables; section empties use `EmptyState`).
- **Graph API capabilities not yet adopted (8)** — **F264+F276 closed
  2026-10-03** (Identity Protection `riskyServicePrincipals` read once per audit
  run: on-demand `IdentityRiskyServicePrincipal.Read.All` CAE token + capability
  catalog row, tenant-wide prefetch joined onto both scoring phases by SP object
  id, Rule 22 +20 with the shared DisableSignIn fix, risky grantless principals
  admitted to the SP-only phase, unavailable-vs-gap split with the
  `RiskyServicePrincipals` coverage gap). Partial: it ships as a Findings group
  only — no Enterprise-overview chip, no facet filter. **F259 closed 2026-10-03**
  (per-credential last-used signal: one tenant-wide beta
  `appCredentialSignInActivities` read per audit, shared with the Credentials
  tab's `list_credential_usage`; `{tenant}|app_credential_sign_in_activities`
  cache bucket under `CacheKind::Permissions`, `$top` cap + origin-checked
  paging, per-origin newest-wins fold; `unused_credential` advisory gated on
  report availability with Unknown≠never-flagged pinned; Last-used column on
  both Credentials tables; Global-cloud-only noted in the `audit_reports`
  capability). Partial: shown in the Credentials tab only — no dashboard chip
  or facet; the SP-only phase skips the post-pass (a service principal carries
  no local credentials). **F260+F270 closed 2026-10-03** (read-only app-management-policy
  trio on the shared `policy` / `Policy.Read.All` token, v1.0 endpoints, degrading to
  `available:false` — never an `Err` nor a degraded run; `ScoreCtx::secret_cap_for` —
  ≥2 overrides = no verdict, an assigned override REPLACES the default, grandfathered =
  no cap — shared by the audit advisory and the new `credential_over_cap` predicate, so
  the audit advice and the Credentials-tab "Over cap" markers fold one rule; advisory
  beside (not replacing) the 365-day legacy floor, no ranking change; add-secret dialog
  warns a policy-rejected lifetime, warn-only; Home posture line only for a knowable
  cap; "no cap enforced" wording pinned out). Partial: the F260 "map the
  policy-violation error code" half is not done — a rejected add still surfaces as the
  Graph 400. **F265 closed 2026-10-03** (`requestSignatureVerification` added to the
  SSO-fields `$select` and projected onto `SsoConfigDto` — the SAML SSO section now shows
  Required / Required-but-weak / Not-verified with a warn Callout naming `rsaSha1`, and a
  missing block renders nothing (never-flag-on-unknown, pinned by `gui/sso_signed_requests.rs`).
  Partial by evidence, not by choice: the "patch struct" half was NOT implemented — the v1.0
  `application-update` property list (checked 2026-10-03) does not list
  `requestSignatureVerification` as updatable, so a toggle would ship an undocumented write
  on an auth-trust control; reopen only with proof a PATCH lands. The optional low-weight
  `rsaSha1` audit rule is also deferred: scoring would need a per-app SSO-field read added to
  the audit fan-out for every app, and any ranking change needs its own CHANGELOG-gated
  justification. **F274 closed 2026-10-03** (tenant consent posture as mount-time
  context: a two-read pair `authorizationPolicy` + `adminConsentRequestPolicy` on the
  shared `policy` / `Policy.Read.All` token via `tokio::join!`, all-or-nothing — any
  failure or missing token ⇒ `available:false` ⇒ renders nothing, never an `Err` nor a
  degraded run, no new scope; `defaultUserRolePermissions.permissionGrantPoliciesAssigned`
  is decidable (empty = confirmed no self-consent, non-empty = warn naming the assigned
  policies) and a missing ACW policy object reads as "never enabled"; rendered as the
  grants-view header Callout (new `header_note` prop on `AuditDashboard`) and an
  independent Suspense note on the Home posture card, pinned by
  `gui/consent_posture.rs`). Partial by evidence, not by choice: the review's third
  read `permissionGrantPolicies` was NOT implemented — it is a *catalog* (assignment to
  the default user role is what enables self-consent, and the assignment list already
  names the policies) and needs `Policy.Read.PermissionGrant`, which the
  `Policy.Read.All` token does not carry; pending `appConsentRequests` deferred to the
  second step — its read needs a dedicated consent-requests scope and its own feature.
  Remaining 3: F161 · F078 · F268
- **Product-gap proposals (11)** — F266 · F267 (#109 posture snapshot + drift
  report, effort L) · F278 · F269 · F272 · F273 · F275 · F277 · F279 · F280 ·
  F283
- **Docs, demo, packaging & release tooling (7)** — F247 · F413 · F420 · F222 ·
  F250 · F298 · F311

If picking items up, respect "Changes that must ship together": F027+F058 and
F127+F402+F393 shipped closed (see above — the paired flag/Callout and the
marker/group/posture trio landed in one change each); F075 is closed —
`sso_summary.rs` already renders the `warnings` field (pinned by the
`a_partial_saml_create_says_what_was_not_applied` GUI test). Before implementing a
remaining item, confirm it against current main — several entries describe
gaps that have since been closed.

## Wrap-up
- `just verify-full` is **green end to end** on this branch's final head (incl.
  the two `Cargo.lock` yoke-derive 0.8.3→0.8.4 fixes, needed because 0.8.3 was
  yanked and `[advisories] yanked = "deny"`).
- Correction to the earlier note: this box CAN run the browser GUI tests —
  wasm-pack downloads a matching chromedriver and `web-itest` ran here, all 4
  shards. The first run failed 3/48 in `gui_2`: the three F094
  `permission_tester` probe tests timed out because `mount_and_probe` typed the
  SharePoint URL without a tick after the tab click, so the URL input was not
  yet mounted and `set_input_value` no-oped. Fixed with flush ticks in
  `tests/gui/permission_tester.rs`; gui_2 is 48/48.
- Still unproven locally, CI-only: actionlint, shellcheck, secrets scan, CodeQL.
