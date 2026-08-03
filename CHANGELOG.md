# Changelog

All notable changes to azapptoolkit are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Older releases (**0.19.2 and earlier**) live in
[docs/CHANGELOG-archive.md](docs/CHANGELOG-archive.md).

## [Unreleased]

## [0.22.2] - 2026-08-03

### Added

- **`just verify-ui`** — `verify` plus the browser GUI tests, for a box with
  Chrome. `just verify` now also prints what it did not run and why, instead of
  omitting the frontend behavioral tests silently.
- **`just web-itest-size`** — enforces the per-shard wasm ceiling the GUI test
  strategy depends on (CI runs it after the GUI tests). The number lived only in
  comments; a shard drifting past it fails as an opaque 60-second "Failed to
  detect test as having been run" timeout that reads like a flaky browser.
- Tests for the paths that mutate a tenant and had none: `run_bulk_seq` (the
  shared driver behind all ten bulk commands, including delete and
  disable-sign-in), the `VALID_AUDIENCES` bulk-create rule, `sleep_before_retry`
  (its pure helpers were tested but not which branch it takes — an explicit
  `Retry-After` must be honored verbatim, never jittered or clamped),
  `use_filtered_list` (207 lines of layered memo/facet logic), and `AppShell`,
  which no GUI test had ever mounted.
- Tests pinning three invariants that were previously prose only: the two
  RUSTSEC ignore lists (`deny.toml` and `.cargo/audit.toml`) stay in sync, both
  deny recipes run the advisories check, and every infallible `invoke()` in the
  frontend bindings has a demo fixture registered — an unregistered one panics
  the whole published demo page rather than failing one widget.

### Changed

- **`CHANGELOG.md` split.** Releases 0.19.2 and earlier moved to
  `docs/CHANGELOG-archive.md`; this file dropped from 130 KB to 63 KB. It was
  the repo's highest-churn file by a wide margin (touched by roughly a third of
  all commits) while most of its content is years-stable. The updater's
  notes-extraction reads only `CHANGELOG.md`, and only the released version's
  section, so it is unaffected — verified against 0.22.1.
- **`[profile.release] opt-level = "z"` kept, now with a measurement behind it.**
  Benchmarked at 193 000 scored apps/sec vs 313 000 at `opt-level = 3` (1.62×)
  for +9% binary size — but scoring is not the bottleneck: a 10 000-app tenant
  spends ~50 ms there versus ~32 ms, inside a run dominated by minutes of
  throttled Graph round trips. Numbers and the reproduction command are recorded
  next to the profile block.
- **The WASM frontend now declares its own `unsafe_code = "deny"`.** The root
  workspace calls that lint an explicit security boundary for a tool handling
  delegated tokens, but `[workspace.lints]` reaches only workspace members — and
  `web-rs` is excluded for build-target reasons. That silently carried the
  largest tier in the repo, running inside the webview with full IPC access, out
  from under the boundary. It is declared locally now; the exclusion is a
  build-target decision and can no longer widen what the frontend may do.
- **`cargo deny` actually runs the advisories check.** Both `just deny` and
  `just web-deny` ran `check bans licenses sources`, so `deny.toml`'s
  `[advisories]` block — `yanked = "deny"` plus three reviewed RUSTSEC ignores —
  was configuration nothing executed. Enabling it surfaced 16 `unmaintained`
  advisories, all transitive and none with an upgrade path from this repo (the
  archived gtk-rs GTK3 stack, `proc-macro-error`, the `unic-*` family), so the
  policy now scopes `unmaintained` to direct workspace dependencies. Yanked
  crates and vulnerabilities are enforced for the whole graph, as intended.

### Fixed

- **A bulk run kept going after the session died, turning one recoverable
  prompt into a wall of failures.** Per-item errors were flattened to
  `Some(e.message)`, discarding the `code` and `retryable` fields — so a mid-run
  `refresh_missing` (a refresh token that cannot be re-minted silently) was
  indistinguishable from "this one app failed", and the loop ground through
  every remaining app against a dead session. Outcomes now carry a structured
  `BulkError { code, message, retryable }`, the shared driver halts on a
  session-fatal code, and the frontend surfaces the existing in-place re-auth
  action instead of a list of unexplained failures.
- The re-auth-fatal code set is now defined once, as
  `UiError::is_reauth_fatal()` in the shared DTO crate. It was three
  hand-maintained `matches!` arms — the footgun AGENTS.md called out ("a new
  re-auth-fatal code must extend BOTH sets").


- **`apply_tenant_defaults` could silently drop a new setting.** It hand-copied
  five named fields to preserve the two vault fields, with nothing tying that
  allowlist to `TenantDefaults`'s actual shape — so a field added and wired into
  the Settings page would compile, appear to save, and never persist. It now
  destructures exhaustively, making the compiler demand a decision per field.

- **Exchange scoping silently failed for two permissions sharing one Exchange
  role, and the failure was permanent.** `assign_scoped_roles` snapshotted the
  app's existing role assignments *once* before its loop, but the permission →
  Exchange-role map is many-to-one: `Mail.ReadBasic` and `Mail.ReadBasic.All`
  both map to `Application Mail.ReadBasic`. The second target re-read the stale
  snapshot, issued a duplicate `New-RoleAssignment`, and its error marked the
  target unsafe to strip — so `targets_safe_to_strip` excluded it and its
  org-wide Entra grant survived, leaving the grant unioned with the scope. The
  scoping never took effect, and every re-run reproduced the same failure. Roles
  assigned inside the loop now count as in place.
- **A failure to resolve the Office 365 Exchange Online service principal could
  delete an Application Access Policy that was still confining a live
  `full_access_as_app` grant** — widening the app to every mailbox in the tenant.
  `mailbox_resource_roles` propagates the Microsoft Graph failure but resolves
  the Exchange Online resource best-effort, so a transient failure yields zero
  migration targets; `policies_safe_to_remove`'s "no targets ⇒ the policy governs
  nothing" branch then read that as licence to delete. The empty-target branch
  now **fails closed**: it is trusted only when both mailbox-bearing resources
  actually resolved, and the migration report says so when it declines.

- **The audit scored the EWS `full_access_as_app` grant at zero.** That scope —
  full access to *every* mailbox in the tenant, strictly broader than
  `Mail.ReadWrite` — is named nothing like a mail permission, so Rule 11's
  `Mail.*` / `MailboxSettings.*` prefix filter never saw it, and the risk tables
  only ever listed Microsoft Graph names. The tenant's single most dangerous
  mailbox grant therefore raised no finding, contributed no risk score and
  offered no fix. It is now high-risk, raises the org-wide mailbox finding, and
  carries the `ScopeMailboxAccess` remediation (it *is* confinable, via
  `Application EWS.AccessAsApp`). **This shifts risk ranking** for any app or
  service principal holding it.
- **A service principal holding *only* the EWS scope was never audited at all.**
  The SP-only phase's candidate filter required a Microsoft Graph application
  grant, and `full_access_as_app` lives on the legacy Office 365 Exchange Online
  resource — so a principal with org-wide mailbox access and no Graph role was
  dropped before scoring. The candidate rule now spans both mailbox-bearing
  resources.
- **A scoped Microsoft Graph mail permission lent its verdict to the identically
  named legacy Exchange Online grant.** The audit's permission model carried bare
  permission *values* with no resource id, and `mail_scopes` was keyed the same
  way, so an app declaring `Mail.Read` on both resources had the unscopable
  legacy grant read as "scoped" — dropping a genuinely org-wide grant out of the
  mailbox findings and scoring it at the reduced scoped weight. Application
  permissions now travel as `ResourcePermission { resource_app_id, value }`, and
  every mailbox verdict is gated on the grant's own resource. Unscopable legacy
  grants get their own finding (RBAC for Applications covers Microsoft Graph and
  EWS only) and deliberately **no** "Scope…" button, since removing the grant is
  the only remedy.

## [0.22.1] - 2026-07-29

### Fixed

- **The Permissions-tab Scope column let one resource's row borrow another's
  verdict.** The effective-scope map is keyed on permission *value* alone, but
  two resources expose an identically named `Mail.Read` / `Mail.ReadWrite` /
  `Mail.Send` / `Contacts.*` — so an app declaring a mail permission on both
  Microsoft Graph *and* the legacy Office 365 Exchange Online resource painted
  the Exchange Online row with the Graph row's badge. The legacy rows aren't
  scopable at all, so an "Org-wide" badge there read as a scoping failure on a
  permission that could never be scoped. The same hole gave a *delegated* mail
  row the application verdict, contradicting the column's own contract that
  delegated permissions read "—". The verdict is now gated on the row's own
  resource and kind, matching the resource-aware checks the rest of the frontend
  already used.

### Added

- **A callout naming legacy Office 365 Exchange Online mailbox grants.** That
  resource's own `Mail.*` / `Calendars.*` / `Contacts.*` / `MailboxSettings.*`
  appRoles (the Outlook REST API, decommissioned March 2024) can't be confined —
  RBAC for Applications covers Microsoft Graph and EWS only — but they still
  count as org-wide mailbox reach, so a surviving grant flips the identically
  named Graph permission's verdict back to `OrgWide`. A correctly migrated,
  correctly scoped app therefore read "Org-wide" with nothing on the page
  explaining why, and no scoping action could clear it (those roles are never
  scope targets, so the grant strip never touches them). The app-registration
  Permissions tab and the shared held-permissions panel (enterprise apps and
  managed identities) now name the offending grants and say that removing them is
  the fix. The resource's live-protocol roles — `full_access_as_app`,
  `EWS.AccessAsApp`, `Exchange.ManageAsApp`, `IMAP`/`POP`/`SMTP.*AsApp` — are
  deliberately excluded, so the callout can never advise breaking EWS, Exchange
  Online PowerShell, or IMAP/POP/SMTP.

## [0.22.0] - 2026-07-28

### Fixed

- **The EWS `full_access_as_app` scope was invisible to every Exchange scoping
  path, and migrating its Application Access Policy widened the app's access.**
  Per [Microsoft's AAP
  documentation](https://learn.microsoft.com/exchange/permissions-exo/application-access-policies),
  a policy can confine eleven Microsoft Graph mail permissions **and** the
  Exchange Web Services `full_access_as_app` scope — the latter an appRole on the
  legacy *Office 365 Exchange Online* resource, not on Graph. Target derivation,
  grant stripping and org-wide reconciliation all filtered to the Graph resource
  SP, so for an app scoped that way the migration assigned no
  `Application EWS.AccessAsApp` role and revoked no consent (the admin consent
  stayed granted), yet **still deleted the legacy policy** and reported
  `migrated` — leaving the app with org-wide EWS access to every mailbox. The
  same blind spot made the Permissions-tab Scope column, the security audit and
  the Permission tester report a mail permission as `Scoped` while a surviving
  org-wide EWS grant still reached every mailbox: an under-report, the one
  direction those surfaces are not allowed to err in. All of them now resolve
  grants against both mailbox-bearing resources via one shared index
  (`graph_roles::mailbox_resource_roles`), each scope target carries the resource
  its grant lives on so a strip can't hit the wrong API, and a surviving
  `full_access_as_app` grant vetoes *every* per-permission scope verdict rather
  than only its own name. Office 365 Exchange Online's own `Mail.Read`-style
  appRoles (retired Outlook REST) deliberately do **not** map — RBAC for
  Applications covers MS Graph and EWS only, so claiming a scope there would
  strip a grant that has no scoped replacement.

- **A `DenyAccess` Application Access Policy migrated into its own inverse.** The
  migration filtered policies by appId alone and never read `AccessRight`. A
  `DenyAccess` policy is a blocklist — every mailbox *except* its group — whereas
  an RBAC management scope allows only what it names, so converting one gave the
  app access to exactly the mailboxes it had been denied and removed the rest.
  Only `RestrictAccess` policies are migrated now; a `DenyAccess` policy (or one
  whose `AccessRight` can't be read) is reported with an explanation instead.

- **Apps with several Application Access Policies silently lost scope groups.**
  Policies were migrated one at a time, each deriving the same per-app management
  scope name; `ensure_management_scope` keeps an existing scope, so the second
  policy's group never made it into the filter — and then both policies were
  deleted, cutting those mailboxes off. Migration now batches every
  `RestrictAccess` policy of one app into a single scope spanning all their
  groups, which is what the policies granted (their combined effect is the union
  — `New-ApplicationAccessPolicy` evaluation rule 3).

- **The legacy policy is no longer deleted while it is still load-bearing.**
  Deletion (documented step 5) now runs only once every org-wide grant the policy
  was constraining has actually been re-scoped. Anything left org-wide keeps its
  policy and the run reports `partial`, naming the grants that held it back —
  because that policy is the only thing still restricting them.

- **Composite RBAC roles read as organization-wide.** `Application Mail Full
  Access` and `Application Exchange Full Access` bundle several permissions and
  carry none of their individual role names, so matching
  `Test-ServicePrincipalAuthorization` rows on `RoleName` alone found no row for
  (say) `Mail.Send` and fell through to the no-rows ⇒ org-wide default. A
  correctly scoped app was reported as unscoped, inflating its audit score. Rows
  are now matched on `GrantedPermissions` as well, which is where the cmdlet
  reports the bundle.

- **The UI couldn't name the permission the backend had started acting on.** Held
  app-role grants resolved values for Microsoft Graph only, so a principal holding
  the EWS `full_access_as_app` scope showed a bare GUID, got no Scope verdict, no
  Exchange scoping section and no org-wide callout — while the audit and the
  Permission tester had begun treating that grant as org-wide mailbox reach.
  `AppRoleGrantDto` now carries `resource_app_id` and resolves values for both
  mailbox resources, and every held-permission surface judges scopability with
  `is_exchange_scopable_on(resource, value)` instead of the value alone. That
  distinction is load-bearing in both directions: Office 365 Exchange Online's own
  `Mail.Read` (retired Outlook REST, no RBAC role) no longer offers a "Scope…"
  action the backend refuses to honour or shows an "Unknown" verdict that will
  never arrive, and a `full_access_as_app` row seeds the Grant-access wizard with
  its *own* resource rather than Microsoft Graph, which doesn't expose it.

- **The org-wide callout now explains a blanket grant.** When a principal holds
  `full_access_as_app`, the callout says it reaches every mailbox on its own and
  overrides any per-permission mailbox scope until removed — the same rule
  `reconcile_orgwide_grant` applies, so the callout and the Scope column can no
  longer appear to contradict each other.

- **A migration that stopped short no longer reads as a success.** The result
  header and per-app rows distinguish `migrated` from `partial`, show
  "Legacy policies: N kept" rather than a bare boolean, and render each app's
  warnings inline — which is where "kept the policy because X is still org-wide"
  is explained. A dry run says explicitly that nothing has changed yet.

### Changed

- **`AapMigrationItem` is per application, not per policy.**
  `source_policy_identity: Option<String>` became `source_policy_identities:
  Vec<String>` and `removed_policy: bool` became `removed_policies: Vec<String>`,
  since one item can now fold several policies and may deliberately delete none
  of them. `status` gains `partial`. The migration result list also renders each
  item's warnings, which is where the "kept the policy because X is still
  org-wide" explanation lands.

- **One directory-search control instead of four copies.** The Settings
  default-owner editors, the Settings SSO-notification distribution-list picker,
  the Exchange scope forms' group typeahead, and both search blocks on the
  enterprise Access tab each carried their own copy of the same sixty lines —
  same 300 ms debounce, same 2-character gate, same `Suspense` + "Searching…"
  spinner, same `.candidates` markup — and had already drifted: two showed a
  bare "No matches." under an untouched search box (their empty-check could not
  tell "searched and found none" from "hasn't searched yet"), and the Access tab
  subtitled a group with the literal word "Group" where the others showed the
  object id. `components::directory_search::DirectorySearch` now backs all of
  them; it never mutates anything, handing the picked `DirectoryObject` to the
  caller, which is what lets one component serve a direct callback, a
  text-field append, and a stage-then-confirm dialog flow. Net −477/+134 lines.

- **One tab implementation instead of two.** Six surfaces used Thaw's `TabList`
  while the rest used the in-house `TabBar`. They now all use `TabBar`, which is
  an accessibility fix rather than a matter of taste: `thaw::Tab` emits
  `role="tab"` and `aria-selected` but has **no roving `tabindex` and no keydown
  handler**, so the 10-tab enterprise detail pane cost a keyboard user ten Tab
  presses to cross and offered no arrow-key movement at all. Converting also
  deleted a CSS workaround — `.thaw-tab-list` needed an app-side `overflow-x`
  patch to stop clipping tabs past the pane edge, which `.ui-tabs` never needed.
  `FilterChip` deliberately stays a `<button>` (Thaw's `Tab` takes only
  `class`/`value`/`children`, so it cannot carry a count badge or the
  zero-count disabled state), and selects stay selects where the option list is
  long.

### Fixed

- **A false rationale that was steering design decisions.** `FilterChip`'s doc
  comment asserted that a dynamic Thaw `TabList` "pulls `uuid-v4` on wasm, a
  known no-go". Both halves were wrong: thaw's `tab_list/` contains no `uuid`
  reference at all — a tab's identity is the caller's `value` string — and
  `ConfigProvider` mints a `Uuid::new_v4()` on wasm at root mount on every
  single boot, so uuid-on-wasm cannot be a no-go or the app would not start.
  Three of the six `TabList` call sites were already dynamic and shipping. The
  claim had no supporting evidence anywhere in the repo's history.

- **Form labels read as labels.** A thaw `<Field>` label rendered at body size,
  regular weight and the primary foreground — typographically identical to the
  value underneath it — across ~97 fields, so a form had a heading tier and then
  two indistinguishable tiers below it. Labels are now medium-weight and muted,
  matching the treatment the app had already hand-rolled for `.sso-field__label`
  on three of those ~100 sites. One rule; every dialog, wizard step and detail
  tab gets the hierarchy.

- **The enterprise Access tab.** Its "Assign: Users / Groups" choice was a pair
  of buttons whose selected state was a Primary appearance — the only instance
  of that technique in the app; it now uses `TabBar`, the same primitive the
  permission picker uses for its identical Application/Delegated choice, which
  brings `role="tab"`, roving tabindex and arrow-key navigation with it. Row
  actions were 7px above their own row text (`.data-table` cells are
  `vertical-align: top` and the button is taller than a line), fixed with the
  `.cell-mid` opt-out that already existed and that five other tables use —
  except on the two-line group-identity cell, which stays top-aligned per that
  rule's own carve-out. `.ent-access` and `.ent-owners` had **no CSS rule at
  all**, so those tabs' vertical rhythm was whatever the UA's `<h4>` margins
  collapsed to while every sibling tab was a token-gapped grid. The "Requires:
  Groups Administrator" pill sat *inside* the `<h4>`, inheriting its bold.
  Search failures used `.app-detail__error` (the whole-pane variant: 16px
  padding, no `pre-wrap`, so it dropped the backend's guidance line breaks)
  where the two equivalent primitives use `.form-error`.

### Fixed

- **Tabs never announced which one was selected.** `TabBar` bound `aria-selected`
  to a `bool`, which Leptos renders as a *boolean* attribute — present-and-empty
  for true, omitted for false — so the active tab shipped `aria-selected=""`,
  not a valid ARIA value, and no tab ever carried `aria-selected="true"`. Now
  set as a string, matching how `global_search.rs` and `permission_tester_view.rs`
  already set the same attribute. Affects every `TabBar`: Security, Settings,
  Bulk Actions, the permission picker, and the Access tab.

- **Destructive actions are red everywhere, and red now means destructive.** A
  census of every button in the front-end found the treatment applied by hand
  and unevenly: three one-click Trash buttons on the API permissions tab
  (revoke an app-role assignment, revoke a delegated scope, strip a declared
  permission from the manifest) rendered in the ordinary glyph colour, as did
  both **Remove** buttons on the enterprise **Access** tab, Exchange scoping's
  "Remove all…", and "Rotate & remove existing" — which sits next to "Rotate
  (keep old)" and deletes every existing secret. In Bulk Actions only *Delete*
  reddened, so "Remove expired credentials" and "Remove redundant permissions"
  armed as ordinary buttons; that now comes from a single
  `BulkAction::is_destructive()` instead of two hand-maintained match arms that
  disagreed. The shared CSS rule also contradicted its own comment: it promised
  icon-only actions "just the red colour so they don't become heavy red squares"
  while setting `border-color` on a transparent 1px border — i.e. drawing
  exactly that square. Labeled buttons keep border + text + fill; icon-only ones
  are a red glyph with the tint deferred to hover, so a forty-row list reads as
  forty actions rather than forty errors. `DisableSignIn` is deliberately left
  un-reddened: it is reversible, and reserving red for the irreversible is what
  makes it worth reading.

- **Dropdowns look like the rest of the app.** There was no select styling at
  all, so the Access tab's "Role" picker and the SSO tab's "Set sign-on method"
  rendered as raw native controls — browser-grey border, square corners, no
  padding, and a UA-chosen font, so they didn't even inherit the app's typeface.
  Both now use a `.ui-select` primitive whose metrics match the inputs and
  buttons they sit beside, with an inline-SVG chevron (no network request; the
  CSP forbids one). The root also declares `color-scheme`, which is what makes
  the *native* parts CSS cannot reach — the dropdown popup list, scrollbars —
  follow the dark theme instead of staying light.

- **The enterprise SSO tab matches its siblings.** Its five "one per line"
  textareas (SAML identifiers and reply URLs, OIDC web and SPA redirect URIs,
  notification emails) are now the same per-row editor the Authentication tab
  uses. Validation is per-list rather than shared, which the migration forced
  into the open: a SAML Entity ID is routinely a bare `urn:`, and the redirect
  rules reject `urn:` on purpose — one shared validator would have painted a red
  bar on a correct SAML config. Reply URLs and redirect URIs take the redirect
  rules; identifiers and emails don't. Also fixed there: every button rendered
  as a full-width bar (the tab is a stretch flex column and nothing constrained
  them), section headings sat a rank below the sibling tabs' titles, and the
  read-only "Current method" value carried the browser's default 40px `<dd>`
  indent. The GitHub Pages demo now mocks `get_sso_config`, so the SSO tab shows
  the tab instead of an error.

- **Redirect URIs are edited one per row, not as a block of text.** All three
  platform lists on an app registration's Authentication tab were
  newline-separated text boxes, so an app with thirty web reply URLs was a small
  scrolling textarea in which no single entry could be removed without hand
  editing the text around it — and leaving a stray fragment behind was one
  keystroke away. Each URI is now its own field with its own Remove button, the
  list carries an entry count, and "Add" appends a row (Enter from a row does the
  same, and pasting a multi-line block still works — it splits into one row per
  line rather than collapsing into a single unusable entry). Entries are checked
  as you type against the *same* validator the backend runs, so an offending URI
  is marked on its own row, with the reason, before you save: previously the
  backend reported only the **first** rejection across all three platforms, so
  three bad URIs cost three round trips and nothing pointed at which line was
  wrong. Exact repeats are flagged too. None of this blocks Save — the backend
  remains the authority, so a rule the client doesn't mirror can never make an
  app unsavable through the UI.

### Removed

- **Four public client APIs with no callers**, including a superseded
  server-side gallery search whose ~110 lines of tests were the only thing
  exercising it (the command of the same name ranks against a cached corpus
  instead). The caching doc claimed that method was "still present and
  unit-tested" — corrected.

### Added

- **Confirm dialogs can name the object they are about to destroy.** The dialog
  body is a `&'static str` describing the *kind* of thing ("this client
  secret"), so an app with six secrets rendered six identical dialogs and the
  operator had to trust that the button they clicked belonged to the row they
  meant. An optional `subject` now names the instance; the credential,
  certificate, and federated-credential removals pass it (the federated one had
  the name staged already and was discarding it at the dialog).

- **The Bulk Actions page shows what is selected, and names failures.** It
  operates on a selection made on another surface, and showed only a count — so
  an operator typed DELETE against a set they could not review. It now lists the
  selected apps by name, and a tenant-wide `object_id -> name` map on the
  session means a failure list is names rather than the raw GUIDs the `names`
  prop was added to eliminate.

- **Enterprise Application and Managed Identity rows show sign-in state.** Both
  lists offer an Enabled/Disabled facet but neither row displayed the state it
  filtered on, so a filtered view and an unfiltered one looked identical
  row-for-row.

- **The revealed Key Vault secret is copyable and can be hidden.** It rendered
  as a bare `<pre>` — no copy button (selecting it by hand risks a trailing
  newline) and no way to put it away short of navigating off the page.

- **Enterprise Applications and Managed Identities warn when the directory
  index truncated.** Both lists are filtered views of one shared
  service-principal index that caps at 10 000 rows; past that they silently
  showed a subset, so filtering for an app that exists returned "No matching
  enterprise applications" and the operator concluded it wasn't in the tenant.
  Note the trap this avoids: neither list can detect the cap from its own row
  count — both are *subsets* of the index, so their totals sit below it even
  when it truncated (the App Registrations list can, because its rows are the
  capped set). The flag now comes from the index itself via a small, fallible
  read, so a failure costs the notice and never the list.

### Fixed

- **The Security lenses no longer claim "No matches" on top of a load error.**
  Credential expiry, Delegated grants, and Application permissions share one
  scaffold, so on a failed fetch (429, expired token, missing role) all three
  rendered a red error *and* "No matches" underneath — false, and contradicting
  the error directly above it. "Nothing here at all" and "your filter hid
  everything" also shared one message, implying a filter was hiding data that
  does not exist; they are now distinct. The table shell is built once instead
  of inside the reactive closure, so a keystroke patches rows through the keyed
  `<For>` rather than tearing the table down and rebuilding it.

- **The audit's All-apps pane no longer renders a dead select-all bar over an
  empty table.** A filter matching nothing left a select-all control governing
  nothing, a bare table header, and a flat one-line notice; it now shows the
  standard empty state. The table stays mounted (hidden) so the keyed rows are
  not torn down on every filter tick.

- **Access Readiness uses the standard page header and shows a loading state.**
  It hand-rolled its own header and rendered blank space while the slow
  three-plane check ran. The `Suspense` boundary is deliberately local to the
  view.

- **Managed Identities matches its sibling lists.** It skipped `ListScaffold`
  entirely — no filter drawer, no active-filter badge — and printed no result
  count, so a filtered view gave no sense of how much it was hiding.

- **Bulk "Grant admin consent" now asks before it runs.** It was the one bulk
  action that fired on the first click — every sibling arms an inline confirm
  panel first, and the far less consequential "Remove expired credentials" makes
  you type `REMOVE`. A misclick with 200 apps selected granted tenant-wide
  consent, for all users, to every permission each of those apps requests, with
  no preview and no undo. Grant now arms like the others and requires the typed
  keyword `GRANT`, with a description that states the blast radius and the
  selected count.

- **Home's inventory counts refresh after a bulk mutation.** Home stays mounted
  across view switches (keep-alive panes), so its App Registrations, credential,
  and Enterprise Applications cards kept serving pre-mutation numbers until a
  tenant switch or an explicit per-card Retry — delete 50 apps and the total was
  still the old one. Those cards now track the same reload bumps the audit tile
  already honoured. (The Managed Identities card has no bump to track and is
  unchanged.)

- **A cancelled security audit no longer reads as a complete one.** Cancelling
  mid-scan left an arbitrary prefix of the tenant scored, and every number on
  the workbench — the posture counts, the finding groups, each "Fix all N" —
  was computed over that prefix with no marker anywhere. Worst case, a
  cancelled run that happened to find nothing rendered the green "No actionable
  findings — nothing to fix right now" all-clear. On a security-posture surface
  an unmarked partial is an unmarked false negative. The strip now carries a
  persistent warning naming how many of how many principals were scored, and
  the all-clear is replaced by an explicit "this is not an all-clear" for a
  cancelled run. `total_apps` on the audit result now means what its name says
  (the number of principals the run set out to score) rather than repeating the
  scored count; it had no consumers.

- **Detail-pane tabs keep their state.** Switching tabs in an App Registration,
  Enterprise Application, or Managed Identity window unmounted the previous tab,
  so every switch re-ran that tab's fetches and discarded its UI state — scroll
  position, expanded rows, a half-filled add-credential or add-owner form.
  Bouncing Overview→Permissions→Overview→Permissions cost four Exchange scope
  lookups. All three panes now use the same keep-alive primitive the Security
  workbench does. For managed identities this also makes the tabs lazy (opening
  an identity no longer fires the Azure RBAC read unless you visit that tab) and
  restores `.mi-tab`'s intended spacing, which an inline `display: block` had
  been overriding.

### Changed

- **The two heaviest tenant-wide grant matrices are cached.** Every delegated
  grant in the tenant (`/oauth2PermissionGrants`) and every app-permission grant
  (`appRoleAssignedTo` on the Microsoft Graph service principal — the read the
  caching doc calls the one that dominates) were re-pulled from scratch by the
  security audit *and* again by each Consent lens, so moving between those
  surfaces paid for the same full-tenant walk twice.

  Caching a security-posture read is only safe if a revoke can never keep
  rendering as present, so the invalidation lives in the Graph client next to
  the reads — the same reasoning that puts `CacheKind::ServicePrincipal`'s sweep
  there. All seven grant mutators drop the matrices on `Ok`, which makes it
  correct by construction rather than by remembering at the seven command files
  that write grants. The sweep is scoped so it cannot evict the sign-in-activity
  report that shares the same cache kind. Three tests pin all of this.

- **The SharePoint site sweep actually throttles, and runs concurrently.** It
  attached a `ConcurrencyThrottle` and then never read its limit, so the
  observer halved a number nothing consulted — the adaptive back-off the comment
  advertised did not exist, on the endpoint family the transport documents as
  the throttle-happiest. The chunk walk was also fully serial. Both fixed by
  routing it through the shared `dispatch_capped` driver with the tracker as the
  cap.

- **Three commands no longer await independent reads serially.** The app-detail
  read waited a full round trip before fetching owners, though the owners list
  keys off the object id the caller already passed; the delegated-grant audit
  walked the service-principal index and the grant collection back to back; and
  the enterprise-app detail paid a live Graph lookup for a pairing join the
  pinned app-registration index already answers in memory (hit-only, so a cold
  deep-link still uses the filtered live call rather than enumerating the
  tenant).

- **The managed-identity detail window stopped fetching the whole identity list
  twice.** Its mail-scoping resource re-ran the full-tenant list command to read
  one `app_id` off an identity another resource had already resolved — on every
  open and every reload.

- **The security audit's five tenant-wide reads now overlap.** The app listing,
  the service-principal index, the tenant-wide delegated-grant read, the Graph
  app-role read, and the sign-in activity report were awaited one after another,
  so a large tenant sat through five full page-walks before the progress bar left
  0/N. They are independent — every join between them is synchronous and already
  ran afterwards — so they now run concurrently and cost one wait rather than the
  sum. Failure behaviour is unchanged: four of the five are best-effort and the
  run still fails only if the app listing does.

- **The sign-in activity report asks for full-size pages.** It was the last paged
  read still on Graph's default of 100 rows, which made it a 10× round-trip
  multiplier on the slowest, most rate-limited endpoint the audit touches — a
  10 000-principal tenant walked ~100 serial pages where ~11 will do. As a side
  effect its 200-page ceiling now covers ~200 000 rows instead of 20 000.

## [0.21.1] - 2026-07-27

### Changed

- **Lists, search, and the DR backup now share one app-registration
  enumeration.** There was a shared, cached service-principal index but no
  `/applications` equivalent, so `/applications` was enumerated tenant-wide from
  five places with five projections — three of them (the Enterprise Apps pairing
  join, the DR backup's estate read, the mailbox probe's routing map) **uncached**
  and re-run every time. They now read one typed, pinned per-tenant index, the
  same way every service-principal reader already shares `sp_index`. A cold
  Enterprise Apps load right after browsing App Registrations, or a backup right
  after either, no longer pays for its own full-tenant scan; when two indexes are
  cold together they are fetched concurrently rather than serially. Global search
  keeps degrading each half of its corpus independently, so one unreadable index
  can't blank the other's results.

  Two consequences worth knowing: the search corpus is now bounded at the same
  10 000-app cap as every other tenant-wide enumeration (it was unbounded, which
  meant it could disagree with the lists on a very large tenant), and the shared
  index is pinned against LRU eviction, so a mail-heavy audit run can no longer
  push it out and force the next list visit to rescan.

- **Every paged Graph read asks for full-size pages.** Paging is strictly serial,
  so an omitted `$top` left Graph on its default of 100 rows — a 10× round-trip
  multiplier. The app-role assignment, delegated-grant, owner, and group-membership
  reads (and their `$batch` sub-requests) now request the documented maximum, as do
  the managed-identity and tenant-resource service-principal scans, which had been
  paging at 200 while the neighbouring index scan used 999.

  The one operators will feel is the security audit: it reads every
  application-permission grant in the tenant from a single collection before it
  can score anything, and that read was the run's longest serial prologue.

- **The DR backup no longer rescans every service principal to find the managed
  identities.** It fetched the SP index and then issued a second, near-identical
  full `/servicePrincipals` scan filtered to managed identities — whose entire
  payload the index already carried. The managed-identity list had already been
  fixed this way; the backup had not.

- **Admin consent reads the app's delegated grants once, not once per resource.**
  `grant_admin_consent` hoisted its app-role snapshot out of the per-resource loop
  but left the matching delegated-grant read inside it, so an app declaring N APIs
  re-read the same grant collection N times. Both snapshots are now taken once, up
  front, and concurrently.

### Fixed

- **A hung connection could stall a Graph call for the full request timeout, on
  every retry.** The HTTP client had a 60-second total-request budget — sized for
  the slowest legitimate response — but no separate connect budget, so a host that
  never completed a handshake burned the whole 60 seconds before the retry loop
  saw a failure, and then did it again. Connections now time out in 10 seconds;
  idle sockets are also held long enough to survive the quiet gaps between fan-out
  waves.

- **Retried writes no longer re-serialize their request body.** The body was
  built inside the retry loop, so every 429/5xx retry re-encoded the payload —
  most visibly on the 20-sub-request `$batch` POSTs, which retry precisely when
  the tenant is already under pressure.

- **`prewarm_sps` measured its seeding budget against the wrong cache bound**
  (the global entry cap rather than the per-kind one from `Cache::capacity_for`),
  so it would under-seed the service-principal bucket, which is allowed to be
  larger. No live caller hit this — the only remaining one seeds a kind where the
  two bounds coincide — but the helper exists to be kind-generic.

## [0.21.0] - 2026-07-25

### Added

- **Keyboard shortcuts for the surfaces you move between constantly.**
  `Cmd/Ctrl-1…5` jump to Home / App Registrations / Enterprise Apps / Managed
  Identities / Security; `/` focuses the **current list's** filter (deliberately
  distinct from `Cmd/Ctrl-K`, which searches the whole tenant); `Cmd/Ctrl-W`
  closes the open item; `?` shows the full list. Bare-key bindings never fire
  while you're typing in a field.

- **The security audit scores reach beyond the tenant (Rules 19 & 20).**
  `signInAudience` and `verifiedPublisher` were both fetched, carried on
  `AuditItem`, and exported to CSV — but nothing scored them, even though
  Rule 15's own guidance leans on multitenant risk. A new
  `rule_external_exposure` flags an app whose audience lets other directories
  (or personal Microsoft accounts) consent to it **while it holds application
  permissions or credentials**, and adds a second finding when such an app also
  has no verified publisher. The gating is deliberate: the audience is a
  blast-radius multiplier on other findings rather than a finding on its own,
  so a multi-tenant app holding nothing is not flagged, and publisher
  verification is only assessed where a foreign admin actually has to attribute
  the app. Unrecognised audience values never inflate a score. Surfaced as a
  "Reachable outside this tenant" group in the Findings pane.
  **Operators will see some scores rise**: an app can gain up to 5 points.
- **Exchange mailbox scoping can be removed from the app.**
  `remove_exchange_mailbox_access` shipped as a registered command with no UI,
  so an operator could *create* Exchange RBAC scoping here but had to drop to
  PowerShell to undo it. The scoping section now has a "Remove all…" action
  behind a confirmation that states plainly what it does — reverting to the
  org-wide access the Entra grant allows, which **widens** access rather than
  revoking it.

- **The Security workbench now has an Application permissions lens.** The
  tenant-wide inventory of every *application* permission
  (`appRoleAssignment`) apps hold on Microsoft Graph / Exchange / SharePoint
  was fully implemented backend-side — `list_app_permission_grants`,
  `save_app_permission_grants_to_file`, the DTO, and the frontend binding all
  shipped — but **nothing ever called the binding**, so the feature the README
  advertised was unreachable. It is now a fifth sub-tab
  (`views::app_permission_grants_view`) alongside Delegated grants, with
  risk facets, a high-risk banner, search across app/permission/resource,
  CSV **and** JSON export, and a deep-link into each holder's Enterprise
  Application permissions tab. Both grant lenses are now registered in
  `demo::register_fixtures` too, so the hosted demo shows them populated
  rather than in an error state.

### Fixed

- **The security audit no longer evicts its own service-principal cache
  seeding.** `seed_lean_sps_from_index` wrote one entry per app registration
  (up to 10 000) into a bucket capped at 5000, so past entry 5000 every insert
  LRU-evicted one of this same pass's earlier entries — and each evicted app
  then fell back to an individual Graph GET, the exact N+1 the function exists
  to remove. The predecessor it superseded (`prewarm_sps`) had the guard; it
  was not carried over. The pass is now bounded by the bucket size, and
  `CacheKind::ServicePrincipal` — which holds one small entry *per directory
  object* rather than a handful of tenant-wide aggregates — is capped at the
  10 000-app enumeration ceiling instead of the aggregate-sized
  `MAX_CACHE_SIZE`, so a large tenant actually fits.
- **Cache eviction is no longer quadratic.** `evict_lru` picked its victim with
  a `min_by_key` scan over the whole bucket (up to 5000 entries) plus a key
  clone, repeated per eviction and held under the bucket lock — so a seeding
  pass cost millions of comparisons while blocking every other reader of that
  bucket. Eviction now pops from a `tick -> key` ordering index in O(log n).
- **Tenant-wide index entries can no longer be evicted by per-app churn.** The
  `Lists` bucket holds the expensive directory indexes (`sp_index`,
  `apps_pairing`, the search/gallery corpora) alongside thousands of cheap
  `app_detail|…` / `mail_scopes|…` entries, so one mail-heavy audit run could
  evict indexes that cost a full tenant scan to rebuild. `put_index` /
  `put_typed_index` mark those entries exempt from LRU (TTL and tenant
  invalidation still apply, so sign-out cannot leak them across tenants).
- **`/applications` scans page at Graph's documented maximum.** The browse
  list, the security audit, the credential-expiry dashboard, and the bulk
  credential sweep all paged at `$top=100` under a comment claiming "Graph caps
  `$top` at 100 on `/applications`" — Graph documents the maximum as **999**,
  and this codebase already used 999 on the same endpoint elsewhere. Paging is
  strictly serial, so at the 10 000-app ceiling this was 100 sequential round
  trips where 11 suffice. Larger pages also *reduce* throttling on these
  queries, which `$select` `keyCredentials` and so fall under Graph's
  150-requests-per-minute-per-tenant limit for that projection.
- **Plain `/applications` enumerations no longer run as advanced queries.**
  Every page carried `$count=true` (whose `@odata.count` has no reader on this
  path) and `$orderby=displayName` (sorting happens in the frontend), forcing
  `ConsistencyLevel: eventual` handling for values that were discarded. Both
  are now scoped to the `$search` path, which genuinely requires them. This
  also removes an officially **unsupported** combination from the audit's scan:
  Graph does not support `$expand` together with an advanced query, and
  documents that such combinations may fail *silently* — which would have left
  the audit's inline owner ids quietly missing. The audit's `$expand=owners`
  truncation limit (20 items, no `nextLink`) is now documented at the call site.
- **A failed managed-identity load no longer claims the identity was deleted.**
  `ManagedIdentityDetailWindow` collapsed the fetch error with `.ok()`, so a
  transient 429 rendered "Identity not found — it may have been deleted" with
  no way to retry. Fetch failure and genuine absence are now distinct: the
  former routes through `DetailLoadError` (message + Retry), the latter keeps
  the empty state. Its full-window `Spinner` is also now a `DetailSkeleton`,
  matching the other detail panes.
- **The Security audit's "Risk" column header shows its sort direction.** It
  drove `SortCol::Score` but rendered no sort glyph, so clicking it silently
  re-sorted the table with no visible feedback.

### Removed

- **Five unreachable Tauri commands (171 → 164).** `kv_set_secret`,
  `resolve_permission`, `update_required_resource_access`, and
  `current_tenants` were registered on the IPC boundary and bound in the
  frontend, but **no view ever called them** — untested, unreachable surface on
  a security-critical boundary. `kv_set_secret` in particular duplicated a
  write path `rotate_app_credential` already performs itself (and which also
  mints the credential and records the vault binding), so the sanctioned
  rotation flow is unaffected. `export_audit_csv` stays as an internal helper —
  `save_audit_to_file` is its only caller — but loses its command registration.

### Changed

- **Large tenants are markedly faster to browse and audit.** Several hot paths
  were doing far more work than they needed: the app/enterprise/managed-identity
  lists re-materialized their filter state on every keystroke (at the 10 000-app
  ceiling, ~10 000 string allocations per keypress); the audit's name sort
  allocated inside its comparator; filter predicates allocated per row per pass;
  and facet counts made one full pass over the row set *per facet*. The
  SharePoint site sweep now reads permissions in `$batch` POSTs of 20 rather
  than one request per site (5 000 requests → 250 at the sweep cap) and backs
  off adaptively on 429s like the audit does. The observed-Graph-activity panel
  no longer re-runs a whole subscription × workspace sweep on every open when
  the tenant has no activity export — the "not configured" answer is cached too.
  Three redundant tenant-wide directory scans were removed.

- **The app follows your OS light/dark setting while it's running.** The theme
  was sampled once at launch while the stylesheet reacted live, so flipping the
  OS theme left form controls, buttons, and tabs light on dark chrome until
  restart.

- **Muted text and warning colours now meet WCAG AA.** `--text-faint` was ~3.0:1
  on white and `--warning` ~3.7:1 despite being used as a text colour; both now
  clear 4.5:1. Zero-count filter chips were dimmed with 40% opacity over
  already-muted text — well under 3:1 — and are now muted by colour instead.

- **Bulk-action failures name the app that failed.** Every bulk result except
  remove-expired-credentials labelled failures with the raw object id, so a
  failure list after a large run was a column of GUIDs.

- **The open-items workspace behaves like the modal it visually is.** It covers
  the list opaquely but left the content underneath reachable by Tab and by
  screen readers, and carried no landmark role. It now marks the covered region
  inert while shown.

- **The Security workbench's sub-tabs are keyboard-navigable.** The lens
  selector was a hand-rolled third tab implementation with no `role="tablist"`
  / `role="tab"`, no `aria-selected`, and no arrow-key navigation — on the
  workbench's own top-level navigation. It now uses the shared
  `components::ui::TabBar`, which implements the WAI-ARIA tabs pattern
  (roving tabindex, Left/Right/Home/End). The dead `.security-lens*` CSS is
  removed.
- **The Credential-expiry and Delegated-grants lenses use the shared
  primitives.** `AuditDashboard` bypassed four of them at once: a raw Thaw
  `Input` (so no clear button, while its own empty state told users to change
  the filter), a hand-rolled error block instead of `DetailLoadError`, a bare
  `Body1` instead of `EmptyState`, and a text "Export CSV…" button instead of
  `ExportMenu` + a `busy` `IconButton` — so these lenses alone offered no JSON
  export and no refresh feedback. All four now route through the primitives.
- **`AuditDashboard` no longer re-filters and rebuilds its whole table on every
  reactive tick.** The filter ran inline in the render closure rather than in a
  `Memo`, and the `<table>` was rebuilt wholesale with no keyed `<For>`, so
  "Show more" re-filtered every row and rebuilt all of them — on the surface
  its own comment describes as holding thousands of rows. The filter is now a
  `Memo` over row indices and the body is a keyed `<For>`.
- **README: the Updates section described a flow the app does not implement.**
  It stated updates are "downloaded and applied automatically — there is no
  prompt". The actual flow is interactive: a launch-time check raises a
  notification, and the update installs only on an explicit **Update &
  restart** from the changelog splash. The section now documents that (and the
  on-demand "Check for updates"), and the "auto-updates silently in place"
  claims on the Windows/macOS install notes are corrected.

## [0.20.5] - 2026-07-23

### Fixed

- **Access Readiness no longer takes tens of seconds to load in a large Azure
  estate.** The Azure-RBAC plane's role-assignment enumeration
  (`commands::readiness::enumerate_azure_role_ids`) issued one ARM round trip
  per subscription in a serial loop, so page load scaled linearly with the
  operator's subscription count. It now fans out with the same bounded
  `ARM_CONCURRENCY` (8) `buffer_unordered` pattern the Key Vault and
  managed-identity sweeps already use. A subscription the user can't read is
  still skipped (and now logged) rather than failing the report.
- **`check_readiness` runs its three authorization planes concurrently.**
  Directory roles (Graph), the scope probes (token endpoint), and the ARM
  role-assignment sweep share no inputs but were awaited one after another;
  they're now joined, so the page's cold latency is the slowest single plane
  instead of their sum. Each plane still degrades to `Unknown` independently.
- **The Key Vault picker (`list_available_key_vaults`) no longer serializes its
  cross-subscription sweep.** Like the readiness fix above, it looped
  subscriptions one ARM round trip at a time; it now fans out with the shared
  bounded `ARM_CONCURRENCY` (8) `buffer_unordered` pattern, and a subscription
  it can't read is logged and skipped rather than silently swallowed.
- **"Browse the gallery" search is no longer slow on every keystroke.** The
  New-application gallery picker matched server-side with a non-indexable
  `contains(tolower(…))` `$filter` (plus `$count=true`), so every uncached query
  — and each debounced keystroke was a distinct one — was a full-catalog scan
  costing seconds. It now fetches the whole gallery **once** (unfiltered, at the
  endpoint's `Prefer: odata.maxpagesize=2800` ceiling), caches the corpus, and
  matches every subsequent query in memory. The picker prewarms the corpus on
  open (`prefetch_application_gallery`) so the first search is warm, and match
  counts are now exact instead of derived from a capped fetch pool.

## [0.20.4] - 2026-07-20

### Changed

- **Rust toolchain and MSRV move 1.96 → 1.97.1.** `rust-toolchain.toml` pins
  the exact patch (1.97.1) so a silent stable bump can't break builds, and the
  workspace `rust-version` floor (root `Cargo.toml` + `apps/desktop/web-rs`)
  rises to 1.97 in lockstep. The six `dtolnay/rust-toolchain` SHA pins across
  `ci.yml`, `codeql.yml`, `pages.yml`, and `release.yml` advance to the matching
  `1.97.1` commit so CI, CodeQL, the Pages demo, and the release matrix all
  build on the same compiler as local `just verify`.
- **Silenced 1.97's new `clippy::byte_char_slices` lint** in the demo/test IPC
  mock's deterministic UUID helper — the variant-nibble table is now `b"89ab"`
  instead of `[b'8', b'9', b'a', b'b']`. Behaviour is identical; without it
  `just web-clippy` (`-D warnings`) fails on the new toolchain.
- **Semver-compatible dependency refresh across both lockfiles.** `cargo update`
  on the root workspace and the separate `apps/desktop/web-rs` tree — notably
  `tokio` 1.52.3 → 1.53.0, `serde`/`serde_json` 1.0.228/1.0.150 → 1.0.229/1.0.151,
  `thiserror` 2.0.18 → 2.0.19, `uuid` 1.23.5 → 1.24.0, `time` 0.3.53 → 0.3.54,
  `futures` 0.3.32 → 0.3.33, `tauri-plugin-dialog` 2.7.1 → 2.7.2, and the
  `zbus`/`zvariant` stack. No manifest constraints changed. `syn` 3.0.2 now
  appears alongside 2.x via proc-macro dependencies; `deny.toml` treats
  duplicate versions as a warning, and `bans/licenses/sources` stay clean on
  both trees.
- **Corrected the stale `rsa` justification in `.github/dependabot.yml`.** The
  `rand >= 0.9` / `sha2 >= 0.11` ignores were documented as working around a
  conflict with `rsa` 0.9 — but `rsa` is not in the dependency graph at all
  (rcgen on `aws_lc_rs` keeps it out). The real constraint is that `oauth2` 5
  and `tauri-codegen` already resolve to `rand` 0.8 / `sha2` 0.10, so bumping
  our direct pins would duplicate a crypto major rather than replace one.

### Fixed

- **The top-bar account/settings dropdown no longer dies when a detail item is
  open.** `.shell__topbar` establishes a stacking context (`position:relative;
  z-index:10`), so its account menu — where "Settings" lives — was capped at the
  topbar's level. The open-items workspace overlay (`.workspace`, `z-index:500`)
  sits in the root stacking context, so `500 > 10` meant the menu, which opens
  downward into the content row the workspace covers, rendered *behind* the
  overlay: the pill still toggled but the menu was invisible and unclickable
  until the open app registration was closed. Raised `.shell__topbar` to
  `z-index:600` — above the workspace, below the modal scrim (`z 1000`). The
  topbar is grid row 1 and never geometrically overlaps the row-2 workspace, so
  this only changes paint order for the downward-hanging menu. (Teleporting the
  menu to `<body>` to escape the context is out — a Thaw overlay froze the
  WebView2 webview on teardown, per the `styles.css` note.)

## [0.20.3] - 2026-07-17

### Fixed

- **Gallery search finally searches the whole gallery — by asking the server.**
  The 0.20.2 fix assumed `$top=200` pages `GET /applicationTemplates` via
  `@odata.nextLink`; in reality `$top` is a **total result limit** on that
  endpoint and a `$top`ed response carries **no nextLink** (verified live), so
  the "full catalog" was still just the first 200 rows of what turns out to be a
  **38,922-template** gallery — and apps like CrowdStrike Falcon Platform stayed
  unfindable. Fetch-and-match-locally is unsalvageable at that size, so the
  search now runs **server-side**:
  `$filter=contains(tolower(displayName|publisher),'…')` per query token
  (case-insensitive — bare `contains` is case-sensitive on this endpoint —
  and substring-capable, unlike the `startswith` the 0.20.1 fix removed), with
  `$count=true` so "showing the closest N of M" reports the server's true
  total. The fetched candidate pool is still ranked locally
  (exact → prefix → word-boundary → substring) and each ranked reply is cached
  per query.
- **The Pages demo's gallery no-match message now admits its catalog is a
  sample.** Searching the demo for an app outside its curated catalog said
  "No gallery apps match …", implying the full gallery had been searched —
  which reads as a broken search to anyone who knows the app exists. The demo
  now flags its catalog as partial (the picker's existing "only partly loaded"
  wording), and CrowdStrike Falcon Platform joins the sample catalog.

## [0.20.2] - 2026-07-17

### Fixed

- **Gallery search now covers the whole catalog, not a truncated slice.** The
  0.20.1 fetch requested `GET /applicationTemplates` with `$top=999`, but that
  endpoint caps the page size at **200 once any query parameter is applied**
  (and `$select` is), and a `$top` above the endpoint's max is documented to be
  ignored, clamped, or rejected. Depending on how the tenant's Graph handled the
  over-limit hint, the gallery could come back as a single truncated page, so the
  in-memory search silently missed every template past the first slice — apps
  were unreachable by substring (or any) query even though the matching logic was
  correct. The request now uses `$top=200` (the honoured maximum) and pages
  through the full ~3k-template gallery via `@odata.nextLink`, fetched once and
  cached per tenant.
- **Gallery search in the GitHub Pages demo now actually searches.** The demo
  mocks the Tauri backend, and its `search_application_templates` stub returned
  the entire sample catalog for every query — so the picker looked broken (every
  keystroke showed the same list). The demo mock is now args-aware: it runs the
  same token-AND / exact → prefix → word-boundary → substring ranking as the
  backend over an expanded sample catalog, so `force` → Salesforce and
  `teams` → Microsoft Teams behave in the demo as they do against a live tenant.
  This mock bug was demo-only and independent of the fetch-truncation fix above.

## [0.20.1] - 2026-07-15

### Fixed

- **Entra app-gallery search now finds apps it was missing.** The "Browse the
  gallery" picker filtered server-side with
  `$filter=startswith(displayName,'…')`, so it only ever matched a **prefix**:
  searching `force` never found "Salesforce" and `365` never found "Office 365".
  `GET /applicationTemplates` supports neither `$search` nor a documented
  `contains()`, so the gallery is now fetched whole (paged via `@odata.nextLink`,
  cached per tenant for 60 minutes) and matched in memory — hitting anywhere in a
  template's display name **or publisher**, ranked exact → prefix →
  word-boundary → substring, with multi-word queries matching regardless of word
  order. Searching is also now instant after the first load, since each keystroke
  no longer makes a Graph round trip. Three compounding defects went with it:
  results were silently capped at the 25 alphabetically-first matches with no
  "more results" signal (the reply now carries `total_matches`/`truncated`, and
  the picker says so); templates with no `displayName` were silently dropped
  (they now fall back to publisher, then template id); and the minimum-query gate
  counted **bytes**, so a single-character CJK query slipped past a gate labelled
  "2+ characters" (it now counts characters, on both sides of the IPC boundary).

- **A gallery search that matches nothing now says so.** The picker rendered
  "Type an app name to search the gallery." for *both* an empty query and a
  zero-result search, telling operators to start typing when they already had —
  which is what made the prefix-matching bug above read as a broken search rather
  than a miss. It now distinguishes the two, and admits when the catalog it
  searched was only partly loaded instead of implying the app doesn't exist.

### Changed

- **Full dependency refresh.** Ran `cargo update` across both lockfiles (root
  workspace and the excluded `web-rs` WASM tree), advancing all crates to their
  latest semver-compatible versions — notably `rustls` 0.23.42, the
  `wasm-bindgen`/`web-sys`/`js-sys` 0.2.126/0.3.103 family, `zbus` 5.17.0, `regex`
  1.13.0, and `uuid` 1.23.5. No manifest version requirements changed; the
  deliberate crypto pins hold (`rand` stays on 0.8, `sha2` on 0.10, no `rsa`
  introduced), and the web-rs tree stays within the Rust 1.96 MSRV floor. `audit`
  and `deny` pass clean on both trees.

  Re-audited for this release: no major/minor bumps are available. `rand`
  (0.8 → 0.10) and `sha2` (0.10 → 0.11) remain the only outdated direct deps,
  and both are blocked upstream rather than by preference — `oauth2` 5.0.0 is
  the latest release and still requires `rand` 0.8 + `sha2` 0.10, with `sha2`
  0.10 additionally required by `secret-service` 5.1.0 and `tauri-codegen`
  (`tauri` 2.11.5, also latest). Bumping either would compile a *second* crypto
  major beside the first rather than move one.

## [0.20.0] - 2026-07-08

### Added

- **Resource Access → Mailboxes results are now clickable for investigation.**
  Each app in the "who can reach this mailbox?" table gets an "Open for
  investigation" link that routes to the right detail pane the same way the
  Security audit does — a local app registration opens the App Registration pane,
  a foreign enterprise app the Enterprise pane, a managed identity the Managed
  Identity pane — landing on Permissions where the grant can be reviewed or
  revoked.
- **"Add default owners" in the audit's owner remediation.** The Security audit's
  "Add owner" fix (for the "No owners" / "Single owner" finding) now has an "Add
  default owners" button that applies the owners configured for the tenant in
  Settings in one click — additive, skipping anyone already an owner — alongside
  the existing directory search. Previously the finding could only be closed by
  searching and picking each owner by hand.

### Changed

- **Mailbox reverse-lookup hides confirmed "No access" by default.** The results
  led with every candidate app, most of them confirmed non-reachers; the table now
  shows the apps that can reach the mailbox plus any the tool couldn't confirm, and
  collapses confirmed "No access" behind a "Show N with no access" toggle. The
  summary calls out how many verdicts couldn't be confirmed (an Exchange RBAC check
  that needs admin rights), and the "Unknown" badge gained a tooltip clarifying it
  means *possible* access, not a contradiction of a "blocked" detail line — so a
  row that is blocked on one path but unverifiable on the other reads correctly.
- **Home "App registrations" card button label.** Its "View all" button is now
  "View app registrations", matching the other Home cards ("View enterprise apps",
  "View managed identities", "View credentials").
