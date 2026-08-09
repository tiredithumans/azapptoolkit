# Changelog

All notable changes to azapptoolkit are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Older releases (**0.19.2 and earlier**) live in
[docs/CHANGELOG-archive.md](docs/CHANGELOG-archive.md).

## [Unreleased]

### Fixed

- **A security audit that could not read an API's permissions no longer reports
  itself as clean.** When the toolkit failed to look up the permission
  definitions for a resource — Microsoft Graph itself, most consequentially —
  every application declaring permissions against it was scored as though it
  declared none. Those apps stayed in the results looking spotless, the run
  reported no coverage gaps, and it was then cached as an authoritative scan, so
  re-opening Security showed the same false all-clear without re-running. The
  failure is now reported alongside the other coverage gaps, which means the run
  is neither cached nor shown as complete. The lookup is also shared across
  applications now instead of being repeated once per app on a cold run.
- **A cache read through the wrong accessor no longer discards the tenant-wide
  index it was looking for.** Reading one of the pinned indexes with the plain
  untyped accessor is documented to cost a miss and a rescan; it in fact
  *deleted* the entry, because the decode failure looked identical to a
  corrupted value. One such read anywhere threw away the index every list,
  search and audit surface shares, and the next visit to any of them paid for a
  full directory scan.

- **The legacy-policy migration can now be stopped, and a stopped run says so.**
  Migrating Application Access Policies across a whole tenant looped over every
  affected app doing Exchange and Entra writes with no Cancel and no
  dead-session check: pressing Cancel did nothing, and a session that expired on
  the first app still worked through all of them, producing one identical
  failure line per app that reads as the tenant refusing the writes. It now
  stops on either, and the report is marked incomplete so the apps it never
  reached are not mistaken for migrated ones.
- **Cancel now works during the slowest part of a security audit.** The audit
  took its cancellation handle *after* the tenant-wide prefetch that dominates a
  large run, so a Cancel pressed during that phase — the likeliest moment —
  was discarded and the run scored the whole tenant anyway.
- **Cancelling a restore now stops it.** Cancel was only checked while the app
  shells were being created; once that finished, the remaining four passes
  (wiring, consent, enterprise apps, managed identities) ran to completion
  regardless.
- **A redundant permission held on two resources is no longer missed.** The
  audit decided redundancy from whichever grant it happened to see first, so a
  `Mail.Read` on Microsoft Graph could silently suppress the genuinely redundant
  `Mail.Read` on Office 365 Exchange Online sitting beside a `Mail.ReadWrite`.
  Two tenants with identical grants could score differently. Findings now name
  which resource the pair lives on, rather than leaving you to guess which
  `Mail.Read` to remove.
- **The "Remove redundant permissions" fix can no longer revoke access nothing
  covers.** The audit deliberately does not flag a narrower permission when the
  broader one covering it is confined to specific mailboxes — a confined
  `Mail.ReadWrite` does not cover an org-wide `Mail.Read`. The one-click fix
  re-planned from live state without that rule and would have removed it. It
  now applies the same rule, and skips the removal when Exchange cannot confirm
  the scope rather than guessing.
- **Least-privilege suggestions stop pointing at the wrong resource.** They
  offered Microsoft Graph alternatives for Office 365 Exchange Online grants
  (which do not exist there) and fired for permissions already confined via
  Exchange RBAC.
- **A whole-tenant migration is no longer split in two by GUID casing.** Policies
  for one app were grouped case-sensitively, so the same application appearing
  with differently-cased ids became two batches — the exact failure the
  one-batch-per-app rule exists to prevent.
- **A cached tenant-wide index is no longer evicted by a write that lost a
  race.** Two concurrent refreshes could end with the loser deleting the
  winner's freshly-validated index, costing a full re-scan on the next read with
  nothing to explain it.

- **A bulk action no longer burns through the rest of your selection after the
  session dies.** The expired-credential sweep, the delete sweep and the
  consent-grant sweep each fanned out without checking whether the session was
  still alive, so an expired refresh token mid-run produced one identical
  failure per remaining app — a wall of "permission denied" that reads as the
  tenant rejecting the writes rather than as a session that ended on app 40 of
  900. All three now stop at the next dispatch boundary and report that the run
  was cut short; the writes that already landed still bust the caches, so the
  list you come back to is accurate.
- **Cancelling a long-running run can no longer be silently undone by starting
  another one.** The cancel flag was a bare boolean that every run reset at its
  start, so a second command beginning cleared a cancellation the first had not
  yet noticed and that run carried on writing. Cancellation is now per-run:
  starting a run says nothing about any other, and a run that has been cancelled
  stays cancelled. A tenant backup also claimed a second time partway through,
  which dropped a Cancel pressed during its first phase at the phase boundary.
- **Global search no longer hides a whole entity class for an hour after one
  transient error.** A failed read of either half of the search corpus degraded
  to an empty list — and that half-empty corpus was then cached and pinned, out
  of the cache's own eviction reach, so every app registration (or every
  enterprise app) stayed missing from search for the full list TTL. A partial
  corpus is still served to the query in flight, but never cached, so the next
  keystroke retries.
- **A cache entry invalidated while an index was being stored can no longer
  survive the store.** The generation guard released its watch *before* taking
  the bucket lock, leaving a window where an invalidation found no watch to bump
  and no entry to remove — and the pre-mutation snapshot then landed, pinned.
  The watch is now held across the store and the write rolled back if anything
  invalidated the key meanwhile.
- **The Exchange admin API no longer returns a truncated collection as a
  complete one.** An empty body or a "not found" while following an
  `@odata.nextLink` was reported as success (or, worse, as an absent object) for
  the pages read so far. Both now fail: the consolidation planner and the
  reverse scope lookup treat a short list as proof of absence, so a truncated
  read widens access.
- **Signing out now tells you when it did not work.** The result was discarded
  and the app returned to the sign-in screen regardless, so "signed out" was a
  claim it had never checked — while the refresh token was still in the OS
  credential store. A failed sign-out now keeps you signed in and says why.
- **A scoped-mailbox grant no longer half-applies when Exchange's role
  assignments cannot be read.** The pre-read defaulted to an empty list on
  failure, so every role was re-assigned, every duplicate assignment failed, and
  no org-wide grant was safe to strip — leaving the app with neither a working
  scope nor a narrowed grant, repeatably. An unreadable snapshot is now an
  error.
- **The audit's "already covered by" advice no longer pairs permissions across
  resources.** Both Microsoft Graph and the legacy Office 365 resources expose
  app roles named `Sites.*` and `Mail.*`, and the redundancy rule matched on the
  name alone — so a Graph `Sites.Read.All` was reported as covered by an Office
  365 `Sites.ReadWrite.All`, which authorizes nothing of it. The one-click fix
  always re-planned per resource and did nothing here, so the advice disagreed
  with the remediation beside it; an operator following the text by hand would
  have removed live access.
- **A mailbox permission is resolved to the resource that can actually scope
  it**, rather than to whichever resource happened to come first in the list.
- **A management scope cannot be repointed at a filter that confines nothing,**
  and the post-write proof no longer accepts a filter it could not fully read.
  A group whose distinguished name contains the text `memberofgroup` also no
  longer makes a filter this app generated unrewritable.

### Changed

- The security audit's redundant-permission findings and its one-click fix now
  name the resource alongside the permission (`Mail.Read on Microsoft Graph`),
  since the same name on the legacy Office 365 resource is a different grant.
  No score or ranking changes.
- Least-privilege downgrade suggestions are no longer offered for permissions
  already confined via Exchange RBAC.
- `verify-full` now runs the frontend shard-size gate, so it matches CI; a check
  derives the gate list from `ci.yml` so the two cannot drift again.
- The Graph, ARM and Key Vault error taxonomies come from one definition in
  `azapptoolkit-core::http_error` instead of three identical hand-maintained
  copies, and Graph's `$batch` retry now shares the same budget and backoff as
  every other client instead of re-deriving them.
- Retry policy (budget, backoff, `Retry-After`) is now one loop in
  `azapptoolkit-core::http_retry` instead of four near-identical copies across
  the Graph, ARM, Key Vault and Exchange clients. Behaviour is unchanged; the
  clients still classify their own HTTP statuses.
- `repo_invariants` is split per concern (fan-out, cache, cancel, commands,
  release), and its dead-session rule is checked per `dispatch_capped` **call
  site** rather than per file — the file-level form reported full coverage over
  the three ungated bulk fan-outs above, which is worse than no check.
- Local test coverage for the `.env` and CHANGELOG parsers in both `build.rs`
  files, and for the SAML claims editor's DTO conversion.

## [0.25.0] - 2026-08-07

### Added

- **"Copy all details" on the SSO tab's app-owner summary.** One button copies
  every value the application owner needs as labelled plain text, ready to paste
  into mail or a ticket, instead of copying eight fields one at a time.
  Multi-line values (redirect-URI lists, the SAML signing certificate) are
  indented under their label so a mail client's wrapping cannot run two URIs
  together. For OIDC the **client secret is deliberately excluded** — the block
  is meant for mail or chat, and a credential granting the application's
  identity does not belong there; the copied text says so and the secret keeps
  its own separate copy button.

### Fixed

- **The window no longer scrolls sideways, and content no longer falls off the
  right edge, below about 1000px.** `.shell__main` sized the single column it
  creates for its own children to their widest min-content, so every row —
  top bar, page content, the open-items dock — rendered wider than the window
  and pushed the tenant switcher, the Delete button and the detail tab strip out
  of view. The same bare-`1fr` pattern in the open-items workspace could spill a
  detail pane past its half.
- **The Security Posture card's finding counts sat outside the card.** The
  findings list used an implicit `auto` grid track, which grew to the longest
  finding name ("Legacy Application Access Policy scoping") and pushed each
  row's count and chevron past the card's border. Titles now ellipsize and the
  row stays inside the card.
- **The tenant name is no longer squeezed to an initial on a narrow window.**
  The centred search field was capped against the whole window rather than the
  space beside the tenant chip, so between roughly 740px and 1024px it kept its
  full width and "Contoso Ltd" rendered as "C..". The search yields first now.
- **Seven full-width rows rendered wider than the container they fill** — the
  Permission Tester's identity field (visibly 22px wider than the mailbox field
  below it), the account-menu and vault-picker options, the nav items, the
  global-search rows and the gallery results — each overflowing by exactly its
  own horizontal padding.
- **Org-wide Graph `Calendars.*` and `Contacts.*` grants now appear in the
  mailbox audit, and can be scoped.** The advisory's membership test matched
  `Mail.*` and `MailboxSettings.*` by name only, while the toolkit's own role
  table maps Graph's `Calendars.Read/ReadWrite` and `Contacts.Read/ReadWrite`
  to real RBAC-for-Applications roles. Membership is decided *before* the
  org-wide / scopable / unscopable split, so an application reading or writing
  every calendar and every contact in the tenant produced no finding and was
  never offered "Scope…" — while the identically named grant on the legacy
  Office 365 Exchange Online resource was reported. **This raises risk scores
  for applications holding those grants**, which previously scored as if the
  permissions did not reach mailboxes at all.
- **Exchange admin-API collection reads now follow `@odata.nextLink`.** The
  transport deserialized the `value` array and discarded the continuation link,
  so every unbounded read — group members, management scopes, Exchange service
  principals — silently stopped at the first page (1000 entries by default) and
  returned a short list indistinguishable from a complete one. Scope
  consolidation and the reverse "which scopes reference this group" lookup both
  treat absence as proof, so a truncated read could retire a scope that was
  still in use. A response exceeding the page ceiling is now an error rather
  than a partial collection.
- **A scoped-mailbox grant no longer proceeds against a management scope it
  could not check.** The fail-closed guard that refuses when an existing scope
  targets a different group set was written so that both a failed read *and* a
  scope with no recipient-restriction filter skipped it entirely — falling
  through to assign roles against that scope and strip the org-wide grants,
  confining the application to something the operator never specified. Both
  cases now refuse and change nothing.
- **An audit that could not score every application no longer reports as a
  complete scan.** A transient per-application scoring failure was logged and
  the application dropped from the results, while the run still reported
  nothing cancelled, truncated or degraded — and cached itself as
  authoritative. Such a run is now flagged in the Findings pane and is not
  cached, like its two sibling coverage gaps.
- **The audit now says when part of its analysis could not run, instead of
  presenting a lower score as a clean result.** Two tenant-wide reads — Graph
  app-role assignments and org-wide EWS full-mailbox-access grants — were
  best-effort: a failure logged a line and returned an empty map, which is
  indistinguishable from "this tenant has none". The run then scored *lower*
  risk, skipped every enterprise app / managed identity / orphaned service
  principal, and cached the result as authoritative. Such a run is now flagged
  in the Findings pane, names what it could not determine, and is not cached.
- **Mailbox permission scoping is now decided by the permission's resource, not
  its name.** Office 365 Exchange Online exposes its own `Mail.*`,
  `Calendars.*`, `Contacts.*` and `MailboxSettings.*` appRoles (retired Outlook
  REST) that RBAC for Applications cannot confine, and they share their names
  with Microsoft Graph's. Six gates tested the bare value, so a legacy grant was
  counted as scopable mailbox reach, offered as a scoping candidate, and allowed
  to take a legacy Application Access Policy's reduced "scoped" weight — hiding
  genuinely org-wide mailbox access behind a healthy-looking verdict. The
  "Scope…" and "Grant access" actions are likewise offered only where the
  scoping can actually be applied.
- **A backup now reports the objects it could not capture.** Per-object read
  failures were logged at `warn` and the object silently dropped, so a short
  manifest restored as if those apps never existed. They are recorded on the
  backup and listed before you save it.
- **A restore that stopped because the session expired now says so.** The report
  carried the distinction all along; the DR view showed it identically to an
  operator-initiated cancel.
- **A failed tenant-wide index fetch no longer leaks its cache watch.** Watches
  were released only by a successful store, so every failed or cancelled index
  scan left one behind permanently. Once 256 accumulated, *every* pinned-index
  store refused for the life of the process — presenting as unexplained
  slowness (a full directory rescan on every read) with no error and no recovery
  short of a restart.
- **The App Registrations pairing join now actually seeds the shared
  service-principal index.** It reused one cache watch for two different keys,
  and the second store could never prove its key current, so it silently
  refused every time.

### Changed

- **Cache writes no longer sweep the whole bucket.** Every `put` ran a full
  expiry `retain` plus an LRU rebuild that clones every key, making each write
  proportional to everything else cached — under the lock interactive list reads
  contend on. The sweep now runs only when the bucket is at its cap or something
  has actually expired.
- **The legacy Application Access Policy migration planner moved into
  `azapptoolkit-exchange`.** The rules that decide which policies may be
  rebuilt as an allow-list, and whether a scope may be narrowed onto a partly
  verified group, are now pure functions with their own tests rather than logic
  reachable only through a live Exchange session.

### Added

- **`cargo deny` now blocks the `rsa` crate** (RUSTSEC-2023-0071), which was
  previously policy stated only in comments.
- **Repo invariants now check the properties, not just the shapes:** all four
  version literals agree, cache watches are captured *before* the fetch they
  guard (a capture-after is textually identical and silently disables the
  guard — two production sites had drifted), `generation_for` returns an owned
  guard, and the dead-session coverage allowlist must stay empty.
- The re-auth-fatal wire codes now have one definition shared by `UiError` and
  `TokenError`, with a test asserting the two agree.


- **Granting scoped mailbox access now refuses when the app's existing
  management scope covers different groups, instead of warning and proceeding.**
  Exchange keeps an existing scope rather than repointing it, so the groups you
  picked were never applied — but the org-wide grants were still stripped,
  leaving the app confined to whatever group set was already there. When that
  set was broader than the one requested, the result was an app reaching *more*
  mailboxes than you asked for, behind a warning. Nothing is changed now; use
  "Move to managed group" or edit the scope in Exchange, then grant again.
- **Repointing a management scope now verifies the new filter actually took.**
  The client re-read the scope afterwards but only proved one by that name
  existed — which was already true. It now compares the group set Exchange
  reports against the one requested (tolerating Exchange's own reformatting) and
  fails if they differ, rather than reporting success while every role
  assignment on that scope still points at the old groups.
- **The audit no longer reports a `Sites.Selected` grant as confirmed-scoped
  when it can't inspect it.** The healthy "SharePoint scoped to selected sites"
  verdict keyed off the permission name alone, so the same grant on the legacy
  Office 365 SharePoint Online resource — whose per-site grants this app cannot
  read — was shown as verified-confined.
- **A capped audit scan is no longer cached or presented as a clean result.**
  A tenant holding more app registrations than one run scores was silently
  scanned in part, and "no findings" from that partial scan looked identical to
  an all-clear. It is now surfaced like a cancelled run and never cached.
- **A restore now stops when the sign-in session expires mid-run.** All five
  passes kept going, producing one identical failure per remaining item, so a
  report full of errors read as the tenant rejecting the writes rather than as a
  session that died on the first one. The report still comes back — a restore
  has already created objects and you need to know which.
- **A cache index rebuilt while an unrelated key was invalidated is no longer
  discarded.** The store-after-invalidate guard added in 0.24.2 compared one
  process-wide counter, so a credential-only mutation — whose entire purpose is
  to preserve the two tenant-wide directory indexes — made a valid, in-flight
  index refuse to store, and every reader queued behind it then paid its own
  multi-second directory rescan. The guard is now per cache key.

### Changed

- **Inline notices render through one component.** Thirty files hand-rolled the
  notice markup instead of using the shared primitive, so the tone vocabulary
  could drift box to box; all of them now go through `Callout`, and a check
  keeps the markup in one place.
- **CI can be re-run manually** (`workflow_dispatch`). A cancelled run — which an
  infrastructure outage or a branch update can cause — previously had no retry
  path short of an empty commit or reopening the PR.
- **`just setup` now installs a WebDriver and detects any Chromium-family
  browser**, so the frontend's browser test suite is runnable locally instead of
  loud-skipping by default. It reports precisely what is missing, and explains
  how to point the driver at Brave/Chromium/Edge when Chrome is absent.

## [0.24.2] - 2026-08-06

### Changed

- **Global search warms its corpus when you focus the box, instead of on your
  first keystroke.** The search corpus is rebuilt from two full directory scans
  whenever it expires (60-minute TTL) or an app mutation drops it — and that
  rebuild sat on the keystroke path, so the first search after an idle hour or
  after creating/deleting an app appeared to hang for seconds. Clicking the bar
  (or pressing Cmd/Ctrl-K) now starts the rebuild, so it overlaps your typing.
  A warm corpus still costs nothing, and concurrent rebuilds are collapsed into
  one.

### Fixed

- **A list or search index rebuilt while an app mutation landed is no longer
  cached.** A tenant-wide scan takes seconds, so a create/delete/rename
  routinely lands during one: the mutation cleared the cache, and the in-flight
  scan then stored the snapshot it had fetched *before* the change. Because
  these entries are pinned (exempt from eviction so they survive heavy audit
  runs), the result wasn't a stale read that clears in seconds — App
  Registrations, Enterprise Apps, Managed Identities, and global search could
  each show a deleted app, or miss a new one, for up to an hour. All four now
  drop a snapshot that lost the race and re-fetch, as the two directory indexes
  they are built from already did. Also fixed the two callers that reached the
  audit's and the App Registrations join's service-principal index through an
  unguarded helper, which made the existing check a no-op.

- **A Security finding section now offers only the fix for its own rule.** An
  app scored under several rules is listed under each of their sections and
  carries a fix per rule, but every row rendered the whole set — so
  "Remove 1 expired credential" turned up inside **Legacy Application Access
  Policy scoping**, alongside (and above) the migration the operator opened
  that section for. Each section now shows **Open** plus its own rule's fix;
  the others stay one click away in the section that owns them. Advisory
  sections (high-risk permissions, external exposure, no local app
  registration) and the Healthy positives show **Open** only. The All-apps
  pane is unchanged — its rows are not grouped by rule, so they still offer
  every fix the app carries.
- **"Open" now lands on the tab for the section it was clicked in.** The target
  tab was picked by scanning *all* of an app's findings, which ranks permission
  scoping above credentials — so opening an app from **Expired credentials**
  dropped you on its Permissions tab when that same app also had a scoping
  finding. Each section now names its own tab (expiry → Credentials, ownership
  → Owners, scoping and permission findings → Permissions, unused / external
  exposure → Overview). The All-apps pane keeps the old item-wide behaviour —
  a row there stands for the whole app. Managed identities are clamped to the
  two tabs their pane has, so no deep-link can land on an empty tab body.
- **Applying one fix no longer clears the row's other, still-unfixed ones.**
  A successful remediation dropped the row's entire remediation set, so
  removing an expired credential took the legacy-policy migration button with
  it and nothing short of a full re-run brought it back. Only the remediation
  that actually ran is cleared now.

## [0.24.1] - 2026-08-05

### Fixed

- **Moving a management scope onto the toolkit-managed group now refuses any
  filter it cannot reproduce exactly, instead of silently widening access.** The
  scope filter was rebuilt as a plain `MemberOfGroup` OR-chain from every quoted
  value it found, so a filter that combined group membership with anything else
  — an `-and RecipientTypeDetails` restriction, a `-not` exclusion — came back
  without that clause, and the app could suddenly reach mailboxes the
  restriction had been holding back. Exchange applies a scope's filter to
  **every** role assignment using it, so the widening was tenant-wide for that
  app. The move (and the migration's repoint) now refuse and explain, leaving
  the scope exactly as it was.
- **A group whose name contains an apostrophe is no longer invisible to the
  scope tooling.** Exchange escapes `'` as `''` inside a filter, and the scanner
  skipped any value containing one. Two consequences: "Move to managed group"
  dropped that group from the rebuilt filter (quietly shrinking what the app
  could reach), and the irreversible **Delete group** check reported the group
  as unreferenced while a live management scope still pointed at it. A filter
  the toolkit cannot fully read now counts as a possible reference, so the
  delete is withheld rather than offered.
- **The audit no longer offers a `Sites.Selected` fix for a SharePoint grant it
  cannot confine.** `Sites.*` exists on both Microsoft Graph and Office 365
  SharePoint Online, and the rule keyed on the permission name alone. A
  legacy-resource grant was therefore listed as org-wide *and* offered the
  one-click conversion — which grants Graph's `Sites.Selected`, strips nothing
  on the legacy resource, and left the app just as org-wide as before while the
  audit re-scored it as confined. Those grants now get their own finding, with
  guidance instead of a fix that cannot work.
- **A session that dies mid-run no longer produces a partial result presented as
  complete.** The DR backup, the SharePoint site sweep, the Key Vault access
  sweep and the mailbox-reach probe all warned their way through a dead session
  and returned what they had — in a backup or a least-privilege view that is a
  wrong answer, not a slow one. The root cause was one layer down: the shared
  bearer-token boundary flattened every failure to a generic token error, so a
  dead session was indistinguishable from a transient blip for *any* client
  call. It now carries its classification, and all four commands stop and ask
  for re-authentication.
- **Cache lifecycle:** a tenant-wide index fetched while a mutation lands no
  longer overwrites the fresh state with the pre-mutation snapshot (which, being
  pinned, then survived a full hour out of reach of eviction); lowering the
  cache size limit now actually shrinks the two buckets that hold the most
  memory, rather than reporting a number it never applied; an entry that can
  never be read back is dropped instead of holding its slot; and an expired
  entry is swept even if nothing ever reads it again.

### Changed

- Audit rows whose only finding is an unconfinable mailbox or SharePoint grant
  now open on the **Permissions** tab, where the grant is actually managed.

### Internal

- The Exchange consolidation decision moved out of the Tauri command layer into
  `azapptoolkit-exchange` as `plan_consolidation`, where its fail-closed rules
  are unit-testable without a signed-in session.
- `repo_invariants.rs` grew from 2 checks to 7: pinned cache writes, positive
  resource gating on scope fixes, cancel-flag resets, the CHANGELOG header
  format both release parsers depend on, and AGENTS.md's own size budget. Its
  `KNOWN_GAPS` list of fan-outs missing a dead-session check is now empty.
- Command handlers gained a testable seam (`*_core` taking `&AppState`), with
  the first end-to-end handler tests driving a real Graph request/response and
  asserting caches are invalidated only on success.
- Four duplicated shapes collapsed onto one definition each: the
  forbidden-to-capability remediation splice, the per-client retry policy, the
  `.badge` markup (now always the `Badge` primitive), and the CHANGELOG format
  contract.

## [0.24.0] - 2026-08-04

### Added

- **An app's Permissions tab now shows which SharePoint sites it can reach, and
  with what access — no site URL required.** `Sites.Selected` grants live on the
  *site*, and Microsoft Graph has no reverse app-to-sites lookup, so the only
  way to see them was to already know a site's URL and list that one site. A new
  **Sites this app can reach** panel answers it directly: every site the
  principal is granted on, with the roles (read / write / fullcontrol / manage)
  it holds on each, and a **Manage** action that loads a site into the existing
  grant/revoke flow. It reads the same tenant-wide site index the Resource
  Access → Sites tab builds — so when that scan has run in the last hour the
  answer is free, and running one from here warms it for every other app. The
  panel also appears on **managed identities**, which can hold `Sites.Selected`
  (the Grant-access wizard grants it) but have no app registration to inspect.
  Coverage is stated rather than implied: an empty list only reads as "no
  per-site grants" when the underlying scan was complete, and the panel says so
  when sites failed to read, when a scan was cancelled, and that personal
  OneDrive sites are never enumerable.

- **The Security tab now finds apps still scoped by a legacy Application Access
  Policy, and migrates them to RBAC for Applications in one click.** The audit
  resolves policies from **one** tenant-wide `Get-ApplicationAccessPolicy` read
  per run (the per-app RBAC probe deliberately skips that lookup, which is why
  these apps went unreported), so any principal a `RestrictAccess` policy
  confines — app registration, foreign enterprise app, or managed identity —
  now raises its own **Legacy Application Access Policy scoping** finding
  instead of hiding among the org-wide rows. The finding's **Migrate to RBAC for
  Applications** fix plans first: opening it runs the migration as a dry run and
  shows the management scope it would build, the mailboxes it would copy into
  the toolkit-managed group, the scoped Exchange roles, the org-wide Entra
  grants it would remove and whether the policy itself can be deleted —
  committing is a second, deliberate click. It reuses the existing guarded
  migration wholesale, so every fail-closed rule still holds: `RestrictAccess`
  policies only (a `DenyAccess` blocklist inverts into a management scope), one
  scope per app spanning every policy's groups, and the policy is deleted only
  once every grant it was confining has actually been re-scoped.

- **Consolidating a scope now names the group it retired, and offers to delete
  it.** "Move to managed group" (and the policy migration) ended with "the
  previous group … can be cleaned up" — without saying *which* group, leaving
  the operator to work it out from a recipient filter. Both flows now name it
  (display name, address and DN) and report what still references it, checked
  against every other management scope's filter and every legacy Application
  Access Policy. When nothing does, a **Delete group** action appears behind a
  type-the-name confirmation. It is deliberately never automatic: the delete is
  irreversible, and the checks cover only what Exchange lets the toolkit
  enumerate — transport rules, retention/DLP policies, group nesting, and the
  people and systems that simply mail the address are invisible to it, which the
  panel says on screen. The backend re-verifies every guard immediately before
  deleting and refuses outright on this app's own managed group, on any live
  reference, or when a check couldn't complete (an unknown is never treated as
  clean).

### Changed

- **An app confined only by a legacy Application Access Policy no longer scores
  as organization-wide.** Because the audit never read the policies, such an app
  was reported "Organization-wide mailbox access" at full risk weight while the
  app's own Permissions tab correctly showed it scoped. It now earns the same
  reduced weight as any confirmed-scoped app and moves out of the org-wide
  finding into the new legacy-scoping one — **so expect these apps' risk scores
  to drop and the org-wide mailbox count to fall on the first run after
  upgrading.** Ranking is otherwise unchanged; the new finding is advisory and
  adds no score of its own.

### Fixed

- **Migrating Application Access Policies now refreshes the app caches.** The
  migration removes org-wide Entra grants and assigns scoped Exchange roles, but
  never invalidated anything — so the app lists, detail payloads, mailbox-scope
  verdicts and the security audit all kept serving pre-migration state until
  their TTLs expired. A real run (including a partial one, which still performed
  the removals) now busts them; a dry run still changes nothing.

## [0.23.0] - 2026-08-04

### Added

- **Legacy Application Access Policy migration now consolidates onto the
  toolkit-managed group, and an already-scoped app can be moved onto it.**
  Migration built the app's management scope over the *policy's own* group, so a
  migrated app stayed pinned to a legacy group the toolkit doesn't manage —
  correct, but off the naming standard, and adjusting its mailboxes meant
  editing a group the app's own scoping panel doesn't show. Migration now copies
  that group's mailboxes into `app_scope_group_<appId>` and scopes to *that*, so
  the legacy group can be retired. For apps that already migrated (their policy
  is gone, so migration finds nothing) the Exchange scoping section gains **Move
  to managed group**, which does the same consolidation from the scope's current
  groups: it plans first — listing the mailboxes it would copy — and commits
  only when you confirm. Both paths fail closed: unless every mailbox is
  *verified present* in the managed group afterwards, the scope keeps its
  existing filter rather than narrowing to an incomplete copy. An empty source
  group counts as unreadable for this, because `Get-DistributionGroupMember`
  also returns nothing for a Microsoft 365 group — consolidating that would have
  cut the app off from every mailbox at once. Exchange takes 30 min–2 h to
  apply a repointed scope; the permission tester bypasses that cache.

- **"What's new" reopens the current version's release notes at any time.** The
  update splash was the only place release notes existed: it appeared once,
  before installing, and after the restart there was no way back to what had
  changed. The account menu's version line now carries a **What's new** link
  that opens this build's own notes — baked in at compile time, so it works
  offline and on first launch — alongside a link to the full changelog on
  GitHub.

### Fixed

- **A scoped grant that changed nothing no longer reports as a success.** When
  an app already had a management scope, granting scoped access with a different
  group left the scope untouched — Exchange keeps an existing scope — and the
  toolkit reported this as "…1 warning(s)." in a toast that auto-dismissed
  without ever showing the warning. The groups you asked for silently didn't
  apply. Grant outcomes carrying warnings now stay on screen with the warning
  text, the filter actually in effect, and a button to refresh once you've read
  them; a clean grant still toasts and reloads as before.

### Changed

- **Release notes now show what changed for you, with the engineering detail
  behind a toggle.** The changelog is written for operators and contributors at
  once — each entry leads with a sentence of what changed, then several
  paragraphs of why and how, plus whole sections about tests and refactors —
  and the update splash rendered all of it verbatim. It now shows the lede of
  each entry and drops internal sections; **Show technical details** renders the
  release verbatim, exactly as before, and only appears when there is more to
  see. Nothing is removed from the changelog itself, and past releases summarise
  the same way.

## [0.22.4] - 2026-08-04

### Fixed

- **A "Scope mailbox access" fix is no longer offered where Exchange RBAC cannot
  honour it.** The security audit decided which org-wide mailbox grants got the
  one-click scoping fix by asking whether a permission was *not* the legacy
  Outlook-REST case. That negative test let three unscopable shapes through — a
  grant whose resource could not be resolved, a resource this build does not
  map, and a `Mail.*` / `MailboxSettings.*` permission on Microsoft Graph
  outside the supported role set — each of which got a Fix button the handler
  could never apply. The gate is now the positive
  `is_scopable_exchange_resource_permission`, the same one `AppPermissions::is_scoped`
  already used. Grants that reach mailboxes but cannot be confined now raise
  their own finding ("Org-wide mailbox access that RBAC cannot confine") and no
  fix, kept distinct from the legacy-grant finding because "remove this legacy
  Office 365 grant" is the wrong advice for access that may be legitimate.
  Risk scores are unchanged — this rule is advisory and adds no points.
- **Scoping an application's mailbox access now fails closed when nothing is
  scopable.** `grant_exchange_mailbox_access` logged "nothing to scope" and
  carried on, which still created the app's single Exchange management scope
  pinned to the requested groups while assigning no roles at all. Because
  Exchange keeps an existing scope rather than rewriting its filter, every later
  *correct* scoping request for that app could then only warn that its groups
  were not applied — an unrecoverable mis-scope produced by a request that
  scoped nothing. It now returns `no_scopable_permission`, exactly as the
  managed-identity path already did; both share one guard so they cannot drift
  apart again.
- **A security audit interrupted by a dead session is no longer cached as a
  finished one.** `run_audit` collapsed every per-app failure to a log warning,
  so a session whose refresh token died mid-run produced a report silently
  missing applications, stored under the audit cache and served to the dashboard
  as authoritative — a partial risk report that reads as clean. It now stops on
  the shared `UiError::is_reauth_fatal` codes (as bulk actions already did),
  skips the cache write, and surfaces the code so the shell re-authenticates in
  place.
- **Cache lifecycle gaps.** Lowering the cache size limit now evicts immediately
  instead of converging one write at a time (and never at all once writes to
  that kind stopped); an entry that no longer deserializes is dropped rather
  than re-read, re-warned, and kept alive by its own LRU touch until its TTL
  expired; and the `Lists` bucket is sized for the per-object entries it
  actually holds, which had been silently truncating bulk seeding at the
  aggregate-sized cap.

### Changed

- **Cold-tenant directory scans are de-duplicated.** The tenant-wide
  service-principal and app-registration indexes are read by six surfaces (both
  lists, global search, the security audit, the consent audit, DR backup). On a
  cold tenant they each ran their own full directory scan and then raced to
  overwrite the same cache entry; they now share one fetch through the existing
  single-flight gate.
- **`just verify` runs the frontend GUI tests when it can.** The largest tier in
  the repo had its only behavioural gate living in CI, so a renamed CSS class or
  aria-label passed locally and failed a full round trip later. `verify` now
  runs `web-itest` when Chrome and a matching chromedriver are present and
  prints a loud, unmissable skip when they are not; `just verify-ui` keeps it
  mandatory.

### Internal

- Exchange scoping's target derivation — resolving an application's declared or
  granted permissions into concrete RBAC targets, and the fail-closed guard
  above — moved out of the Tauri command layer into
  `azapptoolkit-exchange::targets`, where it is pure and directly unit-testable
  rather than reachable only through a signed-in session.
- Two repo invariants that were previously prose in `AGENTS.md` are now tests:
  the frontend's `[lints.rust]` block must match the workspace one (web-rs is
  outside the workspace and cannot inherit it), and every long-running fan-out
  must honour `UiError::is_reauth_fatal`.
- Per-tenant API client construction and the shell's tool dialogs each collapse
  onto one shared helper instead of five and four hand-rolled copies.

## [0.22.3] - 2026-08-03

### Changed

- **Dependency maintenance only — no application behavior changes.** `webbrowser`
  1.2.1 → 1.2.2, the crate `azapptoolkit-auth` uses to open the sign-in URL in
  your default browser during interactive authentication. Everything else in
  this release is build and CI configuration that does not reach the shipped
  binary: a GitHub Actions bump, and a documented hold keeping `base64` at 0.22
  (0.23 would add a third copy of that crate to the dependency graph, since
  `oauth2` excludes it outright and the HTTP stack still requires `^0.22`).

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
