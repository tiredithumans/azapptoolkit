## [Unreleased]

### Added

- **The app restores your signed-in session at launch instead of asking you to sign in again.** The
  refresh token has always lived in the OS keyring, but the account object id it is keyed by
  (`{tenant}:{oid}`) lived only in memory — so every launch landed on the sign-in card, and clicking
  it opened the system browser with `prompt=select_account`: a forced account picker for someone who
  signed in ten minutes earlier. A successful sign-in now records the account (object ids and your
  own UPN — identifiers, never the token) in `settings.json`, and startup redeems the stored refresh
  token for the read scopes behind a brief "Restoring your session" card. Nothing to restore — you
  signed out, the tenant was reconfigured, the token expired or was revoked — is not an error: it
  lands on the ordinary sign-in card. An account remembered under a different tenant than the one
  this build is configured for is refused rather than used.
- **Settings gained a "Tenant connection" tab, so the client and tenant IDs are editable after first
  run.** They could previously be entered exactly once: a well-formed but wrong tenant GUID was an
  in-app dead end, fixable only by hand-editing `settings.json`, and a consultant working several
  tenants had to re-point the app from outside the UI. The tab mounts the same form the first-run
  screen does, pre-filled from the current values, and saving relaunches behind a confirmation that
  names the tenant. The sign-in card now also states which tenant it is about to redirect to, so a
  typo is caught before the browser round trip rather than after an opaque failure.
- **The Cmd/Ctrl-K palette can reach destinations by name.** Twenty-five named destinations — the
  Security sub-tabs, the Resource Access tabs, Credential expiry, SSO certificates, Delegated
  grants, Access Readiness, the Settings tabs — existed only as strips revealed after you already
  guessed the right nav row. They are now a "Go to" group above the record results, routed through
  the existing navigation helpers. The two things called "Key Vault" (the secret browser and the
  vault-access lookup) are now distinguishable, and the Resource Access tab reads "Vault access".
- **The security audit says how old it is, and Home's "Run a security audit" button runs one.** The
  posture card showed severity counts with nothing saying when the scan behind them happened, on a
  cache with a 60-minute TTL. A run is stamped when it completes and the stamp is stored with its
  items, so a cache hit reports the original run time rather than the moment it was read back; both
  surfaces render "Scanned 12 min ago", with the exact UTC time on hover. The empty state no longer
  claims "No audit has been run yet" — what you see after every relaunch — and the button now
  navigates *and* starts the scan instead of leaving you to press "Run audit" a second time.
- **App Registration rows carry credential state, and the list sorts.** `credential_status`,
  `soonest_credential_expiry` and `created_date_time` already crossed IPC on every row and reached
  nothing: on a 5,000-app tenant you could filter to "Expiring" and still not see which credential
  expired when, in an order Graph happened to return. Rows now show the credential badge and a
  relative expiry, and the list sorts by name, soonest expiry, or created date.
- **The inventory lists search by appId, not just display name.** An appId is what a sign-in log, a
  change ticket and a Conditional Access policy name an app by — and the lists printed it on every
  row while matching only the name, so pasting one returned "No matching apps" over rows that
  contained it. Every other search box in the app already matched both.
- **The Findings pane shows each finding's own detail.** It is the surface organised *by* finding,
  yet its rows showed Application / Risk / Score / Last sign-in and nothing about the finding: under
  "Org-wide mailbox access" you could not see *which* mail permission was org-wide without opening
  every row, even though the ungrouped All-apps pane rendered exactly that. "Last sign-in" now
  appears only in the group where it is the evidence, and its space pays for the detail.
- **The resource reverse-lookups export, and the scope badges link to the permission tester.** "Which
  apps can reach this mailbox", "which apps can touch this site" and "who can read this vault" are
  answers an operator is asked to produce in writing, and none of them could leave the app. Each
  panel now exports its filtered rows together with its coverage summary, so the partial-coverage
  caveat travels with the data. And the "Scoped (selected items)" badge — whose own tooltip says
  reach is not enumerable and to check a specific resource — now offers the way to do it.
- **The open-items dock survives a restart, keyboard-steps, and stops silently dropping items.** It
  is where you park a reference app while triaging, and past eight items it discarded the oldest
  with no cue and no way back — the one you opened first, usually the reference. Overflow now names
  what it dropped and offers to reopen it, eviction is least-recently-*focused* rather than
  oldest-opened, and the working set is parked per tenant across restarts. Cmd/Ctrl-`]` and `[` step
  along the dock, which is also the keyboard route back after Escape collapses the workspace.
- **Arrow keys move between rows in the three inventory lists.** Every table in the app already had
  roving-tabindex navigation; the lists an operator actually lives in did not, so crossing twenty
  rows cost about fifty Tab presses. The focus ring for those rows had shipped in the stylesheet all
  along and could never match, because nothing gave the row a tabindex.

### Changed

- **Finding groups are ranked by their own worst severity, not by their members' total risk scores.**
  Group order summed each member's whole `risk_score` — every rule's contribution, not this rule's —
  so "Missing or single owner", a rule that contributes no points and matches a large fraction of
  any tenant, outranked everything, while a twelve-app Critical org-wide-mailbox group sat below the
  fold of a findings-first workbench. Ranking is now worst severity, then affected-principal count,
  then catalog order.
- **Opening an item no longer throws away the surface you were working.** Every "Open" deep link
  switched the top-level view before opening the pane, so remediating a row from a finding group and
  pressing Escape dropped you on the App Registrations list instead of the group you were halfway
  through — a nav click and a re-orient per row. The workspace overlay is mounted over the shared
  content slot and the dock is global, so the pane opens the same way without the switch.
- **Access Readiness leads with what is unmet.** The checklist rendered in flat catalog order, which
  buried the two capabilities you were short among a dozen green ticks — the answer was on the page
  and still had to be hunted for. A count line states the gap, planes holding one come first, and
  within a plane Missing precedes Unknown precedes satisfied. A check that fails outright now offers
  a Retry, which "Refresh token" (the re-check after activating a PIM role) was never the answer to.
- **The Grant-access wizard's review step names what it is about to do.** It was one sentence: the
  permission values and a mode blurb. It never named the principal, never listed the targets you
  typed two steps earlier, and never said that the scoped apply *removes* the matching org-wide
  grants — the irreversible half, previously disclosed only afterwards in a toast. Step 3 now states
  the principal, the permissions, the resolved targets read from the same signals the apply sends,
  and warns about the removal before you commit to it.
- **A bulk action shows which apps it will touch, and which one it is touching.** The armed panel
  said only "the 40 selected app(s)" — the standalone Bulk Actions page had solved this and the four
  other hosts of the same bar had not, which mattered most where the selection was not built by hand
  ("Fix all N" seeds it in one click). Progress dropped the current app entirely, so the person
  deciding whether to cancel a 40-app scope-and-strip was the one person who could not see what was
  being mutated — while the read-only audit scan showed exactly that.
- **An exported audit report carries the run's coverage caveats.** The workbench never presents a
  partial scan as an all-clear, but the export dropped all of it — and a cancelled run is
  *specifically* the one that ships its rows to the exporter, so the file with the most to disclose
  said only "N application(s)". Every format now opens with the scored/total fraction, the run time,
  the cancelled/truncated sentences shown on screen and the degraded reads, plus a severity summary.
- **Global search admits what it left out.** The dropdown capped each kind at ten rows and stopped,
  so on a tenant where two hundred apps matched "svc" you saw ten and reasonably concluded the
  eleventh did not exist — on the fastest input path in the app, whose silence reads as an answer.
  Each group now carries a "10 of 47 — keep typing to narrow" footer, outside the keyboard
  selection. Searching over a corpus truncated by the directory index cap shows the same warning the
  lists already show, above the results — including above the "No matches." it would otherwise state
  as fact.
- **"Grant read access" is the emphasized button in the SharePoint scoping remediation.** In a
  least-privilege remediation the primary button granted the broader role, and an operator working
  down a findings list at speed clicks the primary. The two equivalent paths already defaulted to
  read.

- **Rust toolchain and MSRV move 1.97.1 → 1.98.0.** `rust-toolchain.toml` pins the exact patch
  (1.98.0) so a silent stable bump can't break builds, and the workspace `rust-version` floor (root
  `Cargo.toml` + `apps/desktop/web-rs`) rises to 1.98 in lockstep. The six `dtolnay/rust-toolchain`
  SHA pins across `ci.yml`, `codeql.yml`, `pages.yml`, and `release.yml` advance to the matching
  `1.98.0` commit so CI, CodeQL, the Pages demo, and the release matrix all build on the same
  compiler as local `just verify`.
- **Dropped five redundant `use leptos::prelude::*;` globs** from the frontend's `state/`
  submodules. 1.98 reports a glob import whose names a second glob already supplies, and each of
  those files sits under `use super::*`, which reaches `state/mod.rs`'s own prelude glob. Nothing
  resolved through the local copies; without removing them `just web-clippy` (`-D warnings`) fails
  on the new toolchain.
- **Semver-compatible dependency refresh across both lockfiles.** `cargo update` on the root
  workspace and the separate `apps/desktop/web-rs` tree — notably `tauri-plugin-updater`
  2.10.1 → 2.11.0, `tauri-plugin-dialog` 2.7.2 → 2.7.3, `aws-lc-rs` 1.18.0 → 1.18.1 (with
  `aws-lc-sys` 0.44 → 0.45), `rustls-webpki` 0.103.14 → 0.103.15, `hyper` 1.11.0 → 1.11.1,
  `h2` 0.4.17 → 0.4.19, `flate2` 1.1.9 → 1.1.10, and `uuid` 1.24.1 → 1.26.0 in both trees.
  `secret-service` 5.1.0 → 5.2.0 moves the Linux keyring's session crypto onto the RustCrypto
  0.11 generation (`sha2` 0.11, `hmac` 0.13, `hkdf` 0.13, `aes` 0.9, `cbc` 0.2), so those majors
  now sit beside the 0.10-line copies — upstream's move on a Linux/FreeBSD-only path, not one of
  our pins, and `deny.toml` already treats duplicate versions as a warning. The deliberate holds
  are unchanged (`base64` 0.22, `p12-keystore` 0.2.x, `rand` 0.8; `generic-array` is pinned to
  exactly 0.14.7 by `crypto-common` 0.1.7, upstream's constraint rather than ours). `cargo audit`
  and `cargo deny` pass on both trees.
- **Developer workflow.** `just check` (type-check both trees) and `just test-crate <crate>` join
  the recipes as the sanctioned inner loop; `just --list` now describes every recipe in one line;
  the `setup` bodies moved to `scripts/setup.{sh,ps1}`. `AGENTS.md` is a true one-line-per-rule
  index (20 KB budget) with the detail in `docs/architecture/` and path-scoped `.claude/rules/`;
  the 62 KB scoping/audit deep-dive is split into four; `commands/exchange.rs` is a module
  directory and the largest inline test modules are sibling files. Releases up to 0.26.3 moved to
  `docs/CHANGELOG-archive.md`, and editing this file no longer recompiles the frontend.


### Fixed

- **Revoking a permission from an app registration now asks first.** The trash icon on the
  Permissions tab stripped a live app-role assignment or delegated grant on one click — no
  confirmation, no indication of which row, and no confirmation afterwards; the only signal was a
  row vanishing on the next refetch. The identical call was already confirm-gated on both the
  Enterprise Application and Managed Identity panes, making the busiest surface in the app the only
  unguarded one. Each of the three cases now gets its own dialog naming the permission, with bodies
  that distinguish revoking a live grant (calls start failing immediately) from removing a
  declaration (nothing the app can do today changes).
- **A stopped bulk run no longer hides the apps it never reached.** Cancelling at item 12 of 40
  reported "Scoped mailbox access on 11 app(s); 1 failed" and never mentioned the 28 untouched apps,
  because the summary counted the outcomes produced rather than the apps attempted. A cancelled
  delete also cleared the entire selection — including everything it had not deleted — destroying
  the work queue. Summaries now name the unattempted remainder, cancellation keeps it selected, and
  the failures list can narrow the selection to just what failed so it can be re-run.
- **A missing admin consent is no longer a dead end.** Graph write scopes are consented on first
  write, so in a tenant without pre-granted admin consent the first mutation returned
  `consent_required` and reached the UI as red text with nothing to click — the app's seventeen
  "Grant consent" buttons all covered on-demand feature scopes, and none of them this. It is now
  handled where a dead session already is, offering the grant for the scope set that actually
  failed. The Grant-access wizard's own button offered the *Exchange* scopes for a failed org-wide
  Graph grant, which could never have fixed it.
- **Cmd-W closes the open item instead of the window.** The shortcut sheet documented it as closing
  the open item, but no application menu was installed, so macOS supplied its own Close Window and
  routed the key there first. The handler also only claimed the key while an item was open — so
  immediately after Escape collapsed the workspace, Cmd-W fell through to the OS and dropped the
  whole working set, the audit run and any in-flight dialog. In a two-pane compare it also closed
  the left pane regardless of which one you were reading.
- **Keyboard focus follows the workspace open and collapse.** Opening an item from the keyboard left
  focus on the document body — about thirteen Tab presses from the pane it had just opened, past the
  whole nav rail — because the overlay correctly marks the content behind it inert, which blurs the
  row button you activated. Escape had the mirror problem, returning you to the top of the page
  instead of the row, losing your place in a four-thousand-row list.
- **Critical badges are legible in dark mode.** Five foregrounds were hardcoded white on backgrounds
  that invert between themes, so the Critical risk badge — the loudest signal in the audit table —
  rendered white on light red at about 2.8:1, and the filter count badge at about 2.0:1, both at
  11–12px.
- **Spinners keep spinning with reduced motion enabled.** The blanket reduced-motion reset froze
  every spinner and the skeleton shimmer, so on a managed or VDI desktop with animation effects off
  — this tool's usual environment — a multi-second Graph fan-out showed a motionless arc that reads
  as a hung UI. A steady rotation is what that preference is meant to preserve.
- **A paired list row announces its own name.** The "jump to the paired application" button was
  nested inside the row button, which is invalid HTML and spliced its label into the middle of every
  paired row's accessible name; it also sat in the tab order between the name and the appId.
- **Finding-group severity is readable without color.** A collapsed group's worst severity was a
  10px dot with no text and no label, and Critical and High resolved to the same fill — so the dot
  could not separate the top two tiers, and severity was absent entirely from the header's
  accessible name. Sortable audit columns now expose their sort state, the open-items dock's label
  is attached to a role that announces it, and each dock chip's close button names the item it
  closes rather than all announcing "Close".
- **Confirmation dialogs name what they are about to act on.** The `subject` field existed precisely
  because six identical dialogs for six secrets made the operator trust that the button they clicked
  belonged to the row they meant — and it was passed at two of roughly twenty sites. Thirteen more
  now name the permission, principal, URI, site or owner, including the audit's one-click fixes,
  whose detail line the dialog was covering.
- **A failed sign-in explains the AADSTS code it is showing you.** Entra's numeric code was already
  on screen and already preserved through the redaction that strips tenant and correlation ids
  around it, but the recovery hint could only speak in generalities — `token_exchange` covers wrong
  tenant, unknown client id, an unregistered redirect URI and a Conditional Access block alike. The
  common codes now name the cause and the step that clears it, and an unmapped code still falls back
  rather than guessing.
- **"Set them in Settings" is a link.** Four callouts named a page reachable only through the account
  menu — the one destination with no nav row and no shortcut — and left the operator to go find it.

## [0.29.0] - 2026-08-31

### Added

- **"Generate certificate" now also produces a password-protected `.pfx`.** The reveal has always
  shown the private key as PKCS#8 PEM — which is what Linux and macOS hosts, the Python/Node MSAL
  libraries, the Azure SDK's `certificate_path` and a Key Vault import all want, and what Windows
  wants least. An operator running `Connect-MgGraph -CertificateThumbprint` needs the certificate
  *with its private key* in `Cert:\CurrentUser\My`, and the only supported way in is
  `Import-PfxCertificate`. Getting there meant pasting a one-time, unrecoverable private key into
  an `openssl pkcs12 -export` invocation and inventing a password — and it left the system
  clipboard as the key's only export channel. The reveal now carries a **Save .pfx…** button
  beside the PEM blocks, bundling the certificate and its key into a PKCS#12 file encrypted with
  **AES-256 (PBES2, HMAC-SHA256)** under a 192-bit password the app generates and shows once next
  to it, with its own copy button. The bundle's `localKeyId` is the certificate's SHA-1
  thumbprint — the same string the Credentials tab and the portal show — so Windows attaches the
  private key rather than silently importing a certificate without one. The file is written
  owner-only, and the reveal says to install it and then delete it. Windows Server 2016 and older
  cannot read AES-256 `.pfx` files; the reveal points at the PEM for those, which is unchanged —
  the bundle is an addition, not a replacement.

## [0.28.2] - 2026-08-31

### Fixed

- **The generated certificate's thumbprint now matches the one the Credentials
  tab shows.** The reveal modal computed its own **SHA-256** digest of the
  certificate while the Credentials tab renders the **SHA-1** thumbprint Entra
  derives into `customKeyIdentifier` — two algorithms over the same certificate,
  so the two values could never agree, and neither could the Azure portal's
  Thumbprint column. An operator who copied the value out of the reveal was
  holding a string that identified the certificate nowhere, and is not the `x5t`
  a client-assertion config needs. The reveal now shows **Thumbprint (SHA-1)** —
  the value Entra, the portal and the Credentials tab all agree on — with the
  SHA-256 digest kept alongside it on its own labelled line for anyone verifying
  or pinning on the stronger hash.

- **A hand-uploaded certificate's thumbprint no longer renders as 60 characters
  of garbage.** The Credentials tab base64-decoded `customKeyIdentifier`
  unconditionally, but a certificate uploaded by hand can carry that identifier
  already written as hex — and a 40-character hex string is *also* valid base64,
  so the decode quietly succeeded, produced 30 meaningless bytes, and rendered a
  plausible-looking thumbprint that belonged to no certificate. Both trees now
  share one converter (`core::thumbprint::canonical`), which recognises the hex
  form instead of decoding it. A DR backup's certificate thumbprints now go
  through it too — the field exists so an operator can match a certificate
  against their PKI, and it was exporting Graph's raw base64, which matches
  neither their PKI nor the portal.

## [0.28.1] - 2026-08-31

### Fixed

- **"Generate certificate" now actually shows the private key it promises.** The
  success handler reloaded the application detail immediately, which re-runs the
  resource the Credentials tab is rendered from — tearing the tab down and
  rebuilding it before the reveal modal could paint. The dialog said it "shows
  the private key once", the certificate was created, and the operator was left
  with a public key on the app and no private half, unrecoverable. The reload is
  now deferred until the reveal is dismissed, matching what the client-secret
  reveal beside it has always done.

- **"Remove N expired" and Key Vault rotation now confirm what they did.** Both
  parked their result in a signal owned by the Credentials tab and then reloaded
  the application detail, which unmounts that tab — so the confirmation was
  destroyed on the tick it was created and never rendered. A partial sweep was
  the worst case: some secrets refused removal, the list came back shorter, and
  nothing said so. Both now report through the session toast stack, which lives
  above the detail pane and survives the reload, with partial failures on an
  error toast that lingers. Same route `remove_secret`/`remove_cert` already took.

## [0.28.0] - 2026-08-31

### Added

- **The permission tester now takes any SharePoint resource, not just a site
  collection.** Paste a library, folder or file URL and it resolves the
  securable, then answers in the order SharePoint itself does: an org-wide
  `Sites.*` grant wins outright; otherwise it walks the chain **upward** —
  item, list, site collection — because Microsoft's access calculation finds the
  application record "on the resource *or a securable hierarchical parent*", so a
  file with no entry of its own still reports the access it inherits from the
  library or the site.

  It also checks the half that used to go unasked. A Selected permission entry
  grants nothing until the app's token carries a matching scope, so an entry with
  no matching `*.SelectedOperations.Selected` assignment is now reported as **no
  access**, naming the missing half, instead of as scoped access the app doesn't
  have. Pairing reuses `selected_scope_accepts`, so the tester and the granter
  agree on which scope reaches what — including the asymmetry where `ListItems.*`
  covers a file but `Files.*` doesn't cover a plain-list item. If the app's
  assignments can't be read, the verdict is `unknown`, never "no access".

### Fixed

- **A Selected permission granted through the wizard never appeared in the
  Permissions tab.** Both SharePoint apply paths created the app-role assignment
  and stopped there. The permission was genuinely granted and effective, but the
  tab renders the app registration's `requiredResourceAccess` and joins runtime
  assignments *onto* declared rows — so an assignment with no declaration was
  invisible. The wizard's picker is the full live catalog rather than the declared
  set, which made "granted but never declared" the normal case for
  `Files.` / `Lists.SelectedOperations.Selected`, not an edge one.

  `grant_selected_item_access` and `convert_site_access_to_selected` now declare
  the permission before assigning it, exactly as the ordinary grant path does, and
  report it back as `declared_permission`. Service-principal-only principals
  (enterprise apps, managed identities) have no registration to declare on and are
  unchanged.

- **A 403 on a list/folder/file Selected grant blamed a role the operator already
  held.** Every SharePoint 403 was rewritten to one fixed sentence — "requires the
  SharePoint Administrator role (or Global Administrator) and the
  Sites.FullControl.All scope" — and Graph's own `error.code`/`error.message` was
  dropped on the floor, logged nowhere. An operator who *was* a SharePoint
  Administrator, whose site-collection grants worked, got told they were not.

  The requirement genuinely differs by level, so the sub-site endpoints now carry
  their own capability (`sharepoint_selected_items`), which
  `ScopeKind::SharePointItem` resolves to: a delegated call is the intersection of
  the token's scopes and the caller's *own* SharePoint permissions, and a grant
  below the site collection writes onto a securable inside the site's content —
  which the tenant SharePoint Administrator role doesn't reach. It also needs Full
  Control on the target site (site collection administrator, or the site's Owners
  group). That is now what the 403 message, the readiness row and the proactive
  "Requires:" tooltip say for those levels.

  The raw Graph 403 body is also logged at `warn` before the substitution, so the
  log file can distinguish "you lack rights on this site" from any other denial.

## [0.27.0] - 2026-08-28

### Added

- **SharePoint access can now be scoped to a single library, folder or file.**
  The toolkit modelled only one of Microsoft's four Selected permission scopes —
  `Sites.Selected`, at the site-collection level. Adding
  `Files.SelectedOperations.Selected` (or the `Lists.` / `ListItems.` siblings)
  produced no scoping affordance at all: no "Scope…" button, no Scope badge, and
  a Grant-access wizard that fell through to *"these permissions can't be scoped
  together"* and granted org-wide — the exact opposite of what those scopes are
  for. `ScopeKind::SharePointItem` is now a second SharePoint mechanism, with its
  own target panel and apply path (`grant_selected_item_access`).

  The panel **resolves every URL before granting** and shows what it found
  ("Folder · Finance / Documents / Invoices"), for two reasons: a grant below the
  site collection breaks SharePoint permission inheritance on the target and
  consumes one of the library's unique permission scopes, and a URL can resolve
  one level away from where it was aimed. A target the chosen permission cannot
  reach is flagged in the panel and skipped by the backend rather than granted
  one level up — `Files.*` reaches items in document libraries, `ListItems.*`
  reaches those *and* items in plain lists, and neither reaches a site.

  Unlike the site path this strips nothing: a Selected scope has no org-wide
  predecessor to convert away from. Reach is also **not enumerable** — there is
  no reverse `appId → items` lookup and no bounded walk of every folder in a
  tenant, so grants are verified per resource by URL and an empty result means
  "this resource has no app grants", never "this app has no item-level access".

### Fixed

- **A failed action in a Credentials-tab dialog gave no visible reason.** The
  three dialogs that run a command — new client secret, generate certificate,
  rotate into Key Vault — wrote their failures to the tab-body banner, which
  renders *behind* the modal backdrop. On failure the dialog stays open (only
  success closes it), so an operator saw the dialog sitting there having
  apparently done nothing: no certificate, no key, and no explanation. Most
  visible on "Generate self-signed certificate", whose own copy promises to
  show the private key once. Each dialog now shows its own failure, and opening
  one clears any earlier unrelated error.



- **Concurrent token refreshes could splice two refresh tokens together and kill
  the session.** The refresh lock is keyed per (tenant, scope set) *by design*,
  so refreshes for different audiences run concurrently — Access Readiness fans
  about six out at once — and every one of them writes the rotated refresh token
  to the same chunked keyring entries with no lock of its own. Interleave a
  three-chunk writer with a two-chunk one and the store holds one token's first
  chunk followed by another's tail; the loader had "no length, no checksum, and
  nothing marking where this token ends", so it returned the splice. The next
  silent refresh then failed `invalid_grant` and the session was purged, reading
  as a revoked token rather than a corrupt one.

  The whole read-modify-write of a chunk set is now serialized, and chunk 0
  carries the set's total count so a torn set — which a crash mid-write or a
  second app instance can still produce — **fails closed as "no stored session"**
  rather than loading as a plausible token. Entries written before this still
  load, so upgrading doesn't sign anyone out.
- **One idle socket could block sign-in for the full five-minute timeout.** The
  accept loop read each connection to completion before accepting the next, with
  no deadline — so it returned only on EOF, a complete request head, or 16 KiB.
  The existing mitigation covered a speculative preconnect that *closes*; it did
  not cover one that stays open idle, which is what browsers actually do (Chrome
  and Edge hold speculative sockets in the pool for seconds). The browser opened
  an idle socket, sent the redirect on a second one, and the listener sat parked
  on the first — never accepting the second. The user saw sign-in hang after a
  successful consent. Each connection is now bounded independently.


- **A tenant name pattern missing `{appId}` collapsed every app onto one shared
  scope, group and secret.** The substitution is a no-op when the pattern omits
  the placeholder, so with `scope_name_pattern = "contoso_app_scope"` every app
  in the tenant resolved to the same name. Scoping app A created a management
  scope filtered to A's group; scoping app B then got A's scope back untouched
  (the ensure step is create-only) and **B's scoped Exchange roles were attached
  to a scope pointing at A's mailboxes**. The same collapse cross-wired Key Vault
  secret names between apps. Such a pattern is now rejected when saved, and the
  resolvers fall back to the built-in per-app default if one reaches them anyway.
- **An interrupted settings write could destroy the tenant defaults and vault
  bindings.** `settings.json` was truncated in place, so any interruption before
  the write completed left it empty or torn; parsing then failed, the caller
  swallowed it behind a default, and the next writer serialized those defaults
  back over the file. The write is now a temp-and-rename, which is atomic and
  keeps the owner-only mode.
- **Three unsynchronized writers of `settings.json` could lose a vault
  binding.** The rotation flow, the auth config and the tenant defaults each did
  their own read-modify-write, and the last runs synchronously on the main
  thread while the first is async on the runtime pool — so they genuinely
  interleave. Either order silently dropped one side's write: the operator's
  just-saved defaults, or the freshly recorded binding the next rotation needs to
  find the secret again. All three now go through one serialized helper.

- **"All credentials expired" was reported — and scored — for an app that still
  holds a working credential.** The active count deliberately excludes
  expiring-soon credentials so the expiring-soon rules can say "nothing but
  expiring credentials left"; that exclusion is sound in the branch it was
  written for and wrong in the branch above it. With one expired secret and one
  expiring-soon secret the app was scored and labelled as dead while a working
  credential was still authenticating, so an operator stopped looking and the
  ranking overstated the risk. **Affects audit scores and issue text.**
- **A legacy Application Access Policy was matched case-sensitively, against the
  crate's own documented rule.** Exchange echoes the AppId back in whatever case
  it stored it, and a GUID differing only in case is the same application. In a
  tenant where `New-ApplicationAccessPolicy` ran with an upper-case GUID, a
  confined app reported as **org-wide** on the Permissions-tab Scope column and
  scored at full risk. Fixed at all three comparison sites (verdict, migration
  filter, permission tester). **Affects audit scores and the Scope column.**
- **An app confined by several Application Access Policies named only the
  first.** Multiple RestrictAccess policies grant the *union* of their groups —
  which is why the migration planner carries a vector of source policies — but
  the verdict used `find`, so an app confined to Sales *and* Execs reported
  `Sales` alone, with Sales' description as the recipient filter. That string is
  operator-facing on three surfaces, including the permission tester's "which
  mailboxes can this reach" answer. Scope names are now unioned, sorted and
  deduped, and the per-policy description is dropped when the union spans more
  than one policy rather than misdescribing the reach.



- **Deleting a service principal left the tenant-wide grant matrices reporting
  its access.** The SP objects and the grant matrices live under different cache
  kinds, and the delete swept only the first — no command compensated, because
  `invalidate_app_lists` touches `Lists` and the audit cache, never the
  `grants:` prefix. An operator deleted an over-privileged enterprise
  application and the Security tab kept listing its application permissions as
  live, which is the worst direction for a least-privilege view to be wrong in.
- **Publishing an app role or an API scope didn't reach the picker.** The cached
  resource-SP definitions were invalidated by none of the three mutators that
  change them, so an operator published a role on their own API — which the
  tenant app-role resource list exists to make grantable — opened the
  Grant-access wizard, and the role wasn't there. The definitions now sit under
  their own `resource:` key segment, mirroring how `grants:` separates the grant
  matrices in the same bucket, so the sweep can be precise instead of taking
  both families with it.


- **The shared retry loop replayed non-idempotent writes after a network error
  or a 5xx.** `with_retries` re-invokes the caller's whole closure — request
  send included — with no notion of the verb, and the transports route
  everything through it. A `POST /applications/{id}/addPassword` that hit a
  connection reset or a 502 *after* Graph committed the write was replayed up to
  three more times, so the registration ended up holding several client secrets
  while the operator only ever saw the plaintext of the last one — an orphaned,
  never-rotated credential, exactly the class of thing this tool exists to
  surface. Retries now carry a reason and a class: a 429 is still retried for
  every verb (the service refused *before* doing the work), while a transient
  failure is only replayed for an idempotent request. A repo invariant keeps a
  verb-dispatching transport from hard-coding the safe-looking answer.
- **A scoped `$batch` fetched its second page with the wrong token.**
  `finish_paged_batch` continued through the verb-selected read token, but
  `batch_list_site_permissions` deliberately uses the SharePoint token because
  `/sites/{id}/permissions` needs `Sites.FullControl.All`. A site whose
  `Sites.Selected` grant list overflowed one page therefore failed with 403 on
  page 2 — and the sub-requests sent no `$top`, so Graph's small default made
  overflow common. Both are fixed.
- **Paging hard-coded `ConsistencyLevel: eventual`, silently dropping `$expand`
  results after page one.** `list_applications` computes whether the request is
  an advanced query precisely because Graph answers an advanced query that also
  expands with a 200 and the expanded property *missing* — but only page one
  honoured that decision. In a tenant past one page of applications, every
  subsequent page lost `owners`, and the audit's ownerless-app finding fired on
  apps that have owners. The choice now travels with the paging.
- **The capped paging helper could spin forever.** Only a non-empty page
  advances toward the item cap, so a response of `{"value": [], "@odata.nextLink":
  "<same url>"}` looped without bound — and Graph legitimately returns empty
  pages carrying a `nextLink` on filtered directory collections, which is what
  both callers page through. The helper's own doc claimed the cap was its cycle
  guard; it now has the explicit page limit its sibling always had.


- **Adding or removing one certificate stripped the certificate blob from every
  other credential on the app.** `keyCredentials` is a full-replace collection,
  so both application-side mutators re-read the array and PATCH it back whole —
  but they round-tripped it through the typed `KeyCredential`, which does not
  model `key`. Graph returns `key` on exactly the `$select=keyCredentials` read
  those paths issue, so every *surviving* certificate was written back keyless.
  The audit's one-click "remove expired credentials" Fix reaches this on any app
  that also holds a live certificate. Both paths now round-trip raw JSON, the
  shape the service-principal twin was deliberately written against for this
  reason, so `key` and every other unmodeled field survive byte-for-byte.

### Performance

- **A cache bucket at its entry cap ran a full TTL sweep on every write.** The
  "has anything expired?" flag was computed and then ignored on the at-cap
  branch, so past the cap every single `put` did a `retain` over the whole
  bucket, a rebuild that clones every key, and a `min()` scan — all under the
  mutex the interactive list reads contend on, and all provably removing nothing.

### Security

- **An unparseable `/token` error body was written verbatim to the on-disk
  log.** Tracing is wired to a daily rolling *file* appender at info, so this
  warning lands on disk — while every other AAD error path here is meticulously
  redacted, dropping `error_description` because it embeds tenant/user GUIDs and
  client IPs. The branch fires precisely when the responder is **not** Entra: a
  TLS-intercepting proxy, WAF or captive portal, which commonly echo the
  offending request back in the block page. It now logs only the status, the
  body length and the response content type — which is the signal an operator
  actually wants ("a proxy answered"), without the content.
- **Four secret-bearing IPC types derived `Debug`, opting out of the workspace
  redaction convention.** A plaintext RSA private key, two Key Vault secret
  values and an OIDC client secret would each be written in full by any `?dto`
  in a tracing macro — into the same rolling log file. Six sibling types
  hand-write a redacting impl for exactly this reason; these four now do too,
  and each is pinned by a test rather than left to convention.
- **Reassembling a refresh token left plaintext copies on the heap the caller's
  `Zeroizing` could not reach.** Each keyring chunk was a fully-materialized
  plaintext string dropped un-wiped, and the accumulator reallocated as it grew,
  stranding the earlier buffer too — a refresh token spans one to two 2048-byte
  chunks, so at least one growth realloc happened on every refresh. Chunks are
  now wiped after appending, the buffer is preallocated, and the function
  returns `Zeroizing<String>` so the contract is structural rather than
  something each caller has to remember.



- **A federated-credential issuer could disguise the host its signing keys are
  fetched from.** `validate_issuer` checked the scheme and that a host segment
  existed, but never rejected userinfo — so
  `https://token.actions.githubusercontent.com@evil.example/` passed while Entra
  fetched the OIDC metadata and signing keys from **evil.example**. This module
  is the only control on the value (Graph accepts an incorrect issuer without
  error), and both call sites depend on it, including the restore path. The
  result was a secretless, non-expiring trust that read as GitHub in the UI.
- **DR restore wrote reply URLs from an untrusted manifest without validating
  them.** The interactive authentication editor rejects a wildcard or plaintext
  reply URL before its PATCH; restore wrote them verbatim, so a manifest
  carrying `https://*.evil.example/cb` created the app in the operator's tenant
  with that URL and auth codes for it could be delivered to the attacker's host.
  Each list is now validated per-URI — one bad entry no longer discards the good
  ones — with every rejection named in the restore report, and the reply URLs
  that *were* written are surfaced there too. A new repo invariant derives the
  rule from the source tree, so a future command that builds an authentication
  patch without validating is caught.
- **The loopback-only exception for plaintext `http` reply URLs was defeated by
  userinfo.** The authority was split on `:` before `@` was considered, so
  `http://127.0.0.1:1@evil.com/cb` read as host `127.0.0.1` and passed —
  as did `http://localhost:80@evil.com/cb` and `http://[::1]@evil.com/cb`. The
  one intentional plaintext exception admitted a reply URL pointed at an
  arbitrary host.
- **A server-supplied ARM role-definition id was spliced onto the base URL with
  the bearer attached.** Both call sites pass the value straight out of an ARM
  `roleAssignments` response — the same attacker-influenced server-output class
  the file already guards `nextLink` for — but it was concatenated with no
  separator and no validation, so an id without a leading `/` reinterpreted the
  authority of the composed URL. It must now be an absolute path free of
  `?`/`#`, and the composed URL is re-checked against the ARM origin.
- **The usage query's KQL literal used SQL-style quote doubling, which KQL does
  not honour.** This is the only caller of the Log Analytics `query` endpoint,
  so it is the whole KQL trust boundary. A non-verbatim `'…'` literal escapes an
  inner quote with a backslash, not by doubling: `''` closed the literal and
  opened another, which KQL silently concatenates, so a value containing `'`
  filtered on the wrong string and a backslash was not neutralised at all. The
  literal is now verbatim (`@'…'`), where `''` genuinely is the documented
  escape.


- **The Exchange client followed `@odata.nextLink` with no same-origin check.**
  `core::net` states the rule in its own module doc, and Graph, ARM and Key
  Vault all enforce it — a paging link is attacker-influenced server output, so
  a response body naming a foreign host got the Exchange admin bearer attached
  to a request to that host. The doc header listed only "(Graph, Key Vault,
  ARM)", which is how the gap stayed invisible.
