# Changelog archive — azapptoolkit 0.26.3 and earlier

Entries for released versions **0.26.3 and older**. Split out of the main
[CHANGELOG.md](../CHANGELOG.md), which had grown past 130 KB while being the
single highest-churn file in the repo — it is touched by roughly a third of all
commits, so every one of them was rewriting a file most of whose content is
years-stable history.

Nothing depends on this file. The release workflow's notes extraction reads only
`CHANGELOG.md`, and only ever the section for the version being released (see
`.github/workflows/release.yml`), so it never looks backwards. Keep the
`## [X.Y.Z] - YYYY-MM-DD` header format here anyway — no `v` prefix, ASCII
hyphen — so entries can be moved between the two files verbatim.

## [0.26.3] - 2026-08-20

### Security

- **A failed service-principal read no longer reports itself as a clean audit.**
  When the tenant-wide SP index could not be read, the error was logged at
  `info!`, an empty list was returned, and the entire SP-only scoring phase —
  enterprise applications, managed identities and orphaned service principals —
  was silently dropped. The run still reported `degraded: []`, so it cached
  itself as authoritative and an operator could not tell "no findings" from
  "never looked". It now records a `ServicePrincipalIndex` coverage gap, which
  both surfaces the caveat and stops the run being cached — matching what the
  sibling Graph app-role prefetch already did for the same consequence.
- **SAML federation metadata with namespace prefixes is now read correctly.**
  `parse_signing_certs` matched the literal `<KeyDescriptor` and
  `<X509Certificate>`, so any document using prefixes — `<md:KeyDescriptor>`,
  `<ds:X509Certificate>`, which is what Microsoft's own federation metadata
  publishes — yielded **zero** certificates, and the probe reported "0
  published" exactly as it would for an app that genuinely publishes none. Both
  element names are now matched on their local name with an optional prefix, and
  each certificate is attributed to the descriptor it actually sits in, so an
  encryption key between two signing ones cannot leak into a neighbour.
- **Two apps could be handed the same Key Vault secret name, so one app's
  rotate wrote a new version of another app's credential.** The name derived
  from a credential's display name dropped every character Key Vault disallows
  instead of replacing it, so `My App` and `MyApp` collapsed to one name — and
  any wholly non-Latin display name reduced to nothing and landed on the bare
  literal `client-secret`, which every such app shared. Code trusting "the
  latest version at that name" for one app could then receive another's secret
  material. Disallowed characters now become a single separator (runs collapsed,
  ends trimmed), and a name that still reduces to nothing gets a stable digest
  of the original appended. The common path is unchanged: a resolved
  `secret-<appId>` is already legal and sanitises to itself.
- **Eight tenant-wide application permissions that scored zero are now weighted,
  which shifts audit scores upward for apps holding them.** Each was already
  named in this codebase as the *broader* side of a subsumption pair — the
  scorer's own advice was to downgrade away from them — yet none appeared in
  either risk table, so an app holding one ranked as though it held nothing.
  `MailboxSettings.ReadWrite` is the one to note: it sets mail forwarding on
  every mailbox in the tenant, the classic exfiltration primitive, and it needs
  no read permission to act. Also added: `GroupMember.ReadWrite.All`,
  `Chat.ReadWrite.All`, `Device.ReadWrite.All`,
  `Contacts.ReadWrite` and `Notes.ReadWrite.All` as high risk;
  `Chat.Read.All` and `Calendars.Read` as medium. Weights follow the split the
  tables already used everywhere else — tenant-wide write is high, tenant-wide
  read is medium, matching `Mail.ReadWrite`/`Mail.Read` and
  `Files.ReadWrite.All`/`Files.Read.All`. **Apps holding these will rank higher
  than they did in 0.26.2; that is the correction, not a scoring change.**
- **A new invariant makes the omission impossible to repeat.** The existing
  guard scanned table → role map, so it caught a misspelling in an entry that
  existed but could say nothing about an entry never written — which is exactly
  how these values went unscored. The reverse rule now walks
  `SUBSUMED_APP_PERMISSIONS` and requires every broader-side value to carry a
  weight, deriving the check from the table itself rather than a hand-kept list,
  so adding a subsumption pair forces the weight decision at the same time. A
  value can be left unscored only by naming it in `INTENTIONALLY_UNSCORED` with
  a reason.
- **Every command that can answer from the tenant cache now proves the session
  first.** Sixteen commands read the tenant-scoped cache; on a cache hit, the
  `tenant_id` argument from the webview was the only thing deciding whose
  directory data came back, with no check that the tenant had signed in. Six
  answered from cache alone — `save_audit_to_file` was the worst shape, serving
  the cached audit for whatever tenant id it was handed and then writing it to a
  user-chosen file, which made the leak persistent on disk. The other ten are
  read-through commands whose *hit* path returns before any client is built, so
  the `graph_for` on the miss path never ran. All now call a shared
  `prove_tenant_session` (or `tenant_context` directly) ahead of the read, and
  refuse with `not_signed_in` otherwise. This is the cross-tenant leak AGENTS.md
  names the #1 footgun.
- **The invariant test meant to prevent exactly that had gone blind.** It scanned
  raw source text for the literal `cache.get(`, which rustfmt defeats — a wrapped
  `state\n.cache\n.get(...)` and the turbofish `cache.get::<Vec<T>>(...)` contain
  no such substring. It matched one command, the compliant one, and that cleared
  its own `found >= 1` floor while fifteen others went unseen. The detector is now
  whitespace-insensitive, handles nested generics in the turbofish, and requires
  the session proof to come *before* the first cache read rather than merely
  appear somewhere in the body. Its floor is the real count (16), and a second
  test pins the detector against the shapes rustfmt actually produces.
- **Bumped `h2` to 0.4.17** (RUSTSEC-2026-0258 — unbounded empty DATA frames, a
  remote DoS against HTTP/2 servers). It reaches this tree transitively through
  `hyper` under `reqwest` and the `wiremock` test server; the app is an HTTP/2
  *client*, so the server-side frame handling the advisory covers is not
  exercised at runtime. Bumped regardless, because the advisory failed `audit`
  and `deny` on every branch and blocked all merges.

### Fixed

- **A management-scope repoint that succeeded is no longer reported as
  refused.** Exchange Online returns group distinguished names in its own
  casing, but the post-write proof compared the DN set it asked for against the
  DN set Exchange echoed back *case-sensitively*. A write that had already been
  applied to every role assignment on the scope could therefore be reported as
  "the scope was NOT repointed as requested" — the worst direction for that
  message to be wrong in. Both the post-write proof and the plan-side "a scope
  already exists with a different group set" warning now compare case-folded,
  matching how the rest of the Exchange client already treats identities.

### Changed

- **Refreshed both dependency trees.** `cargo update` over the workspace
  lockfile (79 crates moved) and the frontend's separate one (56 moved), and the
  direct `tokio` / `zeroize` requirements now name the versions the lockfile had
  already resolved (1.53 / 1.9) instead of a stale floor. Notable transitive
  majors: `zvariant_utils` 3 -> 4 under `zbus` (Linux keyring only) and `phf`
  0.11 -> 0.13 in the frontend, which drops `rand` 0.8 and `rand_core` 0.6 from
  the WASM tree outright.
- **The deliberate crypto/encoding pins are unchanged.** `rand` 0.8, `sha2` 0.10
  and `base64` 0.22 still match what `oauth2` 5, `tauri-codegen` and the
  reqwest/hyper stack resolve to, so advancing them would add a duplicate major
  rather than remove an old one — the rationale and drop conditions stay in
  `dependabot.yml`. `windows-sys` unification is unchanged at five majors (a
  narrower `cargo update -p` had previously threatened to un-unify it), and the
  git-pinned `tauri-sys` rev is already upstream `HEAD`.

## [0.26.2] - 2026-08-13

### Added

- **Expired signing certificates can now be removed.** The rollover panel shows
  a Remove button on any certificate that has expired and is no longer the
  nominated signing key — the equivalent of the Entra portal's "Delete
  certificate" on an inactive cert. The backend had always been willing to
  remove one (it deletes both key halves and the associated key-file password);
  no surface offered the action, so expired leftovers accumulated forever. The
  active and staged certificates still can't be removed, and the previous
  (rollback) certificate keeps its own explicit "Retire" action.

### Fixed

- **A certificate that expired within the last 24 hours no longer reads "0d
  left".** Day counts rounded toward zero, so for the first day after expiry the
  expiry board called the certificate "expiring soon", the Expired filter missed
  it, and the SSO tab contradicted itself in a single row (an "Expired" badge
  next to "0 days left"). Day counts are now floored and the board takes
  expired-ness from the same timestamp comparison the rollover panel uses, so
  every surface agrees the moment a certificate expires.
- **Removing an expired-but-still-nominated certificate now explains itself.**
  It used to be refused with "that certificate is signing assertions right now",
  which is wrong once it has expired (Entra has already switched to the staged
  replacement). The refusal now says the certificate is expired but still
  nominated, and that activating the replacement is what makes it removable.
- **The SSO certificate board says what it can't see.** It lists applications
  whose single sign-on mode is recorded as SAML, and Microsoft documents that
  the field can be unset on older SAML apps — those never appear. The board now
  carries that caveat instead of letting a short list read as tenant-wide proof.

## [0.26.1] - 2026-08-13

### Fixed

- **The SAML signing-certificate features didn't work against a real tenant, and
  said nothing was wrong.** Microsoft Entra reports a certificate's identifier in
  two different encodings — `customKeyIdentifier` as base64 of the thumbprint
  bytes, `preferredTokenSigningKeyThumbprint` as hexadecimal — and the app
  compared them directly, so it never recognised which certificate was actually
  in use. Every certificate showed as "Staged" with no active one, every expiry
  read "Unknown", the "no replacement staged" filter matched nothing, the banner
  never warned, and staging in bulk silently skipped every application. Nothing
  errored: the board simply reported all-clear no matter how close an expiry
  was, which is the opposite of what it exists for. Both encodings are now
  normalised to one form before anything is compared, displayed, or written — so
  thumbprints on screen match what the Entra portal shows, and activating a
  certificate writes the value Entra expects.
- **Retiring a certificate left part of it behind.** Entra stores three objects
  per signing certificate — two keys and a password for the key file. Removal
  only took the two keys, stranding the password on the enterprise application
  permanently. It's now removed with them.
- **A staged rollover could show a sentence with a missing date** — "expires
  on  — activate before then" — when the active certificate couldn't be
  resolved. The deadline is only offered when there is a date to name.

### Changed

- **Signing-certificate dates are easier to read at a glance.** The rollover
  panel shows the expiry date rather than a full timestamp, marks status with the
  same badges as the expiry board, and highlights a certificate expiring within
  30 days (red inside 7) instead of printing "4 days left" in the same plain text
  as "1095 days left".

## [0.26.0] - 2026-08-12

### Added

- **Stage replacement certificates for a whole queue at once.** The SSO
  certificates board's "≤ 30 days, no replacement staged" filter is the work
  queue; now you can select those apps (one button selects all of them) and
  stage a fresh signing certificate on every one. The certificates land
  **inactive** — nothing changes for users, each app keeps signing with its
  current certificate until you activate the new one from its SSO tab. That is
  why staging is the only part of a rollover offered in bulk: activation is a
  coordinated switch and stays per-app on purpose. An app that already has a
  replacement staged is skipped rather than given a second spare, so re-running
  it over the queue on a later day doesn't pile up unused certificates. The run
  is cancellable, reports per-app failures, and stops if your session expires
  mid-way rather than failing every remaining app the same way.

- **Expiring SAML signing certificates are now visible before they bite.**
  Security → **SSO certificates** lists every SAML application in the tenant
  with its signing certificate, soonest to expire first, with the same filters
  and CSV export as the Credential expiry board. Until now these were invisible
  in the app: the audit reads an *app registration's* credentials, while a
  signing certificate lives on the enterprise application — so the first anyone
  heard of an expiry was Microsoft's 60-day email, which goes to whoever is on
  that app's notification list and, by default, only to the admin who first
  added it. Two columns say what the expiry date alone can't: whether a
  replacement is already **staged** (the difference between clicking Activate
  and starting a rollover), and whether **anyone at all** is on Entra's
  60/30/7-day warnings. A "≤ 30 days, no replacement staged" filter is the work
  queue. The banner counts the rows that are actually at risk, not every row
  with a date coming up.
- **The board says "Auto-promoted" when Entra has already switched for you** —
  an expired certificate that still has a valid replacement staged is one Entra
  is signing with regardless of whether anyone pressed Activate.

  These certificates deliberately **do not** change an application's audit risk
  score. An expiring certificate is a scheduled outage, not excess privilege,
  and the risk score ranks how much an app can reach — adding points would push
  apps up that ranking for being due for routine maintenance.

- **SAML signing certificates can now be rolled over without a sign-in outage.**
  Renewing a certificate used to be one button that minted a new one and made it
  live in the same breath — from that moment every sign-in was signed with a key
  the application had never seen, so nobody could sign in until someone uploaded
  the new certificate at the other end. The SSO tab now walks the rollover
  instead: **stage** a certificate (it lands inactive, and Entra starts
  publishing it in the app's federation metadata, so an application that polls
  metadata can pick it up before it ever goes live), **check** what Entra
  publishes, **activate** when the application is ready, and **retire** the old
  one only once sign-ins look healthy. Because the previous certificate stays in
  place until you retire it, **Revert** puts it back instantly if anything goes
  wrong. The panel reads its state live from Entra, so a rollover interrupted
  half way — you closed the app, switched tenants, handed it to a colleague —
  picks up exactly where it was.
- **The panel shows the deadline Entra imposes on you.** Once a replacement is
  staged, Entra promotes it on its own the moment the current certificate
  expires. That date is now shown as an activation deadline, so the switch
  happens when you choose it rather than at 3am on the expiry date. If the
  nominated certificate has *already* expired, the panel says so plainly —
  Entra is signing with the staged one whether or not anyone activated it.

### Changed

- **The immediate-rotation button is still there, and now says what it does.**
  Renamed to "Rotate and activate immediately" and carries a warning: it's the
  right tool for an application that can only hold one certificate at a time,
  and the wrong one everywhere else.

### Internal

- **Frontend debug builds no longer carry full DWARF.** The development wasm had
  grown to 2.19 GB, past what the linker can emit as a single debug section — the
  next view added anywhere in the front-end would have failed the build with an
  error that said nothing about size. Debug info is now line tables only
  (0.31 GB), which keeps file and line in a panic trace and makes development
  rebuilds noticeably faster. Shipped builds were never affected.

## [0.25.2] - 2026-08-11

### Internal

- **A second HTTP client was being compiled into the app and never used.** The
  OAuth library is used here for three small helper types; every network call
  goes through the toolkit's own HTTP client. Its default settings quietly
  brought along a second, older HTTP client and a second set of TLS root
  certificates that nothing ever called. Both are gone. No behaviour changes —
  in an app that handles tenant credentials, a network path nothing uses is
  worth removing rather than shipping.

### Security

- **Files this app writes are now readable only by you.** The settings file, the
  tenant backup manifest, every export, and the restore report — which carries
  freshly-minted client secrets in plain text for you to hand out — were written
  with whatever permissions the system default gave them, commonly readable by
  every account on the machine. They are now owner-only. This changes the
  default, not what you can do: sharing a file you exported still works exactly
  as before. (No mode bits exist on Windows, where files inherit the permissions
  of the folder you save into.)
- **A failed save no longer leaves a corrupted sign-in behind.** The saved
  refresh token is split across several entries in the OS keyring, and if a
  write failed part way the older token's tail stayed behind — the next launch
  then read a spliced value that looked like a valid stored session and was
  rejected as if your access had been revoked. A failed save is now rolled back
  to no stored session, so the app simply asks you to sign in.
- **Restoring a backup no longer imports sign-in trusts unchecked.** A backup
  file can carry federated identity credentials — the setting that lets an
  outside system sign in as an application **with no secret and no expiry**.
  Restore replayed them verbatim, so a manifest that had been tampered with
  could hand an outside party permanent access to a restored app, and nothing
  in the report would have said so. Every credential is now validated the same
  way the app's own editor validates one, and every credential that *is* created
  is listed in the restore report with its issuer and subject, so you can
  confirm each one belongs. Microsoft Entra accepts a bad issuer without an
  error and only fails much later, at sign-in, so this check has to happen here.
- **The same validation now applies when you add or edit a federated credential
  by hand.** An issuer that isn't an `https` address, a wildcard, a stray space
  that silently breaks sign-in, or a name Entra would reject are all refused up
  front instead of becoming a credential that looks fine and never works.
- **Restore refuses a backup written by a newer version.** The manifest has
  always carried a schema version for this purpose but never checked it, so a
  newer file was restored anyway — silently skipping settings this version does
  not understand, after the apps had already been created. Older backups restore
  as before.
- **SAML signing certificates can no longer be given an unlimited lifetime.**
  The certificate that proves a sign-in response came from Entra could be minted
  with any lifetime at all, including one far beyond the three years Entra
  permits — a certificate that in practice never expires and never has to be
  re-established. Lifetimes are now bounded, and rejected before anything is
  created rather than half-way through setting up the app.

### Fixed

- **One mistaken read no longer throws away a tenant-wide index.** The two cache
  accessors are paired with the two ways a value is stored, and reading through
  the wrong one deleted the entry — including the pinned, tenant-wide indexes
  that exist specifically so they survive memory pressure. Losing one sent every
  surface into a full directory rescan. The wrong read is now simply a miss; the
  entry is kept for the callers using the matching accessor. The other accessor
  was fixed this way in 0.25.0 and its twin was missed.
- **The cached security audit is no longer returned without a signed-in
  session.** It was the one thing this app answers from cache alone, so unlike
  every other read it never needed a token — which meant the tenant id it was
  asked for was the only thing deciding whose data came back, and a stale one
  (after switching tenants, say) could show the previous tenant's findings.
- **A legacy-policy migration can no longer point an app at the wrong mailboxes
  and call it done.** If a management scope already existed for the app and
  confined access to a *different* set of groups than the migration worked out,
  the scope was left exactly as it was — but the app's Exchange roles were still
  assigned against it, its org-wide grants were still removed, and the legacy
  policy was still deleted. The app then reached whatever that older scope
  covered, which could be wider, narrower or simply somebody else's set of
  mailboxes, while the report showed the groups the migration had intended. The
  migration now repoints the scope where it is allowed to, proves the repoint
  actually took effect, and otherwise refuses that app and changes nothing. The
  report shows the filter Exchange really has rather than the one that was
  planned, and a dry run says up front when an existing scope disagrees.
- **A mailbox scope filter naming several groups is no longer described by
  whichever one Exchange mentioned first.** An application confined through more
  than one management scope reaches the union of them; the effective-access
  readout named only the first, so it understated the reach and could describe
  the same tenant differently between two runs.
- **A recipient filter the toolkit cannot fully read is refused before it is
  written, not after.** The check existed but ran after the change had already
  been applied to every role assignment using that scope, so it could report the
  problem and never prevent it.
- **Two filter shapes that quietly defeated the safety checks.** A property whose
  name merely *ends* in `MemberOfGroup` — such as an exclusion clause — was read
  as an ordinary group clause, so a rewrite could have dropped the exclusion and
  widened what the app reaches; and a clause naming an empty group (`-eq ''`)
  counted as a real group, letting a filter that confines nothing pass the check
  that exists to catch exactly that. Both are now refused outright.
- **Applications with org-wide calendar access were scored as harmless.** The
  audit's medium-risk list named `Calendar.ReadWrite`, which is not a permission
  Microsoft Graph defines — every calendar permission is plural. The entry could
  therefore never match anything, and an application allowed to create, read,
  change and delete events in *every* mailbox in the tenant scored zero and could
  be ranked Low. **Applications holding `Calendars.ReadWrite` will now appear in
  your findings and their risk scores will rise.** A new check compares the mail,
  calendar and contacts entries against the scoping rules that already spell the
  same names, so a future typo fails the build instead of silently disabling a
  rule.
- **Three more permissions that can compromise a tenant now score.**
  `Application.ReadWrite.OwnedBy` (manage the credentials of apps it owns — it
  can act as them), `EntitlementManagement.ReadWrite.All` (grant Entra roles, app
  role assignments and API permissions to anyone including itself) and
  `Directory.Read.All` (Microsoft describes it as the highest-privileged
  read-only permission for Entra) all scored zero. Applications holding them will
  now be flagged, so **expect some scores to rise on the next run.**
- **Risky delegated permissions are advised on consistently.** The audit warned
  about only two named delegated scopes while the consent-grant review used a
  much broader definition that also covers mail, files, directory, group and
  role-management scopes. An admin-consented delegated `Mail.ReadWrite` produced
  no advisory at all. Both surfaces now use the same definition.
- **An app whose only working credential never expires is no longer reported as
  having none.** A credential with no expiry date counted as neither active nor
  expired, so an application holding one expired secret alongside one that never
  expires was described as "All credentials expired" — reading as a dead app,
  when in fact it held a permanent credential that never rotates.
- **Federated credentials in US Gov and China tenants used the wrong default
  audience.** The token-exchange audience differs per cloud, and the commercial
  value was used everywhere. Entra accepted the credential and it then failed at
  sign-in with nothing to indicate why. Sovereign builds now default to their
  own audience.

### Internal

- **The "Show N more" footer is one component instead of six copies.** Six list
  views had each grown their own copy of the same footer, identical apart from
  the word they counted — and all six carried an `audit-`prefixed style class,
  including the Key Vault, Sites and Mailboxes panels, which are not audit
  views. They now share one primitive, and the style class is named for what it
  does. No visible change.
- **The mailbox permission checks that could not see which resource a grant was
  on are gone.** Both Microsoft Graph and the legacy Office 365 Exchange Online
  resource publish permissions with the same names, and only Graph's can be
  confined to specific mailboxes — so a check that looked at the name alone
  called an unconfinable grant confinable. Deprecating them had not worked:
  they were still re-exported in a way that suppressed the warning for anyone
  using them. They are deleted, the three remaining callers now state the
  resource they were already relying on, and a build check fails if one
  reappears.
- **Secret scanning now blocks a merge, and knows Azure secrets.** The check ran
  on every pull request and could not stop one: it was not among the required
  checks, so a run that found a committed key was advisory. It is now required
  (8 checks, not 7) — and it always runs, including on documentation-only
  changes, because those can commit a key too. Separately, the scanner's own
  pattern set — used whenever `gitleaks` is not installed, which is the normal
  local case — knew AWS, Google, GitHub, GitLab, Slack and OpenAI key shapes and
  **not a single Azure one**, in a tool whose entire subject is Entra
  credentials. It now recognises storage and Service Bus connection strings, SAS
  signatures, bearer tokens and Entra client secrets.
- Two guards that could not catch what they were written for: the rule keeping
  pinned cache writes on tenant-wide keys stopped its search only at an
  unindented function, so a key mentioned in an *earlier* function — or merely
  named in a doc comment — excused an offending write; and nothing checked that
  a cache-only command proves the session. Both are now enforced and tested
  against the shapes that slipped past.

## [0.25.1] - 2026-08-09

### Fixed

- **Risk scores no longer depend on how an app's manifest happens to be
  written.** The scorer multiplied each risk band's points by the *number* of
  matching permissions, counting a permission twice if the manifest listed it
  twice — which Entra allows, since the same API can appear in more than one
  block of an app's required permissions. Two apps with identical effective
  access could land in different risk bands. **Some applications will therefore
  score lower than they did before, and a few may drop a risk level.** Nothing
  about their access changed; the earlier number was inflated. The same value
  held on two *different* APIs is still two permissions, and still scores as
  two — those grant genuinely different access.
- **"Remove redundant permissions" no longer reports success while leaving
  redundant access in place.** A permission redundant on *both* Microsoft Graph
  and Office 365 Exchange Online produced a single finding, so the one-click fix
  removed the grant that finding named, said it was done, and left the other
  standing — where the next audit found it again. Each is now reported and fixed
  separately, naming the API it belongs to. Tenants holding mail permissions on
  both resources will see more redundancy findings than before; each is a real
  grant that was previously hidden behind another.
- **The over-privilege banner on a service principal now says which API each
  permission belongs to.** It listed bare names, so an identity holding
  `Mail.ReadWrite` on both Microsoft Graph and Office 365 Exchange Online showed
  one name and left you to work out which of the two rows below it meant — and
  only the Graph one can be confined to specific mailboxes.

- **The legacy-policy migration no longer confines an app to a management scope
  that confines nothing.** If a management scope already existed for the app but
  carried no recipient restriction filter, the migration accepted it silently,
  assigned the app's Exchange roles against it, removed the org-wide Entra
  grants and deleted the legacy Application Access Policy — leaving the app able
  to reach *every* mailbox in the tenant while the report said it had been
  scoped. That is strictly worse than the policy it replaced. The migration now
  refuses that app and changes nothing, with the same message the "Grant scoped
  access" flow has always shown for the identical situation. Checked on every
  path, including a dry run, so the plan shows the refusal instead of promising
  a migration that would misfire.
- **Cancel now works during the first minutes of five more long-running
  operations.** A backup, the expired-secret sweep, the Key Vault access sweep,
  the "who can reach this mailbox" search and the SharePoint site sweep all took
  their cancellation handle *after* the tenant-wide enumeration that precedes
  any visible progress — so a Cancel pressed during that phase, the likeliest
  moment, was discarded and the run continued. Same fix and same cause as the
  audit and legacy-policy entries below; a test now pins the ordering for every
  long-running command rather than for one at a time.
- **A stopped legacy-policy migration now names the apps it never reached.** The
  report said only that it was incomplete, leaving the remaining apps to be
  found by comparing it against the tenant — the one thing least likely to work
  when the run stopped because the session died.
- **A mailbox scope filter containing a non-ASCII character no longer crashes
  the app.** Reading an Exchange recipient filter walked it a byte at a time, so
  the first accented letter, curly quote or non-breaking space *outside* a
  quoted value hit a character boundary mid-way and panicked. Operator-authored
  filters reach this from three places, and a filter pasted from a document is
  enough to trigger it.
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

## [0.19.2] - 2026-07-07

### Fixed

- **Export confirmations now toast instead of sticking to the top.** Saving an
  audit export (and the Credential-expiry / Delegated-grants lens exports) showed
  a persistent "Saved to …" banner pinned above the content; it now appears as a
  bottom-right toast and auto-dismisses, matching the tenant list-view exports.
  Failures route through the same toast path (with the standard re-auth action)
  rather than a stuck inline error.

## [0.19.1] - 2026-07-07

### Fixed

- **Security-tab export no longer freezes the app.** Exporting an audit (CSV,
  JSON, or HTML) from the Security workbench blanked and locked up the whole
  window on Windows, requiring a force-quit. The Export control was a Thaw `Menu`
  overlay, and opening the native "Save file" dialog from inside that teleported
  overlay raced its teardown and wedged the webview. It's now a plain-DOM
  disclosure dropdown that closes before the dialog opens.

### Changed

- **Consistent "Export ▾" dropdown across every list.** The App Registrations,
  Enterprise Applications, and Managed Identities tabs replaced their inline
  "Export CSV" / "Export JSON" buttons with the same compact "Export ▾" disclosure
  the Security tab now uses (a shared `ExportMenu` component). No behaviour change
  beyond the surface — the same plain-DOM control on every tab.

## [0.19.0] - 2026-07-07

### Added

- **Create enterprise applications from the Microsoft Entra gallery.** The
  renamed **New application** button (Enterprise Applications header + the Home
  Overview card) now opens a chooser — **Browse the Entra gallery** or **Create
  your own** — mirroring the Azure portal. "Browse the gallery" searches the
  `applicationTemplates` catalog and instantiates the picked app (e.g. Salesforce,
  ServiceNow) into a paired app + service principal; single sign-on is then
  finished on the app's SSO tab. "Create your own" opens the existing custom
  SAML/OIDC SSO wizard. New backend: `search_application_templates` +
  `create_gallery_application`.

### Changed

- **Renamed "New SSO application" → "New application".** Matches the Azure portal
  and the app's "New app registration" convention; it now covers both the gallery
  and custom creation paths (see Added).

- **Home Overview — card action buttons align to a common baseline.** Every card's
  action(s) now sit in a consistent row pinned to the card bottom, so the buttons
  line up across the row instead of floating at content-dependent heights.
- **Left nav slimmed to navigation; account actions moved to the tenant pill.**
  The signed-in tenant pill (top right) is now an account menu: clicking it drops
  Access Readiness, Settings, Cache diagnostics, Check for updates, Sign Out, and
  the app version — the cluster that used to sit at the foot of the left rail. The
  rail is now purely Inventory / Security / Operations, and the account actions
  stay reachable from the always-visible pill even when the rail collapses. The
  Refresh-token control stays beside the pill.
- **Access Readiness — removed the standalone "Re-check" button.** Refreshing your
  token (the top-right control) now re-runs the readiness check in place, since a
  refresh is exactly when your active roles change — one action instead of
  refresh-then-re-check.

- **Global search is now a records-only finder.** The command palette (nav/tool
  actions that appeared as a "Commands" group in the results) was removed now that
  the nav rail and account menu cover navigation — so searching for an app is no
  longer buried under command rows. Records (App Registrations / Enterprise
  Applications / Managed Identities) stay keyboard-navigable, and Cmd/Ctrl-K still
  focuses the bar.

### Fixed

- **Global search hint no longer shows a Mac-only shortcut or truncates.** The
  placeholder dropped the `⌘K` reference (the focus hotkey still works with
  Ctrl/Cmd on every platform) and is now a short "Search apps by name or GUID…"
  tip that fits the field.

## [0.18.1] - 2026-07-07

### Changed

- **Settings — organized into three tabs.** The per-tenant operator defaults are
  now grouped under **App Registration Defaults** (default owners), **Enterprise
  Application Defaults** (default owners + SSO notification emails), and **Naming
  Defaults** (Key Vault secret, management scope, and mail-enabled security group
  name patterns), replacing the single long scroll. One **Save defaults** button
  still persists every tab at once.
- **Left nav — removed the "More" dropdown.** Cache diagnostics and Check for
  updates are now direct items in the account block (one click instead of two);
  the app version shows as a line beneath Sign Out.

## [0.18.0] - 2026-07-07

### Changed

- **Exchange scoping — configurable scope + group naming, applied to all scoping.**
  Two per-tenant naming patterns on the **Settings** page now drive the names the
  toolkit creates when it scopes an app's mailbox access via Exchange RBAC:
  - **Management scope naming** (default `app_scope_{appId}`) — previously wired
    only into the legacy-AAP migration, this pattern now governs the management
    scope name for **every** Exchange scoping path, including fresh scoped-mailbox
    grants from the Grant-access wizard. The old migration-only "Exchange
    migration" settings section is replaced by this clearer one.
  - **Mail-enabled security group naming** (new, default `app_scope_group_{appId}`)
    — the toolkit-managed scope group whose membership defines which mailboxes an
    app can reach is now configurable too. **Note:** the built-in default changed
    from `azapptoolkit_{appId}`; a scope group already created under the old name
    won't be auto-discovered unless you set the group pattern to
    `azapptoolkit_{appId}`.
- **Scope wizard — clearer managed-group status.** Step 2's mailbox panel now
  badges whether the scope group already **exists** (with its live member count)
  or **will be created** on first add — the previous heading implied the group
  existed even when it didn't — and lists the group's current members so it's
  clear exactly which mailboxes the scoping covers.

## [0.17.0] - 2026-07-06

### Added

- **App registration — editable Internal notes.** The Overview tab now shows an
  **Internal notes** field (Microsoft Graph `application.notes`, the same
  free-text property the Entra portal surfaces under *Branding & properties*).
  It reads in the overview and is editable in the same **Edit → Save** form as
  display name / sign-in audience / description; clearing the box removes the
  note. Saving reuses the existing `update_application` path, so the cached
  detail is refreshed automatically.

## [0.16.0] - 2026-07-06

### Added

- **Settings page — per-tenant operator defaults.** A new **Settings** entry in
  the account section of the nav configures defaults that are stored locally
  (per tenant, in `settings.json`) and reused so you don't re-enter them each
  time:
  - **Default owners** for app registrations and enterprise applications.
    Each Owners tab gains an **"Add Default Owners"** button that adds them in
    one click — additive (it skips owners already present and never removes).
    Enterprise-app owners are users only, matching Entra's rules.
  - A **default SSO notification-email list** that seeds the notification field
    when creating a new SAML SSO configuration (only when the field is empty, so
    it never clobbers an edit).
  - A **management-scope-name pattern** (with an `{appId}` placeholder) that
    becomes the default name when migrating a legacy Application Access Policy —
    still overridable per migration; blank falls back to `app_scope_<AppId>`.
  - A **Key Vault secret-name pattern** (with an `{appId}` placeholder) that
    names the vault secret on rotation; defaults to `secret-<AppId GUID>`. (KV
    secret names allow only letters, digits, and dashes — no underscores — so the
    prefix is `secret-`.) A per-app remembered name still wins.
  - A **distribution-list search** on the SSO notification-email default: search
    mail-enabled groups / distribution lists and add a team address (e.g.
    `sso-alerts@contoso.com`) without typing it. (Owners stay users-only — Graph
    rejects groups as service-principal owners.)

- **Key Vault vault picker with discovery + per-app memory.** The rotation
  dialog and the Key Vault browser show the vaults you can access (discovered via
  Azure Resource Manager) in a **searchable, filter-as-you-type list** beside the
  vault field — type to filter the full set (with a match count), or enter any
  name directly. When you rotate an app registration's secret into a vault, that
  vault (and secret name) is **remembered per app**, so the next rotation
  pre-selects it; a tenant-level default vault fills in for apps with no history
  yet. Only names are stored, never secrets.

### Changed

- **Access Readiness now checks Azure RBAC accurately instead of always "?".**
  It enumerates your **direct** Azure role assignments across your subscriptions
  and reports **✓ Have** when a matching assignment is found (with conservative
  supersets — e.g. Owner/Contributor satisfy "Reader", but control-plane roles do
  **not** stand in for Key Vault data-plane access). Because group-inherited roles
  aren't visible to the per-user lookup, it never downgrades to a false "Missing":
  without a confirmed direct assignment it stays "?" with guidance. Falls back to
  the previous "?" + nudge when Azure (ARM) access hasn't been consented.

### Fixed

- **Access Readiness now reports Exchange Online RBAC accurately instead of
  always "? Unknown".** The `exchange_rbac` capability was tagged as an
  unimplemented "Exchange probe" whose role verdict was hardcoded to Unknown, so
  an operator with an **active** Exchange Administrator role still saw "?".
  Exchange Online RBAC is activated through the Entra *Exchange Administrator*
  directory role (roleTemplateId `29232cdf-…`), which `/me` already returns — so
  the capability is now detected like every other directory-role capability
  (matched by template id, with Global Administrator as a superset). An active
  Exchange/Global Admin now reads **✓ Have**; PIM-eligible-but-inactive reads
  **✗ Missing**. The unused `RoleDetect::ExchangeProbe` path was removed. Azure
  RBAC remains "?" (it's genuinely per-subscription/-vault and not enumerable
  from the directory), but its detail text now explains that and points to
  Resource Access rather than reading like a failure.

### Changed

- **The "Readiness" tab moved next to Sign Out and is renamed "Access
  Readiness".** It reports the *signed-in operator's own* permissions, not the
  org's apps, so it now lives in the account block at the bottom of the nav rail
  (directly above Sign Out) instead of the Security group. The page heading, tab,
  and top-bar crumb all read "Access Readiness" consistently (the crumb group is
  now "Account").

- **Legacy Application Access Policy migration: the management-scope name now
  defaults to `app_scope_<AppId GUID>` and is customizable.** Previously the scope
  reused the mail-group's `azapptoolkit_<AppId>` name; it's now named separately
  (`app_scope_<AppId>`) so a scope and its backing group never collide, and the
  migration UI exposes an optional "Management scope name" field (blank ⇒ the
  default). The override applies to single-app migrations; a whole-tenant run
  always derives the per-app default so scopes can't clash.

## [0.15.1] - 2026-07-05

### Fixed

- **CI: the GitHub Pages demo deploy no longer flakes red on a transient backend
  error.** `actions/deploy-pages` intermittently reports "Deployment failed, try
  again later" on its first status poll (~1 run in 30) even when the build and
  uploaded artifact are fine; a manual re-run always cleared it. `pages.yml` now
  retries the deploy step once (after a short pause) via `continue-on-error` + a
  conditional second attempt, so the transient self-heals. A genuinely persistent
  failure still fails the job (the retry has no `continue-on-error`).

### Changed

- **Perf: the security audit no longer fetches every service principal twice.**
  `run_audit` already enumerates the whole tenant's service principals once (the
  `sp_index` scan that drives the SP-only scoring phase), and that projection
  (`id,appId,accountEnabled,…`) is a superset of the two fields per-app scoring
  reads. The run previously *also* issued a batched lean-SP prewarm — roughly one
  `$batch` POST per 20 app registrations (~250 extra POSTs on a 5 000-app tenant)
  — re-fetching the same directory objects. It now seeds the audit's lean SP
  cache from the index in memory (new `GraphClient::seed_lean_sps_from_index`),
  cutting those POSTs to zero and reducing 429 pressure on large tenants. App
  registrations absent from the index are left cold, so a per-app lean lookup
  still resolves them (an SP-less app caches `None`; a truncated index falls back
  to a real GET) — identical to the prior failed-batch degradation. Removed the
  now-unused `GraphClient::prewarm_service_principals_lean`.

- **Docs: trimmed `AGENTS.md` over-prompting.** Removed the generic "Coding
  fundamentals" bullets that restated Claude's default behaviour (style-matching,
  scope discipline, comments-explain-why, keep-the-suite-green), keeping only the
  security-critical + dependency-cost invariants that are specific to this repo;
  deleted the duplicate CSP rule from **Common patterns** (it survives in
  **Conventions & gotchas**); and collapsed Verification-playbook steps 1–4 into a
  single pointer to `just verify` so the section leads with the CI-only detail that
  isn't obvious. No behavioural rules changed — pure dead-weight removal.

- **CI: the browser GUI tests (`just web-itest`) run far faster** via two changes
  to `apps/desktop/web-rs`:
  - **Strip debuginfo from the test wasm** — `[profile.test] strip = "debuginfo"`.
    Each integration-test wasm was ~1.9 GB, ~96% of it DWARF debuginfo that
    wasm-bindgen-test-runner had to decode before every run (~24s/binary). Stripping
    it cuts each binary to ~8–52 MB so the decode is near-free. The runner already
    strips debuginfo from the served module, so in-browser behaviour and panic
    messages are unchanged (only already-unusable wasm stack frames lose line info);
    scoped to the `test` profile, so `just dev` / `web-build` keep their debuginfo.
  - **Group the 21 one-file-per-binary tests into 3 shard binaries**
    (`tests/gui_N.rs` pulling `tests/gui/<view>.rs` modules), so Chrome is booted 3×
    instead of 21×. A *single* merged binary was tried first but its ~78 MB served
    wasm exceeds what headless Chrome will instantiate (timed out even at 120s); each
    shard is kept under ~52 MB. Tests in a shard share one page and rely on Leptos
    disposing each mounted view on unmount for isolation (the runner scrapes results
    from the DOM, so `reset()` must NOT clear the body). `WASM_BINDGEN_TEST_TIMEOUT=60`
    (justfile) gives the larger shards load headroom over the runner's 20s default.

## [0.15.0] - 2026-07-04

### Added

- **Key Vault reverse lookup** — a third tab in Resource Access sweeps every reachable Key Vault's
  direct Azure RBAC role assignments and shows which principals (apps, managed identities, users)
  hold which role on which vault. Filter by principal to see the vaults an app can reach, or by
  vault to see who can touch it; broadly-privileged roles (Owner, Key Vault Administrator, …) are
  flagged. Progress-streamed, cancellable, and backend-cached like the Sites sweep; reads use the
  signed-in user's Azure Reader rights (ARM scope, consented on demand). Complements the existing
  per-managed-identity Azure-roles view (the forward direction).

### Changed

- **Release/CI hardening:** the `release.yml` `guard` job now runs `cargo audit` against the
  workspace-excluded `web-rs` lockfile too (via `just web-audit`), so a fresh advisory in the
  IPC-privileged frontend tree fails fast before the build matrix spends minutes.
- **Developer tooling:** new `just verify-full` recipe runs full CI parity locally — `just verify`
  plus both RustSec scans, both `cargo deny` policies, and the browser GUI tests (`web-itest`). The
  agent instructions (`AGENTS.md`) were put on an invariant-plus-pointer diet with deep detail moved
  into `docs/architecture/` (new `frontend-workspace.md`, `release-updater-demo.md`), and the
  contributor hooks/skills were realigned to the actual release, verify, and branch-protection flow.
  No application behavior change.

## [0.14.0] - 2026-07-04

### Changed

- **CSS token housekeeping** (internal hygiene, no visual change): finished the
  design-token migration in `styles.css` — dropped the dead compatibility aliases
  (`--shadow-sm`→`--shadow-2`, `--shadow-md`→`--shadow-4`, `--surface-elevated`→
  `--surface-raised`) after repointing their uses, and swept hardcoded 4px-grid
  spacing and 12px font-sizes onto the existing `--space-*` / `--text-*` tokens
  where a token exactly equals the value. Pixel-identical output.
- **Design polish — iconography pass, posture-card hierarchy, labeled compare panes**
  (visual only, no behavior change). Chrome buttons now draw from the shared `Icon`
  catalog so one action reads the same everywhere: the dock chip close (`×`) and
  workspace pane close (`✕`) — two different glyphs for the same "close" — collapse
  onto one `Close` icon; the pane "⤢ Full" control becomes a `Maximize` icon (new
  catalog entry); "Export ▾" becomes **Export** + a `ChevronDown`; and the "+ New
  app" / "+ New SSO application" / "New app registration" primary buttons lead with a
  `Plus` icon (label kept, `+` prefix dropped). The Home **Security Posture** card is
  reworked from a flat 9-metric grid into a hierarchy — a large **Critical / High /
  Medium** severity row above a ranked **Top findings** list (tone dot · title · count
  · chevron) that reuses the Security workbench's impact ordering (`GROUP_CATALOG`) and
  the shared `posture_counts`, so it rhymes with the pane it opens (same drill targets).
  Workspace compare panes get a real title bar — the dock chip's kind glyph + the item's
  live name — so a 2-up side-by-side labels which pane is which, and the overlay panes
  lift onto a deeper `--shadow-16` layer. A button-ladder note is added to `styles.css`.
- **Shell refresh — the top bar earns its keep and the nav rail regroups** (muscle-memory
  reorg, no feature change): the previously-empty top-bar thirds now carry the
  persistent app-level anchor — the left shows the active view's nav-group crumb +
  title (mirrors the page `SectionHeader` so identity survives content scroll) and the
  right adds a signed-in **tenant chip** (org name + primary verified domain, previously
  buried in the nav user block) plus the **Refresh token** affordance (silent
  `refresh_session` → interactive `reauthenticate` fallback, unchanged behavior). The
  left navigation is regrouped into three labeled sections — **Inventory** (Home / App
  Registrations / Enterprise Applications / Managed Identities), **Security** (Security /
  Permission Tester / Resource Access / **Readiness**, promoted up out of the user block
  since it's a real page), **Operations** (Bulk Actions / Disaster Recovery / Key Vault).
  The signed-in user block slims to identity + Sign Out with an overflow "…" popover
  (closes on outside-click / Escape) holding the low-frequency utilities — cache
  diagnostics, check-for-updates, and the version string.
- **UI consistency pass — one page-header, one loading, one failure grammar** (design
  unification; visuals ≈ unchanged): every page now uses the single `SectionHeader`
  (uppercase category eyebrow + title) — the App Registrations and Enterprise
  Applications views moved off the old `.view-header`, and `ListScaffold` lost its
  `title`/`actions` props so the list card starts at its search box instead of
  re-rendering the page title a second time (the `.view-header*` and
  `.app-list__header` CSS is deleted). Loading fallbacks follow one rule — skeletons
  for content regions, spinners only for in-button busy: the Home dashboard cards and
  the detail tabs (Authentication / Expose an API / Conditional Access / Activity /
  Federated credentials) now fall back to a `DetailSkeleton`/`SkeletonList` matching
  the region instead of a centered spinner. Failure states collapse onto two
  primitives: `DetailLoadError` is now the universal "section failed → message +
  Retry" block (detail panes, all three list views, and the dashboard cards route
  through it), and a new `Callout` (info/ok/warn/danger) is the single home for the
  scattered `.alert` boxes, adopted at the consent prompts and audit notices.
- **Frontend view code split for maintainability** (no behavior or DOM change): the
  enterprise-application detail pane finished its module-directory split (Overview /
  Owners / Credentials / the small Provisioning-Activity-CA panels moved out of
  `mod.rs`); `resource_access_view.rs` became a `resource_access/` directory (Sites
  and Mailboxes panels in their own files); the lazily-loading Usage panel moved out
  of `permissions_tab.rs`; the three list views' identical export snapshot + double-
  submit guard + toast logic collapsed into one `use_list_export` hook and the
  Managed Identities list now renders through the shared `ListScaffold` like the
  other two; and the duplicated `ls_get`/`ls_set` localStorage helpers plus the
  recurring two-field IPC arg shapes were single-sourced (`util.rs`,
  `bindings/common.rs`). The dialog-dense `credentials_tab`/`expose_api_tab` splits
  were deliberately left for later — extracting their dialogs would thread 10+
  signals through props and touch the Suspend-reset footgun for no real gain.
- **The desktop backend's largest command modules were decomposed** (no behavior,
  wire, or cancel/progress change): `run_audit`'s ~380-line orchestrator split its
  best-effort tenant-wide prefetch blocks into named `async fn`s and bundled
  `score_one`'s ~10 parameters into one `Arc<ScoreCtx>` (each scoring task now clones
  one `Arc`, not a dozen values); the six sequential bulk commands share one
  `run_bulk_seq` scaffold (the AGENTS.md-pinned "per-app cores take `State`, so these
  stay sequential" invariant kept — plus the leftover fixed 50 ms create-loop pause
  removed); `commands/sso.rs` split into `sso/mod.rs` + a self-contained `sso/claims.rs`
  claims-policy codec, and `get_sso_config`'s previously untested service-principal
  field spelunking became a tested `extract_sp_sso_fields`; the seven
  `AppState::ensure_*_token` probes collapse onto one private `ensure_scoped_token`
  core (centralizing the hand-maintained CAE/adapter pairing); and the five SharePoint
  pre-acquire blocks share a `sharepoint_client_checked` helper mirroring
  `exchange_client_checked`.
- **Internal: the audit engine is now a module directory** (`azapptoolkit-core::audit`
  split into `permissions` / `types` / `scoring` / `credentials` submodules with a
  re-exporting `mod.rs`) — no behavior or wire-format change; every public path and
  all 124 characterization tests are unchanged.
- **The capabilities catalog pairs each directory-role name with its immutable
  `roleTemplateId` in one entry** (previously two index-aligned slices whose
  alignment only a test enforced — the shape the v0.12.1 "Role missing" fix worked
  around). Misaligned name/id pairs are now unrepresentable; display consumers use
  the new `Capability::role_names()`. Also removed two dead public helpers
  (`capabilities_for_plane`, `ScopeKind::target_noun`) and derived the cache's
  per-kind bucket array size from `CacheKind::ALL` instead of a hand-synced literal.
- **Graph client restructured for maintainability** (no behavior change): the
  transport/retry core, pagination helpers, and request/patch body types moved out
  of the 1,150-line `client.rs` into `client/transport.rs` and their domain modules
  (all import paths preserved via re-exports); the 2,700-line test monolith split
  into per-domain files. The two near-identical service-principal batch-prewarm
  functions now share one core, and the dead `GraphError::Url` variant was removed.
- **The auth service is now a module directory** (`service/{wire,loopback,scopes}.rs` +
  a ~900-line core): the AAD wire protocol (error classification/redaction, claims
  decoding), the loopback redirect listener, and the per-feature scope catalog each
  live in their own file. Pure code motion plus one shared `ensure_same_identity`
  helper for the tid+oid cache-safety check `consent_for_scopes` and `reauthenticate`
  previously duplicated. `AccessToken` also dropped its never-used serde derives, so
  the memory-only token contract is now compiler-enforced.
- **Exchange client restructured the same way** (no behavior change): the 1,136-line
  `client.rs` split into `client/transport.rs` (envelope POST + retry loop with the
  bodyless-403 diagnostics capture), `client/rbac.rs` (service principals, scopes,
  role assignments, legacy AAP, verification), `client/groups.rs` (recipient groups
  + the managed scope group + the OPATH filter builder), and `client/tests.rs`; the
  four optional `Get-*` lookups now share one `first_optional_as` projection, and an
  empty single-object cmdlet result is reported honestly as a protocol error instead
  of a fabricated HTTP-200 API error. Key Vault dropped a dead transport parameter
  and its unused `SecretProperties` alias, and both the ARM and Key Vault paging
  loops gained a defensive page cap against self-referencing `nextLink`s.
- **The frontend's tenant-scoped UI state resets structurally on tenant switch.**
  Every lifted search, facet, bulk selection, pending deep-link tab, and shell
  dialog flag now lives in one `TenantScopedUi` substruct on `Session` whose
  `reset()` sits directly under its field declarations, and `set_active_tenant`
  resets the whole group in one call — previously each of ~18 fields had to be
  remembered individually there, and two dialog flags had already been missed
  (fixed in the prior release wave). A pinning test asserts every field returns
  to its sentinel. No behavior change beyond that structural guarantee.

### Fixed

- **Interactive sign-in no longer hangs when the browser opens a speculative
  connection to the loopback listener.** The redirect listener previously accepted
  exactly one connection and read one TCP segment; a browser preconnect or a stray
  `/favicon.ico` probe could consume that slot and the real OAuth redirect was lost
  until the 300s timeout. It now loops — non-redirect requests get a 404 — and reads
  to the end of the request head instead of assuming a single segment.
- **Azure Resource Manager paging now refuses off-origin `nextLink`s** before the
  bearer token is attached — the same guard the Graph and Key Vault clients already
  had. The origin check (including its embedded-credentials rejection, which the Key
  Vault copy had missed) is now single-sourced in `azapptoolkit-core::net` so the
  three clients can't drift again.
- **Throttled one-shot scoped Graph calls (sync jobs, directory audits, sign-in
  activity, claims-policy writes) now surface as `throttled`/retryable** instead of a
  generic Graph error, so the UI's retry affordance and backoff messaging apply. The
  one-shot transport still deliberately skips the retry loop.
- **Key Vault secret reads can no longer leak the secret via `{:?}` debug
  formatting** — `SecretValue` got the same redacted `Debug` its write-side twin
  gained in v0.12.0.
- **Interactive sign-in / consent / re-authenticate no longer block an async worker
  on the OS-keyring write** (the silent-refresh path already ran it off-thread); the
  four flows now share one post-token-exchange persistence helper.
- **A dead session during DR backup/restore now offers the Re-authenticate toast
  action** instead of a dead-end error banner (the DR view's hand-rolled handlers
  bypassed the central error sink).
- **Switching tenants closes the create-app dialog and SSO wizard** — previously a
  tenant switch mid-dialog left the stale form floating over the new tenant's Home.

## [0.13.0] - 2026-07-03

### Changed

- **The Security tab is now a findings-first workbench.** The old audit pane had three
  competing controls for the same two filter signals — a severity tab bar, an 11-chip
  finding drawer, and an 11-card clickable scorecard — with remediation buried per-row
  in one big table. The redesign gives one clear path: a read-only posture strip
  (severity counts + Run/Cancel/Export/progress/consent) above four sub-tabs.
  **Findings** (the new default) is a ranked, grouped list of finding categories —
  worst-impact first, healthy/scoped configurations demoted to a collapsed section —
  where expanding a group shows the affected principals with per-row Open/Fix, a
  multi-select, and a bulk bar offering exactly the fix that pairs with that group's
  rule ("Fix all N" pre-selects every eligible app; typed confirmations and target
  forms still gate execution). This also retires the old mismatch where the
  Over-privileged filter offered the Remove-redundant bulk fix (a different rule) —
  Redundant permissions now has its own group, and new group fixes cover ownership
  (Add owner) and unused apps (Disable sign-in / Delete). **All apps** keeps the
  ranked score table with a single severity filter + search for triage. Credential
  expiry and Delegated grants stay as sibling tabs. Home's Security Posture card keeps
  its metrics but now shares the workbench's count code (the numbers can never
  disagree), and its drills route severity clicks to All apps and finding clicks to
  the matching expanded group. Saved views for the audit were removed along with the
  filter drawer (any stored `audit` saved views are simply ignored).

### Added

- **Two new one-click audit remediations: "Add owner" and "Disable sign-in".** The
  ownership finding (no owners / single owner) now carries an **Add owner** Fix — a
  guided directory-search modal that adds the picked user via the existing owner
  mutation (purely additive, so it can't break a working sign-in). Apps flagged
  **Unused** carry a **Disable sign-in** Fix that sets `accountEnabled: false` on the
  app's service principal — reversible any time from the enterprise app's Overview
  toggle, which is why a plain confirm suffices. Both follow the audit's safe-fix
  contract: the backend re-resolves live state before acting (disable-sign-in resolves
  the SP fresh from the application; an app with no SP reports not-found), and both
  clear the row's Fix button on success. Previously the ownership and unused findings
  were advisory-only — 12 of ~18 finding types had no remediation path at all; this
  starts closing that gap ahead of the findings-first Security tab revamp.

- **An inline callout points at scoping when an identity holds org-wide access.** On the
  Enterprise Application and Managed Identity Permissions tabs — the surfaces where a
  foreign-tenant (no local app registration) principal gets scoped — a warning callout
  now names the held org-wide mail/SharePoint permissions up front and its "Scope…"
  button opens the Grant-access wizard pre-seeded, the same contract as a held row's
  "Scope…". Previously the Exchange/SharePoint scoping sections rendered further down
  the tab and mail had no per-row scope entry, so the path was easy to miss.

- **The Security Audit now covers principals without a local app registration** —
  foreign-tenant (OIDC/multi-tenant) enterprise applications, managed identities, and
  orphaned service principals. Previously the audit enumerated only `/applications`, so
  a foreign app holding org-wide `Mail.*` or `Sites.*` produced no finding at all. Such
  principals are scored from their *granted* Graph application roles (plus
  admin-consented delegated scopes): permission risk, admin consent, disabled-SP,
  org-wide mailbox/SharePoint advisories, and the unused-app signal apply; credential
  and manifest rules don't (those live on the application in its home tenant). The
  noise filter — only SPs holding at least one Graph application grant — keeps the
  hundreds of grantless first-party Microsoft SPs out. Rows carry a new additive
  `principal_kind` field and a "No app registration" finding chip; their Open
  deep-links to the Enterprise Application / Managed Identity detail, and their
  one-click mailbox/SharePoint Fixes route to the SP-only scoping commands (the
  app-registration remediation wrappers would 404). SP rows are excluded from the bulk
  selection — bulk actions target app registrations. The extra coverage costs no new
  per-item Graph traffic: it reuses the tenant-wide grants and app-role reads the run
  already made. CSV export gains a trailing `PrincipalKind` column, and granting a
  permission to a bare SP now invalidates the cached audit run.

## [0.12.1] - 2026-07-02

### Fixed

- **Readiness no longer reports an active role as missing in tenants with legacy role
  names.** The checklist matched directory roles by display name, but the `directoryRole`
  objects in long-lived tenants carry legacy names — Graph names the SharePoint
  Administrator role "SharePoint Service Administrator" (documented), Global
  Administrator historically "Company Administrator" — so an **active** role could show
  "Role missing" no matter how often the token was refreshed. Roles are now matched by
  their immutable `roleTemplateId` (with a display-name fallback), so the SharePoint
  site access row — and every other directory-role check — recognizes the activated
  role regardless of what the tenant calls it.
- **Global search finds anything by any of its GUIDs.** Pasting a full GUID into the
  top-bar search only probed two of the four identities (app registration by appId,
  service principal by object id) — so an Enterprise Application was unfindable by its
  Application ID (and an app registration by its object id), returning nothing at all
  for a gallery/third-party app with no local registration. The GUID branch now probes
  all four in parallel: app registration by appId *and* object id, service principal by
  object id *and* appId.
- **The copy confirmation now covers every copy button.** v0.12.0's "Copied" badge only
  landed on `CopyableId` (MI detail fields, DR view, credential-table ID cells) — the
  detail-pane header's app-id copy button and the SSO summary fields still gave no
  feedback. The badge behavior is extracted into a shared `CopyIconButton` and all
  icon-button copy affordances render it.

### Changed

- **The compare gesture hint is visible in the dock itself.** Once a second item is
  open, the dock shows an inline "Ctrl/Cmd-click a chip to compare" hint (hidden while
  a side-by-side compare is active) — the hover tooltip alone required knowing to hover.
- **Dependency refresh.** tauri 2.11.3 → 2.11.5, leptos 0.8.19 → 0.8.20,
  anyhow 1.0.103, time 0.3.53 (Dependabot), and the `taiki-e/install-action` CI pin
  → 2.82.7. Two fresh `quick-xml` advisories (RUSTSEC-2026-0194/0195 — DoS-class
  parser issues, transitive via `plist` → `tauri`, which parses only the app's own
  bundle metadata) are triaged as documented ignores until `plist` ships on
  quick-xml 0.41+.

## [0.12.0] - 2026-07-01

### Fixed

- **Failed loads offer an in-context Retry.** The tenant-wide audit dashboards
  (Credential expiry, Consent grants, Application permissions) and the Managed
  Identities list now show a Retry button with a "Failed to load: …" message instead
  of a dead-end error, matching the App Registrations and Enterprise Applications
  lists — so a transient 429/network failure recovers in place.
- **An invalid SAML certificate subject fails before the app is created.** SAML setup
  now rejects a certificate subject that doesn't start with `CN=` up front (a typed
  validation error, like the reply-URL check) instead of failing at the
  certificate step — after the app and service principal already exist — and leaving a
  half-configured app. The rotate-certificate command gets the same friendly rejection.

### Security

- **Rotated client secrets are zeroized in backend memory.** The rotate-into-Key-Vault
  flow holds the freshly minted secret in exactly one buffer and wipes it on drop
  (`SecretSetRequest` now zeroizes its value — covering manual `kv_set_secret` writes
  too — and redacts it from `Debug` output), matching the existing access-token and
  generated-certificate handling.

### Changed

- **Copy buttons confirm the copy.** `CopyableId` (the copy-to-clipboard GUID fields in
  detail panes and table cells) shows a brief "Copied" badge after a click, instead of
  no feedback at all.
- **The open-items compare gesture is discoverable.** Dock chips' tooltip now reads
  "click to focus · Ctrl/Cmd-click to compare side-by-side" — the 2-up compare was
  previously invisible unless you already knew the shortcut.
- **Admin-consent grants resolve resource service principals in one batched read.**
  "Grant admin consent" (single, bulk, and DR-restore paths) pre-resolves every declared
  resource's service principal via Graph `$batch` and the shared Permissions cache instead
  of one sequential lookup per resource — on a cold cache an app with N resources costs
  1 POST, not N GETs. A batch failure degrades to the existing per-resource lookups;
  per-resource failure reporting is unchanged.

## [0.11.0] - 2026-06-30

### Added

- **Grant a custom app registration's app role to a managed identity (or another app) from
  the UI.** The "Grant access" wizard's resource picker now lists the tenant's own app
  registrations that expose application app roles — a new **"Tenant app registrations"**
  group below the bundled Microsoft APIs — so a managed identity (or an app registration)
  can be granted a custom API's app role without hand-crafting the assignment. The backend
  grant path already accepted any resource; this surfaces those resources in the picker
  (`list_app_role_resources`, owner-scoped to the tenant).

### Fixed

- **The in-app update changelog renders as formatted text, not raw Markdown.** The
  "Update available" splash showed the release notes as a raw `**…**` / `- ` / `###`
  Markdown dump in a monospace block. A small renderer (`components/changelog_notes.rs`)
  now formats the subset our changelog uses — headings, bullet lists (nested +
  wrapped), bold, inline code, and links — so the notes read like the GitHub release.

### Changed

- **Trimmed redundant CI work.** CodeQL no longer runs on pull requests — it's not
  a required check and the current extractor doesn't expand Rust macros, so PR-level
  alerts add little; it still runs on `main` (Security tab) and the weekly re-scan.
  The weekly `ci.yml` cron now runs only the dependency-advisory jobs (`cargo-audit`
  / `cargo-deny`) instead of re-running the full 3-OS build matrix. Every job now has
  a `timeout-minutes` backstop so a hung runner is killed in minutes, not hours.
- **Docs-only changes skip the build matrix.** A new change-detection job classifies
  each PR/push; when only docs change (Markdown, `docs/`, `LICENSE`, `.claude/`), the
  compile/test/lint jobs skip their work while still reporting their required status
  checks as green — so a docs-only PR goes green in seconds instead of ~12 minutes
  without being blocked by pending required checks. CodeQL also skips docs-only pushes.

## [0.10.0] - 2026-06-29

### Added

- **Open-items workspace — full-width lists + a shared "working set" dock.** The
  App Registrations, Enterprise Applications, and Managed Identities lists are now
  full-width; selecting a row opens it in a workspace overlay on top, rather than
  a cramped side detail pane. A persistent **Open** dock (a strip of chips,
  shared across all three entity types) holds everything you've opened — your
  working set — so you can switch between items without re-finding them, and pin
  **two side-by-side to compare**. Chip click shows an item full-width;
  `Cmd`/`Ctrl`-click (or a second pin) opens it alongside the first; `Esc` — or
  navigating to another view from the nav rail — collapses the workspace back to
  the list; the chip × closes an item and a **Close all** button clears the whole
  working set. The dock persists across navigation (Home, Security, …) and resets
  on tenant switch.

### Fixed

- **Detail-pane tabs are reachable on narrow panes.** Thaw's `<TabList>` (the App
  Registration / Enterprise / Managed Identity detail tabs) doesn't scroll, so
  when the tab row was wider than the pane — a narrow screen, or the many-tab App
  Registration detail — the overflowing tabs were clipped by the pane's
  `overflow-x: hidden` and couldn't be reached. The tab strip now scrolls
  horizontally (`.thaw-tab-list { overflow-x: auto }`).

### Changed

- **Mobile-friendly responsive layout.** The web UI (and the GitHub Pages demo)
  now reads well on a phone: fixed a page-level horizontal-scroll bug where a
  wide child (data table, long id) could stretch the main column past the
  viewport (`.shell__main` now pins `min-width: 0`); the list/detail split stacks
  with the detail given the larger share instead of an even 50/50; dashboard
  cards drop to a single overflow-proof column; and a new ≤560px breakpoint
  narrows the icon rail, tightens padding, near-full-bleeds dialogs, and wraps or
  stacks dense headers, action clusters, and editor grids.

- **CI: bump SHA-pinned GitHub Actions to their latest releases.**
  `Swatinem/rust-cache` (`v2` → `v2.9.1`) and `taiki-e/install-action`
  (`v2.82.3` → `v2.82.5`) across `ci.yml`, `codeql.yml`, `pages.yml`, and
  `release.yml`. All other actions were already at their latest release SHA;
  `dtolnay/rust-toolchain` stays pinned to the MSRV `1.96.0` and
  `github/codeql-action` to `codeql-bundle-v2.25.6` (both intentional pins).

## [0.9.0] - 2026-06-26

### Added

- **macOS and Linux release packages.** The release workflow now builds for all
  three platforms on their native runners: Windows (MSI + NSIS, unchanged), macOS
  (`.dmg` + auto-update payload, Apple Silicon), and Linux (`.AppImage` + `.deb`).
  The in-app auto-updater covers all three — `latest.json` now carries
  `darwin-aarch64` and `linux-x86_64` alongside `windows-x86_64`. macOS builds are
  unsigned for now (first launch needs a one-time Gatekeeper bypass — see the
  README); Apple notarization can be layered on later like the optional Windows
  Authenticode signing. New `just build-macos-updater` / `build-linux-updater`
  recipes; `bundle.targets` is now `"all"`. The GitHub release page groups the
  downloads by OS (Windows / macOS / Linux) in its notes.

- **Live web demo on GitHub Pages.** The full Leptos/Thaw UI now runs in a plain
  browser with curated sample data and no Tauri backend — try it at
  <https://tiredithumans.github.io/azapptoolkit/> with no install and no sign-in.
  The demo reuses the GUI test harness's mock IPC bridge (extracted to a shared
  `ipc_mock` module): a new `demo` Cargo feature pre-loads it with fixtures and
  signs into a demo tenant, and a banner marks it as read-only (mutations and
  exports are disabled). Built with `just web-build-pages` and published by a new
  `pages.yml` workflow; the desktop build is unaffected (the feature is off by
  default, so the mock and fixtures never enter the shipped bundle).

## [0.8.0] - 2026-06-26

### Added

- **Force re-authenticate in place when a session expires — no manual sign-out.**
  When the stored refresh token is expired or revoked, the **Refresh Token**
  button now falls back from the silent re-mint to one interactive browser
  round trip (pinned to the current account), restoring the session without
  signing out — so the cached lists and audit run survive. Additionally, any
  command that fails because the session is dead now surfaces an error toast
  with a **Re-authenticate** action, so recovery appears exactly when it's
  needed instead of leaving the user stuck. New `reauthenticate` command.

- **Interactive auto-update with a changelog splash.** When a new release is
  available, the app now shows a toast on launch ("Update available: vX.Y.Z —
  View changelog") that opens a splash listing the version's release notes with
  an **Update & restart** button (which downloads, installs, and relaunches,
  showing download progress) and a **Later** dismiss. A manual **Check for
  updates** button sits by the version in the nav. The release manifest
  (`latest.json`) now carries the `CHANGELOG.md` section as its `notes`, so the
  splash shows real changelog text.

### Changed

- **Updates are no longer installed silently in the background.** The former
  silent download-and-install on launch is replaced by the interactive prompt
  above, so the user sees what's changing and chooses when to restart.

## [0.7.0] - 2026-06-24

### Changed

- **Security Audit revamp — the audit is now the hero of the Security surface.**
  The Security sub-tabs are reframed: the audit is the default, full-width view,
  and the inventory lenses (Credential expiry, Delegated grants) move behind a
  subordinate "Detailed inventories" selector (all deep-links and keep-alive
  panes are preserved). The **App permissions** lens is removed — its data was
  redundant with the audit's findings. The audit's flat 14-item facet tab bar is
  replaced by **two combinable filters** — a primary risk-severity selector (All
  / Critical / High / Medium / Low) and a collapsible finding-type chip drawer
  (Expired, Unused, Over-privileged, High-risk delegated, Org-wide mailbox,
  Scoped mailbox, Org-wide SharePoint, Scoped sites, Unowned) — that
  **intersect** (e.g. "Critical apps with an expired credential"). The
  **Expired** finding matches only already-expired credentials (proactive
  "expiring soon" rotation lead-time stays in the Credential-expiry lens). The
  posture scorecard is regrouped into Risk and Findings rows; each card seeds its
  own dimension and composes with the other.
- **The Home dashboard's Security Posture card surfaces more drill-ins** —
  Critical / High / Medium / Expired / Over-privileged / Org-wide mailbox /
  Org-wide SharePoint / Unowned / Unused — each jumping to the audit pre-filtered
  to that subset.

### Added

- **Multi-select + context-aware inline bulk actions on the Security Audit table
  and App Registrations list.** Check rows to reveal an inline bar; on the audit
  it offers the remediation matching the active finding filter — **Remove expired
  credentials** (Expired), **Remove redundant permissions** (Over-privileged),
  **Scope mailbox access** to chosen groups (Org-wide mailbox), **Scope SharePoint
  access** to chosen sites (Org-wide SharePoint) — plus Delete, with live
  progress, cancel, typed confirmation for destructive actions, and a per-item
  result summary. The App Registrations list / Bulk Actions page keep the
  management set (Grant consent / Remove expired / Delete). The new bulk
  remediations (`bulk_remove_redundant_permissions`, `bulk_scope_mailbox_access`,
  `bulk_scope_sharepoint_access`) reuse the single-app remediation cores, so each
  app's live re-resolution, grant-before-strip safety, and cache invalidation
  match the one-click fixes. The audit table keeps its own selection set, separate
  from the App Registrations list's. The Enterprise Applications list is
  intentionally excluded (its rows are service principals, which the
  app-registration bulk commands can't target).

## [0.6.0] - 2026-06-24

### Added

- **Home dashboard metrics drill into a pre-filtered list.** Clicking a count on
  the Overview cards now jumps to the matching list/lens filtered to that subset,
  instead of just landing on an unfiltered list: Enterprise Applications'
  Disabled / Foreign and Managed Identities' System / User → their list's facet;
  Credential Health's Expired / ≤7d / ≤30d → the per-credential Credential-expiry
  lens (so the drilled count matches the clicked metric); Security Posture's
  Critical / High / Ownership / Unused → the audit view's matching facet. Zero
  counts stay muted and non-clickable (nothing to drill into). The facet of each
  drilled surface (enterprise / managed-identity / audit / credential-expiry) is
  lifted to the `Session` alongside the searches and reset on tenant switch so a
  metric click can seed it; drilling into the Enterprise list also auto-expands
  its filter drawer so the active chip is visible.
- **`just clean` reclaims disk.** A new task-runner recipe that runs `cargo
  clean` against both independent build trees — the root workspace and the
  web-rs frontend (excluded from the workspace, so the root clean never reaches
  it, and its `target/` is by far the larger). Frees disk when the cargo build
  caches grow unbounded.
- **Typed "DELETE" confirmation for the dangerous SP deletes.** Deleting a
  foreign-tenant or Microsoft first-party enterprise application's service
  principal (which can break tenant-wide sign-in) now requires typing `DELETE` to
  confirm, matching the bulk-delete guard; an ordinary in-tenant SP keeps the
  one-click confirm.
- **Detail panes now offer Retry when a load fails.** A transient 429 / network
  blip on an App Registration, Enterprise App, or Managed Identity detail load
  used to leave a static `error [code]: message` dead-end; it now shows the
  message with a Retry button (and a muted code), matching the list views. Shared
  `DetailLoadError` component across the three panes.
- **Empty tenants get an onboarding call-to-action.** An App Registrations /
  Enterprise Applications list with no items shows a "Create your first…" empty
  state with a primary create button, instead of the "adjust your search or
  filters" copy meant for a filtered-empty list.

### Changed

- **Permissions tab — clearer primary action.** "Grant access" (the wizard) is
  now the sole primary button; "Grant admin consent" (in-place consent of
  already-declared permissions) is demoted to a secondary action so the two are no
  longer competing primaries.
- **Grant-access wizard explains a disabled "Next".** Step 1 now shows a "Select
  at least one permission to continue." hint while the cart is empty, instead of a
  mutely-disabled button.
- **Consistent loading skeletons.** The Managed Identity detail pane's permission
  and Azure-role tables now show a skeleton placeholder while loading, matching
  the other detail surfaces (was a bare spinner).
- **Bulk delete / grant-consent now run with bounded concurrency and adaptive
  throttling.** Both ran fully serially with a fixed 50 ms pause between items —
  slow on the healthy path yet with no back-off under throttling. They now fan out
  through the shared bounded-concurrency dispatcher with an adaptive
  `ConcurrencyThrottle` (the in-flight cap halves on a Graph 429 and recovers when
  quiet), and report the live cap to the progress UI. The expired-credential sweep
  gains the same adaptive back-off (it had a fixed cap) and now projects only the
  fields it reads (`passwordCredentials`) instead of full app payloads.
- **Removed a dead, uncached `list_applications` command** that bypassed the
  cached app-list path and had no callers.
- **Workspace upgraded to Rust edition 2024** (from 2021), across both the native
  workspace and the excluded `web-rs` (WASM) frontend. `web-rs`'s declared MSRV
  rises 1.82 → 1.96 to clear the edition's 1.85 floor and match the root workspace;
  the pinned toolchain (`rust-toolchain.toml`, 1.96.0) and CI are unchanged. No
  source edits were required — `cargo fix --edition` surfaced only benign
  `tail_expr_drop_order` drop-order notes (HTTP-client and `JsValue` teardown),
  which are allow-by-default on edition 2024.
- **Tenant-wide reads are now cached, cutting redundant Graph traffic.** The
  service-principal sign-in activity report (a slow beta endpoint that paginates
  the whole tenant) is cached per tenant, so clicking through several apps' Activity
  tabs — and the security audit — share one fetch instead of re-scanning it each
  time. The Home dashboard's credential-expiry list is likewise read-through cached
  (it was re-scanning every app registration on each cold load, duplicating the
  apps list's own scan); it's busted whenever a credential or app changes, so a
  just-rotated credential is never shown as still-expiring. The discovered Graph
  activity workspace and ARM role-definition names are documented as read-only
  until their cache TTL / sign-out (cleared via "Clear all" in Cache diagnostics if
  ever re-pointed mid-session).

### Fixed

- **Stale service-principal cache no longer skews audit posture or detail panes.**
  Mutating an enterprise application's service principal — toggling sign-in /
  assignment-required, hiding it, changing SSO mode, or deleting it — now busts
  the per-app SP cache, so a re-run security audit reads the live `accountEnabled`
  (correct Rule-4 risk score) and the app-registration detail pane never shows a
  just-deleted paired SP. Previously these stayed cached for up to 60 minutes.
- **First permission grant on an unpaired app now appears immediately.** When a
  grant (single, admin-consent, or bulk) creates an app registration's first
  enterprise service principal, the App Registrations / Enterprise Apps lists and
  global search now refresh right away instead of waiting out the 60-minute cache
  TTL or a manual refresh.

## [0.5.0] - 2026-06-23

### Changed

- **The "Grant scoped access" wizard is now the unified "Grant access" flow,
  replacing the separate "Add permission" picker.** Each Permissions surface (app
  registration, enterprise app, managed identity) now has a single **Grant
  access** button. Step 1 is the full live permission catalog (every resource,
  Application + Delegated, searchable) as a **multi-select cart** — pick as many
  permissions as you want, then grant them in one pass. Step 2 auto-offers scoped
  targets (mailbox group or SharePoint sites) **only when the whole selection is
  one scopable mechanism** (all mailbox, or all SharePoint); mixed, non-scopable,
  or delegated selections grant org-wide, preserving "one mechanism per run". The
  per-row **Scope…** action still opens the wizard pre-seeded to that permission.
  The old inline single-grant picker (one permission per click, always org-wide)
  is retired; the catalog `PermissionPicker` is now a reusable multi-select
  component the wizard embeds.

## [0.4.0] - 2026-06-22

### Added

- **"Grant scoped access" wizard — one guided flow for confining permissions,
  across mechanisms.** A single always-available **Grant scoped access…** button
  on the Permissions tab (app registrations) and the Enterprise App / Managed
  Identity detail panes opens a three-step wizard — pick the permissions → choose
  the targets → review & grant — replacing the old "grant org-wide, then hunt for
  the scoping menu, then strip the grant" dance *and* the per-row inline scope
  nudge (now retired, along with `scope_panel.rs`). The wizard **dispatches on the
  scoping mechanism**: **Exchange RBAC** (Mail/Calendars/Contacts) confines to a
  mailbox group — declare-only, so no org-wide Entra grant is ever created (the
  `declare_app_permission` command) — and **SharePoint** (`Sites.*`) confines to
  specific sites via `Sites.Selected` (`convert_site_access_to_selected`). Picking
  a permission locks the run to its mechanism (scope the other separately); a held
  row's **Scope…** opens the wizard pre-selected to that permission. A de-emphasized
  **org-wide (no scoping)** option remains for the rare permission that needs
  tenant-wide reach. Built on the `ScopeKind` registry, so new mechanisms
  (Administrative Units, Azure RBAC, Teams resource-specific consent) drop in as a
  registry entry + a target panel + an apply arm. Managed-group mailboxes and the
  site list are managed inline via shared `ManagedScopeGroupPanel` /
  `SiteSelectionPanel` components.

### Internal

- **Scope-mechanism registry in `azapptoolkit-core::scoping`.** A single
  `scope_kind(value)` classifier + the `ScopeKind` enum (Exchange / SharePoint) +
  per-mechanism metadata (`target_noun` / `capability_key` / `admin_applicable`) —
  one source of truth for which mechanism, if any, scopes a Graph permission, and
  the dispatch key the scope wizard is built on. `admin_applicable()` is the seam
  for future owner-consented mechanisms (e.g. Teams resource-specific consent) that
  render guidance instead of an apply button.
- **GUI test coverage for the scope wizard.** Browser GUI tests (`just web-itest`)
  drive `ScopeWizard` end-to-end per mechanism: the Exchange scoped path declares
  each permission and assigns scoped roles with `removeUnscopedEntraGrants = true`
  (no org-wide grant); the org-wide option grants via `grant_single_permission`;
  SharePoint routes to `convert_site_access_to_selected` (`removeOrgwide = true`)
  and never touches Exchange RBAC; and a pre-seeded open jumps to the target step.
  The managed-identity picker test verifies the org-wide-direct grant after the
  inline scope nudge's retirement. Adds a `set_textarea_value` harness helper plus
  typed catalog / exchange / sharepoint fixture builders behind `test-support`.

## [0.3.2] - 2026-06-22

### Internal

- **Dependency refresh.** Both lockfiles — the root workspace and the
  workspace-excluded `web-rs` front-end — were updated to their latest
  semver-compatible versions: notably `rustls` 0.23.41, `quinn` 0.11.11, and
  `time` 0.3.51 (+ `time-macros`), alongside routine bumps to `bytes`,
  `camino`, `cc`, `getrandom`, `log`, `quote`, `web_atoms`, and the
  `wasm_split_*` helpers. Stale build-time transitives (`wit-bindgen` /
  `wasm-encoder` / `wasmparser` tooling) were pruned from the graph. No held
  major versions were touched (`rand` / `sha2` / `rsa` unchanged), and the
  RustSec advisory scan plus the cargo-deny license/source/bans gates remain
  green on both trees.

## [0.3.1] - 2026-06-22

### Added

- **Cancel button for Bulk Actions.** A long-running bulk grant / delete /
  remove-expired / create run can now be stopped from the UI — the backend bulk
  loops already polled the shared cancel flag, but the page had no control wired
  to it. A new `cancel_bulk` command drives it; the in-flight run still returns
  its partial result, tagged cancelled.
- **Retry on a failed list load.** When the App Registrations or Enterprise Apps
  list fails to load (e.g. a transient 429 or network blip), the error now offers
  an in-context **Retry** instead of a dead-end message — matching the dashboard
  cards.
- **Rate-limit back-off notice on the security audit.** When Microsoft Graph
  throttles a scan and the adaptive concurrency cap drops below its peak, the
  audit view now explains the slow-down (the same notice the DR backup shows), so
  a throttled scan reads as expected rather than stalled.

### Changed

- **Confirmation before revoking an enterprise application's permission.**
  Revoking a held app-role grant on an Enterprise App now prompts for
  confirmation, matching the Managed Identity pane — the identical action was
  previously a single un-guarded click that could break a live integration.
- **The App Registrations "Permissions" tab is now labelled "API permissions"**
  (the Entra portal's term) to distinguish the permissions an app *requests*
  (`requiredResourceAccess`) from the *held* grants shown on the Enterprise App /
  Managed Identity "Permissions" tabs. The routing value is unchanged, so
  deep-links still work.
- **Faster mailbox reverse-lookup.** The "who can reach this mailbox" probe now
  resolves every candidate's service-principal appId in one batched Graph read
  (`$batch`, ~20×) up front instead of one round trip per candidate.
- **Faster security audit on cold caches.** Each app's distinct resource indexes
  are now resolved concurrently rather than one serial round trip at a time.
- **Faster DR restore.** Principal resolution (users/groups by UPN / display
  name) is memoized for the run, so a principal reused across owners, assignees,
  and group memberships is searched once instead of per occurrence.

### Fixed

- **Actionable error guidance no longer collapses onto one line.** The recovery
  hints the backend attaches after a blank line (e.g. "You may need the Exchange
  Administrator role" on a 403) are now rendered with their line breaks intact
  instead of being flattened away.
- **The first-run configuration screen now shows a recovery hint** for each
  failure (invalid client/tenant ID, or a settings.json write error) instead of a
  raw `error [code]: message` dump — matching the sign-in screen.

### Internal

- **The WASM frontend (`web-rs`) is now linted under clippy** (`-D warnings`) in
  `just verify` and CI. Previously the largest, IPC-privileged tier escaped the
  lint gate entirely because it is excluded from the root workspace; the existing
  warnings are fixed.
- **The release workflow re-runs the RustSec advisory scan before building the
  installers**, so an advisory filed after the last main-branch CI run can't ride
  into a shipped build unscanned.
- **Internal cleanup (no behaviour change):** the 1,700-line
  `commands/applications.rs` was split into a `commands/applications/` module
  directory; the 13-site detail-pane cache-invalidation pairing was factored into
  one `invalidate_app_detail_state` helper; and the duplicated (and already
  drifting) premium-feature error mapper shared by the Activity and Conditional
  Access tabs was unified into one `graph_err::premium_feature_err`.
- **DR backup/restore now have automated coverage of their hardest invariants.**
  A mock-Graph (wiremock) test proves the backup degrades to per-object reads when
  a whole `$batch` fails and skips an individual failed object rather than aborting
  the run; a unit test pins `plan_restore`'s action counts and cloud/tenant-change
  flags. (The backup chunk helper now takes a progress callback instead of the
  Tauri `AppHandle`, so the test needs no webview/mock runtime; `wiremock` was
  added as a dev-dependency.)

## [0.3.0] - 2026-06-21

### Changed

- **Disaster-recovery backup is now batched and throttle-aware — far faster and
  no longer rate-limit-bound on large tenants.** The per-app/-SP/-MI reads that
  the backup fanned out as individual Graph calls (the bulk of a backup) now go
  out via Graph JSON batching (`$batch`, 20 sub-requests per round trip),
  collapsing the round-trip count roughly 20× and cutting wall-clock sharply. All
  three passes (app registrations, enterprise apps, managed identities) are
  batched, including the enterprise group-membership read (the advanced
  `memberOf` query now rides a per-sub-request `ConsistencyLevel` header in the
  batch). The managed-identity pass resolves each distinct resource service
  principal once via a batched prewarm. A whole-batch failure degrades to
  per-object reads for that chunk, and per-object failures still skip just that
  one object — a cancelled run remains an error, never a partial manifest.
- **Adaptive concurrency for the backup.** The backup now reuses the security
  audit's throttle tracker (promoted to a shared `ConcurrencyThrottle`): every
  Graph 429 halves the in-flight chunk cap, which then recovers after a quiet
  window — so a throttling tenant backs off gracefully instead of hammering at a
  fixed concurrency.
- **Legible DR progress.** The Disaster Recovery screen now shows a progress bar
  and the live concurrency for both backup and restore, plus a back-off notice
  while Graph is rate-limiting the backup (the adaptive cap has dropped below its
  peak) so a slow run reads as expected rather than stuck. `BulkProgress` gained
  an optional `in_flight_cap` field (additive; absent for the fixed-cap bulk
  flows).

## [0.2.0] - 2026-06-20

### Added

- **Exposed app roles management on enterprise applications.** A new **App roles**
  tab on the enterprise-app detail pane adds, edits, enables/disables, and deletes
  the app-role definitions an application publishes (the Entra "App roles" blade) —
  previously these were read-only in the Permissions tab. Edits target the role's
  canonical home: the **linked app registration** when one exists (Entra mirrors
  them onto the service principal), otherwise the **service principal** directly
  (gallery / foreign-tenant apps). The whole `appRoles` collection is re-read live
  and full-replaced on each change, preserving built-in roles (e.g. the SAML
  `msiam_access` default, surfaced read-only) byte-for-byte; deleting an enabled
  role disables it first (Graph rejects removing an enabled role). New backend
  commands `list_enterprise_app_roles`, `upsert_enterprise_app_role`, and
  `delete_enterprise_app_role` with typed frontend stubs.

## [0.1.4] - 2026-06-20

### Added

- **Enterprise Application management parity.** The enterprise-app detail pane
  gained the core lifecycle controls it was missing relative to the Microsoft
  Entra admin center:
  - **SSO tab** — a single sign-on **method selector** (SAML / OIDC / Disabled)
    that sets `preferredSingleSignOnMode`, so you can now enable or switch an
    existing app's SSO mode (previously the tab always showed the SAML editor for
    any non-OIDC value and could not turn SSO on). The SAML editor now accepts
    **multiple identifiers (Entity IDs) and reply URLs (ACS)**, and apps that
    aren't configured for SAML/OIDC (e.g. password-based) get a clear prompt
    instead of a misleading SAML form.
  - **Overview tab** — toggles for **"Enabled for sign-in"** (`accountEnabled`)
    and **"Assignment required"** (`appRoleAssignmentRequired`), plus an editable
    free-text **Notes** field.
  - **Owners tab** — **add/remove owners** (users only — groups can't own a
    service principal), replacing the previous read-only list.
  New backend commands (`set_sso_mode`, `set_enterprise_app_account_enabled`,
  `set_enterprise_app_assignment_required`, `set_enterprise_app_notes`,
  `add_enterprise_app_owner`, `remove_enterprise_app_owner`) with typed frontend
  stubs; `set_saml_urls` now takes lists of identifiers/reply URLs.

## [0.1.3] - 2026-06-19

### Added

- Browser-based **GUI functionality tests** for the front-end. Real Leptos views
  mount in a headless browser with the Tauri IPC bridge mocked (no tenant, no
  backend) and assert on rendered DOM + recorded commands. New `just web-itest`
  recipe (the CI `web` job runs it on headless Chrome); the harness lives behind
  a `test-support` cargo feature, so it never enters the shipped Trunk bundle.
  Coverage spans the App Registrations / Enterprise Applications / Managed
  Identities lists (load, filter, error, empty, and Refresh → invalidate-cache
  command paths), the readiness checklist, the App Registration detail pane, the
  Key Vault secret browser, the streamed-progress event plumbing, and mount-smoke
  for the bulk-actions, disaster-recovery, resource-access, and permission-tester
  views. `just setup` now installs `wasm-pack` and flags the browser + WebDriver
  prerequisite this gate needs.

### Fixed

- Directory and organization reads no longer fail to parse when Microsoft Graph
  returns an explicit `null` (or omits) `id` on a directory object or
  `verifiedDomains` on the organization — both now tolerate null/missing and
  fall back to a default instead of erroring the whole response.

### Changed

- **Front-end list-view maintainability refactor** (internal; no behavior change).
  The App Registration and Enterprise Application lists now share a `ListScaffold`
  component (header + search + filter drawer chrome) and a `use_filtered_list`
  hook (the layered search/facet filter memos, per-facet counts, and export
  snapshot), replacing two near-identical hand-rolled copies. A new `use_command`
  hook collapses the busy/error/tenant/spawn boilerplate that mutation handlers
  repeated. The 1.2k-line `audit_view` and 1k-line `managed_identities` views were
  each split into a module directory, and the IPC bindings' duplicated argument
  structs were centralized in `bindings/common.rs` alongside shared list constants
  in `constants.rs`.

- AAD token-endpoint failures now log the request **correlation ID** (the GUID
  Microsoft support needs to trace an issue) alongside the OAuth/AADSTS code,
  while still keeping the raw `error_description` — which can embed tenant/user
  GUIDs and client IPs — out of logs, the UI, and the audit log.

## [0.1.2] - 2026-06-17

### Added

- The app version is now shown beneath the **Sign Out** button in the
  navigation rail.

### Changed

- Moved **Cache** from the Tools group to the bottom of the navigation rail,
  directly above **Sign Out**.

### Documentation

- Clarified in the README that the in-app auto-updater manages only the NSIS
  (`-setup.exe`) per-user install. MSI/enterprise deployments must disable
  auto-update and update through their management tooling — installing one
  installer type and updating with the other leaves two conflicting Windows
  entries (and a stray Windows Installer "uninstall this product?" prompt).

## [0.1.1] - 2026-06-17

### Changed

- Input fields now show their full placeholder hint — it was being clipped in
  narrow boxes.
- Destructive actions (Delete / Remove / Revoke) are now styled red, and
  removing a mailbox from an Exchange scope group or revoking a managed-identity
  app-role assignment now asks for confirmation first.
- Updated to the `keyring` 4.1 architecture (the OS-native credential store is
  registered directly via `keyring-core`); on Linux, refresh tokens now use the
  Secret Service.

## [0.1.0] - 2026-06-17

Initial public release.
