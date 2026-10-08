# Changelog

Releases 0.26.3 and earlier are in [docs/CHANGELOG-archive.md](docs/CHANGELOG-archive.md).
Headers follow `## [X.Y.Z] - YYYY-MM-DD` exactly (parsed by `release.yml` and `web-rs/build.rs`).

## [Unreleased]

### Added

- **A "SharePoint item access" section on an app's Permissions tab lists the libraries, folders
  and files it was granted, and lets you add or remove one.** It appears for apps holding
  `Lists.`, `ListItems.` or `Files.SelectedOperations.Selected`, next to "SharePoint site access",
  and shows each grant's current role. Remove revokes the app's access to that one item. Add grants
  read or write access to a URL you paste. Rows that are no longer granted or no longer exist can
  be dropped from the list. SharePoint can't list an app's item grants, so the app records each
  grant made through azapptoolkit on the app registration (one tag per grant). Grants made before
  this version or elsewhere appear once you track them by URL. To change a role, remove the access
  and grant it again.

### Changed

- **Creating, deleting or renaming an app registration no longer reloads every app in the tenant.**
  The lists used to throw away their cached copy after each of these and fetch every app
  registration and enterprise application again, which took a long time in a large tenant. They
  now add, remove or rename just that app, so they refresh straight away. This covers the New app
  dialog, bulk create, the SSO wizard, gallery apps, single and bulk delete, and editing an app's
  name or sign-in audience. If a step fails partway, the lists still do a full refresh.
- **An enterprise app's SSO tab shows its claims the way the Entra admin center does.**
  "Attributes & claims" now lists the Required claim (Unique User Identifier, with its Name ID
  format) and then every Additional claim, and says where they come from: Entra's defaults, the
  admin center, or a claims mapping policy. Claims set up in the admin center were missing before,
  and group claims are now listed too. The editor below still saves a claims mapping policy, and it
  now warns that saving replaces the claims set in the admin center, which can then no longer edit
  them. In US Government and China clouds, where Microsoft offers no way to read the admin center's
  claims, the tab says so and claims editing works as before.

- **The Permission Tester names who each SharePoint permission entry is for.** Entries that read
  "User or group (not a Selected app grant)" now show the user, Microsoft 365 group, SharePoint
  group or sharing link, with its email or sign-in name where SharePoint gives one.
- **Granting SharePoint site or item access no longer reloads every app in the tenant.** These
  grants only change the app's permissions, so they now refresh just the app's details and the
  audit instead of re-fetching every app registration and enterprise application.

### Fixed

- **The App Registrations list now updates after you delete or rename an app from its details.**
  A deleted app stayed in the list, and a renamed one kept its old name, until something else
  refreshed it. Enterprise Applications now also refreshes when you delete an app (its enterprise
  application is deleted with it) or create one from the New app dialog, and App Registrations
  refreshes after an app is created with the SSO wizard or from the gallery.

## [0.32.0] - 2026-10-05

### Changed

- **A restore shows the access a backup file grants, and grants it only when you approve.**
  Before you confirm, the restore plan lists, for each app, the admin consent it re-grants
  (every permission named and risk-rated), its federated credentials (issuer and subject),
  owners and group memberships, plus pre-authorized client apps from outside the backup and
  the users and groups assigned to its roles. Managed identities list the app roles they get
  back. An app gets its admin consent, federated credentials, owners and group memberships
  only if you tick it, when it has any of these: consent to any application permission,
  consent to a broad or unidentified delegated one, a federated credential, or a group
  membership. A managed identity gets its app roles back only if you tick it. Anything you
  leave unticked is still created and set up without that access, and the report lists what
  was left out as manual steps. Consent is also skipped, and reported, if the app's API
  permissions in this tenant don't match the backup. Pre-authorized clients and role
  assignments are shown but not gated. Owners, assignees and groups are now matched only when
  exactly one user or group of the recorded type has that exact name.
  If two managed identities here share a name, the restore reports them instead of guessing.
  A backup in which a managed identity's id is empty, not a GUID, or repeated is now refused
  (shown in the plan, before Confirm). An **Approve all listed** button after the list ticks
  every item at once. Nothing starts ticked.
- **Lists, the Security tab and the Resource Access sweeps open faster on a revisit, and the window
  no longer stalls while they load.** A cached list or scan result is now handed back as is
  instead of being rebuilt on every visit, and reading the last security audit or site/Key Vault
  sweep no longer blocks the window. Moving a mailbox scope to its managed group, deleting a
  retired group, and opening an app's mailbox-scope details also wait on fewer back-to-back
  Exchange calls.
- **Tier-0 permissions are Critical on their own.** A permission that is by itself a path to
  Global Administrator or tenant takeover now adds 25 points, so one grant ranks the app
  Critical. `RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All` and
  `Application.ReadWrite.All` used to add 10. The PIM role and group assignment permissions,
  `Policy.ReadWrite.PermissionGrant`, `Policy.ReadWrite.ConditionalAccess`,
  `Domain.ReadWrite.All` and `UserAuthenticationMethod.ReadWrite.All` used to add nothing. The
  permission badge reads "Tier-0". Audit scores shift with this release, so re-run the audit
  before comparing with an earlier one.
  `Directory.ReadWrite.All` stays high-risk. Several permissions that used to score nothing are
  now high-risk, including `Exchange.ManageAsApp`, `Organization.ReadWrite.All`,
  `DelegatedPermissionGrant.ReadWrite.All` and the remaining `Policy.ReadWrite.*` permissions.
- **Permissions granted to an app but missing from its manifest are scored.** The audit read
  only the permissions an app registration requests. A role granted straight to its service
  principal never shows on the API permissions blade, and it scored nothing. It is now scored,
  and the new "Granted but not declared" finding lists each one. Those grants don't get a
  one-click Fix: review each and revoke it or add it to the manifest.
- **Enterprise apps and managed identities that hold only Exchange Online or SharePoint Online
  roles are audited.** Before, only Microsoft Graph roles and EWS full mailbox access got a
  principal into the audit. Holding only `Exchange.ManageAsApp` or SharePoint Online
  `Sites.FullControl.All` was skipped.
- **The app's own one-year certificate no longer counts as long-lived.** A credential is
  long-lived once it runs more than 366 whole days. The toolkit's default certificate (one year,
  backdated an hour) and a 12-month secret that spans 29 February no longer add 3 points. A
  secret with no end date now does.
- **Never-expiring credentials no longer read as "no credentials".** An app whose only secrets
  never expire showed under the App Registrations list's "None" credential filter. It now shows
  as active.
- **More delegated permissions count as broad.** `User.ReadWrite.All` and the write permissions
  of the `Application`, `Policy`, `UserAuthenticationMethod`, `GroupMember`,
  `DelegatedPermissionGrant`, `Calendars` and `Chat` families are now treated as broad. That
  shows in three places: the audit's high-risk delegated finding (admin-consented grants only),
  the delegated permission grants list (user-consented grants too), and the permission picker's
  "Broad scope" badge.
  `Files.SelectedOperations.Selected` and the other Selected permissions are no longer flagged.
- **An audit that couldn't read the tenant's delegated permission grants says so.** Before,
  admin-consent findings disappeared without a warning and the result was kept as a complete
  scan. The audit now shows the incomplete-scan notice and doesn't keep the result. It does the
  same when SharePoint Online's grants can't be read.
- **Mailbox scope verdicts are more accurate, so some apps' scores go up and some go down.** On
  the Security tab, the Permissions tab's Scope column and the Permission tester:
  - A legacy Application Access Policy now scopes only the permissions it can govern.
    `MailboxItem.ReadWrite.All` and the other RBAC-only permissions on a policy-confined app read
    organization-wide instead of "Scoped (legacy)".
  - An Exchange assignment with a scope type the app doesn't recognise now counts as
    organization-wide, and the type is logged.
  - Role and permission names now match in any case, and an `Application Mail Full Access` or
    `Application Exchange Full Access` assignment counts even when Exchange omits the permissions
    it bundles. An organization-wide one of these now counts against the app (score goes up). A
    scoped one that used to be missed, and so read organization-wide, now counts as scoped
    (score goes down). Scoping a permission that an organization-wide composite role already
    covers now warns that the scope is not effective.

### Fixed

- **Sign-in is sturdier.** A momentary credential-store error while renewing a token no longer
  sends you back to sign in. A malformed token lifetime from the sign-in service no longer crashes
  the app. If your username changes in Entra ID, the app picks up the new one the next time it
  starts. If a saved session can't be restored and you sign in as a different account, the
  earlier account's saved sign-in is now removed instead of left on this computer. A saved
  session that turns out to belong to a different account is discarded, and the app shows the
  sign-in screen.
- **SAML sign-out URLs are now validated like reply URLs, and untrusted files are checked more
  strictly.** The SAML URL editor and the New SSO application wizard checked their reply URLs but
  saved the sign-out URL as typed; a plaintext or custom-scheme one is now refused before anything
  is written. A restore now drops a custom-scheme sign-out URL from a backup (with a warning),
  blocks a backup whose app ids are missing, malformed or repeated (shown in the plan, before
  Confirm), and refuses a backup file over 256 MiB. A federated credential whose issuer hides its
  real host behind a backslash, a space or other stray characters is refused. A bulk-create or
  backup file saved as UTF-16 (Excel's "Unicode Text") is now named as such, rather than failing
  with a generic "not valid UTF-8" read error.
- **A change made during a scan is no longer undone by the scan.** You might fix a finding, grant
  or remove access, or change a mailbox scope while the app is still loading something. That
  could be a security audit, a site or Key Vault sweep, the SSO certificate board, an app's
  details, the Grant-access list of tenant apps, or a mailbox-scope check. The load used to save
  its older result over your change, and the app showed that older result for up to an hour. Now
  the older result is discarded, and the next view fetches fresh data. An audit that started
  before an org-wide mail grant was removed no longer leaves that app's mailbox verdict cached
  for the next audit. Signing out also stops any running audit, sweep, mailbox probe or backup.
- **An interrupted sign-in save no longer leaves a broken saved sign-in.** If the app closed, or a
  second copy of it was running, while it saved your sign-in, the next launch could load a
  corrupted session that then failed. That is now detected, and you're asked to sign in once.
  Saved sign-ins use a new format, so going back to an older version asks you to sign in once.
- **Signing out or switching tenants mid-action no longer crashes the window.** A bulk action or
  a save that finished after you signed out or switched tenants could crash the window, and its
  notifications carried over into the next sign-in. It now reports nothing. Leaving a view while
  its save or bulk action is still running no longer crashes the window either: its notifications
  still appear, a failure is reported instead of lost, and apps a bulk delete removed leave the
  selection.
- **Exchange mailbox scoping no longer widens access or reports a partial result as done.** "Move
  to managed group" and the legacy-policy migration now refuse to point a scope at the
  toolkit-managed group when that group already holds mailboxes the source group doesn't. The
  preview now says the move would be refused and names those mailboxes, instead of offering "Move
  now". Before, a group left over from an earlier attempt was reused as
  it was, so the app could end up reaching both the old and the new mailboxes. Scoped access now
  warns when an org-wide Exchange role assignment for the same role still gives the app every
  mailbox. Groups with more than 1000 members are now read in full instead of being cut off at
  1000. "Remove all…" now reports assignments it couldn't remove instead of only counting the ones
  it did, and fails when none came off. A move to the managed group can be stopped while it copies
  members, and a stopped move leaves the scope where it was. Stopping a migration while it copies
  members now leaves that app on its legacy policy, unchanged, and reports the run as incomplete. A migration re-run for a policy
  stored with an upper-case app ID no longer reports the app as "partial" every time.

## [0.31.0] - 2026-10-03

### Added

- **Bulk create can load a CSV or JSON inventory, owners and permissions included.** Bulk
  Actions → Create apps has a **Load from file…** button that fills the form from a CSV
  (`DisplayName`, `SignInAudience`, `Description`, `Owners`, `Permissions`) or a JSON array,
  so a legacy inventory can seed a migration without retyping it. Owners are user principal
  names; permissions are `Kind:Resource/Value` entries such as
  `Application:Microsoft Graph/User.Read.All`. Every owner and permission is checked against
  the tenant before its app is created, and **Validate** runs the same check. A row naming an
  unknown user or permission is rejected and nothing is created for it. Permissions are
  declared on the new app, not consented: grant consent from App Registrations afterwards. A
  created app whose owner could not be added is now listed as a problem rather than counted
  as a clean success. The column format is in `docs/DEVELOPMENT.md`.
- **The tenant's own consent settings are now visible above the delegated grants.** Two
  mount-time reads on the existing `Policy.Read.All` token (`authorizationPolicy` +
  `adminConsentRequestPolicy` — no new scope, no new consent) answer whether users in this
  tenant can grant delegated permissions to themselves, whether risky apps can obtain user
  consent, and whether the admin consent workflow is on. When self-consent is open, the
  Consent-grants view shows a warning in its header naming the app-consent policies assigned
  to the default user role — those policies make every "User" grant in the list potentially
  self-granted — and the Home Security Posture card says the same in shorter form. A tenant
  with self-consent confirmed off gets a quiet one-liner instead, naming the admin consent
  workflow state. A failed read — or a tenant that never enabled the workflow — shows nothing
  at all: unknown is never rendered as "consent is restricted" or as an all-clear. Pending
  admin-consent requests are deliberately deferred (their read needs a dedicated
  consent-requests scope). **No ranking change** — the audit is untouched.
- **The SSO tab now shows SAML signed-request enforcement.** The enterprise-app SSO tab's SAML
  section reads Microsoft's v1.0 `requestSignatureVerification` property on the paired application
  (one more field on the SSO read that already happens — no new scope, no new consent) and shows
  its state: **"Required"**, **"Required, but allows rsaSha1"**, or **"Not verified"** — the last
  with a warning that unsigned SAML authentication requests are accepted, and a warning naming
  `rsaSha1` when verification is on but the weak algorithm is still allowed (a SHA-1-signed
  request is spoofable anyway). A missing property means **unknown**: the tab shows nothing at all
  rather than implying unsigned requests are fine. Read-only by design — the v1.0
  `application-update` property list does not document `requestSignatureVerification` as
  patchable, so the tab shows the state instead of offering an unverifiable toggle; change it in
  the Entra admin center. **No ranking change** — the audit is untouched.
- **Tenant app-management policies are now visible, and explain policy-driven secret adds before they fail.**
  Each audit run and each Credentials-tab open read Microsoft's v1.0 app-management policy endpoints
  (tenant default + the overrides assigned to the app) on the on-demand `Policy.Read.All` token —
  no new consent surface, and a tenant without the permission or a failed read simply shows nothing,
  never a degraded run. The add-secret dialog now warns when the chosen lifetime exceeds the
  effective cap ("… the add would be rejected. Pick a shorter expiry, or a certificate instead.") —
  warn only, never clamp or block; valid secrets provably over the cap carry an **"Over cap"** badge
  beside their expiry status (expired ones keep their single, louder signal). The Home Security
  Posture card gains a one-line "Tenant policy caps secret lifetimes at N days." — shown only when
  a cap is actually knowable, never "no cap enforced" (unknown and known-capless both stay silent).
  The audit's lifetime advisory compares against the same effective cap instead of the fixed
  365-day floor where a policy exists: ≥2 assigned overrides mean no verdict, an assigned override
  *replaces* the tenant default, a grandfathered app gets no cap. One shared predicate
  (`credential_over_cap`) drives the audit advice and the tab markers, so they can never name
  different secrets for one app. **No ranking change** — the 365-day legacy rule is untouched;
  this only adds advice.
- **The security audit and Credentials tab now show whether a credential is actually used.** Each
  audit run makes one tenant-wide read of the beta `appCredentialSignInActivities` report (same
  on-demand `AuditLog.Read.All` token as the sign-in reports; **Global cloud only** — a sovereign
  cloud or a failed read simply leaves the feature off, never a degraded run). Credentials the
  report tracked but hadn't seen used for over 90 days raise an advisory **"Unused
  credential(s)"** finding — no score added (ranking is unchanged) and no Fix, removing a
  credential stays admin-judged — naming up to three per app and deep-linking to the Credentials
  tab, which gained a **Last used** column on both tables. Three-state honesty: a dated
  credential shows the day, a tracked-never-used one reads "No use recorded", and anything the
  report couldn't observe reads "—" — absence from the report is never treated as "unused", so
  the rule never mis-flags an unobserved credential. The same read backs the Credentials tab
  live (per-tenant read-through cache), and the `audit_reports` capability description now names
  the Global-cloud-only limit.
- **The security audit now reads Microsoft's own risky-service-principal report.** Each audit run
  makes one tenant-wide Identity Protection call (`atRisk` / `confirmedCompromised` service
  principals, delegated `IdentityRiskyServicePrincipal.Read.All`, consented on demand) and joins it
  onto audit rows by the service principal's object id. A flagged principal scores +20 — High on
  that signal alone, Critical alongside any other finding (**this shifts audit ranking**: a
  compromised-but-otherwise-clean principal now surfaces at the top of the Findings workbench
  instead of reading clean). Risky principals that hold no enumerable grants — a managed identity
  or foreign app whose grant lives on a resource the matrices don't read — are now scored too,
  and a risky *enabled* principal offers a one-click **Disable sign-in** fix (reversible, one Fix
  per row shared with the Unused rule) alongside an Identity Protection deep-read recommendation.
  Tenants that haven't consented the scope or lack a Workload Identities premium license degrade
  to a quiet "report unavailable" (no permanent coverage-gap banner); a genuinely failed read on an
  entitled tenant is reported as a coverage gap, and such a run is never cached or shown as an
  all-clear.
- **Conditional Access visibility now reads both policy axes, so workload-identity policies stop lying.**
  The Conditional Access tab previously matched only the resource axis (`applications`), which made
  every workload-identity policy claiming `All apps` look like it applied to every app — and hid
  policies that block an app's **service principal** while naming other resources. The tab now also
  evaluates `clientApplications` (the client axis: specific SPs, `workloadIdentityAll`, or a client
  attribute filter) against the app's own service principal, resolved through the existing cached SP
  lookup — no extra scope, and tenants without a P1/P2 license still see the graceful "unavailable"
  note. Exclusions still win on either axis; a policy whose client axis names neither this app's SP
  nor workload identities no longer shows; a block that only gates the app's SP signing in elsewhere
  now surfaces as "This app's service principal (as a client)"; and combined rows are labelled
  "workload-identity clients only". Apps without a service principal behave exactly as before.
- **Apps Microsoft has disabled for a policy violation are now impossible to miss.** The audit
  reads Graph's `disabledByMicrosoftStatus` — Microsoft's own flag for suspicious, abusive or
  malicious activity, set on the application and its service principal — and scores it +15, so a
  disabled principal is at least High on that signal alone (**this shifts audit ranking**: a
  previously-invisible flag now leads the issue list and moves apps up). Disables appear as a
  "Disabled by Microsoft" group in the Findings workbench, as a red badge on the App Registration
  and Enterprise Application headers, and on SP-only rows (foreign enterprise apps, managed
  identities) where the application object lives in another tenant. A no-credential, no-permission
  disabled app now finally reads as what it is; there is deliberately no one-click fix — deleting
  or re-enabling is admin-judged.
- **The Security audit and the permission picker now flag tenant-wide Files permissions.** An app
  holding `Files.Read.All` or `Files.ReadWrite.All` — which reach every file across all site
  collections and OneDrive — now gets an "Org-wide Files access" advisory finding, counted on the
  posture strip and Home, with its rows drilling to the Permissions tab. It carries no one-click
  Fix: only removal, or re-declaring as the item-scoped `Files.SelectedOperations.Selected`, is
  possible. In the grant-time permission picker those two permissions now show "Org-wide — reaches
  every file. Prefer Files.SelectedOperations.Selected.", and the Grant-access wizard's item
  scoping accepts that scoped model, so the picker hint, the audit recommendation and the wizard
  point at one answer. Audit scores are unchanged — this is visibility, not re-ranking.
- **Key Vault access scans flag vaults whose access the scan cannot see.** A vault set to the
  legacy Access Policy permission model grants data access through a mechanism the Azure RBAC
  listing does not enumerate, so an empty result from such a vault previously looked the same as a
  vault with no access. The scan's summary line — and its CSV/JSON export — now names how many
  vaults are in access-policy mode and that their grants are invisible to the scan. A vault whose
  model Azure did not report is never guessed either way.
- **The Key Vault secret browser now distinguishes certificate-backed entries from real secrets.**
  Every vault certificate appears in the secret listing as a *managed* entry, previously
  indistinguishable from a rotatable app secret; those rows now carry a "certificate-backed" badge
  and a hint that they are not writable secrets.
- **A rotated Key Vault secret records what it belongs to, and refuses to overwrite another
  app's secret.** Every secret version written by credential rotation is tagged with the owning
  app and its key id, so a vault reader can tell which app minted it. Before rotation mints
  anything it checks the target secret's tags: a secret tagged to a different app is refused with
  "nothing was minted". Untagged secrets remain rotatable (no ownership is claimed from absent
  tags), and a transient failure of the ownership check skips the check rather than blocking a
  legitimate rotation.
- **The SSO wizard's lifetime fields now reject impossible values instead of
  silently using the default.** A mistyped certificate or secret lifetime ("3650",
  "abc") used to be dropped and the app created with the 365/180-day default the
  operator never typed; Next now stays disabled while the value is outside 1–1095
  (cert) or 1–730 (secret) days, with the reason shown under the field. Blank
  remains a deliberate "use the default", and the create call re-checks the same
  bounds behind the button.
- **The claims editor now warns about edits that quietly strip claims from tokens.** While a
  claims policy is being edited (SSO tab and the New SSO application wizard alike), the editor
  flags: switching the basic claim set off with no claims defined, a claim with neither a SAML
  URI nor a JWT name, a transformation-sourced claim naming no transformation (or one that
  doesn't exist), duplicate SAML claim URIs, and transformations with no output claim. The
  warnings are advisory — Save stays enabled, because a deliberate lockdown is legitimate.
- **The Permission tester's SharePoint check now lists — and can undo — the permission entries on
  the tested resource.** After a SharePoint probe, a section under the verdict lists every app
  grant on the resource the URL resolves to, each with a confirm-gated Revoke, so a per-URL
  ("Selected") grant made in the Grant-access wizard can be undone where it was verified.
  User or group sharing entries are listed but carry no Revoke — removing one would cut a person's
  access, not an app's. Because the read is by URL, an empty list means "no grants on this
  resource", never that the app has no item-level access elsewhere (a file inherits from its
  library and site); the section and its empty state say so, and a failed read shows an error
  rather than an empty table. A revocation re-runs the probe, so the fresh verdict proves it landed.
- **A managed identity's Azure role form accepts any role, and its consent button says what it does.**
  A "Custom role definition id…" option takes the GUID of any other built-in or custom Azure role
  (checked as a GUID before the request), where the form offered only eight common roles; and the
  Azure Resource Manager consent button now reads "Grant consent to Azure", no longer the same
  "Grant access" as the permission wizard in the same pane.
- **Home's "With secrets" and "With certs" counts now open the matching App Registrations.** They
  were the only numbers on Home you couldn't click, and the list had no way to show every app that
  holds a client secret or a certificate — the question to answer before moving apps from secrets
  to certificates. App Registrations has two new filter chips, With secrets and With certs. Its
  credential filter also now clears when you switch tenants, like the other lists' filters.
- **Access Readiness now covers SCIM provisioning and SAML claims mapping.** Both features need
  their own consented scope (`Synchronization.Read.All`, `Policy.ReadWrite.ApplicationConfiguration`)
  and an app-management role, but the checklist didn't list them, so it couldn't show why the
  Provisioning tab or a custom-claims save failed. Each now has a row with its roles and scopes, and
  a 403 when saving claims or reading provisioning now names the role to activate.
- **The Provisioning tab offers "Grant consent & retry".** It used to name
  `Synchronization.Read.All` and stop there. It now runs the consent round trip and reloads, as the
  Group memberships section does, and shows which roles can read provisioning.
- **Settings → Tenant connection now says when an environment variable or the build decides your
  tenant.** The tab only warned that an `AZAPPTOOLKIT_CLIENT_ID` / `AZAPPTOOLKIT_TENANT_ID` variable
  *could* override a saved ID, so after saving and restarting you could see the old tenant come back
  with no explanation. It now shows when a variable on this computer is supplying either ID, or when
  the ID is built into your copy of azapptoolkit. A team build made from a `.env` with an empty or
  mistyped ID also warns at build time instead of failing at sign-in.
- **A team build can now bake in the sovereign cloud, like the client and tenant IDs.** Add
  `AZAPPTOOLKIT_CLOUD` to `.env` before building, and the installer targets US Gov, US Gov DoD or
  China with nothing set on each workstation. Previously every recipient had to set the variable,
  or the app used the commercial endpoints and sign-in failed with an Entra error. A variable set on
  the workstation still overrides the baked-in value.
- **Creating an app from the gallery or the New SSO application wizard now takes you to it.** A
  gallery app opens on its SSO tab, where its own hint says to finish single sign-on. The wizard's
  summary has an Open application button. Before, the dialog just closed, and you had to find the
  new app in the list.
- **The Access tab can filter its assignments, and its search hides anyone who already has the
  chosen role.** Type in the new filter box to narrow the list by name, type or role. The user and
  group search no longer lists someone who already holds the selected role, since assigning it a
  second time failed with a generic Graph error. People who hold a different role are still listed.

- **Authorized client applications show their names, and you can find a client by name.** The
  Expose an API tab listed each pre-authorized client by its application ID alone, so you couldn't
  tell which app skips the consent prompt without looking it up. Each row now shows the app's name
  from this tenant's directory. The Add dialog searches enterprise apps and app registrations by
  name or ID. You can still add a client from another tenant by pasting its application ID.
- **If azapptoolkit can't open your browser to sign in, it shows the sign-in link.** Sign-in,
  consent and re-authentication used to wait five minutes and then fail when no default browser
  could be launched (a confined `xdg-open`, or a policy that blocks the browser handler). The link
  now appears at the top of the window with a Copy button. Paste it into a browser on this computer
  to continue.
- **The Authentication and Overview forms now wait for an actual change before they write.**
  Both are full-replace or whole-patch forms, so clicking Save on a form you hadn't edited used to
  re-send byte-identical settings — a pointless round trip that also busted every cached app list
  behind the write. Save is now disabled until something actually differs from the loaded state
  (whitespace and blank URI rows don't count), and the backend treats an all-empty update patch as
  a no-op too. The Authentication tab also gains a Reset button that restores the loaded URIs,
  logout URL and toggles, and Cancel on the Overview tab now discards half-typed edits instead of
  parking them until the next edit session.
- **Saved views now carry the "created on" date window, and applying one says
  whether it changes.** A saved view used to snapshot only the facet and search,
  so "Disabled, created this quarter" couldn't be saved, and applying a view
  left whatever date range was active silently narrowing the list. Saved views
  on the App Registrations and Enterprise Applications lists now store the
  created-on window too; applying one restores it — or, if it was saved without
  a range, clears the active one. Each chip's tooltip names the window it will
  restore, and the chips gained accessible names ("Apply saved view …").
  Views saved before this change keep working (the new fields default).
- **Deleted app registrations are recoverable, and the app now says so.** A deleted app
  registration sits in the Entra recycle bin for ~30 days and can be restored (its paired
  enterprise application comes back with it), but the app presented deletion as irreversible and
  the bin was invisible. The App Registrations header gains a **Recently deleted…** dialog listing
  the bin — per row, when it was deleted and how much of the window is left — with **Restore**
  (carries the paired enterprise app along) and a two-step **Delete forever** for skipping the
  window deliberately. After a bulk delete the action bar's result summary offers **Undo
  (restore N deleted)**, replaying exactly the ids that run confirmed gone, and the delete
  confirmation copy now points at both exits instead of saying "cannot be undone". The bin is
  read live and never cached — a restore or purge refetches rather than serving a stale bin —
  and a read that hits its row cap says "this list is partial" rather than showing a short bin
  as the whole truth.

### Fixed

- **The Permission tester's open resource tab now resets on tenant switch.** The mailbox and site
  URL fields already cleared between tenants; the open tab (Exchange or SharePoint) survived the
  switch. It now returns to Exchange like the rest.
- **Screen readers now name every field and remove button in the SAML claims editor.** Its inputs
  were named only by placeholders, which vanish once a value is typed, and each input claim,
  parameter and output claim had an unnamed "✕" remove button; they now carry labels (the remove
  buttons name the claim they drop). The retired scope group's typed delete confirmation is labelled
  the same way.
- **The Permission tester sees org-wide `Sites.*` grants on Office 365 SharePoint Online.** An app
  holding `Sites.FullControl.All` on the SharePoint REST/CSOM resource reaches every site, but the
  site test read only Microsoft Graph's grants, so such an app could read as "No access". Both
  resources are now read, and a SharePoint Online grant is labelled as such in the verdict.
- **CSV exports open correctly in Excel when names are not plain ASCII.** Every CSV now starts with
  a UTF-8 byte-order mark, which Excel needs to read `Zürich Finanz` or a Japanese app name
  without garbling it (pandas strips the mark on its own; base R's `read.csv` wants
  `fileEncoding = "UTF-8-BOM"`).
- **Audit coverage caveats no longer carry runs of spaces.** Four "what this run could not
  determine" sentences, shown on the Security tab and written into the audit export, had lost
  their line continuations and showed long gaps mid-sentence.
- **Application Access Policies are called "legacy", not "deprecated".** The Security tab group
  and the audit recommendation now match Microsoft's wording: the policies are replaced by RBAC
  for Applications, and a deprecation is yet to be announced.
- **Resource Access no longer shows the previous mailbox's verdicts while checking a different one.**
  The old table stayed under the progress bar (and under any error) for a mailbox you were no longer
  asking about; it now clears when you check a new address. The Permission tester also shows a
  seeded identity by its display name instead of a bare appId, and clears the mailbox and site URL
  when you switch tenants.

- **The app-registration Owners tab no longer says "No matches." under an empty search box.** Both
  Owners tabs and the audit's add-owner dialog now use the same directory search as the Access tab,
  so the search behaves identically everywhere and only reports "No matches." after an actual search.

- **The keyboard shortcuts sheet draws each key as a filled key cap.** The key style pointed at a
  colour that was never defined, so in both themes every key showed as an empty outline. The
  Filters button on the lists also gets a hover highlight, which it was missing for the same reason.
- **Actions that fail on a throttled or briefly unavailable service now offer Retry.** Saving an
  enterprise app's settings, SSO configuration or signing certificates showed a red notification
  that vanished after ten seconds, so the only way back was to find the control and click it again.
  When the service says the failure is temporary, the notification now has a Retry button and stays
  until you use or dismiss it. It won't retry after you switch tenants or close that app, or while
  another action on it is still running; it tells you why instead.
- **An expired session now offers Re-authenticate everywhere, once.** The Permission Tester, the
  Resource Access sites, Key Vault and mailbox scans, the Key Vault browser and global search showed
  the raw error with no way forward, and global search repeated it on every keystroke. Each now
  raises the Re-authenticate notification. Repeated failures raise it once instead of stacking
  copies, and a burst of other notifications can no longer push it, or any notification waiting for
  you to act, off the screen. The Key Vault browser and the mailbox scan likewise offer Refresh
  token, Grant consent or Verify identity where one of those fixes the failure, instead of the raw
  error.
- **An enterprise app's Access, Permissions and App roles tabs, and a SharePoint site's permission
  list, offer Retry when they fail to load.** A throttled or dropped request left a red line — on
  the Access tab one that began with the raw code, such as `error [throttled]` — and you had to
  switch tabs or refresh the app to try again. They now show the same message and Retry button as
  the other tabs, with the code in small print after the message. Sign-in and Access Readiness
  errors now lead with the message too.
- **Screen readers announce errors and the "Copied" confirmation.** A failed save in a dialog, a
  tab that failed to load, or a failed backup or restore appeared on screen without a sound, so a
  screen reader user was left on a re-enabled button with no idea why. Each error is now read out as
  it appears, and copying an ID says "Copied".
- **Screen readers now hear which filters, findings groups and filter chips are open or selected.**
  The Filters button on each list and every group header on the Security tab's Findings pane
  announced no expanded or collapsed state, and a Findings header read its arrow glyph aloud as part
  of its name. The list filter chips showed the active one by color alone; each chip now says
  whether it is pressed. Global search and the Permission Tester's app picker no longer announce
  "Searching…", "No matching records" or the result-limit warning as if they were results, and
  global search names the group (Go to, App Registrations, …) a result belongs to.
- **Arrow keys now move between rows in every table.** The keyboard shortcuts sheet promises ↑ ↓ /
  Home / End in tables, but the Permissions and Expose an API tabs, an enterprise app's App roles
  and SAML signing-certificate tables, and the observed Graph usage table ignored them. They now
  work like the other tables. A staged SAML signing certificate also gets its own blue badge, so
  the certificate waiting to be activated stands out from the others.
- **Removing an expired SAML signing certificate now asks first.** The SSO tab's Remove button
  deleted the certificate on a single click, and once the table gained keyboard navigation, Enter
  on that row did the same. Removal can't be undone, so both now open a confirmation naming the
  certificate's thumbprint, like Retire previous certificate already did.
- **The Permissions tab's kind filter can no longer hide every row.** You could switch off both the
  Application and Delegated toggles and be left with an empty table and no explanation. It is now
  one All / Application / Delegated choice, and a choice with nothing in it says so. An app with no
  permissions now points you to Grant access instead of the Entra portal.
- **The Activity and Conditional Access tabs now name every role that can grant their admin
  consent.** When Microsoft Graph refused the read for lack of consent, the message said to ask a
  Global Administrator. A Privileged Role Administrator, Application Administrator or Cloud
  Application Administrator can grant these delegated permissions too, so the message now lists
  all of them from the same role catalog Access Readiness uses.
- **Assigning an Azure role that a managed identity already holds now says so.** ARM rejects a
  duplicate assignment, and the Assign Azure role form showed its raw reply,
  `arm error (409): {"error":{"code":"RoleAssignmentExists",…}}`. The form now says the identity
  already holds that role at that scope and that nothing was changed.
- **The Vault access tab will keep finding your key vaults after Microsoft retires older Key Vault
  management APIs.** Microsoft stops accepting Key Vault control-plane API versions older than
  2026-02-01 on February 27, 2027, and the sweep listed vaults with 2023-07-01. From that date it
  would have reported no vaults instead of showing an error. It now uses 2026-02-01. Reading and
  writing secrets uses a different API and is not affected.
- **Removing expired credentials no longer counts a credential that was already gone.** The
  audit's one-click Fix rewrote an app's certificate list even when the expired certificate had
  already been removed (by another admin, or since the audit ran), and counted it as removed. It
  now skips a secret or certificate that no longer exists and keeps removing the rest. Removing a
  certificate, or retiring a SAML signing certificate, that is already gone now reports that it
  wasn't found instead of succeeding without changing anything.
- **The Exchange scoping section no longer lists an administrative-unit-scoped role assignment as
  org-wide.** "Current Exchange role assignments" showed "(org-wide)" for any assignment without a
  management scope, so an assignment created with `-RecipientAdministrativeUnitScope` looked as if it
  reached every mailbox. It now shows "Administrative unit" and the unit's ID. The mailbox Scope
  verdicts and audit scoring already read these assignments correctly; only this list was wrong.
- **Scoping mailbox access now tells you when a permission still reaches every mailbox.** If an
  Exchange role couldn't be assigned or an org-wide grant couldn't be removed, the result listed each
  failure but not what it meant. A single note now names the permissions that are still granted
  organization-wide in Entra ID, where scoping has no effect yet, as the legacy-policy migration
  already did. A permission the app only declares, with no org-wide grant, isn't listed.
- **Scoping mailbox access for an app with nothing to scope no longer creates its enterprise app.**
  The toolkit created the app's service principal before checking that the app declared any
  mailbox permission it could scope, so a refused request still added an enterprise application,
  and App Registrations and Enterprise Apps didn't show it until their caches expired. It now checks
  first, and a new enterprise app created before a later failure refreshes both lists.
- **Uploading a certificate now refuses a private key and shows which certificate went up.** The
  upload dialog sent whatever you pasted to Microsoft Graph after checking only that it was base64,
  so a PEM file that also held the private key sent the key along, and Graph's rejection didn't say
  why. The toolkit now reads the certificate first: a private key, a paste with more than one
  certificate, an expired certificate, or anything that isn't an X.509 certificate is refused with
  the reason, and nothing is sent. After an upload, a confirmation shows the certificate's
  thumbprint and expiry date as the Entra portal lists them.
- **Redirect URIs and the front-channel logout URL are checked against Entra's rules before you
  save.** A redirect URI using the IPv6 loopback address (`http://[::1]`) or longer than 256
  characters passed the toolkit's check, but Entra supports neither, so the whole save then failed
  with a generic Graph error. Both are now flagged on the row. The Authentication tab's
  front-channel logout URL wasn't checked at all; it must now be an https address (or http on
  localhost), and a bad one is named before anything is saved.
- **Starting the app offline no longer looks like you were signed out.** If Entra ID can't be
  reached to restore your last session, the sign-in screen now says so and offers Retry, which
  picks the session back up once you're online, without a browser sign-in. Before, you got the
  plain sign-in card, and signing in opened a browser that couldn't load.
- **On Linux without a credential store, sign-in says what's missing.** azapptoolkit keeps your
  sign-in in the Secret Service (GNOME Keyring or KWallet). When none is running, the error told
  you to unlock a keychain that doesn't exist. It now says no credential store is available and how
  to fix it, and the README lists the requirement.
- **A sign-in Entra refuses in the browser now shows the step that fixes it, and a stray request
  can no longer cancel a sign-in.** When you declined consent (AADSTS65004) or a Conditional Access
  policy blocked you (AADSTS53003), the sign-in card showed only the generic "declined" hint,
  because the Entra error code was dropped. The code is now kept, so the card shows the specific
  step. While the app waited for your browser, any program on the machine, or any web page open in
  your browser, could send a fake reply to its sign-in port. That ended the sign-in with an error
  of its choosing. Those requests are now ignored, and the real sign-in still completes.
- **The permission picker no longer tells you to scope Office 365 Exchange Online mail permissions
  to specific mailboxes.** Picking `Mail.Read` or another mail, calendar or contacts permission on
  Office 365 Exchange Online showed "Scope to specific mailboxes (Exchange RBAC)". RBAC for
  Applications only confines the Microsoft Graph versions of these permissions, so there was no way
  to follow that advice. The note now appears only where it applies, and a `Sites.` role on an API
  other than SharePoint no longer suggests Sites.Selected.
- **Legacy Exchange Online mail grants and org-wide access the toolkit can't confine now appear in
  the Security findings.** The audit already flagged an app holding, for example, `Mail.Read` on
  Office 365 Exchange Online or `Sites.Read.All` on Office 365 SharePoint Online, but the finding
  sat in no group and no count, so you only saw it in the All apps issue column or an export. Two
  new groups, "Legacy Exchange Online mailbox grants" and "Org-wide access that can't be confined
  here", list these apps with an Open link to the Permissions tab. They have no Fix button, because
  removing or re-declaring the grant is your call. The Home Security Posture card counts them too.
- **An audit that stopped at the per-run app limit now says so above the results, even when it
  found problems.** On a tenant with more than 10,000 app registrations the audit scores at most
  10,000. The notice only appeared when those came back clean, so the findings and every "Fix all"
  count looked like a full scan. The notice now sits under the posture counts next to the
  cancelled-scan notice. The "Part of this scan could not run" notice moved there too, so the All
  apps view shows both.
- **`/` now jumps to the filter on the page you're looking at.** Once you had opened App
  Registrations, pressing `/` on Enterprise Applications, Managed Identities or Security did
  nothing, because it found the hidden App Registrations filter first. With an app open, it now
  goes to that app's filter box where it has one. `/` and `?` also work right after you tick a
  row's checkbox, and `?` no longer opens the shortcut list on top of another dialog, where one
  Escape closed both.
- **The account menu and the Export menu now work from the keyboard.** Opening either one moves
  focus to its first item. The arrow keys, Home and End move between items, and Escape puts you
  back on the button that opened it. Screen readers announced both as menus, but neither supported
  this, and the Export button didn't say whether its menu was open.
- **Deleting apps, removing expired credentials or Refresh no longer sends the App Registrations
  and Enterprise Apps lists back to the top.** Any change that reloads the list used to drop you
  back at the first row, so on a large tenant you lost your place. The list now returns to where
  you were. A new search, filter or sort still starts at the top.
- **Opening an app that's already open no longer changes which tab the next app opens on.** "Open"
  from the credential dashboard, a Security finding or a mailbox-scope row asks for a specific tab.
  If the app was already open, it came to the front on the tab you'd left it on, but the request
  stayed queued, so the next app you opened from a list landed on Credentials or Permissions
  instead of your last-used tab. Enterprise applications had the same problem.
- **Refresh on the App Registrations and Enterprise Applications lists now always fetches fresh
  rows.** The list could reload before the app had cleared its cached copy, so Refresh spun and
  showed the same rows. It now clears the cache first, as the detail pane's Refresh already did.
- **Re-authenticating from the "session has expired" message now re-checks Access Readiness.** The
  top bar's Refresh token already did this; the message's Re-authenticate button left an open
  Access Readiness checklist showing your old access.
- **Sign-in errors for a wrong tenant or client ID now point to the Change link on the sign-in
  card.** They said to check Settings → Tenant connection, which can't be opened until you've
  signed in.
- **Choosing "Org-wide" in the Grant access wizard no longer strands a SharePoint grant.** For a
  SharePoint site permission, or a library, folder or file permission, picking "Org-wide — no
  scoping" hid the site or item picker, and nothing on that step brought it back: you had to go
  back and pick the permission again. These permissions now have a "Specific sites" or "Specific
  libraries, folders & files" option above the picker, as mailbox permissions already did.
- **"Grant read" is now the highlighted button in the SharePoint site access section.** "Grant
  write" was highlighted too, so the broader role looked like the default. It now uses the plain
  style the audit's Scope fix already gives write access.
- **The SharePoint site access section no longer opens for a `Sites.*` permission on a
  non-SharePoint API.** It is shown only for Microsoft Graph or Office 365 SharePoint Online
  permissions, whose per-site grants it can list.
- **Adding or removing an Application ID URI no longer undoes a change someone else made.** The
  Expose an API tab saved the list of URIs it loaded when it opened, with your change applied. So a
  URI added since then, by another admin or in the Entra portal, was silently deleted. The app now
  reads the current list when you save and changes only the URI you added or removed, as it already
  did for scopes and authorized client applications.
- **The Expose an API, Authentication and Federated credentials tabs, and the permission picker,
  offer Retry when they fail to load.** A throttled or dropped request used to leave a red error
  line, and you had to close and reopen the app or the dialog. They now show the same message and
  Retry button as the other tabs.
- **An enterprise app's secret or certificate that expired within the last day now shows as
  expired.** The enterprise Credentials tab dropped partial days, so a SAML signing certificate
  that had lapsed a few hours earlier showed "0d left". It now rounds down, as the SSO tab does.
  The SSO tab's certificate list now uses the same wording ("12d left", "Expired 3d ago") instead
  of "1 days left" and "expired 3 days ago".
- **The Access tab no longer lets you pick a role that only applications can hold.** Entra rejects
  those roles for a user or group, and the tab showed the error only after the confirmation
  dialog. They now appear greyed out and labelled "(applications only)".
- **The new certificate from "Rotate and activate immediately" now stays on screen.** Entra returns
  the new signing certificate only once, but the SSO tab reloaded right after the rotation and the
  certificate vanished before you could copy it. It now stays up through the reload. It, and the
  certificate shown after staging a replacement, now has a label, a hint and a Copy button that
  says so when the clipboard write fails.
- **The SSO certificate board shows thumbprints the way the SSO tab and the Entra portal do.** When
  Entra stored an app's nominated signing key in lower case, the board's Thumbprint column showed it
  that way, beside the upper-case value the SSO tab shows for the same certificate. The board and
  the SSO tab's owner details now show it in upper case.
- **Restoring group memberships and granting SharePoint access to several sites or lists now
  waits out Microsoft Graph throttling.** These writes use their own permissions, and unlike every
  other change the app makes they gave up at the first "too many requests" reply, so a DR restore
  or a multi-site grant recorded failures you had to redo by hand. They now wait as long as Graph
  asks and try again, like other writes. A write that creates something is still never re-sent
  after a server error, so nothing is granted twice.
- **A brief Microsoft Graph server error on one site no longer leaves the whole SharePoint sweep
  incomplete.** Reads sent in batches of 20 retried an item that was throttled but not one that hit
  a server error, though the same read sent on its own was retried. One such reply marked the site
  sweep incomplete and kept it from being cached, and made a DR backup skip that object. Those
  items are now retried on the same schedule.
- **Long lists now read every page the same way.** Owners, permission grants, role assignments and
  federated credentials read their first page from the directory and later pages from its search
  index, which can lag behind recent changes, so a grant you had just made could be missing from
  page two. Every page now uses the same source.
- **The New SSO application wizard now refuses an OIDC client-secret lifetime outside 1–730 days
  instead of creating a broken app.** A lifetime of 0 created a secret that had already expired, and
  a very large one failed only after the application and its service principal existed, leaving a
  half-configured app. The wizard now says "client secret lifetime must be between 1 and 730 days"
  and creates nothing, as it already does for a SAML certificate lifetime, and the cap matches the
  24 months the Credentials tab allows.
- **A SAML app whose custom claims or notification emails couldn't be saved no longer looks fully
  set up.** The New SSO application wizard treats those two steps as best-effort. When one failed,
  the wizard still showed the same success screen, so the missing claims only came to light at the
  first federated sign-in. The summary now lists what wasn't applied and where to retry it on the
  app's SSO tab. The certificate and activation steps now also wait out Entra's replication delay,
  like the steps before them, instead of leaving a half-configured app.
- **Creating an SSO application now works in US Gov and China tenants, and the URLs it gives app
  owners point at your cloud.** The New SSO application wizard always used the global cloud's
  custom-application template, which US Gov and 21Vianet tenants don't have, so creating a SAML or
  OIDC app failed there. The Login, Logout and Metadata URLs, and the OIDC authority and discovery
  URLs, always named `login.microsoftonline.com`, and in China the Entra Identifier named
  `sts.windows.net`. A service provider set up from them couldn't sign anyone in. The metadata check
  during a staged certificate rollover fetched the same wrong address, so it always read "couldn't
  check" in a sovereign tenant. All of these now follow `AZAPPTOOLKIT_CLOUD`.
- **Access Readiness now names the consent scope your cloud actually uses.** A US Gov or China build
  said, for example, "Not consented: https://vault.azure.net/.default" while the app had asked for
  the Key Vault, Azure Resource Manager, Log Analytics or Exchange scope at its own cloud's address.
- **Access Readiness no longer reports Application Administrator or Cloud Application Administrator
  as missing for admin consent.** Those roles can grant consent for any API except Microsoft Graph
  (and Azure AD Graph) application roles, which still need Privileged Role Administrator or Global
  Administrator. The row now says so.
- **A directory role you don't hold now links to PIM.** A missing role now says to activate it in
  PIM if you're eligible, or to request an assignment otherwise, and "Open PIM (My roles)" opens the
  activation page in your cloud's Entra admin center.
- **A multi-factor prompt required for Azure, Exchange or Log Analytics no longer signs you out of
  everything.** When a Conditional Access policy required extra verification for one service, the
  app threw away your whole session. Every view, including browsing Entra ID, then needed
  Re-authenticate, and when the policy covered only that one service, re-authenticating didn't
  clear it, so the prompt came back. Your session is now kept, and the error offers "Verify
  identity", which completes the check for that service in your browser and, where the error is
  shown in place (Azure RBAC, Key Vault access, Observed Graph activity, mailbox scoping), retries.
  For Microsoft Graph the check runs on the permissions you signed in with, so it never turns into
  a consent prompt; Refresh token handles the same prompt by re-authenticating in place.
- **Microsoft Graph tokens obtained at sign-in, launch, Refresh token and Grant consent now support
  Continuous Access Evaluation.** The app has always asked Graph for tokens that are revoked
  promptly when a password is reset, a user is disabled or a sign-in is flagged as risky. Tokens
  from those flows lacked it for up to their full lifetime.
- **A busy or briefly unavailable Microsoft sign-in service no longer fails the action or signs you
  out at launch.** Token requests are now retried after a throttling (429) or server error, waiting
  as long as the service asks, like every other Microsoft call the app makes, up to 30 seconds (a
  longer wait fails straight away rather than stalling every sign-in step behind it). Access
  Readiness no longer shows "Couldn't determine" for a scope just because several token requests
  ran at once. A brief outage at launch no longer sends you back through the browser sign-in.
- **Adding or removing an enterprise app from a security group now requests every permission
  Microsoft Graph requires for it.** Graph needs Application.ReadWrite.All as well as
  GroupMember.ReadWrite.All to add a service principal to a group. The app asked only for the
  second, so the change could be refused even though Access Readiness said the scope was consented.
  You may be asked to consent once; Access Readiness now lists both scopes.
- **Closing the browser during sign-in, or cancelling at the Microsoft sign-in page, now says so
  instead of blaming your network or an administrator.** An abandoned sign-in timed out after five
  minutes with "Check your network and try again". Cancelling showed "The sign-in was declined. An
  administrator may need to grant the app consent." Both now say the browser sign-in was closed
  before it finished.
- **The audit now scores the read-only halves of permission families it already scores high.**
  Org-wide application grants of `Contacts.Read`, `MailboxSettings.Read`, `Notes.Read.All`,
  `Device.Read.All`, `Application.Read.All`, `GroupMember.Read.All` and
  `RoleManagement.Read.Directory` scored zero, while `Mail.Read` and `Calendars.Read` scored as
  medium risk. `Contacts.Read` and `MailboxSettings.Read` already raised "Organization-wide mailbox
  access" yet added nothing, so an app holding both could rank Low. They now score as medium risk
  like the other tenant-wide reads, and permission risk badges show them as medium. A mailbox grant
  confined through RBAC for Applications keeps the reduced scoped weight. **This shifts risk
  ranking** for any app holding these grants.
- **"High-risk delegated permissions" now lists broad delegated scopes only when an admin
  consented to them for all users.** Any app registration that merely requested a delegated scope
  such as `Mail.Read` or `Files.Read` joined the finding, whose description says the scopes are
  admin-consented, although a scope a user consents to reaches only that user's data. The audit now
  checks the tenant's admin-consent grants for each scope. `Directory.AccessAsUser.All` and
  `user_impersonation` are still listed whenever an app requests them. If the consent grants can't
  be read, requested broad scopes are still listed rather than hidden. This finding adds no points,
  so scores are unchanged.
- **A certificate valid for more than a year is no longer reported as a "long-lived secret".** The
  rule checks secrets and certificates alike, but the finding always said "Long-lived secrets (>1
  year)", so replacing a secret with a normal two-year certificate, as the audit recommends, filed
  it under secrets. Certificates now get their own "Long-lived certificates (>1 year)" line. The
  score is unchanged.
- **An app for personal Microsoft accounts only is no longer described as reachable from any Entra
  tenant.** For the `PersonalMicrosoftAccount` audience, the finding said the app "can be consented
  to from any Entra tenant and personal Microsoft accounts". It now names personal Microsoft
  accounts only, and the recommendation asks whether the app is meant to accept them. The score is
  unchanged.

- **Apps with a flexible federated credential now open their Federated credentials tab, and DR
  backups include them.** A flexible credential (one that matches a claims expression instead of a
  single subject, as GitHub recommends for pull-request and branch workflows) has no subject, and
  reading one failed with `invalid type: null`, so the tab showed only that error and a backup
  skipped the whole application. The tab now lists it with "Expression-matched (flexible)" in the
  Subject column (edit it in the Entra portal). Restore reports that it was not recreated, and the
  restore preview no longer counts it.
- **A new app registration now shows up in the list even when a later step of creating it
  fails.** If the app was created but its enterprise application (service principal) couldn't be
  (for example a 403, throttling or a directory replication delay), you saw only the error, and the
  App Registrations list and search kept their cached copy for up to an hour, so trying again
  created a second app with the same name. The error now says the application was created and
  gives its object ID, and the list and search show it the next time they load. Granting a
  permission or admin consent that fails partway now refreshes the app's details and the
  Enterprise applications list in the same way.

- **Removing expired secrets or replacing an app's owners now stops and offers Re-authenticate if
  your session expires partway.** Before, every remaining secret or owner failed with the same
  message and no way to recover.

- **"Rotate & remove existing" now asks before deleting your other client secrets.** In the Rotate
  secret into Key Vault dialog, this button removed every client secret on the app, including
  active ones, in a single click, and its label didn't say how many. It now reads "Rotate & remove
  N existing" and asks for confirmation, naming the app and the count, as removing one secret or
  sweeping expired ones already did. If an old secret couldn't be removed, the message now names
  it and gives the reason instead of "see the log".

- **Lifetimes you type for a rotated secret or a generated certificate are no longer silently
  changed.** Text that wasn't a number became 180 or 365 days, and longer values were cut to 730
  or 1095 days, without a message. An out-of-range or non-numeric value now shows "Enter a whole
  number of days between 1 and 730." (1095 for certificates), and nothing is created.

- **The one-time secret and private-key reveals no longer say "Copied" when the copy failed, and
  Escape no longer closes them.** If the clipboard refused, the new-secret reveal still said
  "Copied", and "Copy private key" gave no feedback at all. Once the dialog closes the value is
  gone for good. A failed copy now says so and asks you to copy the text by hand, and both dialogs
  close only with Done.

- **Row buttons on the Security dashboards and several detail tabs now line up with their row,
  and the Credentials tab's empty lists match the rest of the app.** The Open, Remove and similar
  buttons sat a few pixels below the text of their row.

- **Search and the other commands that read the cached directory indexes now check that you are
  signed in.** Top-bar search, the directory cap notice, DR backup, the delegated-grants audit, the
  enterprise-app detail, the gallery picker, the Key Vault access sweep, a managed identity's Azure
  roles and the mailbox-reach lookup could answer from the cached app and service-principal lists
  without checking the tenant's session. After a session expired they kept serving the cached names
  instead of reporting "not signed in", as the lists already do. They now check the session before
  reading the cache.

- **Pasting an ID into search now says when a lookup failed.** A GUID search runs four exact
  directory lookups, and any lookup that failed (throttled after retries, refused with 403, or a
  network error) counted as "not found", so the dropdown showed "No matching records." for an app
  that exists. Only a real "not found" now counts as no match. Any other failure shows a warning
  that the results may be incomplete.

- **Search now warns when the tenant has more than 10 000 app registrations.** The top-bar search
  already warned when it could see only the first 10 000 service principals, but not when the
  app-registration list hit the same cap, so a registration past it searched as "No matching
  records." Either cap now shows the warning.

- **A damaged settings.json is no longer overwritten with defaults.** If settings.json could not
  be read or parsed (for example after a hand edit left a stray comma, or while antivirus held the
  file), the next sign-in, Settings save or secret rotation replaced it with a fresh file,
  permanently losing your tenant defaults and the Key Vault each app's secret was rotated into.
  The app now leaves the file untouched and the save reports the problem ("Could not write
  settings.json: …") so you can fix or remove it. Saves from two running copies of the app also no
  longer overwrite each other.

- **A throttled request now tells you how long to wait.** When Microsoft Graph, Exchange, Key Vault
  or Azure kept throttling a request after the app's retries, the error read "throttled (429);
  retry after Some(30)s" (or "retry after Nones"). It now reads "Wait 30 seconds, then try again".

- **Azure, Key Vault and Exchange requests fail in seconds, not minutes, when a firewall blocks
  them.** Only Microsoft Graph limited how long it waits to connect. On a network that silently
  drops traffic to management.azure.com, a key vault, outlook.office365.com or Log Analytics, a
  read could spin for up to four minutes before failing. Connections now give up after 10 seconds,
  like Graph.

- **Network errors now say what went wrong.** A failed request showed only "error sending request
  for url (…)", whether the cause was DNS, a timeout, a refused connection, a proxy or a
  certificate. The underlying cause is now included, on the sign-in card too.

- **Error pop-ups keep their guidance on separate lines, and long error pages are trimmed.** The
  admin-consent failure's remediation steps ran together into one paragraph. Error pages returned
  by Graph, Azure or Key Vault (for example a proxy block page) are now cleaned and capped at 800
  characters in messages and logs, as Exchange errors already were.

- **A rejected access token now offers "Refresh token" instead of telling you to sign out.** When
  Microsoft Graph, Exchange, Key Vault or Azure rejected the app's token (for example after a
  Conditional Access re-check the app couldn't satisfy silently), the error read "unauthorized
  (401)" with no way forward, and the Exchange, Key Vault and Azure messages said to sign out and
  back in, which also clears every cached list and the last audit run. An error raised by a
  command or action now carries a "Refresh token" action that re-mints the token in place and
  falls back to re-authenticating if the session has expired. The Exchange, Key Vault and Azure
  messages point to the same control and still say what to check if the error persists. Clicking
  "Refresh token" again, or on a second error, while a refresh is running no longer starts another.

- **Forms and dialogs now offer "Re-authenticate" when your session has expired.** Most edit
  dialogs and tab actions showed an expired session only as red text under the form. They now
  raise the same Re-authenticate action the rest of the app uses, and keep the message where it
  was.

- **A missing admin consent now offers "Grant consent" wherever it occurs.** When a permission the
  tenant hadn't consented to was needed partway through an operation, the error reached the screen
  as a generic token failure, so the "Grant consent" action never appeared. It now does. The
  Security tab's "Scope … mailbox permission(s) to specific mailboxes" fix also gets the "Grant
  consent" button its SharePoint counterpart already had.

- **A network drop while the app refreshes its token is reported as a network error you can
  retry.** A network failure during the hourly token refresh was reported as a permanent token
  error, while the same outage a moment later was reported as a retryable network error. Both are
  now treated as network errors.

- **An unexpected reply from the app's backend no longer freezes the window.** If a request was ever
  rejected with something other than the app's usual error — for example a request the window built
  in the wrong shape, or a permission the app is not allowed to use — the whole window stopped
  responding with no message. The failure now shows as an ordinary error on the action that caused
  it.

- **"Migrate to RBAC for Applications" on the Permissions tab no longer reports success when the
  legacy policy was kept.** When a grant can't be re-scoped, the migration keeps the app's
  Application Access Policy, because that policy is the only thing still confining it. The Exchange
  scoping section checked only for outright failures, so it showed "Migrated 1 policy(ies)" and hid
  the report explaining what was kept. It now keeps the report on screen whenever an app needs
  attention or the run left apps unreached, the same as the Security tab's Fix (which now also stays
  open for a stopped run), and the success message counts apps and removed policies separately.

- **Remove redundant permissions no longer reports "Removed 0" and hides the Fix when it couldn't
  confirm the covering permission.** If the broader mail permission is scoped with Exchange RBAC, or
  Exchange can't be checked (for example, you aren't an Exchange administrator), the narrower
  permission is kept on purpose. It was left out of the result, so the Fix reported success and
  disappeared while the finding and the permission stayed. The kept permission is now listed with
  the reason, and the Fix stays on the row.

- **Scoping mailbox access from the Security tab no longer hides Exchange's warnings.** For a
  foreign enterprise app or a managed identity, warnings were dropped entirely; for an app
  registration they were only counted. The most common one means the groups you asked for were not
  applied, because the app already has a management scope with a different group set. Warnings are
  now listed in the dialog, which stays open, and the Fix stays on the row.

- **Admin consent that partly fails now says so.** "Grant admin consent" on the Permissions tab
  reported success even when some grants failed. The failure count was shown only in a note that
  disappeared as the tab reloaded. A partial consent now shows an error naming the failure, and a
  least-privilege downgrade's outcome is shown the same way instead of vanishing.

- **A throttled lookup no longer shows granted permissions as "Not granted" for an hour.** If
  Microsoft Graph couldn't return a resource's service principal while an app's details were
  loading, every permission on that resource read as not granted, and the result was cached for 60
  minutes. Such a result is no longer cached, and the Permissions tab says the grants couldn't be
  read and to refresh.

- **The SSO tab no longer overwrites claims it could not read.** When the app had not yet been
  granted consent to read an enterprise app's claims-mapping policy, "Attributes & claims" showed an
  empty editor even if the app had custom claims. Clicking "Save claims" then detached the real
  policy and replaced it with whatever was in the editor, so a single added claim could wipe the
  rest. The tab now says the claims couldn't be loaded, turns off Save, and offers a "Load claims"
  button that grants consent and reloads the current policy.
- **Claims generated by a transformation now appear in tokens.** A transformation-sourced claim
  needs two ids: its own `ID`, which the transformation's output claim refers to, and a
  `TransformationID` naming the transformation. The editor wrote only the transformation id, so the
  claim had nothing to join to and was never issued. Saving an existing policy also rewrote its
  reference to point at a transformation that didn't exist. Each claim now has a separate
  Transformation id field. Policies using Microsoft's documented `ClaimsTransformations` /
  `TransformationId` spelling load correctly, and a transformation parameter's `DataType` is kept
  on save.
- **Saving claims no longer leaves an orphaned policy in the tenant each time.** Every "Save claims"
  unassigned the old claims-mapping policy without deleting it and created a new one, so each save
  left another unused policy under the tenant's policies. The save now updates the app's policy in
  place. A policy shared with other apps is left unchanged for them, and this app gets its own copy.
  Clearing all claims deletes the policy once nothing else uses it. A failure to read the current
  assignment is now reported instead of being ignored and followed by a second policy assignment
  that Graph rejected. The claims consent now requests `Application.ReadWrite.All` together with
  `Policy.ReadWrite.ApplicationConfiguration`, the pair Microsoft documents for assigning and
  listing these policies.
- **Scope checks no longer trip over how Exchange capitalises group names.** Exchange returns a
  group's distinguished name in its own casing. The legacy-policy migration compared these exactly,
  so it could refuse an app whose management scope already pointed at the right group, with "still
  does not confine access to the groups this migration computed". "Move to managed group" could
  also repoint a scope that was already on the managed group and then list that group as a cleanup
  candidate. Group comparisons now ignore case, as the post-write check already did. Granting scoped
  access against an existing scope whose filter can't be fully read is now refused instead of
  treated as matching.
- **A legacy Application Access Policy reads the same in the audit as in the migration.** A
  `RestrictAccess` value with stray spaces was migrated as confining, but the security audit and the
  permission tester reported the app as reaching every mailbox and scored it at full risk. Both now
  read it as confining, so such apps can rank lower in the audit.
- **Deleting a retired scope group is refused when Exchange's scope or policy list can't be read.**
  A rejected read whose message happened to say "not found" was treated as an empty list, so the
  reference check could report no references to a group that was still in use. It now fails, and
  the delete is withheld.
- **Exchange changes are no longer re-sent after a server error or a dropped connection.** The
  Exchange client ran a retry loop of its own that replayed every cmdlet after a 5xx or network
  failure, including `New-ManagementRoleAssignment`, `New-ManagementScope`, `New-ServicePrincipal`
  and `Remove-ApplicationAccessPolicy`. When the first attempt had already taken effect, the replay
  failed as a duplicate or a missing object. A scoped grant that had landed was reported as "failed
  to assign" (the org-wide grant was kept and scoping was reported as not effective), and a legacy
  access policy that was removed was reported as a partial migration. Exchange now uses the same
  retry policy as Graph, ARM and Key Vault: throttling is still retried for every cmdlet, but only
  reads and group-membership changes (which are safe to repeat) are replayed after a server or
  network error. A write that fails that way is reported as that error, and re-running the action
  finishes it.
- **A sign-in that expires while Exchange is paging a long list now stops the operation for
  re-sign-in.** Any failure on the second or later page of an Exchange read was reported as a
  generic protocol error. An expired session was therefore not recognised, so the security audit and
  bulk actions carried on against it, and a 401/403 lost its sign-in or role guidance. Only a "not
  found" on a later page is still reported as a refusal to return a truncated list.
- **Cancel now stops only the run it belongs to.** The security audit, every bulk action and the
  legacy-policy migration shared one stop signal. So did the Resource Access site scan, Key Vault
  scan and mailbox probe, and the Disaster Recovery backup and restore. Because those screens keep
  running while you work elsewhere, pressing Cancel on one stopped the others as well: cancelling a
  read-only audit or mailbox probe could halt a bulk delete, a scoping change or a multi-minute site
  scan part-way, and cancelling a backup could stop a restore between passes. Each kind of run now
  has its own Cancel. Two bulk actions running at the same time still stop together. The "Migrate
  to RBAC for Applications" flows gain a Stop migration button: it stops before the next
  application, and one already being migrated finishes. A stopped or interrupted bulk run's
  progress bar now shows how far it got instead of jumping to 100%.
- **Turning off update checks now works.** `AZAPPTOOLKIT_AUTO_UPDATE=0` and `"auto_update": false`
  in settings.json were documented but never read, so the app still contacted the release endpoint
  on every launch and offered updates. Both now stop the launch check, the account-menu check and
  the install before any network call, and the menu item reads "Update checks turned off" instead
  of offering a check.
- **MSI and .deb installs are no longer offered the NSIS or AppImage update.** The updater could
  not tell how the app was installed: an MSI install was prompted on every launch, and accepting
  installed a second, per-user copy beside the managed one. A .deb install downloaded the whole
  AppImage only to fail with "invalid updater binary format". These installs now skip the update
  check, and the account menu says the update comes from your deployment tooling or package
  manager.
- **The Linux AppImage and .deb start on Ubuntu 22.04 and Debian 12.** They were built on the
  newest Ubuntu runner and so required glibc 2.38 or newer, failing at launch with "GLIBC_2.38 not
  found" (the .deb even installed cleanly first). They are now built against glibc 2.35, the
  release fails if a build ever needs a newer one, and the README states the floor.
- **A failed update install is now written to the log.** A download or signature failure during
  Update & restart left no trace in the log file the README points to.
- **Running a DR restore again no longer duplicates every app it already created.** The restore
  report, and the expired-session notice in the Disaster Recovery view, told you to re-run the
  restore — but each run created every app in the backup afresh, so a second run left a second copy
  of the estate with new appIds, service principals and live secrets. Restored apps now carry an
  `azapptoolkit:restoredFrom:<source appId>` tag, and a re-run recognises and finishes them instead
  of creating them again: a secret that already exists is not re-issued, and an app whose tag is
  ambiguous, or whose lookup fails, is listed for manual follow-up rather than created. Because
  anyone who can register apps could plant that tag, a tagged app is only taken over when it was
  created after the backup and has no owner besides you and the backup's own owners; otherwise it
  is listed, with the unexpected owners named, and is never granted the backup's permissions or
  admin consent. After a restore completes, the Restore button is withdrawn until you load a
  backup file again. Apps restored by earlier versions carry no tag and are not recognised.
- **A failed directory read during a restore is reported as a failure, not as a missing object.**
  If listing the destination's managed identities failed, every managed identity was reported "not
  found — recreate it via your infrastructure-as-code"; a failed service-principal read was reported
  as "the app had none in the backup". Both now say the read failed, and a session that expires
  during these steps stops the restore for re-sign-in.
- **Restore no longer re-issues client secrets that had already expired when the backup was
  taken.** Each one is named in the report and counted in the plan; a secret that expired after the
  backup is still re-issued.
- **The restore plan now shows what blocks a restore, and all the work it will do, before you
  confirm.** A backup written by a newer version of azapptoolkit was accepted by the plan and
  refused only after you confirmed; it is now blocked in the plan, as a backup from another cloud
  already was. Loading a backup into the tenant it was taken from now warns that restoring creates
  a second copy of every app instead of rolling anything back. The plan also counts the enterprise
  apps whose access will be re-applied, those that need manual follow-up, the managed identities
  to re-bind, and the gaps the backup itself recorded.
- **Restored apps keep their Expose-an-API settings when an identifier URI contains the tenant ID
  or a custom prefix.** Only `api://{appId}` was rewritten to the new app's ID.
  `api://{tenantId}/{appId}`, `api://{tenantId}/{name}` and `api://{name}/{appId}` kept the source
  tenant's IDs and were rejected by the destination tenant, and because the scopes and
  pre-authorized apps go in the same update, all of them were lost with a single warning. Every
  `api://` URI now has the source app and tenant IDs replaced.
- **A tenant backup no longer reads as complete when it could not read a managed identity's
  permissions or an enterprise app's assignments.** When Graph failed to return a managed
  identity's held app roles, or an enterprise app's assigned users/groups or group memberships, the
  backup quietly recorded them as empty — so a restore from it re-bound nothing and re-assigned no
  one, and neither the backup screen nor the file said so. Each gap is now listed alongside the
  objects the backup could not capture, and a sign-in that expires while managed identities are
  being read stops the backup for re-authentication instead of saving a manifest with every
  identity's permissions missing.
- **An app whose service principal could not be read during a security audit is no longer
  scored as clean.** When the per-app service-principal lookup failed (a Graph outage that
  outlasted the retries), the audit carried on without it: the admin-consent and disabled-sign-in
  rules lost their input, and a mailbox permission scoped through Exchange RBAC was never checked
  against a surviving org-wide grant — yet the run reported itself complete and was cached for an
  hour. The app is now counted among those that could not be scored, the run carries the "some
  applications could not be scored" caveat and is not cached, and a session that expired during
  the lookup stops the run for re-sign-in instead of being ignored.
- **Exporting an incomplete audit writes that run, with its caveats.** Only a cancelled run handed
  its own results to the exporter; a truncated or degraded run — never cached — was exported from
  the cache instead, so the file either failed with "no cached audit" or held an earlier complete
  scan presented as the current one.
- **The security audit says what it is doing before it starts scoring.** The first phase reads the
  tenant's app registrations, service principals, consent grants and role assignments, and is the
  longest part of a large run; during it the progress readout showed "0 / 0 apps (cap: 8)" over an
  empty bar. It now reads "Reading tenant-wide directory data…" until the app count is known.
- **A tenant with more than 5,000 SharePoint sites no longer gets its site scan reported — and
  cached — as complete.** The `Sites.Selected` reverse lookup enumerates sites up to a 5,000-site
  safety cap and silently stopped there: the Sites tab read "scanned 5000 of 5000 sites", the result
  was cached for an hour, and "Sites this app can reach" affirmatively answered "no per-site grants"
  for an app whose grants sat on a site past the cap. The cap is now a stated coverage caveat: the
  summary line, the per-app panel and the CSV/JSON export say the scan stopped at the cap, an empty
  per-app list reads as "not proof the app has none", and the cached result carries the caveat
  instead of posing as a complete answer.
- **A SharePoint URL you lack rights to is no longer reported as "did not resolve to a list,
  library or item".** When the Grant-access wizard probed for a subsite and SharePoint answered 403,
  401 or a throttle, every one of them was collapsed into that message — steering you to fix a URL
  that was fine and bypassing the Full Control remediation the 403 should have carried. Only a 404
  now means "not a subsite"; anything else surfaces with its own code and, for a 403, the
  requirement it actually names.
- **Editing an app's SAML URLs, OIDC redirect URIs or claims mapping, and the bulk "Remove expired
  credentials" sweep, no longer force a re-scan of the whole tenant.** Each of those changes one
  app in place, yet they dropped the two tenant-wide directory indexes (every app registration and
  every service principal) that the App Registrations, Enterprise Apps and search surfaces join
  against — so the next list visit re-enumerated the tenant (tens of seconds on a large one) for a
  change that touched neither. They now bust only what they changed: the affected app's detail
  payload, its list row, the credential-expiry board and the audit, exactly as the per-app
  credential actions already did.
- **"Fix all" and the bulk "Remove expired credentials" action read only the selected apps.** The
  sweep walked every page of the tenant's app registrations (to the same 10 000-app ceiling the
  lists use) and then discarded everything but the selection; a selection now arrives in a handful
  of batched reads, with the full walk reserved for the tenant-wide sweep. An app that could not
  be read is listed among the failures instead of silently left out.
- **The Grant-access picker's "Tenant app registrations" group reflects app-role changes at
  once.** Exposing an app's first Application role (or removing its last) on the App roles tab,
  and creating or deleting an app, left the cached directory untouched for up to an hour, so a
  freshly published API was missing and a deleted app lingered. Those writes now refresh it.
- **Assigning an Azure role to a managed identity refreshes the Key Vault access view.** The "who
  can touch this vault?" sweep was cached for an hour and not cleared by the app's own role
  assignment, so a role granted from the Managed Identities pane was invisible there until the
  cache expired. The assignment now drops the cached sweep; the next visit re-runs it.
- **The audit now sees the newer mailbox permissions Exchange RBAC can scope — `MailboxItem.*`,
  `MailboxFolder.*`, `MailboxConfigItem.*`, `MailTips.ReadBasic.All` and
  `Mail-Advanced.ReadWrite.All`.** An org-wide Microsoft Graph grant of `MailboxItem.ReadWrite.All`
  or `Mail-Advanced.ReadWrite.All` — read, write and delete every item in every mailbox — raised no
  mailbox finding, offered no Scope fix and scored zero, because the advisory's name test only knew
  `Mail.`/`MailboxSettings.`/`Calendars.`/`Contacts.` and the risk tables listed none of them. They
  now enter the "Organization-wide mailbox access" finding with the one-click Scope fix, appear in
  the Grant-access wizard and the Permissions-tab Scope column, and the write and export variants
  score high (`MailboxItem.ReadWrite.All`, `MailboxItem.Export.All`, `MailboxItem.ImportExport.All`,
  `MailboxFolder.ReadWrite.All`, `Mail-Advanced.ReadWrite.All`) with the read variants medium
  (`MailboxItem.Read.All`, `MailboxFolder.Read.All`); `MailboxConfigItem.*` and
  `MailTips.ReadBasic.All` are advisory only. The legacy Application Access Policy migration
  deliberately still targets only the permissions a policy could confine, so it never narrows a
  grant the policy never governed. **This shifts risk ranking** for any app holding these grants.
- **The EWS `full_access_as_app` scope finally gets a mailbox-scope verdict.** The resolver
  re-derived every permission's Exchange role against Microsoft Graph, which has no such permission,
  so the row was dropped before the probe: the Permissions tab showed "Unknown" forever for an app
  declaring only the EWS scope (after paying the Exchange round trip), and the audit scored a
  correctly RBAC-scoped `Application EWS.AccessAsApp` grant at full org-wide weight. The resolver now
  carries the role its resource-aware callers already computed, so the row reads Org-wide or Scoped
  like any Graph row and a scoped EWS grant earns the reduced scoped weight. **Affects audit scores
  and the Scope column.**
- **Long-running scans keep backing off for as long as Microsoft Graph keeps throttling them.**
  The adaptive concurrency cap behind the security audit, bulk actions, the site sweep and the DR
  backup was meant to halve on every burst of 429s until a single request at a time was left, then
  recover once the tenant went quiet. In practice it halved exactly once: every throttled reply,
  including the retries of one hot request, re-opened the two-second "one halving per burst" window,
  so a sustained storm held the cap at half and burned the retry budget instead of easing off. The
  window is now anchored on the last actual halving. Separately, two of these runs on the same tenant
  at once — an audit still scoring while a backup finished, say — shared one observer slot, and the
  run that finished first switched off the other's back-off for the rest of its life; a finishing
  run now detaches only its own tracker, and the survivor keeps adapting.

- **The permission tester no longer reports "No access" when it couldn't read the app's grants.**
  If Microsoft Graph failed while the tester was reading an app's app-role assignments, a mailbox
  check could answer "No access" and state that no organization-wide mailbox permission was granted,
  and a SharePoint check could state that the app held no organization-wide SharePoint grant — even
  for an app holding `Mail.Read` or `Sites.Read.All` tenant-wide. Both now answer "Couldn't
  determine" and say the assignments couldn't be read. An app with no service principal in the
  tenant is still reported as having no access.

- **"Who can reach this mailbox?" now finds apps holding EWS `full_access_as_app`.** The Resource
  Access Mailboxes tab looked for candidates only among Microsoft Graph grants, so an app whose only
  mailbox grant was the legacy Exchange Web Services full-access permission, which reaches every
  mailbox, was missing from the list or shown as "No access". Those apps are now listed as
  organization-wide, matching the permission tester and the security audit.

- **The Mailboxes tab now says when Exchange couldn't be used.** It reported Exchange as available
  whenever you were signed in, even without Exchange consent, so its "verdicts derive from the Entra
  grants alone" note never appeared. It now checks the Exchange sign-in first, and also says when
  Exchange's service-principal list couldn't be read, because apps granted access only through
  Exchange RBAC are then missing. Both notes are included in CSV and JSON exports.

- **The security audit now says when it couldn't check mailbox scoping.** When Exchange couldn't be
  queried, every mail permission is scored as organization-wide so risk is never under-reported, but
  nothing said so: apps already confined through Exchange RBAC were listed under "Org-wide mailbox
  access" with a Scope fix that needs the same Exchange access. That group now shows a note, and
  CSV, JSON and HTML exports carry the same sentence. The run is still cached.

- **The tenant setup screen no longer accepts a domain it can't sign in with.** Entering a domain
  such as contoso.onmicrosoft.com as the Directory (tenant) ID was saved without complaint, but every
  sign-in then failed after the browser step, because Entra identifies the tenant by its GUID. The
  screen now asks for the GUID from the app registration's Overview page. An install already set to
  a domain says so before opening the browser. A GUID typed in capitals now works too: it used to fail
  the same way, because Entra reports the tenant GUID in lowercase.

- **A failed sign-out no longer leaves the app half signed out.** If the OS credential store refused
  to delete the saved sign-in, the app had already dropped the session. Every action then failed as
  "not signed in" while the error said you were still signed in, and the next launch restored the
  session you had tried to end. The saved sign-in is now deleted first, so a failed sign-out leaves
  you signed in and Sign out can be retried.

- **Re-authenticating no longer gets undone by a slow request.** A token refresh that was still
  waiting on the network when you re-authenticated could fail afterwards and delete the new sign-in,
  putting you back on the Re-authenticate prompt. It now leaves the newer sign-in alone.

- **A managed identity's Azure roles no longer list a management-group role once per
  subscription.** Azure returns a role assigned at a management group (or the tenant root) with every
  subscription beneath it, so an identity with Reader on a management group over 20 subscriptions
  showed 20 identical rows, each labelled with a different subscription, and the high-privilege
  roles looked 20 times more widespread than they are. Each assignment is now shown once, and one
  made above the subscription level is labelled "(inherited from above the subscription)" instead
  of borrowing a subscription's name.

- **Vault access now marks roles inherited from a parent scope instead of calling them direct.**
  The Key Vault sweep said it listed only roles assigned on the vault itself, but Azure also
  returns roles inherited from the vault's resource group, subscription and management group, so a
  subscription Owner appeared as a per-vault grant. Those rows are now marked Inherited (hover for
  the scope they come from), the export has an Inherited column, and the panel text describes what
  is actually listed.

- **Observed Graph usage is no longer built on a partial Log Analytics result.** When a usage query
  hit a Log Analytics limit, the service returned the rows it had with a "PartialError" warning,
  which the app ignored. The panel could then show fewer call patterns than the app really makes,
  and suggest removing a permission it still uses. A partial result now shows an error asking you
  to retry, instead of an incomplete summary.

- **Access Readiness accepts Reader, Contributor or Owner on the Log Analytics workspace for usage
  analysis.** The guidance already said "Log Analytics Reader (or Reader)", but the checklist
  counted only the two Log Analytics roles, so an operator with plain Reader saw "?" instead of a
  confirmed role.

- **Key Vault no longer shows the previous tenant's secrets after you switch tenants.** The Key
  Vault page kept the last vault name and its list of secret names, content types and expiry dates
  when you switched tenant or signed out, so the next tenant's Key Vault page opened on another
  tenant's listing, and Reveal sent the old vault name with the new tenant. Switching tenant or
  signing out now clears the page, and a listing that finishes after you switched is discarded.

- **The creation-date filter on the App Registrations and Enterprise Applications lists now resets
  when you switch tenants.** A date range set in one tenant kept filtering the next tenant's list,
  with the filter drawer collapsed so only the small active-filter badge hinted why apps were
  missing. It now clears with the search and facet filters.

- **The app now starts when it cannot write its log folder.** If the log folder could not be
  created or written (a read-only or redirected profile folder, a locked-down kiosk account), the
  app closed at launch with no window, no error and no log to explain why. It now opens and logs to
  the console instead.

- **Log and settings folders are readable by your account only on macOS and Linux.** The logs
  record tenant IDs, app names and Microsoft Graph error details, but their folder was created with
  default permissions, so on a shared machine other accounts could read two weeks of them. The app
  now creates both folders, and tightens existing ones, so that only your account can open them.

- **Refresh on the Managed Identities page now shows a managed identity created since the list
  loaded.** The list is built from the tenant's cached service-principal index, but Refresh cleared
  only the list itself, so it was rebuilt from that same index and a new managed identity stayed
  missing for up to an hour, or until you refreshed App Registrations or Enterprise Apps. Refresh now
  re-reads the service principals, as those two pages' Refresh already did.

- **Adding or removing a secret or certificate while the Credential expiry list is loading no longer
  leaves the list out of date for an hour.** The list stored the scan it had started before your
  change, so a removed secret still showed as expiring. That scan is now discarded, and the list is
  no longer dropped from the cache during heavy browsing on a large tenant.

- **Screen readers can tell repeated row actions and filter fields apart.** Every trash button in a
  permissions table announced the same name, such as "Revoke application permission", and every
  Remove in the Expose an API tab just "Remove", so you had to count rows to know which grant or URI
  you were about to remove.
  Each now names its row, for example "Revoke application permission Mail.Read on Microsoft Graph",
  and so do the Remove and Delete buttons on credentials, owners, federated credentials, default
  owners, claims, app roles, assignments, groups and expired SAML certificates. The Created before
  and Created after date filters, the saved-view name box and each permission checkbox in the grant
  picker now have a name too. A table's unlabelled action column, including on the tenant-wide
  dashboards, is announced as Actions.
- **The bulk Delete confirmation no longer says deleted apps are gone for good.** It said "This
  cannot be undone", but Entra keeps a deleted app registration for 30 days, and the Delete dialog on
  an app's own page already says so. Seeing that warning after deleting the wrong apps, you could
  recreate them, which gives each a new application ID and breaks everything that signs in with the
  old one. The bulk panel now says deletion can be undone from the Entra admin center within 30 days.

### Changed

- **Counts in toasts, confirmations, bulk-action summaries and the disaster-recovery plan read "1
  app" and "3 apps" instead of "app(s)".** These are the lines you paste into a change ticket.
  Where a verb follows the count it now agrees too, e.g. "1 app was never attempted", "2 enterprise
  apps need manual follow-up".
- **Settings, the permission picker, the Cache dialog and the managed scope group panel show
  placeholder rows while they load,** like the other pages, instead of a spinner or a bare
  "Loading…".
- **The sample Azure custom role no longer grants deleting Key Vault secrets.**
  `docs/operator-rbac/azure-custom-role.json` included
  `Microsoft.KeyVault/vaults/secrets/deleteSecret/action`, but the app never deletes a secret: it
  lists and reads secrets and writes a new version when it rotates a credential. If you created the
  role from that file, you can remove that permission.
- **Audit CSV exports put a service principal's home tenant in its own column.** For enterprise
  apps with no local registration, and for managed identities, the Publisher column held the owning
  tenant's ID. App registrations put their publisher domain there, so filtering or sorting on
  Publisher mixed the two. Publisher is now empty on those rows, and the tenant ID is in a new last
  column, AppOwnerOrgId, named as in the Enterprise Applications export.
- **Rotating a SAML signing certificate immediately, and retiring the previous one, now ask
  first.** An immediate rotation stops sign-in for any application that holds a single static
  certificate, and retiring removes your only rollback. Both ran on one click, unlike every other
  destructive action in the enterprise app pane. Rotating now asks you to type ROTATE; retiring
  asks for confirmation. Removing an expired certificate is still one click.
- **The SSO tab opens with about half the Microsoft Graph requests.** Opening it read the service
  principal, its application and its claims policy, then read them all again for "Details for the
  application owner", and read the service principal a third time for the signing-certificate
  panel. One read now fills the whole tab.
- **Home and the App Registrations list load from one scan of your app registrations instead of
  three.** On a cold start, the App Registrations, Enterprise Apps and Credential Health cards each
  paged through every app registration on their own (18 serial requests on a 5,000-app tenant, two
  of them fetching every secret and certificate). One scan now feeds all three. Opening App
  Registrations while Home is still loading waits for that scan instead of starting another scan of
  every app registration and every service principal. Moving between the security audit and the
  Application permissions consent view also no longer re-reads every application-permission grant
  in the tenant, and permission changes now always check an app's current grants instead of a copy
  up to an hour old. Changes made in the app show up in both views at once; an application
  permission granted or revoked outside the app (for example in the Entra portal) can take up to an
  hour to appear there, or until you clear Permissions in the Cache dialog. The Enterprise Apps
  Access tab and the permission tester still read assignments live.
- **Home's Security Posture card no longer loads the whole security audit.** To show a few counts
  it received every scored app from the last scan (tens of megabytes on a large tenant), and it
  loaded it again after every scan, while the Security tab kept a second copy. Home now receives
  only the counts, so it updates straight after a scan and uses less memory.
- **Items parked in the Open dock no longer load when you sign in.** Every parked app
  registration, enterprise app and managed identity used to fetch its full details from Microsoft
  Graph at launch, for panes you had not opened: up to eight apps' worth of requests competing with
  Home's scans. A parked item now loads the first time you open its chip, and stays loaded after
  that.

- **The Cache dialog can clear each cache on its own.** Service principal, permissions, audit and
  list entries each get a Clear button in their row, so dropping a stale audit result no longer
  means clearing everything and rebuilding the tenant-wide indexes. The on/off button now says what
  it will do ("Disable cache" / "Enable cache") instead of "Toggle enabled".

- **On Windows, logs are now written to `%LOCALAPPDATA%\azapptoolkit\logs`.** They were in
  `%APPDATA%` (Roaming), which roaming profiles copy between machines at every sign-in and sign-out.
  Settings stay in `%APPDATA%\azapptoolkit`, and the old `%APPDATA%\azapptoolkit\logs` folder can
  be deleted.

- **Log files now say more about where they came from.** Each line names the component that wrote
  it, and the first lines of a run record the OS, architecture, build type, cloud, tenant, and
  whether the client and tenant IDs came from an environment variable, settings.json or the build.
  A log excerpt attached to a bug report no longer needs these asked for separately.

- **The window reads backend replies and progress updates through JSON.** `tauri-sys`, the
  frontend's bridge to the backend, moves to upstream `571cef4`. That version decodes every reply
  and event via JSON instead of `serde-wasm-bindgen` — upstream's workaround for a reported webview
  crash ("Out of bounds table access") in Tauri + Leptos apps that decode many events, such as the
  per-app progress of a tenant-wide audit or bulk fix. A progress update the window can't read is
  now skipped instead of stopping the window.

- **Release builds ship a minified stylesheet and page.** The 121 KB stylesheet was bundled as
  written; Trunk now minifies it (and `index.html`) in release and Pages builds, taking it to 69 KB
  (28 KB → 11 KB compressed). The script that loads the app is unchanged: Trunk's minifier cannot
  parse it and ships it as written.
- **Bulk "Scope mailbox access" can now search for groups, and so can a permission's advanced "scope
  to existing groups" form.** The per-app Scope… dialog and the Grant access wizard already had the
  typeahead; these two were bare text boxes, and the bulk one applies the same groups to every
  selected app. All four places now use the same search and placeholder.

### Security

- **The app window can no longer contact Microsoft endpoints or install an update by itself.**
  The app's backend makes every Graph, sign-in, Key Vault and Azure Resource Manager call, but
  the window's content security policy still allowed it to reach 13 Microsoft hosts. Its
  permissions also let it download and install an update without the Update & restart prompt.
  Neither was used. The window can now only talk to the app itself, and update checks and file
  dialogs still run through the backend as before. A link in the release notes becomes clickable
  only when it is an https address.
- **Subscription, workspace and scope IDs that Azure Resource Manager sends back are now checked
  before the app uses them in a request.** A role-definition ID already had to be a plain ARM path,
  but a subscription ID, a Log Analytics workspace ID or a Key Vault's resource ID from the same
  responses went into the request address unchecked, so a `?`, `#` or `..` in one could change
  which address the app called with your token. Subscription and workspace IDs must now be GUIDs,
  and scopes must be absolute ARM paths without `?`, `#`, `%`, `\` or `..`. Anything else is
  refused before the request is sent, and that subscription or vault is skipped.

## [0.30.2] - 2026-09-25

### Changed

- **Rust toolchain moves 1.98.0 → 1.98.1** (the MSRV stays 1.98). `rust-toolchain.toml` and the six
  `dtolnay/rust-toolchain` SHA pins across CI, CodeQL, the Pages demo and the release matrix advance
  together, so every build runs on the same compiler as a local `just verify`. `tauri-cli` moves
  2.11.4 → 2.11.5 in the release workflow and both `setup` scripts.
- **Semver-compatible dependency refresh across both lockfiles.** `tauri` 2.11.5 → 2.11.6,
  `tauri-plugin-updater` 2.11.0 → 2.12.0 (the auto-update client), `rand` 0.10.2 → 0.10.3, the
  TLS-adjacent `hyper-rustls` 0.27.9 → 0.27.10, `hyper-util` 0.1.20 → 0.1.21 and
  `rustls-platform-verifier` 0.7.0 → 0.7.1, and `wasm-bindgen` 0.2.128 → 0.2.129 with its companions
  in the frontend. The deliberate holds are unchanged (`p12-keystore` 0.2.x, since 0.3 still needs
  `cms 0.3.0-pre.2`; `sha2` 0.10). `cargo audit` and `cargo deny` pass on both trees.

## [0.30.1] - 2026-09-14

### Security

- **The TLS stack every Graph, Exchange, Key Vault and ARM call rides on is patched.**
  RUSTSEC-2026-0285 (published 2026-09-14, severity 5.3) had rustls accepting TLS 1.3
  handshake messages across encryption level boundaries; 0.30.0 shipped the affected
  0.23.43. This build carries 0.23.45 — a patch bump inside the same 0.23.x line, still
  on the aws-lc-rs backend, with no other change to how the app talks to Azure.

## [0.30.0] - 2026-09-02

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
