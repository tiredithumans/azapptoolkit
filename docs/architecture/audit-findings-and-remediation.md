# Security audit: scoring, findings & remediation

Deep-dive companion to the audit gotchas in [AGENTS.md](../../AGENTS.md). Read this before editing
`azapptoolkit-core::audit`, `commands::audit`, `commands::remediation`, `commands::bulk`, the
`ScopeWizard`, or the Security workbench's findings/filters. The scoping mechanisms the audit reasons
about are in [exchange-scoping.md](./exchange-scoping.md) and
[sharepoint-selected.md](./sharepoint-selected.md).

## Rule catalog

`score_application` folds the numbered rules in this order (helpers in `audit/scoring.rs`, markers
in `audit::issue`, finding keys in `audit/finding.rs`, weights in `audit/permissions.rs`). A rule
that is "advisory" adds issues/recommendations but no score. Provenance says only what the code or
tests cite — the legacy PowerShell module is not vendored here (see `audit/mod.rs`).

| Rule | Helper | Score | Issue marker | Finding key | Fix | Provenance |
|---|---|---|---|---|---|---|
| 21 | `rule_disabled_by_microsoft` | +15 flat (folded **first**, despite the number: alone it reaches High) | `DISABLED_BY_MICROSOFT` | `disabled_by_microsoft` | — (delete/disable is admin-judged) | net-new |
| 22 | `apply_service_principal_risk` (runner post-pass, **before** the unused post-pass) | +20 flat (alone it reaches High; stacks any other finding to Critical) | `RISKY_SERVICE_PRINCIPAL` | `risky_service_principal` | `DisableSignIn` (shared with the unused post-pass — deduped to one per row) | net-new |
| 1 | `rule_app_permission_risk` | +25 per tier-0 grant (`TIER0_APP_PERMISSIONS`: one alone is Critical, scored INSTEAD of high — the lists are disjoint); +10 per org-wide high-risk grant (+3 if mailbox-confined) | `HIGH_RISK_APP_PERMS` (the tier-0 line carries it too, worded "tier-0 (a direct path to Global Administrator)") | `high_risk_perms` | — | `Constants.ps1:104-115`; the tier-0 tier is net-new (three of its entries are promoted ported high entries); net-new entries marked in `permissions.rs` |
| 2 | same | +5 per org-wide medium-risk grant (+2 if confined) | none | — | — | `Constants.ps1:123-130`; net-new entries marked |
| 3 | `rule_admin_consent` | +5 flat | none | — | — | not cited |
| 4 | `rule_sp_disabled` | +2 | none | — | — | not cited |
| 5 / 6 | `rule_credentials` | +8 all expired / +4 mixed | none (structured `credential_status`) | `expired` | `RemoveExpiredCredentials` | not cited |
| 7 | same | +3 flat (secrets and certificates) — lifetime past 365 days in WHOLE days with one day of grace (`> 366`), so a one-year credential backdated an hour or spanning 29 February is not long-lived; a credential with a start but no end date is | none | — | — | `Credential-Analysis.ps1:169` (whole-day grace and no-end-date are net-new) |
| 8 / 9 | same | +3 all expiring / +2 mixed (only when none expired) | none | — | — | threshold `Constants.ps1:202` |
| 10 | `rule_stale_app` | +2 (older than `STALE_APP_DAYS`) | none | — | — | `MaxAuditHistoryDays` in `Constants.ps1` |
| 11 | `rule_mailbox_advisory` | advisory | `ORG_WIDE_MAILBOX`, `LEGACY_MAILBOX_POLICY`, `UNSCOPABLE_LEGACY_MAILBOX`, `UNCONFINABLE_MAILBOX`, `SCOPED_VIA_RBAC` (contains) | `orgwide_mailbox`, `legacy_mailbox_scope`, `unscopable_legacy_mailbox`, `unconfinable_orgwide`, `scoped_mailbox` | `ScopeMailboxAccess`, `MigrateApplicationAccessPolicy` | `Resource-Analysis.ps1::Add-ExchangePermissionAnalysis` |
| 12 | `rule_sharepoint_advisory` | advisory | `ORG_WIDE_SHAREPOINT`, `UNCONFINABLE_SHAREPOINT`, `ORG_WIDE_FILES`, `SCOPED_SHAREPOINT` | `orgwide_sharepoint`, `unconfinable_orgwide`, `orgwide_files`, `scoped_sites` | `ScopeSharePointAccess` (Sites only — the Files advisory has no fix) | not cited |
| 13 | `rule_high_risk_delegated` | advisory | `HIGH_RISK_DELEGATED_PERMS` | `high_risk_delegated` | — | list `Constants.ps1:104-130`; the broad-prefix half (`is_risky_delegated_scope`, every Selected scope excluded) is net-new |
| 23 | `rule_granted_undeclared` | advisory (the grants themselves are weighted by Rules 1/2 — the runner merges them into `app_role_grants`) | `GRANTED_NOT_DECLARED` | `granted_undeclared` | — (revoking a deliberate grant is admin-judged) | net-new |
| 14 | `rule_app_hygiene` | advisory | `NO_OWNERS`, `SINGLE_OWNER` | `ownership` | `AddOwner` | not cited |
| 15–17 | same | advisory | `INSTANCE_LOCK_DISABLED`, `PUBLIC_CLIENT_CREDENTIALS`, `PREFER_CERT_OVER_SECRET` | — | — | net-new (tests' "Tier-2 advisory rules") |
| 18 | `rule_redundant_permissions` | advisory (the narrower grant keeps its Rule 1/2 weight) | `REDUNDANT_APP_PERMS` | `redundant_perms` | `RemoveRedundantPermissions` | not cited |
| 19 / 20 | `rule_external_exposure` | +3 audience / +2 unverified publisher | `MULTITENANT_AUDIENCE`, `UNVERIFIED_PUBLISHER` | `external_exposure` | — | not cited |
| — | `rule_downgrade_pointers` | recommendation only | none | — | — (Downgrade… is admin-judged) | not cited |
| runner | `unused_app_advisory` (sign-in post-pass) | advisory | none (structured `unused`) | `unused` | `DisableSignIn` | net-new |
| runner | `unused_credential_advisory` (credential-usage post-pass, **Application rows only**) | advisory | `UNUSED_CREDENTIAL` | `unused_credential` | — (removing a credential is admin-judged) | net-new |
| per-app | `secret_lifetime_advisory` (against the app-management policy cap, **Application rows only**) | recommendation only (no marker, key or score) | none | — | — | net-new (rides beside the Rule 7 floor; no ranking change) |

Risk levels: Critical ≥ 25, High ≥ 15, Medium ≥ 8 (`Constants.ps1:207-213`).

**Tier-0 vs high.** `TIER0_APP_PERMISSIONS` holds the grants that are, alone, a path to Global
Administrator or tenant takeover (PIM and role writes, `AppRoleAssignment.ReadWrite.All`,
`Application.ReadWrite.All`, `Policy.ReadWrite.PermissionGrant` / `.ConditionalAccess`,
`Domain.ReadWrite.All`, `UserAuthenticationMethod.ReadWrite.All`). Borderline values stay in the
high list with the reason written on the constant — `Directory.ReadWrite.All` and the
user/group writers can't touch role membership (their remaining path detours through Azure RBAC
on an ordinary group), `Application.ReadWrite.OwnedBy` is limited to owned apps, and the rest
need a precondition or another grant. `risk_level_for_app_permission` answers `Critical` for
tier-0, so the per-permission badge reads "Tier-0"; the consent-grants view folds it into its
`high` facet.

**Granted, not just declared (Rule 23).** An app registration is scored on what its SP *holds*:
`score_one` merges the SP's granted roles from the run's tenant-wide matrices
(`ScoreCtx::granted_roles_by_sp` — Graph plus Office 365 Exchange Online and SharePoint Online,
each carrying its resource) into `app_role_grants` via the pure `merge_granted_roles`, before the
mailbox-scope probe and every rule. The undeclared ones also land in
`AppPermissions::undeclared_grants`, which drives the Rule 23 advisory naming each with its
resource. Undeclared grants are **scored only**: Rules 11/12/18 and the downgrade pointers read
`AppPermissions::declared_view()` (undeclared grants taken back out), because their Fixes
re-plan from the live manifest — an undeclared grant there offered a Remove-redundant Fix that
removed nothing, or a Scope Fix that refused (`no_scopable_permission`) or scoped the declared half
while the undeclared org-wide grant kept its reach. Rule 23's revoke-or-declare advice is their
one home. A grant on a declared resource whose permission index failed to resolve is merged for
scoring but never labelled undeclared (its declarations were what failed — the run already
carries `PermissionResolution`).

SP-only rows run
Rules 1–4, 11–13 and 21–22 plus the risky-SP and sign-in post-passes (not the credential-usage
one: a service principal carries no local credentials to judge; see
[SP-only principals](#sp-only-principals-in-the-audit-no-local-application)).

## Scope-aware audit risk

Mail/calendar/contacts application permissions are scopable via Exchange RBAC for Applications, so
their *effective* risk depends on whether they're confined to specific mailboxes.
The two-resource permission mapping, the legacy-AAP migration and the Exchange grant core are in
[exchange-scoping.md](./exchange-scoping.md).

**The `mail_scopes` map.** `score_application` reads `AppPermissions.mail_scopes` (a
`value → MailPermissionScope` map in `azapptoolkit-core::audit`): a permission confirmed `Scoped`
earns a reduced weight (high 10→3, medium 5→2) and a positive Rule-11 note instead of the org-wide
advisory. An **empty** map (the default) means scoping wasn't resolved — every mail permission
scores at its full org-wide weight, i.e. byte-for-byte the pre-scope behavior, so the non-mail
rules keep PowerShell parity.

**Unresolved scoping is said, not hidden (`mailbox_scoping_resolved`).** The degrade below never
under-reports, but it leaves apps Exchange already confines listed under "Org-wide mailbox
access" with a Scope fix that needs the same Exchange access. So the run records
`AuditRunResult.mailbox_scoping_resolved = false` when there was no Exchange client, the legacy
AAP read failed (`prefetch_legacy_access_policies` reports it), or any app declaring a scopable
mail permission went unprobed (the breaker was open or its probe failed — `ScoreCtx`'s
`mail_scoping_unresolved`). It is **not** a `degraded` gap: the fallback over-reports, so the run
is still cached (the sign-in-report precedent) and `is_complete()` ignores it — but the flag rides
the cache entry (`CachedAuditRun`), the export coverage and every export format, and the one
sentence `dto::audit::MAILBOX_SCOPING_UNRESOLVED` is shared by the export's coverage notes and the
Callout on the org-wide mailbox group.

**Bulk vs. detail resolution.** `run_audit` resolves the map on **every** run (best-effort — it
degrades to the empty-map org-wide scoring when the signed-in user lacks Exchange-admin rights, so
no toggle is needed). The resolver (`commands::exchange::resolve_mail_scopes`, authoritative via
`Test-ServicePrincipalAuthorization`) **returns `Result`**:

- The bulk-audit caller (`enrich == false`) swallows any error (empty map → scored org-wide,
  never under-reported). An **auth** failure (401/403) additionally trips a run-wide circuit
  breaker — it would recur for every remaining mail app, each a doomed 1-5s cmdlet POST — so the
  rest of the run skips the probes; scoring is identical to the swallowed-error path, and the
  next run probes afresh ("resolved on every run" still holds).
- The per-app detail commands (`get_mail_permission_scopes` / `get_mail_scopes_for_principal`,
  `enrich == true`) instead *resolve* most probe failures rather than propagating them: a
  **missing-principal** error (a managed identity — or any SP never registered in Exchange RBAC —
  isn't in Exchange's SP store, so the cmdlet can't resolve it) means the SP has no RBAC scope ⇒
  `OrgWide`, unless a `RestrictAccess` legacy AAP confines it ⇒
  `Scoped { LegacyApplicationAccessPolicy }`. Only a *genuine* 403/consent failure (the user holds
  the Entra Exchange-Admin role but lacks the effective EXO "Role Management" RBAC role — see
  `ExchangeError::ui_hint`) **propagates**, so the UI shows the reason + a "Grant consent / Retry"
  affordance (the app-reg Permissions tab **and** the MI detail view) instead of silently painting
  every row "Unknown".

**Org-wide-grant reconciliation.** `Test-ServicePrincipalAuthorization` sees **only the Exchange
RBAC layer** — it deliberately excludes app-role grants made in Entra. A scoped RBAC verdict
coexisting with an un-stripped org-wide Entra grant still reaches every mailbox, so verdicts are
reconciled against `held_orgwide_mail_grants` (`reconcile_orgwide_grant` in
`commands::exchange`): scoped-RBAC + surviving org-wide grant ⇒ `OrgWide`. The one exemption is a
legacy AAP, which genuinely confines an org-wide grant. This is what catches "scope created but
org-wide grant never removed".

**Legacy Application Access Policies (AAP).** The detail path resolves the legacy AAP up front
(`enrich`-gated, so the *per-app probe* never pays the extra call) — keyed only on appId via an
independent cmdlet, so it overrides an org-wide RBAC verdict **and** answers when the probe itself
errors (the MI case, where the old code propagated before the AAP was ever read). A
`RestrictAccess` AAP yields `Scoped { mechanism: LegacyApplicationAccessPolicy }` (`DenyAccess` is
a blocklist → still org-wide). The missing-principal→`OrgWide` vs. propagate decision is the pure
`scope_from_rbac_error`, with `ExchangeError::is_missing_object` distinguishing the two failure
modes. `MailPermissionScope::Scoped` carries a `ScopeMechanism`
(`Rbac` | `LegacyApplicationAccessPolicy`) so the badge can label legacy scopes and nudge
migration.

**The audit gets the same verdict from ONE tenant-wide read, not N per-app ones.** A policy gates a
whole application, so `Get-ApplicationAccessPolicy` answers for every app in the tenant at once:
`run_audit` fetches it alongside its other tenant-wide reads (`prefetch_legacy_access_policies`,
best-effort — Exchange unavailable ⇒ empty map ⇒ today's org-wide scoring) and folds it in with the
pure `apply_legacy_policy_verdict`. Three invariants:

- **It is applied by the caller, after `resolve_mail_scopes_audit_cached`**, so that cache keeps
  holding the *pure RBAC* verdict and the audit's cache warmth still can't leak into the Permissions
  tab's (the reason the two use separate keys in the first place).
- **It fills `OrgWide` and *missing* verdicts, never a `Scoped { Rbac }` one** — an app that already
  migrated keeps its RBAC verdict. Filling a missing verdict is the same call `scope_from_rbac_error`
  makes: a policy keyed on this exact appId is stronger evidence than a probe that failed or never ran
  (breaker open, Exchange down, MI absent from the Exchange SP store), which is why it is applied
  *outside* the per-app Exchange block.
- **Phase 2 (SP-only rows) gets it too, and only it.** Their RBAC verdict is deliberately never
  resolved (a held mail value there IS an un-stripped org-wide grant, and grant ∪ RBAC is always
  org-wide), but an AAP *does* constrain that Entra grant — so a confined foreign app / managed
  identity would otherwise be reported org-wide.

Rule 11 then splits its scoped bucket by mechanism (`AppPermissions::scope_mechanism`, the single
read of `mail_scopes`): RBAC keeps the positive `SCOPED_VIA_RBAC` advisory, legacy gets
`issue::LEGACY_MAILBOX_POLICY` plus the `MigrateApplicationAccessPolicy` remediation. **Rules 1 & 2
split the same way** (`push_scoped_risk_issue`) — the score is identical (both mechanisms genuinely
confine, so both earn the reduced weight), but the *wording* must differ: that advisory also carries
`SCOPED_VIA_RBAC`, and the UI matches it mid-string to fill the **healthy** "Mailbox access scoped"
group. Emitting it for a legacy policy files the row under a positive signal and buries the
migration finding raised for the very same permission.

## The scope registry + the mechanism-dispatched wizard

Scoping is a **family of independent authorities**, unified behind one classifier and one UI shell:

- **Registry** (`azapptoolkit-core::scoping`): `ScopeKind` (Exchange / SharePoint / SharePointItem,
  room to grow) + `scope_kind_for(resource, value) -> Option<ScopeKind>` (the single, resource-aware
  "what mechanism, if any?" decision) + metadata (`capability_key` / `admin_applicable`).
  `admin_applicable() == false` is reserved as the seam for future owner-consented mechanisms
  (Teams/Chat RSC), where the UI should render guidance instead of an apply — **the wizard does not
  read it yet**, so a mechanism that returns `false` must wire that in first.
- **Wizard** (`web-rs/components/scope_wizard.rs`) — the single **"Grant access"** button on every
  principal's Permissions surface. It **subsumes the old inline "Add permission" picker** — there is
  no separate single-grant picker. Uniform shell: **select permissions → choose access → review &
  grant**. Step 1 is the **full live catalog** (the reusable multi-select `PermissionPicker`, every
  resource + Application/Delegated; **`ApplicationOnly` for a bare SP**, whose org-wide grant is
  app-role-only) used as a cart — the wizard owns `selected: Vec<PickerSelection>` and the picker
  emits toggles. `mechanism` is `Some(kind)` only when the cart is non-empty *and* every item is an
  Application permission mapping to the **same** `ScopeKind`; delegated / mixed / non-scopable ⇒
  `None` ⇒ org-wide only. Step 2 **dispatches the target panel and the apply by `ScopeKind`**.
  **One mechanism per run**; a held org-wide row's **"Scope…"** opens it *pre-seeded* with the full
  `PickerSelection`. The de-emphasized **org-wide** path falls back to `grant_single_permission` per
  item (app reg) / `grant_managed_identity_permission` grouped by resource (bare SP).

Per-mechanism apply (each does grant-before-strip, so a failure never strands the principal):

- **Exchange** — declare-only: `declare_app_permission` per permission using the cart's id
  (manifest only, **no** runtime grant) then `grant_exchange_mailbox_access(Some([…]))` /
  `grant_managed_identity_scoped_exchange_access` with `remove_unscoped=true`. RBAC for
  Applications authorizes independently of the Entra grant — reach is the **union**, so leaving an
  org-wide Entra grant in place defeats the scoping. Targets: `ManagedScopeGroupPanel` (mailbox
  group membership) or existing groups.
- **SharePoint** — `commands::sharepoint::convert_site_access_to_selected` (works for an app SP *and*
  an MI — caller passes the SP object id + app id): grant `Sites.Selected` (idempotent) → grant
  per-site access → **only if ≥1 site grant landed** strip the broad `Sites.*` grant
  (`should_remove_orgwide`). Targets: `SiteSelectionPanel` (site URLs + read/write). Graph has **no
  reverse `appId → sites` lookup**, so the site URL(s) are user-supplied.
- **SharePoint item** — `commands::sharepoint::grant_selected_item_access`: grant the Selected
  appRole (idempotent) → resolve each target URL → reject any whose level the scope cannot reach →
  grant per resource. Strips nothing (see [sharepoint-selected.md](./sharepoint-selected.md#the-selected-family-is-four-levels-not-one)). Targets: `ItemSelectionPanel`, which resolves each
  URL as you type and renders what it found, so a level mismatch is a correctable typo rather than a
  post-hoc warning. The cart must be level-**homogeneous** as well as mechanism-homogeneous:
  `Lists.*` and `Files.*` address different securables, so a cart holding both has no single target
  panel and falls back to org-wide, exactly as a mixed-mechanism cart does.

Graph appRole id↔value resolution lives in `commands::graph_roles::graph_role_index` (shared by
exchange + sharepoint); SharePoint org-wide detection is name-based (`is_sharepoint_orgwide`, defined
once in `azapptoolkit-core::scoping`). Org-wide **Files** reach is the opposite shape — an explicit
two-value list (`is_files_orgwide_permission` / `FILES_ORGWIDE_PERMISSIONS`, also in `scoping`) —
because the `Files.` family contains scopes that are *not* tenant-wide file reach
(`Files.SelectedOperations.Selected`, app-folder scopes), so a prefix rule would misclassify them.

**To teach the app a new mechanism**, touch:

1. **Core** — the `ScopeKind` variant, its arms in `capability_key` / `admin_applicable`, its
   predicate in `scope_kind_for`, and a capabilities-catalog entry for its key.
2. **Wizard** — the `ScopeMode` variant(s) and the `mode_options` row(s). The first row is the
   mechanism's default; org-wide is appended for every mechanism, so no choice is a one-way door.
   Everything that describes or runs the grant reads `effective_mode`, which forces org-wide when
   the cart has no mechanism.
3. **Compiler-enforced** — every per-mechanism branch in `scope_wizard.rs` is an exhaustive match
   with no `_` arm, so the compiler then demands `mode_panel` (the target panel), the `Plan` arm in
   `run_apply`, `consent_scope`, and `targets_label` / `review_targets` / `strip_warning` /
   `review_line`.
4. **Not compiler-checked** — the step-2 "can't be scoped together" hint and the step-1 intro copy;
   mechanism-specific cart state in `anchor` / `reset` (like the SharePoint read/write default);
   and the per-row "Scope…" entry gates `permissions_tab::row_scope_kind` and
   `held_permissions_panel::is_held_scopable`.

**Discoverability**: the enterprise-app and managed-identity Permissions tabs render the shared
`OrgwideScopeCallout` (`web-rs/components/orgwide_scope_callout.rs`) above the held-permissions
table when the principal holds org-wide access — a scopable mail value whose verdict is not
`Scoped` (unresolved counts, never-under-report) or any broad `Sites.*`. It names the values and
its "Scope…" opens the wizard pre-seeded to the first one, same contract as a held row's "Scope…".
This is the front door for scoping a **foreign-tenant** enterprise app (no local app registration
⇒ no App Registrations surface, and the scoping sections only render further down the tab).

## Audit remediations (one-click "Fix")

Only for findings whose fix maps to a **safe, existing** mutation. Add a `RemediationKind` variant
in `azapptoolkit-core::audit` and populate a `RemediationAction` in `score_application` from the
same data the issue uses (so the button appears exactly when the finding does). Each kind maps 1:1
to a `commands/remediation.rs` handler that **re-resolves live state** before acting — the audit
snapshot is advisory, never the source of truth for what gets mutated (e.g. remove-expired
recomputes the expired set from a fresh `get_application` using the *same* whole-day rule the
scorer uses — `azapptoolkit_core::audit::is_expired`, the single definition shared by the scorer,
the one-click remediation, the per-app `remove_expired_passwords`, and the bulk sweep, so no
removal path can delete a credential the audit never flagged).

On success the command busts caches (`invalidate_app_lists`) — and, unlike most mutations, a
**partial** success still invalidates, because credentials were really removed. The audit view's
`result` signal is a snapshot; drop **the kind that just succeeded** from the item's `remediations`
(that button gone) and re-run for fresh scores. Only that kind: `AuditController::on_remediated`
takes `(object_id, RemediationKind)` and `retain`s the rest, because one item routinely carries a
fix per rule it tripped and the others are still unfixed.

**What a row renders is a property of the surface, not the item.** An `AuditItem` carries every
remediation the scorer attached and is listed under every finding group it matches, so
`AuditRowActions` takes a `section: Option<&'static GroupSpec>` — the Findings pane passes the
group's spec, the All-apps pane passes nothing (not grouped by rule). It decides two things:

- **Which Fixes show** — `groups::group_remediation_kinds(spec.key)`, that section's rule only
  (advisory and Healthy groups own none, so their rows are "Open"-only); no section ⇒ every fix.
  A new `RemediationKind` must be claimed by exactly one group key;
  `every_remediation_kind_is_owned_by_exactly_one_group` fails until it is. Without this, one
  section rendered another's button — and firing it cleared the section's own Fix.
- **Where "Open" lands** — `GroupSpec::tab`, so the deep-link opens the tab where *this* finding
  is acted on. `row::scan_item_for_tab` (the item-wide scan) is the no-section fallback only: it
  ranks a scoping finding above a credential one, so an app tripping both opened on Permissions
  even from the Expired-credentials section. `target_tab` then clamps managed identities to
  Overview/Permissions — their pane has no Owners or Credentials tab, and an unmatched deep-link
  renders an empty tab body rather than failing loudly.

Two kinds vary the pattern:

- **`AddOwner`** (Rule 14 ownership gap) has **no dedicated handler** — the guided user-picker
  modal (`views/dialogs/add_owner.rs`) calls the existing `add_application_owner`, which already
  busts the detail + audit caches. Safe because it's purely additive. `build_remediations` takes
  the owner count (`app.owners.as_ref().map(Vec::len)` — the same data Rule 14 keys off); `None`
  (owners not fetched, incl. every SP-only row) attaches nothing.
- **`MigrateApplicationAccessPolicy`** (Rule 11's legacy bucket) also has **no dedicated handler**:
  the modal (`views/dialogs/migrate_legacy_scope.rs`) drives the existing
  `migrate_application_access_policies` command scoped to one app, which already re-resolves every
  input live and carries the three guards in [exchange-scoping.md](./exchange-scoping.md#migrating-a-legacy-application-access-policy). Two consequences to preserve: it is keyed on the
  **appId** (a policy names an application, not a directory object) and works from *granted* roles,
  so it needs **no `ScopeFixTarget` split** — one call serves an app registration, a foreign
  enterprise app and an MI alike; and it is **plan-first** — opening the modal runs the dry run and
  the commit stays disabled until that plan returns, because the fail-closed outcomes (scope left on
  the legacy group, policy kept) are only visible there. Both surfaces render the report through
  `components::aap_migration_report::AapMigrationReportView`, whose one job is that a `partial`
  status never reads as success. The command now busts `invalidate_app_lists` on a **non-dry** run
  that produced any item (partial included — the grants really were removed); a dry run busts
  nothing.
- **`DisableSignIn`** is attached by **two runner post-passes**, deduped to one Fix per row: the
  risky-SP pass (`apply_service_principal_risk`) attaches it first for a risky *enabled* principal,
  and the sign-in pass (`unused` app) skips when that already happened — or when the SP is already
  disabled or absent. Neither attaches it inside `score_application` — both flags (`sp_risk_state`,
  `unused`) are post-pass facts. Safe because it's reversible: the handler
  (`remediate_disable_sign_in`) re-resolves the SP from the live application and sets
  `accountEnabled: false`; the enterprise app's Overview toggle re-enables. SP-only unused rows
  don't get it (their Open lands on the enterprise/MI detail, which has the toggle) — SP-only
  *risky* rows do, since that finding is about live abuse, not staleness.

## Redundant application permissions (Rule 18)

`subsuming_app_permissions` in `azapptoolkit-core::audit` is the table of "broader permission
fully covers narrower one" relationships (transitive closure flattened, e.g. `Sites.Read.All` →
all three broader `Sites.*` tiers). Rule 18 flags a held narrower permission whose broader sibling
is also held — advisory, **no score** (the broader permission already carries the risk weight).
The covered narrower grant still keeps its own Rule 1/2 weight: the risk rules measure surface area
(every held risk-listed grant), not effective reach, so `Mail.ReadWrite` + `Mail.Read` scores 15
where `Mail.ReadWrite` alone scores 10. That is deliberate — Rules 1/2 are the ported per-grant
weights, and dropping covered grants would re-rank apps; the one-click removal is what pays the
difference back. Pinned by `redundant_permissions_rule_is_advisory_with_remediation`.
Constraints baked into the table; keep them when extending it:

- **Application permissions only.** Graph authorizes app-only calls by the union of `roles` in the
  token (a client-credentials token always carries every granted role), so a covered narrower role
  is pure surface area and removing it can never break a call. Delegated scopes are matched
  *literally* in token requests — removing a narrower consented scope can break an app that
  requests it by name — so delegated redundancy is deliberately not flagged.
- **Only documented full-coverage pairs.** `Mail.Send` is not covered by `Mail.ReadWrite`;
  `Directory.ReadWrite.All` does not cover `User.ReadWrite.All`/`Group.ReadWrite.All` (no user
  delete / password reset).
- **`Sites.Selected` is never the narrower value** — it's the least-privilege model Rule 12 pushes
  *toward*; calling it redundant would invert that guidance.
- **A scoped broader doesn't cover.** `score_application` vetoes a broader mail permission whose
  `mail_scopes` verdict is `Scoped` — confined `Mail.ReadWrite` no longer reaches everything an
  org-wide `Mail.Read` does, so the pair isn't redundant.

The one-click fix (`RemediationKind::RemoveRedundantPermissions` →
`commands::remediation::remediate_remove_redundant_permissions`) re-plans from a fresh manifest +
live `appRoleAssignments` (`plan_redundant_removals`, pure + unit-tested), with three rules
**stricter than the scorer** (the scorer also pairs on `(resource, value)`, but reads an empty
`mail_scopes` as org-wide):

- The covering broader permission must be declared on the **same resource** (Graph's
  `Mail.ReadWrite` doesn't cover Exchange Online's `Mail.Read` appRole of the same name).
- A **granted** narrower permission is removed only while a covering broader **grant** is live;
  if the broader grant has since been revoked or scoped away (Exchange RBAC strips the org-wide
  Entra grant), the value is reported `skipped`, never removed. An ungranted declaration is
  removable whenever the broader is declared — declarations authorize nothing.
- The covering broader permission must be **confirmed org-wide** from live `mail_scopes`. A
  `Scoped`/`Unknown` verdict, or Exchange being unreachable (including an operator who isn't an
  Exchange admin), vetoes it and the value is reported `skipped` — fail closed, whereas the scorer
  reads an empty `mail_scopes` as org-wide. The Fix stays on the row while anything is `skipped`.

Per removal: revoke the narrower `appRoleAssignment` (when granted), then drop all affected
declarations in **one** trailing `requiredResourceAccess` patch. A revocation error stops further
revocations but already-revoked grants still get their declarations patched out (a revoked grant
with a lingering declaration is the inconsistent state to avoid), and caches are busted on any
partial success — the same exception remove-expired-credentials makes.

## Least-privilege downgrades (the inverse direction)

`downgrade_alternatives` is the **inverse scan of the same coverage table** (broader → narrowers,
ordered closest-tier-first by subsumer count), so Rule 18 and the downgrade suggestions can never
disagree about what covers what. It drives three surfaces:

- the permission picker's grant-time "Narrower alternative: …" note (closest tier only);
- an audit *recommendation* (never an issue, never a score) naming concrete swaps for
  risk-flagged application permissions, capped at three alternatives;
- the Permissions tab's per-row **"Downgrade…"** action →
  `commands::permissions::downgrade_application_permission`.

**A downgrade is NOT safe by construction** — the narrower permission only suffices if the app
genuinely never uses the broader capability — so it is *never* offered as a one-click audit
remediation; every surface presents it as an admin-judged choice. The command re-validates the
pair against the table, then swaps non-strandingly: grant the narrower `appRoleAssignment`
**before** revoking the broad one (grant-before-strip, matching the Exchange/SharePoint scoping
cores), then swap the declaration in one `requiredResourceAccess` patch (`swap_declared_role`,
pure — note `remove_declared_access` prunes an emptied resource entry, so a broad-only resource is
recreated to carry the narrow role). Idempotent: a broad permission already gone is a no-op
success with every `DowngradeOutcome` flag `false`.

## The risky-service-principal signal (Rule 22)

The run's tenant-wide Identity Protection read — ONE `GET /identityProtection/riskyServicePrincipals`
per audit, paged with `$top = MAX_PAGE_SIZE`, served by the one-shot `scoped_get` (premium reports
deliberately skip the retry budget; a first-page 404 is an empty answer). Only
`confirmedCompromised` / `atRisk` rows are kept, keyed by `servicePrincipalId` — the SP **object**
id, the same join key the grant matrices use — and joined onto audit rows in BOTH phases
(`score_one` and `score_sp_only`), never via a per-principal read. Deliberately **uncached**: a
compromise flag must be re-read by every run, and the payload is one row per flagged principal.

- **Auth:** an on-demand `ScopedTokenAdapter` token for `IdentityRiskyServicePrincipal.Read.All`
  (CAE), capability `identity_protection_risk`. Audit surfaces carry no Grant-consent button, so
  consent arrives only through the readiness checklist's silent probe of every `scope_feature`.
- **Unavailable ≠ gap:** no consent or no Workload Identities premium license (the endpoint 403s
  `Authentication_RequestFromNonPremiumTenantOrB2CTenant`) means the check reads as *unavailable* —
  no coverage gap, no degraded banner, following the sign-in-report precedent that most tenants
  are not entitled. A genuine failed read on an entitled tenant IS
  `AuditCoverageGap::RiskyServicePrincipals`: unlike the sign-in report, a failed risky read means
  the security check silently stopped working, so the run is degraded — never cached, never shown
  as an all-clear. While unavailable, `ScoreCtx::risk_for` answers `None` even for a principal
  present in the map; Rule 22 never fires on an unchecked assumption.
- **Scoring:** `apply_service_principal_risk` adds +20 (alone ⇒ High; stacks any other finding to
  Critical — a CHANGELOG-gated ranking shift), the `RISKY_SERVICE_PRINCIPAL` marker issue, and a
  `DisableSignIn` Fix while the SP is still enabled. It runs BEFORE the unused post-pass, which
  then skips its own Fix — one Fix per row either way.
- **UI:** the `risky_service_principal` finding group is advisory (no `group_bulk_actions`, no
  `group_remediation_kinds` entry — `DisableSignIn` stays solely owned by the `unused` group, which
  the exactly-one-owner test pins); risky rows still render their Fix in the All-apps pane, where
  no per-group kinds filter narrows the row buttons.

## The per-credential last-used signal (credential-usage post-pass)

One tenant-wide read per audit — `GET /beta/reports/appCredentialSignInActivities` (beta preview,
**Global cloud only**, `AuditLog.Read.All`) — returns the last observed sign-in use of every
credential, per origin. Same transport shape as the sign-in report (`$top = MAX_PAGE_SIZE`,
origin-checked paging), but unlike the risky read it IS read-through cached
(`{tenant}|app_credential_sign_in_activities` under `CacheKind::Permissions`): last-used moves on
a days-scale, and the identical read backs the Credentials tab's `list_credential_usage`, so a
fresh audit warms the tab and vice versa. Rows fold into one `"appId|keyId" → CredentialActivity`
map with the newest date winning (one credential can appear under both the `application` and the
`servicePrincipal` origin); the Credentials tab re-applies the fold client-side because the join
happens there too. Application rows only — `score_sp_only` never runs it.

- **Unknown is never unused.** A credential with no report row resolves to `Unknown` and is never
  flagged — absence from the report is not evidence of no use (the report covers only some sign-in
  flows). Only a `Never` credential older than the window, or a `LastSeen` one whose last use is
  past 90 days (`UNUSED_CREDENTIAL_DAYS`), becomes the advisory. The never-false-positive contract;
  pinned by `unused_credential_advisory_never_flags_unknown`.
- **Scope of the judgment:** only still-valid credentials are considered (an expired one is the
  `expired` finding's job, which keeps the sole `RemoveExpiredCredentials` Fix), age counts from
  each credential's `start_date_time` (falling back to the app's creation date — the unused-app
  rule's brand-new guard, per credential), and one issue line names up to three stale credentials
  ("and N more") per the mixed-credential-status line precedent. Advisory only: no score —
  last-used is operator context on top of the expiry signals, not a new severity — and no Fix;
  removal stays admin-judged.
- **Unavailable disables, never degrades:** a failed read, a missing `AuditLog.Read.All` consent or
  a non-global cloud sets `ScoreCtx.credential_usage_available = false` and the advisory is simply
  off — no coverage gap, no degraded banner (the sign-in-report precedent: most tenants can never
  see this report, and it only feeds an advisory). `list_credential_usage` degrades the same way
  (`available: false` + empty rows) rather than failing the command.
- **UI:** the `unused_credential` finding group sits in the Actionable section with a
  Credentials-tab deep link, and deliberately has no `group_bulk_actions` /
  `group_remediation_kinds` entry (pinned by `advisory_and_healthy_groups_offer_no_row_fix`). The
  Credentials tab shows a **Last used** column on both tables, three-state by construction:
  dated → the day, tracked-with-no-use → "No use recorded", unknown → "—". "—" is a real answer
  ("we don't know"), never rendered as "unused"; when the report is unavailable the whole column
  reads "—" under one info `Callout`.

## The credential-lifetime policy (app-management policies, v1.0)

Two v1.0 reads per audit (`prefetch_app_management_policy`): `policies/defaultAppManagementPolicy` and
`policies/appManagementPolicies?$expand=appliesTo`, joined in one pair on the shared `policy` bearer
(`Policy.Read.All`, acquired on demand like Conditional Access — these are v1.0, not beta, so there is no
preview/sovereign caveat to carry). Either read failing makes the WHOLE pair unavailable: without the
`appliesTo` target map a default-policy cap could mis-flag an app that adopted an override, so partial
policy data is no data. That is an unavailable advisory, not a coverage gap — the lifetime signal is
operator context on top of the expiry findings, its absence hides no finding, and a tenant that never
consented `Policy.Read.All` must not carry a permanent degraded banner (the sign-in-report precedent).
The Credentials tab's per-app `get_app_credential_policy` (three reads joined, same token) degrades the
same way: `available: false`, `Ok` never `Err`.

- **One cap rule, two surfaces.** `ScoreCtx::secret_cap_for` + `enforced_secret_max_days` (core) resolve
  the cap enforced ON one principal: an assigned per-app override REPLACES the tenant default — even
  disabled or holding no lifetime rule, so the default must not leak onto an app that adopted an override
  either; ≥2 assigned overrides is a shape Graph does not document → no verdict; a disabled policy enforces
  no cap; an app predating a date-gated restriction is grandfathered → no cap. `credential_over_cap(end,
  start, cap)` is the ONE over-cap predicate, shared by the audit advisory and the Credentials-tab markers
  (expiry-state filtering stays with the caller: expired secrets keep their single Expired signal), so the
  two surfaces can never name different secrets for one app. `None` is "no verdict", never "compliant".
  Application rows only — a service principal carries no local secrets, and the join starts from
  `app.password_credentials`.
- **Recommendation-only.** The audit emits one per-app recommendation line when a cap is knowable — no
  issue marker, no finding key, no score, no `groups.rs` entry; the 365-day Rule 7 floor is untouched and
  this compares ALONGSIDE it (replacing the floor would be a CHANGELOG-gated ranking change). The tab
  shows a section `Callout` only for a known cap (info tone, warn while violations exist), an "Over cap"
  `Badge` on valid provably-over secrets only, and the add-secret dialog warns — never clamps or blocks,
  for a chosen lifetime over the cap ("the add would be rejected"); only Graph decides.
- **Never "no cap enforced."** Unknown (pair unavailable) and known-capless both render NOTHING on every
  surface — the same never-flag-on-unknown contract as the Last-used column, and a permanent notice on
  every healthy tenant trains operators to ignore it. Home's one-line
  "Tenant policy caps secret lifetimes at N days." comes from `tenant_secret_max_days` (the gate-ignoring
  tenant lens, paired with `credential_policy_available` on `CachedAuditSummary`), not from any per-app
  verdict.

## Structured audit signals over issue-text parsing

The Security workbench's finding groups and filters key off structured `AuditItem` fields
(`risk_level`, `credential_status`, `unused`, `last_sign_in`, `sign_in_report_available`) rather
than `starts_with(...)` on free-text issues — `score_one` populates the sign-in fields after
`score_application` (which stays sign-in-agnostic, defaulting them). When adding a new finding
group or filter, prefer a structured flag on `AuditItem` over matching an advisory string.

## Finding groups, filters & bulk-action pairing

The Findings pane renders `groups::group_findings` — the `GROUP_CATALOG`, keyed by the **same**
finding keys `azapptoolkit_core::audit::matches_finding` understands (core, not the workbench,
because the backend's Home summary classifies with it too). Classification delegates to
`matches_finding`, so each marker predicate lives exactly once. Actionable groups are ranked by
their own **worst severity**, then affected-principal count, then catalog order (the sort is stable);
healthy positives (`scoped_mailbox` / `scoped_sites`) are demoted to a collapsed disclosure.

> Ranking used to be Σ `risk_score` over the group's members — each member's *total* score from every
> rule, not what this rule contributed. Because the ownership rule carries no points of its own and
> matches a large fraction of any tenant, "Missing or single owner" led a findings-first workbench
> while a twelve-app Critical org-wide-mailbox group sat below the fold. If a group ever needs a
> scalar "how much risk sits here" again, compute it at the call site: a field named `impact` that
> nothing ranks by is what produced the bug.

- **`expired` matches only `CredentialStatus::Expired`** — expiring-soon lives in the
  Credential-expiry lens, not this finding.
- **The three mailbox findings are mutually exclusive by construction.** `legacy_mailbox_scope` is
  neither `orgwide_mailbox` (the access IS confined) nor `scoped_mailbox` (that group is the healthy
  end state it migrates toward); the separation rests entirely on the scorer keeping
  `SCOPED_VIA_RBAC` out of *both* legacy advisories. It is Actionable with **no bulk action**: the
  migration is per-app and plan-first, so a uniform bulk form would have nothing to show (the same
  shape as `high_risk_perms` / `no_local_app`).
- **Unconfinable org-wide reach has advisory homes:** `unscopable_legacy_mailbox`
  (`UNSCOPABLE_LEGACY_MAILBOX` — legacy Office 365 Exchange Online mail roles; advice is remove) and
  `unconfinable_orgwide` (`UNCONFINABLE_MAILBOX` + `UNCONFINABLE_SHAREPOINT`; advice is review /
  re-declare on Graph). Both are Actionable with no bulk action and no row Fix, kept out of
  `orgwide_mailbox` / `orgwide_sharepoint` (whose Fix can't apply to them) and apart from each other
  because the recommendations differ. `every_reach_marker_has_a_group` pins that every reach/risk
  marker the scorer emits lands in some group; the three hygiene notes (instance lock, public
  client, secret-over-cert) are deliberately left to the All-apps issue column.
- **Org-wide Files reach is advisory with its own group.** `orgwide_files` (`ORG_WIDE_FILES`)
  fires for the two tenant-wide file grants on Microsoft Graph (`Files.Read.All`,
  `Files.ReadWrite.All`). Actionable with **no bulk action and no row Fix**: the wizard scopes
  `Files.SelectedOperations.Selected` to chosen files/libraries, but no handler converts a held
  `Files.*.All`, so removal stays admin-judged — the same reason it is kept out of
  `orgwide_sharepoint`, whose Sites.Selected bulk Fix cannot apply to a Files grant. The picker
  hint, this rule's recommendation and the wizard all name the one scoped value; its single source
  is `audit::least_privilege_alternative_for`, whose Files arm must stay worded off the helper.
- **Load-bearing asymmetry:** `scoped_mailbox` matches with `.contains(SCOPED_VIA_RBAC)` while
  every sibling finding uses `.starts_with` — the marker sits mid-issue, not at the front. The
  core `audit/finding.rs` tests pin this; a "normalize everything to `starts_with`" sweep silently empties
  the finding.
- **Shared counts, one source:** `azapptoolkit_core::audit::posture_counts` (+ `finding_worst`)
  feeds both the Security tab's posture strip (over the run it holds) and the Home posture card
  (severity row + Top-findings counts), so the numbers can't disagree. Home never pulls the run:
  it reads `get_cached_audit_summary`, a `dto::audit::CachedAuditSummary` of counts and per-finding
  worst severity the backend computes from the cached entry — the run is up to 10k items, and Home
  used to ship it over IPC on every audit reload. The buckets classify through `matches_finding`,
  so a count can't diverge from the group it summarizes (pinned by
  `posture_counts_agree_with_finding_groups`); `PostureCounts::finding(key)` is the one key→bucket
  map. The Home card counts the two unconfinable-reach groups and the org-wide Files finding too. `groups::tone` is the one
  `RiskLevel` → tone map (group dots, risk badges, the Home card). The Home card's ranked
  Top-findings list goes through `groups::ranked_actionable_findings`, which ranks the summary's
  tallies with the same `rank_key` as `group_findings`, so the finding *order* and tone can't
  disagree either (pinned by `summary_ranking_matches_the_workbench_ranking`).
- **Bulk-action pairing:** `groups::group_bulk_actions(key)` pairs each finding group with the
  fix that addresses **that rule**: Expired → RemoveExpired, Org-wide mailbox/SharePoint → Scope,
  Redundant → RemoveRedundant, Ownership → AddOwner, Unused → DisableSignIn + Delete. Advisory
  groups (`high_risk_perms`, `high_risk_delegated`, `external_exposure`, `no_local_app`,
  `unscopable_legacy_mailbox`, `unconfinable_orgwide`) get none — the old Over-privileged → RemoveRedundant cross-rule mapping is retired; do
  not reintroduce it. **No Grant consent on audit surfaces.** "Fix all N" only seeds
  `selected_audit_ids` with the group's *eligible* (Application-kind) ids — the
  `BulkActionBar`'s typed-confirm / target forms still gate execution.

## Bulk remediations reuse the single-app cores, sequentially

`bulk_remove_redundant_permissions` / `bulk_scope_mailbox_access` / `bulk_scope_sharepoint_access`
(`commands/bulk.rs`) loop the per-app remediation paths
(`remediation::remediate_remove_redundant_permissions`, `exchange::grant_exchange_mailbox_access`
with `permissions: None` = all, `remediation::remediate_scope_sharepoint_access`) — **not** the
`dispatch_capped` spawn fan-out, because those cores take `State` (not `Send` into a spawn) and
the selection is a small admin-chosen set. They `claim()` a `bulk_cancel` token once, before the
first await, and poll it, emit
`bulk-progress` (no `in_flight_cap`), and degrade to a per-app `error` rather than aborting; each
per-app core busts its own cache. The scope targets (mailbox groups / site URLs + role) are
**uniform across the selection**.

## SP-only principals in the audit (no local application)

The audit run has **two phases**. Phase 1 scores every `/applications` entry
(`score_application`). Phase 2 scores service principals with **no local application object** —
foreign-tenant (OIDC/multi-tenant) enterprise apps, managed identities, orphaned SPs — via
`score_service_principal`, from their *granted* state instead of a manifest.

- **Candidates** (`sp_audit_candidates`, pure + unit-tested): shared `{tenant}|sp_index` rows whose
  `appId` joins to no scanned application AND that hold ≥1 application grant in the run's
  combined matrix (`combine_granted_roles`: the Microsoft Graph `appRoleAssignedTo` read plus one
  read each on Office 365 Exchange Online and SharePoint Online — `prefetch_office365_role_grants`
  keeps EVERY role value with its resource, not just EWS `full_access_as_app`), OR are flagged
  risky by the run's Identity Protection map. So an SP holding only `Exchange.ManageAsApp`, the EWS
  scope or SharePoint Online `Sites.*` is scored (high-risk weight, plus `UNCONFINABLE_SHAREPOINT`
  for the SharePoint ones). A failed Exchange Online read is `AuditCoverageGap::EwsFullAccessGrants`,
  a failed SharePoint Online read `SharePointOnlineGrants`; a resource with no SP in the tenant is
  an empty answer, not a gap. The grant/risk requirement is the noise filter (grantless first-party
  Microsoft SPs vanish); disabled SPs stay in (Rule 4). The risky admission path is deliberate: a
  compromised managed identity or foreign SP often holds no *enumerable* grant, and "no grants ⇒
  skip it" is exactly the wrong inference when Identity Protection says the principal is
  compromised. Known limitation: roles held only on resources other than these three (a
  third-party or custom API) aren't in any matrix, so an *unflagged* SP holding only those isn't
  scored.
- **Zero extra per-item Graph traffic.** Phase 2 reuses the run's tenant-wide reads — the Graph
  `appRoleAssignedTo` matrix (now fetched regardless of Exchange availability; its mail-scopable
  subset still feeds `score_one`'s reconciliation) and the `oauth2PermissionGrants` read (which now
  also keeps AllPrincipals scope strings per client for Rule 13). A failed grants read is
  `AuditCoverageGap::DelegatedConsentGrants`: it drops every admin-consent flag (Rule 3) and the
  SP rows' delegated scopes, so the run is degraded — never cached, never an all-clear. Phase 1 uses the same map: an app
  row's broad-prefix delegated scopes (`Mail.`, `Files.`, `Sites.`, …) are reported by Rule 13 only
  when they are in its SP's AllPrincipals set (`AppPermissions::admin_consented_scopes`), falling
  back to the declared scopes when the grants read failed; the ported pair
  (`Directory.AccessAsUser.All`, `user_impersonation`) is reported whenever requested. Scoring is
  pure CPU — a plain sequential loop, no `dispatch_capped` fan-out.
- **Applicable rules only**: permission risk (1 & 2), admin consent (3), disabled SP (4),
  mailbox/SharePoint advisories (11, 12), high-risk delegated (13), plus the sign-in post-pass.
  Credential rules (5–9) and manifest rules (10, 14–18, downgrades) are deliberately absent —
  those objects live in the app's home tenant. No **RBAC** verdict is resolved, **on purpose**: a
  held mail value here IS an un-stripped org-wide Entra grant, so the reconciliation would force
  `OrgWide` regardless of any RBAC probe — skipping it scores identically without the 1–5s Exchange
  probe per SP. (A properly scoped principal no longer holds the grant and drops out of the
  candidate set; its RBAC-only access is not surfaced — under-reporting an advisory, never risk.)
  The **legacy AAP verdict is the one exception**, and it costs nothing extra (see
  `apply_legacy_policy_verdict` above): unlike an RBAC scope, a policy *does* constrain the org-wide
  Entra grant these rows are scored from.
- **Wire shape**: two additive fields. `AuditItem.principal_kind`
  (`application` | `service_principal` | `managed_identity`, `#[serde(default)]` so pre-field
  cached runs deserialize as `Application`), and `AuditItem.app_owner_organization_id`
  (`#[serde(default)]`): the SP's home tenant, exported as the last CSV column `AppOwnerOrgId`
  (named as in the Enterprise Applications export). `publisher` is `None` on SP rows — it is an
  application's verified publisher domain, never a tenant GUID. For SP rows `object_id` is the
  **SP object id**.
- **Frontend routing keys off `principal_kind`** (structured-signals rule): the `no_local_app`
  finding group; Open → enterprise / MI detail (`open_enterprise_on_tab` /
  `open_managed_identity_on_tab`); scope Fixes carry a `ScopeFixTarget` — `AppReg` rows call the
  `remediation::remediate_scope_*` wrappers (which `get_application` first), SP rows call the
  SP-only cores (`grant_managed_identity_scoped_exchange_access` /
  `convert_site_access_to_selected`) that a foreign principal needs. **SP rows are non-selectable**
  — the bulk commands loop app-registration cores and would 404 on an SP object id.
- **Invalidation**: the SP-only scoping/revoke paths already bust the audit transitively
  (`invalidate_app_lists` / `invalidate_app_detail_state`); `grant_managed_identity_permission`
  busts it explicitly (its old "audit scans only app registrations" rationale died with this).

