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
| 1 | `rule_app_permission_risk` | +10 per org-wide high-risk grant (+3 if mailbox-confined) | `HIGH_RISK_APP_PERMS` | `high_risk_perms` | — | `Constants.ps1:104-115`; net-new entries marked in `permissions.rs` |
| 2 | same | +5 per org-wide medium-risk grant (+2 if confined) | none | — | — | `Constants.ps1:123-130`; net-new entries marked |
| 3 | `rule_admin_consent` | +5 flat | none | — | — | not cited |
| 4 | `rule_sp_disabled` | +2 | none | — | — | not cited |
| 5 / 6 | `rule_credentials` | +8 all expired / +4 mixed | none (structured `credential_status`) | `expired` | `RemoveExpiredCredentials` | not cited |
| 7 | same | +3 flat (secrets and certificates) | none | — | — | `Credential-Analysis.ps1:169` |
| 8 / 9 | same | +3 all expiring / +2 mixed (only when none expired) | none | — | — | threshold `Constants.ps1:202` |
| 10 | `rule_stale_app` | +2 (older than `STALE_APP_DAYS`) | none | — | — | `MaxAuditHistoryDays` in `Constants.ps1` |
| 11 | `rule_mailbox_advisory` | advisory | `ORG_WIDE_MAILBOX`, `LEGACY_MAILBOX_POLICY`, `UNSCOPABLE_LEGACY_MAILBOX`, `UNCONFINABLE_MAILBOX`, `SCOPED_VIA_RBAC` (contains) | `orgwide_mailbox`, `legacy_mailbox_scope`, `unscopable_legacy_mailbox`, `unconfinable_orgwide`, `scoped_mailbox` | `ScopeMailboxAccess`, `MigrateApplicationAccessPolicy` | `Resource-Analysis.ps1::Add-ExchangePermissionAnalysis` |
| 12 | `rule_sharepoint_advisory` | advisory | `ORG_WIDE_SHAREPOINT`, `UNCONFINABLE_SHAREPOINT`, `SCOPED_SHAREPOINT` | `orgwide_sharepoint`, `unconfinable_orgwide`, `scoped_sites` | `ScopeSharePointAccess` | not cited |
| 13 | `rule_high_risk_delegated` | advisory | `HIGH_RISK_DELEGATED_PERMS` | `high_risk_delegated` | — | list `Constants.ps1:104-130` |
| 14 | `rule_app_hygiene` | advisory | `NO_OWNERS`, `SINGLE_OWNER` | `ownership` | `AddOwner` | not cited |
| 15–17 | same | advisory | `INSTANCE_LOCK_DISABLED`, `PUBLIC_CLIENT_CREDENTIALS`, `PREFER_CERT_OVER_SECRET` | — | — | net-new (tests' "Tier-2 advisory rules") |
| 18 | `rule_redundant_permissions` | advisory (the narrower grant keeps its Rule 1/2 weight) | `REDUNDANT_APP_PERMS` | `redundant_perms` | `RemoveRedundantPermissions` | not cited |
| 19 / 20 | `rule_external_exposure` | +3 audience / +2 unverified publisher | `MULTITENANT_AUDIENCE`, `UNVERIFIED_PUBLISHER` | `external_exposure` | — | not cited |
| — | `rule_downgrade_pointers` | recommendation only | none | — | — (Downgrade… is admin-judged) | not cited |
| runner | `unused_app_advisory` (sign-in post-pass) | advisory | none (structured `unused`) | `unused` | `DisableSignIn` | net-new |

Risk levels: Critical ≥ 25, High ≥ 15, Medium ≥ 8 (`Constants.ps1:207-213`). SP-only rows run
Rules 1–4 and 11–13 plus the sign-in post-pass (see
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
once in `azapptoolkit-core::scoping`).

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
- **`DisableSignIn`** (unused app) is attached by the **audit runner's sign-in post-pass**, not
  `score_application` — `unused` is a post-pass flag (the sign-in report is fetched after scoring),
  and it's skipped when the SP is already disabled. Safe because it's reversible: the handler
  (`remediate_disable_sign_in`) re-resolves the SP from the live application and sets
  `accountEnabled: false`; the enterprise app's Overview toggle re-enables. SP-only unused rows
  don't get it (their Open lands on the enterprise/MI detail, which has the toggle).

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
  map. The Home card counts the two unconfinable-reach groups too. `groups::tone` is the one
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
  `appId` joins to no scanned application AND that hold ≥1 **Microsoft Graph** application grant in
  the tenant-wide `appRoleAssignedTo` matrix. The grant requirement is the noise filter (grantless
  first-party Microsoft SPs vanish); disabled SPs stay in (Rule 4). Known limitation: roles held
  only on non-Graph resources (e.g. legacy Office 365 Exchange Online `full_access_as_app`) aren't
  in the matrix, so such an SP isn't scored.
- **Zero extra per-item Graph traffic.** Phase 2 reuses the run's tenant-wide reads — the Graph
  `appRoleAssignedTo` matrix (now fetched regardless of Exchange availability; its mail-scopable
  subset still feeds `score_one`'s reconciliation) and the `oauth2PermissionGrants` read (which now
  also keeps AllPrincipals scope strings per client for Rule 13). Phase 1 uses the same map: an app
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

