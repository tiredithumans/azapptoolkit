# Disaster-recovery backup & restore

This subsystem lets an operator capture a tenant's app estate to a portable file
and rebuild it in a **new** tenant — for DR, a tenant-compromise recovery, or a
forced migration. Read this before touching `commands/backup.rs`,
`commands/restore.rs`, or `azapptoolkit-dto/src/backup.rs`.

## The shape: file-bridged, two single-tenant instances

The app is **single-tenant-bound** — `EntraAuthService::sign_in` rejects any
token whose `tid` claim ≠ the configured `AZAPPTOOLKIT_TENANT_ID`
(`crates/azapptoolkit-auth/src/service/mod.rs`). A running instance therefore can
**never** touch two tenants. We do not change that. Instead:

```
[source-tenant build]                         [destination-tenant build]
  backup_tenant ──► TenantBackup (JSON) ──►  plan_restore ──► restore_tenant
                    (config only,                (dry-run:        (replay + bulk
                     NO secret values)            remap + warns)   credential regen)
                                                                       │
                                                                       ▼
                                                              RestoreReport
                                                              new ids + show-once
                                                              secrets + unresolved
```

The JSON manifest is the only thing that crosses the boundary. Backup runs on a
build pointed at the source tenant; restore on a build pointed at the
destination. This preserves the single-tenant security invariant and needs no
multi-authority auth.

> The Microsoft Entra **Backup & Recovery API** (beta) is *same-tenant* rollback
> only (daily snapshots, 5-day retention) — it does **not** do cross-tenant DR,
> which is why we carry our own portable manifest.

## Three hard constraints the design is built around

1. **Secret/cert values are unrecoverable.** Graph returns `secretText` only
   once at `addPassword` ("There is no way to retrieve this password in the
   future"); certificate private keys are never stored (only the thumbprint).
   So the manifest captures credential **metadata** only — `CredentialMeta` has
   no value field, and that absence is the structural guarantee that secrets
   never reach the backup file. **Restore regenerates** fresh secrets/certs and
   emits a redistribution report. **Federated identity credentials** carry no
   secret, so they are the DR-friendly credential type — but restore still
   validates each one through `core::federation` and reports every one it
   creates (see below).

2. **`appId`/`objectId` change in a new tenant** (Graph auto-assigns them).
   - First-party Microsoft resource appIds (Graph `00000003-…`) and their
     permission GUIDs are **stable** and survive verbatim.
   - Custom in-tenant resource appIds, `api://{appId}` identifier URIs, and
     user/group/owner object ids must be **remapped by a stable key**
     (identifierUri / displayName / UPN). The DTOs store these resource-relative
     (`AppRoleGrantRef.resource_app_id` + `app_role_value`) or by principal key
     (`PrincipalRef.user_principal_name` / `display_name`) for exactly this
     reason.

3. **Managed identities can't be restored or moved cross-tenant.** Moving a
   subscription to another directory *breaks* both system- and user-assigned
   MIs; soft-deleted MI service principals can't be recovered. So MIs are a
   **redeploy runbook + permission re-bind**, never a restorable object: the
   infra team recreates them (ARM/Bicep) with new principal ids, then the
   restore re-binds their Graph app-roles, matched by `display_name`, and lists
   their Azure RBAC as a runbook item.

## The manifest (`azapptoolkit-dto/src/backup.rs`)

`TenantBackup` is versioned (`schema_version` / `BACKUP_SCHEMA_VERSION`) and
records the source `cloud` (`CloudEnvironment::as_str()`); restore rejects a
**cross-cloud** manifest (endpoints and well-known appIds differ) and *warns* on
a tenant mismatch (that mismatch is the expected DR case).

Restore also refuses a manifest whose `schema_version` is **newer** than this
build's (`check_manifest_schema`). A restore is not a read — it mutates the
tenant before anyone can inspect the result — so a manifest carrying fields this
build cannot interpret must be rejected, not partially applied. Only the future
direction is refused: every field is `serde(default)` and additive, so an older
manifest restores correctly, which is the DR case the version field exists for.
The same rule (`schema_too_new`) also feeds the dry-run, so a too-new manifest
is shown as blocked in the plan, before Confirm, rather than refused only after.

Three object classes:

- `AppRegistrationBackup` — full config: manifest (`required_resource_access`),
  Expose-an-API (`identifier_uris`, `api_scopes`, `pre_authorized_applications`),
  authentication (redirect URIs + implicit-grant flags), `federated_credentials`
  (see below), `owners` (by `PrincipalRef`), credential **metadata**,
  and an `admin_consent_granted` flag (drives re-consent).
- `EnterpriseAppBackup` — identity + flags + foreign-tenant info + paired
  app-registration ref; assignees and held app-roles are resource-relative.
- `ManagedIdentityBackup` — identity + subtype + ARM resource id + held Graph
  app-roles. Azure RBAC is not captured — it is runbook-only on restore. (Builds
  before this carried never-populated `azureRoles` / `azureRoleCoverage` keys;
  those manifests still load, the keys are ignored.)

## Backup (`commands/backup.rs`) — shipped

`backup_tenant` is read-only (never invalidates a cache) and runs three passes
over the estate. The estate is enumerated up front from `list_application_index`
+ the cached `sp_index` (reused from the Enterprise Apps list — same per-tenant
scan, not re-pulled) + `list_managed_identities`.

The per-object reads are **batched** via Graph JSON batching to keep round-trips
(and the throttling they trigger) low. Each pass chunks its objects into groups
of `BATCH_CHUNK` (20, Graph's `$batch` cap) and `dispatch_capped`s the chunks:

- **Pass 1 — app registrations:** per chunk, `batch_get_applications_backup_json`
  (one consolidated `$expand=owners` doc per app — app + auth + Expose-an-API +
  owners) and `batch_list_federated_credentials`, fired together. `has_sp` comes
  from the index, and `admin_consent_granted` is derived from declared
  permissions — no per-app SP/grant probe.
- **Pass 2 — enterprise apps:** per chunk, the full SP read
  (`batch_get_service_principals` — the lean index lacks `appRoles`/`tags`/
  `appRoleAssignmentRequired`), `batch_list_app_role_assigned_to`, and
  `batch_list_service_principal_groups` (the advanced `memberOf` query rides a
  per-sub-request `ConsistencyLevel` header). A group/assignee read failure still
  captures the SP, without that part, and is recorded in `TenantBackup.skipped`
  as a partial entry (`enterpriseAppAssignments` / `enterpriseAppGroups`); a
  vanished SP is left out.
- **Pass 3 — managed identities:** `batch_list_app_role_assignments` for all MIs,
  then one batched prewarm of each **distinct** resource SP (seeding
  `ResourceLookup`), then assembly with no further round trips. Azure RBAC isn't
  scanned (runbook-only on restore). A per-MI assignment read failure captures
  the MI without its app-roles and is recorded as a `managedIdentity` skip; like
  Passes 1 and 2, every failure is classified through `SessionDead`, so a dead
  session aborts the backup.

Each batched read returns `Vec<Result<T>>` in input order; a **whole-batch
failure degrades to per-object reads** for that chunk (never failing the backup),
and a per-object failure skips (or partially captures) just that object,
recorded in `skipped`. Concurrency is **adaptive**: a
shared `ConcurrencyThrottle` (`commands/throttle.rs`, the audit's tracker)
wired as the Graph client's `ThrottleObserver` halves the chunk cap on each 429
and recovers it when quiet; the cap is fed to `dispatch_capped` and emitted as
`BulkProgress.in_flight_cap` so the DR view can show it (and a back-off notice).

It is long-running, so it claims (once, before the first await) its own
`backup_cancel` token (cancelled only by `cancel_backup`, so neither a restore
nor an audit/bulk run can stop it; checked at chunk boundaries) and emits
`backup-progress` (`BulkProgress` shape) events the DR view renders. A cancelled
run is an **error**, not a truncated success — a partial backup is a dangerous DR
artifact. `save_backup_to_file` writes JSON only (the manifest is a structured
restore artifact, not a spreadsheet) via the shared `save_export_via_dialog`.

## Restore (`commands/restore.rs`) — shipped (app registrations, enterprise apps, managed identities)

`plan_restore` is a dry-run, no writes (mirrors the `bulk_create` validate-only
pattern). It computes the counts for all five passes — including the Pass 4
split into enterprise apps to re-apply vs. runbook items (foreign, or no paired
app registration with an SP in this backup), the MIs to re-bind, and the
backup's own `skipped` gaps — and surfaces both hard blockers, a cross-cloud
manifest and a too-new `schema_version` (`RestorePlan::is_blocked`, the one
definition the view reads; `restore_tenant` still enforces both itself), plus
the tenant-change note and, when the destination is the source tenant, a
warning that restoring duplicates every app rather than rolling anything back.
The frontend shows it before the operator confirms.

`restore_tenant` replays the manifest in five passes so inter-app dependencies
resolve:

1. **Create shells** — `create_application_core_with` per app (+ paired SP),
   or adoption of the app an earlier run created (below); build the
   `source_app_id → new_app_id` remap.
2. **Wire references** — declared permissions (`remap_required_resource_access`:
   first-party appIds survive, custom ones remapped, permission ids preserved),
   identifier URIs (`rewrite_identifier_uris`: every `api://` segment naming
   the source appId or source tenant → the new appId / destination tenant —
   Microsoft rejects a GUID segment matching neither, and the URIs share one
   PATCH with the scopes and pre-authorized apps),
   Expose-an-API scopes (ids preserved) + pre-authorized apps (remapped),
   authentication, federated credentials (validated + reported, below), owners (`resolve_principal`
   by UPN / display name — unresolved are reported), and secret regeneration
   (`add_password`, show-once values into the report). Every step is
   best-effort: a failure is a per-app warning, not a run failure.
3. **Re-consent** — `grant_admin_consent_core` per app that had consent, run
   *after* all apps are wired so a custom resource's SP + scopes already exist.
4. **Enterprise applications** and 5. **Managed identities** — below.

**Re-running a restore adopts what an earlier run created.** Pass 1 has no
natural key that survives the tenant move — the appId changes and `api://{new}`
is not in the manifest — so every app is created with the tag
`azapptoolkit:restoredFrom:<source appId>` (`restore_marker`), written in the
create POST itself so no restored app can exist untagged. Before creating, Pass 1
looks the tag up (`find_applications_by_tag`, a basic `tags/any` filter) and
`adoption_for` decides:

- **no hit** → create;
- **one renamed hit, or several** → a `ManualItem`, nothing created;
- **one hit whose `createdDateTime` is missing or precedes `TenantBackup.created_at`**
  → a `ManualItem`: no restore of this backup can have created it;
- **exactly one hit with the manifest's exact display name, created after the
  backup** → a provisional adopt, which `decide_adoption` then checks.

**Adoption must prove provenance, not just match.** The tag and the display name
are both writable by anyone allowed to register apps (the tenant default), and
source appIds are not secret — while an adopted app goes on to receive the
manifest's `requiredResourceAccess`, fresh secrets and, in Pass 3, tenant-wide
admin consent, and Pass 2 never removes owners. So `decide_adoption` reads the
hit's owners and adopts only when every one is either the signed-in operator
(`TenantContext.account_oid`) or one of the manifest's owners resolved in the
destination (through the run's principal memo, which Pass 2 reuses). Any other
owner is a `ManualItem` that names them; the operator removes them and re-runs,
or deletes the app to have it recreated. A re-run by a *different* admin than the
first run is refused the same way — fail closed, and the item says who owns it.
Only then does the app join the remap: its SP is ensured (the earlier run may
have died between the two POSTs) and Pass 2 finishes it (`RestoredApp.adopted`).

A failed lookup — of the tag or of the owners — **fails closed** into a
`ManualItem` too: creating blind is how a re-run duplicates the estate, and
adopting blind is how someone else's app is granted this one's consent. For an adopted app Pass 2 re-applies the
full-replace PATCHes as-is and skips what is already there among the additive
writes: federated credentials by name, owners by resolved id, secrets by display
name (as a multiset). Pass 3 updates existing grants, so it needs nothing. Known
limitation: Pass 4 does not de-duplicate, so a re-run's repeated app-role
assignments and group memberships come back as per-app warnings. Apps restored by
builds before the tag existed carry none and are not recognised.

**Secrets already expired at backup time are not re-issued.** A backed-up secret
whose `end_date_time` precedes `TenantBackup.created_at` (`expired_at_backup`)
cannot have been in use, so Pass 2 names it in a warning instead of minting a
fresh 180-day credential, and `plan_restore` counts it in
`RestorePlan.expired_secrets_skipped`. The cutoff is the backup's time, never
"now": a secret that expired during the outage is the one a recovering client
still holds.

**Federated identity credentials are the one thing a manifest can carry that
grants standing access with no secret at all**: whoever controls the named
issuer can mint tokens as the restored app, indefinitely, and there is no
expiry to notice. A manifest is a *file*, and the operator restoring it may not
be the person who wrote it. So pass 2 treats each one as untrusted input:

- It is validated through `core::federation::validate_federated_credential` —
  the same check the interactive editor uses, and the reason that check lives in
  `core` rather than in one command. A rejected credential becomes a per-app
  warning naming why; the rest of the app still restores.
- Each one that *is* created is reported as a `ManualItem` naming its issuer and
  subject. Graph never validates a federated identity credential (Microsoft
  documents that a wrong issuer "is created successfully without error", failing
  only later at token exchange), so a planted trust is otherwise invisible.
  `wire_application` returns these alongside the `RestoredApp` for that reason.
- A *flexible* credential (no subject; matched by a `claimsMatchingExpression`,
  which only Graph beta exposes, so the v1.0 read never sees it) is backed up
  as-is with `subject: null`. Restore does not recreate it: `restorable_fic_subject`
  turns it into a "was NOT restored" warning, and `build_restore_plan` leaves it out of
  `RestorePlan.federated_credentials_to_restore`.

It refuses a **cross-cloud** manifest outright, claims its own `restore_cancel`
(stopped only by `cancel_restore`, never by a backup's Cancel; a cancel stops at
the next item in whichever pass is running and the report flags the run
cancelled, so a re-run adopts the already-created, tagged apps and finishes
them), emits `restore-progress`, and busts the destination's list
caches (`invalidate_app_lists`) when anything was created. The `RestoreReport`
carries the new ids, the show-once regenerated secrets, unresolved owners,
certificates needing manual re-upload, per-app warnings, and hard failures.

The remap helpers (`remap_required_resource_access`, `rewrite_identifier_uris`,
`remap_pre_authorized`) are pure and unit-tested (first-party-survives vs
custom-remap, the `api://` rewrite across Microsoft's four supported forms —
`api://<appId>`, `api://<tenantId>/<appId>`, `api://<tenantId>/<string>`,
`api://<string>/<appId>`).

**Enterprise applications** restore in Pass 4. For an SP that was recreated by
its paired app registration (it's in the `app_id_remap` and not foreign), the
restore re-applies settings (tags, `appRoleAssignmentRequired`), **app-role
assignments** (each principal remapped by display name via `resolve_principal`;
the role remapped by `map_assignee_role_id` — the default-access role passes
through, a custom role is matched by `value` on the new SP), and **group
memberships** (each group remapped by display name). Foreign/gallery apps and
paired apps that weren't restored become `ManualItem` runbook entries
(re-consent / re-instantiate from the gallery). Custom app-role *definitions*
aren't restored, so an assignment to an unmatched custom role is reported, not
applied. The backup captures this detail in its batched Pass 2
(`backup_enterprise_chunk`, above).

**Managed identities** restore in Pass 5. MIs can't be created via Graph
(they're Azure resources), so `restore_managed_identities` matches each
backed-up MI to one **already recreated** in the destination — by display name
— and re-binds its held Graph app-roles to the new principal (grouped by
resource appId, granted by value via the shared
`grant_managed_identity_roles_core`). Two things are always runbook items
(`ManualItem`): MIs not yet recreated (recreate via ARM/Bicep, then run the
restore again with the same backup — the apps it already created are adopted by
their restore tag, not duplicated), and
**Azure RBAC** — source role scopes are subscription/resource-specific and don't
exist in the destination, so the operator re-creates them at the equivalent
scopes. The backup captures MI held Graph app-roles (resource-relative, via a
cached `ResourceLookup`); it deliberately does **not** scan Azure RBAC (it's
runbook-only and the MI detail view already surfaces it for DR planning).

**A failed read in passes 4-5 is reported as a failure, not as an absence.** A
failed destination MI listing becomes one `ManualItem` saying so — never a "not
found" item per MI — and a failed SP read is not reported as "the app had none
in the backup". Every failure in these passes is noted through `SessionDead`, as
in Pass 2, so a session that dies there stops the restore with
`session_expired` set.

### Security posture

The backup manifest carries configuration but **no secret values** — still treat
it as sensitive (it enumerates permissions, owners, identifier URIs). The restore
**report** *does* carry show-once regenerated secret values: handle it with the
same discipline as the in-app secret reveal (`PasswordCredential` is
`Debug`-redacted and never logged; `SelfSignedCertificate.key` likewise). The
report file is the only place those values land, and the operator is warned it is
secret-bearing.
