# Disaster-recovery backup & restore

This subsystem lets an operator capture a tenant's app estate to a portable file
and (in later slices) rebuild it in a **new** tenant — for DR, a tenant-compromise
recovery, or a forced migration. Read this before touching `commands/backup.rs`,
`commands/restore.rs`, or `azapptoolkit-dto/src/backup.rs`.

## The shape: file-bridged, two single-tenant instances

The app is **single-tenant-bound** — `EntraAuthService::sign_in` rejects any
token whose `tid` claim ≠ the configured `AZAPPTOOLKIT_TENANT_ID`
(`crates/azapptoolkit-auth/src/service.rs`). A running instance therefore can
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
   secret and so restore **verbatim** — the DR-friendly credential type.

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
   restore re-applies their Azure RBAC and Graph app-roles, matched by
   `display_name`.

## The manifest (`azapptoolkit-dto/src/backup.rs`)

`TenantBackup` is versioned (`schema_version` / `BACKUP_SCHEMA_VERSION`) and
records the source `cloud` (`CloudEnvironment::as_str()`); restore rejects a
**cross-cloud** manifest (endpoints and well-known appIds differ) and *warns* on
a tenant mismatch (that mismatch is the expected DR case). Three object classes:

- `AppRegistrationBackup` — full config: manifest (`required_resource_access`),
  Expose-an-API (`identifier_uris`, `api_scopes`, `pre_authorized_applications`),
  authentication (redirect URIs + implicit-grant flags), `federated_credentials`
  (restorable verbatim), `owners` (by `PrincipalRef`), credential **metadata**,
  and an `admin_consent_granted` flag (drives re-consent).
- `EnterpriseAppBackup` — identity + flags + foreign-tenant info + paired
  app-registration ref; assignees and held app-roles are resource-relative.
- `ManagedIdentityBackup` — identity + subtype + ARM resource id + held Graph
  app-roles + Azure RBAC assignments (with scan-coverage).

## Backup (`commands/backup.rs`) — shipped

`backup_tenant` is read-only (never invalidates a cache) and fans out the
existing read paths. **App registrations** are captured in full (a per-app
concurrent fan-out reusing `get_application`, `get_application_auth_fields` +
`extract_auth_fields`, `get_application_expose_api`, `list_federated_credentials`,
`list_owners`, and the SP role/grant reads for the consent flag). **Enterprise
apps and managed identities** are captured at the inventory level from the
existing index calls; their per-principal assignment / held-permission /
Azure-RBAC detail is captured alongside the restore slice that consumes it.

It is long-running, so it resets and polls the dedicated `AppState.dr_cancel`
flag (its own — **not** `audit_cancel` — so a backup and a concurrent audit/bulk
run can't cancel each other) and emits `backup-progress` (`BulkProgress` shape)
events the DR view renders. A cancelled run is an **error**, not a truncated
success — a partial backup is a dangerous DR artifact. `save_backup_to_file`
writes JSON only (the manifest is a structured restore artifact, not a
spreadsheet) via the shared `save_export_via_dialog`.

## Restore (`commands/restore.rs`) — shipped (app registrations)

`plan_restore` is a dry-run: it computes the counts and surfaces the
cloud-mismatch blocker + the tenant-change note, no writes (mirrors the
`bulk_create` validate-only pattern). The frontend shows it before the operator
confirms.

`restore_tenant` replays **app registrations** in passes so inter-app
dependencies resolve:

1. **Create shells** — `create_application_core` per app (+ paired SP); build
   the `source_app_id → new_app_id` remap.
2. **Wire references** — declared permissions (`remap_required_resource_access`:
   first-party appIds survive, custom ones remapped, permission ids preserved),
   identifier URIs (`rewrite_identifier_uris`: `api://{old}` → `api://{new}`),
   Expose-an-API scopes (ids preserved) + pre-authorized apps (remapped),
   authentication, federated credentials (verbatim), owners (`resolve_principal`
   by UPN / display name — unresolved are reported), and secret regeneration
   (`add_password`, show-once values into the report). Every step is
   best-effort: a failure is a per-app warning, not a run failure.
3. **Re-consent** — `grant_admin_consent_core` per app that had consent, run
   *after* all apps are wired so a custom resource's SP + scopes already exist.

It refuses a **cross-cloud** manifest outright, resets/polls `dr_cancel` (a
cancel stops creating *new* apps but still finishes wiring the created ones —
never bare shells), emits `restore-progress`, and busts the destination's list
caches (`invalidate_app_lists`) when anything was created. The `RestoreReport`
carries the new ids, the show-once regenerated secrets, unresolved owners,
certificates needing manual re-upload, per-app warnings, and hard failures.

The remap helpers (`remap_required_resource_access`, `rewrite_identifier_uris`,
`remap_pre_authorized`) are pure and unit-tested (first-party-survives vs
custom-remap, the `api://` rewrite).

**Enterprise applications** restore in Pass 5. For an SP that was recreated by
its paired app registration (it's in the `app_id_remap` and not foreign), the
restore re-applies settings (tags, `appRoleAssignmentRequired`), **app-role
assignments** (each principal remapped by display name via `resolve_principal`;
the role remapped by `map_assignee_role_id` — the default-access role passes
through, a custom role is matched by `value` on the new SP), and **group
memberships** (each group remapped by display name). Foreign/gallery apps and
paired apps that weren't restored become `ManualItem` runbook entries
(re-consent / re-instantiate from the gallery). Custom app-role *definitions*
aren't restored, so an assignment to an unmatched custom role is reported, not
applied. The backup captures this detail in a bounded per-SP fan-out
(`backup_one_enterprise_app`: full SP + `appRoleAssignedTo` + group memberships).

**Managed identities** restore in Pass 6. MIs can't be created via Graph
(they're Azure resources), so `restore_managed_identities` matches each
backed-up MI to one **already recreated** in the destination — by display name
— and re-binds its held Graph app-roles to the new principal (grouped by
resource appId, granted by value via the shared
`grant_managed_identity_roles_core`). Two things are always runbook items
(`ManualItem`): MIs not yet recreated (recreate via ARM/Bicep, then re-run), and
**Azure RBAC** — source role scopes are subscription/resource-specific and don't
exist in the destination, so the operator re-creates them at the equivalent
scopes. The backup captures MI held Graph app-roles (resource-relative, via a
cached `ResourceLookup`); it deliberately does **not** scan Azure RBAC (it's
runbook-only and the MI detail view already surfaces it for DR planning).

### Security posture

The backup manifest carries configuration but **no secret values** — still treat
it as sensitive (it enumerates permissions, owners, identifier URIs). The restore
**report** *does* carry show-once regenerated secret values: handle it with the
same discipline as the in-app secret reveal (`PasswordCredential` is
`Debug`-redacted and never logged; `SelfSignedCertificate.key` likewise). The
report file is the only place those values land, and the operator is warned it is
secret-bearing.
