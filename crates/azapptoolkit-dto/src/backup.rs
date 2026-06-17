//! Disaster-recovery backup manifest DTOs.
//!
//! A [`TenantBackup`] is the portable, file-bridged artifact that crosses the
//! source→destination tenant boundary. The app is **single-tenant-bound** (it
//! rejects any token whose `tid` ≠ the configured tenant), so a running
//! instance can never touch two tenants — the JSON file is the only thing that
//! travels. Backup runs on the source-tenant build; restore runs on the
//! destination-tenant build and replays the existing create/grant commands with
//! an old→new id remap.
//!
//! Two hard constraints shape this schema (confirmed against Microsoft Learn):
//!
//! - **Secret/cert *values* are unrecoverable.** Graph returns `secretText`
//!   only once at `addPassword`; cert private keys are never stored. So the
//!   manifest captures credential *metadata* ([`CredentialMeta`] — which has no
//!   value field, by design) and restore *regenerates* fresh credentials,
//!   emitting a redistribution report. Federated identity credentials carry no
//!   secret and so restore verbatim — the DR-friendly credential type.
//! - **`appId`/`objectId` are auto-assigned and change in a new tenant.**
//!   First-party Microsoft resource appIds (Graph `00000003-…`) and their
//!   permission GUIDs are stable and survive; everything else is captured by a
//!   stable key (identifierUri / displayName / UPN) so restore can remap it.
//!
//! Managed identities can't be restored via Graph (they're Azure resources);
//! their backup is a redeploy-runbook + permission-rebind snapshot, not a
//! restorable object. See `docs/architecture/backup-and-restore.md`.

use azapptoolkit_core::models::{
    FederatedIdentityCredential, OAuth2PermissionScope, PreAuthorizedApplication,
    RequiredResourceAccess,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Manifest schema version. Bump on any breaking shape change so a restore can
/// refuse a manifest it can't safely interpret.
pub const BACKUP_SCHEMA_VERSION: u32 = 1;

/// The full portable backup of a tenant's app estate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantBackup {
    pub schema_version: u32,
    pub created_at: DateTime<Utc>,
    /// Tenant the backup was taken from. Informational: restore warns (does not
    /// fail) when this differs from the destination tenant — that mismatch is
    /// the *expected* DR case.
    pub source_tenant_id: String,
    /// Cloud label (`Commercial` / `UsGov` / `UsGovDod` / `China`). Restore
    /// rejects a cross-cloud manifest — endpoints and well-known appIds differ.
    pub cloud: String,
    #[serde(default)]
    pub app_registrations: Vec<AppRegistrationBackup>,
    #[serde(default)]
    pub enterprise_apps: Vec<EnterpriseAppBackup>,
    #[serde(default)]
    pub managed_identities: Vec<ManagedIdentityBackup>,
}

/// Full configuration of one app registration. Source ids are kept for
/// provenance and for building the restore's remap table; everything that
/// references *other* objects is stored resource-relative or by stable key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRegistrationBackup {
    pub source_object_id: String,
    pub source_app_id: String,
    pub display_name: String,
    #[serde(default)]
    pub sign_in_audience: Option<String>,
    #[serde(default)]
    pub description: Option<String>,

    // ---- Expose-an-API + identity ----
    /// May contain `api://{source_app_id}` — restore rewrites that to the new
    /// appId once the shell app exists.
    #[serde(default)]
    pub identifier_uris: Vec<String>,
    #[serde(default)]
    pub api_scopes: Vec<OAuth2PermissionScope>,
    #[serde(default)]
    pub pre_authorized_applications: Vec<PreAuthorizedApplication>,

    // ---- Authentication (web/spa/publicClient) ----
    #[serde(default)]
    pub web_redirect_uris: Vec<String>,
    #[serde(default)]
    pub spa_redirect_uris: Vec<String>,
    #[serde(default)]
    pub public_client_redirect_uris: Vec<String>,
    #[serde(default)]
    pub logout_url: Option<String>,
    #[serde(default)]
    pub is_fallback_public_client: bool,
    #[serde(default)]
    pub enable_access_token_issuance: bool,
    #[serde(default)]
    pub enable_id_token_issuance: bool,

    // ---- API permissions (declared manifest) ----
    /// Drives restore's re-consent. `resource_app_id` is stable for first-party
    /// resources and survives verbatim; a custom resource's appId is remapped
    /// against the destination tenant.
    #[serde(default)]
    pub required_resource_access: Vec<RequiredResourceAccess>,
    /// Whether the source app's permissions were admin-consented (its SP had any
    /// app-role assignments or delegated grants). Restore re-grants consent only
    /// when this was true.
    #[serde(default)]
    pub admin_consent_granted: bool,

    // ---- Credentials (METADATA ONLY — values are unrecoverable) ----
    #[serde(default)]
    pub secrets: Vec<CredentialMeta>,
    #[serde(default)]
    pub certificates: Vec<CredentialMeta>,
    /// Federated identity credentials — fully restorable (no secret material).
    #[serde(default)]
    pub federated_credentials: Vec<FederatedIdentityCredential>,

    // ---- Owners (remapped by UPN / displayName on restore) ----
    #[serde(default)]
    pub owners: Vec<PrincipalRef>,

    /// True when a paired enterprise-app SP exists in the source tenant, so
    /// restore recreates the SP alongside the app registration.
    #[serde(default)]
    pub has_service_principal: bool,
}

/// Configuration of one enterprise application (service principal). For an SP
/// backed by an in-backup app registration this is light; for foreign/gallery
/// apps it carries the assignment + held-permission state that restore must
/// re-apply (after re-instantiating or re-consenting the app).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnterpriseAppBackup {
    pub source_sp_object_id: String,
    pub source_app_id: String,
    pub display_name: String,
    #[serde(default)]
    pub account_enabled: Option<bool>,
    #[serde(default)]
    pub app_role_assignment_required: Option<bool>,
    #[serde(default)]
    pub service_principal_type: Option<String>,
    /// Home tenant of the app this SP fronts. When it differs from the source
    /// tenant the SP is a foreign/gallery enterprise app — re-instantiated from
    /// the gallery or re-consented on restore rather than recreated.
    #[serde(default)]
    pub app_owner_organization_id: Option<String>,
    #[serde(default)]
    pub is_foreign_tenant: bool,
    /// Source object id of a paired app registration captured in this same
    /// backup, if any (the SP is then recreated by recreating that app).
    #[serde(default)]
    pub paired_app_registration_object_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Users/groups assigned to the app's roles — remapped by UPN/displayName.
    #[serde(default)]
    pub app_role_assignees: Vec<AppRoleAssigneeRef>,
    /// Security/M365 groups this SP is a member of (the group-gated-API access
    /// model) — remapped by display name on restore.
    #[serde(default)]
    pub group_memberships: Vec<PrincipalRef>,
    /// Application permissions **held by** this SP, resource-relative.
    #[serde(default)]
    pub held_app_roles: Vec<AppRoleGrantRef>,
}

/// A managed identity snapshot. MIs can't be restored via Graph — they're Azure
/// resources, recreated out-of-band (ARM/Bicep) with new principal/client ids.
/// This captures what the restore's runbook + permission re-bind needs: the
/// identity (matched to the redeployed MI by `display_name`), its held Graph
/// app-roles, and its Azure RBAC assignments.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedIdentityBackup {
    pub source_principal_id: String,
    pub source_app_id: String,
    pub display_name: String,
    /// `systemAssigned` / `userAssigned` / `unknown`.
    pub subtype: String,
    /// ARM resource id (user-assigned MIs only) — tells the infra team which
    /// resource to recreate. `None` for system-assigned (recreated with host).
    #[serde(default)]
    pub arm_resource_id: Option<String>,
    /// Graph application permissions held by the MI (e.g. `Mail.Send`),
    /// resource-relative — re-granted by `grant_app_role` after redeploy.
    #[serde(default)]
    pub held_app_roles: Vec<AppRoleGrantRef>,
    /// Azure RBAC role assignments — best-effort (requires ARM consent); empty
    /// when the ARM scan was unavailable. `coverage` records how complete it was.
    #[serde(default)]
    pub azure_roles: Vec<AzureRoleRef>,
    /// Coverage of the Azure-RBAC scan, so an incomplete scan never reads as
    /// "this MI holds no Azure roles".
    #[serde(default)]
    pub azure_role_coverage: Option<AzureRoleCoverage>,
}

/// Credential **metadata** — never a value. Client-secret values and cert
/// private keys are unrecoverable by Graph design (returned once at creation),
/// so a backup can only *describe* a credential, never reproduce it. There is
/// deliberately no value/secret field here — that absence is what guarantees
/// secrets never touch the backup file. Restore mints a fresh secret (or
/// re-uploads a cert from the operator's own PKI) and emits a redistribution
/// report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialMeta {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub start_date_time: Option<DateTime<Utc>>,
    #[serde(default)]
    pub end_date_time: Option<DateTime<Utc>>,
    /// SHA-1 thumbprint (certificates only) — tells the operator which cert to
    /// re-supply from their PKI/offline backup.
    #[serde(default)]
    pub thumbprint: Option<String>,
}

/// A directory principal (user / group / service principal) referenced by the
/// keys that survive a tenant move. Object ids change in the new tenant, so
/// restore re-resolves by `user_principal_name` (users) or `display_name`
/// (groups / SPs); `source_id` is provenance only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalRef {
    pub source_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub user_principal_name: Option<String>,
    /// Graph `@odata.type` (`#microsoft.graph.user` / `group` / …), when known.
    #[serde(default)]
    pub principal_type: Option<String>,
}

/// An application-permission grant **held by** a service principal, expressed
/// resource-relative so it survives remapping: the resource is keyed by its
/// `resource_app_id` (stable for first-party), and the role by both id and
/// resolved value (so a custom resource's reassigned role id can be re-resolved
/// by value in the destination tenant).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRoleGrantRef {
    pub resource_app_id: String,
    #[serde(default)]
    pub resource_display_name: Option<String>,
    pub app_role_id: String,
    #[serde(default)]
    pub app_role_value: Option<String>,
}

/// A user/group assigned to one of an enterprise app's roles. The principal is
/// remapped by UPN/displayName; the role by its value (ids are app-local, so a
/// re-instantiated gallery app may reassign them).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRoleAssigneeRef {
    pub principal: PrincipalRef,
    pub app_role_id: String,
    #[serde(default)]
    pub app_role_value: Option<String>,
}

/// One Azure RBAC role assignment held by a managed identity. Built-in role
/// definition ids are stable across tenants and survive verbatim; a *custom*
/// role definition must already exist in the destination (restore reports it as
/// unresolved otherwise). The scope is stored verbatim — the operator maps it
/// to the destination subscription/resource group as part of the redeploy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureRoleRef {
    pub role_name: String,
    /// Bare role-definition GUID (built-in ids are stable across tenants).
    #[serde(default)]
    pub role_definition_id: Option<String>,
    /// ARM scope the role was granted at, in the source subscription.
    pub scope: String,
    #[serde(default)]
    pub high_privilege: bool,
}

/// How complete an MI's Azure-RBAC scan was, mirroring
/// `managed_identity::AzureRolesResult` so a partial scan never reads as
/// authoritative.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AzureRoleCoverage {
    pub scanned: usize,
    pub total: usize,
    pub skipped: usize,
}

// ===================== Restore =====================

/// Dry-run analysis of restoring a [`TenantBackup`] into the current tenant —
/// what would be created and what needs operator attention, computed without
/// any writes (mirrors the bulk-create validate-only pattern).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestorePlan {
    /// Hard blocker: the manifest's cloud differs from this build's cloud
    /// (endpoints + well-known appIds differ). When set, restore refuses to run.
    #[serde(default)]
    pub cloud_mismatch: Option<CloudMismatch>,
    /// Informational: the source tenant differs from the destination — the
    /// expected DR case, surfaced so the operator confirms intent.
    pub tenant_changed: bool,
    pub source_tenant_id: String,
    pub destination_tenant_id: String,
    pub app_registrations_to_create: usize,
    /// Secrets that will be regenerated (their values can't be restored).
    pub secrets_to_regenerate: usize,
    /// Certificates needing manual re-upload (the private key is unavailable).
    pub certificates_needing_manual_upload: usize,
    pub federated_credentials_to_restore: usize,
    pub owners_to_remap: usize,
}

/// The manifest's cloud doesn't match this build's configured cloud.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudMismatch {
    pub backup_cloud: String,
    pub destination_cloud: String,
}

/// Outcome of a restore run. Carries the old→new id remap, the freshly-minted
/// (show-once) secrets to redistribute, and everything that needs follow-up.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreReport {
    pub apps: Vec<RestoredApp>,
    /// Apps that failed to create at all (no new id was assigned).
    pub failures: Vec<RestoreFailure>,
    /// Enterprise applications whose access (assignments + group memberships)
    /// was re-applied to a service principal recreated by the app-reg restore.
    #[serde(default)]
    pub enterprise_apps: Vec<RestoredEnterpriseApp>,
    /// Managed identities matched by name in the destination, with their Graph
    /// app-roles re-bound. (Azure RBAC re-creation is a manual runbook item —
    /// source scopes don't exist in the destination.)
    #[serde(default)]
    pub managed_identities: Vec<RestoredManagedIdentity>,
    /// Items that can't be restored automatically and need an operator runbook —
    /// foreign/gallery enterprise apps (re-consent / re-instantiate from the
    /// gallery) and the deeper SSO surface (SAML signing cert, claims policy).
    #[serde(default)]
    pub manual_items: Vec<ManualItem>,
    /// True when the run stopped early (cancelled) before creating every app;
    /// the apps that *were* created are still fully wired and reported.
    pub cancelled: bool,
}

/// An enterprise application whose access was re-applied on restore (its SP was
/// recreated by the paired app registration).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoredEnterpriseApp {
    pub display_name: String,
    pub new_sp_object_id: String,
    pub assignments_applied: usize,
    pub group_memberships_applied: usize,
    /// Assignees / groups that couldn't be resolved in the destination tenant.
    pub unresolved_principals: Vec<String>,
    pub warnings: Vec<String>,
}

/// A managed identity matched by display name in the destination tenant, with
/// its held Graph app-roles re-bound to the new principal.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoredManagedIdentity {
    pub display_name: String,
    pub new_principal_id: String,
    pub app_roles_rebound: usize,
    pub warnings: Vec<String>,
}

/// Something the restore can't do automatically — surfaced as a runbook entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManualItem {
    pub display_name: String,
    pub reason: String,
}

/// One successfully recreated app registration and its follow-ups.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoredApp {
    pub display_name: String,
    pub source_app_id: String,
    pub new_app_id: String,
    pub new_object_id: String,
    /// Freshly minted secrets — **show-once** values to redistribute to the
    /// app's consumers, then discard.
    pub regenerated_secrets: Vec<RegeneratedSecret>,
    /// Certificate display names that need manual re-upload (the private key
    /// was never in the backup).
    pub certificates_needing_manual_upload: Vec<String>,
    /// Owners that couldn't be resolved in the destination tenant (by UPN /
    /// display name) — re-add them manually once those principals exist.
    pub unresolved_owners: Vec<String>,
    /// Non-fatal per-step warnings (a redirect-URI patch failed, a federated
    /// credential was rejected, a consent resource wasn't found, …). The app
    /// was still created.
    pub warnings: Vec<String>,
    pub consent_granted: bool,
}

/// A regenerated client secret. `secret_value` is plaintext and shown once —
/// it is never retrievable again. Custom `Debug` keeps it out of logs.
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegeneratedSecret {
    pub display_name: String,
    pub key_id: String,
    pub secret_value: String,
    #[serde(default)]
    pub expires: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for RegeneratedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegeneratedSecret")
            .field("display_name", &self.display_name)
            .field("key_id", &self.key_id)
            .field("secret_value", &"<redacted>")
            .field("expires", &self.expires)
            .finish()
    }
}

/// An app registration that couldn't be created (so it has no new id and
/// nothing downstream was attempted for it).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreFailure {
    pub display_name: String,
    pub source_app_id: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire format is a cross-build, cross-tenant contract (the manifest is
    /// written by one build and read by another), so pin a full round-trip
    /// through camelCase JSON.
    #[test]
    fn tenant_backup_round_trips_through_camel_case_json() {
        let backup = TenantBackup {
            schema_version: BACKUP_SCHEMA_VERSION,
            created_at: chrono::DateTime::parse_from_rfc3339("2026-06-15T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            source_tenant_id: "tenant-src".into(),
            cloud: "Commercial".into(),
            app_registrations: vec![AppRegistrationBackup {
                source_object_id: "obj-1".into(),
                source_app_id: "app-1".into(),
                display_name: "Demo".into(),
                identifier_uris: vec!["api://app-1".into()],
                secrets: vec![CredentialMeta {
                    display_name: Some("rotate-me".into()),
                    end_date_time: Some(
                        chrono::DateTime::parse_from_rfc3339("2026-12-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    ),
                    ..Default::default()
                }],
                admin_consent_granted: true,
                has_service_principal: true,
                ..Default::default()
            }],
            enterprise_apps: vec![EnterpriseAppBackup {
                source_sp_object_id: "sp-1".into(),
                source_app_id: "ent-1".into(),
                display_name: "Gallery App".into(),
                is_foreign_tenant: true,
                held_app_roles: vec![AppRoleGrantRef {
                    resource_app_id: "00000003-0000-0000-c000-000000000000".into(),
                    resource_display_name: Some("Microsoft Graph".into()),
                    app_role_id: "role-1".into(),
                    app_role_value: Some("Mail.Read".into()),
                }],
                ..Default::default()
            }],
            managed_identities: vec![ManagedIdentityBackup {
                source_principal_id: "mi-1".into(),
                source_app_id: "mi-app-1".into(),
                display_name: "mi-prod".into(),
                subtype: "userAssigned".into(),
                arm_resource_id: Some("/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-prod".into()),
                ..Default::default()
            }],
        };

        let json = serde_json::to_value(&backup).unwrap();
        // camelCase keys on the wire.
        assert_eq!(json["schemaVersion"], BACKUP_SCHEMA_VERSION);
        assert_eq!(json["sourceTenantId"], "tenant-src");
        assert!(json["appRegistrations"][0]["adminConsentGranted"]
            .as_bool()
            .unwrap());

        // A backup file must never carry a secret value, even when one existed.
        let raw = serde_json::to_string(&backup).unwrap();
        assert!(
            !raw.contains("secretText"),
            "backup manifest must never serialize a secret value"
        );

        let back: TenantBackup = serde_json::from_value(json).unwrap();
        assert_eq!(back.app_registrations.len(), 1);
        assert_eq!(back.app_registrations[0].secrets.len(), 1);
        assert_eq!(
            back.enterprise_apps[0].held_app_roles[0]
                .app_role_value
                .as_deref(),
            Some("Mail.Read")
        );
        assert_eq!(back.managed_identities[0].subtype, "userAssigned");
    }

    /// `CredentialMeta` has no value field — this is the structural guarantee
    /// that secrets can't be persisted. If anyone adds one, this fails to
    /// compile (the literal omits it) — and the assertion documents intent.
    #[test]
    fn credential_meta_carries_no_value() {
        let meta = CredentialMeta {
            display_name: Some("s".into()),
            ..Default::default()
        };
        let json = serde_json::to_value(&meta).unwrap();
        assert!(json.get("secretText").is_none());
        assert!(json.get("value").is_none());
        assert!(json.get("secret").is_none());
        assert!(json.get("key").is_none());
    }

    /// The restore report carries the only plaintext secrets in the system (the
    /// regenerated values). They must serialize for the show-once UI but never
    /// leak through `Debug` / logs.
    #[test]
    fn regenerated_secret_serializes_value_but_redacts_in_debug() {
        let secret = RegeneratedSecret {
            display_name: "rotated".into(),
            key_id: "kid-1".into(),
            secret_value: "PLAINTEXT-SECRET-VALUE".into(),
            expires: None,
        };
        // Serializes for the UI (camelCase).
        let json = serde_json::to_value(&secret).unwrap();
        assert_eq!(json["secretValue"], "PLAINTEXT-SECRET-VALUE");
        // But Debug never prints it.
        let dbg = format!("{secret:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("PLAINTEXT-SECRET-VALUE"));
    }

    #[test]
    fn restore_report_round_trips() {
        let report = RestoreReport {
            apps: vec![RestoredApp {
                display_name: "Demo".into(),
                source_app_id: "old".into(),
                new_app_id: "new".into(),
                new_object_id: "new-obj".into(),
                regenerated_secrets: vec![RegeneratedSecret {
                    display_name: "s".into(),
                    key_id: "k".into(),
                    secret_value: "v".into(),
                    expires: None,
                }],
                consent_granted: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["apps"][0]["newAppId"], "new");
        let back: RestoreReport = serde_json::from_value(json).unwrap();
        assert_eq!(back.apps[0].regenerated_secrets[0].secret_value, "v");
    }
}
