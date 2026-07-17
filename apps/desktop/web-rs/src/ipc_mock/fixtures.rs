//! Typed fixture builders for the mock IPC bridge (the GUI test harness and the
//! GitHub Pages demo). Built from the shared DTO types (not hand-written JSON),
//! so they can't drift from the wire format the bindings deserialize — the same
//! `serde-wasm-bindgen` round-trip the real IPC uses validates them.

use azapptoolkit_core::audit::{
    AuditItem, AuditPrincipalKind, CredentialKind, CredentialStatus, ListCredentialStatus,
    MailPermissionScope, RemediationAction, RemediationKind, RiskLevel, ScopeMechanism,
    disable_sign_in_remediation, issue,
};
use azapptoolkit_core::identity::{SignInOutcome, TenantContext};
use azapptoolkit_core::models::{
    AppRole, Application, DirectoryObject, KeyCredential, Organization, PasswordCredential,
};
use azapptoolkit_dto::UiError;
use azapptoolkit_dto::applications::{ApplicationDetail, ApplicationListRowDto};
use azapptoolkit_dto::audit::AuditRunResult;
use azapptoolkit_dto::bulk::BulkProgress;
use azapptoolkit_dto::config::AuthConfigStatus;
use azapptoolkit_dto::credentials::CredentialRowDto;
use azapptoolkit_dto::diagnostics::CacheStatsDto;
use azapptoolkit_dto::enterprise_application::{
    AppAssignmentDto, AppRolesView, ApplicationTemplateDto, EnterpriseApplicationDetail,
    EnterpriseApplicationDto, GalleryAppSummary, GallerySearchResultsDto, GroupMembershipDto,
    ProvisioningJobDto,
};
use azapptoolkit_dto::exchange::{ExchangeAccessResult, MailScopeEntry};
use azapptoolkit_dto::keyvault::{KeyVaultSweepProgress, KvSecretItemDto, KvSecretValueDto};
use azapptoolkit_dto::managed_identity::{
    AppRoleGrantDto, AzureRoleDto, AzureRolesResult, ManagedIdentityDto, MiSubtype,
};
use azapptoolkit_dto::permission_tester::MailboxProbeProgress;
use azapptoolkit_dto::permissions::{
    CatalogResourceSummary, PermissionKind, ResolvedPermission, ResourcePermissions, RoleEntry,
};
use azapptoolkit_dto::readiness::{ReadinessItem, ReadinessReport, Verdict};
use azapptoolkit_dto::sharepoint::SiteSweepProgress;
use chrono::{DateTime, TimeZone, Utc};

/// A `UiError` with the given code and message (the error-path mock payload).
pub fn ui_error(code: &str, message: &str) -> UiError {
    UiError {
        code: code.to_string(),
        message: message.to_string(),
        retryable: false,
    }
}

/// A single App Registrations list row with sensible defaults; `id`/`display_name`
/// are the fields the list and its filter key off.
pub fn app_row(id: &str, display_name: &str) -> ApplicationListRowDto {
    ApplicationListRowDto {
        id: id.to_string(),
        app_id: format!("{id}-appid"),
        display_name: display_name.to_string(),
        sign_in_audience: Some("AzureADMyOrg".to_string()),
        publisher_domain: None,
        created_date_time: None,
        password_credential_count: 0,
        key_credential_count: 0,
        soonest_credential_expiry: None,
        credential_status: ListCredentialStatus::None,
        paired_service_principal_id: None,
    }
}

/// A list of App Registration rows from display names (object ids are derived).
pub fn apps(display_names: &[&str]) -> Vec<ApplicationListRowDto> {
    display_names
        .iter()
        .enumerate()
        .map(|(i, name)| app_row(&format!("obj-{i}"), name))
        .collect()
}

/// An empty App Registrations result (drives the empty state). Typed so callers
/// don't have to name the DTO.
pub fn no_apps() -> Vec<ApplicationListRowDto> {
    Vec::new()
}

/// A "configured" auth-config status (client/tenant IDs already set), so the
/// app shell proceeds past the first-run config screen.
pub fn configured() -> AuthConfigStatus {
    AuthConfigStatus {
        configured: true,
        client_id: "11111111-1111-1111-1111-111111111111".to_string(),
        tenant_id: "22222222-2222-2222-2222-222222222222".to_string(),
    }
}

/// The signed-in tenant's organization (its display name shows in the nav user
/// block).
pub fn organization(display_name: &str) -> Organization {
    Organization {
        id: "22222222-2222-2222-2222-222222222222".to_string(),
        display_name: display_name.to_string(),
        verified_domains: Vec::new(),
    }
}

/// Wraps a tenant in the `sign_in` / `reauthenticate` return shape.
pub fn sign_in_outcome(tenant: TenantContext) -> SignInOutcome {
    SignInOutcome { tenant }
}

// ---------------- Enterprise applications ----------------

/// One Enterprise Application (service principal) list row.
pub fn enterprise_app(id: &str, display_name: &str) -> EnterpriseApplicationDto {
    EnterpriseApplicationDto {
        id: id.to_string(),
        app_id: format!("{id}-appid"),
        display_name: display_name.to_string(),
        account_enabled: Some(true),
        app_role_assignment_required: None,
        service_principal_type: Some("Application".to_string()),
        app_owner_organization_id: None,
        is_foreign_tenant: false,
        paired_app_registration_id: None,
        password_credentials: Vec::new(),
        key_credentials: Vec::new(),
        app_roles: Vec::new(),
        oauth2_permission_scopes: Vec::new(),
        created_date_time: None,
        tags: Vec::new(),
        notes: None,
    }
}

pub fn enterprise_apps(display_names: &[&str]) -> Vec<EnterpriseApplicationDto> {
    display_names
        .iter()
        .enumerate()
        .map(|(i, name)| enterprise_app(&format!("sp-{i}"), name))
        .collect()
}

/// An Enterprise Application detail payload (service principal + owners).
pub fn enterprise_application_detail(id: &str, display_name: &str) -> EnterpriseApplicationDetail {
    EnterpriseApplicationDetail {
        service_principal: enterprise_app(id, display_name),
        owners: Vec::new(),
    }
}

// ---------------- Managed identities ----------------

pub fn managed_identity(id: &str, display_name: &str) -> ManagedIdentityDto {
    ManagedIdentityDto {
        id: id.to_string(),
        app_id: format!("{id}-appid"),
        display_name: display_name.to_string(),
        account_enabled: Some(true),
        mi_subtype: MiSubtype::UserAssigned,
    }
}

pub fn managed_identities(display_names: &[&str]) -> Vec<ManagedIdentityDto> {
    display_names
        .iter()
        .enumerate()
        .map(|(i, name)| managed_identity(&format!("mi-{i}"), name))
        .collect()
}

// ---------------- Readiness ----------------

/// A readiness report with one "have" item and one "missing" item, enough to
/// render the checklist and a remediation hint.
pub fn readiness_report() -> ReadinessReport {
    ReadinessReport {
        items: vec![
            ReadinessItem {
                key: "manage_apps".to_string(),
                plane: "entra".to_string(),
                plane_label: "Microsoft Entra".to_string(),
                label: "Manage app registrations".to_string(),
                description: "Create, update, and delete app registrations.".to_string(),
                role_verdict: Verdict::Have,
                role_detail: "Application Administrator".to_string(),
                scope_verdict: Verdict::Have,
                scope_detail: "Tenant-wide".to_string(),
                remediation: String::new(),
            },
            ReadinessItem {
                key: "key_vault".to_string(),
                plane: "azure".to_string(),
                plane_label: "Azure RBAC".to_string(),
                label: "Read Key Vault secrets".to_string(),
                description: "Browse and reveal Key Vault secrets.".to_string(),
                role_verdict: Verdict::Missing,
                role_detail: "Key Vault Secrets User not assigned".to_string(),
                scope_verdict: Verdict::Unknown,
                scope_detail: "Not evaluated".to_string(),
                remediation: "Assign the Key Vault Secrets User role.".to_string(),
            },
        ],
        directory_roles_indeterminate: false,
    }
}

// ---------------- Application detail ----------------

/// A minimal but valid `ApplicationDetail`. `Application` derives `Default`, so
/// only the identifying fields are set; no service principal / owners / grants.
pub fn application_detail(object_id: &str, app_id: &str, display_name: &str) -> ApplicationDetail {
    ApplicationDetail {
        application: Application {
            id: object_id.to_string(),
            app_id: app_id.to_string(),
            display_name: display_name.to_string(),
            sign_in_audience: Some("AzureADMyOrg".to_string()),
            description: Some("Sample application shown in the live demo.".to_string()),
            ..Default::default()
        },
        service_principal: None,
        owners: Vec::new(),
        app_role_assignments: Vec::new(),
        oauth2_permission_grants: Vec::new(),
        resolved_permissions: Vec::new(),
    }
}

// ---------------- Security audit ----------------

/// One audit row at `risk` carrying the given free-text `issues` (the home tiles
/// and audit facets key off issue prefixes from [`issue`]). Other fields take
/// benign defaults; callers mutate `credential_status` / `unused` as needed.
pub fn audit_item(name: &str, risk: RiskLevel, issues: &[String]) -> AuditItem {
    let risk_score = match risk {
        RiskLevel::Critical => 92,
        RiskLevel::High => 71,
        RiskLevel::Medium => 44,
        RiskLevel::Low => 12,
    };
    AuditItem {
        application_name: name.to_string(),
        app_id: format!("{name}-appid"),
        object_id: format!("obj-{name}"),
        created_date: None,
        publisher: None,
        sign_in_audience: Some("AzureADMyOrg".to_string()),
        risk_score,
        risk_level: risk,
        issues: issues.to_vec(),
        recommendations: Vec::new(),
        remediations: Vec::new(),
        credential_status: CredentialStatus::Active,
        permission_count: 3,
        service_principal_enabled: Some(true),
        days_since_created: Some(180),
        certificates: Vec::new(),
        secrets: Vec::new(),
        last_sign_in: None,
        unused: false,
        sign_in_report_available: true,
        principal_kind: AuditPrincipalKind::Application,
    }
}

/// A populated cached audit run spanning every severity + every finding group
/// the Security workbench renders (expired, org-wide mailbox/SharePoint,
/// redundant, ownership, unused, over-privileged, high-risk delegated,
/// SP-only, and the scoped/healthy counterparts), so the Home posture tile and
/// every findings group light up. Per-row Fix remediations are attached where
/// the finding has one (the mutations stay unmocked in the demo and degrade to
/// the demo-unsupported toast).
pub fn audit_run_result() -> AuditRunResult {
    let mut over_privileged = audit_item(
        "Contoso CRM",
        RiskLevel::Critical,
        &[format!("{} Mail.ReadWrite.All", issue::HIGH_RISK_APP_PERMS)],
    );
    over_privileged.credential_status = CredentialStatus::Expired;
    over_privileged.remediations = vec![RemediationAction {
        kind: RemediationKind::RemoveExpiredCredentials,
        label: "Remove 1 expired credential".to_string(),
        detail: "Removes: legacy-secret".to_string(),
        targets: Vec::new(),
    }];

    let mut mailbox = audit_item(
        "Fabrikam Mail Sync",
        RiskLevel::High,
        &[issue::ORG_WIDE_MAILBOX.to_string()],
    );
    mailbox.remediations = vec![RemediationAction {
        kind: RemediationKind::ScopeMailboxAccess,
        label: "Scope 1 mailbox permission to specific mailboxes".to_string(),
        detail: "Confines via Exchange RBAC: Mail.ReadWrite".to_string(),
        targets: vec!["Mail.ReadWrite".to_string()],
    }];
    let mut sharepoint = audit_item(
        "Northwind SharePoint Bot",
        RiskLevel::High,
        &[issue::ORG_WIDE_SHAREPOINT.to_string()],
    );
    sharepoint.remediations = vec![RemediationAction {
        kind: RemediationKind::ScopeSharePointAccess,
        label: "Restrict 1 SharePoint permission to selected sites".to_string(),
        detail: "Converts to Sites.Selected: Sites.ReadWrite.All".to_string(),
        targets: vec!["Sites.ReadWrite.All".to_string()],
    }];
    let mut redundant = audit_item(
        "Trey Research Sync",
        RiskLevel::Medium,
        &[format!(
            "{} Mail.Read (covered by Mail.ReadWrite)",
            issue::REDUNDANT_APP_PERMS
        )],
    );
    redundant.remediations = vec![RemediationAction {
        kind: RemediationKind::RemoveRedundantPermissions,
        label: "Remove 1 redundant permission".to_string(),
        detail: "Removes: Mail.Read".to_string(),
        targets: vec!["Mail.Read".to_string()],
    }];
    let delegated = audit_item(
        "Woodgrove Portal",
        RiskLevel::Medium,
        &[format!(
            "{} Directory.AccessAsUser.All",
            issue::HIGH_RISK_DELEGATED_PERMS
        )],
    );
    // A foreign-tenant enterprise app (no local app registration) — exercises
    // the no_local_app group, its non-selectable rows, and the SP-only scope
    // Fix routing.
    let mut foreign_sp = audit_item(
        "Fourth Coffee Connector",
        RiskLevel::High,
        &[format!("{} Mail.Read", issue::ORG_WIDE_MAILBOX)],
    );
    foreign_sp.principal_kind = AuditPrincipalKind::ServicePrincipal;
    foreign_sp.remediations = vec![RemediationAction {
        kind: RemediationKind::ScopeMailboxAccess,
        label: "Scope 1 mailbox permission to specific mailboxes".to_string(),
        detail: "Confines via Exchange RBAC: Mail.Read".to_string(),
        targets: vec!["Mail.Read".to_string()],
    }];

    let mut no_owners = audit_item(
        "Adventure Works API",
        RiskLevel::Medium,
        &[issue::NO_OWNERS.to_string()],
    );
    no_owners.unused = true;
    // The ownership + unused fixes light up in the demo (the mutations they
    // invoke stay unmocked and degrade to the demo-unsupported toast).
    no_owners.remediations = vec![
        RemediationAction {
            kind: RemediationKind::AddOwner,
            label: "Add an owner".to_string(),
            detail: "No owners assigned — ownership/accountability gap".to_string(),
            targets: Vec::new(),
        },
        disable_sign_in_remediation(),
    ];

    let mut single_owner = audit_item(
        "Tailspin Reporting",
        RiskLevel::Medium,
        &[issue::SINGLE_OWNER.to_string()],
    );
    single_owner.remediations = vec![RemediationAction {
        kind: RemediationKind::AddOwner,
        label: "Add a second owner".to_string(),
        detail: "Single owner — vulnerable to owner departure".to_string(),
        targets: Vec::new(),
    }];
    let second_over = audit_item(
        "Wingtip Toys Connector",
        RiskLevel::Medium,
        &[format!(
            "{} Directory.ReadWrite.All",
            issue::HIGH_RISK_APP_PERMS
        )],
    );
    // Scoped (well-configured) counterparts to the org-wide findings above —
    // demonstrate mailbox access confined via Exchange RBAC and SharePoint
    // confined to selected sites. The `issues` strings carry the
    // `SCOPED_VIA_RBAC` / `SCOPED_SHAREPOINT` markers the audit facets key off.
    let scoped_mailbox = audit_item(
        "Margie's Travel Portal",
        RiskLevel::Low,
        &["Mailbox access scoped via RBAC for Applications: Mail.Read".to_string()],
    );
    let scoped_sharepoint = audit_item(
        "Alpine Ski House Booking",
        RiskLevel::Low,
        &["SharePoint access scoped to selected sites: Sites.Selected".to_string()],
    );

    let clean_a = audit_item("Proseware Sync", RiskLevel::Low, &[]);
    let clean_b = audit_item("Litware Analytics", RiskLevel::Low, &[]);

    AuditRunResult {
        tenant_id: "demo-tenant".to_string(),
        total_apps: 13,
        items: vec![
            over_privileged,
            mailbox,
            sharepoint,
            redundant,
            delegated,
            foreign_sp,
            no_owners,
            single_owner,
            second_over,
            scoped_mailbox,
            scoped_sharepoint,
            clean_a,
            clean_b,
        ],
        cancelled: false,
        sign_in_report_available: true,
        sign_in_consent_required: false,
    }
}

// ---------------- Credential expiry ----------------

pub fn credential_row(
    app: &str,
    name: &str,
    kind: CredentialKind,
    days_to_expiry: Option<i64>,
    status: CredentialStatus,
) -> CredentialRowDto {
    CredentialRowDto {
        app_object_id: format!("obj-{app}"),
        app_id: format!("{app}-appid"),
        app_display_name: app.to_string(),
        credential_name: name.to_string(),
        kind,
        start_date_time: None,
        end_date_time: None,
        days_to_expiry,
        status,
    }
}

/// A credential-expiry list spanning expired / ≤7-day / ≤30-day / healthy, so the
/// Home Credential-Health tile shows non-zero counts in each bucket.
pub fn credential_expirations() -> Vec<CredentialRowDto> {
    vec![
        credential_row(
            "Contoso CRM",
            "client-secret",
            CredentialKind::Secret,
            Some(-12),
            CredentialStatus::Expired,
        ),
        credential_row(
            "Fabrikam Mail Sync",
            "rotation-key",
            CredentialKind::Secret,
            Some(3),
            CredentialStatus::ExpiringSoon,
        ),
        credential_row(
            "Tailspin Reporting",
            "signing-cert-2024",
            CredentialKind::Certificate,
            Some(21),
            CredentialStatus::ExpiringSoon,
        ),
        credential_row(
            "Wingtip Toys Connector",
            "legacy-secret",
            CredentialKind::Secret,
            Some(190),
            CredentialStatus::Active,
        ),
    ]
}

// ---------------- Key Vault ----------------

pub fn kv_secret_item(name: &str) -> KvSecretItemDto {
    KvSecretItemDto {
        name: name.to_string(),
        id: format!("https://myvault.vault.azure.net/secrets/{name}"),
        enabled: Some(true),
        expires: None,
        content_type: None,
    }
}

pub fn kv_secrets(names: &[&str]) -> Vec<KvSecretItemDto> {
    names.iter().map(|n| kv_secret_item(n)).collect()
}

pub fn kv_secret_value(name: &str, value: &str) -> KvSecretValueDto {
    KvSecretValueDto {
        name: name.to_string(),
        value: value.to_string(),
        content_type: None,
        expires: None,
    }
}

// ---------------- Diagnostics ----------------

/// Plausible cache hit/miss counters + TTL config for the Cache diagnostics
/// dialog (an infallible `invoke`, so it must resolve in the demo).
pub fn cache_stats() -> CacheStatsDto {
    CacheStatsDto {
        service_principal_hits: 128,
        service_principal_misses: 12,
        permissions_hits: 64,
        permissions_misses: 8,
        audit_hits: 4,
        audit_misses: 1,
        lists_hits: 32,
        lists_misses: 5,
        enabled: true,
        service_principal_ttl_secs: 300,
        permissions_ttl_secs: 3600,
        audit_ttl_secs: 600,
        lists_ttl_secs: 120,
        max_cache_size: 512,
    }
}

// ---------------- Progress payloads (streamed events) ----------------

pub fn bulk_progress(done: usize, total: usize) -> BulkProgress {
    BulkProgress {
        done,
        total,
        current_app: None,
        cancelled: false,
        in_flight_cap: None,
    }
}

/// A backup-progress event carrying the adaptive concurrency cap — drives the DR
/// view's progress bar and (when the cap drops below its peak) its back-off notice.
pub fn backup_progress(done: usize, total: usize, in_flight_cap: usize) -> BulkProgress {
    BulkProgress {
        done,
        total,
        current_app: None,
        cancelled: false,
        in_flight_cap: Some(in_flight_cap),
    }
}

pub fn site_sweep_progress(done: usize, total: usize) -> SiteSweepProgress {
    SiteSweepProgress {
        done,
        total,
        current_site: None,
        cancelled: false,
    }
}

pub fn keyvault_sweep_progress(done: usize, total: usize) -> KeyVaultSweepProgress {
    KeyVaultSweepProgress {
        done,
        total,
        current_vault: None,
        cancelled: false,
    }
}

pub fn mailbox_probe_progress(done: usize, total: usize) -> MailboxProbeProgress {
    MailboxProbeProgress {
        done,
        total,
        current_app: None,
        cancelled: false,
    }
}

/// A `global_search` result carrying only `app_registrations` hits (synthetic
/// ids/appIds), with no enterprise/MI hits — for the top-bar search dropdown.
pub fn global_search_apps(display_names: &[&str]) -> azapptoolkit_dto::search::GlobalSearchResults {
    azapptoolkit_dto::search::GlobalSearchResults {
        query: String::new(),
        looked_up_as_guid: false,
        app_registrations: display_names
            .iter()
            .enumerate()
            .map(|(i, n)| azapptoolkit_dto::search::SearchHit {
                id: format!("obj-{i}"),
                app_id: Some(format!("app-{i}")),
                display_name: (*n).to_string(),
            })
            .collect(),
        enterprise_apps: Vec::new(),
        managed_identities: Vec::new(),
    }
}

// ---------------- Permission picker (catalog) ----------------

/// Microsoft Graph's well-known first-party appId — the picker's default
/// resource, and the only one the MI / SP grant flows resource-scope against.
pub const MICROSOFT_GRAPH_APP_ID: &str = "00000003-0000-0000-c000-000000000000";

/// The Microsoft Graph entry for the picker's resource dropdown.
pub fn graph_resource_summary() -> CatalogResourceSummary {
    CatalogResourceSummary {
        app_id: MICROSOFT_GRAPH_APP_ID.to_string(),
        display_name: "Microsoft Graph".to_string(),
        role_count: 1,
        scope_count: 0,
    }
}

/// A `ResourcePermissions` for Microsoft Graph exposing the given application
/// permissions (app roles) by value — each with
/// `allowed_member_types = ["Application"]` so the managed-identity picker
/// (`ApplicationOnly`) keeps them.
pub fn graph_resource_permissions(role_values: &[&str]) -> ResourcePermissions {
    ResourcePermissions {
        app_id: MICROSOFT_GRAPH_APP_ID.to_string(),
        display_name: "Microsoft Graph".to_string(),
        app_roles: role_values
            .iter()
            .map(|v| RoleEntry {
                id: format!("{v}-role-id"),
                value: (*v).to_string(),
                display_name: format!("{v} (application)"),
                description: None,
                allowed_member_types: vec!["Application".to_string()],
            })
            .collect(),
        oauth2_permission_scopes: Vec::new(),
        source: "demo".to_string(),
    }
}

/// A tenant-owned resource (the org's own app registration) that exposes
/// Application app roles — the picker's "Tenant app registrations" group, used
/// by the managed-identity / app-registration grant flow. Stable synthetic
/// appId so `list_resource_permissions` can be keyed to it.
pub fn tenant_app_role_resource() -> CatalogResourceSummary {
    CatalogResourceSummary {
        app_id: guid("contoso-orders-api"),
        display_name: "Contoso Orders API".to_string(),
        role_count: 2,
        scope_count: 0,
    }
}

/// The app roles [`tenant_app_role_resource`] exposes, as `ResourcePermissions`
/// (each an Application role so the `ApplicationOnly` picker keeps them). Keyed
/// off the same appId so selecting the tenant app shows its own roles, not
/// Graph's.
pub fn tenant_app_role_permissions() -> ResourcePermissions {
    ResourcePermissions {
        app_id: guid("contoso-orders-api"),
        display_name: "Contoso Orders API".to_string(),
        app_roles: ["Orders.Read.All", "Orders.ReadWrite.All"]
            .iter()
            .map(|v| RoleEntry {
                id: format!("{v}-role-id"),
                value: (*v).to_string(),
                display_name: format!("{v} (application)"),
                description: None,
                allowed_member_types: vec!["Application".to_string()],
            })
            .collect(),
        oauth2_permission_scopes: Vec::new(),
        source: "demo".to_string(),
    }
}

/// A clean `GrantResult` (no failures) — the outcome of an org-wide
/// `grant_single_permission`.
pub fn grant_result() -> azapptoolkit_dto::permissions::GrantResult {
    azapptoolkit_dto::permissions::GrantResult {
        client_service_principal_id: "client-sp".to_string(),
        role_assignments_created: Vec::new(),
        role_assignments_skipped: Vec::new(),
        scope_grants_upserted: Vec::new(),
        failures: Vec::new(),
    }
}

/// A successful `ExchangeAccessResult` — the outcome the inline scope panel
/// reports after confining a mail permission to a group (one role assigned,
/// one org-wide grant removed).
pub fn exchange_access_result() -> ExchangeAccessResult {
    ExchangeAccessResult {
        app_id: "mi-0-appid".to_string(),
        service_principal_object_id: Some("mi-0".to_string()),
        scope_name: "azapptoolkit_mi-0-appid".to_string(),
        scope_filter: "MemberOfGroup -eq 'azapptoolkit_mi-0-appid'".to_string(),
        groups: Vec::new(),
        roles_assigned: vec!["Application Mail.Read".to_string()],
        roles_skipped: Vec::new(),
        removed_entra_grants: vec!["Mail.Read".to_string()],
        warnings: Vec::new(),
    }
}

// ---------------- Detail-pane atoms (credentials, held permissions, scope) ----------------

/// A fixed UTC date — demo data is deterministic (no runtime clock).
pub fn date(year: i32, month: u32, day: u32) -> Option<DateTime<Utc>> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).single()
}

/// A deterministic, synthetic v4-shaped GUID from a seed string: stable across
/// reloads (no RNG) so detail lookups by id are reproducible, while *looking*
/// like a real Entra object/app id (`8-4-4-4-12` hex, version+variant nibbles set).
pub fn guid(seed: &str) -> String {
    // FNV-1a 64-bit of the seed, expanded to 128 bits via two splitmix64 draws.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in seed.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    fn mix(mut z: u64) -> u64 {
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    let hi = mix(h);
    let lo = mix(h ^ 0xd1b5_4a32_d192_ed03);
    let mut s = format!("{hi:016x}{lo:016x}").into_bytes();
    s[12] = b'4'; // version nibble
    s[16] = [b'8', b'9', b'a', b'b'][(lo & 3) as usize]; // variant nibble
    let s = String::from_utf8(s).expect("hex is ascii");
    format!(
        "{}-{}-{}-{}-{}",
        &s[0..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    )
}

/// A client secret with a display name, masked hint, and expiry (Credentials tab).
pub fn password_credential(
    display_name: &str,
    hint: &str,
    end: Option<DateTime<Utc>>,
) -> PasswordCredential {
    PasswordCredential {
        key_id: guid(&format!("secret:{display_name}")),
        display_name: Some(display_name.to_string()),
        hint: Some(hint.to_string()),
        start_date_time: date(2024, 6, 1),
        end_date_time: end,
        secret_text: None,
    }
}

/// A certificate (key) credential with a display name and expiry (Credentials tab).
pub fn key_credential(display_name: &str, end: Option<DateTime<Utc>>) -> KeyCredential {
    KeyCredential {
        key_id: guid(&format!("cert:{display_name}")),
        display_name: Some(display_name.to_string()),
        usage: Some("Verify".to_string()),
        r#type: Some("AsymmetricX509Cert".to_string()),
        start_date_time: date(2024, 6, 1),
        end_date_time: end,
        custom_key_identifier: Some("0f7a2c9b1e4d6a8f3b5c2e1d9a4f6b8c0e2d4a6f".to_string()),
    }
}

/// A resolved (held) permission row for the Permissions tab. SharePoint scope
/// badges are name-based off `value` (`Sites.Selected` → scoped, `Sites.*` →
/// org-wide); Exchange mailbox scope comes from [`mail_scope_scoped`] via
/// `get_mail_permission_scopes`.
pub fn resolved_permission(
    resource_app_id: &str,
    resource_display_name: &str,
    value: &str,
    display_name: &str,
    kind: PermissionKind,
) -> ResolvedPermission {
    ResolvedPermission {
        resource_app_id: resource_app_id.to_string(),
        resource_display_name: Some(resource_display_name.to_string()),
        permission_id: guid(&format!("perm:{value}")),
        permission_value: Some(value.to_string()),
        permission_display_name: Some(display_name.to_string()),
        permission_kind: kind,
        runtime_assignment_id: Some(guid(&format!("assign:{value}"))),
        runtime_grant_id: None,
    }
}

/// A `get_mail_permission_scopes` entry confining a Graph mail permission to a
/// named group via Exchange RBAC for Applications — drives the "Scoped: N
/// group(s)" mailbox badge on the Permissions tab.
pub fn mail_scope_scoped(
    graph_permission: &str,
    scope_name: &str,
    group_count: u32,
) -> MailScopeEntry {
    MailScopeEntry {
        graph_permission: graph_permission.to_string(),
        exchange_role: format!("Application {graph_permission}"),
        scope: MailPermissionScope::Scoped {
            scope_name: Some(scope_name.to_string()),
            recipient_filter: Some(format!("MemberOfGroup -eq '{scope_name}'")),
            group_count: Some(group_count),
            mechanism: ScopeMechanism::Rbac,
        },
    }
}

// ---------------- Enterprise-app & managed-identity detail tabs ----------------

/// A directory object (user/group) — an enterprise-app owner or assigned principal.
pub fn directory_object(id_seed: &str, display_name: &str, upn: &str) -> DirectoryObject {
    DirectoryObject {
        id: guid(id_seed),
        display_name: Some(display_name.to_string()),
        user_principal_name: Some(upn.to_string()),
        mail: None,
        odata_type: Some("#microsoft.graph.user".to_string()),
    }
}

/// Demo users returned by `search_users` (owner pickers). Args-agnostic — any
/// 2+ char query surfaces this set so the add-owner flow is demoable.
pub fn directory_user_search() -> Vec<DirectoryObject> {
    vec![
        directory_object("search:jordan", "Jordan Lee", "jordan@contoso.com"),
        directory_object("search:pat", "Pat Rivera", "pat@contoso.com"),
        directory_object("search:morgan", "Morgan Diaz", "morgan@contoso.com"),
    ]
}

/// Demo distribution lists returned by `search_distribution_lists` (each carries
/// a mail address), for the SSO notification-email picker.
/// Sample Entra application-gallery templates for the "Browse the gallery"
/// picker (demo + GUI tests). Deliberately varied — names that only match a
/// query mid-word ("force" → Salesforce), by a later word ("teams" → Microsoft
/// Teams), or via the publisher only ("google" → Workspace) — so the demo's
/// args-aware mock ([`gallery_search_for`]) actually exercises the backend's
/// substring/token ranking instead of looking like a fixed list.
pub fn application_templates() -> Vec<ApplicationTemplateDto> {
    let tmpl = |seed: &str, name: &str, publisher: &str, modes: &[&str]| ApplicationTemplateDto {
        id: guid(seed),
        display_name: name.to_string(),
        publisher: Some(publisher.to_string()),
        description: Some(format!("{name} single sign-on integration.")),
        categories: vec!["collaboration".to_string()],
        logo_url: None,
        supported_single_sign_on_modes: modes.iter().map(|m| m.to_string()).collect(),
    };
    vec![
        tmpl(
            "tmpl:sf",
            "Salesforce",
            "Salesforce.com",
            &["saml", "password"],
        ),
        tmpl("tmpl:snow", "ServiceNow", "ServiceNow", &["saml"]),
        tmpl("tmpl:zoom", "Zoom", "Zoom Video Communications", &["saml"]),
        tmpl("tmpl:teams", "Microsoft Teams", "Microsoft", &["saml"]),
        tmpl("tmpl:o365", "Office 365", "Microsoft", &["saml"]),
        tmpl(
            "tmpl:gws",
            "Google Workspace",
            "Google LLC",
            &["saml", "password"],
        ),
        tmpl("tmpl:slack", "Slack", "Slack Technologies", &["saml"]),
        tmpl("tmpl:box", "Dropbox Business", "Dropbox", &["saml"]),
        tmpl("tmpl:gh", "GitHub", "GitHub, Inc.", &["saml"]),
        tmpl(
            "tmpl:cs",
            "CrowdStrike Falcon Platform",
            "CrowdStrike",
            &["saml"],
        ),
    ]
}

/// Static GUI-test reply for `search_application_templates`: every sample
/// template as an untruncated full-catalog result, ignoring the query. Used by
/// the gallery GUI test, which only needs a known template (Salesforce) present
/// to drive the pick → confirm → create flow; query matching is covered by
/// [`gallery_search_for`] and the backend's own unit tests.
pub fn gallery_search_results() -> GallerySearchResultsDto {
    let results = application_templates();
    GallerySearchResultsDto {
        total_matches: results.len(),
        results,
        truncated: false,
        partial_catalog: false,
    }
}

/// Args-aware demo reply for `search_application_templates`: actually filters
/// and ranks the sample catalog by `query`, so the GitHub Pages demo shows the
/// real substring search ("force" → Salesforce, "365" → Office 365) instead of
/// echoing the whole list back for every keystroke.
///
/// Mirrors the backend's `gallery_relevance`
/// (`commands::enterprise_application`): a row matches only when **every**
/// whitespace token appears somewhere in its lowercased name or publisher (AND,
/// not OR), and the tier is exact < name-prefix < word-boundary < substring <
/// publisher/token-only. A query under 2 characters returns nothing, matching
/// the picker's gate.
pub fn gallery_search_for(query: &str) -> GallerySearchResultsDto {
    let needle = query.trim().to_lowercase();
    if needle.chars().count() < 2 {
        return GallerySearchResultsDto::default();
    }
    let tokens: Vec<&str> = needle.split_whitespace().collect();

    // Tier for one row (lower = better), or None when it doesn't match. Kept
    // byte-for-byte faithful to the backend's ordering so the demo can't drift
    // from the real ranking.
    let starts_word = |hay: &str, sub: &str| {
        hay.match_indices(sub).any(|(i, _)| {
            hay[..i]
                .chars()
                .next_back()
                .is_none_or(|c| !c.is_alphanumeric())
        })
    };
    let rank = |name_lc: &str, publisher_lc: &str| -> Option<u8> {
        if !tokens
            .iter()
            .all(|t| name_lc.contains(t) || publisher_lc.contains(t))
        {
            return None;
        }
        Some(if name_lc == needle {
            0
        } else if name_lc.starts_with(&needle) {
            1
        } else if starts_word(name_lc, &needle) {
            2
        } else if name_lc.contains(&needle) {
            3
        } else {
            4
        })
    };

    let mut hits: Vec<(u8, ApplicationTemplateDto)> = application_templates()
        .into_iter()
        .filter_map(|t| {
            let name_lc = t.display_name.to_lowercase();
            let publisher_lc = t.publisher.as_deref().unwrap_or_default().to_lowercase();
            rank(&name_lc, &publisher_lc).map(|r| (r, t))
        })
        .collect();
    hits.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.display_name.cmp(&b.1.display_name))
            .then_with(|| a.1.id.cmp(&b.1.id))
    });

    let results: Vec<ApplicationTemplateDto> = hits.into_iter().map(|(_, t)| t).collect();
    GallerySearchResultsDto {
        total_matches: results.len(),
        results,
        truncated: false,
        // The demo's catalog IS partial — a dozen curated samples of a ~39k
        // gallery. Admitting that turns a demo no-match into "the gallery was
        // only partly loaded" instead of the confident "no gallery apps match
        // X", which reads as a broken search to anyone who knows X exists.
        partial_catalog: true,
    }
}

/// A gallery search that ran and matched nothing — distinct from "no query
/// yet", which the picker must not confuse it with.
pub fn gallery_search_no_matches() -> GallerySearchResultsDto {
    GallerySearchResultsDto::default()
}

/// Result of creating an enterprise app from a gallery template (demo).
pub fn gallery_app_summary() -> GalleryAppSummary {
    GalleryAppSummary {
        object_id: guid("gallery:obj"),
        service_principal_id: guid("gallery:sp"),
        app_id: guid("gallery:app"),
        display_name: "Salesforce".to_string(),
    }
}

pub fn distribution_list_search() -> Vec<DirectoryObject> {
    let dl = |seed: &str, name: &str, mail: &str| DirectoryObject {
        id: guid(seed),
        display_name: Some(name.to_string()),
        user_principal_name: None,
        mail: Some(mail.to_string()),
        odata_type: Some("#microsoft.graph.group".to_string()),
    };
    vec![
        dl("dl:sso", "SSO Alerts", "sso-alerts@contoso.com"),
        dl("dl:itops", "IT Operations", "it-ops@contoso.com"),
    ]
}

/// Sample per-tenant operator defaults for the Settings page demo.
pub fn tenant_defaults() -> azapptoolkit_core::defaults::TenantDefaults {
    use azapptoolkit_core::defaults::{
        AppRegistrationDefaults, EnterpriseApplicationDefaults, StoredPrincipal, TenantDefaults,
    };
    let owner = |seed: &str, name: &str, upn: &str| StoredPrincipal {
        id: guid(seed),
        display_name: Some(name.to_string()),
        user_principal_name: Some(upn.to_string()),
        odata_type: Some("#microsoft.graph.user".to_string()),
    };
    TenantDefaults {
        app_registration: AppRegistrationDefaults {
            default_owners: vec![owner("default:alex", "Alex Admin", "alex@contoso.com")],
        },
        enterprise_application: EnterpriseApplicationDefaults {
            default_owners: vec![owner("default:sam", "Sam Owner", "sam@contoso.com")],
            default_notification_emails: vec!["sso-alerts@contoso.com".to_string()],
        },
        scope_name_pattern: None,
        group_name_pattern: None,
        secret_name_pattern: None,
        default_vault: None,
        app_vaults: Default::default(),
    }
}

/// A held Microsoft Graph app-role grant — the Permissions/"granted" tab on an
/// enterprise application or managed identity (`list_held_app_role_grants`).
pub fn held_grant(value: &str) -> AppRoleGrantDto {
    AppRoleGrantDto {
        assignment_id: guid(&format!("held:{value}")),
        resource_id: guid("graph-sp"),
        resource_display_name: Some("Microsoft Graph".to_string()),
        app_role_id: guid(&format!("role:{value}")),
        app_role_value: Some(value.to_string()),
    }
}

/// A principal assigned to an enterprise app's app role ("Users and groups").
pub fn app_assignment(principal: &str, principal_type: &str) -> AppAssignmentDto {
    AppAssignmentDto {
        assignment_id: guid(&format!("assign:{principal}")),
        principal_display_name: Some(principal.to_string()),
        principal_type: Some(principal_type.to_string()),
        // All-zero GUID = "default access" (no specific role).
        app_role_id: "00000000-0000-0000-0000-000000000000".to_string(),
    }
}

/// A group the service principal is a direct member of ("Group memberships").
pub fn group_membership(name: &str, security_enabled: bool, m365: bool) -> GroupMembershipDto {
    GroupMembershipDto {
        id: guid(&format!("group:{name}")),
        display_name: name.to_string(),
        security_enabled: Some(security_enabled),
        group_types: if m365 {
            vec!["Unified".to_string()]
        } else {
            Vec::new()
        },
    }
}

/// A SCIM provisioning job for an enterprise application (Provisioning tab).
pub fn provisioning_job(status: &str, last_state: &str, last_run: &str) -> ProvisioningJobDto {
    ProvisioningJobDto {
        id: guid(&format!("prov:{status}")),
        template_id: Some("scim".to_string()),
        status_code: Some(status.to_string()),
        last_state: Some(last_state.to_string()),
        last_run: Some(last_run.to_string()),
        quarantine_reason: None,
    }
}

/// An exposed app role on the SP (App roles tab).
pub fn exposed_app_role(value: &str, display_name: &str, description: &str) -> AppRole {
    AppRole {
        id: guid(&format!("approle:{value}")),
        allowed_member_types: vec!["User".to_string()],
        display_name: display_name.to_string(),
        description: Some(description.to_string()),
        value: value.to_string(),
        is_enabled: Some(true),
    }
}

pub fn app_roles_view(roles: Vec<AppRole>) -> AppRolesView {
    AppRolesView {
        target_kind: "servicePrincipal".to_string(),
        roles,
    }
}

/// One Azure RBAC role assignment held by a managed identity (Azure roles tab).
pub fn azure_role(
    role_name: &str,
    scope_level: &str,
    subscription: &str,
    high_privilege: bool,
) -> AzureRoleDto {
    AzureRoleDto {
        role_name: role_name.to_string(),
        scope: format!("/subscriptions/{}/resourceGroups/rg-prod", guid("sub")),
        scope_level: scope_level.to_string(),
        subscription: subscription.to_string(),
        high_privilege,
    }
}

pub fn azure_roles(roles: Vec<AzureRoleDto>) -> AzureRolesResult {
    AzureRolesResult {
        roles,
        scanned: 2,
        total: 2,
        skipped: 0,
    }
}
