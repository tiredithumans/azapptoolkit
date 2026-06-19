//! Typed fixture builders for the test harness. Built from the shared DTO types
//! (not hand-written JSON), so they can't drift from the wire format the
//! bindings deserialize — the same `serde-wasm-bindgen` round-trip the real IPC
//! uses validates them.

use azapptoolkit_core::audit::ListCredentialStatus;
use azapptoolkit_core::models::Application;
use azapptoolkit_dto::applications::{ApplicationDetail, ApplicationListRowDto};
use azapptoolkit_dto::bulk::BulkProgress;
use azapptoolkit_dto::config::AuthConfigStatus;
use azapptoolkit_dto::enterprise_application::EnterpriseApplicationDto;
use azapptoolkit_dto::keyvault::{KvSecretItemDto, KvSecretValueDto};
use azapptoolkit_dto::managed_identity::{ManagedIdentityDto, MiSubtype};
use azapptoolkit_dto::permission_tester::MailboxProbeProgress;
use azapptoolkit_dto::readiness::{ReadinessItem, ReadinessReport, Verdict};
use azapptoolkit_dto::sharepoint::SiteSweepProgress;
use azapptoolkit_dto::UiError;

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
    }
}

pub fn enterprise_apps(display_names: &[&str]) -> Vec<EnterpriseApplicationDto> {
    display_names
        .iter()
        .enumerate()
        .map(|(i, name)| enterprise_app(&format!("sp-{i}"), name))
        .collect()
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
            ..Default::default()
        },
        service_principal: None,
        owners: Vec::new(),
        app_role_assignments: Vec::new(),
        oauth2_permission_grants: Vec::new(),
        resolved_permissions: Vec::new(),
    }
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

// ---------------- Progress payloads (streamed events) ----------------

pub fn bulk_progress(done: usize, total: usize) -> BulkProgress {
    BulkProgress {
        done,
        total,
        current_app: None,
        cancelled: false,
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

pub fn mailbox_probe_progress(done: usize, total: usize) -> MailboxProbeProgress {
    MailboxProbeProgress {
        done,
        total,
        current_app: None,
        cancelled: false,
    }
}
