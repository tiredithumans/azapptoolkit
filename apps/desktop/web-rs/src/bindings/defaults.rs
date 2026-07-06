//! Per-tenant operator-defaults IPC bindings. The payload types live in
//! `azapptoolkit-core::defaults` (pure data, shared with the backend).

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::{invoke, invoke_result};

pub use azapptoolkit_core::defaults::{
    AppRegistrationDefaults, AppVaultBinding, EnterpriseApplicationDefaults, StoredPrincipal,
    TenantDefaults,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantArgs<'a> {
    tenant_id: &'a str,
}

/// The saved defaults for a tenant (an empty set if none). Infallible — a
/// missing/unparseable settings file falls back to defaults.
pub async fn get_tenant_defaults(tenant_id: &str) -> TenantDefaults {
    invoke("get_tenant_defaults", TenantArgs { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetArgs<'a> {
    tenant_id: &'a str,
    defaults: &'a TenantDefaults,
}

/// Persists the operator-editable defaults for a tenant. Vault bindings are
/// preserved backend-side. The backend validates the notification-email list.
pub async fn set_tenant_defaults(
    tenant_id: &str,
    defaults: &TenantDefaults,
) -> Result<(), UiError> {
    invoke_result(
        "set_tenant_defaults",
        SetArgs {
            tenant_id,
            defaults,
        },
    )
    .await
}
