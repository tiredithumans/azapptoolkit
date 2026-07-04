//! Shared IPC argument structs used across multiple binding modules.
//! Every file kept its own derives/serde attributes, which made these
//! byte-identical across 8+ files. Centralizing them cuts ~80 lines of
//! repetition and guarantees a single source of truth for the wire format.

use serde::Serialize;

/// Single-tenant argument for commands that only need a `tenant_id`.
///
/// Must be a named-field struct (not a newtype tuple): serde serializes a
/// newtype struct *transparently* to its inner value, which would send a bare
/// JSON string instead of the `{ "tenantId": "..." }` object every Tauri
/// command parameter list expects. The `rename_all` is likewise a no-op on a
/// tuple struct.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantArg<'a> {
    pub tenant_id: &'a str,
}

/// Two-field argument for commands that need `tenant_id` + an object id.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectIdArgs<'a> {
    pub tenant_id: &'a str,
    pub object_id: &'a str,
}

/// Two-field argument for commands keyed on `tenant_id` + an application's
/// `app_id` (client id) — e.g. sign-in activity, Conditional Access, Exchange
/// scope-group reads.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppIdArgs<'a> {
    pub tenant_id: &'a str,
    pub app_id: &'a str,
}

/// Two-field argument for commands keyed on `tenant_id` + a service
/// principal's object id — e.g. the enterprise-app detail, held grants, SSO
/// config reads.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServicePrincipalIdArgs<'a> {
    pub tenant_id: &'a str,
    pub service_principal_id: &'a str,
}

/// Three-field argument for commands that need `tenant_id` + an object id + a key id.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyIdArgs<'a> {
    pub tenant_id: &'a str,
    pub object_id: &'a str,
    pub key_id: &'a str,
}
