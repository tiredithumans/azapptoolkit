//! Auth IPC bindings: `sign_in`, `sign_out`, `current_tenants`.
//!
//! Tauri's invoke layer expects camelCase keys for command args (the macro
//! converts them to the snake_case Rust parameter names), so the `Args`
//! structs use `#[serde(rename_all = "camelCase")]`.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

use super::{SignInOutcome, TenantContext};

pub async fn sign_in() -> Result<SignInOutcome, UiError> {
    invoke_result("sign_in", ()).await
}

#[derive(Serialize)]
struct SignOutArgs<'a> {
    tenant: &'a TenantContext,
}

pub async fn sign_out(tenant: &TenantContext) -> Result<(), UiError> {
    invoke_result("sign_out", SignOutArgs { tenant }).await
}

pub async fn current_tenants() -> Result<Vec<TenantContext>, UiError> {
    invoke_result("current_tenants", ()).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RefreshSessionArgs<'a> {
    tenant_id: &'a str,
}

/// Re-mints the signed-in account's tokens in place — drops the cached access
/// tokens and re-acquires them via the stored refresh token — so a role
/// activated after sign-in (e.g. a PIM "Exchange Administrator" role) takes
/// effect without a full sign-out/sign-in. The session (refresh token) is kept.
pub async fn refresh_session(tenant_id: &str) -> Result<(), UiError> {
    invoke_result("refresh_session", RefreshSessionArgs { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConsentArgs<'a> {
    tenant_id: &'a str,
    feature: &'a str,
}

/// Runs interactive incremental consent for an optional feature's scopes
/// (e.g. `"arm"`, `"audit_log"`, `"write"`). Call this to recover from a command
/// that failed with the `consent_required` code, then retry the command.
pub async fn request_scope_consent(tenant_id: &str, feature: &str) -> Result<(), UiError> {
    invoke_result("request_scope_consent", ConsentArgs { tenant_id, feature }).await
}

/// Cheap probe used by the App shell to short-circuit when the WASM bundle is
/// loaded outside the Tauri webview (e.g. during a `trunk serve` smoke run).
pub fn is_tauri_runtime() -> bool {
    tauri_sys::core::is_tauri()
}
