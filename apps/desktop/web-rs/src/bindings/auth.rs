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

/// Revives the last signed-in session from the OS keyring — no browser, no
/// account picker. Called once at launch, before the sign-in card renders.
///
/// `Ok(None)` is the ordinary "nothing to restore" answer (nobody signed in
/// here, the operator signed out, or the stored refresh token expired or was
/// revoked); the backend deliberately reports every such case this way, so a
/// caller shows the normal sign-in card rather than an error.
pub async fn restore_session() -> Result<Option<TenantContext>, UiError> {
    invoke_result("restore_session", ()).await
}

#[derive(Serialize)]
struct SignOutArgs<'a> {
    tenant: &'a TenantContext,
}

pub async fn sign_out(tenant: &TenantContext) -> Result<(), UiError> {
    invoke_result("sign_out", SignOutArgs { tenant }).await
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

/// Interactively re-authenticates the signed-in account in place — one browser
/// round trip (`prompt=login`, pinned to the current account) that mints a fresh
/// refresh + access token without ending the session or wiping the data caches.
/// The recovery path for a dead session (a `refresh_missing` / `not_signed_in`
/// failure) that the silent [`refresh_session`] can't fix. Reuses the
/// `{ tenant }` args shape because the backend needs the full context (the
/// in-memory tenant entry may have been purged when the token was rejected).
pub async fn reauthenticate(tenant: &TenantContext) -> Result<SignInOutcome, UiError> {
    invoke_result("reauthenticate", SignOutArgs { tenant }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConsentArgs<'a> {
    tenant_id: &'a str,
    feature: &'a str,
}

/// Runs interactive incremental consent for a feature's scopes (e.g. `"arm"`,
/// `"audit_log"`, `"write"`) — the round trip a *silent* refresh-token grant
/// cannot make. Call this to recover from a command that failed with the
/// `consent_required` code, then retry the command.
///
/// `"write"` is the Graph read-write bundle every mutating command redeems on
/// first use; it is the default the shared error sink offers
/// (`Session::report_consent_required`), because the per-feature consent
/// buttons scattered across the views only ever covered the on-demand scopes.
pub async fn request_scope_consent(tenant_id: &str, feature: &str) -> Result<(), UiError> {
    invoke_result("request_scope_consent", ConsentArgs { tenant_id, feature }).await
}

/// Cheap probe used by the App shell to short-circuit when the WASM bundle is
/// loaded outside the Tauri webview (e.g. during a `trunk serve` smoke run).
pub fn is_tauri_runtime() -> bool {
    tauri_sys::core::is_tauri()
}
