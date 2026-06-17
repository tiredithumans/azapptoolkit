use tauri::State;

use azapptoolkit_auth::{SignInOutcome, TenantContext};

use crate::dto::UiError;
use crate::state::AppState;

#[tauri::command]
pub async fn sign_in(state: State<'_, AppState>) -> Result<SignInOutcome, UiError> {
    state.auth.sign_in().await.map_err(Into::into)
}

#[tauri::command]
pub async fn sign_out(state: State<'_, AppState>, tenant: TenantContext) -> Result<(), UiError> {
    state.auth.sign_out(&tenant).await.map_err(UiError::from)?;
    state.graph_clients.lock().remove(&tenant.tenant_id);
    state.exchange_clients.lock().remove(&tenant.tenant_id);
    // Drop EVERY tenant-scoped cache entry — lists, the cached audit run +
    // site sweep (`CacheKind::Audit`), and the SP/permission lookups — so the
    // next sign-in (a different tenant, or a different operator on the SAME
    // tenant) never reads this session's data. `invalidate_tenant` sweeps all
    // kinds by the shared `{tenant_id}|` convention (and is unit-tested in core).
    state.cache.invalidate_tenant(&tenant.tenant_id);
    Ok(())
}

#[tauri::command]
pub async fn current_tenants(state: State<'_, AppState>) -> Result<Vec<TenantContext>, UiError> {
    Ok(state.auth.tenants().await)
}

/// Re-mints the signed-in account's tokens *without* ending the session: drops
/// the tenant's cached access tokens and re-acquires them via the stored
/// refresh token, so a role activated after sign-in — e.g. a PIM "Exchange
/// Administrator" role — is reflected without a full sign-out/sign-in. The
/// per-tenant data caches are deliberately left intact; only the tokens
/// refresh. A dead refresh token surfaces as a typed error so the UI can prompt
/// a fresh sign-in.
#[tauri::command]
pub async fn refresh_session(state: State<'_, AppState>, tenant_id: String) -> Result<(), UiError> {
    state
        .auth
        .refresh_session(&tenant_id)
        .await
        .map_err(UiError::from)
}

/// Runs interactive incremental consent for an optional `feature`'s scopes
/// (e.g. `"arm"`, `"audit_log"`, `"write"`). The recovery path the UI invokes
/// after a command fails with the `consent_required` code: it takes the user
/// through one browser round trip with `prompt=consent`, then seeds the token
/// cache so the retried command's silent token acquisition succeeds.
#[tauri::command]
pub async fn request_scope_consent(
    state: State<'_, AppState>,
    tenant_id: String,
    feature: String,
) -> Result<(), UiError> {
    let scopes = state.consent_scopes_for(&feature).ok_or_else(|| {
        UiError::validation("bad_request", format!("unknown consent feature: {feature}"))
    })?;
    state
        .auth
        .consent_for_scopes(&tenant_id, &scopes)
        .await
        .map_err(UiError::from)
}
