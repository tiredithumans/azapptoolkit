use tauri::State;

use azapptoolkit_auth::{SignInOutcome, TenantContext};

use crate::dto::UiError;
use crate::state::AppState;

#[tauri::command]
pub async fn sign_in(state: State<'_, AppState>) -> Result<SignInOutcome, UiError> {
    let outcome = state.auth.sign_in().await.map_err(UiError::from)?;
    // Remember WHO signed in (not the token — that is already in the keyring) so
    // the next launch can restore this session silently instead of putting the
    // operator back through the account picker. Best-effort: see
    // `AppState::remember_account`.
    state.remember_account(&outcome.tenant);
    Ok(outcome)
}

/// Revives the last signed-in session from the OS keyring, without a browser
/// round trip — what turns "sign in again every launch" back into "the app is
/// already open on your tenant". Called once by the front-end at startup, before
/// the sign-in card is painted.
///
/// `Ok(None)` — never an error — is the answer for *every* way this can come up
/// empty: nobody has signed in on this machine, the operator signed out, the
/// tenant was repointed, the refresh token expired or was revoked, or the
/// keyring is locked. All of them mean the same thing to the operator (sign in),
/// and the existing sign-in card already says it; an error toast at launch would
/// add noise to a screen that is about to ask for the credential anyway. The
/// code is logged so a persistent failure is still diagnosable — the code only,
/// since an AAD message routinely embeds tenant and user GUIDs.
#[tauri::command]
pub async fn restore_session(state: State<'_, AppState>) -> Result<Option<TenantContext>, UiError> {
    let Some(tenant) = state.remembered_account() else {
        return Ok(None);
    };
    match state.auth.restore_session(&tenant).await {
        Ok(outcome) => Ok(Some(outcome.tenant)),
        Err(err) => {
            let code = UiError::from(err).code;
            tracing::info!(target: "auth", %code, "no session to restore; showing sign-in");
            Ok(None)
        }
    }
}

#[tauri::command]
pub async fn sign_out(state: State<'_, AppState>, tenant: TenantContext) -> Result<(), UiError> {
    state.auth.sign_out(&tenant).await.map_err(UiError::from)?;
    // Signing out is the one place that must also drop the restore pointer:
    // leaving it behind would have the next launch try to revive a session whose
    // keyring token `sign_out` just deleted.
    state.forget_account();
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

/// Interactively re-authenticates the signed-in account *without* ending the
/// session: runs one browser round trip (`prompt=login`, pinned to the current
/// account) to mint a fresh refresh + access token, leaving the per-tenant data
/// caches intact. The recovery path for a dead refresh token — what the silent
/// [`refresh_session`] can't fix — so the user skips the manual sign-out/sign-in
/// (which would also wipe the cached lists + audit run). Takes the full
/// `TenantContext` because an `InvalidGrant` purges the in-memory tenant entry,
/// but the front-end still holds it in `active_tenant`.
#[tauri::command]
pub async fn reauthenticate(
    state: State<'_, AppState>,
    tenant: TenantContext,
) -> Result<SignInOutcome, UiError> {
    state
        .auth
        .reauthenticate(&tenant)
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
