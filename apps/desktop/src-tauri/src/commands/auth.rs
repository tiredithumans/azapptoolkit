use tauri::State;

use azapptoolkit_auth::{AuthError, EntraAuthService, SignInOutcome, TenantContext};

use crate::commands::progress::{ProgressSink, emit_progress};
use crate::dto::UiError;
use crate::state::AppState;

/// The event the sign-in link rides when the system browser can't be launched:
/// `Some(authorize_url)` while that browser leg is live, `None` once the flow
/// ended (however it ended). Consumed by the webview's `BrowserFallbackNotice`.
const BROWSER_FALLBACK_EVENT: &str = "auth-browser-fallback";

/// Hands the auth service a way to offer the sign-in link in the app's own
/// window when the system browser won't open (no default handler, a confined
/// `xdg-open`, a policy blocking the handler) — sign-in, consent, step-up and
/// re-auth all run through the same authorization-code flow, so one hook
/// covers them all. Installed once at startup.
///
/// Safe to hand to the operator's own webview: the URL is single-use, bound to
/// this flow's PKCE verifier and `state`, and only redeemable through this
/// process's 127.0.0.1 listener. It is never logged.
pub(crate) fn offer_sign_in_link_in_the_webview<S>(sink: S, auth: &EntraAuthService)
where
    S: ProgressSink + Send + Sync + 'static,
{
    auth.set_browser_fallback(move |url| {
        emit_progress(&sink, BROWSER_FALLBACK_EVENT, url.map(str::to_owned));
    });
}

/// Interactive sign-in (`prompt=select_account`). The account picker can hand
/// back a DIFFERENT operator on the same tenant than the one before, and the
/// tenant data caches key on the tenant, not the account — so a sign-in sweeps
/// them (`AppState::forget_tenant`) and deletes the previous account's keyring
/// token. Only here: `reauthenticate` and the dead-session purge keep the data
/// caches, since they are pinned to the same account.
#[tauri::command]
pub async fn sign_in(state: State<'_, AppState>) -> Result<SignInOutcome, UiError> {
    // Read before `remember_account` below overwrites it.
    let previous = state.remembered_account();
    let outcome = state.auth.sign_in().await.map_err(UiError::from)?;
    let tenant = &outcome.tenant;
    if let Some(previous) = previous
        && previous.tenant_id == tenant.tenant_id
        && previous.account_oid != tenant.account_oid
    {
        // Nothing would address the old `{tenant}:{oid}` keyring entry again
        // once the pointer moves to the new account, so it would sit there as
        // a live refresh token. Best-effort: the sign-in itself succeeded.
        if let Err(err) = state
            .auth
            .forget_previous_account(&previous.tenant_id, &previous.account_oid)
            .await
        {
            let code = UiError::from(err).code;
            tracing::warn!(target: "auth", %code, "could not delete the previous account's stored sign-in");
        }
    }
    // Remember WHO signed in (not the token — that is already in the keyring) so
    // the next launch can restore this session silently instead of putting the
    // operator back through the account picker. Best-effort: see
    // `AppState::remember_account`.
    state.remember_account(tenant);
    // A previous account's lists, audit run and lookups must never be read by
    // this one (see `AppState::forget_tenant`).
    state.forget_tenant(&tenant.tenant_id);
    Ok(outcome)
}

/// Revives the last signed-in session from the OS keyring, without a browser
/// round trip — what turns "sign in again every launch" back into "the app is
/// already open on your tenant". Called once by the front-end at startup, before
/// the sign-in card is painted.
///
/// `Ok(None)` is the answer for *every* way this can come up empty: nobody has
/// signed in on this machine, the operator signed out, the tenant was
/// repointed, the refresh token expired or was revoked, or the keyring is
/// locked. All of them mean the same thing to the operator (sign in), and the
/// existing sign-in card already says it; an error toast at launch would add
/// noise to a screen that is about to ask for the credential anyway. The code
/// is logged so a persistent failure is still diagnosable — the code only,
/// since an AAD message routinely embeds tenant and user GUIDs.
///
/// The ONE exception is an unreachable token endpoint (`network`: offline, a
/// captive portal, a proxy down). There the refresh token is intact — only
/// `InvalidGrant` purges it — so "sign in" is the wrong instruction (it opens a
/// browser that can't load Entra ID either), and a retry succeeds once
/// connectivity returns. That case is an `Err`, which the launch screen answers
/// with a Retry. See [`restore_outcome`].
#[tauri::command]
pub async fn restore_session(state: State<'_, AppState>) -> Result<Option<TenantContext>, UiError> {
    let Some(tenant) = state.remembered_account() else {
        return Ok(None);
    };
    let result = state.auth.restore_session(&tenant).await;
    if forgets_the_remembered_account(&result) {
        // The stored sign-in belonged to someone else (the service already
        // deleted its token); drop the pointer too, so the next launch shows
        // the sign-in card instead of repeating the refused restore.
        state.forget_account();
    }
    let restored = restore_outcome(result)?;
    // The refresh's id token carries the account's current UPN and display
    // name; a rename since the last sign-in is written back so the next launch
    // (and its `login_hint`) starts from it.
    if let Some(fresh) = &restored
        && *fresh != tenant
    {
        state.remember_account(fresh);
    }
    Ok(restored)
}

/// Whether a restore attempt proved the remembered account wrong: the refresh
/// came back for a different identity (`EntraAuthService::restore_session`'s
/// `Authorization`, the only one a silent grant produces). Every other failure
/// keeps the pointer — offline, a locked keyring and a revoked token are not
/// evidence it addresses the wrong account.
fn forgets_the_remembered_account(result: &azapptoolkit_auth::Result<SignInOutcome>) -> bool {
    matches!(result, Err(AuthError::Authorization(_)))
}

/// [`restore_session`]'s answer for one silent restore attempt: the restored
/// tenant, `Err` only for `network`, `Ok(None)` for everything else. Split out
/// so the policy is testable without a `settings.json`.
fn restore_outcome(
    result: azapptoolkit_auth::Result<SignInOutcome>,
) -> Result<Option<TenantContext>, UiError> {
    match result {
        Ok(outcome) => Ok(Some(outcome.tenant)),
        Err(err) => {
            let ui = UiError::from(err);
            // The code only: a `network` message's cause chain can carry the
            // token URL, and with it the tenant GUID.
            if ui.code == "network" {
                tracing::info!(
                    target: "auth",
                    code = %ui.code,
                    "could not reach Entra ID to restore the session; offering retry"
                );
                return Err(ui);
            }
            let code = ui.code;
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
    // Every per-tenant client map, idle gate and cache kind — one sweep, so a
    // new map can't be missed here (see `AppState::forget_tenant`).
    state.forget_tenant(&tenant.tenant_id);
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

/// Completes a Conditional Access step-up for an optional `feature`'s audience
/// (e.g. `"arm"`, `"exchange"`, `"log_analytics"`). The recovery path the UI's
/// "Verify identity" levers invoke after a command fails with the
/// `interaction_required` code (MFA, registration or an external challenge a
/// policy demands for that resource): one browser round trip with
/// `prompt=login`, pinned to the signed-in account, that seeds the token cache
/// so the retried command's silent acquisition succeeds. The session is never
/// dropped — that code does not purge the refresh token.
///
/// `EntraAuthService::step_up_where_required` picks the set: every Graph
/// feature steps up on the sign-in read scopes (a Graph policy targets the
/// resource, and the read set is the one always consented), and a non-Graph
/// feature opens the browser only when its silent acquisition still needs the
/// step-up — so a surface can name every audience its command touches.
#[tauri::command]
pub async fn request_scope_step_up(
    state: State<'_, AppState>,
    tenant_id: String,
    feature: String,
) -> Result<(), UiError> {
    let scopes = state.consent_scopes_for(&feature).ok_or_else(|| {
        UiError::validation("bad_request", format!("unknown step-up feature: {feature}"))
    })?;
    state
        .auth
        .step_up_where_required(&tenant_id, &scopes)
        .await
        .map_err(UiError::from)
}

#[cfg(test)]
mod tests {
    use super::{forgets_the_remembered_account, restore_outcome};
    use azapptoolkit_auth::{AuthError, SignInOutcome, TenantContext};

    fn tenant() -> TenantContext {
        TenantContext {
            tenant_id: "t1".into(),
            account_oid: "oid".into(),
            username: None,
            display_name: None,
        }
    }

    #[test]
    fn restore_outcome_errs_only_when_entra_is_unreachable() {
        // reqwest defers an unparseable URL to `build()`, the one public way
        // to get a `reqwest::Error` without a live socket.
        let http = reqwest::Client::new()
            .get("not a url")
            .build()
            .expect_err("an unparseable URL fails to build");
        let err = restore_outcome(Err(AuthError::Http(http))).expect_err("network is an Err");
        assert_eq!(err.code, "network");

        for empty in [
            AuthError::InvalidGrant("x".into()),
            AuthError::RefreshTokenMissing("t".into()),
            AuthError::Keyring("locked".into()),
            AuthError::NotSignedIn,
        ] {
            let label = format!("{empty:?}");
            assert!(
                matches!(restore_outcome(Err(empty)), Ok(None)),
                "{label} must land on the plain sign-in card"
            );
        }

        let restored = restore_outcome(Ok(SignInOutcome { tenant: tenant() }))
            .expect("a restored session is Ok")
            .expect("and carries its tenant");
        assert_eq!(restored.tenant_id, "t1");
    }

    #[test]
    fn only_an_identity_mismatch_forgets_the_remembered_account() {
        assert!(forgets_the_remembered_account(&Err(
            AuthError::Authorization("session restore completed with a different account".into())
        )));
        for kept in [
            AuthError::InvalidGrant("x".into()),
            AuthError::RefreshTokenMissing("t".into()),
            AuthError::Keyring("locked".into()),
            AuthError::TokenExchange("malformed id_token".into()),
        ] {
            let label = format!("{kept:?}");
            assert!(!forgets_the_remembered_account(&Err(kept)), "{label}");
        }
        assert!(!forgets_the_remembered_account(&Ok(SignInOutcome {
            tenant: tenant()
        })));
    }
}
