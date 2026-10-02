//! The signing-certificate lifecycle: rotate, the staged-rollover commands,
//! the shared mint + preferred-key writers, and the pure projection/guard
//! helpers behind them.

use tauri::State;

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_graph::client::ServicePrincipalSigningKeyPatch;

use crate::commands::applications::invalidate_app_lists;
use crate::dto::UiError;
use crate::dto::sso::{SigningCertRolloverDto, SsoCertResult};
use crate::state::AppState;

use super::board::invalidate_sso_cert_board;
use super::{resolve_cert_lifetime_days, saml_summary_urls, validate_cert_subject};

/// Generates a fresh SAML token-signing certificate and activates it immediately
/// — a **big-bang rotation**. Every new assertion is signed by the new key the
/// moment this returns, so any app holding a single static certificate stops
/// accepting sign-ins until its copy is replaced.
///
/// Kept for the app that genuinely can only hold one certificate, where a
/// maintenance window is the plan. Everything else should use the staged flow
/// ([`stage_saml_signing_certificate`] → [`probe_federation_metadata`] →
/// [`activate_saml_signing_certificate`]), which keeps the old certificate
/// available as an instant rollback.
#[tauri::command]
pub async fn rotate_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    subject: String,
    lifetime_days: Option<u32>,
) -> Result<SsoCertResult, UiError> {
    let cert = mint_signing_certificate(
        &state,
        &tenant_id,
        &service_principal_id,
        &subject,
        lifetime_days,
    )
    .await?;
    state
        .graph_for(&tenant_id)
        .patch_service_principal(
            &service_principal_id,
            &ServicePrincipalSigningKeyPatch {
                preferred_token_signing_key_thumbprint: cert.thumbprint.clone(),
            },
        )
        .await?;
    invalidate_app_lists(&state.cache, &tenant_id);
    invalidate_sso_cert_board(&state, &tenant_id);
    Ok(cert)
}

// ---------------- staged rollover ----------------

/// Reads the staged-rollover state of a SAML app's signing certificates.
///
/// Live read (the SSO tab is uncached anyway). The phase is a **pure projection
/// of live Graph state** — nothing about a rollover is persisted, so one
/// abandoned halfway is always resumable and two operators can't hold different
/// ideas about where it is.
#[tauri::command]
pub async fn get_signing_cert_rollover(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
) -> Result<SigningCertRolloverDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let sp = client
        .get_service_principal_sso_fields(&service_principal_id)
        .await?
        .ok_or_else(|| UiError::not_found("service_principal", "Service principal not found."))?;
    Ok(build_rollover(
        &sp,
        &service_principal_id,
        &tenant_id,
        state.auth.cloud(),
        chrono::Utc::now(),
    ))
}

/// **Phase 1 of a staged rollover** — mints a new signing certificate and stops.
///
/// Deliberately does *not* touch `preferredTokenSigningKeyThumbprint`: the new
/// certificate lands inactive, Entra starts publishing it in the app's
/// federation metadata, and an app that polls metadata can pick it up before it
/// ever signs an assertion. Additive and reversible, so this is the half that is
/// safe to run across many apps at once; activation stays per-app and gated.
#[tauri::command]
pub async fn stage_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    subject: String,
    lifetime_days: Option<u32>,
) -> Result<SsoCertResult, UiError> {
    let cert = mint_signing_certificate(
        &state,
        &tenant_id,
        &service_principal_id,
        &subject,
        lifetime_days,
    )
    .await?;
    // `add_token_signing_certificate` self-invalidates the SP cache; the app
    // lists carry no signing-cert field, but the expiry board does.
    invalidate_sso_cert_board(&state, &tenant_id);
    Ok(cert)
}

/// **Phase 3** — promotes a staged certificate to
/// `preferredTokenSigningKeyThumbprint`. The moment this lands, every new SAML
/// assertion is signed by it.
///
/// Re-resolves live state first and refuses anything unsafe: a thumbprint that
/// is no longer on the service principal, or one that has already expired.
/// Activating the certificate that is already active is a no-op, not an error,
/// so a double-click can't produce a scary failure.
///
/// Deliberately **not** gated on a metadata probe having run — a probe can fail
/// for reasons that have nothing to do with the rollover (offline, proxy), and
/// blocking on it would strand an operator mid-window. The UI surfaces it as an
/// unchecked precondition instead.
#[tauri::command]
pub async fn activate_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    thumbprint: String,
) -> Result<SigningCertRolloverDto, UiError> {
    set_preferred_signing_key(state, tenant_id, service_principal_id, thumbprint).await
}

/// **Phase 3b** — the rollback. Re-points `preferredTokenSigningKeyThumbprint`
/// back at the superseded certificate, which is still in `keyCredentials` and
/// therefore takes effect immediately for new assertions.
///
/// Same PATCH as [`activate_saml_signing_certificate`], kept as its own command
/// so the UI can offer it as a distinct, obviously-safe action and so a revert
/// reads as a revert in the logs rather than as another activation.
#[tauri::command]
pub async fn revert_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    thumbprint: String,
) -> Result<SigningCertRolloverDto, UiError> {
    set_preferred_signing_key(state, tenant_id, service_principal_id, thumbprint).await
}

/// **Phase 4** — removes a retired certificate, ending the rollover.
///
/// Refuses to remove the active certificate or the last usable one (either would
/// break sign-in outright), and refuses to remove the sole remaining fallback
/// while a rollover is still in flight — retiring the superseded certificate is
/// what *ends* the ability to roll back, so it can't happen by accident before
/// the new one is confirmed good.
#[tauri::command]
pub async fn retire_saml_signing_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    key_id: String,
) -> Result<SigningCertRolloverDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let before = get_signing_cert_rollover(
        state.clone(),
        tenant_id.clone(),
        service_principal_id.clone(),
    )
    .await?;

    retire_target(&before, &key_id)?;

    client
        .remove_service_principal_key_credential(&service_principal_id, &key_id)
        .await?;
    invalidate_sso_cert_board(&state, &tenant_id);
    get_signing_cert_rollover(state, tenant_id, service_principal_id).await
}

/// Stages a certificate on `service_principal_id` **unless a valid replacement
/// is already staged**, in which case it returns `Ok(None)` having written
/// nothing.
///
/// The idempotency guard for the bulk path. The board's work-queue filter lists
/// an app until its rollover is *finished* (activated), not until it is started
/// — so an operator who stages the queue on Monday and returns on Wednesday
/// would otherwise mint a second spare certificate on every app they already
/// prepared. Staging is additive, so nothing breaks; the pile of unused
/// certificates is just noise that makes the real replacement harder to pick out.
///
/// Re-resolves live state rather than trusting the caller's list, matching the
/// rule every remediation handler follows.
pub(crate) async fn stage_if_not_already(
    state: &State<'_, AppState>,
    tenant_id: &str,
    service_principal_id: &str,
    subject: &str,
    lifetime_days: Option<u32>,
) -> Result<Option<SsoCertResult>, UiError> {
    let roll = get_signing_cert_rollover(
        state.clone(),
        tenant_id.to_string(),
        service_principal_id.to_string(),
    )
    .await?;
    if roll.staged_thumbprint.is_some() {
        return Ok(None);
    }
    let cert = mint_signing_certificate(
        state,
        tenant_id,
        service_principal_id,
        subject,
        lifetime_days,
    )
    .await?;
    invalidate_sso_cert_board(state, tenant_id);
    Ok(Some(cert))
}

/// Mints a signing certificate on the service principal. Shared by the create
/// flow, the one-shot rotate, and [`stage_saml_signing_certificate`], so the
/// subject/lifetime rules can't drift between them.
pub(crate) async fn mint_signing_certificate(
    state: &State<'_, AppState>,
    tenant_id: &str,
    service_principal_id: &str,
    subject: &str,
    lifetime_days: Option<u32>,
) -> Result<SsoCertResult, UiError> {
    let days = resolve_cert_lifetime_days(lifetime_days)?;
    let subject = if subject.is_empty() {
        "CN=SSO"
    } else {
        subject
    };
    // Typed rejection instead of a raw Graph 400 (consistent with create).
    validate_cert_subject(subject)?;
    let end = chrono::Utc::now() + chrono::Duration::days(days as i64);
    let cert = state
        .graph_for(tenant_id)
        .add_token_signing_certificate(service_principal_id, subject, end)
        .await?;
    Ok(SsoCertResult {
        thumbprint: cert.thumbprint.clone(),
        base64: cert.key.clone(),
        expiry: cert.end_date_time.map(|d| d.to_rfc3339()),
    })
}

/// The one PATCH that changes which certificate signs assertions, shared by
/// activate and revert so the guards can't diverge between the forward and the
/// backward move. Re-resolves live state before writing.
pub(crate) async fn set_preferred_signing_key(
    state: State<'_, AppState>,
    tenant_id: String,
    service_principal_id: String,
    thumbprint: String,
) -> Result<SigningCertRolloverDto, UiError> {
    let before = get_signing_cert_rollover(
        state.clone(),
        tenant_id.clone(),
        service_principal_id.clone(),
    )
    .await?;

    let thumb = match activation_target(&before, &thumbprint)? {
        // Idempotent: a double-click shouldn't read as a failure.
        None => return Ok(before),
        Some(target) => target.thumbprint.clone(),
    };

    state
        .graph_for(&tenant_id)
        .patch_service_principal(
            &service_principal_id,
            &ServicePrincipalSigningKeyPatch {
                preferred_token_signing_key_thumbprint: thumb,
            },
        )
        .await?;
    invalidate_sso_cert_board(&state, &tenant_id);
    get_signing_cert_rollover(state, tenant_id, service_principal_id).await
}

/// The canonical (uppercase hex) thumbprint for a `keyCredentials` entry's
/// `customKeyIdentifier`.
///
/// One definition only: [`azapptoolkit_core::thumbprint::canonical`], which
/// carries the full rationale — `customKeyIdentifier` is base64 while
/// `preferredTokenSigningKeyThumbprint` is hex, and comparing them raw is the
/// bug that once made this whole rollover feature silently inert. The WASM
/// frontend renders through the same function, so display and comparison
/// cannot drift.
pub(crate) fn canonical_thumbprint(custom_key_identifier: &str) -> Option<String> {
    azapptoolkit_core::thumbprint::canonical(custom_key_identifier)
}

/// True when a `keyCredentials` entry's `customKeyIdentifier` denotes the same
/// certificate as `preferred` (`preferredTokenSigningKeyThumbprint`). The single
/// comparison — both sides normalised through [`canonical_thumbprint`] first.
pub(crate) fn is_preferred_key(custom_key_identifier: &str, preferred: &str) -> bool {
    match canonical_thumbprint(custom_key_identifier) {
        Some(hex) => hex.eq_ignore_ascii_case(preferred.trim()),
        None => false,
    }
}

/// `preferredTokenSigningKeyThumbprint`, upper-cased through
/// [`canonical_thumbprint`] when it is the hex thumbprint it should be; raw
/// otherwise, never re-decoded. `canonical` reads anything that is not 40 hex
/// characters as base64, so feeding it a malformed nomination would invent a
/// different thumbprint instead of keeping the broken value visible.
pub(crate) fn preferred_thumbprint(sp: &serde_json::Value) -> Option<String> {
    let raw = sp.get("preferredTokenSigningKeyThumbprint")?.as_str()?;
    Some(
        canonical_thumbprint(raw)
            .filter(|c| c.eq_ignore_ascii_case(raw.trim()))
            .unwrap_or_else(|| raw.to_string()),
    )
}

/// Projects a service principal's raw JSON into the rollover view.
///
/// Pure (no Graph, no `State`) so the phase machine is table-testable — mirrors
/// [`extract_sp_sso_fields`]. Two Graph behaviours are load-bearing here:
///
/// - a signing certificate is **two** `keyCredentials` entries (a `Sign` and a
///   `Verify` half sharing one `customKeyIdentifier`), so entries are deduped by
///   thumbprint or the list shows every certificate twice;
/// - `customKeyIdentifier` (base64 bytes) and `preferredTokenSigningKeyThumbprint`
///   (hex) are DIFFERENT ENCODINGS of the same 20 bytes, so both sides go
///   through [`canonical_thumbprint`] before any comparison or display.
pub(crate) fn build_rollover(
    sp: &serde_json::Value,
    service_principal_id: &str,
    tenant_id: &str,
    cloud: CloudEnvironment,
    now: chrono::DateTime<chrono::Utc>,
) -> SigningCertRolloverDto {
    use azapptoolkit_dto::sso::{CertStatus, RolloverPhase, SigningCertDto};

    let app_id = sp
        .get("appId")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let preferred = preferred_thumbprint(sp);

    let parse_time = |v: Option<&serde_json::Value>| -> Option<chrono::DateTime<chrono::Utc>> {
        v.and_then(|x| x.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&chrono::Utc))
    };

    // Dedupe the Sign/Verify pair down to one row per certificate.
    let mut certs: Vec<(SigningCertDto, Option<chrono::DateTime<chrono::Utc>>)> = Vec::new();
    for cred in sp
        .get("keyCredentials")
        .and_then(|v| v.as_array())
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        // Canonical hex, not the raw base64 `customKeyIdentifier` — see
        // `canonical_thumbprint`. An entry whose identifier can't be decoded is
        // skipped rather than shown with a value that matches nothing and can't
        // be activated.
        let Some(thumbprint) = cred
            .get("customKeyIdentifier")
            .and_then(|v| v.as_str())
            .and_then(canonical_thumbprint)
        else {
            continue;
        };
        if certs
            .iter()
            .any(|(c, _)| c.thumbprint.eq_ignore_ascii_case(&thumbprint))
        {
            continue;
        }
        let end = parse_time(cred.get("endDateTime"));
        let is_active = preferred
            .as_deref()
            .is_some_and(|p| p.trim().eq_ignore_ascii_case(&thumbprint));
        certs.push((
            SigningCertDto {
                key_id: cred
                    .get("keyId")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                thumbprint,
                display_name: cred
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                start_date_time: cred
                    .get("startDateTime")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                end_date_time: cred
                    .get("endDateTime")
                    .and_then(|v| v.as_str())
                    .map(str::to_string),
                is_active,
                // Floored, not truncated: `num_days()` rounds toward zero, so a
                // certificate expired less than 24h ago would read `0` — the
                // same number as one *expiring* within 24h — and every `d < 0`
                // check downstream would call it alive while the `end <= now`
                // comparison below calls it Expired. `div_euclid` keeps the
                // day count's sign in agreement with that comparison.
                days_to_expiry: end.map(|e| (e - now).num_seconds().div_euclid(86_400)),
                // Provisional; the pass below needs the active cert's expiry.
                status: CertStatus::Expired,
            },
            end,
        ));
    }

    // The active certificate's expiry is the pivot: a valid non-active cert that
    // outlives it is the rollover candidate, one that doesn't is the fallback.
    let active_end = certs
        .iter()
        .find(|(c, _)| c.is_active)
        .and_then(|(_, end)| *end);
    let active_expired = active_end.is_some_and(|e| e <= now);

    for (cert, end) in &mut certs {
        let expired = end.is_some_and(|e| e <= now);
        cert.status = if expired {
            CertStatus::Expired
        } else if cert.is_active {
            CertStatus::Active
        } else if active_expired || active_end.is_none_or(|a| end.is_some_and(|e| e > a)) {
            // Newer than the active one — or the active one can no longer sign,
            // in which case every valid certificate is a candidate.
            CertStatus::Staged
        } else {
            CertStatus::Superseded
        };
    }

    // Newest first; undated entries sort last.
    certs.sort_by(|(_, a), (_, b)| match (a, b) {
        (Some(a), Some(b)) => b.cmp(a),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    let certs: Vec<SigningCertDto> = certs.into_iter().map(|(c, _)| c).collect();

    let staged_thumbprint = certs
        .iter()
        .find(|c| matches!(c.status, CertStatus::Staged))
        .map(|c| c.thumbprint.clone());
    let has_superseded = certs
        .iter()
        .any(|c| matches!(c.status, CertStatus::Superseded));
    let has_active = certs.iter().any(|c| matches!(c.status, CertStatus::Active));

    let phase = if preferred.is_none() || certs.is_empty() {
        RolloverPhase::Unconfigured
    } else if staged_thumbprint.is_some() {
        RolloverPhase::Staged
    } else if !has_active {
        // A preferred key that is expired (or missing from keyCredentials) with
        // nothing valid to promote — sign-in is broken, not merely mid-rollover.
        RolloverPhase::Unconfigured
    } else if has_superseded {
        RolloverPhase::PendingRetire
    } else {
        RolloverPhase::Steady
    };

    let auto_promote_deadline = matches!(phase, RolloverPhase::Staged)
        .then(|| {
            certs
                .iter()
                .find(|c| c.is_active)
                .and_then(|c| c.end_date_time.clone())
        })
        .flatten();

    let (_, _, _, federation_metadata_url) = saml_summary_urls(cloud, tenant_id, &app_id);
    SigningCertRolloverDto {
        service_principal_id: service_principal_id.to_string(),
        app_id,
        federation_metadata_url,
        certs,
        active_thumbprint: preferred,
        staged_thumbprint,
        phase,
        auto_promote_deadline,
    }
}

/// The **retire** guard (see *Guards* in `docs/architecture/auth-and-consent.md`):
/// picks the certificate `key_id` names out of the live rollover, refusing one
/// that is gone (`cert_not_found`), the nominated one (`cert_is_active` — with an
/// honest message when it has expired but is still nominated) and the staged
/// one (`cert_is_staged`, a pending rollover rather than a leftover). An expired,
/// non-nominated certificate passes — that is the per-row Remove.
///
/// Pure, so every code is table-tested; [`retire_saml_signing_certificate`] is
/// its only caller.
pub(crate) fn retire_target<'a>(
    roll: &'a SigningCertRolloverDto,
    key_id: &str,
) -> Result<&'a azapptoolkit_dto::sso::SigningCertDto, UiError> {
    let target = roll
        .certs
        .iter()
        .find(|c| c.key_id == key_id)
        .ok_or_else(|| {
            UiError::not_found(
                "cert",
                "That certificate is no longer on the service principal.",
            )
        })?;
    if target.is_active {
        // An expired-but-still-nominated certificate isn't signing anything —
        // Entra already promoted the staged one — but removing it while
        // `preferredTokenSigningKeyThumbprint` still points at it would leave
        // the nomination dangling. Same guard, honest message.
        let message = if matches!(target.status, azapptoolkit_dto::sso::CertStatus::Expired) {
            "That certificate has expired but is still nominated as the signing key. \
             Activate its replacement first — then it can be removed."
        } else {
            "That certificate is signing assertions right now. Activate its replacement first."
        };
        return Err(UiError::validation("cert_is_active", message));
    }
    if matches!(target.status, azapptoolkit_dto::sso::CertStatus::Staged) {
        return Err(UiError::validation(
            "cert_is_staged",
            "That certificate is staged for the next rollover, not retired. Activate it or let it expire.",
        ));
    }
    Ok(target)
}

/// The **activate / revert** guard (see *Guards* in
/// `docs/architecture/auth-and-consent.md`): resolves `thumbprint`
/// (case-insensitively) against the live rollover, refusing one that is gone
/// (`cert_not_staged`) or expired (`cert_expired` — checked before the no-op,
/// so an expired-but-nominated certificate is refused rather than "already
/// active"). `Ok(None)` means it is already the active key: activating it again
/// is a no-op, not an error.
///
/// Pure, so every code is table-tested; [`set_preferred_signing_key`] is its
/// only caller.
pub(crate) fn activation_target<'a>(
    roll: &'a SigningCertRolloverDto,
    thumbprint: &str,
) -> Result<Option<&'a azapptoolkit_dto::sso::SigningCertDto>, UiError> {
    let target = roll
        .certs
        .iter()
        .find(|c| c.thumbprint.eq_ignore_ascii_case(thumbprint))
        .ok_or_else(|| {
            UiError::validation(
                "cert_not_staged",
                "That certificate is no longer on the service principal — stage a new one.",
            )
        })?;
    if matches!(target.status, azapptoolkit_dto::sso::CertStatus::Expired) {
        return Err(UiError::validation(
            "cert_expired",
            "That certificate has expired. Entra won't sign with it — stage a new one instead.",
        ));
    }
    if target.is_active {
        return Ok(None);
    }
    Ok(Some(target))
}
