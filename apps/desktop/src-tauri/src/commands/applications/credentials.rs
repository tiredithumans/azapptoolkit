use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tauri::{AppHandle, State};

use azapptoolkit_core::models::{NewKeyCredential, PasswordCredential};

use crate::dto::UiError;
use crate::dto::applications::{
    AddCertificateInput, AddPasswordInput, GenerateCertificateInput, GeneratedCertificateResult,
    KeyFailure, RemoveExpiredResult, UploadedCertificate,
};
use crate::state::AppState;

use super::invalidate_app_credentials;

#[tauri::command]
pub async fn add_password(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: AddPasswordInput,
) -> Result<PasswordCredential, UiError> {
    add_password_core(&state, &tenant_id, &object_id, input).await
}

/// The handler body, taking `&AppState` instead of `State<'_, AppState>`.
///
/// `tauri::State` can only be built by the Tauri runtime, and the `tauri/test`
/// dev-dependency was dropped (it broke the Windows test binary — see
/// `d8d293e`), so a `#[tauri::command]` signature is unreachable from a test.
/// That is why no test had ever exercised a handler end to end: the rules that
/// live *here* rather than in a pure helper — call Graph, invalidate **only** on
/// `Ok`, and invalidate the credential tier without dropping the tenant-wide
/// indexes — were checked by review alone. Splitting the body out gives that
/// orchestration a seam without adding a dependency.
pub(crate) async fn add_password_core(
    state: &AppState,
    tenant_id: &str,
    object_id: &str,
    input: AddPasswordInput,
) -> Result<PasswordCredential, UiError> {
    let (start, end) = resolve_password_window(&input, chrono::Utc::now())
        .map_err(|e| UiError::validation("invalid_secret_window", e.to_string()))?;
    let client = state.graph_for(tenant_id);
    let cred = client
        .add_password_window(object_id, &input.display_name, start, end)
        .await?;
    invalidate_app_credentials(&state.cache, tenant_id, object_id);
    Ok(cred)
}

/// Maximum client-secret lifetime — the portal's 24-month hard cap, as the
/// `i64` the date arithmetic here wants. The number itself lives in the dto
/// crate beside the frontend's, so one concept has one bound; the OIDC SSO
/// create path (`sso::resolve_secret_lifetime_days`) shares this.
pub(crate) const MAX_SECRET_LIFETIME_DAYS: i64 =
    crate::dto::credentials::MAX_SECRET_LIFETIME_DAYS as i64;

/// Why [`resolve_password_window`] refused a custom secret window. Both causes
/// cross IPC as the one `invalid_secret_window` code (no consumer branches on
/// the cause — the credentials tab validates client-side in its own words);
/// the variant is what tests match, and `Display` is the operator sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretWindowError {
    /// The expiry is not strictly after the (explicit or implied) start.
    EndNotAfterStart,
    /// The window is longer than [`MAX_SECRET_LIFETIME_DAYS`].
    LifetimeOverCap,
}

impl std::fmt::Display for SecretWindowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::EndNotAfterStart => "expiry must be after the start date",
            Self::LifetimeOverCap => "secret lifetime cannot exceed 24 months",
        })
    }
}

/// Resolves an [`AddPasswordInput`] to the `(start, end)` window sent to
/// Graph. An explicit `end_date_time` (portal "Custom" expiry) wins over
/// `lifetime_days`; without either, defaults to 180 days, matching the
/// portal's recommended preset.
fn resolve_password_window(
    input: &AddPasswordInput,
    now: chrono::DateTime<chrono::Utc>,
) -> std::result::Result<
    (
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
    ),
    SecretWindowError,
> {
    match input.end_date_time {
        Some(end) => {
            let effective_start = input.start_date_time.unwrap_or(now);
            if end <= effective_start {
                return Err(SecretWindowError::EndNotAfterStart);
            }
            if end - effective_start > chrono::Duration::days(MAX_SECRET_LIFETIME_DAYS) {
                return Err(SecretWindowError::LifetimeOverCap);
            }
            Ok((input.start_date_time, end))
        }
        None => Ok((None, preset_secret_end(input.lifetime_days, now))),
    }
}

/// The end of a secret created from a preset lifetime: `lifetime_days`
/// (default 180, the portal's recommended preset) clamped to
/// `1..=`[`MAX_SECRET_LIFETIME_DAYS`], counted from `now`.
///
/// The one definition of that rule — `add_password` and the initial secret
/// `create_application` mints both read it, so neither path can mint a
/// zero-length or a past-the-cap secret the other would refuse.
pub(crate) fn preset_secret_end(
    lifetime_days: Option<u32>,
    now: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    let days =
        i64::from(lifetime_days.unwrap_or(crate::dto::credentials::DEFAULT_SECRET_LIFETIME_DAYS))
            .clamp(1, MAX_SECRET_LIFETIME_DAYS);
    now + chrono::Duration::days(days)
}

#[tauri::command]
pub async fn remove_password(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    key_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.remove_password(&object_id, &key_id).await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    Ok(())
}

// ---------------- Certificate credentials ----------------

/// Uploads an operator-supplied certificate as a verify-only key credential
/// and returns what went up (thumbprint + notAfter, read from the certificate).
/// The paste is parsed first ([`parse_cert_upload`]): a private key, a bundle,
/// an expired certificate or anything that isn't an X.509 certificate is
/// refused before anything reaches Graph.
#[tauri::command]
pub async fn add_certificate_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: AddCertificateInput,
) -> Result<UploadedCertificate, UiError> {
    add_certificate_credential_core(&state, &tenant_id, &object_id, input).await
}

/// The body of [`add_certificate_credential`], taking `&AppState` so "a
/// refused paste never reaches Graph" is reachable from a test (the
/// [`add_password_core`] seam).
pub(crate) async fn add_certificate_credential_core(
    state: &AppState,
    tenant_id: &str,
    object_id: &str,
    input: AddCertificateInput,
) -> Result<UploadedCertificate, UiError> {
    let parsed = parse_cert_upload(&input.pem_or_base64, chrono::Utc::now())
        .map_err(|msg| UiError::validation("invalid_certificate", msg))?;
    let client = state.graph_for(tenant_id);
    let new_cred = NewKeyCredential {
        display_name: Some(input.display_name),
        kind: Some("AsymmetricX509Cert".into()),
        usage: Some("Verify".into()),
        key: parsed.key_b64,
        end_date_time: input.end_date_time,
        ..Default::default()
    };
    client.add_key_credential(object_id, new_cred).await?;
    invalidate_app_credentials(&state.cache, tenant_id, object_id);
    Ok(UploadedCertificate {
        thumbprint: parsed.thumbprint,
        not_after: parsed.not_after,
    })
}

/// Generates a self-signed RSA certificate, attaches its public part to the
/// application as a verify-only key credential, and returns the private key
/// once (it is never persisted by the backend). Ports the legacy
/// `New-SelfSignedCertificate` + upload flow.
#[tauri::command]
pub async fn generate_self_signed_certificate(
    state: State<'_, AppState>,
    tenant_id: String,
    input: GenerateCertificateInput,
) -> Result<GeneratedCertificateResult, UiError> {
    let validity = input
        .validity_days
        .unwrap_or(crate::dto::credentials::DEFAULT_CERT_LIFETIME_DAYS);
    let mut generated = crate::cert::generate_self_signed(&input.subject, i64::from(validity))
        .map_err(|e| UiError::validation("cert_generation_failed", e.to_string()))?;

    let expires_dt =
        chrono::DateTime::<chrono::Utc>::from_timestamp(generated.not_after.unix_timestamp(), 0);

    let client = state.graph_for(&tenant_id);
    // `GeneratedCert: Drop` (zeroizes `private_key_pem` on drop), which means
    // none of its `String` fields can be moved out — we extract each via
    // `mem::take`, leaving an empty husk for `Drop` to zeroize harmlessly.
    let new_cred = NewKeyCredential {
        display_name: Some(input.subject.clone()),
        kind: Some("AsymmetricX509Cert".into()),
        usage: Some("Verify".into()),
        key: std::mem::take(&mut generated.cert_der_base64),
        end_date_time: expires_dt,
        ..Default::default()
    };
    client
        .add_key_credential(&input.object_id, new_cred)
        .await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &input.object_id);

    Ok(GeneratedCertificateResult {
        thumbprint: std::mem::take(&mut generated.thumbprint),
        thumbprint_sha256: std::mem::take(&mut generated.thumbprint_sha256),
        certificate_pem: std::mem::take(&mut generated.cert_pem),
        private_key_pem: std::mem::take(&mut generated.private_key_pem),
        pfx_base64: STANDARD.encode(std::mem::take(&mut generated.pfx_der)),
        pfx_password: std::mem::take(&mut generated.pfx_password),
        expires: expires_dt.map(|d| d.to_rfc3339()).unwrap_or_default(),
    })
}

/// Writes the generated PKCS#12 bundle to a file the operator chooses.
///
/// **Secret-bearing artifact.** The bundle holds the private key, encrypted
/// under a password the same reveal shows once — so to anyone who has both, the
/// file *is* the private key. It goes through `private_file::write_owner_only`
/// like every other file this app writes (that module's doc records why these
/// exceptions to "never write secrets to disk" exist), and the reveal tells the
/// operator to install it and then delete it.
///
/// Deliberately separate from `generate_self_signed_certificate`: a blocking
/// save dialog inside that call would hold the one-time reveal off the screen —
/// the 0.28.1 failure — and would make a cancelled dialog indistinguishable
/// from a failed generation, on the one screen where that difference is
/// unrecoverable. Returns the chosen path, or `None` if the dialog was
/// cancelled.
#[tauri::command]
pub async fn save_generated_certificate_pfx(
    app_handle: AppHandle,
    pfx_base64: String,
    subject: String,
) -> Result<Option<String>, UiError> {
    let bytes = STANDARD
        .decode(&pfx_base64)
        .map_err(|e| UiError::validation("invalid_pfx", format!("not valid base64: {e}")))?;
    let default_name = format!(
        "{}-{}.pfx",
        pfx_file_stem(&subject),
        chrono::Utc::now().format("%Y%m%dT%H%M%S")
    );
    crate::commands::export::write_bytes_via_dialog(
        app_handle,
        "PKCS#12",
        "pfx",
        default_name,
        bytes,
    )
    .await
}

/// A filename-safe stem from a certificate subject.
///
/// The common name is operator-typed, so it can hold path separators and shell
/// metacharacters. This only seeds the save dialog — the operator still picks
/// the real path — but a default containing `/` is a default nobody can accept.
fn pfx_file_stem(subject: &str) -> String {
    let cleaned: String = subject
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    let trimmed = cleaned.trim_matches(['-', '.']);
    if trimmed.is_empty() {
        "certificate".to_string()
    } else {
        trimmed.to_string()
    }
}

#[tauri::command]
pub async fn remove_certificate_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    key_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client.remove_key_credential(&object_id, &key_id).await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    Ok(())
}

/// A certificate read from an operator's paste, ready for Graph.
struct UploadedCert {
    /// Base64 of the parsed DER — the `key` on Graph's `keyCredentials`.
    key_b64: String,
    /// SHA-1, uppercase hex (Entra's `customKeyIdentifier`).
    thumbprint: String,
    not_after: chrono::DateTime<chrono::Utc>,
}

/// Reads an operator-pasted certificate: PEM-armoured text
/// (`-----BEGIN CERTIFICATE-----`...) or a raw base64-encoded DER blob.
///
/// Every armour line is checked before anything is decoded, so a private key
/// anywhere in the paste — alone, before or after the certificate — refuses
/// the whole upload, as does any other PEM label (`PKCS7`, `CERTIFICATE
/// REQUEST`, `PUBLIC KEY`) and a paste holding more than one certificate
/// (taking the first could upload a CA certificate instead of the app's own).
/// Lines outside a block (openssl's `Bag Attributes`, `subject=`) are ignored.
/// The body is then parsed as X.509: a non-certificate, trailing data, or a
/// certificate already expired at `now` is refused.
///
/// **Never echoes the pasted material** — a refusal names the PEM label or the
/// problem, never a body line — and logs nothing: the paste may hold a key.
fn parse_cert_upload(
    input: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> std::result::Result<UploadedCert, String> {
    let body = certificate_body(input)?;
    if body.is_empty() {
        return Err("certificate body is empty".to_string());
    }
    let der = STANDARD
        .decode(&body)
        .map_err(|e| format!("not valid base64: {e}"))?;
    let (rest, cert) = x509_parser::parse_x509_certificate(&der).map_err(|_| {
        "not an X.509 certificate — paste the certificate (.cer/.crt/.pem), not a key or a \
         .pfx/.p7b bundle"
            .to_string()
    })?;
    if !rest.is_empty() {
        return Err("unexpected data after the certificate".to_string());
    }
    let not_after =
        chrono::DateTime::<chrono::Utc>::from_timestamp(cert.validity().not_after.timestamp(), 0)
            .ok_or_else(|| "the certificate's expiry date is out of range".to_string())?;
    if not_after <= now {
        return Err(format!(
            "this certificate expired on {}; upload a current one",
            not_after.format("%Y-%m-%d")
        ));
    }
    // SHA-1 because it is Entra's `customKeyIdentifier` (the portal's
    // Thumbprint) — an identifier, not a security primitive; same derivation
    // as `cert::generate_self_signed`.
    let thumbprint = azapptoolkit_core::thumbprint::hex_upper(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, &der).as_ref(),
    );
    Ok(UploadedCert {
        key_b64: STANDARD.encode(&der),
        thumbprint,
        not_after,
    })
}

/// The base64 body of the one `CERTIFICATE` block in `input`, or — with no
/// PEM armour at all — the whole input with whitespace removed.
fn certificate_body(input: &str) -> std::result::Result<String, String> {
    // The label between `-----BEGIN `/`-----END ` and the trailing dashes.
    // Capped: it is echoed in a refusal, and only a real label belongs there.
    let label_of =
        |rest: &str| -> String { rest.trim_end_matches('-').trim().chars().take(40).collect() };
    let mut armoured = false;
    let mut current: Option<String> = None;
    let mut blocks: Vec<String> = Vec::new();
    for line in input.lines().map(str::trim) {
        let (rest, begins) = if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            (rest, true)
        } else if let Some(rest) = line.strip_prefix("-----END ") {
            (rest, false)
        } else {
            if let Some(body) = current.as_mut() {
                body.extend(line.chars().filter(|c| !c.is_whitespace()));
            }
            continue;
        };
        armoured = true;
        let label = label_of(rest);
        if label.contains("PRIVATE KEY") {
            return Err(format!(
                "this paste contains a private key ({label}). Upload only the certificate — \
                 the private key stays with the app that signs with it, and nothing was sent"
            ));
        }
        if label != "CERTIFICATE" {
            return Err(format!(
                "a {label} block isn't a certificate; paste the -----BEGIN CERTIFICATE----- block"
            ));
        }
        match (begins, current.take()) {
            (true, None) => current = Some(String::new()),
            (false, Some(body)) => blocks.push(body),
            // A BEGIN inside an open block, or an END with none open.
            _ => return Err("incomplete PEM block".to_string()),
        }
    }
    if current.is_some() {
        return Err("incomplete PEM block".to_string());
    }
    if !armoured {
        return Ok(input.chars().filter(|c| !c.is_whitespace()).collect());
    }
    match blocks.len() {
        1 => Ok(blocks.remove(0)),
        n => Err(format!(
            "the paste holds {n} certificates; upload only the app's own certificate"
        )),
    }
}

/// Removes every expired password credential, by the audit's shared whole-day
/// rule (`azapptoolkit_core::audit::is_expired` — a sub-day lapse is still
/// "expiring soon" and is left alone). Mirrors `Remove-AzAppExpiredCredential`.
/// Partial success is surfaced via `failures` rather than aborting on the
/// first error — except a re-auth-fatal one: a dead session fails every
/// remaining removal identically, so the sweep stops there and the fatal-coded
/// failure tells the UI to offer Re-authenticate.
#[tauri::command]
pub async fn remove_expired_passwords(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<RemoveExpiredResult, UiError> {
    remove_expired_passwords_core(&state, &tenant_id, &object_id).await
}

/// The body of [`remove_expired_passwords`], taking `&AppState` so the
/// invalidation rule — bust the credential tier only when something was
/// actually removed, never on the error path, and never the tenant-wide
/// indexes — is reachable from a test (the [`add_password_core`] seam).
pub(crate) async fn remove_expired_passwords_core(
    state: &AppState,
    tenant_id: &str,
    object_id: &str,
) -> Result<RemoveExpiredResult, UiError> {
    let client = state.graph_for(tenant_id);
    let app = client.get_application(object_id).await?;
    let now = chrono::Utc::now();

    let mut removed_key_ids = Vec::new();
    let mut failures = Vec::new();
    for cred in app.password_credentials.iter() {
        if !azapptoolkit_core::audit::is_expired(cred.end_date_time, now) {
            continue;
        }
        match client.remove_password(object_id, &cred.key_id).await {
            Ok(()) => removed_key_ids.push(cred.key_id.clone()),
            Err(err) => {
                let e = UiError::from(err);
                let fatal = e.is_reauth_fatal();
                failures.push(KeyFailure {
                    key_id: cred.key_id.clone(),
                    code: e.code,
                    message: e.message,
                });
                if fatal {
                    break;
                }
            }
        }
    }

    if !removed_key_ids.is_empty() {
        invalidate_app_credentials(&state.cache, tenant_id, object_id);
    }
    Ok(RemoveExpiredResult {
        removed_key_ids,
        failures,
    })
}

#[cfg(test)]
mod password_window_tests {
    use super::{
        AddPasswordInput, MAX_SECRET_LIFETIME_DAYS, SecretWindowError, preset_secret_end,
        resolve_password_window,
    };
    use crate::commands::test_support::{at, fixed_now};

    fn input(
        lifetime_days: Option<u32>,
        start: Option<&str>,
        end: Option<&str>,
    ) -> AddPasswordInput {
        AddPasswordInput {
            display_name: "s".into(),
            lifetime_days,
            start_date_time: start.map(at),
            end_date_time: end.map(at),
        }
    }

    #[test]
    fn preset_days_resolve_relative_to_now() {
        let (start, end) =
            resolve_password_window(&input(Some(90), None, None), fixed_now()).unwrap();
        assert!(start.is_none());
        assert_eq!(end, at("2026-04-01T00:00:00Z"));
    }

    #[test]
    fn defaults_to_180_days_and_clamps_to_cap() {
        let (_, end) = resolve_password_window(&input(None, None, None), fixed_now()).unwrap();
        assert_eq!(end, fixed_now() + chrono::Duration::days(180));
        let (_, end) =
            resolve_password_window(&input(Some(9999), None, None), fixed_now()).unwrap();
        assert_eq!(end, fixed_now() + chrono::Duration::days(730));
    }

    /// The initial secret `create_application` mints rides the same clamp as
    /// `add_password`: `Some(0)` would be an already-expired secret Graph
    /// rejects, `Some(9999)` a 27-year one the 24-month cap exists to refuse.
    #[test]
    fn preset_secret_end_defaults_and_clamps() {
        let now = fixed_now();
        for (days, expected) in [
            (None, 180),
            (Some(0), 1),
            (Some(90), 90),
            (Some(730), 730),
            (Some(9999), 730),
            (Some(u32::MAX), 730),
        ] {
            assert_eq!(
                preset_secret_end(days, now),
                now + chrono::Duration::days(expected),
                "{days:?}"
            );
        }
    }

    #[test]
    fn explicit_end_wins_over_lifetime_days() {
        let (start, end) = resolve_password_window(
            &input(
                Some(90),
                Some("2026-02-01T00:00:00Z"),
                Some("2026-06-01T00:00:00Z"),
            ),
            fixed_now(),
        )
        .unwrap();
        assert_eq!(start, Some(at("2026-02-01T00:00:00Z")));
        assert_eq!(end, at("2026-06-01T00:00:00Z"));
    }

    #[test]
    fn rejects_end_not_after_start() {
        let err = resolve_password_window(
            &input(
                None,
                Some("2026-06-01T00:00:00Z"),
                Some("2026-06-01T00:00:00Z"),
            ),
            fixed_now(),
        )
        .unwrap_err();
        assert_eq!(err, SecretWindowError::EndNotAfterStart);
        // Without an explicit start, "now" anchors the window.
        assert_eq!(
            resolve_password_window(
                &input(None, None, Some("2025-12-31T00:00:00Z")),
                fixed_now()
            ),
            Err(SecretWindowError::EndNotAfterStart)
        );
    }

    #[test]
    fn rejects_lifetime_over_24_months() {
        let err = resolve_password_window(
            &input(
                None,
                Some("2026-01-01T00:00:00Z"),
                Some("2028-06-01T00:00:00Z"),
            ),
            fixed_now(),
        )
        .unwrap_err();
        assert_eq!(err, SecretWindowError::LifetimeOverCap);
    }

    /// The cap is inclusive: exactly 730 days is accepted, one second more is
    /// the over-cap cause — not the end-before-start one.
    #[test]
    fn lifetime_cap_is_inclusive_at_730_days() {
        let start = at("2026-01-01T00:00:00Z");
        let window = |end| AddPasswordInput {
            display_name: "s".into(),
            lifetime_days: None,
            start_date_time: Some(start),
            end_date_time: Some(end),
        };
        let cap = start + chrono::Duration::days(MAX_SECRET_LIFETIME_DAYS);
        assert_eq!(
            resolve_password_window(&window(cap), fixed_now()),
            Ok((Some(start), cap))
        );
        assert_eq!(
            resolve_password_window(&window(cap + chrono::Duration::seconds(1)), fixed_now()),
            Err(SecretWindowError::LifetimeOverCap)
        );
    }

    /// The one exact prose pin: `Display` is the sentence the operator reads
    /// in the `invalid_secret_window` error.
    #[test]
    fn secret_window_errors_read_as_the_operator_sentence() {
        assert_eq!(
            SecretWindowError::EndNotAfterStart.to_string(),
            "expiry must be after the start date"
        );
        assert_eq!(
            SecretWindowError::LifetimeOverCap.to_string(),
            "secret lifetime cannot exceed 24 months"
        );
    }
}

#[cfg(test)]
mod cert_tests {
    use super::{STANDARD, parse_cert_upload, pfx_file_stem};
    use base64::Engine as _;

    /// The subject is operator-typed and lands in a *filename*. It only seeds
    /// the save dialog, but a default carrying a path separator is one nobody
    /// can accept — and `..` in a suggested name is worth never emitting.
    #[test]
    fn a_pfx_filename_stem_survives_a_hostile_common_name() {
        assert_eq!(pfx_file_stem("Contoso CRM"), "Contoso-CRM");
        assert_eq!(pfx_file_stem("  spaced  "), "spaced");
        assert_eq!(pfx_file_stem("app.contoso.com"), "app.contoso.com");
        for hostile in ["../../etc/passwd", "a/b\\c", "x;rm -rf ~", "\"q\"", "$(id)"] {
            let out = pfx_file_stem(hostile);
            assert!(
                !out.contains(['/', '\\', ';', '$', '"', '\'', ' ']),
                "{hostile} -> {out}",
            );
            assert!(!out.contains(".."), "{hostile} -> {out}");
        }
        // Never empty: the dialog needs *some* name to offer.
        assert_eq!(pfx_file_stem("///"), "certificate");
        assert_eq!(pfx_file_stem(""), "certificate");
        assert_eq!(pfx_file_stem("..."), "certificate");
    }

    /// A real certificate (and its key) from the generate path.
    fn generated() -> crate::cert::GeneratedCert {
        crate::cert::generate_self_signed("Upload Test", 30).unwrap()
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    /// The base64 body of a PEM block, armour stripped.
    fn pem_body(pem: &str) -> String {
        pem.lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>()
    }

    #[test]
    fn accepts_a_pem_certificate_and_matches_the_generate_paths_thumbprint() {
        let c = generated();
        let up = parse_cert_upload(&c.cert_pem, now()).unwrap();
        assert_eq!(up.key_b64, c.cert_der_base64);
        // The two SHA-1 derivations (upload, generate) must agree.
        assert_eq!(up.thumbprint, c.thumbprint);
        assert_eq!(up.not_after.timestamp(), c.not_after.unix_timestamp());
    }

    #[test]
    fn accepts_raw_base64_der_and_indented_crlf_pem() {
        let c = generated();
        let raw = parse_cert_upload(&c.cert_der_base64, now()).unwrap();
        assert_eq!(raw.thumbprint, c.thumbprint);

        let indented: String = c.cert_pem.lines().map(|l| format!("   {l}\r\n")).collect();
        let up = parse_cert_upload(&indented, now()).unwrap();
        assert_eq!(up.key_b64, c.cert_der_base64);

        // openssl's text around a block is ignored.
        let with_headers = format!("Bag Attributes\nsubject=CN = Upload Test\n{}", c.cert_pem);
        assert!(parse_cert_upload(&with_headers, now()).is_ok());
    }

    /// The upload must never forward a private key: refused wherever it sits,
    /// and the refusal never echoes the key material.
    #[test]
    fn refuses_a_private_key_alone_and_in_a_bundle_either_order() {
        let c = generated();
        let key = c.private_key_pem.as_str();
        let cases = [
            key.to_string(),
            format!("{}{key}", c.cert_pem),
            format!("{key}{}", c.cert_pem),
            // Armour built at runtime (like `refuses_other_pem_labels_…` below) so the
            // whole-history secrets scan never sees a literal private-key block.
            format!(
                "-----BEGIN {l}-----\nMIIB\n-----END {l}-----",
                l = "RSA PRIVATE KEY"
            ),
            format!(
                "-----BEGIN {l}-----\nMIIB\n-----END {l}-----",
                l = "ENCRYPTED PRIVATE KEY"
            ),
        ];
        for paste in &cases {
            let err = parse_cert_upload(paste, now()).err().expect("refused");
            assert!(err.contains("private key"), "{err}");
            for line in key
                .lines()
                .filter(|l| !l.starts_with("-----") && l.len() > 10)
            {
                assert!(!err.contains(line), "the refusal echoed key material");
            }
        }
    }

    #[test]
    fn refuses_a_bare_base64_private_key() {
        let c = generated();
        let err = parse_cert_upload(&pem_body(&c.private_key_pem), now())
            .err()
            .expect("a PKCS#8 key is not a certificate");
        assert!(err.contains("not an X.509 certificate"), "{err}");
    }

    #[test]
    fn refuses_other_pem_labels_and_multiple_certificates() {
        for label in ["PKCS7", "CERTIFICATE REQUEST", "PUBLIC KEY"] {
            let paste = format!("-----BEGIN {label}-----\nMIIB\n-----END {label}-----\n");
            let err = parse_cert_upload(&paste, now()).err().expect(label);
            assert!(err.contains("isn't a certificate"), "{label}: {err}");
        }
        let c = generated();
        let err = parse_cert_upload(&format!("{}{}", c.cert_pem, c.cert_pem), now())
            .err()
            .expect("two certificates are refused, not cut down to the first");
        assert!(err.contains("2 certificates"), "{err}");
        // A block missing its END line.
        let truncated = c.cert_pem.replace("-----END CERTIFICATE-----", "");
        assert_eq!(
            parse_cert_upload(&truncated, now()).err().as_deref(),
            Some("incomplete PEM block")
        );
    }

    #[test]
    fn refuses_an_expired_certificate() {
        let c = generated();
        let not_after =
            chrono::DateTime::<chrono::Utc>::from_timestamp(c.not_after.unix_timestamp(), 0)
                .unwrap();
        let err = parse_cert_upload(&c.cert_pem, not_after + chrono::Duration::days(1))
            .err()
            .expect("expired");
        assert!(err.contains("expired"), "{err}");
        assert!(parse_cert_upload(&c.cert_pem, not_after - chrono::Duration::days(1)).is_ok());
    }

    #[test]
    fn refuses_trailing_data_after_the_certificate() {
        let c = generated();
        let mut der = STANDARD.decode(&c.cert_der_base64).unwrap();
        der.extend_from_slice(&[0, 0, 0]);
        let err = parse_cert_upload(&STANDARD.encode(der), now())
            .err()
            .expect("trailing bytes");
        assert!(err.contains("unexpected data"), "{err}");
    }

    #[test]
    fn rejects_non_base64() {
        assert!(parse_cert_upload("!!!!", now()).is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(parse_cert_upload("", now()).is_err());
        assert_eq!(
            parse_cert_upload(
                "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n",
                now()
            )
            .err()
            .as_deref(),
            Some("certificate body is empty")
        );
    }
}

#[cfg(test)]
mod handler_tests {
    use super::*;

    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, ResponseTemplate};

    use crate::commands::test_support::{
        detail_cached, dies_after, indexes_intact, mock_state, mock_state_with_write_token,
        sample_app_json, seed_indexes_and_detail,
    };

    const TENANT: &str = "t1";
    const OBJECT: &str = "obj-1";

    /// Seeds what a credential mutation must NOT drop (the two pinned
    /// tenant-wide indexes) alongside what it must drop (the app's detail row).
    fn seed(state: &AppState) {
        seed_indexes_and_detail(state, TENANT, OBJECT);
    }

    fn detail_cached_here(state: &AppState) -> bool {
        detail_cached(state, TENANT, OBJECT)
    }

    fn input() -> AddPasswordInput {
        AddPasswordInput {
            display_name: "test secret".to_string(),
            lifetime_days: None,
            start_date_time: None,
            end_date_time: None,
        }
    }

    #[tokio::test]
    async fn a_successful_secret_add_busts_the_credential_tier_and_keeps_the_indexes() {
        let (server, state) = mock_state(TENANT).await;
        Mock::given(method("POST"))
            .and(path(format!("/v1.0/applications/{OBJECT}/addPassword")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keyId": "k1",
                "displayName": "test secret",
                "secretText": "s3cret",
            })))
            .mount(&server)
            .await;

        seed(&state);

        let cred = add_password_core(&state, TENANT, OBJECT, input())
            .await
            .expect("the mocked addPassword succeeds");
        assert_eq!(cred.key_id, "k1");

        assert!(
            !detail_cached_here(&state),
            "the app's detail row must be busted — it carries the credential list"
        );
        // The AGENTS.md rule a credential-only mutation exists to respect: the
        // tenant-wide indexes cost a full directory scan and are unaffected by
        // one app's secret.
        assert!(
            indexes_intact(&state, TENANT),
            "the SP and app-registration indexes must survive a credential-only mutation"
        );
    }

    #[tokio::test]
    async fn a_failed_secret_add_invalidates_nothing() {
        let (server, state) = mock_state(TENANT).await;
        Mock::given(method("POST"))
            .and(path(format!("/v1.0/applications/{OBJECT}/addPassword")))
            .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
            .mount(&server)
            .await;

        seed(&state);

        let err = add_password_core(&state, TENANT, OBJECT, input())
            .await
            .expect_err("a 403 must surface as an error");
        assert_eq!(err.code, "forbidden");

        // "Invalidate caches only on `Ok`" — on failure the cached data is still
        // accurate, and dropping it costs a re-fetch for nothing.
        assert!(
            detail_cached_here(&state),
            "a failed mutation must leave the cached detail row alone"
        );
        assert!(indexes_intact(&state, TENANT));
    }

    /// A paste holding a private key is refused before the client is used —
    /// the key material never reaches Graph, and nothing is invalidated.
    #[tokio::test]
    async fn a_private_key_paste_never_reaches_graph() {
        // No mock mounted: any request would 404 and fail the test differently.
        let (server, state) = mock_state(TENANT).await;
        seed(&state);
        let generated = crate::cert::generate_self_signed("Upload Test", 30).unwrap();
        let err = add_certificate_credential_core(
            &state,
            TENANT,
            OBJECT,
            AddCertificateInput {
                display_name: "bundle".to_string(),
                pem_or_base64: format!("{}{}", generated.cert_pem, generated.private_key_pem),
                end_date_time: None,
            },
        )
        .await
        .expect_err("a private key is refused");
        assert_eq!(err.code, "invalid_certificate");
        assert!(
            detail_cached_here(&state),
            "a refused paste invalidates nothing"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_invalid_secret_window_never_reaches_graph() {
        // No mock mounted: any request would 404 and fail the test differently.
        let (server, state) = mock_state(TENANT).await;
        seed(&state);

        // An explicit window past the 24-month cap is REJECTED (a bare
        // `lifetime_days` is clamped instead, so it wouldn't exercise this).
        let now = chrono::Utc::now();
        let err = add_password_core(
            &state,
            TENANT,
            OBJECT,
            AddPasswordInput {
                display_name: "too long".to_string(),
                lifetime_days: None,
                start_date_time: Some(now),
                end_date_time: Some(now + chrono::Duration::days(MAX_SECRET_LIFETIME_DAYS + 1)),
            },
        )
        .await
        .expect_err("a window past the 24-month cap is rejected");
        assert_eq!(err.code, "invalid_secret_window");
        assert!(
            detail_cached_here(&state),
            "a rejected input invalidates nothing"
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty()
        );
    }

    // ---- remove_expired_passwords_core ----
    //
    // An expired `endDateTime` must be past "now" by more than a whole day
    // (`audit::is_expired`), so the fixtures use dates years away from the wall
    // clock in either direction.

    const EXPIRED: &str = "2020-01-01T00:00:00Z";
    const LIVE: &str = "2999-01-01T00:00:00Z";

    /// `sample_app_json()` carrying the given `(keyId, endDateTime)` secrets.
    fn app_with_secrets(secrets: &[(&str, &str)]) -> serde_json::Value {
        let mut app = sample_app_json();
        app["passwordCredentials"] = secrets
            .iter()
            .map(|(key_id, end)| serde_json::json!({"keyId": key_id, "endDateTime": end}))
            .collect();
        app
    }

    async fn mount_app(server: &wiremock::MockServer, app: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/applications/{OBJECT}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(app))
            .mount(server)
            .await;
    }

    async fn mount_remove(server: &wiremock::MockServer, key_id: &str, status: u16) {
        Mock::given(method("POST"))
            .and(path(format!("/v1.0/applications/{OBJECT}/removePassword")))
            .and(body_partial_json(serde_json::json!({ "keyId": key_id })))
            .respond_with(ResponseTemplate::new(status))
            .mount(server)
            .await;
    }

    async fn removal_requests(server: &wiremock::MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.url.path().ends_with("/removePassword"))
            .count()
    }

    #[tokio::test]
    async fn removing_an_expired_secret_busts_the_credential_tier_and_keeps_the_indexes() {
        let (server, state) = mock_state(TENANT).await;
        mount_app(
            &server,
            app_with_secrets(&[("old", EXPIRED), ("new", LIVE)]),
        )
        .await;
        mount_remove(&server, "old", 204).await;
        seed(&state);

        let out = remove_expired_passwords_core(&state, TENANT, OBJECT)
            .await
            .expect("the mocked removal succeeds");
        assert_eq!(out.removed_key_ids, ["old"], "only the expired secret goes");
        assert!(out.failures.is_empty());
        assert_eq!(
            removal_requests(&server).await,
            1,
            "the live secret is never touched"
        );

        assert!(!detail_cached_here(&state), "the credential list changed");
        assert!(
            indexes_intact(&state, TENANT),
            "a credential-only removal must keep both tenant-wide indexes"
        );
    }

    #[tokio::test]
    async fn nothing_expired_writes_nothing_and_busts_nothing() {
        let (server, state) = mock_state(TENANT).await;
        mount_app(&server, app_with_secrets(&[("new", LIVE)])).await;
        seed(&state);

        let out = remove_expired_passwords_core(&state, TENANT, OBJECT)
            .await
            .expect("a no-op run is a success");
        assert!(out.removed_key_ids.is_empty());
        assert!(out.failures.is_empty());
        assert_eq!(removal_requests(&server).await, 0);
        assert!(
            detail_cached_here(&state),
            "nothing changed, so the cached detail is still right"
        );
        assert!(indexes_intact(&state, TENANT));
    }

    #[tokio::test]
    async fn an_unreadable_app_errs_and_busts_nothing() {
        let (server, state) = mock_state(TENANT).await;
        Mock::given(method("GET"))
            .and(path(format!("/v1.0/applications/{OBJECT}")))
            .respond_with(ResponseTemplate::new(403).set_body_string("Insufficient privileges"))
            .mount(&server)
            .await;
        seed(&state);

        let err = remove_expired_passwords_core(&state, TENANT, OBJECT)
            .await
            .expect_err("a 403 on the read must surface");
        assert_eq!(err.code, "forbidden");
        assert_eq!(removal_requests(&server).await, 0);
        assert!(detail_cached_here(&state), "invalidate only on Ok");
        assert!(indexes_intact(&state, TENANT));
    }

    #[tokio::test]
    async fn a_partial_removal_busts_and_reports_the_failure() {
        let (server, state) = mock_state(TENANT).await;
        mount_app(
            &server,
            app_with_secrets(&[("gone-1", EXPIRED), ("gone-2", EXPIRED)]),
        )
        .await;
        mount_remove(&server, "gone-1", 204).await;
        mount_remove(&server, "gone-2", 403).await;
        seed(&state);

        let out = remove_expired_passwords_core(&state, TENANT, OBJECT)
            .await
            .expect("a per-secret failure is data, not an error");
        assert_eq!(out.removed_key_ids, ["gone-1"]);
        assert_eq!(out.failures.len(), 1);
        assert_eq!(out.failures[0].key_id, "gone-2");
        assert_eq!(out.failures[0].code, "forbidden");
        assert!(!out.failures[0].is_reauth_fatal());
        assert!(
            !detail_cached_here(&state),
            "one secret WAS removed, so the credential list changed"
        );
        assert!(indexes_intact(&state, TENANT));
    }

    /// A dead session fails every remaining removal the same way, so the sweep
    /// stops at the first re-auth-fatal failure and names its code — the UI
    /// reads that code to offer Re-authenticate instead of N identical errors.
    #[tokio::test]
    async fn a_dead_session_stops_the_expired_sweep_and_names_the_code() {
        let (server, state) = mock_state_with_write_token(TENANT, dies_after(1)).await;
        mount_app(
            &server,
            app_with_secrets(&[("a", EXPIRED), ("b", EXPIRED), ("c", EXPIRED)]),
        )
        .await;
        for key in ["a", "b", "c"] {
            mount_remove(&server, key, 204).await;
        }
        seed(&state);

        let out = remove_expired_passwords_core(&state, TENANT, OBJECT)
            .await
            .expect("a per-secret failure is data, not an error");
        assert_eq!(out.removed_key_ids, ["a"]);
        assert_eq!(out.failures.len(), 1, "the sweep stops at the dead session");
        assert_eq!(out.failures[0].key_id, "b");
        assert_eq!(out.failures[0].code, "refresh_missing");
        assert!(out.failures[0].is_reauth_fatal());
        assert_eq!(
            removal_requests(&server).await,
            1,
            "only the first removal reached Graph; `c` was never attempted"
        );
        assert!(!detail_cached_here(&state), "`a` WAS removed");
        assert!(indexes_intact(&state, TENANT));
    }
}
