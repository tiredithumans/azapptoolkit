use tauri::State;

use azapptoolkit_core::models::{NewKeyCredential, PasswordCredential};

use crate::dto::applications::{
    AddCertificateInput, AddPasswordInput, GenerateCertificateInput, GeneratedCertificateResult,
    KeyFailure, RemoveExpiredResult,
};
use crate::dto::UiError;
use crate::state::AppState;

use super::invalidate_app_credentials;

#[tauri::command]
pub async fn add_password(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: AddPasswordInput,
) -> Result<PasswordCredential, UiError> {
    let (start, end) = resolve_password_window(&input, chrono::Utc::now())
        .map_err(|msg| UiError::validation("invalid_secret_window", msg))?;
    let client = state.graph_for(&tenant_id);
    let cred = client
        .add_password_window(&object_id, &input.display_name, start, end)
        .await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    Ok(cred)
}

/// Maximum client-secret lifetime — the portal's 24-month hard cap.
const MAX_SECRET_LIFETIME_DAYS: i64 = 730;

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
    String,
> {
    match input.end_date_time {
        Some(end) => {
            let effective_start = input.start_date_time.unwrap_or(now);
            if end <= effective_start {
                return Err("expiry must be after the start date".to_string());
            }
            if end - effective_start > chrono::Duration::days(MAX_SECRET_LIFETIME_DAYS) {
                return Err("secret lifetime cannot exceed 24 months".to_string());
            }
            Ok((input.start_date_time, end))
        }
        None => {
            let days =
                i64::from(input.lifetime_days.unwrap_or(180)).clamp(1, MAX_SECRET_LIFETIME_DAYS);
            Ok((None, now + chrono::Duration::days(days)))
        }
    }
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

#[tauri::command]
pub async fn add_certificate_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: AddCertificateInput,
) -> Result<(), UiError> {
    let key_b64 = normalize_cert_blob(&input.pem_or_base64)
        .map_err(|msg| UiError::validation("invalid_certificate", msg))?;
    let client = state.graph_for(&tenant_id);
    let new_cred = NewKeyCredential {
        display_name: Some(input.display_name),
        kind: Some("AsymmetricX509Cert".into()),
        usage: Some("Verify".into()),
        key: key_b64,
        end_date_time: input.end_date_time,
        ..Default::default()
    };
    client.add_key_credential(&object_id, new_cred).await?;
    invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    Ok(())
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
    let validity = input.validity_days.unwrap_or(365);
    let mut generated = crate::cert::generate_self_signed(&input.subject, i64::from(validity))
        .map_err(|msg| UiError::validation("cert_generation_failed", msg))?;

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
        certificate_pem: std::mem::take(&mut generated.cert_pem),
        private_key_pem: std::mem::take(&mut generated.private_key_pem),
        expires: expires_dt.map(|d| d.to_rfc3339()).unwrap_or_default(),
    })
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

/// Accepts either PEM-armoured text (`-----BEGIN CERTIFICATE-----`...) or a
/// raw base64 blob. Returns a clean base64-encoded DER string suitable for
/// the `key` field on Graph's `keyCredentials`. Performs minimal validation:
/// strips headers/whitespace and confirms the remainder is valid base64.
fn normalize_cert_blob(input: &str) -> std::result::Result<String, String> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    let stripped: String = input
        .lines()
        .filter(|line| !line.trim_start().starts_with("-----"))
        .flat_map(|line| line.chars())
        .filter(|c| !c.is_whitespace())
        .collect();

    if stripped.is_empty() {
        return Err("certificate body is empty".to_string());
    }
    STANDARD
        .decode(&stripped)
        .map_err(|e| format!("not valid base64: {e}"))?;
    Ok(stripped)
}

/// Removes every expired password credential, by the audit's shared whole-day
/// rule (`azapptoolkit_core::audit::is_expired` — a sub-day lapse is still
/// "expiring soon" and is left alone). Mirrors `Remove-AzAppExpiredCredential`.
/// Partial success is surfaced via `failures` rather than aborting on the
/// first error.
#[tauri::command]
pub async fn remove_expired_passwords(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<RemoveExpiredResult, UiError> {
    let client = state.graph_for(&tenant_id);
    let app = client.get_application(&object_id).await?;
    let now = chrono::Utc::now();

    let mut removed_key_ids = Vec::new();
    let mut failures = Vec::new();
    for cred in app.password_credentials.iter() {
        if !azapptoolkit_core::audit::is_expired(cred.end_date_time, now) {
            continue;
        }
        match client.remove_password(&object_id, &cred.key_id).await {
            Ok(()) => removed_key_ids.push(cred.key_id.clone()),
            Err(err) => failures.push(KeyFailure {
                key_id: cred.key_id.clone(),
                message: err.to_string(),
            }),
        }
    }

    if !removed_key_ids.is_empty() {
        invalidate_app_credentials(&state.cache, &tenant_id, &object_id);
    }
    Ok(RemoveExpiredResult {
        removed_key_ids,
        failures,
    })
}

#[cfg(test)]
mod password_window_tests {
    use super::{resolve_password_window, AddPasswordInput};

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

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

    const NOW: &str = "2026-01-01T00:00:00Z";

    #[test]
    fn preset_days_resolve_relative_to_now() {
        let (start, end) = resolve_password_window(&input(Some(90), None, None), at(NOW)).unwrap();
        assert!(start.is_none());
        assert_eq!(end, at("2026-04-01T00:00:00Z"));
    }

    #[test]
    fn defaults_to_180_days_and_clamps_to_cap() {
        let (_, end) = resolve_password_window(&input(None, None, None), at(NOW)).unwrap();
        assert_eq!(end, at(NOW) + chrono::Duration::days(180));
        let (_, end) = resolve_password_window(&input(Some(9999), None, None), at(NOW)).unwrap();
        assert_eq!(end, at(NOW) + chrono::Duration::days(730));
    }

    #[test]
    fn explicit_end_wins_over_lifetime_days() {
        let (start, end) = resolve_password_window(
            &input(
                Some(90),
                Some("2026-02-01T00:00:00Z"),
                Some("2026-06-01T00:00:00Z"),
            ),
            at(NOW),
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
            at(NOW),
        )
        .unwrap_err();
        assert!(err.contains("after the start"));
        // Without an explicit start, "now" anchors the window.
        assert!(
            resolve_password_window(&input(None, None, Some("2025-12-31T00:00:00Z")), at(NOW))
                .is_err()
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
            at(NOW),
        )
        .unwrap_err();
        assert!(err.contains("24 months"));
    }
}

#[cfg(test)]
mod cert_tests {
    use super::normalize_cert_blob;

    #[test]
    fn strips_pem_armour_and_whitespace() {
        let pem = "-----BEGIN CERTIFICATE-----\nAAAAAA==\n-----END CERTIFICATE-----\n";
        let out = normalize_cert_blob(pem).unwrap();
        assert_eq!(out, "AAAAAA==");
    }

    #[test]
    fn accepts_raw_base64() {
        let out = normalize_cert_blob("AAAAAA==").unwrap();
        assert_eq!(out, "AAAAAA==");
    }

    #[test]
    fn rejects_non_base64() {
        assert!(normalize_cert_blob("!!!!").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(normalize_cert_blob("").is_err());
        assert!(
            normalize_cert_blob("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")
                .is_err()
        );
    }
}
