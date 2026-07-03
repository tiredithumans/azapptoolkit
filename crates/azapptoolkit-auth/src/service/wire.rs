//! AAD wire protocol: `/token` response/error shapes, error classification +
//! redaction, scope parsing, ID-token claims decoding, and CAE claims
//! building. Free functions and private types with zero coupling to
//! [`super::EntraAuthService`] — the flows in `service` call these; nothing
//! here touches the network or the keyring.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::error::{AuthError, Result};

#[derive(Debug, Deserialize)]
pub(super) struct TokenResponse {
    pub(super) access_token: String,
    #[serde(default)]
    pub(super) refresh_token: Option<String>,
    #[serde(default)]
    pub(super) id_token: Option<String>,
    pub(super) expires_in: u64,
    #[serde(default)]
    pub(super) scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct TokenErrorBody {
    pub(super) error: String,
    #[serde(default)]
    pub(super) error_description: Option<String>,
    // AAD's request-tracing GUID. Safe for operator logs (it identifies the
    // request, not the user) and the one field Microsoft support asks for —
    // unlike `error_description`, which embeds tenant/user GUIDs and client IPs.
    #[serde(default)]
    pub(super) correlation_id: Option<String>,
}

/// Maps an AAD `/token` error body to the right [`AuthError`]. A missing-consent
/// rejection (AADSTS65001 "not consented", 65004 "user declined", or the
/// `consent_required` OAuth code) is recoverable via interactive consent and
/// must be distinguished *first* — unlike [`AuthError::InvalidGrant`], it must
/// NOT purge the refresh token. Everything else `invalid_grant`-like means the
/// refresh token is dead; the remainder is a generic exchange failure. The
/// carried string is always the UI-safe redacted summary.
pub(super) fn classify_token_error(body: &TokenErrorBody) -> AuthError {
    let safe = redacted_aad_error(body);
    let aadsts = body
        .error_description
        .as_deref()
        .and_then(extract_aadsts_code);
    if body.error == "consent_required"
        || matches!(aadsts.as_deref(), Some("AADSTS65001") | Some("AADSTS65004"))
    {
        return AuthError::ConsentRequired(safe);
    }
    if matches!(
        body.error.as_str(),
        "invalid_grant" | "interaction_required" | "login_required"
    ) {
        return AuthError::InvalidGrant(safe);
    }
    AuthError::TokenExchange(safe)
}

/// Builds a UI-safe summary of an AAD error response. Keeps the canonical
/// OAuth error code (e.g. `invalid_client`) and the AADSTS numeric code if
/// present, and drops the rest of `error_description` (which routinely
/// embeds tenant/user GUIDs, correlation IDs, and client IPs).
pub(super) fn redacted_aad_error(body: &TokenErrorBody) -> String {
    let aadsts = body
        .error_description
        .as_deref()
        .and_then(extract_aadsts_code);
    match aadsts {
        Some(code) => format!("{} ({})", body.error, code),
        None => body.error.clone(),
    }
}

/// Pulls the first `AADSTSnnnnn` token out of an AAD error_description.
fn extract_aadsts_code(description: &str) -> Option<String> {
    let idx = description.find("AADSTS")?;
    let tail = &description[idx + "AADSTS".len()..];
    // A non-digit right after "AADSTS" yields no digits below → `None`.
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        None
    } else {
        Some(format!("AADSTS{digits}"))
    }
}

/// Parse space-delimited scope strings from a token response. When the response
/// omits `scope` entirely (`None`), fall back to `fallback` — the scopes we
/// requested — so a refresh that doesn't echo the grant still records what the
/// token covers. A present-but-empty `scope` stays empty (the server said so).
pub(super) fn parse_scopes(raw: Option<&str>, fallback: &[String]) -> Vec<String> {
    match raw {
        Some(s) => s.split_whitespace().map(str::to_string).collect(),
        None => fallback.to_vec(),
    }
}

/// Base64-decodes a CAE `claims=` challenge value, tolerating both the
/// URL-safe (no-pad) and standard alphabets that different services emit.
fn decode_claims_challenge(b64: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(b64)
        .ok()
        .or_else(|| STANDARD.decode(b64).ok())
}

/// Builds the `claims` request parameter for a CAE-capable token. It always
/// advertises the `cp1` client capability (`xms_cc`) so Microsoft Graph issues a
/// CAE token; when a base64 `challenge` from a `401 insufficient_claims` is
/// supplied, its decoded claims are merged under `access_token` so the re-minted
/// token also satisfies the resource's new requirement.
pub(super) fn build_cae_claims(challenge_b64: Option<&str>) -> String {
    use serde_json::{Value, json};
    let mut claims: Value = challenge_b64
        .and_then(decode_claims_challenge)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));

    let root = claims
        .as_object_mut()
        .expect("claims initialized as an object");
    let access_token = root.entry("access_token").or_insert_with(|| json!({}));
    if !access_token.is_object() {
        *access_token = json!({});
    }
    access_token
        .as_object_mut()
        .expect("access_token is an object")
        .insert("xms_cc".into(), json!({ "values": ["cp1"] }));
    claims.to_string()
}

#[derive(Debug, Default)]
pub(super) struct IdClaims {
    pub(super) tid: Option<String>,
    pub(super) oid: Option<String>,
    pub(super) preferred_username: Option<String>,
    pub(super) name: Option<String>,
    pub(super) nonce: Option<String>,
}

/// Decodes the **claims** segment of an ID token *without verifying its
/// signature* — it base64-decodes the middle JWT segment and reads fields.
///
/// Safe **only** because every call site feeds a token that arrived over TLS
/// directly from Entra's `/token` endpoint, and the security-relevant claims
/// (`nonce`, `tid`, `oid`) are re-bound to the request afterwards. Do NOT reuse
/// this on a token from an untrusted source: it performs no signature, issuer,
/// audience, or expiry validation.
pub(super) fn parse_id_token(id_token: Option<&str>) -> Result<IdClaims> {
    let id_token =
        id_token.ok_or_else(|| AuthError::TokenExchange("no id_token in response".into()))?;
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() < 2 {
        return Err(AuthError::TokenExchange("malformed id_token".into()));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| AuthError::TokenExchange(format!("id_token b64 decode: {e}")))?;
    let value: serde_json::Value = serde_json::from_slice(&decoded)?;
    let claim = |key: &str| value.get(key).and_then(|v| v.as_str()).map(str::to_string);
    Ok(IdClaims {
        tid: claim("tid"),
        oid: claim("oid"),
        preferred_username: claim("preferred_username"),
        name: claim("name"),
        nonce: claim("nonce"),
    })
}

#[cfg(test)]
mod aad_redaction_tests {
    use super::*;

    #[test]
    fn extracts_aadsts_code() {
        let s = "AADSTS50034: The user account does not exist in <tenant guid> directory.";
        assert_eq!(extract_aadsts_code(s).as_deref(), Some("AADSTS50034"));
    }

    #[test]
    fn returns_none_when_no_code() {
        assert!(extract_aadsts_code("invalid_grant").is_none());
    }

    #[test]
    fn rejects_non_digit_after_aadsts() {
        // "AADSTS" present but immediately followed by a non-digit → no code.
        assert!(extract_aadsts_code("AADSTS: malformed, no number").is_none());
    }

    #[test]
    fn redacted_combines_oauth_and_aadsts() {
        let body = TokenErrorBody {
            error: "invalid_grant".into(),
            error_description: Some("AADSTS70008: The refresh token has expired...".into()),
            correlation_id: None,
        };
        assert_eq!(redacted_aad_error(&body), "invalid_grant (AADSTS70008)");
    }

    #[test]
    fn redacted_falls_back_to_oauth_code() {
        let body = TokenErrorBody {
            error: "invalid_client".into(),
            error_description: None,
            correlation_id: None,
        };
        assert_eq!(redacted_aad_error(&body), "invalid_client");
    }

    #[test]
    fn consent_codes_classify_as_consent_required_not_invalid_grant() {
        // AADSTS65001 ("not consented") arrives wrapped as `invalid_grant`; it
        // must surface as ConsentRequired so the refresh token is NOT purged.
        let body = TokenErrorBody {
            error: "invalid_grant".into(),
            error_description: Some(
                "AADSTS65001: The user or administrator has not consented to use the application."
                    .into(),
            ),
            correlation_id: None,
        };
        assert!(matches!(
            classify_token_error(&body),
            AuthError::ConsentRequired(_)
        ));

        // 65004 (user declined) and the explicit `consent_required` OAuth code
        // are the same recoverable class.
        let declined = TokenErrorBody {
            error: "invalid_grant".into(),
            error_description: Some("AADSTS65004: User declined to consent...".into()),
            correlation_id: None,
        };
        assert!(matches!(
            classify_token_error(&declined),
            AuthError::ConsentRequired(_)
        ));
        let explicit = TokenErrorBody {
            error: "consent_required".into(),
            error_description: None,
            correlation_id: None,
        };
        assert!(matches!(
            classify_token_error(&explicit),
            AuthError::ConsentRequired(_)
        ));
    }

    #[test]
    fn expired_refresh_token_stays_invalid_grant() {
        // A genuinely dead refresh token (70008) must still purge — it is NOT
        // a consent problem.
        let body = TokenErrorBody {
            error: "invalid_grant".into(),
            error_description: Some("AADSTS70008: The refresh token has expired...".into()),
            correlation_id: None,
        };
        assert!(matches!(
            classify_token_error(&body),
            AuthError::InvalidGrant(_)
        ));
    }

    #[test]
    fn other_errors_are_generic_token_exchange() {
        let body = TokenErrorBody {
            error: "invalid_client".into(),
            error_description: Some("AADSTS7000215: Invalid client secret...".into()),
            correlation_id: None,
        };
        assert!(matches!(
            classify_token_error(&body),
            AuthError::TokenExchange(_)
        ));
    }
}

#[cfg(test)]
mod parse_scopes_tests {
    use super::parse_scopes;

    #[test]
    fn splits_present_scope() {
        let fallback = vec!["req".to_string()];
        assert_eq!(parse_scopes(Some("a b a"), &fallback), ["a", "b", "a"]);
    }

    #[test]
    fn falls_back_only_when_scope_absent() {
        let fallback = vec!["req".to_string()];
        // Absent → requested scopes (a refresh that omits `scope`).
        assert_eq!(parse_scopes(None, &fallback), ["req"]);
        // Present-but-empty → empty (the server explicitly returned none).
        assert!(parse_scopes(Some("   "), &fallback).is_empty());
    }
}

#[cfg(test)]
mod claims_tests {
    use super::*;

    #[test]
    fn parse_id_token_reads_tid_oid() {
        let payload =
            URL_SAFE_NO_PAD.encode(r#"{"tid":"t1","oid":"o1","name":"Alice","nonce":"n1"}"#);
        let id_token = format!("header.{payload}.sig");
        let claims = parse_id_token(Some(&id_token)).unwrap();
        assert_eq!(claims.tid.as_deref(), Some("t1"));
        assert_eq!(claims.oid.as_deref(), Some("o1"));
        assert_eq!(claims.name.as_deref(), Some("Alice"));
        assert_eq!(claims.nonce.as_deref(), Some("n1"));
    }

    #[test]
    fn cae_claims_advertise_cp1_and_merge_challenge() {
        // No challenge → just the cp1 client capability under access_token.
        let v: serde_json::Value = serde_json::from_str(&build_cae_claims(None)).unwrap();
        assert_eq!(v["access_token"]["xms_cc"]["values"][0], "cp1");

        // A challenge's claims are preserved AND cp1 is added alongside.
        let challenge = URL_SAFE_NO_PAD
            .encode(r#"{"access_token":{"nbf":{"essential":true,"value":"1700000000"}}}"#);
        let v: serde_json::Value =
            serde_json::from_str(&build_cae_claims(Some(&challenge))).unwrap();
        assert_eq!(v["access_token"]["nbf"]["value"], "1700000000");
        assert_eq!(v["access_token"]["xms_cc"]["values"][0], "cp1");
    }
}
