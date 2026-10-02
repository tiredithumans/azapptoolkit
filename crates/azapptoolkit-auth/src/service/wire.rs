//! AAD wire protocol: `/token` response/error shapes, error classification +
//! redaction, scope parsing, ID-token claims decoding, and CAE claims
//! building. Free functions and private types with zero coupling to
//! [`super::EntraAuthService`] — the `service` flows call these; nothing here
//! touches the network or the keyring.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

use crate::error::{AuthError, Result};

/// A `/token` success body. The three tokens are [`Zeroizing`], so every path
/// that drops a response (a nonce/tid mismatch, a save, the move into
/// `AccessToken`) wipes them; `Debug` prints `<redacted>` for each.
#[derive(Deserialize)]
pub(super) struct TokenResponse {
    #[serde(deserialize_with = "zeroizing")]
    pub(super) access_token: Zeroizing<String>,
    #[serde(default, deserialize_with = "zeroizing_opt")]
    pub(super) refresh_token: Option<Zeroizing<String>>,
    #[serde(default, deserialize_with = "zeroizing_opt")]
    pub(super) id_token: Option<Zeroizing<String>>,
    pub(super) expires_in: u64,
    #[serde(default)]
    pub(super) scope: Option<String>,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |t: &Option<Zeroizing<String>>| t.as_ref().map(|_| "<redacted>");
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("refresh_token", &redact(&self.refresh_token))
            .field("id_token", &redact(&self.id_token))
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

// zeroize's `serde` feature is off in the workspace; these move the
// deserialized `String` into the wrapper (no copy is left behind).
fn zeroizing<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}

fn zeroizing_opt<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(d).map(|o| o.map(Zeroizing::new))
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
/// NOT purge the refresh token. A Conditional Access step-up
/// (`interaction_required` / `login_required`, or `invalid_grant` carrying
/// AADSTS50074/50076/50079/50158 — MFA, registration, an external challenge)
/// comes next: the refresh token is still good for other audiences, so it is
/// [`AuthError::InteractionRequired`], never a purge. What remains of
/// `invalid_grant` means the refresh token is dead; the rest is a generic
/// exchange failure. The carried string is always the UI-safe redacted summary.
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
        "interaction_required" | "login_required"
    ) || (body.error == "invalid_grant"
        && matches!(
            aadsts.as_deref(),
            Some("AADSTS50074" | "AADSTS50076" | "AADSTS50079" | "AADSTS50158")
        ))
    {
        return AuthError::InteractionRequired(safe);
    }
    if body.error == "invalid_grant" {
        return AuthError::InvalidGrant(safe);
    }
    AuthError::TokenExchange(safe)
}

/// Builds a UI-safe summary of an AAD error response. Keeps the canonical
/// OAuth error code (e.g. `invalid_client`) and the AADSTS numeric code if
/// present, and drops the rest of `error_description` (which routinely
/// embeds tenant/user GUIDs, correlation IDs, and client IPs).
pub(super) fn redacted_aad_error(body: &TokenErrorBody) -> String {
    redact_aad_error(&body.error, body.error_description.as_deref())
}

/// The one redaction rule behind [`redacted_aad_error`], shared with the
/// loopback redirect's `error=` / `error_description=` pair:
/// `"{error} (AADSTSnnnnn)"`, or the bare `error` when the description carries
/// no AADSTS code.
pub(super) fn redact_aad_error(error: &str, description: Option<&str>) -> String {
    match description.and_then(extract_aadsts_code) {
        Some(code) => format!("{error} ({code})"),
        None => error.to_string(),
    }
}

/// Pulls the first `AADSTSnnnnn` token out of an AAD error_description.
pub(super) fn extract_aadsts_code(description: &str) -> Option<String> {
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

/// Parses the space-delimited `scope` from a token response. When the response
/// omits it entirely (`None`), falls back to `fallback` — the scopes
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
/// this on a token from an untrusted source: no signature, issuer, audience,
/// or expiry validation.
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
    fn redact_aad_error_is_the_shared_rule() {
        assert_eq!(
            redact_aad_error(
                "access_denied",
                Some("AADSTS65004: User declined. Trace ID: abc")
            ),
            "access_denied (AADSTS65004)"
        );
        assert_eq!(redact_aad_error("access_denied", None), "access_denied");
        assert_eq!(
            redact_aad_error("access_denied", Some("no code here")),
            "access_denied"
        );
    }

    #[test]
    fn token_response_wraps_every_token() {
        let r: TokenResponse = serde_json::from_str(
            r#"{"access_token":"at-SECRET","refresh_token":"rt-SECRET","id_token":"id-SECRET","expires_in":3600,"scope":"a b"}"#,
        )
        .unwrap();
        let _: &Zeroizing<String> = &r.access_token;
        let _: &Option<Zeroizing<String>> = &r.refresh_token;
        let _: &Option<Zeroizing<String>> = &r.id_token;
        assert_eq!(r.access_token.as_str(), "at-SECRET");
        assert_eq!(
            r.refresh_token.as_deref().map(String::as_str),
            Some("rt-SECRET")
        );
        assert_eq!(r.id_token.as_deref().map(String::as_str), Some("id-SECRET"));
        assert_eq!(r.expires_in, 3600);
        let debug = format!("{r:?}");
        assert!(!debug.contains("SECRET"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");

        let bare: TokenResponse =
            serde_json::from_str(r#"{"access_token":"at","expires_in":60}"#).unwrap();
        assert_eq!(bare.access_token.as_str(), "at");
        assert!(bare.refresh_token.is_none());
        assert!(bare.id_token.is_none());
        assert!(bare.scope.is_none());
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
    fn step_up_codes_classify_as_interaction_required_not_invalid_grant() {
        // A CA step-up for one resource must NOT read as a dead refresh token.
        for (error, description) in [
            (
                "interaction_required",
                Some("AADSTS50076: Due to a configuration change..."),
            ),
            ("login_required", None),
            (
                "invalid_grant",
                Some("AADSTS50079: The user is required to enroll..."),
            ),
            (
                "invalid_grant",
                Some("AADSTS50074: Strong Authentication is required."),
            ),
            (
                "invalid_grant",
                Some("AADSTS50158: External security challenge not satisfied."),
            ),
        ] {
            let body = TokenErrorBody {
                error: error.into(),
                error_description: description.map(str::to_string),
                correlation_id: None,
            };
            assert!(
                matches!(
                    classify_token_error(&body),
                    AuthError::InteractionRequired(_)
                ),
                "{error} {description:?}"
            );
        }
    }

    #[test]
    fn consent_still_wins_over_interaction_required() {
        let body = TokenErrorBody {
            error: "interaction_required".into(),
            error_description: Some(
                "AADSTS65001: The user or administrator has not consented".into(),
            ),
            correlation_id: None,
        };
        assert!(matches!(
            classify_token_error(&body),
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
