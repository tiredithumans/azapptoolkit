//! Transport core for the Exchange Online Admin API: the `CmdletInput`
//! envelope POST, the retry loop with its diagnostics-header capture (the
//! bodyless-403 semantics live here), and the shared result projections.

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::json;

use azapptoolkit_core::http_retry::{
    BASE_DELAY_MS, MAX_RETRIES, next_backoff_ms, parse_retry_after_seconds, sleep_before_retry,
    sleep_with_jitter,
};

use super::{ADMIN_API_VERSION, ExchangeClient, INVOKE_ENDPOINT, X_ANCHOR_MAILBOX};
use crate::error::{ExchangeError, Result, is_not_found_body};

impl ExchangeClient {
    /// POSTs a `CmdletInput` envelope and returns the parsed `value` array.
    pub(crate) async fn invoke_command(
        &self,
        cmdlet: &str,
        parameters: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "{}/adminapi/{}/{}/{}",
            self.base_url.trim_end_matches('/'),
            ADMIN_API_VERSION,
            self.tenant_id,
            INVOKE_ENDPOINT
        );
        let body = json!({
            "CmdletInput": { "CmdletName": cmdlet, "Parameters": parameters }
        });
        let bytes = self.send_core(cmdlet, &url, &body).await?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        #[derive(serde::Deserialize)]
        struct Envelope {
            #[serde(default)]
            value: Vec<serde_json::Value>,
        }
        let env: Envelope = serde_json::from_slice(&bytes)
            .map_err(|e| ExchangeError::Deserialize(e.to_string()))?;
        Ok(env.value)
    }

    /// Like [`Self::invoke_command`] but maps a "not found" cmdlet error (the
    /// EXO `Get-*` cmdlets throw when an `-Identity` doesn't resolve) to an
    /// empty result, so callers can treat a missing object as `None`.
    pub(crate) async fn invoke_optional(
        &self,
        cmdlet: &str,
        parameters: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>> {
        match self.invoke_command(cmdlet, parameters).await {
            Ok(values) => Ok(values),
            Err(ExchangeError::NotFound(_)) => Ok(Vec::new()),
            Err(ExchangeError::Api { body, .. }) if is_not_found_body(&body) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    async fn send_core(
        &self,
        cmdlet: &str,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<bytes::Bytes> {
        let bearer = self.token.bearer().await.map_err(ExchangeError::Token)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| ExchangeError::Token(e.to_string()))?,
        );
        headers.insert(
            X_ANCHOR_MAILBOX,
            HeaderValue::from_str(&self.anchor_mailbox)
                .map_err(|e| ExchangeError::Protocol(e.to_string()))?,
        );

        let mut attempt = 0u32;
        let mut delay_ms = BASE_DELAY_MS;
        loop {
            let resp = self
                .http
                .post(url)
                .headers(headers.clone())
                .json(body)
                .send()
                .await;
            let resp = match resp {
                Ok(r) => r,
                Err(err) => {
                    if attempt < MAX_RETRIES {
                        tracing::warn!(%attempt, ?err, "transport error; retrying");
                        sleep_with_jitter(delay_ms).await;
                        attempt += 1;
                        delay_ms = next_backoff_ms(delay_ms);
                        continue;
                    }
                    return Err(ExchangeError::Network(err.to_string()));
                }
            };

            let status = resp.status();
            if status.is_success() {
                return resp
                    .bytes()
                    .await
                    .map_err(|e| ExchangeError::Network(e.to_string()));
            }

            let retry_after = parse_retry_after_seconds(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            // The EXO admin endpoint returns its real authorization reason in the
            // `x-ms-diagnostics` header, not the body (a 403 body is typically a
            // NUL-padded blob). Capture the diagnostic headers so the surfaced
            // error names *why* and *which request*, not just `<no body>`.
            let header_str = |name: &str| {
                resp.headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let diagnostics = header_str("x-ms-diagnostics");
            let request_id = header_str("request-id").or_else(|| header_str("x-ms-request-id"));
            // On a bodyless rejection the auth middleware's reason (if any)
            // rides `WWW-Authenticate` — captured for the log line below.
            let www_authenticate = header_str("www-authenticate");
            let raw_body = resp.text().await.unwrap_or_default();
            let body_text = compose_error_detail(cmdlet, &raw_body, &diagnostics, &request_id);
            let code = status.as_u16();
            // Any non-429 4xx is a terminal client error (401/403/404 get their
            // own variants below; everything else falls through to `Api`).
            let is_client_4xx = (400..500).contains(&code) && code != 429;

            if code == 401 {
                return Err(ExchangeError::Unauthorized);
            }
            if is_client_4xx {
                tracing::warn!(
                    cmdlet,
                    status = code,
                    diagnostics = diagnostics.as_deref().unwrap_or(""),
                    request_id = request_id.as_deref().unwrap_or(""),
                    www_authenticate = www_authenticate.as_deref().unwrap_or(""),
                    "exchange admin cmdlet rejected"
                );
            }
            if code == 403 {
                // Whether EXO named an RBAC reason (`x-ms-diagnostics`) vs. a
                // bodyless/reasonless 403 — `ui_hint` branches on this so a stale
                // role token isn't misreported as a definite Exchange RBAC gap.
                let had_diagnostics = diagnostics
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|d| !d.is_empty());
                return Err(ExchangeError::Forbidden {
                    detail: body_text,
                    had_diagnostics,
                });
            }
            if code == 404 {
                return Err(ExchangeError::NotFound(body_text));
            }
            if is_client_4xx {
                return Err(ExchangeError::Api {
                    status: code,
                    body: body_text,
                });
            }

            // Retryable (429, 5xx). An explicit `Retry-After` is waited exactly
            // (no jitter / no 30s clamp); only the no-header path uses backoff.
            if attempt < MAX_RETRIES {
                tracing::warn!(%attempt, status = %status, retry_after_secs = ?retry_after, "transient error; retrying");
                sleep_before_retry(retry_after, delay_ms).await;
                attempt += 1;
                delay_ms = next_backoff_ms(delay_ms);
                continue;
            }

            return if code == 429 {
                Err(ExchangeError::Throttled {
                    retry_after_secs: retry_after,
                })
            } else {
                Err(ExchangeError::Server {
                    status: code,
                    body: body_text,
                })
            };
        }
    }
}

/// Normalizes an HTTP error-response body before it is stored in an
/// [`ExchangeError`]. Exchange/edge responses are sometimes binary or
/// NUL-padded (e.g. a 403 from a front-end proxy returns a long run of `\0`),
/// which otherwise pollutes logs and surfaced error messages. Strips control
/// characters (keeping ordinary whitespace), trims, and caps the length;
/// returns `<no body>` when nothing printable remains.
fn sanitize_error_body(raw: &str) -> String {
    const MAX_CHARS: usize = 800;
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return "<no body>".to_string();
    }
    let mut out: String = trimmed.chars().take(MAX_CHARS).collect();
    if trimmed.chars().count() > MAX_CHARS {
        out.push('…');
    }
    out
}

/// Builds the human-readable detail stored in a client/server `ExchangeError`.
/// EXO puts the real authorization reason in `x-ms-diagnostics` rather than the
/// (often NUL-padded, empty) response body, so prefer the diagnostics header and
/// fall back to the sanitized body. The detail is prefixed with the originating
/// `cmdlet` and suffixed with the `request-id` (when present) so a 403 names both
/// *why* and *which request* instead of the old opaque `<no body>`.
fn compose_error_detail(
    cmdlet: &str,
    raw_body: &str,
    diagnostics: &Option<String>,
    request_id: &Option<String>,
) -> String {
    let reason = match diagnostics.as_deref().map(str::trim) {
        Some(d) if !d.is_empty() => sanitize_error_body(d),
        _ => sanitize_error_body(raw_body),
    };
    let mut out = format!("[{cmdlet}] {reason}");
    if let Some(id) = request_id.as_deref().map(str::trim)
        && !id.is_empty()
    {
        out.push_str(&format!(" (request-id: {id})"));
    }
    out
}

/// Projects the single object a `New-*`/`Test-*` cmdlet must return. An empty
/// `value` array is a broken-contract response, not an HTTP failure — surfaced
/// as [`ExchangeError::Protocol`] (it used to fabricate `Api { status: 200 }`,
/// which anything reasoning about HTTP status would misread).
pub(crate) fn first_as<T: DeserializeOwned>(
    values: Vec<serde_json::Value>,
    cmdlet: &str,
) -> Result<T> {
    let v = values
        .into_iter()
        .next()
        .ok_or_else(|| ExchangeError::Protocol(format!("{cmdlet} returned no object")))?;
    serde_json::from_value(v).map_err(|e| ExchangeError::Deserialize(e.to_string()))
}

/// Projects the first returned object to `T`, or `None` when the cmdlet
/// returned nothing — the shared tail of every optional `Get-*` lookup
/// (paired with [`ExchangeClient::invoke_optional`]).
pub(crate) fn first_optional_as<T: DeserializeOwned>(
    values: Vec<serde_json::Value>,
) -> Result<Option<T>> {
    values
        .into_iter()
        .next()
        .map(|v| serde_json::from_value(v).map_err(|e| ExchangeError::Deserialize(e.to_string())))
        .transpose()
}

/// Projects every returned object to `T`.
pub(crate) fn all_as<T: DeserializeOwned>(values: Vec<serde_json::Value>) -> Result<Vec<T>> {
    values
        .into_iter()
        .map(|v| serde_json::from_value(v).map_err(|e| ExchangeError::Deserialize(e.to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_error_body_strips_nul_padding_trims_and_caps() {
        // A NUL-padded 403 body (observed from an edge proxy) collapses to the
        // placeholder rather than a screenful of escaped \0 in the logs.
        assert_eq!(sanitize_error_body(&"\0".repeat(256)), "<no body>");
        // Control chars are stripped; ordinary text + whitespace survive trimmed.
        assert_eq!(sanitize_error_body("  Forbidden\0\u{7}  "), "Forbidden");
        assert_eq!(sanitize_error_body("line1\nline2"), "line1\nline2");
        // Over-long bodies are capped with an ellipsis marker.
        let out = sanitize_error_body(&"x".repeat(1000));
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 801);
    }

    #[test]
    fn compose_error_detail_prefers_diagnostics_and_names_cmdlet() {
        // Empty body but a populated x-ms-diagnostics header: the reason comes
        // from the header, the cmdlet is named, and the request id is appended.
        let detail = compose_error_detail(
            "New-ManagementRoleAssignment",
            &"\0".repeat(64),
            &Some("2000003;reason=\"role required\"".to_string()),
            &Some("abc-123".to_string()),
        );
        assert!(detail.starts_with("[New-ManagementRoleAssignment] "));
        assert!(detail.contains("role required"));
        assert!(detail.contains("(request-id: abc-123)"));
        assert!(!detail.contains("<no body>"));
    }

    #[test]
    fn compose_error_detail_falls_back_to_no_body_when_nothing_present() {
        // No diagnostics and an empty/NUL body: still `<no body>`, but now the
        // failing cmdlet is identified.
        let detail = compose_error_detail("Get-Group", &"\0".repeat(16), &None, &None);
        assert_eq!(detail, "[Get-Group] <no body>");
    }

    #[test]
    fn first_as_reports_empty_result_as_protocol_error() {
        let err = first_as::<serde_json::Value>(Vec::new(), "New-ServicePrincipal").unwrap_err();
        assert!(
            matches!(err, ExchangeError::Protocol(ref m) if m.contains("New-ServicePrincipal")),
            "got {err:?}"
        );
    }
}
