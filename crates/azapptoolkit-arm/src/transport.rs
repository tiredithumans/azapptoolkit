//! Shared ARM-stack transport: one retry + jitter + `Retry-After` loop that
//! maps HTTP status → typed [`ArmError`], used by both the control-plane
//! [`crate::ArmClient`] and the data-plane [`crate::LogAnalyticsClient`] (same
//! error stack, same `azapptoolkit_core::http_retry` knobs).

use std::sync::Arc;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use azapptoolkit_core::http_retry::{
    BASE_DELAY_MS, MAX_RETRIES, next_backoff_ms, parse_retry_after_seconds, sleep_before_retry,
    sleep_with_jitter,
};
use azapptoolkit_core::token::BearerProvider;

use crate::error::{ArmError, Result};

/// Sends one request through the shared retry loop and returns the raw success
/// body. 401/403/404 are typed; any other non-429 4xx is terminal → `Api`
/// (which lets a Logs `query` treat a 400 "table absent" as a probe miss rather
/// than a hard failure); 429 and 5xx are retried, honoring an explicit
/// `Retry-After` exactly and otherwise using jittered exponential backoff.
/// `label` tags the retry warnings (e.g. `"arm"`, `"log analytics"`).
pub(crate) async fn send_with_retry(
    http: &reqwest::Client,
    token: &Arc<dyn BearerProvider>,
    label: &str,
    method: Method,
    url: &str,
    query: &[(&str, &str)],
    body: Option<&serde_json::Value>,
) -> Result<bytes::Bytes> {
    let bearer = token.bearer().await.map_err(ArmError::Token)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {bearer}"))
            .map_err(|e| ArmError::Token(e.to_string()))?,
    );

    let mut attempt = 0u32;
    let mut delay_ms = BASE_DELAY_MS;
    loop {
        let mut req = http
            .request(method.clone(), url)
            .headers(headers.clone())
            .query(query);
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = match req.send().await {
            Ok(r) => r,
            Err(err) => {
                if attempt < MAX_RETRIES {
                    tracing::warn!(%attempt, ?err, "{label} transport error; retrying");
                    sleep_with_jitter(delay_ms).await;
                    attempt += 1;
                    delay_ms = next_backoff_ms(delay_ms);
                    continue;
                }
                return Err(ArmError::Network(err.to_string()));
            }
        };
        let status = resp.status();
        if status.is_success() {
            return resp
                .bytes()
                .await
                .map_err(|e| ArmError::Network(e.to_string()));
        }
        let retry_after = parse_retry_after_seconds(
            resp.headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
        );
        let body_text = resp.text().await.unwrap_or_default();
        let code = status.as_u16();

        if code == 401 {
            return Err(ArmError::Unauthorized);
        }
        if code == 403 {
            return Err(ArmError::Forbidden(body_text));
        }
        if code == 404 {
            return Err(ArmError::NotFound(body_text));
        }
        if (400..500).contains(&code) && code != 429 {
            return Err(ArmError::Api {
                status: code,
                body: body_text,
            });
        }
        if attempt < MAX_RETRIES {
            // An explicit `Retry-After` is honored exactly; only the
            // no-header path uses jittered exponential backoff.
            tracing::warn!(%attempt, status = %status, retry_after_secs = ?retry_after, "{label} transient; retrying");
            sleep_before_retry(retry_after, delay_ms).await;
            attempt += 1;
            delay_ms = next_backoff_ms(delay_ms);
            continue;
        }
        return if code == 429 {
            Err(ArmError::Throttled {
                retry_after_secs: retry_after,
            })
        } else {
            Err(ArmError::Server {
                status: code,
                body: body_text,
            })
        };
    }
}
