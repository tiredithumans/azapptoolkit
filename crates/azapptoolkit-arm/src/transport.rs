//! Shared ARM-stack transport: one retry + jitter + `Retry-After` loop that
//! maps HTTP status → typed [`ArmError`], used by both the control-plane
//! [`crate::ArmClient`] and the data-plane [`crate::LogAnalyticsClient`] (same
//! error stack, same `azapptoolkit_core::http_retry` knobs).

use std::sync::Arc;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use azapptoolkit_core::http_retry::{
    Attempt, RetryClass, RetryReason, parse_retry_after_seconds, with_retries,
};
use azapptoolkit_core::token::{BearerProvider, TokenError};

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
            .map_err(|e| ArmError::Token(TokenError::opaque(e.to_string())))?,
    );

    // Retry budget, backoff and `Retry-After` handling all live in
    // `http_retry::with_retries`; this closure only classifies one attempt.
    with_retries(label, retry_class_for(&method), |_| {
        let http = http.clone();
        let headers = headers.clone();
        let method = method.clone();
        async move {
            let mut req = http.request(method, url).headers(headers).query(query);
            if let Some(b) = body {
                req = req.json(b);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                // No response means no `Retry-After` to honor — the shared loop
                // falls back to jittered exponential backoff.
                Err(err) => {
                    return Attempt::Retry {
                        reason: RetryReason::Transient,
                        retry_after_secs: None,
                        err: ArmError::Network(err.to_string()),
                    };
                }
            };
            let status = resp.status();
            if status.is_success() {
                return Attempt::Done(
                    resp.bytes()
                        .await
                        .map_err(|e| ArmError::Network(e.to_string())),
                );
            }
            let retry_after = parse_retry_after_seconds(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            let body_text = resp.text().await.unwrap_or_default();
            let code = status.as_u16();

            // 401/403/404 are typed; any other non-429 4xx is terminal → `Api`
            // (which lets a Logs `query` treat a 400 "table absent" as a probe
            // miss rather than a hard failure).
            let terminal = match code {
                401 => Some(ArmError::Unauthorized),
                403 => Some(ArmError::Forbidden(body_text.clone())),
                404 => Some(ArmError::NotFound(body_text.clone())),
                c if (400..500).contains(&c) && c != 429 => Some(ArmError::Api {
                    status: code,
                    body: body_text.clone(),
                }),
                _ => None,
            };
            if let Some(err) = terminal {
                return Attempt::Done(Err(err));
            }

            // 429 and 5xx: retryable, and this is the error the shared loop
            // surfaces once the budget is spent.
            Attempt::Retry {
                reason: if code == 429 {
                    RetryReason::Throttled
                } else {
                    RetryReason::Transient
                },
                retry_after_secs: retry_after,
                err: if code == 429 {
                    ArmError::Throttled {
                        retry_after_secs: retry_after,
                    }
                } else {
                    ArmError::Server {
                        status: code,
                        body: body_text,
                    }
                },
            }
        }
    })
    .await
}

/// The retry class for an HTTP verb.
///
/// `GET`/`HEAD`/`PUT`/`DELETE` are idempotent by definition, so replaying one
/// whose outcome is unknown is safe. `POST`/`PATCH` may have already committed,
/// so only an explicit throttle is replayed for them — see
/// [`azapptoolkit_core::http_retry::RetryClass`].
fn retry_class_for(method: &Method) -> RetryClass {
    match *method {
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE => RetryClass::Idempotent,
        _ => RetryClass::NonIdempotent,
    }
}
