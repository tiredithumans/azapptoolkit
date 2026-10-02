//! Shared ARM-stack transport: one retry + jitter + `Retry-After` loop whose
//! attempts map HTTP status → typed [`ArmError`], used by both the control-plane
//! [`crate::ArmClient`] and the data-plane [`crate::LogAnalyticsClient`] (same
//! error stack, same `azapptoolkit_core::http_retry` knobs).

use std::sync::Arc;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use azapptoolkit_core::http_error::{describe_error_chain, failed_response, send_failure};
use azapptoolkit_core::http_retry::{Attempt, RetryClass, parse_retry_after_seconds, with_retries};
use azapptoolkit_core::net::endpoint_family;
use azapptoolkit_core::token::{BearerProvider, TokenError};

use crate::error::{ArmError, Result};

/// Sends one request through the shared retry loop and returns the raw success
/// body. Failed responses are classified by
/// [`azapptoolkit_core::http_error::failed_response`] (the Key Vault client's
/// same table): a non-429 4xx is terminal — letting a Logs `query` treat a 400
/// "table absent" as a probe miss — while 429 and 5xx are retried, honoring an
/// explicit `Retry-After` exactly. `label` tags the retry warnings (e.g.
/// `"arm"`, `"log analytics"`), followed by the verb and endpoint family (ids
/// masked, no query).
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
    let label = format!("{label} {method} {}", endpoint_family(url));
    with_retries(&label, retry_class_for(&method), |_| {
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
                Err(err) => return send_failure(&err),
            };
            let status = resp.status();
            if status.is_success() {
                return Attempt::Done(
                    resp.bytes()
                        .await
                        .map_err(|e| ArmError::Network(describe_error_chain(&e))),
                );
            }
            // `Retry-After` first: reading the body consumes the response.
            let retry_after = parse_retry_after_seconds(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            let raw_body = resp.text().await.unwrap_or_default();
            failed_response(status.as_u16(), retry_after, &raw_body)
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
