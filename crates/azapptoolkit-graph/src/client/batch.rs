//! Microsoft Graph JSON batching (`POST /$batch`).
//!
//! Combines up to 20 GET requests into a single HTTP round trip, cutting the
//! request count (and throttling exposure) on the audit's per-app fan-out. The
//! outer POST goes through the shared retry/throttle loop; inner per-request
//! statuses are mapped to the same typed [`GraphError`]s as an individual GET,
//! and inner 429s re-batch just the throttled sub-requests (honoring the inner
//! `Retry-After`) — the outer retry loop can't see those.
//! See <https://learn.microsoft.com/en-us/graph/json-batching>.

use std::collections::HashMap;

use reqwest::Method;
use serde::de::DeserializeOwned;

use azapptoolkit_core::http_retry::{
    next_backoff_ms, parse_retry_after_seconds, sleep_before_retry, BASE_DELAY_MS, MAX_RETRIES,
};

use super::GraphClient;
use crate::error::{GraphError, Result};

/// Max sub-requests Microsoft Graph accepts in one `$batch` POST.
const BATCH_MAX: usize = 20;

/// `$batch` POSTs in flight at once. The audit prewarm sends up to 250 chunks
/// for a 5k-app tenant; strictly serial POSTs left the run idle for minutes
/// before scoring started. 4 stays well under the scoring loop's own fan-out
/// pressure while cutting the dead time roughly 4x.
const CHUNK_CONCURRENCY: usize = 4;

#[derive(serde::Deserialize)]
struct BatchEnvelope {
    #[serde(default)]
    responses: Vec<BatchSubResponse>,
}

#[derive(serde::Deserialize)]
struct BatchSubResponse {
    id: String,
    status: u16,
    #[serde(default)]
    body: serde_json::Value,
    #[serde(default)]
    headers: HashMap<String, String>,
}

impl BatchSubResponse {
    /// Inner `Retry-After` (seconds); header lookup is case-insensitive.
    fn retry_after_secs(&self) -> Option<u64> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("retry-after"))
            .and_then(|(_, v)| parse_retry_after_seconds(Some(v.as_str())))
    }
}

/// Maps one inner batch response to the typed result an individual GET yields.
fn map_batch_response<T: DeserializeOwned>(r: BatchSubResponse) -> Result<T> {
    let code = r.status;
    if (200..300).contains(&code) {
        serde_json::from_value(r.body).map_err(|e| GraphError::Deserialize(e.to_string()))
    } else {
        let retry_after_secs = r.retry_after_secs();
        let body = r.body.to_string();
        Err(match code {
            401 => GraphError::Unauthorized,
            403 => GraphError::Forbidden(body),
            404 => GraphError::NotFound(body),
            429 => GraphError::Throttled { retry_after_secs },
            s if s >= 500 => GraphError::Server { status: s, body },
            s => GraphError::Api { status: s, body },
        })
    }
}

impl GraphClient {
    /// Issues many GET requests in a single `POST /$batch` (max 20 per call;
    /// chunks automatically, up to [`CHUNK_CONCURRENCY`] chunks in flight).
    /// Returns one `Result<T>` per input URL, **in order**.
    /// Inner per-request statuses map to the same typed `GraphError`s as an
    /// individual GET; inner 429s re-batch the throttled subset (honoring the
    /// inner `Retry-After`) up to `MAX_RETRIES`. `urls` are relative to the Graph
    /// version root (e.g. `"/servicePrincipals?$filter=..."`). The `$batch` POST
    /// rides the **read** token — it wraps reads, so a browse-only session can use it.
    pub async fn batch_get_json<T: DeserializeOwned>(
        &self,
        urls: &[String],
    ) -> Result<Vec<Result<T>>> {
        // Grouped `join_all` rather than `stream::buffered`: the stream
        // adapter's higher-ranked lifetime bounds break the Send inference the
        // Tauri command handlers need (rust-lang/rust#64552). A group barrier
        // costs a little wall-clock vs a sliding window, but results stay in
        // input order, which the index-keyed callers depend on.
        let chunks: Vec<&[String]> = urls.chunks(BATCH_MAX).collect();
        let mut out: Vec<Result<T>> = Vec::with_capacity(urls.len());
        for group in chunks.chunks(CHUNK_CONCURRENCY) {
            let results =
                futures::future::join_all(group.iter().map(|c| self.batch_chunk::<T>(c))).await;
            for chunk in results {
                out.extend(chunk?);
            }
        }
        Ok(out)
    }

    /// One `$batch` POST for `urls` (already ≤ `BATCH_MAX`), with inner-429 retry.
    async fn batch_chunk<T: DeserializeOwned>(&self, urls: &[String]) -> Result<Vec<Result<T>>> {
        let batch_url = format!("{}/$batch", self.base_url);
        let mut results: Vec<Option<Result<T>>> = (0..urls.len()).map(|_| None).collect();
        // `pending` holds the original chunk indices still awaiting a non-retry
        // response; the sub-request `id` is the index so order is preserved.
        let mut pending: Vec<usize> = (0..urls.len()).collect();
        let mut attempt = 0u32;
        let mut delay_ms = BASE_DELAY_MS;

        while !pending.is_empty() {
            let requests: Vec<serde_json::Value> = pending
                .iter()
                .map(|&i| serde_json::json!({ "id": i.to_string(), "method": "GET", "url": urls[i] }))
                .collect();
            let body = serde_json::json!({ "requests": requests });
            let bytes = self
                .send_core_url_with(
                    &self.read_token,
                    Method::POST,
                    &batch_url,
                    &[],
                    false,
                    Some(body),
                )
                .await?;
            let envelope: BatchEnvelope = serde_json::from_slice(&bytes)
                .map_err(|e| GraphError::Deserialize(e.to_string()))?;

            let mut throttled: Vec<usize> = Vec::new();
            let mut max_retry_after: Option<u64> = None;
            for sub in envelope.responses {
                let Ok(idx) = sub.id.parse::<usize>() else {
                    continue;
                };
                if idx >= urls.len() || results[idx].is_some() {
                    continue;
                }
                // Retry inner 429s while we still have budget; otherwise let
                // map_batch_response surface them as `Throttled`.
                if sub.status == 429 && attempt < MAX_RETRIES {
                    let ra = sub.retry_after_secs();
                    max_retry_after = match (max_retry_after, ra) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                    throttled.push(idx);
                    continue;
                }
                results[idx] = Some(map_batch_response::<T>(sub));
            }

            if throttled.is_empty() {
                break;
            }
            if let Some(obs) = self.throttle_observer.read().as_ref() {
                obs.on_throttle(max_retry_after);
            }
            sleep_before_retry(max_retry_after, delay_ms).await;
            delay_ms = next_backoff_ms(delay_ms);
            attempt += 1;
            pending = throttled;
        }

        // Any index the server never answered (omitted from `responses`) stays
        // `None` → a protocol error, rather than a silently-missing result.
        Ok(results
            .into_iter()
            .map(|r| {
                r.unwrap_or_else(|| Err(GraphError::Protocol("missing batch response".into())))
            })
            .collect())
    }
}
