//! Microsoft Graph JSON batching (`POST /$batch`).
//!
//! Combines up to 20 GETs into one round trip, cutting the request count (and throttle exposure)
//! on the audit's per-app fan-out. The outer POST goes through the shared retry/throttle loop;
//! inner statuses map to the same typed [`GraphError`]s as an individual GET, and inner 429/5xx
//! sub-responses re-batch just the retried sub-requests (honoring an inner `Retry-After`) on the
//! shared `RetryBudget` — the outer loop can't see those, and the same GET sent alone would be
//! retried. See <https://learn.microsoft.com/en-us/graph/json-batching>.

use std::collections::HashMap;
use std::sync::Arc;

use azapptoolkit_core::http_retry::RetryClass;
use reqwest::Method;
use serde::de::DeserializeOwned;

use azapptoolkit_core::BearerProvider;
use azapptoolkit_core::http_error::sanitize_error_body;
use azapptoolkit_core::http_retry::{RetryBudget, parse_retry_after_seconds};
use azapptoolkit_core::models::Paged;

use super::GraphClient;
use crate::error::{GraphError, Result};

/// Max sub-requests Microsoft Graph accepts in one `$batch` POST.
const BATCH_MAX: usize = 20;

/// `$batch` POSTs in flight at once. The audit prewarm sends up to 250 chunks for a 5k-app
/// tenant; serial POSTs left the run idle for minutes before scoring started. 4 cuts the dead
/// time roughly 4x while staying well under the scoring loop's own fan-out pressure.
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
        // The same cap as a top-level error body: a sub-response feeds the
        // same variants, the same logs and the same toasts.
        let body = sanitize_error_body(&r.body.to_string());
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
    /// Issues many GETs in a single `POST /$batch` (max 20 per call; chunks
    /// automatically, up to `CHUNK_CONCURRENCY` chunks in flight), returning one `Result<T>`
    /// per URL **in order**. Inner statuses map to the same typed `GraphError`s as an
    /// individual GET; inner 429/5xx re-batch just that subset (honoring an inner `Retry-After`)
    /// on the shared retry budget — the policy the GET would get sent alone. `urls` are relative
    /// to the Graph version root (e.g. `"/servicePrincipals?$filter=..."`). Rides the **read**
    /// token — it wraps reads, so a browse-only session can use it.
    pub async fn batch_get_json<T: DeserializeOwned>(
        &self,
        urls: &[String],
    ) -> Result<Vec<Result<T>>> {
        self.batch_get_json_with_headers(urls, &[]).await
    }

    /// [`Self::batch_get_json`] on a **caller-supplied** bearer.
    ///
    /// `/sites/{id}/permissions` is a `Sites.*`-scoped read and can't ride the read token the
    /// way the directory batches do — yet it is by far the largest un-batched fan-out (one GET
    /// per site, up to the sweep's 5000-site cap; 20 GETs fit in one POST).
    pub(crate) async fn batch_get_json_scoped<T: DeserializeOwned>(
        &self,
        token: &Arc<dyn BearerProvider>,
        urls: &[String],
    ) -> Result<Vec<Result<T>>> {
        self.batch_get_json_inner(token, urls, &[]).await
    }

    /// [`Self::batch_get_json`] applying `headers` to **every** sub-request. The lone caller
    /// that needs this is an advanced query (`memberOf/microsoft.graph.group` with `$count`),
    /// which Graph rejects without a per-sub-request `ConsistencyLevel: eventual` — the outer
    /// POST's headers don't propagate to the batched sub-requests.
    pub async fn batch_get_json_with_headers<T: DeserializeOwned>(
        &self,
        urls: &[String],
        headers: &[(&str, &str)],
    ) -> Result<Vec<Result<T>>> {
        self.batch_get_json_inner(&self.read_token, urls, headers)
            .await
    }

    async fn batch_get_json_inner<T: DeserializeOwned>(
        &self,
        token: &Arc<dyn BearerProvider>,
        urls: &[String],
        headers: &[(&str, &str)],
    ) -> Result<Vec<Result<T>>> {
        // Grouped `join_all` rather than `stream::buffered`: the stream adapter's higher-ranked
        // lifetime bounds break the Send inference the Tauri command handlers need
        // (rust-lang/rust#64552). The group barrier costs a little wall-clock vs a sliding
        // window, but results stay in input order, which the index-keyed callers depend on.
        let chunks: Vec<&[String]> = urls.chunks(BATCH_MAX).collect();
        let mut out: Vec<Result<T>> = Vec::with_capacity(urls.len());
        for group in chunks.chunks(CHUNK_CONCURRENCY) {
            let results = futures::future::join_all(
                group
                    .iter()
                    .map(|c| self.batch_chunk::<T>(token, c, headers)),
            )
            .await;
            for chunk in results {
                out.extend(chunk?);
            }
        }
        Ok(out)
    }

    /// Resolves a batch of `Paged<T>` sub-results into fully-paginated item lists, preserving
    /// input order and the per-item `Result`. The common case (a small collection whose first
    /// page is complete) does no extra I/O; only a sub-response carrying `@odata.nextLink` is
    /// followed — once, outside the batch — via `collect_all_pages`. The outer `Result` is
    /// always `Ok` (a whole-batch failure already surfaced via `batch_get_json`'s `?`); it's
    /// kept so paged-batch helpers read uniformly.
    ///
    /// `consistency_eventual` states whether the sub-requests were advanced queries (the
    /// `ConsistencyLevel: eventual` sub-request header, as `batch_list_service_principal_groups`
    /// sends). Graph does not carry the header into the `nextLink` request, so an overflow
    /// continuation must restate it — and a plain batch must not add it, or pages 2+ come from
    /// the eventually-consistent index while page 1 came from the directory.
    ///
    /// Overflow continuations resolve serially **by design**: an order-preserving `join_all`
    /// would parallelize them, but the path almost never fires (federated creds cap at ~20/app,
    /// role assignments rarely page) — left serial until profiling shows it matters (a deliberate
    /// no-action item from the caching/perf assessment).
    pub(crate) async fn finish_paged_batch<T: DeserializeOwned>(
        &self,
        pages: Vec<Result<Paged<T>>>,
        consistency_eventual: bool,
    ) -> Result<Vec<Result<Vec<T>>>> {
        let mut out = Vec::with_capacity(pages.len());
        for page in pages {
            match page {
                Ok(p) => out.push(self.collect_all_pages(p, consistency_eventual).await),
                Err(e) => out.push(Err(e)),
            }
        }
        Ok(out)
    }

    /// [`Self::finish_paged_batch`] for a batch issued under a **specific** token.
    ///
    /// The unscoped version continues through `get_json_absolute_with`, which picks the default
    /// read token by verb — right for batches the read token already covers, wrong for a batch
    /// issued via `batch_get_json_scoped`: `/sites/{id}/permissions` needs `Sites.FullControl.All`,
    /// which the verb-selected Directory.Read.All does not carry, so page 2 of a site whose grant
    /// list overflowed came back 403 while page 1 succeeded.
    ///
    /// `collect_pages_from` re-applies the same-origin guard on every hop, so the scoped bearer
    /// never leaves the Graph origin.
    pub(crate) async fn finish_paged_batch_scoped<T: DeserializeOwned + Send>(
        &self,
        token: &Arc<dyn BearerProvider>,
        pages: Vec<Result<Paged<T>>>,
    ) -> Result<Vec<Result<Vec<T>>>> {
        let mut out = Vec::with_capacity(pages.len());
        for page in pages {
            match page {
                Ok(p) => out.push(
                    self.collect_pages_from(p, |u| async move {
                        self.scoped_get_retried(token, &u).await
                    })
                    .await,
                ),
                Err(e) => out.push(Err(e)),
            }
        }
        Ok(out)
    }

    /// One `$batch` POST for `urls` (already ≤ `BATCH_MAX`), with inner 429/5xx
    /// retry (see [`retried_sub_status`]).
    /// `headers`, when non-empty, are attached to every sub-request.
    async fn batch_chunk<T: DeserializeOwned>(
        &self,
        token: &Arc<dyn BearerProvider>,
        urls: &[String],
        headers: &[(&str, &str)],
    ) -> Result<Vec<Result<T>>> {
        let batch_url = format!("{}/$batch", self.base_url);
        let mut results: Vec<Option<Result<T>>> = (0..urls.len()).map(|_| None).collect();
        // `pending` holds the original chunk indices still awaiting a non-retry
        // response; the sub-request `id` is the index so order is preserved.
        let mut pending: Vec<usize> = (0..urls.len()).collect();
        // The SAME schedule the four unified clients use — this loop retries only
        // throttled/failed sub-requests, so it can't be `with_retries`, but the budget
        // and backoff curve are not its to re-derive.
        let mut budget = RetryBudget::new();
        // Inner 429s/5xx surfaced as `Throttled`/`Server` because the budget
        // was spent — logged once after the loop so an exhausted re-batch is
        // not silent.
        let mut exhausted: usize = 0;

        while !pending.is_empty() {
            let requests: Vec<serde_json::Value> = pending
                .iter()
                .map(|&i| {
                    let mut req =
                        serde_json::json!({ "id": i.to_string(), "method": "GET", "url": urls[i] });
                    if !headers.is_empty() {
                        req["headers"] = serde_json::Value::Object(
                            headers
                                .iter()
                                .map(|(k, v)| ((*k).to_string(), serde_json::Value::from(*v)))
                                .collect(),
                        );
                    }
                    req
                })
                .collect();
            let body = serde_json::json!({ "requests": requests });
            let bytes = self
                .send_core_url_with(
                    token,
                    // A POST by transport, a read by semantics: every sub-request is a GET
                    // (`batch_sub_url` takes no body; callers are all `batch_get_*`), so replaying
                    // cannot double-commit anything. Stated explicitly rather than inferred from
                    // the verb, which would read this as a mutation and stop retrying — `$batch`
                    // is the throttle-happiest endpoint in the API.
                    RetryClass::Idempotent,
                    Method::POST,
                    &batch_url,
                    &[],
                    false,
                    Some(body),
                    None,
                )
                .await?;
            let envelope: BatchEnvelope = serde_json::from_slice(&bytes)
                .map_err(|e| GraphError::Deserialize(e.to_string()))?;

            let mut retry: Vec<usize> = Vec::new();
            // Inner 429s this round — the only status that is service
            // pressure worth telling the throttle observer about.
            let mut throttled_count: usize = 0;
            let mut max_retry_after: Option<u64> = None;
            for sub in envelope.responses {
                let Ok(idx) = sub.id.parse::<usize>() else {
                    continue;
                };
                if idx >= urls.len() || results[idx].is_some() {
                    continue;
                }
                // Retry inner 429s/5xx while we still have budget; otherwise
                // let map_batch_response surface them as `Throttled`/`Server`.
                if retried_sub_status(sub.status) && budget.may_retry() {
                    // A 5xx normally carries no `Retry-After`, so the wait
                    // below falls back to the shared jittered backoff.
                    let ra = sub.retry_after_secs();
                    max_retry_after = match (max_retry_after, ra) {
                        (Some(a), Some(b)) => Some(a.max(b)),
                        (a, b) => a.or(b),
                    };
                    if sub.status == 429 {
                        throttled_count += 1;
                    }
                    retry.push(idx);
                    continue;
                }
                if retried_sub_status(sub.status) {
                    exhausted += 1;
                }
                results[idx] = Some(map_batch_response::<T>(sub));
            }

            if retry.is_empty() {
                break;
            }
            // A 5xx is a failed request, not service pressure: only a 429
            // feeds the adaptive concurrency throttle.
            if throttled_count > 0
                && let Some(obs) = self.throttle_observer.read().as_ref()
            {
                obs.on_throttle(max_retry_after);
            }
            // Counts only — the sub-request URLs carry object ids and filters.
            tracing::info!(
                throttled = throttled_count,
                failed = retry.len() - throttled_count,
                chunk = urls.len(),
                attempt = budget.attempt(),
                retry_after_secs = ?max_retry_after,
                "graph $batch: re-batching throttled or failed sub-requests"
            );
            budget.wait(max_retry_after).await;
            pending = retry;
        }
        if exhausted > 0 {
            tracing::warn!(
                exhausted,
                attempts = budget.attempt() + 1,
                "graph $batch: retry budget exhausted; surfacing throttled or failed sub-requests"
            );
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

/// Whether an inner `$batch` sub-response status is re-batched. Mirrors the single-request
/// classification in `transport.rs` (`send_core_url_with`): every status that is not a terminal
/// 4xx — a 429 or any 5xx — is an `Attempt::Retry`, so the same GET gets the same policy
/// batched or alone. Every sub-request here is a GET, so replaying a 5xx cannot double-commit.
fn retried_sub_status(status: u16) -> bool {
    status == 429 || status >= 500
}
