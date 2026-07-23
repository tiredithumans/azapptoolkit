//! HTTP transport for [`GraphClient`]: the retrying core (`send_core*`), the
//! one-shot scoped (explicit-token) family, the pagination helpers, and the
//! wire-building free functions the domain modules share. Split out of
//! `client.rs` as pure code motion — the behavioral contracts (retry budget,
//! CAE single re-mint, origin guard, one-shot scoped calls degrading fast)
//! are unchanged and pinned by `tests/transport.rs`.

use super::*;

const CONSISTENCY_LEVEL: HeaderName = HeaderName::from_static("consistencylevel");
const PREFER: HeaderName = HeaderName::from_static("prefer");

impl GraphClient {
    /// GET an absolute URL with an explicit (non-default) bearer token, decoding
    /// the JSON body. Used for optional, separately-scoped reads (provisioning,
    /// reports) that bypass the verb-selected read/write token. Maps HTTP errors
    /// to typed `GraphError`s so callers can degrade gracefully (e.g. 404 =
    /// feature not configured, 403 = missing scope/license).
    pub(crate) async fn scoped_get<T: DeserializeOwned>(
        &self,
        token: &Arc<dyn BearerProvider>,
        url: &str,
    ) -> Result<T> {
        let bearer = token.bearer().await.map_err(GraphError::Token)?;
        let resp = self
            .http
            .get(url)
            .header(AUTHORIZATION, format!("Bearer {bearer}"))
            .send()
            .await
            .map_err(|e| GraphError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            let retry_after = parse_retry_after_seconds(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            let body = resp.text().await.unwrap_or_default();
            return Err(map_error_status(code, body, retry_after));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| GraphError::Network(e.to_string()))?;
        serde_json::from_slice(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// GET an absolute URL with an explicit (non-default) bearer token through
    /// the retrying transport ([`Self::send_core_url_with`]), decoding the JSON
    /// body. High-volume scoped reads — the SharePoint site sweep fans
    /// [`Self::list_site_permissions`] out across thousands of sites against
    /// the throttle-happiest endpoint family — ride this so transient 429s/5xx
    /// are absorbed with `Retry-After` honored exactly, instead of surfacing as
    /// phantom per-site failures. One-off feature probes that prefer to degrade
    /// fast keep using the single-shot [`Self::scoped_get`].
    pub(crate) async fn scoped_get_retried<T: DeserializeOwned>(
        &self,
        token: &Arc<dyn BearerProvider>,
        url: &str,
    ) -> Result<T> {
        let bytes = self
            .send_core_url_with(token, Method::GET, url, &[], false, None, None)
            .await?;
        serde_json::from_slice(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// POST/PATCH an absolute URL with an explicit (non-default) bearer token,
    /// decoding the JSON response. The non-GET sibling of [`Self::scoped_get`]
    /// — used for writes that need a separately-scoped token (claims-mapping
    /// policies on `policy_write_token`) rather than the verb-selected
    /// read/write token. Maps HTTP errors to typed `GraphError`s. Like
    /// `scoped_get`, this deliberately skips the retry/throttle loop — these are
    /// one-shot configuration writes, not high-volume reads.
    pub(crate) async fn scoped_send_json<B, T>(
        &self,
        token: &Arc<dyn BearerProvider>,
        method: Method,
        url: &str,
        body: &B,
    ) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let bytes = self
            .scoped_send_core(token, method, url, Some(body))
            .await?;
        serde_json::from_slice(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// Scoped POST/PATCH/DELETE with no decoded response (the `$ref` assignment
    /// and `$ref` removal endpoints return 204).
    pub(crate) async fn scoped_send_no_content<B>(
        &self,
        token: &Arc<dyn BearerProvider>,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<()>
    where
        B: Serialize + ?Sized,
    {
        let _ = self.scoped_send_core(token, method, url, body).await?;
        Ok(())
    }

    /// Shared transport for the scoped (explicit-token) write helpers above.
    pub(crate) async fn scoped_send_core<B>(
        &self,
        token: &Arc<dyn BearerProvider>,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<bytes::Bytes>
    where
        B: Serialize + ?Sized,
    {
        let bearer = token.bearer().await.map_err(GraphError::Token)?;
        let mut req = self
            .http
            .request(method, url)
            .header(AUTHORIZATION, format!("Bearer {bearer}"));
        if let Some(b) = body {
            let value =
                serde_json::to_value(b).map_err(|e| GraphError::Deserialize(e.to_string()))?;
            req = req.json(&value);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| GraphError::Network(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let code = status.as_u16();
            let retry_after = parse_retry_after_seconds(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            let body = resp.text().await.unwrap_or_default();
            return Err(map_error_status(code, body, retry_after));
        }
        resp.bytes()
            .await
            .map_err(|e| GraphError::Network(e.to_string()))
    }

    /// Follows `@odata.nextLink` from an initial page until exhausted,
    /// concatenating every page's items. Collection endpoints that can exceed
    /// Graph's default page size use this so they don't silently truncate.
    ///
    /// Hard-errors past [`MAX_PAGES`], which is the right guard for the
    /// *small* collections that use it (owners, role assignments, grants,
    /// directory reads) — 200 pages there means a cyclic/pathological
    /// `nextLink`, not a real tenant. The tenant-wide index scans that *can*
    /// legitimately be huge use [`Self::collect_all_pages_capped`] instead, so
    /// a large tenant degrades to a truncated list rather than an outright
    /// failure.
    pub(crate) async fn collect_all_pages<T: DeserializeOwned>(
        &self,
        mut page: Paged<T>,
    ) -> Result<Vec<T>> {
        // Bound a pathological/cyclic nextLink; legitimate paging is far under
        // this. (Origin safety is enforced by `get_json_absolute`'s same-origin
        // check.) Mirrors `list_conditional_access_policies`.
        const MAX_PAGES: usize = 200;
        let mut out = Vec::new();
        out.append(&mut page.items);
        let mut pages = 1;
        while let Some(next) = page.next_link.take() {
            if pages >= MAX_PAGES {
                return Err(GraphError::Protocol(
                    "paging exceeded the page limit".into(),
                ));
            }
            page = self.get_json_absolute(&next).await?;
            out.append(&mut page.items);
            pages += 1;
        }
        Ok(out)
    }

    /// Like [`Self::collect_all_pages`] but bounds the result to `max_items`
    /// instead of hard-erroring on a high page count. For the tenant-wide
    /// index scans (service principals), a tenant larger than the bound must
    /// degrade to a truncated-but-usable list: failing the Enterprise Apps
    /// list, the App Registrations pairing join, and global search outright is
    /// strictly worse than returning the first N rows. The cap also bounds a
    /// pathological/cyclic `nextLink` (paging stops once `max_items` is
    /// reached), so this needs no separate page guard. Returns
    /// `(items, truncated)` — `truncated` is `true` when rows existed beyond
    /// the cap, so the caller can log/surface that coverage is partial.
    pub(crate) async fn collect_all_pages_capped<T: DeserializeOwned>(
        &self,
        mut page: Paged<T>,
        max_items: usize,
    ) -> Result<(Vec<T>, bool)> {
        let mut out = Vec::new();
        out.append(&mut page.items);
        while out.len() < max_items {
            let Some(next) = page.next_link.take() else {
                // Exhausted within the cap — full coverage.
                return Ok((out, false));
            };
            page = self.get_json_absolute(&next).await?;
            out.append(&mut page.items);
        }
        // Reached the cap. More rows remain iff we overshot the last page or a
        // further nextLink is still pending.
        let truncated = out.len() > max_items || page.next_link.is_some();
        out.truncate(max_items);
        Ok((out, truncated))
    }

    /// Collects all pages from a scoped FETCH closure, following `@odata.nextLink`
    /// until exhausted or the page cap is hit. Each nextLink is origin-checked
    /// before being passed to `fetch_page`, so the bearer token never leaves the
    /// trusted Graph origin.
    pub(crate) async fn collect_pages_from<F, T, Fut>(
        &self,
        mut first_page: Paged<T>,
        mut fetch_page: F,
    ) -> Result<Vec<T>>
    where
        F: FnMut(String) -> Fut + Send,
        Fut: std::future::Future<Output = Result<Paged<T>>> + Send,
        T: DeserializeOwned + Send,
    {
        const MAX_PAGES: usize = 200;
        let mut out = Vec::new();
        out.append(&mut first_page.items);
        let mut page: Paged<T> = first_page;
        let mut pages = 1usize;
        while let Some(next) = page.next_link.take() {
            if !same_origin(&self.base_url, &next) {
                return Err(GraphError::Protocol(
                    "refusing to follow nextLink to a different origin".into(),
                ));
            }
            if pages >= MAX_PAGES {
                return Err(GraphError::Protocol(
                    "paging exceeded the page limit".into(),
                ));
            }
            page = fetch_page(next).await?;
            out.append(&mut page.items);
            pages += 1;
        }
        Ok(out)
    }

    /// Issues a GET against an absolute URL (e.g. an `@odata.nextLink`) and
    /// decodes the response body. All retry + throttle-observer behavior
    /// applies identically to path-relative requests.
    pub async fn get_json_absolute<T: DeserializeOwned>(&self, url: &str) -> Result<T> {
        // A `nextLink` is attacker-influenced server output; never send the
        // bearer token to a host other than the one we're already talking to.
        if !same_origin(&self.base_url, url) {
            // Surface only the offending host. The full URL is attacker-
            // influenced (a malicious nextLink in a server response) and may
            // contain tokens, paths, or query material we do not want
            // persisted in logs/audit/error UI.
            let host = url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_else(|| "<unparseable>".into());
            return Err(GraphError::Protocol(format!(
                "refusing to follow nextLink to a different origin (host: {host})"
            )));
        }
        // `nextLink` for count/search queries still requires `ConsistencyLevel`
        // so we always attach it — harmless on queries that don't need it.
        let bytes = self
            .send_core_url(Method::GET, url, &[], true, None)
            .await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        consistency_eventual: bool,
    ) -> Result<T> {
        let bytes = self
            .send_core(Method::GET, path, query, consistency_eventual, None)
            .await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// GET the read-token collection with a `Prefer` request header — used by the
    /// whole-gallery fetch to ask for large pages (`odata.maxpagesize=…`) so a
    /// full-collection read is a handful of round trips instead of hundreds. The
    /// effective page size carries into `@odata.nextLink`, so only this first
    /// request needs the header; subsequent pages ride `get_json_absolute`.
    pub(crate) async fn get_json_prefer<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
        prefer: &str,
    ) -> Result<T> {
        let url = format!("{}{path}", self.base_url);
        let bytes = self
            .send_core_url_with(
                &self.read_token,
                Method::GET,
                &url,
                query,
                false,
                None,
                Some(prefer),
            )
            .await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// POST/PATCH with a JSON body, returning a decoded response.
    pub(crate) async fn send_json<B, T>(&self, method: Method, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let value =
            serde_json::to_value(body).map_err(|e| GraphError::Deserialize(e.to_string()))?;
        let bytes = self
            .send_core(method, path, &[], false, Some(value))
            .await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| GraphError::Deserialize(e.to_string()))
    }

    /// POST/PATCH/DELETE with no response body expected (204 No Content or
    /// empty 200). Returns `Ok(())` on any successful status.
    pub(crate) async fn send_no_content<B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<()>
    where
        B: Serialize + ?Sized,
    {
        let value = match body {
            Some(b) => {
                Some(serde_json::to_value(b).map_err(|e| GraphError::Deserialize(e.to_string()))?)
            }
            None => None,
        };
        let _ = self.send_core(method, path, &[], false, value).await?;
        Ok(())
    }

    pub(crate) async fn send_core(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        consistency_eventual: bool,
        body: Option<serde_json::Value>,
    ) -> Result<bytes::Bytes> {
        let url = format!("{}{path}", self.base_url);
        self.send_core_url(method, &url, query, consistency_eventual, body)
            .await
    }

    /// Like [`send_core`] but operates on a pre-assembled absolute URL. Used
    /// to follow `@odata.nextLink`, which arrives fully qualified. GETs are
    /// read-only; everything else mutates — selecting the token by verb keeps the
    /// least-privilege split (read-only sessions never hold write scopes).
    pub(crate) async fn send_core_url(
        &self,
        method: Method,
        url: &str,
        query: &[(&str, &str)],
        consistency_eventual: bool,
        body: Option<serde_json::Value>,
    ) -> Result<bytes::Bytes> {
        let provider = if method == Method::GET {
            &self.read_token
        } else {
            &self.write_token
        };
        self.send_core_url_with(
            provider,
            method,
            url,
            query,
            consistency_eventual,
            body,
            None,
        )
        .await
    }

    /// [`send_core_url`] with an explicit token `provider` — lets a POST that is
    /// semantically a *read* (the `/$batch` endpoint wrapping GET sub-requests)
    /// ride the read token instead of the verb-selected write token. `prefer`,
    /// when set, is sent as the `Prefer` request header (e.g.
    /// `odata.maxpagesize=…` to pull large pages on a whole-collection read).
    // The innermost transport primitive: each argument is an orthogonal HTTP
    // knob (token, verb, url, query, consistency, body, prefer) with no natural
    // grouping, so a params struct would only add indirection.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_core_url_with(
        &self,
        provider: &Arc<dyn BearerProvider>,
        method: Method,
        url: &str,
        query: &[(&str, &str)],
        consistency_eventual: bool,
        body: Option<serde_json::Value>,
        prefer: Option<&str>,
    ) -> Result<bytes::Bytes> {
        // Fetch the token once: it's valid well past the bounded retry window,
        // so re-fetching on every transient retry would just hammer the auth
        // endpoint. A 401 is non-retryable and surfaces to the caller to re-auth.
        let bearer = provider.bearer().await.map_err(GraphError::Token)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| GraphError::Token(e.to_string()))?,
        );
        if consistency_eventual {
            headers.insert(CONSISTENCY_LEVEL, HeaderValue::from_static("eventual"));
        }
        if let Some(prefer) = prefer {
            headers.insert(
                PREFER,
                HeaderValue::from_str(prefer).map_err(|e| GraphError::Protocol(e.to_string()))?,
            );
        }
        if body.is_some() {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }

        let mut attempt = 0u32;
        let mut delay_ms = BASE_DELAY_MS;
        // CAE: set once we've re-minted in response to a claims challenge, so a
        // persistent 401 can't loop (the re-mint is outside the transient budget).
        let mut cae_retried = false;
        loop {
            let mut req = self
                .http
                .request(method.clone(), url)
                .headers(headers.clone())
                .query(query);
            if let Some(v) = body.as_ref() {
                req = req.json(v);
            }
            let resp = req.send().await;
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
                    return Err(GraphError::Network(err.to_string()));
                }
            };

            let status = resp.status();
            if status.is_success() {
                let bytes = resp
                    .bytes()
                    .await
                    .map_err(|e| GraphError::Network(e.to_string()))?;
                return Ok(bytes);
            }

            let retry_after = parse_retry_after_seconds(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            // Capture the CAE challenge header before the body consumes `resp`.
            let www_authenticate = resp
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let body_text = resp
                .text()
                .await
                .unwrap_or_else(|_| "<no body>".to_string());
            let code = status.as_u16();

            // CAE: a 401 carrying an `insufficient_claims` challenge means the
            // resource now requires a fresher token (e.g. after a revocation or
            // policy change). Re-mint once with the challenge and retry — separate
            // from the transient-retry budget. A non-CAE provider can't satisfy it
            // (its `bearer_with_claims` falls back), so the single-retry guard
            // prevents a loop.
            if code == 401 {
                if !cae_retried
                    && let Some(challenge) =
                        www_authenticate.as_deref().and_then(parse_claims_challenge)
                {
                    match provider.bearer_with_claims(&challenge).await {
                        Ok(bearer) => {
                            headers.insert(
                                AUTHORIZATION,
                                HeaderValue::from_str(&format!("Bearer {bearer}"))
                                    .map_err(|e| GraphError::Token(e.to_string()))?,
                            );
                            cae_retried = true;
                            continue;
                        }
                        Err(e) => tracing::info!(
                            detail = %e,
                            "CAE claims challenge could not be satisfied silently; re-auth needed"
                        ),
                    }
                }
                return Err(GraphError::Unauthorized);
            }
            if code == 403 {
                return Err(GraphError::Forbidden(body_text));
            }
            if code == 404 {
                return Err(GraphError::NotFound(body_text));
            }
            if (400..500).contains(&code) && code != 429 {
                return Err(GraphError::Api {
                    status: code,
                    body: body_text,
                });
            }

            // 429 always notifies the observer, whether or not we end up
            // retrying successfully — the signal is about service pressure.
            if code == 429
                && let Some(observer) = self.throttle_observer.read().as_ref()
            {
                observer.on_throttle(retry_after);
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
                Err(GraphError::Throttled {
                    retry_after_secs: retry_after,
                })
            } else {
                Err(GraphError::Server {
                    status: code,
                    body: body_text,
                })
            };
        }
    }
}

/// OData single-quoted-string escape: a `'` inside the literal becomes `''`.
/// Applied to every value we interpolate into a `$filter` string literal —
/// both user-typed prefixes (`startswith(...)`) and IDs echoed from Graph
/// (`appId eq '...'`) — as defense-in-depth, even though IDs are GUIDs in
/// practice. Callers should still trust the Graph schema for non-string types.
pub(crate) fn escape_odata(input: &str) -> String {
    input.replace('\'', "''")
}

/// Builds the quoted `$search` phrase for a display-name term search:
/// `"displayName:<term>"`. Graph's `$search` syntax reserves the double quote
/// as the phrase delimiter with no escape, so any `"` in the user's term is
/// neutralized to a space — pinning that contract here keeps the three
/// name-search call sites from drifting.
pub(crate) fn search_phrase(field: &str, term: &str) -> String {
    format!("\"{field}:{}\"", term.replace('"', " "))
}

/// Builds a Graph-version-root-relative sub-request URL (`/applications/{id}?…`)
/// with percent-encoded query values, for the `$batch` helpers. Mirrors the
/// single-call encoding the SP prewarm (`prewarm_sps`) does inline, so a
/// batched read's URL is byte-identical to its per-item equivalent. `path` is
/// already-escaped (object ids are GUIDs); only the query values are encoded.
pub(crate) fn batch_sub_url(path: &str, query: &[(&str, &str)]) -> String {
    // A throwaway base just to reuse `url`'s query encoder; the host is never
    // emitted — only `path?query` is returned.
    let mut u = url::Url::parse(&format!("https://graph.invalid{path}"))
        .expect("static base + GUID path parses");
    {
        let mut pairs = u.query_pairs_mut();
        for (k, v) in query {
            pairs.append_pair(k, v);
        }
    }
    match u.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

/// Extracts the base64 CAE claims challenge from a `WWW-Authenticate: Bearer …
/// error="insufficient_claims", claims="<base64>"` header. Returns `None` unless
/// the header signals `insufficient_claims` and carries a non-empty `claims`
/// directive, so an ordinary `401` (expired/invalid token) is not mistaken for a
/// Continuous Access Evaluation challenge.
pub(crate) fn parse_claims_challenge(www_authenticate: &str) -> Option<String> {
    if !www_authenticate.contains("insufficient_claims") {
        return None;
    }
    let after = www_authenticate.split("claims=").nth(1)?.trim_start();
    let value = if let Some(rest) = after.strip_prefix('"') {
        // Quoted form: `claims="<base64>"`.
        rest.split('"').next()?
    } else {
        // Bare form: ends at the next comma/space.
        after.split([',', ' ']).next()?
    }
    .trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Maps a non-success status from the one-shot scoped transport
/// ([`GraphClient::scoped_get`] / `scoped_send_core`) to the same typed error
/// the retrying transport returns, so a throttled scoped call surfaces as
/// [`GraphError::Throttled`] (ui code `throttled`, retryable) rather than a
/// generic `Api`. Only the mapping is shared — the one-shot helpers still
/// deliberately skip the retry/throttle loop.
fn map_error_status(code: u16, body: String, retry_after: Option<u64>) -> GraphError {
    match code {
        401 => GraphError::Unauthorized,
        403 => GraphError::Forbidden(body),
        404 => GraphError::NotFound(body),
        429 => GraphError::Throttled {
            retry_after_secs: retry_after,
        },
        c if c >= 500 => GraphError::Server { status: c, body },
        _ => GraphError::Api { status: code, body },
    }
}
