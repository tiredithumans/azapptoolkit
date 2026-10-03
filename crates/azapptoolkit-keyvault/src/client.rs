//! Thin HTTP client over Key Vault's REST surface.
//!
//! Retry budget, backoff, jitter and `Retry-After` come from the shared
//! [`azapptoolkit_core::http_retry::with_retries`] loop (the same one Graph,
//! ARM and Exchange run); the per-attempt status → [`KeyVaultError`] mapping
//! is [`azapptoolkit_core::http_error::failed_response`], as in ARM. Only
//! each verb's [`RetryClass`] (`retry_class_for`, with its `set_secret` PUT
//! decision) is local.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;

use azapptoolkit_core::http_error::{describe_error_chain, failed_response, send_failure};
use azapptoolkit_core::http_retry::{Attempt, RetryClass, parse_retry_after_seconds, with_retries};
use azapptoolkit_core::net::{endpoint_family, redacted_host, same_origin};
use azapptoolkit_core::token::{BearerProvider, TokenError};

use crate::error::{KeyVaultError, Result};
use crate::models::{Paged, SecretItem, SecretSetRequest, SecretValue};

/// Key Vault **data-plane** api-version (`{vault}.vault.azure.net/secrets`).
/// The announced api-version retirement (every version before 2026-02-01 on
/// 2027-02-27) covers the control plane only; stable data-plane versions are
/// explicitly unaffected. Source:
/// <https://learn.microsoft.com/rest/api/keyvault/secrets/get-secret/get-secret>,
/// <https://learn.microsoft.com/azure/key-vault/general/migrate-api-version>
/// (reviewed 2026-09).
pub const DEFAULT_API_VERSION: &str = "7.4";

/// Defensive bound on `nextLink` paging: a self-referencing link must not
/// page forever (far above any real vault).
const MAX_PAGES: usize = 1000;

pub struct KeyVaultClient {
    http: reqwest::Client,
    token: Arc<dyn BearerProvider>,
    /// Full base URL: `https://{vault-name}.vault.azure.net`.
    base_url: String,
    api_version: String,
}

impl KeyVaultClient {
    pub fn new(token: Arc<dyn BearerProvider>, vault_name: &str) -> Result<Self> {
        Self::new_with_dns_suffix(token, vault_name, "vault.azure.net")
    }

    /// Like [`Self::new`] but with a sovereign-cloud Key Vault DNS suffix
    /// (e.g. `vault.usgovcloudapi.net` for US Gov, `vault.azure.cn` for China).
    pub fn new_with_dns_suffix(
        token: Arc<dyn BearerProvider>,
        vault_name: &str,
        dns_suffix: &str,
    ) -> Result<Self> {
        crate::validate::validate_vault_name(vault_name)?;
        let base_url = format!("https://{vault_name}.{dns_suffix}");
        Ok(Self::with_base_url(token, base_url))
    }

    pub fn with_base_url(token: Arc<dyn BearerProvider>, base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("azapptoolkit/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(60))
            .connect_timeout(azapptoolkit_core::http_retry::CONNECT_TIMEOUT)
            .build()
            .expect("reqwest client builds");
        Self {
            http,
            token,
            base_url: base_url.into(),
            api_version: DEFAULT_API_VERSION.to_string(),
        }
    }

    pub fn with_api_version(mut self, version: impl Into<String>) -> Self {
        self.api_version = version.into();
        self
    }

    pub async fn list_secrets(&self) -> Result<Vec<SecretItem>> {
        let path = "/secrets".to_string();
        let mut paged: Paged<SecretItem> = self.get_json(&path).await?;
        let mut out = paged.value;
        let mut pages = 1usize;
        while let Some(link) = paged.next_link.take() {
            if pages >= MAX_PAGES {
                return Err(KeyVaultError::Protocol(format!(
                    "secret listing exceeded {MAX_PAGES} pages; aborting"
                )));
            }
            paged = self.get_json_absolute(&link).await?;
            out.extend(paged.value);
            pages += 1;
        }
        Ok(out)
    }

    pub async fn get_secret(&self, name: &str, version: Option<&str>) -> Result<SecretValue> {
        crate::validate::validate_secret_name(name)?;
        let path = match version {
            Some(v) => {
                // The version is a path segment too: validated like the name.
                crate::validate::validate_secret_version(v)?;
                format!("/secrets/{name}/{v}")
            }
            None => format!("/secrets/{name}"),
        };
        self.get_json(&path).await
    }

    pub async fn set_secret(&self, name: &str, req: &SecretSetRequest) -> Result<SecretValue> {
        crate::validate::validate_secret_name(name)?;
        let path = format!("/secrets/{name}");
        self.send_json(Method::PUT, &path, req).await
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let bytes = self.send_core(Method::GET, path, None).await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| KeyVaultError::Deserialize(e.to_string()))
    }

    async fn get_json_absolute<T: DeserializeOwned>(&self, absolute_url: &str) -> Result<T> {
        let bytes = self.send_core_absolute(Method::GET, absolute_url).await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| KeyVaultError::Deserialize(e.to_string()))
    }

    async fn send_json<B, T>(&self, method: Method, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized + Sync,
        T: DeserializeOwned,
    {
        let value =
            serde_json::to_value(body).map_err(|e| KeyVaultError::Deserialize(e.to_string()))?;
        let bytes = self.send_core(method, path, Some(value)).await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| KeyVaultError::Deserialize(e.to_string()))
    }

    /// Path-relative request: always appends the `api-version` query (only the
    /// absolute `nextLink` path skips it — a link already carries its own).
    async fn send_core(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<bytes::Bytes> {
        let url = format!("{}{}", self.base_url, path);
        self.send_core_url(method, &url, true, body, false).await
    }

    /// Unified transport for path-relative and absolute (`nextLink`) requests:
    /// one retry + jitter + `Retry-After` loop mapping each HTTP status →
    /// typed `KeyVaultError` through the shared `failed_response`.
    /// `check_origin` rejects an off-vault URL before the bearer is attached
    /// (a `nextLink` is attacker-influenced server output);
    /// `attach_api_version` skips the `api-version` query that a `nextLink`
    /// already carries.
    async fn send_core_url(
        &self,
        method: Method,
        url: &str,
        attach_api_version: bool,
        body: Option<serde_json::Value>,
        check_origin: bool,
    ) -> Result<bytes::Bytes> {
        if check_origin && !same_origin(&self.base_url, url) {
            return Err(KeyVaultError::Protocol(format!(
                "refusing to follow nextLink to a different origin (host: {})",
                redacted_host(url)
            )));
        }
        let api_version = attach_api_version.then_some(self.api_version.as_str());
        let mut headers = HeaderMap::new();
        let bearer = self.token.bearer().await.map_err(KeyVaultError::Token)?;
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| KeyVaultError::Token(TokenError::opaque(e.to_string())))?,
        );
        if body.is_some() {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }

        // Retry budget, backoff and `Retry-After` live in
        // `http_retry::with_retries`; this closure only classifies one attempt.
        // The label names verb + endpoint family (ids masked, no query).
        let label = format!("key vault {method} {}", endpoint_family(url));
        with_retries(&label, retry_class_for(&method), |_| {
            let http = self.http.clone();
            let headers = headers.clone();
            let method = method.clone();
            let body = body.clone();
            async move {
                let mut req = http.request(method, url).headers(headers);
                if let Some(v) = api_version {
                    req = req.query(&[("api-version", v)]);
                }
                if let Some(ref b) = body {
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
                            .map_err(|e| KeyVaultError::Network(describe_error_chain(&e))),
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

    /// GET against an absolute URL (a `nextLink`): the link already carries
    /// its own `api-version`, so none is appended; its origin is checked
    /// before the bearer is attached.
    async fn send_core_absolute(&self, method: Method, url: &str) -> Result<bytes::Bytes> {
        self.send_core_url(method, url, false, None, true).await
    }
}

/// The retry class for an HTTP verb.
///
/// `GET`/`HEAD`/`DELETE` are idempotent. `PUT` is replayed as a decision, not
/// a definition: `PUT /secrets/{name}` ([`KeyVaultClient::set_secret`])
/// appends a new version per call, so a replay after a post-commit 5xx or
/// connection reset leaves a second version — but the replay carries the
/// identical value, so the current version is still the right secret; the
/// cost is one duplicate same-value version. Refusing would be worse:
/// `rotate_app_credential` rolls back the freshly minted app secret when this
/// write fails, so a post-commit transient would leave the vault holding a
/// credential Entra no longer accepts. `POST`/`PATCH` replay only an explicit
/// throttle (the `addPassword` hazard documented on
/// `azapptoolkit_core::http_retry::RetryClass`).
fn retry_class_for(method: &Method) -> RetryClass {
    match *method {
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE => RetryClass::Idempotent,
        _ => RetryClass::NonIdempotent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SecretAttributesRequest;
    use azapptoolkit_core::token::StaticTokenProvider;
    use chrono::{TimeZone, Utc};
    use wiremock::matchers::{
        body_json, header, method, path, query_param, query_param_is_missing,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_client(base: &str) -> KeyVaultClient {
        KeyVaultClient::with_base_url(StaticTokenProvider::new("tok"), base.to_string())
    }

    #[tokio::test]
    async fn list_secrets_returns_items() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", DEFAULT_API_VERSION))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "https://v.vault.azure.net/secrets/one",
                    "managed": true
                }, {
                    "id": "https://v.vault.azure.net/secrets/two"
                }]
            })))
            .mount(&server)
            .await;
        let c = make_client(&server.uri());
        let items = c.list_secrets().await.unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name(), Some("one"));
        // The certificate-backed marker must survive the wire read.
        assert_eq!(items[0].managed, Some(true));
        assert_eq!(items[1].managed, None);
    }

    #[tokio::test]
    async fn set_secret_puts_value() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/secrets/my-secret"))
            .and(query_param("api-version", DEFAULT_API_VERSION))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "value": "p@ssw0rd"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": "p@ssw0rd",
                "id": "https://v.vault.azure.net/secrets/my-secret/abc"
            })))
            .mount(&server)
            .await;
        let c = make_client(&server.uri());
        let resp = c
            .set_secret(
                "my-secret",
                &SecretSetRequest {
                    value: "p@ssw0rd".into(),
                    content_type: None,
                    tags: None,
                    attributes: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(resp.value, "p@ssw0rd");
    }

    #[tokio::test]
    async fn get_secret_reads_value() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets/my-secret"))
            .and(query_param("api-version", DEFAULT_API_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": "hello",
                "id": "https://v.vault.azure.net/secrets/my-secret/abc"
            })))
            .mount(&server)
            .await;
        let c = make_client(&server.uri());
        let sv = c.get_secret("my-secret", None).await.unwrap();
        assert_eq!(sv.value, "hello");
    }

    #[tokio::test]
    async fn retries_on_429() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets/foo"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "0")
                    .set_body_string("throttled"),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/secrets/foo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": "ok",
                "id": "https://v.vault.azure.net/secrets/foo/1"
            })))
            .mount(&server)
            .await;
        let c = make_client(&server.uri());
        let sv = c.get_secret("foo", None).await.unwrap();
        assert_eq!(sv.value, "ok");
    }

    #[tokio::test]
    async fn unauthorized_surfaces_typed_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets/foo"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let c = make_client(&server.uri());
        let err = c.get_secret("foo", None).await.unwrap_err();
        assert!(matches!(err, KeyVaultError::Unauthorized));
    }

    /// Key Vault's `nextLink` already carries `api-version`; following it must
    /// not append a second one (a duplicated query parameter is rejected).
    #[tokio::test]
    async fn list_secrets_follows_next_link_without_doubling_api_version() {
        let server = MockServer::start().await;
        let uri = server.uri();
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("api-version", DEFAULT_API_VERSION))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "https://v.vault.azure.net/secrets/one"},
                    {"id": "https://v.vault.azure.net/secrets/two"}
                ],
                "nextLink": format!("{uri}/secrets?$skiptoken=p2&api-version={DEFAULT_API_VERSION}")
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .and(query_param("$skiptoken", "p2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{"id": "https://v.vault.azure.net/secrets/three"}]
            })))
            .mount(&server)
            .await;

        let items = make_client(&uri).list_secrets().await.unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[2].name(), Some("three"));
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2);
        let api_versions = reqs[1]
            .url
            .query_pairs()
            .filter(|(k, _)| k == "api-version")
            .count();
        assert_eq!(api_versions, 1, "follow URL: {}", reqs[1].url);
    }

    /// A `nextLink` is attacker-influenced server output: the vault bearer
    /// must never follow it to another origin.
    #[tokio::test]
    async fn refuses_off_origin_next_link() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{"id": "https://v.vault.azure.net/secrets/one"}],
                "nextLink": "https://evil.example.com/secrets?token=steal"
            })))
            .mount(&server)
            .await;

        let err = make_client(&server.uri()).list_secrets().await.unwrap_err();
        assert!(matches!(err, KeyVaultError::Protocol(_)), "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("evil.example.com"), "got {msg}");
        assert!(!msg.contains("token=steal"), "leaked query: {msg}");
        // Only the first page was requested; nothing was sent off-origin.
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// The rotation write (`rotate_app_credential`) mirrors the app secret's
    /// expiry into the vault: `exp` must be Unix seconds under `attributes`.
    #[tokio::test]
    async fn set_secret_sends_exp_as_unix_seconds_under_attributes() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/secrets/rotated"))
            .and(query_param("api-version", DEFAULT_API_VERSION))
            // 2026-01-01T00:00:00Z in seconds — not milliseconds, not RFC 3339.
            .and(body_json(serde_json::json!({
                "value": "v",
                "attributes": {"enabled": true, "exp": 1767225600}
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": "v",
                "id": "https://v.vault.azure.net/secrets/rotated/1"
            })))
            .mount(&server)
            .await;
        let req = SecretSetRequest {
            value: "v".into(),
            content_type: None,
            tags: None,
            attributes: Some(SecretAttributesRequest {
                enabled: Some(true),
                expires: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
                not_before: None,
            }),
        };
        let resp = make_client(&server.uri())
            .set_secret("rotated", &req)
            .await
            .unwrap();
        assert_eq!(resp.value, "v");
    }

    /// A self-referencing `nextLink` stops at `MAX_PAGES` instead of paging forever.
    #[tokio::test]
    async fn list_secrets_stops_at_the_page_cap() {
        let server = MockServer::start().await;
        let uri = server.uri();
        Mock::given(method("GET"))
            .and(path("/secrets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [],
                "nextLink": format!("{uri}/secrets")
            })))
            .mount(&server)
            .await;

        let err = make_client(&uri).list_secrets().await.unwrap_err();
        assert!(
            matches!(&err, KeyVaultError::Protocol(m) if m.contains("exceeded")),
            "got {err:?}"
        );
        // The first page plus MAX_PAGES - 1 follows: the cap is checked before
        // the MAX_PAGES-th follow is sent.
        assert_eq!(server.received_requests().await.unwrap().len(), MAX_PAGES);
    }

    #[test]
    fn retry_class_for_replays_put_but_not_post_or_patch() {
        for m in [Method::GET, Method::HEAD, Method::PUT, Method::DELETE] {
            assert_eq!(retry_class_for(&m), RetryClass::Idempotent, "{m}");
        }
        for m in [Method::POST, Method::PATCH] {
            assert_eq!(retry_class_for(&m), RetryClass::NonIdempotent, "{m}");
        }
    }

    /// The deliberate `PUT` replay (see `retry_class_for`): a 502 after the
    /// write is replayed with a byte-identical body, so any duplicate version
    /// holds the same value.
    #[tokio::test]
    async fn set_secret_replays_the_identical_value_after_a_502() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/secrets/s"))
            .respond_with(ResponseTemplate::new(502).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/secrets/s"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": "v",
                "id": "https://v.vault.azure.net/secrets/s/1"
            })))
            .mount(&server)
            .await;
        let req = SecretSetRequest {
            value: "v".into(),
            content_type: None,
            tags: None,
            attributes: None,
        };
        make_client(&server.uri())
            .set_secret("s", &req)
            .await
            .unwrap();
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().all(|r| r.method == wiremock::http::Method::PUT));
        assert_eq!(reqs[0].body, reqs[1].body);
    }

    #[tokio::test]
    async fn get_secret_reads_a_specific_version() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/secrets/my-secret/0123456789abcdef0123456789abcdef"))
            .and(query_param("api-version", DEFAULT_API_VERSION))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": "older",
                "id": "https://v.vault.azure.net/secrets/my-secret/0123456789abcdef0123456789abcdef"
            })))
            .mount(&server)
            .await;
        let sv = make_client(&server.uri())
            .get_secret("my-secret", Some("0123456789abcdef0123456789abcdef"))
            .await
            .unwrap();
        assert_eq!(sv.value, "older");
    }

    /// `version` is spliced into the request path, so a traversal value is
    /// refused before any request (and bearer) leaves the process.
    #[tokio::test]
    async fn get_secret_refuses_a_malformed_version_before_any_request() {
        let server = MockServer::start().await;
        let err = make_client(&server.uri())
            .get_secret("my-secret", Some("../keys/x"))
            .await
            .unwrap_err();
        assert!(matches!(err, KeyVaultError::InvalidName(_)), "got {err:?}");
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}
