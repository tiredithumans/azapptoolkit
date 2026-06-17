//! Thin HTTP client over Key Vault's REST surface.
//!
//! Every request runs through the same retry + jitter pattern as
//! [`azapptoolkit_graph::client`]; parity with the PS `Retry-Utility` is the
//! point. We don't share code across crates (the Graph retry is tied to
//! `GraphError`), but the knobs match.

use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

use azapptoolkit_core::http_retry::{
    next_backoff_ms, parse_retry_after_seconds, sleep_before_retry, sleep_with_jitter,
    BASE_DELAY_MS, MAX_RETRIES,
};
use azapptoolkit_core::token::BearerProvider;

use crate::error::{KeyVaultError, Result};
use crate::models::{Paged, SecretItem, SecretSetRequest, SecretValue};

pub const DEFAULT_API_VERSION: &str = "7.4";

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

    /// Like [`Self::new`] but with a sovereign-cloud Key Vault DNS suffix (e.g.
    /// `vault.usgovcloudapi.net` for US Gov, `vault.azure.cn` for China). The
    /// vault URL is `https://{vault-name}.{dns_suffix}`.
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
        let mut out: Vec<SecretItem> = Vec::new();
        let mut first: Paged<SecretItem> = self.get_json(&path, true).await?;
        out.append(&mut first.value);
        let mut next = first.next_link;
        while let Some(link) = next.take() {
            let page: Paged<SecretItem> = self.get_json_absolute(&link).await?;
            out.extend(page.value);
            next = page.next_link;
        }
        Ok(out)
    }

    pub async fn get_secret(&self, name: &str, version: Option<&str>) -> Result<SecretValue> {
        crate::validate::validate_secret_name(name)?;
        let path = match version {
            Some(v) => format!("/secrets/{name}/{v}"),
            None => format!("/secrets/{name}"),
        };
        self.get_json(&path, true).await
    }

    pub async fn set_secret(&self, name: &str, req: &SecretSetRequest) -> Result<SecretValue> {
        crate::validate::validate_secret_name(name)?;
        let path = format!("/secrets/{name}");
        self.send_json(Method::PUT, &path, req).await
    }

    pub async fn delete_secret(&self, name: &str) -> Result<()> {
        crate::validate::validate_secret_name(name)?;
        let path = format!("/secrets/{name}");
        let _ = self.send_core(Method::DELETE, &path, true, None).await?;
        Ok(())
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        attach_api_version: bool,
    ) -> Result<T> {
        let bytes = self
            .send_core(Method::GET, path, attach_api_version, None)
            .await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| KeyVaultError::Deserialize(e.to_string()))
    }

    async fn get_json_absolute<T: DeserializeOwned>(&self, absolute_url: &str) -> Result<T> {
        let bytes = self.send_core_absolute(Method::GET, absolute_url).await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| KeyVaultError::Deserialize(e.to_string()))
    }

    async fn send_json<B, T>(&self, method: Method, path: &str, body: &B) -> Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let value =
            serde_json::to_value(body).map_err(|e| KeyVaultError::Deserialize(e.to_string()))?;
        let bytes = self.send_core(method, path, true, Some(value)).await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| KeyVaultError::Deserialize(e.to_string()))
    }

    async fn send_core(
        &self,
        method: Method,
        path: &str,
        attach_api_version: bool,
        body: Option<serde_json::Value>,
    ) -> Result<bytes::Bytes> {
        let url = format!("{}{}", self.base_url, path);
        self.send_core_url(method, &url, attach_api_version, body, false)
            .await
    }

    /// Unified transport for both path-relative and absolute (`nextLink`)
    /// requests: one retry + jitter + `Retry-After` loop mapping HTTP status →
    /// typed `KeyVaultError`. `check_origin` rejects an off-vault URL before the
    /// bearer is attached (a `nextLink` is attacker-influenced server output);
    /// `attach_api_version` appends the `api-version` query, which a `nextLink`
    /// already carries and so is skipped for it.
    async fn send_core_url(
        &self,
        method: Method,
        url: &str,
        attach_api_version: bool,
        body: Option<serde_json::Value>,
        check_origin: bool,
    ) -> Result<bytes::Bytes> {
        if check_origin && !same_origin(&self.base_url, url) {
            // Surface only the offending host. The full URL is attacker-
            // influenced (a malicious nextLink in a server response) and may
            // contain tokens, paths, or query material we do not want
            // persisted in logs/audit/error UI.
            let host = url::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .unwrap_or_else(|| "<unparseable>".into());
            return Err(KeyVaultError::Protocol(format!(
                "refusing to follow nextLink to a different origin (host: {host})"
            )));
        }
        let api_version = attach_api_version.then_some(self.api_version.as_str());
        let mut headers = HeaderMap::new();
        let bearer = self.token.bearer().await.map_err(KeyVaultError::Token)?;
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| KeyVaultError::Token(e.to_string()))?,
        );
        if body.is_some() {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        }

        let mut attempt = 0u32;
        let mut delay_ms = BASE_DELAY_MS;
        loop {
            let mut req = self
                .http
                .request(method.clone(), url)
                .headers(headers.clone());
            if let Some(v) = api_version {
                req = req.query(&[("api-version", v)]);
            }
            if let Some(ref b) = body {
                req = req.json(b);
            }
            let resp = match req.send().await {
                Ok(r) => r,
                Err(err) => {
                    if attempt < MAX_RETRIES {
                        tracing::warn!(%attempt, ?err, "kv transport error; retrying");
                        sleep_with_jitter(delay_ms).await;
                        attempt += 1;
                        delay_ms = next_backoff_ms(delay_ms);
                        continue;
                    }
                    return Err(KeyVaultError::Network(err.to_string()));
                }
            };
            let status = resp.status();
            if status.is_success() {
                return resp
                    .bytes()
                    .await
                    .map_err(|e| KeyVaultError::Network(e.to_string()));
            }
            let retry_after = parse_retry_after_seconds(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            let body_text = resp.text().await.unwrap_or_default();
            let code = status.as_u16();

            if code == 401 {
                return Err(KeyVaultError::Unauthorized);
            }
            if code == 403 {
                return Err(KeyVaultError::Forbidden(body_text));
            }
            if code == 404 {
                return Err(KeyVaultError::NotFound(body_text));
            }
            if (400..500).contains(&code) && code != 429 {
                return Err(KeyVaultError::Api {
                    status: code,
                    body: body_text,
                });
            }

            if attempt < MAX_RETRIES {
                // Honor an explicit `Retry-After` exactly; back off only when absent.
                tracing::warn!(%attempt, status = %status, retry_after_secs = ?retry_after, "kv transient; retrying");
                sleep_before_retry(retry_after, delay_ms).await;
                attempt += 1;
                delay_ms = next_backoff_ms(delay_ms);
                continue;
            }
            return if code == 429 {
                Err(KeyVaultError::Throttled {
                    retry_after_secs: retry_after,
                })
            } else {
                Err(KeyVaultError::Server {
                    status: code,
                    body: body_text,
                })
            };
        }
    }

    /// GET against an absolute URL (a `nextLink`). The link already carries its
    /// own `api-version` query, so we don't append one; its origin is checked
    /// before the bearer is attached.
    async fn send_core_absolute(&self, method: Method, url: &str) -> Result<bytes::Bytes> {
        self.send_core_url(method, url, false, None, true).await
    }
}

/// True when `candidate` has the same scheme/host/port as `base`. Used to
/// reject `nextLink` values that point off this vault's origin before the
/// bearer token is attached.
fn same_origin(base: &str, candidate: &str) -> bool {
    match (url::Url::parse(base), url::Url::parse(candidate)) {
        (Ok(b), Ok(c)) => b.origin() == c.origin(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{header, method, path, query_param};
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
                    "id": "https://v.vault.azure.net/secrets/one"
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
                    ..Default::default()
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
}
