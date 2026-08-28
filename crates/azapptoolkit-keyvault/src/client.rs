//! Thin HTTP client over Key Vault's REST surface.
//!
//! Every request runs through the same retry + jitter pattern as
//! [`azapptoolkit_graph::client`]; parity with the PS `Retry-Utility` is the
//! point. We don't share code across crates (the Graph retry is tied to
//! `GraphError`), but the knobs match.

use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;

use azapptoolkit_core::http_retry::{
    Attempt, RetryClass, RetryReason, parse_retry_after_seconds, with_retries,
};
use azapptoolkit_core::net::{redacted_host, same_origin};
use azapptoolkit_core::token::{BearerProvider, TokenError};

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
        // Defensive bound: a misbehaving server returning a self-referencing
        // `nextLink` must not page forever (far above any real vault).
        const MAX_PAGES: usize = 1000;
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
            Some(v) => format!("/secrets/{name}/{v}"),
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
        B: Serialize + ?Sized,
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

        // Retry budget, backoff and `Retry-After` handling live in
        // `http_retry::with_retries`; this closure only classifies one attempt.
        with_retries("key vault", retry_class_for(&method), |_| {
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
                    // No response means no `Retry-After` to honor — the shared
                    // loop falls back to jittered exponential backoff.
                    Err(err) => {
                        return Attempt::Retry {
                            reason: RetryReason::Transient,
                            retry_after_secs: None,
                            err: KeyVaultError::Network(err.to_string()),
                        };
                    }
                };
                let status = resp.status();
                if status.is_success() {
                    return Attempt::Done(
                        resp.bytes()
                            .await
                            .map_err(|e| KeyVaultError::Network(e.to_string())),
                    );
                }
                let retry_after = parse_retry_after_seconds(
                    resp.headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|v| v.to_str().ok()),
                );
                let body_text = resp.text().await.unwrap_or_default();
                let code = status.as_u16();

                let terminal = match code {
                    401 => Some(KeyVaultError::Unauthorized),
                    403 => Some(KeyVaultError::Forbidden(body_text.clone())),
                    404 => Some(KeyVaultError::NotFound(body_text.clone())),
                    c if (400..500).contains(&c) && c != 429 => Some(KeyVaultError::Api {
                        status: code,
                        body: body_text.clone(),
                    }),
                    _ => None,
                };
                if let Some(err) = terminal {
                    return Attempt::Done(Err(err));
                }

                Attempt::Retry {
                    reason: if code == 429 {
                        RetryReason::Throttled
                    } else {
                        RetryReason::Transient
                    },
                    retry_after_secs: retry_after,
                    err: if code == 429 {
                        KeyVaultError::Throttled {
                            retry_after_secs: retry_after,
                        }
                    } else {
                        KeyVaultError::Server {
                            status: code,
                            body: body_text,
                        }
                    },
                }
            }
        })
        .await
    }

    /// GET against an absolute URL (a `nextLink`). The link already carries its
    /// own `api-version` query, so we don't append one; its origin is checked
    /// before the bearer is attached.
    async fn send_core_absolute(&self, method: Method, url: &str) -> Result<bytes::Bytes> {
        self.send_core_url(method, url, false, None, true).await
    }
}

/// The retry class for an HTTP verb.
///
/// `GET`/`HEAD`/`PUT`/`DELETE` are idempotent by definition, so replaying one
/// whose outcome is unknown is safe. `POST`/`PATCH` may have already committed
/// — a Key Vault `setSecret` replayed after a 502 writes a second version — so
/// only an explicit throttle is replayed for them.
fn retry_class_for(method: &Method) -> RetryClass {
    match *method {
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE => RetryClass::Idempotent,
        _ => RetryClass::NonIdempotent,
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
}
