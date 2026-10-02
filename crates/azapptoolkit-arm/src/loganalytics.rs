//! Azure Monitor Logs query client (data plane).
//!
//! Distinct from [`crate::ArmClient`] — the query API lives at its own host
//! (`https://api.loganalytics.azure.com`, sovereign variants via
//! `CloudEnvironment::log_analytics_resource`) and its own token audience, so
//! it takes its own [`BearerProvider`]. Used to read `MicrosoftGraphActivityLogs`
//! for the granted-vs-used permission analysis; kept in this crate because it
//! shares the ARM crate's error/retry stack and the workspaces it queries are
//! discovered through [`crate::ArmClient::list_log_analytics_workspaces`].

use std::sync::Arc;
use std::time::Duration;

use azapptoolkit_core::http_error::sanitize_error_body;
use azapptoolkit_core::token::BearerProvider;

use crate::error::{ArmError, Result};
use crate::models::{LogsQueryResponse, LogsQueryTable};

pub struct LogAnalyticsClient {
    http: reqwest::Client,
    token: Arc<dyn BearerProvider>,
    base_url: String,
}

impl LogAnalyticsClient {
    pub fn new(token: Arc<dyn BearerProvider>, base_url: impl Into<String>) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("azapptoolkit/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(120))
            .connect_timeout(azapptoolkit_core::http_retry::CONNECT_TIMEOUT)
            .build()
            .expect("reqwest client builds");
        Self {
            http,
            token,
            base_url: base_url.into(),
        }
    }

    /// Runs `kql` against the workspace identified by `workspace_customer_id`
    /// (the workspace GUID, not the ARM resource id) over an ISO-8601 `timespan`
    /// (e.g. `P90D`), returning the first result table. A workspace that doesn't
    /// contain a referenced table answers 400 (semantic error) — surfaced as
    /// [`ArmError::Api`] so callers probing for table presence can treat it as
    /// "not here" rather than a hard failure. A 200 that carries an `error`
    /// object (Log Analytics' `PartialError`: the query hit a limit and the
    /// rows are incomplete) is refused as [`ArmError::Protocol`] — the Kusto
    /// guidance is to ignore the entire result rather than read a truncated
    /// one as complete.
    ///
    /// `workspace_customer_id` comes out of an ARM workspace listing and is
    /// spliced into the path, so anything but a GUID is refused as
    /// [`ArmError::Protocol`] before a request is sent — a `?` would override
    /// the `timespan`, a `..` walk the path (see `crate::validate`).
    pub async fn query(
        &self,
        workspace_customer_id: &str,
        kql: &str,
        timespan: &str,
    ) -> Result<LogsQueryTable> {
        crate::validate::require_guid("workspace id", workspace_customer_id)?;
        let url = format!(
            "{}/v1/workspaces/{workspace_customer_id}/query",
            self.base_url
        );
        let body = serde_json::json!({ "query": kql, "timespan": timespan });

        let bytes = crate::transport::send_with_retry(
            &self.http,
            &self.token,
            "log analytics",
            reqwest::Method::POST,
            &url,
            &[],
            Some(&body),
        )
        .await?;
        let parsed: LogsQueryResponse =
            serde_json::from_slice(&bytes).map_err(|e| ArmError::Deserialize(e.to_string()))?;
        // Any present `error` means the rows are partial — don't match on the
        // literal "PartialError", a differently-coded warning is no safer.
        if let Some(e) = parsed.error {
            return Err(ArmError::Protocol(format!(
                "Log Analytics returned a partial result ({}): {}. The result was discarded \
                 because incomplete rows would undercount the app's calls; retry later.",
                sanitize_error_body(&e.code),
                sanitize_error_body(&e.message),
            )));
        }
        parsed
            .tables
            .into_iter()
            .next()
            .ok_or_else(|| ArmError::Deserialize("response carried no tables".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(base: &str) -> LogAnalyticsClient {
        LogAnalyticsClient::new(StaticTokenProvider::new("tok"), base.to_string())
    }

    /// A workspace `customerId` is a GUID; anything else is refused unsent.
    const WS: &str = "6f1c2a4e-0000-4000-8000-00000000abcd";

    #[tokio::test]
    async fn query_returns_first_table() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/workspaces/{WS}/query")))
            // The KQL and ISO-8601 timespan ride the request body.
            .and(body_partial_json(serde_json::json!({
                "query": "AppEvents | take 1",
                "timespan": "P90D"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tables": [
                    {
                        "name": "PrimaryResult",
                        "columns": [{"name": "AppId"}],
                        "rows": [["app-1"]]
                    },
                    {"name": "SecondResult", "columns": [], "rows": []}
                ]
            })))
            .mount(&server)
            .await;

        let table = client(&server.uri())
            .query(WS, "AppEvents | take 1", "P90D")
            .await
            .expect("query returns the first table");
        assert_eq!(table.name, "PrimaryResult");
        assert_eq!(table.column_index("AppId"), Some(0));
        assert_eq!(table.rows, vec![vec![serde_json::json!("app-1")]]);
    }

    #[tokio::test]
    async fn query_with_a_partial_error_is_refused() {
        // Log Analytics signals a runaway / truncated query with 200 + tables +
        // an `error` object; the rows are incomplete and must not be read as a
        // complete usage picture.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/workspaces/{WS}/query")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tables": [{
                    "name": "PrimaryResult",
                    "columns": [{"name": "AppId"}],
                    "rows": [["app-1"]]
                }],
                "error": {
                    "code": "PartialError",
                    "message": "Query result set has exceeded the internal data size limit",
                    "details": []
                }
            })))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .query(WS, "AppEvents", "P90D")
            .await
            .unwrap_err();
        let ArmError::Protocol(ref msg) = err else {
            panic!("expected a protocol error, got {err:?}");
        };
        assert!(msg.contains("PartialError"), "names the code: {msg}");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn query_with_a_null_error_returns_the_table() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/workspaces/{WS}/query")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "tables": [{"name": "PrimaryResult", "columns": [], "rows": []}],
                "error": null
            })))
            .mount(&server)
            .await;

        let table = client(&server.uri())
            .query(WS, "AppEvents", "P1D")
            .await
            .expect("a null error is a complete result");
        assert_eq!(table.name, "PrimaryResult");
    }

    #[tokio::test]
    async fn query_without_tables_is_deserialize_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/workspaces/{WS}/query")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "tables": [] })),
            )
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .query(WS, "AppEvents", "P1D")
            .await
            .unwrap_err();
        assert!(matches!(err, ArmError::Deserialize(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn query_400_maps_to_terminal_api_probe_miss() {
        // A workspace that doesn't contain a referenced table answers 400; the
        // caller relies on this surfacing as a terminal `Api` (not retried, not
        // a hard failure) so it can treat "table absent" as a probe miss.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/workspaces/{WS}/query")))
            .respond_with(
                ResponseTemplate::new(400).set_body_string("SemanticError: table not found"),
            )
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .query(WS, "MissingTable", "P1D")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ArmError::Api { status: 400, .. }),
            "got {err:?}"
        );
        assert!(!err.is_retryable());
    }

    /// A failed send names its cause, not just "error sending request for url
    /// (…)" — reqwest's Display stops there and drops the source chain that
    /// says DNS, connect, TLS or proxy. A refused local port is the one cause a
    /// test can produce without a network; the query is a POST, so there is a
    /// single attempt and no real backoff to wait out.
    #[tokio::test]
    async fn a_network_failure_keeps_its_cause() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().expect("addr").port()
        };
        let err = client(&format!("http://127.0.0.1:{port}"))
            .query(WS, "AppEvents | take 1", "P1D")
            .await
            .unwrap_err();
        let ArmError::Network(message) = err else {
            panic!("expected a network error, got {err:?}");
        };
        assert!(
            message.contains("error sending request"),
            "the outer error is kept: {message}"
        );
        assert!(
            message.to_ascii_lowercase().contains("connect"),
            "the cause chain must survive into the message: {message}"
        );
    }

    /// An error page is capped before it reaches the error (and so the log and
    /// the toast) — a proxy block page can be megabytes of HTML.
    #[tokio::test]
    async fn an_error_body_is_sanitized_and_capped() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!("/v1/workspaces/{WS}/query")))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(format!("  <html>\0{}</html>  ", "x".repeat(5_000))),
            )
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .query(WS, "MissingTable", "P1D")
            .await
            .unwrap_err();
        let ArmError::Api { status: 400, body } = err else {
            panic!("expected a terminal Api error, got {err:?}");
        };
        assert!(body.starts_with("<html>x"), "NUL stripped, trimmed: {body}");
        assert_eq!(
            body.chars().count(),
            azapptoolkit_core::http_error::ERROR_BODY_MAX_CHARS + 1
        );
        assert!(body.ends_with('…'));
    }

    /// `customerId` comes out of an ARM workspace listing. A `?` would let a
    /// second query override the `timespan`, a `..` walk the path, a `#`
    /// truncate it — so a non-GUID is refused before the Logs bearer is sent.
    #[tokio::test]
    async fn query_refuses_a_workspace_id_that_is_not_a_guid() {
        let server = MockServer::start().await;
        let client = client(&server.uri());
        for ws in ["../x?y", "ws?timespan=P1D", "ws#f", "ws-guid"] {
            let err = client.query(ws, "AppEvents", "P1D").await.unwrap_err();
            assert!(
                matches!(&err, ArmError::Protocol(m) if m == "refusing a workspace id that is not a GUID"),
                "{ws} must be refused, got {err:?}"
            );
        }
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a refused workspace id must not reach the wire"
        );
    }
}
