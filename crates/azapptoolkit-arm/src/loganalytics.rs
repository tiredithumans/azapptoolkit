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
    /// "not here" rather than a hard failure.
    pub async fn query(
        &self,
        workspace_customer_id: &str,
        kql: &str,
        timespan: &str,
    ) -> Result<LogsQueryTable> {
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

    #[tokio::test]
    async fn query_returns_first_table() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/workspaces/ws-guid/query"))
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
            .query("ws-guid", "AppEvents | take 1", "P90D")
            .await
            .expect("query returns the first table");
        assert_eq!(table.name, "PrimaryResult");
        assert_eq!(table.column_index("AppId"), Some(0));
        assert_eq!(table.rows, vec![vec![serde_json::json!("app-1")]]);
    }

    #[tokio::test]
    async fn query_without_tables_is_deserialize_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/workspaces/ws-guid/query"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "tables": [] })),
            )
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .query("ws-guid", "AppEvents", "P1D")
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
            .and(path("/v1/workspaces/ws-guid/query"))
            .respond_with(
                ResponseTemplate::new(400).set_body_string("SemanticError: table not found"),
            )
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .query("ws-guid", "MissingTable", "P1D")
            .await
            .unwrap_err();
        assert!(
            matches!(err, ArmError::Api { status: 400, .. }),
            "got {err:?}"
        );
        assert!(!err.is_retryable());
    }
}
