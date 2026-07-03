//! Thin HTTP client over the ARM REST surface. Mirrors the Key Vault client's
//! retry/jitter pattern (the knobs match `azapptoolkit_core::http_retry`).

use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use serde::de::DeserializeOwned;

use azapptoolkit_core::net::{redacted_host, same_origin};
use azapptoolkit_core::token::BearerProvider;

use crate::error::{ArmError, Result};
use crate::models::{LogAnalyticsWorkspace, Paged, RoleAssignment, RoleDefinition, Subscription};

pub const ARM_BASE: &str = "https://management.azure.com";
const SUBSCRIPTIONS_API: &str = "2022-12-01";
const AUTHORIZATION_API: &str = "2022-04-01";
const LOG_ANALYTICS_WORKSPACES_API: &str = "2022-10-01";

pub struct ArmClient {
    http: reqwest::Client,
    token: Arc<dyn BearerProvider>,
    base_url: String,
}

impl ArmClient {
    pub fn new(token: Arc<dyn BearerProvider>) -> Self {
        Self::with_base_url(token, ARM_BASE)
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
        }
    }

    /// Subscriptions the signed-in user can access.
    pub async fn list_subscriptions(&self) -> Result<Vec<Subscription>> {
        let url = format!("{}/subscriptions", self.base_url);
        self.collect_paged(&url, &[("api-version", SUBSCRIPTIONS_API)])
            .await
    }

    /// Role assignments held by `principal_id` at or below the subscription
    /// scope. The default (no `atScope()`) collection returns assignments across
    /// the whole subscription hierarchy, so one call per subscription is enough.
    pub async fn list_role_assignments_for_principal(
        &self,
        subscription_id: &str,
        principal_id: &str,
    ) -> Result<Vec<RoleAssignment>> {
        let url = format!(
            "{}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments",
            self.base_url
        );
        // Defense-in-depth: a principal id is a GUID in practice, but escape the
        // OData single-quote literal anyway (a `'` would otherwise break the
        // filter). Mirrors the Graph client's `escape_odata`.
        let filter = format!("principalId eq '{}'", principal_id.replace('\'', "''"));
        self.collect_paged(
            &url,
            &[("api-version", AUTHORIZATION_API), ("$filter", &filter)],
        )
        .await
    }

    /// Log Analytics workspaces in `subscription_id` the signed-in user can see
    /// (control plane). The returned `properties.customer_id` is the workspace
    /// GUID the Azure Monitor Logs *query* API addresses workspaces by.
    pub async fn list_log_analytics_workspaces(
        &self,
        subscription_id: &str,
    ) -> Result<Vec<LogAnalyticsWorkspace>> {
        let url = format!(
            "{}/subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces",
            self.base_url
        );
        self.collect_paged(&url, &[("api-version", LOG_ANALYTICS_WORKSPACES_API)])
            .await
    }

    /// Resolves a role-definition id (an absolute ARM path) to its definition,
    /// so the UI can show the role name instead of a GUID.
    pub async fn get_role_definition(&self, role_definition_id: &str) -> Result<RoleDefinition> {
        let url = format!("{}{role_definition_id}", self.base_url);
        self.get_json(&url, &[("api-version", AUTHORIZATION_API)])
            .await
    }

    async fn collect_paged<T: DeserializeOwned>(
        &self,
        url: &str,
        query: &[(&str, &str)],
    ) -> Result<Vec<T>> {
        // Defensive bound: a misbehaving server returning a self-referencing
        // `nextLink` must not page forever (far above any real collection).
        const MAX_PAGES: usize = 1000;
        let mut out = Vec::new();
        let mut page: Paged<T> = self.get_json(url, query).await?;
        out.append(&mut page.value);
        let mut next = page.next_link;
        let mut pages = 1usize;
        // `nextLink` is fully qualified and already carries every query param.
        while let Some(link) = next.take() {
            if pages >= MAX_PAGES {
                return Err(ArmError::Protocol(format!(
                    "paged listing exceeded {MAX_PAGES} pages; aborting"
                )));
            }
            // A `nextLink` is attacker-influenced server output: refuse to
            // attach the bearer off the ARM origin (mirrors the Graph and Key
            // Vault clients' guard).
            if !same_origin(&self.base_url, &link) {
                return Err(ArmError::Protocol(format!(
                    "refusing to follow nextLink to a different origin (host: {})",
                    redacted_host(&link)
                )));
            }
            let p: Paged<T> = self.get_json(&link, &[]).await?;
            out.extend(p.value);
            next = p.next_link;
            pages += 1;
        }
        Ok(out)
    }

    /// Creates an Azure RBAC role assignment (PUT
    /// `{scope}/providers/Microsoft.Authorization/roleAssignments/{name}`).
    /// `assignment_name` must be a client-generated GUID — the caller generates it
    /// so a retry of this idempotent PUT reuses the same name rather than creating
    /// a duplicate. `principalType=ServicePrincipal` is set so the assignment
    /// survives directory replication delay for a freshly-created managed identity
    /// (per the ARM `role-assignments-rest` guidance). `scope` is the resource
    /// path the assignment applies to (subscription / resource group / resource);
    /// `role_definition_id` is the full ARM role-definition path.
    pub async fn create_role_assignment(
        &self,
        scope: &str,
        assignment_name: &str,
        role_definition_id: &str,
        principal_id: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/{}/providers/Microsoft.Authorization/roleAssignments/{assignment_name}",
            self.base_url.trim_end_matches('/'),
            scope.trim_start_matches('/').trim_end_matches('/'),
        );
        let body = serde_json::json!({
            "properties": {
                "roleDefinitionId": role_definition_id,
                "principalId": principal_id,
                "principalType": "ServicePrincipal",
            }
        });
        self.send(
            Method::PUT,
            &url,
            &[("api-version", AUTHORIZATION_API)],
            Some(&body),
        )
        .await?;
        Ok(())
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str, query: &[(&str, &str)]) -> Result<T> {
        let bytes = self.send(Method::GET, url, query, None).await?;
        serde_json::from_slice::<T>(&bytes).map_err(|e| ArmError::Deserialize(e.to_string()))
    }

    async fn send(
        &self,
        method: Method,
        url: &str,
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> Result<bytes::Bytes> {
        crate::transport::send_with_retry(&self.http, &self.token, "arm", method, url, query, body)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{body_partial_json, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn client(base: &str) -> ArmClient {
        ArmClient::with_base_url(StaticTokenProvider::new("tok"), base.to_string())
    }

    #[tokio::test]
    async fn creates_role_assignment_with_service_principal_type() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(
                "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/assign-guid",
            ))
            .and(query_param("api-version", AUTHORIZATION_API))
            .and(body_partial_json(serde_json::json!({
                "properties": {
                    "roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-guid",
                    "principalId": "mi-principal",
                    "principalType": "ServicePrincipal"
                }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/assign-guid",
                "name": "assign-guid"
            })))
            .mount(&server)
            .await;

        client(&server.uri())
            .create_role_assignment(
                "/subscriptions/sub-1/resourceGroups/rg",
                "assign-guid",
                "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-guid",
                "mi-principal",
            )
            .await
            .expect("create role assignment succeeds");
    }

    #[tokio::test]
    async fn lists_subscriptions() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .and(query_param("api-version", SUBSCRIPTIONS_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"subscriptionId": "sub-1", "displayName": "Prod"},
                    {"subscriptionId": "sub-2"}
                ]
            })))
            .mount(&server)
            .await;

        let subs = client(&server.uri()).list_subscriptions().await.unwrap();
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].subscription_id, "sub-1");
        assert_eq!(subs[0].display_name.as_deref(), Some("Prod"));
        // displayName is optional and absent on the second.
        assert_eq!(subs[1].display_name, None);
    }

    #[tokio::test]
    async fn follows_next_link_across_pages() {
        let server = MockServer::start().await;
        let uri = server.uri();
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .and(query_param("api-version", SUBSCRIPTIONS_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{"subscriptionId": "sub-1"}],
                "nextLink": format!("{uri}/subscriptions/page2")
            })))
            .mount(&server)
            .await;
        // The nextLink is fetched verbatim (no api-version query re-appended).
        Mock::given(method("GET"))
            .and(path("/subscriptions/page2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{"subscriptionId": "sub-2"}]
            })))
            .mount(&server)
            .await;

        let subs = client(&uri).list_subscriptions().await.unwrap();
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[1].subscription_id, "sub-2");
    }

    #[tokio::test]
    async fn refuses_off_origin_next_link() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .and(query_param("api-version", SUBSCRIPTIONS_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{"subscriptionId": "sub-1"}],
                "nextLink": "https://evil.example.com/subscriptions?token=steal"
            })))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .list_subscriptions()
            .await
            .unwrap_err();
        // The bearer must never be sent off-origin; the error names only the
        // host (the full link is attacker-influenced).
        assert!(matches!(err, ArmError::Protocol(_)), "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("evil.example.com"), "got {msg}");
        assert!(!msg.contains("token=steal"), "leaked query: {msg}");
    }

    #[tokio::test]
    async fn resolves_role_definition_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/providers/Microsoft.Authorization/roleDefinitions/owner-guid",
            ))
            .and(query_param("api-version", AUTHORIZATION_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "properties": {"roleName": "Owner"}
            })))
            .mount(&server)
            .await;

        let def = client(&server.uri())
            .get_role_definition("/providers/Microsoft.Authorization/roleDefinitions/owner-guid")
            .await
            .unwrap();
        assert_eq!(def.properties.role_name.as_deref(), Some("Owner"));
    }

    #[tokio::test]
    async fn maps_401_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let err = client(&server.uri())
            .list_subscriptions()
            .await
            .unwrap_err();
        assert!(matches!(err, ArmError::Unauthorized), "got {err:?}");
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn maps_403_to_forbidden() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403).set_body_string("no access"))
            .mount(&server)
            .await;
        let err = client(&server.uri())
            .list_subscriptions()
            .await
            .unwrap_err();
        assert!(matches!(err, ArmError::Forbidden(b) if b.contains("no access")));
    }

    #[tokio::test]
    async fn maps_404_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let err = client(&server.uri())
            .get_role_definition("/missing")
            .await
            .unwrap_err();
        assert!(matches!(err, ArmError::NotFound(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn maps_other_4xx_to_api_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad filter"))
            .mount(&server)
            .await;
        let err = client(&server.uri())
            .list_subscriptions()
            .await
            .unwrap_err();
        assert!(
            matches!(err, ArmError::Api { status: 400, .. }),
            "got {err:?}"
        );
        // 4xx (except 429) is terminal, not retried.
        assert!(!err.is_retryable());
    }

    #[tokio::test]
    async fn retries_transient_500_then_succeeds() {
        let server = MockServer::start().await;
        // First response is a 5xx (consumed once), then a success.
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{"subscriptionId": "sub-1"}]
            })))
            .mount(&server)
            .await;

        let subs = client(&server.uri()).list_subscriptions().await.unwrap();
        assert_eq!(subs.len(), 1);
    }

    #[tokio::test]
    async fn role_assignments_filter_by_principal() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments",
            ))
            .and(query_param("$filter", "principalId eq 'mi-1'"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "/ra/1",
                    "properties": {
                        "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/def-1",
                        "scope": "/subscriptions/sub-1",
                        "principalId": "mi-1"
                    }
                }]
            })))
            .mount(&server)
            .await;

        let got = client(&server.uri())
            .list_role_assignments_for_principal("sub-1", "mi-1")
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].properties.scope.as_deref(),
            Some("/subscriptions/sub-1")
        );
    }
}
