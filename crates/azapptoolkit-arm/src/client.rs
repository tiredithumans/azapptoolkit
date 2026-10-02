//! Thin HTTP client over the ARM REST surface. Mirrors the Key Vault client's
//! retry/jitter pattern (the knobs match `azapptoolkit_core::http_retry`).

use std::sync::Arc;
use std::time::Duration;

use reqwest::Method;
use serde::de::DeserializeOwned;

use azapptoolkit_core::net::{redacted_host, same_origin};
use azapptoolkit_core::token::BearerProvider;

use crate::error::{ArmError, Result};
use crate::models::{
    KeyVaultResource, LogAnalyticsWorkspace, Paged, RoleAssignment, RoleDefinition, Subscription,
};
use crate::validate::{require_arm_path, require_guid};

pub const ARM_BASE: &str = "https://management.azure.com";
/// `Microsoft.Resources/subscriptions` (Subscriptions - List): latest stable.
/// Source: <https://learn.microsoft.com/rest/api/resources/subscriptions/list>
/// (reviewed 2026-09).
const SUBSCRIPTIONS_API: &str = "2022-12-01";
/// `Microsoft.Authorization` (role assignments / definitions): latest stable.
/// Source: <https://learn.microsoft.com/rest/api/authorization/versions>
/// (reviewed 2026-09).
const AUTHORIZATION_API: &str = "2022-04-01";
/// `Microsoft.OperationalInsights/workspaces`: behind the latest stable
/// (2025-07-01) but not retiring; only `properties.customerId` is read. Source:
/// <https://learn.microsoft.com/azure/templates/microsoft.operationalinsights/workspaces>
/// (reviewed 2026-09).
const LOG_ANALYTICS_WORKSPACES_API: &str = "2022-10-01";
/// `Microsoft.KeyVault/vaults` (control plane): every version before
/// 2026-02-01 retires on 2027-02-27 with no exception or extension. Only the
/// vault listing uses it (`id`/`name`), and the 2026-02-01 RBAC-by-default
/// change affects only vault creation. Pinned by
/// `keyvault_control_plane_api_survives_the_2027_retirement`. Source:
/// <https://learn.microsoft.com/azure/key-vault/general/migrate-api-version>
/// (reviewed 2026-09).
const KEYVAULT_API: &str = "2026-02-01";

/// Defensive bound on `nextLink` paging: a misbehaving server returning a
/// self-referencing `nextLink` must not page forever (far above any real
/// collection).
const MAX_PAGES: usize = 1000;

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
            .connect_timeout(azapptoolkit_core::http_retry::CONNECT_TIMEOUT)
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

    /// Role assignments held by `principal_id` **at, above or below** the
    /// subscription scope. ARM's `$filter=principalId eq {id}` returns the
    /// subscription's own assignments, everything beneath it, and those
    /// inherited from above it (a management group, the tenant root) — so an
    /// above-subscription assignment comes back once per subscription queried.
    /// A caller that fans out over subscriptions must dedupe by assignment id
    /// (`managed_identity::flatten_assignments` in the desktop crate); a caller
    /// that only collects role GUIDs into a set (readiness) is unaffected.
    ///
    /// Both ids must be GUIDs: the subscription id comes out of an ARM response
    /// and is spliced into the path (see `crate::validate`).
    pub async fn list_role_assignments_for_principal(
        &self,
        subscription_id: &str,
        principal_id: &str,
    ) -> Result<Vec<RoleAssignment>> {
        require_guid("subscription id", subscription_id)?;
        require_guid("principal id", principal_id)?;
        let url = format!(
            "{}/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments",
            self.base_url
        );
        // Defense-in-depth: the principal id was just checked to be a GUID, so
        // it holds no `'`; escape the OData single-quote literal anyway, in case
        // that check is ever relaxed. Mirrors the Graph client's `escape_odata`.
        let filter = format!("principalId eq '{}'", principal_id.replace('\'', "''"));
        self.collect_paged(
            &url,
            &[("api-version", AUTHORIZATION_API), ("$filter", &filter)],
        )
        .await
    }

    /// Key Vaults in `subscription_id` the signed-in user can see (control
    /// plane). Each returned `id` is the ARM resource path, which doubles as the
    /// scope for [`Self::list_role_assignments_at_scope`]. `subscription_id`
    /// must be a GUID (it comes out of an ARM response).
    pub async fn list_key_vaults(&self, subscription_id: &str) -> Result<Vec<KeyVaultResource>> {
        require_guid("subscription id", subscription_id)?;
        let url = format!(
            "{}/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults",
            self.base_url
        );
        self.collect_paged(&url, &[("api-version", KEYVAULT_API)])
            .await
    }

    /// Role assignments that apply **at or above** `scope` (a vault / resource /
    /// resource-group / subscription ARM path). `$filter=atScope()` returns the
    /// ones made on `scope` itself plus every one inherited from its ancestors
    /// (resource group, subscription, management group, root), and excludes
    /// those on child scopes. Each row's `properties.scope` says where it was
    /// made, so a caller separates direct from inherited by comparing it to
    /// `scope`.
    ///
    /// `scope` is a vault's `id` from [`Self::list_key_vaults`] — ARM output —
    /// so it must be an absolute ARM path, and the composed URL is re-checked
    /// against the ARM origin before the bearer is attached.
    pub async fn list_role_assignments_at_scope(&self, scope: &str) -> Result<Vec<RoleAssignment>> {
        require_arm_path("scope", scope)?;
        let url = format!(
            "{}/{}/providers/Microsoft.Authorization/roleAssignments",
            self.base_url.trim_end_matches('/'),
            scope.trim_start_matches('/').trim_end_matches('/'),
        );
        self.require_arm_origin("scope", &url)?;
        self.collect_paged(
            &url,
            &[("api-version", AUTHORIZATION_API), ("$filter", "atScope()")],
        )
        .await
    }

    /// Log Analytics workspaces in `subscription_id` the signed-in user can see
    /// (control plane). The returned `properties.customer_id` is the workspace
    /// GUID the Azure Monitor Logs *query* API addresses workspaces by.
    /// `subscription_id` must be a GUID (it comes out of an ARM response).
    pub async fn list_log_analytics_workspaces(
        &self,
        subscription_id: &str,
    ) -> Result<Vec<LogAnalyticsWorkspace>> {
        require_guid("subscription id", subscription_id)?;
        let url = format!(
            "{}/subscriptions/{subscription_id}/providers/Microsoft.OperationalInsights/workspaces",
            self.base_url
        );
        self.collect_paged(&url, &[("api-version", LOG_ANALYTICS_WORKSPACES_API)])
            .await
    }

    /// Resolves a role-definition id (an absolute ARM path) to its definition,
    /// so the UI can show the role name instead of a GUID.
    ///
    /// `role_definition_id` is never a caller constant: both call sites pass
    /// `RoleAssignmentProperties::role_definition_id` straight out of an ARM
    /// `roleAssignments` response. That is the same attacker-influenced
    /// server-output class `collect_paged` guards `nextLink` for, so the
    /// composed URL is re-checked against the ARM origin rather than trusted —
    /// a value like `@evil.example/x` reinterprets the authority of a
    /// `format!`-spliced URL, and the bearer would follow it.
    pub async fn get_role_definition(&self, role_definition_id: &str) -> Result<RoleDefinition> {
        // Structure first: an ARM resource id is an absolute path, so anything
        // that could reinterpret the *shape* of the composed URL is refused
        // before it is composed. `?`/`#` would inject a second `api-version` or
        // truncate the query the call depends on; a `..` segment would walk it.
        require_arm_path("role definition id", role_definition_id)?;
        let url = format!("{}{role_definition_id}", self.base_url);
        // Then the authority: `@` turns everything composed so far into
        // userinfo, so the bearer would be sent to whatever follows it.
        self.require_arm_origin("role definition id", &url)?;
        self.get_json(&url, &[("api-version", AUTHORIZATION_API)])
            .await
    }

    async fn collect_paged<T: DeserializeOwned>(
        &self,
        url: &str,
        query: &[(&str, &str)],
    ) -> Result<Vec<T>> {
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
    ///
    /// `scope` is typed by the operator, so it must be an absolute ARM path, and
    /// `assignment_name` and `principal_id` must be GUIDs; the composed URL is
    /// re-checked against the ARM origin before the bearer is attached.
    pub async fn create_role_assignment(
        &self,
        scope: &str,
        assignment_name: &str,
        role_definition_id: &str,
        principal_id: &str,
    ) -> Result<()> {
        require_arm_path("scope", scope)?;
        require_guid("role assignment name", assignment_name)?;
        require_guid("principal id", principal_id)?;
        let url = format!(
            "{}/{}/providers/Microsoft.Authorization/roleAssignments/{assignment_name}",
            self.base_url.trim_end_matches('/'),
            scope.trim_start_matches('/').trim_end_matches('/'),
        );
        self.require_arm_origin("scope", &url)?;
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

    /// Refuses a composed `url` that left the ARM origin — the check that stands
    /// between a spliced value and the bearer.
    fn require_arm_origin(&self, what: &str, url: &str) -> Result<()> {
        if same_origin(&self.base_url, url) {
            Ok(())
        } else {
            Err(ArmError::Protocol(format!(
                "refusing a {what} that redirects off the ARM origin (host: {})",
                redacted_host(url)
            )))
        }
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

    /// Subscription, principal and assignment ids are GUIDs on the wire, and the
    /// client now refuses anything else before a request is sent.
    const SUB: &str = "11111111-1111-1111-1111-111111111111";
    const PRINCIPAL: &str = "22222222-2222-2222-2222-222222222222";
    const ASSIGNMENT: &str = "33333333-3333-3333-3333-333333333333";

    #[tokio::test]
    async fn creates_role_assignment_with_service_principal_type() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(format!(
                "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/{ASSIGNMENT}"
            )))
            .and(query_param("api-version", AUTHORIZATION_API))
            .and(body_partial_json(serde_json::json!({
                "properties": {
                    "roleDefinitionId": "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-guid",
                    "principalId": PRINCIPAL,
                    "principalType": "ServicePrincipal"
                }
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": format!("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Authorization/roleAssignments/{ASSIGNMENT}"),
                "name": ASSIGNMENT
            })))
            .mount(&server)
            .await;

        client(&server.uri())
            .create_role_assignment(
                "/subscriptions/sub-1/resourceGroups/rg",
                ASSIGNMENT,
                "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/role-guid",
                PRINCIPAL,
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
    async fn lists_key_vaults() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/subscriptions/{SUB}/providers/Microsoft.KeyVault/vaults"
            )))
            .and(query_param("api-version", KEYVAULT_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-1", "name": "kv-1"},
                    {"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-2"}
                ]
            })))
            .mount(&server)
            .await;

        let vaults = client(&server.uri()).list_key_vaults(SUB).await.unwrap();
        assert_eq!(vaults.len(), 2);
        assert_eq!(vaults[0].name.as_deref(), Some("kv-1"));
        // name is optional and absent on the second.
        assert_eq!(vaults[1].name, None);
        assert!(vaults[1].id.as_deref().unwrap().ends_with("kv-2"));
    }

    #[tokio::test]
    async fn role_assignments_at_scope_uses_atscope_filter_and_reads_principal_type() {
        let server = MockServer::start().await;
        let scope =
            "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-1";
        Mock::given(method("GET"))
            .and(path(format!(
                "{scope}/providers/Microsoft.Authorization/roleAssignments"
            )))
            .and(query_param("api-version", AUTHORIZATION_API))
            .and(query_param("$filter", "atScope()"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "/ra/1",
                    "properties": {
                        "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/def-1",
                        "scope": scope,
                        "principalId": "sp-1",
                        "principalType": "ServicePrincipal"
                    }
                }]
            })))
            .mount(&server)
            .await;

        let got = client(&server.uri())
            .list_role_assignments_at_scope(scope)
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].properties.principal_id.as_deref(), Some("sp-1"));
        assert_eq!(
            got[0].properties.principal_type.as_deref(),
            Some("ServicePrincipal")
        );
    }

    #[tokio::test]
    async fn role_assignments_at_scope_returns_inherited_ancestor_rows_with_their_own_scope() {
        let server = MockServer::start().await;
        let scope =
            "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-1";
        Mock::given(method("GET"))
            .and(path(format!(
                "{scope}/providers/Microsoft.Authorization/roleAssignments"
            )))
            .and(query_param("$filter", "atScope()"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    {
                        "id": "/ra/direct",
                        "properties": {
                            "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/def-1",
                            "scope": scope,
                            "principalId": "sp-1"
                        }
                    },
                    {
                        "id": "/ra/inherited",
                        "properties": {
                            "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/def-2",
                            "scope": "/subscriptions/sub-1",
                            "principalId": "sp-2"
                        }
                    }
                ]
            })))
            .mount(&server)
            .await;

        let got = client(&server.uri())
            .list_role_assignments_at_scope(scope)
            .await
            .unwrap();
        // The client never filters or rewrites provenance: the inherited
        // subscription row comes back beside the direct one, each carrying the
        // scope it was actually made at.
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].properties.scope.as_deref(), Some(scope));
        assert_eq!(
            got[1].properties.scope.as_deref(),
            Some("/subscriptions/sub-1")
        );
    }

    #[tokio::test]
    async fn role_assignments_filter_by_principal() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments"
            )))
            .and(query_param("$filter", format!("principalId eq '{PRINCIPAL}'")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "/ra/1",
                    "properties": {
                        "roleDefinitionId": "/providers/Microsoft.Authorization/roleDefinitions/def-1",
                        "scope": "/subscriptions/sub-1",
                        "principalId": PRINCIPAL
                    }
                }]
            })))
            .mount(&server)
            .await;

        let got = client(&server.uri())
            .list_role_assignments_for_principal(SUB, PRINCIPAL)
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].properties.scope.as_deref(),
            Some("/subscriptions/sub-1")
        );
    }

    /// `role_definition_id` comes straight out of an ARM response, so it is
    /// attacker-influenced server output — the same class `nextLink` is guarded
    /// for. Spliced with `format!` and no leading slash it reinterprets the
    /// authority of the composed URL and sends the ARM bearer to another host;
    /// with `?`/`#` it rewrites the query the call depends on.
    ///
    /// Note an `@` *after* a leading `/` is inert — it sits in the path, past
    /// the authority — which is why the structural check, not the origin check,
    /// is what closes this.
    #[tokio::test]
    async fn get_role_definition_refuses_an_id_that_redirects_off_origin() {
        let server = MockServer::start().await;
        let client = client(&server.uri());
        for id in [
            // No leading slash, so `@` lands in the *authority*: everything
            // composed before it becomes userinfo and the real host is
            // evil.example. This is the form the finding describes.
            "@evil.example/x",
            "evil.example/x",
            // Not an absolute path at all.
            "https://evil.example/x",
            // Injects a second api-version / truncates the query the call needs.
            "/subscriptions/s/roleDefinitions/r?api-version=2015-01-01",
            "/subscriptions/s/roleDefinitions/r#frag",
            // Dot-segments (plain or percent-encoded) walk the path elsewhere.
            "/subscriptions/s/../../x",
            "/x/%2e%2e/y",
        ] {
            let err = client.get_role_definition(id).await.unwrap_err();
            assert!(
                matches!(err, ArmError::Protocol(_)),
                "{id} must be refused, got {err:?}"
            );
        }
        // No request should have reached the mock at all.
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty()
        );
    }

    /// The ordinary absolute-path form still resolves.
    #[tokio::test]
    async fn get_role_definition_resolves_an_ordinary_arm_path() {
        let server = MockServer::start().await;
        let id = "/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/def-1";
        Mock::given(method("GET"))
            .and(path(id))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": id,
                "properties": { "roleName": "Reader" }
            })))
            .mount(&server)
            .await;
        let client = client(&server.uri());
        let def = client.get_role_definition(id).await.unwrap();
        assert_eq!(def.properties.role_name.as_deref(), Some("Reader"));
    }

    /// Microsoft retires every Key Vault control-plane api-version before
    /// 2026-02-01 on 2027-02-27; after that the vault sweep's per-subscription
    /// listing would fail (logged and skipped) and report no vaults. Guards
    /// against a downgrade. YYYY-MM-DD compares correctly as a string.
    #[test]
    fn keyvault_control_plane_api_survives_the_2027_retirement() {
        assert!(KEYVAULT_API >= "2026-02-01", "{KEYVAULT_API}");
    }

    #[tokio::test]
    async fn lists_log_analytics_workspaces_and_reads_customer_id() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/subscriptions/{SUB}/providers/Microsoft.OperationalInsights/workspaces"
            )))
            .and(query_param("api-version", LOG_ANALYTICS_WORKSPACES_API))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/law-1",
                    "name": "law-1",
                    "properties": {"customerId": "6f1c2a4e-0000-4000-8000-00000000abcd"}
                }]
            })))
            .mount(&server)
            .await;

        let ws = client(&server.uri())
            .list_log_analytics_workspaces(SUB)
            .await
            .unwrap();
        assert_eq!(ws.len(), 1);
        // The query API addresses a workspace by `customerId`, not its ARM id.
        assert_eq!(
            ws[0].properties.customer_id.as_deref(),
            Some("6f1c2a4e-0000-4000-8000-00000000abcd")
        );
    }

    /// A self-referencing `nextLink` stops at `MAX_PAGES` instead of paging
    /// forever.
    #[tokio::test]
    async fn collect_paged_stops_at_the_page_cap() {
        let server = MockServer::start().await;
        let uri = server.uri();
        // No query matcher: the follows are sent verbatim, without `api-version`.
        Mock::given(method("GET"))
            .and(path("/subscriptions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [],
                "nextLink": format!("{uri}/subscriptions")
            })))
            .mount(&server)
            .await;

        let err = client(&uri).list_subscriptions().await.unwrap_err();
        assert!(
            matches!(&err, ArmError::Protocol(m) if m.contains("exceeded")),
            "got {err:?}"
        );
        // The first page plus MAX_PAGES - 1 follows.
        assert_eq!(server.received_requests().await.unwrap().len(), MAX_PAGES);
    }

    /// Subscription ids, principal ids and scopes come out of earlier ARM
    /// responses (or the operator), and are spliced into the request path. A
    /// `?`/`#` rewrites the query, a `..` walks the path — so each is refused
    /// before any request, and the bearer never leaves.
    #[tokio::test]
    async fn arm_supplied_ids_are_refused_before_any_request() {
        let server = MockServer::start().await;
        let client = client(&server.uri());
        let refused = |what: &str, err: ArmError| {
            assert!(
                matches!(err, ArmError::Protocol(_)),
                "{what} must be refused, got {err:?}"
            );
        };
        for sub in [
            "sub?api-version=2015-01-01",
            "../providers/Microsoft.Authorization/roleAssignments",
            "sub-1",
        ] {
            refused(sub, client.list_key_vaults(sub).await.unwrap_err());
            refused(
                sub,
                client.list_log_analytics_workspaces(sub).await.unwrap_err(),
            );
            refused(
                sub,
                client
                    .list_role_assignments_for_principal(sub, PRINCIPAL)
                    .await
                    .unwrap_err(),
            );
        }
        let principal = "x' or '1'='1";
        refused(
            principal,
            client
                .list_role_assignments_for_principal(SUB, principal)
                .await
                .unwrap_err(),
        );
        for scope in [
            "subscriptions/s",
            "/subscriptions/s/../../x",
            "/subscriptions/s?x=1",
            "/subscriptions/%2e%2e/x",
        ] {
            refused(
                scope,
                client
                    .list_role_assignments_at_scope(scope)
                    .await
                    .unwrap_err(),
            );
            refused(
                scope,
                client
                    .create_role_assignment(scope, ASSIGNMENT, "/r", PRINCIPAL)
                    .await
                    .unwrap_err(),
            );
        }
        // The assignment name and principal of a write are GUIDs too.
        refused(
            "assignment name",
            client
                .create_role_assignment("/subscriptions/s", "../x", "/r", PRINCIPAL)
                .await
                .unwrap_err(),
        );
        refused(
            "principal",
            client
                .create_role_assignment("/subscriptions/s", ASSIGNMENT, "/r", "mi-1")
                .await
                .unwrap_err(),
        );
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a refused id must not reach the wire"
        );
    }

    /// ARM answers a duplicate assignment with 409 `RoleAssignmentExists`. It is
    /// terminal (sent once, not replayed) and recognisable, so the command layer
    /// can say so instead of showing the raw JSON.
    #[tokio::test]
    async fn create_role_assignment_409_exists_is_terminal_and_recognisable() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "error": {
                    "code": "RoleAssignmentExists",
                    "message": "The role assignment already exists."
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let err = client(&server.uri())
            .create_role_assignment(
                "/subscriptions/s/resourceGroups/rg",
                ASSIGNMENT,
                "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/r",
                PRINCIPAL,
            )
            .await
            .unwrap_err();
        assert!(err.is_role_assignment_exists(), "{err:?}");
    }
}
