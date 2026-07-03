//! Shared fixtures for the per-domain client test modules: the
//! mock-server-backed client constructor and canned Graph payloads.

pub(crate) use azapptoolkit_core::cache::Cache;
pub(crate) use azapptoolkit_core::token::StaticTokenProvider;
pub(crate) use wiremock::matchers::{
    body_string_contains, header, method, path, query_param, query_param_is_missing,
};
pub(crate) use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::GraphClient;

pub(crate) fn sample_org_json() -> serde_json::Value {
    serde_json::json!({
        "value": [{
            "id": "tenant-1",
            "displayName": "Contoso",
            "verifiedDomains": [{"name": "contoso.onmicrosoft.com", "isDefault": true}]
        }]
    })
}

pub(crate) fn sample_apps_json() -> serde_json::Value {
    serde_json::json!({
        "@odata.count": 1,
        "value": [{
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "Demo App",
            "signInAudience": "AzureADMyOrg",
            "passwordCredentials": [],
            "keyCredentials": [],
            "requiredResourceAccess": []
        }]
    })
}

pub(crate) fn make_client(base: &str) -> GraphClient {
    let token = StaticTokenProvider::new("tok");
    GraphClient::with_base_url(
        "tenant-test",
        token.clone(),
        token,
        Cache::new(),
        base.to_string(),
    )
}
