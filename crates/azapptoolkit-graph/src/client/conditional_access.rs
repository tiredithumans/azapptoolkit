//! The network lock's Conditional Access writes (one per-app policy, IP named
//! locations) and the service-principal sign-in read behind its report-only
//! readout. Reads of the policy list live in `directory.rs`.

use super::*;
use azapptoolkit_core::models::{NamedLocation, SignIn};
use jiff::Timestamp;

/// Cap on sign-in rows read for one app's report-only readout: a week of an
/// app's sign-ins can be large, and the readout only needs a count and a few
/// addresses.
const SIGN_IN_ROW_CAP: usize = 1_000;

impl GraphClient {
    /// Every named location (IP and country). Rides the `Policy.Read.All`
    /// token the Conditional Access tab already uses.
    pub async fn list_named_locations(&self) -> Result<Vec<NamedLocation>> {
        let token = self.policy_token()?;
        let url = format!(
            "{}/identity/conditionalAccess/namedLocations?$top={MAX_PAGE_SIZE}",
            self.base_url
        );
        let page: Paged<NamedLocation> = self.scoped_get_retried(token, &url).await?;
        self.collect_pages_from(
            page,
            |u| async move { self.scoped_get_retried(token, &u).await },
        )
        .await
    }

    /// Creates an UNTRUSTED IP named location from validated CIDR ranges
    /// (`(is_ipv6, cidr)`): a trusted one would join `AllTrusted`, which user
    /// MFA policies and Identity Protection treat as safe.
    pub async fn create_ip_named_location(
        &self,
        display_name: &str,
        cidrs: &[(bool, String)],
    ) -> Result<NamedLocation> {
        let token = self.conditional_access_write_token()?;
        let ranges: Vec<serde_json::Value> = cidrs
            .iter()
            .map(|(v6, cidr)| {
                serde_json::json!({
                    "@odata.type": if *v6 { "#microsoft.graph.iPv6CidrRange" } else { "#microsoft.graph.iPv4CidrRange" },
                    "cidrAddress": cidr,
                })
            })
            .collect();
        let body = serde_json::json!({
            "@odata.type": "#microsoft.graph.ipNamedLocation",
            "displayName": display_name,
            "isTrusted": false,
            "ipRanges": ranges,
        });
        let url = format!(
            "{}/identity/conditionalAccess/namedLocations",
            self.base_url
        );
        self.scoped_send_json(token, Method::POST, &url, &body)
            .await
    }

    /// One Conditional Access policy, read on the write token so a verify-then-
    /// write needs one consent.
    pub async fn get_ca_policy(&self, policy_id: &str) -> Result<ConditionalAccessPolicy> {
        validate::require_path_segment("policy id", policy_id)?;
        let token = self.conditional_access_write_token()?;
        let url = format!(
            "{}/identity/conditionalAccess/policies/{policy_id}",
            self.base_url
        );
        self.scoped_get_retried(token, &url).await
    }

    /// Creates a Conditional Access policy from a prepared body
    /// (`conditional_access::lock_policy_body`). A POST is never replayed
    /// after a 5xx, so a create can't land twice.
    pub async fn create_ca_policy(
        &self,
        body: &serde_json::Value,
    ) -> Result<ConditionalAccessPolicy> {
        let token = self.conditional_access_write_token()?;
        let url = format!("{}/identity/conditionalAccess/policies", self.base_url);
        self.scoped_send_json(token, Method::POST, &url, body).await
    }

    /// Sets a policy's `state` (`enabled` / `enabledForReportingButNotEnforced`
    /// / `disabled`) and nothing else.
    pub async fn set_ca_policy_state(&self, policy_id: &str, state: &str) -> Result<()> {
        validate::require_path_segment("policy id", policy_id)?;
        let token = self.conditional_access_write_token()?;
        let url = format!(
            "{}/identity/conditionalAccess/policies/{policy_id}",
            self.base_url
        );
        let body = serde_json::json!({ "state": state });
        self.scoped_send_no_content(token, Method::PATCH, &url, Some(&body))
            .await
    }

    /// Deletes a Conditional Access policy.
    pub async fn delete_ca_policy(&self, policy_id: &str) -> Result<()> {
        validate::require_path_segment("policy id", policy_id)?;
        let token = self.conditional_access_write_token()?;
        let url = format!(
            "{}/identity/conditionalAccess/policies/{policy_id}",
            self.base_url
        );
        self.scoped_send_no_content::<()>(token, Method::DELETE, &url, None)
            .await
    }

    /// One app's service-principal sign-ins since `since` (beta: the
    /// `signInEventTypes` filter is beta-only), with the report-only CA
    /// results Graph hides unless asked (`Prefer: include-unknown-enum-members`).
    /// Capped at 1 000 rows (newest first); the flag says the cap was hit.
    pub async fn list_service_principal_sign_ins(
        &self,
        app_id: &str,
        since: Timestamp,
    ) -> Result<(Vec<SignIn>, bool)> {
        let token = self.audit_log_token()?;
        let filter = format!(
            "appId eq '{}' and createdDateTime ge {} and signInEventTypes/any(t: t eq 'servicePrincipal')",
            escape_odata(app_id),
            // Whole seconds, as Graph's documented sign-in filters use.
            since.strftime("%Y-%m-%dT%H:%M:%SZ")
        );
        let mut url = url::Url::parse(&format!("{}/auditLogs/signIns", self.beta_base()))
            .map_err(|e| GraphError::Protocol(format!("bad sign-in url: {e}")))?;
        url.query_pairs_mut()
            .append_pair("$filter", &filter)
            .append_pair("$top", MAX_PAGE_SIZE);
        let prefer = Some("include-unknown-enum-members");
        let fetch = |u: String| async move {
            let bytes = self
                .send_core_url_with(
                    token,
                    RetryClass::Idempotent,
                    Method::GET,
                    &u,
                    &[],
                    false,
                    None,
                    prefer,
                )
                .await?;
            serde_json::from_slice::<Paged<SignIn>>(&bytes)
                .map_err(|e| GraphError::Deserialize(e.to_string()))
        };
        let first = fetch(url.to_string()).await?;
        self.collect_pages_from_capped(first, SIGN_IN_ROW_CAP, fetch)
            .await
    }
}
