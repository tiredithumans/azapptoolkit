use super::*;

impl GraphClient {
    /// Creates a claims-mapping policy (`/policies/claimsMappingPolicies`).
    /// `definition_json` is the policy JSON; Graph stores it as a single-element
    /// `definition` array. Requires the `policy_write_token`.
    pub async fn create_claims_mapping_policy(
        &self,
        definition_json: &str,
        display_name: &str,
    ) -> Result<ClaimsMappingPolicy> {
        let token = self.policy_write_token()?;
        let body = serde_json::json!({
            "definition": [definition_json],
            "displayName": display_name,
            "isOrganizationDefault": false,
        });
        let url = format!("{}/policies/claimsMappingPolicies", self.base_url);
        self.scoped_send_json(token, Method::POST, &url, &body)
            .await
    }

    /// Assigns a claims-mapping policy to a service principal
    /// (`servicePrincipals/{id}/claimsMappingPolicies/$ref`). The `@odata.id` is
    /// built from `base_url` so mock tests resolve. Requires `policy_write_token`.
    pub async fn assign_claims_mapping_policy(
        &self,
        service_principal_id: &str,
        policy_id: &str,
    ) -> Result<()> {
        let token = self.policy_write_token()?;
        let odata_id = format!(
            "{}/policies/claimsMappingPolicies/{policy_id}",
            self.base_url.trim_end_matches('/')
        );
        let body = serde_json::json!({ "@odata.id": odata_id });
        let url = format!(
            "{}/servicePrincipals/{service_principal_id}/claimsMappingPolicies/$ref",
            self.base_url
        );
        self.scoped_send_no_content(token, Method::POST, &url, Some(&body))
            .await
    }

    /// Lists the claims-mapping policies assigned to a service principal.
    /// Requires `policy_write_token`. Returns an empty list when none.
    pub async fn list_assigned_claims_mapping_policies(
        &self,
        service_principal_id: &str,
    ) -> Result<Vec<ClaimsMappingPolicy>> {
        let token = self.policy_write_token()?;
        let url = format!(
            "{}/servicePrincipals/{service_principal_id}/claimsMappingPolicies",
            self.base_url
        );
        let page: Paged<ClaimsMappingPolicy> = self.scoped_get(token, &url).await?;
        Ok(page.items)
    }

    /// Removes a claims-mapping policy assignment from a service principal
    /// (`.../claimsMappingPolicies/{id}/$ref`). Requires `policy_write_token`.
    pub async fn remove_claims_mapping_policy(
        &self,
        service_principal_id: &str,
        policy_id: &str,
    ) -> Result<()> {
        let token = self.policy_write_token()?;
        let url = format!(
            "{}/servicePrincipals/{service_principal_id}/claimsMappingPolicies/{policy_id}/$ref",
            self.base_url
        );
        self.scoped_send_no_content::<()>(token, Method::DELETE, &url, None)
            .await
    }
}
