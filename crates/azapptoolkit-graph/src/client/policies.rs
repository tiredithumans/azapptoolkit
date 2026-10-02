use super::*;

impl GraphClient {
    /// Creates a claims-mapping policy; `definition_json` is wrapped in the single-element
    /// `definition` array Graph stores. Requires `policy_write_token`.
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

    /// Assigns a claims-mapping policy to a service principal. The `@odata.id` is built from
    /// `base_url` so mock tests resolve. Requires `policy_write_token`.
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

    /// Lists the claims-mapping policies assigned to a service principal; empty list when none.
    /// Requires `policy_write_token` (Learn documents the delegated `Application.ReadWrite.All`
    /// + `Policy.*` pair even for this read).
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

    /// Unassigns a policy from a service principal — the tenant-level object survives;
    /// [`Self::delete_claims_mapping_policy`] removes it. Requires `policy_write_token`.
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

    /// Replaces a policy's `definition` in place. Only `definition` is sent — omitted properties
    /// keep their values (Learn "Update claimsmappingpolicy"). Every subject the policy applies
    /// to sees the change, so the caller must prove it is the sole subject first.
    /// Requires `policy_write_token`.
    pub async fn update_claims_mapping_policy(
        &self,
        policy_id: &str,
        definition_json: &str,
    ) -> Result<()> {
        let token = self.policy_write_token()?;
        let body = serde_json::json!({ "definition": [definition_json] });
        let url = format!(
            "{}/policies/claimsMappingPolicies/{policy_id}",
            self.base_url
        );
        self.scoped_send_no_content(token, Method::PATCH, &url, Some(&body))
            .await
    }

    /// Deletes the tenant-level policy object — not the `$ref` assignment. The caller must
    /// prove nothing else uses it. Requires `policy_write_token`.
    pub async fn delete_claims_mapping_policy(&self, policy_id: &str) -> Result<()> {
        let token = self.policy_write_token()?;
        let url = format!(
            "{}/policies/claimsMappingPolicies/{policy_id}",
            self.base_url
        );
        self.scoped_send_no_content::<()>(token, Method::DELETE, &url, None)
            .await
    }

    /// Lists the directory-object ids a policy applies to (`appliesTo`) — the ownership proof
    /// before an in-place PATCH or delete: any id other than the caller's service principal means
    /// the policy is shared. Sends `$top` and follows `@odata.nextLink` (same-origin guarded);
    /// a paging error propagates rather than truncating the proof. Requires `policy_write_token`.
    pub async fn list_claims_mapping_policy_subjects(
        &self,
        policy_id: &str,
    ) -> Result<Vec<String>> {
        let token = self.policy_write_token()?;
        let url = format!(
            "{}/policies/claimsMappingPolicies/{policy_id}/appliesTo?$select=id&$top={MAX_PAGE_SIZE}",
            self.base_url
        );
        let page: Paged<DirectoryObject> = self.scoped_get(token, &url).await?;
        let subjects = self
            .collect_pages_from(page, |u| async move { self.scoped_get(token, &u).await })
            .await?;
        Ok(subjects.into_iter().map(|o| o.id).collect())
    }
}
