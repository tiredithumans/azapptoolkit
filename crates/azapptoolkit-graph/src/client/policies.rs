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

    /// The custom claims policy the Entra admin center writes for this service
    /// principal's "Attributes & Claims", or `None` when the app has none (the
    /// admin center hasn't customized it). Beta only, and **global cloud only**:
    /// the resource has no v1.0 form and no national-cloud deployment, so the
    /// caller decides whether to ask at all. Rides `policy_write_token`
    /// (`Policy.ReadWrite.ApplicationConfiguration`, the documented least
    /// privilege for this read).
    ///
    /// Microsoft documents two response shapes: the policy object itself (the
    /// how-to's examples) and a `value` collection holding it (the API
    /// reference). Both are accepted; an empty collection is no policy. Reading
    /// the wrong shape as a policy would show "configured in the admin center"
    /// with no claims, so anything else is a deserialize error, not an empty
    /// policy.
    pub async fn get_custom_claims_policy(
        &self,
        service_principal_id: &str,
    ) -> Result<Option<CustomClaimsPolicy>> {
        let token = self.policy_write_token()?;
        let url = format!(
            "{}/servicePrincipals/{service_principal_id}/claimsPolicy",
            self.beta_base()
        );
        let Some(body) =
            not_found_as_none(self.scoped_get::<serde_json::Value>(token, &url).await)?
        else {
            return Ok(None);
        };
        let policy = match body.get("value") {
            Some(serde_json::Value::Array(items)) => match items.first() {
                Some(first) => first.clone(),
                None => return Ok(None),
            },
            Some(_) => {
                return Err(GraphError::Deserialize(
                    "claimsPolicy: `value` is not a collection".into(),
                ));
            }
            None => body,
        };
        if !policy.is_object() {
            return Err(GraphError::Deserialize(
                "claimsPolicy: the policy is not an object".into(),
            ));
        }
        serde_json::from_value(policy)
            .map(Some)
            .map_err(|e| GraphError::Deserialize(e.to_string()))
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

    /// The tenant-wide default app-management policy
    /// (`GET /policies/defaultAppManagementPolicy`, v1.0). `Ok(None)` means the
    /// tenant never configured the feature — `isEnabled` defaults to false, so a
    /// present-but-disabled policy and an absent one both mean "no enforced
    /// credential lifetime". Requires the `Policy.Read.All` token
    /// ([`Self::with_policy_token`]).
    ///
    /// Read-through cache like the optional reports: this is slow-changing
    /// tenant config, one tiny read per TTL window is plenty, and the sign-out
    /// sweep bounds staleness. A 404 (endpoint not provisioned for the tenant)
    /// reads as "no policy" exactly like the CA collection's first-404 rule;
    /// any other error propagates so the caller degrades explicitly.
    pub async fn get_default_app_management_policy(
        &self,
    ) -> Result<Option<TenantAppManagementPolicy>> {
        let cache_key = format!("{}|app_management_policy", self.tenant_id);
        if let Some(cached) = self
            .cache
            .get::<Option<TenantAppManagementPolicy>>(CacheKind::Permissions, &cache_key)
        {
            return Ok(cached);
        }
        let token = self.policy_token()?;
        let url = format!("{}/policies/defaultAppManagementPolicy", self.base_url);
        let policy = match self.scoped_get(token, &url).await {
            Ok(policy) => Some(policy),
            Err(GraphError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };
        self.cache.put(CacheKind::Permissions, cache_key, &policy);
        Ok(policy)
    }

    /// Every custom `appManagementPolicy` with its assigned targets
    /// (`GET /policies/appManagementPolicies?$expand=appliesTo`). One tenant-wide
    /// read backs both the audit (apps adopt an override INSTEAD of the tenant
    /// default — without the target map, a default-policy cap could mis-flag an
    /// overridden app) and the Credentials tab's per-app policy panel.
    /// Requires the `Policy.Read.All` token.
    ///
    /// The audit keys off the `appliesTo` object ids, so the expand is the
    /// payload: a policy assigned to an application or to a service principal
    /// both matter (credential mirrors ride both objects), and callers match by
    /// object id without needing the discriminator. A 404 means no custom
    /// policies exist; paging follows via `collect_pages_from` (origin-checked).
    /// Read-through cache, as [`Self::get_default_app_management_policy`].
    pub async fn list_app_management_policies(&self) -> Result<Vec<AppManagementPolicy>> {
        let cache_key = format!("{}|app_management_policies", self.tenant_id);
        if let Some(cached) = self
            .cache
            .get::<Vec<AppManagementPolicy>>(CacheKind::Permissions, &cache_key)
        {
            return Ok(cached);
        }
        let token = self.policy_token()?;
        let url = format!(
            "{}/policies/appManagementPolicies?$expand=appliesTo&$top={MAX_PAGE_SIZE}",
            self.base_url
        );
        let policies = match self.scoped_get(token, &url).await {
            Ok(page) => {
                self.collect_pages_from(page, |u| async move { self.scoped_get(token, &u).await })
                    .await?
            }
            Err(GraphError::NotFound(_)) => Vec::new(),
            Err(e) => return Err(e),
        };
        self.cache.put(CacheKind::Permissions, cache_key, &policies);
        Ok(policies)
    }

    /// The app-management policies assigned to ONE application
    /// (`GET /applications/{id}/appManagementPolicies`) — the per-app override
    /// lookup behind the Credentials tab. "Only one policy is typically assigned
    /// to an application", so no target expand is needed; paging still follows in
    /// the rare multi-assignment case. Requires the `Policy.Read.All` token.
    /// 404 → empty; read-through cache keyed per app.
    pub async fn list_app_management_policies_for_app(
        &self,
        object_id: &str,
    ) -> Result<Vec<AppManagementPolicy>> {
        let cache_key = format!("{}|app_management_policies:{object_id}", self.tenant_id);
        if let Some(cached) = self
            .cache
            .get::<Vec<AppManagementPolicy>>(CacheKind::Permissions, &cache_key)
        {
            return Ok(cached);
        }
        let token = self.policy_token()?;
        let url = format!(
            "{}/applications/{object_id}/appManagementPolicies?$top={MAX_PAGE_SIZE}",
            self.base_url
        );
        let policies = match self.scoped_get(token, &url).await {
            Ok(page) => {
                self.collect_pages_from(page, |u| async move { self.scoped_get(token, &u).await })
                    .await?
            }
            Err(GraphError::NotFound(_)) => Vec::new(),
            Err(e) => return Err(e),
        };
        self.cache.put(CacheKind::Permissions, cache_key, &policies);
        Ok(policies)
    }

    /// The tenant-wide `authorizationPolicy` (F274 consent posture). Returned
    /// as raw JSON: the two properties the posture reads
    /// (`allowUserConsentForRiskyApps`, and
    /// `defaultUserRolePermissions.permissionGrantPoliciesAssigned`) are
    /// sometimes `null` or absent, and the command side renders that as
    /// "unknown" — a typed model would force every absent property to pose as
    /// a default. Requires the `Policy.Read.All` token.
    ///
    /// No read-through cache: both consent-posture surfaces read once at mount
    /// (never in a fan-out), and the consent module's contract is "always
    /// fresh" — unlike the app-management trio above, a TTL cache would trade
    /// its only real benefit (mount-time freshness after a portal change) for
    /// one saved tiny read per view.
    pub async fn get_authorization_policy(&self) -> Result<serde_json::Value> {
        let token = self.policy_token()?;
        let url = format!("{}/policies/authorizationPolicy", self.base_url);
        self.scoped_get(token, &url).await
    }

    /// The tenant admin consent request (workflow) policy
    /// (`GET /policies/adminConsentRequestPolicy`, v1.0, `Policy.Read.All`).
    /// `Ok(None)` means 404 — the workflow has never been enabled, since
    /// enabling it requires the policy object to be created. Absence is
    /// decidable here (same reading as an absent default app-management
    /// policy); no cache, as [`Self::get_authorization_policy`].
    pub async fn get_admin_consent_request_policy(
        &self,
    ) -> Result<Option<AdminConsentRequestPolicy>> {
        let token = self.policy_token()?;
        let url = format!("{}/policies/adminConsentRequestPolicy", self.base_url);
        match self.scoped_get(token, &url).await {
            Ok(policy) => Ok(Some(policy)),
            Err(GraphError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
