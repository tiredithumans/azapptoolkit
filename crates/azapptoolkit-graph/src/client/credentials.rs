use super::*;

impl GraphClient {
    pub async fn add_password(
        &self,
        object_id: &str,
        display_name: &str,
        lifetime: Duration,
    ) -> Result<PasswordCredential> {
        let end = chrono::Utc::now()
            + chrono::Duration::from_std(lifetime).unwrap_or(chrono::Duration::days(180));
        self.add_password_window(object_id, display_name, None, end)
            .await
    }

    /// `addPassword` with an explicit validity window. `startDateTime` is only
    /// sent when given — Graph defaults it to "now", and sending an explicit
    /// value also lets callers schedule a not-yet-valid secret (the portal's
    /// "Custom" expiry option).
    pub async fn add_password_window(
        &self,
        object_id: &str,
        display_name: &str,
        start: Option<chrono::DateTime<chrono::Utc>>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<PasswordCredential> {
        let mut credential = serde_json::json!({
            "displayName": display_name,
            "endDateTime": end.to_rfc3339(),
        });
        if let Some(start) = start {
            credential["startDateTime"] = serde_json::Value::String(start.to_rfc3339());
        }
        let body = serde_json::json!({ "passwordCredential": credential });
        let path = format!("/applications/{object_id}/addPassword");
        self.send_json(Method::POST, &path, &body).await
    }

    pub async fn remove_password(&self, object_id: &str, key_id: &str) -> Result<()> {
        let body = serde_json::json!({ "keyId": key_id });
        let path = format!("/applications/{object_id}/removePassword");
        self.send_no_content(Method::POST, &path, Some(&body)).await
    }

    /// Lists an application's federated identity credentials (workload identity
    /// federation). Follows `@odata.nextLink` (Graph caps at 20 per app).
    pub async fn list_federated_credentials(
        &self,
        object_id: &str,
    ) -> Result<Vec<FederatedIdentityCredential>> {
        let path = format!("/applications/{object_id}/federatedIdentityCredentials");
        let params: [(&str, &str); 1] =
            [("$select", "id,name,issuer,subject,description,audiences")];
        let page: Paged<FederatedIdentityCredential> = self.get_json(&path, &params, false).await?;
        self.collect_all_pages(page).await
    }

    /// Creates a federated identity credential on an application.
    pub async fn add_federated_credential(
        &self,
        object_id: &str,
        body: &FederatedCredentialRequest,
    ) -> Result<FederatedIdentityCredential> {
        let path = format!("/applications/{object_id}/federatedIdentityCredentials");
        self.send_json(Method::POST, &path, body).await
    }

    /// Updates a federated identity credential in place. `name` is immutable
    /// in Graph, so the patch body deliberately has no `name` field.
    pub async fn update_federated_credential(
        &self,
        object_id: &str,
        credential_id: &str,
        body: &FederatedCredentialPatch,
    ) -> Result<()> {
        let path =
            format!("/applications/{object_id}/federatedIdentityCredentials/{credential_id}");
        self.send_no_content(Method::PATCH, &path, Some(body)).await
    }

    /// Removes a federated identity credential from an application.
    pub async fn remove_federated_credential(
        &self,
        object_id: &str,
        credential_id: &str,
    ) -> Result<()> {
        let path =
            format!("/applications/{object_id}/federatedIdentityCredentials/{credential_id}");
        self.send_no_content::<()>(Method::DELETE, &path, None)
            .await
    }

    /// Appends a certificate-credential entry to the application's
    /// `keyCredentials` array. Graph requires the full array on PATCH, so we
    /// fetch the current state first, append, and send the new list back.
    ///
    /// Note: this writes a "verify-only" credential (no private key), which
    /// is what users typically upload when an external issuer holds the
    /// private key and signs JWTs locally. For full client-credentials flow,
    /// users still need to use Graph's `addKey` action with a proof-of-
    /// possession JWT — out of scope for v1.
    pub async fn add_key_credential(
        &self,
        object_id: &str,
        new_cred: NewKeyCredential,
    ) -> Result<()> {
        let existing = self.get_application(object_id).await?.key_credentials;
        // Round-trip each existing entry through serde so we preserve whatever
        // Graph gave us on read. A serialization failure must abort: PATCH
        // replaces the whole array, so a dropped entry would delete a live
        // credential.
        let mut entries = existing
            .into_iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<serde_json::Value>, _>>()?;
        entries.push(serde_json::to_value(&new_cred)?);
        let body = serde_json::json!({ "keyCredentials": entries });
        let path = format!("/applications/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(&body))
            .await
    }

    /// Drops a certificate credential by `key_id`. Mirrors `add_key_credential`'s
    /// fetch-modify-patch shape.
    pub async fn remove_key_credential(&self, object_id: &str, key_id: &str) -> Result<()> {
        let existing = self.get_application(object_id).await?.key_credentials;
        let entries: Vec<KeyCredential> = existing
            .into_iter()
            .filter(|c| c.key_id != key_id)
            .collect();
        let body = serde_json::json!({ "keyCredentials": entries });
        let path = format!("/applications/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(&body))
            .await
    }

    /// Generates a self-signed SAML token-signing certificate on the service
    /// principal (`addTokenSigningCertificate`). Returns the new certificate,
    /// including its thumbprint; the caller then sets the SP's
    /// `preferredTokenSigningKeyThumbprint` to activate it.
    pub async fn add_token_signing_certificate(
        &self,
        service_principal_id: &str,
        display_name: &str,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Result<SelfSignedCertificate> {
        let body = serde_json::json!({
            "displayName": display_name,
            "endDateTime": end.to_rfc3339(),
        });
        let path = format!("/servicePrincipals/{service_principal_id}/addTokenSigningCertificate");
        self.send_json(Method::POST, &path, &body).await
    }
}
