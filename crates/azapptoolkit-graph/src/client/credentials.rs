use super::*;

/// Body for `POST /applications/{id}/federatedIdentityCredentials`. `audiences`
/// defaults to `["api://AzureADTokenExchange"]` (the value Entra recommends for
/// token exchange; only the "Other issuer" flow may override it). `description`
/// is serialized even when `None` (as JSON `null`), matching the prior
/// hand-built body.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedCredentialRequest {
    pub name: String,
    pub issuer: String,
    pub subject: String,
    pub audiences: Vec<String>,
    pub description: Option<String>,
}

/// Body for `PATCH /applications/{id}/federatedIdentityCredentials/{ficId}`. Graph rejects
/// changing `name` (immutable), so the field is deliberately absent. `description: None`
/// serializes as JSON `null` to clear a previously-set description.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedCredentialPatch {
    pub issuer: String,
    pub subject: String,
    pub audiences: Vec<String>,
    pub description: Option<String>,
}

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

    /// `addPassword` with an explicit validity window; `startDateTime` is sent only when given
    /// (Graph defaults it to "now"). The explicit value also lets callers schedule a
    /// not-yet-valid secret (the portal's "Custom" expiry option).
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
        self.collect_all_pages(page, false).await
    }

    /// Batched [`Self::list_federated_credentials`]: one `$batch` POST per 20 apps, returning
    /// each app's credentials in input order. Graph caps federated credentials at ~20/app, so
    /// the first (batched) page is almost always complete; the rare overflow finishes via
    /// `collect_all_pages` outside the batch. A per-app failure is one `Err` in the vec.
    pub async fn batch_list_federated_credentials(
        &self,
        object_ids: &[String],
    ) -> Result<Vec<Result<Vec<FederatedIdentityCredential>>>> {
        let urls: Vec<String> = object_ids
            .iter()
            .map(|id| {
                batch_sub_url(
                    &format!("/applications/{id}/federatedIdentityCredentials"),
                    &[("$select", "id,name,issuer,subject,description,audiences")],
                )
            })
            .collect();
        let pages: Vec<Result<Paged<FederatedIdentityCredential>>> =
            self.batch_get_json(&urls).await?;
        self.finish_paged_batch(pages, false).await
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

    /// Updates a federated identity credential in place; `name` is immutable in Graph, so the
    /// patch body deliberately has no `name` field.
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

    /// Reads an application's live `keyCredentials` as **raw JSON**.
    ///
    /// The typed [`KeyCredential`] deliberately does not model `key` (the base64 DER
    /// certificate blob), and Graph returns it precisely on a `$select=keyCredentials` read.
    /// `keyCredentials` is a not-nullable, full-replace collection, so a typed round-trip on the
    /// fetch-modify-PATCH path writes every *surviving* certificate back **without its key** —
    /// silently destroying live credentials on an operation that was supposed to touch one entry.
    ///
    /// Both mutators below therefore go through raw JSON, which round-trips `key` and every
    /// other unmodeled field byte-for-byte — the same shape
    /// [`Self::remove_service_principal_key_credential`] was written against for this reason.
    async fn live_key_credentials(&self, object_id: &str) -> Result<Vec<serde_json::Value>> {
        let path = format!("/applications/{object_id}");
        let params: [(&str, &str); 1] = [("$select", "keyCredentials")];
        let app: serde_json::Value = self.get_json(&path, &params, false).await?;
        Ok(app
            .get("keyCredentials")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// Appends a certificate-credential entry to the application's `keyCredentials` array:
    /// fetch the live array, append, PATCH the full array back (Graph full-replaces it) — as
    /// raw JSON, so the surviving entries keep their `key` (see [`Self::live_key_credentials`]).
    ///
    /// Writes a "verify-only" credential (no private key) — what users upload when an external
    /// issuer holds the key and signs JWTs. Full client-credentials flow still needs Graph's
    /// `addKey` action with a proof-of-possession JWT — out of scope for v1.
    pub async fn add_key_credential(
        &self,
        object_id: &str,
        new_cred: NewKeyCredential,
    ) -> Result<()> {
        let mut entries = self.live_key_credentials(object_id).await?;
        entries.push(serde_json::to_value(&new_cred)?);
        let body = serde_json::json!({ "keyCredentials": entries });
        let path = format!("/applications/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(&body))
            .await
    }

    /// Drops a certificate credential by `key_id` — the same fetch-modify-patch shape as
    /// `add_key_credential`, raw JSON included: the audit's one-click "remove expired
    /// credentials" Fix reaches this on apps that also hold a live certificate, so stripping
    /// `key` from the survivors here is the worst case of the bug it guards against.
    ///
    /// A `key_id` not on the application is `Err(GraphError::NotFound)` and sends no PATCH:
    /// another admin (or a stale finding) removed it first, and writing the unchanged array
    /// back would report a removal that never happened. Callers that want "already gone" to
    /// count as done match on it.
    pub async fn remove_key_credential(&self, object_id: &str, key_id: &str) -> Result<()> {
        let live = self.live_key_credentials(object_id).await?;
        let before = live.len();
        let entries: Vec<serde_json::Value> = live
            .into_iter()
            .filter(|c| c.get("keyId").and_then(|v| v.as_str()) != Some(key_id))
            .collect();
        if entries.len() == before {
            return Err(GraphError::NotFound(format!(
                "certificate credential {key_id} is not on the application"
            )));
        }
        let body = serde_json::json!({ "keyCredentials": entries });
        let path = format!("/applications/{object_id}");
        self.send_no_content(Method::PATCH, &path, Some(&body))
            .await
    }

    /// Generates a self-signed SAML token-signing certificate on the service principal
    /// (`addTokenSigningCertificate`); returns the new certificate, including its thumbprint —
    /// activation is the caller setting `preferredTokenSigningKeyThumbprint`.
    ///
    /// Self-invalidates `CacheKind::ServicePrincipal`: this POST appends to `keyCredentials`,
    /// which the cached SP projection `$select`s, and staging ends here (activation is a
    /// separate call) — without this the rollover view would read the pre-stage array back.
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
        let cert = self.send_json(Method::POST, &path, &body).await?;
        self.invalidate_sp_cache();
        Ok(cert)
    }

    /// Removes one `keyCredentials` entry from a **service principal** by `key_id` — the
    /// SP-side twin of [`Self::remove_key_credential`], which only targets applications.
    ///
    /// `keyCredentials` is a full-collection PATCH: this re-reads live state and writes the
    /// whole array back, round-tripping every surviving entry as raw JSON. A dropped entry
    /// deletes a live signing certificate, so a serialization failure must abort rather than
    /// write a partial array.
    ///
    /// `addTokenSigningCertificate` writes **three** objects per certificate, all sharing one
    /// `customKeyIdentifier`: a `Sign` key, a `Verify` key, and a **`passwordCredentials`
    /// entry** (the PFX password). Removing only the key halves stranded that password
    /// credential forever, so this sweeps `passwordCredentials` by the same identifier.
    ///
    /// A `key_id` not on the service principal is `Err(GraphError::NotFound)` and sends no
    /// PATCH (nothing was written, so there is no cache to invalidate) — as for
    /// [`Self::remove_key_credential`].
    pub async fn remove_service_principal_key_credential(
        &self,
        object_id: &str,
        key_id: &str,
    ) -> Result<()> {
        let path = format!("/servicePrincipals/{object_id}");
        let params: [(&str, &str); 1] = [("$select", "keyCredentials,passwordCredentials")];
        let sp: serde_json::Value = self.get_json(&path, &params, false).await?;
        let entries = sp
            .get("keyCredentials")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let passwords = sp
            .get("passwordCredentials")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        // Resolve the target first: an absent key is already gone — a PATCH would rewrite the
        // unchanged arrays and report a removal that never happened.
        let Some(target) = entries
            .iter()
            .find(|c| c.get("keyId").and_then(|v| v.as_str()) == Some(key_id))
        else {
            return Err(GraphError::NotFound(format!(
                "signing key {key_id} is not on the service principal"
            )));
        };
        // Resolve the target's thumbprint so the paired half goes with it.
        let thumbprint = target
            .get("customKeyIdentifier")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let kept: Vec<serde_json::Value> = entries
            .into_iter()
            .filter(|c| {
                let this_key = c.get("keyId").and_then(|v| v.as_str());
                let this_tp = c.get("customKeyIdentifier").and_then(|v| v.as_str());
                match (&thumbprint, this_tp) {
                    // Same certificate (either half of the Sign/Verify pair).
                    (Some(target), Some(tp)) if tp.eq_ignore_ascii_case(target) => false,
                    // No thumbprint to match on — fall back to the exact entry.
                    _ => this_key != Some(key_id),
                }
            })
            .collect();

        // The certificate's PFX password rides `passwordCredentials` under the same
        // `customKeyIdentifier`. Only drop it when a thumbprint is resolved — without one we
        // can't tell which password belongs to the key being retired, and removing the wrong
        // one breaks a live cert.
        let kept_passwords: Vec<serde_json::Value> = passwords
            .into_iter()
            .filter(|c| {
                match (
                    &thumbprint,
                    c.get("customKeyIdentifier").and_then(|v| v.as_str()),
                ) {
                    (Some(target), Some(tp)) => !tp.eq_ignore_ascii_case(target),
                    _ => true,
                }
            })
            .collect();

        let body = serde_json::json!({
            "keyCredentials": kept,
            "passwordCredentials": kept_passwords,
        });
        self.send_no_content(Method::PATCH, &path, Some(&body))
            .await?;
        self.invalidate_sp_cache();
        Ok(())
    }
}
