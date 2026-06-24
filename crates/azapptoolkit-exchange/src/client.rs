use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use serde::de::DeserializeOwned;
use serde_json::json;

use azapptoolkit_core::http_retry::{
    BASE_DELAY_MS, MAX_RETRIES, next_backoff_ms, parse_retry_after_seconds, sleep_before_retry,
    sleep_with_jitter,
};
use azapptoolkit_core::token::BearerProvider;

use crate::error::{
    ExchangeError, Result, is_already_member_body, is_not_a_member_body, is_not_found_body,
};
use crate::models::{
    ExoAppAccessPolicyTestResult, ExoApplicationAccessPolicy, ExoAuthorizationResult, ExoGroup,
    ExoGroupMember, ExoManagementScope, ExoRoleAssignment, ExoServicePrincipal,
};

/// Microsoft 365 / GCC base URL for the Exchange Online Admin API. Other
/// clouds use a different host (e.g. `outlook.office365.us` for GCC High);
/// overridable via [`ExchangeClient::with_base_url`].
pub const EXCHANGE_BASE: &str = "https://outlook.office365.com";

/// The classic Exchange cmdlets that RBAC for Applications relies on
/// (`New-ServicePrincipal`, `New-ManagementRoleAssignment`, …) are proxied
/// through the `InvokeCommand` endpoint rather than a per-cmdlet REST route.
///
/// NOTE (verify during the live transport spike): the path version segment and
/// endpoint name are the single most likely thing to need adjustment against a
/// real tenant. They are isolated here so a fix is a one-line change.
const ADMIN_API_VERSION: &str = "beta";
const INVOKE_ENDPOINT: &str = "InvokeCommand";

const X_ANCHOR_MAILBOX: HeaderName = HeaderName::from_static("x-anchormailbox");

/// Thin client over the Exchange Online Admin API (`/adminapi/.../InvokeCommand`).
///
/// Every call is a POST carrying a `CmdletInput` envelope; the v2.0+ API
/// requires an `X-AnchorMailbox` routing hint on every request, which for the
/// delegated admin flow is the signed-in admin's UPN.
pub struct ExchangeClient {
    http: reqwest::Client,
    token: Arc<dyn BearerProvider>,
    base_url: String,
    tenant_id: String,
    /// `X-AnchorMailbox` header value, e.g. `UPN:admin@contoso.com` — the
    /// `UPN:` prefix matches the ExchangeOnlineManagement module's captured
    /// traffic for this endpoint.
    anchor_mailbox: String,
}

impl ExchangeClient {
    /// `admin_upn` is the signed-in administrator's user principal name; it
    /// becomes the `X-AnchorMailbox` routing hint for the org-level cmdlets
    /// this client issues.
    pub fn new(
        token: Arc<dyn BearerProvider>,
        tenant_id: impl Into<String>,
        admin_upn: &str,
    ) -> Self {
        Self::with_base_url(token, tenant_id, admin_upn, EXCHANGE_BASE)
    }

    pub fn with_base_url(
        token: Arc<dyn BearerProvider>,
        tenant_id: impl Into<String>,
        admin_upn: &str,
        base_url: impl Into<String>,
    ) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("azapptoolkit/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(60))
            .build()
            .expect("reqwest client builds");
        Self {
            http,
            token,
            base_url: base_url.into(),
            tenant_id: tenant_id.into(),
            anchor_mailbox: format!("UPN:{admin_upn}"),
        }
    }

    // ---------------- Service principals ----------------

    /// Registers the Entra service principal pointer in Exchange. Idempotent:
    /// returns the existing pointer if one already exists for `app_id`.
    pub async fn ensure_service_principal(
        &self,
        app_id: &str,
        object_id: &str,
        display_name: &str,
    ) -> Result<ExoServicePrincipal> {
        if let Some(existing) = self.get_service_principal(app_id).await? {
            return Ok(existing);
        }
        let values = self
            .invoke_command(
                "New-ServicePrincipal",
                json!({
                    "AppId": app_id,
                    "ObjectId": object_id,
                    "DisplayName": display_name,
                }),
            )
            .await?;
        first_as(values, "New-ServicePrincipal")
    }

    /// Looks up the Exchange service-principal pointer by AppId, ObjectId, or
    /// DisplayName. Returns `None` if no pointer is registered.
    pub async fn get_service_principal(
        &self,
        identity: &str,
    ) -> Result<Option<ExoServicePrincipal>> {
        let values = self
            .invoke_optional("Get-ServicePrincipal", json!({ "Identity": identity }))
            .await?;
        Ok(values
            .into_iter()
            .next()
            .map(serde_json::from_value)
            .transpose()?)
    }

    /// Every service-principal pointer registered in Exchange (the population
    /// eligible for RBAC-for-Applications role assignments). This is the only
    /// way to discover principals whose mailbox access comes *solely* from
    /// Exchange RBAC — they hold no Graph app-role assignment, so no Graph
    /// query can surface them.
    pub async fn list_service_principals(&self) -> Result<Vec<ExoServicePrincipal>> {
        let values = self
            .invoke_command("Get-ServicePrincipal", json!({}))
            .await?;
        all_as(values)
    }

    // ---------------- Management scopes ----------------

    /// Creates a management scope with the given OPATH recipient filter.
    /// Idempotent: returns the existing scope if `name` already exists.
    pub async fn ensure_management_scope(
        &self,
        name: &str,
        recipient_restriction_filter: &str,
    ) -> Result<ExoManagementScope> {
        if let Some(existing) = self.get_management_scope(name).await? {
            return Ok(existing);
        }
        let values = self
            .invoke_command(
                "New-ManagementScope",
                json!({
                    "Name": name,
                    "RecipientRestrictionFilter": recipient_restriction_filter,
                }),
            )
            .await?;
        first_as(values, "New-ManagementScope")
    }

    pub async fn get_management_scope(&self, name: &str) -> Result<Option<ExoManagementScope>> {
        let values = self
            .invoke_optional("Get-ManagementScope", json!({ "Identity": name }))
            .await?;
        Ok(values
            .into_iter()
            .next()
            .map(serde_json::from_value)
            .transpose()?)
    }

    // ---------------- Role assignments ----------------

    /// Assigns an Exchange application `role` to the service principal `app`
    /// (AppId/ObjectId/DisplayName), optionally constrained to a management
    /// scope. `custom_resource_scope = None` grants org-wide.
    pub async fn new_role_assignment(
        &self,
        app: &str,
        role: &str,
        custom_resource_scope: Option<&str>,
    ) -> Result<ExoRoleAssignment> {
        let mut params = json!({ "App": app, "Role": role });
        if let Some(scope) = custom_resource_scope {
            params["CustomResourceScope"] = json!(scope);
        }
        let values = self
            .invoke_command("New-ManagementRoleAssignment", params)
            .await?;
        first_as(values, "New-ManagementRoleAssignment")
    }

    /// All management role assignments for the service principal `app`.
    pub async fn get_role_assignments(&self, app: &str) -> Result<Vec<ExoRoleAssignment>> {
        let values = self
            .invoke_optional(
                "Get-ManagementRoleAssignment",
                json!({ "RoleAssignee": app }),
            )
            .await?;
        all_as(values)
    }

    pub async fn remove_role_assignment(&self, identity: &str) -> Result<()> {
        self.invoke_command(
            "Remove-ManagementRoleAssignment",
            json!({ "Identity": identity, "Confirm": false }),
        )
        .await?;
        Ok(())
    }

    // ---------------- Groups (scope source) ----------------

    /// Resolves a recipient group to its `DistinguishedName`, which a
    /// `MemberOfGroup` recipient filter must reference. Works for mail-enabled
    /// security groups, Microsoft 365 groups, and distribution lists.
    pub async fn get_group(&self, identity: &str) -> Result<Option<ExoGroup>> {
        let values = self
            .invoke_optional("Get-Group", json!({ "Identity": identity }))
            .await?;
        Ok(values
            .into_iter()
            .next()
            .map(serde_json::from_value)
            .transpose()?)
    }

    // ---------------- Managed scope group (create + membership) ----------------

    /// Looks up a distribution / mail-enabled security group by identity (name,
    /// alias, GUID, SMTP, or DN). Narrower than [`get_group`]: only matches
    /// distribution-list / mail-enabled-security recipients, so it won't collide
    /// with an unrelated object that happens to share the toolkit's name. Returns
    /// `None` if no such group exists.
    pub async fn get_distribution_group(&self, identity: &str) -> Result<Option<ExoGroup>> {
        let values = self
            .invoke_optional("Get-DistributionGroup", json!({ "Identity": identity }))
            .await?;
        Ok(values
            .into_iter()
            .next()
            .map(serde_json::from_value)
            .transpose()?)
    }

    /// Ensures a mail-enabled security group named `name` (alias `alias`) exists,
    /// creating it via `New-DistributionGroup -Type Security` if missing.
    /// Idempotent: returns the existing group when present. `-IgnoreNamingPolicy`
    /// keeps the exact toolkit naming convention so a later lookup by name
    /// resolves it. A freshly created group can return without its
    /// `DistinguishedName` populated, so we re-resolve in that case — the DN is
    /// what a `MemberOfGroup` management-scope filter must reference.
    pub async fn ensure_security_group(&self, name: &str, alias: &str) -> Result<ExoGroup> {
        if let Some(existing) = self.get_distribution_group(name).await? {
            return Ok(existing);
        }
        let values = self
            .invoke_command(
                "New-DistributionGroup",
                json!({
                    "Name": name,
                    "Alias": alias,
                    "Type": "Security",
                    "IgnoreNamingPolicy": true,
                }),
            )
            .await?;
        let created: ExoGroup = first_as(values, "New-DistributionGroup")?;
        if created.distinguished_name.is_some() {
            return Ok(created);
        }
        match self.get_distribution_group(name).await? {
            Some(resolved) => Ok(resolved),
            None => Ok(created),
        }
    }

    /// Adds `member` (a mailbox UPN, SMTP, GUID, …) to `group`. Idempotent:
    /// adding an existing member returns success rather than an error.
    pub async fn add_group_member(&self, group: &str, member: &str) -> Result<()> {
        match self
            .invoke_command(
                "Add-DistributionGroupMember",
                json!({ "Identity": group, "Member": member }),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(ExchangeError::Api { body, .. }) if is_already_member_body(&body) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Removes `member` from `group`. Idempotent: removing a non-member returns
    /// success. `BypassSecurityGroupManagerCheck` lets an admin who isn't listed
    /// as the group's manager still edit membership.
    pub async fn remove_group_member(&self, group: &str, member: &str) -> Result<()> {
        match self
            .invoke_command(
                "Remove-DistributionGroupMember",
                json!({
                    "Identity": group,
                    "Member": member,
                    "Confirm": false,
                    "BypassSecurityGroupManagerCheck": true,
                }),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(ExchangeError::Api { body, .. }) if is_not_a_member_body(&body) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Lists the direct members of `group`. Returns an empty list when the group
    /// doesn't exist (via [`invoke_optional`]).
    ///
    /// [`invoke_optional`]: Self::invoke_optional
    pub async fn list_group_members(&self, group: &str) -> Result<Vec<ExoGroupMember>> {
        let values = self
            .invoke_optional("Get-DistributionGroupMember", json!({ "Identity": group }))
            .await?;
        all_as(values)
    }

    // ---------------- Legacy Application Access Policies (migration) ----------------

    pub async fn get_application_access_policies(&self) -> Result<Vec<ExoApplicationAccessPolicy>> {
        let values = self
            .invoke_optional("Get-ApplicationAccessPolicy", json!({}))
            .await?;
        all_as(values)
    }

    pub async fn remove_application_access_policy(&self, identity: &str) -> Result<()> {
        self.invoke_command(
            "Remove-ApplicationAccessPolicy",
            json!({ "Identity": identity, "Confirm": false }),
        )
        .await?;
        Ok(())
    }

    // ---------------- Verification ----------------

    /// Simulates the access a service principal has, optionally against a
    /// specific `resource` mailbox. Bypasses the RBAC propagation cache, so it
    /// is the reliable check immediately after granting access.
    pub async fn test_service_principal_authorization(
        &self,
        identity: &str,
        resource: Option<&str>,
    ) -> Result<Vec<ExoAuthorizationResult>> {
        let mut params = json!({ "Identity": identity });
        if let Some(res) = resource {
            params["Resource"] = json!(res);
        }
        let values = self
            .invoke_command("Test-ServicePrincipalAuthorization", params)
            .await?;
        all_as(values)
    }

    /// Live evaluation of the legacy Application Access Policy gate: can
    /// `app_id`'s **Entra-granted** permissions reach `mailbox`? This is the
    /// complement of [`test_service_principal_authorization`]: AAPs constrain
    /// only the Microsoft Entra ID grants (never Exchange RBAC assignments),
    /// while `Test-ServicePrincipalAuthorization` sees only the RBAC layer —
    /// actual access is the union of the two answers.
    ///
    /// [`test_service_principal_authorization`]: Self::test_service_principal_authorization
    pub async fn test_application_access_policy(
        &self,
        app_id: &str,
        mailbox: &str,
    ) -> Result<ExoAppAccessPolicyTestResult> {
        let values = self
            .invoke_command(
                "Test-ApplicationAccessPolicy",
                json!({ "AppId": app_id, "Identity": mailbox }),
            )
            .await?;
        first_as(values, "Test-ApplicationAccessPolicy")
    }

    // ---------------- Transport ----------------

    /// POSTs a `CmdletInput` envelope and returns the parsed `value` array.
    async fn invoke_command(
        &self,
        cmdlet: &str,
        parameters: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>> {
        let url = format!(
            "{}/adminapi/{}/{}/{}",
            self.base_url.trim_end_matches('/'),
            ADMIN_API_VERSION,
            self.tenant_id,
            INVOKE_ENDPOINT
        );
        let body = json!({
            "CmdletInput": { "CmdletName": cmdlet, "Parameters": parameters }
        });
        let bytes = self.send_core(cmdlet, &url, &body).await?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        #[derive(serde::Deserialize)]
        struct Envelope {
            #[serde(default)]
            value: Vec<serde_json::Value>,
        }
        let env: Envelope = serde_json::from_slice(&bytes)
            .map_err(|e| ExchangeError::Deserialize(e.to_string()))?;
        Ok(env.value)
    }

    /// Like [`invoke_command`] but maps a "not found" cmdlet error (the EXO
    /// `Get-*` cmdlets throw when an `-Identity` doesn't resolve) to an empty
    /// result, so callers can treat a missing object as `None`.
    async fn invoke_optional(
        &self,
        cmdlet: &str,
        parameters: serde_json::Value,
    ) -> Result<Vec<serde_json::Value>> {
        match self.invoke_command(cmdlet, parameters).await {
            Ok(values) => Ok(values),
            Err(ExchangeError::NotFound(_)) => Ok(Vec::new()),
            Err(ExchangeError::Api { body, .. }) if is_not_found_body(&body) => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    async fn send_core(
        &self,
        cmdlet: &str,
        url: &str,
        body: &serde_json::Value,
    ) -> Result<bytes::Bytes> {
        let bearer = self.token.bearer().await.map_err(ExchangeError::Token)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}"))
                .map_err(|e| ExchangeError::Token(e.to_string()))?,
        );
        headers.insert(
            X_ANCHOR_MAILBOX,
            HeaderValue::from_str(&self.anchor_mailbox)
                .map_err(|e| ExchangeError::Protocol(e.to_string()))?,
        );

        let mut attempt = 0u32;
        let mut delay_ms = BASE_DELAY_MS;
        loop {
            let resp = self
                .http
                .post(url)
                .headers(headers.clone())
                .json(body)
                .send()
                .await;
            let resp = match resp {
                Ok(r) => r,
                Err(err) => {
                    if attempt < MAX_RETRIES {
                        tracing::warn!(%attempt, ?err, "transport error; retrying");
                        sleep_with_jitter(delay_ms).await;
                        attempt += 1;
                        delay_ms = next_backoff_ms(delay_ms);
                        continue;
                    }
                    return Err(ExchangeError::Network(err.to_string()));
                }
            };

            let status = resp.status();
            if status.is_success() {
                return resp
                    .bytes()
                    .await
                    .map_err(|e| ExchangeError::Network(e.to_string()));
            }

            let retry_after = parse_retry_after_seconds(
                resp.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            // The EXO admin endpoint returns its real authorization reason in the
            // `x-ms-diagnostics` header, not the body (a 403 body is typically a
            // NUL-padded blob). Capture the diagnostic headers so the surfaced
            // error names *why* and *which request*, not just `<no body>`.
            let header_str = |name: &str| {
                resp.headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let diagnostics = header_str("x-ms-diagnostics");
            let request_id = header_str("request-id").or_else(|| header_str("x-ms-request-id"));
            // On a bodyless rejection the auth middleware's reason (if any)
            // rides `WWW-Authenticate` — captured for the log line below.
            let www_authenticate = header_str("www-authenticate");
            let raw_body = resp.text().await.unwrap_or_default();
            let body_text = compose_error_detail(cmdlet, &raw_body, &diagnostics, &request_id);
            let code = status.as_u16();
            // Any non-429 4xx is a terminal client error (401/403/404 get their
            // own variants below; everything else falls through to `Api`).
            let is_client_4xx = (400..500).contains(&code) && code != 429;

            if code == 401 {
                return Err(ExchangeError::Unauthorized);
            }
            if is_client_4xx {
                tracing::warn!(
                    cmdlet,
                    status = code,
                    diagnostics = diagnostics.as_deref().unwrap_or(""),
                    request_id = request_id.as_deref().unwrap_or(""),
                    www_authenticate = www_authenticate.as_deref().unwrap_or(""),
                    "exchange admin cmdlet rejected"
                );
            }
            if code == 403 {
                // Whether EXO named an RBAC reason (`x-ms-diagnostics`) vs. a
                // bodyless/reasonless 403 — `ui_hint` branches on this so a stale
                // role token isn't misreported as a definite Exchange RBAC gap.
                let had_diagnostics = diagnostics
                    .as_deref()
                    .map(str::trim)
                    .is_some_and(|d| !d.is_empty());
                return Err(ExchangeError::Forbidden {
                    detail: body_text,
                    had_diagnostics,
                });
            }
            if code == 404 {
                return Err(ExchangeError::NotFound(body_text));
            }
            if is_client_4xx {
                return Err(ExchangeError::Api {
                    status: code,
                    body: body_text,
                });
            }

            // Retryable (429, 5xx). An explicit `Retry-After` is waited exactly
            // (no jitter / no 30s clamp); only the no-header path uses backoff.
            if attempt < MAX_RETRIES {
                tracing::warn!(%attempt, status = %status, retry_after_secs = ?retry_after, "transient error; retrying");
                sleep_before_retry(retry_after, delay_ms).await;
                attempt += 1;
                delay_ms = next_backoff_ms(delay_ms);
                continue;
            }

            return if code == 429 {
                Err(ExchangeError::Throttled {
                    retry_after_secs: retry_after,
                })
            } else {
                Err(ExchangeError::Server {
                    status: code,
                    body: body_text,
                })
            };
        }
    }
}

/// Builds an OPATH `MemberOfGroup` recipient filter for a management scope,
/// OR-ing across multiple group distinguished names. The DNs are obtained via
/// [`ExchangeClient::get_group`].
pub fn member_of_group_filter(distinguished_names: &[String]) -> String {
    distinguished_names
        .iter()
        .map(|dn| format!("MemberOfGroup -eq '{}'", escape_opath(dn)))
        .collect::<Vec<_>>()
        .join(" -or ")
}

/// OPATH single-quoted-string escape: a `'` inside the literal becomes `''`.
fn escape_opath(input: &str) -> String {
    input.replace('\'', "''")
}

/// Normalizes an HTTP error-response body before it is stored in an
/// [`ExchangeError`]. Exchange/edge responses are sometimes binary or
/// NUL-padded (e.g. a 403 from a front-end proxy returns a long run of `\0`),
/// which otherwise pollutes logs and surfaced error messages. Strips control
/// characters (keeping ordinary whitespace), trims, and caps the length;
/// returns `<no body>` when nothing printable remains.
fn sanitize_error_body(raw: &str) -> String {
    const MAX_CHARS: usize = 800;
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        return "<no body>".to_string();
    }
    let mut out: String = trimmed.chars().take(MAX_CHARS).collect();
    if trimmed.chars().count() > MAX_CHARS {
        out.push('…');
    }
    out
}

/// Builds the human-readable detail stored in a client/server `ExchangeError`.
/// EXO puts the real authorization reason in `x-ms-diagnostics` rather than the
/// (often NUL-padded, empty) response body, so prefer the diagnostics header and
/// fall back to the sanitized body. The detail is prefixed with the originating
/// `cmdlet` and suffixed with the `request-id` (when present) so a 403 names both
/// *why* and *which request* instead of the old opaque `<no body>`.
fn compose_error_detail(
    cmdlet: &str,
    raw_body: &str,
    diagnostics: &Option<String>,
    request_id: &Option<String>,
) -> String {
    let reason = match diagnostics.as_deref().map(str::trim) {
        Some(d) if !d.is_empty() => sanitize_error_body(d),
        _ => sanitize_error_body(raw_body),
    };
    let mut out = format!("[{cmdlet}] {reason}");
    if let Some(id) = request_id.as_deref().map(str::trim)
        && !id.is_empty()
    {
        out.push_str(&format!(" (request-id: {id})"));
    }
    out
}

fn first_as<T: DeserializeOwned>(values: Vec<serde_json::Value>, cmdlet: &str) -> Result<T> {
    let v = values
        .into_iter()
        .next()
        .ok_or_else(|| ExchangeError::Api {
            status: 200,
            body: format!("{cmdlet} returned no object"),
        })?;
    serde_json::from_value(v).map_err(|e| ExchangeError::Deserialize(e.to_string()))
}

fn all_as<T: DeserializeOwned>(values: Vec<serde_json::Value>) -> Result<Vec<T>> {
    values
        .into_iter()
        .map(|v| serde_json::from_value(v).map_err(|e| ExchangeError::Deserialize(e.to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn make_client(base: &str) -> ExchangeClient {
        let token = StaticTokenProvider::new("tok");
        ExchangeClient::with_base_url(token, "tenant-1", "admin@contoso.com", base.to_string())
    }

    fn invoke_path() -> String {
        format!("/adminapi/{ADMIN_API_VERSION}/tenant-1/{INVOKE_ENDPOINT}")
    }

    #[tokio::test]
    async fn new_service_principal_posts_cmdlet_envelope_with_anchor() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(header("authorization", "Bearer tok"))
            .and(header("x-anchormailbox", "UPN:admin@contoso.com"))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "New-ServicePrincipal",
                    "Parameters": {
                        "AppId": "app-1",
                        "ObjectId": "obj-1",
                        "DisplayName": "Demo"
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{ "AppId": "app-1", "ObjectId": "obj-1", "DisplayName": "Demo" }]
            })))
            .mount(&server)
            .await;

        // get-first lookup returns nothing so we fall through to New-.
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "Get-ServicePrincipal",
                    "Parameters": { "Identity": "app-1" }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .mount(&server)
            .await;

        let client = make_client(&server.uri());
        let sp = client
            .ensure_service_principal("app-1", "obj-1", "Demo")
            .await
            .unwrap();
        assert_eq!(sp.app_id.as_deref(), Some("app-1"));
        assert_eq!(sp.object_id.as_deref(), Some("obj-1"));
    }

    #[tokio::test]
    async fn ensure_service_principal_skips_new_when_present() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "Get-ServicePrincipal",
                    "Parameters": { "Identity": "app-1" }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{ "AppId": "app-1", "ObjectId": "obj-existing", "DisplayName": "Existing" }]
            })))
            .mount(&server)
            .await;
        // No New-ServicePrincipal mock registered: any such call 404s and fails.
        let client = make_client(&server.uri());
        let sp = client
            .ensure_service_principal("app-1", "obj-1", "Demo")
            .await
            .unwrap();
        assert_eq!(sp.object_id.as_deref(), Some("obj-existing"));
    }

    #[tokio::test]
    async fn new_role_assignment_includes_scope_when_present() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "New-ManagementRoleAssignment",
                    "Parameters": {
                        "App": "app-1",
                        "Role": "Application Mail.Read",
                        "CustomResourceScope": "azapptoolkit_app-1"
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "Name": "ra-1",
                    "Role": "Application Mail.Read",
                    "RoleAssigneeName": "app-1",
                    "CustomResourceScope": "azapptoolkit_app-1",
                    "Identity": "ra-1"
                }]
            })))
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let ra = client
            .new_role_assignment("app-1", "Application Mail.Read", Some("azapptoolkit_app-1"))
            .await
            .unwrap();
        assert_eq!(ra.role.as_deref(), Some("Application Mail.Read"));
    }

    #[tokio::test]
    async fn list_service_principals_posts_empty_params() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "Get-ServicePrincipal",
                    "Parameters": {}
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    { "AppId": "app-1", "ObjectId": "obj-1", "DisplayName": "Demo" },
                    { "AppId": "app-2", "ObjectId": "obj-2", "DisplayName": "Other" }
                ]
            })))
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let sps = client.list_service_principals().await.unwrap();
        assert_eq!(sps.len(), 2);
        assert_eq!(sps[1].object_id.as_deref(), Some("obj-2"));
    }

    #[tokio::test]
    async fn test_application_access_policy_posts_app_and_identity() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "Test-ApplicationAccessPolicy",
                    "Parameters": { "AppId": "app-1", "Identity": "user@contoso.com" }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "AppId": "app-1",
                    "Mailbox": "user",
                    "AccessCheckResult": "Denied"
                }]
            })))
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let result = client
            .test_application_access_policy("app-1", "user@contoso.com")
            .await
            .unwrap();
        assert_eq!(result.granted, Some(false));
    }

    #[tokio::test]
    async fn get_group_returns_none_on_not_found_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                "The operation couldn't be performed because object 'x' couldn't be found.",
            ))
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let group = client.get_group("missing").await.unwrap();
        assert!(group.is_none());
    }

    #[tokio::test]
    async fn ensure_security_group_creates_when_missing() {
        let server = MockServer::start().await;
        // Get-first lookup returns nothing → fall through to New-.
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "Get-DistributionGroup",
                    "Parameters": { "Identity": "azapptoolkit_app-1" }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "New-DistributionGroup",
                    "Parameters": {
                        "Name": "azapptoolkit_app-1",
                        "Alias": "azapptoolkit_app-1",
                        "Type": "Security",
                        "IgnoreNamingPolicy": true
                    }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "DistinguishedName": "CN=azapptoolkit_app-1,OU=contoso,DC=prod",
                    "PrimarySmtpAddress": "azapptoolkit_app-1@contoso.com",
                    "Name": "azapptoolkit_app-1"
                }]
            })))
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let g = client
            .ensure_security_group("azapptoolkit_app-1", "azapptoolkit_app-1")
            .await
            .unwrap();
        assert_eq!(
            g.distinguished_name.as_deref(),
            Some("CN=azapptoolkit_app-1,OU=contoso,DC=prod")
        );
    }

    #[tokio::test]
    async fn ensure_security_group_reuses_existing() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "Get-DistributionGroup",
                    "Parameters": { "Identity": "azapptoolkit_app-1" }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "DistinguishedName": "CN=existing,DC=prod",
                    "Name": "azapptoolkit_app-1"
                }]
            })))
            .mount(&server)
            .await;
        // No New-DistributionGroup mock: creating again would 404 and fail.
        let client = make_client(&server.uri());
        let g = client
            .ensure_security_group("azapptoolkit_app-1", "azapptoolkit_app-1")
            .await
            .unwrap();
        assert_eq!(g.distinguished_name.as_deref(), Some("CN=existing,DC=prod"));
    }

    #[tokio::test]
    async fn add_group_member_swallows_already_member() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .respond_with(ResponseTemplate::new(400).set_body_string(
                "The recipient \"user@contoso.com\" is already a member of the group.",
            ))
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        // A 400 "already a member" must resolve to Ok (idempotent re-add).
        client
            .add_group_member("azapptoolkit_app-1", "user@contoso.com")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn remove_group_member_swallows_not_a_member() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .respond_with(
                ResponseTemplate::new(400).set_body_string(
                    "The recipient \"user@contoso.com\" isn't a member of the group.",
                ),
            )
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        client
            .remove_group_member("azapptoolkit_app-1", "user@contoso.com")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_group_members_projects_recipients() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .and(body_json(json!({
                "CmdletInput": {
                    "CmdletName": "Get-DistributionGroupMember",
                    "Parameters": { "Identity": "azapptoolkit_app-1" }
                }
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    { "DisplayName": "Ada", "PrimarySmtpAddress": "ada@contoso.com", "RecipientType": "UserMailbox" },
                    { "DisplayName": "Bo", "PrimarySmtpAddress": "bo@contoso.com", "RecipientType": "UserMailbox" }
                ]
            })))
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let members = client
            .list_group_members("azapptoolkit_app-1")
            .await
            .unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(
            members[0].primary_smtp_address.as_deref(),
            Some("ada@contoso.com")
        );
    }

    #[tokio::test]
    async fn unauthorized_maps_to_typed_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let err = client.get_application_access_policies().await.unwrap_err();
        assert!(matches!(err, ExchangeError::Unauthorized));
    }

    #[tokio::test]
    async fn retry_after_is_honored_on_429() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let policies = client.get_application_access_policies().await.unwrap();
        assert!(policies.is_empty());
    }

    #[test]
    fn member_of_group_filter_ors_multiple_dns() {
        let f = member_of_group_filter(&["CN=a,DC=x".to_string(), "CN=b,DC=y".to_string()]);
        assert_eq!(
            f,
            "MemberOfGroup -eq 'CN=a,DC=x' -or MemberOfGroup -eq 'CN=b,DC=y'"
        );
    }

    #[test]
    fn escape_opath_doubles_quotes() {
        assert_eq!(escape_opath("O'Brien"), "O''Brien");
    }

    #[test]
    fn sanitize_error_body_strips_nul_padding_trims_and_caps() {
        // A NUL-padded 403 body (observed from an edge proxy) collapses to the
        // placeholder rather than a screenful of escaped \0 in the logs.
        assert_eq!(sanitize_error_body(&"\0".repeat(256)), "<no body>");
        // Control chars are stripped; ordinary text + whitespace survive trimmed.
        assert_eq!(sanitize_error_body("  Forbidden\0\u{7}  "), "Forbidden");
        assert_eq!(sanitize_error_body("line1\nline2"), "line1\nline2");
        // Over-long bodies are capped with an ellipsis marker.
        let out = sanitize_error_body(&"x".repeat(1000));
        assert!(out.ends_with('…'));
        assert_eq!(out.chars().count(), 801);
    }

    #[test]
    fn compose_error_detail_prefers_diagnostics_and_names_cmdlet() {
        // Empty body but a populated x-ms-diagnostics header: the reason comes
        // from the header, the cmdlet is named, and the request id is appended.
        let detail = compose_error_detail(
            "New-ManagementRoleAssignment",
            &"\0".repeat(64),
            &Some("2000003;reason=\"role required\"".to_string()),
            &Some("abc-123".to_string()),
        );
        assert!(detail.starts_with("[New-ManagementRoleAssignment] "));
        assert!(detail.contains("role required"));
        assert!(detail.contains("(request-id: abc-123)"));
        assert!(!detail.contains("<no body>"));
    }

    #[test]
    fn compose_error_detail_falls_back_to_no_body_when_nothing_present() {
        // No diagnostics and an empty/NUL body: still `<no body>`, but now the
        // failing cmdlet is identified.
        let detail = compose_error_detail("Get-Group", &"\0".repeat(16), &None, &None);
        assert_eq!(detail, "[Get-Group] <no body>");
    }

    #[tokio::test]
    async fn forbidden_surfaces_diagnostics_header_reason() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("x-ms-diagnostics", "2000003;reason=\"role required\"")
                    .insert_header("request-id", "req-9")
                    .set_body_string("\0\0\0"),
            )
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let err = client.get_application_access_policies().await.unwrap_err();
        match err {
            ExchangeError::Forbidden {
                detail,
                had_diagnostics,
            } => {
                assert!(detail.contains("Get-ApplicationAccessPolicy"));
                assert!(detail.contains("role required"));
                assert!(detail.contains("req-9"));
                // x-ms-diagnostics was present → the confident RBAC hint applies.
                assert!(had_diagnostics);
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn forbidden_without_diagnostics_is_flagged_reasonless() {
        // A 403 with neither an x-ms-diagnostics reason nor a body (only a
        // request-id) — the shape a stale role token produces. It must be flagged
        // `had_diagnostics: false` so the UI hint avoids asserting a definite
        // Exchange RBAC gap (see `ExchangeError::ui_hint`).
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(invoke_path()))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("request-id", "req-7")
                    .set_body_string("\0\0\0"),
            )
            .mount(&server)
            .await;
        let client = make_client(&server.uri());
        let err = client.get_application_access_policies().await.unwrap_err();
        match err {
            ExchangeError::Forbidden {
                detail,
                had_diagnostics,
            } => {
                assert!(!had_diagnostics);
                assert!(detail.contains("<no body>"));
                assert!(detail.contains("req-7"));
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }
}
