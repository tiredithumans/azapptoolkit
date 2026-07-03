use std::sync::Arc;
use std::time::Duration;

use reqwest::header::HeaderName;

use azapptoolkit_core::token::BearerProvider;

mod groups;
mod rbac;
mod transport;

#[cfg(test)]
mod tests;

pub use groups::member_of_group_filter;

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
///
/// The surface is split by concern: [`transport`] owns the envelope POST +
/// retry loop (and the bodyless-403 diagnostics capture), [`rbac`] the
/// RBAC-for-Applications cmdlets (service principals / scopes / role
/// assignments / legacy AAP / verification), [`groups`] the recipient-group
/// scope sources and the managed scope group.
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
}
