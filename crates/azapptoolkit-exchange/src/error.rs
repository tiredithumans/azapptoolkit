use thiserror::Error;

pub type Result<T> = std::result::Result<T, ExchangeError>;

/// Errors from the Exchange Online Admin API. Mirrors `GraphError` so the
/// desktop layer can map both into a single `UiError` shape.
#[derive(Debug, Error)]
pub enum ExchangeError {
    #[error("unauthorized (401)")]
    Unauthorized,

    /// `had_diagnostics` records whether the 403 response carried a non-empty
    /// `x-ms-diagnostics` header — i.e. the EXO RBAC engine named a reason.
    /// `false` is a bodyless, reasonless 403 (typically a stale role token or an
    /// edge/front-door rejection), which must NOT be surfaced as a definite
    /// Exchange RBAC gap. See [`ExchangeError::ui_hint`].
    #[error("forbidden (403): {detail}")]
    Forbidden {
        detail: String,
        had_diagnostics: bool,
    },

    #[error("not found (404): {0}")]
    NotFound(String),

    #[error("throttled (429); retry after {retry_after_secs:?}s")]
    Throttled { retry_after_secs: Option<u64> },

    #[error("server error ({status}): {body}")]
    Server { status: u16, body: String },

    /// A cmdlet ran but returned an error (e.g. 400 Bad Request for an
    /// unsupported parameter, or a cmdlet-level failure).
    #[error("exchange error ({status}): {body}")]
    Api { status: u16, body: String },

    #[error("network: {0}")]
    Network(String),

    #[error("deserialize: {0}")]
    Deserialize(String),

    #[error("token: {0}")]
    Token(String),

    #[error("protocol: {0}")]
    Protocol(String),
}

impl From<serde_json::Error> for ExchangeError {
    fn from(value: serde_json::Error) -> Self {
        ExchangeError::Deserialize(value.to_string())
    }
}

impl ExchangeError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ExchangeError::Throttled { .. }
                | ExchangeError::Server { .. }
                | ExchangeError::Network(_)
        )
    }

    pub fn ui_code(&self) -> &'static str {
        match self {
            ExchangeError::Unauthorized => "unauthorized",
            ExchangeError::Forbidden { .. } => "forbidden",
            ExchangeError::NotFound(_) => "not_found",
            ExchangeError::Throttled { .. } => "throttled",
            ExchangeError::Server { .. } => "server_error",
            ExchangeError::Api { .. } => "exchange_error",
            ExchangeError::Network(_) => "network_error",
            ExchangeError::Deserialize(_) => "deserialize_error",
            ExchangeError::Token(_) => "token_error",
            ExchangeError::Protocol(_) => "protocol_error",
        }
    }

    /// Actionable guidance appended to the raw message when surfacing the error
    /// to a user. The hint for a 403 branches on whether EXO named a reason in
    /// `x-ms-diagnostics` (the `Forbidden { had_diagnostics }` flag):
    /// - **With** a diagnostic reason, the RBAC engine actually evaluated and
    ///   denied the caller, so a missing Exchange management role (e.g. the
    ///   "Role Management" role held by "Organization Management") is the
    ///   credible cause — `Exchange.Manage` only grants impersonation, not the
    ///   right to run cmdlets like `Test-ServicePrincipalAuthorization`.
    /// - **Without** one (a bodyless, reasonless 403 — only a request-id), it is
    ///   usually *not* a missing role: most often the access token predates a
    ///   just-activated PIM role (stale role claim), or an "Exchange
    ///   Administrator" activation hasn't propagated to Exchange yet. Asserting a
    ///   definite RBAC gap there sends users to fix a role they already hold, so
    ///   the hint leads with the token-refresh / propagation causes instead.
    pub fn ui_hint(&self) -> Option<&'static str> {
        match self {
            // EXO named an RBAC reason → a missing role is the credible cause.
            // Source the role guidance from the capability catalog (the single
            // source of truth), matching the ARM/Key Vault ui_hints — so an
            // Exchange role/wording change updates here too. The token-shape
            // branches below have no catalog analog and stay inline.
            ExchangeError::Forbidden {
                had_diagnostics: true,
                ..
            } => azapptoolkit_core::capabilities::capability("exchange_rbac").map(|c| c.remediation),
            // No diagnostic reason → don't assert a definite RBAC gap; lead with
            // the stale-token and propagation causes and the Refresh token lever.
            ExchangeError::Forbidden {
                had_diagnostics: false,
                ..
            } => Some(
                "Exchange rejected this request without a diagnostic reason, which usually is NOT \
                 a missing Exchange role. Most common causes after activating a role: (1) your \
                 access token predates the activation, so its role claim is stale — use \"Refresh \
                 token\" (next to Sign out), then retry; (2) an \"Exchange Administrator\" \
                 activation that hasn't finished propagating to Exchange yet — wait a few minutes \
                 and retry; (3) only if neither helps, a genuine Exchange RBAC gap — confirm your \
                 account holds the \"Role Management\" role (e.g. Organization Management).",
            ),
            ExchangeError::Unauthorized => Some(
                "Your Exchange admin-API token was rejected. Sign out and back in; if it persists, \
                 confirm the app registration has the delegated \"Office 365 Exchange Online → \
                 Exchange.Manage\" permission with admin consent.",
            ),
            _ => None,
        }
    }

    /// True when the error means Exchange couldn't resolve the *object* a cmdlet
    /// referenced — a 404, or a cmdlet-level "couldn't be found" (EXO returns
    /// these as 400s carrying a `ManagementObjectNotFound` body). For
    /// `Test-ServicePrincipalAuthorization` this is the managed-identity case:
    /// the principal was never registered in Exchange RBAC, so it simply has no
    /// Exchange scope — its mailbox reach is whatever its Graph app-role grant
    /// confers. Distinct from a 403 (the caller can't run the cmdlet at all),
    /// which is genuinely indeterminate.
    pub fn is_missing_object(&self) -> bool {
        match self {
            ExchangeError::NotFound(_) => true,
            ExchangeError::Api { body, .. } => is_not_found_body(body),
            _ => false,
        }
    }
}

/// True when an Exchange error body indicates a missing object — the EXO `Get-*`
/// / `Test-*` cmdlets throw a `ManagementObjectNotFound` (surfaced as a 400 with
/// one of these phrases) when an `-Identity` doesn't resolve. Shared by
/// [`ExchangeError::is_missing_object`] and the client's `invoke_optional`.
pub(crate) fn is_not_found_body(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("couldn't be found")
        || lower.contains("wasn't found")
        || lower.contains("not found")
        || lower.contains("managementobjectnotfound")
}

/// True when `Add-DistributionGroupMember` failed only because the recipient is
/// already in the group (EXO returns a 400 with "is already a member of the
/// group"). Lets the client treat a re-add as success, so adding the same
/// mailbox twice is idempotent.
pub(crate) fn is_already_member_body(body: &str) -> bool {
    body.to_ascii_lowercase().contains("already a member")
}

/// True when `Remove-DistributionGroupMember` failed only because the recipient
/// isn't in the group (EXO returns a 400 with "isn't a member of the group").
/// Lets the client treat removing a non-member as success, so removal is
/// idempotent.
pub(crate) fn is_not_a_member_body(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    lower.contains("isn't a member") || lower.contains("not a member")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_object_true_for_not_found_and_cmdlet_not_found_body() {
        assert!(ExchangeError::NotFound("object couldn't be found".into()).is_missing_object());
        assert!(ExchangeError::Api {
            status: 400,
            body: "[Test-ServicePrincipalAuthorization] The operation couldn't be found...".into(),
        }
        .is_missing_object());
        assert!(ExchangeError::Api {
            status: 400,
            body: "ManagementObjectNotFoundException".into(),
        }
        .is_missing_object());
    }

    #[test]
    fn missing_object_false_for_forbidden_unauthorized_and_unrelated_api() {
        assert!(!ExchangeError::Forbidden {
            detail: "RBAC denied".into(),
            had_diagnostics: true,
        }
        .is_missing_object());
        assert!(!ExchangeError::Unauthorized.is_missing_object());
        assert!(!ExchangeError::Api {
            status: 400,
            body: "A parameter is invalid".into(),
        }
        .is_missing_object());
    }

    #[test]
    fn membership_body_matchers_are_specific() {
        // Add: only "already a member" is benign (idempotent re-add).
        assert!(is_already_member_body(
            "[Add-DistributionGroupMember] The recipient \"user\" is already a member of the group."
        ));
        assert!(!is_already_member_body("some other failure"));
        // Remove: only "isn't a member" / "not a member" is benign.
        assert!(is_not_a_member_body(
            "[Remove-DistributionGroupMember] The recipient \"user\" isn't a member of the group."
        ));
        assert!(is_not_a_member_body("user is not a member of the group"));
        assert!(!is_not_a_member_body("some other failure"));
    }

    #[test]
    fn forbidden_hint_branches_on_diagnostics_presence() {
        // EXO named an RBAC reason (x-ms-diagnostics present) → keep the
        // confident role guidance, and don't point at the token-refresh lever.
        let with_diag = ExchangeError::Forbidden {
            detail: "[Test-ServicePrincipalAuthorization] role required".into(),
            had_diagnostics: true,
        }
        .ui_hint()
        .expect("forbidden always has a hint");
        assert!(with_diag.contains("Role Management"));
        assert!(!with_diag.contains("Refresh token"));

        // Bodyless / reasonless 403 (the stale-PIM-token shape) → do NOT assert a
        // definite RBAC gap: lead with the stale-token + propagation causes and
        // the "Refresh token" affordance, with the role gap only as a last resort.
        let no_diag = ExchangeError::Forbidden {
            detail: "[Test-ServicePrincipalAuthorization] <no body> (request-id: x)".into(),
            had_diagnostics: false,
        }
        .ui_hint()
        .expect("forbidden always has a hint");
        assert!(no_diag.contains("Refresh token"));
        assert!(no_diag.contains("stale"));
        assert!(no_diag.contains("propagat"));
        assert!(no_diag.contains("Role Management"));
    }
}
