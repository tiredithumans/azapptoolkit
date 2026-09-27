use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    #[error("not signed in")]
    NotSignedIn,

    #[error("refresh token missing for tenant {0}; re-authentication required")]
    RefreshTokenMissing(String),

    /// AAD returned `invalid_grant` for a dead refresh token (e.g. AADSTS70008
    /// expired, 70000 revoked, 50173 invalidated by a password change) — it is
    /// no longer usable and must be discarded. A consent gap
    /// ([`AuthError::ConsentRequired`]) or a Conditional Access step-up
    /// ([`AuthError::InteractionRequired`]) is classified first and never lands
    /// here. The string carries the redacted AAD code for tracing only; do not
    /// show it to users.
    #[error("refresh token rejected by AAD ({0}); re-authentication required")]
    InvalidGrant(String),

    /// AAD refused a *silent* token request because the user or tenant admin
    /// has not consented to the requested scope(s) (AADSTS65001/65004). Unlike
    /// [`AuthError::InvalidGrant`], the refresh token is still valid — only
    /// interactive incremental consent is missing, so the caller should NOT
    /// purge it. Recover via [`crate::EntraAuthService::consent_for_scopes`].
    /// The string carries AAD's code for tracing; show users a generic message.
    #[error("consent required for the requested permissions ({0})")]
    ConsentRequired(String),

    /// AAD requires the user to complete an interactive step — MFA,
    /// registration, or an external challenge a Conditional Access policy
    /// demands for THIS resource (`interaction_required` / `login_required`, or
    /// `invalid_grant` with AADSTS50074/50076/50079/50158). The refresh token is
    /// still valid for other audiences (MSAL keeps the account on
    /// `InteractionRequiredAuthError`), so it must NOT be purged. Recover via
    /// [`crate::EntraAuthService::step_up_for_scopes`]. The string carries the
    /// redacted AAD code for tracing; show users a generic message.
    #[error("additional verification required for this resource ({0})")]
    InteractionRequired(String),

    #[error("token exchange failed: {0}")]
    TokenExchange(String),

    #[error("authorization request failed: {0}")]
    Authorization(String),

    #[error("loopback listener failed: {0}")]
    Loopback(String),

    /// The loopback listener no longer produces this: a redirect with a
    /// foreign or missing `state` is answered 400 and ignored rather than
    /// ending the sign-in. Kept for the public, `non_exhaustive` API and its
    /// DTO mapping.
    #[error("state mismatch on redirect — possible CSRF")]
    StateMismatch,

    /// The browser round trip was abandoned: the redirect never arrived within
    /// the wait (the tab was closed), or the operator cancelled at Entra
    /// (`access_denied` with no AADSTS code / `error_subcode=cancel`).
    #[error("sign-in was cancelled or not completed in the browser")]
    Cancelled,

    #[error("keyring: {0}")]
    Keyring(String),

    /// Rendered with its cause chain: reqwest's own Display stops at "error
    /// sending request for url (…)", hiding DNS / connect / TLS / proxy on the
    /// sign-in card.
    #[error("http: {}", azapptoolkit_core::http_error::describe_error_chain(.0))]
    Http(#[from] reqwest::Error),

    #[error("url: {0}")]
    Url(#[from] url::ParseError),

    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<keyring_core::Error> for AuthError {
    fn from(value: keyring_core::Error) -> Self {
        AuthError::Keyring(value.to_string())
    }
}
