use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("not signed in")]
    NotSignedIn,

    #[error("refresh token missing for tenant {0}; re-authentication required")]
    RefreshTokenMissing(String),

    /// AAD returned `invalid_grant` / `interaction_required` / etc. — the
    /// refresh token is no longer usable and must be discarded. The string
    /// carries AAD's description for tracing only; do not show it to users.
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

    #[error("token exchange failed: {0}")]
    TokenExchange(String),

    #[error("authorization request failed: {0}")]
    Authorization(String),

    #[error("loopback listener failed: {0}")]
    Loopback(String),

    #[error("state mismatch on redirect — possible CSRF")]
    StateMismatch,

    #[error("user cancelled sign-in")]
    Cancelled,

    #[error("keyring: {0}")]
    Keyring(String),

    #[error("http: {0}")]
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
