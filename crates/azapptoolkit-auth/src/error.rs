use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuthError>;

/// Every way the Entra sign-in / token path can fail.
///
/// Exhaustive on purpose (no `#[non_exhaustive]`): the crate is
/// workspace-internal (`publish = false`), and `From<AuthError> for UiError`
/// in `azapptoolkit-dto` matches every variant, so a new variant fails to
/// compile until it is given a wire code there. With the attribute it would
/// fall into a catch-all arm — silently non-retryable and never re-auth-fatal.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("not signed in")]
    NotSignedIn,

    #[error("refresh token missing for tenant {0}; re-authentication required")]
    RefreshTokenMissing(String),

    /// AAD returned `invalid_grant` for a dead refresh token (e.g. AADSTS70008
    /// expired, 70000 revoked, 50173 invalidated by a password change, 70043
    /// past the sign-in frequency); it must be discarded. A consent gap ([`AuthError::ConsentRequired`]) or a
    /// Conditional Access step-up ([`AuthError::InteractionRequired`]) is
    /// classified first and never lands here. The string is the redacted AAD
    /// code for tracing only — do not show it to users.
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
    /// registration, an external challenge, a device or app requirement — or
    /// blocks access outright, by a Conditional Access policy for THIS resource
    /// (`interaction_required` / `login_required`, or `invalid_grant` with
    /// AADSTS50074/50076/50078/50079/50158 or 53000–53004/530032 —
    /// `wire::CONDITIONAL_ACCESS_CODES`). The refresh token is still valid for
    /// other audiences (MSAL keeps the account on
    /// `InteractionRequiredAuthError`), so it must NOT be purged. Recover via
    /// [`crate::EntraAuthService::step_up_for_scopes`]. The string carries the
    /// redacted AAD code for tracing; show users a generic message.
    #[error("additional verification required for this resource ({0})")]
    InteractionRequired(String),

    #[error("token exchange failed: {0}")]
    TokenExchange(String),

    /// Something other than Entra ID answered the `/token` request: a
    /// non-success response whose body is not an OAuth error body (a
    /// TLS-inspecting proxy's or a WAF's block page, a captive portal, a 3xx
    /// the client refuses to follow), or a 200 whose body is not JSON. Entra
    /// rejected nothing, so the refresh token is untouched and a retry can
    /// succeed once the network path lets the login host through. Metadata
    /// only — the status and a coarse class of the `Content-Type`
    /// (`html`/`json`/`text`/`other`/`untyped`) — never the body, which such a
    /// responder commonly fills with the request it intercepted.
    #[error(
        "something other than Entra ID answered the token request (HTTP {status}, {content_type_class} body)"
    )]
    UnexpectedResponder {
        status: u16,
        content_type_class: &'static str,
    },

    /// The `/token` endpoint answered 429 or 5xx and the retry policy did not
    /// clear it: a refresh grant still failing after its retries, an
    /// authorization-code grant at once (a 5xx after the single-use code may
    /// have been redeemed is never replayed; only a 429 is), or a
    /// `Retry-After` too long to wait under the refresh lock. Nothing was
    /// rejected: the refresh token is untouched and a later retry can
    /// succeed. `detail` is the redacted AAD error
    /// (`"{error} (AADSTSnnnnn)"`) when Entra sent one, else the body's
    /// content-type class — never the body.
    #[error(
        "the sign-in service is throttling or temporarily unavailable (HTTP {status}: {detail})"
    )]
    ServiceUnavailable { status: u16, detail: String },

    #[error("authorization request failed: {0}")]
    Authorization(String),

    #[error("loopback listener failed: {0}")]
    Loopback(String),

    /// The loopback listener no longer produces this: a redirect with a
    /// foreign or missing `state` is answered 400 and ignored rather than
    /// ending the sign-in. Kept for its DTO mapping (`state_mismatch`).
    #[error("state mismatch on redirect — possible CSRF")]
    StateMismatch,

    /// The browser round trip was abandoned: the redirect never arrived within
    /// the wait (the tab was closed), or the operator cancelled at Entra
    /// (`access_denied` with no AADSTS code / `error_subcode=cancel`).
    #[error("sign-in was cancelled or not completed in the browser")]
    Cancelled,

    #[error("keyring: {0}")]
    Keyring(String),

    /// The OS credential store could not be registered at all — on Linux, no
    /// Secret Service provider (GNOME Keyring / KWallet) on the D-Bus session
    /// bus. Distinct from [`AuthError::Keyring`] (a store that exists but
    /// refused, e.g. locked). The failure is memoised for the process
    /// (`token_cache::ensure_keyring_store`), so recovering needs a restart
    /// once a provider is running.
    #[error("no OS credential store is available: {0}")]
    KeyringUnavailable(String),

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
