//! Entra ID authentication.
//!
//! v1 uses OAuth2 authorization code + PKCE against `login.microsoftonline.com`
//! with a loopback redirect on an ephemeral port. Refresh tokens persist in the
//! OS secret store via [`keyring`]; access tokens stay in memory and are
//! refreshed lazily 60s before expiry.

pub mod error;
pub mod service;
pub mod token_cache;

pub use azapptoolkit_core::identity::{SignInOutcome, TenantContext};
pub use error::{AuthError, Result};
pub use service::EntraAuthService;
pub use token_cache::{AccessToken, TokenCache};
