//! Re-exports the shared `UiError` from `azapptoolkit-dto` for use throughout the
//! backend. The wire shape and the `From<AuthError>` / `From<GraphError>`
//! conversions live in that crate (gated behind its `backend` feature).

pub use azapptoolkit_dto::UiError;
pub use azapptoolkit_dto::{
    activity, applications, audit, backup, bulk, conditional_access, config, consent, credentials,
    diagnostics, enterprise_application, exchange, expose_api, keyvault, managed_identity,
    permission_tester, permissions, readiness, remediation, search, sharepoint, sso, usage,
};
