pub mod audit;
pub mod azure_roles;
#[cfg(not(target_arch = "wasm32"))]
pub mod cache;
pub mod capabilities;
pub mod cloud;
pub mod constants;
// Pure data types (no fs I/O), so ungated — the wasm frontend uses them as the
// IPC payload for get/set_tenant_defaults. Persistence lives in `settings`.
pub mod defaults;
pub mod federation;
// Both are server-side only: the macro's generated `is_retryable` calls into
// `http_retry`, and no WASM surface constructs a client error.
#[cfg(not(target_arch = "wasm32"))]
pub mod http_error;
#[cfg(not(target_arch = "wasm32"))]
pub mod http_retry;
pub mod identity;
pub mod models;
#[cfg(not(target_arch = "wasm32"))]
pub mod net;
// Server-side only: no filesystem in the WASM frontend.
#[cfg(not(target_arch = "wasm32"))]
pub mod private_file;
pub mod reauth;
pub mod redirect;
pub mod restore_plan;
pub mod scoping;
#[cfg(not(target_arch = "wasm32"))]
pub mod settings;
pub mod thumbprint;
#[cfg(not(target_arch = "wasm32"))]
pub mod token;

#[cfg(not(target_arch = "wasm32"))]
pub use token::{BearerProvider, StaticTokenProvider};
