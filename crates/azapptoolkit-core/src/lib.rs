pub mod audit;
pub mod azure_roles;
#[cfg(not(target_arch = "wasm32"))]
pub mod cache;
pub mod capabilities;
pub mod cloud;
pub mod constants;
// Pure data types, ungated for wasm: used as the get/set_tenant_defaults IPC
// payload; persistence lives in `settings`.
pub mod defaults;
pub mod federation;
// Pure shape check, ungated: shared by the ARM client and the command layer.
pub mod guid;
// Server-side only: the macro's generated `is_retryable` calls `http_retry`,
// and no WASM surface constructs a client error.
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
