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
#[cfg(not(target_arch = "wasm32"))]
pub mod http_retry;
pub mod identity;
pub mod models;
#[cfg(not(target_arch = "wasm32"))]
pub mod net;
pub mod redirect;
pub mod scoping;
#[cfg(not(target_arch = "wasm32"))]
pub mod settings;
#[cfg(not(target_arch = "wasm32"))]
pub mod token;

#[cfg(not(target_arch = "wasm32"))]
pub use token::{BearerProvider, StaticTokenProvider};
