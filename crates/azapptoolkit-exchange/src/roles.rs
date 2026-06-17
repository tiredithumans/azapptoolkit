//! Maps Microsoft Graph application permissions to the equivalent Exchange
//! Online RBAC "application role" names.
//!
//! The canonical mapping now lives in `azapptoolkit_core::scoping` so the WASM
//! frontend's scope badges and this backend share one definition; this module
//! re-exports it for `azapptoolkit-exchange`'s existing callers (and the crate
//! root re-export in `lib.rs`).

pub use azapptoolkit_core::scoping::{
    exchange_role_for_graph_permission, is_scopable_exchange_permission,
};
