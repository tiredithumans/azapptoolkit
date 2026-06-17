//! Typed Microsoft Graph client.
//!
//! Thin wrapper over [`reqwest`] that:
//! - Pulls bearer tokens from an [`azapptoolkit_core::BearerProvider`] per request.
//! - Retries transient failures (429 w/ `Retry-After`, 503, 504, network) with
//!   exponential backoff + jitter — matches `Retry-Utility.ps1`.
//! - Deserializes responses into strongly-typed models from
//!   [`azapptoolkit_core::models`].
//! - Adds `ConsistencyLevel: eventual` automatically for `$search` / `$count`
//!   queries.

pub mod client;
pub mod error;

pub use client::{GraphClient, ThrottleObserver};
pub use error::{GraphError, Result};
