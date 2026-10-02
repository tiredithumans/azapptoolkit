//! Typed Microsoft Graph client.
//!
//! Thin wrapper over [`reqwest`] that:
//! - Pulls the verb-selected read/write bearer token (or an explicit per-resource provider for
//!   scoped calls) from a [`azapptoolkit_core::BearerProvider`] per request.
//! - Retries under the shared `azapptoolkit_core::http_retry` policy: a 429, any 5xx and a network
//!   failure are transient; every other 4xx is terminal. An explicit `Retry-After` is honored
//!   exactly (no jitter); without one the wait is jittered exponential backoff. `GET`/`HEAD`/
//!   `PUT`/`DELETE` (and a read-only `$batch`) retry every transient failure, but a mutating
//!   `POST`/`PATCH` is replayed only after a 429 (`RetryClass`) — a write retried after a 5xx may
//!   already have committed. The one-shot report reads (`scoped_get`) do not retry.
//!   (Ported from the legacy `Retry-Utility.ps1`.)
//! - Deserializes responses into strongly-typed models from [`azapptoolkit_core::models`].
//! - Sends `ConsistencyLevel: eventual` only when the caller opts in per request
//!   (`consistency_eventual`). Nothing inspects the query string, so a new `$search`/`$count`
//!   read must pass it (Graph silently ignores `$count` without it), and an `$expand` read must not.

pub mod client;
pub mod error;

pub use client::{GraphClient, ThrottleObserver};
pub use error::{GraphError, Result};
