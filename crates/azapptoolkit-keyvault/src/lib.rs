//! Minimal Azure Key Vault client for secret list/read/write.
//!
//! Scope: just the secrets surface on `{vault}.vault.azure.net` against the
//! `2016-10-01`-compatible `secrets` REST API (we use `7.4` — the general-
//! availability API version). Pulls bearer tokens through the shared
//! [`azapptoolkit_core::BearerProvider`] so the desktop layer wires one token
//! adapter across audiences.
//!
//! Only the operations the desktop app needs are implemented: `list_secrets`
//! and `get_secret` (the Key Vault view) and `set_secret` (credential rotation).

pub mod client;
pub mod error;
pub mod models;
pub mod validate;

pub use client::{DEFAULT_API_VERSION, KeyVaultClient};
pub use error::{KeyVaultError, Result};
pub use models::{SecretItem, SecretSetRequest, SecretValue};
