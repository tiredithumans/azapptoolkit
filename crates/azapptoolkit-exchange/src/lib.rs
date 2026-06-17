//! Exchange Online Admin API client for RBAC for Applications.
//!
//! RBAC for Applications (service principals + management scopes + management
//! role assignments) is the supported replacement for the deprecated Exchange
//! Application Access Policies. It is reachable only through the Exchange
//! Online Admin REST API — there is no Microsoft Graph surface — so this crate
//! talks to `https://outlook.office365.com/adminapi/.../InvokeCommand`,
//! POSTing a `CmdletInput` envelope per call.
//!
//! Mirrors [`azapptoolkit_graph`]: pulls a bearer token from a
//! [`azapptoolkit_core::token::BearerProvider`] (here for the
//! `https://outlook.office365.com/Exchange.Manage` audience) and retries
//! transient failures with the same exponential backoff.

pub mod client;
pub mod error;
pub mod models;
pub mod roles;

pub use client::{member_of_group_filter, ExchangeClient, EXCHANGE_BASE};
pub use error::{ExchangeError, Result};
pub use roles::{exchange_role_for_graph_permission, is_scopable_exchange_permission};
