//! Exchange Online Admin API client for RBAC for Applications.
//!
//! RBAC for Applications (service principals + management scopes + management
//! role assignments) is the supported replacement for the deprecated Exchange
//! Application Access Policies. It is reachable only through Exchange Online's
//! admin REST gateway — there is no Microsoft Graph surface — so this crate
//! talks to `https://outlook.office365.com/adminapi/beta/{tenant}/InvokeCommand`
//! (the ExchangeOnlineManagement PowerShell module's own transport, not the
//! documented v2.0 Admin API; see [`client`]'s doc), POSTing a `CmdletInput`
//! envelope per call.
//!
//! Mirrors `azapptoolkit_graph`: pulls a bearer token from a
//! [`azapptoolkit_core::token::BearerProvider`] (here for the
//! `https://outlook.office365.com/Exchange.Manage` audience) and retries
//! transient failures through the same `core::http_retry::with_retries` policy,
//! with the retry class taken from the cmdlet verb (every call is a POST).
//!
//! Only the entry types and the scoping constants are re-exported at the root;
//! everything else is reached through its module (`targets`, `verdict`, `aap`,
//! `references`, `models`), because the modules are the documented seams
//! between pure decisions and I/O.

pub mod aap;
pub mod client;
pub mod error;
pub mod models;
pub mod references;
pub mod roles;
pub mod targets;
pub mod verdict;

pub use client::{EXCHANGE_BASE, ExchangeClient, member_of_group_filter};
pub use error::{ExchangeError, Result};
pub use roles::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
    exchange_role_for_resource_permission, is_aap_confinable_permission, is_blanket_mailbox_grant,
    is_scopable_exchange_resource_permission,
};
