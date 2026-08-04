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
pub mod targets;

pub use client::{EXCHANGE_BASE, ExchangeClient, member_of_group_filter};
pub use error::{ExchangeError, Result};
pub use roles::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
    exchange_role_for_permission, exchange_role_for_resource_permission, is_blanket_mailbox_grant,
    is_scopable_exchange_permission,
};
pub use targets::{
    ExchangeTarget, NoScopablePermission, ResourceRoles, count_member_of_group, exchange_target,
    filter_targets_by_value, group_dns_in_filter, mailbox_resources_complete,
    policies_safe_to_remove, require_scopable_targets, resolve_grant, resolve_value,
    scope_dns_after_consolidation, targets_from_declared, targets_from_grants,
    targets_safe_to_strip,
};
