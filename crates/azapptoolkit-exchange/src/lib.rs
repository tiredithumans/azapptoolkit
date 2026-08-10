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

pub mod aap;
pub mod client;
pub mod error;
pub mod models;
pub mod references;
pub mod roles;
pub mod targets;
pub mod verdict;

pub use aap::{
    SourceGroupRead, SourceMember, group_policies_for_migration, plan_source_membership,
    source_member, unverified_members,
};
pub use client::{EXCHANGE_BASE, ExchangeClient, member_of_group_filter};
pub use error::{ExchangeError, Result};
// Re-exported for existing callers; the deprecation is theirs to see, not
// this line's. Removing it from the re-export would be a breaking change
// unrelated to the hazard.
#[allow(deprecated)]
pub use roles::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
    exchange_role_for_permission, exchange_role_for_resource_permission, is_blanket_mailbox_grant,
    is_scopable_exchange_resource_permission,
};
pub use targets::{
    ConsolidationPlan, ExchangeTarget, NoScopablePermission, Refusal, ResourceRoles, ScopeGroups,
    UnrewritableFilter, count_member_of_group, exchange_target, filter_targets_by_value,
    group_dns_in_filter, mailbox_resources_complete, plan_consolidation, policies_safe_to_remove,
    require_scopable_targets, resolve_grant, resolve_value, rewritable_scope_dns,
    scope_groups_in_filter, targets_from_declared, targets_from_grants, targets_safe_to_strip,
};
