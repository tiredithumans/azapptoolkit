//! Minimal Azure Resource Manager (ARM) client + Azure Monitor Logs query.
//!
//! Scope: the pieces needed to show a managed identity's **Azure RBAC**
//! footprint — list subscriptions the signed-in user can reach, the role
//! assignments held by a principal within each, and resolve role-definition
//! names — plus the Azure Monitor Logs *data-plane* query client
//! ([`LogAnalyticsClient`], its own host + token audience) used to read
//! `MicrosoftGraphActivityLogs` for usage analysis. Talks to
//! `https://management.azure.com` / `https://api.loganalytics.azure.com` and
//! pulls bearer tokens through the shared
//! [`azapptoolkit_core::token::BearerProvider`], like the Graph / Key Vault
//! clients.

pub mod client;
pub mod error;
pub mod loganalytics;
pub mod models;
mod transport;

pub use client::{ARM_BASE, ArmClient};
pub use error::{ArmError, Result};
pub use loganalytics::LogAnalyticsClient;
pub use models::{
    KeyVaultResource, LogAnalyticsWorkspace, LogsQueryResponse, LogsQueryTable, RoleAssignment,
    RoleAssignmentProperties, RoleDefinition, RoleDefinitionProperties, Subscription,
};
