//! ARM response models — only the fields the managed-identity RBAC view needs.

use serde::Deserialize;

/// ARM's standard paged collection envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct Paged<T> {
    #[serde(default = "Vec::new")]
    pub value: Vec<T>,
    #[serde(rename = "nextLink", default)]
    pub next_link: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subscription {
    pub subscription_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
}

/// A Log Analytics workspace (ARM control plane). `properties.customer_id` —
/// NOT the ARM resource id — is what the Azure Monitor Logs query API keys
/// workspaces by.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogAnalyticsWorkspace {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    pub properties: LogAnalyticsWorkspaceProperties,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogAnalyticsWorkspaceProperties {
    #[serde(default)]
    pub customer_id: Option<String>,
}

/// One Azure Monitor Logs query response — `tables[0]` carries the result set
/// as a column schema plus untyped rows. A present `error` means a non-fatal
/// execution failure (HTTP 200, `code == "PartialError"`); the rows are
/// incomplete and `LogAnalyticsClient::query` refuses the response.
#[derive(Debug, Clone, Deserialize)]
pub struct LogsQueryResponse {
    #[serde(default)]
    pub tables: Vec<LogsQueryTable>,
    #[serde(default)]
    pub error: Option<LogsQueryError>,
}

/// The OneAPI error object beside `tables` on a non-fatal failure — HTTP 200
/// with `code == "PartialError"` (runaway / timeout / truncation); the rows
/// are incomplete.
#[derive(Debug, Clone, Deserialize)]
pub struct LogsQueryError {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogsQueryTable {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub columns: Vec<LogsQueryColumn>,
    #[serde(default)]
    pub rows: Vec<Vec<serde_json::Value>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogsQueryColumn {
    pub name: String,
}

impl LogsQueryTable {
    /// Index of `column` in this table's schema, for row-cell lookups.
    pub fn column_index(&self, column: &str) -> Option<usize> {
        self.columns.iter().position(|c| c.name == column)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoleAssignment {
    #[serde(default)]
    pub id: Option<String>,
    pub properties: RoleAssignmentProperties,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleAssignmentProperties {
    /// Absolute ARM id of the role definition (e.g. `/subscriptions/.../roleDefinitions/{guid}`).
    #[serde(default)]
    pub role_definition_id: Option<String>,
    /// The scope the role is granted at (subscription / resource group / resource).
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub principal_id: Option<String>,
    /// `User` / `Group` / `ServicePrincipal` — lets the reverse-lookup route
    /// name resolution (only ServicePrincipal ids resolve via the Graph SP
    /// batch) and label a row by identity kind.
    #[serde(default)]
    pub principal_type: Option<String>,
}

/// A Key Vault (ARM control plane), from
/// `/subscriptions/{sub}/providers/Microsoft.KeyVault/vaults`. The id doubles as
/// the ARM scope for a role-assignment query; `properties` carries the access
/// model so a sweep can tell *why* a vault answered with no role assignments.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyVaultResource {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub properties: Option<VaultProperties>,
}

impl KeyVaultResource {
    /// True only when ARM explicitly reports `enableRbacAuthorization: false` —
    /// an absent flag is never asserted either way.
    pub fn access_policy_mode(&self) -> bool {
        self.properties
            .as_ref()
            .and_then(|p| p.enable_rbac_authorization)
            == Some(false)
    }
}

/// The part of ARM's vault `properties` the reverse lookup reads. A vault in
/// legacy access-policy mode grants data access through access policies, which
/// the RBAC role-assignment listing never returns — without this flag an empty
/// listing reads as "no access" for exactly those vaults.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultProperties {
    #[serde(default)]
    pub enable_rbac_authorization: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RoleDefinition {
    pub properties: RoleDefinitionProperties,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleDefinitionProperties {
    #[serde(default)]
    pub role_name: Option<String>,
}
