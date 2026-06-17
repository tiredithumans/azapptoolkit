//! Microsoft resource directory.
//!
//! Ships a bundled `catalog.json` listing the well-known Microsoft API
//! resources (Graph, SharePoint, Exchange, Key Vault, ARM, …) by `appId` and
//! `displayName` so the permission picker can populate its resource dropdown
//! offline. It deliberately carries **no** per-permission data: the actual
//! `appRoles`/`oauth2PermissionScopes` are resolved live from Microsoft Graph
//! via [`azapptoolkit_graph::GraphClient::resolve_resource_sp`] so the picker
//! always shows the complete, current Application **and** Delegated set without
//! a hand-maintained GUID catalog. `ResourceEntry` keeps the permission fields
//! (they default to empty here) so the same type can hold a live SP's data.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;

const BUNDLED: &str = include_str!("../data/catalog.json");

/// Convenience: the bundled catalog's resource list. The slice is stable for
/// the lifetime of the process.
pub fn bundled_resources_slice() -> &'static [ResourceEntry] {
    PermissionsCatalog::bundled().resources()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CatalogRoot {
    #[serde(default)]
    pub generated: String,
    #[serde(default)]
    pub version: u32,
    pub resources: Vec<ResourceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(default, rename = "appRoles")]
    pub app_roles: Vec<AppRoleEntry>,
    #[serde(default, rename = "oauth2PermissionScopes")]
    pub oauth2_permission_scopes: Vec<ScopeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleEntry {
    pub id: String,
    pub value: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Graph's `appRoles[].allowedMemberTypes`. Defaulted because older
    /// catalog snapshots don't carry this field; the consumer treats an
    /// empty list as "unknown — show it".
    #[serde(default, rename = "allowedMemberTypes")]
    pub allowed_member_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeEntry {
    pub id: String,
    pub value: String,
    #[serde(default, rename = "adminConsentDisplayName")]
    pub admin_consent_display_name: Option<String>,
    #[serde(default, rename = "adminConsentDescription")]
    pub admin_consent_description: Option<String>,
}

pub struct PermissionsCatalog {
    by_app_id: HashMap<String, ResourceEntry>,
    ordered: Vec<ResourceEntry>,
}

impl PermissionsCatalog {
    pub fn from_root(root: CatalogRoot) -> Self {
        let ordered = root.resources.clone();
        let mut by_app_id = HashMap::with_capacity(ordered.len());
        for r in &ordered {
            by_app_id.insert(r.app_id.clone(), r.clone());
        }
        Self { by_app_id, ordered }
    }

    pub fn bundled() -> &'static Self {
        static ONCE: OnceLock<PermissionsCatalog> = OnceLock::new();
        ONCE.get_or_init(|| {
            let root: CatalogRoot =
                serde_json::from_str(BUNDLED).expect("bundled catalog is valid JSON");
            PermissionsCatalog::from_root(root)
        })
    }

    pub fn resource(&self, app_id: &str) -> Option<&ResourceEntry> {
        self.by_app_id.get(app_id)
    }

    pub fn resources(&self) -> &[ResourceEntry] {
        &self.ordered
    }

    /// Friendly name for a role/scope on a resource. Returns (display, kind)
    /// where kind is `"Role"` or `"Scope"`. `None` when the catalog has no
    /// match.
    pub fn lookup_permission(
        &self,
        resource_app_id: &str,
        permission_id: &str,
    ) -> Option<(String, &'static str)> {
        let res = self.resource(resource_app_id)?;
        if let Some(role) = res.app_roles.iter().find(|r| r.id == permission_id) {
            return Some((role.display_name.clone(), "Role"));
        }
        if let Some(scope) = res
            .oauth2_permission_scopes
            .iter()
            .find(|s| s.id == permission_id)
        {
            let name = scope
                .admin_consent_display_name
                .clone()
                .unwrap_or_else(|| scope.value.clone());
            return Some((name, "Scope"));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_directory_parses() {
        let catalog = PermissionsCatalog::bundled();
        let graph = catalog
            .resource("00000003-0000-0000-c000-000000000000")
            .expect("Graph entry present");
        assert_eq!(graph.display_name, "Microsoft Graph");
        // The directory is intentionally permission-free — definitions are
        // resolved live from Graph, not bundled.
        assert!(graph.app_roles.is_empty());
        assert!(graph.oauth2_permission_scopes.is_empty());
    }

    #[test]
    fn directory_lists_common_microsoft_resources() {
        let catalog = PermissionsCatalog::bundled();
        // The picker dropdown is driven entirely by these entries, so the
        // well-known resources must be present by appId.
        for app_id in [
            "00000003-0000-0000-c000-000000000000", // Microsoft Graph
            "00000003-0000-0ff1-ce00-000000000000", // SharePoint Online
            "00000002-0000-0ff1-ce00-000000000000", // Exchange Online
            "cfa8b339-82a2-471a-a3c9-0fc0be7a4093", // Azure Key Vault
            "797f4846-ba00-4fd7-ba43-dac1f8f63013", // Azure Service Management
        ] {
            assert!(
                catalog.resource(app_id).is_some(),
                "directory missing resource {app_id}"
            );
        }
    }

    #[test]
    fn lookup_permission_returns_none_without_bundled_data() {
        // The directory carries no per-permission data, so every lookup misses
        // and callers fall through to a live `resolve_resource_sp`.
        let catalog = PermissionsCatalog::bundled();
        assert!(catalog
            .lookup_permission(
                "00000003-0000-0000-c000-000000000000",
                "df021288-bdef-4463-88db-98f22de89214"
            )
            .is_none());
    }
}
