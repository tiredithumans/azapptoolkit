//! Microsoft resource directory.
//!
//! Ships a bundled `catalog.json` listing the well-known Microsoft API
//! resources (Graph, SharePoint, Exchange, Key Vault, ARM, …) by `appId` and
//! `displayName` only. It feeds two things: the permission picker's resource
//! dropdown and the resource names on the Permissions tab. It deliberately
//! carries **no** per-permission data: every `appRoles` /
//! `oauth2PermissionScopes` definition is resolved live from Microsoft Graph
//! via `GraphClient::resolve_resource_sp` and cached under
//! `CacheKind::Permissions`, so the picker always shows the complete, current
//! Application **and** Delegated set without a hand-maintained GUID catalog.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

const BUNDLED: &str = include_str!("../data/catalog.json");

/// Convenience: the bundled directory's resource list. The slice is stable for
/// the lifetime of the process.
pub fn bundled_resources_slice() -> &'static [ResourceEntry] {
    ResourceDirectory::bundled().resources()
}

/// On-disk shape of `data/catalog.json`.
#[derive(Deserialize)]
struct DirectoryFile {
    resources: Vec<ResourceEntry>,
}

/// One well-known Microsoft API resource: its `appId` and display name.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceEntry {
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// The bundled directory of well-known Microsoft API resources, indexed by
/// `appId` and kept in file order for the picker dropdown.
pub struct ResourceDirectory {
    /// `appId` → index into `ordered`.
    by_app_id: HashMap<String, usize>,
    ordered: Vec<ResourceEntry>,
}

impl ResourceDirectory {
    fn from_file(file: DirectoryFile) -> Self {
        let ordered = file.resources;
        let by_app_id = ordered
            .iter()
            .enumerate()
            .map(|(i, r)| (r.app_id.clone(), i))
            .collect();
        Self { by_app_id, ordered }
    }

    pub fn bundled() -> &'static Self {
        static ONCE: OnceLock<ResourceDirectory> = OnceLock::new();
        ONCE.get_or_init(|| {
            let file: DirectoryFile =
                serde_json::from_str(BUNDLED).expect("bundled resource directory is valid JSON");
            ResourceDirectory::from_file(file)
        })
    }

    pub fn resource(&self, app_id: &str) -> Option<&ResourceEntry> {
        self.by_app_id.get(app_id).map(|&i| &self.ordered[i])
    }

    pub fn resources(&self) -> &[ResourceEntry] {
        &self.ordered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_directory_parses() {
        let directory = ResourceDirectory::bundled();
        let graph = directory
            .resource("00000003-0000-0000-c000-000000000000")
            .expect("Graph entry present");
        assert_eq!(graph.display_name, "Microsoft Graph");
    }

    #[test]
    fn directory_lists_common_microsoft_resources() {
        let directory = ResourceDirectory::bundled();
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
                directory.resource(app_id).is_some(),
                "directory missing resource {app_id}"
            );
        }
    }

    #[test]
    fn all_resources_have_non_empty_app_id() {
        // Regression: ensure every entry has an app_id so the HashMap index is valid.
        let directory = ResourceDirectory::bundled();
        for entry in directory.resources() {
            assert!(
                !entry.app_id.is_empty(),
                "resource entry has empty app_id: {:?}",
                entry.display_name
            );
        }
    }

    #[test]
    fn directory_app_ids_are_unique() {
        // A duplicate appId would silently shadow an earlier row in the index.
        let directory = ResourceDirectory::bundled();
        assert_eq!(directory.by_app_id.len(), directory.ordered.len());
    }

    #[test]
    fn directory_entries_carry_no_permission_data() {
        // Permission definitions resolve live from the resource SP. Keeping
        // the file to `{appId, displayName}` stops per-permission data from
        // creeping back in without any code learning to read it.
        let root: serde_json::Value = serde_json::from_str(BUNDLED).expect("valid JSON");
        let resources = root["resources"].as_array().expect("resources array");
        assert!(!resources.is_empty());
        for entry in resources {
            let obj = entry.as_object().expect("resource entry is an object");
            for key in obj.keys() {
                assert!(
                    key == "appId" || key == "displayName",
                    "resource entry carries unexpected key {key:?}: {entry}"
                );
            }
        }
    }
}
