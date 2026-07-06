//! Well-known Azure built-in role definition GUIDs + a conservative
//! "does a held role satisfy a required role" check, used by the Access
//! Readiness Azure-RBAC enumeration.
//!
//! Role assignments returned by ARM carry only the role-definition **id** (a
//! path ending in a GUID), never the human name — so we match by GUID. The
//! satisfaction sets are deliberately conservative: they include only
//! unambiguous supersets (Owner/Contributor grant control-plane read; Owner
//! grants role-assignment write), and they do NOT assume a control-plane role
//! grants Key Vault **data-plane** secret access (which in RBAC mode needs a
//! data-plane role). The goal is to never report "Have" for access the operator
//! may not actually have.

use std::collections::HashSet;

// Control-plane built-ins.
const READER: &str = "acdd72a7-3385-48ef-bd42-f606fba81ae7";
const CONTRIBUTOR: &str = "b24988ac-6180-42a0-ab88-20f7382dd24c";
const OWNER: &str = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";
const USER_ACCESS_ADMIN: &str = "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9";
// Key Vault data-plane built-ins.
const KV_SECRETS_OFFICER: &str = "b86a8fe4-44ce-4948-aee5-eccb2c155cd6";
const KV_ADMINISTRATOR: &str = "00482a5a-887f-4fb3-b363-3b7fe8e74483";
// Log Analytics built-ins.
const LOG_ANALYTICS_READER: &str = "73c42c96-874c-492b-b04d-ab87d138a893";
const LOG_ANALYTICS_CONTRIBUTOR: &str = "92aaf0da-9dab-42b6-94a3-d43ce8d16293";

/// The role GUIDs that satisfy a capability's required role **name** (as it
/// appears in the capabilities catalog's `directory_roles_any`). An unknown name
/// yields an empty slice, so it can never be "satisfied" — the caller then
/// reports Unknown rather than guessing.
fn satisfying_guids(required_role_name: &str) -> &'static [&'static str] {
    match required_role_name {
        // Control-plane read: Contributor and Owner both include it.
        "Reader" => &[READER, CONTRIBUTOR, OWNER],
        "Contributor" => &[CONTRIBUTOR, OWNER],
        "Owner" => &[OWNER],
        // Writing role assignments: User Access Administrator or Owner.
        "User Access Administrator" => &[USER_ACCESS_ADMIN, OWNER],
        // Key Vault secret *data-plane* access — control-plane roles do NOT grant
        // this in RBAC mode, so only the data-plane roles qualify.
        "Key Vault Secrets Officer" => &[KV_SECRETS_OFFICER, KV_ADMINISTRATOR],
        "Log Analytics Reader" => &[LOG_ANALYTICS_READER, LOG_ANALYTICS_CONTRIBUTOR],
        _ => &[],
    }
}

/// The trailing GUID of a role-definition id path
/// (`/subscriptions/…/roleDefinitions/{guid}` or
/// `/providers/Microsoft.Authorization/roleDefinitions/{guid}`), lowercased.
pub fn role_id_tail(role_definition_id: &str) -> Option<String> {
    role_definition_id
        .rsplit('/')
        .find(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
}

/// Whether any of the operator's held role GUIDs satisfies `required_role_name`.
/// `held_role_ids` must be lowercased trailing GUIDs (see [`role_id_tail`]).
pub fn azure_role_satisfied(required_role_name: &str, held_role_ids: &HashSet<String>) -> bool {
    satisfying_guids(required_role_name)
        .iter()
        .any(|g| held_role_ids.contains(*g))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_ascii_lowercase()).collect()
    }

    #[test]
    fn role_id_tail_extracts_lowercased_guid() {
        assert_eq!(
            role_id_tail(&format!(
                "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/{}",
                READER.to_uppercase()
            ))
            .as_deref(),
            Some(READER)
        );
        assert_eq!(role_id_tail(""), None);
    }

    #[test]
    fn exact_role_satisfies() {
        assert!(azure_role_satisfied("Reader", &held(&[READER])));
        assert!(azure_role_satisfied(
            "Key Vault Secrets Officer",
            &held(&[KV_SECRETS_OFFICER])
        ));
    }

    #[test]
    fn control_plane_supersets_satisfy_reader_but_not_kv_data_plane() {
        // Owner/Contributor grant control-plane read.
        assert!(azure_role_satisfied("Reader", &held(&[OWNER])));
        assert!(azure_role_satisfied("Reader", &held(&[CONTRIBUTOR])));
        // ...but NOT Key Vault data-plane secret access.
        assert!(!azure_role_satisfied(
            "Key Vault Secrets Officer",
            &held(&[OWNER])
        ));
        assert!(!azure_role_satisfied(
            "Key Vault Secrets Officer",
            &held(&[CONTRIBUTOR])
        ));
    }

    #[test]
    fn owner_satisfies_role_assignment_write() {
        assert!(azure_role_satisfied(
            "User Access Administrator",
            &held(&[OWNER])
        ));
        assert!(azure_role_satisfied(
            "User Access Administrator",
            &held(&[USER_ACCESS_ADMIN])
        ));
        // Contributor cannot write role assignments.
        assert!(!azure_role_satisfied(
            "User Access Administrator",
            &held(&[CONTRIBUTOR])
        ));
    }

    #[test]
    fn unrelated_or_unknown_roles_do_not_satisfy() {
        assert!(!azure_role_satisfied(
            "Reader",
            &held(&[KV_SECRETS_OFFICER])
        ));
        assert!(!azure_role_satisfied(
            "Totally Made Up Role",
            &held(&[OWNER])
        ));
    }
}
