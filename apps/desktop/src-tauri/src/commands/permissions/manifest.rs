use tauri::State;

use azapptoolkit_core::models::{RequiredResourceAccess, ResourceAccess};

use crate::commands::applications::invalidate_app_detail_state;
use crate::dto::UiError;
use crate::dto::permissions::PermissionKind;
use crate::state::AppState;

use super::entry_type_for;

/// Removes one declared permission from an application's `requiredResourceAccess`.
/// Re-resolves the live manifest before acting (the UI snapshot is advisory):
/// drops the `ResourceAccess` whose `id` matches `permission_id` (and `type`
/// matches `kind`, when known), then prunes any resource entry left with no
/// permissions. Runtime grants are left untouched — the UI offers this only for
/// *not-granted* (declared-only) rows; a granted permission is revoked first.
/// Idempotent: removing an already-absent permission is a no-op success.
#[tauri::command]
pub async fn remove_declared_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    resource_app_id: String,
    permission_id: String,
    kind: PermissionKind,
) -> Result<(), UiError> {
    // `None` for Unknown — a raw-GUID row whose declared type we couldn't
    // classify, so match on the permission id alone.
    let entry_type = entry_type_for(kind).ok();

    let client = state.graph_for(&tenant_id);
    let app = client.get_application(&object_id).await?;

    let mut next = app.required_resource_access.clone();
    // Nothing matched — already gone. Succeed without a write so a double-click
    // (or a stale snapshot) doesn't clobber the manifest.
    if !remove_declared_access(&mut next, &resource_app_id, &permission_id, entry_type) {
        return Ok(());
    }

    let patch = azapptoolkit_graph::client::AppPatch {
        required_resource_access: Some(next),
        ..Default::default()
    };
    client.update_application(&object_id, &patch).await?;
    invalidate_app_detail_state(&state.cache, &tenant_id);
    Ok(())
}

/// Removes the `(permission_id, entry_type)` access from `required` in place,
/// then prunes any resource entry the removal emptied. Returns whether anything
/// was removed. `entry_type` is `None` for an unclassified (Unknown-kind) row —
/// the match is on `permission_id` alone then. Pure so it can be unit-tested
/// without a Graph client. Shared with the remove-redundant-permissions
/// remediation, which drops several declarations in one manifest patch.
pub(crate) fn remove_declared_access(
    required: &mut Vec<RequiredResourceAccess>,
    resource_app_id: &str,
    permission_id: &str,
    entry_type: Option<&str>,
) -> bool {
    let mut removed = false;
    for resource in required.iter_mut() {
        if resource.resource_app_id != resource_app_id {
            continue;
        }
        let before = resource.resource_access.len();
        resource
            .resource_access
            .retain(|a| !(a.id == permission_id && entry_type.is_none_or(|t| a.r#type == t)));
        removed |= resource.resource_access.len() != before;
    }
    if removed {
        required.retain(|r| !r.resource_access.is_empty());
    }
    removed
}

/// Adds the `(resource_app_id, permission_id, entry_type)` access to `required`
/// in place unless it's already declared, creating the resource entry when the
/// app declares nothing for that resource yet. Returns whether the manifest
/// changed (`false` = already declared, so the caller skips the PATCH). Pure so
/// the declaration semantics are unit-testable without a Graph client; shared by
/// `grant_single_permission` (declare-then-grant) and `declare_app_permission`
/// (declare-only).
pub(crate) fn declare_resource_access(
    required: &mut Vec<RequiredResourceAccess>,
    resource_app_id: &str,
    permission_id: &str,
    entry_type: &str,
) -> bool {
    let already = required
        .iter()
        .find(|r| r.resource_app_id == resource_app_id)
        .is_some_and(|r| {
            r.resource_access
                .iter()
                .any(|a| a.id == permission_id && a.r#type == entry_type)
        });
    if already {
        return false;
    }
    let access = ResourceAccess {
        id: permission_id.to_string(),
        r#type: entry_type.to_string(),
    };
    if let Some(existing) = required
        .iter_mut()
        .find(|r| r.resource_app_id == resource_app_id)
    {
        existing.resource_access.push(access);
    } else {
        required.push(RequiredResourceAccess {
            resource_app_id: resource_app_id.to_string(),
            resource_access: vec![access],
        });
    }
    true
}

/// Declares a single permission in `object_id`'s `requiredResourceAccess`
/// **without** creating any runtime grant — the manifest half of
/// `grant_single_permission`, nothing else. Used by the scoped-mailbox flow: the
/// permission is declared so it's visible in the UI and the Exchange scoping path
/// can derive its target from the manifest, while effective access comes solely
/// from a scoped Exchange RBAC role assignment — never an org-wide Entra app-role
/// grant (RBAC for Applications authorizes independently of the Entra consent).
/// Idempotent: an already-declared permission is a no-op success (no write, no
/// cache bust).
#[tauri::command]
pub async fn declare_app_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    resource_app_id: String,
    permission_id: String,
    kind: PermissionKind,
) -> Result<(), UiError> {
    let entry_type = entry_type_for(kind)?;

    let client = state.graph_for(&tenant_id);
    let mut app = client.get_application(&object_id).await?;
    if declare_resource_access(
        &mut app.required_resource_access,
        &resource_app_id,
        &permission_id,
        entry_type,
    ) {
        let patch = azapptoolkit_graph::client::AppPatch {
            required_resource_access: Some(app.required_resource_access.clone()),
            ..Default::default()
        };
        client.update_application(&object_id, &patch).await?;
        invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    Ok(())
}

/// Swaps the declared `(broad_id → narrow_id)` Role access on `resource_app_id`
/// in place: removes the broad entry and adds the narrow one unless already
/// declared. Returns whether the manifest changed (`false` = broad wasn't
/// declared, nothing touched). `remove_declared_access` prunes a resource entry
/// it empties, so a broad-only resource is recreated to carry the narrow entry.
/// Pure so the swap semantics are unit-testable without a Graph client.
pub(crate) fn swap_declared_role(
    required: &mut Vec<RequiredResourceAccess>,
    resource_app_id: &str,
    broad_id: &str,
    narrow_id: &str,
) -> bool {
    if !remove_declared_access(required, resource_app_id, broad_id, Some("Role")) {
        return false;
    }
    let narrow_declared = required.iter().any(|r| {
        r.resource_app_id == resource_app_id
            && r.resource_access
                .iter()
                .any(|a| a.id == narrow_id && a.r#type == "Role")
    });
    if !narrow_declared {
        let access = ResourceAccess {
            id: narrow_id.to_string(),
            r#type: "Role".into(),
        };
        if let Some(existing) = required
            .iter_mut()
            .find(|r| r.resource_app_id == resource_app_id)
        {
            existing.resource_access.push(access);
        } else {
            required.push(RequiredResourceAccess {
                resource_app_id: resource_app_id.to_string(),
                resource_access: vec![access],
            });
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(id: &str, ty: &str) -> ResourceAccess {
        ResourceAccess {
            id: id.into(),
            r#type: ty.into(),
        }
    }

    fn manifest(entries: &[(&str, &[(&str, &str)])]) -> Vec<RequiredResourceAccess> {
        entries
            .iter()
            .map(|(res, accesses)| RequiredResourceAccess {
                resource_app_id: (*res).into(),
                resource_access: accesses.iter().map(|(id, ty)| access(id, ty)).collect(),
            })
            .collect()
    }

    #[test]
    fn remove_declared_access_drops_match_and_prunes_empty_resource() {
        // A resource with a single Role; removing it empties and prunes the
        // whole resource entry.
        let mut req = manifest(&[("graph", &[("role-1", "Role")])]);
        assert!(remove_declared_access(
            &mut req,
            "graph",
            "role-1",
            Some("Role")
        ));
        assert!(req.is_empty(), "emptied resource entry should be pruned");
    }

    #[test]
    fn remove_declared_access_keeps_siblings() {
        // Removing one access leaves the resource (with its other access) intact.
        let mut req = manifest(&[("graph", &[("role-1", "Role"), ("scope-1", "Scope")])]);
        assert!(remove_declared_access(
            &mut req,
            "graph",
            "role-1",
            Some("Role")
        ));
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].id, "scope-1");
    }

    #[test]
    fn remove_declared_access_respects_type_when_ids_collide() {
        // Same id declared as both a Role and a Scope: the type narrows it to one.
        let mut req = manifest(&[("graph", &[("dup", "Role"), ("dup", "Scope")])]);
        assert!(remove_declared_access(
            &mut req,
            "graph",
            "dup",
            Some("Scope")
        ));
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].r#type, "Role");
    }

    #[test]
    fn remove_declared_access_unknown_kind_matches_id_alone() {
        // `None` type (an unclassified raw-GUID row) matches on id regardless of type.
        let mut req = manifest(&[("graph", &[("dup", "Role")])]);
        assert!(remove_declared_access(&mut req, "graph", "dup", None));
        assert!(req.is_empty());
    }

    #[test]
    fn declare_resource_access_creates_resource_entry_when_absent() {
        // No declaration for the resource yet — a fresh entry carries the access.
        let mut req = manifest(&[]);
        assert!(declare_resource_access(&mut req, "graph", "role-1", "Role"));
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].resource_app_id, "graph");
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].id, "role-1");
        assert_eq!(req[0].resource_access[0].r#type, "Role");
    }

    #[test]
    fn declare_resource_access_appends_to_existing_resource() {
        // Resource already declared with a sibling — the new access is appended,
        // not a duplicate resource entry.
        let mut req = manifest(&[("graph", &[("scope-1", "Scope")])]);
        assert!(declare_resource_access(&mut req, "graph", "role-1", "Role"));
        assert_eq!(req.len(), 1);
        let ids: Vec<(&str, &str)> = req[0]
            .resource_access
            .iter()
            .map(|a| (a.id.as_str(), a.r#type.as_str()))
            .collect();
        assert_eq!(ids, [("scope-1", "Scope"), ("role-1", "Role")]);
    }

    #[test]
    fn declare_resource_access_already_declared_is_noop() {
        // Same (id, type) already present → no change, so the caller skips the PATCH.
        let mut req = manifest(&[("graph", &[("role-1", "Role")])]);
        assert!(!declare_resource_access(
            &mut req, "graph", "role-1", "Role"
        ));
        assert_eq!(req[0].resource_access.len(), 1);
        // Same id but a different type is a distinct declaration and is added.
        assert!(declare_resource_access(
            &mut req, "graph", "role-1", "Scope"
        ));
        assert_eq!(req[0].resource_access.len(), 2);
    }

    #[test]
    fn swap_declared_role_replaces_broad_with_narrow() {
        // Broad + sibling: broad goes, narrow is appended, sibling untouched.
        let mut req = manifest(&[("graph", &[("id-broad", "Role"), ("id-other", "Scope")])]);
        assert!(swap_declared_role(
            &mut req,
            "graph",
            "id-broad",
            "id-narrow"
        ));
        let ids: Vec<(&str, &str)> = req[0]
            .resource_access
            .iter()
            .map(|a| (a.id.as_str(), a.r#type.as_str()))
            .collect();
        assert_eq!(ids, [("id-other", "Scope"), ("id-narrow", "Role")]);
    }

    #[test]
    fn swap_declared_role_recreates_a_pruned_resource_entry() {
        // Broad was the resource's only access: remove_declared_access prunes
        // the entry, so the swap must recreate it to carry the narrow role.
        let mut req = manifest(&[("graph", &[("id-broad", "Role")])]);
        assert!(swap_declared_role(
            &mut req,
            "graph",
            "id-broad",
            "id-narrow"
        ));
        assert_eq!(req.len(), 1);
        assert_eq!(req[0].resource_app_id, "graph");
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].id, "id-narrow");
        assert_eq!(req[0].resource_access[0].r#type, "Role");
    }

    #[test]
    fn swap_declared_role_skips_duplicate_narrow_and_missing_broad() {
        // Narrow already declared → no duplicate entry is added.
        let mut req = manifest(&[("graph", &[("id-broad", "Role"), ("id-narrow", "Role")])]);
        assert!(swap_declared_role(
            &mut req,
            "graph",
            "id-broad",
            "id-narrow"
        ));
        assert_eq!(req[0].resource_access.len(), 1);
        assert_eq!(req[0].resource_access[0].id, "id-narrow");

        // Broad absent → untouched no-op (idempotent re-run).
        let mut req = manifest(&[("graph", &[("id-narrow", "Role")])]);
        assert!(!swap_declared_role(
            &mut req,
            "graph",
            "id-broad",
            "id-narrow"
        ));
        assert_eq!(req[0].resource_access.len(), 1);
    }

    #[test]
    fn remove_declared_access_no_match_is_noop() {
        // Wrong type, wrong resource, and wrong id each leave the manifest untouched.
        // (RequiredResourceAccess has no PartialEq, so compare projected tuples.)
        let project = |req: &[RequiredResourceAccess]| {
            req.iter()
                .map(|r| {
                    (
                        r.resource_app_id.clone(),
                        r.resource_access
                            .iter()
                            .map(|a| (a.id.clone(), a.r#type.clone()))
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let original = manifest(&[("graph", &[("role-1", "Role")])]);
        for (res, id, ty) in [
            ("graph", "role-1", Some("Scope")), // right id, wrong type
            ("other", "role-1", Some("Role")),  // wrong resource
            ("graph", "missing", Some("Role")), // wrong id
        ] {
            let mut req = original.clone();
            assert!(!remove_declared_access(&mut req, res, id, ty));
            assert_eq!(
                project(&req),
                project(&original),
                "no-match must not mutate the manifest"
            );
        }
    }
}
