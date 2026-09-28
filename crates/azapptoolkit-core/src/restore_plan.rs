//! Pure planning for a disaster-recovery restore: given a backup and the
//! source→destination `appId` remap built as apps are recreated, decide what
//! the *intended* state of each restored application is.
//!
//! This is the half of `commands::restore` that has no I/O in it. It lived in
//! the command layer, where a Tauri `State<AppState>` and a live `GraphClient`
//! sit between a test and the logic — which is why the DR surface carried
//! roughly a quarter the test density of comparable command files while being
//! the one flow whose mistakes are hardest to undo. Down here the decisions are
//! ordinary functions over ordinary data, so the awkward cases (a first-party
//! resource that must NOT be remapped, an identifier URI that names the source
//! appId or tenant in any of several segment positions, a pre-authorized client
//! absent from the backup) are cheap to pin.
//!
//! The command layer keeps what genuinely needs the client: creating the
//! objects, applying these plans, and reporting per-item outcomes.

use std::collections::HashMap;

use crate::models::{PreAuthorizedApplication, RequiredResourceAccess};

/// Source `appId` → the `appId` it was recreated as in the destination tenant.
///
/// Populated one entry at a time as Pass 1 creates each application, so a
/// lookup MISS is the normal case for anything the backup did not own — a
/// first-party Microsoft resource, or a third-party app that already exists in
/// the destination. Every function here therefore treats a miss as "leave it
/// alone", never as an error: rewriting `00000003-0000-0000-c000-000000000000`
/// to something else would point the restored app's permissions at nothing.
pub type AppIdRemap = HashMap<String, String>;

/// Re-points declared API permissions at the destination's appIds.
///
/// Only resources the backup itself recreated are remapped; the permission
/// *ids* inside each resource are preserved verbatim, because the resource
/// app's own restore re-declares those same ids (that is what makes a
/// cross-app permission graph survive a restore at all).
pub fn remap_required_resource_access(
    rra: &[RequiredResourceAccess],
    app_id_remap: &AppIdRemap,
) -> Vec<RequiredResourceAccess> {
    rra.iter()
        .map(|r| RequiredResourceAccess {
            resource_app_id: remap_or_keep(&r.resource_app_id, app_id_remap),
            resource_access: r.resource_access.clone(),
        })
        .collect()
}

/// Rewrites every `api://` identifier-URI segment that names the source appId
/// (→ `new_app_id`) or the source tenant id (→ `dest_tenant_id`).
///
/// Microsoft supports `api://<appId>`, `api://<tenantId>/<appId>`,
/// `api://<tenantId>/<string>` and `api://<string>/<appId>`, and a GUID in one
/// of them must match the app's own appId or the tenant id. A source GUID left
/// in place is therefore rejected by the destination — and the identifier URIs
/// share one PATCH with the app's scopes and pre-authorized clients, so one
/// stale URI loses the whole Expose-an-API surface.
///
/// Matching is whole-segment and case-insensitive (GUIDs have no canonical
/// case); a same-tenant restore makes the tenant rewrite a no-op. Non-`api://`
/// URIs (`https://` / verified-domain forms) are operator-owned and pass
/// through untouched.
pub fn rewrite_identifier_uris(
    uris: &[String],
    source_app_id: &str,
    new_app_id: &str,
    source_tenant_id: &str,
    dest_tenant_id: &str,
) -> Vec<String> {
    const SCHEME: &str = "api://";
    let names = |seg: &str, id: &str| !id.is_empty() && seg.eq_ignore_ascii_case(id);
    uris.iter()
        .map(|u| {
            let Some(rest) = u
                .get(..SCHEME.len())
                .filter(|p| p.eq_ignore_ascii_case(SCHEME))
                .map(|_| &u[SCHEME.len()..])
            else {
                return u.clone();
            };
            let rewritten: Vec<&str> = rest
                .split('/')
                .map(|seg| {
                    if names(seg, source_app_id) {
                        new_app_id
                    } else if names(seg, source_tenant_id) {
                        dest_tenant_id
                    } else {
                        seg
                    }
                })
                .collect();
            format!("{}{}", &u[..SCHEME.len()], rewritten.join("/"))
        })
        .collect()
}

/// Remaps pre-authorized client appIds against the backup; a client app that
/// isn't in the backup is left as-is (it may pre-exist in the destination).
pub fn remap_pre_authorized(
    pre_auth: &[PreAuthorizedApplication],
    app_id_remap: &AppIdRemap,
) -> Vec<PreAuthorizedApplication> {
    pre_auth
        .iter()
        .map(|p| PreAuthorizedApplication {
            app_id: remap_or_keep(&p.app_id, app_id_remap),
            delegated_permission_ids: p.delegated_permission_ids.clone(),
        })
        .collect()
}

/// The one remap rule, so "a miss means keep the original" cannot drift between
/// the two callers that depend on it.
fn remap_or_keep(app_id: &str, app_id_remap: &AppIdRemap) -> String {
    app_id_remap
        .get(app_id)
        .cloned()
        .unwrap_or_else(|| app_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ResourceAccess;
    use crate::scoping::MICROSOFT_GRAPH_APP_ID;

    fn remap() -> AppIdRemap {
        // Only the custom app is in the backup; Graph's appId is not.
        AppIdRemap::from([("custom-src-app".to_string(), "custom-new-app".to_string())])
    }

    fn rra(resource: &str, id: &str, kind: &str) -> RequiredResourceAccess {
        RequiredResourceAccess {
            resource_app_id: resource.to_string(),
            resource_access: vec![ResourceAccess {
                id: id.into(),
                r#type: kind.into(),
            }],
        }
    }

    #[test]
    fn first_party_resource_survives_custom_is_remapped() {
        let out = remap_required_resource_access(
            &[
                rra(MICROSOFT_GRAPH_APP_ID, "role-1", "Role"),
                rra("custom-src-app", "scope-1", "Scope"),
            ],
            &remap(),
        );
        // First-party Graph appId untouched; its permission id preserved.
        assert_eq!(out[0].resource_app_id, MICROSOFT_GRAPH_APP_ID);
        assert_eq!(out[0].resource_access[0].id, "role-1");
        // Custom resource appId remapped; scope id preserved (re-applied by the
        // custom app's own restore).
        assert_eq!(out[1].resource_app_id, "custom-new-app");
        assert_eq!(out[1].resource_access[0].id, "scope-1");
    }

    /// The remap is populated incrementally as Pass 1 creates apps, so a miss is
    /// routine — and must always mean "leave it", never "drop it" or "blank it".
    /// A remapped first-party resource points the restored app's permissions at
    /// an appId that does not exist.
    #[test]
    fn every_unknown_resource_is_left_exactly_as_it_was() {
        let empty = AppIdRemap::new();
        for resource in [
            MICROSOFT_GRAPH_APP_ID,
            "00000002-0000-0ff1-ce00-000000000000", // Office 365 Exchange Online
            "some-third-party-app",
            "",
        ] {
            let out = remap_required_resource_access(&[rra(resource, "p", "Role")], &empty);
            assert_eq!(
                out[0].resource_app_id, resource,
                "a resource absent from the remap must pass through untouched"
            );
            assert_eq!(out[0].resource_access.len(), 1, "permissions preserved");
        }
    }

    #[test]
    fn identifier_uri_rewrites_every_segment_naming_the_source_app_or_tenant() {
        // Table-driven over Microsoft's four supported `api://` forms: a GUID
        // segment must match the app's appId or the tenant id, so every segment
        // naming the source app or source tenant has to move with the restore.
        for (input, expected) in [
            // api://<appId>
            ("api://src-app", "api://new-app"),
            // api://<tenantId>/<appId> — one of the two "default" forms.
            ("api://src-tenant/src-app", "api://dst-tenant/new-app"),
            // api://<tenantId>/<string>
            ("api://src-tenant/api", "api://dst-tenant/api"),
            // api://<string>/<appId>
            ("api://productapi/src-app", "api://productapi/new-app"),
            ("api://contoso.com/src-app", "api://contoso.com/new-app"),
            // GUIDs have no canonical case.
            ("api://SRC-APP", "api://new-app"),
            ("API://src-app", "API://new-app"),
            // A different app's URI, even in the same form.
            ("api://other-app", "api://other-app"),
            // Substring, not a whole segment — must not match.
            ("api://src-app-two", "api://src-app-two"),
            ("api://src-tenant-x/api", "api://src-tenant-x/api"),
            // Non-api:// forms are operator-owned and pass through.
            ("https://contoso.com/app", "https://contoso.com/app"),
            ("https://contoso.com/src-app", "https://contoso.com/src-app"),
        ] {
            let out = rewrite_identifier_uris(
                &[input.to_string()],
                "src-app",
                "new-app",
                "src-tenant",
                "dst-tenant",
            );
            assert_eq!(out[0], expected, "input {input}");
        }
    }

    #[test]
    fn identifier_uri_rewrite_is_app_only_within_one_tenant_and_ignores_an_empty_id() {
        // Same-tenant restore: the tenant rewrite is a no-op.
        let out =
            rewrite_identifier_uris(&["api://t/src-app".into()], "src-app", "new-app", "t", "t");
        assert_eq!(out, vec!["api://t/new-app".to_string()]);
        // An empty source tenant id never matches an empty segment.
        let out =
            rewrite_identifier_uris(&["api:///src-app".into()], "src-app", "new-app", "", "dst");
        assert_eq!(out, vec!["api:///new-app".to_string()]);
    }

    #[test]
    fn pre_authorized_client_appid_remapped_when_in_backup() {
        let out = remap_pre_authorized(
            &[
                PreAuthorizedApplication {
                    app_id: "custom-src-app".into(),
                    delegated_permission_ids: vec!["p1".into()],
                },
                PreAuthorizedApplication {
                    app_id: "external-app".into(),
                    delegated_permission_ids: vec!["p2".into()],
                },
            ],
            &remap(),
        );
        assert_eq!(out[0].app_id, "custom-new-app");
        assert_eq!(
            out[0].delegated_permission_ids,
            vec!["p1".to_string()],
            "the delegated permission ids the client was pre-authorized for must survive"
        );
        // Not in the backup → left as-is (may pre-exist in the destination).
        assert_eq!(out[1].app_id, "external-app");
    }

    #[test]
    fn empty_inputs_produce_empty_plans_rather_than_panicking() {
        let empty = AppIdRemap::new();
        assert!(remap_required_resource_access(&[], &empty).is_empty());
        assert!(remap_pre_authorized(&[], &empty).is_empty());
        assert!(rewrite_identifier_uris(&[], "a", "b", "c", "d").is_empty());
    }
}
