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
//! absent from the backup or present in it but never recreated) are cheap to
//! pin.
//!
//! The command layer keeps what genuinely needs the client: creating the
//! objects, applying these plans, and reporting per-item outcomes.

use std::collections::{HashMap, HashSet};

use crate::models::{PreAuthorizedApplication, RequiredResourceAccess};

/// Source `appId` → the `appId` it was recreated as in the destination tenant.
///
/// Populated one entry at a time as Pass 1 creates each application, so a
/// lookup MISS is the normal case for anything the backup did not own — a
/// first-party Microsoft resource, or a third-party app that already exists in
/// the destination. The resource remaps therefore treat a miss as "leave it
/// alone", never as an error: rewriting `00000003-0000-0000-c000-000000000000`
/// to something else would point the restored app's permissions at nothing.
///
/// A miss is NOT that for an app the backup does own: one Pass 1 failed or
/// refused has no destination appId, and its source appId names the source
/// tenant's app. [`plan_pre_authorized`] tells the two apart, because a
/// pre-authorized client is a trust grant rather than a pointer.
pub type AppIdRemap = HashMap<String, String>;

/// The app registrations a backup owns, by source appId, with each one's
/// display name for the report.
///
/// Matched ignoring ASCII case: GUIDs have no canonical case, a pre-authorized
/// client id is stored in whatever case it was typed, and the Expose-an-API
/// editor and the manifest's own duplicate check already compare them that
/// way. A lookup yields the appId exactly as the backup spells it, which is
/// what the [`AppIdRemap`] is keyed by.
#[derive(Debug, Clone, Default)]
pub struct BackupApps(HashMap<String, BackupApp>);

#[derive(Debug, Clone)]
struct BackupApp {
    source_app_id: String,
    display_name: String,
}

impl BackupApps {
    /// From `(source appId, display name)` pairs.
    pub fn new<'a>(apps: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        Self(
            apps.into_iter()
                .map(|(source_app_id, display_name)| {
                    (
                        source_app_id.to_ascii_lowercase(),
                        BackupApp {
                            source_app_id: source_app_id.to_string(),
                            display_name: display_name.to_string(),
                        },
                    )
                })
                .collect(),
        )
    }

    /// Whether the backup owns `app_id`, in any case.
    pub fn contains(&self, app_id: &str) -> bool {
        self.get(app_id).is_some()
    }

    /// The display name the backup records for `app_id`, when it has one.
    pub fn display_name(&self, app_id: &str) -> Option<&str> {
        self.get(app_id)
            .map(|a| a.display_name.as_str())
            .filter(|name| !name.is_empty())
    }

    /// `app_id` spelled as the backup spells it — the remap's key.
    fn source_app_id(&self, app_id: &str) -> Option<&str> {
        self.get(app_id).map(|a| a.source_app_id.as_str())
    }

    fn get(&self, app_id: &str) -> Option<&BackupApp> {
        self.0.get(&app_id.to_ascii_lowercase())
    }
}

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

/// The pre-authorized clients a restored API is written with, and the ones it
/// must not be: `(kept, own_not_restored)`.
///
/// - A client this backup recreated is remapped to its destination appId, with
///   its delegated permission ids preserved.
/// - A client from outside the backup (`backup_apps` does not name it) is kept
///   as listed: it may already exist in the destination, and the plan shows it
///   (`external_pre_authorized_clients`) — shown, never withheld.
/// - A client this backup owns that Pass 1 failed or refused has no
///   destination appId. It is left out and its appId returned as listed, for
///   the caller to report. Kept, it would pre-authorize the backup's source
///   tenant's app — in a tenant-compromise recovery with a multi-tenant source
///   app, the very app being moved away from — and the plan, which lists only
///   clients from outside the backup, never showed it.
///
/// Membership ignores ASCII case ([`BackupApps`]), and so does the remap
/// lookup it leads to, so a client listed as `BBBB…` for a backup app
/// `bbbb…` is that app. A client listed more than once is planned once,
/// with its delegated permission ids merged.
pub fn plan_pre_authorized(
    pre_auth: &[PreAuthorizedApplication],
    app_id_remap: &AppIdRemap,
    backup_apps: &BackupApps,
) -> (Vec<PreAuthorizedApplication>, Vec<String>) {
    let mut kept = Vec::new();
    let mut own_not_restored = Vec::new();
    for p in dedup_pre_authorized(pre_auth) {
        match backup_apps.source_app_id(&p.app_id) {
            None => kept.push(p),
            Some(source_app_id) => match app_id_remap.get(source_app_id) {
                Some(new_app_id) => kept.push(PreAuthorizedApplication {
                    app_id: new_app_id.clone(),
                    delegated_permission_ids: p.delegated_permission_ids,
                }),
                None => own_not_restored.push(p.app_id),
            },
        }
    }
    (kept, own_not_restored)
}

/// One entry per client appId (ignoring case; the first spelling wins), its
/// delegated permission ids merged without repeats. Graph holds one entry per
/// client, and a list naming one twice would otherwise be planned — and, if it
/// is left out, reported — twice.
fn dedup_pre_authorized(pre_auth: &[PreAuthorizedApplication]) -> Vec<PreAuthorizedApplication> {
    let mut out: Vec<PreAuthorizedApplication> = Vec::new();
    let mut seen: HashMap<String, (usize, HashSet<String>)> = HashMap::new();
    for p in pre_auth {
        let (at, permissions) = seen
            .entry(p.app_id.to_ascii_lowercase())
            .or_insert_with(|| {
                out.push(PreAuthorizedApplication {
                    app_id: p.app_id.clone(),
                    delegated_permission_ids: Vec::new(),
                });
                (out.len() - 1, HashSet::new())
            });
        for id in &p.delegated_permission_ids {
            if permissions.insert(id.to_ascii_lowercase()) {
                out[*at].delegated_permission_ids.push(id.clone());
            }
        }
    }
    out
}

/// The resource remap rule, so "a miss means keep the original" is stated once.
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

    fn pre_authorized(app_id: &str, permission: &str) -> PreAuthorizedApplication {
        PreAuthorizedApplication {
            app_id: app_id.into(),
            delegated_permission_ids: vec![permission.into()],
        }
    }

    /// A backup owning `ids`, each named after itself.
    fn backup_apps(ids: &[&'static str]) -> BackupApps {
        BackupApps::new(ids.iter().map(|id| (*id, *id)))
    }

    #[test]
    fn pre_authorized_client_appid_remapped_when_in_backup() {
        let backup = backup_apps(&["custom-src-app"]);
        let (kept, own_not_restored) = plan_pre_authorized(
            &[
                pre_authorized("custom-src-app", "p1"),
                pre_authorized("external-app", "p2"),
            ],
            &remap(),
            &backup,
        );
        assert_eq!(kept[0].app_id, "custom-new-app");
        assert_eq!(
            kept[0].delegated_permission_ids,
            vec!["p1".to_string()],
            "the delegated permission ids the client was pre-authorized for must survive"
        );
        // Not in the backup → left as-is (may pre-exist in the destination).
        assert_eq!(kept[1].app_id, "external-app");
        assert_eq!(kept[1].delegated_permission_ids, vec!["p2".to_string()]);
        assert!(own_not_restored.is_empty());
    }

    /// A client the backup owns but Pass 1 never recreated has no destination
    /// appId. Its source appId names the source tenant's app, so writing it
    /// would pre-authorize that app — the plan never showed it, because the
    /// plan lists only clients from outside the backup.
    #[test]
    fn a_backup_client_that_was_not_restored_is_left_out_never_kept_by_source_appid() {
        let backup = backup_apps(&["custom-src-app", "failed-src-app", "refused-src-app"]);
        let (kept, own_not_restored) = plan_pre_authorized(
            &[
                pre_authorized("failed-src-app", "p1"),
                pre_authorized("custom-src-app", "p2"),
                pre_authorized("external-app", "p3"),
                pre_authorized("refused-src-app", "p4"),
            ],
            &remap(),
            &backup,
        );
        let kept_ids: Vec<&str> = kept.iter().map(|p| p.app_id.as_str()).collect();
        assert_eq!(kept_ids, ["custom-new-app", "external-app"]);
        assert_eq!(own_not_restored, ["failed-src-app", "refused-src-app"]);
        assert!(
            !kept_ids.iter().any(|id| backup.contains(id)),
            "no source appId from the backup may survive into the written list"
        );
    }

    /// GUIDs have no canonical case, and a pre-authorized client id keeps
    /// whatever case it was typed in. A backup app listed in another case is
    /// still that app: remapped when it was recreated, left out when it was
    /// not — never kept under its source appId as if it were foreign.
    #[test]
    fn pre_authorized_membership_and_remap_ignore_case() {
        let backup = backup_apps(&["custom-src-app", "failed-src-app"]);
        let (kept, own_not_restored) = plan_pre_authorized(
            &[
                pre_authorized("CUSTOM-SRC-APP", "p1"),
                pre_authorized("Failed-Src-App", "p2"),
            ],
            &remap(),
            &backup,
        );
        let kept_ids: Vec<&str> = kept.iter().map(|p| p.app_id.as_str()).collect();
        assert_eq!(kept_ids, ["custom-new-app"]);
        assert_eq!(own_not_restored, ["Failed-Src-App"]);
        assert!(backup.contains("FAILED-SRC-APP"));
        assert_eq!(
            backup.display_name("FAILED-SRC-APP"),
            Some("failed-src-app")
        );
    }

    /// A client listed twice (in any case) is planned once — one written
    /// entry with the permissions merged, or one left-out id to report.
    #[test]
    fn a_client_listed_twice_is_planned_once() {
        let backup = backup_apps(&["custom-src-app", "failed-src-app"]);
        let (kept, own_not_restored) = plan_pre_authorized(
            &[
                pre_authorized("external-app", "p1"),
                pre_authorized("EXTERNAL-APP", "p2"),
                pre_authorized("external-app", "P1"),
                pre_authorized("failed-src-app", "p3"),
                pre_authorized("FAILED-SRC-APP", "p3"),
                pre_authorized("custom-src-app", "p4"),
                pre_authorized("custom-src-app", "p5"),
            ],
            &remap(),
            &backup,
        );
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert_eq!(kept[0].app_id, "external-app");
        assert_eq!(kept[0].delegated_permission_ids, ["p1", "p2"]);
        assert_eq!(kept[1].app_id, "custom-new-app");
        assert_eq!(kept[1].delegated_permission_ids, ["p4", "p5"]);
        assert_eq!(own_not_restored, ["failed-src-app"]);
    }

    #[test]
    fn empty_inputs_produce_empty_plans_rather_than_panicking() {
        let empty = AppIdRemap::new();
        assert!(remap_required_resource_access(&[], &empty).is_empty());
        let (kept, own_not_restored) = plan_pre_authorized(&[], &empty, &BackupApps::default());
        assert!(kept.is_empty() && own_not_restored.is_empty());
        assert!(rewrite_identifier_uris(&[], "a", "b", "c", "d").is_empty());
    }
}
