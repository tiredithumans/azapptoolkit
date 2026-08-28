//! Pure mailbox-scope **decisions** over already-fetched Exchange data.
//!
//! These seven functions decide what an operator is told about an application's
//! effective mailbox reach: whether an authorization row is org-wide, whether a
//! composite role confers a permission, how rows fold into a verdict, whether a
//! legacy Application Access Policy confines the app, and how a surviving
//! org-wide Entra grant defeats a scoped RBAC verdict.
//!
//! They lived in `apps/desktop/src-tauri/src/commands/exchange.rs` — the largest
//! file in the repo at ~3,100 lines — reachable only through a
//! `#[tauri::command]` and therefore only testable with a Tauri `State`. That is
//! why the run-7 audit found both of that file's defects here rather than in the
//! I/O around them: the logic was correct-looking prose with no unit test able
//! to contradict it.
//!
//! Nothing here does I/O. The callers fetch (`Test-ServicePrincipalAuthorization`
//! rows, `Get-ApplicationAccessPolicy` results, the principal's Entra grants) and
//! then ask this module what the answer is.

use std::collections::{HashMap, HashSet};

use azapptoolkit_core::audit::{MailPermissionScope, ResourcePermission, ScopeMechanism};
use azapptoolkit_core::scoping::is_scopable_exchange_resource_permission;

use crate::error::ExchangeError;
use crate::models::{ExoApplicationAccessPolicy, ExoAuthorizationResult};
use crate::roles::is_blanket_mailbox_grant;

pub fn is_org_wide_auth_row(r: &ExoAuthorizationResult) -> bool {
    let allowed = r.allowed_resource_scope.as_deref().unwrap_or("").trim();
    if allowed.is_empty() || allowed.eq_ignore_ascii_case("Not Applicable") {
        return true;
    }
    matches!(
        r.scope_type
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "" | "notapplicable" | "organizationconfig" | "organizationscope" | "organization"
    )
}

/// True when a `Test-ServicePrincipalAuthorization` row confers `value` — either
/// because it *is* that permission's dedicated role, or because it's one of the
/// **composite** roles that bundle several permissions (`Application Mail Full
/// Access` → `Mail.ReadWrite` + `Mail.Send`; `Application Exchange Full Access`
/// → five permissions).
///
/// Matching `RoleName` alone missed every composite role, so a correctly scoped
/// app produced no matching row and read `OrgWide`. The cmdlet reports the
/// bundle in `GrantedPermissions`, so that is the authoritative field; the
/// role-name check stays as the fast path and as a fallback for a row that omits
/// the list.
pub fn row_grants_permission(row: &ExoAuthorizationResult, role: &str, value: &str) -> bool {
    if row.role_name.as_deref() == Some(role) {
        return true;
    }
    row.granted_permissions
        .as_deref()
        .is_some_and(|granted| granted.split(',').any(|g| g.trim() == value))
}

/// Folds the authorization rows for one Exchange role into a single verdict:
/// no row → `OrgWide` (queried OK, no scoped restriction); any org-wide row →
/// `OrgWide` (it unions to tenant-wide reach); otherwise `Scoped` to the named
/// management scope.
pub fn verdict_from_rows(rows: &[&ExoAuthorizationResult]) -> MailPermissionScope {
    if rows.is_empty() || rows.iter().any(|r| is_org_wide_auth_row(r)) {
        return MailPermissionScope::OrgWide;
    }
    // Every DISTINCT scope named across the rows, not the first one found.
    //
    // A principal can hold the same Exchange role through more than one scoped
    // assignment, and its effective reach is then the UNION of those scopes.
    // Reporting whichever row Exchange happened to return first named one scope
    // as *the* scope — so the operator saw a narrower confinement than the
    // principal actually had, and the scope shown was decided by response order.
    // Naming them all keeps the verdict a statement about reach rather than
    // about ordering.
    let mut names: Vec<String> = rows
        .iter()
        .filter_map(|r| r.allowed_resource_scope.clone())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    names.sort();
    names.dedup();
    let scope_name = match names.len() {
        0 => None,
        1 => names.pop(),
        _ => Some(names.join(", ")),
    };
    MailPermissionScope::Scoped {
        scope_name,
        recipient_filter: None,
        group_count: None,
        mechanism: ScopeMechanism::Rbac,
    }
}

/// Pure decision behind [`legacy_aap_scope`]: does any legacy Application Access
/// Policy *confine* `app_id`'s mailbox access? Only a `RestrictAccess` policy
/// scopes access to its group; a `DenyAccess` policy is a blocklist (access to
/// everything *except* the group), which is still effectively org-wide, so it is
/// not reported as scoped.
pub fn aap_verdict_for(
    policies: &[ExoApplicationAccessPolicy],
    app_id: &str,
) -> Option<MailPermissionScope> {
    // `filter`, not `find`: several RestrictAccess policies on one app grant the
    // UNION of their groups, which is why `AapMigrationItem` carries
    // `source_policy_identities` as a vector. Naming only the first understated
    // the confinement on three operator-facing surfaces, including the
    // permission tester's "which mailboxes can this reach" answer. The same bug
    // was already fixed in `verdict_from_rows`; this sibling was missed.
    //
    // The app id is casefolded because Exchange echoes back whatever case it
    // stored, and a GUID differing only in case is the same application —
    // `aap.rs` states that precondition explicitly and every other comparison in
    // that module already honours it. Left case-sensitive here, a tenant whose
    // `New-ApplicationAccessPolicy` ran with an upper-case GUID reported a
    // confined app as org-wide and scored it at full risk.
    let matching: Vec<&ExoApplicationAccessPolicy> = policies
        .iter()
        .filter(|p| {
            p.app_id
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(app_id))
                && p.access_right
                    .as_deref()
                    .is_some_and(|r| r.eq_ignore_ascii_case("RestrictAccess"))
        })
        .collect();
    if matching.is_empty() {
        return None;
    }

    let mut names: Vec<String> = matching
        .iter()
        .filter_map(|p| p.scope_name.clone().or_else(|| p.scope_identity.clone()))
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect();
    names.sort();
    names.dedup();

    Some(MailPermissionScope::Scoped {
        scope_name: match names.len() {
            0 => None,
            1 => names.pop(),
            _ => Some(names.join(", ")),
        },
        // A description belongs to ONE policy, but the confinement spans all of
        // them — showing the first policy's filter beside a multi-scope name
        // would misdescribe the reach. Dropped unless exactly one policy matched.
        recipient_filter: match matching.as_slice() {
            [only] => only.description.clone(),
            _ => None,
        },
        group_count: None,
        mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
    })
}

/// Folds a legacy Application Access Policy verdict over the lean (audit-path)
/// RBAC verdicts for one principal — the bulk-run equivalent of the per-app
/// `aap_override` [`resolve_mail_scopes`] applies on the enriched detail path.
///
/// Applied by the caller, **after** the cached probe, so
/// `resolve_mail_scopes_audit_cached` keeps caching the pure RBAC verdict and
/// the two surfaces' cache warmth stays independent (see its doc comment).
///
/// Two shapes get the override, matching the detail path's two rules:
/// - a permission RBAC reports `OrgWide` — a `RestrictAccess` policy genuinely
///   confines the org-wide Entra grant, which is why `reconcile_orgwide_grant`
///   exempts it;
/// - a permission with **no** verdict at all — the probe failed or never ran
///   (Exchange unavailable, breaker open, managed identity absent from the
///   Exchange SP store). A policy keyed on this exact appId is stronger
///   evidence than a failed probe, the same call `scope_from_rbac_error` makes.
///
/// A `Scoped` RBAC verdict is never overwritten: that app already migrated.
///
/// Takes the grants with their resources attached, not bare values: Office 365
/// Exchange Online exposes its own `Mail.*` appRoles (retired Outlook REST) that
/// an Application Access Policy cannot confine either, and a value-keyed test
/// answers `true` for them because it can only see the name. That handed the
/// legacy namesake a scoped verdict and dropped a genuinely org-wide grant out
/// of the mailbox findings at the reduced weight.
pub fn apply_legacy_policy_verdict(
    scopes: &mut HashMap<String, MailPermissionScope>,
    grants: &[ResourcePermission],
    verdict: Option<&MailPermissionScope>,
) {
    let Some(verdict) = verdict else { return };
    for grant in grants {
        if !is_scopable_exchange_resource_permission(grant.resource_app_id.as_deref(), &grant.value)
        {
            continue;
        }
        match scopes.get(&grant.value) {
            Some(MailPermissionScope::Scoped { .. }) => {}
            _ => {
                scopes.insert(grant.value.clone(), verdict.clone());
            }
        }
    }
}

/// Per-app mailbox-scope fallback when `Test-ServicePrincipalAuthorization`
/// itself fails (detail/enrich path only). An AAP confines the *whole* app (see
/// [`legacy_aap_scope`]), so the verdict applies to every scopable permission.
/// A `RestrictAccess` AAP keyed on this exact appId is stronger evidence than a
/// failed probe, so it wins even over a 403. A principal Exchange can't resolve
/// (the managed-identity case — it isn't in Exchange's SP store) has no RBAC
/// scope, so absent an AAP its org-wide Graph grant reaches every mailbox =>
/// `OrgWide`. Any other failure (403/401/network) is genuinely indeterminate and
/// is surfaced to the caller so the UI can explain *why*.
pub fn scope_from_rbac_error(
    err: ExchangeError,
    aap: Option<MailPermissionScope>,
) -> Result<MailPermissionScope, ExchangeError> {
    if let Some(scoped) = aap {
        return Ok(scoped);
    }
    if err.is_missing_object() {
        return Ok(MailPermissionScope::OrgWide);
    }
    Err(err)
}

/// Reconciles one permission's scope verdict against the org-wide Entra grants
/// the principal still holds. A scoped **RBAC** verdict for a permission whose
/// org-wide grant was never removed unions to tenant-wide reach, so it becomes
/// `OrgWide` (what `Test-ServicePrincipalAuthorization` alone misses — it can't
/// see Entra grants). A legacy Application Access Policy is exempt: it genuinely
/// confines an org-wide grant. Org-wide / unknown verdicts pass through.
///
/// A **blanket** grant (the EWS `full_access_as_app` scope) vetoes the scope of
/// *every* permission, not just its own name: it reaches every mailbox with full
/// access, so a `Mail.Read` confined to one group is still effectively org-wide
/// while it survives.
pub fn reconcile_orgwide_grant(
    verdict: MailPermissionScope,
    perm: &str,
    orgwide_granted: &HashSet<String>,
) -> MailPermissionScope {
    let scoped_via_rbac = matches!(
        verdict,
        MailPermissionScope::Scoped {
            mechanism: ScopeMechanism::Rbac,
            ..
        }
    );
    let defeated = orgwide_granted.contains(perm)
        || orgwide_granted.iter().any(|g| is_blanket_mailbox_grant(g));
    if scoped_via_rbac && defeated {
        MailPermissionScope::OrgWide
    } else {
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two scoped assignments mean the reach is the UNION, and the verdict must
    /// name both rather than whichever row Exchange returned first.
    ///
    /// A principal can hold one Exchange role through more than one scoped
    /// assignment. Reporting only the first named scope understated the reach
    /// AND made the answer depend on response ordering, so the same tenant could
    /// describe itself differently between two runs.
    #[test]
    fn several_distinct_scopes_are_all_named() {
        let a = row(
            Some("Application Mail.Read"),
            None,
            Some("scope_a"),
            Some("CustomRecipientScope"),
        );
        let b = row(
            Some("Application Mail.Read"),
            None,
            Some("scope_b"),
            Some("CustomRecipientScope"),
        );
        match verdict_from_rows(&[&a, &b]) {
            MailPermissionScope::Scoped { scope_name, .. } => {
                let named = scope_name.expect("a scoped verdict names its scope");
                assert!(
                    named.contains("scope_a") && named.contains("scope_b"),
                    "{named}"
                );
            }
            other => panic!("expected Scoped, got {other:?}"),
        }
        // Order must not change the answer.
        let forward = verdict_from_rows(&[&a, &b]);
        let reverse = verdict_from_rows(&[&b, &a]);
        assert_eq!(forward, reverse, "the verdict must not depend on row order");

        // One scope repeated is still one scope, not a list.
        let dup = row(
            Some("Application Mail.Read"),
            None,
            Some("scope_a"),
            Some("CustomRecipientScope"),
        );
        match verdict_from_rows(&[&a, &dup]) {
            MailPermissionScope::Scoped { scope_name, .. } => {
                assert_eq!(scope_name.as_deref(), Some("scope_a"));
            }
            other => panic!("expected Scoped, got {other:?}"),
        }
    }

    fn row(
        role: Option<&str>,
        granted: Option<&str>,
        scope: Option<&str>,
        scope_type: Option<&str>,
    ) -> ExoAuthorizationResult {
        ExoAuthorizationResult {
            role_name: role.map(str::to_string),
            granted_permissions: granted.map(str::to_string),
            allowed_resource_scope: scope.map(str::to_string),
            scope_type: scope_type.map(str::to_string),
            in_scope: None,
        }
    }

    fn policy(app_id: &str, right: &str, scope: &str) -> ExoApplicationAccessPolicy {
        ExoApplicationAccessPolicy {
            identity: Some(format!("{app_id}\\policy")),
            app_id: Some(app_id.to_string()),
            scope_name: Some(scope.to_string()),
            scope_identity: None,
            access_right: Some(right.to_string()),
            description: Some("desc".to_string()),
        }
    }

    fn scoped_rbac() -> MailPermissionScope {
        MailPermissionScope::Scoped {
            scope_name: Some("app_scope_x".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::Rbac,
        }
    }

    /// Every shape the cmdlet uses to say "this row is not confined". Table-driven
    /// because the set is a wire contract, not a rule: `AllowedResourceScope` is
    /// blank or the literal "Not Applicable", or `ScopeType` names an
    /// organization-level scope. Reading any of these as *scoped* would report a
    /// confinement that does not exist.
    #[test]
    fn org_wide_rows_are_recognised_in_every_spelling() {
        for (scope, scope_type) in [
            (None, None),
            (Some(""), None),
            (Some("   "), None),
            (Some("Not Applicable"), None),
            (Some("not applicable"), None),
            (Some("SomeScope"), Some("OrganizationConfig")),
            (Some("SomeScope"), Some("organizationscope")),
            (Some("SomeScope"), Some("Organization")),
            (Some("SomeScope"), Some("")),
        ] {
            assert!(
                is_org_wide_auth_row(&row(None, None, scope, scope_type)),
                "scope={scope:?} scope_type={scope_type:?} must read org-wide"
            );
        }
        // A named scope with a recipient-level ScopeType is genuinely confined.
        assert!(!is_org_wide_auth_row(&row(
            None,
            None,
            Some("app_scope_x"),
            Some("RecipientScope")
        )));
    }

    /// The composite-role case. Matching `RoleName` alone missed every bundled
    /// role, so a correctly scoped app produced no matching row and read
    /// `OrgWide` — a confined app reported as tenant-wide.
    #[test]
    fn a_composite_role_confers_the_permissions_it_bundles() {
        let composite = row(
            Some("Application Mail Full Access"),
            Some("Mail.ReadWrite, Mail.Send"),
            Some("app_scope_x"),
            Some("RecipientScope"),
        );
        assert!(row_grants_permission(
            &composite,
            "Application Mail.ReadWrite",
            "Mail.ReadWrite"
        ));
        assert!(row_grants_permission(
            &composite,
            "Application Mail.Send",
            "Mail.Send"
        ));
        assert!(
            !row_grants_permission(&composite, "Application Calendars.Read", "Calendars.Read"),
            "the bundle must not confer a permission it does not list"
        );

        // The dedicated-role fast path still works when the bundle list is absent.
        let dedicated = row(Some("Application Mail.Read"), None, Some("s"), Some("R"));
        assert!(row_grants_permission(
            &dedicated,
            "Application Mail.Read",
            "Mail.Read"
        ));
    }

    #[test]
    fn rows_fold_to_org_wide_unless_every_row_is_confined() {
        // No rows at all: the probe answered, and found no restriction.
        assert!(matches!(
            verdict_from_rows(&[]),
            MailPermissionScope::OrgWide
        ));

        let confined = row(None, None, Some("app_scope_x"), Some("RecipientScope"));
        let wide = row(None, None, None, None);

        // One org-wide row unions to tenant-wide reach, even beside a scoped one.
        assert!(matches!(
            verdict_from_rows(&[&confined, &wide]),
            MailPermissionScope::OrgWide
        ));

        match verdict_from_rows(&[&confined]) {
            MailPermissionScope::Scoped {
                scope_name,
                mechanism,
                ..
            } => {
                assert_eq!(scope_name.as_deref(), Some("app_scope_x"));
                assert_eq!(mechanism, ScopeMechanism::Rbac);
            }
            other => panic!("expected Scoped, got {other:?}"),
        }
    }

    /// `DenyAccess` is a blocklist — access to everything EXCEPT the group — so
    /// rebuilding it as an allow-list scope inverts it. It must never read as a
    /// confinement.
    #[test]
    fn only_a_restrict_access_policy_confines() {
        let policies = vec![
            policy("app-1", "RestrictAccess", "Sales"),
            policy("app-2", "DenyAccess", "Interns"),
        ];
        match aap_verdict_for(&policies, "app-1") {
            Some(MailPermissionScope::Scoped {
                scope_name,
                mechanism,
                ..
            }) => {
                assert_eq!(scope_name.as_deref(), Some("Sales"));
                assert_eq!(mechanism, ScopeMechanism::LegacyApplicationAccessPolicy);
            }
            other => panic!("expected a legacy-policy verdict, got {other:?}"),
        }
        assert!(
            aap_verdict_for(&policies, "app-2").is_none(),
            "a DenyAccess blocklist is still effectively org-wide"
        );
        assert!(aap_verdict_for(&policies, "app-3").is_none());
        // Case-insensitive on AccessRight, matching the migration planner.
        assert!(aap_verdict_for(&[policy("a", "restrictaccess", "S")], "a").is_some());
    }

    /// Exchange echoes the AppId back in whatever case it stored, and a GUID
    /// differing only in case is the same application — `aap.rs` states that
    /// precondition explicitly. This comparison was the one that still didn't
    /// honour it, so in a tenant where `New-ApplicationAccessPolicy` ran with an
    /// upper-case GUID a confined app reported as org-wide and scored at full
    /// risk.
    #[test]
    fn the_app_id_match_is_case_insensitive_like_the_rest_of_the_module() {
        let stored = policy(
            "11111111-AAAA-2222-BBBB-333333333333",
            "RestrictAccess",
            "Sales",
        );
        for queried in [
            "11111111-aaaa-2222-bbbb-333333333333",
            "11111111-AAAA-2222-BBBB-333333333333",
            "11111111-AaAa-2222-BbBb-333333333333",
        ] {
            assert!(
                aap_verdict_for(std::slice::from_ref(&stored), queried).is_some(),
                "{queried} is the same application as the stored GUID"
            );
        }
        // A genuinely different app is still not confined.
        assert!(aap_verdict_for(&[stored], "44444444-4444-4444-4444-444444444444").is_none());
    }

    /// Several RestrictAccess policies on one app grant the UNION of their
    /// groups — which is why `AapMigrationItem` carries a vector of source
    /// policies. Naming only the first understated the confinement on three
    /// operator-facing surfaces, including the permission tester's "which
    /// mailboxes can this reach" answer. `verdict_from_rows` already unions;
    /// this sibling was missed.
    #[test]
    fn several_restrict_access_policies_union_their_scopes() {
        let policies = vec![
            policy("app-1", "RestrictAccess", "Sales"),
            policy("app-1", "RestrictAccess", "Execs"),
            // Neither a match for this app nor a confining right.
            policy("app-1", "DenyAccess", "Interns"),
            policy("app-2", "RestrictAccess", "Support"),
        ];
        match aap_verdict_for(&policies, "app-1") {
            Some(MailPermissionScope::Scoped {
                scope_name,
                recipient_filter,
                ..
            }) => {
                // Sorted and deduped, so the string is stable across Exchange's
                // response ordering.
                assert_eq!(scope_name.as_deref(), Some("Execs, Sales"));
                // A description belongs to ONE policy; showing the first
                // policy's filter beside a two-scope name would misdescribe the
                // reach, so it is dropped when the union spans policies.
                assert_eq!(recipient_filter, None);
            }
            other => panic!("expected a unioned legacy verdict, got {other:?}"),
        }
        // A single match still carries its own description.
        match aap_verdict_for(&policies, "app-2") {
            Some(MailPermissionScope::Scoped {
                scope_name,
                recipient_filter,
                ..
            }) => {
                assert_eq!(scope_name.as_deref(), Some("Support"));
                assert_eq!(recipient_filter.as_deref(), Some("desc"));
            }
            other => panic!("expected a single-scope verdict, got {other:?}"),
        }
    }

    /// The legacy override must reach only the resources an Application Access
    /// Policy can actually confine. Office 365 Exchange Online's own `Mail.*`
    /// appRoles (retired Outlook REST) are not among them, and a value-keyed
    /// test answers `true` for them because it can only see the name — handing
    /// the legacy namesake a scoped verdict and dropping a genuinely org-wide
    /// grant out of the mailbox findings at the reduced weight.
    #[test]
    fn the_legacy_override_is_resource_aware_and_never_downgrades_rbac() {
        let graph = azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
        let ews = azapptoolkit_core::scoping::OFFICE365_EXCHANGE_ONLINE_APP_ID;
        let grants = vec![
            ResourcePermission {
                resource_app_id: Some(graph.to_string()),
                value: "Mail.Read".to_string(),
            },
            // Same NAME, unconfinable resource.
            ResourcePermission {
                resource_app_id: Some(ews.to_string()),
                value: "Calendars.Read".to_string(),
            },
            ResourcePermission {
                resource_app_id: Some(graph.to_string()),
                value: "Mail.ReadWrite".to_string(),
            },
        ];
        let legacy = MailPermissionScope::Scoped {
            scope_name: Some("Sales".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
        };

        let mut scopes = HashMap::new();
        // An existing RBAC verdict is never overwritten: that app already migrated.
        scopes.insert("Mail.ReadWrite".to_string(), scoped_rbac());
        apply_legacy_policy_verdict(&mut scopes, &grants, Some(&legacy));

        assert!(
            matches!(
                scopes.get("Mail.Read"),
                Some(MailPermissionScope::Scoped {
                    mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
                    ..
                })
            ),
            "a Graph mail permission with no verdict takes the legacy one"
        );
        assert!(
            !scopes.contains_key("Calendars.Read"),
            "the Office 365 namesake is not confinable by a policy, so it must be left alone"
        );
        assert!(
            matches!(
                scopes.get("Mail.ReadWrite"),
                Some(MailPermissionScope::Scoped {
                    mechanism: ScopeMechanism::Rbac,
                    ..
                })
            ),
            "an existing RBAC verdict must not be downgraded to the legacy mechanism"
        );

        // No verdict ⇒ no change at all.
        let before = scopes.clone();
        apply_legacy_policy_verdict(&mut scopes, &grants, None);
        assert_eq!(scopes.len(), before.len());
    }

    /// Microsoft's guidance: an un-stripped org-wide grant *unions* with the
    /// scoped role, so the app still reaches every mailbox. A legacy policy is
    /// exempt — it genuinely confines the org-wide grant.
    #[test]
    fn a_surviving_org_wide_grant_defeats_a_scoped_rbac_verdict() {
        let held: HashSet<String> = ["Mail.Read".to_string()].into_iter().collect();
        assert!(matches!(
            reconcile_orgwide_grant(scoped_rbac(), "Mail.Read", &held),
            MailPermissionScope::OrgWide
        ));
        // A different permission's grant does not defeat this one.
        assert!(matches!(
            reconcile_orgwide_grant(scoped_rbac(), "Calendars.Read", &held),
            MailPermissionScope::Scoped { .. }
        ));

        // A BLANKET grant vetoes every permission's scope, not just its own name:
        // EWS full_access_as_app reaches every mailbox with full access.
        let blanket: HashSet<String> =
            [azapptoolkit_core::scoping::EWS_FULL_ACCESS_AS_APP.to_string()]
                .into_iter()
                .collect();
        assert!(matches!(
            reconcile_orgwide_grant(scoped_rbac(), "Calendars.Read", &blanket),
            MailPermissionScope::OrgWide
        ));

        // A legacy policy is exempt.
        let legacy = MailPermissionScope::Scoped {
            scope_name: Some("Sales".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
        };
        assert!(matches!(
            reconcile_orgwide_grant(legacy, "Mail.Read", &held),
            MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
                ..
            }
        ));
    }

    /// A `RestrictAccess` policy keyed on this exact appId is stronger evidence
    /// than a failed probe — it wins even over a 403. A principal Exchange
    /// cannot resolve (the managed-identity case) has no RBAC scope, so absent a
    /// policy its org-wide Graph grant reaches every mailbox. Anything else is
    /// genuinely indeterminate and must surface so the UI can say why.
    #[test]
    fn a_failed_probe_falls_back_to_the_policy_then_to_org_wide_then_errors() {
        let legacy = MailPermissionScope::Scoped {
            scope_name: Some("Sales".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
        };
        assert!(matches!(
            scope_from_rbac_error(
                ExchangeError::Forbidden {
                    detail: String::new(),
                    had_diagnostics: false,
                },
                Some(legacy)
            ),
            Ok(MailPermissionScope::Scoped { .. })
        ));
        assert!(
            scope_from_rbac_error(
                ExchangeError::Forbidden {
                    detail: String::new(),
                    had_diagnostics: false,
                },
                None
            )
            .is_err(),
            "a 403 with no policy is indeterminate, not org-wide"
        );
    }

    // ---- relocated from commands/exchange.rs with the logic they cover ----

    #[test]
    fn legacy_policy_verdict_fills_org_wide_and_missing_but_never_an_rbac_scope() {
        let legacy = aap_verdict_for(&[policy("app-1", "RestrictAccess", "Sales")], "app-1")
            .expect("legacy verdict");
        let rbac = MailPermissionScope::Scoped {
            scope_name: Some("app_scope_app-1".into()),
            recipient_filter: None,
            group_count: Some(1),
            mechanism: ScopeMechanism::Rbac,
        };
        let mut scopes = HashMap::from([
            ("Mail.Read".to_string(), MailPermissionScope::OrgWide),
            ("Mail.Send".to_string(), rbac.clone()),
        ]);
        let grants = [
            ResourcePermission::graph("Mail.Read"),
            ResourcePermission::graph("Mail.Send"),
            // No verdict at all (probe failed / never ran) — the policy answers.
            ResourcePermission::graph("Calendars.Read"),
            // Not Exchange-scopable: a policy can't confine it, so it must not
            // gain a scoped verdict (that would under-report its reach).
            ResourcePermission::graph("Directory.Read.All"),
            // Same NAME as a scopable Graph permission, different resource. An
            // Application Access Policy cannot confine Office 365 Exchange
            // Online's retired Outlook REST appRoles, so this must not lend the
            // legacy grant a scoped verdict — the value-keyed test could not
            // tell the two apart and did exactly that.
            ResourcePermission::exchange_online("Contacts.Read"),
            // An unresolvable resource is never treated as scoped.
            ResourcePermission {
                resource_app_id: None,
                value: "MailboxSettings.Read".to_string(),
            },
        ];

        apply_legacy_policy_verdict(&mut scopes, &grants, Some(&legacy));

        assert_eq!(scopes.get("Mail.Read"), Some(&legacy), "org-wide → legacy");
        assert_eq!(
            scopes.get("Calendars.Read"),
            Some(&legacy),
            "no verdict → legacy"
        );
        assert_eq!(
            scopes.get("Mail.Send"),
            Some(&rbac),
            "an app that already migrated keeps its RBAC verdict"
        );
        assert!(!scopes.contains_key("Directory.Read.All"));
        assert!(
            !scopes.contains_key("Contacts.Read"),
            "an AAP cannot confine Office 365 Exchange Online's own Contacts.Read, so it must \
             not earn a scoped verdict — scoring it at the reduced weight hides org-wide reach"
        );
        assert!(
            !scopes.contains_key("MailboxSettings.Read"),
            "an unresolved resource must be scored conservatively, never as scoped"
        );

        // No policy for this app ⇒ untouched (today's behavior).
        let mut untouched =
            HashMap::from([("Mail.Read".to_string(), MailPermissionScope::OrgWide)]);
        apply_legacy_policy_verdict(&mut untouched, &grants, None);
        assert_eq!(
            untouched.get("Mail.Read"),
            Some(&MailPermissionScope::OrgWide)
        );
    }

    #[test]
    fn rbac_error_restrict_access_aap_wins_even_over_forbidden() {
        // A RestrictAccess AAP keyed on this appId is authoritative regardless of
        // why the probe failed — it confines the whole app.
        let aap = aap_verdict_for(&[policy("app-1", "RestrictAccess", "Sales")], "app-1");
        match scope_from_rbac_error(
            ExchangeError::Forbidden {
                detail: "nope".into(),
                had_diagnostics: false,
            },
            aap,
        )
        .expect("AAP should resolve the verdict")
        {
            MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
                ..
            } => {}
            other => panic!("expected legacy-AAP Scoped, got {other:?}"),
        }
    }

    #[test]
    fn rbac_missing_object_without_aap_is_org_wide() {
        // The managed-identity case: the principal isn't in Exchange's SP store,
        // so it has no RBAC scope — its org-wide Graph grant reaches every mailbox.
        for err in [
            ExchangeError::NotFound("object couldn't be found".into()),
            ExchangeError::Api {
                status: 400,
                body: "[Test-ServicePrincipalAuthorization] couldn't be found".into(),
            },
        ] {
            assert_eq!(
                scope_from_rbac_error(err, None).expect("missing object => org-wide"),
                MailPermissionScope::OrgWide,
            );
        }
    }

    #[test]
    fn rbac_genuine_forbidden_without_aap_propagates() {
        // Not a missing object — the caller can't run the cmdlet, so scoping is
        // genuinely indeterminate. Surface it (caller shows a consent/403 banner).
        let err = scope_from_rbac_error(
            ExchangeError::Forbidden {
                detail: "RBAC denied".into(),
                had_diagnostics: true,
            },
            None,
        )
        .expect_err("genuine 403 must propagate");
        assert!(matches!(err, ExchangeError::Forbidden { .. }));
    }
}
