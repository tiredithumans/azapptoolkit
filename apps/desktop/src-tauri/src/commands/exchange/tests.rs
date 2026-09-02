//! Unit tests for the Exchange command layer (`super`).

use super::*;

use azapptoolkit_core::models::{
    AppRoleAssignment, Application, RequiredResourceAccess, ResourceAccess,
};
use azapptoolkit_core::scoping::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
    exchange_role_for_resource_permission,
};

fn target(value: &str) -> ExchangeTarget {
    ExchangeTarget {
        graph_value: value.to_string(),
        exchange_role: "Application Mail.Read",
        app_role_id: "role-id".to_string(),
        resource_sp_object_id: "graph-sp".to_string(),
    }
}

fn values(targets: &[ExchangeTarget]) -> Vec<&str> {
    targets.iter().map(|t| t.graph_value.as_str()).collect()
}

/// The two mailbox resources as they resolve in a tenant, with one appRole
/// each keyed `role-<value>`.
fn mailbox_resources() -> Vec<ResourceRoles> {
    let index = |values: &[&str]| -> HashMap<String, String> {
        values
            .iter()
            .map(|v| (format!("role-{v}"), v.to_string()))
            .collect()
    };
    vec![
        ResourceRoles {
            app_id: MICROSOFT_GRAPH_APP_ID,
            sp_object_id: "graph-sp".to_string(),
            role_value_by_id: index(&["Mail.Read", "Mail.Send", "User.Read.All"]),
        },
        ResourceRoles {
            app_id: OFFICE365_EXCHANGE_ONLINE_APP_ID,
            sp_object_id: "exo-sp".to_string(),
            // The legacy resource exposes the EWS scope AND its own
            // Outlook-REST `Mail.Read` appRole (a different GUID).
            role_value_by_id: [
                (
                    format!("exo-role-{EWS_FULL_ACCESS_AS_APP}"),
                    EWS_FULL_ACCESS_AS_APP.to_string(),
                ),
                ("exo-role-Mail.Read".to_string(), "Mail.Read".to_string()),
            ]
            .into(),
        },
    ]
}

fn declared(resource_app_id: &str, role_ids: &[&str]) -> RequiredResourceAccess {
    RequiredResourceAccess {
        resource_app_id: resource_app_id.to_string(),
        resource_access: role_ids
            .iter()
            .map(|id| ResourceAccess {
                id: id.to_string(),
                r#type: "Role".to_string(),
            })
            .collect(),
    }
}

fn grant(resource_sp_id: &str, app_role_id: &str) -> AppRoleAssignment {
    AppRoleAssignment {
        id: format!("assign-{app_role_id}"),
        resource_id: resource_sp_id.to_string(),
        app_role_id: app_role_id.to_string(),
        ..Default::default()
    }
}

#[test]
fn declared_targets_span_graph_and_the_legacy_ews_scope() {
    // The EWS `full_access_as_app` scope is the one non-Graph permission an
    // Application Access Policy could confine. Deriving targets from Microsoft
    // Graph alone made it invisible: no `Application EWS.AccessAsApp` was ever
    // assigned and its org-wide grant was never stripped.
    let app = Application {
        required_resource_access: vec![
            declared(
                MICROSOFT_GRAPH_APP_ID,
                &["role-Mail.Read", "role-User.Read.All"],
            ),
            declared(
                OFFICE365_EXCHANGE_ONLINE_APP_ID,
                &[&format!("exo-role-{EWS_FULL_ACCESS_AS_APP}")],
            ),
        ],
        ..Default::default()
    };
    let targets = targets_from_declared(&app, &mailbox_resources());
    assert_eq!(values(&targets), ["Mail.Read", EWS_FULL_ACCESS_AS_APP]);
    // Each target carries the resource SP its grant lives on, so the strip
    // can't hit the wrong resource.
    assert_eq!(targets[0].resource_sp_object_id, "graph-sp");
    assert_eq!(targets[1].resource_sp_object_id, "exo-sp");
    assert_eq!(targets[1].exchange_role, "Application EWS.AccessAsApp");
}

#[test]
fn declared_targets_skip_exchange_onlines_own_mail_roles() {
    // Office 365 Exchange Online's `Mail.Read` (retired Outlook REST) has no
    // RBAC-for-Applications counterpart, so it must not become a target —
    // stripping it would leave the app with no scoped replacement.
    let app = Application {
        required_resource_access: vec![declared(
            OFFICE365_EXCHANGE_ONLINE_APP_ID,
            &["exo-role-Mail.Read"],
        )],
        ..Default::default()
    };
    assert!(targets_from_declared(&app, &mailbox_resources()).is_empty());
}

#[test]
fn granted_targets_span_both_resources_and_keep_resources_apart() {
    // Migration derives its targets from held grants. Both resources expose an
    // appRole named `Mail.Read`; each target must point at the resource its own
    // grant was made on.
    let assignments = vec![
        grant("graph-sp", "role-Mail.Send"),
        grant("exo-sp", &format!("exo-role-{EWS_FULL_ACCESS_AS_APP}")),
        grant("exo-sp", "exo-role-Mail.Read"), // not RBAC-scopable
        grant("other-sp", "role-Mail.Read"),   // unrelated resource
    ];
    let targets = targets_from_grants(&assignments, &mailbox_resources());
    assert_eq!(values(&targets), ["Mail.Send", EWS_FULL_ACCESS_AS_APP]);
    assert_eq!(targets[0].resource_sp_object_id, "graph-sp");
    assert_eq!(targets[1].resource_sp_object_id, "exo-sp");
}

#[test]
fn filter_none_keeps_every_target() {
    // The coarse Exchange-scoping-section path scopes all declared mail permissions.
    let targets = vec![target("Mail.Read"), target("Mail.Send")];
    let out = filter_targets_by_value(targets, None);
    assert_eq!(values(&out), ["Mail.Read", "Mail.Send"]);
}

#[test]
fn scope_and_group_names_follow_distinct_conventions() {
    let app = "71487acd-ec93-476d-bd0e-6c8b31831053";
    // The management scope and its backing mail-group are deliberately named
    // apart so they never collide: scope = `app_scope_<app>`,
    // group = `app_scope_group_<app>`. Both defaults are user-overridable via
    // the Settings naming patterns (resolved by `TenantDefaults`).
    let d = TenantDefaults::default();
    assert_eq!(d.scope_name_for(app), format!("app_scope_{app}"));
    assert_eq!(d.group_name_for(app), format!("app_scope_group_{app}"));
    assert_ne!(d.scope_name_for(app), d.group_name_for(app));
}

#[test]
fn alias_is_safe_and_bounded() {
    let app = "71487acd-ec93-476d-bd0e-6c8b31831053";
    let alias = sanitize_alias(&TenantDefaults::default().group_name_for(app));
    // A GUID-based name is already alias-safe and well under the 64 cap.
    assert_eq!(alias, format!("app_scope_group_{app}"));
    assert!(alias.len() <= 64);
    // Disallowed characters are dropped; length is capped.
    let messy = sanitize_alias(&format!("azapptoolkit_a b@c!{}", "x".repeat(80)));
    assert!(
        messy
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    );
    assert_eq!(messy.len(), 64);
}

#[test]
fn filter_some_keeps_only_requested() {
    // The per-permission "Scope this one" path narrows to a single value.
    let targets = vec![
        target("Mail.Read"),
        target("Mail.Send"),
        target("Calendars.Read"),
    ];
    let out = filter_targets_by_value(targets, Some(&["Mail.Send".to_string()]));
    assert_eq!(values(&out), ["Mail.Send"]);
}

fn rbac_scope() -> MailPermissionScope {
    MailPermissionScope::Scoped {
        scope_name: Some("azapptoolkit_x".into()),
        recipient_filter: None,
        group_count: None,
        mechanism: ScopeMechanism::Rbac,
    }
}

#[tokio::test]
async fn audit_cached_scopes_skip_probe_and_cache_for_nonmail_perms() {
    // A non-mail permission set must short-circuit before any Exchange call
    // (the base points nowhere) AND leave no cache entry — otherwise the
    // audit would create a useless entry per non-mail app, bloating the
    // cache it's meant to reuse.
    use azapptoolkit_core::token::StaticTokenProvider;
    let cache = Cache::new();
    let exo = ExchangeClient::with_base_url(
        StaticTokenProvider::new("t"),
        "tenant-1",
        "admin@contoso.com",
        "http://127.0.0.1:9".to_string(),
    );
    let out = resolve_mail_scopes_audit_cached(
        &cache,
        "tenant-1",
        &exo,
        "app-1",
        &["User.Read.All".to_string()],
        &HashSet::new(),
    )
    .await
    .unwrap();
    assert!(out.is_empty());
    // The whole audit discriminator for this app is absent (empty perm set).
    let key = mail_scopes_key("tenant-1", "audit|app-1|");
    assert!(
        cache
            .get::<HashMap<String, MailPermissionScope>>(CacheKind::Lists, &key)
            .is_none()
    );
}

#[test]
fn reconcile_downgrades_rbac_scope_when_orgwide_grant_remains() {
    let granted: HashSet<String> = ["Mail.Read".to_string()].into_iter().collect();
    // Test-ServicePrincipalAuthorization can't see the Entra grant, so a scoped
    // RBAC role coexisting with the un-stripped org-wide grant unions to org-wide.
    assert!(matches!(
        reconcile_orgwide_grant(rbac_scope(), "Mail.Read", &granted),
        MailPermissionScope::OrgWide
    ));
}

#[test]
fn reconcile_keeps_rbac_scope_when_no_residual_grant() {
    // Properly stripped: scoped RBAC with no org-wide grant stays scoped.
    assert!(matches!(
        reconcile_orgwide_grant(rbac_scope(), "Mail.Read", &HashSet::new()),
        MailPermissionScope::Scoped {
            mechanism: ScopeMechanism::Rbac,
            ..
        }
    ));
    // A grant for a *different* permission must not affect this one.
    let other: HashSet<String> = ["Calendars.ReadWrite".to_string()].into_iter().collect();
    assert!(matches!(
        reconcile_orgwide_grant(rbac_scope(), "Mail.Read", &other),
        MailPermissionScope::Scoped { .. }
    ));
}

#[test]
fn reconcile_lets_a_surviving_ews_grant_defeat_every_scope() {
    // `full_access_as_app` reaches every mailbox with full access, so while it
    // survives org-wide, a `Mail.Read` confined to one group is still org-wide
    // in effect — even though the granted set never names `Mail.Read`.
    let granted: HashSet<String> = [EWS_FULL_ACCESS_AS_APP.to_string()].into_iter().collect();
    assert!(matches!(
        reconcile_orgwide_grant(rbac_scope(), "Mail.Read", &granted),
        MailPermissionScope::OrgWide
    ));
    assert!(matches!(
        reconcile_orgwide_grant(rbac_scope(), "Calendars.ReadWrite", &granted),
        MailPermissionScope::OrgWide
    ));
}

#[test]
fn reconcile_never_downgrades_legacy_aap_scope() {
    // A RestrictAccess AAP genuinely confines an org-wide grant — exempt.
    let granted: HashSet<String> = ["Mail.Read".to_string()].into_iter().collect();
    let aap = MailPermissionScope::Scoped {
        scope_name: Some("Policy-X".into()),
        recipient_filter: None,
        group_count: None,
        mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
    };
    assert!(matches!(
        reconcile_orgwide_grant(aap, "Mail.Read", &granted),
        MailPermissionScope::Scoped {
            mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
            ..
        }
    ));
}

#[test]
fn filter_empty_list_keeps_nothing() {
    let targets = vec![target("Mail.Read")];
    let out = filter_targets_by_value(targets, Some(&[]));
    assert!(out.is_empty());
}

#[test]
fn org_wide_strip_skips_targets_whose_scoped_role_failed() {
    // Mirrors sharepoint::org_wide_removal_requires_a_landed_site_grant: a
    // target whose scoped Exchange role did NOT land keeps its org-wide grant,
    // so a partial assignment failure never strands the principal with no
    // mailbox access. Only the landed/already-present ones are stripped.
    let scoped = vec![
        (target("Mail.Read"), true),  // assigned or already present → strip
        (target("Mail.Send"), false), // assignment failed → keep org-wide grant
    ];
    let out = targets_safe_to_strip(scoped);
    assert_eq!(values(&out), ["Mail.Read"]);
}

#[test]
fn org_wide_strip_keeps_nothing_when_all_assignments_fail() {
    let scoped = vec![(target("Mail.Read"), false), (target("Mail.Send"), false)];
    assert!(targets_safe_to_strip(scoped).is_empty());
}

#[test]
fn group_dns_in_filter_extracts_the_dn_set() {
    // Round-trips what `member_of_group_filter` produces, set-wise.
    let dns = ["CN=a,DC=x".to_string(), "CN=b,DC=y".to_string()];
    let filter = member_of_group_filter(&dns);
    let got = group_dns_in_filter(&filter);
    assert_eq!(
        got,
        ["CN=a,DC=x".to_string(), "CN=b,DC=y".to_string()]
            .into_iter()
            .collect()
    );
}

#[test]
fn group_dns_in_filter_is_formatting_agnostic() {
    // Exchange may echo the filter with extra parens/whitespace; the group
    // *set* is what we compare, so those differences don't trip the warning.
    let same = group_dns_in_filter("(MemberOfGroup  -eq  'CN=a,DC=x')")
        == group_dns_in_filter("MemberOfGroup -eq 'CN=a,DC=x'");
    assert!(same);
    // A genuinely different group set is detected.
    assert_ne!(
        group_dns_in_filter("MemberOfGroup -eq 'CN=a,DC=x'"),
        group_dns_in_filter("MemberOfGroup -eq 'CN=b,DC=y'"),
    );
}

fn auth_row(role: &str, allowed_scope: Option<&str>, scope_type: &str) -> ExoAuthorizationResult {
    ExoAuthorizationResult {
        role_name: Some(role.to_string()),
        granted_permissions: None,
        allowed_resource_scope: allowed_scope.map(str::to_string),
        scope_type: Some(scope_type.to_string()),
        in_scope: None,
    }
}

#[test]
fn verdict_from_rows_tags_rbac_mechanism() {
    // A row confined to a custom recipient scope is RBAC-scoped.
    let row = auth_row(
        "Application Mail.Read",
        Some("azapptoolkit_app-1"),
        "CustomRecipientScope",
    );
    assert!(matches!(
        verdict_from_rows(&[&row]),
        MailPermissionScope::Scoped {
            mechanism: ScopeMechanism::Rbac,
            ..
        }
    ));
}

#[test]
fn composite_roles_confer_each_bundled_permission() {
    // `Application Mail Full Access` grants Mail.ReadWrite + Mail.Send without
    // carrying either permission's role name. Matching RoleName alone found no
    // row for `Mail.Send`, so a correctly scoped app read org-wide.
    let mut row = auth_row(
        "Application Mail Full Access",
        Some("azapptoolkit_app-1"),
        "CustomRecipientScope",
    );
    row.granted_permissions = Some("Mail.ReadWrite, Mail.Send".to_string());
    assert!(row_grants_permission(
        &row,
        "Application Mail.Send",
        "Mail.Send"
    ));
    assert!(row_grants_permission(
        &row,
        "Application Mail.ReadWrite",
        "Mail.ReadWrite"
    ));
    // A permission the composite does NOT bundle still doesn't match.
    assert!(!row_grants_permission(
        &row,
        "Application Calendars.Read",
        "Calendars.Read"
    ));
    // ...and a permission substring must not match a longer value.
    let mut basic = auth_row("Application Mail.ReadBasic", None, "CustomRecipientScope");
    basic.granted_permissions = Some("Mail.ReadBasic".to_string());
    assert!(!row_grants_permission(
        &basic,
        "Application Mail.Read",
        "Mail.Read"
    ));
}

#[test]
fn dedicated_role_name_still_matches_without_a_permission_list() {
    // The fast path / fallback: a row that omits GrantedPermissions is still
    // matched by its role name.
    let row = auth_row("Application Mail.Read", None, "CustomRecipientScope");
    assert!(row_grants_permission(
        &row,
        "Application Mail.Read",
        "Mail.Read"
    ));
}

fn aap(app_id: &str, access_right: &str, scope: Option<&str>) -> ExoApplicationAccessPolicy {
    ExoApplicationAccessPolicy {
        identity: Some("policy-1".into()),
        app_id: Some(app_id.into()),
        scope_name: scope.map(str::to_string),
        scope_identity: None,
        access_right: Some(access_right.into()),
        description: None,
    }
}

#[test]
fn aap_restrict_access_is_scoped_via_legacy_mechanism() {
    // The legacy fallback only fires when RBAC reports org-wide; a
    // RestrictAccess policy then confines the app to its scope group.
    let policies = [aap("app-1", "RestrictAccess", Some("Sales"))];
    match aap_verdict_for(&policies, "app-1").expect("should be scoped") {
        MailPermissionScope::Scoped {
            mechanism,
            scope_name,
            ..
        } => {
            assert_eq!(mechanism, ScopeMechanism::LegacyApplicationAccessPolicy);
            assert_eq!(scope_name.as_deref(), Some("Sales"));
        }
        other => panic!("expected Scoped, got {other:?}"),
    }
}

#[test]
fn aap_deny_access_is_not_scoped() {
    // DenyAccess is a blocklist (everything *except* the group) — still
    // effectively org-wide, so it must NOT be reported as scoped.
    let policies = [aap("app-1", "DenyAccess", Some("Execs"))];
    assert!(aap_verdict_for(&policies, "app-1").is_none());
}

#[test]
fn aap_ignores_policies_for_other_apps() {
    let policies = [aap("other-app", "RestrictAccess", Some("Sales"))];
    assert!(aap_verdict_for(&policies, "app-1").is_none());
}

#[test]
fn retired_groups_note_names_them_and_only_claims_clean_when_it_is() {
    let clean = RetiredScopeGroupDto {
        display_name: Some("Sales Mailboxes".into()),
        primary_smtp_address: None,
        distinguished_name: "CN=Sales,DC=x".into(),
        still_referenced_by: Vec::new(),
        reference_check_complete: true,
    };
    let note = retired_groups_note(std::slice::from_ref(&clean));
    assert!(note.starts_with("'Sales Mailboxes' is"), "{note}");
    assert!(note.contains("can be cleaned up"), "{note}");

    // A live reference must NOT read as cleanable.
    let referenced = RetiredScopeGroupDto {
        still_referenced_by: vec!["management scope 'app_scope_other'".into()],
        ..clean.clone()
    };
    let note = retired_groups_note(&[referenced]);
    assert!(!note.contains("can be cleaned up"), "{note}");
    assert!(note.contains("review the notes"), "{note}");

    // Nor may an INCOMPLETE check — an unknown is not a clean bill of
    // health. The name falls back to the DN, still enough to find it.
    let unchecked = RetiredScopeGroupDto {
        display_name: None,
        primary_smtp_address: None,
        distinguished_name: "CN=Ghost,DC=x".into(),
        still_referenced_by: Vec::new(),
        reference_check_complete: false,
    };
    let note = retired_groups_note(&[unchecked]);
    assert!(note.starts_with("'CN=Ghost,DC=x' is"), "{note}");
    assert!(!note.contains("can be cleaned up"), "{note}");

    assert!(
        !retired_groups_note(&[]).is_empty(),
        "no resolved group must still read as a sentence"
    );
}

#[test]
fn migration_keeps_the_policy_while_any_grant_is_still_org_wide() {
    // The policy is the ONLY thing constraining a surviving org-wide grant, so
    // deleting it widens the app's reach to every mailbox — the regression that
    // shipped when an EWS-confining policy was deleted with nothing re-scoped.
    assert!(
        !policies_safe_to_remove(2, 1, true),
        "one of two grants stripped ⇒ keep the policy"
    );
    assert!(
        !policies_safe_to_remove(1, 0, true),
        "nothing stripped ⇒ keep the policy"
    );
    // Fully re-scoped ⇒ the documented step 5 runs.
    assert!(policies_safe_to_remove(2, 2, true));
    // No constrainable grant at all ⇒ the policy governs nothing.
    assert!(policies_safe_to_remove(0, 0, true));
}

#[test]
fn two_permission_values_can_share_one_exchange_role() {
    // The precondition that made `assign_scoped_roles` strand a grant: the
    // role map is many-to-one, so an app declaring BOTH of these emits two
    // targets carrying the SAME Exchange role. The second assignment is then a
    // duplicate, and before the in-loop dedupe its Err marked the target
    // unsafe to strip — so its org-wide grant survived the scoping, forever.
    assert_eq!(
        exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "Mail.ReadBasic"),
        exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "Mail.ReadBasic.All"),
    );
    assert!(
        exchange_role_for_resource_permission(MICROSOFT_GRAPH_APP_ID, "Mail.ReadBasic").is_some()
    );
}

#[test]
fn an_incomplete_resource_view_never_authorizes_deleting_a_policy() {
    // `mailbox_resource_roles` resolves Office 365 Exchange Online
    // best-effort, so a transient failure yields ZERO targets for an app whose
    // full_access_as_app grant is live. The old "no targets ⇒ delete" branch
    // then removed the only thing confining it — widening the app to every
    // mailbox in the tenant, which is strictly worse than misreporting.
    assert!(
        !policies_safe_to_remove(0, 0, false),
        "an unverifiable empty target set must never authorize deletion"
    );
    // ...and the guard is absolute: even a "fully re-scoped" count is not
    // trustworthy when the target set it was derived from may be incomplete.
    assert!(!policies_safe_to_remove(2, 2, false));
}

#[test]
fn resource_completeness_requires_both_mailbox_resources() {
    let roles = |app_id: &'static str| ResourceRoles {
        app_id,
        sp_object_id: "sp".into(),
        role_value_by_id: HashMap::new(),
    };
    assert!(mailbox_resources_complete(&[
        roles(MICROSOFT_GRAPH_APP_ID),
        roles(OFFICE365_EXCHANGE_ONLINE_APP_ID),
    ]));
    // Graph alone is the exact shape a swallowed Exchange Online lookup
    // produces — the case that must read as incomplete.
    assert!(!mailbox_resources_complete(&[roles(
        MICROSOFT_GRAPH_APP_ID
    )]));
    assert!(!mailbox_resources_complete(&[]));
}

/// A pre-existing scope confining a DIFFERENT group set is not agreement.
///
/// This is the comparison behind the fail-closed guard. Before it, the
/// migration assigned roles against whatever scope was already there
/// whenever it was not permitted to repoint — so the app's live mailbox
/// reach became that stale scope's, its org-wide grants were stripped, the
/// legacy policy was deleted, and the report printed the filter this run had
/// computed rather than the one in force.
#[test]
fn a_divergent_or_unreadable_scope_filter_is_never_agreement() {
    let wanted =
        azapptoolkit_exchange::client::member_of_group_filter(&["CN=Managed,DC=x".to_string()]);

    // Same group set, different formatting: Exchange normalizes OPATH, so
    // this must NOT read as divergent or every re-run would refuse.
    assert!(scope_filter_agrees(
        "(MemberOfGroup  -eq  'CN=Managed,DC=x')",
        &wanted
    ));

    // A different group set is the case that used to sail through.
    assert!(!scope_filter_agrees(
        "MemberOfGroup -eq 'CN=SomethingElse,DC=x'",
        &wanted
    ));

    // A superset is still divergent — wider, and still not what was asked.
    assert!(!scope_filter_agrees(
        "MemberOfGroup -eq 'CN=Managed,DC=x' -or MemberOfGroup -eq 'CN=Extra,DC=x'",
        &wanted
    ));

    // Unreadable is never agreement: an unstatable reach cannot be asserted
    // equal to an intended one.
    assert!(!scope_filter_agrees(
        "MemberOfGroup -like 'CN=Managed,DC=x'",
        &wanted
    ));
    assert!(!scope_filter_agrees(
        "RecipientTypeDetails -eq 'UserMailbox'",
        &wanted
    ));
    assert!(!scope_filter_agrees("", &wanted));
}

/// The migration refuses a pre-existing scope that confines nothing.
///
/// `ensure_management_scope` is create-only, so such a scope is KEPT.
/// Proceeding assigned this app's roles against it, then stripped the
/// org-wide Entra grants and deleted the legacy policy — leaving the app
/// reaching every mailbox in the tenant while the report said it had been
/// confined, which is strictly worse than the policy it replaced. The grant
/// path has always refused this exact state (`scope_filter_unreadable`);
/// the migration reached it through `repoint_scope_if_stale`, which
/// returned silently on `None`, and through the two branches that never
/// called it at all.
#[test]
fn a_scope_with_no_recipient_filter_fails_the_migration_closed() {
    let scope = |filter: Option<&str>| ExoManagementScope {
        name: Some("app_scope_1".into()),
        identity: Some("app_scope_1".into()),
        recipient_filter: filter.map(str::to_string),
    };

    // No scope yet: the clean path — `ensure_management_scope` creates it
    // below with exactly the filter the migration computed.
    assert_eq!(scope_filter_decision(None, "app_scope_1").unwrap(), None);

    // A scope with a filter is readable, and its filter is handed back so
    // the repoint can compare group sets without a second round trip.
    assert_eq!(
        scope_filter_decision(
            Some(scope(Some("MemberOfGroup -eq 'CN=a,DC=x'"))),
            "app_scope_1"
        )
        .unwrap()
        .as_deref(),
        Some("MemberOfGroup -eq 'CN=a,DC=x'")
    );

    // The fail-closed case, carrying the same code the grant path uses so
    // one UI mapping covers both.
    let err = scope_filter_decision(Some(scope(None)), "app_scope_1")
        .expect_err("an unrestricted scope must not be migrated onto");
    assert_eq!(err.code, "scope_filter_unreadable");
    assert!(
        err.message.contains("confines nothing"),
        "the refusal must say WHY, not just that it refused: {}",
        err.message
    );
}
