//! Unit tests for the Exchange command layer (`super`).
//!
//! Pure decisions are tested beside their code in `azapptoolkit-exchange`;
//! only the command-layer glue is tested here.

use super::*;

use azapptoolkit_core::models::AppRoleAssignment;
use azapptoolkit_core::scoping::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
};

use crate::dto::exchange::AapItemStatus;

/// A Microsoft Graph permission as the resolver receives it.
fn graph_perm(value: &str) -> ScopableMailPermission {
    ScopableMailPermission::on_resource(MICROSOFT_GRAPH_APP_ID, value)
        .expect("a scopable Graph mail permission")
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

#[tokio::test]
async fn audit_cached_scopes_skip_probe_and_cache_for_nonmail_perms() {
    // An app with no scopable mail permission must short-circuit before any
    // Exchange call (the base points nowhere) AND leave no cache entry —
    // otherwise the audit would create a useless entry per non-mail app,
    // bloating the cache it's meant to reuse. The resolver now takes
    // `(value, role)` pairs the caller's resource-aware gate produced, so a
    // non-mail value can no longer even be passed: the empty slice IS that
    // app's vetted set.
    use azapptoolkit_core::token::StaticTokenProvider;
    let cache = Cache::new();
    let exo = ExchangeClient::with_base_url(
        StaticTokenProvider::new("t"),
        "tenant-1",
        "admin@contoso.com",
        "http://127.0.0.1:9".to_string(),
    );
    let out =
        resolve_mail_scopes_audit_cached(&cache, "tenant-1", &exo, "app-1", &[], &HashSet::new())
            .await
            .unwrap();
    assert!(out.is_empty());
    // The whole audit discriminator for this app is absent (empty perm set).
    let key = audit_mail_scopes_key("tenant-1", "app-1", &[], &HashSet::new());
    assert!(
        cache
            .get::<HashMap<String, MailPermissionScope>>(CacheKind::Lists, &key)
            .is_none()
    );
}

/// A `Test-ServicePrincipalAuthorization` mock that answers every cmdlet POST
/// with one scoped row for `role`, and the client pointed at it.
async fn exo_answering_one_scoped_row(
    role: &str,
    granted: &str,
) -> (wiremock::MockServer, ExchangeClient) {
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "RoleName": role,
                "GrantedPermissions": granted,
                "AllowedResourceScope": "app_scope_app-1",
                "ScopeType": "CustomRecipientScope",
                "InScope": "Not Run"
            }]
        })))
        .mount(&server)
        .await;
    let exo = ExchangeClient::with_base_url(
        StaticTokenProvider::new("t"),
        "tenant-1",
        "admin@contoso.com",
        server.uri(),
    );
    (server, exo)
}

#[tokio::test]
async fn the_ews_scope_is_resolved_not_short_circuited() {
    // The join the two halves lacked: `azapptoolkit_exchange::targets`'s
    // `declared_targets_span_graph_and_the_legacy_ews_scope` proves the EWS
    // `full_access_as_app` target reaches the resolver, and this proves the resolver PROBES for it and keys a verdict
    // under it. The resolver used to re-derive the role against Microsoft
    // Graph, which has no such permission, so an EWS-only set returned
    // `Ok(empty)` with zero requests — the Permissions tab showed `Unknown`
    // forever and the audit scored a correctly scoped EWS grant org-wide.
    // `enrich = false` keeps the AAP / Get-ManagementScope calls out of it.
    let (server, exo) =
        exo_answering_one_scoped_row("Application EWS.AccessAsApp", "EWS.AccessAsApp").await;
    let out = resolve_mail_scopes(
        &exo,
        "app-1",
        &[ScopableMailPermission::on_resource(
            OFFICE365_EXCHANGE_ONLINE_APP_ID,
            EWS_FULL_ACCESS_AS_APP,
        )
        .expect("the EWS scope is scopable")],
        &HashSet::new(),
        false,
    )
    .await
    .unwrap();
    assert!(
        matches!(
            out.get(EWS_FULL_ACCESS_AS_APP),
            Some(MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::Rbac,
                scope_name: Some(name),
                ..
            }) if name == "app_scope_app-1"
        ),
        "the EWS row must carry the probe's verdict: {out:?}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "exactly one Test-ServicePrincipalAuthorization probe was attempted"
    );
}

#[tokio::test]
async fn a_graph_mail_row_resolves_through_the_same_path() {
    // Positive control for the test above: a Graph row takes the identical
    // path, so the EWS fix did not special-case one resource.
    let (server, exo) = exo_answering_one_scoped_row("Application Mail.Read", "Mail.Read").await;
    let out = resolve_mail_scopes(
        &exo,
        "app-1",
        &[graph_perm("Mail.Read")],
        &HashSet::new(),
        false,
    )
    .await
    .unwrap();
    assert!(matches!(
        out.get("Mail.Read"),
        Some(MailPermissionScope::Scoped {
            mechanism: ScopeMechanism::Rbac,
            ..
        })
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn the_audit_verdict_key_carries_the_orgwide_snapshot_it_was_reconciled_against() {
    let scopable = |vals: &[&str]| -> Vec<ScopableMailPermission> {
        vals.iter()
            .map(|v| ScopableMailPermission {
                value: v.to_string(),
                exchange_role: "Application Mail.Read",
                aap_confinable: true,
            })
            .collect()
    };
    let set = |vals: &[&str]| -> HashSet<String> { vals.iter().map(|v| v.to_string()).collect() };
    let key = |s: &[&str], o: &[&str]| audit_mail_scopes_key("t1", "app-1", &scopable(s), &set(o));

    // Order-insensitive, and an org-wide grant the app's scopable set does not
    // name cannot change the verdict, so it does not split the key.
    assert_eq!(
        key(&["Mail.Send", "Mail.Read"], &[]),
        key(&["Mail.Read", "Mail.Send"], &["Calendars.Read"])
    );
    // A stripped (or newly consented) org-wide grant the verdict reconciles
    // against is a different key: a verdict built from the run-start snapshot
    // is never read by a run that sees the live set.
    assert_ne!(
        key(&["Mail.Read"], &["Mail.Read"]),
        key(&["Mail.Read"], &[])
    );
    // Still under the one prefix `invalidate_app_details` drops.
    assert!(key(&["Mail.Read"], &[]).starts_with("t1|mail_scopes|audit|app-1|"));
}

#[tokio::test]
async fn a_verdict_cached_against_a_stale_orgwide_snapshot_is_not_served_to_a_fresh_one() {
    // Run 1 read the org-wide set at its start, before a strip removed
    // `Mail.Read`; its verdict is cached. Run 2 reads the live (stripped) set
    // and must probe again rather than serve run 1's reconciliation.
    let (server, exo) = exo_answering_one_scoped_row("Application Mail.Read", "Mail.Read").await;
    let cache = Cache::new();
    let scopable = [graph_perm("Mail.Read")];
    let stale: HashSet<String> = ["Mail.Read".to_string()].into();

    let first =
        resolve_mail_scopes_audit_cached(&cache, "tenant-1", &exo, "app-1", &scopable, &stale)
            .await
            .unwrap();
    let fresh = resolve_mail_scopes_audit_cached(
        &cache,
        "tenant-1",
        &exo,
        "app-1",
        &scopable,
        &HashSet::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        2,
        "the fresh snapshot must miss the stale verdict and probe"
    );
    assert!(matches!(
        fresh.get("Mail.Read"),
        Some(MailPermissionScope::Scoped { .. })
    ));
    assert_ne!(
        format!("{first:?}"),
        format!("{fresh:?}"),
        "the stale snapshot reconciled to a different verdict, which is why it must not be served"
    );

    // The same snapshot again is a hit: no further probe.
    resolve_mail_scopes_audit_cached(
        &cache,
        "tenant-1",
        &exo,
        "app-1",
        &scopable,
        &HashSet::new(),
    )
    .await
    .unwrap();
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

/// A Graph target on its own appRole, keyed `role-<value>`.
fn graph_target(value: &str) -> ExchangeTarget {
    ExchangeTarget {
        graph_value: value.to_string(),
        exchange_role: "Application Mail.Read",
        app_role_id: format!("role-{value}"),
        resource_sp_object_id: "graph-sp".to_string(),
        aap_confinable: true,
    }
}

#[test]
fn a_declared_but_never_granted_permission_is_not_reported_org_wide() {
    // The wizard declares each permission before scoping it, so a target is
    // routinely declared but NOT held. Only a live assignment is org-wide reach:
    // "targets minus removed" would name Mail.Send on every wizard run.
    let targets = [graph_target("Mail.Read"), graph_target("Mail.Send")];
    let assignments = [grant("graph-sp", "role-Mail.Read")];
    assert_eq!(
        still_held_orgwide(&targets, &assignments, &[]),
        ["Mail.Read"]
    );
    assert!(still_held_orgwide(&targets, &assignments, &["Mail.Read".to_string()]).is_empty());
}

#[test]
fn still_org_wide_matches_on_resource_and_role() {
    // Graph's appRole id assigned on Exchange Online's resource is not the
    // Graph grant the target names.
    let targets = [graph_target("Mail.Read")];
    let assignments = [grant("exo-sp", "role-Mail.Read")];
    assert!(still_held_orgwide(&targets, &assignments, &[]).is_empty());
}

#[test]
fn still_org_wide_names_a_permission_once() {
    // Two targets can carry one value (several values map to one role, or a
    // caller repeats it); the note names it once.
    let targets = [graph_target("Mail.Read"), graph_target("Mail.Read")];
    let assignments = [grant("graph-sp", "role-Mail.Read")];
    assert_eq!(
        still_held_orgwide(&targets, &assignments, &[]),
        ["Mail.Read"]
    );
}

#[test]
fn the_not_effective_note_names_every_permission() {
    let note = still_granted_orgwide(&["Mail.Read", "Mail.Send"]);
    assert!(note.contains("Mail.Read"), "{note}");
    assert!(note.contains("Mail.Send"), "{note}");
    assert!(note.contains("organization-wide"), "{note}");
    assert_eq!(it_or_them(1), "it");
    assert_eq!(it_or_them(2), "them");
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
    // Exchange echoes DNs in its own casing: still the same group.
    assert!(scope_filter_agrees(
        "MemberOfGroup -eq 'cn=managed,dc=X'",
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

    // Names the wanted group AND something else. The DN-set comparison this
    // used to be read every one of these as "confines exactly {Managed}", so
    // the migration bound the app's roles to the scope and stripped its
    // org-wide grants — against a reach of every user mailbox, every mailbox
    // but Managed, or a narrower set the report did not describe.
    for compound in [
        "MemberOfGroup -eq 'CN=Managed,DC=x' -or RecipientTypeDetails -eq 'UserMailbox'",
        "MemberOfGroup -eq 'CN=Managed,DC=x' -and RecipientTypeDetails -eq 'UserMailbox'",
        "-not (MemberOfGroup -eq 'CN=Managed,DC=x')",
        "(-not(MemberOfGroup -eq 'CN=Managed,DC=x'))",
        "CustomAttribute1 -eq \"MemberOfGroup -eq 'CN=Managed,DC=x'\"",
    ] {
        assert!(!scope_filter_agrees(compound, &wanted), "{compound}");
    }
    // ...while Exchange's own re-parenthesising of the pure chain still agrees.
    assert!(scope_filter_agrees(
        "((MemberOfGroup -eq 'CN=Managed,DC=x'))",
        &wanted
    ));
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

/// An Exchange role assignment row for the command-layer tests.
fn exo_assignment(
    role: &str,
    scope: Option<&str>,
    identity: Option<&str>,
) -> azapptoolkit_exchange::models::ExoRoleAssignment {
    azapptoolkit_exchange::models::ExoRoleAssignment {
        name: None,
        role: Some(role.to_string()),
        role_assignee_name: None,
        custom_resource_scope: scope.map(str::to_string),
        identity: identity.map(str::to_string),
        recipient_write_scope: None,
        custom_recipient_write_scope: None,
        recipient_administrative_unit_scope: None,
    }
}

/// RBAC unions: a scoped role added beside an org-wide assignment of the same
/// role confines nothing, so the scoped grant must say so — in the
/// "Scoping is NOT effective" voice — rather than report success. A confined
/// assignment (custom scope or administrative unit) is not org-wide.
#[test]
fn an_org_wide_exchange_assignment_makes_scoping_not_effective() {
    let targets = [graph_target("Mail.Read")];
    let orgwide = exo_assignment("Application Mail.Read", None, Some("legacy-orgwide"));
    let warnings = orgwide_assignment_warnings(&[orgwide], &targets);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0].starts_with("Scoping is NOT effective for Application Mail.Read")
            && warnings[0].contains("legacy-orgwide"),
        "{}",
        warnings[0]
    );

    let scoped = exo_assignment("Application Mail.Read", Some("app_scope_x"), Some("s"));
    let mut au = exo_assignment("Application Mail.Read", None, Some("au"));
    au.recipient_administrative_unit_scope = Some("au-1".into());
    assert!(orgwide_assignment_warnings(&[scoped, au], &targets).is_empty());
}

/// A removal that took nothing off but left something in place is a failure,
/// not "Removed 0"; a partial removal returns its result with the failures
/// named; an identity-less row is counted as failed, never skipped silently.
#[test]
fn a_failed_exchange_removal_is_reported_as_a_failure() {
    let row = exo_assignment("Application Mail.Read", None, None);
    let identityless = identityless_failure(&row);
    assert_eq!(identityless.assignment, "Application Mail.Read");

    // Nothing removed, one identity-less row: a validation failure naming it.
    let err = removal_failed_outright(&[], std::slice::from_ref(&identityless), None)
        .expect("nothing removed and something left is a failure");
    assert_eq!(err.code, "exchange_assignment_unremovable");
    assert!(
        err.message.contains("Application Mail.Read"),
        "{}",
        err.message
    );

    // Nothing removed, a rejected removal: the rejection's code survives (a
    // dead session must still read as one).
    let rejected = UiError::new("refresh_missing", "session ended", false);
    let err =
        removal_failed_outright(&[], std::slice::from_ref(&identityless), Some(rejected)).unwrap();
    assert_eq!(err.code, "refresh_missing");

    // Partial: some removed — the result is returned and carries `failed`.
    assert!(
        removal_failed_outright(&["Application Mail.Send".into()], &[identityless], None).is_none()
    );
    // Nothing to remove at all is not a failure.
    assert!(removal_failed_outright(&[], &[], None).is_none());
}

/// A real migration run that reached `migrate_one` busts the caches even when
/// that app returned `Err` — it can fail after a write landed. A dry run never
/// does, and neither does a run that reached no app.
#[test]
fn a_migration_invalidates_whenever_a_real_run_attempted_an_app() {
    assert!(migration_should_invalidate(false, true));
    assert!(!migration_should_invalidate(false, false));
    assert!(!migration_should_invalidate(true, true));
}

/// A principal holding the role through TWO scopes gets the joined display
/// name "A, B", which names no scope. Enrichment must not look it up as one —
/// that found nothing and silently dropped the filter/group count — so the
/// verdict keeps `group_count: None` and no `Get-ManagementScope` is sent.
#[tokio::test]
async fn a_two_scope_verdict_is_not_enriched_as_one_scope() {
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("Test-ServicePrincipalAuthorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "RoleName": "Application Mail.Read", "GrantedPermissions": "Mail.Read",
                  "AllowedResourceScope": "scope_a", "ScopeType": "CustomRecipientScope" },
                { "RoleName": "Application Mail.Read", "GrantedPermissions": "Mail.Read",
                  "AllowedResourceScope": "scope_b", "ScopeType": "CustomRecipientScope" }
            ]
        })))
        .mount(&server)
        .await;
    // Everything else (the legacy-AAP lookup, and a scope lookup were one sent)
    // answers empty.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .mount(&server)
        .await;
    let exo = ExchangeClient::with_base_url(
        StaticTokenProvider::new("t"),
        "tenant-1",
        "admin@contoso.com",
        server.uri(),
    );
    let out = resolve_mail_scopes(
        &exo,
        "app-1",
        &[graph_perm("Mail.Read")],
        &HashSet::new(),
        true,
    )
    .await
    .unwrap();
    match out.get("Mail.Read") {
        Some(MailPermissionScope::Scoped {
            scope_name: Some(name),
            group_count,
            recipient_filter,
            ..
        }) => {
            assert_eq!(name, "scope_a, scope_b");
            assert_eq!(*group_count, None);
            assert_eq!(*recipient_filter, None);
        }
        other => panic!("expected a two-scope RBAC verdict, got {other:?}"),
    }
    let bodies: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect();
    assert!(
        !bodies.iter().any(|b| b.contains("Get-ManagementScope")),
        "no scope lookup for a joined name: {bodies:?}"
    );
}

/// An Exchange mock whose `Test-ServicePrincipalAuthorization` answers
/// `probe` and whose `Get-ApplicationAccessPolicy` reports one
/// `RestrictAccess` policy confining `app-1` to `Sales`.
async fn exo_with_restrict_policy_and_probe(
    probe: wiremock::ResponseTemplate,
) -> (wiremock::MockServer, ExchangeClient) {
    use azapptoolkit_core::token::StaticTokenProvider;
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("Test-ServicePrincipalAuthorization"))
        .respond_with(probe)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("Get-ApplicationAccessPolicy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "Identity": "app-1\\policy",
                "AppId": "app-1",
                "ScopeName": "Sales",
                "AccessRight": "RestrictAccess"
            }]
        })))
        .mount(&server)
        .await;
    let exo = ExchangeClient::with_base_url(
        StaticTokenProvider::new("t"),
        "tenant-1",
        "admin@contoso.com",
        server.uri(),
    );
    (server, exo)
}

fn is_legacy(scope: Option<&MailPermissionScope>) -> bool {
    matches!(
        scope,
        Some(MailPermissionScope::Scoped {
            mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
            ..
        })
    )
}

/// A legacy policy confines only what it governed. `MailboxItem.ReadWrite.All`
/// is RBAC-scopable but no Application Access Policy ever confined it, so on a
/// policy-confined app with no RBAC scope it stays org-wide — gating the
/// override on the scopable set read it "Scoped (legacy)" and scored it at the
/// reduced weight.
#[tokio::test]
async fn the_legacy_override_skips_an_rbac_only_permission() {
    let (_server, exo) = exo_with_restrict_policy_and_probe(
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
    )
    .await;
    let out = resolve_mail_scopes(
        &exo,
        "app-1",
        &[
            graph_perm("Mail.Read"),
            graph_perm("MailboxItem.ReadWrite.All"),
        ],
        &HashSet::new(),
        true,
    )
    .await
    .unwrap();
    assert!(is_legacy(out.get("Mail.Read")), "{out:?}");
    assert_eq!(
        out.get("MailboxItem.ReadWrite.All"),
        Some(&MailPermissionScope::OrgWide)
    );
}

/// The probe-failure fallback honours the same gate. A principal Exchange
/// can't resolve has no RBAC scope, so its RBAC-only grant is org-wide while
/// the policy still answers for `Mail.Read`; a genuine 403 leaves the RBAC-only
/// value indeterminate rather than lending it the policy's scope, and with
/// nothing the policy governs, the 403 propagates as before.
#[tokio::test]
async fn the_probe_failure_fallback_skips_an_rbac_only_permission() {
    let perms = [
        graph_perm("Mail.Read"),
        graph_perm("MailboxItem.ReadWrite.All"),
    ];

    let (_server, exo) =
        exo_with_restrict_policy_and_probe(wiremock::ResponseTemplate::new(404).set_body_string(
            "The operation couldn't be performed because object couldn't be found",
        ))
        .await;
    let out = resolve_mail_scopes(&exo, "app-1", &perms, &HashSet::new(), true)
        .await
        .unwrap();
    assert!(is_legacy(out.get("Mail.Read")), "{out:?}");
    assert_eq!(
        out.get("MailboxItem.ReadWrite.All"),
        Some(&MailPermissionScope::OrgWide)
    );

    let (_server, exo) = exo_with_restrict_policy_and_probe(
        wiremock::ResponseTemplate::new(403).set_body_string("Forbidden"),
    )
    .await;
    let out = resolve_mail_scopes(&exo, "app-1", &perms, &HashSet::new(), true)
        .await
        .unwrap();
    assert!(is_legacy(out.get("Mail.Read")), "{out:?}");
    assert_eq!(
        out.get("MailboxItem.ReadWrite.All"),
        Some(&MailPermissionScope::Unknown)
    );
    // That failure-derived `Unknown` must not be cached by the commands.
    let entry = |scope: MailPermissionScope| MailScopeEntry {
        graph_permission: "MailboxItem.ReadWrite.All".into(),
        exchange_role: "Application MailboxItem.ReadWrite".into(),
        scope,
    };
    assert!(!verdicts_are_cacheable(&[
        entry(MailPermissionScope::OrgWide),
        entry(MailPermissionScope::Unknown)
    ]));
    assert!(verdicts_are_cacheable(&[entry(
        MailPermissionScope::OrgWide
    )]));
    let err = resolve_mail_scopes(&exo, "app-1", &perms[1..], &HashSet::new(), true)
        .await
        .expect_err("no policy-governed permission: the 403 must reach the UI");
    assert!(matches!(err, ExchangeError::Forbidden { .. }), "{err:?}");
}

/// The managed group's name for `app-1` under the default pattern.
const MANAGED: &str = "app_scope_group_app-1";

/// A mock Exchange for `consolidate_scope_group`: the source group `CN=Src`
/// holds `source`; the managed group (DN `CN=Managed,DC=x`) lists `managed`
/// on every read; `add` answers `Add-DistributionGroupMember`; anything else
/// answers empty. `token` lets a test end the session partway.
async fn exo_for_consolidation_with(
    source: &[&str],
    managed: &[&str],
    add: impl wiremock::Respond + 'static,
    token: std::sync::Arc<dyn azapptoolkit_core::token::BearerProvider>,
) -> (wiremock::MockServer, ExchangeClient) {
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    let members = |smtps: &[&str]| {
        serde_json::json!({
            "value": smtps
                .iter()
                .map(|s| serde_json::json!({ "PrimarySmtpAddress": s }))
                .collect::<Vec<_>>()
        })
    };
    Mock::given(method("POST"))
        .and(body_string_contains("Get-DistributionGroupMember"))
        .and(body_string_contains("CN=Src"))
        .respond_with(ResponseTemplate::new(200).set_body_json(members(source)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("Get-DistributionGroupMember"))
        .and(body_string_contains(MANAGED))
        .respond_with(ResponseTemplate::new(200).set_body_json(members(managed)))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("Get-DistributionGroup\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "Name": MANAGED, "DistinguishedName": "CN=Managed,DC=x" }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("Add-DistributionGroupMember"))
        .respond_with(add)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .with_priority(10)
        .mount(&server)
        .await;
    let exo = ExchangeClient::with_base_url(token, "tenant-1", "admin@contoso.com", server.uri());
    (server, exo)
}

/// [`exo_for_consolidation_with`] with source `a` + `b`, adds that succeed and
/// a token that never expires.
async fn exo_for_consolidation(managed: &[&str]) -> (wiremock::MockServer, ExchangeClient) {
    exo_for_consolidation_with(
        &["a@contoso.com", "b@contoso.com"],
        managed,
        ok_empty(),
        azapptoolkit_core::token::StaticTokenProvider::new("t"),
    )
    .await
}

fn ok_empty() -> wiremock::ResponseTemplate {
    wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] }))
}

/// `n` source mailboxes, `m0@contoso.com` … — enough that a stop partway shows.
fn many(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("m{i}@contoso.com")).collect()
}

fn params<'a>(
    exo: &'a ExchangeClient,
    defaults: &'a TenantDefaults,
    source: &'a [String],
    dry_run: bool,
    live_filter: Option<&'a str>,
    cancel: &'a CancelToken,
) -> ConsolidateParams<'a> {
    ConsolidateParams {
        exo,
        app_id: "app-1",
        source_dns: source,
        tenant_defaults: defaults,
        dry_run,
        live_filter,
        cancel,
    }
}

async fn sent_cmdlets(server: &wiremock::MockServer, needle: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| String::from_utf8_lossy(&r.body).contains(needle))
        .count()
}

/// Cancel before the copy stops it and keeps the source: not consolidated,
/// flagged incomplete, nothing written.
#[tokio::test]
async fn a_cancelled_consolidation_keeps_the_source_and_is_incomplete() {
    let (server, exo) = exo_for_consolidation(&[]).await;
    let flag = crate::state::CancelFlag::new();
    let cancel = flag.claim();
    flag.cancel();
    let (defaults, source) = (TenantDefaults::default(), vec!["CN=Src,DC=x".to_string()]);
    let mut warnings = Vec::new();
    let out = consolidate_scope_group(
        params(&exo, &defaults, &source, false, None, &cancel),
        &mut warnings,
    )
    .await;
    assert!(!out.consolidated, "a stopped copy must never repoint");
    assert!(out.incomplete);
    assert_eq!(out.scope_dns, source);
    assert_eq!(out.unverified.len(), 2, "both mailboxes are uncopied");
    assert_eq!(
        sent_cmdlets(&server, "Add-DistributionGroupMember").await,
        0
    );
    assert_eq!(sent_cmdlets(&server, "New-DistributionGroup").await, 0);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("nothing this app can reach has changed")),
        "{warnings:?}"
    );
}

/// Responds to an add by pressing Cancel: the operator stops the run while
/// the first wave of adds is in flight.
struct CancelOnAdd(crate::state::CancelFlag);

impl wiremock::Respond for CancelOnAdd {
    fn respond(&self, _: &wiremock::Request) -> wiremock::ResponseTemplate {
        self.0.cancel();
        ok_empty()
    }
}

/// Cancel pressed MID-copy: the adds already in flight finish, no further add
/// starts, and the source is kept with the result flagged incomplete.
#[tokio::test]
async fn a_cancel_mid_copy_stops_the_remaining_adds() {
    let source_members = many(12);
    let refs: Vec<&str> = source_members.iter().map(String::as_str).collect();
    let flag = crate::state::CancelFlag::new();
    let cancel = flag.claim();
    let (server, exo) = exo_for_consolidation_with(
        &refs,
        &[],
        CancelOnAdd(flag.clone()),
        azapptoolkit_core::token::StaticTokenProvider::new("t"),
    )
    .await;
    let (defaults, source) = (TenantDefaults::default(), vec!["CN=Src,DC=x".to_string()]);
    let mut warnings = Vec::new();
    let out = consolidate_scope_group(
        params(&exo, &defaults, &source, false, None, &cancel),
        &mut warnings,
    )
    .await;
    let adds = sent_cmdlets(&server, "Add-DistributionGroupMember").await;
    assert!(
        (1..12).contains(&adds),
        "the copy started and then stopped partway: {adds} add(s)"
    );
    assert!(!out.consolidated && out.incomplete);
    assert_eq!(out.copied.len() + out.unverified.len(), 12);
    assert!(
        warnings.iter().any(|w| w.contains("the run was cancelled")),
        "{warnings:?}"
    );
}

/// The session dies partway through the adds: the `SessionDead` latch stops
/// the copy (no add starts after it, and the failed ones are not retried), the
/// source is kept and the result is incomplete.
#[tokio::test]
async fn a_session_that_dies_mid_copy_latches_and_stops_the_adds() {
    let source_members = many(12);
    let refs: Vec<&str> = source_members.iter().map(String::as_str).collect();
    // Three reads (source, managed pre-read, the group lookup) then two adds.
    let (server, exo) = exo_for_consolidation_with(
        &refs,
        &[],
        ok_empty(),
        crate::commands::test_support::dies_after(5),
    )
    .await;
    let cancel = crate::state::CancelFlag::new().claim();
    let (defaults, source) = (TenantDefaults::default(), vec!["CN=Src,DC=x".to_string()]);
    let mut warnings = Vec::new();
    let out = consolidate_scope_group(
        params(&exo, &defaults, &source, false, None, &cancel),
        &mut warnings,
    )
    .await;
    let adds = sent_cmdlets(&server, "Add-DistributionGroupMember").await;
    assert!(
        adds < 12,
        "the latch stopped the remaining adds: {adds} sent"
    );
    assert!(!out.consolidated && out.incomplete);
    assert!(
        warnings.iter().any(|w| w.contains("the session ended")),
        "the stop is attributed to the dead session: {warnings:?}"
    );
}

/// An add that collides on Exchange's "object modified" conflict under
/// concurrency is retried once, serially, and the consolidation then verifies.
#[tokio::test]
async fn a_conflicting_add_is_retried_once_before_verifying() {
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, ResponseTemplate};
    let (server, exo) = exo_for_consolidation(&["a@contoso.com", "b@contoso.com"]).await;
    Mock::given(method("POST"))
        .and(body_string_contains("Add-DistributionGroupMember"))
        .and(body_string_contains("b@contoso.com"))
        .respond_with(
            ResponseTemplate::new(400).set_body_string("The object has been modified by another"),
        )
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    let cancel = crate::state::CancelFlag::new().claim();
    let (defaults, source) = (TenantDefaults::default(), vec!["CN=Src,DC=x".to_string()]);
    let mut warnings = Vec::new();
    let out = consolidate_scope_group(
        params(&exo, &defaults, &source, false, None, &cancel),
        &mut warnings,
    )
    .await;
    assert!(out.consolidated, "the retry landed: {warnings:?}");
    assert_eq!(
        sent_cmdlets(&server, "\"Member\":\"b@contoso.com\"").await,
        2
    );
    assert!(
        !warnings.iter().any(|w| w.contains("could not add")),
        "a retried success is not a failure: {warnings:?}"
    );
}

/// A managed group already holding a mailbox the source does not (G1 left by an
/// earlier refused run, source now G2) would WIDEN reach if repointed at. The
/// plan names it and carries it as the refusal; a real run refuses before
/// writing anything.
#[tokio::test]
async fn a_managed_group_with_extra_members_is_named_in_the_plan_and_refused() {
    let (_server, exo) = exo_for_consolidation(&["A@Contoso.com", "g1@contoso.com"]).await;
    let cancel = crate::state::CancelFlag::new().claim();
    let (defaults, source) = (TenantDefaults::default(), vec!["CN=Src,DC=x".to_string()]);

    let mut warnings = Vec::new();
    let plan = consolidate_scope_group(
        params(&exo, &defaults, &source, true, None, &cancel),
        &mut warnings,
    )
    .await;
    assert!(!plan.consolidated);
    let named = warnings.iter().find(|w| w.contains("would be refused"));
    assert!(
        named.is_some_and(|w| w.contains("g1@contoso.com") && !w.contains("A@Contoso.com")),
        "the plan names the extra (case-folded compare, so `A@Contoso.com` is not one): \
         {warnings:?}"
    );
    assert!(
        plan.refusal
            .as_deref()
            .is_some_and(|r| r.contains("g1@contoso.com")),
        "the plan carries the refusal for its headline"
    );

    let (server, exo) = exo_for_consolidation(&["g1@contoso.com"]).await;
    let mut warnings = Vec::new();
    let run = consolidate_scope_group(
        params(&exo, &defaults, &source, false, None, &cancel),
        &mut warnings,
    )
    .await;
    assert!(
        !run.consolidated,
        "a superset managed group must not be repointed at"
    );
    assert_eq!(run.scope_dns, source);
    assert_eq!(
        sent_cmdlets(&server, "Add-DistributionGroupMember").await,
        0
    );
    assert!(
        warnings.iter().any(|w| w.contains("g1@contoso.com")),
        "{warnings:?}"
    );
}

/// When the live scope ALREADY names the managed group alone, its members are
/// the app's current reach — an extra there is not a widening, and refusing
/// blocked every re-run after an operator edited the managed group.
#[tokio::test]
async fn extras_are_not_refused_when_the_managed_group_is_already_the_live_scope() {
    let (_server, exo) =
        exo_for_consolidation(&["a@contoso.com", "b@contoso.com", "x@contoso.com"]).await;
    let cancel = crate::state::CancelFlag::new().claim();
    let (defaults, source) = (TenantDefaults::default(), vec!["CN=Src,DC=x".to_string()]);
    let live = member_of_group_filter(&["CN=Managed,DC=x".to_string()]);
    let mut warnings = Vec::new();
    let out = consolidate_scope_group(
        params(&exo, &defaults, &source, false, Some(&live), &cancel),
        &mut warnings,
    )
    .await;
    assert!(out.consolidated, "{warnings:?}");

    // The same managed group while the live scope still names the source:
    // `x@contoso.com` would be new reach, so it is refused.
    let live_src = member_of_group_filter(&source);
    let mut warnings = Vec::new();
    let out = consolidate_scope_group(
        params(&exo, &defaults, &source, false, Some(&live_src), &cancel),
        &mut warnings,
    )
    .await;
    assert!(!out.consolidated, "{warnings:?}");
}

/// The removal loop counts an identity-less row as failed (never a silent
/// skip), fails outright when nothing came off, and reports a partial removal
/// with its failures — and only a landed removal sets the invalidation flag.
#[tokio::test]
async fn remove_role_assignments_counts_identityless_rows_as_failed() {
    let (server, exo) = exo_for_consolidation(&[]).await;
    let nameless = exo_assignment("Application Mail.Read", None, None);

    let (result, removed_any) =
        remove_role_assignments(&exo, "app-1".into(), vec![nameless.clone()]).await;
    let err = result.expect_err("nothing removed and something left is a failure");
    assert_eq!(err.code, "exchange_assignment_unremovable");
    assert!(!removed_any);
    assert_eq!(
        sent_cmdlets(&server, "Remove-ManagementRoleAssignment").await,
        0
    );

    let removable = exo_assignment("Application Mail.Send", Some("app_scope_x"), Some("id-2"));
    let (result, removed_any) =
        remove_role_assignments(&exo, "app-1".into(), vec![nameless, removable]).await;
    let res = result.expect("a partial removal returns its result");
    assert_eq!(res.removed_assignments, ["Application Mail.Send"]);
    assert_eq!(res.failed.len(), 1);
    assert_eq!(res.failed[0].assignment, "Application Mail.Read");
    assert!(removed_any, "a landed removal busts the caches");
}

/// `assign_scoped_roles` itself emits the org-wide warning from the live
/// role snapshot, beside the scoped assignment it creates.
#[tokio::test]
async fn assign_scoped_roles_warns_about_an_org_wide_assignment() {
    use wiremock::matchers::{body_string_contains, method};
    use wiremock::{Mock, ResponseTemplate};
    let (server, exo) = exo_for_consolidation(&[]).await;
    Mock::given(method("POST"))
        .and(body_string_contains("Get-ManagementRoleAssignment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "Role": "Application Mail.Read", "Identity": "orgwide-1" }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("New-ManagementRoleAssignment"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "Role": "Application Mail.Read", "CustomResourceScope": "app_scope_app-1" }]
        })))
        .mount(&server)
        .await;
    let mut warnings = Vec::new();
    let (assigned, _, scoped) = assign_scoped_roles(
        &exo,
        "app-1",
        "app_scope_app-1",
        &[graph_target("Mail.Read")],
        &mut warnings,
    )
    .await
    .unwrap();
    assert_eq!(assigned, ["Application Mail.Read"]);
    assert!(scoped[0].1);
    assert!(
        warnings.iter().any(|w| w
            .starts_with("Scoping is NOT effective for Application Mail.Read")
            && w.contains("orgwide-1")),
        "{warnings:?}"
    );
}

const UPPER_APP: &str = "71487ACD-EC93-476D-BD0E-6C8B31831053";

/// Graph + Exchange mocks for one `migrate_one` run on [`UPPER_APP`]: the SP
/// resolves, it holds no grants, the policy group is `CN=Src`.
async fn migration_mocks() -> (
    wiremock::MockServer,
    GraphClient,
    wiremock::MockServer,
    ExchangeClient,
) {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let graph_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1.0/servicePrincipals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-1", "appId": UPPER_APP.to_ascii_lowercase(), "displayName": "Legacy" }]
        })))
        .mount(&graph_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1.0/servicePrincipals/sp-1/appRoleAssignments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .mount(&graph_server)
        .await;
    let graph = crate::commands::test_support::mock_graph(&graph_server);

    let (exo_server, exo) = exo_for_consolidation(&[]).await;
    Mock::given(method("POST"))
        .and(body_string_contains("Get-Group\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "Name": "Src", "DistinguishedName": "CN=Src,DC=x" }]
        })))
        .mount(&exo_server)
        .await;
    (graph_server, graph, exo_server, exo)
}

fn policy() -> ExoApplicationAccessPolicy {
    ExoApplicationAccessPolicy {
        app_id: Some(UPPER_APP.to_string()),
        access_right: Some("RestrictAccess".into()),
        scope_name: Some("Src".into()),
        identity: Some("policy-1".into()),
        ..Default::default()
    }
}

/// `migrate_one` names the scope and the managed group from the LOWER-cased
/// AppId even when Exchange stored the policy's AppId upper-case, so it agrees
/// with every other path (and with the scope a previous run created).
#[tokio::test]
async fn migrate_one_names_scope_and_group_from_the_lowercased_app_id() {
    let (_g, graph, exo_server, exo) = migration_mocks().await;
    let defaults = TenantDefaults::default();
    let cancel = crate::state::CancelFlag::new().claim();
    let ctx = MigrationContext {
        graph: &graph,
        exo: &exo,
        resources: &[],
        scope_override: None,
        tenant_defaults: &defaults,
        dry_run: true,
        cancel: &cancel,
    };
    let out = migrate_one(ctx, UPPER_APP, &[policy()]).await.unwrap();
    let lower = UPPER_APP.to_ascii_lowercase();
    assert_eq!(
        out.item.scope_name.as_deref(),
        Some(format!("app_scope_{lower}").as_str())
    );
    assert!(
        sent_cmdlets(&exo_server, &format!("\"app_scope_{lower}\"")).await > 0,
        "the scope lookup used the lower-cased name"
    );
    assert!(
        sent_cmdlets(&exo_server, &format!("\"app_scope_group_{lower}\"")).await > 0,
        "the managed-group read used the lower-cased name"
    );
    assert_eq!(sent_cmdlets(&exo_server, UPPER_APP).await, 0);
}

/// Cancel during an app's member copy stops THAT app before any scope, role,
/// grant or policy write, reports it `partial`, and marks the run stopped.
#[tokio::test]
async fn a_cancel_during_the_copy_stops_the_app_before_any_scope_write() {
    let (graph_server, graph, exo_server, exo) = migration_mocks().await;
    let defaults = TenantDefaults::default();
    let flag = crate::state::CancelFlag::new();
    let cancel = flag.claim();
    flag.cancel();
    let ctx = MigrationContext {
        graph: &graph,
        exo: &exo,
        resources: &[],
        scope_override: None,
        tenant_defaults: &defaults,
        dry_run: false,
        cancel: &cancel,
    };
    let out = migrate_one(ctx, UPPER_APP, &[policy()]).await.unwrap();
    assert!(out.stopped);
    assert_eq!(out.item.status, AapItemStatus::Partial);
    assert!(out.item.removed_policies.is_empty() && out.item.roles_assigned.is_empty());
    for write in [
        "New-ManagementScope",
        "Set-ManagementScope",
        "New-ServicePrincipal",
        "New-ManagementRoleAssignment",
        "Remove-ApplicationAccessPolicy",
        "Add-DistributionGroupMember",
    ] {
        assert_eq!(
            sent_cmdlets(&exo_server, write).await,
            0,
            "{write} was sent"
        );
    }
    let graph_writes = graph_server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method != wiremock::http::Method::GET)
        .count();
    assert_eq!(graph_writes, 0, "no Entra grant was touched");
    assert!(
        out.item.warnings.iter().any(|w| w.starts_with("STOPPED")),
        "{:?}",
        out.item.warnings
    );
}

fn item(app_id: &str) -> AapMigrationItem {
    AapMigrationItem {
        app_id: app_id.into(),
        source_policy_identities: Vec::new(),
        scope_name: None,
        scope_filter: None,
        managed_group_name: None,
        members_copied: Vec::new(),
        members_unverified: Vec::new(),
        roles_assigned: Vec::new(),
        removed_entra_grants: Vec::new(),
        removed_policies: Vec::new(),
        retired_groups: Vec::new(),
        status: AapItemStatus::Migrated,
        warnings: Vec::new(),
    }
}

fn batches(ids: &[&str]) -> Vec<(String, Vec<ExoApplicationAccessPolicy>)> {
    ids.iter().map(|id| (id.to_string(), Vec::new())).collect()
}

/// The run loop: an app that returned `Err` was still ATTEMPTED, so a real run
/// invalidates; a stop inside the last (or only) app makes the run incomplete;
/// a pre-cancelled run attempts nothing and names every app unattempted.
#[tokio::test]
async fn the_migration_loop_tracks_attempts_and_stops() {
    let cancel = crate::state::CancelFlag::new().claim();
    let session = SessionDead::new();
    let run = run_migration_batches(batches(&["app-1"]), &cancel, &session, |_, _| async {
        Err(UiError::validation(
            "scope_filter_mismatch",
            "refused after a write",
        ))
    })
    .await;
    assert!(run.attempted && run.items.is_empty() && run.failures.len() == 1);
    assert!(
        run.should_invalidate(false),
        "an Err after a landed write still busts"
    );
    assert!(!run.should_invalidate(true), "a dry run never does");

    let run = run_migration_batches(batches(&["app-1"]), &cancel, &session, |id, _| async move {
        Ok(MigratedApp {
            item: item(&id),
            stopped: true,
        })
    })
    .await;
    assert!(
        run.cancelled,
        "a stop inside the only app makes the run incomplete"
    );

    let flag = crate::state::CancelFlag::new();
    let stopped = flag.claim();
    flag.cancel();
    let run = run_migration_batches(
        batches(&["a", "b"]),
        &stopped,
        &session,
        |id, _| async move {
            Ok(MigratedApp {
                item: item(&id),
                stopped: false,
            })
        },
    )
    .await;
    assert!(run.cancelled && !run.attempted && !run.should_invalidate(false));
    assert_eq!(run.unattempted, ["a", "b"]);
}

/// The command busts the caches from the run's own verdict, before returning.
/// Pinned at the call site because the helper alone passes on a revert of the
/// command to the old `!items.is_empty()` gate.
#[test]
fn the_migration_command_invalidates_from_the_run_verdict() {
    // Normalised: a Windows checkout has CRLF line endings.
    let src = include_str!("aap_migration.rs").replace("\r\n", "\n");
    let body = src
        .split_once("pub async fn migrate_application_access_policies(")
        .and_then(|(_, rest)| rest.split_once("\n}\n"))
        .map(|(body, _)| body)
        .expect("command body");
    assert!(
        body.contains(
            "if run.should_invalidate(dry_run) {\n        invalidate_app_lists(&state.cache, &tenant_id);"
        ),
        "the command must invalidate on `run.should_invalidate(dry_run)`"
    );
    assert!(!body.contains("items.is_empty()"));
}
