//! Unit tests for the Exchange command layer (`super`).
//!
//! Pure decisions are tested beside their code in `azapptoolkit-exchange`;
//! only the command-layer glue is tested here.

use super::*;

use azapptoolkit_core::models::AppRoleAssignment;
use azapptoolkit_core::scoping::EWS_FULL_ACCESS_AS_APP;

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
        &[(
            EWS_FULL_ACCESS_AS_APP.to_string(),
            "Application EWS.AccessAsApp",
        )],
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
        &[("Mail.Read".to_string(), "Application Mail.Read")],
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
    let scopable = |vals: &[&str]| -> Vec<(String, &'static str)> {
        vals.iter()
            .map(|v| (v.to_string(), "Application Mail.Read"))
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
    let scopable = [("Mail.Read".to_string(), "Application Mail.Read")];
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
