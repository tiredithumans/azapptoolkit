//! Unit tests for the DR restore (`super` and its per-phase modules).

use super::*;

use azapptoolkit_core::models::{
    Application, DirectoryObject, FederatedIdentityCredential, OAuth2PermissionScope,
    PreAuthorizedApplication,
};
use azapptoolkit_core::redirect::validate_redirect_uri;
use azapptoolkit_core::restore_plan::BackupApps;

use crate::dto::backup::{
    AppRegistrationBackup, BACKUP_SCHEMA_VERSION, CredentialMeta, EnterpriseAppBackup,
    ManagedIdentityBackup, ManualItem, PermissionRisk, PrincipalRef, PrivilegedKind, RestoredApp,
};
use crate::dto::managed_identity::MiSubtype;

use super::adoption::*;
use super::enterprise::*;
use super::manifest::*;
use super::plan::app_approval;
use super::principals::*;
use super::wire::*;

#[test]
fn a_manifest_from_a_newer_build_is_refused_but_an_older_one_restores() {
    // Older and current: additive, `serde(default)` fields — restoring one
    // is the DR case the version field exists to support.
    assert!(check_manifest_schema(0).is_ok());
    assert!(check_manifest_schema(BACKUP_SCHEMA_VERSION).is_ok());
    // Newer: this build cannot know what it would be dropping, and a
    // restore mutates the tenant before anyone can look.
    let err = check_manifest_schema(BACKUP_SCHEMA_VERSION + 1).unwrap_err();
    assert_eq!(err.code, "schema_too_new");
}

#[test]
fn assignee_role_maps_default_passthrough_value_match_or_none() {
    use crate::dto::backup::{AppRoleAssigneeRef, PrincipalRef};
    use azapptoolkit_core::models::AppRole;

    let roles = vec![AppRole {
        id: "new-role-id".into(),
        value: "Writer".into(),
        ..Default::default()
    }];

    // Default-access role passes through unchanged (always present).
    let default = AppRoleAssigneeRef {
        principal: PrincipalRef::default(),
        app_role_id: DEFAULT_ACCESS_ROLE.into(),
        app_role_value: None,
    };
    assert_eq!(
        map_assignee_role_id(&default, &roles).as_deref(),
        Some(DEFAULT_ACCESS_ROLE)
    );

    // Custom role matched by value → the new SP's role id.
    let writer = AppRoleAssigneeRef {
        principal: PrincipalRef::default(),
        app_role_id: "old-role-id".into(),
        app_role_value: Some("Writer".into()),
    };
    assert_eq!(
        map_assignee_role_id(&writer, &roles).as_deref(),
        Some("new-role-id")
    );

    // Custom role whose value isn't on the restored app → unmapped.
    let admin = AppRoleAssigneeRef {
        principal: PrincipalRef::default(),
        app_role_id: "old-admin-id".into(),
        app_role_value: Some("Admin".into()),
    };
    assert_eq!(map_assignee_role_id(&admin, &roles), None);
}

#[test]
fn owner_label_prefers_upn_then_name_then_id() {
    let by_upn = PrincipalRef {
        source_id: "id".into(),
        user_principal_name: Some("a@b.com".into()),
        display_name: Some("Alice".into()),
        ..Default::default()
    };
    assert_eq!(owner_label(&by_upn), "a@b.com");
    let by_name = PrincipalRef {
        source_id: "id".into(),
        display_name: Some("Group X".into()),
        ..Default::default()
    };
    assert_eq!(owner_label(&by_name), "Group X");
}

#[test]
fn principal_cache_key_prefers_lowercased_upn_then_name_then_none() {
    // UPN wins and is lowercased, so case-variant UPNs share one memo entry.
    let by_upn = PrincipalRef {
        source_id: "id".into(),
        user_principal_name: Some("Alice@Contoso.com".into()),
        display_name: Some("Alice".into()),
        ..Default::default()
    };
    assert_eq!(
        principal_cache_key(&by_upn).as_deref(),
        Some("upn:alice@contoso.com")
    );

    // No UPN → keyed by kind + display name: a user and a group may share
    // a name, and are different lookups.
    let by_name = PrincipalRef {
        source_id: "id".into(),
        display_name: Some("Group X".into()),
        ..Default::default()
    };
    assert_eq!(
        principal_cache_key(&by_name).as_deref(),
        Some("name:any:Group X")
    );
    let typed = PrincipalRef {
        principal_type: Some("#microsoft.graph.group".into()),
        ..by_name.clone()
    };
    assert_eq!(
        principal_cache_key(&typed).as_deref(),
        Some("name:group:Group X")
    );

    // An empty UPN is ignored, falling through to the display name.
    let empty_upn = PrincipalRef {
        source_id: "id".into(),
        user_principal_name: Some(String::new()),
        display_name: Some("Group Y".into()),
        ..Default::default()
    };
    assert_eq!(
        principal_cache_key(&empty_upn).as_deref(),
        Some("name:any:Group Y")
    );

    // Neither set → no key (nothing to resolve or memoize).
    assert_eq!(principal_cache_key(&PrincipalRef::default()), None);
}

#[test]
fn build_restore_plan_counts_actions_and_flags_cloud_and_tenant_changes() {
    use crate::dto::backup::{AppRegistrationBackup, CredentialMeta, TenantBackup};
    let app = |secrets: usize, certs: usize, feds: usize, owners: usize| AppRegistrationBackup {
        secrets: vec![CredentialMeta::default(); secrets],
        certificates: vec![CredentialMeta::default(); certs],
        federated_credentials: vec![
            FederatedIdentityCredential {
                subject: Some("sub".into()),
                ..Default::default()
            };
            feds
        ],
        owners: vec![PrincipalRef::default(); owners],
        ..Default::default()
    };
    let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
    let ending = |secs: i64| CredentialMeta {
        end_date_time: chrono::DateTime::from_timestamp(secs, 0),
        ..Default::default()
    };
    // Two undated secrets, one still valid at backup time, one already
    // expired then: only the expired one is left out.
    let mut first = app(2, 1, 3, 1);
    first.secrets.push(ending(2_000_000));
    // A flexible credential (no subject) is not recreated, so it is not
    // counted as one to restore.
    first
        .federated_credentials
        .push(FederatedIdentityCredential::default());
    let mut second = app(0, 0, 0, 2);
    second.secrets.push(ending(500_000));
    let backup = TenantBackup {
        schema_version: 1,
        created_at: taken_at,
        source_tenant_id: "src-tenant".into(),
        cloud: CloudEnvironment::Commercial,
        app_registrations: vec![first, second],
        enterprise_apps: Vec::new(),
        managed_identities: Vec::new(),
        skipped: Vec::new(),
    };

    // Same cloud, different destination tenant — the expected DR case. Counts
    // are summed across every app registration.
    let plan = build_restore_plan(
        &backup,
        "dest-tenant".to_string(),
        CloudEnvironment::Commercial,
    );
    assert!(plan.cloud_mismatch.is_none());
    assert!(plan.tenant_changed);
    assert_eq!(plan.destination_tenant_id, "dest-tenant");
    assert_eq!(plan.app_registrations_to_create, 2);
    assert_eq!(plan.secrets_to_regenerate, 3);
    assert_eq!(plan.expired_secrets_skipped, 1);
    assert_eq!(plan.certificates_needing_manual_upload, 1);
    assert_eq!(plan.federated_credentials_to_restore, 3);
    assert_eq!(plan.owners_to_remap, 3);

    // A cross-cloud manifest is flagged; restoring into the source tenant is
    // not a "tenant change".
    let blocked = build_restore_plan(&backup, "src-tenant".to_string(), CloudEnvironment::UsGov);
    assert!(blocked.cloud_mismatch.is_some());
    assert!(!blocked.tenant_changed);
}

#[test]
fn build_restore_plan_forecasts_passes_4_and_5_and_blocks_a_newer_schema() {
    use crate::dto::backup::{
        AppRegistrationBackup, EnterpriseAppBackup, ManagedIdentityBackup, SkippedObject,
        TenantBackup,
    };

    let app = |id: &str, sp: bool| AppRegistrationBackup {
        source_app_id: id.into(),
        has_service_principal: sp,
        ..Default::default()
    };
    let ent = |id: &str, foreign: bool| EnterpriseAppBackup {
        source_app_id: id.into(),
        is_foreign_tenant: foreign,
        ..Default::default()
    };
    const PAIRED: &str = "11111111-1111-1111-1111-111111111111";
    const NO_SP: &str = "22222222-2222-2222-2222-222222222222";
    let mut backup = TenantBackup {
        schema_version: BACKUP_SCHEMA_VERSION,
        created_at: chrono::DateTime::from_timestamp(1_000_000, 0).unwrap(),
        source_tenant_id: "src-tenant".into(),
        cloud: CloudEnvironment::Commercial,
        app_registrations: vec![app(PAIRED, true), app(NO_SP, false)],
        enterprise_apps: vec![
            // Replayed: paired, not foreign, its app reg carries an SP.
            ent(PAIRED, false),
            // Runbook items: foreign/gallery, no app reg in the backup,
            // and an app reg Pass 1 creates without an SP.
            ent(PAIRED, true),
            ent("absent", false),
            ent(NO_SP, false),
        ],
        managed_identities: [
            "33333333-3333-3333-3333-333333333333",
            "44444444-4444-4444-4444-444444444444",
        ]
        .map(|id| ManagedIdentityBackup {
            source_app_id: id.into(),
            ..Default::default()
        })
        .to_vec(),
        skipped: vec![SkippedObject::new("application", "obj-x", None, "403")],
    };

    let plan = build_restore_plan(
        &backup,
        "dest-tenant".to_string(),
        CloudEnvironment::Commercial,
    );
    assert_eq!(plan.enterprise_apps_to_reapply, 1);
    assert_eq!(plan.enterprise_apps_manual, 3);
    assert_eq!(plan.managed_identities_to_rebind, 2);
    assert_eq!(plan.skipped_in_backup, 1);
    assert!(plan.schema_too_new.is_none());
    assert!(!plan.is_blocked());

    // A newer manifest still gets a plan — carrying the blocker, so the
    // operator sees it before Confirm rather than after.
    backup.schema_version = BACKUP_SCHEMA_VERSION + 1;
    let plan = build_restore_plan(
        &backup,
        "dest-tenant".to_string(),
        CloudEnvironment::Commercial,
    );
    let too_new = plan.schema_too_new.as_ref().expect("blocked");
    assert_eq!(too_new.manifest_version, BACKUP_SCHEMA_VERSION + 1);
    assert_eq!(too_new.supported_version, BACKUP_SCHEMA_VERSION);
    assert!(plan.is_blocked());
}

fn manifest_with_ids(ids: &[&str]) -> TenantBackup {
    TenantBackup {
        schema_version: BACKUP_SCHEMA_VERSION,
        created_at: chrono::DateTime::from_timestamp(1_000_000, 0).unwrap(),
        source_tenant_id: "src-tenant".into(),
        cloud: CloudEnvironment::Commercial,
        app_registrations: ids
            .iter()
            .enumerate()
            .map(|(i, id)| AppRegistrationBackup {
                source_app_id: (*id).into(),
                display_name: format!("app-{i}"),
                ..Default::default()
            })
            .collect(),
        enterprise_apps: Vec::new(),
        managed_identities: Vec::new(),
        skipped: Vec::new(),
    }
}

/// A repeated source appId would be adopted against the app Pass 1 just
/// created for its first copy and wired twice — two sets of secrets. The
/// plan shows the blocker before Confirm and the restore refuses on its own.
#[test]
fn a_duplicate_source_app_id_blocks_the_plan_and_the_restore() {
    const ID: &str = "11111111-1111-1111-1111-111111111111";
    let backup = manifest_with_ids(&[ID, "22222222-2222-2222-2222-222222222222", ID]);
    let plan = build_restore_plan(&backup, "dest".into(), CloudEnvironment::Commercial);
    assert!(plan.is_blocked());
    assert_eq!(
        plan.invalid_manifest,
        vec![format!("source appId {ID} appears 2 times")]
    );
    let err = validate_manifest(&backup).unwrap_err();
    assert_eq!(err.code, "invalid_manifest");

    // GUIDs compare case-insensitively.
    assert!(
        validate_manifest(&manifest_with_ids(&[
            "aaaaaaaa-0000-0000-0000-000000000000",
            "AAAAAAAA-0000-0000-0000-000000000000",
        ]))
        .is_err()
    );
}

/// An empty source appId would tag the app with the bare
/// `azapptoolkit:restoredFrom:` prefix; a non-GUID one cannot have come
/// from Graph. Both block the plan and the restore.
#[test]
fn an_empty_or_malformed_source_app_id_blocks_the_plan_and_the_restore() {
    for bad in [
        "",
        "  ",
        "not-a-guid",
        "{11111111-1111-1111-1111-111111111111}",
        // Padded: the tag and the remap would carry the whitespace.
        " 22222222-2222-2222-2222-222222222222",
        "22222222-2222-2222-2222-222222222222\n",
    ] {
        let backup = manifest_with_ids(&["11111111-1111-1111-1111-111111111111", bad]);
        let plan = build_restore_plan(&backup, "dest".into(), CloudEnvironment::Commercial);
        assert!(plan.is_blocked(), "{bad:?}");
        assert_eq!(plan.invalid_manifest.len(), 1, "{bad:?}");
        assert!(plan.invalid_manifest[0].contains("'app-1'"), "{bad:?}");
        assert_eq!(
            validate_manifest(&backup).unwrap_err().code,
            "invalid_manifest"
        );
    }

    // A sound manifest, and an empty one, pass.
    assert!(
        validate_manifest(&manifest_with_ids(&[
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        ]))
        .is_ok()
    );
    assert!(validate_manifest(&manifest_with_ids(&[])).is_ok());
}

/// Values from the file are echoed bounded: a hostile display name or id
/// cannot become the plan's text, and the cut never splits a character.
#[test]
fn manifest_problems_echo_file_values_bounded() {
    let mut backup = manifest_with_ids(&[&"x".repeat(10_000)]);
    backup.app_registrations[0].display_name = "é".repeat(10_000);
    let problems = manifest_problems(&backup);
    assert_eq!(problems.len(), 1);
    let expected = format!(
        "app registration '{}…' has a source appId that is not a GUID ('{}…')",
        "é".repeat(MAX_ECHOED_CHARS),
        "x".repeat(MAX_ECHOED_CHARS)
    );
    assert_eq!(problems[0], expected);
    // Short values are echoed whole.
    assert_eq!(excerpt("Payroll"), "Payroll");
    assert_eq!(
        excerpt(&"a".repeat(MAX_ECHOED_CHARS)),
        "a".repeat(MAX_ECHOED_CHARS)
    );
}

/// A file that repeats the problem thousands of times still yields a
/// readable plan.
#[test]
fn manifest_problems_are_capped() {
    let ids = vec![""; MAX_MANIFEST_PROBLEMS + 5];
    let problems = manifest_problems(&manifest_with_ids(&ids));
    assert_eq!(problems.len(), MAX_MANIFEST_PROBLEMS + 1);
    assert_eq!(problems.last().map(String::as_str), Some("and 5 more"));
}

#[test]
fn expired_at_backup_uses_the_backup_time_not_now() {
    let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
    let ending = |end: Option<DateTime<Utc>>| CredentialMeta {
        end_date_time: end,
        ..Default::default()
    };
    // Expired before the backup was taken: nothing could have used it.
    assert!(expired_at_backup(
        &ending(chrono::DateTime::from_timestamp(999_999, 0)),
        taken_at
    ));
    // Live at backup time, long expired by now: a recovering client still
    // holds it, so it is re-issued.
    assert!(!expired_at_backup(
        &ending(chrono::DateTime::from_timestamp(1_000_001, 0)),
        taken_at
    ));
    // No end date is not "expired".
    assert!(!expired_at_backup(&ending(None), taken_at));
}

#[test]
fn restore_marker_is_prefix_plus_source_app_id() {
    assert_eq!(
        restore_marker("11111111-2222-3333-4444-555555555555"),
        "azapptoolkit:restoredFrom:11111111-2222-3333-4444-555555555555"
    );
    assert!(restore_marker("x").starts_with(RESTORE_MARKER_PREFIX));
}

#[test]
fn adoption_for_creates_adopts_or_refuses() {
    use azapptoolkit_core::models::PasswordCredential;

    let app = AppRegistrationBackup {
        display_name: "App A".into(),
        source_app_id: "src-a".into(),
        // The one secret an earlier run of this restore would have issued.
        secrets: vec![CredentialMeta {
            display_name: Some("ci".into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
    // Created after the backup was taken, as anything a restore of it made.
    let hit = |id: &str, name: &str| TagHit {
        app: Application {
            id: format!("obj-{id}"),
            app_id: format!("app-{id}"),
            display_name: name.into(),
            created_date_time: chrono::DateTime::from_timestamp(1_000_600, 0),
            ..Default::default()
        },
        ..Default::default()
    };
    let decide_on =
        |hits: &[TagHit]| adoption_for(&app, hits, taken_at, "src-tenant", "dst-tenant");

    // Nothing carries the tag: create.
    assert_eq!(decide_on(&[]), Adoption::Create);

    // One tagged app with the same name holding exactly the manifest's
    // secret: an earlier run made it — adopt it, carrying the names of the
    // secrets it already holds and the clients it pre-authorizes.
    let mut same = hit("1", "App A");
    same.app.password_credentials = vec![PasswordCredential {
        key_id: "key-1".into(),
        display_name: Some("ci".into()),
        hint: Some("Ab1".into()),
        start_date_time: chrono::DateTime::from_timestamp(1_000_700, 0),
        ..Default::default()
    }];
    assert_eq!(
        decide_on(&[same]),
        Adoption::Adopt {
            object_id: "obj-1".into(),
            app_id: "app-1".into(),
            live_secrets: vec![LiveSecret {
                name: "ci".into(),
                key_id: "key-1".into(),
                valid_from: chrono::DateTime::from_timestamp(1_000_700, 0),
                hint: Some("Ab1".into()),
            }],
            pre_authorized: Vec::new(),
        }
    );

    // Tagged but renamed: never adopted on the tag alone, never duplicated.
    let Adoption::Refuse(reason) = decide_on(&[hit("2", "Renamed")]) else {
        panic!("a renamed tagged app must be refused");
    };
    assert!(reason.contains("Renamed") && reason.contains("app-2"));

    // Two tagged apps: ambiguous, so neither is taken and nothing is created.
    let Adoption::Refuse(reason) = decide_on(&[hit("1", "App A"), hit("2", "App A")]) else {
        panic!("two tagged apps must be refused");
    };
    assert!(reason.starts_with("2 apps carry the restore tag"));

    // Tag and name match, but the app predates the backup — or its creation
    // time is unknown: no restore of this backup can be proven to have made
    // it, so it is refused rather than handed this app's consent.
    let mut older = hit("3", "App A");
    older.app.created_date_time = chrono::DateTime::from_timestamp(999_000, 0);
    let Adoption::Refuse(reason) = decide_on(&[older]) else {
        panic!("an app older than the backup must be refused");
    };
    assert!(
        reason.contains("not after this backup was taken"),
        "{reason}"
    );
    let mut undated = hit("4", "App A");
    undated.app.created_date_time = None;
    let Adoption::Refuse(reason) = decide_on(&[undated]) else {
        panic!("an app of unknown age must be refused");
    };
    assert!(reason.contains("an unknown time"), "{reason}");

    // A reply URL the backup does not list: refused, the URL named. The
    // clients it pre-authorizes are carried for Pass 1 to check once every
    // app has its destination appId.
    let mut planted = hit("5", "App A");
    planted.auth.spa_redirect_uris = vec!["https://evil.example/cb".into()];
    let Adoption::Refuse(reason) = decide_on(&[planted]) else {
        panic!("a reply URL the backup does not list must refuse the adoption");
    };
    assert!(
        reason.contains("SPA redirect URI 'https://evil.example/cb'"),
        "{reason}"
    );
    let client = pre_authorized("client-1", &["scope-1"]);
    let mut api = hit("6", "App A");
    api.expose.api.pre_authorized_applications = vec![client.clone()];
    let Adoption::Adopt { pre_authorized, .. } = decide_on(&[api]) else {
        panic!("pre-authorized clients are checked after the loop, not here");
    };
    assert_eq!(pre_authorized, [client]);
}

#[test]
fn unexpected_owners_names_everyone_not_allowed() {
    let owner = |id: &str, upn: Option<&str>, name: Option<&str>| DirectoryObject {
        id: id.into(),
        user_principal_name: upn.map(Into::into),
        display_name: name.map(Into::into),
        ..Default::default()
    };
    let owners = [
        owner("op", Some("admin@contoso.com"), None),
        owner("x1", Some("mallory@contoso.com"), Some("Mallory")),
        owner("x2", None, Some("Some Group")),
        owner("x3", None, None),
    ];
    let allowed = HashSet::from(["op".to_string()]);
    assert_eq!(
        unexpected_owners(&owners, &allowed),
        ["mallory@contoso.com", "Some Group", "x3"]
    );
    let everyone = HashSet::from(["op", "x1", "x2", "x3"].map(String::from));
    assert!(unexpected_owners(&owners, &everyone).is_empty());
}

/// A token provider whose refresh token is gone: every read fails with the
/// re-auth-fatal code before any request is sent.
struct DeadSession;
#[async_trait::async_trait]
impl azapptoolkit_core::token::BearerProvider for DeadSession {
    async fn bearer(&self) -> Result<String, azapptoolkit_core::token::TokenError> {
        Err(azapptoolkit_core::token::TokenError::new(
            "refresh_missing",
            "gone",
        ))
    }
}

fn graph_over(server: &wiremock::MockServer, dead: bool) -> GraphClient {
    use azapptoolkit_core::cache::Cache;
    use azapptoolkit_core::token::{BearerProvider, StaticTokenProvider};
    use std::sync::Arc;
    let token: Arc<dyn BearerProvider> = if dead {
        Arc::new(DeadSession)
    } else {
        StaticTokenProvider::new("tok")
    };
    GraphClient::with_base_url(
        "tenant-test",
        token.clone(),
        token,
        Cache::new(),
        server.uri(),
    )
}

/// Pass 5 on its own, its progress ticks recorded nowhere a test reads.
async fn rebind_mis(
    client: &GraphClient,
    mis: &[ManagedIdentityBackup],
    approved: &HashSet<RestoreApproval>,
    report: &mut RestoreReport,
    session: &SessionDead,
    cancel: &CancelToken,
) {
    let sink = crate::commands::test_support::Recorder::default();
    let mut progress = RestoreProgress::start(&sink, mis.len());
    restore_managed_identities(
        client,
        mis,
        approved,
        report,
        session,
        cancel,
        &mut progress,
    )
    .await;
}

fn two_mis() -> Vec<ManagedIdentityBackup> {
    ["mi-one", "mi-two"]
        .into_iter()
        .map(|name| ManagedIdentityBackup {
            display_name: name.into(),
            ..Default::default()
        })
        .collect()
}

// `unwrap_or_default()` once turned a failed listing into an empty
// destination, and every MI was reported "not found — recreate it via IaC".
#[tokio::test]
async fn a_failed_mi_listing_is_reported_once_not_as_missing_identities() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let client = graph_over(&server, false);
    let session = SessionDead::new();
    let mut report = RestoreReport::default();

    rebind_mis(
        &client,
        &two_mis(),
        &HashSet::new(),
        &mut report,
        &session,
        &never_cancelled(),
    )
    .await;

    assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
    assert!(report.manual_items[0].reason.contains("Couldn't list"));
    assert!(
        !report
            .manual_items
            .iter()
            .any(|m| m.reason.contains("not found in the destination")),
        "a failed read must not be reported as missing identities"
    );
    assert!(report.managed_identities.is_empty());
    assert!(!session.is_dead(), "a 403 is not a dead session");
}

#[tokio::test]
async fn a_dead_session_during_the_mi_listing_latches() {
    // Never answered: the token fails before any request is sent.
    let server = wiremock::MockServer::start().await;
    let client = graph_over(&server, true);
    let session = SessionDead::new();
    let mut report = RestoreReport::default();

    rebind_mis(
        &client,
        &two_mis(),
        &HashSet::new(),
        &mut report,
        &session,
        &never_cancelled(),
    )
    .await;

    assert!(session.is_dead(), "a dead refresh token must latch");
    assert_eq!(report.manual_items.len(), 1);
}

// The `_` arm once reported any read failure as "the app had none in the
// backup", which is false whenever the backup said it had one.
#[tokio::test]
async fn a_failed_sp_read_is_not_reported_as_having_no_sp() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let client = graph_over(&server, false);
    let session = SessionDead::new();
    let mut report = RestoreReport::default();
    let ent = EnterpriseAppBackup {
        display_name: "Ent A".into(),
        source_app_id: "src-a".into(),
        ..Default::default()
    };
    let remap = HashMap::from([("src-a".to_string(), "new-a".to_string())]);

    restore_enterprise_app(
        &pass_ctx(&client, &session, &remap),
        &ent,
        false,
        &mut report,
        &mut HashMap::new(),
        &never_cancelled(),
    )
    .await;

    assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
    let reason = &report.manual_items[0].reason;
    assert!(!reason.contains("had none in the backup"), "{reason}");
    assert!(reason.contains("Couldn't read the restored service principal"));
    assert!(report.enterprise_apps.is_empty());
}

fn tagged_app_a() -> AppRegistrationBackup {
    AppRegistrationBackup {
        display_name: "App A".into(),
        source_app_id: "src-a".into(),
        ..Default::default()
    }
}

/// Mounts the tag lookup answering one hit named "App A", created after
/// `taken_at` in [`decide`], and its owners.
async fn mount_tagged_hit(server: &wiremock::MockServer, owners: serde_json::Value) {
    mount_tagged_hit_with(server, owners, serde_json::json!({})).await;
}

/// [`mount_tagged_hit`], the hit also carrying `settings`: any of the
/// authentication and Expose-an-API fields the tag lookup selects (`web`,
/// `spa`, `publicClient`, `isFallbackPublicClient`, `identifierUris`, `api`).
async fn mount_tagged_hit_with(
    server: &wiremock::MockServer,
    owners: serde_json::Value,
    settings: serde_json::Value,
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let mut hit = serde_json::json!({
        "id": "obj-1",
        "appId": "app-1",
        "displayName": "App A",
        "createdDateTime": "2026-01-02T00:00:00Z"
    });
    if let (Some(hit), Some(settings)) = (hit.as_object_mut(), settings.as_object()) {
        hit.extend(settings.clone());
    }
    Mock::given(method("GET"))
        .and(path("/applications"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [hit] })),
        )
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1/owners"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": owners })),
        )
        .mount(server)
        .await;
    mount_tagged_fics(server, serde_json::json!([]), 5).await;
    mount_tagged_sp(server, serde_json::json!([]), 5).await;
    mount_tagged_sp_owners(server, serde_json::json!([]), 5).await;
}

/// The tagged hit's service principal (`sp-1`), read live with its
/// credentials once the app's own checks pass. A test that plants a
/// credential mounts again at a higher priority (lower number).
async fn mount_tagged_sp(
    server: &wiremock::MockServer,
    passwords: serde_json::Value,
    priority: u8,
) {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, ResponseTemplate};
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "appId eq 'app-1'"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "sp-1",
                "appId": "app-1",
                "displayName": "App A",
                "passwordCredentials": passwords,
                "keyCredentials": []
            }]
        })))
        .with_priority(priority)
        .mount(server)
        .await;
}

/// The owners of the tagged hit's service principal.
async fn mount_tagged_sp_owners(
    server: &wiremock::MockServer,
    owners: serde_json::Value,
    priority: u8,
) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/sp-1/owners"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": owners })),
        )
        .with_priority(priority)
        .mount(server)
        .await;
}

/// The tagged hit's federated credentials, read after its owners pass. A
/// test that plants one mounts again at a higher priority (lower number).
async fn mount_tagged_fics(server: &wiremock::MockServer, fics: serde_json::Value, priority: u8) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    Mock::given(method("GET"))
        .and(path("/applications/obj-1/federatedIdentityCredentials"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": fics })),
        )
        .with_priority(priority)
        .mount(server)
        .await;
}

/// A cancel token nothing ever cancels.
fn never_cancelled() -> CancelToken {
    crate::state::CancelFlag::new().claim()
}

/// The pass context the wiring and enterprise-app tests run under: the
/// commercial cloud, a backup taken 2026-01-01, `src-tenant` → `dst-tenant`.
fn pass_ctx<'a>(
    client: &'a GraphClient,
    session: &'a SessionDead,
    app_id_remap: &'a HashMap<String, String>,
) -> PassCtx<'a> {
    PassCtx {
        client,
        session,
        app_id_remap,
        cloud: CloudEnvironment::Commercial,
        taken_at: "2026-01-01T00:00:00Z".parse().unwrap(),
        source_tenant_id: "src-tenant",
        dest_tenant_id: "dst-tenant",
    }
}

async fn decide(client: &GraphClient, session: &SessionDead) -> Adoption {
    decide_app(client, &tagged_app_a(), session).await
}

/// [`decide_adoption`] for `app` under the run the pass-loop tests use: the
/// [`manifest`] backup (taken 2026-01-01 in `src-tenant`), restored into
/// `dst-tenant` by `operator-oid`.
async fn decide_app(
    client: &GraphClient,
    app: &AppRegistrationBackup,
    session: &SessionDead,
) -> Adoption {
    let backup = manifest(Vec::new());
    let approved = HashSet::new();
    let run = RestoreRun {
        backup: &backup,
        tenant_id: "dst-tenant",
        cloud: CloudEnvironment::Commercial,
        operator_oid: Some("operator-oid"),
        approved: &approved,
    };
    decide_adoption(client, app, &run, &mut HashMap::new(), session).await
}

// The fail-closed branch is the package's key safety property: a failed tag
// lookup must never fall through to a create.
#[tokio::test]
async fn a_failed_tag_lookup_refuses_instead_of_creating() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    let client = graph_over(&server, false);
    let session = SessionDead::new();

    let Adoption::Refuse(reason) = decide(&client, &session).await else {
        panic!("a failed lookup must be refused");
    };
    assert!(reason.contains("it was NOT created"), "{reason}");
    assert!(!session.is_dead(), "a 403 is not a dead session");
}

#[tokio::test]
async fn a_dead_session_during_the_tag_lookup_refuses_and_latches() {
    let server = wiremock::MockServer::start().await;
    let client = graph_over(&server, true);
    let session = SessionDead::new();

    assert!(matches!(
        decide(&client, &session).await,
        Adoption::Refuse(_)
    ));
    assert!(session.is_dead(), "a dead refresh token must latch");
}

// Anyone who may register apps can write the tag and the name, so a hit
// with an owner the restore did not set is someone else's app: adopting it
// would give them this app's permissions and admin consent.
#[tokio::test]
async fn a_tagged_app_with_a_foreign_owner_is_not_adopted() {
    let server = wiremock::MockServer::start().await;
    mount_tagged_hit(
        &server,
        serde_json::json!([
            { "id": "operator-oid", "userPrincipalName": "admin@contoso.com" },
            { "id": "mallory-oid", "userPrincipalName": "mallory@contoso.com" }
        ]),
    )
    .await;
    let client = graph_over(&server, false);

    let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
        panic!("a foreign owner must block adoption");
    };
    assert!(reason.contains("mallory@contoso.com"), "{reason}");
    assert!(!reason.contains("admin@contoso.com"), "{reason}");
}

#[tokio::test]
async fn a_tagged_app_owned_only_by_the_operator_is_adopted() {
    let server = wiremock::MockServer::start().await;
    mount_tagged_hit(
        &server,
        serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
    )
    .await;
    let client = graph_over(&server, false);

    assert_eq!(
        decide(&client, &SessionDead::new()).await,
        Adoption::Adopt {
            object_id: "obj-1".into(),
            app_id: "app-1".into(),
            live_secrets: Vec::new(),
            pre_authorized: Vec::new(),
        }
    );
}

/// The service principal is the other half of the app: a secret or
/// certificate on it signs in as this app once Pass 3 consents. A restore
/// never adds one, so any credential there refuses the adoption.
#[tokio::test]
async fn a_tagged_app_whose_service_principal_holds_a_credential_is_not_adopted() {
    let server = wiremock::MockServer::start().await;
    mount_tagged_hit(
        &server,
        serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
    )
    .await;
    mount_tagged_sp(
        &server,
        serde_json::json!([{ "keyId": "k-sp", "displayName": "backdoor" }]),
        1,
    )
    .await;
    let client = graph_over(&server, false);

    let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
        panic!("a credential on the service principal must block adoption");
    };
    assert!(
        reason.contains("service principal") && reason.contains("secret 'backdoor'"),
        "{reason}"
    );
    // The credential read is live, never a cached copy from before it was added.
    let reads = requests(&server, "GET", "/servicePrincipals").await;
    assert!(
        reads.iter().any(|r| r
            .url
            .query()
            .unwrap_or_default()
            .contains("passwordCredentials")),
        "the service principal is read with its credentials"
    );
}

/// An owner of the service principal can add a credential to it, so one the
/// restore did not set refuses the adoption just as an app owner does.
#[tokio::test]
async fn a_tagged_app_with_a_foreign_sp_owner_is_not_adopted() {
    let server = wiremock::MockServer::start().await;
    mount_tagged_hit(
        &server,
        serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
    )
    .await;
    mount_tagged_sp_owners(
        &server,
        serde_json::json!([
            { "id": "operator-oid", "userPrincipalName": "admin@contoso.com" },
            { "id": "mallory-oid", "userPrincipalName": "mallory@contoso.com" }
        ]),
        1,
    )
    .await;
    let client = graph_over(&server, false);

    let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
        panic!("a foreign service-principal owner must block adoption");
    };
    assert!(
        reason.contains("service principal") && reason.contains("mallory@contoso.com"),
        "{reason}"
    );
    assert!(!reason.contains("admin@contoso.com"), "{reason}");
}

/// Both service-principal reads fail closed, like the tag, owner and
/// credential reads before them.
#[tokio::test]
async fn a_failed_service_principal_read_refuses_the_adoption() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let operator = serde_json::json!([{ "id": "operator-oid" }]);
    let server = wiremock::MockServer::start().await;
    mount_tagged_hit(&server, operator.clone()).await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(403))
        .with_priority(1)
        .mount(&server)
        .await;
    let client = graph_over(&server, false);
    let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
        panic!("an unreadable service principal must block adoption");
    };
    assert!(
        reason.contains("Couldn't read the service principal"),
        "{reason}"
    );

    let server = wiremock::MockServer::start().await;
    mount_tagged_hit(&server, operator).await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals/sp-1/owners"))
        .respond_with(ResponseTemplate::new(403))
        .with_priority(1)
        .mount(&server)
        .await;
    let client = graph_over(&server, false);
    let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
        panic!("unreadable service-principal owners must block adoption");
    };
    assert!(
        reason.contains("Couldn't read the owners of the service principal"),
        "{reason}"
    );
}

#[tokio::test]
async fn a_failed_owner_read_refuses_the_adoption() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = wiremock::MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1/owners"))
        .respond_with(ResponseTemplate::new(403))
        .with_priority(1)
        .mount(&server)
        .await;
    mount_tagged_hit(&server, serde_json::json!([])).await;
    let client = graph_over(&server, false);

    let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
        panic!("an unreadable owner list must block adoption");
    };
    assert!(reason.contains("Couldn't read the owners"), "{reason}");
}

/// A manifest is untrusted input — the same premise the federated-credential
/// loop states. Reply URLs are where auth codes are delivered, so a wildcard
/// or plaintext one must not reach the tenant just because it arrived in a
/// file rather than through the editor.
#[test]
fn a_flexible_federated_credential_is_skipped_with_a_warning() {
    let flexible = FederatedIdentityCredential {
        name: "gh-flex".into(),
        ..Default::default()
    };
    let warning = restorable_fic_subject(&flexible).unwrap_err();
    assert!(warning.contains("'gh-flex' was NOT restored"), "{warning}");
    assert!(warning.contains("flexible credential"), "{warning}");

    let pinned = FederatedIdentityCredential {
        name: "gh-main".into(),
        subject: Some("repo:contoso/app:ref:refs/heads/main".into()),
        ..Default::default()
    };
    assert_eq!(
        restorable_fic_subject(&pinned),
        Ok("repo:contoso/app:ref:refs/heads/main")
    );
}

#[test]
fn restored_reply_urls_are_validated_like_editor_input() {
    let uris = [
        "https://good.contoso.com/cb",
        "https://*.evil.example/cb",
        "http://attacker.example/cb",
        "http://localhost:5173/cb",
    ]
    .map(String::from);
    let mut warnings = Vec::new();
    let kept = checked_uris(&uris, "web redirect URIs", &mut warnings);

    // Per-URI, not all-or-nothing: one bad entry must not discard the good
    // ones, and loopback http stays legal exactly as it is in the editor.
    assert_eq!(
        kept,
        vec![
            "https://good.contoso.com/cb".to_string(),
            "http://localhost:5173/cb".to_string()
        ]
    );
    assert_eq!(
        warnings.len(),
        2,
        "each rejection is reported: {warnings:?}"
    );
    assert!(warnings.iter().any(|w| w.contains("*.evil.example")));
    assert!(warnings.iter().any(|w| w.contains("attacker.example")));
    // The operator can tell which list it was.
    assert!(
        warnings
            .iter()
            .all(|w| w.starts_with("web redirect URIs: "))
    );
}

/// The logout URL is checked by the logout rules, not the reply-URL ones: a
/// custom scheme passes `validate_redirect_uri` but must not be restored as
/// a sign-out page.
#[test]
fn a_restored_logout_url_is_validated_like_editor_input() {
    let mut warnings = Vec::new();
    assert_eq!(
        checked_logout_url(Some(" https://app.contoso.com/logout "), &mut warnings),
        Some("https://app.contoso.com/logout".to_string())
    );
    assert_eq!(checked_logout_url(Some("  "), &mut warnings), None);
    assert_eq!(checked_logout_url(None, &mut warnings), None);
    assert!(warnings.is_empty(), "{warnings:?}");

    assert!(validate_redirect_uri("myapp://logout").is_ok());
    for bad in ["myapp://logout", "http://attacker.example/logout"] {
        assert_eq!(checked_logout_url(Some(bad), &mut warnings), None, "{bad}");
    }
    assert_eq!(
        warnings.len(),
        2,
        "each rejection is reported: {warnings:?}"
    );
    assert!(warnings[0].contains("'myapp://logout' was NOT restored"));
}

/// An empty list restores nothing and warns about nothing — the common case
/// must stay silent.
#[test]
fn checked_uris_is_silent_when_everything_is_valid() {
    let uris = ["https://a.contoso.com/cb"].map(String::from);
    let mut warnings = Vec::new();
    assert_eq!(
        checked_uris(&uris, "web redirect URIs", &mut warnings).len(),
        1
    );
    assert!(warnings.is_empty());
}

#[test]
fn principal_kind_reads_odata_and_assignment_types() {
    let with = |t: Option<&str>| PrincipalRef {
        principal_type: t.map(Into::into),
        ..Default::default()
    };
    assert_eq!(principal_kind(&with(None)), PrincipalKind::Either);
    assert_eq!(principal_kind(&with(Some(" "))), PrincipalKind::Either);
    assert_eq!(
        principal_kind(&with(Some("#microsoft.graph.user"))),
        PrincipalKind::User
    );
    // An app-role assignment records `principalType` bare.
    assert_eq!(principal_kind(&with(Some("Group"))), PrincipalKind::Group);
    assert_eq!(
        principal_kind(&with(Some("ServicePrincipal"))),
        PrincipalKind::Other("ServicePrincipal".into())
    );
}

#[test]
fn an_unresolved_label_names_the_reason() {
    let p = PrincipalRef {
        display_name: Some("Ops".into()),
        ..Default::default()
    };
    assert_eq!(Unresolved::NotFound.label(&p), "Ops");
    assert_eq!(
        Unresolved::Ambiguous(2).label(&p),
        "Ops (ambiguous: 2 matches)"
    );
    assert_eq!(Unresolved::LookupFailed.label(&p), "Ops (lookup failed)");
}

// ---- behavioural tests of the pass loop, against a mock Graph ----

use wiremock::matchers::{method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const GRAPH: &str = "00000003-0000-0000-c000-000000000000";
const APP_RW_ROLE: &str = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9";
const MAIL_SEND_ROLE: &str = "b633e1c5-b582-4048-a93e-9f11b44c7e96";
const USER_READ_SCOPE: &str = "e1fe6dd8-ba31-4d61-89e7-88639da4683d";
const SRC_A: &str = "aaaaaaaa-0000-0000-0000-000000000001";
const SRC_B: &str = "bbbbbbbb-0000-0000-0000-000000000002";
const SRC_C: &str = "cccccccc-0000-0000-0000-000000000003";

/// Answers whatever a test did not mount: 204 for a PATCH, an empty page
/// for anything else. A test mounts only what it asserts on and reads the
/// rest off [`requests`].
async fn mount_fallback(server: &MockServer) {
    Mock::given(method("PATCH"))
        .respond_with(ResponseTemplate::new(204))
        .with_priority(10)
        .mount(server)
        .await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })))
        .with_priority(11)
        .mount(server)
        .await;
}

/// The requests `server` received with `verb` on exactly `url_path`.
async fn requests(server: &MockServer, verb: &str, url_path: &str) -> Vec<Request> {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method.as_str() == verb && r.url.path() == url_path)
        .collect()
}

fn created(app: AppRegistrationBackup) -> CreatedApp {
    CreatedApp {
        backup: app,
        new_object_id: "new-obj".into(),
        new_app_id: "new-app".into(),
        adopted: false,
        live_secrets: Vec::new(),
        warnings: Vec::new(),
    }
}

async fn wire(client: &GraphClient, c: &CreatedApp) -> (RestoredApp, Vec<ManualItem>) {
    wire_with(client, c, false).await
}

async fn wire_with(
    client: &GraphClient,
    c: &CreatedApp,
    withhold: bool,
) -> (RestoredApp, Vec<ManualItem>) {
    wire_application(
        &pass_ctx(client, &SessionDead::new(), &HashMap::new()),
        c,
        &BackupApps::default(),
        &mut PrincipalMemo::new(),
        &never_cancelled(),
        withhold,
    )
    .await
}

/// The authentication PATCH carries only the reply URLs that passed
/// validation — the wildcard one never reaches the tenant.
#[tokio::test]
async fn the_auth_patch_omits_a_rejected_redirect_uri() {
    let server = MockServer::start().await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let c = created(AppRegistrationBackup {
        display_name: "App A".into(),
        web_redirect_uris: vec![
            "https://good.contoso.com/cb".into(),
            "https://*.evil.example/cb".into(),
        ],
        ..Default::default()
    });

    let (out, _) = wire(&client, &c).await;

    let patches = requests(&server, "PATCH", "/applications/new-obj").await;
    let auth: Vec<serde_json::Value> = patches
        .iter()
        .map(|r| serde_json::from_slice(&r.body).unwrap())
        .filter(|b: &serde_json::Value| b.get("web").is_some())
        .collect();
    assert_eq!(auth.len(), 1, "one authentication PATCH");
    assert_eq!(
        auth[0]["web"]["redirectUris"],
        serde_json::json!(["https://good.contoso.com/cb"])
    );
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("*.evil.example") && w.contains("NOT restored")),
        "{:?}",
        out.warnings
    );
}

/// A federated credential with an issuer validation refuses is never
/// POSTed — and is not reported as a restored trust.
#[tokio::test]
async fn a_federated_credential_with_a_bad_issuer_is_never_posted() {
    let server = MockServer::start().await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let c = created(AppRegistrationBackup {
        display_name: "App A".into(),
        federated_credentials: vec![FederatedIdentityCredential {
            name: "planted".into(),
            issuer: "http://attacker.example".into(),
            subject: Some("repo:x/y:ref:refs/heads/main".into()),
            ..Default::default()
        }],
        ..Default::default()
    });

    let (out, trusts) = wire(&client, &c).await;

    assert!(
        requests(
            &server,
            "POST",
            "/applications/new-obj/federatedIdentityCredentials"
        )
        .await
        .is_empty(),
        "a refused credential must not be created"
    );
    assert!(trusts.is_empty());
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("'planted' was NOT restored")),
        "{:?}",
        out.warnings
    );
}

/// An adopted app keeps the owners and secrets an earlier run gave it: no
/// owner is added twice, no secret issued twice.
#[tokio::test]
async fn an_adopted_app_skips_existing_owners_and_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/applications/new-obj/owners"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "value": [{ "id": "alice-oid" }] })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "alice-oid", "userPrincipalName": "alice@contoso.com" }]
        })))
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let mut c = created(AppRegistrationBackup {
        display_name: "App A".into(),
        owners: vec![PrincipalRef {
            user_principal_name: Some("alice@contoso.com".into()),
            ..Default::default()
        }],
        secrets: vec![CredentialMeta {
            display_name: Some("ci".into()),
            ..Default::default()
        }],
        ..Default::default()
    });
    c.adopted = true;
    c.live_secrets = vec![LiveSecret {
        name: "ci".into(),
        key_id: "key-live-1".into(),
        valid_from: Some("2026-01-02T03:04:00Z".parse().unwrap()),
        hint: Some("Ab1".into()),
    }];

    let (out, _) = wire(&client, &c).await;

    assert!(
        requests(&server, "POST", "/applications/new-obj/owners/$ref")
            .await
            .is_empty(),
        "an existing owner must not be added again"
    );
    assert!(
        requests(&server, "POST", "/applications/new-obj/addPassword")
            .await
            .is_empty(),
        "an already-issued secret must not be issued again"
    );
    assert!(out.regenerated_secrets.is_empty());
    assert!(
        out.unresolved_owners.is_empty(),
        "{:?}",
        out.unresolved_owners
    );
    // The kept secret is named by what tells it from a planted copy of the
    // name: its key id, start date and hint.
    let kept = out
        .warnings
        .iter()
        .find(|w| w.contains("secret 'ci' already exists"))
        .unwrap_or_else(|| panic!("{:?}", out.warnings));
    assert!(
        kept.contains("key id key-live-1")
            && kept.contains("valid from 2026-01-02 03:04 UTC")
            && kept.contains("hint 'Ab1'"),
        "{kept}"
    );
}

/// An app whose admin consent covers a Graph application permission; the
/// backup's own `Application.ReadWrite.All` (high risk).
fn consenting_app(src: &str, name: &str) -> AppRegistrationBackup {
    AppRegistrationBackup {
        source_app_id: src.into(),
        display_name: name.into(),
        admin_consent_granted: true,
        required_resource_access: vec![azapptoolkit_core::models::RequiredResourceAccess {
            resource_app_id: GRAPH.into(),
            resource_access: vec![azapptoolkit_core::models::ResourceAccess {
                id: APP_RW_ROLE.into(),
                r#type: "Role".into(),
            }],
        }],
        ..Default::default()
    }
}

fn manifest(apps: Vec<AppRegistrationBackup>) -> TenantBackup {
    TenantBackup {
        schema_version: BACKUP_SCHEMA_VERSION,
        created_at: "2026-01-01T00:00:00Z".parse().unwrap(),
        source_tenant_id: "src-tenant".into(),
        cloud: CloudEnvironment::Commercial,
        app_registrations: apps,
        enterprise_apps: Vec::new(),
        managed_identities: Vec::new(),
        skipped: Vec::new(),
    }
}

/// Pass 1's create answers with an object id derived from the display
/// name ("App A" → `obj-a`), so each app's later requests are tellable.
async fn mount_create(server: &MockServer) {
    mount_create_then(server, |_| {}).await;
}

/// [`mount_create`], calling `on_create` with each created app's display
/// name before answering — where a test cancels the run.
async fn mount_create_then(server: &MockServer, on_create: impl Fn(&str) + Send + Sync + 'static) {
    Mock::given(method("POST"))
        .and(path("/applications"))
        .respond_with(move |req: &Request| {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            let name = body["displayName"].as_str().unwrap_or_default().to_string();
            on_create(&name);
            let tag = name
                .rsplit(' ')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": format!("obj-{tag}"),
                "appId": format!("app-{tag}"),
                "displayName": name,
                "passwordCredentials": [],
                "keyCredentials": [],
                "requiredResourceAccess": []
            }))
        })
        .mount(server)
        .await;
}

/// Microsoft Graph's service principal, exposing the high-risk role.
async fn mount_graph_sp(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", format!("appId eq '{GRAPH}'")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "graph-sp",
                "appId": GRAPH,
                "displayName": "Microsoft Graph",
                "appRoles": [{
                    "id": APP_RW_ROLE,
                    "value": "Application.ReadWrite.All",
                    "allowedMemberTypes": ["Application"],
                    "isEnabled": true
                }, {
                    "id": MAIL_SEND_ROLE,
                    "value": "Mail.Send",
                    "allowedMemberTypes": ["Application"],
                    "isEnabled": true
                }],
                "oauth2PermissionScopes": [{
                    "id": USER_READ_SCOPE,
                    "value": "User.Read",
                    "isEnabled": true
                }]
            }]
        })))
        .mount(server)
        .await;
}

/// Pass 3's re-read: each restored app (`obj-…`) declares what
/// [`consenting_app`] does — what Pass 2 PATCHed.
async fn mount_live_apps(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path_regex(r"^/applications/obj-[a-z0-9]+$"))
        .respond_with(|req: &Request| {
            let id = req
                .url
                .path()
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string();
            let tag = id.trim_start_matches("obj-").to_string();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": id,
                "appId": format!("app-{tag}"),
                "displayName": format!("App {tag}"),
                "requiredResourceAccess": [{
                    "resourceAppId": GRAPH,
                    "resourceAccess": [{ "id": APP_RW_ROLE, "type": "Role" }]
                }]
            }))
        })
        .mount(server)
        .await;
}

/// Whether Pass 3 got as far as ensuring `app_id`'s service principal —
/// the first step of an actual consent. Pass 1's live credential read of an
/// adoption candidate's service principal (it selects `passwordCredentials`)
/// is not one.
async fn consent_attempted(server: &MockServer, app_id: &str) -> bool {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .any(|r| {
            let query = r.url.query().unwrap_or_default();
            r.method.as_str() == "GET"
                && r.url.path() == "/servicePrincipals"
                && query.contains(app_id)
                && !query.contains("passwordCredentials")
        })
}

async fn restore(
    client: &GraphClient,
    backup: &TenantBackup,
    cancel: CancelToken,
    approved: &[&str],
) -> (RestoreReport, RestoreEffects) {
    let approved: HashSet<RestoreApproval> = approved.iter().map(|s| app_approval(s)).collect();
    run_restore(
        client,
        &crate::commands::test_support::Recorder::default(),
        cancel,
        RestoreRun {
            backup,
            tenant_id: "dst-tenant",
            cloud: CloudEnvironment::Commercial,
            operator_oid: Some("operator-oid"),
            approved: &approved,
        },
    )
    .await
}

/// The backend enforces the plan's opt-in: an app whose consent grants a
/// high-risk permission gets no consent call unless approved, whatever the
/// front end sent — and the skip is a runbook item, not a failure.
#[tokio::test]
async fn high_risk_consent_is_granted_only_to_approved_apps() {
    let server = MockServer::start().await;
    mount_create(&server).await;
    mount_graph_sp(&server).await;
    mount_live_apps(&server).await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let backup = manifest(vec![
        consenting_app(SRC_A, "App A"),
        consenting_app(SRC_B, "App B"),
    ]);

    let (report, effects) = restore(
        &client,
        &backup,
        crate::state::CancelFlag::new().claim(),
        &[SRC_A],
    )
    .await;

    assert!(effects.created_any);
    assert_eq!(report.apps.len(), 2, "both apps restore: {report:?}");
    // Pass 3's first read is the app itself.
    assert_eq!(
        requests(&server, "GET", "/applications/obj-a").await.len(),
        1
    );
    assert!(
        requests(&server, "GET", "/applications/obj-b")
            .await
            .is_empty(),
        "an unapproved app must get no consent call"
    );
    // Re-read, matched what the plan showed, consented.
    assert!(consent_attempted(&server, "app-a").await);
    assert!(!consent_attempted(&server, "app-b").await);
    let skipped = report
        .manual_items
        .iter()
        .find(|m| m.display_name == "App B")
        .expect("the withheld consent is a runbook item");
    assert!(
        skipped.reason.contains("not approved in the plan")
            && skipped.reason.contains("Application.ReadWrite.All"),
        "{}",
        skipped.reason
    );
    assert!(!report.apps[1].consent_granted);
    assert!(!report.cancelled);
}

/// A cancel pressed during Pass 2 stops the run before Pass 3: no consent
/// is granted, and the report says it stopped.
#[tokio::test]
async fn a_cancel_between_passes_is_reported_and_skips_consent() {
    let server = MockServer::start().await;
    mount_create(&server).await;
    let flag = crate::state::CancelFlag::new();
    let cancel = flag.claim();
    // The app's only Pass-2 write: the operator cancels while it lands.
    Mock::given(method("PATCH"))
        .and(path("/applications/obj-a"))
        .respond_with(move |_: &Request| {
            flag.cancel();
            ResponseTemplate::new(204)
        })
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let backup = manifest(vec![consenting_app(SRC_A, "App A")]);

    let (report, _) = restore(&client, &backup, cancel, &[SRC_A]).await;

    assert!(report.cancelled);
    assert!(!report.session_expired, "a cancel is not a dead session");
    assert_eq!(report.apps.len(), 1, "Pass 2 finished the app");
    assert!(
        requests(&server, "GET", "/applications/obj-a")
            .await
            .is_empty(),
        "Pass 3 must not run after a cancel"
    );
    assert!(!report.apps[0].consent_granted);
    // Pass 2 finished it; the consent the backup asks for is what is missing.
    let warnings = &report.apps[0].warnings;
    assert!(report.apps[0].incomplete, "{warnings:?}");
    assert!(
        warnings
            .iter()
            .any(|w| w.starts_with("admin consent not re-granted"))
            && !warnings
                .iter()
                .any(|w| w.starts_with("stopped before finishing")),
        "{warnings:?}"
    );
}

/// Progress covers every pass: the total counts each app twice (create,
/// wire), each consenting app, each enterprise app and each managed identity,
/// and each pass ticks as it settles an item — the bar once sat at "2/2"
/// from the end of Pass 1 to the end of the run.
#[tokio::test]
async fn progress_advances_through_every_pass() {
    let server = MockServer::start().await;
    mount_create(&server).await;
    mount_graph_sp(&server).await;
    mount_live_apps(&server).await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let mut backup = manifest(vec![
        consenting_app(SRC_A, "App A"),
        AppRegistrationBackup {
            source_app_id: SRC_B.into(),
            display_name: "App B".into(),
            ..Default::default()
        },
    ]);
    backup.enterprise_apps = vec![EnterpriseAppBackup {
        source_app_id: SRC_B.into(),
        display_name: "Ent B".into(),
        ..Default::default()
    }];
    backup.managed_identities = vec![ManagedIdentityBackup {
        source_app_id: SRC_C.into(),
        display_name: "mi-one".into(),
        ..Default::default()
    }];
    let sink = crate::commands::test_support::Recorder::default();
    let approved: HashSet<RestoreApproval> = HashSet::from([app_approval(SRC_A)]);

    let (report, _) = run_restore(
        &client,
        &sink,
        never_cancelled(),
        RestoreRun {
            backup: &backup,
            tenant_id: "dst-tenant",
            cloud: CloudEnvironment::Commercial,
            operator_oid: Some("operator-oid"),
            approved: &approved,
        },
    )
    .await;
    assert!(!report.cancelled, "{report:?}");

    let ticks: Vec<crate::dto::bulk::BulkProgress> =
        sink.payloads(crate::dto::events::RESTORE_PROGRESS);
    // 2 apps × 2 + 1 consenting + 1 enterprise app + 1 managed identity.
    assert!(ticks.iter().all(|t| t.total == 7), "{ticks:?}");
    assert_eq!(ticks.first().map(|t| t.done), Some(0));
    assert_eq!(ticks.last().map(|t| t.done), Some(7));
    assert!(
        ticks.windows(2).all(|w| w[0].done <= w[1].done),
        "done never goes back: {ticks:?}"
    );
    let ticked = |name: &str, done: usize| {
        ticks
            .iter()
            .any(|t| t.done == done && t.current_app.as_deref() == Some(name))
    };
    assert!(
        ticked("App A", 1) && ticked("App B", 2),
        "Pass 1: {ticks:?}"
    );
    assert!(
        ticked("App A", 3) && ticked("App B", 4),
        "Pass 2: {ticks:?}"
    );
    assert!(ticked("App A", 5), "Pass 3: {ticks:?}");
    assert!(ticked("Ent B", 6), "Pass 4: {ticks:?}");
    assert!(ticked("mi-one", 7), "Pass 5: {ticks:?}");
}

/// Plain apps: no consent, credentials or owners, so nothing needs approval.
fn plain_apps(names: &[(&str, &str)]) -> TenantBackup {
    manifest(
        names
            .iter()
            .map(|(src, name)| AppRegistrationBackup {
                source_app_id: (*src).into(),
                display_name: (*name).into(),
                ..Default::default()
            })
            .collect(),
    )
}

/// The report entries of a run that stopped before wiring: one per app Pass 1
/// created, in order, each with its new ids and flagged unfinished.
fn assert_reported_unwired(report: &RestoreReport, tags: &[&str]) {
    assert_eq!(report.apps.len(), tags.len(), "{report:?}");
    for (app, tag) in report.apps.iter().zip(tags) {
        assert_eq!(app.new_app_id, format!("app-{tag}"));
        assert_eq!(app.new_object_id, format!("obj-{tag}"));
        assert!(app.incomplete, "{app:?}");
        assert!(
            app.warnings.iter().any(|w| w.starts_with("not wired")),
            "{:?}",
            app.warnings
        );
    }
}

/// A cancel during Pass 1 keeps every app it already created in the report,
/// with its new ids, flagged unfinished — the report is the operator's only
/// record of what exists. It once listed none of them ("Restored 0 apps").
#[tokio::test]
async fn a_cancel_during_pass_1_reports_every_created_app() {
    let server = MockServer::start().await;
    let flag = crate::state::CancelFlag::new();
    let cancel = flag.claim();
    // The operator cancels while App B is being created.
    mount_create_then(&server, move |name| {
        if name == "App B" {
            flag.cancel();
        }
    })
    .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let backup = plain_apps(&[(SRC_A, "App A"), (SRC_B, "App B"), (SRC_C, "App C")]);

    let (report, effects) = restore(&client, &backup, cancel, &[]).await;

    assert!(report.cancelled);
    assert!(!report.session_expired);
    assert!(effects.created_any);
    assert_reported_unwired(&report, &["a", "b"]);
    assert_eq!(
        requests(&server, "POST", "/applications").await.len(),
        2,
        "App C is never created after the cancel"
    );
    assert!(
        requests(&server, "PATCH", "/applications/obj-a")
            .await
            .is_empty(),
        "nothing is wired after a cancel"
    );
}

/// The same when the session dies during Pass 1: the apps it created are all
/// reported, unwired, with the run marked as stopped by the expired session.
#[tokio::test]
async fn a_dead_session_during_pass_1_reports_every_created_app() {
    use azapptoolkit_core::token::StaticTokenProvider;
    let server = MockServer::start().await;
    mount_create(&server).await;
    mount_fallback(&server).await;
    // Reads succeed; the third write (App C's create) finds the session dead.
    let client = GraphClient::with_base_url(
        "tenant-test",
        StaticTokenProvider::new("tok"),
        crate::commands::test_support::dies_after(2),
        azapptoolkit_core::cache::Cache::new(),
        server.uri(),
    );
    let backup = plain_apps(&[(SRC_A, "App A"), (SRC_B, "App B"), (SRC_C, "App C")]);

    let (report, _) = restore(&client, &backup, never_cancelled(), &[]).await;

    assert!(report.session_expired);
    assert_reported_unwired(&report, &["a", "b"]);
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert_eq!(report.failures[0].display_name, "App C");
}

/// A cancel inside an app's secret loop marks that app unfinished and says how
/// much was left — it once read as a finished app with fewer secrets.
#[tokio::test]
async fn a_cancel_inside_the_secret_loop_marks_the_app_incomplete() {
    let server = MockServer::start().await;
    let flag = crate::state::CancelFlag::new();
    let cancel = flag.claim();
    // The operator cancels while the first secret is issued.
    Mock::given(method("POST"))
        .and(path("/applications/new-obj/addPassword"))
        .respond_with(move |_: &Request| {
            flag.cancel();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keyId": "key-1",
                "displayName": "ci",
                "secretText": "s3cr3t"
            }))
        })
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let secret = |name: &str| CredentialMeta {
        display_name: Some(name.into()),
        ..Default::default()
    };
    let c = created(AppRegistrationBackup {
        display_name: "App A".into(),
        secrets: vec![secret("ci"), secret("deploy"), secret("ops")],
        ..Default::default()
    });

    let (out, _) = wire_application(
        &pass_ctx(&client, &SessionDead::new(), &HashMap::new()),
        &c,
        &BackupApps::default(),
        &mut PrincipalMemo::new(),
        &cancel,
        false,
    )
    .await;

    assert_eq!(out.regenerated_secrets.len(), 1, "the issued one is kept");
    assert!(out.incomplete);
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("stopped before finishing: 2 of 3 secrets not processed")),
        "{:?}",
        out.warnings
    );
    assert_eq!(
        requests(&server, "POST", "/applications/new-obj/addPassword")
            .await
            .len(),
        1
    );
}

/// A consent withheld because its API could not be read during the run says
/// so — the plan may never have asked about it, so "not approved in the plan"
/// would send the operator looking for a checkbox that was never shown.
#[tokio::test]
async fn a_failed_resource_read_at_run_time_withholds_consent_with_its_own_reason() {
    let server = MockServer::start().await;
    mount_create(&server).await;
    // Microsoft Graph's service principal cannot be read: User.Read, low-risk
    // in the plan, is unidentified now.
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", format!("appId eq '{GRAPH}'")))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let mut app = consenting_app(SRC_A, "App A");
    app.required_resource_access[0].resource_access =
        vec![azapptoolkit_core::models::ResourceAccess {
            id: USER_READ_SCOPE.into(),
            r#type: "Scope".into(),
        }];
    // An application permission needs approval whatever it is, so the plan
    // asked about App B: its reason stays "not approved in the plan".
    let backup = manifest(vec![app, consenting_app(SRC_B, "App B")]);

    let (report, _) = restore(&client, &backup, never_cancelled(), &[]).await;

    assert!(!consent_attempted(&server, "app-a").await);
    let item = report
        .manual_items
        .iter()
        .find(|m| m.display_name == "App A")
        .expect("the withheld consent is a runbook item");
    assert!(
        item.reason
            .contains("could not be identified when the restore ran")
            && !item.reason.contains("not approved in the plan"),
        "{}",
        item.reason
    );
    assert!(
        report.apps[0]
            .warnings
            .iter()
            .any(|w| w.contains("could not be identified when the restore ran")),
        "{:?}",
        report.apps[0].warnings
    );
    let asked = report
        .manual_items
        .iter()
        .find(|m| m.display_name == "App B")
        .expect("App B's withheld consent is a runbook item");
    assert!(
        asked.reason.contains("not approved in the plan")
            && !asked.reason.contains("could not be identified"),
        "{}",
        asked.reason
    );
    assert!(!report.session_expired, "a 403 is not a dead session");
}

/// A cancel during Pass 3 leaves each later consenting app without the
/// consent the backup asks for: those are marked unfinished, never reported
/// as finished apps that simply have none.
#[tokio::test]
async fn a_cancel_during_pass_3_marks_the_unreached_consent_unfinished() {
    let server = MockServer::start().await;
    mount_create(&server).await;
    mount_graph_sp(&server).await;
    let flag = crate::state::CancelFlag::new();
    let cancel = flag.claim();
    // The operator cancels while Pass 3 re-reads App A, the first consent.
    Mock::given(method("GET"))
        .and(path("/applications/obj-a"))
        .respond_with(move |_: &Request| {
            flag.cancel();
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "obj-a",
                "appId": "app-a",
                "displayName": "App A",
                "requiredResourceAccess": [{
                    "resourceAppId": GRAPH,
                    "resourceAccess": [{ "id": APP_RW_ROLE, "type": "Role" }]
                }]
            }))
        })
        .with_priority(1)
        .mount(&server)
        .await;
    mount_live_apps(&server).await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let backup = manifest(vec![
        consenting_app(SRC_A, "App A"),
        consenting_app(SRC_B, "App B"),
    ]);

    let (report, _) = restore(&client, &backup, cancel, &[SRC_A, SRC_B]).await;

    assert!(report.cancelled);
    assert!(!consent_attempted(&server, "app-b").await);
    let b = &report.apps[1];
    assert!(b.incomplete && !b.consent_granted, "{b:?}");
    assert!(
        b.warnings
            .iter()
            .any(|w| w.starts_with("admin consent not re-granted")),
        "{:?}",
        b.warnings
    );
    assert!(
        !report.apps[0]
            .warnings
            .iter()
            .any(|w| w.starts_with("admin consent not re-granted")),
        "App A was reached: {:?}",
        report.apps[0].warnings
    );
}

/// A session that dies in a step that is not a loop — here the
/// authentication PATCH — leaves the app part-wired, and says so.
#[tokio::test]
async fn a_session_that_dies_in_a_patch_marks_the_app_incomplete() {
    use azapptoolkit_core::token::StaticTokenProvider;
    let server = MockServer::start().await;
    mount_fallback(&server).await;
    // Reads succeed; the first write finds the session dead.
    let client = GraphClient::with_base_url(
        "tenant-test",
        StaticTokenProvider::new("tok"),
        crate::commands::test_support::dies_after(0),
        azapptoolkit_core::cache::Cache::new(),
        server.uri(),
    );
    let session = SessionDead::new();
    let c = created(AppRegistrationBackup {
        display_name: "App A".into(),
        web_redirect_uris: vec!["https://good.contoso.com/cb".into()],
        ..Default::default()
    });

    let (out, _) = wire_application(
        &pass_ctx(&client, &session, &HashMap::new()),
        &c,
        &BackupApps::default(),
        &mut PrincipalMemo::new(),
        &never_cancelled(),
        false,
    )
    .await;

    assert!(session.is_dead());
    assert!(out.incomplete, "{out:?}");
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("the sign-in session ended while this app was being wired")),
        "{:?}",
        out.warnings
    );
}

/// The plan names what the file grants and which items need approval:
/// consent covering any application permission (even an unrisky one, or
/// one on an API the backup recreates), a broad or unidentified delegated
/// one, an accepted federated credential, a group membership, any
/// managed-identity role — and any consent at all beside owners, reply
/// URLs or the public-client flag. Low-risk delegated consent alone, a
/// refused credential, foreign pre-authorized clients, role assignees, and
/// owners or reply URLs without consent are shown only.
#[tokio::test]
async fn the_plan_lists_privileged_grants_and_what_needs_approval() {
    let server = MockServer::start().await;
    mount_graph_sp(&server).await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let consent_to = |src: &str, name: &str, resource: &str, id: &str, kind: &str| {
        let mut app = consenting_app(src, name);
        app.required_resource_access[0].resource_app_id = resource.into();
        app.required_resource_access[0].resource_access[0].id = id.into();
        app.required_resource_access[0].resource_access[0].r#type = kind.into();
        app
    };
    const SRC_C: &str = "cccccccc-0000-0000-0000-000000000003";
    const SRC_D: &str = "dddddddd-0000-0000-0000-000000000004";
    const SRC_E: &str = "eeeeeeee-0000-0000-0000-000000000005";
    const SRC_F: &str = "ffffffff-0000-0000-0000-000000000006";
    const SRC_G: &str = "99999999-0000-0000-0000-000000000007";

    // Delegated User.Read only, a refused credential, a foreign client.
    let mut low = consent_to(SRC_A, "App A", GRAPH, USER_READ_SCOPE, "Scope");
    low.pre_authorized_applications = vec![
        azapptoolkit_core::models::PreAuthorizedApplication {
            app_id: "foreign-client".into(),
            ..Default::default()
        },
        azapptoolkit_core::models::PreAuthorizedApplication {
            app_id: SRC_B.into(),
            ..Default::default()
        },
    ];
    low.federated_credentials = vec![FederatedIdentityCredential {
        name: "planted".into(),
        issuer: "http://attacker.example".into(),
        subject: Some("sub".into()),
        ..Default::default()
    }];
    let unknown = consent_to(SRC_B, "App B", "nowhere", APP_RW_ROLE, "Role");
    let high = consenting_app(SRC_C, "App C");
    let restored_api = consent_to(SRC_D, "App D", SRC_A, "custom-role", "Role");
    // No SP in the backup: Pass 3 or an adopted app can still supply one,
    // so its group memberships are shown and gated all the same.
    let grouped = AppRegistrationBackup {
        source_app_id: SRC_E.into(),
        display_name: "App E".into(),
        has_service_principal: false,
        ..Default::default()
    };
    // Owners but no consent: shown, approval-free (nothing routes tokens).
    let owners_only = AppRegistrationBackup {
        source_app_id: SRC_F.into(),
        display_name: "App F".into(),
        owners: vec![PrincipalRef {
            user_principal_name: Some("bob@contoso.com".into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    // Low-risk consent AND a reply URL the file chose: consented tokens
    // would be delivered where the file says, so approval.
    let mut routed = consent_to(SRC_G, "App G", GRAPH, USER_READ_SCOPE, "Scope");
    routed.spa_redirect_uris = vec!["https://portal.example/cb".into()];
    routed.is_fallback_public_client = true;
    let mut backup = manifest(vec![
        low,
        unknown,
        high,
        restored_api,
        grouped,
        owners_only,
        routed,
    ]);
    backup.enterprise_apps = vec![EnterpriseAppBackup {
        source_app_id: SRC_E.into(),
        display_name: "App E".into(),
        group_memberships: vec![named("Global Admins", Some("#microsoft.graph.group"))],
        app_role_assignees: vec![crate::dto::backup::AppRoleAssigneeRef {
            principal: named("Ops", Some("Group")),
            app_role_id: "x".into(),
            app_role_value: Some("Reader".into()),
        }],
        ..Default::default()
    }];
    backup.managed_identities = vec![ManagedIdentityBackup {
        source_app_id: "mi-app".into(),
        display_name: "mi-one".into(),
        held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
            resource_app_id: GRAPH.into(),
            app_role_id: "r".into(),
            app_role_value: Some("User.Read.All".into()),
            ..Default::default()
        }],
        ..Default::default()
    }];
    let session = SessionDead::new();

    let items = privileged_restore_items(&client, &backup, &session).await;

    assert_eq!(items.len(), 8, "{items:#?}");
    let [
        low,
        unknown,
        high,
        restored_api,
        grouped,
        owners_only,
        routed,
        mi,
    ] = &items[..]
    else {
        unreachable!()
    };
    // Shown, but nothing in it needs approval: low-risk consent alone, a
    // refused credential and a foreign client.
    assert_eq!(low.delegated_scopes[0].value.as_deref(), Some("User.Read"));
    assert_eq!(low.delegated_scopes[0].risk, PermissionRisk::Low);
    assert_eq!(low.external_pre_authorized_clients, ["foreign-client"]);
    assert!(low.federated_credentials[0].rejected.is_some());
    assert!(low.owners.is_empty());
    assert!(!low.requires_approval, "{low:#?}");
    // Owners alone are shown and approval-free.
    assert_eq!(owners_only.owners, ["bob@contoso.com"]);
    assert!(!owners_only.admin_consent);
    assert!(!owners_only.requires_approval, "{owners_only:#?}");
    // Reply URLs and the public-client flag are shown; with consent, gated.
    assert_eq!(routed.reply_urls, ["https://portal.example/cb"]);
    assert!(routed.public_client);
    assert!(routed.requires_approval, "{routed:#?}");
    // Nobody can name it.
    assert_eq!(unknown.app_roles[0].risk, PermissionRisk::Unknown);
    assert!(unknown.requires_approval);
    // Resolved live and ranked by `core::audit`.
    assert_eq!(
        high.app_roles[0].value.as_deref(),
        Some("Application.ReadWrite.All")
    );
    assert_eq!(high.app_roles[0].risk, PermissionRisk::High);
    assert!(high.requires_approval);
    // Any application permission needs approval, even on an API the backup
    // recreates (not knowable yet, so not "unknown").
    assert!(restored_api.app_roles[0].restored_api);
    assert_eq!(restored_api.app_roles[0].risk, PermissionRisk::Low);
    assert!(restored_api.requires_approval);
    // The file chooses the group: approval. Assignees are shown only.
    assert_eq!(grouped.group_memberships, ["Global Admins"]);
    assert_eq!(grouped.app_role_assignees, ["Ops (Reader)"]);
    assert!(grouped.requires_approval);
    // Every managed-identity role needs approval, whatever its risk.
    assert_eq!(mi.kind, PrivilegedKind::ManagedIdentity);
    assert!(mi.requires_approval);
    assert!(!session.is_dead());
}

/// The bypass this gate exists for: an adopted app — pre-planted with the
/// restore tag, a name and owners the file vouches for — already declares
/// a high-risk permission, and the manifest declares none, so the plan
/// shows no consent and asks for no approval. Consent must not grant what
/// the live app declares.
#[tokio::test]
async fn consent_never_grants_permissions_the_plan_did_not_show() {
    let server = MockServer::start().await;
    mount_tagged_hit(
        &server,
        serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "obj-1",
            "appId": "app-1",
            "displayName": "App A",
            "requiredResourceAccess": [{
                "resourceAppId": GRAPH,
                "resourceAccess": [{ "id": APP_RW_ROLE, "type": "Role" }]
            }]
        })))
        .mount(&server)
        .await;
    mount_graph_sp(&server).await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let backup = manifest(vec![AppRegistrationBackup {
        source_app_id: SRC_A.into(),
        display_name: "App A".into(),
        admin_consent_granted: true,
        ..Default::default()
    }]);
    assert!(
        privileged_restore_items(&client, &backup, &SessionDead::new())
            .await
            .is_empty(),
        "the plan shows nothing to approve"
    );

    let (report, _) = restore(
        &client,
        &backup,
        crate::state::CancelFlag::new().claim(),
        &[],
    )
    .await;

    assert!(report.apps[0].adopted, "{report:?}");
    assert!(
        !consent_attempted(&server, "app-1").await,
        "no consent for a live permission list the plan never showed"
    );
    assert!(!report.apps[0].consent_granted);
    assert!(
        report
            .manual_items
            .iter()
            .any(|m| m.reason.contains("don't match the backup")),
        "{:?}",
        report.manual_items
    );
}

/// A pre-authorized client the backup owns but Pass 1 failed to create has
/// no appId in this tenant. The restored API never names it by its source
/// appId — that would pre-authorize the source tenant's app, which the plan
/// (listing only clients from outside the backup) never showed — while a
/// foreign client the plan did show is written as listed. Clients are
/// matched ignoring case (a backup app listed as `CCCC…` is still that app,
/// and is remapped), a client listed twice is reported once, and an API
/// whose every client was left out is written an empty list, so the
/// full-replace PATCH clears what an earlier run wrote.
#[tokio::test]
async fn a_client_that_failed_to_restore_is_not_pre_authorized_by_its_source_appid() {
    const SRC_C: &str = "cccccccc-0000-0000-0000-000000000003";
    const SRC_D: &str = "dddddddd-0000-0000-0000-000000000004";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/applications"))
        .and(wiremock::matchers::body_partial_json(
            serde_json::json!({ "displayName": "App B" }),
        ))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": { "code": "Request_BadRequest", "message": "refused" }
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    mount_create(&server).await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let pre_authorized = |app_id: &str| azapptoolkit_core::models::PreAuthorizedApplication {
        app_id: app_id.into(),
        delegated_permission_ids: vec!["scope-1".into()],
    };
    let api = AppRegistrationBackup {
        source_app_id: SRC_A.into(),
        display_name: "App A".into(),
        pre_authorized_applications: vec![
            pre_authorized(&SRC_C.to_ascii_uppercase()),
            pre_authorized(SRC_B),
            pre_authorized(&SRC_B.to_ascii_uppercase()),
            pre_authorized("foreign-client"),
        ],
        ..Default::default()
    };
    let failed = AppRegistrationBackup {
        source_app_id: SRC_B.into(),
        display_name: "App B".into(),
        ..Default::default()
    };
    let restored = AppRegistrationBackup {
        source_app_id: SRC_C.into(),
        display_name: "App C".into(),
        ..Default::default()
    };
    // Every client it lists is left out.
    let emptied = AppRegistrationBackup {
        source_app_id: SRC_D.into(),
        display_name: "App D".into(),
        pre_authorized_applications: vec![pre_authorized(SRC_B)],
        ..Default::default()
    };
    let backup = manifest(vec![api, failed, restored, emptied]);

    let items = privileged_restore_items(&client, &backup, &SessionDead::new()).await;
    assert_eq!(
        items[0].external_pre_authorized_clients,
        ["foreign-client"],
        "the plan shows only the client from outside the backup, in any case"
    );

    let (report, _) = restore(
        &client,
        &backup,
        crate::state::CancelFlag::new().claim(),
        &[],
    )
    .await;

    assert_eq!(report.failures.len(), 1, "{report:?}");
    assert_eq!(report.failures[0].source_app_id, SRC_B);
    let server = &server;
    let written = |obj: &'static str| async move {
        requests(server, "PATCH", &format!("/applications/{obj}"))
            .await
            .iter()
            .filter_map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).ok())
            .filter_map(|b| b["api"]["preAuthorizedApplications"].as_array().cloned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        written("obj-a").await,
        [vec![
            serde_json::json!({ "appId": "app-c", "delegatedPermissionIds": ["scope-1"] }),
            serde_json::json!({ "appId": "foreign-client", "delegatedPermissionIds": ["scope-1"] }),
        ]],
        "the recreated client remapped, the foreign one as listed, nothing else"
    );
    assert_eq!(
        written("obj-d").await,
        [Vec::<serde_json::Value>::new()],
        "an emptied list is still written, so the PATCH replaces"
    );
    let app_a = report
        .apps
        .iter()
        .find(|a| a.display_name == "App A")
        .expect("App A restored");
    let left_out: Vec<&String> = app_a
        .warnings
        .iter()
        .filter(|w| w.contains("was NOT restored"))
        .collect();
    assert_eq!(
        left_out.len(),
        1,
        "listed twice, reported once: {left_out:?}"
    );
    assert!(
        left_out[0].contains("'App B'") && left_out[0].contains(SRC_B),
        "{left_out:?}"
    );
}

/// Every value from the file the plan shows is an excerpt — the source
/// tenant id, a consented permission's resource and permission ids, a
/// managed identity's role fields — and a federated credential's refusal is
/// bounded too: `core::federation` checks length before it quotes a value,
/// and the plan caps the (escaped) refusal at `MAX_REPORT_VALUE_CHARS`.
#[tokio::test]
async fn the_plan_echoes_file_values_bounded() {
    let server = MockServer::start().await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let long = "x".repeat(10_000);
    let mut app = consenting_app(SRC_A, "App A");
    app.required_resource_access[0].resource_app_id = long.clone();
    app.required_resource_access[0].resource_access[0].id = long.clone();
    app.federated_credentials = vec![FederatedIdentityCredential {
        name: "gh-main".into(),
        issuer: format!("https://issuer.example/{long} "),
        subject: Some("sub".into()),
        ..Default::default()
    }];
    let mut backup = manifest(vec![app]);
    backup.source_tenant_id = long.clone();
    backup.managed_identities = vec![ManagedIdentityBackup {
        source_app_id: SRC_B.into(),
        display_name: "mi-one".into(),
        held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
            resource_app_id: long.clone(),
            resource_display_name: Some(long.clone()),
            app_role_id: long.clone(),
            app_role_value: Some(long.clone()),
        }],
        ..Default::default()
    }];

    let plan = build_restore_plan(&backup, "dst-tenant".into(), CloudEnvironment::Commercial);
    assert_eq!(plan.source_tenant_id, excerpt(&long));
    assert!(plan.tenant_changed, "compared on the whole id");

    let items = privileged_restore_items(&client, &backup, &SessionDead::new()).await;
    let [app, mi] = &items[..] else {
        panic!("{items:#?}")
    };
    assert_eq!(app.app_roles[0].resource_app_id, excerpt(&long));
    assert_eq!(app.app_roles[0].permission_id, excerpt(&long));
    let rejected = app.federated_credentials[0]
        .rejected
        .as_deref()
        .expect("an oversized issuer is refused");
    assert!(
        rejected.contains("longer than 600 characters") && rejected.chars().count() < 100,
        "{} characters",
        rejected.len()
    );
    let role = &mi.app_roles[0];
    for field in [
        role.resource_app_id.as_str(),
        role.permission_id.as_str(),
        role.resource_display_name.as_deref().unwrap_or_default(),
        role.value.as_deref().unwrap_or_default(),
    ] {
        assert_eq!(field, excerpt(&long));
    }
}

/// A hostile manifest's multi-megabyte strings never reach the report (the
/// DR view's text and the saved file) whole: every name and label is cut
/// at `MAX_REPORT_VALUE_CHARS`, every warning and runbook reason at
/// `MAX_REPORT_LINE_CHARS`, the progress events' app names too — and the
/// show-once secret value is left exactly as Graph minted it.
#[tokio::test]
async fn a_hostile_manifest_cannot_make_the_report_carry_its_strings_whole() {
    let huge = "x".repeat(100_000);
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/applications"))
        .and(wiremock::matchers::body_partial_json(
            serde_json::json!({ "displayName": format!("{huge} B") }),
        ))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": { "code": "Request_BadRequest", "message": "refused" }
        })))
        .with_priority(1)
        .mount(&server)
        .await;
    mount_create(&server).await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/applications/obj-[a-z]+/addPassword$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keyId": "key-1",
            "secretText": "s3cr3t-value",
            "endDateTime": "2027-01-01T00:00:00Z"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(
            r"^/applications/obj-[a-z]+/federatedIdentityCredentials$",
        ))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "fic-1",
            "name": "gh-main",
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": "repo:contoso/app:ref:refs/heads/main",
            "audiences": ["api://AzureADTokenExchange"]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "appId eq 'app-a'"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-a", "appId": "app-a", "displayName": "App A" }]
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param(
            "$filter",
            "servicePrincipalType eq 'ManagedIdentity'",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "mi-sp", "appId": "mi-app", "displayName": huge.clone() }]
        })))
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    // Looked up by nothing: a type the restore cannot search by name.
    let unsearchable = PrincipalRef {
        display_name: Some(huge.clone()),
        principal_type: Some("ServicePrincipal".into()),
        ..Default::default()
    };
    let valid_fic = |name: &str| FederatedIdentityCredential {
        name: name.into(),
        issuer: "https://token.actions.githubusercontent.com".into(),
        subject: Some("repo:contoso/app:ref:refs/heads/main".into()),
        ..Default::default()
    };
    let hostile_fic = FederatedIdentityCredential {
        name: huge.clone(),
        issuer: huge.clone(),
        subject: Some(huge.clone()),
        ..Default::default()
    };
    let named_secret = CredentialMeta {
        display_name: Some(huge.clone()),
        ..Default::default()
    };
    // Approved: every value goes through its writer or validator.
    let approved = AppRegistrationBackup {
        source_app_id: SRC_A.into(),
        display_name: format!("{huge} A"),
        web_redirect_uris: vec![format!("https://app.example/{huge}")],
        logout_url: Some(format!("https://app.example/{huge}")),
        federated_credentials: vec![
            valid_fic("gh-main"),
            hostile_fic.clone(),
            FederatedIdentityCredential {
                subject: None,
                ..hostile_fic.clone()
            },
        ],
        owners: vec![unsearchable.clone()],
        secrets: vec![named_secret.clone()],
        certificates: vec![named_secret],
        ..Default::default()
    };
    // Pass 1 refuses it.
    let failed = AppRegistrationBackup {
        source_app_id: SRC_B.into(),
        display_name: format!("{huge} B"),
        ..Default::default()
    };
    // Not approved: its credentials and owners are listed, never validated.
    let withheld = AppRegistrationBackup {
        source_app_id: "cccccccc-0000-0000-0000-000000000003".into(),
        display_name: format!("{huge} C"),
        federated_credentials: vec![valid_fic("gh-c"), hostile_fic],
        owners: vec![PrincipalRef {
            user_principal_name: Some(huge.clone()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut backup = manifest(vec![approved, failed, withheld]);
    backup.enterprise_apps = vec![EnterpriseAppBackup {
        source_app_id: SRC_A.into(),
        display_name: huge.clone(),
        app_role_assignees: vec![crate::dto::backup::AppRoleAssigneeRef {
            principal: unsearchable.clone(),
            app_role_id: DEFAULT_ACCESS_ROLE.into(),
            app_role_value: None,
        }],
        group_memberships: vec![unsearchable],
        ..Default::default()
    }];
    backup.managed_identities = vec![ManagedIdentityBackup {
        source_app_id: "dddddddd-0000-0000-0000-000000000004".into(),
        display_name: huge.clone(),
        held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
            resource_app_id: GRAPH.into(),
            app_role_id: "r".into(),
            app_role_value: Some(huge.clone()),
            ..Default::default()
        }],
        ..Default::default()
    }];
    let recorder = crate::commands::test_support::Recorder::default();
    let approvals = HashSet::from([app_approval(SRC_A)]);

    let (report, _) = run_restore(
        &client,
        &recorder,
        crate::state::CancelFlag::new().claim(),
        RestoreRun {
            backup: &backup,
            tenant_id: "dst-tenant",
            cloud: CloudEnvironment::Commercial,
            operator_oid: Some("operator-oid"),
            approved: &approvals,
        },
    )
    .await;

    // The run reached every surface that echoes the file.
    assert_eq!(report.apps.len(), 2, "{:?}", report.failures);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.enterprise_apps.len(), 1);
    assert_eq!(report.managed_identities.len(), 1);
    let secret = &report.apps[0].regenerated_secrets[0];
    assert_eq!(secret.secret_value, "s3cr3t-value", "never cut");
    assert_eq!(secret.key_id, "key-1");

    let chars = |s: &str| s.chars().count();
    let value_cap = MAX_REPORT_VALUE_CHARS + 1; // the ellipsis
    let mut values: Vec<&str> = vec![&report.failures[0].display_name];
    for app in &report.apps {
        values.push(&app.display_name);
        values.extend(
            app.regenerated_secrets
                .iter()
                .map(|s| s.display_name.as_str()),
        );
        values.extend(
            app.certificates_needing_manual_upload
                .iter()
                .map(String::as_str),
        );
        values.extend(app.unresolved_owners.iter().map(String::as_str));
    }
    let ent = &report.enterprise_apps[0];
    values.push(&ent.display_name);
    values.extend(ent.unresolved_principals.iter().map(String::as_str));
    values.push(&report.managed_identities[0].display_name);
    values.extend(report.manual_items.iter().map(|m| m.display_name.as_str()));
    assert!(values.len() > 10, "{values:?}");
    for v in &values {
        assert!(chars(v) <= value_cap, "a {}-character value", chars(v));
    }
    assert_eq!(chars(&report.apps[0].display_name), value_cap);
    assert!(report.apps[0].display_name.ends_with('…'));

    // No string anywhere in the report — warnings and runbook reasons
    // included — is longer than a composed line's cap, and the huge
    // values did reach some of them (so the cap is what bounded them).
    fn strings<'a>(v: &'a serde_json::Value, out: &mut Vec<&'a str>) {
        match v {
            serde_json::Value::String(s) => out.push(s),
            serde_json::Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
            serde_json::Value::Object(o) => o.values().for_each(|v| strings(v, out)),
            _ => {}
        }
    }
    let json = serde_json::to_value(&report).expect("the report serializes");
    let mut all = Vec::new();
    strings(&json, &mut all);
    for s in &all {
        assert!(
            chars(s) <= MAX_REPORT_LINE_CHARS + 1,
            "a {}-character string",
            chars(s)
        );
    }
    let cut_lines = all
        .iter()
        .filter(|s| chars(s) == MAX_REPORT_LINE_CHARS + 1)
        .count();
    assert!(cut_lines >= 5, "{cut_lines} lines were cut");

    let progress: Vec<BulkProgress> = recorder.payloads(crate::dto::events::RESTORE_PROGRESS);
    assert!(!progress.is_empty());
    for p in &progress {
        let name = p.current_app.as_deref().unwrap_or_default();
        assert!(chars(name) <= value_cap, "a {}-character name", chars(name));
    }
}

/// An app not approved in the plan is created and wired, but gets no
/// federated credential and no owner from the file.
#[tokio::test]
async fn a_withheld_app_gets_no_federated_credential_or_owner() {
    let server = MockServer::start().await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let c = created(AppRegistrationBackup {
        display_name: "App A".into(),
        federated_credentials: vec![FederatedIdentityCredential {
            name: "gh-main".into(),
            issuer: "https://token.actions.githubusercontent.com".into(),
            subject: Some("repo:contoso/app:ref:refs/heads/main".into()),
            ..Default::default()
        }],
        owners: vec![PrincipalRef {
            user_principal_name: Some("alice@contoso.com".into()),
            ..Default::default()
        }],
        secrets: vec![CredentialMeta::default()],
        ..Default::default()
    });

    let (_, manual) = wire_with(&client, &c, true).await;

    const FICS: &str = "/applications/new-obj/federatedIdentityCredentials";
    assert!(requests(&server, "POST", FICS).await.is_empty());
    assert!(
        requests(&server, "POST", "/applications/new-obj/owners/$ref")
            .await
            .is_empty()
    );
    assert!(
        requests(&server, "GET", "/users").await.is_empty(),
        "a withheld owner is not even looked up"
    );
    // Structure still restores: the secret is regenerated.
    assert_eq!(
        requests(&server, "POST", "/applications/new-obj/addPassword")
            .await
            .len(),
        1
    );
    assert_eq!(manual.len(), 2, "{manual:?}");
    assert!(
        manual
            .iter()
            .all(|m| m.reason.contains("not approved in the plan"))
    );
    assert!(
        manual[0]
            .reason
            .contains("token.actions.githubusercontent.com")
    );
    assert!(manual[1].reason.contains("alice@contoso.com"));

    // Approved, the credential is created.
    wire_with(&client, &c, false).await;
    assert_eq!(requests(&server, "POST", FICS).await.len(), 1);
}

/// A withheld app's service principal joins no group the file names.
#[tokio::test]
async fn a_withheld_app_joins_no_group() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-new", "appId": "new-a", "displayName": "Ent A" }]
        })))
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false)
        .with_group_member_token(azapptoolkit_core::token::StaticTokenProvider::new("tok"));
    let mut report = RestoreReport::default();
    let ent = EnterpriseAppBackup {
        display_name: "Ent A".into(),
        source_app_id: "src-a".into(),
        group_memberships: vec![named("Global Admins", Some("#microsoft.graph.group"))],
        ..Default::default()
    };
    let remap = HashMap::from([("src-a".to_string(), "new-a".to_string())]);

    restore_enterprise_app(
        &pass_ctx(&client, &SessionDead::new(), &remap),
        &ent,
        true,
        &mut report,
        &mut PrincipalMemo::new(),
        &never_cancelled(),
    )
    .await;

    assert!(requests(&server, "GET", "/groups").await.is_empty());
    let posts = server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .count();
    assert_eq!(posts, 0, "no membership is added");
    assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
    assert!(report.manual_items[0].reason.contains("Global Admins"));
    assert_eq!(report.enterprise_apps.len(), 1, "the rest still applies");
}

/// The run, not just the plan: an unapproved app's service principal joins
/// no group even when the backup says it had no SP — whether its SP came
/// from somewhere else at restore time (created, or already on an adopted
/// app). Approved, it joins.
#[tokio::test]
async fn pass_4_adds_no_group_membership_without_approval() {
    for adopted in [false, true] {
        let server = MockServer::start().await;
        if adopted {
            mount_tagged_hit(&server, serde_json::json!([{ "id": "operator-oid" }])).await;
        } else {
            mount_create(&server).await;
        }
        // Whichever way, a service principal exists when Pass 4 looks.
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "sp-x", "appId": "whatever", "displayName": "App A" }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "g-admins", "displayName": "Global Admins" }]
            })))
            .mount(&server)
            .await;
        mount_fallback(&server).await;
        // Group writes ride their own token; without one nothing is sent and
        // the approved run below could not tell "withheld" from "failed".
        let client = graph_over(&server, false)
            .with_group_member_token(azapptoolkit_core::token::StaticTokenProvider::new("tok"));
        let mut backup = manifest(vec![AppRegistrationBackup {
            source_app_id: SRC_A.into(),
            display_name: "App A".into(),
            has_service_principal: false,
            ..Default::default()
        }]);
        backup.enterprise_apps = vec![EnterpriseAppBackup {
            source_app_id: SRC_A.into(),
            display_name: "App A".into(),
            group_memberships: vec![named("Global Admins", Some("#microsoft.graph.group"))],
            ..Default::default()
        }];
        let items = privileged_restore_items(&client, &backup, &SessionDead::new()).await;
        assert!(items[0].requires_approval, "the plan shows and gates it");

        let (report, _) = restore(
            &client,
            &backup,
            crate::state::CancelFlag::new().claim(),
            &[],
        )
        .await;
        assert_eq!(report.apps.len(), 1, "adopted={adopted}: {report:?}");
        assert!(
            requests(&server, "POST", "/groups/g-admins/members/$ref")
                .await
                .is_empty(),
            "adopted={adopted}: an unapproved app joins no group"
        );
        assert!(
            report
                .manual_items
                .iter()
                .any(|m| m.reason.contains("Group memberships not added")),
            "adopted={adopted}: {:?}",
            report.manual_items
        );

        restore(
            &client,
            &backup,
            crate::state::CancelFlag::new().claim(),
            &[SRC_A],
        )
        .await;
        assert_eq!(
            requests(&server, "POST", "/groups/g-admins/members/$ref")
                .await
                .len(),
            1,
            "adopted={adopted}: approved, it joins"
        );
    }
}

/// Graph's `eq` ignores case, so "Ops" and "OPS" are two principals —
/// ambiguous, not one resolved by a stricter client-side comparison.
#[tokio::test]
async fn names_differing_only_in_case_are_ambiguous() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/groups"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "g1", "displayName": "Ops" },
                { "id": "g2", "displayName": "OPS" }
            ]
        })))
        .mount(&server)
        .await;
    let client = graph_over(&server, false);
    assert_eq!(
        resolve_principal_uncached(&client, &named("Ops", Some("Group")), &SessionDead::new())
            .await,
        Err(Unresolved::Ambiguous(2))
    );
}

/// Managed-identity source ids are approval keys, so they are held to the
/// app-registration rule: GUIDs, unrepeated.
#[test]
fn managed_identity_source_ids_must_be_unique_guids() {
    const ID: &str = "33333333-3333-3333-3333-333333333333";
    let mut backup = manifest_with_ids(&[]);
    backup.managed_identities = [ID, ID, ""]
        .map(|id| ManagedIdentityBackup {
            source_app_id: id.into(),
            display_name: "mi".into(),
            ..Default::default()
        })
        .to_vec();
    let problems = manifest_problems(&backup);
    assert_eq!(
        problems,
        [
            "managed identity 'mi' has no source appId".to_string(),
            format!("managed identity source appId {ID} appears 2 times"),
        ]
    );
    assert!(validate_manifest(&backup).is_err());
}
fn named(name: &str, kind: Option<&str>) -> PrincipalRef {
    PrincipalRef {
        display_name: Some(name.into()),
        principal_type: kind.map(Into::into),
        ..Default::default()
    }
}

/// With no recorded type, a name matching a group AND a user is ambiguous,
/// never the first one found.
#[tokio::test]
async fn an_ambiguous_principal_is_left_unresolved() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/groups"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "value": [{ "id": "g1", "displayName": "Ops" }] }),
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "u1", "displayName": "Ops" },
                { "id": "u2", "displayName": "Ops team" }
            ]
        })))
        .mount(&server)
        .await;
    let client = graph_over(&server, false);

    assert_eq!(
        resolve_principal_uncached(&client, &named("Ops", None), &SessionDead::new()).await,
        Err(Unresolved::Ambiguous(2))
    );
    // A recorded type searches only its own collection.
    assert_eq!(
        resolve_principal_uncached(
            &client,
            &named("Ops", Some("#microsoft.graph.group")),
            &SessionDead::new()
        )
        .await,
        Ok("g1".to_string())
    );
    assert_eq!(
        resolve_principal_uncached(&client, &named("Ops", Some("User")), &SessionDead::new()).await,
        Ok("u1".to_string())
    );
    // A service principal is never matched to a same-named user or group.
    assert_eq!(
        resolve_principal_uncached(
            &client,
            &named("Ops", Some("ServicePrincipal")),
            &SessionDead::new()
        )
        .await,
        Err(Unresolved::UnsupportedType("ServicePrincipal".into()))
    );
}

/// A failed group search is not an absent group: the principal stays
/// unresolved, and no user search runs in its place.
#[tokio::test]
async fn a_failed_group_search_never_falls_back_to_users() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/groups"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);

    for kind in [Some("#microsoft.graph.group"), None] {
        assert_eq!(
            resolve_principal_uncached(&client, &named("Ops", kind), &SessionDead::new()).await,
            Err(Unresolved::LookupFailed),
            "{kind:?}"
        );
    }
    assert!(
        requests(&server, "GET", "/users").await.is_empty(),
        "a group-search error must not fall back to a user search"
    );
}

/// Two destination identities under one name: neither is re-bound, and
/// the operator is told why.
#[tokio::test]
async fn duplicate_destination_mi_names_become_a_manual_item() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "sp-1", "appId": "a1", "displayName": "mi-one" },
                { "id": "sp-2", "appId": "a2", "displayName": "MI-One" }
            ]
        })))
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let mut report = RestoreReport::default();
    let mis = vec![ManagedIdentityBackup {
        display_name: "mi-one".into(),
        held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
            resource_app_id: GRAPH.into(),
            app_role_id: "r".into(),
            app_role_value: Some("User.Read.All".into()),
            ..Default::default()
        }],
        ..Default::default()
    }];

    rebind_mis(
        &client,
        &mis,
        &HashSet::new(),
        &mut report,
        &SessionDead::new(),
        &never_cancelled(),
    )
    .await;

    assert!(report.managed_identities.is_empty(), "nothing re-bound");
    assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
    assert!(
        report.manual_items[0]
            .reason
            .contains("2 managed identities")
            && report.manual_items[0].reason.contains("sp-1, sp-2"),
        "{}",
        report.manual_items[0].reason
    );
    let posts = server
        .received_requests()
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.method.as_str() == "POST")
        .count();
    assert_eq!(posts, 0, "no role is granted to either identity");
}

/// Every managed-identity app role needs approval: unapproved, none is
/// POSTed and they are one runbook item; approved, they re-bind.
#[tokio::test]
async fn an_unapproved_mi_gets_no_app_role() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param(
            "$filter",
            "servicePrincipalType eq 'ManagedIdentity'",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-1", "appId": "a1", "displayName": "mi-one" }]
        })))
        .mount(&server)
        .await;
    mount_graph_sp(&server).await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let mis = vec![ManagedIdentityBackup {
        source_app_id: SRC_A.into(),
        display_name: "mi-one".into(),
        held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
            resource_app_id: GRAPH.into(),
            app_role_id: "r".into(),
            app_role_value: Some("Mail.Send".into()),
            ..Default::default()
        }],
        ..Default::default()
    }];
    const GRANTS: &str = "/servicePrincipals/sp-1/appRoleAssignments";

    // An APP approval with the same id does not approve the identity.
    let app_only = HashSet::from([app_approval(SRC_A)]);
    let mut report = RestoreReport::default();
    rebind_mis(
        &client,
        &mis,
        &app_only,
        &mut report,
        &SessionDead::new(),
        &never_cancelled(),
    )
    .await;
    assert!(
        requests(&server, "POST", GRANTS).await.is_empty(),
        "Mail.Send must never be POSTed"
    );
    let withheld = report
        .manual_items
        .iter()
        .find(|m| m.reason.contains("not approved in the plan"))
        .expect("the withheld roles are a runbook item");
    assert!(withheld.reason.contains("Mail.Send"), "{}", withheld.reason);

    let approved = HashSet::from([RestoreApproval {
        kind: PrivilegedKind::ManagedIdentity,
        source_app_id: SRC_A.into(),
    }]);
    let mut report = RestoreReport::default();
    rebind_mis(
        &client,
        &mis,
        &approved,
        &mut report,
        &SessionDead::new(),
        &never_cancelled(),
    )
    .await;
    let posted = requests(&server, "POST", GRANTS).await;
    assert_eq!(posted.len(), 1);
    assert!(
        String::from_utf8_lossy(&posted[0].body).contains(MAIL_SEND_ROLE),
        "approved, the role re-binds"
    );
}

/// Credentials are the standing access the owner check cannot see. A
/// restore never uploads a certificate and issues secrets only under the
/// manifest's names, so either on a hit means someone else put it there.
#[test]
fn a_hit_holding_credentials_the_manifest_does_not_name_is_refused() {
    use azapptoolkit_core::models::{KeyCredential, PasswordCredential};

    let app = AppRegistrationBackup {
        display_name: "App A".into(),
        source_app_id: "src-a".into(),
        secrets: vec![CredentialMeta {
            display_name: Some("ci".into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
    let hit = || TagHit {
        app: Application {
            id: "obj-1".into(),
            app_id: "app-1".into(),
            display_name: "App A".into(),
            created_date_time: chrono::DateTime::from_timestamp(1_000_600, 0),
            ..Default::default()
        },
        ..Default::default()
    };
    let decide_on = |app: &AppRegistrationBackup, hit: TagHit| {
        adoption_for(app, &[hit], taken_at, "src-tenant", "dst-tenant")
    };

    let mut certed = hit();
    certed.app.key_credentials = vec![KeyCredential::default()];
    let Adoption::Refuse(reason) = decide_on(&app, certed) else {
        panic!("a certificate credential must refuse the adoption");
    };
    assert!(reason.contains("certificate"), "{reason}");

    let mut planted = hit();
    planted.app.password_credentials = vec![
        PasswordCredential {
            display_name: Some("ci".into()),
            ..Default::default()
        },
        PasswordCredential {
            display_name: Some("backdoor".into()),
            ..Default::default()
        },
    ];
    let Adoption::Refuse(reason) = decide_on(&app, planted) else {
        panic!("a secret the manifest does not name must refuse the adoption");
    };
    assert!(reason.contains("(backdoor)"), "{reason}");

    // Two live "ci" against one manifest entry: the second is foreign.
    let mut doubled = hit();
    doubled.app.password_credentials = vec![
        PasswordCredential {
            display_name: Some("ci".into()),
            ..Default::default()
        },
        PasswordCredential {
            display_name: Some("ci".into()),
            ..Default::default()
        },
    ];
    let Adoption::Refuse(reason) = decide_on(&app, doubled) else {
        panic!("more same-named secrets than the manifest lists must refuse");
    };
    assert!(reason.contains("(ci)"), "{reason}");

    // A certificate whose thumbprint the manifest lists (the runbook's own
    // re-upload) is accounted for; any other is foreign.
    let mut with_cert = app.clone();
    with_cert.certificates = vec![CredentialMeta {
        thumbprint: Some("DA20FCA696C4F83E8A9AED59BE33368ED421F3C1".into()),
        ..Default::default()
    }];
    let mut reuploaded = hit();
    reuploaded.app.key_credentials = vec![KeyCredential {
        custom_key_identifier: Some("2iD8ppbE+D6Kmu1ZvjM2jtQh88E=".into()),
        ..Default::default()
    }];
    assert!(matches!(
        decide_on(&with_cert, reuploaded),
        Adoption::Adopt { .. }
    ));
    let mut other_cert = hit();
    other_cert.app.key_credentials = vec![KeyCredential {
        key_id: "k-other".into(),
        custom_key_identifier: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()),
        ..Default::default()
    }];
    let Adoption::Refuse(reason) = decide_on(&with_cert, other_cert) else {
        panic!("a certificate the manifest does not list must refuse");
    };
    assert!(reason.contains("k-other"), "{reason}");

    // Exactly the manifest's secret, issued by the earlier run: adopted.
    let mut legit = hit();
    legit.app.password_credentials = vec![PasswordCredential {
        display_name: Some("ci".into()),
        ..Default::default()
    }];
    assert!(matches!(decide_on(&app, legit), Adoption::Adopt { .. }));
}

/// A planted federated credential is a secretless, permanent sign-in as
/// the app; the owner check cannot see it, so adoption reads them.
#[tokio::test]
async fn a_tagged_app_with_a_federated_credential_the_manifest_does_not_name_is_not_adopted() {
    let server = wiremock::MockServer::start().await;
    mount_tagged_hit(
        &server,
        serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
    )
    .await;
    mount_tagged_fics(
        &server,
        serde_json::json!([{
            "id": "fic-1", "name": "gh-main",
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": "repo:mallory/app:ref:refs/heads/main",
            "audiences": ["api://AzureADTokenExchange"]
        }]),
        1,
    )
    .await;
    let client = graph_over(&server, false);

    let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
        panic!("a credential the manifest does not name must block adoption");
    };
    assert!(reason.contains("repo:mallory/app"), "{reason}");
}

/// A live credential the manifest names — matched on name, issuer, subject
/// and audiences, the manifest's empty audiences defaulting to the cloud's
/// — is the one an earlier run created: adopted. A flexible credential
/// (no subject) is never matched.
#[tokio::test]
async fn a_tagged_app_whose_federated_credential_the_manifest_names_is_adopted() {
    let server = wiremock::MockServer::start().await;
    mount_tagged_hit(
        &server,
        serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
    )
    .await;
    let live = |subject: Option<&str>| {
        serde_json::json!([{
            "id": "fic-1", "name": "gh-main",
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": subject,
            "audiences": ["api://AzureADTokenExchange"]
        }])
    };
    let client = graph_over(&server, false);
    let mut app = tagged_app_a();
    app.federated_credentials = vec![FederatedIdentityCredential {
        name: "gh-main".into(),
        issuer: "https://token.actions.githubusercontent.com".into(),
        subject: Some("repo:contoso/app:ref:refs/heads/main".into()),
        ..Default::default()
    }];
    mount_tagged_fics(
        &server,
        live(Some("repo:contoso/app:ref:refs/heads/main")),
        2,
    )
    .await;
    assert!(matches!(
        decide_app(&client, &app, &SessionDead::new()).await,
        Adoption::Adopt { .. }
    ));

    mount_tagged_fics(&server, live(None), 1).await;
    let Adoption::Refuse(reason) = decide_app(&client, &app, &SessionDead::new()).await else {
        panic!("a flexible credential can never be matched to the manifest");
    };
    assert!(reason.contains("gh-main"), "{reason}");
}

/// The credential read fails closed like the tag and owner reads.
#[tokio::test]
async fn a_failed_federated_credential_read_refuses_the_adoption() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    let server = wiremock::MockServer::start().await;
    mount_tagged_hit(
        &server,
        serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
    )
    .await;
    Mock::given(method("GET"))
        .and(path("/applications/obj-1/federatedIdentityCredentials"))
        .respond_with(ResponseTemplate::new(503))
        .with_priority(1)
        .mount(&server)
        .await;
    let client = graph_over(&server, false);

    let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
        panic!("a failed credential read must refuse");
    };
    assert!(reason.contains("federated credentials"), "{reason}");
}

/// What Pass 2 writes, in any order, ids in any case and an empty text as
/// absent, is no finding, and neither is less of it (an earlier run that
/// stopped before Pass 2). Anything else on the hit is named.
#[test]
fn foreign_settings_names_only_what_pass_2_would_not_write() {
    let scope = |id: &str, value: &str| OAuth2PermissionScope {
        id: id.into(),
        value: value.into(),
        admin_consent_display_name: Some("Read orders".into()),
        r#type: Some("Admin".into()),
        is_enabled: Some(true),
        ..Default::default()
    };
    let app = AppRegistrationBackup {
        source_app_id: SRC_A.into(),
        web_redirect_uris: vec![
            "https://contoso.com/cb".into(),
            "https://*.contoso.com/cb".into(),
        ],
        spa_redirect_uris: vec!["https://contoso.com/spa".into()],
        logout_url: Some(" https://contoso.com/logout ".into()),
        enable_id_token_issuance: true,
        identifier_uris: vec![format!("api://{SRC_A}"), "api://src-tenant/orders".into()],
        api_scopes: vec![scope("SCOPE-1", "Orders.Read")],
        ..Default::default()
    };
    let findings = |hit: &TagHit| foreign_settings(&app, hit, "src-tenant", "dst-tenant");
    let mut bare = TagHit::default();
    bare.app.app_id = "app-a".into();
    assert!(findings(&bare).is_empty(), "{:?}", findings(&bare));

    let mut written = bare.clone();
    written.auth.web_redirect_uris = vec!["https://contoso.com/cb".into()];
    written.auth.spa_redirect_uris = vec!["https://contoso.com/spa".into()];
    written.auth.logout_url = Some("https://contoso.com/logout".into());
    written.auth.enable_id_token_issuance = true;
    written.expose.identifier_uris = vec!["api://dst-tenant/orders".into(), "api://app-a".into()];
    let mut live_scope = scope("scope-1", "Orders.Read");
    live_scope.user_consent_description = Some(String::new());
    written.expose.api.oauth2_permission_scopes = vec![live_scope];
    assert!(findings(&written).is_empty(), "{:?}", findings(&written));

    let mut planted = written.clone();
    // Listed, but `core::redirect` rejects it, so Pass 2 never writes it.
    planted
        .auth
        .web_redirect_uris
        .push("https://*.contoso.com/cb".into());
    // The manifest's web URL, on another platform.
    planted
        .auth
        .spa_redirect_uris
        .push("https://contoso.com/cb".into());
    planted.auth.public_client_redirect_uris = vec!["ms-app://planted".into()];
    planted.auth.logout_url = Some("https://evil.example/logout".into());
    planted.auth.enable_access_token_issuance = true;
    planted.auth.is_fallback_public_client = true;
    // The source appId, which Pass 2 rewrites.
    planted
        .expose
        .identifier_uris
        .push(format!("api://{SRC_A}"));
    // The manifest's scope made user-consentable, and one it lacks.
    let mut user_consentable = scope("scope-1", "Orders.Read");
    user_consentable.r#type = Some("User".into());
    planted.expose.api.oauth2_permission_scopes =
        vec![user_consentable, scope("scope-2", "Orders.ReadWrite")];
    assert_eq!(
        findings(&planted),
        [
            "web redirect URI 'https://*.contoso.com/cb'".to_string(),
            "SPA redirect URI 'https://contoso.com/cb'".into(),
            "public-client redirect URI 'ms-app://planted'".into(),
            "logout URL 'https://evil.example/logout'".into(),
            "implicit-grant access tokens turned on".into(),
            "public client flows allowed (the public-client flag)".into(),
            format!("identifier URI 'api://{SRC_A}'"),
            "scope 'Orders.Read' (scope-1)".into(),
            "scope 'Orders.ReadWrite' (scope-2)".into(),
        ]
    );
}

fn pre_authorized(app_id: &str, scope_ids: &[&str]) -> PreAuthorizedApplication {
    PreAuthorizedApplication {
        app_id: app_id.into(),
        delegated_permission_ids: scope_ids.iter().map(|id| id.to_string()).collect(),
    }
}

/// A live pre-authorized client is held to Pass 2's own list over the final
/// remap: a client of this backup under the appId this run gave it, one from
/// outside it as listed, either for no scope it was not listed with, all
/// ignoring case.
#[test]
fn foreign_pre_authorized_holds_live_clients_to_what_pass_2_writes() {
    let api = AppRegistrationBackup {
        source_app_id: SRC_A.into(),
        pre_authorized_applications: vec![
            pre_authorized(SRC_B, &["scope-1"]),
            pre_authorized("foreign-client", &["scope-1", "scope-2"]),
        ],
        ..Default::default()
    };
    let backup_apps = BackupApps::new([(SRC_A, "App A"), (SRC_B, "App B")]);
    let remap = HashMap::from([
        (SRC_A.to_string(), "app-a".to_string()),
        (SRC_B.to_string(), "app-b".to_string()),
    ]);
    let findings = |live: &[PreAuthorizedApplication], remap: &HashMap<String, String>| {
        foreign_pre_authorized(&api, live, remap, &backup_apps)
    };
    let written = [
        pre_authorized("APP-B", &["SCOPE-1"]),
        pre_authorized("Foreign-Client", &["scope-2"]),
    ];
    assert!(findings(&written, &remap).is_empty());

    assert_eq!(
        findings(
            &[
                // The backup's own client under its source tenant's appId.
                pre_authorized(SRC_B, &["scope-1"]),
                pre_authorized("mallory-client", &["scope-1"]),
                pre_authorized("foreign-client", &["scope-1", "scope-3"]),
            ],
            &remap
        ),
        [
            format!("pre-authorized client {SRC_B}"),
            "pre-authorized client mallory-client".into(),
            "pre-authorized client foreign-client for scope id(s) scope-3".into(),
        ]
    );
    // A client of this backup the run did not restore has no appId here, so
    // the one the hit names is not this run's.
    let without_b = HashMap::from([(SRC_A.to_string(), "app-a".to_string())]);
    assert_eq!(
        findings(&[pre_authorized("app-b", &["scope-1"])], &without_b),
        ["pre-authorized client app-b"]
    );
}

/// Refusing one pending adoption takes its appId out of the remap, which
/// leaves an app pre-authorizing it unaccounted for in turn: A pre-authorizes
/// B, B pre-authorizes C, and C a client nobody listed. All three are
/// refused, in manifest order, however many rounds that takes.
#[test]
fn refusing_a_pending_adoption_refuses_those_that_pre_authorize_it() {
    let app = |src: &str, name: &str, client: Option<&str>| AppRegistrationBackup {
        source_app_id: src.into(),
        display_name: name.into(),
        pre_authorized_applications: client
            .map(|c| pre_authorized(c, &["scope-1"]))
            .into_iter()
            .collect(),
        ..Default::default()
    };
    let adopted = |backup: AppRegistrationBackup, tag: &str| CreatedApp {
        backup,
        new_object_id: format!("obj-{tag}"),
        new_app_id: format!("app-{tag}"),
        adopted: true,
        live_secrets: Vec::new(),
        warnings: Vec::new(),
    };
    let created = [
        adopted(app(SRC_A, "App A", Some(SRC_B)), "a"),
        adopted(app(SRC_B, "App B", Some(SRC_C)), "b"),
        adopted(app(SRC_C, "App C", None), "c"),
    ];
    let pending =
        [("app-b", 0), ("app-c", 1), ("mallory-client", 2)].map(|(client, at)| PendingAdoption {
            at,
            pre_authorized: vec![pre_authorized(client, &["scope-1"])],
        });
    let backup_apps = BackupApps::new([(SRC_A, "App A"), (SRC_B, "App B"), (SRC_C, "App C")]);
    let mut remap: HashMap<String, String> = [(SRC_A, "app-a"), (SRC_B, "app-b"), (SRC_C, "app-c")]
        .into_iter()
        .map(|(src, new)| (src.to_string(), new.to_string()))
        .collect();

    let refused = refuse_foreign_pre_authorized(&pending, &created, &backup_apps, &mut remap);

    assert_eq!(
        refused.iter().map(|(at, _)| *at).collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert!(
        refused[0].1.contains("pre-authorized client app-b"),
        "{}",
        refused[0].1
    );
    assert!(
        refused[1].1.contains("pre-authorized client app-c"),
        "{}",
        refused[1].1
    );
    assert!(
        refused[2]
            .1
            .contains("pre-authorized client mallory-client")
            && refused[2].1.contains("not adopted"),
        "{}",
        refused[2].1
    );
    assert!(remap.is_empty(), "{remap:?}");
}

/// Answers the tag lookup for `src`'s restore tag with the one app `hit`; its
/// owners, credentials and service principal read as none (the fallback).
async fn mount_tag_lookup(server: &MockServer, src: &str, hit: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path("/applications"))
        .and(query_param(
            "$filter",
            format!("tags/any(t:t eq '{}')", restore_marker(src)),
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [hit] })),
        )
        .mount(server)
        .await;
}

/// W20's bypass. A copy planted with the restore tag and the name, owned by
/// nobody the restore did not set, holds a reply URL, an implicit-grant flag
/// or the public-client flag the backup does not list. The manifest app
/// consents to a low-risk delegated permission and lists none of those, so
/// the plan asks for no approval and Pass 2 writes no authentication. Adopted,
/// the planted setting would stay and Pass 3 would consent, delivering
/// consented tokens wherever the planter chose. Refused instead: never
/// adopted, never consented, not created again, the setting named.
#[tokio::test]
async fn a_tagged_app_with_planted_sign_in_settings_is_never_adopted_or_consented() {
    for (planted, named) in [
        (
            serde_json::json!({ "spa": { "redirectUris": ["https://evil.example/cb"] } }),
            "SPA redirect URI 'https://evil.example/cb'",
        ),
        (
            serde_json::json!({ "web": { "redirectUris": ["https://evil.example/web"] } }),
            "web redirect URI 'https://evil.example/web'",
        ),
        (
            serde_json::json!({ "publicClient": { "redirectUris": ["ms-app://planted"] } }),
            "public-client redirect URI 'ms-app://planted'",
        ),
        (
            serde_json::json!({ "isFallbackPublicClient": true }),
            "public client flows allowed",
        ),
        (
            serde_json::json!({
                "web": { "implicitGrantSettings": { "enableAccessTokenIssuance": true } }
            }),
            "implicit-grant access tokens turned on",
        ),
    ] {
        let server = MockServer::start().await;
        mount_tagged_hit_with(
            &server,
            serde_json::json!([{ "id": "operator-oid" }]),
            planted,
        )
        .await;
        // Pass 3's re-read: the app declares exactly the backup's permission,
        // so nothing but the refusal stands between it and the consent.
        Mock::given(method("GET"))
            .and(path("/applications/obj-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "obj-1",
                "appId": "app-1",
                "displayName": "App A",
                "requiredResourceAccess": [{
                    "resourceAppId": GRAPH,
                    "resourceAccess": [{ "id": USER_READ_SCOPE, "type": "Scope" }]
                }]
            })))
            .mount(&server)
            .await;
        mount_graph_sp(&server).await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let backup = manifest(vec![AppRegistrationBackup {
            source_app_id: SRC_A.into(),
            display_name: "App A".into(),
            admin_consent_granted: true,
            required_resource_access: vec![azapptoolkit_core::models::RequiredResourceAccess {
                resource_app_id: GRAPH.into(),
                resource_access: vec![azapptoolkit_core::models::ResourceAccess {
                    id: USER_READ_SCOPE.into(),
                    r#type: "Scope".into(),
                }],
            }],
            ..Default::default()
        }]);
        let items = privileged_restore_items(&client, &backup, &SessionDead::new()).await;
        assert!(
            items.iter().all(|i| !i.requires_approval),
            "the plan asks for no approval: {items:?}"
        );

        let (report, effects) = restore(&client, &backup, never_cancelled(), &[]).await;

        assert!(report.apps.is_empty(), "{named}: {report:?}");
        assert!(!effects.created_any, "{named}");
        assert!(
            !consent_attempted(&server, "app-1").await,
            "{named}: never consented"
        );
        assert!(
            requests(&server, "POST", "/applications").await.is_empty(),
            "{named}: not created again"
        );
        let refusal = report
            .manual_items
            .iter()
            .find(|m| m.reason.contains("carries this app's restore tag"))
            .unwrap_or_else(|| panic!("{named}: {:?}", report.manual_items));
        assert!(
            refusal.reason.contains(named) && refusal.reason.contains("not adopted"),
            "{}",
            refusal.reason
        );
    }
}

/// W55's bypass. A planted copy of an API the backup restores pre-authorizes
/// a client the backup does not list (the planter's own, which would then get
/// the API's scopes without anyone consenting), and Pass 2 writes that list
/// only when the manifest has one. Refused once Pass 1 knows every app's
/// appId, it gets no write at all, not even its service principal.
#[tokio::test]
async fn a_tagged_api_pre_authorizing_a_client_the_backup_does_not_list_is_not_adopted() {
    let server = MockServer::start().await;
    let scope = serde_json::json!({
        "id": "scope-1", "value": "Orders.Read", "type": "User", "isEnabled": true
    });
    mount_tag_lookup(
        &server,
        SRC_A,
        serde_json::json!({
            "id": "obj-a",
            "appId": "app-a",
            "displayName": "App A",
            "createdDateTime": "2026-01-02T00:00:00Z",
            "identifierUris": ["api://app-a"],
            "api": {
                "oauth2PermissionScopes": [scope],
                "preAuthorizedApplications": [
                    { "appId": "mallory-client", "delegatedPermissionIds": ["scope-1"] }
                ]
            }
        }),
    )
    .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let backup = manifest(vec![AppRegistrationBackup {
        source_app_id: SRC_A.into(),
        display_name: "App A".into(),
        has_service_principal: true,
        identifier_uris: vec![format!("api://{SRC_A}")],
        api_scopes: vec![serde_json::from_value(scope).unwrap()],
        ..Default::default()
    }]);

    let (report, effects) = restore(&client, &backup, never_cancelled(), &[]).await;

    assert!(report.apps.is_empty(), "{report:?}");
    assert!(!effects.created_any);
    let [refusal] = report.manual_items.as_slice() else {
        panic!("{:?}", report.manual_items);
    };
    assert!(
        refusal
            .reason
            .contains("pre-authorized client mallory-client")
            && refusal.reason.contains("not adopted"),
        "{}",
        refusal.reason
    );
    assert!(
        requests(&server, "POST", "/applications").await.is_empty(),
        "not created again"
    );
    assert!(
        requests(&server, "POST", "/servicePrincipals")
            .await
            .is_empty(),
        "no service principal for an app it refused"
    );
    assert!(
        requests(&server, "PATCH", "/applications/obj-a")
            .await
            .is_empty(),
        "nothing wired"
    );
}

/// The other side of every check above: an earlier run's own app, whose
/// settings are exactly what Pass 2 writes (in another order, ids in another
/// case, absent fields as null), is adopted. That includes an API
/// pre-authorizing a client of this backup listed after it in the file, whose
/// appId Pass 1 knows only once it reaches that client.
#[tokio::test]
async fn a_tagged_app_whose_settings_are_what_pass_2_writes_is_adopted() {
    let server = MockServer::start().await;
    let scope = serde_json::json!({
        "id": "scope-1", "value": "Orders.Read", "type": "User", "isEnabled": true,
        "adminConsentDisplayName": "Read orders"
    });
    mount_tag_lookup(
        &server,
        SRC_A,
        serde_json::json!({
            "id": "obj-a",
            "appId": "app-a",
            "displayName": "App A",
            "createdDateTime": "2026-01-02T00:00:00Z",
            "isFallbackPublicClient": null,
            "web": {
                "redirectUris": ["https://a.contoso.com/alt", "https://a.contoso.com/cb"],
                "logoutUrl": null,
                "implicitGrantSettings": {
                    "enableAccessTokenIssuance": false,
                    "enableIdTokenIssuance": false
                }
            },
            "spa": { "redirectUris": [] },
            "publicClient": { "redirectUris": [] },
            "identifierUris": ["api://app-a"],
            "api": {
                "oauth2PermissionScopes": [scope],
                "preAuthorizedApplications": [
                    { "appId": "foreign-client", "delegatedPermissionIds": ["SCOPE-1"] },
                    { "appId": "app-b", "delegatedPermissionIds": ["scope-1"] }
                ]
            }
        }),
    )
    .await;
    mount_tag_lookup(
        &server,
        SRC_B,
        serde_json::json!({
            "id": "obj-b",
            "appId": "app-b",
            "displayName": "App B",
            "createdDateTime": "2026-01-02T00:00:00Z"
        }),
    )
    .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let api = AppRegistrationBackup {
        source_app_id: SRC_A.into(),
        display_name: "App A".into(),
        has_service_principal: true,
        web_redirect_uris: vec![
            "https://a.contoso.com/cb".into(),
            "https://a.contoso.com/alt".into(),
        ],
        identifier_uris: vec![format!("api://{SRC_A}")],
        api_scopes: vec![serde_json::from_value(scope).unwrap()],
        pre_authorized_applications: vec![
            pre_authorized(SRC_B, &["scope-1"]),
            pre_authorized("foreign-client", &["scope-1"]),
        ],
        ..Default::default()
    };
    let api_client = AppRegistrationBackup {
        source_app_id: SRC_B.into(),
        display_name: "App B".into(),
        ..Default::default()
    };

    let (report, _) = restore(
        &client,
        &manifest(vec![api, api_client]),
        never_cancelled(),
        &[],
    )
    .await;

    assert!(
        !report
            .manual_items
            .iter()
            .any(|m| m.reason.contains("restore tag")),
        "{:?}",
        report.manual_items
    );
    assert_eq!(
        report
            .apps
            .iter()
            .map(|a| (a.display_name.as_str(), a.adopted))
            .collect::<Vec<_>>(),
        [("App A", true), ("App B", true)]
    );
    assert!(
        requests(&server, "POST", "/applications").await.is_empty(),
        "nothing created twice"
    );
    // Taken once settled: the service principal it had no write for until
    // then is ensured.
    assert!(
        requests(&server, "POST", "/servicePrincipals")
            .await
            .iter()
            .any(|r| String::from_utf8_lossy(&r.body).contains("app-a")),
        "the settled adoption's service principal is ensured"
    );
}

/// A run that stops in Pass 1 takes none of its pending adoptions: their
/// pre-authorized clients were never checked, so each gets no write and no
/// report entry (its re-run decides it), while the apps the run created are
/// reported as usual.
#[tokio::test]
async fn a_run_that_stops_in_pass_1_takes_no_pending_adoption() {
    let server = MockServer::start().await;
    let flag = crate::state::CancelFlag::new();
    let cancel = flag.claim();
    mount_tag_lookup(
        &server,
        SRC_A,
        serde_json::json!({
            "id": "obj-a",
            "appId": "app-a",
            "displayName": "App A",
            "createdDateTime": "2026-01-02T00:00:00Z",
            "api": {
                "preAuthorizedApplications": [
                    { "appId": "foreign-client", "delegatedPermissionIds": ["scope-1"] }
                ]
            }
        }),
    )
    .await;
    // The operator cancels while App B is being created.
    mount_create_then(&server, move |name| {
        if name == "App B" {
            flag.cancel();
        }
    })
    .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let mut backup = plain_apps(&[(SRC_A, "App A"), (SRC_B, "App B"), (SRC_C, "App C")]);
    backup.app_registrations[0].has_service_principal = true;
    backup.app_registrations[0].pre_authorized_applications =
        vec![pre_authorized("foreign-client", &["scope-1"])];

    let (report, _) = restore(&client, &backup, cancel, &[]).await;

    assert!(report.cancelled);
    assert_reported_unwired(&report, &["b"]);
    assert!(report.manual_items.is_empty(), "{:?}", report.manual_items);
    assert!(
        requests(&server, "POST", "/servicePrincipals")
            .await
            .is_empty(),
        "no write to an adoption the run never settled"
    );
}

/// A run that creates nothing but re-binds a managed identity's roles
/// reports it, so the caller refreshes the audit.
#[tokio::test]
async fn a_run_that_only_rebinds_roles_reports_rebound_any() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param(
            "$filter",
            "servicePrincipalType eq 'ManagedIdentity'",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{ "id": "sp-1", "appId": "a1", "displayName": "mi-one" }]
        })))
        .mount(&server)
        .await;
    mount_graph_sp(&server).await;
    Mock::given(method("POST"))
        .and(path("/servicePrincipals/sp-1/appRoleAssignments"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "assign-1", "principalId": "sp-1", "resourceId": "graph-sp",
            "appRoleId": MAIL_SEND_ROLE
        })))
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let mut backup = manifest(vec![]);
    backup.managed_identities = vec![ManagedIdentityBackup {
        source_app_id: SRC_A.into(),
        display_name: "mi-one".into(),
        held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
            resource_app_id: GRAPH.into(),
            app_role_id: "r".into(),
            app_role_value: Some("Mail.Send".into()),
            ..Default::default()
        }],
        ..Default::default()
    }];
    let approved: HashSet<RestoreApproval> = HashSet::from([RestoreApproval {
        kind: PrivilegedKind::ManagedIdentity,
        source_app_id: SRC_A.into(),
    }]);

    let (report, effects) = run_restore(
        &client,
        &crate::commands::test_support::Recorder::default(),
        never_cancelled(),
        RestoreRun {
            backup: &backup,
            tenant_id: "dst-tenant",
            cloud: CloudEnvironment::Commercial,
            operator_oid: Some("operator-oid"),
            approved: &approved,
        },
    )
    .await;

    assert_eq!(report.managed_identities[0].app_roles_rebound, 1);
    assert_eq!(
        effects,
        RestoreEffects {
            created_any: false,
            rebound_any: true
        }
    );
}

/// A dead session during a principal lookup is noted like every other
/// read, so the latch trips here rather than at the next noted call.
#[tokio::test]
async fn a_dead_session_during_a_principal_lookup_latches() {
    let server = MockServer::start().await;
    let client = graph_over(&server, true);
    let session = SessionDead::new();
    assert_eq!(
        resolve_principal_uncached(&client, &named("Ops", Some("Group")), &session).await,
        Err(Unresolved::LookupFailed)
    );
    assert!(session.is_dead(), "a dead refresh token must latch");
}

/// Cancel is honoured inside Pass 5, not only before it: the second
/// identity is left alone and the report says the run was cancelled.
#[tokio::test]
async fn a_cancel_during_pass_5_stops_at_the_next_identity() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param(
            "$filter",
            "servicePrincipalType eq 'ManagedIdentity'",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                { "id": "sp-1", "appId": "a1", "displayName": "mi-one" },
                { "id": "sp-2", "appId": "a2", "displayName": "mi-two" }
            ]
        })))
        .mount(&server)
        .await;
    mount_graph_sp(&server).await;
    let flag = crate::state::CancelFlag::new();
    let cancel = flag.claim();
    // The operator cancels while the first identity's grant lands.
    Mock::given(method("POST"))
        .and(path("/servicePrincipals/sp-1/appRoleAssignments"))
        .respond_with(move |_: &Request| {
            flag.cancel();
            ResponseTemplate::new(201).set_body_json(serde_json::json!({ "id": "x" }))
        })
        .mount(&server)
        .await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let role = |src: &str, name: &str| ManagedIdentityBackup {
        source_app_id: src.into(),
        display_name: name.into(),
        held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
            resource_app_id: GRAPH.into(),
            app_role_id: "r".into(),
            app_role_value: Some("Mail.Send".into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let mis = vec![role(SRC_A, "mi-one"), role(SRC_B, "mi-two")];
    let approved: HashSet<RestoreApproval> = [SRC_A, SRC_B]
        .into_iter()
        .map(|s| RestoreApproval {
            kind: PrivilegedKind::ManagedIdentity,
            source_app_id: s.into(),
        })
        .collect();
    let mut report = RestoreReport::default();

    rebind_mis(
        &client,
        &mis,
        &approved,
        &mut report,
        &SessionDead::new(),
        &cancel,
    )
    .await;

    assert!(report.cancelled);
    assert!(
        requests(
            &server,
            "POST",
            "/servicePrincipals/sp-2/appRoleAssignments"
        )
        .await
        .is_empty(),
        "the second identity must not be touched after a cancel"
    );
    assert_eq!(report.managed_identities.len(), 1);
}

/// A destination identity of another sub-type is not this identity,
/// however it is named; an unknown sub-type on either side still matches.
#[tokio::test]
async fn an_identity_of_another_subtype_is_not_matched_by_name() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param(
            "$filter",
            "servicePrincipalType eq 'ManagedIdentity'",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": "sp-1", "appId": "a1", "displayName": "mi-one",
                "alternativeNames": ["isExplicit=True", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-one"]
            }]
        })))
        .mount(&server)
        .await;
    mount_graph_sp(&server).await;
    mount_fallback(&server).await;
    let client = graph_over(&server, false);
    let mi = |subtype: MiSubtype| ManagedIdentityBackup {
        source_app_id: SRC_A.into(),
        display_name: "mi-one".into(),
        subtype,
        held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
            resource_app_id: GRAPH.into(),
            app_role_id: "r".into(),
            app_role_value: Some("Mail.Send".into()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let approved = HashSet::from([RestoreApproval {
        kind: PrivilegedKind::ManagedIdentity,
        source_app_id: SRC_A.into(),
    }]);
    const GRANTS: &str = "/servicePrincipals/sp-1/appRoleAssignments";

    let mut report = RestoreReport::default();
    rebind_mis(
        &client,
        &[mi(MiSubtype::SystemAssigned)],
        &approved,
        &mut report,
        &SessionDead::new(),
        &never_cancelled(),
    )
    .await;
    assert!(requests(&server, "POST", GRANTS).await.is_empty());
    assert!(
        report
            .manual_items
            .iter()
            .any(|m| m.reason.contains("not found in the destination")),
        "{:?}",
        report.manual_items
    );

    for subtype in [MiSubtype::UserAssigned, MiSubtype::Unknown] {
        let mut report = RestoreReport::default();
        rebind_mis(
            &client,
            &[mi(subtype)],
            &approved,
            &mut report,
            &SessionDead::new(),
            &never_cancelled(),
        )
        .await;
        assert_eq!(report.managed_identities.len(), 1, "{subtype:?}");
    }
    assert_eq!(requests(&server, "POST", GRANTS).await.len(), 2);
}
