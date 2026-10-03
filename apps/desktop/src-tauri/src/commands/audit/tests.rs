//! Unit tests for the audit command layer (`super`).

use super::*;

use super::prefetch::prefetch_admin_consent_grants;
use super::score::{derive_orgwide_mail_scopes, score_one, sp_audit_candidates};

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use azapptoolkit_core::audit::{AuditItem, AuditPrincipalKind, CredentialStatus, RiskLevel};
use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::models::{Application, RequiredResourceAccess, ServicePrincipal};
use azapptoolkit_core::scoping::{EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID};
use azapptoolkit_core::token::{BearerProvider, StaticTokenProvider, TokenError};
use azapptoolkit_graph::GraphClient;

use crate::dto::audit::{
    AuditCoverageGap, AuditExportCoverage, CachedAuditSummary, MAILBOX_SCOPING_UNRESOLVED,
};

#[test]
fn a_dead_session_stops_the_audit_but_one_bad_app_does_not() {
    // Regression: every non-cancelled failure used to collapse to a warning,
    // so a session that died mid-run produced a report silently missing apps
    // — and then cached it under CacheKind::Audit as authoritative.
    let cases = [
        ("cancelled", AuditFailure::Cancelled),
        ("refresh_missing", AuditFailure::SessionDead),
        ("not_signed_in", AuditFailure::SessionDead),
        ("forbidden", AuditFailure::Transient),
        ("throttled", AuditFailure::Transient),
        ("graph", AuditFailure::Transient),
    ];
    for (code, expected) in cases {
        let err = UiError::new(code, "boom", false);
        assert_eq!(
            classify_audit_failure(&err),
            expected,
            "{code} should classify as {expected:?}"
        );
    }
}

#[test]
fn session_dead_classification_tracks_the_shared_definition() {
    // `UiError::is_reauth_fatal` is the single definition (azapptoolkit-dto,
    // shared by both tiers). Adding a code there must extend the audit's stop
    // condition automatically — this asserts the coupling rather than a list.
    for code in ["refresh_missing", "not_signed_in", "forbidden", "cancelled"] {
        let err = UiError::new(code, "boom", false);
        let expected_stop = err.is_reauth_fatal();
        let stops = classify_audit_failure(&err) == AuditFailure::SessionDead;
        assert_eq!(stops, expected_stop, "{code} diverged from is_reauth_fatal");
    }
}

/// The cache guard, exhaustively. AGENTS.md states that a
/// cancelled/truncated/degraded run is never cached; until this the rule
/// lived only in an `if` inside a `State`-taking command, so nothing could
/// fail when it changed.
///
/// Every combination on purpose: the failure mode is one condition being
/// dropped from the conjunction, which any single-case test would miss.
#[test]
fn only_a_complete_undegraded_run_is_cacheable() {
    let gap = vec![AuditCoverageGap::PermissionResolution];
    for &cancelled in &[false, true] {
        for &truncated in &[false, true] {
            for degraded in [Vec::new(), gap.clone()] {
                let clean = !cancelled && !truncated && degraded.is_empty();
                assert_eq!(
                    run_is_cacheable(cancelled, truncated, &degraded),
                    clean,
                    "cancelled={cancelled} truncated={truncated} degraded={} \
                         — a partial or degraded run cached here reads as a clean \
                         full scan on the next open",
                    degraded.len()
                );
            }
        }
    }
}

/// A run that scored everything and resolved everything is the ONE case
/// that caches — stated separately so the intent survives if the loop above
/// is ever rewritten.
#[test]
fn a_clean_full_run_is_cached() {
    assert!(run_is_cacheable(false, false, &[]));
}

/// The audit key must carry the `{tenant_id}|` prefix every other kind
/// uses, because sign-out invalidates by prefix. The original `run:{tenant}`
/// shape was invisible to that sweep — one tenant's audit survived into the
/// next session, which is the cross-tenant leak AGENTS.md calls the #1
/// footgun. Nothing pinned the shape.
#[test]
fn the_audit_cache_key_is_tenant_prefixed_so_sign_out_reaches_it() {
    let key = audit_cache_key("contoso-tenant-id");
    assert!(
        key.starts_with("contoso-tenant-id|"),
        "key {key:?} does not start with the tenant prefix sign-out sweeps"
    );
    // And distinct tenants never collide.
    assert_ne!(audit_cache_key("tenant-a"), audit_cache_key("tenant-b"));
}

fn sample(name: &str) -> AuditItem {
    AuditItem {
        application_name: name.to_string(),
        app_id: "00000000-0000-0000-0000-000000000001".to_string(),
        object_id: "obj-1".to_string(),
        created_date: None,
        publisher: None,
        sign_in_audience: Some("AzureADMyOrg".to_string()),
        risk_score: 7,
        risk_level: RiskLevel::Medium,
        issues: vec!["one".to_string(), "two".to_string()],
        recommendations: vec![],
        remediations: vec![],
        credential_status: CredentialStatus::Active,
        permission_count: 2,
        service_principal_enabled: Some(true),
        days_since_created: Some(30),
        certificates: vec![],
        secrets: vec![],
        last_sign_in: None,
        unused: false,
        sign_in_report_available: false,
        principal_kind: AuditPrincipalKind::Application,
        app_owner_organization_id: None,
        sp_risk_state: None,
        sp_risk_level: None,
    }
}

/// The run entry is stored typed, so every reader must use `get_typed` —
/// an untyped `get` on it misses, which would read as "no audit run" on
/// Home and fail the by-reference export. And the Home summary carries the
/// stamp the run wrote, never the read time.
#[test]
fn the_cached_run_is_stored_typed_and_summarized_from_its_own_stamp() {
    let cache = Cache::new();
    let key = audit_cache_key("t1");
    cache.put_typed(
        CacheKind::Audit,
        key.clone(),
        Arc::new(CachedAuditRun {
            completed_at: "2026-01-01T00:00:00Z".into(),
            items: vec![sample("A"), sample("B")],
            mailbox_scoping_resolved: true,
            credential_policy_available: true,
            credential_policy_max_days: Some(90),
        }),
    );
    let run = cache
        .get_typed::<CachedAuditRun>(CacheKind::Audit, &key)
        .expect("typed read hits");
    assert_eq!(run.items.len(), 2);
    // The wrong door: `CachedAuditRun` is no longer `Deserialize`, so probe
    // with the item vector the untyped path would have to decode.
    assert!(
        cache
            .get::<Vec<AuditItem>>(CacheKind::Audit, &key)
            .is_none(),
        "an untyped read of the typed run entry must miss"
    );
    let summary = CachedAuditSummary::from_items(
        &run.items,
        Some(run.completed_at.clone()),
        run.credential_policy_available,
        run.credential_policy_max_days,
    );
    assert_eq!(
        summary.completed_at.as_deref(),
        Some("2026-01-01T00:00:00Z")
    );
    assert_eq!(summary.posture.medium, 2);
    // The policy state survives the round trip into the Home summary.
    assert_eq!(summary.credential_policy_max_days, Some(90));
    assert!(summary.credential_policy_available);
}

fn sp(id: &str, app_id: &str, sp_type: Option<&str>) -> ServicePrincipal {
    ServicePrincipal {
        id: id.to_string(),
        app_id: app_id.to_string(),
        service_principal_type: sp_type.map(str::to_string),
        ..ServicePrincipal::default()
    }
}

#[test]
fn orgwide_mail_scopes_include_the_ews_scope_from_the_legacy_resource() {
    // The EWS `full_access_as_app` grant lives on Office 365 Exchange Online,
    // not Microsoft Graph, so the Graph matrix can't see it. Without it a
    // principal with a scoped RBAC role but a surviving org-wide EWS grant
    // scored as scoped — an under-report, since it still reaches every mailbox.
    let graph_roles: HashMap<String, Vec<String>> = [
        (
            "sp-mixed".to_string(),
            vec!["Mail.Read".to_string(), "User.Read.All".to_string()],
        ),
        // Holds no mail role at all: the EWS grant must still register, so this
        // has to insert rather than only extend.
        ("sp-ews-only".to_string(), vec!["User.Read.All".to_string()]),
    ]
    .into();
    let ews: HashSet<String> = ["sp-mixed".to_string(), "sp-ews-only".to_string()].into();

    let out = derive_orgwide_mail_scopes(&graph_roles, &ews);

    assert_eq!(
        out.get("sp-mixed"),
        Some(
            &["Mail.Read".to_string(), EWS_FULL_ACCESS_AS_APP.to_string()]
                .into_iter()
                .collect::<HashSet<_>>()
        ),
        "the Graph mail role and the EWS scope must both be reconciled against"
    );
    assert_eq!(
        out.get("sp-ews-only"),
        Some(&[EWS_FULL_ACCESS_AS_APP.to_string()].into_iter().collect())
    );
}

#[test]
fn orgwide_mail_scopes_drop_principals_with_no_mailbox_grant() {
    // Non-mail roles alone leave nothing to reconcile — the entry is dropped so
    // the map stays the mail-relevant subset it claims to be.
    let graph_roles: HashMap<String, Vec<String>> =
        [("sp-1".to_string(), vec!["Directory.Read.All".to_string()])].into();
    assert!(derive_orgwide_mail_scopes(&graph_roles, &HashSet::new()).is_empty());
}

// The SP-only candidate filter: no local application AND (≥1 application
// grant on either mailbox-bearing resource OR a risky flag from Identity
// Protection). Managed identities and disabled SPs are candidates; paired and
// grantless-unflagged SPs are not.
#[test]
fn sp_audit_candidates_filters_paired_and_grantless() {
    let local_app_ids: HashSet<String> = ["paired-app".to_string()].into();
    let roles: HashMap<String, Vec<String>> = [
        ("sp-foreign".to_string(), vec!["Mail.Read".to_string()]),
        ("sp-paired".to_string(), vec!["Mail.Read".to_string()]),
        ("sp-mi".to_string(), vec!["User.Read.All".to_string()]),
        ("sp-empty".to_string(), Vec::new()),
    ]
    .into();
    let index = vec![
        sp("sp-foreign", "foreign-app", Some("Application")),
        sp("sp-paired", "paired-app", Some("Application")),
        sp("sp-mi", "mi-app", Some("ManagedIdentity")),
        sp("sp-grantless", "gallery-app", Some("Application")),
        sp("sp-empty", "empty-app", Some("Application")),
    ];
    let got: Vec<String> = sp_audit_candidates(
        &index,
        &local_app_ids,
        &roles,
        &HashSet::new(),
        &HashMap::new(),
    )
    .into_iter()
    .map(|s| s.id)
    .collect();
    // Paired (has a local app), grantless (not in the matrix), and
    // empty-role-list SPs are all excluded; the foreign SP and the MI stay.
    assert_eq!(got, vec!["sp-foreign".to_string(), "sp-mi".to_string()]);
}

#[test]
fn sp_holding_only_the_ews_blanket_scope_is_still_a_candidate() {
    // `full_access_as_app` lives on Office 365 Exchange Online, so such a
    // principal has NO Graph role and was filtered out of the SP-only phase
    // entirely — despite holding full access to every mailbox in the tenant,
    // which is the single most audit-worthy grant there is.
    let index = vec![sp("sp-ews", "ews-app", Some("Application"))];
    let ews: HashSet<String> = ["sp-ews".to_string()].into();
    let got: Vec<String> = sp_audit_candidates(
        &index,
        &HashSet::new(),
        &HashMap::new(), // no Graph grants at all
        &ews,
        &HashMap::new(),
    )
    .into_iter()
    .map(|s| s.id)
    .collect();
    assert_eq!(got, vec!["sp-ews".to_string()]);
}

#[test]
fn a_risky_grantless_sp_is_a_candidate_without_any_grant() {
    // Identity Protection flags a managed identity that holds no enumerable
    // grant (or holds it on a resource no matrix reads). "No grants ⇒ skip"
    // is the wrong inference exactly when a live security vendor says the
    // principal is compromised, so the risky set admits on its own.
    let index = vec![
        sp("sp-clean-gallery", "gallery-app", Some("Application")),
        sp("sp-risky-mi", "mi-app", Some("ManagedIdentity")),
    ];
    let risky: HashMap<String, (String, String)> = [(
        "sp-risky-mi".to_string(),
        ("confirmedCompromised".to_string(), "high".to_string()),
    )]
    .into();
    let got: Vec<String> = sp_audit_candidates(
        &index,
        &HashSet::new(),
        &HashMap::new(),
        &HashSet::new(),
        &risky,
    )
    .into_iter()
    .map(|s| s.id)
    .collect();
    assert_eq!(got, vec!["sp-risky-mi".to_string()]);
}

/// A run that covered everything — the shape every export took before the
/// coverage travelled with the items.
fn complete(total: usize) -> AuditExportCoverage {
    AuditExportCoverage {
        total_apps: total,
        cancelled: false,
        truncated: false,
        degraded: Vec::new(),
        sign_in_report_available: true,
        completed_at: Some("2026-09-02T09:00:00+00:00".to_string()),
        mailbox_scoping_resolved: true,
    }
}

/// The one run that ships its items to the exporter instead of being served
/// from the cache — and so the one whose caveat can only travel this way.
fn cancelled(total: usize) -> AuditExportCoverage {
    AuditExportCoverage {
        cancelled: true,
        ..complete(total)
    }
}

/// Lines of a CSV export that are not part of the `#` coverage preamble.
fn csv_data_lines(csv: &str) -> Vec<&str> {
    csv.lines().filter(|l| !l.starts_with('#')).collect()
}

#[test]
fn export_audit_csv_appends_new_columns_last() {
    let mut item = sample("SP App");
    item.principal_kind = AuditPrincipalKind::ServicePrincipal;
    item.app_owner_organization_id = Some("tenant-x".to_string());
    let csv = export_audit_csv(vec![item], &complete(1));
    let lines = csv_data_lines(&csv);
    assert!(lines[0].ends_with(",PrincipalKind,AppOwnerOrgId"));
    assert!(lines[1].ends_with(",ServicePrincipal,tenant-x"));
}

#[test]
fn export_audit_csv_has_header_and_one_row_per_item() {
    let csv = export_audit_csv(vec![sample("App A"), sample("App B")], &complete(2));
    let lines = csv_data_lines(&csv);
    assert!(lines[0].starts_with("ApplicationName,AppId,ObjectId"));
    assert_eq!(lines.len(), 3); // header + 2 rows
    assert!(lines[1].starts_with("App A,"));
    // Issues are joined with "; " and the field is quoted (contains no comma
    // here, so it stays bare) — just confirm both issues survive.
    assert!(csv.contains("one; two"));
}

#[test]
fn export_audit_csv_neutralizes_malicious_display_name() {
    // Comma in the name forces CSV quoting AND the leading '=' is defused,
    // so the cell can never be parsed as a formula by a spreadsheet.
    let csv = export_audit_csv(vec![sample("=cmd|'/c calc',A1")], &complete(1));
    assert!(csv.contains("\"'=cmd|'/c calc',A1\""));
    // No data row begins with a bare formula character.
    assert!(!csv.lines().skip(1).any(|l| l.starts_with('=')));
}

/// The caveat has to reach the file itself — the export is the artifact
/// that leaves the app, and a cancelled run is exactly the one whose items
/// are handed to the writer rather than read back from a (never-written)
/// cache entry.
#[test]
fn a_cancelled_run_says_so_in_every_format() {
    let items = vec![sample("App A")];
    let coverage = cancelled(40);

    let csv = export_audit_csv(items.clone(), &coverage);
    assert!(
        csv.starts_with("# azapptoolkit security audit — 1 of 40 principal(s) scored"),
        "csv preamble missing the coverage fraction:\n{csv}"
    );
    assert!(csv.contains("# This scan was cancelled early — 1 of 40 principals were scored."));
    // …without disturbing the columns a spreadsheet reads.
    assert!(csv_data_lines(&csv)[0].starts_with("ApplicationName,AppId,ObjectId"));

    let html = audit_to_html(&items, &coverage);
    assert!(html.contains("1 of 40 principal(s) scored"));
    assert!(html.contains("This scan was cancelled early"));

    let json = audit_to_json(&items, &coverage).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["cancelled"], serde_json::json!(true));
    assert_eq!(v["complete"], serde_json::json!(false));
    assert_eq!(v["scored"], serde_json::json!(1));
    assert_eq!(v["total_apps"], serde_json::json!(40));
}

/// A run whose tenant-wide reads partly failed scores every app it saw and
/// so reads as a clean scan everywhere the gap isn't stated — the same
/// reason the Findings pane shows its lede unconditionally.
#[test]
fn degraded_gaps_are_listed_by_description_not_by_flag() {
    let items = vec![sample("App A")];
    let coverage = AuditExportCoverage {
        degraded: vec![AuditCoverageGap::PermissionResolution],
        ..complete(1)
    };
    let expected = AuditCoverageGap::PermissionResolution.description();

    let html = audit_to_html(&items, &coverage);
    assert!(html.contains("Part of this scan could not run"));
    assert!(html.contains(&html_escape(expected)));

    let csv = export_audit_csv(items.clone(), &coverage);
    assert!(csv.contains(expected));

    let json = audit_to_json(&items, &coverage).expect("serialize");
    assert!(json.contains("permissionResolution"));
}

/// Unresolved mailbox scoping is a caveat, not a gap: the run is complete
/// and cacheable, yet every export has to carry the sentence the org-wide
/// mailbox group shows, or an over-reported finding reads as confirmed.
#[test]
fn an_unresolved_mailbox_scoping_run_says_so_in_every_export() {
    let items = vec![sample("App A")];
    let coverage = AuditExportCoverage {
        mailbox_scoping_resolved: false,
        ..complete(1)
    };
    assert!(coverage.is_complete());

    let csv = export_audit_csv(items.clone(), &coverage);
    assert!(
        csv.contains(&format!("# {MAILBOX_SCOPING_UNRESOLVED}")),
        "csv preamble missing the caveat:\n{csv}"
    );

    let json = audit_to_json(&items, &coverage).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["mailbox_scoping_resolved"], serde_json::json!(false));
    assert!(
        v["coverage_notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n == MAILBOX_SCOPING_UNRESOLVED)
    );

    let html = audit_to_html(&items, &coverage);
    assert!(html.contains(&html_escape(MAILBOX_SCOPING_UNRESOLVED)));

    // Still cacheable: it is not one of the three completeness flags.
    assert!(run_is_cacheable(false, false, &[]));

    // …and a resolved run carries none of it.
    let clean = audit_to_json(&items, &complete(1)).expect("serialize");
    assert!(!clean.contains(MAILBOX_SCOPING_UNRESOLVED));
}

/// The positive case must stay boring: a complete run's export carries the
/// counts and the run time, and none of the caveat prose.
#[test]
fn a_complete_run_exports_without_caveats() {
    let items = vec![sample("App A"), sample("App B")];
    let csv = export_audit_csv(items.clone(), &complete(2));
    assert!(csv.contains("# Coverage: complete"));
    assert!(csv.contains("# Scan completed: 2026-09-02T09:00:00+00:00"));
    assert!(!csv.contains("cancelled"));
    assert!(!csv.contains("not an all-clear"));

    let html = audit_to_html(&items, &complete(2));
    assert!(html.contains("2 of 2 principal(s) scored"));
    assert!(!html.contains("class=\"caveat\""));
}

/// The severity summary is a count of the rows in THIS file, so an auditor
/// reading the header can't be told about principals the export omits.
#[test]
fn the_severity_summary_counts_the_exported_rows() {
    let mut critical = sample("Critical App");
    critical.risk_level = RiskLevel::Critical;
    let items = vec![critical, sample("App B")]; // sample() is Medium

    assert_eq!(
        severity_summary(&items),
        [("Critical", 1), ("High", 0), ("Medium", 1), ("Low", 0)]
    );
    let html = audit_to_html(&items, &complete(2));
    assert!(html.contains("<li><b>1</b> Critical</li>"));
    assert!(html.contains("<li><b>0</b> High</li>"));
}

#[test]
fn html_escape_covers_the_five_entities() {
    assert_eq!(
        html_escape("<a href=\"x\">&'</a>"),
        "&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;"
    );
}

#[test]
fn audit_to_html_escapes_a_script_payload_in_the_name() {
    let html = audit_to_html(&[sample("<script>alert(1)</script>")], &complete(1));
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(!html.contains("<script>alert(1)</script>"));
}

#[test]
fn audit_to_json_round_trips() {
    let items = vec![sample("App A")];
    let json = audit_to_json(&items, &complete(1)).expect("audit items serialize");
    // The rows keep the shape they always had — a consumer reaches one
    // level deeper for them, and nothing about a row changed.
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    let back: Vec<AuditItem> = serde_json::from_value(v["items"].clone()).unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].application_name, "App A");
    assert_eq!(v["complete"], serde_json::json!(true));
    assert_eq!(
        v["completed_at"],
        serde_json::json!("2026-09-02T09:00:00+00:00")
    );
}

// ── Producers of `degraded` ────────────────────────────────────────────
//
// `only_a_complete_undegraded_run_is_cacheable` pins the guard; these pin
// what FEEDS it from `score_one`. A failed SP lookup used to come back as
// a clean `Ok(AuditItem)`, invisible to the guard.

/// A `ScoreCtx` with every tenant-wide input empty and Exchange off — the
/// shape of a run whose prefetch found nothing, so only the per-app SP
/// lookup reaches the (mock) Graph.
fn score_ctx(client: Arc<GraphClient>, cache: Arc<Cache>) -> ScoreCtx {
    ScoreCtx {
        resolver: Arc::new(ResourceResolver::new(client.clone())),
        client,
        cache,
        tenant_id: "tenant-test".to_string(),
        exo: None,
        admin_consent_clients: Arc::default(),
        admin_consented_scopes_by_client: None,
        orgwide_mail_by_sp: Arc::default(),
        legacy_policies: Arc::default(),
        exo_tripped: Arc::new(AtomicBool::new(false)),
        mail_scoping_unresolved: AtomicBool::new(false),
        sign_in_available: false,
        sign_in_map: Arc::default(),
        credential_usage_available: false,
        credential_activity_map: Arc::default(),
        risky_available: false,
        risky_by_sp: Arc::default(),
        app_policy_available: false,
        app_policy: Arc::default(),
    }
}

/// An app declaring no permissions, so the resolver makes no Graph call.
fn bare_app() -> Application {
    Application {
        app_id: "app-1".into(),
        display_name: "Demo".into(),
        ..Default::default()
    }
}

async fn mock_sp_lookup(server: &wiremock::MockServer, response: wiremock::ResponseTemplate) {
    use wiremock::matchers::{method, path, query_param};
    wiremock::Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param("$filter", "appId eq 'app-1'"))
        .respond_with(response)
        .mount(server)
        .await;
}

fn graph_over(server: &wiremock::MockServer, token: Arc<dyn BearerProvider>) -> ScoreCtx {
    let cache = Cache::new();
    let client = Arc::new(GraphClient::with_base_url(
        "tenant-test",
        token.clone(),
        token,
        cache.clone(),
        server.uri(),
    ));
    score_ctx(client, cache)
}

#[tokio::test]
async fn a_failed_sp_lookup_leaves_the_app_unscored_instead_of_clean() {
    let server = wiremock::MockServer::start().await;
    // `Retry-After: 0` keeps the retry budget from sleeping out its backoff.
    mock_sp_lookup(
        &server,
        wiremock::ResponseTemplate::new(503).insert_header("Retry-After", "0"),
    )
    .await;
    let ctx = graph_over(&server, StaticTokenProvider::new("tok"));

    let err = score_one(&ctx, &bare_app(), None)
        .await
        .expect_err("a failed SP read must not score the app as holding nothing");
    // → `unscored += 1` → `PerPrincipalScoring` in the collector …
    assert_eq!(classify_audit_failure(&err), AuditFailure::Transient);
    // … and a run carrying that gap is never cached as a clean scan.
    assert!(!run_is_cacheable(
        false,
        false,
        &[AuditCoverageGap::PerPrincipalScoring]
    ));
}

#[tokio::test]
async fn a_tenant_without_the_sp_still_scores() {
    // Control: a real "no service principal" answer is not a gap.
    let server = wiremock::MockServer::start().await;
    mock_sp_lookup(
        &server,
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
    )
    .await;
    let ctx = graph_over(&server, StaticTokenProvider::new("tok"));

    let item = score_one(&ctx, &bare_app(), None)
        .await
        .expect("an app with no SP scores normally");
    assert_eq!(item.service_principal_enabled, None);
    // No mail permission, so nothing was left unprobed.
    assert!(!ctx.mail_scoping_unresolved.load(Ordering::Acquire));
}

// A scopable mail permission scored with no Exchange client is left at
// org-wide weight unchecked — the run must say its scoping is unresolved.
#[tokio::test]
async fn an_unprobed_mail_permission_marks_scoping_unresolved() {
    use wiremock::matchers::{method, path, query_param};
    let server = wiremock::MockServer::start().await;
    mock_sp_lookup(
        &server,
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
    )
    .await;
    wiremock::Mock::given(method("GET"))
        .and(path("/servicePrincipals"))
        .and(query_param(
            "$filter",
            format!("appId eq '{MICROSOFT_GRAPH_APP_ID}'"),
        ))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "graph-sp",
                    "appId": MICROSOFT_GRAPH_APP_ID,
                    "appRoles": [{"id": "role-mail-read", "value": "Mail.Read"}],
                }]
            })),
        )
        .mount(&server)
        .await;
    let ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    let app = Application {
        required_resource_access: vec![RequiredResourceAccess {
            resource_app_id: MICROSOFT_GRAPH_APP_ID.to_string(),
            resource_access: vec![azapptoolkit_core::models::ResourceAccess {
                id: "role-mail-read".into(),
                r#type: "Role".into(),
            }],
        }],
        ..bare_app()
    };

    score_one(&ctx, &app, None).await.expect("scores");
    assert!(
        !ctx.resolver.had_unresolved(),
        "the Graph index must resolve, or the flag proves nothing"
    );
    assert!(ctx.mail_scoping_unresolved.load(Ordering::Acquire));
}

async fn mock_grants(server: &wiremock::MockServer, response: wiremock::ResponseTemplate) {
    use wiremock::matchers::{method, path};
    wiremock::Mock::given(method("GET"))
        .and(path("/oauth2PermissionGrants"))
        .respond_with(response)
        .mount(server)
        .await;
}

#[tokio::test]
async fn a_failed_grants_read_reports_consent_as_unknown() {
    let server = wiremock::MockServer::start().await;
    mock_grants(&server, wiremock::ResponseTemplate::new(403)).await;
    let ctx = graph_over(&server, StaticTokenProvider::new("tok"));

    let (clients, scopes, read) = prefetch_admin_consent_grants(&ctx.client).await;
    // Empty maps alone read as "nothing admin-consented"; the flag is what
    // lets Rule 13 fall back to the declared scopes instead of hiding them.
    assert!(
        !read,
        "a failed read must not claim the consent state is known"
    );
    assert!(clients.is_empty() && scopes.is_empty());
}

#[tokio::test]
async fn the_grants_read_keeps_only_all_principals_scopes() {
    let server = wiremock::MockServer::start().await;
    mock_grants(
        &server,
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [
                {"id": "g1", "clientId": "sp-1", "resourceId": "graph-sp",
                 "consentType": "AllPrincipals", "principalId": null,
                 "scope": "Mail.Read  User.Read"},
                {"id": "g2", "clientId": "sp-1", "resourceId": "graph-sp",
                 "consentType": "Principal", "principalId": "user-1",
                 "scope": "Files.ReadWrite.All"},
                {"id": "g3", "clientId": "sp-2", "resourceId": "graph-sp",
                 "consentType": "Principal", "principalId": "user-1",
                 "scope": "Mail.ReadWrite"},
            ]
        })),
    )
    .await;
    let ctx = graph_over(&server, StaticTokenProvider::new("tok"));

    let (clients, scopes, read) = prefetch_admin_consent_grants(&ctx.client).await;
    assert!(read);
    assert_eq!(clients, HashSet::from(["sp-1".to_string()]));
    assert_eq!(
        scopes.len(),
        1,
        "a user-consented grant is not admin consent"
    );
    assert_eq!(
        scopes["sp-1"],
        vec!["Mail.Read".to_string(), "User.Read".to_string()]
    );
}

#[tokio::test]
async fn score_one_hands_rule_13_the_apps_admin_consented_scopes() {
    let server = wiremock::MockServer::start().await;
    mock_sp_lookup(
        &server,
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "sp-1", "appId": "app-1", "accountEnabled": true}]
        })),
    )
    .await;
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.admin_consented_scopes_by_client = Some(Arc::new(HashMap::from([(
        "sp-1".to_string(),
        vec!["Mail.ReadWrite".to_string()],
    )])));

    // The app declares nothing, so the only way the broad scope can reach
    // Rule 13 is through its SP's AllPrincipals grant (dynamic consent).
    let item = score_one(&ctx, &bare_app(), None).await.expect("scores");
    assert!(
        item.issues.iter().any(|i| i
            == &format!(
                "{} Mail.ReadWrite",
                azapptoolkit_core::audit::issue::HIGH_RISK_DELEGATED_PERMS
            )),
        "{:?}",
        item.issues
    );
}

#[tokio::test]
async fn a_dead_session_during_the_sp_lookup_stops_the_run() {
    struct DeadSession;
    #[async_trait::async_trait]
    impl BearerProvider for DeadSession {
        async fn bearer(&self) -> Result<String, TokenError> {
            Err(TokenError::new("refresh_missing", "gone"))
        }
    }
    // Never answered: the token fails before any request is sent.
    let server = wiremock::MockServer::start().await;
    let ctx = graph_over(&server, Arc::new(DeadSession));

    let err = score_one(&ctx, &bare_app(), None)
        .await
        .expect_err("a dead session must surface, not score the app");
    // Swallowed to `None` before, this now stops the run for re-auth.
    assert_eq!(classify_audit_failure(&err), AuditFailure::SessionDead);
}

/// Rule 22 end-to-end at the command layer: the run's tenant-wide risky map
/// joins onto the app row by the SP's object id, and a risky AND unused SP
/// keeps exactly one DisableSignIn fix (the risky pass attaches it first; the
/// unused post-pass must not stack a second).
#[tokio::test]
async fn a_risky_sp_anchors_its_row_at_high_with_one_disable_fix() {
    let server = wiremock::MockServer::start().await;
    mock_sp_lookup(
        &server,
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "sp-1", "appId": "app-1", "accountEnabled": true}]
        })),
    )
    .await;
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.risky_available = true;
    ctx.risky_by_sp = Arc::new(HashMap::from([(
        "sp-1".to_string(),
        ("atRisk".to_string(), "high".to_string()),
    )]));
    // Old + never signed in: the unused post-pass runs too, so this pins the
    // dedupe as well as the join.
    let app = Application {
        created_date_time: Some(Utc::now() - chrono::Duration::days(400)),
        ..bare_app()
    };

    let item = score_one(&ctx, &app, Some(None)).await.expect("scores");
    assert!(item.unused, "the unused post-pass must have run");
    assert_eq!(item.sp_risk_state.as_deref(), Some("atRisk"));
    assert_eq!(item.sp_risk_level.as_deref(), Some("high"));
    assert!(
        item.issues
            .iter()
            .any(|i| i.starts_with(azapptoolkit_core::audit::issue::RISKY_SERVICE_PRINCIPAL)),
        "{:?}",
        item.issues
    );
    assert_eq!(
        item.remediations
            .iter()
            .filter(|r| r.kind == azapptoolkit_core::audit::RemediationKind::DisableSignIn)
            .count(),
        1,
        "a risky AND unused SP gets one Fix, not two"
    );
}

/// The `unavailable` half of the Rule 22 contract: when the report could not
/// be read, `risk_for` answers `None` even for a principal that IS in the
/// map — the run must not fire a security finding on an unchecked assumption.
#[tokio::test]
async fn risk_for_is_silent_while_the_report_is_unavailable() {
    // No request is ever made; the mock server just hosts the client.
    let server = wiremock::MockServer::start().await;
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.risky_by_sp = Arc::new(HashMap::from([(
        "sp-1".to_string(),
        ("confirmedCompromised".to_string(), "high".to_string()),
    )]));
    assert!(
        ctx.risk_for("sp-1").is_none(),
        "a present entry must not fire while risky_available is false"
    );
    ctx.risky_available = true;
    assert_eq!(ctx.risk_for("sp-1"), Some(("confirmedCompromised", "high")));
    assert!(ctx.risk_for("sp-absent").is_none());
}

/// F259 end-to-end at the command layer: the run's tenant-wide credential
/// report joins onto the app row per credential (`appId|keyId`), and only
/// positive evidence flags. Pins the three never-false-positive guards:
/// report unavailable ⇒ rule off; no report row ⇒ `Unknown`; expired ⇒ the
/// credential-expiry finding's job.
#[tokio::test]
async fn credential_usage_post_pass_flags_only_tracked_stale_credentials() {
    use azapptoolkit_core::audit::CredentialActivity;
    use azapptoolkit_core::models::PasswordCredential;

    const MARKER: &str = azapptoolkit_core::audit::issue::UNUSED_CREDENTIAL;
    let server = wiremock::MockServer::start().await;
    mock_sp_lookup(
        &server,
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []})),
    )
    .await;
    let now = Utc::now();
    let secret = |key: &str, end: Option<DateTime<Utc>>| PasswordCredential {
        key_id: key.into(),
        display_name: Some("ci".into()),
        // Older than the 90-day window, so this exercises the staleness rule,
        // not the "avoid flagging brand-new" age gate.
        start_date_time: Some(now - chrono::Duration::days(200)),
        end_date_time: end,
        ..Default::default()
    };
    let app_with = |creds: Vec<PasswordCredential>| Application {
        password_credentials: creds,
        ..bare_app()
    };
    let stale_secret = || {
        app_with(vec![secret(
            "k-stale",
            Some(now + chrono::Duration::days(30)),
        )])
    };

    // Control: the report was never read ⇒ rule off, evidence notwithstanding.
    let ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    let item = score_one(&ctx, &stale_secret(), None)
        .await
        .expect("scores");
    assert!(!item.issues.iter().any(|i| i.starts_with(MARKER)));

    // Tracked + last used 150 days ago ⇒ flagged, day count named.
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.credential_usage_available = true;
    ctx.credential_activity_map = Arc::new(HashMap::from([(
        "app-1|k-stale".to_string(),
        CredentialActivity::LastSeen(now - chrono::Duration::days(150)),
    )]));
    let item = score_one(&ctx, &stale_secret(), None)
        .await
        .expect("scores");
    let issue = item
        .issues
        .iter()
        .find(|i| i.starts_with(MARKER))
        .expect("a stale tracked credential flags");
    assert!(
        issue.contains("secret \"ci\" (last used 150 days ago)"),
        "{issue}"
    );

    // Absent from the report ⇒ `Unknown`. A live credential the preview
    // report simply doesn't surface must never be flagged "unused".
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.credential_usage_available = true;
    ctx.credential_activity_map = Arc::new(HashMap::from([(
        "app-1|other-key".to_string(),
        CredentialActivity::Never,
    )]));
    let item = score_one(&ctx, &stale_secret(), None)
        .await
        .expect("scores");
    assert!(!item.issues.iter().any(|i| i.starts_with(MARKER)));

    // Already expired ⇒ the credential-expiry finding covers it; no second
    // advisory line for the same credential.
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.credential_usage_available = true;
    ctx.credential_activity_map = Arc::new(HashMap::from([(
        "app-1|k-stale".to_string(),
        CredentialActivity::Never,
    )]));
    let expired = app_with(vec![secret(
        "k-stale",
        Some(now - chrono::Duration::days(5)),
    )]);
    let item = score_one(&ctx, &expired, None).await.expect("scores");
    assert!(!item.issues.iter().any(|i| i.starts_with(MARKER)));
}

/// F260+F270 at the scorer layer: the run's tenant-wide policy pair joins onto
/// the app per principal (an override assigned to the APP or its SP replaces
/// the default), and the result reaches the row as a *recommendation* only —
/// recommendation-only is the whole contract, so every no-verdict form is
/// checked end to end: policy unread, override without a cap, date-gate
/// grandfathering, and an unknowable multi-override combination.
#[tokio::test]
async fn secret_lifetime_advisory_is_recommendation_only_and_never_guesses() {
    use azapptoolkit_core::models::{
        AppManagementConfiguration, AppManagementPolicy, CredentialRestrictionConfiguration,
        PasswordCredential, TenantAppManagementPolicy,
    };

    let lifetime = |max: &str, gate: Option<DateTime<Utc>>| CredentialRestrictionConfiguration {
        restriction_type: Some("passwordLifetime".into()),
        state: Some("enabled".into()),
        max_lifetime: Some(max.into()),
        restrict_for_apps_created_after_date_time: gate,
    };
    let restrict = |caps: Vec<CredentialRestrictionConfiguration>| AppManagementConfiguration {
        password_credentials: caps,
        ..Default::default()
    };
    let now = Utc::now();
    let long_secret = || PasswordCredential {
        key_id: "k-long".into(),
        display_name: Some("long".into()),
        start_date_time: Some(now - chrono::Duration::days(200)),
        // Still valid — a past end date is the expiry finding's job, not this
        // advisory's.
        end_date_time: Some(now + chrono::Duration::days(20)),
        ..Default::default()
    };
    let app = |id: &str| Application {
        id: id.into(),
        created_date_time: Some(now - chrono::Duration::days(400)),
        password_credentials: vec![long_secret()],
        ..bare_app()
    };
    let marker = "Policy caps secret lifetimes";
    let no_sp =
        || wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({"value": []}));

    // Control: the policy read failed ⇒ no advisory at all. An unread policy
    // is unknown, never "no cap".
    let server = wiremock::MockServer::start().await;
    mock_sp_lookup(&server, no_sp()).await;
    let ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    let item = score_one(&ctx, &app("app-obj-1"), None)
        .await
        .expect("scores");
    assert!(
        item.recommendations.iter().all(|r| !r.contains(marker)),
        "an unread policy is unknown, never \"no cap\": {:?}",
        item.recommendations
    );

    // Tenant default cap 90 days, retroactive ⇒ the over-long secret advises…
    let default_90 = TenantAppManagementPolicy {
        id: "default".into(),
        display_name: None,
        is_enabled: true,
        application_restrictions: Some(restrict(vec![lifetime("P90D", None)])),
    };
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.app_policy_available = true;
    ctx.app_policy = Arc::new(AppPolicyData {
        default: Some(default_90.clone()),
        by_target: HashMap::new(),
    });
    let item = score_one(&ctx, &app("app-obj-1"), None)
        .await
        .expect("scores");
    let rec = item
        .recommendations
        .iter()
        .find(|r| r.starts_with(marker))
        .expect("the over-long secret is over the 90-day default cap");
    assert!(
        rec.contains("90 days") && rec.contains("secret \"long\" (220-day lifetime)"),
        "{rec}"
    );
    assert!(
        item.issues.iter().all(|i| !i.contains(marker)),
        "the advisory is recommendation-only: {:?}",
        item.issues
    );

    // …while an app predating a date gate is grandfathered out of the same
    // cap (gate 100 days ago, app created 400 days ago) ⇒ no verdict.
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.app_policy_available = true;
    ctx.app_policy = Arc::new(AppPolicyData {
        default: Some(TenantAppManagementPolicy {
            application_restrictions: Some(restrict(vec![lifetime(
                "P90D",
                Some(now - chrono::Duration::days(100)),
            )])),
            ..default_90.clone()
        }),
        by_target: HashMap::new(),
    });
    let item = score_one(&ctx, &app("app-obj-1"), None)
        .await
        .expect("scores");
    assert!(
        item.recommendations.iter().all(|r| !r.contains(marker)),
        "an app predating the gate is grandfathered: {:?}",
        item.recommendations
    );

    // A per-app override REPLACES the default — even one carrying no lifetime
    // rule of its own.
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.app_policy_available = true;
    ctx.app_policy = Arc::new(AppPolicyData {
        default: Some(default_90.clone()),
        by_target: HashMap::from([(
            "app-obj-1".to_string(),
            vec![AppManagementPolicy {
                id: "custom-bare".into(),
                display_name: "Bare".into(),
                is_enabled: true,
                restrictions: Some(restrict(Vec::new())),
                applies_to: vec![],
            }],
        )]),
    });
    let item = score_one(&ctx, &app("app-obj-1"), None)
        .await
        .expect("scores");
    assert!(
        item.recommendations.iter().all(|r| !r.contains(marker)),
        "an assigned override silences the default: {:?}",
        item.recommendations
    );

    // The override join also runs on the SP object id, and an enabled
    // override's own cap is the effective one (30 < 90).
    let server = wiremock::MockServer::start().await;
    mock_sp_lookup(
        &server,
        wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{"id": "sp-1", "appId": "app-1", "accountEnabled": true}]
        })),
    )
    .await;
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.app_policy_available = true;
    ctx.app_policy = Arc::new(AppPolicyData {
        default: Some(default_90.clone()),
        by_target: HashMap::from([(
            "sp-1".to_string(),
            vec![AppManagementPolicy {
                id: "custom-strict".into(),
                display_name: "Strict".into(),
                is_enabled: true,
                restrictions: Some(restrict(vec![lifetime("P30D", None)])),
                applies_to: vec![],
            }],
        )]),
    });
    let item = score_one(&ctx, &app("app-obj-1"), None)
        .await
        .expect("scores");
    let rec = item
        .recommendations
        .iter()
        .find(|r| r.starts_with(marker))
        .expect("the SP-assigned override caps this app at 30 days");
    assert!(rec.contains("30 days"), "{rec}");

    // Two overrides on one principal: the combination is unknowable, so the
    // whole advisory declines — never a guess at the stricter cap.
    let mut ctx = graph_over(&server, StaticTokenProvider::new("tok"));
    ctx.app_policy_available = true;
    ctx.app_policy = Arc::new(AppPolicyData {
        default: Some(default_90),
        by_target: HashMap::from([(
            "sp-1".to_string(),
            vec![
                AppManagementPolicy {
                    id: "custom-a".into(),
                    display_name: "A".into(),
                    is_enabled: true,
                    restrictions: Some(restrict(Vec::new())),
                    applies_to: vec![],
                },
                AppManagementPolicy {
                    id: "custom-b".into(),
                    display_name: "B".into(),
                    is_enabled: true,
                    restrictions: Some(restrict(vec![lifetime("P30D", None)])),
                    applies_to: vec![],
                },
            ],
        )]),
    });
    let item = score_one(&ctx, &app("app-obj-1"), None)
        .await
        .expect("scores");
    assert!(
        item.recommendations.iter().all(|r| !r.contains(marker)),
        "≥2 overrides read as no verdict: {:?}",
        item.recommendations
    );
}
