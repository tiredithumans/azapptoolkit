//! GUI tests for the findings-first Security workbench: the worst-severity
//! ranking, the per-finding row Detail column, the Fix-all eligibility rule,
//! the group↔bulk-action pairing (the retired over-privileged→remove-redundant
//! mismatch), the per-row fix↔section pairing (a section offers its own rule's
//! Fix only, deep-links "Open" to its own tab, and applying one fix leaves the
//! others standing), the add-owner / disable-sign-in bulk flows, and the
//! Home-drill routing (severity → All apps pane, finding → expanded group).
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_core::audit::{
    AuditPrincipalKind, CredentialStatus, RemediationAction, RemediationKind, RiskLevel, issue,
};
use azapptoolkit_core::models::DirectoryObject;
use azapptoolkit_dto::audit::{AuditCoverageGap, AuditRunResult};
use azapptoolkit_dto::bulk::{
    BulkAddOwnerResult, BulkDisableOutcome, BulkDisableSignInResult, BulkOwnerOutcome,
};
use azapptoolkit_dto::exchange::{AapMigrationItem, AapMigrationReport};
use azapptoolkit_dto::remediation::RemediationOutcome;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::security_view::SecurityView;

/// A run exercising every behavior under test: ownership (impact 35, must
/// outrank expired's 8), one expired app, one unused app, an org-wide-mailbox
/// group holding an app row AND an SP-only row (Fix-all eligibility), one
/// redundant-permissions app, and one over-privileged (advisory) app.
fn cached_run() -> AuditRunResult {
    let mut owner_a = fixtures::audit_item(
        "No Owner App",
        RiskLevel::Critical,
        &[format!("{} x", issue::NO_OWNERS)],
    );
    owner_a.risk_score = 30;
    let mut owner_b = fixtures::audit_item(
        "Solo Owner App",
        RiskLevel::Low,
        &[format!("{} x", issue::SINGLE_OWNER)],
    );
    owner_b.risk_score = 5;

    let mut expired = fixtures::audit_item("Expired App", RiskLevel::Medium, &[]);
    expired.credential_status = CredentialStatus::Expired;
    expired.risk_score = 8;

    let mut unused = fixtures::audit_item("Idle App", RiskLevel::Low, &[]);
    unused.unused = true;
    unused.risk_score = 2;

    let mail_app = fixtures::audit_item(
        "Mail App",
        RiskLevel::Low,
        &[format!("{} Mail.Read", issue::ORG_WIDE_MAILBOX)],
    );
    let mut foreign_sp = fixtures::audit_item(
        "Foreign App",
        RiskLevel::Low,
        &[format!("{} Mail.ReadWrite", issue::ORG_WIDE_MAILBOX)],
    );
    foreign_sp.principal_kind = AuditPrincipalKind::ServicePrincipal;

    let redundant = fixtures::audit_item(
        "Redundant App",
        RiskLevel::Low,
        &[format!(
            "{} Mail.Read (covered by Mail.ReadWrite)",
            issue::REDUNDANT_APP_PERMS
        )],
    );
    let over = fixtures::audit_item(
        "Over App",
        RiskLevel::Low,
        &[format!("{} Mail.ReadWrite", issue::HIGH_RISK_APP_PERMS)],
    );
    // Confined by the deprecated policy: its own group, with the plan-first
    // migration Fix attached. It ALSO holds an expired credential, so it is
    // listed under two groups carrying two unrelated fixes — the cross-section
    // leakage `section_rows_offer_only_their_own_rules_fix` pins.
    let mut legacy = fixtures::audit_item(
        "Legacy Policy App",
        RiskLevel::Low,
        &[format!("{}: Mail.Read", issue::LEGACY_MAILBOX_POLICY)],
    );
    legacy.credential_status = CredentialStatus::Expired;
    legacy.remediations = vec![
        RemediationAction {
            kind: RemediationKind::MigrateApplicationAccessPolicy,
            label: "Migrate to RBAC for Applications".to_string(),
            detail: "Replaces the legacy policy confining 1 permission: Mail.Read".to_string(),
            targets: vec!["Mail.Read".to_string()],
        },
        RemediationAction {
            kind: RemediationKind::RemoveExpiredCredentials,
            label: "Remove 1 expired credential".to_string(),
            detail: "old-secret (expired 2024-01-01)".to_string(),
            targets: Vec::new(),
        },
    ];

    AuditRunResult {
        tenant_id: "tenant-1".to_string(),
        total_apps: 9,
        items: vec![
            owner_a, owner_b, expired, unused, mail_app, foreign_sp, redundant, over, legacy,
        ],
        cancelled: false,
        sign_in_report_available: true,
        sign_in_consent_required: false,
        truncated: false,
        degraded: Vec::new(),
        completed_at: None,
        mailbox_scoping_resolved: true,
    }
}

async fn mount_security() -> ts::Mounted {
    ts::reset();
    ts::mock_ok("get_cached_audit", &cached_run());
    let m = ts::mount_view(|| view! { <SecurityView /> });
    ts::wait_for(|| ts::body_contains("Missing or single owner")).await;
    m
}

/// Clicks the "Open" deep-link inside the row for `app_name`. Every row carries
/// one, so the label alone is ambiguous — scope the search to the row.
fn click_row_open(app_name: &str) {
    for row in ts::query_all("tbody tr") {
        if !row.text_content().unwrap_or_default().contains(app_name) {
            continue;
        }
        let buttons = row.query_selector_all("button").unwrap();
        for i in 0..buttons.length() {
            let el: web_sys::HtmlElement = buttons.item(i).unwrap().unchecked_into();
            if el.text_content().unwrap_or_default().trim() == "Open" {
                el.click();
                return;
            }
        }
    }
    panic!("no Open button in a row for `{app_name}`");
}

/// Groups rank by their OWN worst severity, then by how many principals they
/// affect, then by catalog order — never by Σ `risk_score` over their members,
/// which is every rule's score, not this one's. Ownership contributes no points
/// at all yet used to lead the workbench because unowned apps also hold risky
/// permissions and the rule matches a large slice of any tenant.
#[wasm_bindgen_test]
async fn groups_rank_by_worst_severity_then_count() {
    let _m = mount_security().await;
    // A complete run carries none of the coverage caveats — they are real-
    // failure surfaces, and showing one here would call a full scan partial.
    assert!(!ts::body_contains("cancelled early"));
    assert!(!ts::body_contains("arbitrary prefix"));
    assert!(!ts::body_contains("could not run"));
    let titles: Vec<String> = ts::query_all(".finding-group__title")
        .iter()
        .map(|el| el.text_content().unwrap_or_default())
        .collect();
    let pos = |t: &str| {
        titles
            .iter()
            .position(|x| x == t)
            .unwrap_or_else(|| panic!("group {t:?} not rendered: {titles:?}"))
    };
    // Ownership's worst is Critical, so it leads — as it did before, but now
    // for the right reason.
    assert!(pos("Missing or single owner") < pos("Expired credentials"));
    // The pin that flips: expired's worst is Medium against org-wide mailbox's
    // Low, even though the mailbox group's two members outscore expired's.
    assert!(
        pos("Expired credentials") < pos("Org-wide mailbox access"),
        "worst severity outranks the members' score sum: {titles:?}"
    );
    // Equal (Low) severity → the broader group first: 2 principals beats 1.
    assert!(pos("Org-wide mailbox access") < pos("Unused applications"));
    // Equal severity AND count → catalog order, which puts unused ahead of the
    // advisory over-privileged group despite unused scoring lower.
    assert!(
        pos("Unused applications") < pos("High-risk application permissions"),
        "catalog order is the final tie-break: {titles:?}"
    );
    assert!(ts::body_contains("2 principals"), "ownership count renders");
    // The severity tier is text, not colour alone — Critical and High resolve
    // to the same red dot.
    assert!(
        ts::query("[aria-label='Worst: Critical']").is_some(),
        "the worst-severity dot carries its tier as an accessible name"
    );
    // Every header is a disclosure with a real `"true"`/`"false"` state, and
    // its ▾/▸ glyph is hidden from the accessible name.
    let headers = ts::query_all(".finding-group__header");
    assert!(!headers.is_empty());
    for h in &headers {
        assert_eq!(
            h.get_attribute("aria-expanded").as_deref(),
            Some("false"),
            "collapsed header {:?}",
            h.text_content()
        );
    }
    for c in ts::query_all(".finding-group__chevron") {
        assert_eq!(c.get_attribute("aria-hidden").as_deref(), Some("true"));
    }
    // The healthy section trails as a collapsed disclosure; expanding it
    // reveals the positive groups even at zero count.
    assert!(!ts::body_contains("Mailbox access scoped"));
    ts::click(".finding-group__header--section");
    ts::wait_for(|| ts::body_contains("Mailbox access scoped")).await;
    assert_eq!(
        ts::query(".finding-group__header--section")
            .and_then(|h| h.get_attribute("aria-expanded"))
            .as_deref(),
        Some("true")
    );
}

/// An open group's header says so and points `aria-controls` at the body it
/// revealed; a collapsed one carries no `aria-controls` (its body is not in
/// the DOM, so the reference would dangle).
#[wasm_bindgen_test]
async fn an_open_group_header_is_expanded_and_controls_its_body() {
    let m = mount_security().await;
    let unused_header = || {
        ts::query_all(".finding-group__header")
            .into_iter()
            .find(|h| {
                h.query_selector(".finding-group__title")
                    .ok()
                    .flatten()
                    .and_then(|t| t.text_content())
                    .is_some_and(|t| t == "Unused applications")
            })
            .expect("Unused applications header")
    };
    assert_eq!(unused_header().get_attribute("aria-controls"), None);

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("unused".to_string()));
    ts::wait_for(|| ts::query(".finding-group__body").is_some()).await;

    let header = unused_header();
    assert_eq!(
        header.get_attribute("aria-expanded").as_deref(),
        Some("true")
    );
    let body_id = ts::query(".finding-group__body")
        .and_then(|b| b.get_attribute("id"))
        .expect("the open body carries an id");
    assert_eq!(body_id, "finding-group-body-unused");
    assert_eq!(
        header.get_attribute("aria-controls").as_deref(),
        Some(body_id.as_str())
    );
}

/// Trimmed text of the posture strip — the coverage caveats' one home, above
/// both audit panes. Scoped to it because `body_contains` also sees the
/// keep-alive-hidden panes.
fn strip_text() -> String {
    ts::query(".posture-strip")
        .and_then(|el| el.text_content())
        .unwrap_or_default()
}

/// A partial run must say so above everything it computed, whichever pane is
/// showing — including when it DID find problems, which is exactly when the
/// counts and every "Fix all N" look like a full scan. Cancelled, truncated and
/// degraded are independent, so all three render together.
#[wasm_bindgen_test]
async fn partial_runs_are_marked_on_the_strip_above_both_panes() {
    ts::reset();
    ts::mock_ok(
        "get_cached_audit",
        &AuditRunResult {
            cancelled: true,
            truncated: true,
            total_apps: 20,
            degraded: vec![AuditCoverageGap::PerPrincipalScoring],
            ..cached_run()
        },
    );
    let m = ts::mount_view(|| view! { <SecurityView /> });
    // Findings still render — the caveats qualify them, never replace them.
    ts::wait_for(|| ts::body_contains("Missing or single owner")).await;
    let strip = strip_text();
    assert!(
        strip.contains("This scan was cancelled early — 9 of 20 principals were scored"),
        "{strip}"
    );
    assert!(strip.contains("covered an arbitrary prefix"), "{strip}");
    assert!(strip.contains("Part of this scan could not run"), "{strip}");
    assert!(
        strip.contains(AuditCoverageGap::PerPrincipalScoring.description()),
        "each gap is listed under the lede: {strip}"
    );

    // The strip sits above the tab bar, so the All-apps pane carries the same
    // caveats (it rendered none of them before).
    m.session.open_security("apps");
    ts::wait_for(|| ts::query(".audit-apps-pane").is_some()).await;
    let strip = strip_text();
    assert!(strip.contains("arbitrary prefix"), "{strip}");
    assert!(strip.contains("could not run"), "{strip}");
}

/// A truncated scan that found nothing scored only a prefix of the tenant, so
/// the empty Findings pane must qualify itself instead of declaring all-clear.
#[wasm_bindgen_test]
async fn truncated_run_without_findings_is_not_an_all_clear() {
    ts::reset();
    ts::mock_ok(
        "get_cached_audit",
        &AuditRunResult {
            truncated: true,
            items: vec![fixtures::audit_item("Clean App", RiskLevel::Low, &[])],
            total_apps: 1,
            ..cached_run()
        },
    );
    let _m = ts::mount_view(|| view! { <SecurityView /> });
    ts::wait_for(|| {
        ts::body_contains("No actionable findings among the applications this scan reached")
    })
    .await;
    assert!(!ts::body_contains("nothing to fix right now"));
    assert!(strip_text().contains("arbitrary prefix"));
}

/// Org-wide reach the toolkit can't confine is scored, so it must be visible
/// on the findings-first pane: two advisory groups (the legacy-resource advice
/// differs from the rest), no bulk Fix, and never folded into the fixable
/// org-wide mailbox group whose Fix could not apply to them.
#[wasm_bindgen_test]
async fn unconfinable_reach_lands_in_advisory_groups() {
    ts::reset();
    let mut run = cached_run();
    run.items.extend([
        fixtures::audit_item(
            "Legacy EXO App",
            RiskLevel::Medium,
            &[format!("{}: Mail.Read", issue::UNSCOPABLE_LEGACY_MAILBOX)],
        ),
        fixtures::audit_item(
            "Unmapped Mail App",
            RiskLevel::Medium,
            &[format!(
                "{}: Mail.ReadWrite.Shared",
                issue::UNCONFINABLE_MAILBOX
            )],
        ),
        fixtures::audit_item(
            "SPO Legacy App",
            RiskLevel::High,
            &[format!(
                "{}: Sites.Read.All",
                issue::UNCONFINABLE_SHAREPOINT
            )],
        ),
    ]);
    run.total_apps = run.items.len();
    ts::mock_ok("get_cached_audit", &run);
    let m = ts::mount_view(|| view! { <SecurityView /> });
    ts::wait_for(|| ts::body_contains("Legacy Exchange Online mailbox grants")).await;
    let titles: Vec<String> = ts::query_all(".finding-group__title")
        .iter()
        .map(|el| el.text_content().unwrap_or_default())
        .collect();
    assert!(
        titles.contains(&"Org-wide access that can't be confined here".to_string()),
        "{titles:?}"
    );
    // The fixable group keeps exactly its own two members.
    let mailbox_header = ts::query_all(".finding-group__header")
        .iter()
        .map(|el| el.text_content().unwrap_or_default())
        .find(|t| t.starts_with("Org-wide mailbox access"))
        .expect("org-wide mailbox group renders");
    assert!(mailbox_header.contains("2 principals"), "{mailbox_header}");

    let details = || -> Vec<String> {
        ts::query_all(".finding-group__detail")
            .iter()
            .map(|el| el.text_content().unwrap_or_default())
            .collect()
    };
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("unconfinable_orgwide".to_string()));
    ts::wait_for(|| ts::query(".finding-group__detail").is_some()).await;
    let d = details();
    assert!(
        d.iter().any(|x| x.contains("Mail.ReadWrite.Shared")),
        "{d:?}"
    );
    assert!(d.iter().any(|x| x.contains("Sites.Read.All")), "{d:?}");
    assert!(
        !ts::query_all("button").iter().any(|b| b
            .text_content()
            .unwrap_or_default()
            .trim()
            .starts_with("Fix all")),
        "an advisory group offers no bulk Fix"
    );

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("unscopable_legacy_mailbox".to_string()));
    ts::wait_for(|| {
        details()
            .iter()
            .any(|x| x.contains("Unscopable legacy Exchange"))
    })
    .await;
    let d = details();
    assert_eq!(d.len(), 1, "{d:?}");
    assert!(d[0].contains("Mail.Read"), "{d:?}");
}

/// A pane grouped BY finding has to say what the finding is: the row quotes the
/// issue line(s) that put it in this group, and only those. Before this the
/// grouped, remediation-focused pane showed strictly less finding detail than
/// the ungrouped All-apps table beside it.
#[wasm_bindgen_test]
async fn group_rows_quote_their_own_findings_issue_line() {
    let m = mount_security().await;
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("orgwide_mailbox".to_string()));
    ts::wait_for(|| ts::query(".finding-group__detail").is_some()).await;
    let details: Vec<String> = ts::query_all(".finding-group__detail")
        .iter()
        .map(|el| el.text_content().unwrap_or_default())
        .collect();
    assert!(
        details.iter().any(|d| d.contains("Mail.Read")),
        "the org-wide mailbox row names the permission that is org-wide: {details:?}"
    );
    assert!(
        details.iter().any(|d| d.contains("Mail.ReadWrite")),
        "…for the SP-only row too: {details:?}"
    );

    // A row listed under several groups quotes the line for the group it is
    // being shown in: the Legacy Policy App is in this section AND in Expired
    // credentials, and the cell must speak for this one.
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("legacy_mailbox_scope".to_string()));
    ts::wait_for(|| {
        ts::query(".finding-group__detail")
            .and_then(|el| el.text_content())
            .is_some_and(|t| t.contains("legacy Application Access Policy"))
    })
    .await;

    // Last sign-in is the unused rule's evidence and dead weight everywhere
    // else, so only that group spends a column on it. Scope the header query to
    // this pane — the All-apps pane stays keep-alive-mounted (display:none) with
    // its own "Last sign-in" column still in the DOM.
    assert!(
        !findings_headers().contains(&"Last sign-in".to_string()),
        "the legacy-scoping group drops the sign-in column: {:?}",
        findings_headers()
    );
    assert!(findings_headers().contains(&"Detail".to_string()));
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("unused".to_string()));
    ts::wait_for(|| findings_headers().contains(&"Last sign-in".to_string())).await;
}

/// The column headers of the one expanded Findings group.
fn findings_headers() -> Vec<String> {
    ts::query_all(".findings-pane th")
        .iter()
        .map(|el| el.text_content().unwrap_or_default())
        .collect()
}

// A run that couldn't check mail permissions against Exchange scored them all
// org-wide: the group has to say its findings may already be confined, with
// the same sentence the export carries.
#[wasm_bindgen_test]
async fn org_wide_mailbox_group_says_when_scoping_was_unresolved() {
    ts::reset();
    let run = AuditRunResult {
        mailbox_scoping_resolved: false,
        ..cached_run()
    };
    ts::mock_ok("get_cached_audit", &run);
    let m = ts::mount_view(|| view! { <SecurityView /> });
    ts::wait_for(|| ts::body_contains("Missing or single owner")).await;
    // Collapsed, the caveat stays with the group it qualifies.
    assert!(!ts::body_contains("Mailbox scoping could not be resolved"));
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("orgwide_mailbox".to_string()));
    ts::wait_for(|| ts::body_contains("Mailbox scoping could not be resolved")).await;
    assert!(ts::body_contains(
        azapptoolkit_dto::audit::MAILBOX_SCOPING_UNRESOLVED
    ));
}

#[wasm_bindgen_test]
async fn fix_all_selects_only_application_rows() {
    let m = mount_security().await;
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("orgwide_mailbox".to_string()));
    ts::wait_for(|| ts::body_contains("Fix all 1")).await;
    // A run that resolved mailbox scoping carries no scoping caveat.
    assert!(!ts::body_contains("Mailbox scoping could not be resolved"));
    // The group holds 2 principals (app + SP) but only the app registration is
    // bulk-eligible — Fix all must seed exactly it.
    ts::click_button_labelled("Fix all 1");
    ts::wait_for(|| {
        !m.session
            .tenant_ui
            .selected_audit_ids
            .get_untracked()
            .is_empty()
    })
    .await;
    let selected = m.session.tenant_ui.selected_audit_ids.get_untracked();
    assert!(selected.contains("obj-Mail App"));
    assert!(
        !selected.contains("obj-Foreign App"),
        "SP rows must never enter the selection via Fix all"
    );
    assert_eq!(selected.len(), 1);
}

#[wasm_bindgen_test]
async fn group_bar_pairs_each_fix_with_its_own_rule() {
    let m = mount_security().await;
    // The redundant-permissions group offers RemoveRedundant…
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("redundant_perms".to_string()));
    ts::wait_for(|| ts::body_contains("Fix all 1")).await;
    ts::click_button_labelled("Fix all 1");
    ts::wait_for(|| ts::body_contains("Remove redundant permissions")).await;

    // …but the over-privileged (advisory) group must NOT — the old
    // audit_bulk_actions mapped a different rule's fix here.
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("high_risk_perms".to_string()));
    ts::wait_for(|| !ts::body_contains("Remove redundant permissions")).await;
    assert!(
        m.session
            .tenant_ui
            .selected_audit_ids
            .get_untracked()
            .is_empty(),
        "switching groups clears the shared selection"
    );
    // Selecting its row offers no bulk bar actions (advisory group).
    let checkbox: web_sys::HtmlElement = ts::query_all("tbody input[type=checkbox]")
        .into_iter()
        .next()
        .expect("advisory group rows are still visible with checkboxes")
        .unchecked_into();
    checkbox.click();
    ts::wait_for(|| {
        !m.session
            .tenant_ui
            .selected_audit_ids
            .get_untracked()
            .is_empty()
    })
    .await;
    assert!(
        !ts::body_contains("Remove redundant permissions"),
        "no cross-rule fix is offered on the advisory group"
    );
}

#[wasm_bindgen_test]
async fn bulk_add_owner_flow_sends_the_picked_principal() {
    let m = mount_security().await;
    ts::mock_ok(
        "search_users",
        &vec![DirectoryObject {
            id: "user-1".to_string(),
            display_name: Some("Dana Admin".to_string()),
            user_principal_name: Some("dana@contoso.com".to_string()),
            mail: None,
            odata_type: Some("#microsoft.graph.user".to_string()),
        }],
    );
    ts::mock_ok(
        "bulk_add_owner",
        &BulkAddOwnerResult {
            outcomes: vec![
                BulkOwnerOutcome {
                    object_id: "obj-No Owner App".to_string(),
                    added: true,
                    skipped: false,
                    error: None,
                },
                BulkOwnerOutcome {
                    object_id: "obj-Solo Owner App".to_string(),
                    added: true,
                    skipped: false,
                    error: None,
                },
            ],
            cancelled: false,
        },
    );

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("ownership".to_string()));
    ts::wait_for(|| ts::body_contains("Fix all 2")).await;
    ts::click_button_labelled("Fix all 2");
    // A button wait, not a body-text one: group blurbs can mention an action's
    // name before the bulk bar's button renders.
    ts::wait_for(|| ts::has_button_labelled("Add owner")).await;
    ts::click_button_labelled("Add owner");
    ts::wait_for(|| ts::query(".bulk-action-bar__confirm input").is_some()).await;
    ts::set_input_value(".bulk-action-bar__confirm input", "dana");
    ts::wait_for(|| ts::query(".add-owner-candidates button").is_some()).await;
    ts::click(".add-owner-candidates button");
    ts::wait_for(|| ts::body_contains("Adding:")).await;
    // Scoped to the armed panel: its confirm shares its label with the bar's
    // action button.
    ts::click_button_labelled_in(".bulk-action-bar__confirm", "Add owner");
    ts::wait_for(|| ts::call_count("bulk_add_owner") == 1).await;

    let call = ts::last_call("bulk_add_owner").unwrap();
    assert_eq!(
        call.args.get("principalId").and_then(|v| v.as_str()),
        Some("user-1")
    );
    assert_eq!(
        call.args
            .get("objectIds")
            .and_then(|v| v.as_array())
            .map(|a| a.len()),
        Some(2)
    );
}

#[wasm_bindgen_test]
async fn bulk_disable_sign_in_flow_runs_on_the_unused_group() {
    let m = mount_security().await;
    ts::mock_ok(
        "bulk_disable_sign_in",
        &BulkDisableSignInResult {
            outcomes: vec![BulkDisableOutcome {
                object_id: "obj-Idle App".to_string(),
                error: None,
            }],
            cancelled: false,
        },
    );

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("unused".to_string()));
    ts::wait_for(|| ts::body_contains("Fix all 1")).await;
    ts::click_button_labelled("Fix all 1");
    ts::wait_for(|| ts::has_button_labelled("Disable sign-in")).await;
    ts::click_button_labelled("Disable sign-in");
    // Reversible ⇒ plain confirm panel (no typed keyword).
    ts::wait_for(|| ts::query(".bulk-action-bar__confirm").is_some()).await;
    ts::click_button_labelled_in(".bulk-action-bar__confirm", "Disable sign-in");
    ts::wait_for(|| ts::call_count("bulk_disable_sign_in") == 1).await;

    let call = ts::last_call("bulk_disable_sign_in").unwrap();
    assert_eq!(
        call.args
            .get("objectIds")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str()),
        Some("obj-Idle App")
    );
}

/// The legacy-policy migration Fix is plan-first: opening it must run a **dry
/// run** and refuse to commit until that plan has come back. A modal that
/// committed on the first click would perform an Exchange scope build + Entra
/// grant strip before the operator ever saw which mailboxes it covers.
#[wasm_bindgen_test]
async fn legacy_policy_fix_plans_before_it_migrates() {
    let m = mount_security().await;
    ts::mock_ok(
        "migrate_application_access_policies",
        &AapMigrationReport {
            dry_run: true,
            incomplete: false,
            unattempted: Vec::new(),
            items: vec![AapMigrationItem {
                app_id: "Legacy Policy App-appid".to_string(),
                source_policy_identities: vec!["policy-1".to_string()],
                scope_name: Some("app_scope_Legacy Policy App-appid".to_string()),
                scope_filter: Some("MemberOfGroup -eq 'CN=Sales'".to_string()),
                managed_group_name: Some("app_scope_group_Legacy Policy App-appid".to_string()),
                members_copied: vec!["ada@contoso.com".to_string()],
                members_unverified: Vec::new(),
                roles_assigned: vec!["Application Mail.Read".to_string()],
                removed_entra_grants: vec!["Mail.Read".to_string()],
                removed_policies: vec!["policy-1".to_string()],
                retired_groups: Vec::new(),
                status: "planned".to_string(),
                warnings: Vec::new(),
            }],
            failures: Vec::new(),
        },
    );

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("legacy_mailbox_scope".to_string()));
    ts::wait_for(|| ts::has_button_labelled("Migrate to RBAC for Applications")).await;
    ts::click_button_labelled("Migrate to RBAC for Applications");

    // Opening the modal plans; nothing is committed yet.
    ts::wait_for(|| ts::call_count("migrate_application_access_policies") == 1).await;
    let plan = ts::last_call("migrate_application_access_policies").unwrap();
    assert_eq!(
        plan.args.get("dryRun").and_then(|v| v.as_bool()),
        Some(true)
    );
    // Keyed on the appId (what a policy names), not the audit row's object id.
    assert_eq!(
        plan.arg_str("appId").as_deref(),
        Some("Legacy Policy App-appid")
    );
    ts::wait_for(|| ts::body_contains("Nothing has changed yet")).await;

    // Committing sends the same call with dry_run cleared.
    ts::click_button_labelled("Migrate");
    ts::wait_for(|| ts::call_count("migrate_application_access_policies") == 2).await;
    let commit = ts::last_call("migrate_application_access_policies").unwrap();
    assert_eq!(
        commit.args.get("dryRun").and_then(|v| v.as_bool()),
        Some(false)
    );
}

/// A section shows "Open" plus the Fix for **its own** rule and nothing else.
/// The Legacy-policy app also holds an expired credential, so before the
/// `kinds` gate its row rendered "Remove 1 expired credential" inside the
/// legacy-policy section — an action with nothing to do with the finding the
/// operator opened that section for.
#[wasm_bindgen_test]
async fn section_rows_offer_only_their_own_rules_fix() {
    let m = mount_security().await;
    let expand = |key: &str| {
        m.session
            .tenant_ui
            .audit_expanded_group
            .set(Some(key.to_string()))
    };

    expand("legacy_mailbox_scope");
    ts::wait_for(|| ts::has_button_labelled("Migrate to RBAC for Applications")).await;
    assert!(
        !ts::has_button_labelled("Remove 1 expired credential"),
        "the legacy-policy section must not offer the credential fix"
    );

    // …and symmetrically: the expired section owns the credential fix only.
    expand("expired");
    ts::wait_for(|| ts::has_button_labelled("Remove 1 expired credential")).await;
    assert!(
        !ts::has_button_labelled("Migrate to RBAC for Applications"),
        "the expired-credentials section must not offer the migration fix"
    );
}

/// "Open" lands on the tab for the section it was clicked in. The Legacy Policy
/// App trips both the legacy-scoping rule and the expired-credential one, and
/// the item-wide scan ranks scoping first — so from Expired credentials, Open
/// used to drop the operator on Permissions.
#[wasm_bindgen_test]
async fn open_deep_links_to_the_section_it_was_clicked_in() {
    let m = mount_security().await;
    let tab = || m.session.tenant_ui.pending_app_tab.get_untracked();

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("expired".to_string()));
    ts::wait_for(|| ts::has_button_labelled("Remove 1 expired credential")).await;
    click_row_open("Legacy Policy App");
    assert_eq!(tab().as_deref(), Some("credentials"));
    // What the mounted detail pane does: consume the tab once. (The harness
    // mounts no workspace pane, so the test plays its part.)
    m.session.tenant_ui.pending_app_tab.set(None);

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("legacy_mailbox_scope".to_string()));
    ts::wait_for(|| ts::has_button_labelled("Migrate to RBAC for Applications")).await;
    // The app is still open: it keeps its live tab, and no pane mounts to
    // consume a queued one — queuing it would land the NEXT app on it.
    click_row_open("Legacy Policy App");
    assert_eq!(
        tab(),
        None,
        "an already-open app must not queue a tab for the next app"
    );

    // Closed again, Open from this section lands on Permissions.
    m.session.close_all_items();
    click_row_open("Legacy Policy App");
    assert_eq!(tab().as_deref(), Some("permissions"));
}

/// Applying one section's Fix clears **that** remediation only. Clearing the
/// row's whole set made the credential fix take the legacy-policy section's
/// migration button with it — the operator's next stop vanished, with nothing
/// short of a full re-run to bring it back.
#[wasm_bindgen_test]
async fn applying_one_fix_leaves_the_other_sections_fix_standing() {
    let m = mount_security().await;
    ts::mock_ok(
        "remediate_remove_expired_credentials",
        &RemediationOutcome {
            removed_secrets: 1,
            removed_certificates: 0,
        },
    );

    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("expired".to_string()));
    ts::wait_for(|| ts::has_button_labelled("Remove 1 expired credential")).await;
    ts::click_button_labelled("Remove 1 expired credential");
    ts::wait_for(|| ts::body_contains("Remove expired credentials?")).await;
    // The modal covers the row it was opened from, so it has to name what it
    // will remove — a static body describing the *kind* of change left the
    // operator trusting that the button they clicked belonged to the row they
    // meant.
    assert_eq!(
        ts::query(".confirm-dialog__subject")
            .and_then(|el| el.text_content())
            .as_deref(),
        Some("old-secret (expired 2024-01-01)")
    );
    ts::click_button_labelled("Remove");
    ts::wait_for(|| ts::call_count("remediate_remove_expired_credentials") == 1).await;
    // The applied fix is gone for good.
    ts::wait_for(|| !ts::has_button_labelled("Remove 1 expired credential")).await;

    // The legacy-policy section still offers the migration nobody has run.
    m.session
        .tenant_ui
        .audit_expanded_group
        .set(Some("legacy_mailbox_scope".to_string()));
    ts::wait_for(|| ts::has_button_labelled("Migrate to RBAC for Applications")).await;
}

#[wasm_bindgen_test]
async fn home_drills_route_severity_to_apps_and_findings_to_groups() {
    let m = mount_security().await;
    // Finding drill → Findings pane with the group expanded.
    m.session.open_posture_with_facet("ownership");
    assert_eq!(m.session.security_tab.get_untracked(), "findings");
    assert_eq!(
        m.session
            .tenant_ui
            .audit_expanded_group
            .get_untracked()
            .as_deref(),
        Some("ownership")
    );
    ts::wait_for(|| ts::body_contains("Adding an owner is purely additive")).await;

    // Severity drill → All apps pane with the severity filter seeded. Scope
    // queries to the apps pane — the findings pane stays keep-alive-mounted
    // (display:none) with its own tables still in the DOM.
    m.session.open_posture_with_facet("critical");
    assert_eq!(m.session.security_tab.get_untracked(), "apps");
    assert_eq!(
        m.session.tenant_ui.audit_severity.get_untracked(),
        "critical"
    );
    ts::wait_for(|| {
        ts::query_all(".audit-apps-pane tbody tr").iter().any(|r| {
            r.text_content()
                .unwrap_or_default()
                .contains("No Owner App")
        })
    })
    .await;
    // The severity filter narrows the table to the one Critical row.
    assert_eq!(
        ts::query_all(".audit-apps-pane tbody tr").len(),
        1,
        "only the Critical row survives the drill filter"
    );
}
