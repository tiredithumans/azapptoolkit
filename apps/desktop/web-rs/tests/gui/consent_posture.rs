//! GUI tests for the tenant consent-posture surface (F274): the grants-view
//! header Callout and the Home posture card's note.
//!
//! The posture read answers tenant *configuration*, and its whole contract is
//! "never flag on unknown": a tenant with self-consent on must warn (naming
//! the assigned policies, since whether each still allows what its name
//! implies is not knowable from the read); a tenant with self-consent
//! confirmed-off or with an unreadable policy pair must render NOTHING —
//! silence, not "all clear". These tests pin all three states on both
//! surfaces. The grants tests scope their "no Callout" assertions by text:
//! the grants fixture's permanent risky-scope banner is its own warn Callout,
//! so a blanket "no .alert anywhere" assertion would fail for reasons
//! unrelated to this feature.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::audit::CachedAuditSummary;
use azapptoolkit_dto::consent::TenantConsentPostureDto;
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::consent_grants_view::ConsentGrantsView;
use azapptoolkit_web_rs::views::home_dashboard::HomeDashboard;

fn posture(
    policies: Option<Vec<&str>>,
    risky: Option<bool>,
    acw: Option<bool>,
) -> TenantConsentPostureDto {
    TenantConsentPostureDto {
        available: true,
        risky_app_user_consent: risky,
        default_user_role_consent_policies: policies
            .map(|v| v.iter().map(|s| s.to_string()).collect()),
        admin_consent_workflow_enabled: acw,
    }
}

/// The legacy per-user consent policy — the real payload shape from the Learn
/// `authorizationPolicy` example response.
const LEGACY: &str = "ManagePermissionGrantsForSelf.microsoft-user-default-legacy";

fn alert_class(needle: &str) -> Option<String> {
    ts::query_all(".alert")
        .iter()
        .find(|e| e.text_content().unwrap_or_default().contains(needle))
        .map(|e| e.class_name())
}

/// Mount the grants view with the standard grant fixture + a given posture.
fn mount_grants(p: TenantConsentPostureDto) -> ts::Mounted {
    ts::mock_ok("list_oauth2_grants_audit", &fixtures::oauth2_grants());
    ts::mock_ok("get_tenant_consent_posture", &p);
    ts::mount_view(|| view! { <ConsentGrantsView /> })
}

/// Mount Home with the inventory + a cached summary (so "Scanned …" proves the
/// async settled) + a given posture. The posture note is its own Suspense
/// island; these tests read it, not the counts.
fn mount_home(p: TenantConsentPostureDto) -> ts::Mounted {
    ts::mock_ok(
        "list_applications_with_pairing",
        &fixtures::apps(&["Payroll API", "HR Sync"]),
    );
    ts::mock_ok(
        "list_enterprise_applications",
        &fixtures::enterprise_apps(&["Contoso CRM"]),
    );
    ts::mock_ok(
        "list_managed_identities",
        &fixtures::managed_identities(&["mi-build"]),
    );
    ts::mock_ok(
        "list_credential_expirations",
        &fixtures::credential_expirations(),
    );
    let summary = CachedAuditSummary::from_items(
        &fixtures::audit_run_result().items,
        Some(chrono::Utc::now().to_rfc3339()),
        false,
        None,
    );
    ts::mock_ok("get_cached_audit_summary", &Some(summary));
    ts::mock_ok("get_tenant_consent_posture", &p);
    ts::mount_view(|| view! { <HomeDashboard /> })
}

#[wasm_bindgen_test]
async fn grants_warn_when_user_consent_is_unrestricted() {
    ts::reset();
    let _m = mount_grants(posture(Some(vec![LEGACY]), Some(true), Some(false)));
    ts::wait_for(|| ts::body_contains("potentially self-granted")).await;
    let cls = alert_class("self-granted").expect("the posture note must be a Callout");
    assert!(
        cls.contains("alert--warn"),
        "unrestricted user consent is a risk, not a neutral fact: {cls}"
    );
    // The policy NAME is shown verbatim — the read cannot prove what the
    // policy still allows, so the operator gets the evidence, not a verdict.
    assert!(ts::body_contains(LEGACY));
    assert!(ts::body_contains(
        "This tenant also allows user consent for risky apps."
    ));
    let call = ts::last_call("get_tenant_consent_posture").expect("posture read");
    assert_eq!(call.arg_str("tenantId").as_deref(), Some("test-tenant"));
}

#[wasm_bindgen_test]
async fn grants_stay_silent_when_consent_is_confirmed_restricted() {
    ts::reset();
    // `Some(vec![])` is decidable: the tenant confirmed NO self-consent
    // policy. Silence here is the correct render — "restricted" is not a
    // finding, and a Callout per tenant would train operators to ignore it.
    let _m = mount_grants(posture(Some(vec![]), None, Some(true)));
    ts::wait_for(|| ts::query_all(".data-table tbody tr").len() == 4).await;
    ts::tick().await;
    assert!(
        !ts::body_contains("default user role"),
        "confirmed-restricted consent renders no posture note; body was: {}",
        ts::body_text()
    );
}

#[wasm_bindgen_test]
async fn grants_stay_silent_on_an_unreadable_policy_pair() {
    ts::reset();
    // `available: false` = the read pair failed or was unconsented. Unknown
    // must not become either verdict — this is the case the never-flag-on-
    // unknown contract exists for.
    let _m = mount_grants(TenantConsentPostureDto::default());
    ts::wait_for(|| ts::query_all(".data-table tbody tr").len() == 4).await;
    ts::tick().await;
    assert!(
        !ts::body_contains("self-granted") && !ts::body_contains("risky apps."),
        "unknown posture renders nothing; body was: {}",
        ts::body_text()
    );
}

#[wasm_bindgen_test]
async fn home_warns_when_user_consent_is_unrestricted() {
    ts::reset();
    let _m = mount_home(posture(Some(vec![LEGACY]), Some(true), Some(false)));
    ts::wait_for(|| ts::body_contains("delegated permissions to themselves")).await;
    let cls = alert_class("delegated permissions to themselves")
        .expect("the posture note renders through the Callout primitive");
    assert!(cls.contains("alert--warn"), "{cls}");
    assert!(ts::body_contains(
        "This tenant also allows user consent for risky apps."
    ));
    // The note must not displace the run-derived counts (independent reads).
    ts::wait_for(|| ts::body_contains("Scanned ")).await;
}

#[wasm_bindgen_test]
async fn home_states_the_restricted_facts_quietly() {
    ts::reset();
    let _m = mount_home(posture(Some(vec![]), None, Some(true)));
    ts::wait_for(|| ts::body_contains("User self-consent is off for the default user role.")).await;
    assert!(ts::body_contains("Admin consent workflow: on."));
    // Facts render as a muted line, NOT as a warn Callout — and the one
    // permanent Callout on this card belongs to other features.
    assert!(
        ts::query_all(".alert").iter().all(|e| !e
            .text_content()
            .unwrap_or_default()
            .contains("self-consent")),
        "restricted posture must not alarm; body was: {}",
        ts::body_text()
    );
}

#[wasm_bindgen_test]
async fn home_stays_silent_on_an_unknown_posture() {
    ts::reset();
    let _m = mount_home(TenantConsentPostureDto::default());
    // The summary anchor proves the async render pass settled; two ticks give
    // the posture island the same chance before the absence assertions.
    ts::wait_for(|| ts::body_contains("Scanned ")).await;
    ts::tick().await;
    ts::tick().await;
    assert!(
        !ts::body_contains("self-consent") && !ts::body_contains("risky apps."),
        "unknown posture renders nothing; body was: {}",
        ts::body_text()
    );
}
