//! GUI tests for the tenant-wide SSO certificate expiry board and its
//! bulk-stage bar.
//!
//! The board's whole reason to exist is telling an operator *which* apps are
//! about to break and which are already prepared. Two things carry that and are
//! pinned here: the per-row "replacement staged / nobody notified" columns, and
//! the summary after a bulk run reporting **staged** and **already prepared**
//! separately. Folding those two counts together would silently claim work that
//! never happened — the run would look like it prepared every app it touched.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::sso_certificates_dashboard::SsoCertificatesDashboard;

fn mount() -> ts::Mounted {
    ts::mock_ok(
        "list_sso_certificate_expirations",
        &fixtures::sso_certificate_rows(),
    );
    ts::mount_view(|| view! { <SsoCertificatesDashboard /> })
}

#[wasm_bindgen_test]
async fn the_board_flags_apps_with_no_replacement_and_nobody_notified() {
    ts::reset();
    let _m = mount();

    ts::wait_for(|| ts::body_contains("Contoso Payroll")).await;

    // The fixture's Payroll row expires in 15 days with nothing staged and no
    // notification recipients — the exact shape that becomes an outage.
    assert!(
        ts::body_contains("Nobody"),
        "an app with no expiry-notification recipients must say so; body: {}",
        ts::body_text()
    );
    assert!(
        ts::body_contains("Staged"),
        "the prepared app must be distinguishable from the unprepared one",
    );
    assert_eq!(
        ts::last_call("list_sso_certificate_expirations")
            .unwrap()
            .arg_str("tenantId")
            .as_deref(),
        Some("test-tenant")
    );
}

#[wasm_bindgen_test]
async fn selecting_the_queue_selects_only_the_unprepared_apps() {
    ts::reset();
    let _m = mount();
    ts::wait_for(|| ts::body_contains("Contoso Payroll")).await;

    // One row in the fixture is due within 30 days with nothing staged.
    ts::click(".sso-cert-queue-select");
    ts::wait_for(|| checked_boxes() == 1).await;

    assert_eq!(
        checked_boxes(),
        1,
        "the shortcut must select the work queue — the apps needing a \
         replacement — not every row on the board",
    );
}

#[wasm_bindgen_test]
async fn a_bulk_run_reports_staged_and_already_prepared_separately() {
    ts::reset();
    let _m = mount();
    ts::wait_for(|| ts::body_contains("Contoso Payroll")).await;

    // The fixture result: one staged, one skipped because it was already
    // prepared. Counting the skip as "staged" would overstate the run.
    ts::mock_ok(
        "bulk_stage_sso_certificates",
        &fixtures::bulk_stage_cert_result(),
    );

    ts::click(".sso-cert-queue-select");
    ts::wait_for(|| checked_boxes() == 1).await;

    // Arm the action, then confirm it (a plain click — staging is additive).
    ts::click(".bulk-action-bar button");
    ts::wait_for(|| ts::body_contains("Stage certificates")).await;
    ts::click(".bulk-action-bar__confirm button");

    ts::wait_for(|| ts::call_count("bulk_stage_sso_certificates") == 1).await;
    ts::wait_for(|| ts::body_contains("Staged a new signing certificate on 1")).await;

    assert!(
        ts::body_contains("1 already had one staged"),
        "an app skipped because it was already prepared must be reported \
         separately, not folded into the staged count; body: {}",
        ts::body_text()
    );
    assert!(
        ts::body_contains("Nothing has changed for users yet"),
        "the summary must say the certificates are inactive — a staged \
         certificate nobody activates is not a finished rollover",
    );
}

#[wasm_bindgen_test]
async fn the_board_refetches_after_a_bulk_run() {
    ts::reset();
    let _m = mount();
    ts::wait_for(|| ts::call_count("list_sso_certificate_expirations") == 1).await;

    ts::mock_ok(
        "bulk_stage_sso_certificates",
        &fixtures::bulk_stage_cert_result(),
    );
    ts::click(".sso-cert-queue-select");
    ts::wait_for(|| checked_boxes() == 1).await;
    ts::click(".bulk-action-bar button");
    ts::wait_for(|| ts::body_contains("Stage certificates")).await;
    ts::click(".bulk-action-bar__confirm button");

    // Without the lifted `reload`, the board would keep reporting "no
    // replacement staged" for apps it just staged one on.
    ts::wait_for(|| ts::call_count("list_sso_certificate_expirations") == 2).await;
}

/// How many row checkboxes are currently ticked.
fn checked_boxes() -> usize {
    ts::query_all(".row-select")
        .into_iter()
        .filter_map(|e| wasm_bindgen::JsCast::dyn_into::<web_sys::HtmlInputElement>(e).ok())
        .filter(web_sys::HtmlInputElement::checked)
        .count()
}
