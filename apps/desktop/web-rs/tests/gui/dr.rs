//! GUI tests for the Disaster Recovery view.
//!
//! Two halves, and the second was missing entirely. Backup progress renders
//! from streamed `backup-progress` events, with a rate-limit back-off notice
//! once the adaptive concurrency cap drops below its observed peak.
//!
//! The RESTORE half had no coverage at all — the riskiest path in the app, the
//! one flow that both reads and writes a whole tenant, and the only one whose
//! partial outcome is irreversible. What that leaves untested is not the happy
//! path but the reporting of a run that stopped: a restore which cancelled or
//! whose session died has already created N applications, and the report is the
//! operator's only record of which ones. Presenting that as a completed restore
//! is the failure mode the backend's `cancelled` / `session_expired` pair
//! exists to prevent, and nothing checked that the view honoured it.
#![cfg(target_arch = "wasm32")]

use leptos::prelude::*;
use wasm_bindgen_test::*;

use azapptoolkit_dto::backup::{RestorePlan, RestoreReport, TenantBackup};
use azapptoolkit_web_rs::test_support::{self as ts, fixtures};
use azapptoolkit_web_rs::views::dr::DisasterRecoveryView;

#[wasm_bindgen_test]
async fn backup_progress_renders_count_and_throttle_notice() {
    ts::reset();
    let _m = ts::mount_view(|| view! { <DisasterRecoveryView /> });
    // Let `use_progress_stream` register its listener before we emit.
    ts::tick().await;
    ts::tick().await;

    // Healthy cap: the readout shows count + live concurrency, no back-off notice.
    ts::emit_event("backup-progress", &fixtures::backup_progress(2, 10, 4));
    ts::wait_for(|| ts::body_contains("Captured 2/10")).await;
    assert!(ts::body_contains("4 concurrent"));
    assert!(
        ts::query(".dr-view__notice").is_none(),
        "no back-off notice while the cap is at its peak"
    );

    // The cap drops below the peak → Graph is throttling → the notice appears.
    ts::emit_event("backup-progress", &fixtures::backup_progress(4, 10, 2));
    ts::wait_for(|| ts::query(".dr-view__notice").is_some()).await;
    assert!(ts::body_contains("2 concurrent"));
}

/// A minimal manifest — the view only passes it back to `restore_tenant`.
fn backup() -> TenantBackup {
    TenantBackup {
        schema_version: 1,
        created_at: chrono::Utc::now(),
        source_tenant_id: "source-tenant".to_string(),
        cloud: "Commercial".to_string(),
        app_registrations: Vec::new(),
        enterprise_apps: Vec::new(),
        managed_identities: Vec::new(),
        skipped: Vec::new(),
    }
}

fn plan() -> RestorePlan {
    RestorePlan {
        cloud_mismatch: None,
        tenant_changed: true,
        source_tenant_id: "source-tenant".to_string(),
        destination_tenant_id: "test-tenant".to_string(),
        app_registrations_to_create: 2,
        secrets_to_regenerate: 0,
        certificates_needing_manual_upload: 0,
        federated_credentials_to_restore: 0,
        owners_to_remap: 0,
    }
}

/// Drives Load file → confirm → Restore, with `restore_tenant` answering
/// `report`.
async fn run_restore(report: RestoreReport) -> ts::Mounted {
    ts::reset();
    ts::mock_ok("load_backup_from_file", &Some(backup()));
    ts::mock_ok("plan_restore", &plan());
    ts::mock_ok("restore_tenant", &report);

    let m = ts::mount_view(|| view! { <DisasterRecoveryView /> });
    ts::tick().await;

    click_button("Load backup file…");
    // The plan lands before the restore button is offered.
    ts::wait_for(|| has_button("Restore into this tenant…")).await;
    click_button("Restore into this tenant…");
    // The confirm dialog's own "Restore" is the one that fires the command.
    ts::wait_for(|| has_button("Restore")).await;
    click_button("Restore");
    ts::wait_for(|| ts::query(".dr-view__result").is_some()).await;
    m
}

fn has_button(label: &str) -> bool {
    ts::query_all("button")
        .iter()
        .any(|el| el.text_content().unwrap_or_default().trim() == label)
}

fn click_button(label: &str) {
    use wasm_bindgen::JsCast;
    for el in ts::query_all("button") {
        if el.text_content().unwrap_or_default().trim() == label {
            let el: web_sys::HtmlElement = el.unchecked_into();
            el.click();
            return;
        }
    }
    panic!("no button labelled `{label}`");
}

/// A completed restore reads as completed — and says nothing about stopping.
#[wasm_bindgen_test]
async fn a_completed_restore_carries_no_partial_wording() {
    let _m = run_restore(RestoreReport::default()).await;
    let body = ts::body_text();
    assert!(
        !body.contains("cancelled before completing") && !body.contains("session expired"),
        "a clean run must not be described as stopped: {body}"
    );
}

/// A CANCELLED restore is never presented as a completed one.
///
/// The apps it did create are real and wired; the ones it never reached do not
/// exist. Only the summary line distinguishes the two, so this pins its wording
/// rather than merely that a report rendered.
#[wasm_bindgen_test]
async fn a_cancelled_restore_says_it_stopped_partway() {
    let _m = run_restore(RestoreReport {
        cancelled: true,
        ..Default::default()
    })
    .await;
    assert!(
        ts::body_contains("cancelled before completing"),
        "a cancelled restore must say so: {}",
        ts::body_text()
    );
    // A plain cancel is resumable as-is, so it must NOT raise the
    // re-authenticate callout — that is the expired-session remedy.
    assert!(
        !ts::body_contains("Re-authenticate and run the restore again"),
        "a cancel is not a dead session"
    );
}

/// A restore stopped by a DEAD SESSION says so, and says what to do next.
///
/// `cancelled` is set for both cases; `session_expired` is the only thing that
/// tells them apart, and the operator's next action differs — a cancel is
/// resumable as-is, an expired session means re-authenticating first. The
/// backend has always set this flag; the point of the callout is that the view
/// reads it.
#[wasm_bindgen_test]
async fn an_expired_session_during_restore_asks_for_re_authentication() {
    let _m = run_restore(RestoreReport {
        cancelled: true,
        session_expired: true,
        ..Default::default()
    })
    .await;
    let body = ts::body_text();
    assert!(
        body.contains("the sign-in session expired"),
        "the summary must name the expired session, not just 'partial': {body}"
    );
    assert!(
        body.contains("Re-authenticate and run the restore again"),
        "the operator needs the remedy, not only the diagnosis: {body}"
    );
}
