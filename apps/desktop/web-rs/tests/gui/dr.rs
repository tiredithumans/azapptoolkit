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
use wasm_bindgen::JsCast;
use wasm_bindgen_test::*;

use azapptoolkit_dto::backup::{
    PermissionRisk, PlannedFederatedCredential, PrivilegedKind, PrivilegedPermission,
    PrivilegedRestoreItem, RestorePlan, RestoreReport, RestoredApp, SchemaTooNew, SkippedObject,
    TenantBackup,
};
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
        cloud: azapptoolkit_core::cloud::CloudEnvironment::Commercial,
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
        expired_secrets_skipped: 0,
        certificates_needing_manual_upload: 0,
        federated_credentials_to_restore: 0,
        owners_to_remap: 0,
        ..Default::default()
    }
}

/// Mocks Load file → `plan_restore` answering `p`, mounts the view, and waits
/// for the plan to render. `ts::reset()` is the caller's to have done.
async fn load_plan(p: RestorePlan) -> ts::Mounted {
    ts::mock_ok("load_backup_from_file", &Some(backup()));
    ts::mock_ok("plan_restore", &p);

    let m = ts::mount_view(|| view! { <DisasterRecoveryView /> });
    ts::tick().await;

    ts::click_button_labelled("Load backup file…");
    ts::wait_for(|| ts::query(".dr-view__plan").is_some()).await;
    m
}

/// Drives Load file → confirm → Restore, with `restore_tenant` answering
/// `report`.
async fn run_restore(report: RestoreReport) -> ts::Mounted {
    ts::reset();
    ts::mock_ok("restore_tenant", &report);
    let m = load_plan(plan()).await;

    // The plan lands before the restore button is offered.
    ts::wait_for(|| ts::has_button_labelled("Restore into this tenant…")).await;
    ts::click_button_labelled("Restore into this tenant…");
    // The confirm dialog's own "Restore" is the one that fires the command.
    ts::wait_for(|| ts::has_button_labelled("Restore")).await;
    ts::click_button_labelled("Restore");
    ts::wait_for(|| ts::query(".dr-view__result").is_some()).await;
    m
}

/// Runs a backup whose `backup_tenant` answers `b`, and waits for the result
/// panel (summary + Save). `ts::reset()` is the caller's to have done.
async fn run_backup(b: TenantBackup) -> ts::Mounted {
    ts::mock_ok("backup_tenant", &b);
    let m = ts::mount_view(|| view! { <DisasterRecoveryView /> });
    ts::tick().await;
    ts::click_button_labelled("Back up this tenant");
    ts::wait_for(|| ts::query(".dr-view__result").is_some()).await;
    m
}

/// An object the backup could not read restores as if it never existed, so
/// the result must say so — by name — BEFORE the operator decides to save
/// this file as the tenant's DR artifact.
#[wasm_bindgen_test]
async fn a_backup_with_skipped_objects_warns_before_save() {
    ts::reset();
    let _m = run_backup(TenantBackup {
        skipped: vec![SkippedObject::new(
            "application",
            "obj-9",
            Some("Payroll API".to_string()),
            "owners read failed",
        )],
        ..backup()
    })
    .await;

    assert!(
        ts::body_contains("1 object could not be fully read"),
        "{}",
        ts::body_text()
    );
    assert!(ts::body_contains("restoring it will not recreate it"));
    assert!(ts::body_contains("Payroll API"));
    assert!(ts::body_contains("owners read failed"));
    assert_eq!(ts::query_all(".dr-view__skipped-list li").len(), 1);

    // The notice precedes the save decision in document order.
    let list = ts::query(".dr-view__skipped-list").expect("skipped list");
    let save = ts::query_all(".dr-view__result button")
        .into_iter()
        .find(|el| {
            el.text_content()
                .unwrap_or_default()
                .contains("Save backup file")
        })
        .expect("save button");
    let following = web_sys::Node::DOCUMENT_POSITION_FOLLOWING;
    assert_ne!(
        list.compare_document_position(&save) & following,
        0,
        "the skipped-object notice must come before Save backup file…"
    );
}

#[wasm_bindgen_test]
async fn a_clean_backup_shows_no_skipped_notice() {
    ts::reset();
    let _m = run_backup(backup()).await;
    assert!(ts::body_contains("Save backup file"));
    assert!(ts::query(".dr-view__skipped-list").is_none());
    assert!(!ts::body_contains("could not be fully read"));
}

/// A manifest from a newer build is blocked in the plan, before Confirm — not
/// refused by `restore_tenant` only after the operator has confirmed.
#[wasm_bindgen_test]
async fn a_too_new_manifest_blocks_restore_before_confirm() {
    ts::reset();
    let _m = load_plan(RestorePlan {
        schema_too_new: Some(SchemaTooNew {
            manifest_version: 2,
            supported_version: 1,
        }),
        ..plan()
    })
    .await;
    assert!(ts::body_contains("newer version of azapptoolkit"));
    assert!(
        ts::query(".dr-view__plan [role=alert]").is_some(),
        "the blocker is announced"
    );
    assert!(
        !ts::has_button_labelled("Restore into this tenant…"),
        "a blocked plan must not offer the restore"
    );
}

/// A manifest with a repeated or malformed source appId is blocked in the
/// plan, naming the problem, before Confirm.
#[wasm_bindgen_test]
async fn an_invalid_manifest_blocks_restore_before_confirm() {
    ts::reset();
    let _m = load_plan(RestorePlan {
        invalid_manifest: vec!["app registration 'Payroll' has no source appId".into()],
        ..plan()
    })
    .await;
    assert!(ts::body_contains("not a valid manifest"));
    assert!(ts::body_contains("'Payroll' has no source appId"));
    assert!(
        ts::query(".dr-view__plan [role=alert]").is_some(),
        "the blocker is announced"
    );
    assert!(
        !ts::has_button_labelled("Restore into this tenant…"),
        "a blocked plan must not offer the restore"
    );
}

/// Restoring into the tenant the backup came from duplicates the estate — the
/// one case the tenant-change note never covered.
#[wasm_bindgen_test]
async fn restoring_into_the_source_tenant_warns_of_duplicates() {
    ts::reset();
    let _m = load_plan(RestorePlan {
        tenant_changed: false,
        ..plan()
    })
    .await;
    assert!(ts::body_contains("second copy of every app registration"));
    // Not a blocker: an operator may mean it.
    assert!(ts::has_button_labelled("Restore into this tenant…"));
}

/// The plan describes the enterprise-app, managed-identity and backup-gap
/// work too, not just the app registrations.
#[wasm_bindgen_test]
async fn the_plan_lists_enterprise_and_managed_identity_work() {
    ts::reset();
    let _m = load_plan(RestorePlan {
        enterprise_apps_to_reapply: 3,
        enterprise_apps_manual: 2,
        managed_identities_to_rebind: 4,
        skipped_in_backup: 1,
        ..plan()
    })
    .await;
    assert!(ts::body_contains("3 enterprise apps to re-apply access to"));
    assert!(ts::body_contains("2 enterprise apps need manual follow-up"));
    assert!(ts::body_contains("4 managed identities to re-bind by name"));
    assert!(ts::body_contains("1 gap recorded in the backup"));
    assert!(
        !ts::body_contains("second copy"),
        "a cross-tenant plan has no duplicate warning"
    );
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

/// Once a report renders, the Restore button is withdrawn: a second click would
/// be a second restore, so running it again needs a deliberate re-load.
#[wasm_bindgen_test]
async fn the_restore_button_is_withdrawn_once_a_report_renders() {
    let _m = run_restore(RestoreReport::default()).await;
    assert!(
        !ts::has_button_labelled("Restore into this tenant…"),
        "the restore must not be re-runnable with one click"
    );
    assert!(
        ts::has_button_labelled("Load backup file…"),
        "re-loading stays possible"
    );
}

/// An app a re-run recognised from an earlier run (by its restore tag) is
/// labelled, so it does not read as a second, freshly created copy.
#[wasm_bindgen_test]
async fn an_app_recognised_from_an_earlier_run_is_labelled() {
    let _m = run_restore(RestoreReport {
        apps: vec![RestoredApp {
            adopted: true,
            display_name: "App A".into(),
            ..Default::default()
        }],
        ..Default::default()
    })
    .await;
    assert!(
        ts::body_contains("already restored"),
        "an adopted app must be labelled: {}",
        ts::body_text()
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

/// An app whose admin consent covers one Graph application permission.
fn consenting(
    src: &str,
    name: &str,
    value: Option<&str>,
    risk: PermissionRisk,
) -> PrivilegedRestoreItem {
    PrivilegedRestoreItem {
        kind: PrivilegedKind::App,
        source_app_id: src.into(),
        display_name: name.into(),
        admin_consent: true,
        app_roles: vec![PrivilegedPermission {
            resource_app_id: "00000003-0000-0000-c000-000000000000".into(),
            resource_display_name: Some("Microsoft Graph".into()),
            permission_id: "role-id-1".into(),
            value: value.map(Into::into),
            risk,
            restored_api: false,
        }],
        // Consent to any application permission needs approval.
        requires_approval: true,
        ..Default::default()
    }
}

/// What the file would grant renders in the plan, before Confirm: each
/// consented permission with its risk, and each federated credential's issuer
/// and subject. The restore still runs without approvals (the clearer UX: a
/// DR restore is never blocked on ticking boxes), but only the apps ticked
/// are sent as approved — the backend withholds the rest's standing access.
#[wasm_bindgen_test]
async fn privileged_grants_render_before_confirm_and_only_ticked_apps_are_approved() {
    ts::reset();
    ts::mock_ok("restore_tenant", &RestoreReport::default());
    let fic_only = PrivilegedRestoreItem {
        source_app_id: "src-c".into(),
        display_name: "Deployer".into(),
        federated_credentials: vec![PlannedFederatedCredential {
            name: "gh-main".into(),
            issuer: "https://token.actions.githubusercontent.com".into(),
            subject: "repo:contoso/app:ref:refs/heads/main".into(),
            // Refused by validation, so it is shown but never created.
            rejected: Some("issuer must be an https URL".into()),
        }],
        app_role_assignees: vec!["Ops (Reader)".into()],
        ..Default::default()
    };
    let hr_sync = PrivilegedRestoreItem {
        group_memberships: vec!["Global Admins".into()],
        owners: vec!["alice@contoso.com".into()],
        ..consenting("src-b", "HR Sync", None, PermissionRisk::Unknown)
    };
    let _m = load_plan(RestorePlan {
        privileged: vec![
            consenting(
                "src-a",
                "Payroll API",
                Some("Application.ReadWrite.All"),
                PermissionRisk::High,
            ),
            hr_sync,
            fic_only,
        ],
        ..plan()
    })
    .await;

    // Shown before Confirm, by value — and by id when unresolvable.
    assert!(
        ts::body_contains("Access this restore grants"),
        "{}",
        ts::body_text()
    );
    assert!(ts::body_contains("Application.ReadWrite.All"));
    assert!(ts::body_contains("High risk"));
    assert!(
        ts::body_contains("role-id-1"),
        "an unresolved permission shows its id"
    );
    assert!(ts::body_contains("Unknown"));
    assert!(ts::body_contains(
        "issuer https://token.actions.githubusercontent.com"
    ));
    assert!(ts::body_contains(
        "subject repo:contoso/app:ref:refs/heads/main"
    ));
    // Owners and group memberships (withheld unless approved) and role
    // assignees (shown only) are named too.
    assert!(ts::body_contains("Joins group: Global Admins"));
    assert!(ts::body_contains("Owners: alice@contoso.com"));
    assert!(ts::body_contains(
        "Assigned to the app's roles: Ops (Reader)"
    ));
    // One approval box per item that needs it; none for the item whose only
    // credential validation refuses.
    assert_eq!(ts::query_all(".dr-view__approve input").len(), 2);
    assert!(
        ts::has_button_labelled("Restore into this tenant…"),
        "approvals gate the grants, not the restore"
    );

    // Approve Payroll API only.
    ts::click(".dr-view__privileged-item .dr-view__approve input");
    ts::click_button_labelled("Restore into this tenant…");
    ts::wait_for(|| ts::has_button_labelled("Restore")).await;
    assert!(
        ts::body_contains("1 item needing approval is not approved"),
        "the confirm dialog names what will be skipped: {}",
        ts::body_text()
    );
    ts::click_button_labelled("Restore");
    ts::wait_for(|| ts::call_count("restore_tenant") == 1).await;

    let call = ts::last_call("restore_tenant").expect("restore_tenant called");
    assert_eq!(
        call.args["approvals"],
        serde_json::json!([{ "kind": "app", "sourceAppId": "src-a" }])
    );
}

/// Nothing ticked: the restore sends no approvals at all.
#[wasm_bindgen_test]
async fn an_unticked_plan_restores_with_no_approvals() {
    ts::reset();
    ts::mock_ok("restore_tenant", &RestoreReport::default());
    let _m = load_plan(RestorePlan {
        privileged: vec![consenting(
            "src-a",
            "Payroll API",
            Some("Application.ReadWrite.All"),
            PermissionRisk::High,
        )],
        ..plan()
    })
    .await;
    ts::click_button_labelled("Restore into this tenant…");
    ts::wait_for(|| ts::has_button_labelled("Restore")).await;
    ts::click_button_labelled("Restore");
    ts::wait_for(|| ts::call_count("restore_tenant") == 1).await;
    let call = ts::last_call("restore_tenant").expect("restore_tenant called");
    assert_eq!(call.args["approvals"], serde_json::json!([]));
}

/// "Approve all listed" ticks every item that needs approval in one click —
/// offered after the list, with nothing ticked until it is pressed.
#[wasm_bindgen_test]
async fn approve_all_listed_ticks_every_item_needing_approval() {
    ts::reset();
    ts::mock_ok("restore_tenant", &RestoreReport::default());
    let mi = PrivilegedRestoreItem {
        kind: PrivilegedKind::ManagedIdentity,
        ..consenting("src-a", "mi-one", Some("Mail.Send"), PermissionRisk::High)
    };
    let _m = load_plan(RestorePlan {
        privileged: vec![
            consenting(
                "src-a",
                "Payroll API",
                Some("Application.ReadWrite.All"),
                PermissionRisk::High,
            ),
            mi,
        ],
        ..plan()
    })
    .await;

    // Default unticked.
    assert!(
        ts::query_all(".dr-view__approve input").iter().all(|el| !el
            .clone()
            .unchecked_into::<web_sys::HtmlInputElement>()
            .checked()),
        "nothing starts approved"
    );
    // The bulk control comes after the list it approves.
    let list = ts::query(".dr-view__privileged .dr-view__report-list").expect("privileged list");
    let all = ts::button_labelled("Approve all listed").expect("Approve all listed");
    assert_ne!(
        list.compare_document_position(&all) & web_sys::Node::DOCUMENT_POSITION_FOLLOWING,
        0,
        "Approve all listed must follow the list"
    );

    ts::click_button_labelled("Approve all listed");
    ts::wait_for(|| {
        ts::query_all(".dr-view__approve input").iter().all(|el| {
            el.clone()
                .unchecked_into::<web_sys::HtmlInputElement>()
                .checked()
        })
    })
    .await;

    ts::click_button_labelled("Restore into this tenant…");
    ts::wait_for(|| ts::has_button_labelled("Restore")).await;
    ts::click_button_labelled("Restore");
    ts::wait_for(|| ts::call_count("restore_tenant") == 1).await;
    let call = ts::last_call("restore_tenant").expect("restore_tenant called");
    // Kind-keyed: the app and the identity sharing "src-a" are two approvals.
    assert_eq!(
        call.args["approvals"],
        serde_json::json!([
            { "kind": "app", "sourceAppId": "src-a" },
            { "kind": "managedIdentity", "sourceAppId": "src-a" }
        ])
    );
}
