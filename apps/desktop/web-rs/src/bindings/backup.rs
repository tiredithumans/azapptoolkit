//! Disaster-recovery backup IPC bindings. The progress stream lives in
//! `bindings::events::backup_progress`. The restore side (plan, run, cancel,
//! save report) follows the backup commands.

use super::ipc::invoke_result;
use azapptoolkit_dto::UiError;
use serde::Serialize;

// Re-export the manifest types (`TenantBackup`, …) for the DR view, and bring
// them into scope for the signatures below.
use crate::bindings::TenantArg;
pub use azapptoolkit_dto::backup::*;

/// Captures a full, portable backup of the tenant's app estate. Long-running
/// (a per-app fan-out); subscribe to `events::backup_progress` for progress and
/// call [`cancel_backup`] to stop it.
pub async fn backup_tenant(tenant_id: &str) -> Result<TenantBackup, UiError> {
    invoke_result("backup_tenant", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveBackupArgs<'a> {
    backup: &'a TenantBackup,
    format: &'a str,
}

/// Writes the backup to a JSON file via the OS save dialog. Returns the chosen
/// path, or `None` if the user cancelled. JSON only (the manifest is a
/// structured restore artifact, not a spreadsheet).
pub async fn save_backup_to_file(
    backup: &TenantBackup,
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result("save_backup_to_file", SaveBackupArgs { backup, format }).await
}

/// Opens a backup JSON file via the OS dialog and parses it. `None` if the user
/// cancelled the dialog.
pub async fn load_backup_from_file() -> Result<Option<TenantBackup>, UiError> {
    invoke_result("load_backup_from_file", ()).await
}

/// Signals an in-progress backup to stop at the next dispatch boundary. Never
/// stops a restore.
pub async fn cancel_backup() -> Result<(), UiError> {
    invoke_result("cancel_backup", ()).await
}

// ---------------- Restore ----------------

/// Signals an in-progress restore to stop at the next item of whichever pass is
/// running. Never stops a backup.
pub async fn cancel_restore() -> Result<(), UiError> {
    invoke_result("cancel_restore", ()).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoreArgs<'a> {
    tenant_id: &'a str,
    backup: &'a TenantBackup,
}

/// Dry-run analysis of restoring `backup` into the tenant — counts, warnings
/// and the privileged grants (`RestorePlan.privileged`), no writes.
pub async fn plan_restore(tenant_id: &str, backup: &TenantBackup) -> Result<RestorePlan, UiError> {
    invoke_result("plan_restore", RestoreArgs { tenant_id, backup }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RunRestoreArgs<'a> {
    tenant_id: &'a str,
    backup: &'a TenantBackup,
    approvals: &'a [RestoreApproval],
}

/// Replays the backup's app registrations into the tenant. Long-running;
/// subscribe to `events::restore_progress`. `approvals` are the
/// `RestorePlan.privileged` items the operator approved (by kind and source
/// appId); any other item that requires approval restores without its
/// standing access, each withheld grant reported as a manual item.
pub async fn restore_tenant(
    tenant_id: &str,
    backup: &TenantBackup,
    approvals: &[RestoreApproval],
) -> Result<RestoreReport, UiError> {
    invoke_result(
        "restore_tenant",
        RunRestoreArgs {
            tenant_id,
            backup,
            approvals,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveReportArgs<'a> {
    report: &'a RestoreReport,
    format: &'a str,
}

/// Writes the restore report (which carries the show-once regenerated secrets)
/// to a JSON file via the OS save dialog. Returns the path, or `None` if
/// cancelled.
pub async fn save_restore_report_to_file(
    report: &RestoreReport,
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result(
        "save_restore_report_to_file",
        SaveReportArgs { report, format },
    )
    .await
}
