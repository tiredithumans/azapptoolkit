//! Audit IPC bindings: run, cancel, cached read, CSV export. Streamed
//! progress events live in `bindings::events::audit_progress`.

use azapptoolkit_core::audit::AuditItem;
use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::{invoke, invoke_result};

pub use azapptoolkit_dto::audit::{AuditProgress, AuditRunResult};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantArg<'a> {
    tenant_id: &'a str,
}

/// Runs a full security audit. Exchange mailbox-scoping is resolved as part of
/// every run (best-effort — it degrades to unscoped scoring when the signed-in
/// user lacks Exchange-admin rights).
pub async fn run_audit(tenant_id: &str) -> Result<AuditRunResult, UiError> {
    invoke_result("run_audit", TenantArg { tenant_id }).await
}

pub async fn cancel_audit() {
    invoke::<()>("cancel_audit", ()).await
}

pub async fn get_cached_audit(tenant_id: &str) -> Option<AuditRunResult> {
    invoke("get_cached_audit", TenantArg { tenant_id }).await
}

#[derive(Serialize)]
struct ExportArgs<'a> {
    items: &'a [AuditItem],
}

pub async fn export_audit_csv(items: &[AuditItem]) -> String {
    invoke("export_audit_csv", ExportArgs { items }).await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveArgs<'a> {
    tenant_id: &'a str,
    items: Option<&'a [AuditItem]>,
    format: &'a str,
}

/// Opens an OS save dialog and writes the audit in `format` (`csv`, `json`, or
/// `html`). Returns the chosen path on success, `None` if the user cancelled.
/// Exports by reference: pass `items: None` and the backend serves its own
/// cached run (no multi-MB IPC round trip); pass `Some` only for a cancelled
/// run, which is never cached.
pub async fn save_audit_to_file(
    tenant_id: &str,
    items: Option<&[AuditItem]>,
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result(
        "save_audit_to_file",
        SaveArgs {
            tenant_id,
            items,
            format,
        },
    )
    .await
}
