//! Readiness-checklist IPC binding.
//!
//! Mirrors `commands::readiness::check_readiness` — a live check of what the
//! signed-in user holds (active directory roles + consented scopes) against the
//! capability catalog. Best-effort: anything unprovable comes back as
//! `Verdict::Unknown`.

use azapptoolkit_dto::UiError;
use azapptoolkit_dto::readiness::ReadinessReport;
use serde::Serialize;
use tauri_sys::core::invoke_result;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckReadinessArgs<'a> {
    tenant_id: &'a str,
}

pub async fn check_readiness(tenant_id: &str) -> Result<ReadinessReport, UiError> {
    invoke_result("check_readiness", CheckReadinessArgs { tenant_id }).await
}
