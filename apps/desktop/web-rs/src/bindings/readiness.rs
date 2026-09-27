//! Readiness-checklist IPC binding.
//!
//! Mirrors `commands::readiness::check_readiness` — a live check of what the
//! signed-in user holds (active directory roles + consented scopes) against the
//! capability catalog. Best-effort: anything unprovable comes back as
//! `Verdict::Unknown`.

use super::ipc::invoke_result;
use azapptoolkit_dto::UiError;
use azapptoolkit_dto::readiness::ReadinessReport;

use crate::bindings::TenantArg;

pub async fn check_readiness(tenant_id: &str) -> Result<ReadinessReport, UiError> {
    invoke_result("check_readiness", TenantArg { tenant_id }).await
}
