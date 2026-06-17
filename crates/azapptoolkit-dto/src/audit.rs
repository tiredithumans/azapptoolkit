//! Audit IPC DTOs.

use azapptoolkit_core::audit::AuditItem;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditProgress {
    pub done: usize,
    pub total: usize,
    pub current_app: Option<String>,
    pub in_flight_cap: usize,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRunResult {
    pub tenant_id: String,
    pub total_apps: usize,
    pub items: Vec<AuditItem>,
    pub cancelled: bool,
    /// Whether the sign-in activity report was available this run (needs
    /// `AuditLog.Read.All` + Entra ID P1/P2). Drives the "Unused" tab's empty
    /// state: when `false`, no app could be flagged unused.
    #[serde(default)]
    pub sign_in_report_available: bool,
    /// `true` when the sign-in report was unavailable specifically because
    /// `AuditLog.Read.All` is not yet consented — the view shows a "Grant consent"
    /// button (`request_scope_consent(tenant_id, "audit_log")`) so the user can
    /// enable unused-app detection and re-run. Distinct from a license/P1-P2 gap.
    #[serde(default)]
    pub sign_in_consent_required: bool,
}
