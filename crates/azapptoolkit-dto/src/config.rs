//! First-run app-configuration IPC DTOs.
//!
//! The client/tenant IDs the app signs in with are resolved on the backend
//! (env var → `settings.json` → build-time bake → placeholder). This status
//! lets the frontend decide whether to show the first-run config screen and
//! prefill the form when reconfiguring.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthConfigStatus {
    /// True once both client and tenant IDs resolve to a real (non-placeholder)
    /// value — i.e. sign-in has a chance of succeeding.
    pub configured: bool,
    /// Current effective client ID, or empty when still the placeholder (so the
    /// config form renders blank rather than showing the all-zeros GUID).
    pub client_id: String,
    /// Current effective tenant ID, or empty when still the placeholder.
    pub tenant_id: String,
}
