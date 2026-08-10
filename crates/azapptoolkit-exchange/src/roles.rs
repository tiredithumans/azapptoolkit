//! Maps application permissions to the equivalent Exchange Online RBAC
//! "application role" names — the Microsoft Graph mail/calendar/contacts set
//! plus the EWS `full_access_as_app` scope on the legacy Office 365 Exchange
//! Online resource.
//!
//! The canonical mapping now lives in `azapptoolkit_core::scoping` so the WASM
//! frontend's scope badges and this backend share one definition; this module
//! re-exports it for `azapptoolkit-exchange`'s existing callers (and the crate
//! root re-export in `lib.rs`).

// Only the resource-aware forms exist to re-export now: the value-only ones
// were deleted, so the blanket `#[allow(deprecated)]` that used to sit here —
// and hid them from every caller of this crate root — has nothing to allow.
pub use azapptoolkit_core::scoping::{
    EWS_FULL_ACCESS_AS_APP, MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
    exchange_role_for_resource_permission, is_blanket_mailbox_grant,
    is_scopable_exchange_resource_permission,
};
