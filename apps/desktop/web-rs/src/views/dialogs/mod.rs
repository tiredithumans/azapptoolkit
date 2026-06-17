//! Modal dialogs. Each uses a lightweight backdrop+box (rather than Thaw's full
//! Dialog primitive) wired with `use_focus_trap` + `use_escape` and ARIA
//! (`role="dialog"`, `aria-modal`, `aria-labelledby`).

pub mod cache_diagnostics_dialog;
pub mod confirm_dialog;
pub mod create_app_dialog;
pub mod scope_remediation;
pub mod secret_reveal_dialog;
pub mod sso_wizard_dialog;
pub mod upload_certificate_dialog;
