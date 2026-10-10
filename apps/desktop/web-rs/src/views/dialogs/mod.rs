//! Modal dialogs. Each renders through `components::modal_shell::ModalShell` —
//! a lightweight backdrop+box (rather than Thaw's full Dialog primitive) that
//! owns the focus trap, Escape and the dialog ARIA — and supplies only its
//! content. None spells the dialog markup itself (pinned by
//! `tests/dialogs_use_modal_shell.rs`).

pub mod add_owner;
pub mod cache_diagnostics_dialog;
pub mod confirm_dialog;
pub mod create_app_dialog;
pub mod deleted_apps_dialog;
pub mod gallery_dialog;
pub mod migrate_legacy_scope;
pub mod new_app_chooser_dialog;
pub mod scope_remediation;
pub mod secret_reveal_dialog;
pub mod sso_wizard_dialog;
pub mod upload_certificate_dialog;
