//! Typed wrappers over `tauri-sys` for every `#[tauri::command]` exposed by
//! the backend, plus event-stream helpers. Components depend on this module
//! instead of `tauri-sys` directly so the IPC layer stays swappable.
//!
//! Wire format conventions (mirrored from the backend):
//! - `TenantContext` and most input/output DTOs use snake_case (Rust default).
//! - `Application`, `ServicePrincipal`, and other Microsoft Graph domain
//!   models in `azapptoolkit-core::models` use camelCase to match Graph JSON.
//! - Tauri command *parameter* keys (the top-level args object) are always
//!   camelCase; the backend macro maps them to snake_case Rust params.
//!
//! Domain types (`Application`, `Organization`, `AuditItem`, etc.) come from
//! `azapptoolkit_core::models` / `azapptoolkit_core::audit` directly; output
//! DTOs come from `azapptoolkit_dto`. Only argument structs are local to each
//! submodule (shapes several share live in `common.rs`).
//!
//! Every IPC call goes through [`ipc`], which turns a rejection that is not a
//! `UiError` (Tauri's own string errors) into `UiError { code: "ipc" }` instead
//! of the panic upstream `tauri-sys` would raise. `repo_invariants/ipc.rs`
//! pins the registry, the command literal, the arg keys and the return type of
//! every binding against its `#[tauri::command]`.

pub mod activity;
pub mod applications;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod bulk;
mod common;
pub mod conditional_access;
pub mod config;
pub mod consent;
pub mod credentials;
pub mod defaults;
pub mod diagnostics;
pub mod enterprise_application;
pub mod events;
pub mod exchange;
pub mod expose_api;
pub mod graph_roles;
mod ipc;
pub mod keyvault;
pub mod keyvault_rbac;
pub mod managed_identity;
pub mod permission_tester;
pub mod permissions;
pub mod readiness;
pub mod remediation;
pub mod search;
pub mod sharepoint;
pub mod sso;
pub mod updater;
pub mod usage;

// Identity types are shared via azapptoolkit-core (the frontend can't depend on
// the auth crate, which pulls in tokio/reqwest).
pub use azapptoolkit_core::identity::{SignInOutcome, TenantContext};

// Re-exported so callers can use them without a relative import path.
pub use common::{AppIdArgs, KeyIdArgs, ObjectIdArgs, ServicePrincipalIdArgs, TenantArg};
