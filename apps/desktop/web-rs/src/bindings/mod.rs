#![allow(dead_code)]
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
//! `azapptoolkit_core::models` / `azapptoolkit_core::audit` directly. Boundary
//! input/output structs are defined locally in each submodule.

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
