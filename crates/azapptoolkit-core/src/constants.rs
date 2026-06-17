//! Constants ported from the original `azapptoolkit` PowerShell module's
//! `Constants.ps1`.
//!
//! These are the source of truth for v1 semantics; any drift from the PS values
//! must be deliberate and reviewed.

use std::time::Duration;

/// Read-only Graph scope, requested at sign-in and used for every GET. A
/// single `Directory.Read.All` covers all read paths the UI drives —
/// applications, service principals, owners, appRoleAssignments,
/// oauth2PermissionGrants, the organization, and owner-picker user search.
/// It is the *only* read-only scope that can read `/oauth2PermissionGrants`
/// (surfaced in the app-detail and audit views), so narrower per-entity read
/// scopes cannot cover the read path; and since `Directory.Read.All` subsumes
/// those reads, adding them would only widen the admin-consent surface.
pub const GRAPH_READ_SCOPES: &[&str] = &["Directory.Read.All"];

/// Read-write Graph scopes, requested on demand the first time a mutating
/// request (POST/PATCH/DELETE) runs: app + service-principal + credential +
/// owner management (`Application.ReadWrite.All`), app-role assignment
/// (`AppRoleAssignment.ReadWrite.All`), and delegated permission grants
/// (`DelegatedPermissionGrant.ReadWrite.All`). Each requires admin consent.
pub const GRAPH_WRITE_SCOPES: &[&str] = &[
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
];

/// Exchange Online Admin API delegated scope. The audience is
/// `outlook.office365.com` (not Graph), so this token is acquired separately
/// from the Graph read/write tokens. Used for RBAC for Applications —
/// registering service principals, management scopes, and role assignments
/// that scope mailbox access. Requires admin consent on the tenant and an
/// Exchange Administrator / Organization Management signed-in user.
///
/// This must be the **classic** `Exchange.Manage` scope, not `Exchange.ManageV2`:
/// the `/adminapi/.../InvokeCommand` gateway this app calls accepts classic-scope
/// tokens (impersonation; the signed-in user's Exchange RBAC decides which
/// cmdlets run), while `ManageV2` belongs to the newer *preview* per-cmdlet
/// Admin API (`/adminapi/v2.0/<tenant>/<Cmdlet>`, allow-listed cmdlets, not
/// enabled in all tenants). A `ManageV2` token at the InvokeCommand gateway is
/// rejected with a bodyless 403 (no `x-ms-diagnostics`) before RBAC evaluation.
pub const EXCHANGE_SCOPES: &[&str] = &["https://outlook.office365.com/Exchange.Manage"];

/// Cache TTLs and per-kind entry cap. These are the runtime-tunable defaults
/// seeded into [`crate::cache::CacheConfig`]; every kind defaults to a 60-minute
/// TTL with a 5000-entry-per-kind cap (adjustable live via `configure`).
pub const SERVICE_PRINCIPAL_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
pub const PERMISSIONS_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
pub const AUDIT_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
/// TTL for cached list-shaped Graph responses (App Registrations, Enterprise
/// apps, Managed identities). Mutations explicitly invalidate, so this TTL only
/// governs out-of-band changes made by another admin (a manual Refresh re-fetches).
pub const LISTS_CACHE_TTL: Duration = Duration::from_secs(60 * 60);
pub const MAX_CACHE_SIZE: usize = 5000;
