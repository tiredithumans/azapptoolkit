//! Exchange Online RBAC-for-Applications commands.
//!
//! These replace the deprecated Application Access Policy flow: instead of a
//! single mail-enabled security group scoped via `New-ApplicationAccessPolicy`,
//! an app's mailbox access is scoped with an Exchange management scope
//! (`MemberOfGroup` recipient filter) plus per-role management role
//! assignments (`New-ManagementRoleAssignment -App ... -CustomResourceScope`).
//!
//! Because RBAC grants union with Microsoft Entra ID consents, scoping is only
//! effective once the org-wide Entra app-role assignment for the same
//! permission is removed — these commands do that explicitly.

use std::collections::{HashMap, HashSet};

use tauri::State;

use azapptoolkit_core::audit::{MailPermissionScope, ScopeMechanism};
use azapptoolkit_core::cache::{Cache, CacheKind};
use azapptoolkit_core::scoping::exchange_role_for_resource_permission;
use azapptoolkit_core::scoping::is_scopable_exchange_resource_permission;
use azapptoolkit_exchange::models::ExoGroupMember;
use azapptoolkit_exchange::models::{
    ExoApplicationAccessPolicy, ExoAuthorizationResult, ExoManagementScope,
};
use azapptoolkit_exchange::references::{GroupIdentity, references_to_group};
use azapptoolkit_exchange::targets::{
    ExchangeTarget, Refusal, RoleStep, UnrewritableFilter, count_member_of_group, exchange_target,
    filter_targets_by_value, group_dns_in_filter, mailbox_resources_complete, plan_consolidation,
    plan_role_assignments, policies_safe_to_remove, require_scopable_targets, rewritable_scope_dns,
    scope_groups_in_filter, targets_from_declared, targets_from_grants, targets_safe_to_strip,
};
// These three flows resolve roles for permission sets a resource-aware gate has
// already proven scopable — and only Microsoft Graph's mail permissions ever
// are, which is what that proof establishes. So they name the resource instead
// of asking the value-only form to guess it.
use azapptoolkit_exchange::MICROSOFT_GRAPH_APP_ID;
// The pure mailbox-scope decisions now live in the crate, where they are
// unit-testable without a Tauri `State`. This file keeps the I/O around them.
use azapptoolkit_exchange::verdict::{
    aap_verdict_for, reconcile_orgwide_grant, row_grants_permission, scope_from_rbac_error,
    verdict_from_rows,
};
use azapptoolkit_exchange::{
    ExchangeClient, ExchangeError, SourceGroupRead, group_policies_for_migration,
    member_of_group_filter, plan_source_membership, source_member, unverified_members,
};
use azapptoolkit_graph::GraphClient;

use crate::commands::applications::{invalidate_app_detail_state, invalidate_app_lists};
use crate::commands::dispatch::SessionDead;
use crate::commands::graph_roles::{
    ResourceRoles, mailbox_resource_roles, resolve_grant, resolve_value,
};
use crate::dto::UiError;
use crate::dto::exchange::PrincipalPermission;
use crate::dto::exchange::{
    AapMigrationItem, AapMigrationReport, ExchangeAccessRemovalResult, ExchangeAccessResult,
    ExchangeGroupMemberDto, ExchangeGroupRef, ExchangeMemberFailure, ExchangeMemberMutationResult,
    ExchangeRoleAssignmentDto, ExchangeScopeConsolidationResult, ExchangeScopeGroupDto,
    MailScopeEntry, RetiredScopeGroupDto,
};
use crate::state::AppState;
use azapptoolkit_core::defaults::TenantDefaults;
use azapptoolkit_core::settings::UserSettings;

/// Loads this tenant's operator defaults from `settings.json` (an empty set if
/// none). It is the source of the configurable Exchange naming patterns —
/// [`TenantDefaults::scope_name_for`] (management scope, default
/// `app_scope_<app_id>`) and [`TenantDefaults::group_name_for`] (mail-enabled
/// scope group, default `app_scope_group_<app_id>`). The two defaults are kept
/// distinct so a scope and its backing group never collide on name; both apply
/// to every Exchange scoping path (fresh grants and legacy-AAP migration).
fn load_tenant_defaults(tenant_id: &str) -> TenantDefaults {
    UserSettings::stored(&crate::config_directory()).defaults_for(tenant_id)
}

/// Exchange aliases allow only a restricted character set and cap at 64 chars.
/// An appId GUID is already alias-safe; this only guards against anything
/// unexpected in `app_id` by dropping disallowed characters and truncating.
fn sanitize_alias(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(64)
        .collect()
}

/// Resolves the signed-in admin's UPN and returns a ready Exchange client. The
/// UPN is mandatory — it is the `X-AnchorMailbox` routing hint for every Admin
/// API call.
pub(crate) fn exchange_client(
    state: &AppState,
    tenant_id: &str,
) -> Result<std::sync::Arc<ExchangeClient>, UiError> {
    let tenant = state.auth.tenant_context(tenant_id).ok_or_else(|| {
        UiError::validation(
            "not_signed_in",
            format!("not signed in to tenant {tenant_id}"),
        )
    })?;
    let upn = tenant.username.ok_or_else(|| {
        UiError::validation(
            "no_anchor_mailbox",
            "signed-in account has no UPN; cannot set the Exchange X-AnchorMailbox",
        )
    })?;
    Ok(state.exchange_for(tenant_id, &upn))
}

/// Like [`exchange_client`] but first pre-acquires the `Exchange.Manage` token
/// with a typed call, so a not-yet-consented Exchange scope surfaces as the
/// typed `consent_required` (the UI offers a "Grant consent" button) instead of
/// being flattened to a generic `token_error` deep inside the admin-API call.
/// Mirrors the SharePoint/ARM/audit `ensure_*_token` pre-acquire pattern. A
/// *consented-but-RBAC-blocked* user passes this and instead gets an actionable
/// 403 from the admin API (see `ExchangeError::ui_hint`).
pub(crate) async fn exchange_client_checked(
    state: &AppState,
    tenant_id: &str,
) -> Result<std::sync::Arc<ExchangeClient>, UiError> {
    state.ensure_exchange_token(tenant_id).await?;
    exchange_client(state, tenant_id)
}

// The module was one 3 000-line file; it is split by section so an edit reads
// only the part it touches. Everything is re-exported flat, so `commands::exchange::X`
// paths (lib.rs `generate_handler![]`, the other command modules) are unchanged —
// the glob also carries each command's `__cmd__` macro, which `generate_handler!`
// needs (same pattern as `commands::applications`).
mod aap_migration;
mod grants;
mod mail_scopes;
mod scope_group;

pub use aap_migration::*;
pub use grants::*;
pub use mail_scopes::*;
pub use scope_group::*;

#[cfg(test)]
mod tests;
