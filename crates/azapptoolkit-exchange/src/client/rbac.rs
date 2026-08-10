//! RBAC for Applications: Exchange service-principal pointers, management
//! scopes, management role assignments, the legacy Application Access Policy
//! (migration) surface, and the two live verification cmdlets.

use serde_json::json;

use super::ExchangeClient;
use super::transport::{all_as, first_as, first_optional_as};
use crate::error::Result;
use crate::models::{
    ExoAppAccessPolicyTestResult, ExoApplicationAccessPolicy, ExoAuthorizationResult,
    ExoManagementScope, ExoRoleAssignment, ExoServicePrincipal,
};

impl ExchangeClient {
    // ---------------- Service principals ----------------

    /// Registers the Entra service principal pointer in Exchange. Idempotent:
    /// returns the existing pointer if one already exists for `app_id`.
    pub async fn ensure_service_principal(
        &self,
        app_id: &str,
        object_id: &str,
        display_name: &str,
    ) -> Result<ExoServicePrincipal> {
        if let Some(existing) = self.get_service_principal(app_id).await? {
            return Ok(existing);
        }
        let values = self
            .invoke_command(
                "New-ServicePrincipal",
                json!({
                    "AppId": app_id,
                    "ObjectId": object_id,
                    "DisplayName": display_name,
                }),
            )
            .await?;
        first_as(values, "New-ServicePrincipal")
    }

    /// Looks up the Exchange service-principal pointer by AppId, ObjectId, or
    /// DisplayName. Returns `None` if no pointer is registered.
    pub async fn get_service_principal(
        &self,
        identity: &str,
    ) -> Result<Option<ExoServicePrincipal>> {
        let values = self
            .invoke_optional("Get-ServicePrincipal", json!({ "Identity": identity }))
            .await?;
        first_optional_as(values)
    }

    /// Every service-principal pointer registered in Exchange (the population
    /// eligible for RBAC-for-Applications role assignments). This is the only
    /// way to discover principals whose mailbox access comes *solely* from
    /// Exchange RBAC — they hold no Graph app-role assignment, so no Graph
    /// query can surface them.
    pub async fn list_service_principals(&self) -> Result<Vec<ExoServicePrincipal>> {
        let values = self
            .invoke_command("Get-ServicePrincipal", json!({}))
            .await?;
        all_as(values)
    }

    // ---------------- Management scopes ----------------

    /// Creates a management scope with the given OPATH recipient filter.
    /// Idempotent: returns the existing scope if `name` already exists.
    pub async fn ensure_management_scope(
        &self,
        name: &str,
        recipient_restriction_filter: &str,
    ) -> Result<ExoManagementScope> {
        if let Some(existing) = self.get_management_scope(name).await? {
            return Ok(existing);
        }
        let values = self
            .invoke_command(
                "New-ManagementScope",
                json!({
                    "Name": name,
                    "RecipientRestrictionFilter": recipient_restriction_filter,
                }),
            )
            .await?;
        first_as(values, "New-ManagementScope")
    }

    /// Repoints an EXISTING management scope at a new OPATH recipient filter.
    ///
    /// The counterpart to [`ensure_management_scope`], which is create-only and
    /// keeps an existing scope's filter untouched. Exchange applies the updated
    /// filter to **every** role assignment already using the scope, so this
    /// changes what all of them reach in one step — never call it to satisfy an
    /// incidental group mismatch, only from a path the operator chose knowing
    /// that.
    ///
    /// [`ensure_management_scope`]: Self::ensure_management_scope
    pub async fn set_management_scope_filter(
        &self,
        name: &str,
        recipient_restriction_filter: &str,
    ) -> Result<ExoManagementScope> {
        // Refuse an unrestricting filter before the write, not after.
        //
        // `member_of_group_filter(&[])` yields an empty OPATH string, and the
        // post-write proof below compares group DN *sets* — so an empty filter
        // would compare {} to {}, pass, and be reported as a verified success
        // while the scope had been widened. No caller can currently supply one
        // (each fails closed first), but "no caller does" is not a property this
        // function can rely on: it is the single mutator for a filter that
        // governs every role assignment on the scope.
        let wanted_groups = crate::targets::scope_groups_in_filter(recipient_restriction_filter);
        if recipient_restriction_filter.trim().is_empty() || wanted_groups.dns.is_empty() {
            return Err(crate::error::ExchangeError::Protocol(format!(
                "refusing to set management scope '{name}' to a filter that confines nothing \
                 (names no MemberOfGroup clause). Repointing a scope at an empty filter widens \
                 every role assignment using it to the whole organization."
            )));
        }
        // Refuse a filter we cannot fully READ before the write, not after.
        //
        // The post-write proof below already rejects `!complete`, but by then the
        // filter is live on every role assignment using this scope — the check
        // could only report the damage, never prevent it. A filter this parser
        // reads only partially is one whose reach we cannot state, and this is
        // the sole mutator of that reach, so the honest moment to refuse is
        // before the cmdlet runs. Nothing downstream can undo it afterwards.
        if !wanted_groups.complete {
            return Err(crate::error::ExchangeError::Protocol(format!(
                "refusing to set management scope '{name}' to a filter this client cannot fully \
                 read: it holds a MemberOfGroup token that is not a plain `-eq '…'` comparison, \
                 so the groups it would confine access to cannot be stated. Nothing was changed."
            )));
        }

        let values = self
            .invoke_command(
                "Set-ManagementScope",
                json!({
                    "Identity": name,
                    "RecipientRestrictionFilter": recipient_restriction_filter,
                    "Confirm": false,
                }),
            )
            .await?;
        // `Set-ManagementScope` returns nothing on success, so re-read to hand
        // the caller the scope as Exchange now has it.
        let scope = match first_optional_as::<ExoManagementScope>(values)? {
            Some(updated) => updated,
            None => match self.get_management_scope(name).await? {
                Some(scope) => scope,
                None => {
                    return Err(crate::error::ExchangeError::Protocol(format!(
                        "management scope '{name}' disappeared after Set-ManagementScope"
                    )));
                }
            },
        };

        // ...and PROVE the filter landed, which the re-read alone does not: it
        // only shows a scope by that name exists, which was already true before
        // the call. This scope governs every role assignment using it, so a
        // silently-unapplied filter leaves those assignments pointed at the old
        // group set while the caller reports success.
        //
        // Compare the group DN *sets*, not the raw strings: Exchange normalizes
        // OPATH whitespace, parenthesization and quoting, so a byte comparison
        // would reject filters that applied perfectly. The DN set is the
        // property that decides reach, and it is what every caller of this
        // function is actually asserting.
        //
        // Via `scope_groups_in_filter`, not `group_dns_in_filter`: the latter
        // throws away `ScopeGroups::complete`, and an incomplete parse yields a
        // *partial* DN set. Comparing two partial sets can report equal when the
        // unparsed remainders differ — the type's own doc says an incomplete
        // answer must never be read as a definite one, and this is the proof
        // that decides whether a widening write is reported as success.
        let landed = scope
            .recipient_filter
            .as_deref()
            .map(crate::targets::scope_groups_in_filter)
            .unwrap_or(crate::targets::ScopeGroups {
                dns: Default::default(),
                complete: true,
            });
        if !wanted_groups.complete || !landed.complete {
            return Err(crate::error::ExchangeError::Protocol(format!(
                "management scope '{name}' has a recipient filter this client cannot fully \
                 read, so it cannot prove the filter it just wrote took effect. The scope may \
                 or may not have been repointed; inspect it in Exchange before relying on it."
            )));
        }
        if wanted_groups.dns != landed.dns {
            return Err(crate::error::ExchangeError::Protocol(format!(
                "management scope '{name}' did not take the filter it was given: asked for \
                 {} group(s), Exchange reports {}. The scope was NOT repointed as requested; \
                 role assignments using it still reach the previous group set.",
                wanted_groups.dns.len(),
                landed.dns.len(),
            )));
        }
        Ok(scope)
    }

    pub async fn get_management_scope(&self, name: &str) -> Result<Option<ExoManagementScope>> {
        let values = self
            .invoke_optional("Get-ManagementScope", json!({ "Identity": name }))
            .await?;
        first_optional_as(values)
    }

    /// Every custom management scope in the organization (`Get-ManagementScope`
    /// with no `Identity`). Exchange offers no reverse "which scopes reference
    /// this group?" lookup, so answering that means reading them all and
    /// matching their `RecipientFilter` — the reason this exists.
    pub async fn list_management_scopes(&self) -> Result<Vec<ExoManagementScope>> {
        let values = self
            .invoke_optional("Get-ManagementScope", json!({}))
            .await?;
        all_as(values)
    }

    // ---------------- Role assignments ----------------

    /// Assigns an Exchange application `role` to the service principal `app`
    /// (AppId/ObjectId/DisplayName), optionally constrained to a management
    /// scope. `custom_resource_scope = None` grants org-wide.
    pub async fn new_role_assignment(
        &self,
        app: &str,
        role: &str,
        custom_resource_scope: Option<&str>,
    ) -> Result<ExoRoleAssignment> {
        let mut params = json!({ "App": app, "Role": role });
        if let Some(scope) = custom_resource_scope {
            params["CustomResourceScope"] = json!(scope);
        }
        let values = self
            .invoke_command("New-ManagementRoleAssignment", params)
            .await?;
        first_as(values, "New-ManagementRoleAssignment")
    }

    /// All management role assignments for the service principal `app`.
    pub async fn get_role_assignments(&self, app: &str) -> Result<Vec<ExoRoleAssignment>> {
        let values = self
            .invoke_optional(
                "Get-ManagementRoleAssignment",
                json!({ "RoleAssignee": app }),
            )
            .await?;
        all_as(values)
    }

    pub async fn remove_role_assignment(&self, identity: &str) -> Result<()> {
        self.invoke_command(
            "Remove-ManagementRoleAssignment",
            json!({ "Identity": identity, "Confirm": false }),
        )
        .await?;
        Ok(())
    }

    // ---------------- Legacy Application Access Policies (migration) ----------------

    pub async fn get_application_access_policies(&self) -> Result<Vec<ExoApplicationAccessPolicy>> {
        let values = self
            .invoke_optional("Get-ApplicationAccessPolicy", json!({}))
            .await?;
        all_as(values)
    }

    pub async fn remove_application_access_policy(&self, identity: &str) -> Result<()> {
        self.invoke_command(
            "Remove-ApplicationAccessPolicy",
            json!({ "Identity": identity, "Confirm": false }),
        )
        .await?;
        Ok(())
    }

    // ---------------- Verification ----------------

    /// Simulates the access a service principal has, optionally against a
    /// specific `resource` mailbox. Bypasses the RBAC propagation cache, so it
    /// is the reliable check immediately after granting access.
    pub async fn test_service_principal_authorization(
        &self,
        identity: &str,
        resource: Option<&str>,
    ) -> Result<Vec<ExoAuthorizationResult>> {
        let mut params = json!({ "Identity": identity });
        if let Some(res) = resource {
            params["Resource"] = json!(res);
        }
        let values = self
            .invoke_command("Test-ServicePrincipalAuthorization", params)
            .await?;
        all_as(values)
    }

    /// Live evaluation of the legacy Application Access Policy gate: can
    /// `app_id`'s **Entra-granted** permissions reach `mailbox`? This is the
    /// complement of [`test_service_principal_authorization`]: AAPs constrain
    /// only the Microsoft Entra ID grants (never Exchange RBAC assignments),
    /// while `Test-ServicePrincipalAuthorization` sees only the RBAC layer —
    /// actual access is the union of the two answers.
    ///
    /// [`test_service_principal_authorization`]: Self::test_service_principal_authorization
    pub async fn test_application_access_policy(
        &self,
        app_id: &str,
        mailbox: &str,
    ) -> Result<ExoAppAccessPolicyTestResult> {
        let values = self
            .invoke_command(
                "Test-ApplicationAccessPolicy",
                json!({ "AppId": app_id, "Identity": mailbox }),
            )
            .await?;
        first_as(values, "Test-ApplicationAccessPolicy")
    }
}
