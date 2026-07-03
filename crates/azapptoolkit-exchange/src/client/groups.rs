//! Recipient groups as scope sources: resolving any group to its
//! `DistinguishedName`, managing the toolkit's `azapptoolkit_<AppId>`
//! mail-enabled security group (create + membership), and building the OPATH
//! `MemberOfGroup` recipient filter those DNs feed.

use serde_json::json;

use super::ExchangeClient;
use super::transport::{all_as, first_as, first_optional_as};
use crate::error::{ExchangeError, Result, is_already_member_body, is_not_a_member_body};
use crate::models::{ExoGroup, ExoGroupMember};

impl ExchangeClient {
    // ---------------- Groups (scope source) ----------------

    /// Resolves a recipient group to its `DistinguishedName`, which a
    /// `MemberOfGroup` recipient filter must reference. Works for mail-enabled
    /// security groups, Microsoft 365 groups, and distribution lists.
    pub async fn get_group(&self, identity: &str) -> Result<Option<ExoGroup>> {
        let values = self
            .invoke_optional("Get-Group", json!({ "Identity": identity }))
            .await?;
        first_optional_as(values)
    }

    // ---------------- Managed scope group (create + membership) ----------------

    /// Looks up a distribution / mail-enabled security group by identity (name,
    /// alias, GUID, SMTP, or DN). Narrower than [`get_group`]: only matches
    /// distribution-list / mail-enabled-security recipients, so it won't collide
    /// with an unrelated object that happens to share the toolkit's name. Returns
    /// `None` if no such group exists.
    ///
    /// [`get_group`]: Self::get_group
    pub async fn get_distribution_group(&self, identity: &str) -> Result<Option<ExoGroup>> {
        let values = self
            .invoke_optional("Get-DistributionGroup", json!({ "Identity": identity }))
            .await?;
        first_optional_as(values)
    }

    /// Ensures a mail-enabled security group named `name` (alias `alias`) exists,
    /// creating it via `New-DistributionGroup -Type Security` if missing.
    /// Idempotent: returns the existing group when present. `-IgnoreNamingPolicy`
    /// keeps the exact toolkit naming convention so a later lookup by name
    /// resolves it. A freshly created group can return without its
    /// `DistinguishedName` populated, so we re-resolve in that case — the DN is
    /// what a `MemberOfGroup` management-scope filter must reference.
    pub async fn ensure_security_group(&self, name: &str, alias: &str) -> Result<ExoGroup> {
        if let Some(existing) = self.get_distribution_group(name).await? {
            return Ok(existing);
        }
        let values = self
            .invoke_command(
                "New-DistributionGroup",
                json!({
                    "Name": name,
                    "Alias": alias,
                    "Type": "Security",
                    "IgnoreNamingPolicy": true,
                }),
            )
            .await?;
        let created: ExoGroup = first_as(values, "New-DistributionGroup")?;
        if created.distinguished_name.is_some() {
            return Ok(created);
        }
        match self.get_distribution_group(name).await? {
            Some(resolved) => Ok(resolved),
            None => Ok(created),
        }
    }

    /// Adds `member` (a mailbox UPN, SMTP, GUID, …) to `group`. Idempotent:
    /// adding an existing member returns success rather than an error.
    pub async fn add_group_member(&self, group: &str, member: &str) -> Result<()> {
        match self
            .invoke_command(
                "Add-DistributionGroupMember",
                json!({ "Identity": group, "Member": member }),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(ExchangeError::Api { body, .. }) if is_already_member_body(&body) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Removes `member` from `group`. Idempotent: removing a non-member returns
    /// success. `BypassSecurityGroupManagerCheck` lets an admin who isn't listed
    /// as the group's manager still edit membership.
    pub async fn remove_group_member(&self, group: &str, member: &str) -> Result<()> {
        match self
            .invoke_command(
                "Remove-DistributionGroupMember",
                json!({
                    "Identity": group,
                    "Member": member,
                    "Confirm": false,
                    "BypassSecurityGroupManagerCheck": true,
                }),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(ExchangeError::Api { body, .. }) if is_not_a_member_body(&body) => Ok(()),
            Err(err) => Err(err),
        }
    }

    /// Lists the direct members of `group`. Returns an empty list when the group
    /// doesn't exist (via [`invoke_optional`]).
    ///
    /// [`invoke_optional`]: Self::invoke_optional
    pub async fn list_group_members(&self, group: &str) -> Result<Vec<ExoGroupMember>> {
        let values = self
            .invoke_optional("Get-DistributionGroupMember", json!({ "Identity": group }))
            .await?;
        all_as(values)
    }
}

/// Builds an OPATH `MemberOfGroup` recipient filter for a management scope,
/// OR-ing across multiple group distinguished names. The DNs are obtained via
/// [`ExchangeClient::get_group`].
pub fn member_of_group_filter(distinguished_names: &[String]) -> String {
    distinguished_names
        .iter()
        .map(|dn| format!("MemberOfGroup -eq '{}'", escape_opath(dn)))
        .collect::<Vec<_>>()
        .join(" -or ")
}

/// OPATH single-quoted-string escape: a `'` inside the literal becomes `''`.
fn escape_opath(input: &str) -> String {
    input.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_of_group_filter_ors_multiple_dns() {
        let f = member_of_group_filter(&["CN=a,DC=x".to_string(), "CN=b,DC=y".to_string()]);
        assert_eq!(
            f,
            "MemberOfGroup -eq 'CN=a,DC=x' -or MemberOfGroup -eq 'CN=b,DC=y'"
        );
    }

    #[test]
    fn escape_opath_doubles_quotes() {
        assert_eq!(escape_opath("O'Brien"), "O''Brien");
    }
}
