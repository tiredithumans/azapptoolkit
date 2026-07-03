//! The scope catalog: which OAuth scopes each feature's token asks for, and
//! why. Every getter documents the consent posture of its scope (at sign-in
//! vs on-demand incremental consent) — consumed exclusively by the desktop
//! backend's `AppState` client factories.

use azapptoolkit_core::constants::{GRAPH_READ_SCOPES, GRAPH_WRITE_SCOPES};

use super::EntraAuthService;

impl EntraAuthService {
    /// Read-only Graph scopes requested at sign-in and used for every GET.
    /// `GRAPH_READ_SCOPES` plus `offline_access`, `openid`, `profile`.
    pub fn default_graph_read_scopes(&self) -> Vec<String> {
        self.graph_scopes(GRAPH_READ_SCOPES)
    }

    /// Read-write Graph scopes, requested on demand for mutating requests.
    /// `GRAPH_WRITE_SCOPES` plus `offline_access`, `openid`, `profile`. The
    /// refresh token minted at sign-in is redeemed for these the first time a
    /// write runs; admin consent on the tenant keeps the redemption silent.
    pub fn default_graph_write_scopes(&self) -> Vec<String> {
        self.graph_scopes(GRAPH_WRITE_SCOPES)
    }

    /// `Synchronization.Read.All` Graph scope for reading SCIM provisioning job
    /// status. Acquired on demand (incremental consent), not at sign-in, with
    /// the same graceful-degradation contract as the reports scope.
    pub fn default_graph_sync_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["Synchronization.Read.All"])
    }

    /// `AuditLog.Read.All` Graph scope for the directory activity / change log.
    /// Acquired on demand (incremental consent), never at sign-in, with the same
    /// graceful-degradation contract as the reports scope — a tenant that hasn't
    /// admin-consented (or lacks Entra ID P1/P2) can still sign in and browse;
    /// the Activity tab simply reports the feature as unavailable.
    pub fn default_graph_audit_log_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["AuditLog.Read.All"])
    }

    /// `Policy.Read.All` Graph scope for reading Conditional Access policies.
    /// Acquired on demand (incremental consent), never at sign-in, with the same
    /// graceful-degradation contract — a tenant without admin consent (or Entra
    /// ID P1/P2) can still sign in and browse; the Conditional Access tab simply
    /// reports the feature as unavailable.
    pub fn default_graph_policy_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["Policy.Read.All"])
    }

    /// `Policy.ReadWrite.ApplicationConfiguration` Graph scope for creating and
    /// assigning claims-mapping policies (SAML attribute & claim customization
    /// in the SSO setup flow). Admin-consent-only; acquired on demand, never at
    /// sign-in, so SSO setups that don't customize claims never request it and a
    /// tenant that hasn't consented can still sign in and browse.
    pub fn default_graph_policy_write_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["Policy.ReadWrite.ApplicationConfiguration"])
    }

    /// `Sites.FullControl.All` Graph scope for the SharePoint `Sites.Selected`
    /// model — listing, granting, and revoking a site's per-app permissions
    /// (the Permissions tab's SharePoint site access section). The
    /// site-permission endpoints require this
    /// scope even for reads. Acquired on demand (incremental consent), never at
    /// sign-in: it needs admin consent and a SharePoint-admin / site-owner
    /// signed-in user, so baking it into the write bundle would over-request it
    /// on every ordinary app edit and could block sign-in for un-consented
    /// tenants. The UI degrades to a "Grant consent" prompt instead.
    pub fn default_graph_sharepoint_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["Sites.FullControl.All"])
    }

    /// `GroupMember.ReadWrite.All` Graph scope for adding/removing a service
    /// principal as a member of a security group (group-gated APIs like
    /// Power BI / Fabric admit service principals via group membership).
    /// Deliberately the membership-only scope, not `Group.ReadWrite.All` — the
    /// app never creates or deletes groups. Admin-consent-only; acquired on
    /// demand, never at sign-in, with the same graceful-degradation contract
    /// as the SharePoint scope (membership *reads* ride `Directory.Read.All`).
    pub fn default_graph_group_member_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["GroupMember.ReadWrite.All"])
    }

    /// Prefixes each Graph permission with the Graph resource URL and appends
    /// the OIDC scopes (`offline_access` for the refresh token, `openid` +
    /// `profile` for the ID token). Callers that need tokens for other
    /// resources (Key Vault, ARM, SharePoint) use [`Self::resource_default_scopes`].
    fn graph_scopes(&self, permissions: &[&str]) -> Vec<String> {
        let resource = self.cloud.graph_resource();
        let mut scopes: Vec<String> = permissions
            .iter()
            .map(|s| format!("{resource}/{s}"))
            .collect();
        scopes.push("offline_access".to_string());
        scopes.push("openid".to_string());
        scopes.push("profile".to_string());
        scopes
    }

    /// Exchange Online Admin API scopes (`EXCHANGE_SCOPES` plus
    /// `offline_access`), for managing RBAC for Applications. The audience is
    /// `outlook.office365.com`, so this is a distinct token from the Graph
    /// read/write tokens; it is redeemed on demand from the sign-in refresh
    /// token the first time an Exchange operation runs.
    pub fn default_exchange_scopes(&self) -> Vec<String> {
        vec![
            // Classic scope — the InvokeCommand gateway rejects `ManageV2`
            // (preview per-cmdlet API only) with a bodyless 403. See
            // `azapptoolkit_core::constants::EXCHANGE_SCOPES`.
            format!("{}/Exchange.Manage", self.cloud.exchange_resource()),
            "offline_access".to_string(),
        ]
    }

    /// Scopes to request for a non-Graph audience. Every Entra-secured
    /// resource advertises a `<resource>/.default` scope that asks for "every
    /// permission the user consented to for this audience"; we always add
    /// `offline_access` so the refresh token keeps working across audiences.
    pub fn resource_default_scopes(resource_url: &str) -> Vec<String> {
        vec![
            format!("{}/.default", resource_url.trim_end_matches('/')),
            "offline_access".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_scopes_are_read_only_with_offline_access() {
        let scopes = EntraAuthService::new("c", "t").default_graph_read_scopes();
        assert!(scopes.iter().any(|s| s == "offline_access"));
        assert!(
            scopes
                .iter()
                .any(|s| s == "https://graph.microsoft.com/Directory.Read.All")
        );
        assert!(
            !scopes.iter().any(|s| s.contains("ReadWrite")),
            "sign-in must not request any write scope"
        );
    }

    #[test]
    fn write_scopes_cover_mutations() {
        let scopes = EntraAuthService::new("c", "t").default_graph_write_scopes();
        assert!(scopes.iter().any(|s| s == "offline_access"));
        for perm in [
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "DelegatedPermissionGrant.ReadWrite.All",
        ] {
            assert!(
                scopes
                    .iter()
                    .any(|s| s == &format!("https://graph.microsoft.com/{perm}"))
            );
        }
    }

    #[test]
    fn exchange_scopes_target_outlook_audience_with_offline_access() {
        let scopes = EntraAuthService::new("c", "t").default_exchange_scopes();
        assert!(
            scopes
                .iter()
                .any(|s| s == "https://outlook.office365.com/Exchange.Manage")
        );
        assert!(scopes.iter().any(|s| s == "offline_access"));
        // Must not leak any Graph scope into the Exchange token request.
        assert!(!scopes.iter().any(|s| s.contains("graph.microsoft.com")));
    }

    #[test]
    fn resource_default_scopes_appends_default_suffix() {
        let scopes = EntraAuthService::resource_default_scopes("https://vault.azure.net");
        assert!(
            scopes
                .iter()
                .any(|s| s == "https://vault.azure.net/.default")
        );
        assert!(scopes.iter().any(|s| s == "offline_access"));
    }
}
