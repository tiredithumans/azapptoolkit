//! The scope catalog: which OAuth scopes each feature's token asks for, and
//! why. Every getter documents the consent posture of its scope (at sign-in
//! vs on-demand incremental consent) — consumed exclusively by the desktop
//! backend's `AppState` client factories.

use azapptoolkit_core::constants::{EXCHANGE_SCOPES, GRAPH_READ_SCOPES, GRAPH_WRITE_SCOPES};

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

    /// `Policy.ReadWrite.ApplicationConfiguration` + `Application.ReadWrite.All`
    /// — ONE token for every claims-mapping-policy call (SAML attribute & claim
    /// customization in the SSO wizard and the detail "SSO" tab). Creating,
    /// updating and deleting the policy object needs only the Policy scope, but
    /// the service-principal `$ref` assign/list/remove are documented delegated
    /// as "Application.ReadWrite.All and
    /// Policy.ReadWrite.ApplicationConfiguration" (Learn "Assign
    /// claimsMappingPolicy", "List assigned claimsMappingPolicy"), and the
    /// policy's `appliesTo` needs a Policy scope plus Application read. One
    /// bundle covers all of them, so a single consent covers both reading and
    /// saving. Admin-consent-only; acquired on demand, never at sign-in, so SSO
    /// setups that don't customize claims never request it and a tenant that
    /// hasn't consented can still sign in and browse.
    pub fn default_graph_policy_write_scopes(&self) -> Vec<String> {
        self.graph_scopes(&[
            "Policy.ReadWrite.ApplicationConfiguration",
            "Application.ReadWrite.All",
        ])
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

    /// `GroupMember.ReadWrite.All` + `Application.ReadWrite.All` — ONE token for
    /// adding/removing a service principal as a member of a security group
    /// (group-gated APIs like Power BI / Fabric admit service principals via
    /// group membership). Learn's "Add members" permissions table documents
    /// delegated "GroupMember.ReadWrite.All and Application.ReadWrite.All" for a
    /// `servicePrincipal` member — the only member type this app adds — because
    /// Graph also needs to write the service principal. `Application.ReadWrite.All`
    /// is already in the write bundle, so pairing it here widens nothing.
    /// Deliberately the membership-only group scope, not `Group.ReadWrite.All` —
    /// the app never creates or deletes groups. Admin-consent-only; acquired on
    /// demand, never at sign-in, with the same graceful-degradation contract as
    /// the SharePoint scope (membership *reads* ride `Directory.Read.All`).
    pub fn default_graph_group_member_scopes(&self) -> Vec<String> {
        self.graph_scopes(&["GroupMember.ReadWrite.All", "Application.ReadWrite.All"])
    }

    /// Whether `scopes` is a Microsoft Graph scope set — at least one scope, and
    /// every scope other than the reserved OIDC ones (`offline_access`,
    /// `openid`, `profile`) under this cloud's Graph resource. This is the CAE
    /// pairing: `AppState::graph_for` consumes every Graph scope set through
    /// `ScopedTokenAdapter::new_cae`, so an interactive flow that seeds one
    /// must mint a CAE token (the token cache keys on CAE-ness), while Exchange
    /// / ARM / Key Vault / Log Analytics stay non-CAE.
    pub fn is_graph_scope_set(&self, scopes: &[String]) -> bool {
        let prefix = format!("{}/", self.cloud.graph_resource());
        let mut resource_scopes = scopes
            .iter()
            .filter(|s| !matches!(s.as_str(), "offline_access" | "openid" | "profile"))
            .peekable();
        resource_scopes.peek().is_some() && resource_scopes.all(|s| s.starts_with(&prefix))
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

    /// Exchange Online Admin API scopes: each `EXCHANGE_SCOPES` permission
    /// prefixed with this cloud's Exchange resource
    /// ([`CloudEnvironment::exchange_resource`](azapptoolkit_core::cloud::CloudEnvironment::exchange_resource);
    /// commercial `https://outlook.office365.com`), plus `offline_access`, for
    /// managing RBAC for Applications. A distinct audience, so a distinct token
    /// from the Graph read/write tokens; redeemed on demand from the sign-in
    /// refresh token the first time an Exchange operation runs.
    pub fn default_exchange_scopes(&self) -> Vec<String> {
        // `EXCHANGE_SCOPES` is the classic `Exchange.Manage` — the
        // InvokeCommand gateway rejects `ManageV2` (preview per-cmdlet API
        // only) with a bodyless 403; its doc has the detail.
        let resource = self.cloud.exchange_resource();
        let mut scopes: Vec<String> = EXCHANGE_SCOPES
            .iter()
            .map(|s| format!("{resource}/{s}"))
            .collect();
        scopes.push("offline_access".to_string());
        scopes
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
    use azapptoolkit_core::cloud::CloudEnvironment;

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
    fn policy_write_scopes_pair_the_policy_scope_with_application_readwrite() {
        // The SP-side `$ref` assign/list/remove need both scopes in ONE token.
        let scopes = EntraAuthService::new("c", "t").default_graph_policy_write_scopes();
        for perm in [
            "Policy.ReadWrite.ApplicationConfiguration",
            "Application.ReadWrite.All",
        ] {
            assert!(
                scopes
                    .iter()
                    .any(|s| s == &format!("https://graph.microsoft.com/{perm}")),
                "missing {perm}: {scopes:?}"
            );
        }
        assert!(scopes.iter().any(|s| s == "offline_access"));
        // Nothing else that writes rides this token.
        let writes: Vec<&String> = scopes.iter().filter(|s| s.contains("ReadWrite")).collect();
        assert_eq!(writes.len(), 2, "{writes:?}");
    }

    #[test]
    fn group_member_scopes_pair_groupmember_with_application_readwrite() {
        // Adding a servicePrincipal member needs both scopes in ONE token.
        let scopes = EntraAuthService::new("c", "t").default_graph_group_member_scopes();
        for perm in ["GroupMember.ReadWrite.All", "Application.ReadWrite.All"] {
            assert!(
                scopes
                    .iter()
                    .any(|s| s == &format!("https://graph.microsoft.com/{perm}")),
                "missing {perm}: {scopes:?}"
            );
        }
        assert!(scopes.iter().any(|s| s == "offline_access"));
        // Membership only: never the group create/delete scope.
        let writes: Vec<&String> = scopes.iter().filter(|s| s.contains("ReadWrite")).collect();
        assert_eq!(writes.len(), 2, "{writes:?}");
        assert!(
            !scopes.iter().any(|s| s.ends_with("/Group.ReadWrite.All")),
            "{scopes:?}"
        );
    }

    #[test]
    fn graph_scope_sets_are_told_apart_from_other_audiences() {
        let svc = EntraAuthService::new("c", "t");
        for graph in [
            svc.default_graph_read_scopes(),
            svc.default_graph_write_scopes(),
            svc.default_graph_sync_scopes(),
            svc.default_graph_audit_log_scopes(),
            svc.default_graph_policy_scopes(),
            svc.default_graph_policy_write_scopes(),
            svc.default_graph_sharepoint_scopes(),
            svc.default_graph_group_member_scopes(),
        ] {
            assert!(svc.is_graph_scope_set(&graph), "{graph:?}");
        }
        for other in [
            svc.default_exchange_scopes(),
            EntraAuthService::resource_default_scopes("https://management.azure.com"),
            EntraAuthService::resource_default_scopes("https://vault.azure.net"),
            // Only reserved scopes: no audience at all.
            vec!["offline_access".to_string(), "openid".to_string()],
            vec![],
        ] {
            assert!(!svc.is_graph_scope_set(&other), "{other:?}");
        }
        // A mixed set is not a Graph set.
        let mixed = vec![
            "https://graph.microsoft.com/User.Read".to_string(),
            "https://management.azure.com/.default".to_string(),
        ];
        assert!(!svc.is_graph_scope_set(&mixed));
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
    fn exchange_scopes_follow_the_selected_cloud() {
        let scopes = EntraAuthService::new_in_cloud("c", "t", CloudEnvironment::UsGov)
            .default_exchange_scopes();
        assert!(
            scopes
                .iter()
                .any(|s| s == "https://outlook.office365.us/Exchange.Manage"),
            "{scopes:?}"
        );
        assert!(scopes.iter().any(|s| s == "offline_access"));
        assert!(
            !scopes.iter().any(|s| s.contains("office365.com")),
            "{scopes:?}"
        );
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
