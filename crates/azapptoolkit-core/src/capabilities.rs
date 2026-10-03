//! Authorization-capability catalog: the single source of truth mapping each
//! privileged feature area to the role(s) and delegated OAuth scope(s) it needs.
//!
//! azapptoolkit is a delegated public client — every action runs with the
//! signed-in user's rights across **three independent authorization planes**
//! ([`Plane`]), each with its own role model and its own PIM. There is no single
//! role that unlocks the whole app (see `docs/operator-rbac/OPERATOR-ROLES.md`),
//! so the UI instead tells the user *which* role each function needs. All three
//! feedback mechanisms read from this one table so the guidance never drifts:
//!   - reactive 403 hints (a backend error appends [`Capability::remediation`]),
//!   - proactive "Requires: …" labels (`web-rs`'s `RequiresRole` component),
//!   - the live readiness checklist (the `check_readiness` command + view).
//!
//! Two halves, both required (OPERATOR-ROLES.md "Two halves, both required"): a
//! feature needs the standing **role** (`directory_roles_any` / an Azure/Exchange
//! RBAC role) *and* the consented delegated **scope** (`scopes` / `scope_feature`).
//! The checklist reports them as distinct signals.
//!
//! Pure data + pure functions — no I/O, no wasm-gated deps — so the Tauri backend
//! and the WASM frontend both depend on it directly (mirrors [`crate::scoping`]).
//! Keep it in sync with `docs/operator-rbac/OPERATOR-ROLES.md`.

use crate::cloud::CloudEnvironment;

/// One of the three independent authorization planes a capability lives on. Each
/// has its own role model and its own PIM (`OPERATOR-ROLES.md` table, lines 13-17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plane {
    /// Entra ID directory roles — PIM for Microsoft Entra roles.
    EntraDirectory,
    /// Azure RBAC (ARM + Key Vault) — PIM for Azure resources.
    AzureRbac,
    /// Exchange Online RBAC — activated via the Entra "Exchange Administrator"
    /// role (PIM for Entra roles) but enforced inside Exchange's own RBAC.
    ExchangeRbac,
}

impl Plane {
    /// Stable snake_case key crossing the IPC boundary (the DTO `plane` field).
    pub fn as_str(self) -> &'static str {
        match self {
            Plane::EntraDirectory => "entra_directory",
            Plane::AzureRbac => "azure_rbac",
            Plane::ExchangeRbac => "exchange_rbac",
        }
    }

    /// Human-readable plane name for the checklist's section header.
    pub fn label(self) -> &'static str {
        match self {
            Plane::EntraDirectory => "Entra ID directory roles",
            Plane::AzureRbac => "Azure RBAC",
            Plane::ExchangeRbac => "Exchange Online RBAC",
        }
    }
}

/// How the readiness checklist can verify the **role** half of a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleDetect {
    /// Active directory-role membership is enumerable from `/me` — match the
    /// user's active roles against [`Capability::directory_roles_any`]. PIM-
    /// eligible-but-inactive roles are absent (the intended nudge to activate).
    /// Exchange Online RBAC uses this too: it's activated via the Entra
    /// "Exchange Administrator" role, which `/me` reports like any other.
    DirectoryRole,
    /// Not cheaply enumerable per-user (Azure RBAC is per-subscription/-vault) →
    /// the checklist reports "?" with guidance to verify in PIM.
    Indeterminate,
}

/// A privileged feature area mapped to what it needs on the role and scope axes.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    /// Stable machine key — also the lookup key from command-level 403 hints and
    /// the proactive-label call sites (e.g. `"admin_consent"`).
    pub key: &'static str,
    pub plane: Plane,
    /// Short human label shown in "Requires: {label}" and as the checklist title.
    pub label: &'static str,
    pub description: &'static str,
    /// The roles that satisfy the role half — **any one** is sufficient
    /// (encodes built-in alternatives, e.g. Global Administrator OR Cloud
    /// Application Administrator). Each entry pairs the display name with the
    /// immutable `roleTemplateId` when the role is directory-enumerable.
    /// **Matching must use the template id, not the display name**: the
    /// `directoryRole` objects in long-lived tenants carry legacy names — the
    /// SharePoint Administrator role reads "SharePoint Service Administrator"
    /// from Graph (Microsoft documents the rename), Global Administrator
    /// historically "Company Administrator" — so a name match silently reports
    /// an active role as missing. `None` marks the Azure / Exchange planes'
    /// display-only rows (not directory-enumerable). Pairing name and id in
    /// one entry makes a misaligned name/id unrepresentable (the old parallel
    /// index-aligned slices needed a test to police alignment — and the
    /// v0.12.0 "Role missing" bug lived exactly there).
    pub directory_roles_any: &'static [(&'static str, Option<&'static str>)],
    pub role_detect: RoleDetect,
    /// Delegated scope name(s) this capability needs, for display. **All** required.
    /// Graph scopes are bare names; a resource audience is written as a
    /// `{keyvault}` / `{arm}` / `{log_analytics}` / `{exchange}` placeholder that
    /// [`Capability::display_scopes`] expands for the configured cloud, so the
    /// catalog never hardcodes one cloud's host.
    pub scopes: &'static [&'static str],
    /// The `AppState::consent_scopes_for` feature key used to silently probe scope
    /// consent in the checklist, or `None` when the scope half isn't separately
    /// probable (always present once signed in).
    pub scope_feature: Option<&'static str>,
    /// "What to do" guidance — appended to a matching 403 (mechanism 1), shown
    /// under a missing checklist row, and in the proactive-label tooltip. The
    /// single copy of each role-requirement string.
    pub remediation: &'static str,
}

// Well-known Entra built-in role template ids (immutable, tenant-independent).
// Source: https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference
const TID_APPLICATION_ADMIN: &str = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3";
const TID_CLOUD_APPLICATION_ADMIN: &str = "158c047a-c907-4556-b7ef-446551a6b5f7";
const TID_GLOBAL_ADMIN: &str = "62e90394-69f5-4237-9190-012177145e10";
const TID_GLOBAL_READER: &str = "f2ef992c-3afb-46b9-b7cf-a126ee74c451";
const TID_PRIVILEGED_ROLE_ADMIN: &str = "e8611ab8-c189-46e8-94e1-60213ab1f814";
const TID_REPORTS_READER: &str = "4a5d8f65-41da-4de4-8968-e035b65339cf";
const TID_SECURITY_READER: &str = "5d6b6bb7-de71-4623-b4af-96380a352509";
const TID_SECURITY_ADMIN: &str = "194ae4cb-b126-40b2-bd5b-6091b380977d";
const TID_CONDITIONAL_ACCESS_ADMIN: &str = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9";
const TID_SHAREPOINT_ADMIN: &str = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c";
const TID_GROUPS_ADMIN: &str = "fdd7a751-b60b-444a-984c-02652fe8fa1c";
const TID_USER_ADMIN: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";
const TID_EXCHANGE_ADMIN: &str = "29232cdf-9323-42fd-ade2-1d097af3e4de";
const TID_HYBRID_IDENTITY_ADMIN: &str = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2";

/// The catalog. Derived from `docs/operator-rbac/OPERATOR-ROLES.md`.
pub static CAPABILITIES: &[Capability] = &[
    Capability {
        key: "app_registrations",
        plane: Plane::EntraDirectory,
        label: "App registration management",
        description: "Create, update, and delete app registrations; manage credentials, owners, \
                      and authentication.",
        directory_roles_any: &[
            ("Application Administrator", Some(TID_APPLICATION_ADMIN)),
            (
                "Cloud Application Administrator",
                Some(TID_CLOUD_APPLICATION_ADMIN),
            ),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["Application.ReadWrite.All", "Directory.Read.All"],
        scope_feature: Some("write"),
        remediation: "Activate an Entra role that can manage app registrations — Application \
                      Administrator or Cloud Application Administrator (Global Administrator also \
                      works). Write access additionally needs the Application.ReadWrite.All \
                      delegated scope, consented on the first write.",
    },
    Capability {
        key: "tenant_restore",
        plane: Plane::EntraDirectory,
        label: "Disaster-recovery restore",
        description: "Recreate app registrations from a backup, re-grant their permissions, and \
                      regenerate their client secrets in the current tenant.",
        directory_roles_any: &[
            ("Application Administrator", Some(TID_APPLICATION_ADMIN)),
            (
                "Cloud Application Administrator",
                Some(TID_CLOUD_APPLICATION_ADMIN),
            ),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &[
            "Application.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
            "DelegatedPermissionGrant.ReadWrite.All",
        ],
        scope_feature: Some("write"),
        remediation: "Restoring creates app registrations and grants their permissions: it needs an \
                      app-management role (Application Administrator or Cloud Application \
                      Administrator) to create apps and credentials, and re-granting admin consent \
                      to sensitive Graph permissions additionally needs Privileged Role \
                      Administrator or Global Administrator. (Backup itself is read-only — \
                      Directory.Read.All, consented at sign-in.)",
    },
    Capability {
        key: "admin_consent",
        plane: Plane::EntraDirectory,
        label: "Admin consent for API permissions",
        // The Graph gate lives in the *description*, not only the remediation:
        // the checklist hides a remediation once both halves read "have", and an
        // active Cloud Application Administrator reads "have" here yet still
        // can't grant Microsoft Graph app roles.
        description: "Grant tenant-wide admin consent to delegated scopes and application roles. \
                      Application Administrator or Cloud Application Administrator can consent \
                      for any API except Microsoft Graph (and Azure AD Graph) application roles, \
                      which need Privileged Role Administrator or Global Administrator.",
        // Privileged Role Administrator stays first: `RequiresRole` shows the
        // first role as its label, and it is the one role that covers the Graph
        // app roles the Permissions tab grants most.
        directory_roles_any: &[
            (
                "Privileged Role Administrator",
                Some(TID_PRIVILEGED_ROLE_ADMIN),
            ),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
            ("Application Administrator", Some(TID_APPLICATION_ADMIN)),
            (
                "Cloud Application Administrator",
                Some(TID_CLOUD_APPLICATION_ADMIN),
            ),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &[
            "DelegatedPermissionGrant.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
        ],
        scope_feature: Some("write"),
        remediation: "Granting admin consent needs Application Administrator or Cloud \
                      Application Administrator for most APIs, but Microsoft Graph (and Azure AD \
                      Graph) application roles — like Application.ReadWrite.All — need Privileged \
                      Role Administrator or Global Administrator. A custom role is not sufficient \
                      for sensitive Graph permissions.",
    },
    Capability {
        key: "audit_reports",
        plane: Plane::EntraDirectory,
        label: "Activity & sign-in reports",
        description: "Directory audit log (Activity tab), service-principal sign-in activity \
                      (unused-app detection), and per-credential last-used data. The credential \
                      report is beta and served in the Global cloud only — elsewhere the \
                      Last-used signals degrade to unknown.",
        directory_roles_any: &[
            ("Reports Reader", Some(TID_REPORTS_READER)),
            ("Security Reader", Some(TID_SECURITY_READER)),
            ("Security Administrator", Some(TID_SECURITY_ADMIN)),
            ("Global Reader", Some(TID_GLOBAL_READER)),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["AuditLog.Read.All"],
        scope_feature: Some("audit_log"),
        remediation: "The directory activity log and sign-in reports need the AuditLog.Read.All \
                      scope plus a reporting role (Reports Reader, Security Reader, or Global \
                      Reader). Sign-in activity (unused-app detection) additionally requires an \
                      Entra ID P1 or P2 license.",
    },
    Capability {
        key: "conditional_access",
        plane: Plane::EntraDirectory,
        label: "Conditional Access (read)",
        description: "View the Conditional Access policies that target an app.",
        directory_roles_any: &[
            ("Security Reader", Some(TID_SECURITY_READER)),
            ("Security Administrator", Some(TID_SECURITY_ADMIN)),
            (
                "Conditional Access Administrator",
                Some(TID_CONDITIONAL_ACCESS_ADMIN),
            ),
            ("Global Reader", Some(TID_GLOBAL_READER)),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["Policy.Read.All"],
        scope_feature: Some("policy"),
        remediation: "Conditional Access visibility needs the Policy.Read.All scope and a role \
                      that can read policies (Security Reader or Global Reader), plus an Entra ID \
                      P1/P2 license.",
    },
    Capability {
        key: "identity_protection_risk",
        plane: Plane::EntraDirectory,
        label: "Identity Protection risky-service-principal report (read)",
        description: "Read the risky-service-principal report so the tenant audit flags \
                      service principals Identity Protection marks at risk or compromised.",
        directory_roles_any: &[
            ("Security Reader", Some(TID_SECURITY_READER)),
            ("Security Administrator", Some(TID_SECURITY_ADMIN)),
            ("Global Reader", Some(TID_GLOBAL_READER)),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["IdentityRiskyServicePrincipal.Read.All"],
        scope_feature: Some("risky_service_principals"),
        remediation: "The risky-service-principal report needs the \
                      IdentityRiskyServicePrincipal.Read.All scope and a security-read role \
                      (Security Reader or Global Reader), plus a Workload Identities premium \
                      license — without the license the endpoint answers 403 \
                      Authentication_RequestFromNonPremiumTenantOrB2CTenant.",
    },
    Capability {
        key: "sharepoint_sites_selected",
        plane: Plane::EntraDirectory,
        label: "SharePoint resource access (Selected permissions)",
        description: "List, grant, and revoke a site's, list's, folder's or file's per-app \
                      permissions; convert org-wide Sites.* to Sites.Selected.",
        directory_roles_any: &[
            ("SharePoint Administrator", Some(TID_SHAREPOINT_ADMIN)),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["Sites.FullControl.All"],
        scope_feature: Some("sharepoint"),
        remediation: "Managing SharePoint permissions requires the SharePoint Administrator \
                      role (or Global Administrator) and the Sites.FullControl.All scope — the \
                      permission endpoints need it even for reads, at every level from a site \
                      collection down to a single file.",
    },
    Capability {
        key: "sharepoint_selected_items",
        plane: Plane::EntraDirectory,
        label: "SharePoint resource access (list, folder and file level)",
        // The extra half lives in the *description*, not only the remediation:
        // the checklist hides a remediation once both axes read "have", and
        // both axes DO read "have" for a SharePoint Administrator who still
        // can't call these endpoints. Stating it here keeps the row honest.
        description: "List, grant, and revoke a list's, folder's or file's per-app permissions \
                      (the Lists./ListItems./Files.SelectedOperations.Selected model). Also needs \
                      Full Control on the target site itself, which the tenant SharePoint \
                      Administrator role does not confer.",
        directory_roles_any: &[
            ("SharePoint Administrator", Some(TID_SHAREPOINT_ADMIN)),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["Sites.FullControl.All"],
        scope_feature: Some("sharepoint"),
        // Distinct from `sharepoint_sites_selected` because the requirement is
        // genuinely different, not merely worded differently: a delegated call
        // is the intersection of the token's scopes and the signed-in user's
        // own SharePoint permissions, and a grant below the site collection
        // writes a role assignment onto a securable inside the site's content.
        // The tenant admin flag covers the site-collection root; it does not
        // reach into the site's ACL.
        remediation: "Granting at the list, folder or file level needs the Sites.FullControl.All \
                      scope AND Full Control on the target site itself — a delegated call can \
                      never exceed your own SharePoint permissions. The tenant SharePoint \
                      Administrator role covers site-collection grants (Sites.Selected) but not \
                      securables inside a site, so add yourself as a site collection \
                      administrator, or to the site's Owners group, on that site. If the role was \
                      only just assigned or is PIM-eligible, activate it and sign out and back in \
                      so the new token carries it.",
    },
    Capability {
        key: "group_membership",
        plane: Plane::EntraDirectory,
        label: "Security-group membership",
        description: "Add or remove a service principal as a member of a security group — the \
                      access model for group-gated APIs like Power BI / Fabric.",
        directory_roles_any: &[
            ("Groups Administrator", Some(TID_GROUPS_ADMIN)),
            ("User Administrator", Some(TID_USER_ADMIN)),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["GroupMember.ReadWrite.All", "Application.ReadWrite.All"],
        scope_feature: Some("group_membership"),
        remediation: "Changing group membership needs the Groups Administrator role (User \
                      Administrator or Global Administrator also work) — or ownership of the \
                      target group — plus the GroupMember.ReadWrite.All and \
                      Application.ReadWrite.All delegated scopes (Graph needs both to add a \
                      service principal as a member), consented on first use. \
                      Dynamic-membership groups can't be modified directly (membership is \
                      rule-based).",
    },
    Capability {
        key: "provisioning_read",
        plane: Plane::EntraDirectory,
        label: "SCIM provisioning status (read)",
        description: "Read an enterprise application's SCIM provisioning jobs and their last run \
                      (Provisioning tab).",
        // Learn "List synchronization jobs": supported roles.
        directory_roles_any: &[
            ("Application Administrator", Some(TID_APPLICATION_ADMIN)),
            (
                "Cloud Application Administrator",
                Some(TID_CLOUD_APPLICATION_ADMIN),
            ),
            (
                "Hybrid Identity Administrator",
                Some(TID_HYBRID_IDENTITY_ADMIN),
            ),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["Synchronization.Read.All"],
        scope_feature: Some("sync"),
        remediation: "Provisioning status needs the Synchronization.Read.All delegated scope \
                      (admin consent, granted on first use) and a role that can read provisioning \
                      — Application Administrator, Cloud Application Administrator or Hybrid \
                      Identity Administrator (Global Administrator also works). The provisioning \
                      service also needs an Entra ID P1 or P2 license.",
    },
    Capability {
        key: "sso_claims_mapping",
        plane: Plane::EntraDirectory,
        label: "SAML claims mapping",
        description: "Create, edit and assign the claims-mapping policy that customises an SSO \
                      app's token claims.",
        directory_roles_any: &[
            ("Application Administrator", Some(TID_APPLICATION_ADMIN)),
            (
                "Cloud Application Administrator",
                Some(TID_CLOUD_APPLICATION_ADMIN),
            ),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        // One token (`default_graph_policy_write_scopes`): the policy object
        // needs the Policy scope, the service-principal `$ref` assign/list/remove
        // need both.
        scopes: &[
            "Policy.ReadWrite.ApplicationConfiguration",
            "Application.ReadWrite.All",
        ],
        scope_feature: Some("policy_write"),
        remediation: "Custom claims need an Entra role that can manage application policies — \
                      Application Administrator or Cloud Application Administrator (Global \
                      Administrator also works) — plus the \
                      Policy.ReadWrite.ApplicationConfiguration and Application.ReadWrite.All \
                      delegated scopes, consented on first use.",
    },
    Capability {
        key: "keyvault_secrets",
        plane: Plane::AzureRbac,
        label: "Key Vault secrets",
        description: "List, read, create, and rotate Key Vault secrets.",
        directory_roles_any: &[("Key Vault Secrets Officer", None)],
        role_detect: RoleDetect::Indeterminate,
        scopes: &["{keyvault}/.default"],
        scope_feature: Some("keyvault"),
        remediation: "Key Vault secret access needs an Azure RBAC role on the vault — Key Vault \
                      Secrets Officer (or the equivalent custom role's secret DataActions) — and \
                      the vault must use RBAC permission mode, not legacy access policies.",
    },
    Capability {
        key: "azure_role_reads",
        plane: Plane::AzureRbac,
        label: "Managed-identity Azure role reads",
        description: "Read a managed identity's Azure RBAC role assignments.",
        directory_roles_any: &[("Reader", None)],
        role_detect: RoleDetect::Indeterminate,
        scopes: &["{arm}/.default"],
        scope_feature: Some("arm"),
        remediation: "Reading Azure role assignments needs the Reader role (or a custom role with \
                      Microsoft.Authorization/roleAssignments/read and roleDefinitions/read) on \
                      the subscription, plus the ARM (management.azure.com) scope.",
    },
    Capability {
        key: "keyvault_rbac_reads",
        plane: Plane::AzureRbac,
        label: "Key Vault RBAC reverse lookup",
        description: "List every Key Vault and the principals holding Azure RBAC roles on it.",
        directory_roles_any: &[("Reader", None)],
        role_detect: RoleDetect::Indeterminate,
        scopes: &["{arm}/.default"],
        scope_feature: Some("arm"),
        remediation: "Enumerating Key Vaults and their role assignments needs the Reader role (or \
                      a custom role with Microsoft.KeyVault/vaults/read and \
                      Microsoft.Authorization/roleAssignments/read) across the subscriptions, plus \
                      the ARM (management.azure.com) scope.",
    },
    Capability {
        key: "graph_activity_usage",
        plane: Plane::AzureRbac,
        label: "Graph activity usage",
        description: "Read MicrosoftGraphActivityLogs from a Log Analytics workspace to compare \
                      an app's granted permissions with its observed Graph calls.",
        directory_roles_any: &[("Log Analytics Reader", None)],
        role_detect: RoleDetect::Indeterminate,
        scopes: &["{log_analytics}/.default"],
        scope_feature: Some("log_analytics"),
        remediation: "Usage analysis needs Microsoft Entra diagnostic settings exporting \
                      MicrosoftGraphActivityLogs to a Log Analytics workspace, the Log Analytics \
                      Reader Azure RBAC role (or Reader) on that workspace, plus the \
                      api.loganalytics.azure.com scope.",
    },
    Capability {
        key: "azure_role_assign",
        plane: Plane::AzureRbac,
        label: "Assign Azure role to a managed identity",
        description: "Create an Azure RBAC role assignment for a managed identity.",
        directory_roles_any: &[("User Access Administrator", None), ("Owner", None)],
        role_detect: RoleDetect::Indeterminate,
        scopes: &["{arm}/.default"],
        scope_feature: Some("arm"),
        remediation: "Assigning an Azure role needs Owner or User Access Administrator (the \
                      Microsoft.Authorization/roleAssignments/write permission) on the target \
                      subscription, resource group, or resource.",
    },
    Capability {
        key: "exchange_rbac",
        plane: Plane::ExchangeRbac,
        label: "Exchange mailbox scoping (RBAC for Applications)",
        description: "Scope mail/calendar/contacts permissions to specific mailboxes and resolve \
                      effective scope.",
        directory_roles_any: &[
            ("Exchange Administrator", Some(TID_EXCHANGE_ADMIN)),
            ("Global Administrator", Some(TID_GLOBAL_ADMIN)),
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["{exchange}/Exchange.Manage"],
        scope_feature: Some("exchange"),
        remediation: "Exchange RBAC for Applications needs your account in a role group \
                      containing the \"Role Management\" role (e.g. Organization Management); \
                      creating and populating the toolkit's scope group additionally needs the \
                      \"Distribution Groups\" role (in Recipient Management / Organization \
                      Management). The Entra \"Exchange Administrator\" role grants all of these, \
                      but it must be active (not just PIM-eligible) and can take a few minutes to \
                      propagate.",
    },
];

impl Capability {
    /// Display names of the satisfying roles, in catalog order — for
    /// "Requires: …" labels and "Activate one of: …" guidance.
    pub fn role_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.directory_roles_any.iter().map(|(name, _)| *name)
    }

    /// [`scopes`](Self::scopes) with every resource placeholder expanded to
    /// `cloud`'s audience — the form the readiness checklist prints, and the
    /// form `AppState::consent_scopes_for` probes.
    pub fn display_scopes(&self, cloud: CloudEnvironment) -> Vec<String> {
        self.scopes.iter().map(|s| expand_scope(s, cloud)).collect()
    }
}

/// Expands a leading `{resource}` placeholder to `cloud`'s audience origin; a
/// bare Graph scope (or an unknown key) is returned unchanged.
fn expand_scope(scope: &str, cloud: CloudEnvironment) -> String {
    let Some((key, rest)) = scope
        .strip_prefix('{')
        .and_then(|tail| tail.split_once('}'))
    else {
        return scope.to_string();
    };
    let origin = match key {
        "keyvault" => cloud.keyvault_resource(),
        "arm" => cloud.arm_resource().to_string(),
        "log_analytics" => cloud.log_analytics_resource().to_string(),
        "exchange" => cloud.exchange_resource().to_string(),
        _ => return scope.to_string(),
    };
    format!("{origin}{rest}")
}

/// The capability with this `key`, or `None`. Used by command-level 403 hints
/// (mechanism 1) and the proactive `RequiresRole` label (mechanism 2).
pub fn capability(key: &str) -> Option<&'static Capability> {
    CAPABILITIES.iter().find(|c| c.key == key)
}

/// The first of the user's `active_roles` that satisfies the capability, or
/// `None`. Matches primarily on the immutable `roleTemplateId` — long-lived
/// tenants' `directoryRole` objects carry legacy display names ("SharePoint
/// Service Administrator", "Company Administrator"), so a name-only match
/// silently reports an active role as missing — with a case-insensitive
/// display-name fallback. Returns the **catalog** display name that matched,
/// for "Active role: …" detail text. A capability with empty role lists is
/// never satisfied this way.
pub fn matched_directory_role(
    cap: &Capability,
    active_roles: &[crate::models::ActiveDirectoryRole],
) -> Option<&'static str> {
    // Template-id match: ids are immutable while display names drift.
    for role in active_roles {
        if let Some(tid) = role.role_template_id.as_deref()
            && let Some((name, _)) = cap
                .directory_roles_any
                .iter()
                .find(|(_, want)| want.is_some_and(|w| w.eq_ignore_ascii_case(tid)))
        {
            return Some(name);
        }
    }
    // Display-name fallback (covers a role listed without a template id).
    cap.role_names().find(|needed| {
        active_roles.iter().any(|have| {
            have.display_name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(needed))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CLOUDS: [CloudEnvironment; 4] = [
        CloudEnvironment::Commercial,
        CloudEnvironment::UsGov,
        CloudEnvironment::UsGovDod,
        CloudEnvironment::China,
    ];

    #[test]
    fn no_catalog_scope_hardcodes_a_cloud_host() {
        for c in CAPABILITIES {
            for s in c.scopes {
                assert!(
                    !s.contains("://"),
                    "{}: scope {s} hardcodes a host; use a {{resource}} placeholder",
                    c.key
                );
            }
        }
    }

    #[test]
    fn every_resource_placeholder_expands_in_every_cloud() {
        for cloud in ALL_CLOUDS {
            for c in CAPABILITIES {
                let shown = c.display_scopes(cloud);
                assert_eq!(shown.len(), c.scopes.len(), "{}", c.key);
                for (raw, s) in c.scopes.iter().zip(&shown) {
                    assert!(
                        !s.contains('{') && !s.contains('}'),
                        "{cloud:?} {}: {s} left a placeholder",
                        c.key
                    );
                    if raw.starts_with('{') {
                        assert!(s.starts_with("https://"), "{cloud:?} {}: {s}", c.key);
                    }
                }
            }
        }
    }

    #[test]
    fn resource_scopes_follow_the_cloud() {
        let kv = capability("keyvault_secrets").unwrap();
        // Commercial is byte-for-byte the previously hardcoded string.
        assert_eq!(
            kv.display_scopes(CloudEnvironment::Commercial),
            ["https://vault.azure.net/.default"]
        );
        assert_eq!(
            kv.display_scopes(CloudEnvironment::UsGov),
            ["https://vault.usgovcloudapi.net/.default"]
        );
        assert_eq!(
            capability("exchange_rbac")
                .unwrap()
                .display_scopes(CloudEnvironment::China),
            ["https://partner.outlook.cn/Exchange.Manage"]
        );
        assert_eq!(
            capability("azure_role_reads")
                .unwrap()
                .display_scopes(CloudEnvironment::UsGov),
            ["https://management.usgovcloudapi.net/.default"]
        );
        assert_eq!(
            capability("graph_activity_usage")
                .unwrap()
                .display_scopes(CloudEnvironment::Commercial),
            ["https://api.loganalytics.azure.com/.default"]
        );
        let reports = capability("audit_reports").unwrap();
        for cloud in ALL_CLOUDS {
            assert_eq!(reports.display_scopes(cloud), reports.scopes, "{cloud:?}");
        }
    }

    #[test]
    fn group_membership_lists_the_service_principal_member_scope_pair() {
        // Learn "Add members": a servicePrincipal member needs both delegated
        // scopes, so the checklist must not read "have" with only the first.
        let c = CAPABILITIES
            .iter()
            .find(|c| c.key == "group_membership")
            .expect("group_membership capability");
        assert_eq!(
            c.scopes,
            &["GroupMember.ReadWrite.All", "Application.ReadWrite.All"]
        );
        assert!(c.remediation.contains("Application.ReadWrite.All"));
    }

    #[test]
    fn entra_planes_are_contiguous() {
        // The readiness view groups rows by plane in catalog order, so each
        // plane must appear as one contiguous run or it renders twice.
        let mut seen: Vec<Plane> = Vec::new();
        for c in CAPABILITIES {
            if seen.last() != Some(&c.plane) {
                assert!(
                    !seen.contains(&c.plane),
                    "{}: plane {:?} reappears after another plane",
                    c.key,
                    c.plane
                );
                seen.push(c.plane);
            }
        }
    }

    #[test]
    fn claims_mapping_and_provisioning_rows_bind_their_consent_features() {
        assert_eq!(
            capability("sso_claims_mapping").and_then(|c| c.scope_feature),
            Some("policy_write")
        );
        assert_eq!(
            capability("provisioning_read").and_then(|c| c.scope_feature),
            Some("sync")
        );
        assert_eq!(
            capability("provisioning_read").map(|c| c.scopes),
            Some(&["Synchronization.Read.All"][..])
        );
    }

    #[test]
    fn admin_consent_accepts_app_admins_and_states_the_graph_gate() {
        let cap = capability("admin_consent").unwrap();
        assert_eq!(
            matched_directory_role(
                cap,
                &[active_role(
                    "Cloud Application Administrator",
                    TID_CLOUD_APPLICATION_ADMIN
                )]
            ),
            Some("Cloud Application Administrator")
        );
        // The proactive label reads the first role; it must stay the one that
        // covers Graph app roles.
        assert_eq!(
            cap.role_names().next(),
            Some("Privileged Role Administrator")
        );
        assert!(cap.description.contains("Microsoft Graph"));
        assert!(cap.remediation.contains("Privileged Role Administrator"));
    }

    #[test]
    fn keys_are_unique() {
        let mut keys: Vec<&str> = CAPABILITIES.iter().map(|c| c.key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "capability keys must be unique");
    }

    #[test]
    fn every_capability_has_non_empty_text() {
        for c in CAPABILITIES {
            assert!(!c.label.is_empty(), "{} label empty", c.key);
            assert!(!c.description.is_empty(), "{} description empty", c.key);
            assert!(!c.remediation.is_empty(), "{} remediation empty", c.key);
            assert!(!c.scopes.is_empty(), "{} scopes empty", c.key);
        }
    }

    #[test]
    fn directory_role_capabilities_list_their_roles() {
        // A DirectoryRole capability must name at least one satisfying role, or
        // the checklist could never report it as "have".
        for c in CAPABILITIES {
            if c.role_detect == RoleDetect::DirectoryRole {
                assert!(
                    !c.directory_roles_any.is_empty(),
                    "{} is DirectoryRole but lists no roles",
                    c.key
                );
            }
        }
    }

    #[test]
    fn lookup_finds_known_and_misses_unknown() {
        assert_eq!(
            capability("admin_consent").map(|c| c.key),
            Some("admin_consent")
        );
        assert!(capability("does_not_exist").is_none());
    }

    #[test]
    fn directory_roles_satisfy_honors_alternatives_and_case() {
        let cap = capability("app_registrations").unwrap();
        // Third alternative (Global Administrator) satisfies it, by template id.
        assert_eq!(
            matched_directory_role(
                cap,
                &[active_role("Global Administrator", TID_GLOBAL_ADMIN)]
            ),
            Some("Global Administrator")
        );
        // Case-insensitive display-name fallback (no template id on the row).
        assert_eq!(
            matched_directory_role(cap, &[named_role("cloud application administrator")]),
            Some("Cloud Application Administrator")
        );
        // An unrelated role does not.
        assert_eq!(
            matched_directory_role(cap, &[active_role("User Administrator", TID_USER_ADMIN)]),
            None
        );
        // Empty active set never satisfies.
        assert_eq!(matched_directory_role(cap, &[]), None);
    }

    #[test]
    fn legacy_display_name_matches_by_template_id() {
        // The regression: Graph names the SharePoint Administrator directory
        // role "SharePoint Service Administrator" (documented legacy name), so
        // a name-only match reported an ACTIVE role as missing. The immutable
        // template id must match regardless of the display name.
        let cap = capability("sharepoint_sites_selected").unwrap();
        assert_eq!(
            matched_directory_role(
                cap,
                &[active_role(
                    "SharePoint Service Administrator",
                    TID_SHAREPOINT_ADMIN
                )]
            ),
            Some("SharePoint Administrator")
        );
        // Same family: "Company Administrator" is Global Administrator.
        assert_eq!(
            matched_directory_role(
                cap,
                &[active_role("Company Administrator", TID_GLOBAL_ADMIN)]
            ),
            Some("Global Administrator")
        );
    }

    #[test]
    fn directory_role_capabilities_carry_template_ids() {
        // Matching is template-id-first; a DirectoryRole-detect entry without
        // an id would silently fall back to display-name matching — the exact
        // legacy-name bug (v0.12.0 "Role missing") the ids exist to prevent.
        for c in CAPABILITIES {
            if c.role_detect == RoleDetect::DirectoryRole {
                for (name, tid) in c.directory_roles_any {
                    assert!(tid.is_some(), "{}: role {name} lacks a template id", c.key);
                }
            }
        }
    }

    fn active_role(name: &str, template_id: &str) -> crate::models::ActiveDirectoryRole {
        crate::models::ActiveDirectoryRole {
            id: "role-obj".into(),
            display_name: Some(name.into()),
            role_template_id: Some(template_id.into()),
        }
    }

    fn named_role(name: &str) -> crate::models::ActiveDirectoryRole {
        crate::models::ActiveDirectoryRole {
            id: "role-obj".into(),
            display_name: Some(name.into()),
            role_template_id: None,
        }
    }

    #[test]
    fn azure_rbac_is_not_directory_enumerable() {
        // Azure RBAC is per-subscription/-vault, so it can't be verified from
        // /me directory-role membership — guard the "?" detect method.
        assert_eq!(
            capability("keyvault_secrets").unwrap().role_detect,
            RoleDetect::Indeterminate
        );
    }

    #[test]
    fn exchange_rbac_is_detected_via_the_entra_exchange_admin_role() {
        // Exchange Online RBAC is activated through the Entra "Exchange
        // Administrator" role, which /me reports — so it's directory-enumerable,
        // not an opaque probe. The template id (not the drift-prone display name)
        // is what the matcher keys on.
        let cap = capability("exchange_rbac").unwrap();
        assert_eq!(cap.role_detect, RoleDetect::DirectoryRole);
        assert!(cap.directory_roles_any.iter().any(|(name, tid)| *name
            == "Exchange Administrator"
            && *tid == Some(TID_EXCHANGE_ADMIN)));
    }

    #[test]
    fn three_planes_are_represented() {
        for plane in [Plane::EntraDirectory, Plane::AzureRbac, Plane::ExchangeRbac] {
            assert!(
                CAPABILITIES.iter().any(|c| c.plane == plane),
                "no capability on {plane:?}"
            );
        }
    }
}
