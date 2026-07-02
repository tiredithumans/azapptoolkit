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
    DirectoryRole,
    /// Best-effort Exchange RBAC probe (a benign admin-API call): success ⇒ has
    /// it, a diagnosed 403 ⇒ missing, anything else (incl. a bodyless 403) ⇒
    /// indeterminate.
    ExchangeProbe,
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
    /// Directory-role display names that satisfy the role half — **any one** is
    /// sufficient (encodes built-in alternatives, e.g. Global Administrator OR
    /// Cloud Application Administrator). For Azure/Exchange planes these name the
    /// RBAC role for *display only* (not directory-enumerable).
    pub directory_roles_any: &'static [&'static str],
    /// The immutable `roleTemplateId`s matching `directory_roles_any`, index-
    /// aligned. **Matching must use these, not the display names**: the
    /// `directoryRole` objects in long-lived tenants carry legacy names —
    /// the SharePoint Administrator role reads "SharePoint Service
    /// Administrator" from Graph (Microsoft documents the rename), Global
    /// Administrator historically "Company Administrator" — so a name match
    /// silently reports an active role as missing. Empty for the Azure /
    /// Exchange planes (not directory-enumerable).
    pub directory_role_template_ids_any: &'static [&'static str],
    pub role_detect: RoleDetect,
    /// Delegated scope name(s) this capability needs, for display. **All** required.
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

/// The catalog. Derived from `docs/operator-rbac/OPERATOR-ROLES.md`.
pub static CAPABILITIES: &[Capability] = &[
    Capability {
        key: "app_registrations",
        plane: Plane::EntraDirectory,
        label: "App registration management",
        description: "Create, update, and delete app registrations; manage credentials, owners, \
                      and authentication.",
        directory_roles_any: &[
            "Application Administrator",
            "Cloud Application Administrator",
            "Global Administrator",
        ],
        directory_role_template_ids_any: &[
            TID_APPLICATION_ADMIN,
            TID_CLOUD_APPLICATION_ADMIN,
            TID_GLOBAL_ADMIN,
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
            "Application Administrator",
            "Cloud Application Administrator",
            "Global Administrator",
        ],
        directory_role_template_ids_any: &[
            TID_APPLICATION_ADMIN,
            TID_CLOUD_APPLICATION_ADMIN,
            TID_GLOBAL_ADMIN,
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
        description: "Grant tenant-wide admin consent to delegated scopes and application roles.",
        directory_roles_any: &["Privileged Role Administrator", "Global Administrator"],
        directory_role_template_ids_any: &[TID_PRIVILEGED_ROLE_ADMIN, TID_GLOBAL_ADMIN],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &[
            "DelegatedPermissionGrant.ReadWrite.All",
            "AppRoleAssignment.ReadWrite.All",
        ],
        scope_feature: Some("write"),
        remediation: "Granting admin consent — especially to high-privilege Graph permissions \
                      like Application.ReadWrite.All — requires the Privileged Role Administrator \
                      or Global Administrator role. A custom or Cloud Application Administrator \
                      role is not sufficient for sensitive permissions.",
    },
    Capability {
        key: "audit_reports",
        plane: Plane::EntraDirectory,
        label: "Activity & sign-in reports",
        description: "Directory audit log (Activity tab) and service-principal sign-in activity \
                      (unused-app detection).",
        directory_roles_any: &[
            "Reports Reader",
            "Security Reader",
            "Security Administrator",
            "Global Reader",
            "Global Administrator",
        ],
        directory_role_template_ids_any: &[
            TID_REPORTS_READER,
            TID_SECURITY_READER,
            TID_SECURITY_ADMIN,
            TID_GLOBAL_READER,
            TID_GLOBAL_ADMIN,
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
            "Security Reader",
            "Security Administrator",
            "Conditional Access Administrator",
            "Global Reader",
            "Global Administrator",
        ],
        directory_role_template_ids_any: &[
            TID_SECURITY_READER,
            TID_SECURITY_ADMIN,
            TID_CONDITIONAL_ACCESS_ADMIN,
            TID_GLOBAL_READER,
            TID_GLOBAL_ADMIN,
        ],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["Policy.Read.All"],
        scope_feature: Some("policy"),
        remediation: "Conditional Access visibility needs the Policy.Read.All scope and a role \
                      that can read policies (Security Reader or Global Reader), plus an Entra ID \
                      P1/P2 license.",
    },
    Capability {
        key: "sharepoint_sites_selected",
        plane: Plane::EntraDirectory,
        label: "SharePoint site access (Sites.Selected)",
        description: "List, grant, and revoke a site's per-app permissions; convert org-wide \
                      Sites.* to Sites.Selected.",
        directory_roles_any: &["SharePoint Administrator", "Global Administrator"],
        directory_role_template_ids_any: &[TID_SHAREPOINT_ADMIN, TID_GLOBAL_ADMIN],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["Sites.FullControl.All"],
        scope_feature: Some("sharepoint"),
        remediation: "Managing SharePoint site permissions requires the SharePoint Administrator \
                      role (or Global Administrator) and the Sites.FullControl.All scope — the \
                      site-permission endpoints need it even for reads.",
    },
    Capability {
        key: "group_membership",
        plane: Plane::EntraDirectory,
        label: "Security-group membership",
        description: "Add or remove a service principal as a member of a security group — the \
                      access model for group-gated APIs like Power BI / Fabric.",
        directory_roles_any: &[
            "Groups Administrator",
            "User Administrator",
            "Global Administrator",
        ],
        directory_role_template_ids_any: &[TID_GROUPS_ADMIN, TID_USER_ADMIN, TID_GLOBAL_ADMIN],
        role_detect: RoleDetect::DirectoryRole,
        scopes: &["GroupMember.ReadWrite.All"],
        scope_feature: Some("group_membership"),
        remediation: "Changing group membership needs the Groups Administrator role (User \
                      Administrator or Global Administrator also work) — or ownership of the \
                      target group — plus the GroupMember.ReadWrite.All delegated scope, \
                      consented on first use. Dynamic-membership groups can't be modified \
                      directly (membership is rule-based).",
    },
    Capability {
        key: "keyvault_secrets",
        plane: Plane::AzureRbac,
        label: "Key Vault secrets",
        description: "List, read, create, and rotate Key Vault secrets.",
        directory_roles_any: &["Key Vault Secrets Officer"],
        directory_role_template_ids_any: &[],
        role_detect: RoleDetect::Indeterminate,
        scopes: &["https://vault.azure.net/.default"],
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
        directory_roles_any: &["Reader"],
        directory_role_template_ids_any: &[],
        role_detect: RoleDetect::Indeterminate,
        scopes: &["https://management.azure.com/.default"],
        scope_feature: Some("arm"),
        remediation: "Reading Azure role assignments needs the Reader role (or a custom role with \
                      Microsoft.Authorization/roleAssignments/read and roleDefinitions/read) on \
                      the subscription, plus the ARM (management.azure.com) scope.",
    },
    Capability {
        key: "graph_activity_usage",
        plane: Plane::AzureRbac,
        label: "Graph activity usage",
        description: "Read MicrosoftGraphActivityLogs from a Log Analytics workspace to compare \
                      an app's granted permissions with its observed Graph calls.",
        directory_roles_any: &["Log Analytics Reader"],
        directory_role_template_ids_any: &[],
        role_detect: RoleDetect::Indeterminate,
        scopes: &["https://api.loganalytics.azure.com/.default"],
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
        directory_roles_any: &["User Access Administrator", "Owner"],
        directory_role_template_ids_any: &[],
        role_detect: RoleDetect::Indeterminate,
        scopes: &["https://management.azure.com/.default"],
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
        directory_roles_any: &["Exchange Administrator"],
        directory_role_template_ids_any: &[],
        role_detect: RoleDetect::ExchangeProbe,
        scopes: &["https://outlook.office365.com/Exchange.Manage"],
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

/// The capability with this `key`, or `None`. Used by command-level 403 hints
/// (mechanism 1) and the proactive `RequiresRole` label (mechanism 2).
pub fn capability(key: &str) -> Option<&'static Capability> {
    CAPABILITIES.iter().find(|c| c.key == key)
}

/// Every capability on `plane`, in catalog order. Used to group the readiness
/// checklist by plane.
pub fn capabilities_for_plane(plane: Plane) -> impl Iterator<Item = &'static Capability> {
    CAPABILITIES.iter().filter(move |c| c.plane == plane)
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
    // Template-id match: catalog ids are index-aligned with the display names.
    for role in active_roles {
        if let Some(tid) = role.role_template_id.as_deref()
            && let Some(i) = cap
                .directory_role_template_ids_any
                .iter()
                .position(|want| want.eq_ignore_ascii_case(tid))
        {
            // The names/ids lists are index-aligned; guard anyway.
            return cap.directory_roles_any.get(i).copied();
        }
    }
    // Display-name fallback (covers a role listed without a template id).
    cap.directory_roles_any.iter().copied().find(|needed| {
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
    fn directory_role_names_and_template_ids_are_index_aligned() {
        // matched_directory_role maps a template-id hit back to the display
        // name at the same index — the two lists must stay in lockstep.
        for c in CAPABILITIES {
            if c.role_detect == RoleDetect::DirectoryRole {
                assert_eq!(
                    c.directory_roles_any.len(),
                    c.directory_role_template_ids_any.len(),
                    "{}: directory_roles_any and directory_role_template_ids_any lengths differ",
                    c.key
                );
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
    fn azure_and_exchange_capabilities_are_not_directory_enumerable() {
        // These planes can't be verified from /me directory-role membership, so
        // the checklist falls back to a probe ("?") — guard the detect method.
        assert_eq!(
            capability("keyvault_secrets").unwrap().role_detect,
            RoleDetect::Indeterminate
        );
        assert_eq!(
            capability("exchange_rbac").unwrap().role_detect,
            RoleDetect::ExchangeProbe
        );
    }

    #[test]
    fn three_planes_are_represented() {
        assert!(capabilities_for_plane(Plane::EntraDirectory).count() >= 1);
        assert!(capabilities_for_plane(Plane::AzureRbac).count() >= 1);
        assert!(capabilities_for_plane(Plane::ExchangeRbac).count() >= 1);
    }
}
