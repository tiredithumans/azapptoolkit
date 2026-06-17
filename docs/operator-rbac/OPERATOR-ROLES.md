# Operator RBAC — PIM-activatable roles for azapptoolkit

This folder describes the **least-privilege roles a human operator needs to run azapptoolkit**, all
PIM-eligible. It is operator/deployment documentation — it does not affect the app's code or build.

## Why it isn't one role

azapptoolkit is a **delegated public client**: it signs in as you (OAuth2 PKCE, single-tenant) and
holds **no privileges of its own**. Every action runs with *your* delegated rights against Microsoft
Graph, the Exchange Online Admin API, Azure Key Vault, and Azure Resource Manager. Those land on
**three independent authorization planes**, each with its own role type and its own PIM:

| Plane | What it governs here | Role | PIM flavor | File |
|---|---|---|---|---|
| **Entra ID directory roles** | App registrations, enterprise apps, credentials, owners, API-permission **admin consent**, sign-in/audit reports, Conditional Access (read) | Custom directory role (`microsoft.directory/*`) | **PIM for Microsoft Entra roles** | [`entra-custom-role.ps1`](./entra-custom-role.ps1) |
| **Azure RBAC** | ARM managed-identity role **reads** + **Key Vault secrets** CRUD | Custom Azure role (`Actions`/`DataActions`) | **PIM for Azure resources** | [`azure-custom-role.json`](./azure-custom-role.json) |
| **Exchange Online RBAC** | RBAC-for-Applications: mailbox access grants, management scopes/role assignments | Built-in **Exchange Administrator** | **PIM for Microsoft Entra roles** | (built-in — no file) |

So: **two custom roles + one built-in role**.

> **Two halves, both required.** These roles grant the *standing directory/Azure privilege*. The
> operator must *separately* have consented the toolkit's **delegated OAuth scopes** (the app's
> incremental-consent flow). A PIM role with no consented scope — or a consented scope with no
> directory privilege — does nothing.

---

## 1. Azure RBAC custom role (ARM + Key Vault)

ARM usage is **read-mostly** (subscriptions, role assignments, role definitions — the Managed Identity
→ Azure-roles view); Key Vault is full secret CRUD (the credential-rotation feature). One ARM **write**
path — assigning an Azure role to a managed identity — needs
`Microsoft.Authorization/roleAssignments/write`, which this least-privilege role deliberately **omits**;
see caveat 4.

Definition: [`azure-custom-role.json`](./azure-custom-role.json). Edit `AssignableScopes` to your
subscription/management-group, then:

```bash
az role definition create --role-definition azure-custom-role.json
# then assign PIM-eligible via: Azure portal > PIM > Azure resources > <scope> > Roles > Add eligible assignments
```

| App operation | Permission |
|---|---|
| List subscriptions | `Microsoft.Resources/subscriptions/read` (Action) |
| Read MI role assignments | `Microsoft.Authorization/roleAssignments/read` (Action) |
| Resolve role-definition GUIDs → names | `Microsoft.Authorization/roleDefinitions/read` (Action) |
| List Key Vaults (management plane) | `Microsoft.KeyVault/vaults/read` (Action) |
| List secrets | `Microsoft.KeyVault/vaults/secrets/readMetadata/action` (DataAction) |
| Read secret value | `Microsoft.KeyVault/vaults/secrets/getSecret/action` (DataAction) |
| Create/update secret | `Microsoft.KeyVault/vaults/secrets/setSecret/action` (DataAction) |
| Delete secret | `Microsoft.KeyVault/vaults/secrets/deleteSecret/action` (DataAction) |

Notes:
- **Key Vault must be in RBAC permission mode** (not legacy access policies) for `DataActions` to
  apply.
- **Assigning roles to managed identities is *not* in this role.** That write path needs
  `Microsoft.Authorization/roleAssignments/write` — grant a separate **User Access Administrator**
  (or **Owner**) on the target scope only for operators who use it (caveat 4).
- Built-in equivalent if you'd rather not maintain a custom role: **Reader** + **Key Vault Secrets
  Officer**.

---

## 2. Entra ID custom directory role (app/SP management + consent + read-only tabs)

Created via Microsoft Graph PowerShell because the admin-consent permission can't be added in the
portal. Run [`entra-custom-role.ps1`](./entra-custom-role.ps1) (signer must be Privileged Role
Administrator or Global Administrator), then make it PIM-eligible in **Entra PIM > Roles**.

| App area | Permissions |
|---|---|
| App registrations create/delete/read | `applications/create`, `applications/delete`, `applications/allProperties/read` |
| App basic/audience/auth/permissions updates | `applications/basic/update`, `.../audience/update`, `.../authentication/update`, `.../permissions/update` |
| Secrets, certs, **federated credentials** | `applications/credentials/update` |
| App owners | `applications/owners/update` |
| Enterprise apps create/read/update | `servicePrincipals/create`, `.../allProperties/read`, `.../basic/update` |
| Assign users/groups to app roles | `servicePrincipals/appRoleAssignedTo/update` |
| SCIM provisioning tab | `servicePrincipals/synchronization/standard/read` |
| **Admin consent** (delegated + app-role grants) | `servicePrincipals/managePermissionGrantsForAll.<consentPolicyId>` |
| Owner/assignee pickers, org header | `users/standard/read`, `groups/standard/read`, `organization/standard/read` |
| Activity tab | `auditLogs/allProperties/read` |
| Unused-app / sign-in activity | `signInReports/allProperties/read` |
| Conditional Access tab | `conditionalAccessPolicies/standard/read` |

Built-in equivalent: **Cloud Application Administrator** + **Reports Reader** + **Security Reader**.

---

## 3. Exchange Online — built-in Exchange Administrator

The Exchange RBAC-for-Applications cmdlets (`New-ManagementScope`,
`New-/Remove-ManagementRoleAssignment`, `*-ApplicationAccessPolicy`, `Test-ServicePrincipalAuthorization`)
run against the Exchange Online Admin API and **can't be expressed in an Entra custom directory
role**. Assign the built-in **Exchange Administrator** Entra role (PIM-eligible). For finer scoping,
build a custom RBAC role group *inside* Exchange Online (a separate system).

The toolkit-managed scope group feature additionally runs the recipient cmdlets
`New-DistributionGroup` / `Add-`/`Remove-`/`Get-DistributionGroupMember`, which live in the Exchange
**Distribution Groups** role (held by **Recipient Management** and **Organization Management**). The
built-in **Exchange Administrator** role covers both this and the **Role Management** role below, so a
single Exchange Administrator grant is sufficient. A least-privilege custom role group that holds only
**Role Management** can assign scoped roles but **cannot** create or populate the scope group — add
**Distribution Groups** to it (or pre-create the group out of band).

**Why a 403 / "Unknown" scope can happen even as an Exchange Administrator.** The delegated
`Exchange.Manage` scope only grants *impersonation* — what the token can actually run is decided by
the signed-in user's **Exchange Online RBAC**, not the OAuth scope. The cmdlets above live in the
Exchange **Role Management** role (`Get-ManagementRole -Cmdlet Get-ServicePrincipal` →
`Role Management`), which the **Organization Management** role group holds. The Entra **Exchange
Administrator** role maps to that group, but the grant must be **active** (not merely PIM-*eligible*)
and can take a few minutes to propagate to Exchange. A still-ineffective role returns
`403 Forbidden` from the admin API — often with an empty body / no `x-ms-diagnostics` — which the app
surfaces as a `forbidden (403)` banner (Exchange scoping section) and an **Unknown** Scope column
(both on the Permissions tab). To confirm/repair:

```powershell
# Are you in a role group that includes Role Management?
Get-ManagementRoleGroupMember "Organization Management"
# Which management roles does your account actually have?
Get-ManagementRoleAssignment -RoleAssignee <your-upn> | Select-Object Role
```

Activate the eligible role (PIM), or add your account to a role group containing **Role Management**,
then sign out and back in so a fresh token is issued.

---

## Gaps & caveats (read before relying on these roles)

1. **Admin consent to high-privilege Graph permissions is gated above any custom role.**
   `managePermissionGrantsForAll.{id}` requires **Entra ID P1**, must be set via Graph (not the
   portal), and is bounded by an **app consent policy**. Consenting to sensitive app roles (e.g.
   Graph `Application.ReadWrite.All`) still requires **Privileged Role Administrator** or **Global
   Administrator** — no custom role substitutes. If operators must grant arbitrary high-privilege
   consent, plan a PIM-eligible **Privileged Role Administrator** assignment for that path.

2. **SharePoint `Sites.Selected` grants** (the `Sites.FullControl.All` write path,
   `POST /sites/{id}/permissions`) are governed by SharePoint, not a clean `microsoft.directory/*`
   permission — effective access needs **SharePoint Administrator** (or Global Admin). Add a
   PIM-eligible SharePoint Administrator role if you use that feature.

3. **Delegated OAuth scopes still required** (the second half above). The operator's consented
   scopes must include: `Directory.Read.All`, `Application.ReadWrite.All`,
   `AppRoleAssignment.ReadWrite.All`, `DelegatedPermissionGrant.ReadWrite.All`, and — optionally,
   per feature — `Synchronization.Read.All`, `AuditLog.Read.All`, `Policy.Read.All`,
   `Policy.ReadWrite.ApplicationConfiguration`, `Sites.FullControl.All`,
   `GroupMember.ReadWrite.All`,
   `https://outlook.office365.com/Exchange.Manage`, `https://management.azure.com/.default`,
   `https://vault.azure.net/.default`, `https://api.loganalytics.azure.com/.default`.

4. **Group-membership changes** (adding/removing a service principal as a security-group member —
   the access model for group-gated APIs like Power BI / Fabric tenant settings) need
   **Groups Administrator** (or User Administrator / Global Administrator), or **ownership of the
   target group**, plus the `GroupMember.ReadWrite.All` scope. The Entra custom role above does not
   cover `microsoft.directory/groups/members/update`; add a PIM-eligible Groups Administrator
   assignment — or prefer per-group ownership — for operators who manage those memberships.

5. **Assigning Azure roles to managed identities needs a higher-privileged write role.** The Managed
   Identity → *Assign role* flow calls `Microsoft.Authorization/roleAssignments/write` (via
   `ArmClient::create_role_assignment`), which the read-mostly Azure custom role above deliberately omits.
   Grant a separate **User Access Administrator** (or **Owner**) on the target subscription / resource
   group — ideally PIM-eligible — only for operators who assign roles; the app otherwise surfaces a clear
   "needs `roleAssignments/write`" error.

6. **Observed Graph activity (usage analysis) is not covered by the Azure custom role.** The
   granted-vs-used view queries `MicrosoftGraphActivityLogs` through the Log Analytics API
   (`api.loganalytics.azure.com`), which needs two prerequisites the roles above don't provide:
   Microsoft Entra **diagnostic settings** exporting `MicrosoftGraphActivityLogs` to a Log
   Analytics workspace, and the **Log Analytics Reader** Azure RBAC role (or **Reader**) on that
   workspace for the operator. [`azure-custom-role.json`](./azure-custom-role.json) deliberately
   omits the `Microsoft.OperationalInsights/*` read/query actions — grant Log Analytics Reader on
   the specific workspace, PIM-eligible, only to operators who use the feature. Without it the
   app degrades to an "unavailable" notice on that view.

## Verification

- **Azure role:** `az role definition create --role-definition azure-custom-role.json`, assign at a
  test subscription, confirm Key Vault list/get/set/delete and the Managed-Identity Azure-roles view
  work.
- **Entra role:** run `entra-custom-role.ps1` against a test tenant, assign PIM-eligible to a
  non-admin test account, confirm app create/update/credential/owner flows and the
  Reports/Activity/Conditional-Access tabs load.
- **Negative check:** confirm a high-privilege consent attempt is correctly **blocked** (validates
  caveat #1).
