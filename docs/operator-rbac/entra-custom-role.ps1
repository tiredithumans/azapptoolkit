<#
.SYNOPSIS
    Creates the "azapptoolkit Operator (Directory)" custom Entra ID directory role.

.DESCRIPTION
    The azapptoolkit desktop app is a delegated public client: it performs every Microsoft Graph
    operation AS the signed-in user. This role grants the directory privileges an operator needs to
    drive the app's app-registration / enterprise-app / consent surface, plus the read-only
    Reports / Audit-log / Conditional-Access tabs.

    Why PowerShell and not the Entra admin center: the admin-consent permission
    (microsoft.directory/servicePrincipals/managePermissionGrantsForAll.<policyId>) CANNOT be added
    to a custom role in the portal — it must be set via Microsoft Graph. Requires Microsoft Entra ID P1.

    Read OPERATOR-ROLES.md for the full three-plane picture and the consent caveats before using this.

.NOTES
    Requires: Microsoft.Graph PowerShell SDK, and a signer who is Privileged Role Administrator or
    Global Administrator (creating/assigning directory roles is itself a privileged action).
#>

#Requires -Modules Microsoft.Graph.Identity.Governance, Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    # App consent policy ID that bounds what the operator may consent to. The built-in
    # low-impact policy is "microsoft-application-admin" (same policy Cloud Application
    # Administrator uses). Use a custom app consent policy ID to tighten/loosen this.
    [string] $ConsentPolicyId = "microsoft-application-admin"
)

$ErrorActionPreference = "Stop"

Connect-MgGraph -Scopes "RoleManagement.ReadWrite.Directory"

$allowedResourceActions = @(
    # --- App registrations (applications/*) ---
    "microsoft.directory/applications/create",
    "microsoft.directory/applications/delete",
    "microsoft.directory/applications/allProperties/read",
    "microsoft.directory/applications/basic/update",            # displayName, description
    "microsoft.directory/applications/audience/update",         # signInAudience
    "microsoft.directory/applications/authentication/update",   # redirect URIs
    "microsoft.directory/applications/credentials/update",      # addPassword/removePassword, keyCredentials, federatedIdentityCredentials
    "microsoft.directory/applications/owners/update",
    "microsoft.directory/applications/permissions/update",      # requiredResourceAccess

    # --- Enterprise apps (servicePrincipals/*) ---
    "microsoft.directory/servicePrincipals/create",
    "microsoft.directory/servicePrincipals/allProperties/read",
    "microsoft.directory/servicePrincipals/basic/update",            # tags / HideApp toggle
    "microsoft.directory/servicePrincipals/appRoleAssignedTo/update", # assign users/groups to app roles
    "microsoft.directory/servicePrincipals/synchronization/standard/read", # SCIM provisioning tab

    # --- Admin consent (delegated grants + app-role grants); bounded by the consent policy below ---
    "microsoft.directory/servicePrincipals/managePermissionGrantsForAll.$ConsentPolicyId",

    # --- Directory reads (owner/assignee pickers, org header) ---
    "microsoft.directory/users/standard/read",
    "microsoft.directory/groups/standard/read",
    "microsoft.directory/organization/standard/read",

    # --- Read-only audit / report / policy tabs ---
    "microsoft.directory/auditLogs/allProperties/read",          # Activity tab (AuditLog.Read.All)
    "microsoft.directory/signInReports/allProperties/read",      # unused-app / sign-in activity (Reports.Read.All)
    "microsoft.directory/conditionalAccessPolicies/standard/read" # Conditional Access tab (Policy.Read.All)
)

$rolePermissions = @(
    @{ allowedResourceActions = $allowedResourceActions }
)

$params = @{
    displayName = "azapptoolkit Operator (Directory)"
    description = "App-registration / enterprise-app management + admin consent + read-only reports for azapptoolkit operators. See docs/operator-rbac/OPERATOR-ROLES.md."
    rolePermissions = $rolePermissions
    isEnabled = $true
    # Omit templateId to let Graph mint a new custom role definition.
}

$role = New-MgRoleManagementDirectoryRoleDefinition -BodyParameter $params
Write-Host "Created custom directory role:" $role.DisplayName "(id:" $role.Id ")"
Write-Host "Next: make it PIM-eligible for your operators via Microsoft Entra PIM (Roles > the new role > Add assignments > Eligible)."
