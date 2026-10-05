//! Permission risk lists, score weights, and the subsumption table —
//! the rule *constants* section of the audit module (see the module doc
//! in `mod.rs` for the PowerShell provenance contract).

use super::*;

// ---------------- Rule constants ----------------

/// Score breakpoints. Mirrors `$script:AuditDefaults.RiskLevels` in
/// `Constants.ps1:207-213`.
pub const RISK_CRITICAL: u32 = 25;
pub const RISK_HIGH: u32 = 15;
pub const RISK_MEDIUM: u32 = 8;

/// Credential-expiry warning threshold. `Constants.ps1:202`. The legacy
/// `Constants.ps1:203` 7-day "critical" tier is intentionally not ported:
/// credential status uses a single `ExpiringSoon` bucket at 30 days, not a
/// separate critical one, so a 7-day constant would be dead code.
pub const EXPIRY_WARNING_DAYS: i64 = 30;

/// Stale-app threshold (`MaxAuditHistoryDays` in `Constants.ps1`).
pub const STALE_APP_DAYS: i64 = 90;

/// Days without a sign-in before an app is flagged "likely unused". Net-new
/// (no PowerShell origin) — drives [`unused_app_advisory`].
pub const UNUSED_APP_DAYS: i64 = 90;

/// Days without ANY credential sign-in activity before a still-valid
/// credential is flagged "unused" — drives
/// [`unused_credential_advisory`](super::unused_credential_advisory). Set
/// equal to [`UNUSED_APP_DAYS`] deliberately: both answers come from the same
/// beta sign-in-activity reports and a credential unused as long as its app
/// is exactly the case the two advisories are meant to surface together.
pub const UNUSED_CREDENTIAL_DAYS: i64 = 90;

/// Long-lived secret threshold. `Credential-Analysis.ps1:169`. Applies to
/// certificates too: Rule 7 checks every credential kind against it and names
/// the two kinds on separate lines. Ported spelling kept (public, re-exported).
pub const LONG_LIVED_SECRET_DAYS: i64 = 365;

/// Score increments.
/// One [`TIER0_APP_PERMISSIONS`] grant. Net-new tier (no PowerShell origin):
/// equal to [`RISK_CRITICAL`] on purpose, so a single tier-0 grant ALONE ranks
/// the principal Critical — a direct path to Global Administrator is the worst
/// thing an app can hold, and at the ported +10 it read Medium. Scored INSTEAD
/// of [`PTS_HIGH_RISK_APP_PERM`], never on top (the two lists are disjoint).
/// Ranking change over the legacy port — CHANGELOG-gated.
pub(super) const PTS_TIER0_APP_PERM: u32 = 25;
pub(super) const PTS_HIGH_RISK_APP_PERM: u32 = 10;
pub(super) const PTS_MEDIUM_RISK_APP_PERM: u32 = 5;
pub(super) const PTS_ADMIN_CONSENT_DELEGATED: u32 = 5;
pub(super) const PTS_SP_DISABLED: u32 = 2;
/// Microsoft has disabled the app/SP for a Services Agreement violation
/// (`disabledByMicrosoftStatus`). Highest single-item weight: it is
/// Microsoft's own "suspicious, abusive or malicious activity" verdict, so a
/// flagged principal is at least High on this signal alone (+15 ≥ the 15-point
/// High threshold). Ranking change over the legacy port — CHANGELOG-gated.
pub(super) const PTS_DISABLED_BY_MICROSOFT: u32 = 15;
/// Identity Protection flags the service principal `confirmedCompromised` or
/// `atRisk` (the risky-service-principal report). Above the disable flag: a
/// *confirmed-compromised* principal may already be minting tokens — this is
/// the one signal that can mean live abuse, so it is worth more than any
/// single permission and pushes any other finding to Critical. Ranking change
/// over the legacy port — CHANGELOG-gated.
pub(super) const PTS_RISKY_SERVICE_PRINCIPAL: u32 = 20;
pub(super) const PTS_ALL_CREDS_EXPIRED: u32 = 8;
pub(super) const PTS_MIXED_EXPIRED: u32 = 4;
pub(super) const PTS_ALL_EXPIRING_SOON: u32 = 3;
pub(super) const PTS_MIXED_EXPIRING: u32 = 2;
pub(super) const PTS_LONG_LIVED: u32 = 3;
pub(super) const PTS_STALE_APP: u32 = 2;
/// Multi-tenant / personal-account audience on an app that holds permissions or
/// credentials. Scored, not advisory: the audience is a *blast-radius
/// multiplier* — it decides whether permissions are reachable outside this
/// directory. Weighted below one medium-risk permission; fires only alongside
/// real findings, never alone.
pub(super) const PTS_MULTITENANT_EXPOSURE: u32 = 3;
/// Additional weight when a multi-tenant app also has **no verified publisher**.
/// Publisher verification is what lets a consenting tenant's admin tell who the
/// app's author actually is; without it, a multi-tenant app asking for consent
/// is unattributable.
pub(super) const PTS_UNVERIFIED_PUBLISHER: u32 = 2;
/// Reduced weight for a high/medium-risk *mail* permission confirmed scoped via
/// Exchange RBAC for Applications (see [`AppPermissions::mail_scopes`]).
/// Confined ≠ zero risk: the scope can still cover many recipients, so a small
/// residual stays.
pub(super) const PTS_SCOPED_HIGH_RISK_MAIL: u32 = 3;
pub(super) const PTS_SCOPED_MEDIUM_RISK_MAIL: u32 = 2;

/// Tier-0 application permissions (by `value` string): each is, on its own, a
/// path to Global Administrator or to taking over the tenant, with no other
/// grant and no unusual tenant configuration needed. Net-new tier (scored
/// `PTS_TIER0_APP_PERM` = 25, so one grant alone is Critical).
///
/// The first three are `Constants.ps1:104-115` entries PROMOTED out of
/// [`HIGH_RISK_APP_PERMISSIONS`] (where they scored +10, so an app holding
/// only `RoleManagement.ReadWrite.Directory` read Medium); the rest are
/// net-new. Disjoint from the high and medium lists, pinned by
/// `tests::tier0_high_and_medium_lists_are_disjoint`: a tier-0 grant scores the
/// tier-0 weight ONLY.
///
/// The bar is "self-sufficient": the grant is the whole attack. Borderline
/// values deliberately kept in the HIGH list instead, with the reason:
/// - `Directory.ReadWrite.All`, `Group.ReadWrite.All`,
///   `GroupMember.ReadWrite.All`, `User.ReadWrite.All`,
///   `User-PasswordProfile.ReadWrite.All` — none can touch Entra role
///   membership or role-assignable groups (Microsoft fenced both off from
///   `Directory.ReadWrite.All` in 2022), nor reset a privileged admin's
///   password. Their remaining path to Global Administrator detours through an
///   ordinary group that holds Azure RBAC rights — real, but tenant-specific.
/// - `Application.ReadWrite.OwnedBy` — the same credential-injection primitive
///   as `Application.ReadWrite.All`, limited to the apps it owns.
/// - `EntitlementManagement.ReadWrite.All` — needs an access package that
///   already provisions a privileged role.
/// - `Organization.ReadWrite.All` — the trusted-root-CA path needs
///   certificate-based authentication enabled first.
/// - `Policy.ReadWrite.AuthenticationMethod` / `RoleManagementPolicy.ReadWrite.Directory`
///   — they loosen the guards on another grant's path; alone they assign
///   nothing.
/// - `DelegatedPermissionGrant.ReadWrite.All` — grants DELEGATED permissions,
///   which still need a privileged user to sign in to the client.
pub const TIER0_APP_PERMISSIONS: &[&str] = &[
    // Ported (`Constants.ps1:104-115`), promoted from high.
    // Assigns any directory role, Global Administrator included.
    "RoleManagement.ReadWrite.Directory",
    // Grants itself any app role (e.g. the one above) without admin consent.
    "AppRoleAssignment.ReadWrite.All",
    // Adds a credential to any application or service principal, then signs
    // in as whichever holds more privilege.
    "Application.ReadWrite.All",
    // Net-new: PIM writes — an active or eligible Global Administrator
    // assignment, or membership of a role-assignable group, for a principal the
    // app controls.
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
    // Net-new: a permission grant policy that lets the app consent itself to
    // `RoleManagement.ReadWrite.Directory`.
    "Policy.ReadWrite.PermissionGrant",
    // Net-new: a Conditional Access policy can lock every account out of the
    // tenant (break-glass included) or strip MFA from privileged sign-ins.
    "Policy.ReadWrite.ConditionalAccess",
    // Net-new: adds a federated domain and signs in as an existing Global
    // Administrator with no password or MFA.
    "Domain.ReadWrite.All",
    // Net-new: issues a Temporary Access Pass (or another sign-in method) for
    // any user, administrators included.
    "UserAuthenticationMethod.ReadWrite.All",
];

/// High-risk application permissions (by `value` string). Mirrors
/// `Constants.ps1:104-115`, less the three entries promoted to
/// [`TIER0_APP_PERMISSIONS`] (scored there instead, never in both).
pub const HIGH_RISK_APP_PERMISSIONS: &[&str] = &[
    // Stays high, not tier-0 — see the borderline list on TIER0_APP_PERMISSIONS.
    "Directory.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    // Net-new (not in `Constants.ps1`): org-wide `Sites.ReadWrite.All` is
    // tenant-wide write, so it is weighted alongside `Sites.FullControl.All`
    // rather than left advisory. The scoped alternative `Sites.Selected`
    // (Rule 12) is in no risk list, by design.
    "Sites.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    // Net-new; Microsoft's permissions reference flags both with a "Caution":
    // `Application.ReadWrite.OwnedBy` can update the secrets of apps it owns
    // (act as those entities) and lists every app/SP in the tenant;
    // `EntitlementManagement.ReadWrite.All` can grant privileges to itself,
    // other apps, or any user (Entra role, app role, and API permissions).
    // Both scored ZERO.
    "Application.ReadWrite.OwnedBy",
    "EntitlementManagement.ReadWrite.All",
    // Net-new batch, one shared origin: each appears in
    // `SUBSUMED_APP_PERMISSIONS` as a BROADER side yet scored ZERO. Families
    // follow the ported split — tenant-wide WRITE high, READ medium (read halves
    // in the medium list). The one ported exception, `Calendars.ReadWrite`, keeps
    // its legacy medium tier.
    // `MailboxSettings.ReadWrite` is the one to note: it sets mail forwarding on
    // every mailbox — the classic exfiltration primitive, and needs no read
    // permission to act.
    "MailboxSettings.ReadWrite",
    // Adds any principal — including the app's own service principal — to any
    // group, so it reaches whatever access those groups gate.
    "GroupMember.ReadWrite.All",
    // Read and write every Teams chat message in the tenant.
    "Chat.ReadWrite.All",
    // Tenant-wide write over device objects, which back conditional-access and
    // compliance decisions.
    "Device.ReadWrite.All",
    // The write side of the contacts family, matching `Mail.ReadWrite`.
    "Contacts.ReadWrite",
    // Tenant-wide write over OneNote content, matching `Files.ReadWrite.All`.
    "Notes.ReadWrite.All",
    // Net-new (not in `Constants.ps1:104-115`): the newer Graph mailbox
    // permissions that RBAC for Applications exposes a scoped role for. Each
    // reaches every mailbox and scored ZERO. Tenant-wide write/delete
    // (`MailboxItem/MailboxFolder.ReadWrite.All`) is at least `Mail.ReadWrite`;
    // `Mail-Advanced.ReadWrite.All` also edits non-draft message bodies; Export
    // and ImportExport are bulk-exfiltration primitives.
    // `MailboxConfigItem.*` (UserConfiguration) and `MailTips.ReadBasic.All`
    // (metadata) are deliberately in NEITHER table: they reach mailboxes (so they
    // enter the org-wide advisory) but do not read or write mailbox content.
    "MailboxItem.ReadWrite.All",
    "MailboxItem.Export.All",
    "MailboxItem.ImportExport.All",
    "MailboxFolder.ReadWrite.All",
    "Mail-Advanced.ReadWrite.All",
    // Net-new (not in `Constants.ps1`): EWS `full_access_as_app` (legacy Office
    // 365 Exchange Online) is strictly broader than the already-high
    // `Mail.ReadWrite`; it scored zero because the risk tables only listed Graph
    // names. Unambiguous as a bare value — no other resource exposes it (see
    // `scoping::EWS_FULL_ACCESS_AS_APP`).
    crate::scoping::EWS_FULL_ACCESS_AS_APP,
    // Net-new: the borderline tier-0 candidates kept at high (reasons on
    // `TIER0_APP_PERMISSIONS`). Each scored ZERO before.
    "User-PasswordProfile.ReadWrite.All",
    "Organization.ReadWrite.All",
    "Policy.ReadWrite.AuthenticationMethod",
    "RoleManagementPolicy.ReadWrite.Directory",
    "DelegatedPermissionGrant.ReadWrite.All",
    // Net-new: tenant-wide policy writes one step short of tier-0 —
    // cross-tenant trust (inbound B2B, MFA trust), the authorization policy
    // (default user permissions, user consent), and app-management/claims
    // policies (credential restrictions, token contents).
    "Policy.ReadWrite.CrossTenantAccess",
    "Policy.ReadWrite.Authorization",
    "Policy.ReadWrite.ApplicationConfiguration",
    // Net-new: Office 365 Exchange Online's app-only Exchange administration
    // role (Exchange PowerShell as the app). With an Exchange admin role it
    // manages every mailbox, transport rule and RBAC scope; it scored zero
    // because only Graph names were listed. Unambiguous as a bare value — no
    // other resource exposes it.
    "Exchange.ManageAsApp",
];

/// Medium-risk application permissions (by `value` string). Mirrors
/// `Constants.ps1:123-130`.
pub const MEDIUM_RISK_APP_PERMISSIONS: &[&str] = &[
    "User.Read.All",
    "Group.Read.All",
    "Mail.Read",
    "Files.Read.All",
    "Sites.Read.All",
    // `Calendars.ReadWrite`, PLURAL. The entry read `Calendar.ReadWrite` its
    // whole life — a permission Graph does not define (calendar permissions are
    // plural) that could never match, so org-wide `Calendars.ReadWrite` scored
    // zero.
    // The MEDIUM tier is deliberate parity with `Constants.ps1:123-130`; the
    // typo fix kept it. The write = high split governs only families this file
    // ADDED, so this is the one mailbox write that stays medium — promoting it
    // needs a CHANGELOG note. Pinned by
    // `tests::mailbox_family_writes_are_high_unless_ported_otherwise`.
    "Calendars.ReadWrite",
    // Net-new: "the highest privileged read-only permission for Microsoft Entra
    // ID resources" (Microsoft). Medium band with the other tenant-wide reads —
    // high is reserved for write and impersonation — but it reads strictly more
    // than `User/Group.Read.All` and scored zero.
    "Directory.Read.All",
    // Net-new — read halves weighted like `Mail.Read` rather than their write
    // counterparts: `Chat.Read.All` pairs with the high `Chat.ReadWrite.All`,
    // `Calendars.Read` with the ported `Calendars.ReadWrite` above.
    "Chat.Read.All",
    "Calendars.Read",
    // Net-new — the read halves of the newer RBAC-scopable mailbox families
    // (see the high list), weighted like `Mail.Read` per the read/write split
    // `Constants.ps1:123-130` uses for every other family.
    "MailboxItem.Read.All",
    "MailboxFolder.Read.All",
    // Net-new: read halves of the HIGH families, medium per the read = medium
    // split. Each scored ZERO until
    // `tests::every_narrower_subsumed_permission_carries_a_risk_weight`. A
    // mailbox read confined through RBAC takes `PTS_SCOPED_MEDIUM_RISK_MAIL`
    // like `Mail.Read`.
    // Reads every contact; Rule 11 already raised the mailbox advisory without
    // it adding points.
    "Contacts.Read",
    // Reads every mailbox's forwarding, auto-reply and delegate-facing settings.
    "MailboxSettings.Read",
    // Reads every user's OneNote notebooks.
    "Notes.Read.All",
    // Tenant-wide read of device objects, on par with `Group.Read.All`.
    "Device.Read.All",
    // Tenant-wide read of every application and service principal, including
    // their credential metadata and granted permissions.
    "Application.Read.All",
    // Tenant-wide read of every group's membership.
    "GroupMember.Read.All",
    // Tenant-wide read of Entra role definitions and assignments, which maps
    // who holds privileged roles.
    "RoleManagement.Read.Directory",
];

/// High-risk delegated permissions (by scope `value`). Ported from
/// `Constants.ps1:104-130`. The legacy module did not add risk *points* for
/// delegated permissions beyond the admin-consent check (see Rule 3), so this
/// list drives an advisory issue (Rule 13, no score) that names the specific
/// high-risk delegated scopes an app declares, so admins can review them.
pub const HIGH_RISK_DELEGATED_PERMISSIONS: &[&str] =
    &["Directory.AccessAsUser.All", "user_impersonation"];

/// Delegated scope prefixes that grant broad reach across the tenant's data
/// when admin-consented. Net-new (no PowerShell origin); used by
/// [`is_risky_delegated_scope`] for the consent-grant audit.
const RISKY_DELEGATED_SCOPE_PREFIXES: &[&str] = &[
    "Mail.",
    "MailboxSettings.",
    "Files.",
    "Sites.",
    "Directory.",
    "Group.",
    "AppRoleAssignment.",
    "RoleManagement.",
];

/// Delegated scope prefixes added later, deliberately narrower than the
/// families above: each names only the WRITE half of its family, because these
/// families' reads are routine (`Policy.Read.All`, `Application.Read.All`,
/// `Calendars.ReadBasic`, `Chat.ReadBasic`, `UserAuthenticationMethod.Read`) and
/// flagging them would bury the writes that matter. Net-new: each writes
/// identities, sign-in methods, policy, consent or membership as the signed-in
/// user, or writes every consenting user's calendar/chat the way `Mail.`
/// reaches mail.
const RISKY_DELEGATED_WRITE_PREFIXES: &[&str] = &[
    "Application.ReadWrite.",
    "Policy.ReadWrite.",
    "UserAuthenticationMethod.ReadWrite",
    "GroupMember.ReadWrite.",
    "DelegatedPermissionGrant.ReadWrite.",
    "Calendars.ReadWrite",
    "Chat.ReadWrite",
];

/// Delegated scopes matched exactly rather than by family prefix, because
/// their family also holds harmless scopes (`User.Read` is every app's
/// sign-in basic).
const RISKY_DELEGATED_SCOPES_EXACT: &[&str] = &["User.ReadWrite.All"];

/// True for a **Selected** scope — `Sites.Selected` and the
/// `*.SelectedOperations.Selected` sub-site family. These grant nothing until
/// an owner grants a specific site, list or file, so they are the
/// least-privilege end state, never broad reach. The one definition the
/// delegated risk classifier excludes on; a value-only test is sound here
/// because every Selected scope on every resource is confined by construction
/// (contrast the resource-aware `crate::scoping` gates, which decide whether
/// the toolkit can ACT on a grant, not whether it is broad).
fn is_selected_scope(scope: &str) -> bool {
    scope == crate::scoping::SP_SITES_SELECTED || scope.ends_with(".SelectedOperations.Selected")
}

/// Splits held application permissions into `(high, medium)` hits by value —
/// "high" includes [`TIER0_APP_PERMISSIONS`] (a surface that wants the tier-0
/// distinction asks [`risk_level_for_app_permission`]). Reusable for
/// permissions *held* by managed identities and enterprise-app SPs, not just
/// app registrations.
///
/// Takes whole [`ResourcePermission`]s, not bare values (AGENTS.md: carry the
/// resource): `Mail.ReadWrite` on Graph and on Office 365 Exchange Online are
/// different grants with different reach, only Graph's is confinable, and the
/// old `&[String]` signature made naming the resource impossible.
///
/// Matching stays value-only (behaviour-preserving): an unrelated API's same-
/// named role still counts. Over-reporting is the safe direction; narrowing the
/// risk model needs a deliberate decision, not a refactor.
pub fn classify_app_permission_risk(
    grants: &[ResourcePermission],
) -> (Vec<ResourcePermission>, Vec<ResourcePermission>) {
    let high = grants
        .iter()
        .filter(|g| {
            TIER0_APP_PERMISSIONS.contains(&g.value.as_str())
                || HIGH_RISK_APP_PERMISSIONS.contains(&g.value.as_str())
        })
        .cloned()
        .collect();
    let medium = grants
        .iter()
        .filter(|g| MEDIUM_RISK_APP_PERMISSIONS.contains(&g.value.as_str()))
        .cloned()
        .collect();
    (high, medium)
}

/// Whether a single delegated scope `value` is high-risk for consent review.
/// Combines the ported [`HIGH_RISK_DELEGATED_PERMISSIONS`] with broad
/// read/write categories (mail, files, directory, policy, …). Every Selected
/// scope (`is_selected_scope`: `Sites.Selected`,
/// `Files.SelectedOperations.Selected`, …) is excluded — those are the
/// *least*-privilege models, and the bare `Files.` prefix used to flag them.
pub fn is_risky_delegated_scope(scope: &str) -> bool {
    if HIGH_RISK_DELEGATED_PERMISSIONS.contains(&scope) {
        return true;
    }
    if is_selected_scope(scope) {
        return false;
    }
    RISKY_DELEGATED_SCOPES_EXACT.contains(&scope)
        || RISKY_DELEGATED_SCOPE_PREFIXES
            .iter()
            .chain(RISKY_DELEGATED_WRITE_PREFIXES)
            .any(|p| scope.starts_with(p))
}

/// Risk level of a single application-permission `value`, or `None` when it is
/// not on a risk list: [`TIER0_APP_PERMISSIONS`] answer
/// [`RiskLevel::Critical`] (one grant alone scores Critical), then high and
/// medium. The single source the grant-time picker and the held-permission
/// badges read, so a permission's risk is classified in exactly one place.
pub fn risk_level_for_app_permission(value: &str) -> Option<RiskLevel> {
    if TIER0_APP_PERMISSIONS.contains(&value) {
        Some(RiskLevel::Critical)
    } else if HIGH_RISK_APP_PERMISSIONS.contains(&value) {
        Some(RiskLevel::High)
    } else if MEDIUM_RISK_APP_PERMISSIONS.contains(&value) {
        Some(RiskLevel::Medium)
    } else {
        None
    }
}

/// A least-privilege alternative to a broad application permission on
/// `resource_app_id` — advisory at grant time, never an automatic rewrite;
/// `None` when already least-privilege. Derives from the shared resource-aware
/// scope predicates (consistent with Rule 11/12 and the scope badges).
///
/// Deliberately no value-only form: defaulting the resource to Graph made the
/// picker offer mailbox-scoping advice for Office 365 Exchange Online's mail
/// appRoles, which RBAC for Applications cannot confine (it covers Graph and
/// the EWS scope, not the retired Outlook REST roles — whose only remedy is
/// removal). A `None` resource yields no Exchange advice for the same reason.
/// SharePoint advice follows [`crate::scoping::is_sharepoint_orgwide_permission`]:
/// both SharePoint resources expose `Sites.Selected`, but another API's
/// `Sites.`-named role is not SharePoint site access. The org-wide Files family
/// ([`crate::scoping::is_files_orgwide_permission`]) points at
/// `Files.SelectedOperations.Selected`, the item-level model the Scope wizard
/// applies.
pub fn least_privilege_alternative_for(
    resource_app_id: Option<&str>,
    value: &str,
) -> Option<&'static str> {
    if crate::scoping::is_sharepoint_orgwide_permission(resource_app_id, value) {
        // Every broad `Sites.*` has the scoped `Sites.Selected` model (Rule 12).
        Some(crate::scoping::SP_SITES_SELECTED)
    } else if crate::scoping::is_files_orgwide_permission(resource_app_id, value) {
        // Org-wide Files reach points at the item-level scoped model — the same
        // answer the audit's Rule 12 advisory and the Scope wizard give. It is
        // advisory only: nothing auto-converts `Files.*.All`, so unlike the
        // `Sites.*` arm there is no one-click fix behind this pointer.
        Some(crate::scoping::SP_FILES_SELECTED)
    } else if crate::scoping::is_scopable_exchange_resource_permission(resource_app_id, value) {
        // Mail/calendar/contacts can be confined to mailboxes via Exchange RBAC.
        Some("Scope to specific mailboxes (Exchange RBAC)")
    } else {
        None
    }
}

/// The broader Microsoft Graph **application** permissions that fully cover
/// `value` (every call it authorizes), per the "least to most privileged"
/// orderings in the Graph permissions reference.
///
/// Application permissions only: app-only tokens always carry every granted
/// role, so the narrower role is pure surface area — removing it cannot break a
/// call. Delegated scopes are NOT (token requests name scopes literally, so
/// removing a consented narrower scope can break an app); delegated redundancy
/// is deliberately out of scope.
///
/// Conservative pairs — documented full coverage only:
/// - `Mail.Send` is NOT covered by `Mail.ReadWrite` (sending is separate);
/// - `Directory.ReadWrite.All` does NOT cover `User/Group.ReadWrite.All`
///   (can't delete users or reset passwords);
/// - `Sites.Selected` is never listed as narrower: calling it redundant would
///   push admins to drop the scoped grant and keep the broad one, backwards.
///
/// Chains are flattened to their transitive closure (e.g. `Sites.Read.All`
/// lists all three broader tiers) so detection needs no traversal.
/// [`subsuming_app_permissions`] and [`downgrade_alternatives`] are forward and
/// inverse scans of this one table, so the two features can never disagree.
const SUBSUMED_APP_PERMISSIONS: &[(&str, &[&str])] = &[
    // Exchange families: ReadBasic ⊂ Read ⊂ ReadWrite.
    ("Mail.Read", &["Mail.ReadWrite"]),
    ("Mail.ReadBasic", &["Mail.Read", "Mail.ReadWrite"]),
    ("Mail.ReadBasic.All", &["Mail.Read", "Mail.ReadWrite"]),
    ("MailboxSettings.Read", &["MailboxSettings.ReadWrite"]),
    ("Calendars.Read", &["Calendars.ReadWrite"]),
    (
        "Calendars.ReadBasic",
        &["Calendars.Read", "Calendars.ReadWrite"],
    ),
    ("Contacts.Read", &["Contacts.ReadWrite"]),
    // OneDrive / SharePoint. Files.* and Sites.* are distinct families —
    // no cross-family coverage is claimed.
    ("Files.Read.All", &["Files.ReadWrite.All"]),
    (
        "Sites.Read.All",
        &[
            "Sites.ReadWrite.All",
            "Sites.Manage.All",
            "Sites.FullControl.All",
        ],
    ),
    (
        "Sites.ReadWrite.All",
        &["Sites.Manage.All", "Sites.FullControl.All"],
    ),
    ("Sites.Manage.All", &["Sites.FullControl.All"]),
    // Directory objects: Directory.Read.All is the documented
    // higher-privileged alternative for user/group/device/application reads.
    (
        "User.ReadBasic.All",
        &[
            "User.Read.All",
            "User.ReadWrite.All",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
        ],
    ),
    (
        "User.Read.All",
        &[
            "User.ReadWrite.All",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
        ],
    ),
    (
        "Group.Read.All",
        &[
            "Group.ReadWrite.All",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
        ],
    ),
    (
        "GroupMember.Read.All",
        &[
            "GroupMember.ReadWrite.All",
            "Group.Read.All",
            "Group.ReadWrite.All",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
        ],
    ),
    ("GroupMember.ReadWrite.All", &["Group.ReadWrite.All"]),
    (
        "Device.Read.All",
        &[
            "Device.ReadWrite.All",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
        ],
    ),
    (
        "Application.Read.All",
        &[
            "Application.ReadWrite.All",
            "Directory.Read.All",
            "Directory.ReadWrite.All",
        ],
    ),
    (
        "Application.ReadWrite.OwnedBy",
        &["Application.ReadWrite.All"],
    ),
    ("Directory.Read.All", &["Directory.ReadWrite.All"]),
    (
        "RoleManagement.Read.Directory",
        &["RoleManagement.ReadWrite.Directory"],
    ),
    // Teams / OneNote read-write supersets.
    (
        "Chat.ReadBasic.All",
        &["Chat.Read.All", "Chat.ReadWrite.All"],
    ),
    ("Chat.Read.All", &["Chat.ReadWrite.All"]),
    ("Notes.Read.All", &["Notes.ReadWrite.All"]),
];

/// Forward scan of `SUBSUMED_APP_PERMISSIONS` — see the table doc above.
pub fn subsuming_app_permissions(value: &str) -> &'static [&'static str] {
    SUBSUMED_APP_PERMISSIONS
        .iter()
        .find(|(narrower, _)| *narrower == value)
        .map(|(_, broaders)| *broaders)
        .unwrap_or(&[])
}

/// The narrower application permissions an admin could hold *instead of*
/// `value` — inverse scan of `SUBSUMED_APP_PERMISSIONS`, empty when already
/// least-privilege.
/// Unlike Rule-18 removal, acting on a downgrade is **not** safe by
/// construction — it only suffices if the app genuinely never uses the broader
/// capability — so every surface must offer it as an admin-judged choice, never
/// an automatic fix.
/// Ordered closest-tier-first (fewer subsumers = higher on the ladder, e.g.
/// `Sites.Manage.All` before `Sites.ReadWrite.All` for FullControl), so the
/// first entry is the least disruptive downgrade.
pub fn downgrade_alternatives(value: &str) -> Vec<&'static str> {
    let mut alts: Vec<&'static str> = SUBSUMED_APP_PERMISSIONS
        .iter()
        .filter(|(_, broaders)| broaders.contains(&value))
        .map(|(narrower, _)| *narrower)
        .collect();
    alts.sort_by_key(|a| subsuming_app_permissions(a).len());
    alts
}

/// The redundant application permissions among `grants`: each `(narrower,
/// covered_by)` pair is a held permission whose access the held `covered_by`
/// permissions fully grant on the **same resource** (per
/// [`subsuming_app_permissions`]).
///
/// Cross-resource pairs are excluded: Graph and the legacy Office 365 resources
/// both expose literal `Sites.*` / `Mail.*` appRoles that authorize nothing of
/// each other, and the old value-keyed pairing called a Graph grant "covered by"
/// an Office 365 one — text the per-resource one-click fix contradicted, and
/// following it by hand would have removed real access.
///
/// A `None` `resource_app_id` pairs with nothing: an unresolved resource cannot
/// be *proven* to be the same one, and over-reporting is advice to remove access
/// that is not in fact covered.
///
/// `broader_is_confined` vetoes a broader whose effective reach is *narrower
/// than its name implies* — a mailbox-scoped `Mail.ReadWrite` does NOT cover an
/// org-wide `Mail.Read`. Callers without scoping data pass `|_| false`.
///
/// Reported once per (resource, value) — the *first redundant* occurrence. The
/// old code deduped on the bare value BEFORE computing coverage, so iteration
/// order decided: a non-redundant Graph `Mail.Read` suppressed the genuinely
/// redundant Office 365 one, and identical tenants could score differently.
pub fn redundant_app_permissions(
    grants: &[ResourcePermission],
    broader_is_confined: impl Fn(&str) -> bool,
) -> Vec<RedundantPermission> {
    // (resource_app_id, value) — the pair that actually authorizes something.
    let held: std::collections::HashSet<(&str, &str)> = grants
        .iter()
        .filter_map(|g| Some((g.resource_app_id.as_deref()?, g.value.as_str())))
        .collect();
    // (resource, value): the same grant listed twice is one redundancy, but the
    // same value on two DIFFERENT resources is two independent questions.
    let mut examined = std::collections::HashSet::new();
    let mut out = Vec::new();
    for g in grants {
        let Some(resource) = g.resource_app_id.as_deref() else {
            continue;
        };
        if !examined.insert((resource, g.value.as_str())) {
            continue;
        }
        let covered_by: Vec<String> = subsuming_app_permissions(&g.value)
            .iter()
            .filter(|b| held.contains(&(resource, **b)) && !broader_is_confined(b))
            .map(|b| (*b).to_string())
            .collect();
        if covered_by.is_empty() {
            continue;
        }
        // One finding per (resource, value) — NOT per value. `examined` above
        // already keys on the pair, so this loop reaches each pair once; a
        // second set keyed on the bare value used to collapse those back
        // together, emitting one finding for a permission that was redundant on
        // BOTH mailbox resources. The one-click Fix then removed the grant it
        // named and left the other standing, reporting success, and the next
        // audit found the survivor again. `Mail.Read` on Microsoft Graph and on
        // Office 365 Exchange Online are two separate grants of two separate
        // kinds of access; removing one says nothing about the other.
        out.push(RedundantPermission {
            resource_app_id: resource.to_string(),
            value: g.value.clone(),
            covered_by,
        });
    }
    out
}

/// One redundant application permission: a held `value` on `resource_app_id`
/// whose access the held `covered_by` permissions **on that same resource**
/// fully grant.
///
/// Carries the resource because pairing is resource-keyed and both consumers
/// need it: the advisory must name where the pair lives (`Mail.Read` is a
/// different permission per resource), and the one-click removal must target the
/// right grant. Dropping it is how the finding text and its Fix came to describe
/// different grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedundantPermission {
    pub resource_app_id: String,
    pub value: String,
    pub covered_by: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_level_for_app_permission_matches_the_lists() {
        assert_eq!(
            risk_level_for_app_permission("Directory.ReadWrite.All"),
            Some(RiskLevel::High)
        );
        // Net-new high-risk deviation documented at the HIGH_RISK list (Sites.ReadWrite.All).
        assert_eq!(
            risk_level_for_app_permission("Sites.ReadWrite.All"),
            Some(RiskLevel::High)
        );
        assert_eq!(
            risk_level_for_app_permission("Mail.Read"),
            Some(RiskLevel::Medium)
        );
        // Net-new read halves of high-weighted families (see the medium list).
        for read_half in [
            "Contacts.Read",
            "MailboxSettings.Read",
            "Application.Read.All",
        ] {
            assert_eq!(
                risk_level_for_app_permission(read_half),
                Some(RiskLevel::Medium),
                "{read_half}"
            );
        }
        // Tier-0 answers Critical, so the per-permission badge can say so.
        assert_eq!(
            risk_level_for_app_permission("RoleManagement.ReadWrite.Directory"),
            Some(RiskLevel::Critical)
        );
        // Metadata-only mail read: deliberately unscored (INTENTIONALLY_UNSCORED).
        assert_eq!(risk_level_for_app_permission("Mail.ReadBasic.All"), None);
        // Sites.Selected is the least-privilege model — not on any risk list.
        assert_eq!(risk_level_for_app_permission("Sites.Selected"), None);
        assert_eq!(risk_level_for_app_permission("User.Read"), None);
    }

    #[test]
    fn least_privilege_alternative_points_to_the_scoped_model() {
        use crate::scoping::{
            MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID,
            OFFICE365_SHAREPOINT_ONLINE_APP_ID,
        };
        let graph = |v| least_privilege_alternative_for(Some(MICROSOFT_GRAPH_APP_ID), v);
        // Broad Sites.* -> Sites.Selected (Rule 12 scoped model).
        assert_eq!(graph("Sites.ReadWrite.All"), Some("Sites.Selected"));
        assert_eq!(graph("Sites.FullControl.All"), Some("Sites.Selected"));
        // Exchange-scopable mail -> RBAC pointer; a lookalike with no Exchange
        // role does not (parallels scoping::loose_mail_lookalikes_are_not_scopable).
        assert_eq!(
            graph("Mail.Send"),
            Some("Scope to specific mailboxes (Exchange RBAC)")
        );
        assert_eq!(graph("Mail.ReadWrite.Shared"), None);
        // Org-wide Files -> the item-level scoped model. The picker hint, the
        // audit's Rule 12 advisory and the wizard all name this one value, so
        // the family is a list, not a `Files.` prefix.
        assert_eq!(
            graph("Files.Read.All"),
            Some("Files.SelectedOperations.Selected")
        );
        assert_eq!(
            graph("Files.ReadWrite.All"),
            Some("Files.SelectedOperations.Selected")
        );
        assert_eq!(graph("Files.SelectedOperations.Selected"), None);
        assert_eq!(graph("Files.ReadWrite.AppFolder"), None);
        // Already least-privilege / no narrower equivalent.
        assert_eq!(graph("Sites.Selected"), None);
        assert_eq!(graph("Directory.ReadWrite.All"), None);

        // The resource decides: RBAC for Applications cannot confine Office 365
        // Exchange Online's mail appRoles, and an unknown resource gets no
        // mailbox advice either.
        assert_eq!(
            least_privilege_alternative_for(Some(OFFICE365_EXCHANGE_ONLINE_APP_ID), "Mail.Read"),
            None
        );
        assert_eq!(least_privilege_alternative_for(None, "Mail.Send"), None);
        // Office 365 SharePoint Online exposes Sites.Selected too.
        assert_eq!(
            least_privilege_alternative_for(
                Some(OFFICE365_SHAREPOINT_ONLINE_APP_ID),
                "Sites.Read.All"
            ),
            Some("Sites.Selected")
        );
        // Another API's `Sites.`-named role is not SharePoint site access.
        assert_eq!(
            least_privilege_alternative_for(Some("custom-api"), "Sites.Read.All"),
            None
        );
    }

    /// Every mailbox-family name in the risk tables must be one `scoping.rs`
    /// recognises — the guard that would have caught `Calendar.ReadWrite`: a
    /// permission Graph does not define (calendar permissions are plural), and a
    /// string that matches nothing looks exactly like one that has not come up.
    ///
    /// `scoping.rs` independently maps every scopable mail/calendar/contacts
    /// permission to its Exchange role — a second spelling of the same names, so
    /// a name in one list that the other rejects is a typo by construction.
    /// Limited to that family: the tables also carry names `scoping.rs` has no
    /// opinion on.
    #[test]
    fn mailbox_family_risk_entries_agree_with_the_scoping_role_map() {
        // `Mail` unterminated on purpose: it has to see `Mailbox*` and `Mail-*`
        // as well as `Mail.*`, or the newer RBAC-scopable entries are invisible
        // to this typo guard.
        let mailbox_family = |v: &str| {
            v.starts_with("Mail") || v.starts_with("Calendar") || v.starts_with("Contacts.")
        };
        let mut unmapped: Vec<&str> = Vec::new();
        let mut checked = 0usize;
        for value in HIGH_RISK_APP_PERMISSIONS
            .iter()
            .chain(MEDIUM_RISK_APP_PERMISSIONS.iter())
        {
            if !mailbox_family(value) {
                continue;
            }
            checked += 1;
            if crate::scoping::exchange_role_for_resource_permission(
                crate::scoping::MICROSOFT_GRAPH_APP_ID,
                value,
            )
            .is_none()
            {
                unmapped.push(value);
            }
        }
        assert!(
            checked >= 4,
            "only {checked} mailbox-family risk entries found — the family test is broken and \
             this rule would pass vacuously"
        );
        assert!(
            unmapped.is_empty(),
            "risk-table entries in the mail/calendar/contacts family that scoping.rs does not \
             recognise: {unmapped:?}\nA name no gate maps is a name no grant can match, so the \
             entry is dead and the permission scores zero. Check the exact spelling against the \
             Microsoft Graph permissions reference — `Calendars.*` is plural."
        );
    }

    /// Subsumption-table values that deliberately carry no risk weight, shared
    /// by the broader-side and narrower-side weight walks below. An entry here
    /// is a claim that holding this permission tenant-wide is not itself a risk
    /// signal — write the reason next to it.
    const INTENTIONALLY_UNSCORED: &[(&str, &str)] = &[
        (
            "Sites.Manage.All",
            "Rule 12 already raises the org-wide SharePoint advisory for any broad `Sites.*`, \
             and `scoring::tests::broad_sharepoint_manage_flags_issue_without_score` pins that \
             the advisory fires INDEPENDENTLY of risk-list weighting — using this value as its \
             example. Giving it points would make that test's example unrepresentative and \
             double-count reach the advisory already reports. Left to the owner as a risk-model \
             call; the permission is surfaced either way.",
        ),
        (
            "Mail.ReadBasic",
            "Message metadata only (sender, subject, dates) — no body, no attachments. Rule 11 \
             still raises the org-wide mailbox advisory and offers the Scope fix, so the grant \
             is surfaced without points.",
        ),
        (
            "Mail.ReadBasic.All",
            "Message metadata only (sender, subject, dates) — no body, no attachments. Rule 11 \
             still raises the org-wide mailbox advisory and offers the Scope fix, so the grant \
             is surfaced without points.",
        ),
        (
            "Calendars.ReadBasic",
            "Event metadata (times, subject, location) without the event body; the \
             least-privileged calendar read.",
        ),
        (
            "User.ReadBasic.All",
            "Basic profile fields only (name, mail, photo) — the minimal directory read every \
             people-picker needs.",
        ),
        (
            "Chat.ReadBasic.All",
            "Chat metadata (names, members) without any message content.",
        ),
    ];

    /// The reverse guard, and the one that was missing: the role-map scan catches
    /// typos in entries that exist, this catches entries never written (how nine
    /// values scored zero while this file named them as broader sides).
    ///
    /// If the file asserts B ⊇ N, holding B is at least N's reach, so B must
    /// carry a weight. Derived from `SUBSUMED_APP_PERMISSIONS` itself, so it
    /// cannot drift — adding a pair forces the weight decision. Deliberately
    /// unscored values go in `INTENTIONALLY_UNSCORED` with a reason, keeping the
    /// decision visible.
    #[test]
    fn every_broader_subsuming_permission_carries_a_risk_weight() {
        let scored = |v: &str| risk_level_for_app_permission(v).is_some();
        let mut unscored: Vec<&str> = Vec::new();
        let mut checked = 0usize;
        for (_, broaders) in SUBSUMED_APP_PERMISSIONS {
            for b in *broaders {
                checked += 1;
                if scored(b) || INTENTIONALLY_UNSCORED.iter().any(|(v, _)| v == b) {
                    continue;
                }
                unscored.push(b);
            }
        }
        unscored.sort_unstable();
        unscored.dedup();

        assert!(
            checked >= 20,
            "only {checked} broader-side values walked — the subsumption table or this walk is \
             broken, and the rule would pass vacuously"
        );
        assert!(
            unscored.is_empty(),
            "these permissions are named as the BROADER side of a subsumption pair — this file \
             tells operators to downgrade away from them — yet they carry no risk weight and so \
             score zero: {unscored:?}\nAdd them to HIGH_RISK_APP_PERMISSIONS or \
             MEDIUM_RISK_APP_PERMISSIONS (tenant-wide write is high, tenant-wide read is medium), \
             or list them in INTENTIONALLY_UNSCORED with a reason."
        );
    }

    /// The narrower side of the same table: read halves (e.g. `Contacts.Read`,
    /// `MailboxSettings.Read`) scored zero while their write halves scored high —
    /// `Contacts.Read` even raised the mailbox advisory while adding nothing.
    /// Every narrower value needs a weight or a written `INTENTIONALLY_UNSCORED`
    /// reason.
    #[test]
    fn every_narrower_subsumed_permission_carries_a_risk_weight() {
        let scored = |v: &str| risk_level_for_app_permission(v).is_some();
        let mut unscored: Vec<&str> = Vec::new();
        let mut checked = 0usize;
        for (narrower, _) in SUBSUMED_APP_PERMISSIONS {
            checked += 1;
            if scored(narrower) || INTENTIONALLY_UNSCORED.iter().any(|(v, _)| v == narrower) {
                continue;
            }
            unscored.push(narrower);
        }

        assert!(
            checked >= 20,
            "only {checked} narrower-side values walked — the subsumption table or this walk is \
             broken, and the rule would pass vacuously"
        );
        assert!(
            unscored.is_empty(),
            "these permissions are the NARROWER side of a subsumption pair whose broader side is \
             weighted, yet they carry no risk weight and so score zero: {unscored:?}\nAdd them to \
             MEDIUM_RISK_APP_PERMISSIONS (tenant-wide read is medium) or HIGH_RISK_APP_PERMISSIONS, \
             or list them in INTENTIONALLY_UNSCORED with a reason."
        );

        // The exemption list must not go stale: an exempted value that later
        // gained a weight makes its written reason a lie.
        let stale: Vec<&str> = INTENTIONALLY_UNSCORED
            .iter()
            .map(|(v, _)| *v)
            .filter(|v| scored(v))
            .collect();
        assert!(
            stale.is_empty(),
            "INTENTIONALLY_UNSCORED lists values that now carry a risk weight: {stale:?} — \
             remove them from the exemption list"
        );
    }

    /// Mailbox-family WRITE permissions are high-risk: each writes to every
    /// mailbox in the tenant. The one ported exception is `Calendars.ReadWrite`,
    /// whose medium tier is parity with the legacy module — kept visible here so
    /// a new medium write cannot slip in silently, and so promoting the exception
    /// is a deliberate edit that removes it from this list.
    #[test]
    fn mailbox_family_writes_are_high_unless_ported_otherwise() {
        const INTENTIONALLY_MEDIUM_WRITES: &[(&str, &str)] = &[(
            "Calendars.ReadWrite",
            "PowerShell parity: `Constants.ps1:123-130` lists it in the medium tier, and the \
             `Calendar.ReadWrite` typo fix kept that tier. Promoting it shifts risk ranking and \
             needs a CHANGELOG note.",
        )];
        // Same predicate as `mailbox_family_risk_entries_agree_with_the_scoping_role_map`.
        let mailbox_family = |v: &str| {
            v.starts_with("Mail") || v.starts_with("Calendar") || v.starts_with("Contacts.")
        };
        let mut values: Vec<&str> = HIGH_RISK_APP_PERMISSIONS
            .iter()
            .chain(MEDIUM_RISK_APP_PERMISSIONS.iter())
            .copied()
            .chain(
                SUBSUMED_APP_PERMISSIONS
                    .iter()
                    .flat_map(|(n, broaders)| std::iter::once(*n).chain(broaders.iter().copied())),
            )
            .filter(|v| mailbox_family(v) && v.contains("ReadWrite"))
            .collect();
        values.sort_unstable();
        values.dedup();

        let not_high: Vec<&str> = values
            .iter()
            .copied()
            .filter(|v| {
                !HIGH_RISK_APP_PERMISSIONS.contains(v)
                    && !INTENTIONALLY_MEDIUM_WRITES.iter().any(|(e, _)| e == v)
            })
            .collect();
        assert!(
            values.len() >= 6,
            "only {} mailbox-family write values found — the predicate or the tables are broken, \
             and this rule would pass vacuously",
            values.len()
        );
        assert!(
            not_high.is_empty(),
            "mailbox-family write permissions that are not high-risk: {not_high:?}\nTenant-wide \
             mailbox write is high; list a deliberate exception in INTENTIONALLY_MEDIUM_WRITES \
             with its reason."
        );
        for (exempt, _) in INTENTIONALLY_MEDIUM_WRITES {
            assert!(
                MEDIUM_RISK_APP_PERMISSIONS.contains(exempt),
                "{exempt} is exempted as a medium write but is not in MEDIUM_RISK_APP_PERMISSIONS"
            );
        }
    }

    #[test]
    fn classify_app_permission_risk_splits_high_and_medium() {
        let grants: Vec<ResourcePermission> = [
            "Directory.ReadWrite.All", // high
            "Mail.Send",               // high
            "User.Read.All",           // medium
            "openid",                  // neither
        ]
        .iter()
        .map(|v| ResourcePermission::graph(*v))
        .collect();
        let (high, medium) = classify_app_permission_risk(&grants);
        assert_eq!(high.len(), 2);
        assert!(high.iter().any(|g| g.value == "Directory.ReadWrite.All"));
        assert_eq!(medium.len(), 1);
        assert_eq!(medium[0].value, "User.Read.All");
    }

    /// The classifier carries the resource through, so a caller can name it.
    ///
    /// It used to take `&[String]`, which made that impossible for the
    /// held-permissions panel however it wanted to render — and AGENTS.md
    /// requires operator-facing text to name the resource, because `Mail.Send`
    /// on Microsoft Graph and on Office 365 Exchange Online are different
    /// grants and only Graph's is confinable.
    #[test]
    fn classify_app_permission_risk_keeps_the_resource_on_each_hit() {
        let grants = vec![
            ResourcePermission::graph("Mail.Send"),
            ResourcePermission::exchange_online("Mail.Send"),
        ];
        let (high, _) = classify_app_permission_risk(&grants);
        assert_eq!(high.len(), 2, "the same value on two resources is two hits");
        let resources: Vec<Option<&str>> =
            high.iter().map(|g| g.resource_app_id.as_deref()).collect();
        assert!(
            resources.contains(&Some(crate::scoping::MICROSOFT_GRAPH_APP_ID))
                && resources.contains(&Some(crate::scoping::OFFICE365_EXCHANGE_ONLINE_APP_ID)),
            "both resources must survive classification: {resources:?}"
        );
    }

    #[test]
    fn risky_delegated_scope_classifier() {
        for s in [
            "Mail.Read",
            "Mail.ReadWrite",
            "Files.ReadWrite.All",
            "Directory.AccessAsUser.All",
            "Directory.Read.All",
            "Group.ReadWrite.All",
            "Sites.FullControl.All",
            "user_impersonation",
            "RoleManagement.ReadWrite.Directory",
            // Net-new widening: identity, consent, policy and membership
            // writers, plus the calendar/chat families that reach users' data
            // the way Mail.* does.
            "User.ReadWrite.All",
            "Application.ReadWrite.All",
            "Policy.ReadWrite.ConditionalAccess",
            "UserAuthenticationMethod.ReadWrite.All",
            "GroupMember.ReadWrite.All",
            "DelegatedPermissionGrant.ReadWrite.All",
            "Calendars.ReadWrite",
            "Calendars.ReadWrite.Shared",
            "Chat.ReadWrite",
            "Chat.ReadWrite.All",
            "UserAuthenticationMethod.ReadWrite",
            "Policy.ReadWrite.Authorization",
        ] {
            assert!(is_risky_delegated_scope(s), "{s} should be risky");
        }
        for s in [
            "User.Read",
            "User.ReadBasic.All",
            "openid",
            "profile",
            "email",
            "offline_access",
            // Every Selected scope is the least-privilege end state — the bare
            // `Files.` prefix used to flag the sub-site one.
            "Sites.Selected",
            "Files.SelectedOperations.Selected",
            "Lists.SelectedOperations.Selected",
            "ListItems.SelectedOperations.Selected",
            // The newer families flag their WRITE half only.
            "Policy.Read.All",
            "Application.Read.All",
            "Calendars.Read",
            "Calendars.ReadBasic",
            "Chat.Read",
            "Chat.ReadBasic",
            "UserAuthenticationMethod.Read",
            "UserAuthenticationMethod.Read.All",
            "GroupMember.Read.All",
            "DelegatedPermissionGrant.Read.All",
        ] {
            assert!(!is_risky_delegated_scope(s), "{s} should not be risky");
        }
    }

    /// A tier-0 grant scores the tier-0 weight ONLY — never tier-0 plus high —
    /// which holds by construction only while the lists share no value.
    #[test]
    fn tier0_high_and_medium_lists_are_disjoint() {
        for v in TIER0_APP_PERMISSIONS {
            assert!(
                !HIGH_RISK_APP_PERMISSIONS.contains(v) && !MEDIUM_RISK_APP_PERMISSIONS.contains(v),
                "{v} is tier-0 AND on another risk list — it would score twice"
            );
        }
        for v in HIGH_RISK_APP_PERMISSIONS {
            assert!(
                !MEDIUM_RISK_APP_PERMISSIONS.contains(v),
                "{v} is high AND medium"
            );
        }
        // The weight is what makes one grant Critical alone (the user-chosen
        // contract), not an accident of the current thresholds.
        const {
            assert!(PTS_TIER0_APP_PERM >= RISK_CRITICAL);
            assert!(PTS_HIGH_RISK_APP_PERM < RISK_CRITICAL);
        }
    }

    /// Table-driven tier placement. `net_new` marks rows with no
    /// `Constants.ps1` origin; the three ported rows were `Constants.ps1:104-115`
    /// high entries promoted to tier-0, and `Directory.ReadWrite.All` is the
    /// ported high entry deliberately NOT promoted.
    #[test]
    fn tier_placement_table() {
        use RiskLevel::{Critical, High};
        // (value, expected level, net_new)
        let rows: &[(&str, RiskLevel, bool)] = &[
            ("RoleManagement.ReadWrite.Directory", Critical, false),
            ("AppRoleAssignment.ReadWrite.All", Critical, false),
            ("Application.ReadWrite.All", Critical, false),
            ("RoleAssignmentSchedule.ReadWrite.Directory", Critical, true),
            (
                "RoleEligibilitySchedule.ReadWrite.Directory",
                Critical,
                true,
            ),
            ("PrivilegedAccess.ReadWrite.AzureADGroup", Critical, true),
            (
                "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
                Critical,
                true,
            ),
            (
                "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
                Critical,
                true,
            ),
            ("Policy.ReadWrite.PermissionGrant", Critical, true),
            ("Policy.ReadWrite.ConditionalAccess", Critical, true),
            ("Domain.ReadWrite.All", Critical, true),
            ("UserAuthenticationMethod.ReadWrite.All", Critical, true),
            ("Directory.ReadWrite.All", High, false),
            ("Application.ReadWrite.OwnedBy", High, true),
            ("EntitlementManagement.ReadWrite.All", High, true),
            ("User-PasswordProfile.ReadWrite.All", High, true),
            ("Organization.ReadWrite.All", High, true),
            ("Policy.ReadWrite.AuthenticationMethod", High, true),
            ("RoleManagementPolicy.ReadWrite.Directory", High, true),
            ("DelegatedPermissionGrant.ReadWrite.All", High, true),
            ("Policy.ReadWrite.CrossTenantAccess", High, true),
            ("Policy.ReadWrite.Authorization", High, true),
            ("Policy.ReadWrite.ApplicationConfiguration", High, true),
            ("Exchange.ManageAsApp", High, true),
        ];
        for (value, level, _net_new) in rows {
            assert_eq!(
                risk_level_for_app_permission(value),
                Some(*level),
                "{value}"
            );
        }
        // Every tier-0 entry is in the table, so adding one forces a row.
        for v in TIER0_APP_PERMISSIONS {
            assert!(
                rows.iter().any(|(r, l, _)| r == v && *l == Critical),
                "{v} has no tier_placement_table row"
            );
        }
    }

    #[test]
    fn redundant_app_permissions_pairs_held_subsumed_values() {
        // Every case here holds its permissions on Microsoft Graph; the
        // cross-resource behaviour has its own test below.
        let values = |vs: &[&str]| {
            vs.iter()
                .map(|v| ResourcePermission::graph(*v))
                .collect::<Vec<_>>()
        };
        let unconfined = |_: &str| false;

        // (held values, expected (narrower, covered_by) pairs)
        type Case = (
            &'static [&'static str],
            &'static [(&'static str, &'static [&'static str])],
        );
        let cases: [Case; 6] = [
            // ReadWrite covers Read within a family.
            (
                &["Mail.ReadWrite", "Mail.Read"],
                &[("Mail.Read", &["Mail.ReadWrite"])],
            ),
            // Transitive chain: FullControl covers both lower Sites tiers.
            (
                &[
                    "Sites.FullControl.All",
                    "Sites.ReadWrite.All",
                    "Sites.Read.All",
                ],
                &[
                    ("Sites.ReadWrite.All", &["Sites.FullControl.All"]),
                    (
                        "Sites.Read.All",
                        &["Sites.ReadWrite.All", "Sites.FullControl.All"],
                    ),
                ],
            ),
            // Cross-family: Directory.Read.All covers user/group reads.
            (
                &["Directory.Read.All", "User.Read.All", "Group.Read.All"],
                &[
                    ("User.Read.All", &["Directory.Read.All"]),
                    ("Group.Read.All", &["Directory.Read.All"]),
                ],
            ),
            // Mail.Send is NOT covered by Mail.ReadWrite — sending is separate.
            (&["Mail.ReadWrite", "Mail.Send"], &[]),
            // Sites.Selected is never flagged redundant, even under FullControl:
            // it's the least-privilege model Rule 12 pushes toward.
            (&["Sites.FullControl.All", "Sites.Selected"], &[]),
            // Directory.ReadWrite.All does not cover the user/group writes.
            (
                &[
                    "Directory.ReadWrite.All",
                    "User.ReadWrite.All",
                    "Group.ReadWrite.All",
                ],
                &[],
            ),
        ];
        for (held, expected) in cases {
            let got = redundant_app_permissions(&values(held), unconfined);
            let want: Vec<(String, Vec<String>)> = expected
                .iter()
                .map(|(n, bs)| {
                    (
                        n.to_string(),
                        bs.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
                    )
                })
                .collect();
            let got_pairs: Vec<(String, Vec<String>)> = got
                .iter()
                .map(|r| (r.value.clone(), r.covered_by.clone()))
                .collect();
            assert_eq!(got_pairs, want, "held = {held:?}");
        }

        // The same value declared twice (e.g. on two resources) reports once.
        let got = redundant_app_permissions(
            &values(&["Mail.ReadWrite", "Mail.Read", "Mail.Read"]),
            unconfined,
        );
        assert_eq!(got.len(), 1);

        // NOT covered by a same-named broader grant on a DIFFERENT resource:
        // keyed on the bare value this paired them and told the operator to
        // remove live access, while the per-resource re-plan did nothing — the
        // advisory text and its remediation disagreed.
        let cross_resource = vec![
            ResourcePermission {
                resource_app_id: Some(
                    crate::scoping::OFFICE365_SHAREPOINT_ONLINE_APP_ID.to_string(),
                ),
                value: "Sites.ReadWrite.All".to_string(),
            },
            ResourcePermission::graph("Sites.Read.All"),
        ];
        assert!(
            redundant_app_permissions(&cross_resource, unconfined).is_empty(),
            "a Graph Sites.Read.All is not covered by an Office 365 Sites.ReadWrite.All"
        );

        // ...and the same two values on ONE resource still pair, so the fix did
        // not simply disable the rule.
        let same_resource = values(&["Sites.ReadWrite.All", "Sites.Read.All"]);
        assert_eq!(
            redundant_app_permissions(&same_resource, unconfined),
            vec![RedundantPermission {
                resource_app_id: crate::scoping::MICROSOFT_GRAPH_APP_ID.to_string(),
                value: "Sites.Read.All".to_string(),
                covered_by: vec!["Sites.ReadWrite.All".to_string()],
            }]
        );

        // An unresolved resource pairs with nothing: it cannot be proven to be
        // the same resource, and over-reporting here is advice to remove access
        // that is not in fact covered.
        let unresolved = vec![
            ResourcePermission {
                resource_app_id: None,
                value: "Mail.ReadWrite".to_string(),
            },
            ResourcePermission {
                resource_app_id: None,
                value: "Mail.Read".to_string(),
            },
        ];
        assert!(redundant_app_permissions(&unresolved, unconfined).is_empty());

        // THE ORDERING CASE: `Mail.Read` on Graph (nothing covers it there) and
        // on Office 365 Exchange Online beside that resource's `Mail.ReadWrite`.
        // The old dedup-before-coverage made iteration order decide: with Graph
        // first, the real Office 365 redundancy was silently suppressed, and
        // identical tenants could score differently. Correctness, not
        // presentation.
        let ews = crate::scoping::OFFICE365_EXCHANGE_ONLINE_APP_ID.to_string();
        let split = vec![
            // Graph first: the suppressing order.
            ResourcePermission::graph("Mail.Read"),
            ResourcePermission {
                resource_app_id: Some(ews.clone()),
                value: "Mail.ReadWrite".to_string(),
            },
            ResourcePermission {
                resource_app_id: Some(ews.clone()),
                value: "Mail.Read".to_string(),
            },
        ];
        assert_eq!(
            redundant_app_permissions(&split, unconfined),
            vec![RedundantPermission {
                resource_app_id: ews.clone(),
                value: "Mail.Read".to_string(),
                covered_by: vec!["Mail.ReadWrite".to_string()],
            }],
            "the Office 365 redundancy must be found even though the Graph grant of the same \
             value comes first and is not redundant"
        );

        // Same grants, opposite order: the answer must not depend on it.
        let reordered = vec![split[2].clone(), split[1].clone(), split[0].clone()];
        assert_eq!(
            redundant_app_permissions(&reordered, unconfined),
            redundant_app_permissions(&split, unconfined),
            "redundancy must be order-independent"
        );

        // A confined broader permission is vetoed as a coverer.
        let got = redundant_app_permissions(&values(&["Mail.ReadWrite", "Mail.Read"]), |b| {
            b == "Mail.ReadWrite"
        });
        assert!(got.is_empty(), "scoped broader must not cover: {got:?}");
    }

    /// Redundant on BOTH mailbox resources ⇒ TWO findings, not one. A second
    /// dedup set keyed on the bare value used to collapse them: the Fix removed
    /// the named grant, reported success, and left the other standing. `Mail.Read`
    /// per resource is two separate grants, and only Graph's is confinable.
    #[test]
    fn a_value_redundant_on_both_resources_is_reported_for_each() {
        let unconfined = |_: &str| false;
        let ews = crate::scoping::OFFICE365_EXCHANGE_ONLINE_APP_ID.to_string();
        let graph = crate::scoping::MICROSOFT_GRAPH_APP_ID.to_string();
        let both = vec![
            ResourcePermission::graph("Mail.ReadWrite"),
            ResourcePermission::graph("Mail.Read"),
            ResourcePermission {
                resource_app_id: Some(ews.clone()),
                value: "Mail.ReadWrite".to_string(),
            },
            ResourcePermission {
                resource_app_id: Some(ews.clone()),
                value: "Mail.Read".to_string(),
            },
        ];
        let got = redundant_app_permissions(&both, unconfined);
        assert_eq!(
            got.len(),
            2,
            "one finding per (resource, value); a single finding leaves real redundant access \
             behind after the Fix reports success: {got:?}"
        );
        let resources: Vec<&str> = got.iter().map(|r| r.resource_app_id.as_str()).collect();
        assert!(
            resources.contains(&graph.as_str()) && resources.contains(&ews.as_str()),
            "both resources must be named so each Fix targets the right grant: {resources:?}"
        );
        assert!(
            got.iter().all(|r| r.value == "Mail.Read"),
            "only the narrower permission is redundant: {got:?}"
        );
    }

    #[test]
    fn downgrade_alternatives_invert_subsumption_closest_first() {
        // Inverse property: every (narrower → broaders) table entry round-trips,
        // so Rule 18 and the downgrade suggestions can never disagree.
        for v in [
            "Mail.Read",
            "Sites.Read.All",
            "User.Read.All",
            "Application.ReadWrite.OwnedBy",
        ] {
            for b in subsuming_app_permissions(v) {
                assert!(
                    downgrade_alternatives(b).contains(&v),
                    "{b} should offer {v} as a downgrade"
                );
            }
        }
        // Closest tier first: fewer subsumers = higher rung on the ladder.
        assert_eq!(
            downgrade_alternatives("Sites.FullControl.All"),
            vec!["Sites.Manage.All", "Sites.ReadWrite.All", "Sites.Read.All"]
        );
        assert_eq!(downgrade_alternatives("Mail.ReadWrite")[0], "Mail.Read");
        assert_eq!(
            downgrade_alternatives("Directory.ReadWrite.All")[0],
            "Directory.Read.All"
        );
        // Already least-privilege / no narrower equivalent → empty.
        assert!(downgrade_alternatives("Sites.Selected").is_empty());
        assert!(downgrade_alternatives("Mail.Send").is_empty());
    }
}
