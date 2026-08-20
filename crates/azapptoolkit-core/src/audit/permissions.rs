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

/// Long-lived secret threshold. `Credential-Analysis.ps1:169`.
pub const LONG_LIVED_SECRET_DAYS: i64 = 365;

/// Score increments.
pub(super) const PTS_HIGH_RISK_APP_PERM: u32 = 10;
pub(super) const PTS_MEDIUM_RISK_APP_PERM: u32 = 5;
pub(super) const PTS_ADMIN_CONSENT_DELEGATED: u32 = 5;
pub(super) const PTS_SP_DISABLED: u32 = 2;
pub(super) const PTS_ALL_CREDS_EXPIRED: u32 = 8;
pub(super) const PTS_MIXED_EXPIRED: u32 = 4;
pub(super) const PTS_ALL_EXPIRING_SOON: u32 = 3;
pub(super) const PTS_MIXED_EXPIRING: u32 = 2;
pub(super) const PTS_LONG_LIVED: u32 = 3;
pub(super) const PTS_STALE_APP: u32 = 2;
/// Multi-tenant / personal-account sign-in audience on an app that actually
/// holds something worth taking (application permissions or credentials).
///
/// Scored rather than advisory because the audience is a genuine *blast-radius
/// multiplier*, not a preference: it decides whether the app's permissions are
/// reachable by principals outside this directory at all. It is weighted below a
/// single medium-risk permission — the audience alone is not a finding, it
/// sharpens the ones already present, which is why it only fires alongside them.
pub(super) const PTS_MULTITENANT_EXPOSURE: u32 = 3;
/// Additional weight when a multi-tenant app also has **no verified publisher**.
/// Publisher verification is what lets a consenting tenant's admin tell who the
/// app's author actually is; without it, a multi-tenant app asking for consent
/// is unattributable.
pub(super) const PTS_UNVERIFIED_PUBLISHER: u32 = 2;
/// Reduced weight for a high/medium-risk *mail* permission that is confirmed
/// scoped to specific mailboxes via Exchange RBAC for Applications (see
/// [`AppPermissions::mail_scopes`]). A `Mail.Send` confined to one shared
/// mailbox is far lower risk than tenant-wide `Mail.Send`, but it is not zero —
/// the scope can still cover many recipients — so it keeps a small residual.
pub(super) const PTS_SCOPED_HIGH_RISK_MAIL: u32 = 3;
pub(super) const PTS_SCOPED_MEDIUM_RISK_MAIL: u32 = 2;

/// High-risk application permissions (by `value` string). Mirrors
/// `Constants.ps1:104-115`.
pub const HIGH_RISK_APP_PERMISSIONS: &[&str] = &[
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.FullControl.All",
    // Net-new (not in the PowerShell `Constants.ps1` source): org-wide
    // `Sites.ReadWrite.All` grants tenant-wide write to every site, so it is
    // weighted alongside `Sites.FullControl.All` rather than left advisory-only.
    // The scoped alternative is `Sites.Selected` (see Rule 12), which is not in
    // any risk list and therefore scores zero.
    "Sites.ReadWrite.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    // Net-new. Microsoft's own permissions reference flags both of these with a
    // "Caution" note for the reason that makes them tenant-compromising:
    // `Application.ReadWrite.OwnedBy` "allows the same operations as
    // Application.ReadWrite.All but only on applications it is an owner of" —
    // including updating their secrets, i.e. acting as those entities — and it
    // can still list every application and service principal in the tenant;
    // `EntitlementManagement.ReadWrite.All` can "grant additional privileges to
    // itself, other applications, or any user", covering Entra role
    // assignments, app role assignments and API permissions. Both scored ZERO.
    "Application.ReadWrite.OwnedBy",
    "EntitlementManagement.ReadWrite.All",
    // Net-new (not in the PowerShell `Constants.ps1` source): the EWS
    // `full_access_as_app` scope on the legacy Office 365 Exchange Online
    // resource grants full access to *every* mailbox in the tenant — strictly
    // broader than `Mail.ReadWrite`, which is already high-risk here. It scored
    // zero before because the risk tables only ever listed Microsoft Graph
    // names. Unambiguous as a bare value: no other resource exposes it (see
    // `scoping::EWS_FULL_ACCESS_AS_APP`).
    // Net-new, and all nine additions here share one origin: they appear in
    // `SUBSUMED_APP_PERMISSIONS` as the BROADER side of a subsumption pair — the
    // file already names them, and `subsuming_app_permissions` already advises
    // operators to downgrade *to* the narrower one — yet none was in either risk
    // table, so each scored ZERO. Weights follow the split the tables already
    // use for every other family: tenant-wide WRITE is high, tenant-wide READ is
    // medium (`Mail.ReadWrite`/`Mail.Read`, `Files.ReadWrite.All`/
    // `Files.Read.All`, `Sites.ReadWrite.All`/`Sites.Read.All`).
    //
    // `MailboxSettings.ReadWrite` is the one to note: it sets mail forwarding on
    // every mailbox in the tenant, which is the classic exfiltration primitive
    // and needs no read permission to act.
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
    crate::scoping::EWS_FULL_ACCESS_AS_APP,
];

/// Medium-risk application permissions (by `value` string). Mirrors
/// `Constants.ps1:123-130`.
pub const MEDIUM_RISK_APP_PERMISSIONS: &[&str] = &[
    "User.Read.All",
    "Group.Read.All",
    "Mail.Read",
    "Files.Read.All",
    "Sites.Read.All",
    // `Calendars.ReadWrite`, PLURAL. This entry read `Calendar.ReadWrite` for
    // its whole life, which is not a permission Microsoft Graph defines — every
    // calendar permission is plural (`Calendars.Read`, `Calendars.ReadWrite`,
    // `Calendars.ReadWrite.All`), and the rest of this codebase already used the
    // plural form in `scoping.rs`'s role map and in the subsumption table below.
    // So the entry could never match a real grant: an application holding
    // org-wide `Calendars.ReadWrite` — create, read, update and delete events in
    // EVERY mailbox — scored zero and could rank Low.
    "Calendars.ReadWrite",
    // Net-new. Microsoft describes this as "the highest privileged read-only
    // permission for Microsoft Entra ID resources", ranked immediately below
    // `Directory.ReadWrite.All`. It sits in the medium band with the other
    // tenant-wide reads (`User.Read.All`, `Group.Read.All`) rather than the high
    // one, which is reserved for write and impersonation — but it reads strictly
    // more than either of them and scored zero.
    "Directory.Read.All",
    // Net-new — the read halves of the two families added to the high list
    // above, weighted like `Mail.Read` rather than their write counterparts.
    "Chat.Read.All",
    "Calendars.Read",
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
    "Directory.",
    "Group.",
    "AppRoleAssignment.",
    "RoleManagement.",
];

/// Splits held application permissions into `(high_risk, medium_risk)` hits
/// using [`HIGH_RISK_APP_PERMISSIONS`] / [`MEDIUM_RISK_APP_PERMISSIONS`].
/// Reusable for auditing the application permissions *held* by managed
/// identities and enterprise-app service principals (not just app registrations).
///
/// Takes whole [`ResourcePermission`]s, not bare values. AGENTS.md: permissions
/// travel as `ResourcePermission` and operator-facing text names the resource —
/// `Mail.ReadWrite` on Microsoft Graph and on Office 365 Exchange Online are
/// different grants with different reach, and only Graph's is confinable, so a
/// banner naming one without saying which leaves the operator to guess. The
/// previous `&[String]` signature made that impossible for its caller to get
/// right, whatever it wanted to do.
///
/// Matching is still on the value alone, so this is behaviour-preserving: an
/// app-role of the same name on an unrelated API is still counted. Whether it
/// *should* be is a separate question about the risk model — over-reporting is
/// the safe direction for a security tool, and narrowing it would need a
/// deliberate decision rather than a refactor.
pub fn classify_app_permission_risk(
    grants: &[ResourcePermission],
) -> (Vec<ResourcePermission>, Vec<ResourcePermission>) {
    let high = grants
        .iter()
        .filter(|g| HIGH_RISK_APP_PERMISSIONS.contains(&g.value.as_str()))
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
/// read/write categories (mail, files, directory, …). `Sites.Selected` is
/// explicitly excluded as it is the *least*-privilege SharePoint scope.
pub fn is_risky_delegated_scope(scope: &str) -> bool {
    if HIGH_RISK_DELEGATED_PERMISSIONS.contains(&scope) {
        return true;
    }
    if scope == "Sites.Selected" {
        return false;
    }
    scope.starts_with("Sites.")
        || RISKY_DELEGATED_SCOPE_PREFIXES
            .iter()
            .any(|p| scope.starts_with(p))
}

/// Risk level of a single application-permission `value`, or `None` when it is
/// not on the high/medium-risk lists. The single source the grant-time picker
/// and the managed-identity detail badge both read, so a permission's risk is
/// classified in exactly one place.
pub fn risk_level_for_app_permission(value: &str) -> Option<RiskLevel> {
    if HIGH_RISK_APP_PERMISSIONS.contains(&value) {
        Some(RiskLevel::High)
    } else if MEDIUM_RISK_APP_PERMISSIONS.contains(&value) {
        Some(RiskLevel::Medium)
    } else {
        None
    }
}

/// A least-privilege alternative to a broad application permission, as an
/// advisory pointer shown at grant time — never an automatic rewrite. Returns
/// `None` when the permission is already least-privilege or has no narrower
/// equivalent. Derives from the shared scope predicates so it stays consistent
/// with Rule 11/12 and the scope badges.
pub fn least_privilege_alternative(value: &str) -> Option<&'static str> {
    least_privilege_alternative_for(Some(crate::scoping::MICROSOFT_GRAPH_APP_ID), value)
}

/// [`least_privilege_alternative`] for a permission whose resource is known.
///
/// The resource decides whether the Exchange advice is even true: RBAC for
/// Applications confines Microsoft Graph's mail family (and the EWS scope), not
/// Office 365 Exchange Online's identically-named retired Outlook REST
/// appRoles. Offering "scope this to specific mailboxes" for one of those sends
/// an operator after a remediation that cannot be applied, and quietly implies
/// the grant is containable when the only remedy is removing it.
///
/// A `None` resource yields no Exchange advice for the same reason.
pub fn least_privilege_alternative_for(
    resource_app_id: Option<&str>,
    value: &str,
) -> Option<&'static str> {
    if crate::scoping::is_sharepoint_orgwide(value) {
        // Every broad `Sites.*` has the scoped `Sites.Selected` model (Rule 12).
        Some("Sites.Selected")
    } else if crate::scoping::is_scopable_exchange_resource_permission(resource_app_id, value) {
        // Mail/calendar/contacts can be confined to mailboxes via Exchange RBAC.
        Some("Scope to specific mailboxes (Exchange RBAC)")
    } else {
        None
    }
}

/// The broader Microsoft Graph **application** permissions that fully cover
/// `value` — i.e. every Graph call `value` authorizes is also authorized by
/// each listed permission, per the "least to most privileged" orderings in the
/// Graph permissions reference. Empty when `value` has no broader equivalent.
///
/// Application permissions only: Graph authorizes app-only calls by the union
/// of `roles` in the token (a client-credentials token always carries every
/// granted role), so holding the broader role makes the narrower one pure
/// surface area — removing it can never break a call. The same is NOT true of
/// delegated scopes (token requests name scopes literally; removing a narrower
/// consented scope can break an app that requests it by name), so delegated
/// redundancy is deliberately out of scope here.
///
/// Pairs are conservative — only documented full-coverage relationships:
/// - `Mail.Send` is NOT covered by `Mail.ReadWrite` (sending is separate).
/// - `Directory.ReadWrite.All` does NOT cover `User.ReadWrite.All` /
///   `Group.ReadWrite.All` (it can't delete users or reset passwords).
/// - `Sites.Selected` is never listed as a narrower value: it is the
///   least-privilege SharePoint model (Rule 12) — calling it redundant would
///   push an admin to drop the scoped grant and keep the broad one, backwards.
///
/// Chains are flattened to their transitive closure (e.g. `Sites.Read.All`
/// lists all three broader `Sites.*` tiers) so detection needs no traversal.
///
/// One table serves both directions: [`subsuming_app_permissions`] (narrower →
/// broaders, drives Rule 18 redundancy) and [`downgrade_alternatives`]
/// (broader → narrowers, drives the least-privilege downgrade suggestions) are
/// forward and inverse scans of it, so the two features can never disagree
/// about what covers what.
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

/// Forward scan of [`SUBSUMED_APP_PERMISSIONS`] — see the table doc above.
pub fn subsuming_app_permissions(value: &str) -> &'static [&'static str] {
    SUBSUMED_APP_PERMISSIONS
        .iter()
        .find(|(narrower, _)| *narrower == value)
        .map(|(_, broaders)| *broaders)
        .unwrap_or(&[])
}

/// The narrower application permissions an admin could hold *instead of*
/// `value` — the inverse scan of [`SUBSUMED_APP_PERMISSIONS`], in table order.
/// Empty when `value` is already least-privilege or has no narrower equivalent.
///
/// Unlike Rule-18 redundancy removal, acting on a downgrade is **not** safe by
/// construction: the narrower permission only suffices if the app genuinely
/// never uses the broader capability (e.g. never writes). Every surface that
/// offers a downgrade must present it as an admin-judged choice, never an
/// automatic fix.
/// Ordered closest-tier-first: an alternative with fewer subsumers sits higher
/// in the privilege ladder (e.g. for `Sites.FullControl.All`: `Sites.Manage.All`
/// before `Sites.ReadWrite.All` before `Sites.Read.All`), so the first entry is
/// the least disruptive downgrade and the natural default to surface.
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
/// permissions already fully grant (per [`subsuming_app_permissions`]).
///
/// **Pairs only within one resource.** Mailbox and SharePoint permissions live
/// on two resources each, and both Microsoft Graph and the legacy Office 365
/// resources expose appRoles literally named `Sites.*` / `Mail.*`. Keyed on the
/// bare value, this reported a Graph `Sites.Read.All` as "covered by"
/// `Sites.ReadWrite.All` held on Office 365 SharePoint Online — two grants that
/// authorize against different resources and cover nothing of each other. The
/// one-click fix never acted on such a pair (`plan_redundant_removals` builds
/// its `value_to_id` per resource and requires the broader grant live on the
/// *same* `resource_app_id`), so this was advisory text disagreeing with the
/// remediation beside it — an operator reading "covered by" and revoking by hand
/// would have removed real access.
///
/// A grant whose `resource_app_id` is `None` pairs with nothing: an unresolved
/// resource cannot be *proven* to be the same one, and under-reporting a
/// redundancy is a missing suggestion, while over-reporting one is advice to
/// remove access that is not in fact covered.
///
/// `broader_is_confined` lets the caller veto a broader permission whose
/// effective reach is *narrower than the permission name implies* — e.g. a
/// `Mail.ReadWrite` confined to specific mailboxes via Exchange RBAC does NOT
/// cover an org-wide `Mail.Read`, so the pair must not be flagged. Callers
/// without scoping data pass `|_| false`.
///
/// A value redundant on more than one resource is reported once — but the
/// *first redundant* occurrence, not merely the first occurrence. The
/// distinction is the whole of the ordering bug this signature replaced: the
/// old code inserted into its `seen` set BEFORE computing coverage, so a value
/// held on two resources was decided by whichever grant the iteration reached
/// first. A `Mail.Read` on Microsoft Graph (no covering grant there) suppressed
/// the genuinely redundant `Mail.Read` on Office 365 Exchange Online sitting
/// beside a `Mail.ReadWrite`, and the finding vanished — order-dependently, so
/// two tenants with identical grants could score differently.
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
/// already fully grant.
///
/// Carries the resource because the pairing decision is resource-keyed and the
/// consumers need it: the advisory text has to name which resource the pair
/// lives on (`Mail.Read` is a different permission on Graph and on Office 365
/// Exchange Online), and the one-click removal has to target the right one.
/// Dropping it here was how the finding text and the Fix beside it came to
/// describe different grants.
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
        // Sites.Selected is the least-privilege model — not on any risk list.
        assert_eq!(risk_level_for_app_permission("Sites.Selected"), None);
        assert_eq!(risk_level_for_app_permission("User.Read"), None);
    }

    #[test]
    fn least_privilege_alternative_points_to_the_scoped_model() {
        // Broad Sites.* -> Sites.Selected (Rule 12 scoped model).
        assert_eq!(
            least_privilege_alternative("Sites.ReadWrite.All"),
            Some("Sites.Selected")
        );
        assert_eq!(
            least_privilege_alternative("Sites.FullControl.All"),
            Some("Sites.Selected")
        );
        // Exchange-scopable mail -> RBAC pointer; a lookalike with no Exchange
        // role does not (parallels scoping::loose_mail_lookalikes_are_not_scopable).
        assert_eq!(
            least_privilege_alternative("Mail.Send"),
            Some("Scope to specific mailboxes (Exchange RBAC)")
        );
        assert_eq!(least_privilege_alternative("Mail.ReadWrite.Shared"), None);
        // Already least-privilege / no narrower equivalent.
        assert_eq!(least_privilege_alternative("Sites.Selected"), None);
        assert_eq!(least_privilege_alternative("Directory.ReadWrite.All"), None);
    }

    /// Every mailbox-family name in the risk tables must be one `scoping.rs`
    /// recognises — the guard that would have caught `Calendar.ReadWrite`.
    ///
    /// That entry sat in the medium table for its whole life naming a
    /// permission Microsoft Graph does not define (all calendar permissions are
    /// plural), so it could never match a real grant and an org-wide
    /// `Calendars.ReadWrite` scored zero. Nothing could notice, because a risk
    /// table is just a list of strings and a string that matches nothing looks
    /// exactly like a string that has not come up yet.
    ///
    /// `scoping.rs` independently maps every scopable mail/calendar/contacts
    /// permission to its Exchange role, so it is a second spelling of the same
    /// names — and a name in one list that the other rejects is a typo by
    /// construction. Deliberately limited to that family: the tables also carry
    /// Directory/Application/Sites names that `scoping.rs` has no opinion on.
    #[test]
    fn mailbox_family_risk_entries_agree_with_the_scoping_role_map() {
        let mailbox_family = |v: &str| {
            v.starts_with("Mail.") || v.starts_with("Calendar") || v.starts_with("Contacts.")
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

    /// The reverse of the rule above, and the one that was missing.
    ///
    /// `mailbox_family_risk_entries_agree_with_the_scoping_role_map` scans
    /// table -> role map, so it catches a *typo* in an entry that exists. It
    /// cannot catch an entry that was never written, which is how nine values
    /// came to score zero while this same file named every one of them as the
    /// broader side of a subsumption pair and advised downgrading away from it.
    ///
    /// So: if the file asserts B ⊇ N, then holding B is at least as much reach
    /// as holding N, and B must carry a risk weight. Derived from
    /// `SUBSUMED_APP_PERMISSIONS` itself rather than from a hand-kept list, so
    /// it cannot drift — adding a subsumption pair now forces the weight
    /// decision at the same time.
    ///
    /// A deliberately unscored broader value goes in `INTENTIONALLY_UNSCORED`
    /// with a reason, which keeps the decision visible instead of silent.
    #[test]
    fn every_broader_subsuming_permission_carries_a_risk_weight() {
        /// Empty on purpose. An entry here is a claim that holding this
        /// permission tenant-wide is not itself a risk signal — write the
        /// reason next to it.
        const INTENTIONALLY_UNSCORED: &[(&str, &str)] = &[(
            "Sites.Manage.All",
            "Rule 12 already raises the org-wide SharePoint advisory for any broad `Sites.*`, \
             and `scoring::tests::broad_sharepoint_manage_flags_issue_without_score` pins that \
             the advisory fires INDEPENDENTLY of risk-list weighting — using this value as its \
             example. Giving it points would make that test's example unrepresentative and \
             double-count reach the advisory already reports. Left to the owner as a risk-model \
             call; the permission is surfaced either way.",
        )];

        let scored = |v: &str| {
            HIGH_RISK_APP_PERMISSIONS.contains(&v) || MEDIUM_RISK_APP_PERMISSIONS.contains(&v)
        };
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
            "only {checked} broader-side values walked — the subsumption table or this walk is              broken, and the rule would pass vacuously"
        );
        assert!(
            unscored.is_empty(),
            "these permissions are named as the BROADER side of a subsumption pair — this file              tells operators to downgrade away from them — yet they carry no risk weight and so              score zero: {unscored:?}\nAdd them to HIGH_RISK_APP_PERMISSIONS or              MEDIUM_RISK_APP_PERMISSIONS (tenant-wide write is high, tenant-wide read is medium),              or list them in INTENTIONALLY_UNSCORED with a reason."
        );
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
        ] {
            assert!(is_risky_delegated_scope(s), "{s} should be risky");
        }
        for s in ["User.Read", "openid", "profile", "email", "Sites.Selected"] {
            assert!(!is_risky_delegated_scope(s), "{s} should not be risky");
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

        // A permission is NOT covered by a same-named broader one held on a
        // DIFFERENT resource. Both Microsoft Graph and the legacy Office 365
        // resources expose appRoles called `Sites.*`, and a grant on one
        // authorizes nothing on the other — but keyed on the bare value this
        // paired them and told the operator to remove live access. The one-click
        // fix always re-planned per resource and did nothing here, so the
        // advisory text and the remediation beside it disagreed.
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

        // THE ORDERING CASE: one value held on two resources, redundant on
        // only one of them. `Mail.Read` sits on Microsoft Graph (nothing
        // covers it there) and on Office 365 Exchange Online beside that
        // resource's own `Mail.ReadWrite` (which does cover it).
        //
        // The old code inserted into its dedup set BEFORE computing coverage,
        // so whichever grant the iteration reached first decided the answer for
        // the value. With Graph first — the order Graph returns manifests in —
        // the genuine Office 365 redundancy was silently suppressed. Two
        // tenants with identical grants could score differently depending on
        // manifest order, which is why this is a correctness case and not a
        // presentation one.
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

    /// Redundant on BOTH mailbox resources ⇒ TWO findings, not one.
    ///
    /// The loop keys `examined` on `(resource, value)` and so reaches each pair
    /// once — but a second set keyed on the bare VALUE then collapsed the two
    /// back together and emitted a single finding. The one-click Fix removed
    /// the grant that finding named, reported success, and left the other
    /// standing; the next audit found the survivor again. `Mail.Read` on
    /// Microsoft Graph and on Office 365 Exchange Online are two separate
    /// grants of two separate kinds of access, and only Graph's is confinable —
    /// removing one says nothing about the other.
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
