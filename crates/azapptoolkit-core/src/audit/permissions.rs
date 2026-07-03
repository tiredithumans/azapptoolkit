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
];

/// Medium-risk application permissions (by `value` string). Mirrors
/// `Constants.ps1:123-130`.
pub const MEDIUM_RISK_APP_PERMISSIONS: &[&str] = &[
    "User.Read.All",
    "Group.Read.All",
    "Mail.Read",
    "Files.Read.All",
    "Sites.Read.All",
    "Calendar.ReadWrite",
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

/// Splits a set of application-permission `value`s into `(high_risk, medium_risk)`
/// hits using [`HIGH_RISK_APP_PERMISSIONS`] / [`MEDIUM_RISK_APP_PERMISSIONS`].
/// Reusable for auditing the application permissions *held* by managed
/// identities and enterprise-app service principals (not just app registrations).
pub fn classify_app_permission_risk(values: &[String]) -> (Vec<String>, Vec<String>) {
    let high = values
        .iter()
        .filter(|v| HIGH_RISK_APP_PERMISSIONS.contains(&v.as_str()))
        .cloned()
        .collect();
    let medium = values
        .iter()
        .filter(|v| MEDIUM_RISK_APP_PERMISSIONS.contains(&v.as_str()))
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
    if crate::scoping::is_sharepoint_orgwide(value) {
        // Every broad `Sites.*` has the scoped `Sites.Selected` model (Rule 12).
        Some("Sites.Selected")
    } else if crate::scoping::is_scopable_exchange_permission(value) {
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

/// The redundant application permissions among `values`: each `(narrower,
/// covered_by)` pair is a held permission whose access the held `covered_by`
/// permissions already fully grant (per [`subsuming_app_permissions`]).
///
/// `broader_is_confined` lets the caller veto a broader permission whose
/// effective reach is *narrower than the permission name implies* — e.g. a
/// `Mail.ReadWrite` confined to specific mailboxes via Exchange RBAC does NOT
/// cover an org-wide `Mail.Read`, so the pair must not be flagged. Callers
/// without scoping data pass `|_| false`.
///
/// Duplicate values (the same permission declared on more than one resource)
/// are reported once.
pub fn redundant_app_permissions(
    values: &[String],
    broader_is_confined: impl Fn(&str) -> bool,
) -> Vec<(String, Vec<String>)> {
    let held: std::collections::HashSet<&str> = values.iter().map(|s| s.as_str()).collect();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for v in values {
        if !seen.insert(v.as_str()) {
            continue;
        }
        let covered_by: Vec<String> = subsuming_app_permissions(v)
            .iter()
            .filter(|b| held.contains(**b) && !broader_is_confined(b))
            .map(|b| (*b).to_string())
            .collect();
        if !covered_by.is_empty() {
            out.push((v.clone(), covered_by));
        }
    }
    out
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

    #[test]
    fn classify_app_permission_risk_splits_high_and_medium() {
        let values: Vec<String> = [
            "Directory.ReadWrite.All", // high
            "Mail.Send",               // high
            "User.Read.All",           // medium
            "openid",                  // neither
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let (high, medium) = classify_app_permission_risk(&values);
        assert_eq!(high.len(), 2);
        assert!(high.contains(&"Directory.ReadWrite.All".to_string()));
        assert_eq!(medium, vec!["User.Read.All".to_string()]);
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
        let values = |vs: &[&str]| vs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
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
            assert_eq!(got, want, "held = {held:?}");
        }

        // The same value declared twice (e.g. on two resources) reports once.
        let got = redundant_app_permissions(
            &values(&["Mail.ReadWrite", "Mail.Read", "Mail.Read"]),
            unconfined,
        );
        assert_eq!(got.len(), 1);

        // A confined broader permission is vetoed as a coverer.
        let got = redundant_app_permissions(&values(&["Mail.ReadWrite", "Mail.Read"]), |b| {
            b == "Mail.ReadWrite"
        });
        assert!(got.is_empty(), "scoped broader must not cover: {got:?}");
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
