//! Pure mailbox-scope **decisions** over already-fetched Exchange data.
//!
//! These seven functions decide what an operator is told about an application's
//! effective mailbox reach: whether an authorization row is org-wide, whether a
//! composite role confers a permission, how rows fold into a verdict, whether a
//! legacy Application Access Policy confines the app, and how a surviving
//! org-wide Entra grant defeats a scoped RBAC verdict.
//!
//! They moved out of the Tauri command layer (`commands::exchange`) so they are
//! unit-testable without a Tauri `State`. Reachable only through a
//! `#[tauri::command]`, the logic was correct-looking prose with no unit test
//! able to contradict it.
//!
//! Nothing here does I/O. The callers fetch (`Test-ServicePrincipalAuthorization`
//! rows, `Get-ApplicationAccessPolicy` results, the principal's Entra grants) and
//! then ask this module what the answer is.

use std::collections::{HashMap, HashSet};

use azapptoolkit_core::audit::{MailPermissionScope, ResourcePermission, ScopeMechanism};
use azapptoolkit_core::scoping::is_aap_confinable_permission;

use crate::error::ExchangeError;
use crate::models::{ExoApplicationAccessPolicy, ExoAuthorizationResult};
use crate::roles::{composite_role_confers, is_blanket_mailbox_grant};

/// The `Test-ServicePrincipalAuthorization` `ScopeType` values that name a real
/// confinement, lower-cased: a custom management scope (`CustomRecipientScope`,
/// also seen as `RecipientScope`) or an administrative unit (the
/// `-RecipientAdministrativeUnitScope` assignment, in each spelling the
/// codebase's AU readers know). An allowlist on purpose — see
/// [`is_org_wide_auth_row`].
const CONFINED_SCOPE_TYPES: &[&str] = &[
    "customrecipientscope",
    "recipientscope",
    "administrativeunit",
    "administrativeunitscope",
    "recipientadministrativeunitscope",
];

/// `ScopeType` values the cmdlet uses for an organization-level (unconfined)
/// row, lower-cased. Recognised so they read org-wide without the
/// unrecognised-type warning.
const ORG_WIDE_SCOPE_TYPES: &[&str] = &[
    "",
    "notapplicable",
    "not applicable",
    "organizationconfig",
    "organizationscope",
    "organization",
];

/// True when a `Test-ServicePrincipalAuthorization` row is *not* confined to a
/// recipient scope — i.e. the grant reaches every mailbox in the tenant. An
/// empty / "Not Applicable" `AllowedResourceScope` is org-wide, and so is any
/// row whose `ScopeType` is not one of the known confining types (the private
/// `CONFINED_SCOPE_TYPES`: a custom management scope or an administrative
/// unit).
///
/// The `ScopeType` test is an **allowlist** of confinements, not a denylist of
/// org-wide spellings. The denylist read any type it didn't recognise as
/// confined, so a new or differently spelled org-level type beside a non-empty
/// `AllowedResourceScope` reported a tenant-wide grant as scoped — and scored
/// it at the reduced weight. Unsure now means org-wide (the conservative,
/// never-under-report choice), and an unrecognised type is logged so the gap
/// can be closed. Only the type is logged: the scope name is tenant data.
pub fn is_org_wide_auth_row(r: &ExoAuthorizationResult) -> bool {
    let allowed = r.allowed_resource_scope.as_deref().unwrap_or("").trim();
    if allowed.is_empty() || allowed.eq_ignore_ascii_case("Not Applicable") {
        return true;
    }
    let scope_type = r.scope_type.as_deref().unwrap_or("").trim();
    if CONFINED_SCOPE_TYPES
        .iter()
        .any(|t| scope_type.eq_ignore_ascii_case(t))
    {
        return false;
    }
    if !ORG_WIDE_SCOPE_TYPES
        .iter()
        .any(|t| scope_type.eq_ignore_ascii_case(t))
    {
        warn_unrecognised_scope_type(scope_type);
    }
    true
}

/// Logs an unrecognised `ScopeType` once per distinct (lower-cased) value per
/// process. The verdict reads rows per permission per app — and the mailbox
/// reverse lookup per candidate — so an unconditional warning repeated the
/// same line hundreds of times in one run.
fn warn_unrecognised_scope_type(scope_type: &str) {
    static SEEN: parking_lot::Mutex<Option<HashSet<String>>> = parking_lot::Mutex::new(None);
    let first = SEEN
        .lock()
        .get_or_insert_with(HashSet::new)
        .insert(scope_type.to_ascii_lowercase());
    if first {
        tracing::warn!(
            scope_type,
            "unrecognised Test-ServicePrincipalAuthorization ScopeType; reading the row as org-wide"
        );
    }
}

/// True when a `Test-ServicePrincipalAuthorization` row confers `value` — either
/// because it *is* that permission's dedicated role, or because it's one of the
/// **composite** roles that bundle several permissions (`Application Mail Full
/// Access` → `Mail.ReadWrite` + `Mail.Send`; `Application Exchange Full Access`
/// → five permissions).
///
/// Matching `RoleName` alone missed every composite role, so a correctly scoped
/// app produced no matching row and read `OrgWide`. The cmdlet reports the
/// bundle in `GrantedPermissions`; the role-name check is the fast path, and the
/// composite table ([`composite_role_confers`]) answers only for a composite row
/// whose list is **absent or blank**. Without that fallback an **org-wide**
/// composite row beside a scoped dedicated one was dropped and the permission
/// read `Scoped` while it reached every mailbox. An explicit list is
/// authoritative: consulting the table over it would let a *scoped* composite
/// row whose list excludes the value join the fold and turn a genuine
/// no-row `OrgWide` into `Scoped`.
///
/// Every comparison is case-insensitive: Exchange role names are, and the
/// cmdlet echoes whatever case it stored. The list is split on commas,
/// semicolons and whitespace, none of which a permission value contains.
pub fn row_grants_permission(row: &ExoAuthorizationResult, role: &str, value: &str) -> bool {
    let row_role = row.role_name.as_deref().map(str::trim);
    if row_role.is_some_and(|r| r.eq_ignore_ascii_case(role.trim())) {
        return true;
    }
    match row
        .granted_permissions
        .as_deref()
        .map(str::trim)
        .filter(|g| !g.is_empty())
    {
        Some(granted) => granted
            .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
            .any(|g| !g.is_empty() && g.eq_ignore_ascii_case(value.trim())),
        None => row_role.is_some_and(|r| composite_role_confers(r, value)),
    }
}

/// Folds the authorization rows for one Exchange role into a single verdict:
/// no row → `OrgWide` (queried OK, no scoped restriction); any org-wide row →
/// `OrgWide` (it unions to tenant-wide reach); otherwise `Scoped` to the named
/// management scope.
pub fn verdict_from_rows(rows: &[&ExoAuthorizationResult]) -> MailPermissionScope {
    if rows.is_empty() || rows.iter().any(|r| is_org_wide_auth_row(r)) {
        return MailPermissionScope::OrgWide;
    }
    // Every DISTINCT scope named across the rows, not the first one found.
    //
    // A principal can hold the same Exchange role through more than one scoped
    // assignment, and its effective reach is then the UNION of those scopes.
    // Reporting whichever row Exchange happened to return first named one scope
    // as *the* scope — so the operator saw a narrower confinement than the
    // principal actually had, and the scope shown was decided by response order.
    // Naming them all keeps the verdict a statement about reach rather than
    // about ordering.
    let mut names = distinct_scope_names(rows);
    let scope_name = match names.len() {
        0 => None,
        1 => names.pop(),
        _ => Some(names.join(", ")),
    };
    MailPermissionScope::Scoped {
        scope_name,
        recipient_filter: None,
        group_count: None,
        mechanism: ScopeMechanism::Rbac,
    }
}

/// The distinct, non-blank management-scope names `rows` confine to, sorted.
///
/// [`verdict_from_rows`] joins several into one display string (`"A, B"`), so
/// a caller that wants to look the scope up must take the name from here, and
/// only when there is exactly one: looking up the joined string as a single
/// `Get-ManagementScope` identity found nothing and silently dropped the
/// filter and group count.
pub fn distinct_scope_names(rows: &[&ExoAuthorizationResult]) -> Vec<String> {
    let mut names: Vec<String> = rows
        .iter()
        .filter_map(|r| r.allowed_resource_scope.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Pure decision behind `commands::exchange::mail_scopes::legacy_aap_scope`
/// (desktop crate): does any legacy Application Access
/// Policy *confine* `app_id`'s mailbox access? Only a `RestrictAccess` policy
/// scopes access to its group; a `DenyAccess` policy is a blocklist (access to
/// everything *except* the group), which is still effectively org-wide, so it is
/// not reported as scoped.
pub fn aap_verdict_for(
    policies: &[ExoApplicationAccessPolicy],
    app_id: &str,
) -> Option<MailPermissionScope> {
    // `filter`, not `find`: several RestrictAccess policies on one app grant the
    // UNION of their groups, which is why `AapMigrationItem` carries
    // `source_policy_identities` as a vector. Naming only the first understated
    // the confinement on three operator-facing surfaces, including the
    // permission tester's "which mailboxes can this reach" answer. The same bug
    // was already fixed in `verdict_from_rows`; this sibling was missed.
    //
    // The app id is casefolded because Exchange echoes back whatever case it
    // stored, and a GUID differing only in case is the same application —
    // `aap.rs` states that precondition explicitly and every other comparison in
    // that module already honours it. Left case-sensitive here, a tenant whose
    // `New-ApplicationAccessPolicy` ran with an upper-case GUID reported a
    // confined app as org-wide and scored it at full risk.
    let matching: Vec<&ExoApplicationAccessPolicy> = policies
        .iter()
        .filter(|p| {
            p.app_id
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(app_id))
                && p.is_restrict_access()
        })
        .collect();
    if matching.is_empty() {
        return None;
    }

    let mut names: Vec<String> = matching
        .iter()
        .filter_map(|p| p.scope_name.clone().or_else(|| p.scope_identity.clone()))
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty())
        .collect();
    names.sort();
    names.dedup();

    Some(MailPermissionScope::Scoped {
        scope_name: match names.len() {
            0 => None,
            1 => names.pop(),
            _ => Some(names.join(", ")),
        },
        // A description belongs to ONE policy, but the confinement spans all of
        // them — showing the first policy's filter beside a multi-scope name
        // would misdescribe the reach. Dropped unless exactly one policy matched.
        recipient_filter: match matching.as_slice() {
            [only] => only.description.clone(),
            _ => None,
        },
        group_count: None,
        mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
    })
}

/// Folds a legacy Application Access Policy verdict over the lean (audit-path)
/// RBAC verdicts for one principal — the bulk-run equivalent of the per-app
/// `aap_override` that `commands::exchange::mail_scopes::resolve_mail_scopes`
/// applies on the enriched detail path.
///
/// Applied by the caller, **after** the cached probe, so
/// `resolve_mail_scopes_audit_cached` keeps caching the pure RBAC verdict and
/// the two surfaces' cache warmth stays independent (see its doc comment).
///
/// Two shapes get the override, matching the detail path's two rules:
/// - a permission RBAC reports `OrgWide` — a `RestrictAccess` policy genuinely
///   confines the org-wide Entra grant, which is why `reconcile_orgwide_grant`
///   exempts it;
/// - a permission with **no** verdict at all — the probe failed or never ran
///   (Exchange unavailable, breaker open, managed identity absent from the
///   Exchange SP store). A policy keyed on this exact appId is stronger
///   evidence than a failed probe, the same call `scope_from_rbac_error` makes.
///
/// A `Scoped` RBAC verdict is never overwritten: that app already migrated.
///
/// Only a grant a policy could **govern** takes the override
/// ([`is_aap_confinable_permission`]: the eleven Microsoft Graph values plus the
/// EWS scope), not everything RBAC can scope. An Application Access Policy never
/// confined `MailboxItem.*`, `Mail-Advanced.*` and the other RBAC-only values,
/// so gating on the scopable set handed an org-wide `MailboxItem.ReadWrite.All`
/// on a policy-confined app a "Scoped (legacy)" verdict and scored it at the
/// reduced weight. The AAP migration already uses this gate
/// (`targets::targets_from_grants`).
///
/// Takes the grants with their resources attached, not bare values: Office 365
/// Exchange Online exposes its own `Mail.*` appRoles (retired Outlook REST) that
/// an Application Access Policy cannot confine either, and a value-keyed test
/// answers `true` for them because it can only see the name. That handed the
/// legacy namesake a scoped verdict and dropped a genuinely org-wide grant out
/// of the mailbox findings at the reduced weight.
pub fn apply_legacy_policy_verdict(
    scopes: &mut HashMap<String, MailPermissionScope>,
    grants: &[ResourcePermission],
    verdict: Option<&MailPermissionScope>,
) {
    let Some(verdict) = verdict else { return };
    for grant in grants {
        let confinable = grant
            .resource_app_id
            .as_deref()
            .is_some_and(|resource| is_aap_confinable_permission(resource, &grant.value));
        if !confinable {
            continue;
        }
        match scopes.get(&grant.value) {
            Some(MailPermissionScope::Scoped { .. }) => {}
            _ => {
                scopes.insert(grant.value.clone(), verdict.clone());
            }
        }
    }
}

/// Per-app mailbox-scope fallback when `Test-ServicePrincipalAuthorization`
/// itself fails (detail/enrich path only). An AAP confines the *whole* app (see
/// `commands::exchange::mail_scopes::legacy_aap_scope` (desktop crate)), but
/// only the permissions a policy governs: the caller passes `aap` only when at
/// least one probed permission is [`is_aap_confinable_permission`], and applies
/// the result to those alone.
/// A `RestrictAccess` AAP keyed on this exact appId is stronger evidence than a
/// failed probe, so it wins even over a 403. A principal Exchange can't resolve
/// (the managed-identity case — it isn't in Exchange's SP store) has no RBAC
/// scope, so absent an AAP its org-wide Graph grant reaches every mailbox =>
/// `OrgWide`. Any other failure (403/401/network) is genuinely indeterminate and
/// is surfaced to the caller so the UI can explain *why*.
pub fn scope_from_rbac_error(
    err: ExchangeError,
    aap: Option<MailPermissionScope>,
) -> Result<MailPermissionScope, ExchangeError> {
    if let Some(scoped) = aap {
        return Ok(scoped);
    }
    if err.is_missing_object() {
        return Ok(MailPermissionScope::OrgWide);
    }
    Err(err)
}

/// Reconciles one permission's scope verdict against the org-wide Entra grants
/// the principal still holds. A scoped **RBAC** verdict for a permission whose
/// org-wide grant was never removed unions to tenant-wide reach, so it becomes
/// `OrgWide` (what `Test-ServicePrincipalAuthorization` alone misses — it can't
/// see Entra grants). A legacy Application Access Policy is exempt: it genuinely
/// confines an org-wide grant. Org-wide / unknown verdicts pass through.
///
/// A **blanket** grant (the EWS `full_access_as_app` scope) vetoes the scope of
/// *every* permission, not just its own name: it reaches every mailbox with full
/// access, so a `Mail.Read` confined to one group is still effectively org-wide
/// while it survives.
pub fn reconcile_orgwide_grant(
    verdict: MailPermissionScope,
    perm: &str,
    orgwide_granted: &HashSet<String>,
) -> MailPermissionScope {
    let scoped_via_rbac = matches!(
        verdict,
        MailPermissionScope::Scoped {
            mechanism: ScopeMechanism::Rbac,
            ..
        }
    );
    let defeated = orgwide_granted.contains(perm)
        || orgwide_granted.iter().any(|g| is_blanket_mailbox_grant(g));
    if scoped_via_rbac && defeated {
        MailPermissionScope::OrgWide
    } else {
        verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two scoped assignments mean the reach is the UNION, and the verdict must
    /// name both rather than whichever row Exchange returned first (the
    /// ordering rule `verdict_from_rows`'s doc comment explains).
    #[test]
    fn several_distinct_scopes_are_all_named() {
        let a = row(
            Some("Application Mail.Read"),
            None,
            Some("scope_a"),
            Some("CustomRecipientScope"),
        );
        let b = row(
            Some("Application Mail.Read"),
            None,
            Some("scope_b"),
            Some("CustomRecipientScope"),
        );
        match verdict_from_rows(&[&a, &b]) {
            MailPermissionScope::Scoped { scope_name, .. } => {
                let named = scope_name.expect("a scoped verdict names its scope");
                assert!(
                    named.contains("scope_a") && named.contains("scope_b"),
                    "{named}"
                );
            }
            other => panic!("expected Scoped, got {other:?}"),
        }
        // Order must not change the answer.
        let forward = verdict_from_rows(&[&a, &b]);
        let reverse = verdict_from_rows(&[&b, &a]);
        assert_eq!(forward, reverse, "the verdict must not depend on row order");

        // One scope repeated is still one scope, not a list.
        let dup = row(
            Some("Application Mail.Read"),
            None,
            Some("scope_a"),
            Some("CustomRecipientScope"),
        );
        match verdict_from_rows(&[&a, &dup]) {
            MailPermissionScope::Scoped { scope_name, .. } => {
                assert_eq!(scope_name.as_deref(), Some("scope_a"));
            }
            other => panic!("expected Scoped, got {other:?}"),
        }
    }

    fn row(
        role: Option<&str>,
        granted: Option<&str>,
        scope: Option<&str>,
        scope_type: Option<&str>,
    ) -> ExoAuthorizationResult {
        ExoAuthorizationResult {
            role_name: role.map(str::to_string),
            granted_permissions: granted.map(str::to_string),
            allowed_resource_scope: scope.map(str::to_string),
            scope_type: scope_type.map(str::to_string),
            in_scope: None,
        }
    }

    fn policy(app_id: &str, right: &str, scope: &str) -> ExoApplicationAccessPolicy {
        ExoApplicationAccessPolicy {
            identity: Some(format!("{app_id}\\policy")),
            app_id: Some(app_id.to_string()),
            scope_name: Some(scope.to_string()),
            scope_identity: None,
            access_right: Some(right.into()),
            description: Some("desc".to_string()),
        }
    }

    fn scoped_rbac() -> MailPermissionScope {
        MailPermissionScope::Scoped {
            scope_name: Some("app_scope_x".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::Rbac,
        }
    }

    /// Every shape the cmdlet uses to say "this row is not confined". Table-driven
    /// because the set is a wire contract, not a rule: `AllowedResourceScope` is
    /// blank or the literal "Not Applicable", or `ScopeType` names an
    /// organization-level scope. Reading any of these as *scoped* would report a
    /// confinement that does not exist.
    #[test]
    fn org_wide_rows_are_recognised_in_every_spelling() {
        for (scope, scope_type) in [
            (None, None),
            (Some(""), None),
            (Some("   "), None),
            (Some("Not Applicable"), None),
            (Some("not applicable"), None),
            (Some("SomeScope"), Some("OrganizationConfig")),
            (Some("SomeScope"), Some("organizationscope")),
            (Some("SomeScope"), Some("Organization")),
            (Some("SomeScope"), Some("")),
            (Some("SomeScope"), None),
            // Unrecognised types fail closed: unsure means org-wide.
            (Some("SomeScope"), Some("Weird")),
            (Some("SomeScope"), Some("OrganizationWideScope")),
        ] {
            assert!(
                is_org_wide_auth_row(&row(None, None, scope, scope_type)),
                "scope={scope:?} scope_type={scope_type:?} must read org-wide"
            );
        }
        // A named scope with a known confining ScopeType is genuinely confined,
        // in any case.
        for scope_type in [
            "RecipientScope",
            "CustomRecipientScope",
            "customrecipientscope",
            "AdministrativeUnit",
            " administrativeunit ",
            "RecipientAdministrativeUnitScope",
        ] {
            assert!(
                !is_org_wide_auth_row(&row(None, None, Some("app_scope_x"), Some(scope_type))),
                "scope_type={scope_type:?} must read confined"
            );
        }
    }

    /// A composite row Exchange returned without `GrantedPermissions` (or with
    /// it formatted differently) still confers its bundle. Dropping it let an
    /// org-wide composite row beside a scoped dedicated one disappear from the
    /// fold, so the permission read `Scoped` while it reached every mailbox.
    #[test]
    fn a_composite_row_without_its_list_confers_its_bundle() {
        let bare = row(Some("Application Mail Full Access"), None, None, None);
        assert!(row_grants_permission(
            &bare,
            "Application Mail.Send",
            "Mail.Send"
        ));
        assert!(!row_grants_permission(
            &bare,
            "Application Mail.Read",
            "Mail.Read"
        ));
        let full = row(Some("application exchange full access"), None, None, None);
        assert!(row_grants_permission(
            &full,
            "Application Calendars.ReadWrite",
            "Calendars.ReadWrite"
        ));
        // Blank counts as absent.
        let blank = row(Some("Application Mail Full Access"), Some("  "), None, None);
        assert!(row_grants_permission(
            &blank,
            "Application Mail.ReadWrite",
            "Mail.ReadWrite"
        ));
        // An explicit list is authoritative: a scoped composite row whose list
        // excludes the value must not join the fold, or the no-row `OrgWide`
        // turns into `Scoped`.
        let narrowed = row(
            Some("Application Exchange Full Access"),
            Some("Mail.ReadWrite"),
            Some("app_scope_x"),
            Some("CustomRecipientScope"),
        );
        assert!(!row_grants_permission(
            &narrowed,
            "Application Mail.Send",
            "Mail.Send"
        ));
        let matching: Vec<&ExoAuthorizationResult> = [&narrowed]
            .into_iter()
            .filter(|r| row_grants_permission(r, "Application Mail.Send", "Mail.Send"))
            .collect();
        assert_eq!(verdict_from_rows(&matching), MailPermissionScope::OrgWide);
        // Space-separated list, different case.
        let spaced = row(
            Some("Some Custom Role"),
            Some("mail.readwrite  MAIL.SEND"),
            Some("app_scope_x"),
            Some("CustomRecipientScope"),
        );
        assert!(row_grants_permission(
            &spaced,
            "Application Mail.Send",
            "Mail.Send"
        ));

        // The fold: an org-wide composite row beside a scoped dedicated row
        // unions to tenant-wide reach.
        let scoped_dedicated = row(
            Some("Application Mail.Send"),
            Some("Mail.Send"),
            Some("app_scope_x"),
            Some("CustomRecipientScope"),
        );
        let rows = [scoped_dedicated, bare];
        let matching: Vec<&ExoAuthorizationResult> = rows
            .iter()
            .filter(|r| row_grants_permission(r, "Application Mail.Send", "Mail.Send"))
            .collect();
        assert_eq!(matching.len(), 2);
        assert_eq!(verdict_from_rows(&matching), MailPermissionScope::OrgWide);
    }

    /// Exchange role names are case-insensitive and the cmdlet echoes the
    /// stored case; an exact compare dropped the row.
    #[test]
    fn a_mixed_case_row_matches() {
        let r = row(
            Some("application MAIL.read"),
            None,
            Some("app_scope_x"),
            Some("CustomRecipientScope"),
        );
        assert!(row_grants_permission(
            &r,
            "Application Mail.Read",
            "Mail.Read"
        ));
        let listed = row(
            None,
            Some("MAIL.READ"),
            Some("app_scope_x"),
            Some("CustomRecipientScope"),
        );
        assert!(row_grants_permission(
            &listed,
            "Application Mail.Read",
            "Mail.Read"
        ));
        // Still exact per token: Mail.ReadBasic is not Mail.Read.
        let basic = row(None, Some("mail.readbasic"), None, None);
        assert!(!row_grants_permission(
            &basic,
            "Application Mail.Read",
            "Mail.Read"
        ));
    }

    /// The composite-role case. Matching `RoleName` alone missed every bundled
    /// role, so a correctly scoped app produced no matching row and read
    /// `OrgWide` — a confined app reported as tenant-wide.
    #[test]
    fn a_composite_role_confers_the_permissions_it_bundles() {
        let composite = row(
            Some("Application Mail Full Access"),
            Some("Mail.ReadWrite, Mail.Send"),
            Some("app_scope_x"),
            Some("RecipientScope"),
        );
        assert!(row_grants_permission(
            &composite,
            "Application Mail.ReadWrite",
            "Mail.ReadWrite"
        ));
        assert!(row_grants_permission(
            &composite,
            "Application Mail.Send",
            "Mail.Send"
        ));
        assert!(
            !row_grants_permission(&composite, "Application Calendars.Read", "Calendars.Read"),
            "the bundle must not confer a permission it does not list"
        );

        // The dedicated-role fast path still works when the bundle list is absent.
        let dedicated = row(Some("Application Mail.Read"), None, Some("s"), Some("R"));
        assert!(row_grants_permission(
            &dedicated,
            "Application Mail.Read",
            "Mail.Read"
        ));

        // A permission substring must not match a longer value.
        let basic = row(
            Some("Application Mail.ReadBasic"),
            Some("Mail.ReadBasic"),
            Some("app_scope_x"),
            Some("RecipientScope"),
        );
        assert!(!row_grants_permission(
            &basic,
            "Application Mail.Read",
            "Mail.Read"
        ));
    }

    #[test]
    fn rows_fold_to_org_wide_unless_every_row_is_confined() {
        // No rows at all: the probe answered, and found no restriction.
        assert!(matches!(
            verdict_from_rows(&[]),
            MailPermissionScope::OrgWide
        ));

        let confined = row(None, None, Some("app_scope_x"), Some("RecipientScope"));
        let wide = row(None, None, None, None);

        // One org-wide row unions to tenant-wide reach, even beside a scoped one.
        assert!(matches!(
            verdict_from_rows(&[&confined, &wide]),
            MailPermissionScope::OrgWide
        ));

        match verdict_from_rows(&[&confined]) {
            MailPermissionScope::Scoped {
                scope_name,
                mechanism,
                ..
            } => {
                assert_eq!(scope_name.as_deref(), Some("app_scope_x"));
                assert_eq!(mechanism, ScopeMechanism::Rbac);
            }
            other => panic!("expected Scoped, got {other:?}"),
        }
    }

    /// `DenyAccess` is a blocklist — access to everything EXCEPT the group — so
    /// rebuilding it as an allow-list scope inverts it. It must never read as a
    /// confinement.
    #[test]
    fn only_a_restrict_access_policy_confines() {
        let policies = vec![
            policy("app-1", "RestrictAccess", "Sales"),
            policy("app-2", "DenyAccess", "Interns"),
        ];
        match aap_verdict_for(&policies, "app-1") {
            Some(MailPermissionScope::Scoped {
                scope_name,
                mechanism,
                ..
            }) => {
                assert_eq!(scope_name.as_deref(), Some("Sales"));
                assert_eq!(mechanism, ScopeMechanism::LegacyApplicationAccessPolicy);
            }
            other => panic!("expected a legacy-policy verdict, got {other:?}"),
        }
        assert!(
            aap_verdict_for(&policies, "app-2").is_none(),
            "a DenyAccess blocklist is still effectively org-wide"
        );
        assert!(aap_verdict_for(&policies, "app-3").is_none());
        // Case-insensitive on AccessRight, matching the migration planner.
        assert!(aap_verdict_for(&[policy("a", "restrictaccess", "S")], "a").is_some());
    }

    /// Exchange echoes the AppId back in whatever case it stored, and a GUID
    /// differing only in case is the same application — `aap.rs` states that
    /// precondition explicitly. This comparison was the one that still didn't
    /// honour it, so in a tenant where `New-ApplicationAccessPolicy` ran with an
    /// upper-case GUID a confined app reported as org-wide and scored at full
    /// risk.
    #[test]
    fn the_app_id_match_is_case_insensitive_like_the_rest_of_the_module() {
        let stored = policy(
            "11111111-AAAA-2222-BBBB-333333333333",
            "RestrictAccess",
            "Sales",
        );
        for queried in [
            "11111111-aaaa-2222-bbbb-333333333333",
            "11111111-AAAA-2222-BBBB-333333333333",
            "11111111-AaAa-2222-BbBb-333333333333",
        ] {
            assert!(
                aap_verdict_for(std::slice::from_ref(&stored), queried).is_some(),
                "{queried} is the same application as the stored GUID"
            );
        }
        // A genuinely different app is still not confined.
        assert!(aap_verdict_for(&[stored], "44444444-4444-4444-4444-444444444444").is_none());
    }

    /// Several RestrictAccess policies on one app grant the UNION of their
    /// groups — which is why `AapMigrationItem` carries a vector of source
    /// policies. Naming only the first understated the confinement on three
    /// operator-facing surfaces, including the permission tester's "which
    /// mailboxes can this reach" answer. `verdict_from_rows` already unions;
    /// this sibling was missed.
    #[test]
    fn several_restrict_access_policies_union_their_scopes() {
        let policies = vec![
            policy("app-1", "RestrictAccess", "Sales"),
            policy("app-1", "RestrictAccess", "Execs"),
            // Neither a match for this app nor a confining right.
            policy("app-1", "DenyAccess", "Interns"),
            policy("app-2", "RestrictAccess", "Support"),
        ];
        match aap_verdict_for(&policies, "app-1") {
            Some(MailPermissionScope::Scoped {
                scope_name,
                recipient_filter,
                ..
            }) => {
                // Sorted and deduped, so the string is stable across Exchange's
                // response ordering.
                assert_eq!(scope_name.as_deref(), Some("Execs, Sales"));
                // A description belongs to ONE policy; showing the first
                // policy's filter beside a two-scope name would misdescribe the
                // reach, so it is dropped when the union spans policies.
                assert_eq!(recipient_filter, None);
            }
            other => panic!("expected a unioned legacy verdict, got {other:?}"),
        }
        // A single match still carries its own description.
        match aap_verdict_for(&policies, "app-2") {
            Some(MailPermissionScope::Scoped {
                scope_name,
                recipient_filter,
                ..
            }) => {
                assert_eq!(scope_name.as_deref(), Some("Support"));
                assert_eq!(recipient_filter.as_deref(), Some("desc"));
            }
            other => panic!("expected a single-scope verdict, got {other:?}"),
        }
    }

    /// The legacy override must reach only the resources an Application Access
    /// Policy can actually confine. Office 365 Exchange Online's own `Mail.*`
    /// appRoles (retired Outlook REST) are not among them, and a value-keyed
    /// test answers `true` for them because it can only see the name — handing
    /// the legacy namesake a scoped verdict and dropping a genuinely org-wide
    /// grant out of the mailbox findings at the reduced weight.
    #[test]
    fn the_legacy_override_is_resource_aware_and_never_downgrades_rbac() {
        let graph = azapptoolkit_core::scoping::MICROSOFT_GRAPH_APP_ID;
        let ews = azapptoolkit_core::scoping::OFFICE365_EXCHANGE_ONLINE_APP_ID;
        let grants = vec![
            ResourcePermission {
                resource_app_id: Some(graph.to_string()),
                value: "Mail.Read".to_string(),
            },
            // Same NAME, unconfinable resource.
            ResourcePermission {
                resource_app_id: Some(ews.to_string()),
                value: "Calendars.Read".to_string(),
            },
            ResourcePermission {
                resource_app_id: Some(graph.to_string()),
                value: "Mail.ReadWrite".to_string(),
            },
        ];
        let legacy = MailPermissionScope::Scoped {
            scope_name: Some("Sales".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
        };

        let mut scopes = HashMap::new();
        // An existing RBAC verdict is never overwritten: that app already migrated.
        scopes.insert("Mail.ReadWrite".to_string(), scoped_rbac());
        apply_legacy_policy_verdict(&mut scopes, &grants, Some(&legacy));

        assert!(
            matches!(
                scopes.get("Mail.Read"),
                Some(MailPermissionScope::Scoped {
                    mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
                    ..
                })
            ),
            "a Graph mail permission with no verdict takes the legacy one"
        );
        assert!(
            !scopes.contains_key("Calendars.Read"),
            "the Office 365 namesake is not confinable by a policy, so it must be left alone"
        );
        assert!(
            matches!(
                scopes.get("Mail.ReadWrite"),
                Some(MailPermissionScope::Scoped {
                    mechanism: ScopeMechanism::Rbac,
                    ..
                })
            ),
            "an existing RBAC verdict must not be downgraded to the legacy mechanism"
        );

        // No verdict ⇒ no change at all.
        let before = scopes.clone();
        apply_legacy_policy_verdict(&mut scopes, &grants, None);
        assert_eq!(scopes.len(), before.len());
    }

    /// Microsoft's guidance: an un-stripped org-wide grant *unions* with the
    /// scoped role, so the app still reaches every mailbox. A legacy policy is
    /// exempt — it genuinely confines the org-wide grant.
    #[test]
    fn a_surviving_org_wide_grant_defeats_a_scoped_rbac_verdict() {
        let held: HashSet<String> = ["Mail.Read".to_string()].into_iter().collect();
        assert!(matches!(
            reconcile_orgwide_grant(scoped_rbac(), "Mail.Read", &held),
            MailPermissionScope::OrgWide
        ));
        // A different permission's grant does not defeat this one.
        assert!(matches!(
            reconcile_orgwide_grant(scoped_rbac(), "Calendars.Read", &held),
            MailPermissionScope::Scoped { .. }
        ));
        // Properly stripped: no surviving grant keeps the scoped verdict.
        assert!(matches!(
            reconcile_orgwide_grant(scoped_rbac(), "Mail.Read", &HashSet::new()),
            MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::Rbac,
                ..
            }
        ));

        // A BLANKET grant vetoes every permission's scope, not just its own name:
        // EWS full_access_as_app reaches every mailbox with full access.
        let blanket: HashSet<String> =
            [azapptoolkit_core::scoping::EWS_FULL_ACCESS_AS_APP.to_string()]
                .into_iter()
                .collect();
        for permission in ["Mail.Read", "Calendars.Read"] {
            assert!(
                matches!(
                    reconcile_orgwide_grant(scoped_rbac(), permission, &blanket),
                    MailPermissionScope::OrgWide
                ),
                "a surviving EWS grant must defeat the {permission} scope"
            );
        }

        // A legacy policy is exempt.
        let legacy = MailPermissionScope::Scoped {
            scope_name: Some("Sales".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
        };
        assert!(matches!(
            reconcile_orgwide_grant(legacy, "Mail.Read", &held),
            MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
                ..
            }
        ));
    }

    /// A `RestrictAccess` policy keyed on this exact appId is stronger evidence
    /// than a failed probe — it wins even over a 403. A principal Exchange
    /// cannot resolve (the managed-identity case) has no RBAC scope, so absent a
    /// policy its org-wide Graph grant reaches every mailbox. Anything else is
    /// genuinely indeterminate and must surface so the UI can say why.
    #[test]
    fn a_failed_probe_falls_back_to_the_policy_then_to_org_wide_then_errors() {
        let legacy = MailPermissionScope::Scoped {
            scope_name: Some("Sales".into()),
            recipient_filter: None,
            group_count: None,
            mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
        };
        assert!(matches!(
            scope_from_rbac_error(
                ExchangeError::Forbidden {
                    detail: String::new(),
                    had_diagnostics: false,
                },
                Some(legacy)
            ),
            Ok(MailPermissionScope::Scoped { .. })
        ));
        assert!(
            scope_from_rbac_error(
                ExchangeError::Forbidden {
                    detail: String::new(),
                    had_diagnostics: false,
                },
                None
            )
            .is_err(),
            "a 403 with no policy is indeterminate, not org-wide"
        );
    }

    // ---- relocated from commands/exchange.rs with the logic they cover ----

    #[test]
    fn legacy_policy_verdict_fills_org_wide_and_missing_but_never_an_rbac_scope() {
        let legacy = aap_verdict_for(&[policy("app-1", "RestrictAccess", "Sales")], "app-1")
            .expect("legacy verdict");
        let rbac = MailPermissionScope::Scoped {
            scope_name: Some("app_scope_app-1".into()),
            recipient_filter: None,
            group_count: Some(1),
            mechanism: ScopeMechanism::Rbac,
        };
        let mut scopes = HashMap::from([
            ("Mail.Read".to_string(), MailPermissionScope::OrgWide),
            ("Mail.Send".to_string(), rbac.clone()),
        ]);
        let grants = [
            ResourcePermission::graph("Mail.Read"),
            ResourcePermission::graph("Mail.Send"),
            // No verdict at all (probe failed / never ran) — the policy answers.
            ResourcePermission::graph("Calendars.Read"),
            // Not Exchange-scopable: a policy can't confine it, so it must not
            // gain a scoped verdict (that would under-report its reach).
            ResourcePermission::graph("Directory.Read.All"),
            // Same NAME as a scopable Graph permission, different resource. An
            // Application Access Policy cannot confine Office 365 Exchange
            // Online's retired Outlook REST appRoles, so this must not lend the
            // legacy grant a scoped verdict — the value-keyed test could not
            // tell the two apart and did exactly that.
            ResourcePermission::exchange_online("Contacts.Read"),
            // An unresolvable resource is never treated as scoped.
            ResourcePermission {
                resource_app_id: None,
                value: "MailboxSettings.Read".to_string(),
            },
        ];

        apply_legacy_policy_verdict(&mut scopes, &grants, Some(&legacy));

        assert_eq!(scopes.get("Mail.Read"), Some(&legacy), "org-wide → legacy");
        assert_eq!(
            scopes.get("Calendars.Read"),
            Some(&legacy),
            "no verdict → legacy"
        );
        assert_eq!(
            scopes.get("Mail.Send"),
            Some(&rbac),
            "an app that already migrated keeps its RBAC verdict"
        );
        assert!(!scopes.contains_key("Directory.Read.All"));
        assert!(
            !scopes.contains_key("Contacts.Read"),
            "an AAP cannot confine Office 365 Exchange Online's own Contacts.Read, so it must \
             not earn a scoped verdict — scoring it at the reduced weight hides org-wide reach"
        );
        assert!(
            !scopes.contains_key("MailboxSettings.Read"),
            "an unresolved resource must be scored conservatively, never as scoped"
        );

        // RBAC-only values (scopable, but never governed by a policy) keep
        // whatever RBAC said: absent stays absent, OrgWide stays OrgWide.
        let mut rbac_only = HashMap::from([(
            "Mail-Advanced.ReadWrite.All".to_string(),
            MailPermissionScope::OrgWide,
        )]);
        apply_legacy_policy_verdict(
            &mut rbac_only,
            &[
                ResourcePermission::graph("MailboxItem.ReadWrite.All"),
                ResourcePermission::graph("Mail-Advanced.ReadWrite.All"),
            ],
            Some(&legacy),
        );
        assert!(
            !rbac_only.contains_key("MailboxItem.ReadWrite.All"),
            "an AAP never confined MailboxItem.ReadWrite.All, so it must not read Scoped (legacy)"
        );
        assert_eq!(
            rbac_only.get("Mail-Advanced.ReadWrite.All"),
            Some(&MailPermissionScope::OrgWide)
        );

        // No policy for this app ⇒ untouched (today's behavior).
        let mut untouched =
            HashMap::from([("Mail.Read".to_string(), MailPermissionScope::OrgWide)]);
        apply_legacy_policy_verdict(&mut untouched, &grants, None);
        assert_eq!(
            untouched.get("Mail.Read"),
            Some(&MailPermissionScope::OrgWide)
        );
    }

    #[test]
    fn rbac_error_restrict_access_aap_wins_even_over_forbidden() {
        // A RestrictAccess AAP keyed on this appId is authoritative regardless of
        // why the probe failed — it confines the whole app.
        let aap = aap_verdict_for(&[policy("app-1", "RestrictAccess", "Sales")], "app-1");
        match scope_from_rbac_error(
            ExchangeError::Forbidden {
                detail: "nope".into(),
                had_diagnostics: false,
            },
            aap,
        )
        .expect("AAP should resolve the verdict")
        {
            MailPermissionScope::Scoped {
                mechanism: ScopeMechanism::LegacyApplicationAccessPolicy,
                ..
            } => {}
            other => panic!("expected legacy-AAP Scoped, got {other:?}"),
        }
    }

    #[test]
    fn rbac_missing_object_without_aap_is_org_wide() {
        // The managed-identity case: the principal isn't in Exchange's SP store,
        // so it has no RBAC scope — its org-wide Graph grant reaches every mailbox.
        for err in [
            ExchangeError::NotFound("object couldn't be found".into()),
            ExchangeError::Api {
                status: 400,
                body: "[Test-ServicePrincipalAuthorization] couldn't be found".into(),
            },
        ] {
            assert_eq!(
                scope_from_rbac_error(err, None).expect("missing object => org-wide"),
                MailPermissionScope::OrgWide,
            );
        }
    }

    #[test]
    fn rbac_genuine_forbidden_without_aap_propagates() {
        // Not a missing object — the caller can't run the cmdlet, so scoping is
        // genuinely indeterminate. Surface it (caller shows a consent/403 banner).
        let err = scope_from_rbac_error(
            ExchangeError::Forbidden {
                detail: "RBAC denied".into(),
                had_diagnostics: true,
            },
            None,
        )
        .expect_err("genuine 403 must propagate");
        assert!(matches!(err, ExchangeError::Forbidden { .. }));
    }

    /// The migration planner and the audit / permission-tester verdict read an
    /// `AccessRight` through ONE definition, so a policy the migration treats as
    /// confining is never reported org-wide (full risk) by the audit, and a
    /// blocklist is never confining in either. Built via the wire path, since
    /// that is where padding and casing arrive.
    #[test]
    fn restrict_access_reads_the_same_in_the_planner_and_the_verdict() {
        use crate::aap::group_policies_for_migration;
        for raw in [
            "RestrictAccess",
            " RestrictAccess ",
            "restrictaccess",
            "DenyAccess",
            " denyaccess",
            "Other",
            "",
        ] {
            let p: ExoApplicationAccessPolicy = serde_json::from_value(serde_json::json!({
                "AppId": "app-1",
                "ScopeName": "Sales",
                "AccessRight": raw,
            }))
            .expect("policy deserializes");
            let verdict = aap_verdict_for(std::slice::from_ref(&p), "app-1").is_some();
            let migratable = !group_policies_for_migration(vec![p]).0.is_empty();
            assert_eq!(verdict, migratable, "{raw:?}");
        }

        // The drift this pins: the planner trimmed, the verdict did not.
        let padded: ExoApplicationAccessPolicy = serde_json::from_value(serde_json::json!({
            "AppId": "app-1",
            "ScopeName": "Sales",
            "AccessRight": " RestrictAccess ",
        }))
        .unwrap();
        assert!(aap_verdict_for(std::slice::from_ref(&padded), "app-1").is_some());
    }
}
