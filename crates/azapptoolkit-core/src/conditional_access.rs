//! Conditional Access policy applicability — pure, so the Conditional Access
//! tab (`commands::conditional_access`) and the audit's network-lock check read
//! one implementation of the two condition axes.

use crate::models::{CaApplications, CaClientApplications, CaConditions};

/// The client-axis outcome for this app's service principal.
enum ClientAxis {
    /// No client constraint (or no resolvable SP to check it against).
    Unconstrained,
    /// The policy explicitly names this app's SP (or every workload identity)
    /// as an allowed client.
    Matched,
    /// A client attribute filter may cover this SP — never evaluable
    /// client-side, so "may apply".
    MayApply,
    /// The policy's client axis names clients this app is not (or explicitly
    /// excludes it) — it cannot involve this app.
    Hidden,
}

/// Decides whether (and why) a CA policy targets `app_id`, across both
/// condition axes. The security-critical contract: **exclude always wins**
/// on either axis, the well-known `All` token is matched before any GUID
/// compare, and a policy that targets neither this app as a resource nor its
/// SP as a client never matches. Returns `(reason code, client-axis
/// constrained)` or `None`.
///
/// Reason codes name the axis that *made* the policy relevant: resource codes
/// (`appId` / `all` / `office365` / `adminPortals` / `filter` /
/// `filterExclude`) when the resource axis matches, client codes (`sp` /
/// `allWorkload` / `clientFilter` / `clientFilterExclude`) when only the
/// client axis matches — the latter surfaces "blocks this app's SP from
/// other resources" policies that the resource-only view silently dropped.
pub fn applies(
    conditions: &CaConditions,
    app_id: &str,
    sp_id: Option<&str>,
) -> Option<(&'static str, bool)> {
    let apps = conditions.applications.as_ref()?;
    // Excluded apps are never subject to the policy, even under an `All`
    // include and even when the client axis matches.
    if apps
        .exclude_applications
        .iter()
        .any(|a| a.eq_ignore_ascii_case(app_id))
    {
        return None;
    }
    let clients = match &conditions.client_applications {
        Some(ca) if !ca.is_empty() => ca,
        _ => {
            return resource_reason(apps, app_id).map(|r| (r, false));
        }
    };
    let axis = client_axis(clients, sp_id);
    match axis {
        ClientAxis::Hidden => None,
        ClientAxis::Unconstrained => resource_reason(apps, app_id).map(|r| (r, false)),
        ClientAxis::Matched | ClientAxis::MayApply => {
            // The client axis involves this app: show the policy whether it
            // matched on the resource axis or not — a workload-identity
            // block that lists only *other* resources still gates this app
            // signing in elsewhere with its credentials.
            let code = match resource_reason(apps, app_id) {
                Some(r) => r,
                None if matches!(axis, ClientAxis::Matched) => {
                    if client_includes_sp(clients, sp_id) {
                        "sp"
                    } else {
                        "allWorkload"
                    }
                }
                // Filter-only client axis with no resource match: keep the
                // filter codes so the cell still reads "may apply".
                None => {
                    if client_filter_is_exclude(clients) {
                        "clientFilterExclude"
                    } else {
                        "clientFilter"
                    }
                }
            };
            Some((code, true))
        }
    }
}

/// The existing resource-axis ladder, unchanged.
fn resource_reason(apps: &CaApplications, app_id: &str) -> Option<&'static str> {
    let inc = &apps.include_applications;
    if inc.iter().any(|a| a == "All") {
        return Some("all");
    }
    if inc.iter().any(|a| a.eq_ignore_ascii_case(app_id)) {
        return Some("appId");
    }
    // Well-known groupings *may* include this app (Graph doesn't expand them).
    if inc.iter().any(|a| a == "Office365") {
        return Some("office365");
    }
    if inc.iter().any(|a| a == "MicrosoftAdminPortals") {
        return Some("adminPortals");
    }
    // An application filter (attribute-based, on the app's custom security
    // attributes) may target this app; only consider it when no explicit app
    // include is present. We can't evaluate the rule, so the result is always
    // "may apply" — but the *mode* flips the bias, so report it: an `include`
    // filter applies only to the matching subset, while an `exclude` filter
    // applies to everything *except* a matching subset (so it likely applies).
    if inc.is_empty()
        && let Some(f) = &apps.application_filter
    {
        return Some(if f.mode.as_deref() == Some("exclude") {
            "filterExclude"
        } else {
            "filter"
        });
    }
    // Empty include with user actions (or nothing) → not app-targeting.
    None
}

fn client_includes_sp(clients: &CaClientApplications, sp_id: Option<&str>) -> bool {
    let Some(sp) = sp_id else {
        return false;
    };
    clients
        .include_service_principals
        .iter()
        .any(|c| c.eq_ignore_ascii_case(sp))
}

fn client_filter_is_exclude(clients: &CaClientApplications) -> bool {
    clients
        .service_principal_filter
        .as_ref()
        .and_then(|f| f.mode.as_deref())
        == Some("exclude")
}

/// Well-known tokens that name *every* workload identity as a client. Graph
/// has written this set with different casing/spelling across API versions;
/// all spellings under-match (they never name a single foreign SP), so
/// matching all of them only ever over-shows, never hides.
/// `ServicePrincipalsInMyTenant` is the one Graph's v1.0
/// `conditionalAccessClientApplications` reference documents.
const ALL_WORKLOAD_TOKENS: [&str; 5] = [
    "All",
    "ServicePrincipalsInMyTenant",
    "WorkloadIdentities",
    "workloadIdentity",
    "workloadIdentityAll",
];

fn client_axis(clients: &CaClientApplications, sp_id: Option<&str>) -> ClientAxis {
    // No SP (or a failed lookup) → the client axis cannot name this app;
    // skip it rather than guess. Matches the pre-client-axis behaviour.
    let Some(sp) = sp_id else {
        return ClientAxis::Unconstrained;
    };
    // Excluded clients win over any include, including `All`.
    if clients
        .exclude_service_principals
        .iter()
        .any(|c| c.eq_ignore_ascii_case(sp))
    {
        return ClientAxis::Hidden;
    }
    let inc = &clients.include_service_principals;
    if client_includes_sp(clients, Some(sp)) {
        return ClientAxis::Matched;
    }
    if inc
        .iter()
        .any(|t| ALL_WORKLOAD_TOKENS.contains(&t.as_str()))
    {
        return ClientAxis::Matched;
    }
    if !inc.is_empty() {
        // An explicit client list that names neither this SP nor all
        // workload identities targets other clients only.
        return ClientAxis::Hidden;
    }
    // Empty include: a filter "may apply", otherwise clients are not
    // constrained (Graph echoes an empty clientApplications for many
    // user-action policies).
    if clients.service_principal_filter.is_some() {
        ClientAxis::MayApply
    } else {
        ClientAxis::Unconstrained
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::CaApplicationFilter;

    fn apps(include: &[&str], exclude: &[&str], user_actions: &[&str]) -> CaApplications {
        CaApplications {
            include_applications: include.iter().map(|s| s.to_string()).collect(),
            exclude_applications: exclude.iter().map(|s| s.to_string()).collect(),
            include_user_actions: user_actions.iter().map(|s| s.to_string()).collect(),
            application_filter: None,
        }
    }

    fn cond(apps: CaApplications, clients: Option<CaClientApplications>) -> CaConditions {
        CaConditions {
            applications: Some(apps),
            client_applications: clients,
            locations: None,
        }
    }

    fn clients(include: &[&str], exclude: &[&str]) -> CaClientApplications {
        CaClientApplications {
            include_service_principals: include.iter().map(|s| s.to_string()).collect(),
            exclude_service_principals: exclude.iter().map(|s| s.to_string()).collect(),
            service_principal_filter: None,
        }
    }

    fn sp_filter(mode: &str) -> CaClientApplications {
        CaClientApplications {
            include_service_principals: Vec::new(),
            exclude_service_principals: Vec::new(),
            service_principal_filter: Some(CaApplicationFilter {
                mode: Some(mode.into()),
                rule: Some("servicePrincipals.tags -contains \"wi\"".into()),
            }),
        }
    }

    const APP: &str = "11111111-1111-1111-1111-111111111111";
    const OTHER: &str = "22222222-2222-2222-2222-222222222222";
    const SP: &str = "33333333-3333-3333-3333-333333333333";
    const OTHER_SP: &str = "44444444-4444-4444-4444-444444444444";

    /// No client axis → exactly the pre-workload-identity ladder.
    #[test]
    fn resource_axis_ladder_unchanged_without_client_axis() {
        let cases: [(&CaApplications, Option<(&str, bool)>); 8] = [
            (&apps(&[APP], &[], &[]), Some(("appId", false))),
            (&apps(&["All"], &[], &[]), Some(("all", false))),
            // Exclude wins even under an All include.
            (&apps(&["All"], &[APP], &[]), None),
            (&apps(&[OTHER], &[APP], &[]), None),
            (&apps(&[OTHER], &[], &[]), None),
            (&apps(&["Office365"], &[], &[]), Some(("office365", false))),
            (
                &apps(&["MicrosoftAdminPortals"], &[], &[]),
                Some(("adminPortals", false)),
            ),
            // Empty include + user actions → targets user actions, not apps.
            (&apps(&[], &[], &["urn:user:registersecurityinfo"]), None),
        ];
        for (a, want) in cases {
            assert_eq!(
                applies(&cond(a.clone(), None), APP, Some(SP)),
                want,
                "{a:?}"
            );
        }
    }

    #[test]
    fn application_filter_may_apply_when_no_explicit_include() {
        let mut a = apps(&[], &[], &[]);
        a.application_filter = Some(CaApplicationFilter {
            mode: Some("include".into()),
            rule: Some("app.tags -contains \"hr\"".into()),
        });
        assert_eq!(
            applies(&cond(a.clone(), None), APP, Some(SP)),
            Some(("filter", false))
        );
        // An exclude-mode filter targets every app except the matching subset,
        // so it must not be reported with the (narrower) "filter" code.
        a.application_filter = Some(CaApplicationFilter {
            mode: Some("exclude".into()),
            rule: Some("app.tags -contains \"hr\"".into()),
        });
        assert_eq!(
            applies(&cond(a, None), APP, Some(SP)),
            Some(("filterExclude", false))
        );
    }

    #[test]
    fn include_is_case_insensitive() {
        assert_eq!(
            applies(
                &cond(apps(&[&APP.to_uppercase()], &[], &[]), None),
                APP,
                Some(SP)
            ),
            Some(("appId", false))
        );
    }

    // ---- client axis ----------------------------------------------------

    #[test]
    fn all_apps_with_foreign_clients_no_longer_over_reports() {
        // The over-report fix: `applications: All` but the client axis names
        // only other service principals → this app is not a subject.
        let c = cond(apps(&["All"], &[], &[]), Some(clients(&[OTHER_SP], &[])));
        assert_eq!(applies(&c, APP, Some(SP)), None);
        // …but with no resolvable SP the axis is skipped, not guessed.
        assert_eq!(applies(&c, APP, None), Some(("all", false)));
    }

    #[test]
    fn sp_direct_match_narrows_an_all_apps_policy() {
        let c = cond(apps(&["All"], &[], &[]), Some(clients(&[SP], &[])));
        assert_eq!(applies(&c, APP, Some(SP)), Some(("all", true)));
    }

    #[test]
    fn sp_direct_match_shows_policies_that_only_name_other_resources() {
        // The under-report fix: a policy blocking this app's SP while naming
        // other resources was invisible to the resource-only view.
        let c = cond(apps(&[OTHER], &[], &[]), Some(clients(&[SP], &[])));
        assert_eq!(applies(&c, APP, Some(SP)), Some(("sp", true)));
        // Matching is case-insensitive, like the app-id ladder.
        let c = cond(
            apps(&[OTHER], &[], &[]),
            Some(clients(&[&SP.to_uppercase()], &[])),
        );
        assert_eq!(applies(&c, APP, Some(SP)), Some(("sp", true)));
    }

    #[test]
    fn all_workload_tokens_match_this_sp() {
        for token in ALL_WORKLOAD_TOKENS {
            let c = cond(apps(&[OTHER], &[], &[]), Some(clients(&[token], &[])));
            assert_eq!(
                applies(&c, APP, Some(SP)),
                Some(("allWorkload", true)),
                "token {token}"
            );
        }
        // Under the resource ladder the resource code wins, flag set.
        let c = cond(
            apps(&["All"], &[], &[]),
            Some(clients(&["workloadIdentityAll"], &[])),
        );
        assert_eq!(applies(&c, APP, Some(SP)), Some(("all", true)));
    }

    /// Graph's v1.0 `conditionalAccessClientApplications` reference documents
    /// `includeServicePrincipals` as SP object ids "or
    /// ServicePrincipalsInMyTenant" — the value a tenant-wide workload-identity
    /// policy carries. Read as an explicit list naming other clients, it hid
    /// that policy from every app.
    #[test]
    fn documented_all_service_principals_token_matches_this_sp() {
        let token = "ServicePrincipalsInMyTenant";
        let c = cond(apps(&["All"], &[], &[]), Some(clients(&[token], &[])));
        assert_eq!(applies(&c, APP, Some(SP)), Some(("all", true)));
        let c = cond(apps(&[OTHER], &[], &[]), Some(clients(&[token], &[])));
        assert_eq!(applies(&c, APP, Some(SP)), Some(("allWorkload", true)));
        // An excluded SP stays excluded under the tenant-wide token.
        let c = cond(apps(&["All"], &[], &[]), Some(clients(&[token], &[SP])));
        assert_eq!(applies(&c, APP, Some(SP)), None);
    }

    #[test]
    fn client_exclude_wins_over_both_includes() {
        // Exclude wins even under an All-on-everything policy…
        let c = cond(apps(&["All"], &[], &[]), Some(clients(&["All"], &[SP])));
        assert_eq!(applies(&c, APP, Some(SP)), None);
        // …including a direct SP include that also excludes it.
        let c = cond(apps(&[APP], &[], &[]), Some(clients(&[SP], &[SP])));
        assert_eq!(applies(&c, APP, Some(SP)), None);
        // The exclusion is keyed on *our* SP only — excluding another SP
        // changes nothing.
        let c = cond(
            apps(&["All"], &[], &[]),
            Some(clients(&["All"], &[OTHER_SP])),
        );
        assert_eq!(applies(&c, APP, Some(SP)), Some(("all", true)));
    }

    #[test]
    fn resource_exclude_wins_over_client_match() {
        // APP excluded → hidden regardless of the client axis.
        let c = cond(apps(&[OTHER], &[APP], &[]), Some(clients(&[SP], &[])));
        assert_eq!(applies(&c, APP, Some(SP)), None);
    }

    #[test]
    fn empty_client_axis_behaves_as_absent() {
        // Graph echoes `clientApplications: {"excludeServicePrincipals": [], …}`
        // for plain user policies — `is_empty()` must treat that as
        // unconstrained, or every app loses its "All apps" policies.
        let c = cond(
            apps(&["All"], &[], &[]),
            Some(CaClientApplications::default()),
        );
        assert_eq!(applies(&c, APP, Some(SP)), Some(("all", false)));
    }

    #[test]
    fn client_filter_may_apply_and_mode_flips_the_bias() {
        // A filter-only client axis is never evaluable → "may apply", shown
        // even when the resource axis doesn't name this app.
        let c = cond(
            apps(&[], &[], &["urn:user:registersecurityinfo"]),
            Some(sp_filter("include")),
        );
        assert_eq!(applies(&c, APP, Some(SP)), Some(("clientFilter", true)));
        let c = cond(apps(&[], &[], &[]), Some(sp_filter("exclude")));
        assert_eq!(
            applies(&c, APP, Some(SP)),
            Some(("clientFilterExclude", true))
        );
        // Under a matching resource ladder the resource code still leads.
        let c = cond(apps(&[APP], &[], &[]), Some(sp_filter("include")));
        assert_eq!(applies(&c, APP, Some(SP)), Some(("appId", true)));
    }

    #[test]
    fn no_sp_skips_the_client_axis_entirely() {
        // An app without a service principal cannot be a named client; every
        // client-axis shape degrades to the resource ladder unchanged — the
        // OTHER-only policy stays hidden exactly as before this axis existed.
        for (c, want) in [
            (
                cond(apps(&["All"], &[], &[]), Some(clients(&[OTHER_SP], &[]))),
                Some(("all", false)),
            ),
            (
                cond(apps(&["All"], &[], &[]), Some(clients(&[SP], &[]))),
                Some(("all", false)),
            ),
            (
                cond(apps(&["All"], &[], &[]), Some(clients(&["All"], &[SP]))),
                Some(("all", false)),
            ),
            (
                cond(apps(&[OTHER], &[], &[]), Some(sp_filter("include"))),
                None,
            ),
        ] {
            assert_eq!(applies(&c, APP, None), want, "{c:?}");
        }
    }
}
