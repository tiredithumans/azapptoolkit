//! Teams application access policy script (C3). Microsoft has no API for
//! these policies, so the toolkit writes the PowerShell the operator runs.
//!
//! Facts (Microsoft Learn, 2026-11-25): the policy gates the six permissions in
//! [`MEETING_POLICY_PERMISSIONS`]; with none granted, app-only calls fail;
//! `-Global` covers every user without their own policy; a user holds ONE
//! application access policy; changes take up to 30 minutes to reach Graph.
//!
//! The script is injection-safe by construction: every value is a single-
//! quoted literal with `'` doubled ([`ps_quote`]), comment text has control
//! characters stripped, ids are GUIDs, and a `-Global` grant is never written.

use crate::guid::is_guid;
use crate::scoping::MICROSOFT_GRAPH_APP_ID;

/// The Microsoft Graph application permissions an application access policy
/// gates.
pub const MEETING_POLICY_PERMISSIONS: [&str; 6] = [
    "OnlineMeetings.Read.All",
    "OnlineMeetings.ReadWrite.All",
    "OnlineMeetingArtifact.Read.All",
    "OnlineMeetingTranscript.Read.All",
    "OnlineMeetingRecording.Read.All",
    "VirtualEvent.Read.All",
];

/// Whether `value` on `resource_app_id` (Microsoft Graph, any case) is gated
/// by an application access policy.
pub fn is_meeting_policy_permission(resource_app_id: Option<&str>, value: &str) -> bool {
    resource_app_id.is_some_and(|r| r.eq_ignore_ascii_case(MICROSOFT_GRAPH_APP_ID))
        && MEETING_POLICY_PERMISSIONS.contains(&value)
}

/// Create a policy, or add the app to one users already hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    New,
    AddToExisting,
}

/// Who the policy is granted to (never everyone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyTargets {
    /// Users, by object id.
    Users(Vec<String>),
    /// One group (group policy assignment), by object id.
    Group { id: String, rank: Option<u32> },
}

/// Everything the script is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRequest {
    pub app_id: String,
    /// Shown in comments and the description only, sanitised.
    pub app_name: String,
    pub policy_name: String,
    pub mode: PolicyMode,
    pub targets: PolicyTargets,
}

/// Why a script can't be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyScriptError {
    InvalidAppId,
    InvalidPolicyName,
    InvalidTarget(String),
    NoTargets,
}

impl std::fmt::Display for PolicyScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyScriptError::InvalidAppId => write!(f, "The app id isn't a valid id."),
            PolicyScriptError::InvalidPolicyName => write!(
                f,
                "Name the policy with up to 64 letters, digits, spaces, dots, dashes or underscores."
            ),
            PolicyScriptError::InvalidTarget(id) => {
                write!(f, "{id} isn't a valid object id.")
            }
            PolicyScriptError::NoTargets => write!(
                f,
                "Pick at least one user or a group: a new policy granted to no one covers no meetings."
            ),
        }
    }
}

/// A single-quoted PowerShell literal: `'` doubled, nothing interpolated.
pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Text safe for a comment or a description: control characters (newlines
/// included) become spaces.
fn inert(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .to_string()
}

/// `azapptoolkit-` plus the app's name reduced to letters, digits and dashes
/// (spaces become dashes), at most 64 characters.
pub fn default_policy_name(app_name: &str) -> String {
    let mut slug = String::new();
    for c in app_name.trim().chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if (c == ' ' || c == '-' || c == '_') && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "app" } else { slug };
    let mut name = format!("azapptoolkit-{slug}");
    name.truncate(64);
    name.trim_end_matches('-').to_string()
}

fn valid_policy_name(name: &str) -> bool {
    (1..=64).contains(&name.chars().count())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_'))
}

/// The PowerShell for `req`, or why it can't be built.
pub fn script(req: &PolicyRequest) -> Result<String, PolicyScriptError> {
    if !is_guid(&req.app_id) {
        return Err(PolicyScriptError::InvalidAppId);
    }
    if !valid_policy_name(&req.policy_name) {
        return Err(PolicyScriptError::InvalidPolicyName);
    }
    let targets: Vec<String> = match &req.targets {
        PolicyTargets::Users(ids) => ids.clone(),
        PolicyTargets::Group { id, .. } => vec![id.clone()],
    };
    if let Some(bad) = targets.iter().find(|id| !is_guid(id)) {
        return Err(PolicyScriptError::InvalidTarget(inert(bad)));
    }
    if req.mode == PolicyMode::New && targets.is_empty() {
        return Err(PolicyScriptError::NoTargets);
    }

    let app = inert(&req.app_name);
    let name = ps_quote(&req.policy_name);
    let app_id = ps_quote(&req.app_id);
    let mut out = vec![
        format!("# Teams application access policy for {app}, written by azapptoolkit."),
        "# Run in PowerShell with the MicrosoftTeams module, as a Teams administrator.".to_string(),
        "Connect-MicrosoftTeams".to_string(),
        String::new(),
    ];
    match req.mode {
        PolicyMode::New => out.push(format!(
            "New-CsApplicationAccessPolicy -Identity {name} -AppIds {app_id} -Description {}",
            ps_quote(&format!("Created by azapptoolkit for {app}"))
        )),
        PolicyMode::AddToExisting => out.push(format!(
            "Set-CsApplicationAccessPolicy -Identity {name} -AppIds @{{Add={app_id}}}"
        )),
    }
    match &req.targets {
        PolicyTargets::Users(ids) => {
            for id in ids {
                out.push(format!(
                    "Grant-CsApplicationAccessPolicy -PolicyName {name} -Identity {}",
                    ps_quote(id)
                ));
            }
        }
        PolicyTargets::Group { id, rank } => {
            let rank = rank.map(|r| format!(" -Rank {r}")).unwrap_or_default();
            out.push(format!(
                "Grant-CsApplicationAccessPolicy -PolicyName {name} -Group {}{rank}",
                ps_quote(id)
            ));
        }
    }
    out.extend([
        String::new(),
        "# Check: the policies that include the app, and whether the tenant-wide".to_string(),
        "# Global policy does (True there means every user without their own policy".to_string(),
        "# is covered). Changes take up to 30 minutes to reach Microsoft Graph.".to_string(),
        format!(
            "Get-CsApplicationAccessPolicy | Where-Object {{ $_.AppIds -contains {app_id} }} | Format-List Identity, AppIds"
        ),
        format!("(Get-CsApplicationAccessPolicy -Identity 'Global').AppIds -contains {app_id}"),
    ]);
    Ok(out.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoping::MICROSOFT_GRAPH_APP_ID;

    const APP: &str = "11111111-2222-4333-8444-555555555555";
    const U1: &str = "aaaaaaaa-1111-4222-8333-444444444444";
    const U2: &str = "bbbbbbbb-1111-4222-8333-444444444444";
    const G: &str = "cccccccc-1111-4222-8333-444444444444";

    fn req(mode: PolicyMode, targets: PolicyTargets) -> PolicyRequest {
        PolicyRequest {
            app_id: APP.into(),
            app_name: "Contoso Recorder".into(),
            policy_name: "azapptoolkit-Contoso-Recorder".into(),
            mode,
            targets,
        }
    }

    #[test]
    fn quoting_doubles_single_quotes() {
        assert_eq!(ps_quote("O'Brien"), "'O''Brien'");
        assert_eq!(ps_quote(""), "''");
    }

    #[test]
    fn hostile_names_stay_inert() {
        let mut r = req(PolicyMode::New, PolicyTargets::Users(vec![U1.into()]));
        r.app_name = "O'Brien\nRemove-Item C:\\ -Recurse #>".into();
        let s = script(&r).unwrap();
        assert!(
            s.lines()
                .all(|l| !l.trim_start().starts_with("Remove-Item")),
            "{s}"
        );
        let new_line = s
            .lines()
            .find(|l| l.starts_with("New-CsApplicationAccessPolicy"))
            .unwrap();
        assert!(
            new_line.contains("'Created by azapptoolkit for O''Brien"),
            "{new_line}"
        );
    }

    #[test]
    fn ids_are_guids() {
        let mut bad_app = req(PolicyMode::New, PolicyTargets::Users(vec![U1.into()]));
        bad_app.app_id = "x' ; evil".into();
        assert_eq!(script(&bad_app), Err(PolicyScriptError::InvalidAppId));
        let bad_user = req(PolicyMode::New, PolicyTargets::Users(vec!["nope".into()]));
        assert!(matches!(
            script(&bad_user),
            Err(PolicyScriptError::InvalidTarget(_))
        ));
        let bad_group = req(
            PolicyMode::New,
            PolicyTargets::Group {
                id: "nope".into(),
                rank: None,
            },
        );
        assert!(matches!(
            script(&bad_group),
            Err(PolicyScriptError::InvalidTarget(_))
        ));
        let mut bad_name = req(PolicyMode::New, PolicyTargets::Users(vec![U1.into()]));
        bad_name.policy_name = "a'b".into();
        assert_eq!(script(&bad_name), Err(PolicyScriptError::InvalidPolicyName));
    }

    #[test]
    fn targets_rules_per_mode() {
        assert_eq!(
            script(&req(PolicyMode::New, PolicyTargets::Users(Vec::new()))),
            Err(PolicyScriptError::NoTargets)
        );
        let s = script(&req(
            PolicyMode::AddToExisting,
            PolicyTargets::Users(Vec::new()),
        ))
        .unwrap();
        assert!(s.contains(&format!(
            "Set-CsApplicationAccessPolicy -Identity 'azapptoolkit-Contoso-Recorder' -AppIds @{{Add='{APP}'}}"
        )));
        assert!(!s.contains("Grant-CsApplicationAccessPolicy"));
    }

    #[test]
    fn users_and_group_scripts() {
        let s = script(&req(
            PolicyMode::New,
            PolicyTargets::Users(vec![U1.into(), U2.into()]),
        ))
        .unwrap();
        for u in [U1, U2] {
            assert!(s.contains(&format!(
                "Grant-CsApplicationAccessPolicy -PolicyName 'azapptoolkit-Contoso-Recorder' -Identity '{u}'"
            )));
        }
        assert!(s.contains("Connect-MicrosoftTeams"));
        assert!(s.contains(&format!(
            "New-CsApplicationAccessPolicy -Identity 'azapptoolkit-Contoso-Recorder' -AppIds '{APP}'"
        )));
        let g = script(&req(
            PolicyMode::New,
            PolicyTargets::Group {
                id: G.into(),
                rank: Some(2),
            },
        ))
        .unwrap();
        assert!(g.contains(&format!(
            "Grant-CsApplicationAccessPolicy -PolicyName 'azapptoolkit-Contoso-Recorder' -Group '{G}' -Rank 2"
        )));
        let g = script(&req(
            PolicyMode::New,
            PolicyTargets::Group {
                id: G.into(),
                rank: None,
            },
        ))
        .unwrap();
        assert!(!g.contains("-Rank"));
        assert!(
            g.contains("Get-CsApplicationAccessPolicy"),
            "the checks are included"
        );
    }

    #[test]
    fn never_a_global_grant() {
        for targets in [
            PolicyTargets::Users(vec![U1.into()]),
            PolicyTargets::Group {
                id: G.into(),
                rank: None,
            },
        ] {
            let s = script(&req(PolicyMode::New, targets)).unwrap();
            assert!(
                s.lines()
                    .all(|l| !(l.contains("Grant-") && l.contains("-Global"))),
                "{s}"
            );
        }
    }

    #[test]
    fn default_names() {
        assert_eq!(
            default_policy_name("Contoso Recorder!"),
            "azapptoolkit-Contoso-Recorder"
        );
        assert!(default_policy_name(&"x".repeat(200)).len() <= 64);
        assert_eq!(default_policy_name("  "), "azapptoolkit-app");
    }

    #[test]
    fn the_six_permissions() {
        assert_eq!(MEETING_POLICY_PERMISSIONS.len(), 6);
        assert!(is_meeting_policy_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "OnlineMeetings.Read.All"
        ));
        assert!(is_meeting_policy_permission(
            Some(&MICROSOFT_GRAPH_APP_ID.to_uppercase()),
            "VirtualEvent.Read.All"
        ));
        assert!(!is_meeting_policy_permission(
            None,
            "OnlineMeetings.Read.All"
        ));
        assert!(!is_meeting_policy_permission(
            Some(MICROSOFT_GRAPH_APP_ID),
            "User.Read.All"
        ));
    }
}
