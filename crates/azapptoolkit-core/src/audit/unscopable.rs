//! "No built-in scoping": Microsoft Graph application permissions that
//! Microsoft gives no way to narrow (e.g. `CallRecords.Read.All`), so every
//! grant reaches the whole tenant.
//!
//! One classifier for every surface — audit Rule 24, the permission-row badge
//! and the grant-time warnings — so they can never disagree about which
//! permission is "unscopable". It only ever describes reach: a safeguard
//! (Conditional Access network lock, certificate-only credentials) limits
//! where a token works, never what it reads, and never changes this answer.

use serde::{Deserialize, Serialize};

use super::permissions::{least_privilege_alternative_for, risk_level_for_app_permission};
use super::{ResourcePermission, RiskLevel};
use crate::conditional_access::NetworkLock;
use crate::scoping::{
    MICROSOFT_GRAPH_APP_ID, ScopeKind, is_files_orgwide_permission, is_mailbox_reaching_permission,
    is_sharepoint_site_access_permission, scope_kind_for,
};

/// The read-only directory permissions the "no built-in scoping" finding
/// deliberately skips: nearly every app holds one, and flagging them would
/// bury the communications and content reads the finding exists for. They
/// keep their own risk weight.
pub const DIRECTORY_READ_EXCLUSIONS: &[&str] = &[
    "User.Read.All",
    "Group.Read.All",
    "GroupMember.Read.All",
    "Device.Read.All",
    "Application.Read.All",
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
];

/// Risk-weighted permissions that are themselves the narrowed form, so "no
/// way to narrow it" would be false — `Application.ReadWrite.OwnedBy`
/// reaches only the apps it owns.
const ALREADY_NARROWED: &[&str] = &["Application.ReadWrite.OwnedBy"];

/// A narrower permission to switch to, for a broad one whose narrowing is
/// another permission rather than a scoping mechanism (the
/// `least_privilege_alternative_for` arms cover SharePoint and Files).
const NARROWER_PERMISSION: &[(&str, &str)] =
    &[("Application.ReadWrite.All", "Application.ReadWrite.OwnedBy")];

/// A Microsoft-enforced way to narrow a permission that this toolkit does not
/// manage (yet). A permission carrying one is still flagged — the toolkit
/// cannot apply it — but the finding says Microsoft can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmanagedMechanism {
    /// Teams application access policy (`New-CsApplicationAccessPolicy`):
    /// limits the online-meeting permissions to chosen organizers.
    TeamsMeetingAccessPolicy,
    /// Resource-specific consent: a per-team / per-chat permission
    /// (`ChannelMessage.Read.Group`, `ChatMessage.Read.Chat`) instead of the
    /// tenant-wide one.
    ResourceSpecificConsent,
}

impl UnmanagedMechanism {
    /// Operator-facing name, written to follow "Microsoft can narrow this with …".
    pub fn label(self) -> &'static str {
        match self {
            UnmanagedMechanism::TeamsMeetingAccessPolicy => "a Teams meeting access policy",
            UnmanagedMechanism::ResourceSpecificConsent => "per-team (resource-specific) consent",
        }
    }
}

/// One held application permission with no built-in scoping, as audit Rule 24
/// lists it on an [`super::AuditItem`]. `network_lock` is filled by the audit
/// runner from its tenant-wide Conditional Access read; the scorer leaves it
/// [`NetworkLock::Unknown`]. Crosses IPC inside `AuditItem`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnscopableGrant {
    pub permission: ResourcePermission,
    pub risk: RiskLevel,
    pub microsoft_mechanism: Option<UnmanagedMechanism>,
    #[serde(default)]
    pub network_lock: NetworkLock,
    /// The latest Graph call this permission could have authorized, from the
    /// runner's Graph-activity pass. The scorer leaves a tracked permission
    /// `Unknown { NotChecked }` and an untracked one `NotTracked`.
    #[serde(default)]
    pub last_used: super::GrantUsage,
    /// The grant's expiry date when one is set (Rule 25's tag), for the
    /// checklist. Filled by the runner's expiry pass.
    #[serde(default)]
    pub expires_on: Option<jiff::civil::Date>,
}

/// How (if at all) a permission's reach can be narrowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeScoping {
    /// A mechanism this toolkit applies (`scoping::scope_kind_for`).
    Managed(ScopeKind),
    /// A narrower model to switch to (`least_privilege_alternative_for`).
    Swappable(&'static str),
    /// Microsoft can narrow it; this toolkit doesn't manage that mechanism.
    MicrosoftUnmanaged(UnmanagedMechanism),
    /// Nothing narrows it: every grant is tenant-wide.
    None,
}

/// Microsoft Graph application permissions with a Microsoft-documented
/// app-only narrowing mechanism the toolkit does not manage. Graph only.
const MICROSOFT_UNMANAGED: &[(&str, UnmanagedMechanism)] = &[
    // The Teams application access policy page lists exactly these (plus
    // `VirtualEvent.Read.All`, which is on no risk list).
    (
        "OnlineMeetings.Read.All",
        UnmanagedMechanism::TeamsMeetingAccessPolicy,
    ),
    (
        "OnlineMeetings.ReadWrite.All",
        UnmanagedMechanism::TeamsMeetingAccessPolicy,
    ),
    (
        "OnlineMeetingTranscript.Read.All",
        UnmanagedMechanism::TeamsMeetingAccessPolicy,
    ),
    (
        "OnlineMeetingRecording.Read.All",
        UnmanagedMechanism::TeamsMeetingAccessPolicy,
    ),
    (
        "OnlineMeetingArtifact.Read.All",
        UnmanagedMechanism::TeamsMeetingAccessPolicy,
    ),
    // Resource-specific consent has per-team / per-chat counterparts.
    (
        "ChannelMessage.Read.All",
        UnmanagedMechanism::ResourceSpecificConsent,
    ),
    ("Chat.Read.All", UnmanagedMechanism::ResourceSpecificConsent),
    (
        "Chat.ReadWrite.All",
        UnmanagedMechanism::ResourceSpecificConsent,
    ),
    // User / Groups / Cloud Device Administrator, assigned to the service
    // principal over an administrative unit.
];

/// `Some(MICROSOFT_GRAPH_APP_ID)` for the Graph appId in any case, the
/// resource unchanged otherwise. The scoping gates compare the canonical
/// lower-case id.
fn canonical(resource_app_id: Option<&str>) -> Option<&str> {
    match resource_app_id {
        Some(id) if id.eq_ignore_ascii_case(MICROSOFT_GRAPH_APP_ID) => Some(MICROSOFT_GRAPH_APP_ID),
        other => other,
    }
}

/// The Microsoft-documented mechanism this toolkit doesn't manage, for a
/// Graph permission. `None` for every other resource (and an unresolved one).
pub fn unmanaged_mechanism_for(
    resource_app_id: Option<&str>,
    value: &str,
) -> Option<UnmanagedMechanism> {
    if canonical(resource_app_id) != Some(MICROSOFT_GRAPH_APP_ID) {
        return None;
    }
    MICROSOFT_UNMANAGED
        .iter()
        .find(|(v, _)| *v == value)
        .map(|(_, m)| *m)
}

/// How `value` on `resource_app_id` can be narrowed: a toolkit mechanism
/// first, then a narrower model to swap to, then a Microsoft mechanism the
/// toolkit doesn't manage.
pub fn native_scoping_for(resource_app_id: Option<&str>, value: &str) -> NativeScoping {
    let resource = canonical(resource_app_id);
    if let Some(kind) = scope_kind_for(resource, value) {
        NativeScoping::Managed(kind)
    } else if let Some(alt) = least_privilege_alternative_for(resource, value) {
        NativeScoping::Swappable(alt)
    } else if let Some((_, alt)) = NARROWER_PERMISSION
        .iter()
        .find(|(broad, _)| *broad == value)
        .filter(|_| resource == Some(MICROSOFT_GRAPH_APP_ID))
    {
        NativeScoping::Swappable(alt)
    } else if let Some(m) = unmanaged_mechanism_for(resource, value) {
        NativeScoping::MicrosoftUnmanaged(m)
    } else {
        NativeScoping::None
    }
}

/// True when a held or requested **application** permission is risk-weighted,
/// on Microsoft Graph (an unresolved resource is treated as Graph), not a
/// directory read, not already owned by the mailbox / SharePoint / Files
/// findings, and has no mechanism this toolkit can apply or swap to.
pub fn is_unscopable_privileged(resource_app_id: Option<&str>, value: &str) -> bool {
    let graph = Some(MICROSOFT_GRAPH_APP_ID);
    match canonical(resource_app_id) {
        Some(MICROSOFT_GRAPH_APP_ID) | None => {}
        Some(_) => return false,
    }
    if risk_level_for_app_permission(value).is_none()
        || DIRECTORY_READ_EXCLUSIONS.contains(&value)
        || ALREADY_NARROWED.contains(&value)
    {
        return false;
    }
    // Rules 11/12 speak for these, with their own (and different) advice.
    if is_mailbox_reaching_permission(graph, value)
        || is_sharepoint_site_access_permission(graph, value)
        || is_files_orgwide_permission(graph, value)
    {
        return false;
    }
    matches!(
        native_scoping_for(graph, value),
        NativeScoping::None | NativeScoping::MicrosoftUnmanaged(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoping::{MICROSOFT_GRAPH_APP_ID, OFFICE365_EXCHANGE_ONLINE_APP_ID};

    const G: Option<&str> = Some(MICROSOFT_GRAPH_APP_ID);
    const EXO: Option<&str> = Some(OFFICE365_EXCHANGE_ONLINE_APP_ID);

    #[test]
    fn unscopable_classification_table() {
        let upper_graph = Some("00000003-0000-0000-C000-000000000000");
        let cases: [(Option<&str>, &str, bool, &str); 16] = [
            (G, "CallRecords.Read.All", true, "no mechanism"),
            (
                upper_graph,
                "CallRecords.Read.All",
                true,
                "case-insensitive Graph",
            ),
            (
                None,
                "CallRecords.Read.All",
                true,
                "unresolved is treated as Graph",
            ),
            (G, "Chat.Read.All", true, "Microsoft-unmanaged still flags"),
            (G, "User.Read.All", false, "directory read"),
            (G, "Directory.Read.All", false, "directory read"),
            (G, "Mail.Read", false, "Managed(Exchange)"),
            (
                None,
                "Mail.Read",
                false,
                "Rule 11 owns mailbox-reaching values",
            ),
            (EXO, "Mail.ReadWrite", false, "not Graph"),
            (EXO, "Exchange.ManageAsApp", false, "not Graph"),
            (G, "Files.Read.All", false, "Swappable"),
            (G, "Sites.Read.All", false, "Managed(SharePoint)"),
            (
                G,
                "RoleManagement.ReadWrite.Directory",
                true,
                "tier-0, no mechanism",
            ),
            (G, "Organization.Read.All", false, "in no tier"),
            (
                G,
                "Application.ReadWrite.OwnedBy",
                false,
                "already the narrowed form",
            ),
            (
                G,
                "Application.ReadWrite.All",
                false,
                "Swappable to OwnedBy",
            ),
        ];
        for (resource, value, want, why) in cases {
            assert_eq!(
                is_unscopable_privileged(resource, value),
                want,
                "{resource:?} {value}: {why}"
            );
        }
    }

    #[test]
    fn unmanaged_mechanisms_are_graph_only() {
        assert_eq!(
            unmanaged_mechanism_for(G, "OnlineMeetings.Read.All"),
            Some(UnmanagedMechanism::TeamsMeetingAccessPolicy)
        );
        // Admin-unit roles are a toolkit mechanism now (`ScopeKind::AdministrativeUnit`).
        assert_eq!(unmanaged_mechanism_for(G, "User.ReadWrite.All"), None);
        assert_eq!(unmanaged_mechanism_for(EXO, "User.ReadWrite.All"), None);
    }

    #[test]
    fn native_scoping_names_each_arm() {
        assert_eq!(
            native_scoping_for(G, "Mail.Read"),
            NativeScoping::Managed(crate::scoping::ScopeKind::Exchange)
        );
        assert_eq!(
            native_scoping_for(G, "Files.Read.All"),
            NativeScoping::Swappable(crate::scoping::SP_FILES_SELECTED)
        );
        assert_eq!(
            native_scoping_for(G, "Chat.Read.All"),
            NativeScoping::MicrosoftUnmanaged(UnmanagedMechanism::ResourceSpecificConsent)
        );
        assert_eq!(
            native_scoping_for(G, "CallRecords.Read.All"),
            NativeScoping::None
        );
        assert_eq!(
            native_scoping_for(G, "Application.ReadWrite.All"),
            NativeScoping::Swappable("Application.ReadWrite.OwnedBy")
        );
    }

    #[test]
    fn directory_writes_are_managed_by_admin_unit_scoping() {
        use crate::scoping::{MICROSOFT_GRAPH_APP_ID, ScopeKind};
        for v in [
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Device.ReadWrite.All",
        ] {
            assert_eq!(
                native_scoping_for(Some(MICROSOFT_GRAPH_APP_ID), v),
                NativeScoping::Managed(ScopeKind::AdministrativeUnit),
                "{v}"
            );
            assert!(
                !is_unscopable_privileged(Some(MICROSOFT_GRAPH_APP_ID), v),
                "{v}"
            );
        }
    }

    /// The checklist points every Teams-policy row at Meeting policy…, so
    /// the generator's list may be wider than this table, never narrower.
    #[test]
    fn every_teams_policy_row_offers_the_meeting_policy_button() {
        let rows: Vec<&str> = MICROSOFT_UNMANAGED
            .iter()
            .filter(|(_, m)| *m == UnmanagedMechanism::TeamsMeetingAccessPolicy)
            .map(|(v, _)| *v)
            .collect();
        assert!(!rows.is_empty());
        for v in rows {
            assert!(
                crate::teams_meeting_policy::is_meeting_policy_permission(
                    Some(crate::scoping::MICROSOFT_GRAPH_APP_ID),
                    v
                ),
                "{v} has no Meeting policy… button"
            );
        }
    }
}
