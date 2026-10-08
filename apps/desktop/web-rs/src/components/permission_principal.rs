//! "Granted to" text for one SharePoint permission entry, shared by the
//! Permission Tester's entry table and the per-app "SharePoint item access"
//! section so both name a principal the same way.

use crate::bindings::sharepoint::{
    PermissionPrincipalDto, PrincipalKind, SelectedItemPermissionDto,
};

/// The principal's name, or its id when Graph named none.
fn name_of(p: &PermissionPrincipalDto) -> Option<String> {
    p.display_name.clone().or_else(|| p.id.clone())
}

/// `(primary, secondary)` for one entry: who it grants to, and the email,
/// sign-in name, app id or link recipients beneath it.
///
/// An app entry keeps its historical shape (name, then the app id) because the
/// revoke flow and its confirm subject key off it. Anything Graph named without
/// an identity this app recognises reads "Unknown principal", never a guess.
pub fn principal_label(entry: &SelectedItemPermissionDto) -> (String, Option<String>) {
    let Some(first) = entry.principals.first() else {
        return match (&entry.app_id, &entry.app_display_name) {
            (Some(id), Some(name)) => (name.clone(), Some(id.clone())),
            (Some(id), None) => (id.clone(), None),
            (None, _) => ("Unknown principal".to_string(), None),
        };
    };
    match first.kind {
        PrincipalKind::Application => {
            let name = entry
                .app_display_name
                .clone()
                .or_else(|| name_of(first))
                .unwrap_or_else(|| "Application".to_string());
            let id = entry.app_id.clone().or_else(|| first.id.clone());
            (name.clone(), id.filter(|id| *id != name))
        }
        PrincipalKind::SharingLink => {
            let primary = match &first.detail {
                Some(detail) => format!("Sharing link · {detail}"),
                None => "Sharing link".to_string(),
            };
            let recipients: Vec<String> =
                entry.principals[1..].iter().filter_map(name_of).collect();
            let secondary =
                (!recipients.is_empty()).then(|| format!("Sent to {}", recipients.join(", ")));
            (primary, secondary)
        }
        kind => {
            let label = match kind {
                PrincipalKind::User => "User",
                PrincipalKind::Group => "Group",
                PrincipalKind::SiteUser => "SharePoint user",
                PrincipalKind::SiteGroup => "SharePoint group",
                _ => "Device",
            };
            let name = name_of(first).unwrap_or_else(|| "unnamed".to_string());
            (format!("{label} · {name}"), first.detail.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(principals: Vec<PermissionPrincipalDto>) -> SelectedItemPermissionDto {
        SelectedItemPermissionDto {
            id: "p".into(),
            roles: vec!["read".into()],
            app_id: None,
            app_display_name: None,
            principals,
        }
    }

    fn principal(
        kind: PrincipalKind,
        name: Option<&str>,
        detail: Option<&str>,
    ) -> PermissionPrincipalDto {
        PermissionPrincipalDto {
            kind,
            id: Some("id-1".into()),
            display_name: name.map(Into::into),
            detail: detail.map(Into::into),
        }
    }

    #[test]
    fn each_kind_reads_as_who_it_is() {
        let cases = [
            (
                principal(
                    PrincipalKind::User,
                    Some("Jane Doe"),
                    Some("jane@contoso.com"),
                ),
                ("User · Jane Doe", Some("jane@contoso.com")),
            ),
            (
                principal(PrincipalKind::SiteGroup, Some("Finance Members"), None),
                ("SharePoint group · Finance Members", None),
            ),
            (
                principal(PrincipalKind::Group, None, None),
                ("Group · id-1", None),
            ),
        ];
        for (p, (primary, secondary)) in cases {
            let (got, sub) = principal_label(&entry(vec![p]));
            assert_eq!(got, primary);
            assert_eq!(sub.as_deref(), secondary);
        }
    }

    #[test]
    fn a_sharing_link_names_its_recipients() {
        let (primary, secondary) = principal_label(&entry(vec![
            principal(PrincipalKind::SharingLink, None, Some("users, view")),
            principal(PrincipalKind::User, Some("Jane Doe"), None),
            principal(PrincipalKind::User, Some("Raj"), None),
        ]));
        assert_eq!(primary, "Sharing link · users, view");
        assert_eq!(secondary.as_deref(), Some("Sent to Jane Doe, Raj"));
    }

    #[test]
    fn an_entry_naming_nobody_is_unknown() {
        assert_eq!(principal_label(&entry(vec![])).0, "Unknown principal");
    }
}
