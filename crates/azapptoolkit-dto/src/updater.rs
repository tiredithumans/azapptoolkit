//! Auto-updater IPC DTOs — surfaced to the WASM front-end's update splash.

use serde::{Deserialize, Serialize};

/// A pending update, as returned by the updater check. `notes` is the release
/// changelog (the manifest's `notes` field, populated from `CHANGELOG.md` at
/// release time) — may be empty for older releases whose manifest predates it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub current_version: String,
    pub notes: String,
    pub pub_date: Option<String>,
}

/// Download progress emitted on the `updater-progress` channel while an update
/// installs. `total` is `None` until the server reports a content length.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProgress {
    pub downloaded: u64,
    pub total: Option<u64>,
}

/// Result of an update check. `Disabled` means no request was made: the
/// operator turned update checks off, or this install is updated by something
/// other than the in-app updater (see [`UpdatesDisabled`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum UpdateCheck {
    UpToDate,
    Available { info: UpdateInfo },
    Disabled { reason: UpdatesDisabled },
}

/// Why the in-app updater is off for this install. Decided in the backend
/// (`commands::updater::update_policy`) before any updater network call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UpdatesDisabled {
    /// `"auto_update": false` in settings.json, or `AZAPPTOOLKIT_AUTO_UPDATE=0`.
    Policy,
    /// A Windows Installer (MSI) deployment, updated by SCCM / Intune / GPO.
    Msi,
    /// A `.deb` / `.rpm` install, updated by the system package manager.
    SystemPackage,
}

impl UpdatesDisabled {
    /// Short label for the account-menu item that would otherwise offer a check.
    pub fn menu_label(&self) -> &'static str {
        match self {
            UpdatesDisabled::Policy => "Update checks turned off",
            UpdatesDisabled::Msi => "Updates managed by your MSI deployment",
            UpdatesDisabled::SystemPackage => "Updates managed by your package manager",
        }
    }

    /// One sentence saying why no in-app update is offered and where updates
    /// come from instead — written for the operator, shared by the backend
    /// error and the frontend toast / tooltip.
    pub fn description(&self) -> &'static str {
        match self {
            UpdatesDisabled::Policy => {
                "Update checks are turned off on this machine (AZAPPTOOLKIT_AUTO_UPDATE or \
                 \"auto_update\": false in settings.json)."
            }
            UpdatesDisabled::Msi => {
                "This is an MSI install. New versions come from your deployment tooling, \
                 not the in-app updater."
            }
            UpdatesDisabled::SystemPackage => {
                "This is a .deb/.rpm install. Update it with your system package manager."
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_check_wire_shapes_are_tagged_camel_case() {
        assert_eq!(
            serde_json::to_value(UpdateCheck::UpToDate).unwrap(),
            serde_json::json!({ "kind": "upToDate" })
        );
        assert_eq!(
            serde_json::to_value(UpdateCheck::Disabled {
                reason: UpdatesDisabled::Msi
            })
            .unwrap(),
            serde_json::json!({ "kind": "disabled", "reason": "msi" })
        );
        assert_eq!(
            serde_json::to_value(UpdatesDisabled::SystemPackage).unwrap(),
            serde_json::json!("systemPackage")
        );

        let available = serde_json::to_value(UpdateCheck::Available {
            info: UpdateInfo {
                version: "9.9.9".into(),
                current_version: "1.0.0".into(),
                notes: "notes".into(),
                pub_date: None,
            },
        })
        .unwrap();
        assert_eq!(available["kind"], "available");
        assert_eq!(available["info"]["version"], "9.9.9");
        match serde_json::from_value(available).unwrap() {
            UpdateCheck::Available { info } => {
                assert_eq!(info.version, "9.9.9");
                assert_eq!(info.current_version, "1.0.0");
            }
            other => panic!("expected Available, got {other:?}"),
        }
    }

    #[test]
    fn every_disabled_reason_explains_itself() {
        for reason in [
            UpdatesDisabled::Policy,
            UpdatesDisabled::Msi,
            UpdatesDisabled::SystemPackage,
        ] {
            assert!(!reason.menu_label().is_empty(), "{reason:?}");
            assert!(reason.description().ends_with('.'), "{reason:?}");
        }
    }
}
