//! Permission-tester IPC bindings — "App → resource" effective-access checks
//! against a specific Exchange mailbox or SharePoint site.

use azapptoolkit_dto::UiError;
use serde::Serialize;
use tauri_sys::core::invoke_result;

pub use azapptoolkit_dto::permission_tester::{
    MailboxProbeProgress, MailboxReacherRow, MailboxReachersResult, PermissionTestResult,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MailboxArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
    mailbox: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReachersArgs<'a> {
    tenant_id: &'a str,
    mailbox: &'a str,
}

/// The mailbox reverse lookup: every service principal holding a mail-scopable
/// Graph application permission, probed against `mailbox` (long-running;
/// progress arrives via the `mailbox-probe-progress` event stream).
pub async fn find_mailbox_reachers(
    tenant_id: &str,
    mailbox: &str,
) -> Result<MailboxReachersResult, UiError> {
    invoke_result("find_mailbox_reachers", ReachersArgs { tenant_id, mailbox }).await
}

pub async fn test_mailbox_access(
    tenant_id: &str,
    app_id: &str,
    mailbox: &str,
) -> Result<PermissionTestResult, UiError> {
    invoke_result(
        "test_mailbox_access",
        MailboxArgs {
            tenant_id,
            app_id,
            mailbox,
        },
    )
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SiteArgs<'a> {
    tenant_id: &'a str,
    app_id: &'a str,
    site_url: &'a str,
}

pub async fn test_site_access(
    tenant_id: &str,
    app_id: &str,
    site_url: &str,
) -> Result<PermissionTestResult, UiError> {
    invoke_result(
        "test_site_access",
        SiteArgs {
            tenant_id,
            app_id,
            site_url,
        },
    )
    .await
}

// ---------------- Mailbox-reacher export ----------------

/// The panel's own summary sentence rides along with the rows: an `unknown`
/// verdict means an Exchange check couldn't be evaluated, and an Exchange
/// outage leaves the verdicts deriving from Entra grants alone. Both caveats
/// are on screen and both must reach the file.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SaveMailboxReachersArgs<'a> {
    rows: &'a [MailboxReacherRow],
    summary: &'a str,
    format: &'a str,
}

/// Exports the (filtered) mailbox-reacher rows to a CSV/JSON file via the OS
/// save dialog. Returns the chosen path, or `None` if the user cancelled.
pub async fn save_mailbox_reachers_to_file(
    rows: &[MailboxReacherRow],
    summary: &str,
    format: &str,
) -> Result<Option<String>, UiError> {
    invoke_result(
        "save_mailbox_reachers_to_file",
        SaveMailboxReachersArgs {
            rows,
            summary,
            format,
        },
    )
    .await
}
