//! The audit exporter: the save-file dialog command and the JSON/HTML/CSV
//! renderers plus the coverage header they share.

use std::fmt::Write;

use azapptoolkit_core::audit::{AuditItem, RiskLevel};
use azapptoolkit_core::cache::CacheKind;
use chrono::Utc;
use tauri::{AppHandle, State};

use crate::commands::export::{csv_field, write_via_dialog};
use crate::dto::UiError;
use crate::dto::audit::{AuditCoverageGap, AuditExportCoverage, MAILBOX_SCOPING_UNRESOLVED};
use crate::state::AppState;

use super::cache::{CachedAuditRun, audit_cache_key};

/// Opens the OS save-file dialog and writes the audit in the requested
/// `format` (`csv`, `json`, or `html`) to the chosen path. Returns the path,
/// or `None` if the user cancelled. Exports **by reference**: with
/// `items: None` the backend serves its own cached run, so the multi-MB item
/// vector never round-trips the IPC bridge; any run the backend did not
/// cache (cancelled, truncated or degraded — see `run_is_cacheable`) passes
/// its items explicitly, since the cache holds nothing for it or, worse, an
/// earlier complete run that would be exported in its place.
///
/// `coverage` describes the run those explicit items came from, and every
/// writer opens with it: the exported file is the artifact that leaves the app,
/// so it has to carry the same caveats the workbench refuses to omit. It is
/// read **only** on the explicit-items path — a run served from the cache is
/// complete by construction (`run_is_cacheable`), and the backend describes it
/// from the entry itself rather than from what the webview claims about it.
#[tauri::command]
pub async fn save_audit_to_file(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    items: Option<Vec<AuditItem>>,
    coverage: AuditExportCoverage,
    format: String,
) -> Result<Option<String>, UiError> {
    // This can answer entirely from the tenant cache and then WRITE the result to
    // a user-chosen path, so an unproven `tenant_id` would make a cross-tenant
    // leak persistent on disk. Prove the session before either branch.
    crate::commands::session::prove_tenant_session(&state, &tenant_id)?;
    let (items, coverage): (Vec<AuditItem>, AuditExportCoverage) = match items {
        Some(items) => (items, coverage),
        None => {
            let run = state
                .cache
                .get_typed::<CachedAuditRun>(CacheKind::Audit, &audit_cache_key(&tenant_id))
                .ok_or_else(|| {
                    UiError::validation(
                        "no_cached_audit",
                        "no cached audit to export — run the audit again",
                    )
                })?;
            let coverage = cached_run_coverage(&run);
            (run.items.clone(), coverage)
        }
    };
    let (content, ext, filter_name) = match format.as_str() {
        "csv" => (export_audit_csv(items, &coverage), "csv", "CSV"),
        "json" => (audit_to_json(&items, &coverage)?, "json", "JSON"),
        "html" => (audit_to_html(&items, &coverage), "html", "HTML"),
        other => {
            return Err(UiError::validation(
                "unsupported_format",
                format!("unsupported export format: {other}"),
            ));
        }
    };
    let default_name = format!("audit-{}.{ext}", chrono::Utc::now().format("%Y%m%dT%H%M%S"));
    write_via_dialog(app_handle, filter_name, ext, default_name, content).await
}

/// How a cached run describes itself to the exporter.
///
/// Never taken from the webview: `run_is_cacheable` admits only a complete,
/// undegraded scan, so those three flags are known here — and the entry's own
/// stamp is the authority for when the items it holds were produced. Report
/// availability is reconstructed from the items exactly as `get_cached_audit`
/// does it.
fn cached_run_coverage(run: &CachedAuditRun) -> AuditExportCoverage {
    AuditExportCoverage {
        total_apps: run.items.len(),
        cancelled: false,
        truncated: false,
        degraded: Vec::new(),
        sign_in_report_available: run.items.iter().any(|i| i.sign_in_report_available),
        completed_at: Some(run.completed_at.clone()),
        // The one caveat a cacheable run can still carry.
        mailbox_scoping_resolved: run.mailbox_scoping_resolved,
    }
}

/// The run's coverage as plain sentences — one per caveat, none when the scan
/// was complete.
///
/// Deliberately the **same wording** the Security workbench uses (the posture
/// strip's cancelled, truncated and degraded callouts): an operator who read the caveat on screen must recognize it
/// in the file, and a second set of words would eventually drift into a milder
/// claim. `scored` is the exported item count, so the fraction is always about
/// the rows actually in this file.
fn coverage_sentences(scored: usize, coverage: &AuditExportCoverage) -> Vec<String> {
    let mut out = Vec::new();
    if coverage.cancelled {
        out.push(format!(
            "This scan was cancelled early — {scored} of {total} principals were scored. \
             Everything below covers only those; re-run for full coverage.",
            total = coverage.total_apps,
        ));
    }
    if coverage.truncated {
        out.push(
            "The tenant holds more app registrations than one run scores, so this scan \
             covered an arbitrary prefix of them. This is not an all-clear, and re-running \
             will not extend it."
                .to_string(),
        );
    }
    if !coverage.degraded.is_empty() {
        out.push(
            "Part of this scan could not run — treat the results as incomplete and re-run."
                .to_string(),
        );
    }
    if !coverage.sign_in_report_available {
        out.push(
            "Unused-app detection was off for this run — it needs the sign-in activity report \
             (AuditLog.Read.All and Entra ID P1/P2), so no application here could be flagged \
             unused."
                .to_string(),
        );
    }
    if !coverage.mailbox_scoping_resolved {
        out.push(MAILBOX_SCOPING_UNRESOLVED.to_string());
    }
    out
}

/// Per-level counts over the exported rows, highest severity first — the
/// summary an auditor reads before the table.
pub(crate) fn severity_summary(items: &[AuditItem]) -> [(&'static str, usize); 4] {
    let count = |level: RiskLevel| items.iter().filter(|i| i.risk_level == level).count();
    [
        ("Critical", count(RiskLevel::Critical)),
        ("High", count(RiskLevel::High)),
        ("Medium", count(RiskLevel::Medium)),
        ("Low", count(RiskLevel::Low)),
    ]
}

/// Serializes the audit as pretty-printed JSON: the run's coverage as
/// top-level fields, its rows under `items`. Propagates a serialize error
/// instead of writing an empty `"[]"` file — a silent empty export reads as
/// "nothing to report" rather than "the export failed".
///
/// The rows keep the shape they always had (`AuditItem`, verbatim), so a
/// consumer only has to reach one level deeper for them — and now cannot read
/// a partial scan as a full one.
pub(crate) fn audit_to_json(
    items: &[AuditItem],
    coverage: &AuditExportCoverage,
) -> Result<String, UiError> {
    #[derive(serde::Serialize)]
    struct Export<'a> {
        generated_at: String,
        completed_at: Option<&'a str>,
        scored: usize,
        total_apps: usize,
        complete: bool,
        cancelled: bool,
        truncated: bool,
        degraded: &'a [AuditCoverageGap],
        sign_in_report_available: bool,
        mailbox_scoping_resolved: bool,
        /// The caveat sentences, so a consumer that renders the file doesn't
        /// have to re-derive the prose from the flags above.
        coverage_notes: Vec<String>,
        items: &'a [AuditItem],
    }
    let export = Export {
        generated_at: Utc::now().to_rfc3339(),
        completed_at: coverage.completed_at.as_deref(),
        scored: items.len(),
        total_apps: coverage.total_apps,
        complete: coverage.is_complete(),
        cancelled: coverage.cancelled,
        truncated: coverage.truncated,
        degraded: &coverage.degraded,
        sign_in_report_available: coverage.sign_in_report_available,
        mailbox_scoping_resolved: coverage.mailbox_scoping_resolved,
        coverage_notes: coverage_sentences(items.len(), coverage),
        items,
    };
    serde_json::to_string_pretty(&export).map_err(|e| UiError::serde(e.to_string()))
}

/// Renders a standalone HTML report — a coverage header, a severity summary,
/// then a styled table of the key audit columns.
pub(crate) fn audit_to_html(items: &[AuditItem], coverage: &AuditExportCoverage) -> String {
    let mut rows = String::new();
    for item in items {
        let _ = write!(
            rows,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            html_escape(&item.application_name),
            html_escape(&item.app_id),
            item.risk_score,
            html_escape(item.risk_level.as_str()),
            html_escape(item.credential_status.as_str()),
            html_escape(&item.issues.join("; ")),
        );
    }

    // Coverage first, above everything it qualifies. The old header said
    // "N application(s) — generated <timestamp>" and nothing else, so a
    // cancelled run's export — the one export that ships items the cache
    // refuses to hold — read exactly like a clean full scan.
    let mut header = format!(
        "<p class=\"coverage\">{scored} of {total} principal(s) scored — scanned {scanned}, \
         exported {generated}</p>",
        scored = items.len(),
        // `max` only so the fraction can never read "14 of 0": the denominator
        // is what the run set out to score, which is >= what it scored.
        total = coverage.total_apps.max(items.len()),
        scanned = html_escape(coverage.completed_at.as_deref().unwrap_or("unknown")),
        generated = html_escape(&Utc::now().to_rfc3339()),
    );
    for sentence in coverage_sentences(items.len(), coverage) {
        let _ = write!(header, "<p class=\"caveat\">{}</p>", html_escape(&sentence));
    }
    if !coverage.degraded.is_empty() {
        header.push_str("<ul class=\"caveat\">");
        for gap in &coverage.degraded {
            let _ = write!(header, "<li>{}</li>", html_escape(gap.description()));
        }
        header.push_str("</ul>");
    }
    let summary: String = severity_summary(items)
        .iter()
        .map(|(label, n)| format!("<li><b>{n}</b> {label}</li>"))
        .collect();

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<title>azapptoolkit Security Audit</title>\
<style>body{{font-family:system-ui,sans-serif;margin:2rem}}\
table{{border-collapse:collapse;width:100%}}\
th,td{{border:1px solid #ccc;padding:6px 8px;text-align:left;font-size:14px;vertical-align:top}}\
th{{background:#f3f3f3}}\
p.coverage{{color:#444;font-size:14px}}\
.caveat{{background:#fff4e5;border-left:4px solid #d97706;padding:8px 12px;font-size:14px}}\
ul.severities{{list-style:none;display:flex;gap:1.5rem;padding:0;margin:1rem 0;font-size:14px}}\
</style></head>\
<body><h1>Security Audit</h1>{header}\
<ul class=\"severities\">{summary}</ul>\
<table><thead><tr><th>Application</th><th>App ID</th><th>Risk score</th>\
<th>Level</th><th>Credentials</th><th>Issues</th></tr></thead>\
<tbody>{rows}</tbody></table></body></html>",
        header = header,
        summary = summary,
        rows = rows,
    )
}

pub(crate) fn html_escape(s: &str) -> String {
    // `'` included for completeness: every interpolation today is element
    // text content (where &<> suffice), but the export opens outside the app
    // CSP, so a future single-quoted attribute must not become an injection.
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Serializes a set of [`AuditItem`]s as CSV.
///
/// An internal helper, not an IPC command: `save_audit_to_file` is the only
/// caller and the only way the frontend exports an audit. It was registered as
/// a command "so callers that want the text don't need a save dialog", but no
/// such caller was ever written — leaving an unreachable entry point on the IPC
/// boundary.
pub(crate) fn export_audit_csv(items: Vec<AuditItem>, coverage: &AuditExportCoverage) -> String {
    let mut out = String::new();
    // A leading `#` comment block — the convention every CSV reader worth using
    // can skip (`pandas.read_csv(comment='#')`, `read.csv(comment.char='#')`) —
    // so the coverage travels with the rows without touching the column layout
    // downstream tooling parses. Written raw rather than through `csv_field`
    // because nothing here is directory data: the counts are integers, the
    // timestamp is our own RFC3339 stamp, and the sentences and gap
    // descriptions are `&'static str`s from this binary.
    let _ = writeln!(
        out,
        "# azapptoolkit security audit — {scored} of {total} principal(s) scored",
        scored = items.len(),
        total = coverage.total_apps.max(items.len()),
    );
    let _ = writeln!(
        out,
        "# Scan completed: {}",
        coverage.completed_at.as_deref().unwrap_or("unknown")
    );
    let _ = writeln!(out, "# Exported: {}", Utc::now().to_rfc3339());
    for (label, n) in severity_summary(&items) {
        let _ = writeln!(out, "# {label}: {n}");
    }
    if coverage.is_complete() {
        out.push_str("# Coverage: complete\n");
    }
    for sentence in coverage_sentences(items.len(), coverage) {
        let _ = writeln!(out, "# {sentence}");
    }
    for gap in &coverage.degraded {
        let _ = writeln!(out, "# - {}", gap.description());
    }
    out.push_str("ApplicationName,AppId,ObjectId,CreatedDate,Publisher,SignInAudience,RiskScore,RiskLevel,CredentialStatus,PermissionCount,DaysSinceCreated,ServicePrincipalEnabled,Issues,Recommendations,PrincipalKind,AppOwnerOrgId\n");
    for item in items {
        let row = [
            csv_field(&item.application_name),
            csv_field(&item.app_id),
            csv_field(&item.object_id),
            csv_field(
                &item
                    .created_date
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default(),
            ),
            csv_field(item.publisher.as_deref().unwrap_or("")),
            csv_field(item.sign_in_audience.as_deref().unwrap_or("")),
            item.risk_score.to_string(),
            csv_field(item.risk_level.as_str()),
            csv_field(item.credential_status.as_str()),
            item.permission_count.to_string(),
            item.days_since_created
                .map(|d| d.to_string())
                .unwrap_or_default(),
            item.service_principal_enabled
                .map(|b| b.to_string())
                .unwrap_or_default(),
            csv_field(&item.issues.join("; ")),
            csv_field(&item.recommendations.join("; ")),
            csv_field(item.principal_kind.as_str()),
            // Appended last, like PrincipalKind, so positional parsers keep
            // working. Named as in the Enterprise Applications export.
            csv_field(item.app_owner_organization_id.as_deref().unwrap_or("")),
        ]
        .join(",");
        out.push_str(&row);
        out.push('\n');
    }
    out
}
