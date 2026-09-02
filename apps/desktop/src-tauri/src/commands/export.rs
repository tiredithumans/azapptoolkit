//! Shared file-export plumbing for every inventory/report export command:
//! CSV field encoding (with the formula-injection guard) and the save-dialog +
//! write pipeline. Extracted from `commands::audit`, which seven other domains
//! were importing it from — the per-domain `*_to_csv` serializers stay with
//! their domains; only the generic pieces live here.

use tauri::AppHandle;

use crate::dto::UiError;

pub(crate) fn csv_field(s: &str) -> String {
    // Formula-injection guard (CWE-1236): a field beginning with one of these
    // characters is interpreted as a formula by Excel / Sheets when the CSV is
    // opened. App display names are attacker-controllable, so prefix such a
    // value with a single quote to force it to be treated as text.
    let neutralized = match s.chars().next() {
        Some('=' | '+' | '-' | '@' | '\t' | '\r') => {
            let mut out = String::with_capacity(s.len() + 1);
            out.push('\'');
            out.push_str(s);
            std::borrow::Cow::Owned(out)
        }
        _ => std::borrow::Cow::Borrowed(s),
    };
    if neutralized.contains(',') || neutralized.contains('"') || neutralized.contains('\n') {
        let escaped = neutralized.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        neutralized.into_owned()
    }
}

/// Shared "export to CSV/JSON via the OS save dialog" plumbing for the inventory
/// list exports. Picks the serializer by `format`, opens the save dialog with a
/// timestamped default name (`{default_stem}-YYYYMMDDThhmmss.{ext}`), and writes
/// the file. Returns the chosen path, or `None` if the user cancelled. The
/// serializers are closures so each list can pass its own column layout while
/// sharing the format-match / dialog / write boilerplate.
pub(crate) async fn save_export_via_dialog(
    app_handle: &AppHandle,
    default_stem: &str,
    format: &str,
    to_csv: impl FnOnce() -> String,
    to_json: impl FnOnce() -> String,
) -> Result<Option<String>, UiError> {
    let (content, ext, filter_name) = match format {
        "csv" => (to_csv(), "csv", "CSV"),
        "json" => (to_json(), "json", "JSON"),
        other => {
            return Err(UiError::validation(
                "unsupported_format",
                format!("unsupported export format: {other}"),
            ));
        }
    };
    let default_name = format!(
        "{default_stem}-{}.{ext}",
        chrono::Utc::now().format("%Y%m%dT%H%M%S")
    );
    write_via_dialog(app_handle.clone(), filter_name, ext, default_name, content).await
}

/// Save dialog + file write on a blocking thread. In Tauri 2 a *synchronous*
/// command executes on the main thread, where `blocking_save_file` plus a
/// multi-MB `std::fs::write` froze the whole webview until the write finished
/// — every file-export command rides this instead. (Kept separate from
/// [`save_export_via_dialog`]: callers with prebuilt single-format content —
/// the CSV report exports — enter here directly.)
///
/// Text callers use [`write_via_dialog`] below; this one takes bytes because
/// the generated certificate's PKCS#12 bundle is binary and any text round-trip
/// would corrupt it. Both end at the same `write_owner_only`, so the choke
/// point stays one place.
pub(crate) async fn write_bytes_via_dialog(
    app_handle: AppHandle,
    filter_name: &'static str,
    ext: &'static str,
    default_name: String,
    content: Vec<u8>,
) -> Result<Option<String>, UiError> {
    use tauri_plugin_dialog::DialogExt;
    tauri::async_runtime::spawn_blocking(move || {
        let chosen = app_handle
            .dialog()
            .file()
            .add_filter(filter_name, &[ext])
            .set_file_name(&default_name)
            .blocking_save_file();
        let Some(path) = chosen else {
            return Ok(None);
        };
        let path_buf = path
            .into_path()
            .map_err(|e| UiError::validation("invalid_path", e.to_string()))?;
        // Owner-only. This is the single choke point for every file the app
        // writes, and what goes through it is not neutral: a restore report
        // carries plaintext show-once client secrets, a generated certificate's
        // .pfx carries a private key, a backup manifest is the whole app
        // estate, and an export is directory data. Under the process umask
        // these landed world-readable on a shared machine. It does not stop the
        // operator sharing a file deliberately — only the default changes.
        // (No-op on Windows, which has no mode bits; see the helper.)
        azapptoolkit_core::private_file::write_owner_only(&path_buf, &content)
            .map_err(|e| UiError::io(e.to_string()))?;
        Ok(Some(path_buf.display().to_string()))
    })
    .await
    .map_err(|e| UiError::io(e.to_string()))?
}

/// [`write_bytes_via_dialog`] for the text exports — every CSV/JSON caller.
/// `into_bytes` is a move, not a copy.
pub(crate) async fn write_via_dialog(
    app_handle: AppHandle,
    filter_name: &'static str,
    ext: &'static str,
    default_name: String,
    content: String,
) -> Result<Option<String>, UiError> {
    write_bytes_via_dialog(
        app_handle,
        filter_name,
        ext,
        default_name,
        content.into_bytes(),
    )
    .await
}

/// CSV-only export: format guard + timestamped filename + save dialog.
///
/// The three report exports (delegated grants, app-permission grants, credential
/// expirations) each hand-rolled the same preamble — reject any format that
/// isn't `csv`, stamp `stem-YYYYMMDDTHHMMSS.csv`, hand off to
/// [`write_via_dialog`]. Note this does NOT re-point them at
/// [`save_export_via_dialog`]: that one owns the multi-format (JSON/CSV) picker,
/// whereas these callers have prebuilt single-format content, which is exactly
/// the case `write_via_dialog` documents itself as the entry point for.
///
/// `to_csv` is lazy so an unsupported format costs nothing to reject.
pub(crate) async fn save_csv_via_dialog(
    app_handle: AppHandle,
    stem: &'static str,
    format: &str,
    to_csv: impl FnOnce() -> String,
) -> Result<Option<String>, UiError> {
    if format != "csv" {
        return Err(UiError::validation(
            "unsupported_format",
            format!("unsupported export format: {format}"),
        ));
    }
    let default_name = format!("{stem}-{}.csv", chrono::Utc::now().format("%Y%m%dT%H%M%S"));
    write_via_dialog(app_handle, "CSV", "csv", default_name, to_csv()).await
}

/// The leading `#` comment block that carries an export's coverage into the CSV
/// itself: a title line, the panel's own summary sentence, and the export
/// timestamp.
///
/// `#` is the convention every CSV reader worth using can skip
/// (`pandas.read_csv(comment='#')`, `read.csv(comment.char='#')`), so the caveat
/// travels with the rows without touching the column layout downstream tooling
/// parses — the same choice `export_audit_csv` made, and the same reason.
///
/// `summary` is written **verbatim**, never re-derived. It is the sentence the
/// operator read on screen ("scanned 140 of 142 sites (2 failed — coverage is
/// partial)"), and the reverse lookups' whole discipline is that they never
/// overstate coverage; a file that re-phrased it would eventually drift into a
/// milder claim than the panel made. Written raw rather than through
/// [`csv_field`] because none of it is directory data: the title is a
/// `&'static str` from this binary, the summary is composed from the sweep's own
/// counts, and the stamp is our own RFC3339.
pub(crate) fn coverage_comment_block(title: &str, summary: &str) -> String {
    let mut out = format!("# {title}\n");
    // A blank summary is a caller that lost its coverage line, not a clean bill
    // of health — say so rather than shipping a file that reads as complete.
    if summary.trim().is_empty() {
        out.push_str("# Coverage: not stated by the exporting view — treat as incomplete\n");
    } else {
        out.push_str(&format!("# {}\n", summary.trim()));
    }
    out.push_str(&format!(
        "# Exported: {}\n",
        chrono::Utc::now().to_rfc3339()
    ));
    out
}

/// [`coverage_comment_block`]'s JSON counterpart: the rows under `rows`, with
/// the coverage sentence and an export stamp as top-level fields.
///
/// Same shape as the audit's JSON export — coverage first, rows verbatim
/// underneath — so a consumer that already reads one reads the other, and
/// neither can be mistaken for a bare row array whose completeness is unstated.
/// A serialize failure surfaces as an object saying so rather than as `[]`,
/// which would read as "nothing to report".
pub(crate) fn coverage_json<T: serde::Serialize>(summary: &str, rows: &[T]) -> String {
    #[derive(serde::Serialize)]
    struct Export<'a, T> {
        generated_at: String,
        coverage: &'a str,
        rows: &'a [T],
    }
    let export = Export {
        generated_at: chrono::Utc::now().to_rfc3339(),
        coverage: summary,
        rows,
    };
    serde_json::to_string_pretty(&export).unwrap_or_else(|e| {
        serde_json::json!({ "error": format!("export serialization failed: {e}") }).to_string()
    })
}

/// Column count of one CSV line — commas **outside** quotes only.
///
/// A test helper, shared so the per-domain export tests all prove alignment the
/// same way. Counting raw commas is the obvious mistake and a silently wrong
/// one: several real fields carry commas of their own (a Graph site id is
/// literally `hostname,siteId,webId`), and those are quoted, not escaped away.
#[cfg(test)]
pub(crate) fn csv_columns(line: &str) -> usize {
    let mut in_quotes = false;
    let mut columns = 1;
    for c in line.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => columns += 1,
            _ => {}
        }
    }
    columns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_columns_ignores_commas_inside_a_quoted_field() {
        assert_eq!(csv_columns("a,b,c"), 3);
        assert_eq!(csv_columns("a,\"b,still b\",c"), 3);
        assert_eq!(csv_columns(""), 1);
    }

    #[test]
    fn coverage_json_states_its_coverage_alongside_the_rows() {
        let json = coverage_json(
            "scanned 9 of 11 vaults (2 failed — coverage is partial)",
            &[1, 2],
        );
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(
            v["coverage"]
                .as_str()
                .unwrap()
                .contains("coverage is partial")
        );
        assert_eq!(v["rows"].as_array().unwrap().len(), 2);
        assert!(v["generated_at"].is_string());
    }

    #[test]
    fn coverage_block_carries_the_panels_own_sentence_verbatim() {
        let block = coverage_comment_block(
            "azapptoolkit — sites this app can reach",
            "12 app grants across 4 sites — scanned 140 of 142 sites (2 failed — coverage is partial)",
        );
        let lines: Vec<&str> = block.lines().collect();
        assert!(lines.iter().all(|l| l.starts_with('#')));
        assert_eq!(
            lines[1],
            "# 12 app grants across 4 sites — scanned 140 of 142 sites (2 failed — coverage is partial)",
        );
    }

    #[test]
    fn a_missing_coverage_line_reads_as_incomplete_not_as_clean() {
        // The honest failure direction: an export whose view forgot its summary
        // must not be indistinguishable from one with full coverage.
        let block = coverage_comment_block("azapptoolkit — mailbox reachers", "  ");
        assert!(block.contains("treat as incomplete"));
    }

    #[test]
    fn csv_field_quotes_delimiters_and_doubles_quotes() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("a\"b"), "\"a\"\"b\"");
        assert_eq!(csv_field("line1\nline2"), "\"line1\nline2\"");
    }

    #[test]
    fn csv_field_neutralizes_formula_injection() {
        assert_eq!(csv_field("=SUM(A1)"), "'=SUM(A1)");
        assert_eq!(csv_field("+1"), "'+1");
        assert_eq!(csv_field("-1"), "'-1");
        assert_eq!(csv_field("@cmd"), "'@cmd");
        // Neutralization composes with quoting when delimiters are present.
        assert_eq!(csv_field("=a,b"), "\"'=a,b\"");
        // A leading quote-needing char inside an ordinary name is untouched.
        assert_eq!(csv_field("a=b"), "a=b");
    }
}
