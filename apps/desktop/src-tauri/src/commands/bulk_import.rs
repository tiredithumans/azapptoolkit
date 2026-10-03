//! Loads bulk-create specs from a file (F283): a CSV inventory export or the
//! page's own JSON array. The parsed specs only *fill the page's textarea* —
//! nothing is created here, and the operator still validates and runs them
//! through `bulk::bulk_create_applications` like a pasted array.
//!
//! The CSV column contract is documented in `docs/DEVELOPMENT.md` ("Bulk create
//! from a file"). The parsing is pure and lives apart from the dialog so it is
//! unit-testable.

use tauri::AppHandle;

use crate::dto::UiError;
use crate::dto::bulk::{BulkCreatePermission, BulkCreateSpec};
use crate::dto::permissions::PermissionKind;

/// Refuse anything larger before reading it: an inventory of thousands of apps
/// is a few hundred KiB, so a bigger file is the wrong file.
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// The CSV columns, matched case-insensitively. `DisplayName` is required.
const COLUMNS: &[&str] = &[
    "DisplayName",
    "SignInAudience",
    "Description",
    "Owners",
    "Permissions",
];

/// Opens a CSV or JSON file via the OS file dialog and parses it into
/// bulk-create specs. `None` if the user cancelled the dialog; a file that
/// does not parse is a `validation` error naming the row. Runs the dialog +
/// read on a blocking thread (Tauri 2: a sync command would freeze the
/// webview), like `backup::load_backup_from_file`.
#[tauri::command]
pub async fn load_bulk_create_specs_from_file(
    app_handle: AppHandle,
) -> Result<Option<Vec<BulkCreateSpec>>, UiError> {
    use tauri_plugin_dialog::DialogExt;
    tauri::async_runtime::spawn_blocking(move || {
        let chosen = app_handle
            .dialog()
            .file()
            .add_filter("CSV or JSON", &["csv", "json"])
            .blocking_pick_file();
        let Some(path) = chosen else {
            return Ok(None);
        };
        let path_buf = path
            .into_path()
            .map_err(|e| UiError::validation("invalid_path", e.to_string()))?;
        let size = std::fs::metadata(&path_buf)
            .map_err(|e| UiError::io(e.to_string()))?
            .len();
        if size > MAX_FILE_BYTES {
            return Err(UiError::validation(
                "invalid_bulk_file",
                format!("the file is {size} bytes; the limit is {MAX_FILE_BYTES}"),
            ));
        }
        let content = std::fs::read_to_string(&path_buf).map_err(|e| UiError::io(e.to_string()))?;
        let is_json = path_buf
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"));
        parse_bulk_create_file(&content, is_json)
            .map(Some)
            .map_err(|msg| UiError::validation("invalid_bulk_file", msg))
    })
    .await
    .map_err(|e| UiError::io(e.to_string()))?
}

/// Parses a bulk-create file. `is_json` comes from the extension; a file
/// without one is sniffed (a leading `[` is JSON).
pub(crate) fn parse_bulk_create_file(
    content: &str,
    is_json: bool,
) -> Result<Vec<BulkCreateSpec>, String> {
    // Our own CSV exports start with a UTF-8 BOM (Excel needs it), and so do
    // most spreadsheet "Save as CSV" files.
    let content = content.strip_prefix('\u{feff}').unwrap_or(content);
    let specs = if is_json || content.trim_start().starts_with('[') {
        serde_json::from_str::<Vec<BulkCreateSpec>>(content)
            .map_err(|e| format!("not a valid JSON array of apps: {e}"))?
    } else {
        parse_csv_specs(content)?
    };
    if specs.is_empty() {
        return Err("the file lists no apps".into());
    }
    Ok(specs)
}

fn parse_csv_specs(content: &str) -> Result<Vec<BulkCreateSpec>, String> {
    let mut records = parse_csv(content)?.into_iter();
    let header = records.next().ok_or("the file is empty")?;
    // Column index per entry of COLUMNS. An unknown column is an error rather
    // than ignored: a misspelt `Owner` would otherwise silently drop every
    // owner in the inventory.
    let mut index: [Option<usize>; COLUMNS.len()] = [None; COLUMNS.len()];
    for (i, name) in header.iter().enumerate() {
        let name = name.trim();
        let Some(col) = COLUMNS.iter().position(|c| c.eq_ignore_ascii_case(name)) else {
            return Err(format!(
                "unknown column \"{name}\" — expected {}",
                COLUMNS.join(", ")
            ));
        };
        if index[col].replace(i).is_some() {
            return Err(format!("column \"{}\" appears twice", COLUMNS[col]));
        }
    }
    let [
        Some(name_col),
        audience_col,
        description_col,
        owners_col,
        permissions_col,
    ] = index
    else {
        return Err("the DisplayName column is required".into());
    };

    let mut specs = Vec::new();
    // Row 1 is the header, so the first data row is row 2 — the number a
    // spreadsheet shows, as long as no cell spans lines.
    for (row, fields) in (2..).zip(records) {
        if fields.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        if fields.len() != header.len() {
            return Err(format!(
                "row {row} has {} fields; the header has {}",
                fields.len(),
                header.len()
            ));
        }
        let cell = |col: Option<usize>| {
            col.map(|i| fields[i].trim())
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        let permissions = match cell(permissions_col) {
            Some(raw) => list(&raw)
                .map(parse_permission)
                .collect::<Result<_, _>>()
                .map_err(|e| format!("row {row}: {e}"))?,
            None => Vec::new(),
        };
        specs.push(BulkCreateSpec {
            display_name: cell(Some(name_col)).unwrap_or_default(),
            sign_in_audience: cell(audience_col),
            description: cell(description_col),
            owner_upns: cell(owners_col)
                .map(|raw| list(&raw).map(str::to_string).collect())
                .unwrap_or_default(),
            permissions,
        });
    }
    Ok(specs)
}

/// A multi-value cell: `;`-separated, blanks dropped. `;` rather than `,` so
/// the cell needs no quoting in a hand-edited file.
fn list(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(';').map(str::trim).filter(|s| !s.is_empty())
}

/// One `Kind:Resource/Value` entry, e.g. `Application:Microsoft Graph/User.Read.All`.
/// The resource is an `appId` or a bundled-directory display name; whether it
/// and the value exist is checked live when the run validates.
fn parse_permission(entry: &str) -> Result<BulkCreatePermission, String> {
    let shape = || format!("permission \"{entry}\" is not Kind:Resource/Value");
    let (kind, rest) = entry.split_once(':').ok_or_else(shape)?;
    let (resource, value) = rest.split_once('/').ok_or_else(shape)?;
    let kind = match kind.trim().to_ascii_lowercase().as_str() {
        "application" | "role" => PermissionKind::Application,
        "delegated" | "scope" => PermissionKind::Delegated,
        other => {
            return Err(format!(
                "permission \"{entry}\": kind \"{other}\" must be Application or Delegated"
            ));
        }
    };
    let (resource, value) = (resource.trim(), value.trim());
    if resource.is_empty() || value.is_empty() {
        return Err(shape());
    }
    Ok(BulkCreatePermission {
        resource: resource.to_string(),
        value: value.to_string(),
        kind,
    })
}

/// RFC 4180 records: `,`-separated, `"`-quoted fields with `""` escapes,
/// quoted fields may span lines, CRLF or LF line ends.
fn parse_csv(content: &str) -> Result<Vec<Vec<String>>, String> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => in_quotes = false,
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() => in_quotes = true,
            ',' => record.push(std::mem::take(&mut field)),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            _ => field.push(c),
        }
    }
    if in_quotes {
        return Err("a quoted field is never closed".into());
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn perm(resource: &str, value: &str, kind: PermissionKind) -> BulkCreatePermission {
        BulkCreatePermission {
            resource: resource.into(),
            value: value.into(),
            kind,
        }
    }

    #[test]
    fn csv_with_every_column_parses_owners_and_permissions() {
        let csv = "\u{feff}DisplayName,SignInAudience,Description,Owners,Permissions\r\n\
                   App A,AzureADMyOrg,\"Payroll, legacy\",alice@contoso.com; bob@contoso.com,\
                   Application:Microsoft Graph/User.Read.All;delegated:00000003-0000-0000-c000-000000000000/openid\r\n";
        let specs = parse_bulk_create_file(csv, false).unwrap();
        assert_eq!(specs.len(), 1);
        let s = &specs[0];
        assert_eq!(s.display_name, "App A");
        assert_eq!(s.sign_in_audience.as_deref(), Some("AzureADMyOrg"));
        assert_eq!(s.description.as_deref(), Some("Payroll, legacy"));
        assert_eq!(s.owner_upns, ["alice@contoso.com", "bob@contoso.com"]);
        assert_eq!(
            s.permissions,
            [
                perm(
                    "Microsoft Graph",
                    "User.Read.All",
                    PermissionKind::Application
                ),
                perm(
                    "00000003-0000-0000-c000-000000000000",
                    "openid",
                    PermissionKind::Delegated
                ),
            ]
        );
    }

    #[test]
    fn csv_columns_are_case_insensitive_optional_and_blank_cells_are_none() {
        let csv = "displayname,description\nOnly name,\n\n\"Quoted \"\"name\"\"\",multi\nline\n";
        let specs = parse_bulk_create_file(csv, false).unwrap_err();
        // The unquoted newline splits the row: a short row is named, not padded.
        assert!(specs.contains("row 5"), "{specs}");

        let csv =
            "displayname,description\nOnly name,\n\n\"Quoted \"\"name\"\"\",\"multi\nline\"\n";
        let specs = parse_bulk_create_file(csv, false).unwrap();
        assert_eq!(specs.len(), 2, "the blank line is skipped");
        assert_eq!(specs[0].display_name, "Only name");
        assert_eq!(specs[0].description, None);
        assert_eq!(specs[0].sign_in_audience, None);
        assert!(specs[0].owner_upns.is_empty() && specs[0].permissions.is_empty());
        assert_eq!(specs[1].display_name, "Quoted \"name\"");
        assert_eq!(specs[1].description.as_deref(), Some("multi\nline"));
    }

    #[test]
    fn csv_header_mistakes_are_named() {
        let unknown = parse_bulk_create_file("DisplayName,Owner\nA,x@y\n", false).unwrap_err();
        assert!(unknown.contains("unknown column \"Owner\""), "{unknown}");
        let missing = parse_bulk_create_file("Description\nhi\n", false).unwrap_err();
        assert!(missing.contains("DisplayName"), "{missing}");
        let twice = parse_bulk_create_file("DisplayName,displayName\nA,B\n", false).unwrap_err();
        assert!(twice.contains("appears twice"), "{twice}");
        let empty = parse_bulk_create_file("DisplayName\n", false).unwrap_err();
        assert!(empty.contains("no apps"), "{empty}");
        let open = parse_bulk_create_file("DisplayName\n\"A\n", false).unwrap_err();
        assert!(open.contains("never closed"), "{open}");
    }

    #[test]
    fn a_malformed_permission_names_its_row() {
        for bad in [
            "User.Read.All",
            "Application:User.Read.All",
            "Admin:Microsoft Graph/User.Read.All",
            "Application: /User.Read.All",
        ] {
            let csv = format!("DisplayName,Permissions\nA,{bad}\n");
            let err = parse_bulk_create_file(&csv, false).unwrap_err();
            assert!(err.starts_with("row 2:"), "{bad}: {err}");
        }
        let csv = "DisplayName,Permissions\nA,Application:Microsoft Graph/x\nB,Admin:Graph/y\n";
        let err = parse_bulk_create_file(csv, false).unwrap_err();
        assert!(err.starts_with("row 3:") && err.contains("Application or Delegated"));
    }

    #[test]
    fn json_is_parsed_by_extension_or_sniffed_and_old_specs_still_load() {
        let json = r#"[{"displayName":"App A","signInAudience":"AzureADMyOrg"},
            {"displayName":"App B","ownerUpns":["a@b.c"],
             "permissions":[{"resource":"Microsoft Graph","value":"Mail.Send","kind":"application"}]}]"#;
        for is_json in [true, false] {
            let specs = parse_bulk_create_file(json, is_json).unwrap();
            assert_eq!(specs.len(), 2);
            assert!(specs[0].owner_upns.is_empty() && specs[0].permissions.is_empty());
            assert_eq!(specs[1].owner_upns, ["a@b.c"]);
            assert_eq!(
                specs[1].permissions,
                [perm(
                    "Microsoft Graph",
                    "Mail.Send",
                    PermissionKind::Application
                )]
            );
        }
        // A plain spec serializes without the new keys, so the textarea a
        // loaded file fills reads like the hand-typed form.
        let plain = serde_json::to_value(&parse_bulk_create_file(json, true).unwrap()[0]).unwrap();
        assert!(plain.get("ownerUpns").is_none() && plain.get("permissions").is_none());
        assert!(parse_bulk_create_file("[]", true).is_err());
        assert!(parse_bulk_create_file("{}", true).is_err());
    }
}
