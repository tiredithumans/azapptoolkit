//! Per-tenant operator defaults (default owners, SSO notification emails,
//! management-scope-name pattern) read/written from the Settings page. Persisted
//! in `settings.json` alongside the first-run config, using the same
//! read-modify-write pattern as `commands::config` so untouched fields survive.
//!
//! `set_tenant_defaults` intentionally manages only the operator-editable fields;
//! the vault bindings on [`TenantDefaults`] are preserved as-is (they're owned by
//! the credential-rotation flow — see [`UserSettings::apply_tenant_defaults`]).

use azapptoolkit_core::defaults::TenantDefaults;
use azapptoolkit_core::settings::UserSettings;

use crate::dto::UiError;

/// Reads the saved defaults for `tenant_id` (an empty set if none exist).
/// Infallible: a missing/unparseable file falls back to defaults.
#[tauri::command]
pub fn get_tenant_defaults(tenant_id: String) -> TenantDefaults {
    UserSettings::stored(&crate::config_directory()).defaults_for(&tenant_id)
}

/// Persists the operator-editable defaults for `tenant_id`, preserving every
/// other setting (and this tenant's vault bindings). Validates the SSO
/// notification-email list (max 5, each must contain `@`).
#[tauri::command]
pub fn set_tenant_defaults(tenant_id: String, defaults: TenantDefaults) -> Result<(), UiError> {
    let tenant_id = tenant_id.trim().to_string();
    if tenant_id.is_empty() {
        return Err(UiError::validation(
            "invalid_tenant",
            "A tenant must be selected to save defaults.",
        ));
    }

    let mut defaults = defaults;
    defaults.enterprise_application.default_notification_emails =
        sanitize_emails(&defaults.enterprise_application.default_notification_emails)?;
    // A blank pattern is stored as "unset" so it falls back to the built-in default.
    defaults.scope_name_pattern = defaults
        .scope_name_pattern
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty());

    let config_dir = crate::config_directory();
    let mut settings = UserSettings::stored(&config_dir);
    settings.apply_tenant_defaults(&tenant_id, defaults);
    settings
        .save(&config_dir)
        .map_err(|e| UiError::io(format!("Could not write settings.json: {e}")))?;
    Ok(())
}

/// Trims, drops blanks, case-insensitively dedupes, requires `@`, caps at 5 —
/// mirroring `commands::sso::sanitize_notification_emails` so a saved default is
/// always a valid seed for the live SSO field.
fn sanitize_emails(emails: &[String]) -> Result<Vec<String>, UiError> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for raw in emails {
        let e = raw.trim();
        if e.is_empty() {
            continue;
        }
        if !e.contains('@') {
            return Err(UiError::validation(
                "invalid_email",
                format!("\"{e}\" is not a valid email address."),
            ));
        }
        if seen.insert(e.to_ascii_lowercase()) {
            out.push(e.to_string());
        }
    }
    if out.len() > 5 {
        return Err(UiError::validation(
            "too_many_emails",
            "At most 5 notification email addresses can be set.",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_trims_dedupes_and_requires_at() {
        let out = sanitize_emails(&[
            "  a@x.com ".into(),
            "A@X.com".into(), // case-insensitive dup
            "".into(),
        ])
        .unwrap();
        assert_eq!(out, vec!["a@x.com".to_string()]);

        assert!(sanitize_emails(&["nope".into()]).is_err());
        let six: Vec<String> = (0..6).map(|i| format!("u{i}@x.com")).collect();
        assert!(sanitize_emails(&six).is_err());
    }
}
