//! The manifest checks a restore runs before it touches the tenant (schema
//! version, source-appId shape), and the bounds on every value it echoes back
//! into the plan and the report.

use std::collections::HashMap;

use crate::dto::UiError;
use crate::dto::backup::{
    BACKUP_SCHEMA_VERSION, ManualItem, RegeneratedSecret, RestoreFailure, RestoreReport,
    RestoredApp, RestoredEnterpriseApp, RestoredManagedIdentity, SchemaTooNew, TenantBackup,
};

/// Refuses a manifest written by a *newer* build.
///
/// A restore is not a read — it mutates the tenant before anyone can inspect
/// the result — so a manifest carrying fields this build cannot interpret has
/// to be rejected rather than partially applied. `schema_version` exists for
/// exactly this refusal and was never checked.
///
/// Only the future direction is rejected: every field is `serde(default)` and
/// additive, so an older manifest restores correctly, and refusing one would
/// break the DR case the format was versioned to support. Loading a backup
/// file that fails to parse uses it too (`backup::read_backup_file`): its
/// unreadable new fields are what failed.
pub(in crate::commands) fn check_manifest_schema(schema_version: u32) -> Result<(), UiError> {
    if schema_too_new(schema_version).is_some() {
        return Err(UiError::validation(
            "schema_too_new",
            format!(
                "backup uses manifest schema version {schema_version} but this build understands \
                 up to {BACKUP_SCHEMA_VERSION}. Restoring it could silently skip settings it does \
                 not recognise — update azapptoolkit first."
            ),
        ));
    }
    Ok(())
}

/// The one schema rule, shared by the dry-run blocker and the restore's own
/// refusal: only a manifest from a *newer* build is refused.
pub(super) fn schema_too_new(schema_version: u32) -> Option<SchemaTooNew> {
    (schema_version > BACKUP_SCHEMA_VERSION).then_some(SchemaTooNew {
        manifest_version: schema_version,
        supported_version: BACKUP_SCHEMA_VERSION,
    })
}

/// How many manifest problems are named individually; the rest are counted.
/// A hostile file can repeat one id thousands of times, and the plan has to
/// stay readable.
pub(super) const MAX_MANIFEST_PROBLEMS: usize = 10;

/// Refuses a manifest whose app registrations are not individually addressable.
///
/// `source_app_id` is the key every pass hangs off: the restore tag
/// (`azapptoolkit:restoredFrom:<id>`), the adoption lookup and the
/// `source → new` remap. A repeated id makes Pass 1 adopt the app it has just
/// created for the first copy and wire it twice (two sets of fresh secrets); an
/// empty one tags the app with a bare prefix every other empty-id app shares.
/// Neither is a shape a real backup produces, so the file is refused whole
/// rather than partially restored. A managed identity's `source_app_id` is
/// held to the same rule: with its kind, it is the plan's approval key.
pub(super) fn validate_manifest(backup: &TenantBackup) -> Result<(), UiError> {
    let problems = manifest_problems(backup);
    if problems.is_empty() {
        return Ok(());
    }
    Err(UiError::validation(
        "invalid_manifest",
        format!(
            "backup file is not a valid manifest: {}. Nothing was restored.",
            problems.join("; ")
        ),
    ))
}

/// The one manifest-shape rule, shared by the dry-run blocker and the
/// restore's own refusal: every app registration's and every managed
/// identity's `source_app_id` is a GUID, and no two of a kind share one
/// (compared case-insensitively, as Entra does). A managed identity's id is
/// its approval key, so a repeated one would let one opt-in cover two.
pub(super) fn manifest_problems(backup: &TenantBackup) -> Vec<String> {
    let mut problems = Vec::new();
    let apps = backup
        .app_registrations
        .iter()
        .map(|a| (a.source_app_id.as_str(), a.display_name.as_str()));
    id_problems("app registration", "source appId", apps, &mut problems);
    let mis = backup
        .managed_identities
        .iter()
        .map(|m| (m.source_app_id.as_str(), m.display_name.as_str()));
    id_problems(
        "managed identity",
        "managed identity source appId",
        mis,
        &mut problems,
    );
    if problems.len() > MAX_MANIFEST_PROBLEMS {
        let more = problems.len() - MAX_MANIFEST_PROBLEMS;
        problems.truncate(MAX_MANIFEST_PROBLEMS);
        problems.push(format!("and {more} more"));
    }
    problems
}

/// [`manifest_problems`] for one kind of object: `(source_app_id, name)` pairs.
fn id_problems<'a>(
    kind: &str,
    repeated_label: &str,
    ids: impl Iterator<Item = (&'a str, &'a str)>,
    problems: &mut Vec<String>,
) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (id, name) in ids {
        // Checked as-is, never trimmed: the tag, the adoption lookup and the
        // remap all use the raw value, so a padded GUID is not a GUID here.
        let name = excerpt(name);
        if id.is_empty() {
            problems.push(format!("{kind} '{name}' has no source appId"));
        } else if !azapptoolkit_core::guid::is_guid(id) {
            problems.push(format!(
                "{kind} '{name}' has a source appId that is not a GUID ('{}')",
                excerpt(id)
            ));
        } else {
            *seen.entry(id.to_ascii_lowercase()).or_default() += 1;
        }
    }
    let mut repeated: Vec<(String, usize)> = seen.into_iter().filter(|(_, n)| *n > 1).collect();
    repeated.sort();
    problems.extend(
        repeated
            .into_iter()
            .map(|(id, n)| format!("{repeated_label} {id} appears {n} times")),
    );
}

/// Longest value from the file echoed into the plan, in characters.
pub(super) const MAX_ECHOED_CHARS: usize = 80;

/// `value` cut to [`MAX_ECHOED_CHARS`] characters (never mid-character), with
/// an ellipsis when cut: a hostile file's multi-megabyte display name must not
/// become the plan's text.
pub(super) fn excerpt(value: &str) -> String {
    excerpt_to(value, MAX_ECHOED_CHARS)
}

/// `value` cut to `max` characters (never mid-character), with an ellipsis
/// when cut. Copies only what it keeps.
pub(super) fn excerpt_to(value: &str, max: usize) -> String {
    match value.char_indices().nth(max) {
        Some((at, _)) => format!("{}…", &value[..at]),
        None => value.to_string(),
    }
}

/// [`excerpt_to`] in place.
fn cap_chars(text: &mut String, max: usize) {
    // A string of at most `max` bytes has at most `max` characters.
    if text.len() <= max {
        return;
    }
    if let Some((at, _)) = text.char_indices().nth(max) {
        text.truncate(at);
        text.push('…');
    }
}

/// Longest single value the restore report (and its progress events) carries,
/// in characters: a name, a principal label, a URI — and the cap on a plan
/// item's validator refusal, which quotes one value held to Entra's ceiling
/// (escaped, so possibly several times longer). Above every
/// value Entra accepts — a federated credential's issuer, subject and audience
/// stop at 600 characters, a reply URL at 256 — so a legitimate value is never
/// cut, while a hostile file's multi-megabyte one is.
pub(super) const MAX_REPORT_VALUE_CHARS: usize = 1024;

/// Longest warning or runbook reason the report carries, in characters. These
/// compose several values with prose — every federated credential a withheld
/// app would have had (up to 20, each issuer and subject up to 600), every
/// permission a skipped consent covered — so they get room for that worst case
/// rather than one value's cap.
pub(super) const MAX_REPORT_LINE_CHARS: usize = 32 * 1024;

pub(super) fn cap_report_value(text: &mut String) {
    cap_chars(text, MAX_REPORT_VALUE_CHARS);
}

fn cap_report_line(text: &mut String) {
    cap_chars(text, MAX_REPORT_LINE_CHARS);
}

/// Caps every text field of a finished report — the names, labels, warnings
/// and runbook reasons, which echo values from the backup file — so a hostile
/// manifest cannot make the report (the DR view's text and the saved file)
/// carry a multi-megabyte string. A single value is capped at
/// [`MAX_REPORT_VALUE_CHARS`], a composed line at [`MAX_REPORT_LINE_CHARS`];
/// both sit above what a legitimate report holds, so it is never cut.
///
/// Not capped: ids (a source appId passed `validate_manifest` — a GUID —
/// before any run; every new id is one Graph assigned), and a regenerated
/// secret's `key_id` and show-once `secret_value`, which Graph minted. Every
/// struct is destructured exhaustively, so a field added to the report does
/// not compile until it is decided here.
pub(super) fn bound_report_text(report: &mut RestoreReport) {
    let RestoreReport {
        apps,
        failures,
        enterprise_apps,
        managed_identities,
        manual_items,
        cancelled: _,
        session_expired: _,
    } = report;
    for RestoredApp {
        display_name,
        source_app_id: _,
        new_app_id: _,
        new_object_id: _,
        regenerated_secrets,
        certificates_needing_manual_upload,
        unresolved_owners,
        warnings,
        consent_granted: _,
        adopted: _,
        incomplete: _,
    } in apps
    {
        cap_report_value(display_name);
        for RegeneratedSecret {
            display_name,
            key_id: _,
            secret_value: _,
            expires: _,
        } in regenerated_secrets
        {
            cap_report_value(display_name);
        }
        certificates_needing_manual_upload
            .iter_mut()
            .for_each(cap_report_value);
        unresolved_owners.iter_mut().for_each(cap_report_value);
        warnings.iter_mut().for_each(cap_report_line);
    }
    for RestoreFailure {
        display_name,
        source_app_id: _,
        message,
    } in failures
    {
        cap_report_value(display_name);
        cap_report_line(message);
    }
    for RestoredEnterpriseApp {
        display_name,
        new_sp_object_id: _,
        assignments_applied: _,
        group_memberships_applied: _,
        unresolved_principals,
        warnings,
    } in enterprise_apps
    {
        cap_report_value(display_name);
        unresolved_principals.iter_mut().for_each(cap_report_value);
        warnings.iter_mut().for_each(cap_report_line);
    }
    for RestoredManagedIdentity {
        display_name,
        new_principal_id: _,
        app_roles_rebound: _,
        warnings,
    } in managed_identities
    {
        cap_report_value(display_name);
        warnings.iter_mut().for_each(cap_report_line);
    }
    for ManualItem {
        display_name,
        reason,
    } in manual_items
    {
        cap_report_value(display_name);
        cap_report_line(reason);
    }
}
