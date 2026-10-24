//! Pass 3: re-granting admin consent, only for exactly the declared permissions
//! the plan classified.

use std::collections::HashMap;

use azapptoolkit_core::restore_plan::remap_required_resource_access;

use crate::commands::permissions::grant_admin_consent_to_app_core;
use crate::commands::progress::ProgressSink;
use crate::dto::backup::{ManualItem, RestoreReport, RestoredApp};
use crate::state::CancelToken;

use super::plan::Withheld;
use super::wire::CreatedApp;
use super::{PassCtx, RestoreProgress};

/// Pass-3 work for one app: re-grant admin consent — but only for exactly the
/// declared permissions the plan classified.
///
/// Consent grants whatever the app *in the tenant* declares, and the plan
/// classified the backup's list. Those differ whenever Pass 2's PATCH failed or
/// was skipped (an empty manifest list sends none), and an adopted app may
/// carry permissions someone else declared — so the live list is re-read and
/// consent proceeds only when it equals the remapped backup list, using that
/// same read (never a second one that could change in between). Anything else
/// is a runbook item, never a consent.
pub(super) async fn reconsent(
    ctx: &PassCtx<'_>,
    c: &CreatedApp,
    out: &mut RestoredApp,
    manual: &mut Vec<ManualItem>,
) {
    let PassCtx {
        client,
        session,
        app_id_remap,
        ..
    } = *ctx;
    let expected = remap_required_resource_access(&c.backup.required_resource_access, app_id_remap);
    let live = match client.get_application(&c.new_object_id).await {
        Ok(live) => live,
        Err(e) => {
            session.note_code(e.ui_code());
            out.warnings.push(format!(
                "admin consent skipped: couldn't re-read the app's declared permissions ({e})"
            ));
            return;
        }
    };
    if rra_fingerprint(&live.required_resource_access) != rra_fingerprint(&expected) {
        out.warnings.push(
            "admin consent skipped: the app's declared permissions don't match the backup".into(),
        );
        manual.push(ManualItem {
            display_name: c.backup.display_name.clone(),
            reason: "Admin consent skipped: the app's declared API permissions in this tenant \
                     don't match the backup the plan showed (the permissions update failed, or \
                     the app already declared others). Consent would have granted what the app \
                     declares now, which nobody approved. Review its API permissions, then grant \
                     consent from its Permissions tab if they are intended."
                .into(),
        });
        return;
    }
    if expected.is_empty() {
        // Nothing declared, nothing to consent.
        return;
    }
    // The freshly-restored app reg usually has its SP already (Pass 1),
    // and a run that created one still busts the list tier, since
    // `created` is non-empty — so `sp_created` is moot here.
    match grant_admin_consent_to_app_core(client, &live).await {
        Ok(run) => {
            out.consent_granted = run.error.is_none();
            for f in run.result.failures {
                out.warnings
                    .push(format!("consent: {} ({})", f.message, f.resource_app_id));
            }
            if let Some(e) = run.error {
                session.note_code(&e.code);
                out.warnings
                    .push(format!("admin consent failed: {}", e.message));
            }
        }
        Err(e) => {
            session.note_code(&e.code);
            out.warnings
                .push(format!("admin consent failed: {}", e.message));
        }
    }
}

/// Marks each of `created` whose backup had admin consent unfinished, in its
/// report entry (`apps`, index-aligned): the run stopped before Pass 3 reached
/// it. It once read as a finished app that simply has no consent.
fn not_reconsented(created: &[CreatedApp], apps: &mut [RestoredApp]) {
    for (c, out) in created.iter().zip(apps) {
        if c.backup.admin_consent_granted {
            out.incomplete = true;
            out.warnings.push(
                "admin consent not re-granted — the restore stopped before reaching it; run it \
                 again with the same backup"
                    .into(),
            );
        }
    }
}

/// Sorted, case-folded form of a declared-permissions list, for comparing the
/// live app against the remapped backup.
fn rra_fingerprint(
    rra: &[azapptoolkit_core::models::RequiredResourceAccess],
) -> Vec<(String, Vec<(String, String)>)> {
    let mut out: Vec<(String, Vec<(String, String)>)> = rra
        .iter()
        .map(|r| {
            let mut access: Vec<(String, String)> = r
                .resource_access
                .iter()
                .map(|a| (a.id.to_ascii_lowercase(), a.r#type.clone()))
                .collect();
            access.sort();
            (r.resource_app_id.to_ascii_lowercase(), access)
        })
        .collect();
    out.sort();
    out
}

/// Pass 3 of [`run_restore`](super::run_restore): re-grant admin consent
/// ([`reconsent`]) for each created or adopted app that had it — after Pass 2
/// wired every app, so a custom resource's SP and scopes already exist. An app
/// in `withheld` (not approved in the plan, or made to need approval by a read
/// that failed during the run) gets a warning and a runbook item instead.
/// `report.apps` holds Pass 2's entries, index-aligned with `created` (Pass 2
/// reports an app it did not reach as well).
///
/// Stops at the next app on `cancel` (flagging the report) and on a dead
/// session, marking every app it did not reach whose consent the backup asks
/// for unfinished ([`not_reconsented`]). Ticks `progress` once per app whose
/// consent it settles.
pub(super) async fn pass3_reconsent(
    ctx: &PassCtx<'_>,
    created: &[CreatedApp],
    withheld: &HashMap<String, Withheld>,
    cancel: &CancelToken,
    report: &mut RestoreReport,
    progress: &mut RestoreProgress<'_, impl ProgressSink>,
) {
    let session = ctx.session;
    debug_assert_eq!(
        report.apps.len(),
        created.len(),
        "Pass 2 reports one entry per created app, in order"
    );
    for (idx, c) in created.iter().enumerate() {
        if cancel.is_cancelled() {
            report.cancelled = true;
        }
        if cancel.is_cancelled() || session.is_dead() {
            not_reconsented(&created[idx..], &mut report.apps[idx..]);
            break;
        }
        if !c.backup.admin_consent_granted {
            continue;
        }
        // Not approved in the plan: the file asks for tenant-wide consent the
        // operator has not agreed to grant. The app is still restored; the
        // consent becomes a runbook item. A permission whose API could not be
        // read during the run is unidentified, and withheld the same way — but
        // the plan may never have asked about it, so the item says why.
        if let Some(held) = withheld.get(&c.backup.source_app_id) {
            let (warning, why) = if held.lookup_failed {
                (
                    "admin consent skipped: a permission could not be identified when the \
                     restore ran",
                    "a permission it covers could not be identified when the restore ran \
                     (reading its API in this tenant failed), so the consent was withheld \
                     rather than granted unseen",
                )
            } else {
                (
                    "admin consent skipped: not approved in the plan",
                    "not approved in the plan",
                )
            };
            report.apps[idx].warnings.push(warning.into());
            report.manual_items.push(ManualItem {
                display_name: c.backup.display_name.clone(),
                reason: format!(
                    "Admin consent skipped: {why}. The backup asks for tenant-wide consent to {}. \
                     Review them, then grant consent from the app's Permissions tab if they are \
                     intended.",
                    if held.consent.is_empty() {
                        "its declared permissions".to_string()
                    } else {
                        held.consent.join(", ")
                    }
                ),
            });
            progress.tick(&c.backup.display_name);
            continue;
        }
        reconsent(ctx, c, &mut report.apps[idx], &mut report.manual_items).await;
        progress.tick(&c.backup.display_name);
    }
}
