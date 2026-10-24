//! Pass 2: wiring each created (or adopted) app — permissions, identifier URIs,
//! Expose-an-API, authentication, federated credentials, owners and
//! regenerated secrets.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use azapptoolkit_core::federation::validate_federated_credential;
use azapptoolkit_core::models::FederatedIdentityCredential;
use azapptoolkit_core::redirect::{validate_logout_url, validate_redirect_uri};
use azapptoolkit_core::restore_plan::{
    BackupApps, plan_pre_authorized, remap_required_resource_access, rewrite_identifier_uris,
};
use azapptoolkit_graph::client::{
    ApiApplicationPatch, AppPatch, ApplicationAuthenticationPatch, ApplicationExposeApiPatch,
    ApplicationPublicClientPatch, ApplicationSpaPatch, ApplicationWebPatch,
    FederatedCredentialRequest, ImplicitGrantSettingsPatch,
};

use crate::commands::progress::ProgressSink;
use crate::dto::backup::{
    AppRegistrationBackup, CredentialMeta, ManualItem, PrincipalRef, RegeneratedSecret,
    RestoreReport, RestoredApp,
};
use crate::state::CancelToken;

use super::adoption::{FicKey, LiveSecret, fic_key};
use super::plan::Withheld;
use super::principals::{PrincipalMemo, owner_label, resolve_principal};
use super::{PassCtx, RestoreProgress};

/// Keeps only the redirect URIs that pass `core::redirect`, recording each
/// rejection in the restore report.
///
/// Per-URI rather than all-or-nothing on the list: a manifest with one bad
/// reply URL among four good ones should restore the four, and the operator
/// needs to know precisely which one was dropped. Mirrors the
/// federated-credential loop's "was NOT restored — {reason}" phrasing so the
/// report reads consistently.
pub(super) fn checked_uris(
    uris: &[String],
    label: &str,
    warnings: &mut Vec<String>,
) -> Vec<String> {
    uris.iter()
        .filter(|u| match validate_redirect_uri(u) {
            Ok(()) => true,
            Err(reason) => {
                warnings.push(format!("{label}: '{u}' was NOT restored — {reason}"));
                false
            }
        })
        .cloned()
        .collect()
}

/// The manifest's logout URL if it passes `core::redirect::validate_logout_url`
/// — the reply-URL rules plus https (or loopback http) only, as in the editor —
/// trimmed; otherwise `None`, with the rejection recorded in the report.
pub(super) fn checked_logout_url(url: Option<&str>, warnings: &mut Vec<String>) -> Option<String> {
    let url = url.map(str::trim).filter(|u| !u.is_empty())?;
    match validate_logout_url(url) {
        Ok(()) => Some(url.to_string()),
        Err(reason) => {
            warnings.push(format!("logout URL '{url}' was NOT restored — {reason}"));
            None
        }
    }
}

/// Lifetime for regenerated secrets — matches the app-creation default (180d).
///
/// The original expiry can't be honoured (the value is new, and the old end
/// date may already have passed), so a fresh standard window is minted and
/// surfaced in the report — but only for secrets that were still valid when the
/// backup was taken ([`expired_at_backup`]). A secret already expired then
/// cannot have been in use, and re-issuing it would only widen the restored
/// app's live credential surface.
const REGEN_SECRET_DAYS: u32 = crate::dto::credentials::DEFAULT_SECRET_LIFETIME_DAYS;

/// Whether a backed-up secret had already expired when the backup was taken.
///
/// The cutoff is the backup's own timestamp, never "now": a secret that was
/// live at backup time and expired during the outage is exactly the one a
/// recovering client still holds, so it is re-issued. No end date = not expired.
pub(super) fn expired_at_backup(meta: &CredentialMeta, taken_at: DateTime<Utc>) -> bool {
    meta.end_date_time.is_some_and(|end| end < taken_at)
}

/// An app Pass 1 created — or adopted from an earlier run of this restore —
/// paired with its backup and destination ids.
pub(super) struct CreatedApp {
    pub(super) backup: AppRegistrationBackup,
    pub(super) new_object_id: String,
    pub(super) new_app_id: String,
    /// Recognised by its restore tag rather than created by this run.
    pub(super) adopted: bool,
    /// For an adopted app, the named secrets it already holds.
    pub(super) live_secrets: Vec<LiveSecret>,
    /// Pass-1 warnings to carry into the app's report entry.
    pub(super) warnings: Vec<String>,
}

/// The subject a backed-up federated credential is recreated with, or the
/// restore-report warning when it has none.
///
/// A *flexible* credential is matched by a `claimsMatchingExpression` (a
/// beta-only Graph property) instead of a subject, so the v1.0 read backs it up
/// with `subject: null` and nothing to recreate it from. It is skipped with the
/// same "was NOT restored — {reason}" phrasing as a rejected credential.
pub(super) fn restorable_fic_subject(fic: &FederatedIdentityCredential) -> Result<&str, String> {
    fic.subject.as_deref().ok_or_else(|| {
        format!(
            "federated credential '{}' was NOT restored — it is a flexible credential \
             (matched by a claims expression, with no subject), which this app cannot \
             recreate; add it again in the Entra portal",
            fic.name
        )
    })
}

/// Pass-2 work for one created (or adopted) app: declared permissions,
/// identifier URIs + Expose-an-API, authentication, federated credentials,
/// owners, and secret regeneration.
///
/// Every step is best-effort — a failure becomes a warning and the app keeps
/// its other config (it already exists). So a dead session would otherwise be
/// indistinguishable from a tenant rejecting each individual write;
/// `ctx.session` is the latch that tells them apart: each failure is noted
/// through it by `ui_code`, keeping `UiError::is_reauth_fatal` the single
/// definition of which codes are fatal.
///
/// For an adopted app the PATCHes are full-replace and simply re-applied, while
/// the additive writes (federated credentials, owners, secrets) skip what the
/// earlier run already put there. `ctx.taken_at` is the backup's timestamp,
/// the cutoff for [`expired_at_backup`]; the two tenant ids in `ctx` are what
/// the identifier-URI rewrite maps (source → destination).
///
/// `withhold` marks an app that needed approval in the plan and did not get
/// it: it is wired as usual, but gains no federated credential and no owner
/// from the file — each withheld set is one runbook item.
///
/// `backup_apps` is every app registration the backup owns: a pre-authorized
/// client among them that `ctx.app_id_remap` lacks (Pass 1 failed or refused
/// it) is left out with a warning rather than written under its appId from the
/// backup's source tenant ([`plan_pre_authorized`]).
pub(super) async fn wire_application(
    ctx: &PassCtx<'_>,
    c: &CreatedApp,
    backup_apps: &BackupApps,
    principals: &mut PrincipalMemo,
    cancel: &CancelToken,
    withhold: bool,
) -> (RestoredApp, Vec<ManualItem>) {
    let PassCtx {
        client,
        session,
        app_id_remap,
        cloud,
        taken_at,
        source_tenant_id,
        dest_tenant_id,
    } = *ctx;
    let app = &c.backup;
    // Sign-in trusts this app gained from the manifest. Reported separately
    // from `warnings`, because these are the steps that *succeeded* — and a
    // secretless trust the operator did not intend is not visible any other way.
    let mut trusts: Vec<ManualItem> = Vec::new();
    let mut out = RestoredApp {
        display_name: app.display_name.clone(),
        source_app_id: app.source_app_id.clone(),
        new_app_id: c.new_app_id.clone(),
        new_object_id: c.new_object_id.clone(),
        adopted: c.adopted,
        warnings: c.warnings.clone(),
        ..Default::default()
    };

    // Declared API permissions (full-replace), with custom resource appIds
    // remapped to their new ids (first-party appIds survive verbatim).
    let rra = remap_required_resource_access(&app.required_resource_access, app_id_remap);
    if !rra.is_empty() {
        let patch = AppPatch {
            required_resource_access: Some(rra),
            ..Default::default()
        };
        if let Err(e) = client.update_application(&c.new_object_id, &patch).await {
            session.note_code(e.ui_code());
            out.warnings.push(format!("permissions: {e}"));
        }
    }

    // Identifier URIs + Expose-an-API (scope ids preserved so consumers' grants
    // still resolve; every `api://` segment naming the source appId or source
    // tenant rewritten, since the destination rejects a GUID matching neither).
    let identifier_uris = rewrite_identifier_uris(
        &app.identifier_uris,
        &app.source_app_id,
        &c.new_app_id,
        source_tenant_id,
        dest_tenant_id,
    );
    // A client from outside the backup is written as listed (the plan showed
    // it); one the backup owns but did not recreate has no appId here — the
    // one it lists is from the backup's source tenant — so it is left out. A
    // re-run that recreates it adopts this app and re-applies this
    // full-replace PATCH with it.
    let (pre_auth, own_not_restored) =
        plan_pre_authorized(&app.pre_authorized_applications, app_id_remap, backup_apps);
    for client_app_id in own_not_restored {
        let named = match backup_apps.display_name(&client_app_id) {
            Some(name) => format!("'{name}' ({client_app_id})"),
            None => client_app_id,
        };
        out.warnings.push(format!(
            "pre-authorized client {named} was NOT restored — it is an app in this backup \
             that was not recreated here, so its appId from the backup's source tenant was left \
             out; run the restore again once that app is restored"
        ));
    }
    // Whenever the backup lists any client, the list is written — even empty
    // once every client is left out — so this full-replace PATCH also clears
    // an entry an earlier run (or an older build) wrote on an adopted app.
    let lists_pre_auth = !app.pre_authorized_applications.is_empty();
    if !identifier_uris.is_empty() || !app.api_scopes.is_empty() || lists_pre_auth {
        let patch = ApplicationExposeApiPatch {
            identifier_uris: (!identifier_uris.is_empty()).then_some(identifier_uris),
            api: Some(ApiApplicationPatch {
                oauth2_permission_scopes: (!app.api_scopes.is_empty())
                    .then(|| app.api_scopes.clone()),
                pre_authorized_applications: lists_pre_auth.then_some(pre_auth),
            }),
        };
        if let Err(e) = client
            .patch_application_expose_api(&c.new_object_id, &patch)
            .await
        {
            session.note_code(e.ui_code());
            out.warnings
                .push(format!("identifier URIs / Expose-an-API: {e}"));
        }
    }

    // Authentication (redirect URIs + implicit-grant flags + public-client).
    //
    // Reply URLs are where auth codes get delivered, so a manifest carrying
    // `https://*.evil.example/cb` or a plaintext `http://attacker.example/cb`
    // hands an attacker the codes for the restored app. The interactive
    // authentication editor rejects both before its PATCH; a manifest is
    // untrusted input for exactly the reason the federated-credential loop
    // below already documents, so it gets the same validator and the same
    // shape: reject the offending list, name it in the report, keep going.
    let web_redirect_uris = checked_uris(
        &app.web_redirect_uris,
        "web redirect URIs",
        &mut out.warnings,
    );
    let spa_redirect_uris = checked_uris(
        &app.spa_redirect_uris,
        "SPA redirect URIs",
        &mut out.warnings,
    );
    let public_client_redirect_uris = checked_uris(
        &app.public_client_redirect_uris,
        "public-client redirect URIs",
        &mut out.warnings,
    );
    // A logout URL is a single value, not a list, and held to the stricter
    // logout rules: a custom scheme is a legal reply URL but not a logout URL.
    let logout_url = checked_logout_url(app.logout_url.as_deref(), &mut out.warnings);

    let has_auth = !web_redirect_uris.is_empty()
        || !spa_redirect_uris.is_empty()
        || !public_client_redirect_uris.is_empty()
        || logout_url.is_some()
        || app.enable_access_token_issuance
        || app.enable_id_token_issuance
        || app.is_fallback_public_client;
    if has_auth {
        let patch = ApplicationAuthenticationPatch {
            web: Some(ApplicationWebPatch {
                redirect_uris: Some(web_redirect_uris.clone()),
                logout_url: Some(logout_url.clone().unwrap_or_default()),
                implicit_grant_settings: Some(ImplicitGrantSettingsPatch {
                    enable_access_token_issuance: Some(app.enable_access_token_issuance),
                    enable_id_token_issuance: Some(app.enable_id_token_issuance),
                }),
            }),
            spa: Some(ApplicationSpaPatch {
                redirect_uris: Some(spa_redirect_uris.clone()),
            }),
            public_client: Some(ApplicationPublicClientPatch {
                redirect_uris: Some(public_client_redirect_uris.clone()),
            }),
            is_fallback_public_client: Some(app.is_fallback_public_client),
        };
        if let Err(e) = client.patch_application_web(&c.new_object_id, &patch).await {
            session.note_code(e.ui_code());
            out.warnings.push(format!("authentication: {e}"));
        } else {
            // Surface what was actually written, the way a restored federated
            // credential is surfaced: a reply URL is standing configuration an
            // operator should be able to review after the fact.
            for uri in web_redirect_uris
                .iter()
                .chain(&spa_redirect_uris)
                .chain(&public_client_redirect_uris)
            {
                out.warnings.push(format!("restored reply URL: {uri}"));
            }
        }
    }

    // Federated identity credentials.
    //
    // These are the only thing a manifest can carry that grants standing access
    // to the restored app **without any secret**: whoever controls the named
    // issuer can mint tokens as it, indefinitely. The manifest is a file, and a
    // file may not have been written by the operator restoring it — so each one
    // is validated like any other untrusted input (`core::federation`, the same
    // check the interactive editor uses), and each one that *is* created is
    // named in the report rather than applied silently.
    //
    // An adopted app may already hold the ones an earlier run created; a failed
    // read falls through to creating, where a duplicate is a 409 warning.
    let fics: &[FederatedIdentityCredential] = if withhold {
        if !app.federated_credentials.is_empty() {
            trusts.push(ManualItem {
                display_name: app.display_name.clone(),
                reason: format!(
                    "Federated credentials not restored: not approved in the plan ({}). Each \
                     lets an external issuer sign in as this app with no secret; add them from \
                     the app's Certificates & secrets tab if they are intended.",
                    app.federated_credentials
                        .iter()
                        .map(|f| format!(
                            "'{}': issuer {}, subject {}",
                            f.name,
                            f.issuer,
                            f.subject.as_deref().unwrap_or("(none)")
                        ))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            });
        }
        &[]
    } else {
        &app.federated_credentials
    };
    let existing_fics: HashSet<FicKey> = if c.adopted && !fics.is_empty() {
        match client.list_federated_credentials(&c.new_object_id).await {
            Ok(list) => list.iter().map(|f| fic_key(f, cloud)).collect(),
            Err(e) => {
                session.note_code(e.ui_code());
                HashSet::new()
            }
        }
    } else {
        HashSet::new()
    };
    for (i, fic) in fics.iter().enumerate() {
        if cancel.is_cancelled() || session.is_dead() {
            stopped_before(&mut out, fics.len() - i, fics.len(), "federated credential");
            break;
        }
        let subject = match restorable_fic_subject(fic) {
            Ok(subject) => subject,
            Err(warning) => {
                out.warnings.push(warning);
                continue;
            }
        };
        let audiences = if fic.audiences.is_empty() {
            vec![cloud.token_exchange_audience().to_string()]
        } else {
            fic.audiences.clone()
        };
        if let Err(reason) = validate_federated_credential(
            Some(&fic.name),
            &fic.issuer,
            subject,
            &audiences,
            fic.description.as_deref(),
        ) {
            out.warnings.push(format!(
                "federated credential '{}' was NOT restored — {reason}",
                fic.name
            ));
            continue;
        }
        if existing_fics.contains(&fic_key(fic, cloud)) {
            out.warnings.push(format!(
                "federated credential '{}' already exists from an earlier restore run — not added \
                 again",
                fic.name
            ));
            continue;
        }
        let body = FederatedCredentialRequest {
            name: fic.name.clone(),
            issuer: fic.issuer.clone(),
            subject: subject.to_string(),
            audiences,
            description: fic.description.clone(),
        };
        if let Err(e) = client
            .add_federated_credential(&c.new_object_id, &body)
            .await
        {
            session.note_code(e.ui_code());
            out.warnings
                .push(format!("federated credential '{}': {e}", fic.name));
        } else {
            trusts.push(ManualItem {
                display_name: format!("{} — federated credential '{}'", app.display_name, fic.name),
                reason: format!(
                    "Restored a secretless sign-in trust: anything presenting subject '{}' \
                     from issuer '{}' can now obtain tokens as this application, with no \
                     secret and no expiry. Confirm that external workload still exists and \
                     should have this access in this tenant.",
                    subject, fic.issuer
                ),
            });
        }
    }

    // Owners — remap each principal by UPN / display name in the destination.
    // An adopted app skips the owners it already has (a failed read falls
    // through to adding, where a duplicate is only a warning). An owner can add
    // credentials to the app, so a withheld app gets none from the file.
    let owners: &[PrincipalRef] = if withhold {
        if !app.owners.is_empty() {
            trusts.push(ManualItem {
                display_name: app.display_name.clone(),
                reason: format!(
                    "Owners not added: not approved in the plan ({}). Add them from the app's \
                     Owners tab if they are intended.",
                    app.owners
                        .iter()
                        .map(owner_label)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        &[]
    } else {
        &app.owners
    };
    let existing_owners: HashSet<String> = if c.adopted && !owners.is_empty() {
        match client.list_owners(&c.new_object_id).await {
            Ok(list) => list.into_iter().map(|o| o.id).collect(),
            Err(e) => {
                session.note_code(e.ui_code());
                HashSet::new()
            }
        }
    } else {
        HashSet::new()
    };
    for (i, owner) in owners.iter().enumerate() {
        if cancel.is_cancelled() || session.is_dead() {
            stopped_before(&mut out, owners.len() - i, owners.len(), "owner");
            break;
        }
        match resolve_principal(client, principals, owner, session).await {
            Ok(new_id) if existing_owners.contains(&new_id) => {}
            Ok(new_id) => {
                if let Err(e) = client.add_owner(&c.new_object_id, &new_id).await {
                    session.note_code(e.ui_code());
                    out.warnings.push(format!("owner: {e}"));
                }
            }
            Err(why) => out.unresolved_owners.push(why.label(owner)),
        }
    }

    // Secrets — values are unrecoverable, so mint fresh ones (show-once). Not
    // for one already expired when the backup was taken, and not for one an
    // earlier run of this restore already issued on an adopted app (matched by
    // name, as a multiset, so two same-named secrets still count as two).
    let mut already_issued = c.live_secrets.clone();
    for (i, meta) in app.secrets.iter().enumerate() {
        if cancel.is_cancelled() || session.is_dead() {
            stopped_before(&mut out, app.secrets.len() - i, app.secrets.len(), "secret");
            break;
        }
        let name = meta
            .display_name
            .clone()
            .unwrap_or_else(|| "restored".into());
        if expired_at_backup(meta, taken_at) {
            let end = meta
                .end_date_time
                .map(|d| d.format("%Y-%m-%d").to_string())
                .unwrap_or_default();
            out.warnings.push(format!(
                "secret '{name}' had already expired at backup time ({end}) — not re-issued"
            ));
            continue;
        }
        if let Some(pos) = already_issued.iter().position(|s| s.name == name) {
            let live = already_issued.swap_remove(pos);
            out.warnings.push(format!(
                "secret '{name}' already exists ({}) — not issued again. If an earlier restore \
                 run issued it, its value is in that run's report: compare this key id with that \
                 report, and remove the secret if it isn't that one",
                live_secret_label(&live)
            ));
            continue;
        }
        let lifetime = std::time::Duration::from_secs(REGEN_SECRET_DAYS as u64 * 86_400);
        match client.add_password(&c.new_object_id, &name, lifetime).await {
            Ok(cred) => out.regenerated_secrets.push(RegeneratedSecret {
                display_name: name,
                key_id: cred.key_id,
                secret_value: cred.secret_text.unwrap_or_default(),
                expires: cred.end_date_time,
            }),
            Err(e) => {
                session.note_code(e.ui_code());
                out.warnings.push(format!("secret '{name}': {e}"));
            }
        }
    }

    out.certificates_needing_manual_upload = certificates_to_reupload(app);

    (out, trusts)
}

/// The kept secret's key id, when it was added and its hint — what tells the
/// secret an earlier run issued from a planted one that copied its name.
fn live_secret_label(live: &LiveSecret) -> String {
    let created = live.created.map_or_else(
        || "an unknown time".to_string(),
        |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
    );
    let hint = live
        .hint
        .as_deref()
        .map(|h| format!(", hint '{h}'"))
        .unwrap_or_default();
    format!("key id {}, added {created}{hint}", live.key_id)
}

/// Certificates can't be restored (the private key never left the source), so
/// each is listed for manual re-upload from the operator's PKI.
fn certificates_to_reupload(app: &AppRegistrationBackup) -> Vec<String> {
    app.certificates
        .iter()
        .map(|c| c.display_name.clone().unwrap_or_else(|| "(unnamed)".into()))
        .collect()
}

/// Flags `out` incomplete: the run stopped (a cancel, or a dead session) with
/// `left` of the app's `of` items of one step — `what`, singular — never
/// processed. Without it the app read as finished, with no sign that its
/// remaining credentials, owners or secrets were skipped.
fn stopped_before(out: &mut RestoredApp, left: usize, of: usize, what: &str) {
    out.incomplete = true;
    let noun = if of == 1 {
        what.to_string()
    } else {
        format!("{what}s")
    };
    out.warnings.push(format!(
        "stopped before finishing: {left} of {of} {noun} not processed — run the restore again \
         with the same backup to finish this app"
    ));
}

/// The report entry for an app Pass 1 created or adopted that Pass 2 never
/// reached because the run stopped: its ids, its Pass-1 warnings and the
/// certificates it will need, flagged incomplete. Leaving it out made the
/// report — the operator's only record of what the run created — silent about
/// an app that exists in the tenant.
fn not_wired(c: &CreatedApp) -> RestoredApp {
    let mut warnings = c.warnings.clone();
    warnings.push(
        "not wired — the restore stopped before reaching this app, so none of its \
         configuration, credentials, owners or secrets were restored; run the restore again \
         with the same backup to finish it"
            .into(),
    );
    RestoredApp {
        display_name: c.backup.display_name.clone(),
        source_app_id: c.backup.source_app_id.clone(),
        new_app_id: c.new_app_id.clone(),
        new_object_id: c.new_object_id.clone(),
        certificates_needing_manual_upload: certificates_to_reupload(&c.backup),
        warnings,
        adopted: c.adopted,
        incomplete: true,
        ..Default::default()
    }
}

/// Pass 2 of [`run_restore`](super::run_restore): wire every app Pass 1 created
/// or adopted ([`wire_application`]), in order, into the report — its entry,
/// and the sign-in trusts it gained as runbook items. `withheld` holds the apps
/// the plan's approvals left out.
///
/// Stops at the next app on `cancel` (flagging the report) and on a dead
/// session — and still reports every app it did not reach ([`not_wired`]), so
/// `report.apps` stays index-aligned with `created`, which Pass 3 relies on.
/// Ticks `progress` once per app it wires.
pub(super) async fn pass2_wire(
    ctx: &PassCtx<'_>,
    created: &[CreatedApp],
    backup_apps: &BackupApps,
    withheld: &HashMap<String, Withheld>,
    principals: &mut PrincipalMemo,
    cancel: &CancelToken,
    report: &mut RestoreReport,
    progress: &mut RestoreProgress<'_, impl ProgressSink>,
) {
    let session = ctx.session;
    for (i, c) in created.iter().enumerate() {
        // Both stop conditions, in every pass. Passes 2-5 once checked only
        // `is_dead()`, so Cancel stopped mattering the moment Pass 1 finished:
        // the operator pressed it and watched the restore keep wiring, granting
        // consent and re-binding roles for every remaining app.
        if cancel.is_cancelled() {
            report.cancelled = true;
        }
        if cancel.is_cancelled() || session.is_dead() {
            // These exist in the tenant: they stay in the report, unwired.
            report.apps.extend(created[i..].iter().map(not_wired));
            break;
        }
        let (restored, trusts) = wire_application(
            ctx,
            c,
            backup_apps,
            principals,
            cancel,
            withheld.contains_key(&c.backup.source_app_id),
        )
        .await;
        report.apps.push(restored);
        report.manual_items.extend(trusts);
        progress.tick(&c.backup.display_name);
    }
}
