//! Disaster-recovery restore — replays a [`TenantBackup`] into the **current**
//! tenant (which, in a real DR, is a *different* tenant than the one backed up).
//!
//! It restores app registrations, enterprise applications and managed-identity
//! permissions in five passes, so inter-app dependencies resolve (see
//! `docs/architecture/backup-and-restore.md`):
//!
//! 1. **Create shells** — create every app (+ paired SP) and build the
//!    `source_app_id → new_app_id` remap, or adopt the app an earlier run of
//!    this restore already created (see below). Reuses
//!    `create_application_core_with`.
//! 2. **Wire references** — declared permissions (remapped), identifier URIs
//!    (every `api://` segment naming the source appId / source tenant →
//!    the new appId / destination tenant), Expose-an-API scopes + pre-authorized
//!    apps, authentication/redirect URIs, federated credentials (validated +
//!    reported), owners (remapped by UPN / display name), and bulk-regenerate
//!    secrets.
//! 3. **Re-consent** — re-grant admin consent for apps that had it, *after* all
//!    apps are wired so a custom resource's SP + scopes already exist. Consent
//!    covering a high-risk or unidentifiable application permission is granted
//!    only to apps the operator approved in the plan.
//! 4. **Enterprise applications** — re-apply settings, app-role assignments and
//!    group memberships to the SPs recreated in pass 1.
//! 5. **Managed identities** — re-bind Graph app-roles to MIs already recreated
//!    in the destination (high-risk ones only when approved); everything else
//!    becomes a runbook item.
//!
//! **Re-running is safe for the apps a run created.** Every app is created with
//! the tag `azapptoolkit:restoredFrom:<source appId>` in its create POST, so a
//! re-run finds it and finishes wiring it rather than creating it twice. The tag
//! and the display name are both writable by anyone who may register apps, so a
//! hit is adopted only once it is also provably this restore's: created after
//! the backup, owned by nobody but the operator and the manifest's owners, and
//! holding no credential (secret, certificate, federated credential) the
//! manifest does not account for. Anything else — an ambiguous or unprovable
//! match, or a read that failed — is a runbook item and never a blind create.
//!
//! Secret/cert values can't be restored: secrets are regenerated (the show-once
//! values land in the [`RestoreReport`] for redistribution) — except those that
//! had already expired when the backup was taken; certificates are reported as
//! needing manual re-upload from the operator's own PKI.
//!
//! Long-running, so it polls its own `AppState.restore_cancel` token (stopped
//! only by `cancel_restore`, never by a backup's Cancel) and emits
//! `restore-progress`. A cancel stops at the next item in whichever pass is
//! running, and the report flags the run cancelled (partial); a re-run adopts
//! the already-created, tagged apps and finishes wiring them.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use tauri::{AppHandle, State};

use azapptoolkit_core::audit::{
    RiskLevel, is_risky_delegated_scope, risk_level_for_app_permission,
};
use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_core::federation::validate_federated_credential;
use azapptoolkit_core::models::{
    Application, DirectoryObject, FederatedIdentityCredential, ServicePrincipal,
};
use azapptoolkit_core::redirect::{validate_logout_url, validate_redirect_uri};
use azapptoolkit_core::restore_plan::{
    BackupApps, plan_pre_authorized, remap_required_resource_access, rewrite_identifier_uris,
};
use azapptoolkit_graph::GraphClient;
use azapptoolkit_graph::client::{
    ApiApplicationPatch, AppPatch, ApplicationAuthenticationPatch, ApplicationExposeApiPatch,
    ApplicationPublicClientPatch, ApplicationSpaPatch, ApplicationWebPatch,
    FederatedCredentialRequest, ImplicitGrantSettingsPatch,
};

use crate::commands::applications::{
    CreateExtras, create_application_core_with, invalidate_app_lists,
};
use crate::commands::dispatch::SessionDead;
use crate::commands::managed_identity::{grant_managed_identity_roles_core, mi_subtype_label};
use crate::commands::permissions::grant_admin_consent_to_app_core;
use crate::commands::progress::{ProgressSink, emit_progress};
use crate::dto::UiError;
use crate::dto::applications::CreateApplicationInput;
use crate::dto::backup::{
    AppRegistrationBackup, BACKUP_SCHEMA_VERSION, CloudMismatch, CredentialMeta,
    EnterpriseAppBackup, ManagedIdentityBackup, ManualItem, PermissionRisk,
    PlannedFederatedCredential, PrincipalRef, PrivilegedKind, PrivilegedPermission,
    PrivilegedRestoreItem, RegeneratedSecret, RestoreApproval, RestoreFailure, RestorePlan,
    RestoreReport, RestoredApp, RestoredEnterpriseApp, RestoredManagedIdentity, SchemaTooNew,
    TenantBackup,
};
use crate::dto::bulk::BulkProgress;
use crate::dto::managed_identity::MiSubtype;
use crate::state::{AppState, CancelToken};

/// Keeps only the redirect URIs that pass `core::redirect`, recording each
/// rejection in the restore report.
///
/// Per-URI rather than all-or-nothing on the list: a manifest with one bad
/// reply URL among four good ones should restore the four, and the operator
/// needs to know precisely which one was dropped. Mirrors the
/// federated-credential loop's "was NOT restored — {reason}" phrasing so the
/// report reads consistently.
fn checked_uris(uris: &[String], label: &str, warnings: &mut Vec<String>) -> Vec<String> {
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
fn checked_logout_url(url: Option<&str>, warnings: &mut Vec<String>) -> Option<String> {
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
fn expired_at_backup(meta: &CredentialMeta, taken_at: DateTime<Utc>) -> bool {
    meta.end_date_time.is_some_and(|end| end < taken_at)
}

/// Prefix of the tag every app created by a restore carries; the suffix is the
/// app's **source** appId, the one key that survives the tenant move.
const RESTORE_MARKER_PREFIX: &str = "azapptoolkit:restoredFrom:";

/// The restore tag for the app backed up as `source_app_id`.
fn restore_marker(source_app_id: &str) -> String {
    format!("{RESTORE_MARKER_PREFIX}{source_app_id}")
}

/// What Pass 1 does with one manifest app, given the destination apps that
/// already carry its restore tag.
#[derive(Debug, PartialEq)]
enum Adoption {
    /// Nothing carries the tag — create it.
    Create,
    /// An earlier run created it — finish wiring that one instead.
    Adopt {
        object_id: String,
        app_id: String,
        /// Display names of the secrets it already holds, so Pass 2 does not
        /// issue them a second time.
        live_secret_names: Vec<String>,
    },
    /// Something carries the tag but cannot safely be taken for this app;
    /// the reason becomes a runbook item and nothing is created.
    Refuse(String),
}

/// Pure Pass-1 decision on the tag lookup. Adoption needs the tag, the exact
/// display name **and** a creation time after the backup was taken: the tag
/// alone could be on an app someone has since repurposed, the name alone proves
/// nothing, and an app older than the backup cannot be one a restore of it
/// created. Anything else fails closed — never a second copy, and never a hit
/// holding a certificate or secret the manifest does not account for. An
/// `Adopt` here is still provisional: [`decide_adoption`] checks the hit's
/// owners and federated credentials before Pass 1
/// takes it.
fn adoption_for(
    app: &AppRegistrationBackup,
    hits: &[Application],
    taken_at: DateTime<Utc>,
) -> Adoption {
    match hits {
        [] => Adoption::Create,
        [hit] if hit.display_name != app.display_name => Adoption::Refuse(format!(
            "An app carrying the restore tag for source appId {} already exists as '{}' \
             (appId {}), so this app was not created again. Reconcile it manually: rename it \
             back to '{}' and run the restore again to finish it, or delete it to have the \
             restore recreate it.",
            app.source_app_id, hit.display_name, hit.app_id, app.display_name
        )),
        [hit] if !hit.created_date_time.is_some_and(|t| t >= taken_at) => {
            let created = hit.created_date_time.map_or_else(
                || "an unknown time".to_string(),
                |t| t.format("%Y-%m-%d %H:%M UTC").to_string(),
            );
            Adoption::Refuse(format!(
                "An app carrying the restore tag for source appId {} already exists as '{}' \
                 (appId {}), but it was created at {created}, not after this backup was taken \
                 ({}), so no restore of this backup can have created it. It was not adopted \
                 (that would give it this app's permissions and admin consent) and not created \
                 again. Find out who created it; delete it to have the restore recreate the app.",
                app.source_app_id,
                hit.display_name,
                hit.app_id,
                taken_at.format("%Y-%m-%d %H:%M UTC")
            ))
        }
        // Credentials are the standing access an owner check cannot see. A
        // restore uploads no certificate and issues secrets only under the
        // manifest's names, so a certificate whose thumbprint the manifest does
        // not list, or a secret it does not name, is foreign — planted, or
        // added by the operator after the earlier run (a rotation, or the
        // runbook's own "re-upload the certificate"), which this cannot tell
        // apart and so refuses with both ways out. A same-named secret is the
        // one residue this cannot settle; Pass 2 reports it rather than keeping
        // it silently.
        [hit] => {
            let certificates = foreign_certificates(hit, app);
            if !certificates.is_empty() {
                return Adoption::Refuse(format!(
                    "'{}' (appId {}) carries this app's restore tag, but it holds certificate \
                     credential(s) the backup does not list ({}), so it is not provably the app \
                     an earlier run created. It was not adopted (that would give it this app's \
                     permissions and admin consent) and not created again. If you added the \
                     certificate yourself after an earlier run, finish this app by hand or \
                     remove the certificate and run the restore again; otherwise find out who \
                     added it, and delete the app to have the restore recreate it.",
                    hit.display_name,
                    hit.app_id,
                    certificates.join(", ")
                ));
            }
            let secrets = foreign_secrets(hit, app, taken_at);
            if !secrets.is_empty() {
                return Adoption::Refuse(format!(
                    "'{}' (appId {}) carries this app's restore tag, but it holds secret(s) the \
                     backup does not name, or more same-named ones than it lists ({}), so it is \
                     not provably the app an earlier run created. It was not adopted (that would \
                     give it this app's permissions and admin consent) and not created again. If \
                     you added them yourself after an earlier run, finish this app by hand or \
                     remove them and run the restore again; otherwise find out who added them, \
                     and delete the app to have the restore recreate it.",
                    hit.display_name,
                    hit.app_id,
                    secrets.join(", ")
                ));
            }
            Adoption::Adopt {
                object_id: hit.id.clone(),
                app_id: hit.app_id.clone(),
                live_secret_names: hit
                    .password_credentials
                    .iter()
                    .filter_map(|p| p.display_name.clone())
                    .collect(),
            }
        }
        many => Adoption::Refuse(format!(
            "{} apps carry the restore tag for source appId {} ({}), so none was created again. \
             Delete the duplicates, then run the restore again.",
            many.len(),
            app.source_app_id,
            many.iter()
                .map(|h| h.app_id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// The labels of `hit`'s certificate credentials whose thumbprint the manifest
/// does not list. A restore uploads no certificate, so an earlier run cannot
/// have put one there — but the runbook tells the operator to re-upload the
/// backed-up ones, and a certificate the manifest knows by thumbprint is
/// safe to keep: a planter has nothing without its private key. Labelled by
/// display name, else key id; an unreadable thumbprint counts as foreign.
fn foreign_certificates(hit: &Application, app: &AppRegistrationBackup) -> Vec<String> {
    let known: HashSet<String> = app
        .certificates
        .iter()
        .filter_map(|c| c.thumbprint.as_deref())
        .filter_map(azapptoolkit_core::thumbprint::canonical)
        .collect();
    hit.key_credentials
        .iter()
        .filter(|k| {
            !k.custom_key_identifier
                .as_deref()
                .and_then(azapptoolkit_core::thumbprint::canonical)
                .is_some_and(|t| known.contains(&t))
        })
        .map(|k| k.display_name.clone().unwrap_or_else(|| k.key_id.clone()))
        .collect()
}

/// The display names of `hit`'s secrets that the manifest does not account
/// for — as a multiset, so two same-named secrets need two manifest entries —
/// counting only the manifest secrets an earlier run would have issued (those
/// not already expired when the backup was taken). An unnamed secret is
/// listed as "(unnamed)".
fn foreign_secrets(
    hit: &Application,
    app: &AppRegistrationBackup,
    taken_at: DateTime<Utc>,
) -> Vec<String> {
    let mut budget: HashMap<String, usize> = HashMap::new();
    for meta in app
        .secrets
        .iter()
        .filter(|m| !expired_at_backup(m, taken_at))
    {
        let name = meta
            .display_name
            .clone()
            .unwrap_or_else(|| "restored".into());
        *budget.entry(name).or_default() += 1;
    }
    let mut foreign = Vec::new();
    for live in &hit.password_credentials {
        let name = live
            .display_name
            .clone()
            .unwrap_or_else(|| "(unnamed)".into());
        match budget.get_mut(&name) {
            Some(n) if *n > 0 => *n -= 1,
            _ => foreign.push(name),
        }
    }
    foreign
}

/// The owners of an adoption candidate that neither the operator nor the
/// manifest accounts for, labelled for the runbook item (UPN, else display
/// name, else object id). `allowed` holds destination object ids.
fn unexpected_owners(owners: &[DirectoryObject], allowed: &HashSet<String>) -> Vec<String> {
    owners
        .iter()
        .filter(|o| !allowed.contains(&o.id))
        .map(|o| {
            o.user_principal_name
                .clone()
                .or_else(|| o.display_name.clone())
                .unwrap_or_else(|| o.id.clone())
        })
        .collect()
}

/// The whole Pass-1 decision for one manifest app: tag lookup, [`adoption_for`],
/// then the owner and federated-credential checks that make an adoption
/// provable.
///
/// The tag and the display name are both writable by anyone allowed to register
/// apps, and source appIds are not secret — so a pre-seeded app with the right
/// tag and name would otherwise be adopted and then handed the manifest's
/// permissions, fresh secrets and tenant-wide admin consent while keeping its
/// planter as an owner. An app this restore created has no owners but the
/// operator (`operator_oid`, the signed-in account in the destination) and the
/// manifest's own owners (resolved through the run's `principals` memo, which
/// Pass 2 then reuses), so any other owner is refused by name. Every read that
/// fails refuses too: neither adopting nor creating blind is safe.
async fn decide_adoption(
    client: &GraphClient,
    app: &AppRegistrationBackup,
    taken_at: DateTime<Utc>,
    cloud: CloudEnvironment,
    operator_oid: Option<&str>,
    principals: &mut PrincipalMemo,
    session: &SessionDead,
) -> Adoption {
    // Looked up by the restore tag, the only key that survives the tenant move
    // — the appId changes, and `api://{new}` is not in the manifest.
    let hits = match client
        .find_applications_by_tag(&restore_marker(&app.source_app_id))
        .await
    {
        Ok(hits) => hits,
        Err(e) => {
            session.note_code(e.ui_code());
            return Adoption::Refuse(format!(
                "Couldn't check whether an earlier restore already created this app ({e}); it \
                 was NOT created, to avoid a duplicate. Run the restore again once the read \
                 succeeds."
            ));
        }
    };
    let adoption = adoption_for(app, &hits, taken_at);
    let Adoption::Adopt {
        object_id, app_id, ..
    } = &adoption
    else {
        return adoption;
    };
    let owners = match client.list_owners(object_id).await {
        Ok(owners) => owners,
        Err(e) => {
            session.note_code(e.ui_code());
            return Adoption::Refuse(format!(
                "Couldn't read the owners of '{}' (appId {app_id}), which carries this app's \
                 restore tag ({e}), so it was neither adopted nor created again. Run the restore \
                 again once the read succeeds.",
                app.display_name
            ));
        }
    };
    let mut allowed: HashSet<String> = operator_oid
        .filter(|oid| !oid.is_empty())
        .map(str::to_owned)
        .into_iter()
        .collect();
    // Resolve the manifest's owners only when someone besides the operator owns it.
    if owners.iter().any(|o| !allowed.contains(&o.id)) {
        for owner in &app.owners {
            if let Ok(id) = resolve_principal(client, principals, owner, session).await {
                allowed.insert(id);
            }
        }
    }
    // A lookup that failed because the session died leaves that owner out of
    // `allowed`; refusing "owners this restore did not set" would then send
    // the operator after a problem that does not exist.
    if session.is_dead() {
        return Adoption::Refuse(format!(
            "The sign-in session ended while checking '{}' (appId {app_id}), which carries this \
             app's restore tag, so it was neither adopted nor created again. Sign in again and \
             run the restore again.",
            app.display_name
        ));
    }
    let extra = unexpected_owners(&owners, &allowed);
    if !extra.is_empty() {
        return Adoption::Refuse(format!(
            "'{}' (appId {app_id}) carries this app's restore tag, but it has owners this restore \
             did not set: {}. Anyone who can register apps can write that tag and name, so it was \
             not adopted (that would give it this app's permissions and admin consent) and not \
             created again. Find out who created it: if it is legitimate, remove those owners and \
             run the restore again; otherwise delete it to have the restore recreate the app.",
            app.display_name,
            extra.join(", ")
        ));
    }
    // Federated credentials are the one standing trust the owner check cannot
    // see, and the one a planter would leave: a same-named credential with
    // another issuer used to be kept by Pass 2 as "already exists", and a
    // credential the manifest never names was never looked at. Every live one
    // must match a manifest entry on name, issuer, subject and audiences; a
    // flexible one (no subject — matched by a claims expression v1.0 does not
    // return) can never be matched, and a restore never creates one, so it is
    // foreign. A failed read refuses like the other two.
    let live_fics = match client.list_federated_credentials(object_id).await {
        Ok(list) => list,
        Err(e) => {
            session.note_code(e.ui_code());
            return Adoption::Refuse(format!(
                "Couldn't read the federated credentials of '{}' (appId {app_id}), which carries \
                 this app's restore tag ({e}), so it was neither adopted nor created again. Run the \
                 restore again once the read succeeds.",
                app.display_name
            ));
        }
    };
    let manifest_fics: HashSet<FicKey> = app
        .federated_credentials
        .iter()
        .map(|f| fic_key(f, cloud))
        .collect();
    let foreign: Vec<String> = live_fics
        .iter()
        .filter(|f| f.subject.is_none() || !manifest_fics.contains(&fic_key(f, cloud)))
        .map(|f| {
            format!(
                "'{}' (issuer {}, subject {})",
                f.name,
                f.issuer,
                f.subject.as_deref().unwrap_or("(none)")
            )
        })
        .collect();
    if !foreign.is_empty() {
        return Adoption::Refuse(format!(
            "'{}' (appId {app_id}) carries this app's restore tag, but it holds federated \
             credential(s) the backup does not name: {}. Each lets an external issuer sign in as \
             this app with no secret, so it was not adopted (that would give it this app's \
             permissions and admin consent) and not created again. Find out who added them; delete \
             the app to have the restore recreate it.",
            app.display_name,
            foreign.join(", ")
        ));
    }
    adoption
}

/// The fields a federated credential is matched on between the manifest and a
/// live app — name, issuer, subject and audiences (the cloud default when the
/// manifest lists none) — the same tuple Pass 2 creates it with, so "already
/// exists" means the same credential, never a same-named one.
type FicKey = (String, String, Option<String>, Vec<String>);

fn fic_key(fic: &FederatedIdentityCredential, cloud: CloudEnvironment) -> FicKey {
    let mut audiences = if fic.audiences.is_empty() {
        vec![cloud.token_exchange_audience().to_string()]
    } else {
        fic.audiences.clone()
    };
    audiences.sort();
    (
        fic.name.clone(),
        fic.issuer.clone(),
        fic.subject.clone(),
        audiences,
    )
}

/// Dry-run analysis of restoring `backup` into the current tenant — counts,
/// warnings and the privileged grants, no writes. The frontend shows this
/// before the operator confirms the (irreversible) restore: the work of all
/// five passes, the hard blockers (a cross-cloud manifest, a too-new
/// `schema_version` and a malformed or repeated source appId, which
/// [`restore_tenant`] still enforces on its own), whether the destination is
/// the tenant the backup was taken from, and — read-only, against the
/// destination — what the file would grant ([`privileged_restore_items`]). A
/// blocked manifest still returns a plan — carrying the blocker — so the
/// operator sees why before Confirm.
#[tauri::command]
pub async fn plan_restore(
    state: State<'_, AppState>,
    tenant_id: String,
    backup: TenantBackup,
) -> Result<RestorePlan, UiError> {
    let mut plan = build_restore_plan(&backup, tenant_id.clone(), state.auth.cloud());
    if plan.is_blocked() {
        return Ok(plan);
    }
    let client = state.graph_for(&tenant_id);
    let session = SessionDead::new();
    plan.privileged = privileged_restore_items(&client, &backup, &session).await;
    // Every permission would read "unknown" — a plan that says so is no plan.
    if session.is_dead() {
        return Err(session.err("the restore plan"));
    }
    Ok(plan)
}

/// Refuses a manifest written by a *newer* build.
///
/// A restore is not a read — it mutates the tenant before anyone can inspect
/// the result — so a manifest carrying fields this build cannot interpret has
/// to be rejected rather than partially applied. `schema_version` exists for
/// exactly this refusal and was never checked.
///
/// Only the future direction is rejected: every field is `serde(default)` and
/// additive, so an older manifest restores correctly, and refusing one would
/// break the DR case the format was versioned to support.
fn check_manifest_schema(schema_version: u32) -> Result<(), UiError> {
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
fn schema_too_new(schema_version: u32) -> Option<SchemaTooNew> {
    (schema_version > BACKUP_SCHEMA_VERSION).then_some(SchemaTooNew {
        manifest_version: schema_version,
        supported_version: BACKUP_SCHEMA_VERSION,
    })
}

/// How many manifest problems are named individually; the rest are counted.
/// A hostile file can repeat one id thousands of times, and the plan has to
/// stay readable.
const MAX_MANIFEST_PROBLEMS: usize = 10;

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
fn validate_manifest(backup: &TenantBackup) -> Result<(), UiError> {
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
fn manifest_problems(backup: &TenantBackup) -> Vec<String> {
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
const MAX_ECHOED_CHARS: usize = 80;

/// `value` cut to [`MAX_ECHOED_CHARS`] characters (never mid-character), with
/// an ellipsis when cut: a hostile file's multi-megabyte display name must not
/// become the plan's text.
fn excerpt(value: &str) -> String {
    excerpt_to(value, MAX_ECHOED_CHARS)
}

/// `value` cut to `max` characters (never mid-character), with an ellipsis
/// when cut. Copies only what it keeps.
fn excerpt_to(value: &str, max: usize) -> String {
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
const MAX_REPORT_VALUE_CHARS: usize = 1024;

/// Longest warning or runbook reason the report carries, in characters. These
/// compose several values with prose — every federated credential a withheld
/// app would have had (up to 20, each issuer and subject up to 600), every
/// permission a skipped consent covered — so they get room for that worst case
/// rather than one value's cap.
const MAX_REPORT_LINE_CHARS: usize = 32 * 1024;

fn cap_report_value(text: &mut String) {
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
fn bound_report_text(report: &mut RestoreReport) {
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

/// Pure dry-run analysis (no I/O): the counts plus the cloud/schema/tenant
/// checks derived from the backup. Split out from [`plan_restore`] so it is unit-testable
/// without an `AppState`. `dest_cloud` is the destination build's cloud.
fn build_restore_plan(
    backup: &TenantBackup,
    tenant_id: String,
    dest_cloud: CloudEnvironment,
) -> RestorePlan {
    let cloud_mismatch = (backup.cloud != dest_cloud).then_some(CloudMismatch {
        backup_cloud: backup.cloud,
        destination_cloud: dest_cloud,
    });
    let sum = |f: fn(&AppRegistrationBackup) -> usize| -> usize {
        backup.app_registrations.iter().map(f).sum()
    };
    let taken_at = backup.created_at;
    let expired_secrets_skipped: usize = backup
        .app_registrations
        .iter()
        .flat_map(|a| &a.secrets)
        .filter(|m| expired_at_backup(m, taken_at))
        .count();
    // Pass 4 forecast, mirroring `restore_enterprise_app`: an enterprise app is
    // replayed only when it is not foreign and its app registration is in this
    // backup with a service principal (Pass 1 creates the SP only then);
    // everything else becomes a runbook item.
    let with_sp: HashSet<&str> = backup
        .app_registrations
        .iter()
        .filter(|a| a.has_service_principal)
        .map(|a| a.source_app_id.as_str())
        .collect();
    let enterprise_apps_to_reapply = backup
        .enterprise_apps
        .iter()
        .filter(|e| !e.is_foreign_tenant && with_sp.contains(e.source_app_id.as_str()))
        .count();
    RestorePlan {
        cloud_mismatch,
        schema_too_new: schema_too_new(backup.schema_version),
        invalid_manifest: manifest_problems(backup),
        tenant_changed: backup.source_tenant_id != tenant_id,
        source_tenant_id: excerpt(&backup.source_tenant_id),
        destination_tenant_id: tenant_id,
        app_registrations_to_create: backup.app_registrations.len(),
        secrets_to_regenerate: sum(|a| a.secrets.len()) - expired_secrets_skipped,
        expired_secrets_skipped,
        certificates_needing_manual_upload: sum(|a| a.certificates.len()),
        // A flexible credential (no subject) is reported, not recreated — see
        // `restorable_fic_subject` — so the preview does not promise it.
        federated_credentials_to_restore: sum(|a| {
            a.federated_credentials
                .iter()
                .filter(|f| f.subject.is_some())
                .count()
        }),
        owners_to_remap: sum(|a| a.owners.len()),
        enterprise_apps_to_reapply,
        enterprise_apps_manual: backup.enterprise_apps.len() - enterprise_apps_to_reapply,
        managed_identities_to_rebind: backup.managed_identities.len(),
        skipped_in_backup: backup.skipped.len(),
        // Needs the destination; `plan_restore` fills it.
        privileged: Vec::new(),
    }
}

/// How Pass 3 and the plan treat a manifest permission's resource.
enum ResourceLookup {
    Found(Box<ServicePrincipal>),
    /// No service principal with that appId in the destination.
    Absent,
    /// The read failed.
    Failed,
}

/// The appIds of every resource an admin-consenting app declares, deduplicated
/// and sorted — the resources a plan has to resolve.
fn consent_resources(backup: &TenantBackup) -> Vec<String> {
    let ids: std::collections::BTreeSet<&str> = backup
        .app_registrations
        .iter()
        .filter(|a| a.admin_consent_granted)
        .flat_map(|a| &a.required_resource_access)
        .map(|r| r.resource_app_id.as_str())
        .collect();
    ids.into_iter().map(str::to_owned).collect()
}

/// Resolves each resource live (`resolve_resource_sp`, after one batched
/// prewarm), noting failures through `session`. Stops at a dead session: every
/// later read would fail the same way.
async fn resolve_resources(
    client: &GraphClient,
    ids: &[String],
    session: &SessionDead,
) -> HashMap<String, ResourceLookup> {
    let mut out = HashMap::new();
    if ids.is_empty() {
        return out;
    }
    client.prewarm_resource_sps(ids).await;
    for id in ids {
        if session.is_dead() {
            break;
        }
        let lookup = match client.resolve_resource_sp(id).await {
            Ok(Some(sp)) => ResourceLookup::Found(Box::new(sp)),
            Ok(None) => ResourceLookup::Absent,
            Err(e) => {
                session.note_code(e.ui_code());
                ResourceLookup::Failed
            }
        };
        out.insert(id.clone(), lookup);
    }
    out
}

/// The risk of an application permission `value`, from `core::audit`.
fn app_role_risk(value: &str) -> PermissionRisk {
    match risk_level_for_app_permission(value) {
        Some(RiskLevel::High | RiskLevel::Critical) => PermissionRisk::High,
        Some(RiskLevel::Medium) => PermissionRisk::Medium,
        _ => PermissionRisk::Low,
    }
}

/// The permissions admin consent would grant `app`, resolved against the
/// destination: `(application, delegated)`.
///
/// A value that cannot be resolved is shown by id with [`PermissionRisk::Unknown`]
/// — a permission nobody can name is treated as high-risk for approval —
/// except on an API this backup itself recreates (`restored_api`): its values
/// are not knowable until it exists, and its roles grant access only to that
/// fresh, empty app.
fn consent_permissions(
    app: &AppRegistrationBackup,
    resources: &HashMap<String, ResourceLookup>,
    in_backup: &HashSet<&str>,
) -> (Vec<PrivilegedPermission>, Vec<PrivilegedPermission>) {
    let mut roles = Vec::new();
    let mut scopes = Vec::new();
    for rra in &app.required_resource_access {
        let lookup = resources.get(&rra.resource_app_id);
        let sp = match lookup {
            Some(ResourceLookup::Found(sp)) => Some(sp.as_ref()),
            _ => None,
        };
        let restored_api = matches!(lookup, Some(ResourceLookup::Absent))
            && in_backup.contains(rra.resource_app_id.as_str());
        for access in &rra.resource_access {
            let is_role = access.r#type == "Role";
            let value = sp
                .and_then(|sp| {
                    if is_role {
                        sp.app_roles
                            .iter()
                            .find(|r| r.id == access.id)
                            .map(|r| r.value.clone())
                    } else {
                        sp.oauth2_permission_scopes
                            .iter()
                            .find(|s| s.id == access.id)
                            .map(|s| s.value.clone())
                    }
                })
                .filter(|v| !v.is_empty());
            let risk = match (&value, is_role) {
                (Some(v), true) => app_role_risk(v),
                (Some(v), false) if is_risky_delegated_scope(v) => PermissionRisk::High,
                (Some(_), false) => PermissionRisk::Low,
                (None, _) if restored_api => PermissionRisk::Low,
                (None, _) => PermissionRisk::Unknown,
            };
            // The resource and permission ids come from the file; the name
            // and value were resolved in the destination.
            let perm = PrivilegedPermission {
                resource_app_id: excerpt(&rra.resource_app_id),
                resource_display_name: sp.map(|sp| sp.display_name.clone()),
                permission_id: excerpt(&access.id),
                value,
                risk,
                restored_api,
            };
            if is_role {
                roles.push(perm);
            } else {
                scopes.push(perm);
            }
        }
    }
    (roles, scopes)
}

/// Whether an app's admin consent needs the operator's approval: it covers any
/// application permission (app-only access; the risk lists are a short
/// denylist, not proof a permission is harmless), or a delegated one that is
/// broad or that nobody can name.
fn consent_needs_approval(
    app_roles: &[PrivilegedPermission],
    delegated: &[PrivilegedPermission],
) -> bool {
    !app_roles.is_empty()
        || delegated
            .iter()
            .any(|p| matches!(p.risk, PermissionRisk::High | PermissionRisk::Unknown))
}

/// The enterprise apps Pass 4 may replay onto `app`'s service principal:
/// every non-foreign one for the app, exactly what [`restore_enterprise_app`]
/// accepts. Deliberately NOT conditioned on `has_service_principal`: the SP
/// can exist anyway (Pass 3's consent creates one; an adopted app may already
/// have one), and Pass 4 replays onto whatever SP it finds.
fn replayed_enterprise_apps<'a>(
    backup: &'a TenantBackup,
    app: &'a AppRegistrationBackup,
) -> impl Iterator<Item = &'a EnterpriseAppBackup> {
    backup
        .enterprise_apps
        .iter()
        .filter(move |e| !e.is_foreign_tenant && e.source_app_id == app.source_app_id)
}

/// What restoring `backup` grants from the file, per app registration and
/// managed identity: the admin consent Pass 3 re-grants (values resolved live,
/// risk-ranked by `core::audit`), federated credentials (issuer + subject, and
/// whether validation will refuse them), owners, the groups Pass 4 adds the
/// service principal to, and the Graph app roles Pass 5 re-binds — plus, shown
/// only, pre-authorized clients this backup does not recreate and the users
/// and groups assigned to the app's roles. Read-only.
///
/// Shared by the plan and by [`run_restore`], which recomputes it rather than
/// trusting the front end, so the approval gate holds for any caller.
async fn privileged_restore_items(
    client: &GraphClient,
    backup: &TenantBackup,
    session: &SessionDead,
) -> Vec<PrivilegedRestoreItem> {
    // Exact, as `remap_required_resource_access` (Pass 2's resource remap) is.
    let in_backup: HashSet<&str> = backup
        .app_registrations
        .iter()
        .map(|a| a.source_app_id.as_str())
        .collect();
    // Ignoring case, as Pass 2's `plan_pre_authorized` is: a client is foreign
    // here exactly when the run would write it as listed.
    let backup_apps = backup_apps(backup);
    let resources = resolve_resources(client, &consent_resources(backup), session).await;
    let mut items = Vec::new();
    for app in &backup.app_registrations {
        let (app_roles, delegated_scopes) = if app.admin_consent_granted {
            consent_permissions(app, &resources, &in_backup)
        } else {
            (Vec::new(), Vec::new())
        };
        let mut external: Vec<String> = app
            .pre_authorized_applications
            .iter()
            .filter(|p| !backup_apps.contains(&p.app_id))
            .map(|p| excerpt(&p.app_id))
            .collect();
        // One per client, as the run writes them.
        external.sort_by_key(|id| id.to_ascii_lowercase());
        external.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        let federated_credentials: Vec<PlannedFederatedCredential> = app
            .federated_credentials
            .iter()
            .filter_map(|fic| {
                let subject = restorable_fic_subject(fic).ok()?;
                let audiences = if fic.audiences.is_empty() {
                    vec![backup.cloud.token_exchange_audience().to_string()]
                } else {
                    fic.audiences.clone()
                };
                // Validator prose quoting a value `core::federation` has
                // already held to its 600-character ceiling, but Debug-escaped,
                // so possibly several times longer. Capped like a report value:
                // bounded, without cutting the explanation the way an
                // 80-character excerpt would.
                let rejected = validate_federated_credential(
                    Some(&fic.name),
                    &fic.issuer,
                    subject,
                    &audiences,
                    fic.description.as_deref(),
                )
                .err()
                .map(|reason| excerpt_to(&reason, MAX_REPORT_VALUE_CHARS));
                Some(PlannedFederatedCredential {
                    name: excerpt(&fic.name),
                    issuer: excerpt(&fic.issuer),
                    subject: excerpt(subject),
                    rejected,
                })
            })
            .collect();
        let group_memberships: Vec<String> = replayed_enterprise_apps(backup, app)
            .flat_map(|e| &e.group_memberships)
            .map(|g| excerpt(&owner_label(g)))
            .collect();
        let app_role_assignees: Vec<String> = replayed_enterprise_apps(backup, app)
            .flat_map(|e| &e.app_role_assignees)
            .map(|a| {
                let who = excerpt(&owner_label(&a.principal));
                match a.app_role_value.as_deref().filter(|v| !v.is_empty()) {
                    Some(role) => format!("{who} ({})", excerpt(role)),
                    None => who,
                }
            })
            .collect();
        let owners: Vec<String> = app
            .owners
            .iter()
            .map(|o| excerpt(&owner_label(o)))
            .collect();
        // Only what Pass 2 would write: the same validator, refusals dropped
        // here (the report names them when the write happens).
        let reply_urls: Vec<String> = [
            &app.web_redirect_uris,
            &app.spa_redirect_uris,
            &app.public_client_redirect_uris,
        ]
        .into_iter()
        .flat_map(|uris| checked_uris(uris, "", &mut Vec::new()))
        .map(|u| excerpt(&u))
        .collect();
        let public_client = app.is_fallback_public_client;
        let grants_consent = !app_roles.is_empty() || !delegated_scopes.is_empty();
        let adds_trust = federated_credentials.iter().any(|f| f.rejected.is_none());
        // Owners, reply URLs and the public-client flag are harmless on their
        // own and standing access with consent behind them: an owner can add
        // a secret, and a reply URL is where consented tokens are delivered,
        // so an app the file both consents and points somewhere needs the
        // operator's eyes. Low-risk delegated consent alone still does not.
        let routes_tokens = !owners.is_empty() || !reply_urls.is_empty() || public_client;
        let requires_approval = (grants_consent
            && (consent_needs_approval(&app_roles, &delegated_scopes) || routes_tokens))
            || adds_trust
            || !group_memberships.is_empty();
        let shown = grants_consent
            || !external.is_empty()
            || !federated_credentials.is_empty()
            || !group_memberships.is_empty()
            || !app_role_assignees.is_empty()
            || routes_tokens;
        if !shown {
            continue;
        }
        items.push(PrivilegedRestoreItem {
            kind: PrivilegedKind::App,
            source_app_id: app.source_app_id.clone(),
            display_name: excerpt(&app.display_name),
            admin_consent: grants_consent,
            requires_approval,
            app_roles,
            delegated_scopes,
            external_pre_authorized_clients: external,
            federated_credentials,
            owners,
            group_memberships,
            app_role_assignees,
            reply_urls,
            public_client,
        });
    }
    for mi in &backup.managed_identities {
        let app_roles: Vec<PrivilegedPermission> = mi
            .held_app_roles
            .iter()
            .map(|r| {
                // Every field here comes from the file. Risk is ranked on the
                // whole value, then each is shown as an excerpt.
                let value = r.app_role_value.as_deref().filter(|v| !v.is_empty());
                PrivilegedPermission {
                    resource_app_id: excerpt(&r.resource_app_id),
                    resource_display_name: r.resource_display_name.as_deref().map(excerpt),
                    permission_id: excerpt(&r.app_role_id),
                    // No value: Pass 5 cannot re-bind it at all (a warning).
                    risk: value.map_or(PermissionRisk::Unknown, app_role_risk),
                    value: value.map(excerpt),
                    restored_api: false,
                }
            })
            .collect();
        if app_roles.is_empty() {
            continue;
        }
        items.push(PrivilegedRestoreItem {
            kind: PrivilegedKind::ManagedIdentity,
            source_app_id: mi.source_app_id.clone(),
            display_name: excerpt(&mi.display_name),
            // Every app role is app-only access to the resource.
            requires_approval: true,
            app_roles,
            ..Default::default()
        });
    }
    items
}

/// The label a permission gets in a report line: its value, else its id.
fn permission_label(p: &PrivilegedPermission) -> String {
    match &p.value {
        Some(v) => v.clone(),
        None => format!(
            "unidentified permission {} on {}",
            p.permission_id, p.resource_app_id
        ),
    }
}

/// The backup's own app registrations, for classifying pre-authorized clients
/// ([`plan_pre_authorized`]) the same way in the plan and in Pass 2.
fn backup_apps(backup: &TenantBackup) -> BackupApps {
    BackupApps::new(
        backup
            .app_registrations
            .iter()
            .map(|a| (a.source_app_id.as_str(), a.display_name.as_str())),
    )
}

/// The approval key for an app registration.
fn app_approval(source_app_id: &str) -> RestoreApproval {
    RestoreApproval {
        kind: PrivilegedKind::App,
        source_app_id: source_app_id.to_string(),
    }
}

/// The app registrations whose standing access the run withholds: approval
/// required ([`PrivilegedRestoreItem::requires_approval`]) and not given. Maps
/// source appId → the permissions its admin consent would have granted, for the
/// report. Skips the reads entirely when every app is approved.
async fn unapproved_apps(
    client: &GraphClient,
    backup: &TenantBackup,
    approved: &HashSet<RestoreApproval>,
    session: &SessionDead,
) -> HashMap<String, Vec<String>> {
    let any_unapproved = backup
        .app_registrations
        .iter()
        .any(|a| !approved.contains(&app_approval(&a.source_app_id)));
    if !any_unapproved {
        return HashMap::new();
    }
    privileged_restore_items(client, backup, session)
        .await
        .into_iter()
        .filter(|i| {
            i.kind == PrivilegedKind::App
                && i.requires_approval
                && !approved.contains(&app_approval(&i.source_app_id))
        })
        .map(|i| {
            let consent = i
                .app_roles
                .iter()
                .chain(&i.delegated_scopes)
                .map(permission_label)
                .collect();
            (i.source_app_id, consent)
        })
        .collect()
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

/// Replays the backup (app registrations, enterprise apps, managed-identity
/// permissions) into the current tenant. See the module docs for the pass
/// structure. Busts the destination list caches on a
/// run that created anything.
///
/// `approvals` are the `RestorePlan.privileged` items the operator approved,
/// by kind and source appId. An item that
/// [requires approval](crate::dto::backup::PrivilegedRestoreItem::requires_approval)
/// and is not named here is still created and wired, but gets no standing
/// access from the file: an app's admin consent, federated credentials,
/// owners and group memberships, a managed identity's app roles — each
/// withheld one a runbook item.
#[tauri::command]
pub async fn restore_tenant(
    app_handle: AppHandle,
    state: State<'_, AppState>,
    tenant_id: String,
    backup: TenantBackup,
    approvals: Vec<RestoreApproval>,
) -> Result<RestoreReport, UiError> {
    check_manifest_schema(backup.schema_version)?;
    validate_manifest(&backup)?;

    // A cross-cloud restore is never valid: endpoints and well-known appIds
    // differ, so the remapped permissions would point at the wrong resources.
    let cloud = state.auth.cloud();
    if backup.cloud != cloud {
        return Err(UiError::validation(
            "cloud_mismatch",
            format!(
                "backup is from cloud '{}', but this build targets '{}'",
                backup.cloud.as_str(),
                cloud.as_str()
            ),
        ));
    }

    let client = state.graph_for(&tenant_id);
    // One cancel token for the whole restore, claimed before the first await.
    // Claiming per pass would take a new generation each time and lose a cancel
    // the operator issued during an earlier pass.
    let cancel = state.restore_cancel.claim();
    // The signed-in account's object id in the destination: the one owner an
    // app this restore created may have besides the manifest's own.
    let operator_oid = state.auth.tenant_context(&tenant_id).map(|t| t.account_oid);
    let approved: HashSet<RestoreApproval> = approvals.into_iter().collect();
    let (report, effects) = run_restore(
        &client,
        &app_handle,
        cancel,
        RestoreRun {
            backup: &backup,
            tenant_id: &tenant_id,
            cloud,
            operator_oid: operator_oid.as_deref(),
            approved: &approved,
        },
    )
    .await;
    // Anything created means the destination's lists/details/audit are stale.
    // Only on the success path (we're returning Ok). A run that created nothing
    // but re-bound a managed identity's roles changed what the audit scores.
    if effects.created_any {
        invalidate_app_lists(&state.cache, &tenant_id);
    } else if effects.rebound_any {
        crate::commands::audit::invalidate_audit_cache(&state.cache, &tenant_id);
    }
    Ok(report)
}

/// What a run changed in the destination that a cache may still describe.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RestoreEffects {
    /// An app was created or adopted: the list tier is stale.
    created_any: bool,
    /// A managed identity's app roles were re-bound: the audit run is stale.
    rebound_any: bool,
}

/// What one restore run replays, and into where.
struct RestoreRun<'a> {
    backup: &'a TenantBackup,
    /// The destination tenant.
    tenant_id: &'a str,
    cloud: CloudEnvironment,
    operator_oid: Option<&'a str>,
    /// Items approved in the plan (see [`restore_tenant`]).
    approved: &'a HashSet<RestoreApproval>,
}

/// The borrowed inputs the per-app helpers of Passes 2-4 share, built once
/// Pass 1 has stopped changing the remap.
///
/// The principal memo stays a separate `&mut` parameter, and so does the
/// cancel token: the repo invariants find a pass helper as a cancel runner by
/// the `CancelToken` in its signature (`sources::cancel_runners`).
struct PassCtx<'a> {
    client: &'a GraphClient,
    /// The run's one dead-session latch; every failure is noted through it.
    session: &'a SessionDead,
    /// `source_app_id → new app id`, final once Pass 1 ends.
    app_id_remap: &'a HashMap<String, String>,
    cloud: CloudEnvironment,
    /// When the backup was taken: the cutoff for [`expired_at_backup`].
    taken_at: DateTime<Utc>,
    /// The tenant the backup was taken from.
    source_tenant_id: &'a str,
    /// The destination tenant.
    dest_tenant_id: &'a str,
}

/// The five passes of [`restore_tenant`], split from the command the way
/// [`restore_managed_identities`] is, so the pass loop runs in a test against a
/// mock Graph. Returns the report and what the run changed ([`RestoreEffects`],
/// which the caller busts caches on).
///
/// Stops at the next item on `cancel` and on a dead session — in every pass,
/// and inside each pass's per-item loops; both flag the report.
async fn run_restore(
    client: &GraphClient,
    progress: &impl ProgressSink,
    cancel: CancelToken,
    run: RestoreRun<'_>,
) -> (RestoreReport, RestoreEffects) {
    let RestoreRun {
        backup,
        tenant_id,
        cloud,
        operator_oid,
        approved,
    } = run;
    let total = backup.app_registrations.len();
    emit(progress, 0, total, None);

    let mut report = RestoreReport::default();
    // source_app_id → new app id, for remapping cross-app references.
    let mut app_id_remap: HashMap<String, String> = HashMap::new();
    // Per-run principal-resolution memo (UPN/group display name → destination
    // object id), shared across passes so a principal reused across owners,
    // assignees, and group memberships is searched once, not per occurrence.
    let mut principals = PrincipalMemo::new();
    // The apps we actually created, paired with their backup + new ids, so
    // passes 2–3 wire exactly those.
    let mut created: Vec<CreatedApp> = Vec::new();
    // One latch across all five passes: the first re-auth-fatal error stops the
    // rest instead of letting each remaining item fail the same way.
    let session = SessionDead::new();
    // The apps whose standing access passes 2-4 withhold — recomputed here,
    // before anything is created, from the same classification the plan
    // showed, rather than taken from the front end.
    let withheld = unapproved_apps(client, backup, approved, &session).await;

    // ---- Pass 1: create shells ----
    let mut done = 0;
    for app in &backup.app_registrations {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        // A dead session makes every remaining create fail identically, so the
        // loop would otherwise manufacture one indistinguishable failure per
        // remaining app and report them as if the tenant had rejected them.
        if session.is_dead() {
            report.cancelled = true;
            break;
        }
        // Has an earlier run of this restore already created it? Every read
        // failure and every unprovable match is refused into a runbook item:
        // creating blind is how a re-run duplicates apps, and adopting blind
        // would hand someone else's app this one's permissions and consent.
        match decide_adoption(
            client,
            app,
            backup.created_at,
            cloud,
            operator_oid,
            &mut principals,
            &session,
        )
        .await
        {
            Adoption::Refuse(reason) => {
                report.manual_items.push(ManualItem {
                    display_name: app.display_name.clone(),
                    reason,
                });
                done += 1;
                emit(progress, done, total, Some(app.display_name.clone()));
                continue;
            }
            Adoption::Adopt {
                object_id,
                app_id,
                live_secret_names,
            } => {
                let mut warnings = Vec::new();
                // The earlier run may have died between the app POST and its
                // SP; `ensure_service_principal` is a no-op when it exists.
                if app.has_service_principal
                    && let Err(e) = client.ensure_service_principal(&app_id).await
                {
                    session.note_code(e.ui_code());
                    warnings.push(format!("service principal: {e}"));
                }
                app_id_remap.insert(app.source_app_id.clone(), app_id.clone());
                created.push(CreatedApp {
                    backup: app.clone(),
                    new_object_id: object_id,
                    new_app_id: app_id,
                    adopted: true,
                    live_secret_names,
                    warnings,
                });
                done += 1;
                emit(progress, done, total, Some(app.display_name.clone()));
                continue;
            }
            Adoption::Create => {}
        }
        let input = CreateApplicationInput {
            display_name: app.display_name.clone(),
            sign_in_audience: app.sign_in_audience.clone(),
            description: app.description.clone(),
            create_service_principal: app.has_service_principal,
            initial_owner_ids: Vec::new(),
            initial_secret_display_name: None,
            initial_secret_lifetime_days: None,
        };
        // The tag rides the create POST itself, so no app this restore creates
        // can exist without it — not even one whose SP create then failed.
        let marker = restore_marker(&app.source_app_id);
        match create_application_core_with(
            client,
            input,
            CreateExtras {
                tags: vec![marker],
                ..Default::default()
            },
        )
        .await
        {
            // The registration landed even when its SP then failed (the only
            // later step this input runs): record it as created — so it is
            // wired, counted and cache-busted — with the SP failure as a
            // warning, exactly as the adopt branch above does. Recording it as
            // a failure hid an app that exists.
            Ok((res, error)) => {
                let mut warnings = Vec::new();
                if let Some(e) = error {
                    session.note_code(&e.code);
                    warnings.push(format!("service principal: {}", e.message));
                }
                app_id_remap.insert(app.source_app_id.clone(), res.application.app_id.clone());
                created.push(CreatedApp {
                    backup: app.clone(),
                    new_object_id: res.application.id,
                    new_app_id: res.application.app_id,
                    adopted: false,
                    live_secret_names: Vec::new(),
                    warnings,
                });
            }
            Err(e) => {
                session.note_code(&e.code);
                report.failures.push(RestoreFailure {
                    display_name: app.display_name.clone(),
                    source_app_id: app.source_app_id.clone(),
                    message: e.message,
                });
            }
        }
        done += 1;
        emit(progress, done, total, Some(app.display_name.clone()));
    }

    // ---- Pass 2: wire references + regenerate secrets (per created app) ----
    // Every app the backup owns, recreated or not: a pre-authorized client in
    // here with no remap entry is one Pass 1 failed or refused, never foreign.
    let backup_apps = backup_apps(backup);
    // The remap is final from here on: Passes 2-4 share it read-only.
    let ctx = PassCtx {
        client,
        session: &session,
        app_id_remap: &app_id_remap,
        cloud,
        taken_at: backup.created_at,
        source_tenant_id: &backup.source_tenant_id,
        dest_tenant_id: tenant_id,
    };
    for c in &created {
        // Both stop conditions, in every pass. Passes 2-5 once checked only
        // `is_dead()`, so Cancel stopped mattering the moment Pass 1 finished:
        // the operator pressed it and watched the restore keep wiring, granting
        // consent and re-binding roles for every remaining app.
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        let (restored, trusts) = wire_application(
            &ctx,
            c,
            &backup_apps,
            &mut principals,
            &cancel,
            withheld.contains_key(&c.backup.source_app_id),
        )
        .await;
        report.apps.push(restored);
        report.manual_items.extend(trusts);
    }

    // ---- Pass 3: re-consent (after all apps wired, so resources exist) ----
    for (idx, c) in created.iter().enumerate() {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        if !c.backup.admin_consent_granted {
            continue;
        }
        // Not approved in the plan: the file asks for tenant-wide consent the
        // operator has not agreed to grant. The app is still restored; the
        // consent becomes a runbook item.
        if let Some(held) = withheld.get(&c.backup.source_app_id) {
            report.apps[idx]
                .warnings
                .push("admin consent skipped: not approved in the plan".into());
            report.manual_items.push(ManualItem {
                display_name: c.backup.display_name.clone(),
                reason: format!(
                    "Admin consent skipped: not approved in the plan. The backup asks for \
                     tenant-wide consent to {}. Review them, then grant consent from the app's \
                     Permissions tab if they are intended.",
                    if held.is_empty() {
                        "its declared permissions".to_string()
                    } else {
                        held.join(", ")
                    }
                ),
            });
            continue;
        }
        reconsent(&ctx, c, &mut report.apps[idx], &mut report.manual_items).await;
    }

    // ---- Pass 4: enterprise applications ----
    // Re-apply access (assignments + group memberships + settings) for SPs that
    // were recreated by the app-reg restore above. Foreign/gallery apps — and
    // paired apps that weren't restored — become runbook entries.
    for ent in &backup.enterprise_apps {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        // Group memberships always need approval, so they apply only to an app
        // the operator approved — decided from the approvals themselves, never
        // from a classification that could miss an enterprise app.
        restore_enterprise_app(
            &ctx,
            ent,
            !approved.contains(&app_approval(&ent.source_app_id)),
            &mut report,
            &mut principals,
            &cancel,
        )
        .await;
    }

    // ---- Pass 5: managed identities ----
    // MIs are Azure resources — they can't be created here. Re-bind Graph
    // app-roles to any MI already recreated (matched by name and sub-type); Azure RBAC and
    // not-yet-recreated MIs become runbook entries.
    if cancel.is_cancelled() {
        report.cancelled = true;
    } else if !backup.managed_identities.is_empty() && !session.is_dead() {
        restore_managed_identities(
            client,
            &backup.managed_identities,
            approved,
            &mut report,
            &session,
            &cancel,
        )
        .await;
    }

    // Unlike the read-only fan-outs, which return `session.err(..)` rather than
    // a partial result, a restore has already created objects in the tenant —
    // discarding the report would leave the operator with no record of what
    // exists. So the report comes back, flagged, and the front end pairs the
    // flag with the re-auth prompt.
    report.session_expired = session.is_dead();
    // Every text field echoes the file somewhere; bound them all once, here.
    bound_report_text(&mut report);
    emit(progress, total, total, None);
    let effects = RestoreEffects {
        created_any: !created.is_empty(),
        rebound_any: report
            .managed_identities
            .iter()
            .any(|m| m.app_roles_rebound > 0),
    };
    (report, effects)
}

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
async fn reconsent(
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

/// Writes the restore report to a JSON file via the OS save dialog. **The
/// report contains the regenerated client-secret values** (show-once) — it is a
/// secret-bearing artifact; the UI warns the operator to store it securely,
/// redistribute the secrets, then delete it. Returns the path, or `None` if
/// cancelled. JSON only.
#[tauri::command]
pub async fn save_restore_report_to_file(
    app_handle: AppHandle,
    report: RestoreReport,
    format: String,
) -> Result<Option<String>, UiError> {
    if format != "json" {
        return Err(UiError::validation(
            "unsupported_format",
            "restore report is JSON only",
        ));
    }
    // Serialized up front so a failure is an error, never an empty `{}` written
    // as success — this file is the only home of the show-once secret values.
    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| UiError::serde(format!("could not serialize the restore report: {e}")))?;
    super::export::save_export_via_dialog(
        &app_handle,
        "restore-report",
        "json",
        String::new, // unreachable: format validated to "json" above
        move || json,
    )
    .await
}

/// Signals an in-progress [`restore_tenant`] to stop at the next item of
/// whichever pass is running; the report flags the run cancelled.
#[tauri::command]
pub fn cancel_restore(state: State<'_, AppState>) {
    state.restore_cancel.cancel();
}

// ---------------- internals ----------------

/// An app Pass 1 created — or adopted from an earlier run of this restore —
/// paired with its backup and destination ids.
struct CreatedApp {
    backup: AppRegistrationBackup,
    new_object_id: String,
    new_app_id: String,
    /// Recognised by its restore tag rather than created by this run.
    adopted: bool,
    /// For an adopted app, the display names of the secrets it already holds.
    live_secret_names: Vec<String>,
    /// Pass-1 warnings to carry into the app's report entry.
    warnings: Vec<String>,
}

/// The subject a backed-up federated credential is recreated with, or the
/// restore-report warning when it has none.
///
/// A *flexible* credential is matched by a `claimsMatchingExpression` (a
/// beta-only Graph property) instead of a subject, so the v1.0 read backs it up
/// with `subject: null` and nothing to recreate it from. It is skipped with the
/// same "was NOT restored — {reason}" phrasing as a rejected credential.
fn restorable_fic_subject(fic: &FederatedIdentityCredential) -> Result<&str, String> {
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
async fn wire_application(
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
    for fic in fics {
        if cancel.is_cancelled() || session.is_dead() {
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
    for owner in owners {
        if cancel.is_cancelled() || session.is_dead() {
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
    let mut already_issued = c.live_secret_names.clone();
    for meta in &app.secrets {
        if cancel.is_cancelled() || session.is_dead() {
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
        if let Some(pos) = already_issued.iter().position(|n| *n == name) {
            already_issued.swap_remove(pos);
            out.warnings.push(format!(
                "secret '{name}' already exists — not issued again. If an earlier restore run \
                 issued it, its value is in that run's report; compare its key id with that \
                 report, and remove it if it isn't that one"
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

    // Certificates can't be restored (private key never left the source);
    // surface them for manual re-upload from the operator's PKI.
    out.certificates_needing_manual_upload = app
        .certificates
        .iter()
        .map(|c| c.display_name.clone().unwrap_or_else(|| "(unnamed)".into()))
        .collect();

    (out, trusts)
}

/// Default-access app role (the all-zero GUID) — present on every SP, so an
/// assignment to it never needs role remapping.
const DEFAULT_ACCESS_ROLE: &str = "00000000-0000-0000-0000-000000000000";

/// Pass-4 work for one enterprise app. If its service principal was recreated by
/// the app-reg restore, re-applies settings + role assignments + group
/// memberships; otherwise records a runbook entry (foreign/gallery apps and
/// paired apps that weren't restored can't be replayed automatically).
///
/// Every failure is noted through `ctx.session`, as in Pass 2, so a session
/// that dies here stops the restore instead of producing one wrong runbook item
/// per remaining app. `withhold` (its app was not approved in the plan) skips
/// the group memberships into one runbook item; role assignments still apply.
async fn restore_enterprise_app(
    ctx: &PassCtx<'_>,
    ent: &EnterpriseAppBackup,
    withhold: bool,
    report: &mut RestoreReport,
    principals: &mut PrincipalMemo,
    cancel: &CancelToken,
) {
    let PassCtx {
        client,
        session,
        app_id_remap,
        ..
    } = *ctx;
    // Restorable only when its app registration was recreated here.
    let new_app_id = match app_id_remap.get(&ent.source_app_id) {
        Some(id) if !ent.is_foreign_tenant => id.clone(),
        _ => {
            let reason = if ent.is_foreign_tenant {
                "Foreign/gallery enterprise app — re-consent or re-instantiate it from the \
                 gallery in the destination tenant."
            } else {
                "No paired app registration was restored for this enterprise app."
            };
            report.manual_items.push(ManualItem {
                display_name: ent.display_name.clone(),
                reason: reason.into(),
            });
            return;
        }
    };

    // The SP is created alongside its app registration in Pass 1.
    let sp = match client.get_service_principal_by_app_id(&new_app_id).await {
        Ok(Some(sp)) => sp,
        Ok(None) => {
            report.manual_items.push(ManualItem {
                display_name: ent.display_name.clone(),
                reason: "Service principal was not created (the app had none in the backup)."
                    .into(),
            });
            return;
        }
        // A failed read is not an absent SP: saying "the app had none" would
        // send the operator after a problem that does not exist.
        Err(e) => {
            session.note_code(e.ui_code());
            report.manual_items.push(ManualItem {
                display_name: ent.display_name.clone(),
                reason: format!(
                    "Couldn't read the restored service principal ({e}); its access was not \
                     re-applied."
                ),
            });
            return;
        }
    };

    let mut out = RestoredEnterpriseApp {
        display_name: ent.display_name.clone(),
        new_sp_object_id: sp.id.clone(),
        ..Default::default()
    };

    // Settings (best-effort).
    if !ent.tags.is_empty()
        && let Err(e) = client.set_service_principal_tags(&sp.id, &ent.tags).await
    {
        session.note_code(e.ui_code());
        out.warnings.push(format!("tags: {e}"));
    }
    if let Some(required) = ent.app_role_assignment_required {
        let body = serde_json::json!({ "appRoleAssignmentRequired": required });
        if let Err(e) = client.patch_service_principal(&sp.id, &body).await {
            session.note_code(e.ui_code());
            out.warnings.push(format!("assignment-required: {e}"));
        }
    }

    // App-role assignments — principal remapped by name, role by value.
    for assignee in &ent.app_role_assignees {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        let principal_id =
            match resolve_principal(client, principals, &assignee.principal, session).await {
                Ok(id) => id,
                Err(why) => {
                    out.unresolved_principals
                        .push(why.label(&assignee.principal));
                    continue;
                }
            };
        let Some(role_id) = map_assignee_role_id(assignee, &sp.app_roles) else {
            out.warnings.push(format!(
                "role '{}' not found on the restored app; assignment for '{}' skipped",
                assignee.app_role_value.as_deref().unwrap_or("(custom)"),
                owner_label(&assignee.principal),
            ));
            continue;
        };
        match client
            .assign_app_role_to(&sp.id, &principal_id, &role_id)
            .await
        {
            Ok(_) => out.assignments_applied += 1,
            Err(e) => {
                session.note_code(e.ui_code());
                out.warnings.push(format!("assignment: {e}"));
            }
        }
    }

    // Group memberships — resolve each group by display name. The file chooses
    // the group, and a role-assignable group carries a directory role, so an
    // app not approved in the plan joins none of them.
    let groups: &[PrincipalRef] = if withhold {
        if !ent.group_memberships.is_empty() {
            report.manual_items.push(ManualItem {
                display_name: ent.display_name.clone(),
                reason: format!(
                    "Group memberships not added: not approved in the plan ({}). Add the \
                     service principal to them manually if they are intended.",
                    ent.group_memberships
                        .iter()
                        .map(owner_label)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        &[]
    } else {
        &ent.group_memberships
    };
    for group in groups {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        match resolve_principal(client, principals, group, session).await {
            Ok(group_id) => match client.add_group_member(&group_id, &sp.id).await {
                Ok(()) => out.group_memberships_applied += 1,
                Err(e) => {
                    session.note_code(e.ui_code());
                    out.warnings.push(format!("group membership: {e}"));
                }
            },
            Err(why) => out.unresolved_principals.push(why.label(group)),
        }
    }

    report.enterprise_apps.push(out);
}

/// Pass-5 work: re-bind managed-identity permissions. MIs can't be created via
/// Graph (they're Azure resources), so this matches each backed-up MI to one
/// **already recreated** in the destination (by display name and, where both
/// sides know it, sub-type) and re-binds its
/// held Graph app-roles to the new principal. Azure RBAC re-creation, and MIs
/// not yet recreated, are emitted as runbook items (source RBAC scopes don't
/// exist in the destination, so they can't be replayed automatically).
///
/// A failed destination listing is ONE runbook item saying so — never a "not
/// found" item per MI, which would send the infra team to recreate identities
/// that already exist — and is noted through `session`. A name that matches
/// several destination identities re-binds none of them: the backup cannot say
/// which one is this identity.
///
/// Every app role is app-only access, so an MI's roles are re-bound only when
/// `approved` names it (the plan's opt-in); otherwise they are withheld as one
/// runbook item.
async fn restore_managed_identities(
    client: &GraphClient,
    mis: &[ManagedIdentityBackup],
    approved: &HashSet<RestoreApproval>,
    report: &mut RestoreReport,
    session: &SessionDead,
    cancel: &CancelToken,
) {
    let dest = match client.list_managed_identities().await {
        Ok(list) => list,
        Err(e) => {
            session.note_code(e.ui_code());
            report.manual_items.push(ManualItem {
                display_name: format!("Managed identities ({})", mis.len()),
                reason: format!(
                    "Couldn't list the destination's managed identities ({e}), so none were \
                     re-bound and none are reported missing. Run the restore again once the read \
                     succeeds."
                ),
            });
            return;
        }
    };
    // Every destination MI under each name — never a map that keeps only the
    // last, which would re-bind the roles to whichever identity came last.
    let mut by_name: HashMap<String, Vec<(String, MiSubtype)>> = HashMap::new();
    for sp in dest {
        let subtype = MiSubtype::from_alternative_names(&sp.alternative_names);
        by_name
            .entry(sp.display_name.to_ascii_lowercase())
            .or_default()
            .push((sp.id, subtype));
    }

    for mi in mis {
        if cancel.is_cancelled() {
            report.cancelled = true;
            break;
        }
        if session.is_dead() {
            break;
        }
        // By name AND sub-type where both are known: a user-assigned identity
        // created under a system-assigned one's name (or the reverse) is not
        // the identity the backup described, however it is called.
        let matches: Vec<&str> = by_name
            .get(&mi.display_name.to_ascii_lowercase())
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter(|(_, subtype)| subtype_compatible(*subtype, mi.subtype))
            .map(|(id, _)| id.as_str())
            .collect();
        if matches.len() > 1 {
            report.manual_items.push(ManualItem {
                display_name: mi.display_name.clone(),
                reason: format!(
                    "{} managed identities in the destination are named '{}' ({}), so none was \
                     re-bound — the backup cannot say which one is this identity. Rename or \
                     remove the duplicates, then run the restore again with this backup.",
                    matches.len(),
                    mi.display_name,
                    matches.join(", ")
                ),
            });
            continue;
        }
        let Some(principal_id) = matches.first().map(|id| id.to_string()) else {
            let arm = mi
                .arm_resource_id
                .as_deref()
                .map(|a| format!(" — {a}"))
                .unwrap_or_default();
            report.manual_items.push(ManualItem {
                display_name: mi.display_name.clone(),
                reason: format!(
                    "Managed identity ({}{}) not found in the destination. Recreate it via your \
                     infrastructure-as-code, then run the restore again with this backup — apps \
                     it already created are recognised by their restore tag, not duplicated — \
                     to re-bind its Graph app-roles.",
                    mi_subtype_label(mi.subtype),
                    arm
                ),
            });
            continue;
        };

        let mut out = RestoredManagedIdentity {
            display_name: mi.display_name.clone(),
            new_principal_id: principal_id.clone(),
            ..Default::default()
        };

        // Group the held Graph app-roles by resource appId → role values, so one
        // grant call covers all roles on a given resource. Unresolved entries
        // (no value, or the resource couldn't be resolved at backup) can't be
        // re-bound by value.
        let mut by_resource: HashMap<String, Vec<String>> = HashMap::new();
        let mi_approved = approved.contains(&RestoreApproval {
            kind: PrivilegedKind::ManagedIdentity,
            source_app_id: mi.source_app_id.clone(),
        });
        let mut withheld: Vec<String> = Vec::new();
        for r in &mi.held_app_roles {
            match r.app_role_value.as_deref() {
                Some(v) if !v.is_empty() && !r.resource_app_id.is_empty() && !mi_approved => {
                    withheld.push(v.to_string());
                }
                Some(v) if !v.is_empty() && !r.resource_app_id.is_empty() => {
                    by_resource
                        .entry(r.resource_app_id.clone())
                        .or_default()
                        .push(v.to_string());
                }
                _ => out.warnings.push(
                    "a held app-role couldn't be re-bound (resource or value unresolved)".into(),
                ),
            }
        }
        if !withheld.is_empty() {
            report.manual_items.push(ManualItem {
                display_name: mi.display_name.clone(),
                reason: format!(
                    "App roles not re-bound: not approved in the plan ({}). Grant them from the \
                     managed identity's detail view if they are intended.",
                    withheld.join(", ")
                ),
            });
        }
        for (resource_app_id, roles) in by_resource {
            match grant_managed_identity_roles_core(client, &principal_id, &resource_app_id, &roles)
                .await
            {
                Ok((granted, _skipped, failures)) => {
                    out.app_roles_rebound += granted.len();
                    out.warnings.extend(failures);
                }
                Err(e) => {
                    session.note_code(&e.code);
                    out.warnings
                        .push(format!("re-bind on {resource_app_id}: {}", e.message));
                }
            }
        }

        // Azure RBAC always needs manual re-creation — source scopes are
        // subscription/resource-specific and don't exist in the destination.
        report.manual_items.push(ManualItem {
            display_name: mi.display_name.clone(),
            reason:
                "Re-create this managed identity's Azure RBAC role assignments manually at the \
                     destination's equivalent scopes (source scopes don't transfer)."
                    .into(),
        });

        report.managed_identities.push(out);
    }
}

/// Whether two managed-identity sub-types can describe one identity: equal,
/// or either unknown (a system-assigned identity may carry no
/// `alternativeNames`, which reads as `Unknown` on either side).
fn subtype_compatible(a: MiSubtype, b: MiSubtype) -> bool {
    a == MiSubtype::Unknown || b == MiSubtype::Unknown || a == b
}

/// Maps a backed-up assignee's role to a role id on the restored SP: the
/// default-access role passes through (always present); a custom role is matched
/// by its `value` against the new SP's `appRoles`. Custom role *definitions*
/// aren't restored, so an unmatched custom role yields `None` (reported, not
/// assigned).
fn map_assignee_role_id(
    assignee: &crate::dto::backup::AppRoleAssigneeRef,
    new_sp_roles: &[azapptoolkit_core::models::AppRole],
) -> Option<String> {
    if assignee.app_role_id == DEFAULT_ACCESS_ROLE {
        return Some(DEFAULT_ACCESS_ROLE.to_string());
    }
    let value = assignee
        .app_role_value
        .as_deref()
        .filter(|v| !v.is_empty())?;
    new_sp_roles
        .iter()
        .find(|r| r.value == value)
        .map(|r| r.id.clone())
}

/// Which directory collection a backed-up principal is looked up in by display
/// name, from its recorded `principal_type` — an owner's `@odata.type`
/// (`#microsoft.graph.user`) or an assignment's `principalType` (`User`).
#[derive(Debug, Clone, PartialEq)]
enum PrincipalKind {
    User,
    Group,
    /// No type recorded (an older backup): both collections are searched and
    /// exactly one match across them is required.
    Either,
    /// A type the restore cannot look up by name (a service principal, …).
    Other(String),
}

fn principal_kind(principal: &PrincipalRef) -> PrincipalKind {
    let Some(raw) = principal
        .principal_type
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return PrincipalKind::Either;
    };
    let bare = raw.strip_prefix("#microsoft.graph.").unwrap_or(raw);
    match bare.to_ascii_lowercase().as_str() {
        "user" => PrincipalKind::User,
        "group" => PrincipalKind::Group,
        _ => PrincipalKind::Other(bare.to_string()),
    }
}

/// Why a backed-up principal did not resolve in the destination.
#[derive(Debug, Clone, PartialEq)]
enum Unresolved {
    /// No exact match.
    NotFound,
    /// More than one exact match, so none is taken: binding an owner or a role
    /// to the wrong one of two same-named principals grants it to someone the
    /// backup never named.
    Ambiguous(usize),
    /// A lookup failed. Never a reason to try another collection: a group
    /// search that errored is not a group that does not exist.
    LookupFailed,
    /// Its type cannot be looked up by name.
    UnsupportedType(String),
}

impl Unresolved {
    /// The principal's report label, with the reason when it is not plain
    /// "not found".
    fn label(&self, principal: &PrincipalRef) -> String {
        let name = owner_label(principal);
        match self {
            Self::NotFound => name,
            Self::Ambiguous(n) => format!("{name} (ambiguous: {n} matches)"),
            Self::LookupFailed => format!("{name} (lookup failed)"),
            Self::UnsupportedType(t) => format!("{name} (a {t}, not a user or group)"),
        }
    }
}

/// A resolution: the destination object id, or why there is none.
type Resolution = Result<String, Unresolved>;

/// The per-run principal memo ([`resolve_principal`]).
type PrincipalMemo = HashMap<String, Resolution>;

/// Cache key for a principal: its UPN (lowercased) when present, else its
/// [`PrincipalKind`] and display name. `None` when neither is set (nothing to
/// resolve). Mirrors the lookup branch order in [`resolve_principal_uncached`].
fn principal_cache_key(principal: &PrincipalRef) -> Option<String> {
    if let Some(upn) = principal
        .user_principal_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        return Some(format!("upn:{}", upn.to_ascii_lowercase()));
    }
    let kind = match principal_kind(principal) {
        PrincipalKind::User => "user".to_string(),
        PrincipalKind::Group => "group".to_string(),
        PrincipalKind::Either => "any".to_string(),
        PrincipalKind::Other(t) => t,
    };
    principal
        .display_name
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|name| format!("name:{kind}:{name}"))
}

/// Resolves a backed-up principal to its destination object id, memoizing the
/// result for the whole restore run. The same UPN or group is reused across
/// owners, app-role assignees, and group memberships, so without the memo a
/// multi-app restore re-runs identical `search_users`/`search_groups` calls many
/// times. The cache is per-run and keyed by [`principal_cache_key`]; negative
/// results are cached too (a principal absent now stays absent for the run).
/// A failed lookup is noted on `session` like every other read, so a dead
/// session trips the latch here rather than at the next noted call.
async fn resolve_principal(
    client: &GraphClient,
    cache: &mut PrincipalMemo,
    principal: &PrincipalRef,
    session: &SessionDead,
) -> Resolution {
    let Some(key) = principal_cache_key(principal) else {
        return Err(Unresolved::NotFound);
    };
    if let Some(cached) = cache.get(&key) {
        return cached.clone();
    }
    let resolved = resolve_principal_uncached(client, principal, session).await;
    cache.insert(key, resolved.clone());
    resolved
}

/// Exactly one id, or why not.
fn exactly_one(ids: Vec<String>) -> Resolution {
    match <[String; 1]>::try_from(ids) {
        Ok([id]) => Ok(id),
        Err(ids) if ids.is_empty() => Err(Unresolved::NotFound),
        Err(ids) => Err(Unresolved::Ambiguous(ids.len())),
    }
}

/// The ids of every hit whose display name equals `name` ignoring case — as
/// Graph's `eq` does, so "Ops" and "OPS" are two matches (ambiguous), never one
/// resolved by a stricter client-side comparison.
fn exact_name_matches(hits: Vec<DirectoryObject>, name: &str) -> Vec<String> {
    let want = name.to_lowercase();
    hits.into_iter()
        .filter(|h| h.display_name.as_deref().map(str::to_lowercase) == Some(want.clone()))
        .map(|h| h.id)
        .collect()
}

/// Resolves a backed-up principal to its object id in the destination tenant:
/// by UPN when it has one (`find_user_by_upn`, an exact `eq`), else by exact
/// display name (`displayName eq`, every page) in the collection its recorded
/// type names ([`PrincipalKind`]) — no cross-kind fallback, and every match
/// counted, so it resolves only when exactly one principal fits.
/// Best-effort: an unresolved principal is reported, never a run failure.
async fn resolve_principal_uncached(
    client: &GraphClient,
    principal: &PrincipalRef,
    session: &SessionDead,
) -> Resolution {
    if let Some(upn) = principal
        .user_principal_name
        .as_deref()
        .filter(|s| !s.is_empty())
    {
        return match client.find_user_by_upn(upn).await {
            Ok(Some(user)) => Ok(user.id),
            Ok(None) => Err(Unresolved::NotFound),
            Err(e) => {
                session.note_code(e.ui_code());
                Err(Unresolved::LookupFailed)
            }
        };
    }
    let Some(name) = principal.display_name.as_deref().filter(|s| !s.is_empty()) else {
        return Err(Unresolved::NotFound);
    };
    let (users, groups) = match principal_kind(principal) {
        PrincipalKind::User => (true, false),
        PrincipalKind::Group => (false, true),
        PrincipalKind::Either => (true, true),
        PrincipalKind::Other(t) => return Err(Unresolved::UnsupportedType(t)),
    };
    let mut ids = Vec::new();
    if groups {
        let hits = client
            .find_groups_by_display_name(name)
            .await
            .map_err(|e| {
                session.note_code(e.ui_code());
                Unresolved::LookupFailed
            })?;
        ids.extend(exact_name_matches(hits, name));
    }
    if users {
        let hits = client.find_users_by_display_name(name).await.map_err(|e| {
            session.note_code(e.ui_code());
            Unresolved::LookupFailed
        })?;
        ids.extend(exact_name_matches(hits, name));
    }
    exactly_one(ids)
}

fn owner_label(p: &PrincipalRef) -> String {
    p.user_principal_name
        .clone()
        .or_else(|| p.display_name.clone())
        .unwrap_or_else(|| p.source_id.clone())
}

fn emit(progress: &impl ProgressSink, done: usize, total: usize, current_app: Option<String>) {
    let payload = BulkProgress {
        done,
        total,
        // The file's display name, bounded like the report's.
        current_app: current_app.map(|mut name| {
            cap_report_value(&mut name);
            name
        }),
        cancelled: false,
        in_flight_cap: None,
    };
    emit_progress(progress, crate::dto::events::RESTORE_PROGRESS, payload);
}

#[cfg(test)]
mod tests;
