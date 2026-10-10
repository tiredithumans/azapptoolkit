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
    remap_pre_authorized, remap_required_resource_access, rewrite_identifier_uris,
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

/// Longest value from the file echoed into a manifest problem, in characters.
const MAX_ECHOED_CHARS: usize = 80;

/// `value` cut to [`MAX_ECHOED_CHARS`] characters (never mid-character), with
/// an ellipsis when cut: a hostile file's multi-megabyte display name must not
/// become the plan's text.
fn excerpt(value: &str) -> String {
    match value.char_indices().nth(MAX_ECHOED_CHARS) {
        Some((at, _)) => format!("{}…", &value[..at]),
        None => value.to_string(),
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
        source_tenant_id: backup.source_tenant_id.clone(),
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
            let perm = PrivilegedPermission {
                resource_app_id: rra.resource_app_id.clone(),
                resource_display_name: sp.map(|sp| sp.display_name.clone()),
                permission_id: access.id.clone(),
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
    let in_backup: HashSet<&str> = backup
        .app_registrations
        .iter()
        .map(|a| a.source_app_id.as_str())
        .collect();
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
            .filter(|p| !in_backup.contains(p.app_id.as_str()))
            .map(|p| excerpt(&p.app_id))
            .collect();
        external.sort();
        external.dedup();
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
                let rejected = validate_federated_credential(
                    Some(&fic.name),
                    &fic.issuer,
                    subject,
                    &audiences,
                    fic.description.as_deref(),
                )
                .err();
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
                let value = r.app_role_value.clone().filter(|v| !v.is_empty());
                PrivilegedPermission {
                    resource_app_id: r.resource_app_id.clone(),
                    resource_display_name: r.resource_display_name.clone(),
                    permission_id: r.app_role_id.clone(),
                    // No value: Pass 5 cannot re-bind it at all (a warning).
                    risk: value
                        .as_deref()
                        .map_or(PermissionRisk::Unknown, app_role_risk),
                    value,
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
            client,
            c,
            &app_id_remap,
            &mut principals,
            &session,
            &cancel,
            cloud,
            backup.created_at,
            &backup.source_tenant_id,
            tenant_id,
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
        reconsent(
            client,
            c,
            &app_id_remap,
            &session,
            &mut report.apps[idx],
            &mut report.manual_items,
        )
        .await;
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
            client,
            ent,
            &app_id_remap,
            !approved.contains(&app_approval(&ent.source_app_id)),
            &mut report,
            &mut principals,
            &session,
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
    client: &GraphClient,
    c: &CreatedApp,
    app_id_remap: &HashMap<String, String>,
    session: &SessionDead,
    out: &mut RestoredApp,
    manual: &mut Vec<ManualItem>,
) {
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
/// indistinguishable from a tenant rejecting each individual write; `session`
/// is the latch that tells them apart: each failure is noted through it by
/// `ui_code`, keeping `UiError::is_reauth_fatal` the single definition of which
/// codes are fatal.
///
/// For an adopted app the PATCHes are full-replace and simply re-applied, while
/// the additive writes (federated credentials, owners, secrets) skip what the
/// earlier run already put there. `taken_at` is the backup's timestamp, the
/// cutoff for [`expired_at_backup`]; the two tenant ids are what the
/// identifier-URI rewrite maps (source → destination).
///
/// `withhold` marks an app that needed approval in the plan and did not get
/// it: it is wired as usual, but gains no federated credential and no owner
/// from the file — each withheld set is one runbook item.
#[allow(clippy::too_many_arguments)]
async fn wire_application(
    client: &GraphClient,
    c: &CreatedApp,
    app_id_remap: &HashMap<String, String>,
    principals: &mut PrincipalMemo,
    session: &SessionDead,
    cancel: &CancelToken,
    cloud: CloudEnvironment,
    taken_at: DateTime<Utc>,
    source_tenant_id: &str,
    dest_tenant_id: &str,
    withhold: bool,
) -> (RestoredApp, Vec<ManualItem>) {
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
    let pre_auth = remap_pre_authorized(&app.pre_authorized_applications, app_id_remap);
    if !identifier_uris.is_empty() || !app.api_scopes.is_empty() || !pre_auth.is_empty() {
        let patch = ApplicationExposeApiPatch {
            identifier_uris: (!identifier_uris.is_empty()).then_some(identifier_uris),
            api: Some(ApiApplicationPatch {
                oauth2_permission_scopes: (!app.api_scopes.is_empty())
                    .then(|| app.api_scopes.clone()),
                pre_authorized_applications: (!pre_auth.is_empty()).then_some(pre_auth),
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
/// Every failure is noted through `session`, as in Pass 2, so a session that
/// dies here stops the restore instead of producing one wrong runbook item per
/// remaining app. `withhold` (its app was not approved in the plan) skips the
/// group memberships into one runbook item; role assignments still apply.
#[allow(clippy::too_many_arguments)]
async fn restore_enterprise_app(
    client: &GraphClient,
    ent: &EnterpriseAppBackup,
    app_id_remap: &HashMap<String, String>,
    withhold: bool,
    report: &mut RestoreReport,
    principals: &mut PrincipalMemo,
    session: &SessionDead,
    cancel: &CancelToken,
) {
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
        current_app,
        cancelled: false,
        in_flight_cap: None,
    };
    emit_progress(progress, crate::dto::events::RESTORE_PROGRESS, payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_from_a_newer_build_is_refused_but_an_older_one_restores() {
        // Older and current: additive, `serde(default)` fields — restoring one
        // is the DR case the version field exists to support.
        assert!(check_manifest_schema(0).is_ok());
        assert!(check_manifest_schema(BACKUP_SCHEMA_VERSION).is_ok());
        // Newer: this build cannot know what it would be dropping, and a
        // restore mutates the tenant before anyone can look.
        let err = check_manifest_schema(BACKUP_SCHEMA_VERSION + 1).unwrap_err();
        assert_eq!(err.code, "schema_too_new");
    }

    #[test]
    fn assignee_role_maps_default_passthrough_value_match_or_none() {
        use crate::dto::backup::{AppRoleAssigneeRef, PrincipalRef};
        use azapptoolkit_core::models::AppRole;

        let roles = vec![AppRole {
            id: "new-role-id".into(),
            value: "Writer".into(),
            ..Default::default()
        }];

        // Default-access role passes through unchanged (always present).
        let default = AppRoleAssigneeRef {
            principal: PrincipalRef::default(),
            app_role_id: DEFAULT_ACCESS_ROLE.into(),
            app_role_value: None,
        };
        assert_eq!(
            map_assignee_role_id(&default, &roles).as_deref(),
            Some(DEFAULT_ACCESS_ROLE)
        );

        // Custom role matched by value → the new SP's role id.
        let writer = AppRoleAssigneeRef {
            principal: PrincipalRef::default(),
            app_role_id: "old-role-id".into(),
            app_role_value: Some("Writer".into()),
        };
        assert_eq!(
            map_assignee_role_id(&writer, &roles).as_deref(),
            Some("new-role-id")
        );

        // Custom role whose value isn't on the restored app → unmapped.
        let admin = AppRoleAssigneeRef {
            principal: PrincipalRef::default(),
            app_role_id: "old-admin-id".into(),
            app_role_value: Some("Admin".into()),
        };
        assert_eq!(map_assignee_role_id(&admin, &roles), None);
    }

    #[test]
    fn owner_label_prefers_upn_then_name_then_id() {
        let by_upn = PrincipalRef {
            source_id: "id".into(),
            user_principal_name: Some("a@b.com".into()),
            display_name: Some("Alice".into()),
            ..Default::default()
        };
        assert_eq!(owner_label(&by_upn), "a@b.com");
        let by_name = PrincipalRef {
            source_id: "id".into(),
            display_name: Some("Group X".into()),
            ..Default::default()
        };
        assert_eq!(owner_label(&by_name), "Group X");
    }

    #[test]
    fn principal_cache_key_prefers_lowercased_upn_then_name_then_none() {
        // UPN wins and is lowercased, so case-variant UPNs share one memo entry.
        let by_upn = PrincipalRef {
            source_id: "id".into(),
            user_principal_name: Some("Alice@Contoso.com".into()),
            display_name: Some("Alice".into()),
            ..Default::default()
        };
        assert_eq!(
            principal_cache_key(&by_upn).as_deref(),
            Some("upn:alice@contoso.com")
        );

        // No UPN → keyed by kind + display name: a user and a group may share
        // a name, and are different lookups.
        let by_name = PrincipalRef {
            source_id: "id".into(),
            display_name: Some("Group X".into()),
            ..Default::default()
        };
        assert_eq!(
            principal_cache_key(&by_name).as_deref(),
            Some("name:any:Group X")
        );
        let typed = PrincipalRef {
            principal_type: Some("#microsoft.graph.group".into()),
            ..by_name.clone()
        };
        assert_eq!(
            principal_cache_key(&typed).as_deref(),
            Some("name:group:Group X")
        );

        // An empty UPN is ignored, falling through to the display name.
        let empty_upn = PrincipalRef {
            source_id: "id".into(),
            user_principal_name: Some(String::new()),
            display_name: Some("Group Y".into()),
            ..Default::default()
        };
        assert_eq!(
            principal_cache_key(&empty_upn).as_deref(),
            Some("name:any:Group Y")
        );

        // Neither set → no key (nothing to resolve or memoize).
        assert_eq!(principal_cache_key(&PrincipalRef::default()), None);
    }

    #[test]
    fn build_restore_plan_counts_actions_and_flags_cloud_and_tenant_changes() {
        use crate::dto::backup::{AppRegistrationBackup, CredentialMeta, TenantBackup};
        let app =
            |secrets: usize, certs: usize, feds: usize, owners: usize| AppRegistrationBackup {
                secrets: vec![CredentialMeta::default(); secrets],
                certificates: vec![CredentialMeta::default(); certs],
                federated_credentials: vec![
                    FederatedIdentityCredential {
                        subject: Some("sub".into()),
                        ..Default::default()
                    };
                    feds
                ],
                owners: vec![PrincipalRef::default(); owners],
                ..Default::default()
            };
        let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
        let ending = |secs: i64| CredentialMeta {
            end_date_time: chrono::DateTime::from_timestamp(secs, 0),
            ..Default::default()
        };
        // Two undated secrets, one still valid at backup time, one already
        // expired then: only the expired one is left out.
        let mut first = app(2, 1, 3, 1);
        first.secrets.push(ending(2_000_000));
        // A flexible credential (no subject) is not recreated, so it is not
        // counted as one to restore.
        first
            .federated_credentials
            .push(FederatedIdentityCredential::default());
        let mut second = app(0, 0, 0, 2);
        second.secrets.push(ending(500_000));
        let backup = TenantBackup {
            schema_version: 1,
            created_at: taken_at,
            source_tenant_id: "src-tenant".into(),
            cloud: CloudEnvironment::Commercial,
            app_registrations: vec![first, second],
            enterprise_apps: Vec::new(),
            managed_identities: Vec::new(),
            skipped: Vec::new(),
        };

        // Same cloud, different destination tenant — the expected DR case. Counts
        // are summed across every app registration.
        let plan = build_restore_plan(
            &backup,
            "dest-tenant".to_string(),
            CloudEnvironment::Commercial,
        );
        assert!(plan.cloud_mismatch.is_none());
        assert!(plan.tenant_changed);
        assert_eq!(plan.destination_tenant_id, "dest-tenant");
        assert_eq!(plan.app_registrations_to_create, 2);
        assert_eq!(plan.secrets_to_regenerate, 3);
        assert_eq!(plan.expired_secrets_skipped, 1);
        assert_eq!(plan.certificates_needing_manual_upload, 1);
        assert_eq!(plan.federated_credentials_to_restore, 3);
        assert_eq!(plan.owners_to_remap, 3);

        // A cross-cloud manifest is flagged; restoring into the source tenant is
        // not a "tenant change".
        let blocked =
            build_restore_plan(&backup, "src-tenant".to_string(), CloudEnvironment::UsGov);
        assert!(blocked.cloud_mismatch.is_some());
        assert!(!blocked.tenant_changed);
    }

    #[test]
    fn build_restore_plan_forecasts_passes_4_and_5_and_blocks_a_newer_schema() {
        use crate::dto::backup::{
            AppRegistrationBackup, EnterpriseAppBackup, ManagedIdentityBackup, SkippedObject,
            TenantBackup,
        };

        let app = |id: &str, sp: bool| AppRegistrationBackup {
            source_app_id: id.into(),
            has_service_principal: sp,
            ..Default::default()
        };
        let ent = |id: &str, foreign: bool| EnterpriseAppBackup {
            source_app_id: id.into(),
            is_foreign_tenant: foreign,
            ..Default::default()
        };
        const PAIRED: &str = "11111111-1111-1111-1111-111111111111";
        const NO_SP: &str = "22222222-2222-2222-2222-222222222222";
        let mut backup = TenantBackup {
            schema_version: BACKUP_SCHEMA_VERSION,
            created_at: chrono::DateTime::from_timestamp(1_000_000, 0).unwrap(),
            source_tenant_id: "src-tenant".into(),
            cloud: CloudEnvironment::Commercial,
            app_registrations: vec![app(PAIRED, true), app(NO_SP, false)],
            enterprise_apps: vec![
                // Replayed: paired, not foreign, its app reg carries an SP.
                ent(PAIRED, false),
                // Runbook items: foreign/gallery, no app reg in the backup,
                // and an app reg Pass 1 creates without an SP.
                ent(PAIRED, true),
                ent("absent", false),
                ent(NO_SP, false),
            ],
            managed_identities: [
                "33333333-3333-3333-3333-333333333333",
                "44444444-4444-4444-4444-444444444444",
            ]
            .map(|id| ManagedIdentityBackup {
                source_app_id: id.into(),
                ..Default::default()
            })
            .to_vec(),
            skipped: vec![SkippedObject::new("application", "obj-x", None, "403")],
        };

        let plan = build_restore_plan(
            &backup,
            "dest-tenant".to_string(),
            CloudEnvironment::Commercial,
        );
        assert_eq!(plan.enterprise_apps_to_reapply, 1);
        assert_eq!(plan.enterprise_apps_manual, 3);
        assert_eq!(plan.managed_identities_to_rebind, 2);
        assert_eq!(plan.skipped_in_backup, 1);
        assert!(plan.schema_too_new.is_none());
        assert!(!plan.is_blocked());

        // A newer manifest still gets a plan — carrying the blocker, so the
        // operator sees it before Confirm rather than after.
        backup.schema_version = BACKUP_SCHEMA_VERSION + 1;
        let plan = build_restore_plan(
            &backup,
            "dest-tenant".to_string(),
            CloudEnvironment::Commercial,
        );
        let too_new = plan.schema_too_new.as_ref().expect("blocked");
        assert_eq!(too_new.manifest_version, BACKUP_SCHEMA_VERSION + 1);
        assert_eq!(too_new.supported_version, BACKUP_SCHEMA_VERSION);
        assert!(plan.is_blocked());
    }

    fn manifest_with_ids(ids: &[&str]) -> TenantBackup {
        TenantBackup {
            schema_version: BACKUP_SCHEMA_VERSION,
            created_at: chrono::DateTime::from_timestamp(1_000_000, 0).unwrap(),
            source_tenant_id: "src-tenant".into(),
            cloud: CloudEnvironment::Commercial,
            app_registrations: ids
                .iter()
                .enumerate()
                .map(|(i, id)| AppRegistrationBackup {
                    source_app_id: (*id).into(),
                    display_name: format!("app-{i}"),
                    ..Default::default()
                })
                .collect(),
            enterprise_apps: Vec::new(),
            managed_identities: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// A repeated source appId would be adopted against the app Pass 1 just
    /// created for its first copy and wired twice — two sets of secrets. The
    /// plan shows the blocker before Confirm and the restore refuses on its own.
    #[test]
    fn a_duplicate_source_app_id_blocks_the_plan_and_the_restore() {
        const ID: &str = "11111111-1111-1111-1111-111111111111";
        let backup = manifest_with_ids(&[ID, "22222222-2222-2222-2222-222222222222", ID]);
        let plan = build_restore_plan(&backup, "dest".into(), CloudEnvironment::Commercial);
        assert!(plan.is_blocked());
        assert_eq!(
            plan.invalid_manifest,
            vec![format!("source appId {ID} appears 2 times")]
        );
        let err = validate_manifest(&backup).unwrap_err();
        assert_eq!(err.code, "invalid_manifest");

        // GUIDs compare case-insensitively.
        assert!(
            validate_manifest(&manifest_with_ids(&[
                "aaaaaaaa-0000-0000-0000-000000000000",
                "AAAAAAAA-0000-0000-0000-000000000000",
            ]))
            .is_err()
        );
    }

    /// An empty source appId would tag the app with the bare
    /// `azapptoolkit:restoredFrom:` prefix; a non-GUID one cannot have come
    /// from Graph. Both block the plan and the restore.
    #[test]
    fn an_empty_or_malformed_source_app_id_blocks_the_plan_and_the_restore() {
        for bad in [
            "",
            "  ",
            "not-a-guid",
            "{11111111-1111-1111-1111-111111111111}",
            // Padded: the tag and the remap would carry the whitespace.
            " 22222222-2222-2222-2222-222222222222",
            "22222222-2222-2222-2222-222222222222\n",
        ] {
            let backup = manifest_with_ids(&["11111111-1111-1111-1111-111111111111", bad]);
            let plan = build_restore_plan(&backup, "dest".into(), CloudEnvironment::Commercial);
            assert!(plan.is_blocked(), "{bad:?}");
            assert_eq!(plan.invalid_manifest.len(), 1, "{bad:?}");
            assert!(plan.invalid_manifest[0].contains("'app-1'"), "{bad:?}");
            assert_eq!(
                validate_manifest(&backup).unwrap_err().code,
                "invalid_manifest"
            );
        }

        // A sound manifest, and an empty one, pass.
        assert!(
            validate_manifest(&manifest_with_ids(&[
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
            ]))
            .is_ok()
        );
        assert!(validate_manifest(&manifest_with_ids(&[])).is_ok());
    }

    /// Values from the file are echoed bounded: a hostile display name or id
    /// cannot become the plan's text, and the cut never splits a character.
    #[test]
    fn manifest_problems_echo_file_values_bounded() {
        let mut backup = manifest_with_ids(&[&"x".repeat(10_000)]);
        backup.app_registrations[0].display_name = "é".repeat(10_000);
        let problems = manifest_problems(&backup);
        assert_eq!(problems.len(), 1);
        let expected = format!(
            "app registration '{}…' has a source appId that is not a GUID ('{}…')",
            "é".repeat(MAX_ECHOED_CHARS),
            "x".repeat(MAX_ECHOED_CHARS)
        );
        assert_eq!(problems[0], expected);
        // Short values are echoed whole.
        assert_eq!(excerpt("Payroll"), "Payroll");
        assert_eq!(
            excerpt(&"a".repeat(MAX_ECHOED_CHARS)),
            "a".repeat(MAX_ECHOED_CHARS)
        );
    }

    /// A file that repeats the problem thousands of times still yields a
    /// readable plan.
    #[test]
    fn manifest_problems_are_capped() {
        let ids = vec![""; MAX_MANIFEST_PROBLEMS + 5];
        let problems = manifest_problems(&manifest_with_ids(&ids));
        assert_eq!(problems.len(), MAX_MANIFEST_PROBLEMS + 1);
        assert_eq!(problems.last().map(String::as_str), Some("and 5 more"));
    }

    #[test]
    fn expired_at_backup_uses_the_backup_time_not_now() {
        let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
        let ending = |end: Option<DateTime<Utc>>| CredentialMeta {
            end_date_time: end,
            ..Default::default()
        };
        // Expired before the backup was taken: nothing could have used it.
        assert!(expired_at_backup(
            &ending(chrono::DateTime::from_timestamp(999_999, 0)),
            taken_at
        ));
        // Live at backup time, long expired by now: a recovering client still
        // holds it, so it is re-issued.
        assert!(!expired_at_backup(
            &ending(chrono::DateTime::from_timestamp(1_000_001, 0)),
            taken_at
        ));
        // No end date is not "expired".
        assert!(!expired_at_backup(&ending(None), taken_at));
    }

    #[test]
    fn restore_marker_is_prefix_plus_source_app_id() {
        assert_eq!(
            restore_marker("11111111-2222-3333-4444-555555555555"),
            "azapptoolkit:restoredFrom:11111111-2222-3333-4444-555555555555"
        );
        assert!(restore_marker("x").starts_with(RESTORE_MARKER_PREFIX));
    }

    #[test]
    fn adoption_for_creates_adopts_or_refuses() {
        use azapptoolkit_core::models::PasswordCredential;

        let app = AppRegistrationBackup {
            display_name: "App A".into(),
            source_app_id: "src-a".into(),
            // The one secret an earlier run of this restore would have issued.
            secrets: vec![CredentialMeta {
                display_name: Some("ci".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
        // Created after the backup was taken, as anything a restore of it made.
        let hit = |id: &str, name: &str| Application {
            id: format!("obj-{id}"),
            app_id: format!("app-{id}"),
            display_name: name.into(),
            created_date_time: chrono::DateTime::from_timestamp(1_000_600, 0),
            ..Default::default()
        };

        // Nothing carries the tag: create.
        assert_eq!(adoption_for(&app, &[], taken_at), Adoption::Create);

        // One tagged app with the same name holding exactly the manifest's
        // secret: an earlier run made it — adopt it, carrying the names of the
        // secrets it already holds.
        let mut same = hit("1", "App A");
        same.password_credentials = vec![PasswordCredential {
            display_name: Some("ci".into()),
            ..Default::default()
        }];
        assert_eq!(
            adoption_for(&app, &[same], taken_at),
            Adoption::Adopt {
                object_id: "obj-1".into(),
                app_id: "app-1".into(),
                live_secret_names: vec!["ci".into()],
            }
        );

        // Tagged but renamed: never adopted on the tag alone, never duplicated.
        let Adoption::Refuse(reason) = adoption_for(&app, &[hit("2", "Renamed")], taken_at) else {
            panic!("a renamed tagged app must be refused");
        };
        assert!(reason.contains("Renamed") && reason.contains("app-2"));

        // Two tagged apps: ambiguous, so neither is taken and nothing is created.
        let Adoption::Refuse(reason) =
            adoption_for(&app, &[hit("1", "App A"), hit("2", "App A")], taken_at)
        else {
            panic!("two tagged apps must be refused");
        };
        assert!(reason.starts_with("2 apps carry the restore tag"));

        // Tag and name match, but the app predates the backup — or its creation
        // time is unknown: no restore of this backup can be proven to have made
        // it, so it is refused rather than handed this app's consent.
        let mut older = hit("3", "App A");
        older.created_date_time = chrono::DateTime::from_timestamp(999_000, 0);
        let Adoption::Refuse(reason) = adoption_for(&app, &[older], taken_at) else {
            panic!("an app older than the backup must be refused");
        };
        assert!(
            reason.contains("not after this backup was taken"),
            "{reason}"
        );
        let mut undated = hit("4", "App A");
        undated.created_date_time = None;
        let Adoption::Refuse(reason) = adoption_for(&app, &[undated], taken_at) else {
            panic!("an app of unknown age must be refused");
        };
        assert!(reason.contains("an unknown time"), "{reason}");
    }

    #[test]
    fn unexpected_owners_names_everyone_not_allowed() {
        let owner = |id: &str, upn: Option<&str>, name: Option<&str>| DirectoryObject {
            id: id.into(),
            user_principal_name: upn.map(Into::into),
            display_name: name.map(Into::into),
            ..Default::default()
        };
        let owners = [
            owner("op", Some("admin@contoso.com"), None),
            owner("x1", Some("mallory@contoso.com"), Some("Mallory")),
            owner("x2", None, Some("Some Group")),
            owner("x3", None, None),
        ];
        let allowed = HashSet::from(["op".to_string()]);
        assert_eq!(
            unexpected_owners(&owners, &allowed),
            ["mallory@contoso.com", "Some Group", "x3"]
        );
        let everyone = HashSet::from(["op", "x1", "x2", "x3"].map(String::from));
        assert!(unexpected_owners(&owners, &everyone).is_empty());
    }

    /// A token provider whose refresh token is gone: every read fails with the
    /// re-auth-fatal code before any request is sent.
    struct DeadSession;
    #[async_trait::async_trait]
    impl azapptoolkit_core::token::BearerProvider for DeadSession {
        async fn bearer(&self) -> Result<String, azapptoolkit_core::token::TokenError> {
            Err(azapptoolkit_core::token::TokenError::new(
                "refresh_missing",
                "gone",
            ))
        }
    }

    fn graph_over(server: &wiremock::MockServer, dead: bool) -> GraphClient {
        use azapptoolkit_core::cache::Cache;
        use azapptoolkit_core::token::{BearerProvider, StaticTokenProvider};
        use std::sync::Arc;
        let token: Arc<dyn BearerProvider> = if dead {
            Arc::new(DeadSession)
        } else {
            StaticTokenProvider::new("tok")
        };
        GraphClient::with_base_url(
            "tenant-test",
            token.clone(),
            token,
            Cache::new(),
            server.uri(),
        )
    }

    fn two_mis() -> Vec<ManagedIdentityBackup> {
        ["mi-one", "mi-two"]
            .into_iter()
            .map(|name| ManagedIdentityBackup {
                display_name: name.into(),
                ..Default::default()
            })
            .collect()
    }

    // `unwrap_or_default()` once turned a failed listing into an empty
    // destination, and every MI was reported "not found — recreate it via IaC".
    #[tokio::test]
    async fn a_failed_mi_listing_is_reported_once_not_as_missing_identities() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let client = graph_over(&server, false);
        let session = SessionDead::new();
        let mut report = RestoreReport::default();

        restore_managed_identities(
            &client,
            &two_mis(),
            &HashSet::new(),
            &mut report,
            &session,
            &never_cancelled(),
        )
        .await;

        assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
        assert!(report.manual_items[0].reason.contains("Couldn't list"));
        assert!(
            !report
                .manual_items
                .iter()
                .any(|m| m.reason.contains("not found in the destination")),
            "a failed read must not be reported as missing identities"
        );
        assert!(report.managed_identities.is_empty());
        assert!(!session.is_dead(), "a 403 is not a dead session");
    }

    #[tokio::test]
    async fn a_dead_session_during_the_mi_listing_latches() {
        // Never answered: the token fails before any request is sent.
        let server = wiremock::MockServer::start().await;
        let client = graph_over(&server, true);
        let session = SessionDead::new();
        let mut report = RestoreReport::default();

        restore_managed_identities(
            &client,
            &two_mis(),
            &HashSet::new(),
            &mut report,
            &session,
            &never_cancelled(),
        )
        .await;

        assert!(session.is_dead(), "a dead refresh token must latch");
        assert_eq!(report.manual_items.len(), 1);
    }

    // The `_` arm once reported any read failure as "the app had none in the
    // backup", which is false whenever the backup said it had one.
    #[tokio::test]
    async fn a_failed_sp_read_is_not_reported_as_having_no_sp() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let client = graph_over(&server, false);
        let session = SessionDead::new();
        let mut report = RestoreReport::default();
        let ent = EnterpriseAppBackup {
            display_name: "Ent A".into(),
            source_app_id: "src-a".into(),
            ..Default::default()
        };
        let remap = HashMap::from([("src-a".to_string(), "new-a".to_string())]);

        restore_enterprise_app(
            &client,
            &ent,
            &remap,
            false,
            &mut report,
            &mut HashMap::new(),
            &session,
            &never_cancelled(),
        )
        .await;

        assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
        let reason = &report.manual_items[0].reason;
        assert!(!reason.contains("had none in the backup"), "{reason}");
        assert!(reason.contains("Couldn't read the restored service principal"));
        assert!(report.enterprise_apps.is_empty());
    }

    fn tagged_app_a() -> AppRegistrationBackup {
        AppRegistrationBackup {
            display_name: "App A".into(),
            source_app_id: "src-a".into(),
            ..Default::default()
        }
    }

    /// Mounts the tag lookup answering one hit named "App A", created after
    /// `taken_at` in [`decide`], and its owners.
    async fn mount_tagged_hit(server: &wiremock::MockServer, owners: serde_json::Value) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/applications"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "obj-1",
                    "appId": "app-1",
                    "displayName": "App A",
                    "createdDateTime": "2026-01-02T00:00:00Z"
                }]
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/applications/obj-1/owners"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": owners })),
            )
            .mount(server)
            .await;
        mount_tagged_fics(server, serde_json::json!([]), 5).await;
    }

    /// The tagged hit's federated credentials, read after its owners pass. A
    /// test that plants one mounts again at a higher priority (lower number).
    async fn mount_tagged_fics(
        server: &wiremock::MockServer,
        fics: serde_json::Value,
        priority: u8,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/applications/obj-1/federatedIdentityCredentials"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": fics })),
            )
            .with_priority(priority)
            .mount(server)
            .await;
    }

    /// A cancel token nothing ever cancels.
    fn never_cancelled() -> CancelToken {
        crate::state::CancelFlag::new().claim()
    }

    async fn decide(client: &GraphClient, session: &SessionDead) -> Adoption {
        let taken_at = "2026-01-01T00:00:00Z".parse().unwrap();
        decide_adoption(
            client,
            &tagged_app_a(),
            taken_at,
            CloudEnvironment::Commercial,
            Some("operator-oid"),
            &mut HashMap::new(),
            session,
        )
        .await
    }

    // The fail-closed branch is the package's key safety property: a failed tag
    // lookup must never fall through to a create.
    #[tokio::test]
    async fn a_failed_tag_lookup_refuses_instead_of_creating() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/applications"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let client = graph_over(&server, false);
        let session = SessionDead::new();

        let Adoption::Refuse(reason) = decide(&client, &session).await else {
            panic!("a failed lookup must be refused");
        };
        assert!(reason.contains("it was NOT created"), "{reason}");
        assert!(!session.is_dead(), "a 403 is not a dead session");
    }

    #[tokio::test]
    async fn a_dead_session_during_the_tag_lookup_refuses_and_latches() {
        let server = wiremock::MockServer::start().await;
        let client = graph_over(&server, true);
        let session = SessionDead::new();

        assert!(matches!(
            decide(&client, &session).await,
            Adoption::Refuse(_)
        ));
        assert!(session.is_dead(), "a dead refresh token must latch");
    }

    // Anyone who may register apps can write the tag and the name, so a hit
    // with an owner the restore did not set is someone else's app: adopting it
    // would give them this app's permissions and admin consent.
    #[tokio::test]
    async fn a_tagged_app_with_a_foreign_owner_is_not_adopted() {
        let server = wiremock::MockServer::start().await;
        mount_tagged_hit(
            &server,
            serde_json::json!([
                { "id": "operator-oid", "userPrincipalName": "admin@contoso.com" },
                { "id": "mallory-oid", "userPrincipalName": "mallory@contoso.com" }
            ]),
        )
        .await;
        let client = graph_over(&server, false);

        let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
            panic!("a foreign owner must block adoption");
        };
        assert!(reason.contains("mallory@contoso.com"), "{reason}");
        assert!(!reason.contains("admin@contoso.com"), "{reason}");
    }

    #[tokio::test]
    async fn a_tagged_app_owned_only_by_the_operator_is_adopted() {
        let server = wiremock::MockServer::start().await;
        mount_tagged_hit(
            &server,
            serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
        )
        .await;
        let client = graph_over(&server, false);

        assert_eq!(
            decide(&client, &SessionDead::new()).await,
            Adoption::Adopt {
                object_id: "obj-1".into(),
                app_id: "app-1".into(),
                live_secret_names: Vec::new(),
            }
        );
    }

    #[tokio::test]
    async fn a_failed_owner_read_refuses_the_adoption() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/applications/obj-1/owners"))
            .respond_with(ResponseTemplate::new(403))
            .with_priority(1)
            .mount(&server)
            .await;
        mount_tagged_hit(&server, serde_json::json!([])).await;
        let client = graph_over(&server, false);

        let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
            panic!("an unreadable owner list must block adoption");
        };
        assert!(reason.contains("Couldn't read the owners"), "{reason}");
    }

    /// A manifest is untrusted input — the same premise the federated-credential
    /// loop states. Reply URLs are where auth codes are delivered, so a wildcard
    /// or plaintext one must not reach the tenant just because it arrived in a
    /// file rather than through the editor.
    #[test]
    fn a_flexible_federated_credential_is_skipped_with_a_warning() {
        let flexible = FederatedIdentityCredential {
            name: "gh-flex".into(),
            ..Default::default()
        };
        let warning = restorable_fic_subject(&flexible).unwrap_err();
        assert!(warning.contains("'gh-flex' was NOT restored"), "{warning}");
        assert!(warning.contains("flexible credential"), "{warning}");

        let pinned = FederatedIdentityCredential {
            name: "gh-main".into(),
            subject: Some("repo:contoso/app:ref:refs/heads/main".into()),
            ..Default::default()
        };
        assert_eq!(
            restorable_fic_subject(&pinned),
            Ok("repo:contoso/app:ref:refs/heads/main")
        );
    }

    #[test]
    fn restored_reply_urls_are_validated_like_editor_input() {
        let uris = [
            "https://good.contoso.com/cb",
            "https://*.evil.example/cb",
            "http://attacker.example/cb",
            "http://localhost:5173/cb",
        ]
        .map(String::from);
        let mut warnings = Vec::new();
        let kept = checked_uris(&uris, "web redirect URIs", &mut warnings);

        // Per-URI, not all-or-nothing: one bad entry must not discard the good
        // ones, and loopback http stays legal exactly as it is in the editor.
        assert_eq!(
            kept,
            vec![
                "https://good.contoso.com/cb".to_string(),
                "http://localhost:5173/cb".to_string()
            ]
        );
        assert_eq!(
            warnings.len(),
            2,
            "each rejection is reported: {warnings:?}"
        );
        assert!(warnings.iter().any(|w| w.contains("*.evil.example")));
        assert!(warnings.iter().any(|w| w.contains("attacker.example")));
        // The operator can tell which list it was.
        assert!(
            warnings
                .iter()
                .all(|w| w.starts_with("web redirect URIs: "))
        );
    }

    /// The logout URL is checked by the logout rules, not the reply-URL ones: a
    /// custom scheme passes `validate_redirect_uri` but must not be restored as
    /// a sign-out page.
    #[test]
    fn a_restored_logout_url_is_validated_like_editor_input() {
        let mut warnings = Vec::new();
        assert_eq!(
            checked_logout_url(Some(" https://app.contoso.com/logout "), &mut warnings),
            Some("https://app.contoso.com/logout".to_string())
        );
        assert_eq!(checked_logout_url(Some("  "), &mut warnings), None);
        assert_eq!(checked_logout_url(None, &mut warnings), None);
        assert!(warnings.is_empty(), "{warnings:?}");

        assert!(validate_redirect_uri("myapp://logout").is_ok());
        for bad in ["myapp://logout", "http://attacker.example/logout"] {
            assert_eq!(checked_logout_url(Some(bad), &mut warnings), None, "{bad}");
        }
        assert_eq!(
            warnings.len(),
            2,
            "each rejection is reported: {warnings:?}"
        );
        assert!(warnings[0].contains("'myapp://logout' was NOT restored"));
    }

    /// An empty list restores nothing and warns about nothing — the common case
    /// must stay silent.
    #[test]
    fn checked_uris_is_silent_when_everything_is_valid() {
        let uris = ["https://a.contoso.com/cb"].map(String::from);
        let mut warnings = Vec::new();
        assert_eq!(
            checked_uris(&uris, "web redirect URIs", &mut warnings).len(),
            1
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn principal_kind_reads_odata_and_assignment_types() {
        let with = |t: Option<&str>| PrincipalRef {
            principal_type: t.map(Into::into),
            ..Default::default()
        };
        assert_eq!(principal_kind(&with(None)), PrincipalKind::Either);
        assert_eq!(principal_kind(&with(Some(" "))), PrincipalKind::Either);
        assert_eq!(
            principal_kind(&with(Some("#microsoft.graph.user"))),
            PrincipalKind::User
        );
        // An app-role assignment records `principalType` bare.
        assert_eq!(principal_kind(&with(Some("Group"))), PrincipalKind::Group);
        assert_eq!(
            principal_kind(&with(Some("ServicePrincipal"))),
            PrincipalKind::Other("ServicePrincipal".into())
        );
    }

    #[test]
    fn an_unresolved_label_names_the_reason() {
        let p = PrincipalRef {
            display_name: Some("Ops".into()),
            ..Default::default()
        };
        assert_eq!(Unresolved::NotFound.label(&p), "Ops");
        assert_eq!(
            Unresolved::Ambiguous(2).label(&p),
            "Ops (ambiguous: 2 matches)"
        );
        assert_eq!(Unresolved::LookupFailed.label(&p), "Ops (lookup failed)");
    }

    // ---- behavioural tests of the pass loop, against a mock Graph ----

    use wiremock::matchers::{method, path, path_regex, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    const GRAPH: &str = "00000003-0000-0000-c000-000000000000";
    const APP_RW_ROLE: &str = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9";
    const MAIL_SEND_ROLE: &str = "b633e1c5-b582-4048-a93e-9f11b44c7e96";
    const USER_READ_SCOPE: &str = "e1fe6dd8-ba31-4d61-89e7-88639da4683d";
    const SRC_A: &str = "aaaaaaaa-0000-0000-0000-000000000001";
    const SRC_B: &str = "bbbbbbbb-0000-0000-0000-000000000002";

    /// Answers whatever a test did not mount: 204 for a PATCH, an empty page
    /// for anything else. A test mounts only what it asserts on and reads the
    /// rest off [`requests`].
    async fn mount_fallback(server: &MockServer) {
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(204))
            .with_priority(10)
            .mount(server)
            .await;
        Mock::given(wiremock::matchers::any())
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": [] })),
            )
            .with_priority(11)
            .mount(server)
            .await;
    }

    /// The requests `server` received with `verb` on exactly `url_path`.
    async fn requests(server: &MockServer, verb: &str, url_path: &str) -> Vec<Request> {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method.as_str() == verb && r.url.path() == url_path)
            .collect()
    }

    fn created(app: AppRegistrationBackup) -> CreatedApp {
        CreatedApp {
            backup: app,
            new_object_id: "new-obj".into(),
            new_app_id: "new-app".into(),
            adopted: false,
            live_secret_names: Vec::new(),
            warnings: Vec::new(),
        }
    }

    async fn wire(client: &GraphClient, c: &CreatedApp) -> (RestoredApp, Vec<ManualItem>) {
        wire_with(client, c, false).await
    }

    async fn wire_with(
        client: &GraphClient,
        c: &CreatedApp,
        withhold: bool,
    ) -> (RestoredApp, Vec<ManualItem>) {
        wire_application(
            client,
            c,
            &HashMap::new(),
            &mut PrincipalMemo::new(),
            &SessionDead::new(),
            &never_cancelled(),
            CloudEnvironment::Commercial,
            "2026-01-01T00:00:00Z".parse().unwrap(),
            "src-tenant",
            "dst-tenant",
            withhold,
        )
        .await
    }

    /// The authentication PATCH carries only the reply URLs that passed
    /// validation — the wildcard one never reaches the tenant.
    #[tokio::test]
    async fn the_auth_patch_omits_a_rejected_redirect_uri() {
        let server = MockServer::start().await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let c = created(AppRegistrationBackup {
            display_name: "App A".into(),
            web_redirect_uris: vec![
                "https://good.contoso.com/cb".into(),
                "https://*.evil.example/cb".into(),
            ],
            ..Default::default()
        });

        let (out, _) = wire(&client, &c).await;

        let patches = requests(&server, "PATCH", "/applications/new-obj").await;
        let auth: Vec<serde_json::Value> = patches
            .iter()
            .map(|r| serde_json::from_slice(&r.body).unwrap())
            .filter(|b: &serde_json::Value| b.get("web").is_some())
            .collect();
        assert_eq!(auth.len(), 1, "one authentication PATCH");
        assert_eq!(
            auth[0]["web"]["redirectUris"],
            serde_json::json!(["https://good.contoso.com/cb"])
        );
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("*.evil.example") && w.contains("NOT restored")),
            "{:?}",
            out.warnings
        );
    }

    /// A federated credential with an issuer validation refuses is never
    /// POSTed — and is not reported as a restored trust.
    #[tokio::test]
    async fn a_federated_credential_with_a_bad_issuer_is_never_posted() {
        let server = MockServer::start().await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let c = created(AppRegistrationBackup {
            display_name: "App A".into(),
            federated_credentials: vec![FederatedIdentityCredential {
                name: "planted".into(),
                issuer: "http://attacker.example".into(),
                subject: Some("repo:x/y:ref:refs/heads/main".into()),
                ..Default::default()
            }],
            ..Default::default()
        });

        let (out, trusts) = wire(&client, &c).await;

        assert!(
            requests(
                &server,
                "POST",
                "/applications/new-obj/federatedIdentityCredentials"
            )
            .await
            .is_empty(),
            "a refused credential must not be created"
        );
        assert!(trusts.is_empty());
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("'planted' was NOT restored")),
            "{:?}",
            out.warnings
        );
    }

    /// An adopted app keeps the owners and secrets an earlier run gave it: no
    /// owner is added twice, no secret issued twice.
    #[tokio::test]
    async fn an_adopted_app_skips_existing_owners_and_secrets() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/applications/new-obj/owners"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "value": [{ "id": "alice-oid" }] })),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "alice-oid", "userPrincipalName": "alice@contoso.com" }]
            })))
            .mount(&server)
            .await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let mut c = created(AppRegistrationBackup {
            display_name: "App A".into(),
            owners: vec![PrincipalRef {
                user_principal_name: Some("alice@contoso.com".into()),
                ..Default::default()
            }],
            secrets: vec![CredentialMeta {
                display_name: Some("ci".into()),
                ..Default::default()
            }],
            ..Default::default()
        });
        c.adopted = true;
        c.live_secret_names = vec!["ci".into()];

        let (out, _) = wire(&client, &c).await;

        assert!(
            requests(&server, "POST", "/applications/new-obj/owners/$ref")
                .await
                .is_empty(),
            "an existing owner must not be added again"
        );
        assert!(
            requests(&server, "POST", "/applications/new-obj/addPassword")
                .await
                .is_empty(),
            "an already-issued secret must not be issued again"
        );
        assert!(out.regenerated_secrets.is_empty());
        assert!(
            out.unresolved_owners.is_empty(),
            "{:?}",
            out.unresolved_owners
        );
        assert!(
            out.warnings
                .iter()
                .any(|w| w.contains("secret 'ci' already exists")),
            "{:?}",
            out.warnings
        );
    }

    /// An app whose admin consent covers a Graph application permission; the
    /// backup's own `Application.ReadWrite.All` (high risk).
    fn consenting_app(src: &str, name: &str) -> AppRegistrationBackup {
        AppRegistrationBackup {
            source_app_id: src.into(),
            display_name: name.into(),
            admin_consent_granted: true,
            required_resource_access: vec![azapptoolkit_core::models::RequiredResourceAccess {
                resource_app_id: GRAPH.into(),
                resource_access: vec![azapptoolkit_core::models::ResourceAccess {
                    id: APP_RW_ROLE.into(),
                    r#type: "Role".into(),
                }],
            }],
            ..Default::default()
        }
    }

    fn manifest(apps: Vec<AppRegistrationBackup>) -> TenantBackup {
        TenantBackup {
            schema_version: BACKUP_SCHEMA_VERSION,
            created_at: "2026-01-01T00:00:00Z".parse().unwrap(),
            source_tenant_id: "src-tenant".into(),
            cloud: CloudEnvironment::Commercial,
            app_registrations: apps,
            enterprise_apps: Vec::new(),
            managed_identities: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// Pass 1's create answers with an object id derived from the display
    /// name ("App A" → `obj-a`), so each app's later requests are tellable.
    async fn mount_create(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path("/applications"))
            .respond_with(|req: &Request| {
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                let name = body["displayName"].as_str().unwrap_or_default().to_string();
                let tag = name
                    .rsplit(' ')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": format!("obj-{tag}"),
                    "appId": format!("app-{tag}"),
                    "displayName": name,
                    "passwordCredentials": [],
                    "keyCredentials": [],
                    "requiredResourceAccess": []
                }))
            })
            .mount(server)
            .await;
    }

    /// Microsoft Graph's service principal, exposing the high-risk role.
    async fn mount_graph_sp(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param("$filter", format!("appId eq '{GRAPH}'")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "graph-sp",
                    "appId": GRAPH,
                    "displayName": "Microsoft Graph",
                    "appRoles": [{
                        "id": APP_RW_ROLE,
                        "value": "Application.ReadWrite.All",
                        "allowedMemberTypes": ["Application"],
                        "isEnabled": true
                    }, {
                        "id": MAIL_SEND_ROLE,
                        "value": "Mail.Send",
                        "allowedMemberTypes": ["Application"],
                        "isEnabled": true
                    }],
                    "oauth2PermissionScopes": [{
                        "id": USER_READ_SCOPE,
                        "value": "User.Read",
                        "isEnabled": true
                    }]
                }]
            })))
            .mount(server)
            .await;
    }

    /// Pass 3's re-read: each restored app (`obj-…`) declares what
    /// [`consenting_app`] does — what Pass 2 PATCHed.
    async fn mount_live_apps(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path_regex(r"^/applications/obj-[a-z0-9]+$"))
            .respond_with(|req: &Request| {
                let id = req
                    .url
                    .path()
                    .rsplit('/')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let tag = id.trim_start_matches("obj-").to_string();
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "id": id,
                    "appId": format!("app-{tag}"),
                    "displayName": format!("App {tag}"),
                    "requiredResourceAccess": [{
                        "resourceAppId": GRAPH,
                        "resourceAccess": [{ "id": APP_RW_ROLE, "type": "Role" }]
                    }]
                }))
            })
            .mount(server)
            .await;
    }

    /// Whether Pass 3 got as far as ensuring `app_id`'s service principal —
    /// the first step of an actual consent.
    async fn consent_attempted(server: &MockServer, app_id: &str) -> bool {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .any(|r| {
                r.method.as_str() == "GET"
                    && r.url.path() == "/servicePrincipals"
                    && r.url.query().unwrap_or_default().contains(app_id)
            })
    }

    async fn restore(
        client: &GraphClient,
        backup: &TenantBackup,
        cancel: CancelToken,
        approved: &[&str],
    ) -> (RestoreReport, RestoreEffects) {
        let approved: HashSet<RestoreApproval> = approved.iter().map(|s| app_approval(s)).collect();
        run_restore(
            client,
            &crate::commands::test_support::Recorder::default(),
            cancel,
            RestoreRun {
                backup,
                tenant_id: "dst-tenant",
                cloud: CloudEnvironment::Commercial,
                operator_oid: Some("operator-oid"),
                approved: &approved,
            },
        )
        .await
    }

    /// The backend enforces the plan's opt-in: an app whose consent grants a
    /// high-risk permission gets no consent call unless approved, whatever the
    /// front end sent — and the skip is a runbook item, not a failure.
    #[tokio::test]
    async fn high_risk_consent_is_granted_only_to_approved_apps() {
        let server = MockServer::start().await;
        mount_create(&server).await;
        mount_graph_sp(&server).await;
        mount_live_apps(&server).await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let backup = manifest(vec![
            consenting_app(SRC_A, "App A"),
            consenting_app(SRC_B, "App B"),
        ]);

        let (report, effects) = restore(
            &client,
            &backup,
            crate::state::CancelFlag::new().claim(),
            &[SRC_A],
        )
        .await;

        assert!(effects.created_any);
        assert_eq!(report.apps.len(), 2, "both apps restore: {report:?}");
        // Pass 3's first read is the app itself.
        assert_eq!(
            requests(&server, "GET", "/applications/obj-a").await.len(),
            1
        );
        assert!(
            requests(&server, "GET", "/applications/obj-b")
                .await
                .is_empty(),
            "an unapproved app must get no consent call"
        );
        // Re-read, matched what the plan showed, consented.
        assert!(consent_attempted(&server, "app-a").await);
        assert!(!consent_attempted(&server, "app-b").await);
        let skipped = report
            .manual_items
            .iter()
            .find(|m| m.display_name == "App B")
            .expect("the withheld consent is a runbook item");
        assert!(
            skipped.reason.contains("not approved in the plan")
                && skipped.reason.contains("Application.ReadWrite.All"),
            "{}",
            skipped.reason
        );
        assert!(!report.apps[1].consent_granted);
        assert!(!report.cancelled);
    }

    /// A cancel pressed during Pass 2 stops the run before Pass 3: no consent
    /// is granted, and the report says it stopped.
    #[tokio::test]
    async fn a_cancel_between_passes_is_reported_and_skips_consent() {
        let server = MockServer::start().await;
        mount_create(&server).await;
        let flag = crate::state::CancelFlag::new();
        let cancel = flag.claim();
        // The app's only Pass-2 write: the operator cancels while it lands.
        Mock::given(method("PATCH"))
            .and(path("/applications/obj-a"))
            .respond_with(move |_: &Request| {
                flag.cancel();
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let backup = manifest(vec![consenting_app(SRC_A, "App A")]);

        let (report, _) = restore(&client, &backup, cancel, &[SRC_A]).await;

        assert!(report.cancelled);
        assert!(!report.session_expired, "a cancel is not a dead session");
        assert_eq!(report.apps.len(), 1, "Pass 2 finished the app");
        assert!(
            requests(&server, "GET", "/applications/obj-a")
                .await
                .is_empty(),
            "Pass 3 must not run after a cancel"
        );
        assert!(!report.apps[0].consent_granted);
    }

    /// The plan names what the file grants and which items need approval:
    /// consent covering any application permission (even an unrisky one, or
    /// one on an API the backup recreates), a broad or unidentified delegated
    /// one, an accepted federated credential, a group membership, any
    /// managed-identity role — and any consent at all beside owners, reply
    /// URLs or the public-client flag. Low-risk delegated consent alone, a
    /// refused credential, foreign pre-authorized clients, role assignees, and
    /// owners or reply URLs without consent are shown only.
    #[tokio::test]
    async fn the_plan_lists_privileged_grants_and_what_needs_approval() {
        let server = MockServer::start().await;
        mount_graph_sp(&server).await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let consent_to = |src: &str, name: &str, resource: &str, id: &str, kind: &str| {
            let mut app = consenting_app(src, name);
            app.required_resource_access[0].resource_app_id = resource.into();
            app.required_resource_access[0].resource_access[0].id = id.into();
            app.required_resource_access[0].resource_access[0].r#type = kind.into();
            app
        };
        const SRC_C: &str = "cccccccc-0000-0000-0000-000000000003";
        const SRC_D: &str = "dddddddd-0000-0000-0000-000000000004";
        const SRC_E: &str = "eeeeeeee-0000-0000-0000-000000000005";
        const SRC_F: &str = "ffffffff-0000-0000-0000-000000000006";
        const SRC_G: &str = "99999999-0000-0000-0000-000000000007";

        // Delegated User.Read only, a refused credential, a foreign client.
        let mut low = consent_to(SRC_A, "App A", GRAPH, USER_READ_SCOPE, "Scope");
        low.pre_authorized_applications = vec![
            azapptoolkit_core::models::PreAuthorizedApplication {
                app_id: "foreign-client".into(),
                ..Default::default()
            },
            azapptoolkit_core::models::PreAuthorizedApplication {
                app_id: SRC_B.into(),
                ..Default::default()
            },
        ];
        low.federated_credentials = vec![FederatedIdentityCredential {
            name: "planted".into(),
            issuer: "http://attacker.example".into(),
            subject: Some("sub".into()),
            ..Default::default()
        }];
        let unknown = consent_to(SRC_B, "App B", "nowhere", APP_RW_ROLE, "Role");
        let high = consenting_app(SRC_C, "App C");
        let restored_api = consent_to(SRC_D, "App D", SRC_A, "custom-role", "Role");
        // No SP in the backup: Pass 3 or an adopted app can still supply one,
        // so its group memberships are shown and gated all the same.
        let grouped = AppRegistrationBackup {
            source_app_id: SRC_E.into(),
            display_name: "App E".into(),
            has_service_principal: false,
            ..Default::default()
        };
        // Owners but no consent: shown, approval-free (nothing routes tokens).
        let owners_only = AppRegistrationBackup {
            source_app_id: SRC_F.into(),
            display_name: "App F".into(),
            owners: vec![PrincipalRef {
                user_principal_name: Some("bob@contoso.com".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        // Low-risk consent AND a reply URL the file chose: consented tokens
        // would be delivered where the file says, so approval.
        let mut routed = consent_to(SRC_G, "App G", GRAPH, USER_READ_SCOPE, "Scope");
        routed.spa_redirect_uris = vec!["https://portal.example/cb".into()];
        routed.is_fallback_public_client = true;
        let mut backup = manifest(vec![
            low,
            unknown,
            high,
            restored_api,
            grouped,
            owners_only,
            routed,
        ]);
        backup.enterprise_apps = vec![EnterpriseAppBackup {
            source_app_id: SRC_E.into(),
            display_name: "App E".into(),
            group_memberships: vec![named("Global Admins", Some("#microsoft.graph.group"))],
            app_role_assignees: vec![crate::dto::backup::AppRoleAssigneeRef {
                principal: named("Ops", Some("Group")),
                app_role_id: "x".into(),
                app_role_value: Some("Reader".into()),
            }],
            ..Default::default()
        }];
        backup.managed_identities = vec![ManagedIdentityBackup {
            source_app_id: "mi-app".into(),
            display_name: "mi-one".into(),
            held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
                resource_app_id: GRAPH.into(),
                app_role_id: "r".into(),
                app_role_value: Some("User.Read.All".into()),
                ..Default::default()
            }],
            ..Default::default()
        }];
        let session = SessionDead::new();

        let items = privileged_restore_items(&client, &backup, &session).await;

        assert_eq!(items.len(), 8, "{items:#?}");
        let [
            low,
            unknown,
            high,
            restored_api,
            grouped,
            owners_only,
            routed,
            mi,
        ] = &items[..]
        else {
            unreachable!()
        };
        // Shown, but nothing in it needs approval: low-risk consent alone, a
        // refused credential and a foreign client.
        assert_eq!(low.delegated_scopes[0].value.as_deref(), Some("User.Read"));
        assert_eq!(low.delegated_scopes[0].risk, PermissionRisk::Low);
        assert_eq!(low.external_pre_authorized_clients, ["foreign-client"]);
        assert!(low.federated_credentials[0].rejected.is_some());
        assert!(low.owners.is_empty());
        assert!(!low.requires_approval, "{low:#?}");
        // Owners alone are shown and approval-free.
        assert_eq!(owners_only.owners, ["bob@contoso.com"]);
        assert!(!owners_only.admin_consent);
        assert!(!owners_only.requires_approval, "{owners_only:#?}");
        // Reply URLs and the public-client flag are shown; with consent, gated.
        assert_eq!(routed.reply_urls, ["https://portal.example/cb"]);
        assert!(routed.public_client);
        assert!(routed.requires_approval, "{routed:#?}");
        // Nobody can name it.
        assert_eq!(unknown.app_roles[0].risk, PermissionRisk::Unknown);
        assert!(unknown.requires_approval);
        // Resolved live and ranked by `core::audit`.
        assert_eq!(
            high.app_roles[0].value.as_deref(),
            Some("Application.ReadWrite.All")
        );
        assert_eq!(high.app_roles[0].risk, PermissionRisk::High);
        assert!(high.requires_approval);
        // Any application permission needs approval, even on an API the backup
        // recreates (not knowable yet, so not "unknown").
        assert!(restored_api.app_roles[0].restored_api);
        assert_eq!(restored_api.app_roles[0].risk, PermissionRisk::Low);
        assert!(restored_api.requires_approval);
        // The file chooses the group: approval. Assignees are shown only.
        assert_eq!(grouped.group_memberships, ["Global Admins"]);
        assert_eq!(grouped.app_role_assignees, ["Ops (Reader)"]);
        assert!(grouped.requires_approval);
        // Every managed-identity role needs approval, whatever its risk.
        assert_eq!(mi.kind, PrivilegedKind::ManagedIdentity);
        assert!(mi.requires_approval);
        assert!(!session.is_dead());
    }

    /// The bypass this gate exists for: an adopted app — pre-planted with the
    /// restore tag, a name and owners the file vouches for — already declares
    /// a high-risk permission, and the manifest declares none, so the plan
    /// shows no consent and asks for no approval. Consent must not grant what
    /// the live app declares.
    #[tokio::test]
    async fn consent_never_grants_permissions_the_plan_did_not_show() {
        let server = MockServer::start().await;
        mount_tagged_hit(
            &server,
            serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/applications/obj-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "obj-1",
                "appId": "app-1",
                "displayName": "App A",
                "requiredResourceAccess": [{
                    "resourceAppId": GRAPH,
                    "resourceAccess": [{ "id": APP_RW_ROLE, "type": "Role" }]
                }]
            })))
            .mount(&server)
            .await;
        mount_graph_sp(&server).await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let backup = manifest(vec![AppRegistrationBackup {
            source_app_id: SRC_A.into(),
            display_name: "App A".into(),
            admin_consent_granted: true,
            ..Default::default()
        }]);
        assert!(
            privileged_restore_items(&client, &backup, &SessionDead::new())
                .await
                .is_empty(),
            "the plan shows nothing to approve"
        );

        let (report, _) = restore(
            &client,
            &backup,
            crate::state::CancelFlag::new().claim(),
            &[],
        )
        .await;

        assert!(report.apps[0].adopted, "{report:?}");
        assert!(
            !consent_attempted(&server, "app-1").await,
            "no consent for a live permission list the plan never showed"
        );
        assert!(!report.apps[0].consent_granted);
        assert!(
            report
                .manual_items
                .iter()
                .any(|m| m.reason.contains("don't match the backup")),
            "{:?}",
            report.manual_items
        );
    }

    /// An app not approved in the plan is created and wired, but gets no
    /// federated credential and no owner from the file.
    #[tokio::test]
    async fn a_withheld_app_gets_no_federated_credential_or_owner() {
        let server = MockServer::start().await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let c = created(AppRegistrationBackup {
            display_name: "App A".into(),
            federated_credentials: vec![FederatedIdentityCredential {
                name: "gh-main".into(),
                issuer: "https://token.actions.githubusercontent.com".into(),
                subject: Some("repo:contoso/app:ref:refs/heads/main".into()),
                ..Default::default()
            }],
            owners: vec![PrincipalRef {
                user_principal_name: Some("alice@contoso.com".into()),
                ..Default::default()
            }],
            secrets: vec![CredentialMeta::default()],
            ..Default::default()
        });

        let (_, manual) = wire_with(&client, &c, true).await;

        const FICS: &str = "/applications/new-obj/federatedIdentityCredentials";
        assert!(requests(&server, "POST", FICS).await.is_empty());
        assert!(
            requests(&server, "POST", "/applications/new-obj/owners/$ref")
                .await
                .is_empty()
        );
        assert!(
            requests(&server, "GET", "/users").await.is_empty(),
            "a withheld owner is not even looked up"
        );
        // Structure still restores: the secret is regenerated.
        assert_eq!(
            requests(&server, "POST", "/applications/new-obj/addPassword")
                .await
                .len(),
            1
        );
        assert_eq!(manual.len(), 2, "{manual:?}");
        assert!(
            manual
                .iter()
                .all(|m| m.reason.contains("not approved in the plan"))
        );
        assert!(
            manual[0]
                .reason
                .contains("token.actions.githubusercontent.com")
        );
        assert!(manual[1].reason.contains("alice@contoso.com"));

        // Approved, the credential is created.
        wire_with(&client, &c, false).await;
        assert_eq!(requests(&server, "POST", FICS).await.len(), 1);
    }

    /// A withheld app's service principal joins no group the file names.
    #[tokio::test]
    async fn a_withheld_app_joins_no_group() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "sp-new", "appId": "new-a", "displayName": "Ent A" }]
            })))
            .mount(&server)
            .await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false)
            .with_group_member_token(azapptoolkit_core::token::StaticTokenProvider::new("tok"));
        let mut report = RestoreReport::default();
        let ent = EnterpriseAppBackup {
            display_name: "Ent A".into(),
            source_app_id: "src-a".into(),
            group_memberships: vec![named("Global Admins", Some("#microsoft.graph.group"))],
            ..Default::default()
        };
        let remap = HashMap::from([("src-a".to_string(), "new-a".to_string())]);

        restore_enterprise_app(
            &client,
            &ent,
            &remap,
            true,
            &mut report,
            &mut PrincipalMemo::new(),
            &SessionDead::new(),
            &never_cancelled(),
        )
        .await;

        assert!(requests(&server, "GET", "/groups").await.is_empty());
        let posts = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method.as_str() == "POST")
            .count();
        assert_eq!(posts, 0, "no membership is added");
        assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
        assert!(report.manual_items[0].reason.contains("Global Admins"));
        assert_eq!(report.enterprise_apps.len(), 1, "the rest still applies");
    }

    /// The run, not just the plan: an unapproved app's service principal joins
    /// no group even when the backup says it had no SP — whether its SP came
    /// from somewhere else at restore time (created, or already on an adopted
    /// app). Approved, it joins.
    #[tokio::test]
    async fn pass_4_adds_no_group_membership_without_approval() {
        for adopted in [false, true] {
            let server = MockServer::start().await;
            if adopted {
                mount_tagged_hit(&server, serde_json::json!([{ "id": "operator-oid" }])).await;
            } else {
                mount_create(&server).await;
            }
            // Whichever way, a service principal exists when Pass 4 looks.
            Mock::given(method("GET"))
                .and(path("/servicePrincipals"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [{ "id": "sp-x", "appId": "whatever", "displayName": "App A" }]
                })))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/groups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "value": [{ "id": "g-admins", "displayName": "Global Admins" }]
                })))
                .mount(&server)
                .await;
            mount_fallback(&server).await;
            // Group writes ride their own token; without one nothing is sent and
            // the approved run below could not tell "withheld" from "failed".
            let client = graph_over(&server, false)
                .with_group_member_token(azapptoolkit_core::token::StaticTokenProvider::new("tok"));
            let mut backup = manifest(vec![AppRegistrationBackup {
                source_app_id: SRC_A.into(),
                display_name: "App A".into(),
                has_service_principal: false,
                ..Default::default()
            }]);
            backup.enterprise_apps = vec![EnterpriseAppBackup {
                source_app_id: SRC_A.into(),
                display_name: "App A".into(),
                group_memberships: vec![named("Global Admins", Some("#microsoft.graph.group"))],
                ..Default::default()
            }];
            let items = privileged_restore_items(&client, &backup, &SessionDead::new()).await;
            assert!(items[0].requires_approval, "the plan shows and gates it");

            let (report, _) = restore(
                &client,
                &backup,
                crate::state::CancelFlag::new().claim(),
                &[],
            )
            .await;
            assert_eq!(report.apps.len(), 1, "adopted={adopted}: {report:?}");
            assert!(
                requests(&server, "POST", "/groups/g-admins/members/$ref")
                    .await
                    .is_empty(),
                "adopted={adopted}: an unapproved app joins no group"
            );
            assert!(
                report
                    .manual_items
                    .iter()
                    .any(|m| m.reason.contains("Group memberships not added")),
                "adopted={adopted}: {:?}",
                report.manual_items
            );

            restore(
                &client,
                &backup,
                crate::state::CancelFlag::new().claim(),
                &[SRC_A],
            )
            .await;
            assert_eq!(
                requests(&server, "POST", "/groups/g-admins/members/$ref")
                    .await
                    .len(),
                1,
                "adopted={adopted}: approved, it joins"
            );
        }
    }

    /// Graph's `eq` ignores case, so "Ops" and "OPS" are two principals —
    /// ambiguous, not one resolved by a stricter client-side comparison.
    #[tokio::test]
    async fn names_differing_only_in_case_are_ambiguous() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "g1", "displayName": "Ops" },
                    { "id": "g2", "displayName": "OPS" }
                ]
            })))
            .mount(&server)
            .await;
        let client = graph_over(&server, false);
        assert_eq!(
            resolve_principal_uncached(&client, &named("Ops", Some("Group")), &SessionDead::new())
                .await,
            Err(Unresolved::Ambiguous(2))
        );
    }

    /// Managed-identity source ids are approval keys, so they are held to the
    /// app-registration rule: GUIDs, unrepeated.
    #[test]
    fn managed_identity_source_ids_must_be_unique_guids() {
        const ID: &str = "33333333-3333-3333-3333-333333333333";
        let mut backup = manifest_with_ids(&[]);
        backup.managed_identities = [ID, ID, ""]
            .map(|id| ManagedIdentityBackup {
                source_app_id: id.into(),
                display_name: "mi".into(),
                ..Default::default()
            })
            .to_vec();
        let problems = manifest_problems(&backup);
        assert_eq!(
            problems,
            [
                "managed identity 'mi' has no source appId".to_string(),
                format!("managed identity source appId {ID} appears 2 times"),
            ]
        );
        assert!(validate_manifest(&backup).is_err());
    }
    fn named(name: &str, kind: Option<&str>) -> PrincipalRef {
        PrincipalRef {
            display_name: Some(name.into()),
            principal_type: kind.map(Into::into),
            ..Default::default()
        }
    }

    /// With no recorded type, a name matching a group AND a user is ambiguous,
    /// never the first one found.
    #[tokio::test]
    async fn an_ambiguous_principal_is_left_unresolved() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "value": [{ "id": "g1", "displayName": "Ops" }] }),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "u1", "displayName": "Ops" },
                    { "id": "u2", "displayName": "Ops team" }
                ]
            })))
            .mount(&server)
            .await;
        let client = graph_over(&server, false);

        assert_eq!(
            resolve_principal_uncached(&client, &named("Ops", None), &SessionDead::new()).await,
            Err(Unresolved::Ambiguous(2))
        );
        // A recorded type searches only its own collection.
        assert_eq!(
            resolve_principal_uncached(
                &client,
                &named("Ops", Some("#microsoft.graph.group")),
                &SessionDead::new()
            )
            .await,
            Ok("g1".to_string())
        );
        assert_eq!(
            resolve_principal_uncached(&client, &named("Ops", Some("User")), &SessionDead::new())
                .await,
            Ok("u1".to_string())
        );
        // A service principal is never matched to a same-named user or group.
        assert_eq!(
            resolve_principal_uncached(
                &client,
                &named("Ops", Some("ServicePrincipal")),
                &SessionDead::new()
            )
            .await,
            Err(Unresolved::UnsupportedType("ServicePrincipal".into()))
        );
    }

    /// A failed group search is not an absent group: the principal stays
    /// unresolved, and no user search runs in its place.
    #[tokio::test]
    async fn a_failed_group_search_never_falls_back_to_users() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/groups"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);

        for kind in [Some("#microsoft.graph.group"), None] {
            assert_eq!(
                resolve_principal_uncached(&client, &named("Ops", kind), &SessionDead::new()).await,
                Err(Unresolved::LookupFailed),
                "{kind:?}"
            );
        }
        assert!(
            requests(&server, "GET", "/users").await.is_empty(),
            "a group-search error must not fall back to a user search"
        );
    }

    /// Two destination identities under one name: neither is re-bound, and
    /// the operator is told why.
    #[tokio::test]
    async fn duplicate_destination_mi_names_become_a_manual_item() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "sp-1", "appId": "a1", "displayName": "mi-one" },
                    { "id": "sp-2", "appId": "a2", "displayName": "MI-One" }
                ]
            })))
            .mount(&server)
            .await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let mut report = RestoreReport::default();
        let mis = vec![ManagedIdentityBackup {
            display_name: "mi-one".into(),
            held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
                resource_app_id: GRAPH.into(),
                app_role_id: "r".into(),
                app_role_value: Some("User.Read.All".into()),
                ..Default::default()
            }],
            ..Default::default()
        }];

        restore_managed_identities(
            &client,
            &mis,
            &HashSet::new(),
            &mut report,
            &SessionDead::new(),
            &never_cancelled(),
        )
        .await;

        assert!(report.managed_identities.is_empty(), "nothing re-bound");
        assert_eq!(report.manual_items.len(), 1, "{:?}", report.manual_items);
        assert!(
            report.manual_items[0]
                .reason
                .contains("2 managed identities")
                && report.manual_items[0].reason.contains("sp-1, sp-2"),
            "{}",
            report.manual_items[0].reason
        );
        let posts = server
            .received_requests()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.method.as_str() == "POST")
            .count();
        assert_eq!(posts, 0, "no role is granted to either identity");
    }

    /// Every managed-identity app role needs approval: unapproved, none is
    /// POSTed and they are one runbook item; approved, they re-bind.
    #[tokio::test]
    async fn an_unapproved_mi_gets_no_app_role() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param(
                "$filter",
                "servicePrincipalType eq 'ManagedIdentity'",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "sp-1", "appId": "a1", "displayName": "mi-one" }]
            })))
            .mount(&server)
            .await;
        mount_graph_sp(&server).await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let mis = vec![ManagedIdentityBackup {
            source_app_id: SRC_A.into(),
            display_name: "mi-one".into(),
            held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
                resource_app_id: GRAPH.into(),
                app_role_id: "r".into(),
                app_role_value: Some("Mail.Send".into()),
                ..Default::default()
            }],
            ..Default::default()
        }];
        const GRANTS: &str = "/servicePrincipals/sp-1/appRoleAssignments";

        // An APP approval with the same id does not approve the identity.
        let app_only = HashSet::from([app_approval(SRC_A)]);
        let mut report = RestoreReport::default();
        restore_managed_identities(
            &client,
            &mis,
            &app_only,
            &mut report,
            &SessionDead::new(),
            &never_cancelled(),
        )
        .await;
        assert!(
            requests(&server, "POST", GRANTS).await.is_empty(),
            "Mail.Send must never be POSTed"
        );
        let withheld = report
            .manual_items
            .iter()
            .find(|m| m.reason.contains("not approved in the plan"))
            .expect("the withheld roles are a runbook item");
        assert!(withheld.reason.contains("Mail.Send"), "{}", withheld.reason);

        let approved = HashSet::from([RestoreApproval {
            kind: PrivilegedKind::ManagedIdentity,
            source_app_id: SRC_A.into(),
        }]);
        let mut report = RestoreReport::default();
        restore_managed_identities(
            &client,
            &mis,
            &approved,
            &mut report,
            &SessionDead::new(),
            &never_cancelled(),
        )
        .await;
        let posted = requests(&server, "POST", GRANTS).await;
        assert_eq!(posted.len(), 1);
        assert!(
            String::from_utf8_lossy(&posted[0].body).contains(MAIL_SEND_ROLE),
            "approved, the role re-binds"
        );
    }

    /// Credentials are the standing access the owner check cannot see. A
    /// restore never uploads a certificate and issues secrets only under the
    /// manifest's names, so either on a hit means someone else put it there.
    #[test]
    fn a_hit_holding_credentials_the_manifest_does_not_name_is_refused() {
        use azapptoolkit_core::models::{KeyCredential, PasswordCredential};

        let app = AppRegistrationBackup {
            display_name: "App A".into(),
            source_app_id: "src-a".into(),
            secrets: vec![CredentialMeta {
                display_name: Some("ci".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let taken_at = chrono::DateTime::from_timestamp(1_000_000, 0).unwrap();
        let hit = || Application {
            id: "obj-1".into(),
            app_id: "app-1".into(),
            display_name: "App A".into(),
            created_date_time: chrono::DateTime::from_timestamp(1_000_600, 0),
            ..Default::default()
        };

        let mut certed = hit();
        certed.key_credentials = vec![KeyCredential::default()];
        let Adoption::Refuse(reason) = adoption_for(&app, &[certed], taken_at) else {
            panic!("a certificate credential must refuse the adoption");
        };
        assert!(reason.contains("certificate"), "{reason}");

        let mut planted = hit();
        planted.password_credentials = vec![
            PasswordCredential {
                display_name: Some("ci".into()),
                ..Default::default()
            },
            PasswordCredential {
                display_name: Some("backdoor".into()),
                ..Default::default()
            },
        ];
        let Adoption::Refuse(reason) = adoption_for(&app, &[planted], taken_at) else {
            panic!("a secret the manifest does not name must refuse the adoption");
        };
        assert!(reason.contains("(backdoor)"), "{reason}");

        // Two live "ci" against one manifest entry: the second is foreign.
        let mut doubled = hit();
        doubled.password_credentials = vec![
            PasswordCredential {
                display_name: Some("ci".into()),
                ..Default::default()
            },
            PasswordCredential {
                display_name: Some("ci".into()),
                ..Default::default()
            },
        ];
        let Adoption::Refuse(reason) = adoption_for(&app, &[doubled], taken_at) else {
            panic!("more same-named secrets than the manifest lists must refuse");
        };
        assert!(reason.contains("(ci)"), "{reason}");

        // A certificate whose thumbprint the manifest lists (the runbook's own
        // re-upload) is accounted for; any other is foreign.
        let mut with_cert = app.clone();
        with_cert.certificates = vec![CredentialMeta {
            thumbprint: Some("DA20FCA696C4F83E8A9AED59BE33368ED421F3C1".into()),
            ..Default::default()
        }];
        let mut reuploaded = hit();
        reuploaded.key_credentials = vec![KeyCredential {
            custom_key_identifier: Some("2iD8ppbE+D6Kmu1ZvjM2jtQh88E=".into()),
            ..Default::default()
        }];
        assert!(matches!(
            adoption_for(&with_cert, &[reuploaded], taken_at),
            Adoption::Adopt { .. }
        ));
        let mut other_cert = hit();
        other_cert.key_credentials = vec![KeyCredential {
            key_id: "k-other".into(),
            custom_key_identifier: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAA=".into()),
            ..Default::default()
        }];
        let Adoption::Refuse(reason) = adoption_for(&with_cert, &[other_cert], taken_at) else {
            panic!("a certificate the manifest does not list must refuse");
        };
        assert!(reason.contains("k-other"), "{reason}");

        // Exactly the manifest's secret, issued by the earlier run: adopted.
        let mut legit = hit();
        legit.password_credentials = vec![PasswordCredential {
            display_name: Some("ci".into()),
            ..Default::default()
        }];
        assert!(matches!(
            adoption_for(&app, &[legit], taken_at),
            Adoption::Adopt { .. }
        ));
    }

    /// A planted federated credential is a secretless, permanent sign-in as
    /// the app; the owner check cannot see it, so adoption reads them.
    #[tokio::test]
    async fn a_tagged_app_with_a_federated_credential_the_manifest_does_not_name_is_not_adopted() {
        let server = wiremock::MockServer::start().await;
        mount_tagged_hit(
            &server,
            serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
        )
        .await;
        mount_tagged_fics(
            &server,
            serde_json::json!([{
                "id": "fic-1", "name": "gh-main",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:mallory/app:ref:refs/heads/main",
                "audiences": ["api://AzureADTokenExchange"]
            }]),
            1,
        )
        .await;
        let client = graph_over(&server, false);

        let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
            panic!("a credential the manifest does not name must block adoption");
        };
        assert!(reason.contains("repo:mallory/app"), "{reason}");
    }

    /// A live credential the manifest names — matched on name, issuer, subject
    /// and audiences, the manifest's empty audiences defaulting to the cloud's
    /// — is the one an earlier run created: adopted. A flexible credential
    /// (no subject) is never matched.
    #[tokio::test]
    async fn a_tagged_app_whose_federated_credential_the_manifest_names_is_adopted() {
        let server = wiremock::MockServer::start().await;
        mount_tagged_hit(
            &server,
            serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
        )
        .await;
        let live = |subject: Option<&str>| {
            serde_json::json!([{
                "id": "fic-1", "name": "gh-main",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": subject,
                "audiences": ["api://AzureADTokenExchange"]
            }])
        };
        let client = graph_over(&server, false);
        let mut app = tagged_app_a();
        app.federated_credentials = vec![FederatedIdentityCredential {
            name: "gh-main".into(),
            issuer: "https://token.actions.githubusercontent.com".into(),
            subject: Some("repo:contoso/app:ref:refs/heads/main".into()),
            ..Default::default()
        }];
        let taken_at: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        async fn decide_app(
            client: &GraphClient,
            app: &AppRegistrationBackup,
            taken_at: DateTime<Utc>,
        ) -> Adoption {
            decide_adoption(
                client,
                app,
                taken_at,
                CloudEnvironment::Commercial,
                Some("operator-oid"),
                &mut HashMap::new(),
                &SessionDead::new(),
            )
            .await
        }

        mount_tagged_fics(
            &server,
            live(Some("repo:contoso/app:ref:refs/heads/main")),
            2,
        )
        .await;
        assert!(matches!(
            decide_app(&client, &app, taken_at).await,
            Adoption::Adopt { .. }
        ));

        mount_tagged_fics(&server, live(None), 1).await;
        let Adoption::Refuse(reason) = decide_app(&client, &app, taken_at).await else {
            panic!("a flexible credential can never be matched to the manifest");
        };
        assert!(reason.contains("gh-main"), "{reason}");
    }

    /// The credential read fails closed like the tag and owner reads.
    #[tokio::test]
    async fn a_failed_federated_credential_read_refuses_the_adoption() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        mount_tagged_hit(
            &server,
            serde_json::json!([{ "id": "operator-oid", "userPrincipalName": "admin@contoso.com" }]),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/applications/obj-1/federatedIdentityCredentials"))
            .respond_with(ResponseTemplate::new(503))
            .with_priority(1)
            .mount(&server)
            .await;
        let client = graph_over(&server, false);

        let Adoption::Refuse(reason) = decide(&client, &SessionDead::new()).await else {
            panic!("a failed credential read must refuse");
        };
        assert!(reason.contains("federated credentials"), "{reason}");
    }

    /// A run that creates nothing but re-binds a managed identity's roles
    /// reports it, so the caller refreshes the audit.
    #[tokio::test]
    async fn a_run_that_only_rebinds_roles_reports_rebound_any() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param(
                "$filter",
                "servicePrincipalType eq 'ManagedIdentity'",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{ "id": "sp-1", "appId": "a1", "displayName": "mi-one" }]
            })))
            .mount(&server)
            .await;
        mount_graph_sp(&server).await;
        Mock::given(method("POST"))
            .and(path("/servicePrincipals/sp-1/appRoleAssignments"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "assign-1", "principalId": "sp-1", "resourceId": "graph-sp",
                "appRoleId": MAIL_SEND_ROLE
            })))
            .mount(&server)
            .await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let mut backup = manifest(vec![]);
        backup.managed_identities = vec![ManagedIdentityBackup {
            source_app_id: SRC_A.into(),
            display_name: "mi-one".into(),
            held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
                resource_app_id: GRAPH.into(),
                app_role_id: "r".into(),
                app_role_value: Some("Mail.Send".into()),
                ..Default::default()
            }],
            ..Default::default()
        }];
        let approved: HashSet<RestoreApproval> = HashSet::from([RestoreApproval {
            kind: PrivilegedKind::ManagedIdentity,
            source_app_id: SRC_A.into(),
        }]);

        let (report, effects) = run_restore(
            &client,
            &crate::commands::test_support::Recorder::default(),
            never_cancelled(),
            RestoreRun {
                backup: &backup,
                tenant_id: "dst-tenant",
                cloud: CloudEnvironment::Commercial,
                operator_oid: Some("operator-oid"),
                approved: &approved,
            },
        )
        .await;

        assert_eq!(report.managed_identities[0].app_roles_rebound, 1);
        assert_eq!(
            effects,
            RestoreEffects {
                created_any: false,
                rebound_any: true
            }
        );
    }

    /// A dead session during a principal lookup is noted like every other
    /// read, so the latch trips here rather than at the next noted call.
    #[tokio::test]
    async fn a_dead_session_during_a_principal_lookup_latches() {
        let server = MockServer::start().await;
        let client = graph_over(&server, true);
        let session = SessionDead::new();
        assert_eq!(
            resolve_principal_uncached(&client, &named("Ops", Some("Group")), &session).await,
            Err(Unresolved::LookupFailed)
        );
        assert!(session.is_dead(), "a dead refresh token must latch");
    }

    /// Cancel is honoured inside Pass 5, not only before it: the second
    /// identity is left alone and the report says the run was cancelled.
    #[tokio::test]
    async fn a_cancel_during_pass_5_stops_at_the_next_identity() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param(
                "$filter",
                "servicePrincipalType eq 'ManagedIdentity'",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [
                    { "id": "sp-1", "appId": "a1", "displayName": "mi-one" },
                    { "id": "sp-2", "appId": "a2", "displayName": "mi-two" }
                ]
            })))
            .mount(&server)
            .await;
        mount_graph_sp(&server).await;
        let flag = crate::state::CancelFlag::new();
        let cancel = flag.claim();
        // The operator cancels while the first identity's grant lands.
        Mock::given(method("POST"))
            .and(path("/servicePrincipals/sp-1/appRoleAssignments"))
            .respond_with(move |_: &Request| {
                flag.cancel();
                ResponseTemplate::new(201).set_body_json(serde_json::json!({ "id": "x" }))
            })
            .mount(&server)
            .await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let role = |src: &str, name: &str| ManagedIdentityBackup {
            source_app_id: src.into(),
            display_name: name.into(),
            held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
                resource_app_id: GRAPH.into(),
                app_role_id: "r".into(),
                app_role_value: Some("Mail.Send".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mis = vec![role(SRC_A, "mi-one"), role(SRC_B, "mi-two")];
        let approved: HashSet<RestoreApproval> = [SRC_A, SRC_B]
            .into_iter()
            .map(|s| RestoreApproval {
                kind: PrivilegedKind::ManagedIdentity,
                source_app_id: s.into(),
            })
            .collect();
        let mut report = RestoreReport::default();

        restore_managed_identities(
            &client,
            &mis,
            &approved,
            &mut report,
            &SessionDead::new(),
            &cancel,
        )
        .await;

        assert!(report.cancelled);
        assert!(
            requests(
                &server,
                "POST",
                "/servicePrincipals/sp-2/appRoleAssignments"
            )
            .await
            .is_empty(),
            "the second identity must not be touched after a cancel"
        );
        assert_eq!(report.managed_identities.len(), 1);
    }

    /// A destination identity of another sub-type is not this identity,
    /// however it is named; an unknown sub-type on either side still matches.
    #[tokio::test]
    async fn an_identity_of_another_subtype_is_not_matched_by_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/servicePrincipals"))
            .and(query_param(
                "$filter",
                "servicePrincipalType eq 'ManagedIdentity'",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": [{
                    "id": "sp-1", "appId": "a1", "displayName": "mi-one",
                    "alternativeNames": ["isExplicit=True", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi-one"]
                }]
            })))
            .mount(&server)
            .await;
        mount_graph_sp(&server).await;
        mount_fallback(&server).await;
        let client = graph_over(&server, false);
        let mi = |subtype: MiSubtype| ManagedIdentityBackup {
            source_app_id: SRC_A.into(),
            display_name: "mi-one".into(),
            subtype,
            held_app_roles: vec![crate::dto::backup::AppRoleGrantRef {
                resource_app_id: GRAPH.into(),
                app_role_id: "r".into(),
                app_role_value: Some("Mail.Send".into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        let approved = HashSet::from([RestoreApproval {
            kind: PrivilegedKind::ManagedIdentity,
            source_app_id: SRC_A.into(),
        }]);
        const GRANTS: &str = "/servicePrincipals/sp-1/appRoleAssignments";

        let mut report = RestoreReport::default();
        restore_managed_identities(
            &client,
            &[mi(MiSubtype::SystemAssigned)],
            &approved,
            &mut report,
            &SessionDead::new(),
            &never_cancelled(),
        )
        .await;
        assert!(requests(&server, "POST", GRANTS).await.is_empty());
        assert!(
            report
                .manual_items
                .iter()
                .any(|m| m.reason.contains("not found in the destination")),
            "{:?}",
            report.manual_items
        );

        for subtype in [MiSubtype::UserAssigned, MiSubtype::Unknown] {
            let mut report = RestoreReport::default();
            restore_managed_identities(
                &client,
                &[mi(subtype)],
                &approved,
                &mut report,
                &SessionDead::new(),
                &never_cancelled(),
            )
            .await;
            assert_eq!(report.managed_identities.len(), 1, "{subtype:?}");
        }
        assert_eq!(requests(&server, "POST", GRANTS).await.len(), 2);
    }
}
