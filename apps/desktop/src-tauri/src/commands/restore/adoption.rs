//! Pass 1: creating each app's shell, or adopting the app an earlier run of
//! this restore created — only once it is provably that one — and finishing
//! it rather than creating it again.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_core::models::{Application, DirectoryObject, FederatedIdentityCredential};
use azapptoolkit_graph::GraphClient;

use crate::commands::applications::{CreateExtras, create_application_core_with};
use crate::commands::dispatch::SessionDead;
use crate::commands::progress::ProgressSink;
use crate::dto::applications::CreateApplicationInput;
use crate::dto::backup::{AppRegistrationBackup, ManualItem, RestoreFailure, RestoreReport};
use crate::state::CancelToken;

use super::principals::{PrincipalMemo, resolve_principal};
use super::wire::{CreatedApp, expired_at_backup};
use super::{RestoreProgress, RestoreRun};

/// Prefix of the tag every app created by a restore carries; the suffix is the
/// app's **source** appId, the one key that survives the tenant move.
pub(super) const RESTORE_MARKER_PREFIX: &str = "azapptoolkit:restoredFrom:";

/// The restore tag for the app backed up as `source_app_id`.
pub(super) fn restore_marker(source_app_id: &str) -> String {
    format!("{RESTORE_MARKER_PREFIX}{source_app_id}")
}

/// What Pass 1 does with one manifest app, given the destination apps that
/// already carry its restore tag.
#[derive(Debug, PartialEq)]
pub(super) enum Adoption {
    /// Nothing carries the tag — create it.
    Create,
    /// An earlier run created it — finish wiring that one instead.
    Adopt {
        object_id: String,
        app_id: String,
        /// The named secrets it already holds, so Pass 2 does not issue them a
        /// second time — and names the one it keeps by key id.
        live_secrets: Vec<LiveSecret>,
    },
    /// Something carries the tag but cannot safely be taken for this app;
    /// the reason becomes a runbook item and nothing is created.
    Refuse(String),
}

/// A named secret an adoption candidate already holds, as the tag lookup read
/// it. Pass 2 keeps a same-named one rather than issuing it again, and prints
/// these so the operator can tell it from a planted copy of the name.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct LiveSecret {
    pub(super) name: String,
    pub(super) key_id: String,
    /// Its `startDateTime`: when the secret was added.
    pub(super) created: Option<DateTime<Utc>>,
    /// The first characters of its value, as Entra shows them.
    pub(super) hint: Option<String>,
}

/// Pure Pass-1 decision on the tag lookup. Adoption needs the tag, the exact
/// display name **and** a creation time after the backup was taken: the tag
/// alone could be on an app someone has since repurposed, the name alone proves
/// nothing, and an app older than the backup cannot be one a restore of it
/// created. Anything else fails closed — never a second copy, and never a hit
/// holding a certificate or secret the manifest does not account for. An
/// `Adopt` here is still provisional: [`decide_adoption`] checks the hit's
/// owners, federated credentials and service principal before Pass 1 takes
/// it.
pub(super) fn adoption_for(
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
                live_secrets: hit
                    .password_credentials
                    .iter()
                    .filter_map(|p| {
                        Some(LiveSecret {
                            name: p.display_name.clone()?,
                            key_id: p.key_id.clone(),
                            created: p.start_date_time,
                            hint: p.hint.clone(),
                        })
                    })
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
pub(super) fn unexpected_owners(
    owners: &[DirectoryObject],
    allowed: &HashSet<String>,
) -> Vec<String> {
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
/// then the owner, federated-credential and service-principal checks that make
/// an adoption provable.
///
/// The tag and the display name are both writable by anyone allowed to register
/// apps, and source appIds are not secret — so a pre-seeded app with the right
/// tag and name would otherwise be adopted and then handed the manifest's
/// permissions, fresh secrets and tenant-wide admin consent while keeping its
/// planter as an owner. An app this restore created has no owners but the
/// operator (`operator_oid`, the signed-in account in the destination) and the
/// manifest's own owners (resolved through the run's `principals` memo, which
/// Pass 2 then reuses), so any other owner is refused by name. The app's
/// existing service principal is held to the same rule, and to holding no
/// credential at all ([`check_service_principal`]). Every read that fails
/// refuses too: neither adopting nor creating blind is safe.
pub(super) async fn decide_adoption(
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
    let mut owners_allowed = OwnersAllowed::new(operator_oid);
    // A lookup that failed because the session died leaves that owner out of
    // the allowed set; refusing "owners this restore did not set" would then
    // send the operator after a problem that does not exist.
    if owners_allowed
        .cover(&owners, client, app, principals, session)
        .await
        .is_err()
    {
        return session_ended(app, app_id);
    }
    let extra = unexpected_owners(&owners, &owners_allowed.ids);
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
    if let Some(refusal) = check_service_principal(
        client,
        app,
        app_id,
        &mut owners_allowed,
        principals,
        session,
    )
    .await
    {
        return refusal;
    }
    adoption
}

/// The refusal when the session died while an adoption candidate was checked.
fn session_ended(app: &AppRegistrationBackup, app_id: &str) -> Adoption {
    Adoption::Refuse(format!(
        "The sign-in session ended while checking '{}' (appId {app_id}), which carries this \
         app's restore tag, so it was neither adopted nor created again. Sign in again and run \
         the restore again.",
        app.display_name
    ))
}

/// The destination object ids an adoption candidate's owners may have: the
/// operator, and — resolved only once someone else turns up — the manifest's
/// own owners, through the run's principal memo.
struct OwnersAllowed {
    ids: HashSet<String>,
    manifest_resolved: bool,
}

impl OwnersAllowed {
    fn new(operator_oid: Option<&str>) -> Self {
        Self {
            ids: operator_oid
                .filter(|oid| !oid.is_empty())
                .map(str::to_owned)
                .into_iter()
                .collect(),
            manifest_resolved: false,
        }
    }

    /// Resolves the manifest's owners into the set when one of `owners` is
    /// not the operator. `Err` when the session died meanwhile: a lookup it
    /// failed left that owner out, so the set proves nothing.
    async fn cover(
        &mut self,
        owners: &[DirectoryObject],
        client: &GraphClient,
        app: &AppRegistrationBackup,
        principals: &mut PrincipalMemo,
        session: &SessionDead,
    ) -> Result<(), ()> {
        if !self.manifest_resolved && owners.iter().any(|o| !self.ids.contains(&o.id)) {
            self.manifest_resolved = true;
            for owner in &app.owners {
                if let Ok(id) = resolve_principal(client, principals, owner, session).await {
                    self.ids.insert(id);
                }
            }
        }
        if session.is_dead() { Err(()) } else { Ok(()) }
    }
}

/// The adoption check on the candidate's existing service principal, or
/// `None` when it passes (or there is none yet — Pass 1 then creates it).
///
/// The service principal is the other half of the app, and Pass 1 only
/// ensures it exists: a password or certificate on it signs in as this app,
/// and an owner of it can add one — with the consent Pass 3 then grants. A
/// restore never adds a credential or an owner to a service principal, so
/// any credential refuses (one the operator added after an earlier run too:
/// this cannot tell it from a planted one), and an owner must be one the app
/// registration itself may have. The read is live, never cached: a cached
/// copy from before a credential was added would let it through. A failed
/// read refuses like every other.
async fn check_service_principal(
    client: &GraphClient,
    app: &AppRegistrationBackup,
    app_id: &str,
    owners_allowed: &mut OwnersAllowed,
    principals: &mut PrincipalMemo,
    session: &SessionDead,
) -> Option<Adoption> {
    let sp = match client
        .get_service_principal_credentials_by_app_id(app_id)
        .await
    {
        Ok(Some(sp)) => sp,
        Ok(None) => return None,
        Err(e) => {
            session.note_code(e.ui_code());
            return Some(Adoption::Refuse(format!(
                "Couldn't read the service principal of '{}' (appId {app_id}), which carries this \
                 app's restore tag ({e}), so it was neither adopted nor created again. Run the \
                 restore again once the read succeeds.",
                app.display_name
            )));
        }
    };
    let credentials: Vec<String> = sp
        .password_credentials
        .iter()
        .map(|p| {
            p.display_name.clone().map_or_else(
                || format!("secret {}", p.key_id),
                |n| format!("secret '{n}'"),
            )
        })
        .chain(sp.key_credentials.iter().map(|k| {
            k.display_name.clone().map_or_else(
                || format!("certificate {}", k.key_id),
                |n| format!("certificate '{n}'"),
            )
        }))
        .collect();
    if !credentials.is_empty() {
        return Some(Adoption::Refuse(format!(
            "'{}' (appId {app_id}) carries this app's restore tag, but its service principal \
             holds credential(s) a restore never adds ({}). Each lets whoever holds it sign in as \
             this app, so it was not adopted (that would give it this app's permissions and admin \
             consent) and not created again. If you added them yourself after an earlier run, \
             finish this app by hand or remove them from the enterprise application and run the \
             restore again; otherwise find out who added them, and delete the app to have the \
             restore recreate it.",
            app.display_name,
            credentials.join(", ")
        )));
    }
    let sp_owners = match client.list_service_principal_owners(&sp.id).await {
        Ok(owners) => owners,
        Err(e) => {
            session.note_code(e.ui_code());
            return Some(Adoption::Refuse(format!(
                "Couldn't read the owners of the service principal of '{}' (appId {app_id}), \
                 which carries this app's restore tag ({e}), so it was neither adopted nor \
                 created again. Run the restore again once the read succeeds.",
                app.display_name
            )));
        }
    };
    if owners_allowed
        .cover(&sp_owners, client, app, principals, session)
        .await
        .is_err()
    {
        return Some(session_ended(app, app_id));
    }
    let extra = unexpected_owners(&sp_owners, &owners_allowed.ids);
    if !extra.is_empty() {
        return Some(Adoption::Refuse(format!(
            "'{}' (appId {app_id}) carries this app's restore tag, but its service principal has \
             owners this restore did not set: {}. An owner can add a credential to it and sign in \
             as this app, so it was not adopted (that would give it this app's permissions and \
             admin consent) and not created again. Find out who added them: if they are \
             legitimate, remove them from the enterprise application's owners and run the restore \
             again; otherwise delete the app to have the restore recreate it.",
            app.display_name,
            extra.join(", ")
        )));
    }
    None
}

/// The fields a federated credential is matched on between the manifest and a
/// live app — name, issuer, subject and audiences (the cloud default when the
/// manifest lists none) — the same tuple Pass 2 creates it with, so "already
/// exists" means the same credential, never a same-named one.
pub(super) type FicKey = (String, String, Option<String>, Vec<String>);

pub(super) fn fic_key(fic: &FederatedIdentityCredential, cloud: CloudEnvironment) -> FicKey {
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

/// Pass 1 of [`run_restore`](super::run_restore): create every manifest app's
/// shell, or adopt the one an earlier run of this restore created
/// ([`decide_adoption`]); a refused app becomes a runbook item and a failed
/// create a report failure. Returns the `source_app_id → new app id` remap and
/// the apps created or adopted, which Passes 2-4 then share read-only.
///
/// Stops at the next app on `cancel` and on a dead session, flagging the report
/// cancelled either way, and emits one progress tick per app it settles.
pub(super) async fn pass1_create_or_adopt(
    client: &GraphClient,
    progress: &mut RestoreProgress<'_, impl ProgressSink>,
    cancel: &CancelToken,
    run: &RestoreRun<'_>,
    session: &SessionDead,
    principals: &mut PrincipalMemo,
    report: &mut RestoreReport,
) -> (HashMap<String, String>, Vec<CreatedApp>) {
    let RestoreRun {
        backup,
        cloud,
        operator_oid,
        ..
    } = *run;
    // source_app_id → new app id, for remapping cross-app references.
    let mut app_id_remap: HashMap<String, String> = HashMap::new();
    // The apps we actually created, paired with their backup + new ids, so
    // passes 2–3 wire exactly those.
    let mut created: Vec<CreatedApp> = Vec::new();
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
            principals,
            session,
        )
        .await
        {
            Adoption::Refuse(reason) => {
                report.manual_items.push(ManualItem {
                    display_name: app.display_name.clone(),
                    reason,
                });
                progress.tick(&app.display_name);
                continue;
            }
            Adoption::Adopt {
                object_id,
                app_id,
                live_secrets,
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
                    live_secrets,
                    warnings,
                });
                progress.tick(&app.display_name);
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
                    live_secrets: Vec::new(),
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
        progress.tick(&app.display_name);
    }
    (app_id_remap, created)
}
