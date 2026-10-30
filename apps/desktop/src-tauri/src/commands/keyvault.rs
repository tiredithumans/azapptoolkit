//! Key Vault secret operations.
//!
//! Clients are built and cached by [`AppState::kv_for`], which wires the
//! shared token adapter for the `https://vault.azure.net` audience.

use futures::stream::{self, StreamExt};
use tauri::State;

use azapptoolkit_core::defaults::AppVaultBinding;
use azapptoolkit_core::models::PasswordCredential;
use azapptoolkit_core::settings::UserSettings;
use azapptoolkit_graph::GraphClient;
use azapptoolkit_keyvault::{KeyVaultClient, KeyVaultError, SecretItem, SecretSetRequest};

use crate::commands::applications::invalidate_app_credentials;
use crate::commands::dispatch::ARM_CONCURRENCY;
use crate::dto::UiError;
use crate::dto::keyvault::{
    KvSecretItemDto, KvSecretValueDto, RotateCredentialInput, RotateCredentialResult,
};
use crate::state::AppState;

// ---------------- Commands ----------------

#[tauri::command]
pub async fn kv_list_secrets(
    state: State<'_, AppState>,
    tenant_id: String,
    vault_name: String,
) -> Result<Vec<KvSecretItemDto>, UiError> {
    let client = state.kv_for(&tenant_id, &vault_name)?;
    let items = client.list_secrets().await?;
    Ok(items
        .into_iter()
        .map(|item| KvSecretItemDto {
            name: item.name().unwrap_or("").to_string(),
            id: item.id.clone(),
            enabled: item.attributes.as_ref().and_then(|a| a.enabled),
            expires: item
                .attributes
                .as_ref()
                .and_then(|a| a.expires)
                .map(|d| d.to_rfc3339()),
            content_type: item.content_type,
            managed: item.managed,
        })
        .collect())
}

#[tauri::command]
pub async fn kv_get_secret(
    state: State<'_, AppState>,
    tenant_id: String,
    vault_name: String,
    secret_name: String,
) -> Result<KvSecretValueDto, UiError> {
    let client = state.kv_for(&tenant_id, &vault_name)?;
    let sv = client.get_secret(&secret_name, None).await?;
    Ok(KvSecretValueDto {
        name: secret_name,
        value: sv.value,
        content_type: sv.content_type,
        expires: sv
            .attributes
            .and_then(|a| a.expires)
            .map(|d| d.to_rfc3339()),
    })
}

/// Ownership tag keys stamped on every secret version this app mints (F079).
/// A vault reader (or the next rotation) can tell which app — and which
/// credential generation — a version was written for; the collision guard
/// below refuses to overwrite a secret whose tags name a DIFFERENT app.
const TAG_APP_ID: &str = "azapptoolkit-app-id";
const TAG_OBJECT_ID: &str = "azapptoolkit-object-id";
const TAG_KEY_ID: &str = "azapptoolkit-key-id";

/// Builds the provenance tags for a rotated secret version. The ids are
/// identifiers, never secret material (the value itself never appears here —
/// see the app's "never write secrets to disk or logs" rule).
fn rotation_tags(
    app_id: Option<&str>,
    object_id: &str,
    key_id: &str,
) -> std::collections::HashMap<String, String> {
    let mut tags = std::collections::HashMap::new();
    tags.insert(
        TAG_OBJECT_ID.to_string(),
        object_id.trim().to_ascii_lowercase(),
    );
    if let Some(a) = app_id.map(str::trim).filter(|a| !a.is_empty()) {
        tags.insert(TAG_APP_ID.to_string(), a.to_ascii_lowercase());
    }
    tags.insert(TAG_KEY_ID.to_string(), key_id.to_string());
    tags
}

/// True when the existing vault secret's tags provably name a different
/// application. Tag-less secrets (and tag sets without our keys) are NOT
/// treated as foreign: the tags only became trustworthy with this change, and
/// hand-made secrets legitimately carry no ownership claim. Decision order:
/// the object-id tag is decisive; the app-id tag is the fallback.
fn owned_by_other_app(
    tags: &std::collections::HashMap<String, String>,
    object_id: &str,
    app_id: Option<&str>,
) -> Option<String> {
    if let Some(owner) = tags.get(TAG_OBJECT_ID) {
        return Some(owner.clone()).filter(|o| *o != object_id.trim().to_ascii_lowercase());
    }
    if let Some(owner) = tags.get(TAG_APP_ID) {
        return match app_id.map(str::trim).filter(|a| !a.is_empty()) {
            Some(mine) => Some(owner.clone()).filter(|o| *o != mine.to_ascii_lowercase()),
            // No identity on the rotation input: any recorded owner wins.
            None => Some(owner.clone()),
        };
    }
    None
}

/// True when a version's tags claim an owner (the object-id or app-id tag).
fn claims_an_owner(version: &SecretItem) -> bool {
    version
        .tags
        .as_ref()
        .is_some_and(|tags| tags.contains_key(TAG_OBJECT_ID) || tags.contains_key(TAG_APP_ID))
}

/// The app the vault secret's newest *claimed* version is tagged for, when
/// that is provably a different one (see [`owned_by_other_app`]). Only versions
/// that claim an owner count: one written outside this app (a portal "New
/// version", a script) carries no tags, so judging it would let it hide the
/// claim an older version still makes. The versions listing is unordered, so
/// the latest `created` among the claimed versions decides. Claimed versions it
/// can't order — created in the same second (a replayed write), or without a
/// creation time — are all weighed, and any one of them naming another app
/// refuses: the guard fails closed where the order can't tell them apart. A
/// secret no version of which claims an owner stays rotatable (`None`).
fn current_owner_if_other(
    versions: &[SecretItem],
    object_id: &str,
    app_id: Option<&str>,
) -> Option<String> {
    let created = |v: &SecretItem| v.attributes.as_ref().and_then(|a| a.created);
    let claimed: Vec<&SecretItem> = versions.iter().filter(|v| claims_an_owner(v)).collect();
    let newest = claimed.iter().filter_map(|v| created(v)).max();
    claimed
        .into_iter()
        .filter(|v| created(v).is_none_or(|c| Some(c) == newest))
        .find_map(|v| {
            v.tags
                .as_ref()
                .and_then(|tags| owned_by_other_app(tags, object_id, app_id))
        })
}

/// The refusal for an ownership read that failed with anything but "no such
/// secret": the owner is unknown, so nothing is minted. The vault's code and
/// retryability are kept, so a missing consent, a dead session, a rejected
/// token and a throttle still reach their lever, and a 403 carries the
/// capability catalog's Key Vault hint, which names the metadata permission
/// this read needs. The sentence is appended, so a 401's message still opens
/// with its status line, which `UiError::unauthorized_guidance` strips.
fn ownership_unknown(secret_name: &str, err: KeyVaultError) -> UiError {
    let mut e = UiError::from(err);
    e.message = format!(
        "{}\n\nCouldn't read the tags on vault secret '{secret_name}' to check which app owns \
         it, so nothing was minted.",
        e.message
    );
    e
}

/// Why a rotation stopped after its mint: the error to show, and whether the
/// minted client secret is still on the app (its removal failed, or the vault
/// may hold it), which the caller busts the credential tier for.
struct Unstored {
    err: UiError,
    left_on_app: bool,
}

/// Takes a minted client secret back off the app once the vault is known not
/// to hold it, and returns the error to show. When the removal fails too, the
/// secret stays live on the app for its whole lifetime with nobody holding its
/// value (the request that carried it was wiped), so the error names it for
/// the operator to delete, keeping the first failure's code.
async fn roll_back(
    graph: &GraphClient,
    object_id: &str,
    minted: &PasswordCredential,
    display_name: &str,
    mut err: UiError,
) -> Unstored {
    let Err(rollback) = graph.remove_password(object_id, &minted.key_id).await else {
        return Unstored {
            err,
            left_on_app: false,
        };
    };
    tracing::warn!(
        code = rollback.ui_code(),
        key_id = %minted.key_id,
        "rotation rollback failed; the minted client secret is still on the app",
    );
    err.message = format!(
        "{}\n\nThe new client secret '{display_name}' (key id {}) couldn't be removed again \
         ({rollback}). Nobody holds its value: refresh this app, then delete it from the \
         Credentials tab.",
        err.message, minted.key_id
    );
    // Re-running the rotation as it stands would mint another one beside it.
    err.retryable = false;
    Unstored {
        err,
        left_on_app: true,
    }
}

/// Whether any version of the vault secret carries `key_id` in its
/// [`TAG_KEY_ID`] tag: the read-back that tells a write that landed from one
/// that didn't. A secret that doesn't exist holds nothing.
async fn vault_holds_key(
    kv: &KeyVaultClient,
    secret_name: &str,
    key_id: &str,
) -> Result<bool, KeyVaultError> {
    match kv.list_secret_versions(secret_name).await {
        Ok(versions) => Ok(versions.iter().any(|v| {
            v.tags
                .as_ref()
                .and_then(|tags| tags.get(TAG_KEY_ID))
                .is_some_and(|tagged| tagged == key_id)
        })),
        Err(KeyVaultError::NotFound(_)) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Step 2 of a rotation: stores the freshly minted secret as a new version of
/// the vault secret, mirroring its expiry and stamping the provenance tags, and
/// returns the warnings to show beside the success.
///
/// `take()` (not clone) moves the value out of the Graph reply into the
/// Drop-zeroizing [`SecretSetRequest`], which is dropped as soon as the write
/// returns, so this code keeps no other copy of it; the request body and reply
/// buffers the transport builds are the accepted limit that type documents,
/// and the vault's echo of the value is never parsed out of its reply. This is
/// the one flow where the backend is the sole holder of the secret (the result
/// DTO carries no value).
///
/// A secret the vault didn't store comes back off the app ([`roll_back`]),
/// unless the vault may hold it after all. A write that sent nothing (a token
/// that couldn't be minted, a refused name) is rolled back at once. Any other
/// failure is ambiguous — a replayed `PUT` can fail after an earlier attempt
/// committed, and a 2xx whose body didn't arrive is a committed write — so the
/// vault is read back for a version tagged with the new key id first: found,
/// the rotation carries on with a warning; absent, it rolls back; unreadable,
/// the secret is kept and the error says so, rather than revoking one the
/// vault's consumers may already be reading.
async fn store_minted(
    graph: &GraphClient,
    kv: &KeyVaultClient,
    input: &RotateCredentialInput,
    new_cred: &mut PasswordCredential,
    display_name: &str,
) -> Result<Vec<String>, Unstored> {
    let Some(secret_value) = new_cred.secret_text.take() else {
        // addPassword always returns the value; clean up just in case.
        let err = UiError::validation(
            "no_secret_value",
            "Graph did not return the new secret value",
        );
        return Err(roll_back(graph, &input.object_id, new_cred, display_name, err).await);
    };
    let attrs =
        new_cred
            .end_date_time
            .map(|e| azapptoolkit_keyvault::models::SecretAttributesRequest {
                enabled: Some(true),
                expires: Some(e),
                not_before: None,
            });
    let req = SecretSetRequest {
        value: secret_value,
        content_type: None,
        // Provenance, not secrecy: which app + which credential generation this
        // version was minted for (see `TAG_*`).
        tags: Some(rotation_tags(
            input.app_id.as_deref(),
            &input.object_id,
            &new_cred.key_id,
        )),
        attributes: attrs,
    };
    let written = kv.set_secret(&input.secret_name, &req).await;
    // Nothing below needs the value: wipe it now, not after the read-back.
    drop(req);
    let Err(err) = written else {
        return Ok(Vec::new());
    };
    if err.sent_nothing() {
        return Err(roll_back(graph, &input.object_id, new_cred, display_name, err.into()).await);
    }
    match vault_holds_key(kv, &input.secret_name, &new_cred.key_id).await {
        Ok(true) => {
            tracing::warn!(
                code = err.ui_code(),
                secret = %input.secret_name,
                "rotation: the vault write reported an error, but the new version is stored",
            );
            Ok(vec![format!(
                "Key Vault reported an error storing the new version ({err}), but the vault \
                 holds it, so the rotation went ahead"
            )])
        }
        Ok(false) => {
            Err(roll_back(graph, &input.object_id, new_cred, display_name, err.into()).await)
        }
        Err(read_back) => {
            tracing::warn!(
                code = err.ui_code(),
                read_back = read_back.ui_code(),
                key_id = %new_cred.key_id,
                "rotation: couldn't tell whether the vault stored the new version; keeping it",
            );
            let mut e = UiError::from(err);
            e.message = format!(
                "{}\n\nCouldn't check whether the vault stored the new secret anyway \
                 ({read_back}), so client secret '{display_name}' (key id {}) was kept on the \
                 app rather than revoked while the vault may hold it. If no version of '{}' is \
                 tagged {TAG_KEY_ID} = {}, delete that client secret from this app's \
                 Credentials tab.",
                e.message, new_cred.key_id, input.secret_name, new_cred.key_id
            );
            // Re-running the rotation as it stands would mint another one.
            e.retryable = false;
            Err(Unstored {
                err: e,
                left_on_app: true,
            })
        }
    }
}

/// Rotates an application's client secret into Key Vault: check who owns the
/// vault secret, mint a fresh app secret, store it as a new version of the
/// named vault secret, then remove the previous credential(s) in
/// `remove_key_ids` (empty = keep them / overlap). If the Key Vault store
/// fails, the freshly-minted secret is rolled back unless the vault may hold it
/// (see [`store_minted`]), and any secret left on the app is named in the
/// error.
#[tauri::command]
pub async fn rotate_app_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    input: RotateCredentialInput,
) -> Result<RotateCredentialResult, UiError> {
    rotate_app_credential_core(&state, tenant_id, input).await
}

/// The handler body, taking `&AppState` so the fail-closed gate, the rollback
/// and the landed-write cache bust are reachable from a test (the
/// `add_password_core` seam).
pub(crate) async fn rotate_app_credential_core(
    state: &AppState,
    tenant_id: String,
    input: RotateCredentialInput,
) -> Result<RotateCredentialResult, UiError> {
    let graph = state.graph_for(&tenant_id);
    let kv = state.kv_for(&tenant_id, &input.vault_name)?;

    // 0. Provenance gate BEFORE minting, and fail closed: a secret version
    //    written by this app carries the ownership tags below, so a typed-in
    //    secret name that belongs to another app is refused without minting
    //    anything — judged on the newest version that claims an owner, so an
    //    untagged version written over it can't hide the claim. A secret no
    //    version of which claims an owner stays rotatable (legacy/manual
    //    write — the operator chose the name). The read lists the versions'
    //    tags, never a value: what may be another app's live secret has no
    //    business in this process. Only "no such secret" lets the rotation on
    //    without an owner check; any other failure leaves the owner unknown and
    //    refuses. Being the first vault call, it is also the vault token's
    //    pre-acquisition: a missing consent surfaces here, before anything is
    //    minted.
    match kv.list_secret_versions(&input.secret_name).await {
        Ok(versions) => {
            if let Some(owner) =
                current_owner_if_other(&versions, &input.object_id, input.app_id.as_deref())
            {
                return Err(UiError::validation(
                    "secret_owned_by_other_app",
                    format!(
                        "'{}' is tagged as owned by a different app ({owner}). Rotate it from \
                         that app, or pick another secret name — nothing was minted.",
                        input.secret_name
                    ),
                ));
            }
        }
        // No secret yet under that name: a fresh version carries no collision risk.
        Err(KeyVaultError::NotFound(_)) => {}
        Err(err) => return Err(ownership_unknown(&input.secret_name, err)),
    }

    let days = input
        .lifetime_days
        .unwrap_or(crate::dto::credentials::DEFAULT_SECRET_LIFETIME_DAYS)
        .clamp(1, crate::dto::credentials::MAX_SECRET_LIFETIME_DAYS);
    let lifetime = std::time::Duration::from_secs(u64::from(days) * 86_400);
    let display_name = format!("rotated-{}", chrono::Utc::now().format("%Y%m%d"));

    // 1. Mint the new app secret.
    let mut new_cred = graph
        .add_password(&input.object_id, &display_name, lifetime)
        .await?;

    // 2. Store it as a new Key Vault version (see `store_minted`).
    let mut warnings = match store_minted(&graph, &kv, &input, &mut new_cred, &display_name).await {
        Ok(warnings) => warnings,
        Err(unstored) => {
            // A minted secret still on the app (its removal failed, or the
            // vault may hold it) is a write that landed although the
            // rotation failed, so the credential tier hears about it before
            // the error surfaces: bust on the landed write, then return the
            // error, as `create_application_in_state` does. A clean rollback
            // changed nothing a cache holds.
            if unstored.left_on_app {
                invalidate_app_credentials(&state.cache, &tenant_id, &input.object_id);
            }
            return Err(unstored.err);
        }
    };

    // 3. Remove previous credentials (immediate strategy). The new secret is
    //    already live, so a removal failure is a warning, not a hard error.
    let mut removed = Vec::new();
    for key_id in &input.remove_key_ids {
        if key_id == &new_cred.key_id {
            continue;
        }
        match graph.remove_password(&input.object_id, key_id).await {
            Ok(()) => removed.push(key_id.clone()),
            Err(e) => warnings.push(format!("failed to remove {key_id}: {e}")),
        }
    }

    // Credentials really changed (a new secret was minted, old ones removed), so
    // bust the credential-tier caches (apps-pairing row, this app's detail, the
    // audit run) — exactly like the sibling add/remove-password commands. A
    // failed rotation busts only for a secret it left on the app (step 2). A
    // rotation can't add/remove/rename a service principal or app registration,
    // so the tiered path deliberately keeps the shared SP + name indexes (and
    // the search corpus) rather than forcing a full-tenant re-enumeration on the
    // next list visit.
    invalidate_app_credentials(&state.cache, &tenant_id, &input.object_id);

    // Remember where this app's secret went so the next rotation pre-selects the
    // same vault (per-tenant, keyed by appId). Best-effort — a settings-write
    // failure must not fail an otherwise-successful rotation. Stores names only,
    // never the secret.
    if let Some(app_id) = input.app_id.as_deref() {
        let config_dir = crate::config_directory();
        let binding = AppVaultBinding {
            vault_name: input.vault_name.clone(),
            secret_name: Some(input.secret_name.clone()),
        };
        // Serialized with every other settings.json writer (all go through
        // `UserSettings::mutate`): this binding is what the next rotation uses
        // to find the secret again, and it was the write most likely to be
        // lost — it lands while the operator may well be saving defaults. On
        // the blocking pool: the write waits on the cross-process settings
        // lock.
        let (tenant, app) = (tenant_id.clone(), app_id.to_owned());
        if let Err(e) = crate::state::mutate_settings_off_worker(
            config_dir,
            move |settings: &mut UserSettings| {
                settings.set_app_vault_binding(&tenant, &app, binding);
            },
        )
        .await
        {
            warnings.push(format!(
                "rotation succeeded, but couldn't remember the vault for next time: {e}"
            ));
        }
    }

    Ok(RotateCredentialResult {
        new_key_id: new_cred.key_id,
        vault_name: input.vault_name,
        secret_name: input.secret_name,
        expires: new_cred.end_date_time.map(|d| d.to_rfc3339()),
        removed_key_ids: removed,
        warnings,
    })
}

/// Lists the names of Key Vaults the signed-in user can see across all their
/// subscriptions (ARM control-plane discovery), for the rotation/browser vault
/// picker. A per-subscription failure is skipped (partial discovery is fine);
/// missing ARM consent surfaces as a typed error the frontend degrades to
/// free-text entry. Names only — no secret access here.
#[tauri::command]
pub async fn list_available_key_vaults(
    state: State<'_, AppState>,
    tenant_id: String,
) -> Result<Vec<String>, UiError> {
    state.ensure_arm_token(&tenant_id).await?;
    let arm = state.arm_for(&tenant_id);
    let subs = arm.list_subscriptions().await?;
    // Bounded fan-out: a serial loop paid one ARM round trip per subscription
    // back-to-back, which dominated the picker's load time in a large estate.
    // Partial discovery beats none — a subscription we can't read is skipped
    // (and logged), not fatal; a 403 is terminal in the ARM transport, so it
    // fails fast. De-duped + sorted for a stable dropdown.
    let names: std::collections::BTreeSet<String> = stream::iter(subs)
        .map(|sub| {
            let arm = arm.clone();
            async move {
                match arm.list_key_vaults(&sub.subscription_id).await {
                    Ok(vaults) => vaults,
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            subscription = %sub.subscription_id,
                            "vault picker: enumeration failed; skipping subscription",
                        );
                        Vec::new()
                    }
                }
            }
        })
        .buffer_unordered(ARM_CONCURRENCY)
        .collect::<Vec<Vec<_>>>()
        .await
        .into_iter()
        .flatten()
        .filter_map(|v| v.name)
        .collect();
    Ok(names.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn rotation_tags_always_name_the_app_and_generation() {
        let t = rotation_tags(Some("app-id-1"), "OBJ-1", "key-9");
        assert_eq!(t.get(TAG_OBJECT_ID).map(String::as_str), Some("obj-1"));
        assert_eq!(t.get(TAG_APP_ID).map(String::as_str), Some("app-id-1"));
        assert_eq!(t.get(TAG_KEY_ID).map(String::as_str), Some("key-9"));

        // A free-text rotation carries no appId: the object-id tag still
        // establishes ownership, and a blank app id is not written as a tag.
        let t = rotation_tags(Some("  "), "obj-2", "key-1");
        assert!(!t.contains_key(TAG_APP_ID));
        let t = rotation_tags(None, "obj-3", "key-1");
        assert!(!t.contains_key(TAG_APP_ID));
    }

    /// The collision guard must fire on a provably foreign secret and stay
    /// silent on tag-less / own-tagged / unrelated-tag sets — an absent tag is
    /// never asserted as "not another app's" in a way that blocks rotation,
    /// and never as "foreign" either.
    #[test]
    fn collision_guard_keys_on_the_ownership_tags_only() {
        const OBJ: &str = "aaaaaaaa-0000-0000-0000-000000000001";
        const OTHER: &str = "bbbbbbbb-0000-0000-0000-000000000002";

        // No tags, or only unrelated tags → not claimed by another app.
        assert_eq!(owned_by_other_app(&tags(&[]), OBJ, None), None);
        assert_eq!(
            owned_by_other_app(&tags(&[("owner", "someone-else")]), OBJ, None),
            None
        );
        // Our own secret → rotatable.
        assert_eq!(
            owned_by_other_app(&tags(&[(TAG_OBJECT_ID, OBJ)]), OBJ, None),
            None
        );
        assert_eq!(
            owned_by_other_app(&tags(&[(TAG_APP_ID, "app-1")]), OBJ, Some("APP-1")),
            None,
            "case-insensitive id comparison"
        );
        // Another app's secret → refused, whatever else is in the tags.
        assert_eq!(
            owned_by_other_app(&tags(&[(TAG_OBJECT_ID, OTHER)]), OBJ, None),
            Some(OTHER.to_string())
        );
        assert_eq!(
            owned_by_other_app(&tags(&[(TAG_APP_ID, "other-app")]), OBJ, Some("app-1")),
            Some("other-app".to_string())
        );
        // A rotation input with no appId cannot prove it is the owner: a
        // recorded owner wins (fail closed against clobbering).
        assert_eq!(
            owned_by_other_app(&tags(&[(TAG_APP_ID, "app-2")]), OBJ, None),
            Some("app-2".to_string())
        );
        // Object-id tag is decisive even when the app-id tag matches the input
        // (a mismatched pair means the provenance is not this app's).
        assert_eq!(
            owned_by_other_app(
                &tags(&[(TAG_OBJECT_ID, OTHER), (TAG_APP_ID, "app-1")]),
                OBJ,
                Some("app-1")
            ),
            Some(OTHER.to_string())
        );
    }

    const OBJ: &str = "aaaaaaaa-0000-0000-0000-000000000001";
    const OTHER: &str = "bbbbbbbb-0000-0000-0000-000000000002";

    /// One version entry as the listing returns it, created at Unix second
    /// `created`, tagged for `owner` — or, with `None`, carrying only an
    /// unrelated tag, like a version written outside this app.
    fn version(created: Option<i64>, owner: Option<&str>) -> SecretItem {
        let tags = match owner {
            Some(owner) => serde_json::json!({ TAG_OBJECT_ID: owner }),
            None => serde_json::json!({ "env": "prod" }),
        };
        serde_json::from_value(serde_json::json!({
            "id": "https://v.vault.azure.net/secrets/s/0123456789abcdef0123456789abcdef",
            "attributes": created.map(|c| serde_json::json!({ "created": c })),
            "tags": tags,
        }))
        .expect("a version entry")
    }

    /// The versions listing is unordered, so the guard reads ownership off the
    /// newest claimed version and weighs every claimed version it can't order
    /// against it, refusing if any of them is another app's.
    #[test]
    fn the_newest_claimed_version_decides_and_unordered_ones_fail_closed() {
        // Re-claimed by this app after another one: the newest claim decides.
        let reclaimed = [version(Some(1), Some(OTHER)), version(Some(2), Some(OBJ))];
        assert_eq!(current_owner_if_other(&reclaimed, OBJ, None), None);
        // Taken over by another app, whatever this app wrote before.
        let taken = [version(Some(1), Some(OBJ)), version(Some(2), Some(OTHER))];
        assert_eq!(
            current_owner_if_other(&taken, OBJ, None),
            Some(OTHER.to_string())
        );
        // Created in the same second: the order is unknown, so refuse.
        let tied = [version(Some(2), Some(OBJ)), version(Some(2), Some(OTHER))];
        assert_eq!(
            current_owner_if_other(&tied, OBJ, None),
            Some(OTHER.to_string())
        );
        // No creation time: it might be the newest claim, so it is weighed too.
        let undated = [version(Some(2), Some(OBJ)), version(None, Some(OTHER))];
        assert_eq!(
            current_owner_if_other(&undated, OBJ, None),
            Some(OTHER.to_string())
        );
        // No versions at all: nothing to collide with.
        assert_eq!(current_owner_if_other(&[], OBJ, None), None);
    }

    /// A version written outside the app (a portal "New version") carries no
    /// ownership tags. It claims nothing, so it can't hide an older claim, and
    /// a secret no version of which claims an owner stays rotatable.
    #[test]
    fn an_untagged_newer_version_cannot_hide_an_older_claim() {
        let over_another_app = [version(Some(1), Some(OTHER)), version(Some(2), None)];
        assert_eq!(
            current_owner_if_other(&over_another_app, OBJ, None),
            Some(OTHER.to_string()),
            "the history names another app"
        );
        let over_this_app = [version(Some(1), Some(OBJ)), version(Some(2), None)];
        assert_eq!(current_owner_if_other(&over_this_app, OBJ, None), None);
        let never_claimed = [version(Some(1), None), version(Some(2), None)];
        assert_eq!(
            current_owner_if_other(&never_claimed, OBJ, None),
            None,
            "an unclaimed secret stays rotatable"
        );
        // An undated untagged version is not weighed either: it claims nothing.
        let undated_untagged = [version(Some(1), Some(OBJ)), version(None, None)];
        assert_eq!(current_owner_if_other(&undated_untagged, OBJ, None), None);
    }
}

/// `rotate_app_credential` end to end over one mock server: Graph under
/// `{mock}/v1.0`, the vault at `{mock}` itself.
#[cfg(test)]
mod handler_tests {
    use super::*;

    use std::sync::Arc;

    use azapptoolkit_core::token::{BearerProvider, StaticTokenProvider};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::commands::test_support::{
        dead_token, detail_cached, dies_after, indexes_intact, mock_state, seed_indexes_and_detail,
    };

    const TENANT: &str = "t1";
    const OBJECT: &str = "obj-1";
    const VAULT: &str = "my-vault";
    const SECRET: &str = "app-secret";
    const NEW_KEY: &str = "11111111-2222-3333-4444-555555555555";

    /// A mock server plus an `AppState` whose Graph client and whose Key Vault
    /// client for [`VAULT`] (bearer from `kv_token`) both answer from it,
    /// seeded with the app's detail row and the two indexes a rotation keeps.
    async fn rotation_state(kv_token: Arc<dyn BearerProvider>) -> (MockServer, AppState) {
        let (server, state) = mock_state(TENANT).await;
        state.kv_clients.lock().insert(
            (TENANT.to_string(), VAULT.to_string()),
            Arc::new(KeyVaultClient::with_base_url(kv_token, server.uri())),
        );
        seed_indexes_and_detail(&state, TENANT, OBJECT);
        (server, state)
    }

    fn static_token() -> Arc<dyn BearerProvider> {
        StaticTokenProvider::new("tok")
    }

    /// `app_id: None` keeps the run off `settings.json` (the vault binding is
    /// written only for an app id), which lives in the real config directory.
    fn input() -> RotateCredentialInput {
        RotateCredentialInput {
            object_id: OBJECT.to_string(),
            app_id: None,
            vault_name: VAULT.to_string(),
            secret_name: SECRET.to_string(),
            lifetime_days: Some(30),
            remove_key_ids: Vec::new(),
        }
    }

    async fn rotate(state: &AppState) -> Result<RotateCredentialResult, UiError> {
        rotate_app_credential_core(state, TENANT.to_string(), input()).await
    }

    fn versions_path() -> String {
        format!("/secrets/{SECRET}/versions")
    }

    fn mint_path() -> String {
        format!("/v1.0/applications/{OBJECT}/addPassword")
    }

    fn rollback_path() -> String {
        format!("/v1.0/applications/{OBJECT}/removePassword")
    }

    /// A one-version listing whose version carries `tags`.
    fn listing(tags: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": [{
                "id": format!("https://v.vault.azure.net/secrets/{SECRET}/v1"),
                "attributes": { "enabled": true, "created": 1_700_000_000 },
                "tags": tags,
            }]
        }))
    }

    /// Every ownership read and read-back answers `response`.
    async fn mount_versions(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("GET"))
            .and(path(versions_path()))
            .respond_with(response)
            .mount(server)
            .await;
    }

    /// The ownership read answers `gate`; every read after it (the read-back)
    /// answers `read_back`.
    async fn mount_versions_then(
        server: &MockServer,
        gate: ResponseTemplate,
        read_back: ResponseTemplate,
    ) {
        Mock::given(method("GET"))
            .and(path(versions_path()))
            .respond_with(gate)
            .up_to_n_times(1)
            .mount(server)
            .await;
        mount_versions(server, read_back).await;
    }

    async fn mount_mint(server: &MockServer, secret_text: Option<&str>) {
        let mut reply = serde_json::json!({
            "keyId": NEW_KEY,
            "displayName": "rotated",
            "endDateTime": "2999-01-01T00:00:00Z",
        });
        if let Some(text) = secret_text {
            reply["secretText"] = serde_json::Value::String(text.to_string());
        }
        Mock::given(method("POST"))
            .and(path(mint_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(reply))
            .mount(server)
            .await;
    }

    async fn mount_store(server: &MockServer, response: ResponseTemplate) {
        Mock::given(method("PUT"))
            .and(path(format!("/secrets/{SECRET}")))
            .respond_with(response)
            .mount(server)
            .await;
    }

    async fn mount_rollback(server: &MockServer, status: u16) {
        Mock::given(method("POST"))
            .and(path(rollback_path()))
            .and(body_partial_json(serde_json::json!({ "keyId": NEW_KEY })))
            .respond_with(ResponseTemplate::new(status))
            .mount(server)
            .await;
    }

    /// How many requests the server saw with this method and path.
    async fn hits(server: &MockServer, verb: &str, at: &str) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|r| r.method.as_str() == verb && r.url.path() == at)
            .count()
    }

    /// A 5xx that outlives the retry budget, without the backoff.
    fn unavailable() -> ResponseTemplate {
        ResponseTemplate::new(503).insert_header("Retry-After", "0")
    }

    /// W12: an ownership read that fails with anything but "no such secret"
    /// refuses before `addPassword` is called. A 403 (no permission to read
    /// secret metadata) keeps its code and carries the catalog's Key Vault
    /// hint, which names that permission; a 5xx that outlived its retries
    /// keeps its retryability; a 401's message still opens with its status
    /// line, so the Refresh-token toast shows only the guidance after it.
    #[tokio::test]
    async fn an_unreadable_owner_refuses_before_anything_is_minted() {
        let forbidden = ResponseTemplate::new(403).set_body_string("Caller is not authorized");
        for (reply, code, retryable) in [
            (forbidden, "forbidden", false),
            (unavailable(), "server_error", true),
            (ResponseTemplate::new(401), "unauthorized", false),
        ] {
            let (server, state) = rotation_state(static_token()).await;
            mount_versions(&server, reply).await;
            mount_mint(&server, Some("s3cret-value")).await;

            let err = rotate(&state)
                .await
                .expect_err("an owner that can't be read refuses the rotation");
            assert_eq!(err.code, code);
            assert_eq!(err.retryable, retryable, "{code}: retryability is kept");
            assert!(
                err.message.contains("nothing was minted"),
                "{code}: {}",
                err.message
            );
            assert_eq!(
                hits(&server, "POST", &mint_path()).await,
                0,
                "{code}: a secret was minted although its owner is unknown"
            );
            assert!(
                detail_cached(&state, TENANT, OBJECT),
                "nothing changed, so nothing is busted"
            );
            if code == "forbidden" {
                let hint = azapptoolkit_core::capabilities::capability("keyvault_secrets")
                    .expect("the Key Vault catalog entry")
                    .remediation;
                assert!(err.message.contains(hint), "{}", err.message);
                assert!(hint.contains("readMetadata"), "{hint}");
            }
            if code == "unauthorized" {
                let guidance = err
                    .unauthorized_guidance()
                    .expect("a rejected vault token keeps its guidance");
                assert!(
                    !guidance.contains(azapptoolkit_core::reauth::UNAUTHORIZED_STATUS),
                    "the status line leaked into the toast text: {guidance}"
                );
                assert!(guidance.contains("Refresh token"), "{guidance}");
                assert!(guidance.contains("nothing was minted"), "{guidance}");
            }
        }
    }

    /// The ownership read is the vault token's first use, so a dead session
    /// (or a missing consent) surfaces there, with its code, before the mint.
    #[tokio::test]
    async fn a_vault_token_failure_refuses_before_anything_is_minted() {
        let (server, state) = rotation_state(dead_token()).await;
        mount_mint(&server, Some("s3cret-value")).await;

        let err = rotate(&state).await.expect_err("a dead session refuses");
        assert_eq!(err.code, "refresh_missing");
        assert!(err.is_reauth_fatal());
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "neither the vault nor Graph was called"
        );
    }

    /// A name Key Vault would refuse fails the ownership read, before any
    /// request; it used to mint, fail the same check on the write, and roll
    /// back.
    #[tokio::test]
    async fn an_invalid_secret_name_refuses_before_any_request() {
        let (server, state) = rotation_state(static_token()).await;
        let mut typo = input();
        typo.secret_name = "has_underscore".to_string();

        let err = rotate_app_credential_core(&state, TENANT.to_string(), typo)
            .await
            .expect_err("an invalid name refuses");
        assert_eq!(err.code, "invalid_name");
        assert!(err.message.contains("nothing was minted"));
        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_secret_tagged_for_another_app_is_refused_before_anything_is_minted() {
        let (server, state) = rotation_state(static_token()).await;
        mount_versions(
            &server,
            listing(serde_json::json!({ TAG_OBJECT_ID: "obj-2" })),
        )
        .await;
        mount_mint(&server, Some("s3cret-value")).await;

        let err = rotate(&state).await.expect_err("another app's secret");
        assert_eq!(err.code, "secret_owned_by_other_app");
        assert_eq!(hits(&server, "POST", &mint_path()).await, 0);
    }

    /// W10: the rotation reads the vault's tags and never a value — no `GET` of
    /// the secret itself — and writes the new value with its provenance tags.
    /// Only the credential tier is busted.
    #[tokio::test]
    async fn a_rotation_reads_only_tags_and_busts_the_credential_tier() {
        let (server, state) = rotation_state(static_token()).await;
        mount_versions(
            &server,
            listing(serde_json::json!({ TAG_OBJECT_ID: OBJECT })),
        )
        .await;
        mount_mint(&server, Some("s3cret-value")).await;
        Mock::given(method("PUT"))
            .and(path(format!("/secrets/{SECRET}")))
            .and(body_partial_json(serde_json::json!({
                "value": "s3cret-value",
                "tags": { TAG_OBJECT_ID: OBJECT, TAG_KEY_ID: NEW_KEY },
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "value": "s3cret-value",
                "id": format!("https://v.vault.azure.net/secrets/{SECRET}/v2"),
            })))
            .mount(&server)
            .await;

        let out = rotate(&state).await.expect("the rotation succeeds");
        assert_eq!(out.new_key_id, NEW_KEY);
        assert!(out.warnings.is_empty(), "{:?}", out.warnings);
        assert_eq!(
            hits(&server, "GET", &format!("/secrets/{SECRET}")).await,
            0,
            "a secret value was read"
        );
        assert_eq!(hits(&server, "GET", &versions_path()).await, 1);
        assert_eq!(hits(&server, "POST", &rollback_path()).await, 0);
        assert!(
            !detail_cached(&state, TENANT, OBJECT),
            "the credentials changed"
        );
        assert!(
            indexes_intact(&state, TENANT),
            "a rotation keeps both tenant-wide indexes"
        );
    }

    /// W14: a write the vault refused is read back, found absent, and the
    /// minted secret rolled back; a clean rollback changed nothing to bust.
    #[tokio::test]
    async fn a_refused_store_is_read_back_and_rolled_back() {
        let (server, state) = rotation_state(static_token()).await;
        mount_versions(&server, ResponseTemplate::new(404)).await;
        mount_mint(&server, Some("s3cret-value")).await;
        mount_store(&server, ResponseTemplate::new(403)).await;
        mount_rollback(&server, 204).await;

        let err = rotate(&state).await.expect_err("the store failed");
        assert_eq!(err.code, "forbidden");
        assert!(!err.message.contains(NEW_KEY), "{}", err.message);
        assert_eq!(
            hits(&server, "GET", &versions_path()).await,
            2,
            "the ownership read and the read-back"
        );
        assert_eq!(hits(&server, "POST", &rollback_path()).await, 1);
        assert!(detail_cached(&state, TENANT, OBJECT));
    }

    /// W15: a rollback that fails too leaves a live secret nobody holds. The
    /// error keeps the vault's code and names the leftover's key id, and the
    /// credential tier is busted for it.
    #[tokio::test]
    async fn a_failed_rollback_names_the_leftover_and_busts_the_credential_tier() {
        let (server, state) = rotation_state(static_token()).await;
        mount_versions(&server, ResponseTemplate::new(404)).await;
        mount_mint(&server, Some("s3cret-value")).await;
        mount_store(&server, ResponseTemplate::new(403)).await;
        mount_rollback(&server, 503).await;

        let err = rotate(&state).await.expect_err("the store failed");
        assert_eq!(err.code, "forbidden", "the vault's code is kept");
        assert!(err.message.contains(NEW_KEY), "{}", err.message);
        assert!(
            err.message.contains("couldn't be removed"),
            "{}",
            err.message
        );
        assert!(!err.retryable, "a blind re-run mints a second secret");
        assert!(
            !detail_cached(&state, TENANT, OBJECT),
            "the leftover secret is a landed write"
        );
        assert!(indexes_intact(&state, TENANT));
    }

    /// W15, the other rollback: a mint whose reply carried no value is taken
    /// back off the app, and a removal that fails is named the same way.
    #[tokio::test]
    async fn a_mint_without_a_value_names_a_leftover_it_could_not_remove() {
        let (server, state) = rotation_state(static_token()).await;
        mount_versions(&server, ResponseTemplate::new(404)).await;
        mount_mint(&server, None).await;
        mount_rollback(&server, 503).await;

        let err = rotate(&state).await.expect_err("no value to store");
        assert_eq!(err.code, "no_secret_value");
        assert!(err.message.contains(NEW_KEY), "{}", err.message);
        assert_eq!(hits(&server, "PUT", &format!("/secrets/{SECRET}")).await, 0);
        assert!(!detail_cached(&state, TENANT, OBJECT));
        assert!(indexes_intact(&state, TENANT));
    }

    /// W14: a write that failed after its replays, or whose reply never
    /// parsed, may have committed. The read-back finds the version tagged with
    /// the new key id, so the secret the vault serves is kept and the rotation
    /// completes with a warning.
    #[tokio::test]
    async fn a_store_that_landed_despite_its_error_completes_with_a_warning() {
        let unparseable = ResponseTemplate::new(200).set_body_string("<html>gateway</html>");
        for reply in [unavailable(), unparseable] {
            let (server, state) = rotation_state(static_token()).await;
            mount_versions_then(
                &server,
                ResponseTemplate::new(404),
                listing(serde_json::json!({ TAG_KEY_ID: NEW_KEY })),
            )
            .await;
            mount_mint(&server, Some("s3cret-value")).await;
            mount_store(&server, reply).await;
            mount_rollback(&server, 204).await;

            let out = rotate(&state)
                .await
                .expect("the vault holds the new version");
            assert_eq!(out.new_key_id, NEW_KEY);
            assert_eq!(out.warnings.len(), 1, "{:?}", out.warnings);
            assert!(out.warnings[0].contains("holds it"), "{:?}", out.warnings);
            assert_eq!(
                hits(&server, "POST", &rollback_path()).await,
                0,
                "a secret the vault holds was revoked"
            );
            assert!(!detail_cached(&state, TENANT, OBJECT));
            assert!(indexes_intact(&state, TENANT));
        }
    }

    /// W14: when the read-back fails too, nobody can tell whether the vault
    /// serves the new secret, so it is kept, the error says so and names it,
    /// and the credential tier is busted for it.
    #[tokio::test]
    async fn an_unconfirmable_store_keeps_the_secret_and_says_so() {
        let (server, state) = rotation_state(static_token()).await;
        mount_versions_then(
            &server,
            ResponseTemplate::new(404),
            ResponseTemplate::new(403),
        )
        .await;
        mount_mint(&server, Some("s3cret-value")).await;
        mount_store(&server, unavailable()).await;
        mount_rollback(&server, 204).await;

        let err = rotate(&state).await.expect_err("the outcome is unknown");
        assert_eq!(err.code, "server_error", "the write's own code");
        assert!(!err.retryable);
        assert!(err.message.contains(NEW_KEY), "{}", err.message);
        assert!(err.message.contains("was kept"), "{}", err.message);
        assert_eq!(
            hits(&server, "POST", &rollback_path()).await,
            0,
            "a secret the vault may serve was revoked"
        );
        assert!(!detail_cached(&state, TENANT, OBJECT));
        assert!(indexes_intact(&state, TENANT));
    }

    /// W14: a write whose vault token couldn't be minted sent nothing, so
    /// there is nothing to read back and the secret is rolled back at once.
    #[tokio::test]
    async fn a_store_that_sent_nothing_rolls_back_without_a_read_back() {
        // One bearer, spent by the ownership read.
        let (server, state) = rotation_state(dies_after(1)).await;
        mount_versions(&server, ResponseTemplate::new(404)).await;
        mount_mint(&server, Some("s3cret-value")).await;
        mount_rollback(&server, 204).await;

        let err = rotate(&state).await.expect_err("the vault token died");
        assert_eq!(err.code, "refresh_missing");
        assert_eq!(hits(&server, "PUT", &format!("/secrets/{SECRET}")).await, 0);
        assert_eq!(
            hits(&server, "GET", &versions_path()).await,
            1,
            "no read-back"
        );
        assert_eq!(hits(&server, "POST", &rollback_path()).await, 1);
        assert!(detail_cached(&state, TENANT, OBJECT));
    }
}
