//! Key Vault secret operations.
//!
//! Clients are built and cached by [`AppState::kv_for`], which wires the
//! shared token adapter for the `https://vault.azure.net` audience.

use futures::stream::{self, StreamExt};
use tauri::State;

use azapptoolkit_core::defaults::AppVaultBinding;
use azapptoolkit_core::settings::UserSettings;
use azapptoolkit_keyvault::{KeyVaultError, SecretSetRequest};

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

/// Rotates an application's client secret into Key Vault: mint a fresh app
/// secret, store it as a new version of the named vault secret, then remove the
/// previous credential(s) in `remove_key_ids` (empty = keep them / overlap).
/// If the Key Vault store fails the freshly-minted secret is rolled back so no
/// unstored credential is left behind.
#[tauri::command]
pub async fn rotate_app_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    input: RotateCredentialInput,
) -> Result<RotateCredentialResult, UiError> {
    let graph = state.graph_for(&tenant_id);
    let kv = state.kv_for(&tenant_id, &input.vault_name)?;

    // 0. Provenance gate BEFORE minting: a secret version written by this app
    //    carries the ownership tags below, so a typed-in secret name that
    //    belongs to another app is refused without minting anything. A tag-less
    //    secret stays rotatable (legacy/manual write — the operator chose the
    //    name); a failed ownership read is logged and skipped so a transient
    //    vault error can't lock a legitimate rotation.
    match kv.get_secret(&input.secret_name, None).await {
        Ok(sv) => {
            if let Some(owner) = sv.tags.as_ref().and_then(|tags| {
                owned_by_other_app(tags, &input.object_id, input.app_id.as_deref())
            }) {
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
        Err(err) => {
            tracing::warn!(
                ?err,
                secret = %input.secret_name,
                "rotation ownership read failed; continuing without the collision check",
            );
        }
    }

    let days = input
        .lifetime_days
        .unwrap_or(crate::dto::credentials::DEFAULT_SECRET_LIFETIME_DAYS)
        .clamp(1, crate::dto::credentials::MAX_SECRET_LIFETIME_DAYS);
    let lifetime = std::time::Duration::from_secs(u64::from(days) * 86_400);
    let display_name = format!("rotated-{}", chrono::Utc::now().format("%Y%m%d"));

    // 1. Mint the new app secret. `take()` (not clone) the value so exactly one
    //    copy exists, and it ends its life inside the Drop-zeroizing
    //    SecretSetRequest below — this is the one flow where the backend is the
    //    sole holder of the secret (the result DTO carries no value).
    let mut new_cred = graph
        .add_password(&input.object_id, &display_name, lifetime)
        .await?;
    let Some(secret_value) = new_cred.secret_text.take() else {
        // addPassword always returns the value; clean up just in case.
        let _ = graph
            .remove_password(&input.object_id, &new_cred.key_id)
            .await;
        return Err(UiError::validation(
            "no_secret_value",
            "Graph did not return the new secret value",
        ));
    };

    // 2. Store it as a new Key Vault version, mirroring the secret's expiry.
    //    Roll back the minted secret on failure.
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
    if let Err(err) = kv.set_secret(&input.secret_name, &req).await {
        let _ = graph
            .remove_password(&input.object_id, &new_cred.key_id)
            .await;
        return Err(err.into());
    }

    // 3. Remove previous credentials (immediate strategy). The new secret is
    //    already live, so a removal failure is a warning, not a hard error.
    let mut removed = Vec::new();
    let mut warnings = Vec::new();
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
    // audit run) — exactly like the sibling add/remove-password commands, and
    // only on this success path. A rotation can't add/remove/rename a service
    // principal or app registration, so the tiered path deliberately keeps the
    // shared SP + name indexes (and the search corpus) rather than forcing a
    // full-tenant re-enumeration on the next list visit.
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
        // lost — it lands while the operator may well be saving defaults on
        // the main thread.
        if let Err(e) = UserSettings::mutate(&config_dir, |settings| {
            settings.set_app_vault_binding(&tenant_id, app_id, binding);
        }) {
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
}
