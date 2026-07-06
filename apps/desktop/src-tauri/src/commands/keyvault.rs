//! Key Vault secret operations.
//!
//! Clients are built and cached by [`AppState::kv_for`], which wires the
//! shared token adapter for the `https://vault.azure.net` audience.

use tauri::State;

use azapptoolkit_core::defaults::AppVaultBinding;
use azapptoolkit_core::settings::UserSettings;
use azapptoolkit_keyvault::SecretSetRequest;

use crate::commands::applications::invalidate_app_credentials;
use crate::dto::UiError;
use crate::dto::keyvault::{
    KvSecretItemDto, KvSecretMetadataDto, KvSecretValueDto, KvSetSecretInput,
    RotateCredentialInput, RotateCredentialResult,
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

#[tauri::command]
pub async fn kv_set_secret(
    state: State<'_, AppState>,
    tenant_id: String,
    input: KvSetSecretInput,
) -> Result<KvSecretMetadataDto, UiError> {
    let client = state.kv_for(&tenant_id, &input.vault_name)?;
    let expires = parse_rfc3339(input.expires.as_deref())?;
    let attrs = expires.map(|e| azapptoolkit_keyvault::models::SecretAttributesRequest {
        enabled: Some(true),
        expires: Some(e),
        not_before: None,
    });
    let req = SecretSetRequest {
        value: input.value,
        content_type: input.content_type,
        tags: None,
        attributes: attrs,
    };
    let sv = client.set_secret(&input.secret_name, &req).await?;
    Ok(KvSecretMetadataDto {
        name: input.secret_name,
        content_type: sv.content_type,
        expires: sv
            .attributes
            .and_then(|a| a.expires)
            .map(|d| d.to_rfc3339()),
    })
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

    let days = input.lifetime_days.unwrap_or(180).clamp(1, 730);
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
        tags: None,
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
        let mut settings = UserSettings::stored(&config_dir);
        settings.set_app_vault_binding(
            &tenant_id,
            app_id,
            AppVaultBinding {
                vault_name: input.vault_name.clone(),
                secret_name: Some(input.secret_name.clone()),
            },
        );
        if let Err(e) = settings.save(&config_dir) {
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
    // De-duped + sorted for a stable dropdown.
    let mut names = std::collections::BTreeSet::new();
    for sub in subs {
        // Partial discovery beats none: skip a subscription we can't read.
        if let Ok(vaults) = arm.list_key_vaults(&sub.subscription_id).await {
            for v in vaults {
                if let Some(name) = v.name {
                    names.insert(name);
                }
            }
        }
    }
    Ok(names.into_iter().collect())
}

fn parse_rfc3339(s: Option<&str>) -> Result<Option<chrono::DateTime<chrono::Utc>>, UiError> {
    match s {
        None => Ok(None),
        Some(v) => chrono::DateTime::parse_from_rfc3339(v)
            .map(|d| Some(d.with_timezone(&chrono::Utc)))
            .map_err(|e| {
                UiError::validation("invalid_timestamp", format!("expires must be RFC3339: {e}"))
            }),
    }
}
