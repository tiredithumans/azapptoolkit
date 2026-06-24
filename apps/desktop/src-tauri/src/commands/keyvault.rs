//! Key Vault secret operations.
//!
//! Clients are built and cached by [`AppState::kv_for`], which wires the
//! shared token adapter for the `https://vault.azure.net` audience.

use tauri::State;

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

    // 1. Mint the new app secret.
    let new_cred = graph
        .add_password(&input.object_id, &display_name, lifetime)
        .await?;
    let Some(secret_value) = new_cred.secret_text.clone() else {
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

    Ok(RotateCredentialResult {
        new_key_id: new_cred.key_id,
        vault_name: input.vault_name,
        secret_name: input.secret_name,
        expires: new_cred.end_date_time.map(|d| d.to_rfc3339()),
        removed_key_ids: removed,
        warnings,
    })
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
