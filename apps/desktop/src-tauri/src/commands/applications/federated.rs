use tauri::State;

use azapptoolkit_core::models::FederatedIdentityCredential;
use azapptoolkit_graph::client::{FederatedCredentialPatch, FederatedCredentialRequest};

use crate::dto::applications::{
    AddFederatedCredentialInput, FederatedCredentialDto, UpdateFederatedCredentialInput,
};
use crate::dto::UiError;
use crate::state::AppState;

/// Maps a Graph [`FederatedIdentityCredential`] to its IPC DTO. Shared by the
/// list and add commands so the six-field projection lives in one place.
fn fic_dto(c: FederatedIdentityCredential) -> FederatedCredentialDto {
    FederatedCredentialDto {
        id: c.id,
        name: c.name,
        issuer: c.issuer,
        subject: c.subject,
        description: c.description,
        audiences: c.audiences,
    }
}

/// Lists an application's federated identity credentials (workload identity
/// federation — GitHub Actions, Kubernetes, …).
#[tauri::command]
pub async fn list_federated_credentials(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
) -> Result<Vec<FederatedCredentialDto>, UiError> {
    let client = state.graph_for(&tenant_id);
    let creds = client.list_federated_credentials(&object_id).await?;
    Ok(creds.into_iter().map(fic_dto).collect())
}

/// The audience Entra recommends (and the portal defaults to) for workload
/// identity federation token exchange.
const DEFAULT_FIC_AUDIENCE: &str = "api://AzureADTokenExchange";

/// Resolves a caller-supplied audience override to the list sent to Graph:
/// absent or empty falls back to [`DEFAULT_FIC_AUDIENCE`] (only the portal's
/// "Other issuer" flow sends an override).
fn resolve_fic_audiences(audiences: Option<Vec<String>>) -> Vec<String> {
    audiences
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| vec![DEFAULT_FIC_AUDIENCE.to_string()])
}

/// Creates a federated identity credential. The audience defaults to
/// `api://AzureADTokenExchange` (the value Entra recommends for token
/// exchange) unless the caller supplies an override.
#[tauri::command]
pub async fn add_federated_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: AddFederatedCredentialInput,
) -> Result<FederatedCredentialDto, UiError> {
    let client = state.graph_for(&tenant_id);
    let body = FederatedCredentialRequest {
        name: input.name,
        issuer: input.issuer,
        subject: input.subject,
        audiences: resolve_fic_audiences(input.audiences),
        description: input.description,
    };
    let c = client.add_federated_credential(&object_id, &body).await?;
    Ok(fic_dto(c))
}

/// Updates a federated identity credential in place (issuer / subject /
/// description / audiences — `name` is immutable in Graph). No cache
/// invalidation: FICs aren't part of any cached list or detail payload; the
/// tab refetches live.
#[tauri::command]
pub async fn update_federated_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    credential_id: String,
    input: UpdateFederatedCredentialInput,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    let body = FederatedCredentialPatch {
        issuer: input.issuer,
        subject: input.subject,
        audiences: resolve_fic_audiences(input.audiences),
        description: input.description,
    };
    client
        .update_federated_credential(&object_id, &credential_id, &body)
        .await?;
    Ok(())
}

/// Removes a federated identity credential.
#[tauri::command]
pub async fn remove_federated_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    credential_id: String,
) -> Result<(), UiError> {
    let client = state.graph_for(&tenant_id);
    client
        .remove_federated_credential(&object_id, &credential_id)
        .await?;
    Ok(())
}

#[cfg(test)]
mod fic_audience_tests {
    use super::{resolve_fic_audiences, DEFAULT_FIC_AUDIENCE};

    #[test]
    fn absent_or_empty_falls_back_to_default() {
        assert_eq!(resolve_fic_audiences(None), vec![DEFAULT_FIC_AUDIENCE]);
        assert_eq!(
            resolve_fic_audiences(Some(vec![])),
            vec![DEFAULT_FIC_AUDIENCE]
        );
    }

    #[test]
    fn override_is_passed_through() {
        assert_eq!(
            resolve_fic_audiences(Some(vec!["api://custom".into()])),
            vec!["api://custom"]
        );
    }
}
