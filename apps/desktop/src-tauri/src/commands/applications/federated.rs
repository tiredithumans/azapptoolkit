use tauri::State;

use azapptoolkit_core::cloud::CloudEnvironment;
use azapptoolkit_core::federation::validate_federated_credential;
use azapptoolkit_core::models::FederatedIdentityCredential;
use azapptoolkit_graph::client::{FederatedCredentialPatch, FederatedCredentialRequest};

use crate::dto::UiError;
use crate::dto::applications::{
    AddFederatedCredentialInput, FederatedCredentialDto, UpdateFederatedCredentialInput,
};
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

/// Resolves a caller-supplied audience override to the list sent to Graph:
/// absent or empty falls back to the audience Entra recommends for token
/// exchange **in this build's cloud** (only the portal's "Other issuer" flow
/// sends an override).
fn resolve_fic_audiences(audiences: Option<Vec<String>>, cloud: CloudEnvironment) -> Vec<String> {
    audiences
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| vec![cloud.token_exchange_audience().to_string()])
}

/// Rejects a federated identity credential before it is written.
///
/// A federated identity credential is a trust that needs no secret, and Graph
/// does not validate it: Microsoft documents that a wrong issuer or subject "is
/// created successfully without error" and only fails later, silently, at token
/// exchange. So the check has to happen here — on **every** path, which is why
/// it lives in `core::federation` rather than in one command.
fn check_federated_credential(
    name: Option<&str>,
    issuer: &str,
    subject: &str,
    audiences: &[String],
    description: Option<&str>,
) -> Result<(), UiError> {
    validate_federated_credential(name, issuer, subject, audiences, description)
        .map_err(|msg| UiError::validation("invalid_federated_credential", msg))
}

/// Creates a federated identity credential. The audience defaults to the value
/// Entra recommends for token exchange in this build's cloud unless the caller
/// supplies an override.
#[tauri::command]
pub async fn add_federated_credential(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    input: AddFederatedCredentialInput,
) -> Result<FederatedCredentialDto, UiError> {
    let audiences = resolve_fic_audiences(input.audiences, state.auth.cloud());
    check_federated_credential(
        Some(&input.name),
        &input.issuer,
        &input.subject,
        &audiences,
        input.description.as_deref(),
    )?;
    let client = state.graph_for(&tenant_id);
    let body = FederatedCredentialRequest {
        name: input.name,
        issuer: input.issuer,
        subject: input.subject,
        audiences,
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
    let audiences = resolve_fic_audiences(input.audiences, state.auth.cloud());
    // `None`: Graph makes the name immutable, so an update never sends one.
    check_federated_credential(
        None,
        &input.issuer,
        &input.subject,
        &audiences,
        input.description.as_deref(),
    )?;
    let client = state.graph_for(&tenant_id);
    let body = FederatedCredentialPatch {
        issuer: input.issuer,
        subject: input.subject,
        audiences,
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
    use super::{CloudEnvironment, check_federated_credential, resolve_fic_audiences};

    #[test]
    fn absent_or_empty_falls_back_to_the_clouds_own_audience() {
        let c = CloudEnvironment::Commercial;
        assert_eq!(
            resolve_fic_audiences(None, c),
            vec!["api://AzureADTokenExchange"]
        );
        assert_eq!(
            resolve_fic_audiences(Some(vec![]), c),
            vec!["api://AzureADTokenExchange"]
        );
    }

    #[test]
    fn a_sovereign_build_defaults_to_its_own_audience() {
        // The commercial value in a US Gov or China tenant creates a credential
        // Graph accepts and that then fails, silently, at token exchange.
        assert_eq!(
            resolve_fic_audiences(None, CloudEnvironment::UsGov),
            vec!["api://AzureADTokenExchangeUSGov"]
        );
        assert_eq!(
            resolve_fic_audiences(None, CloudEnvironment::UsGovDod),
            vec!["api://AzureADTokenExchangeUSGov"]
        );
        assert_eq!(
            resolve_fic_audiences(None, CloudEnvironment::China),
            vec!["api://AzureADTokenExchangeChina"]
        );
    }

    #[test]
    fn override_is_passed_through() {
        assert_eq!(
            resolve_fic_audiences(
                Some(vec!["api://custom".into()]),
                CloudEnvironment::Commercial
            ),
            vec!["api://custom"]
        );
    }

    #[test]
    fn a_rejected_credential_carries_the_typed_ui_code() {
        let audiences = vec!["api://AzureADTokenExchange".to_string()];
        let err = check_federated_credential(
            Some("ok-name"),
            "http://issuer.example",
            "sub",
            &audiences,
            None,
        )
        .unwrap_err();
        assert_eq!(err.code, "invalid_federated_credential");
        assert!(
            check_federated_credential(
                Some("ok-name"),
                "https://issuer.example",
                "sub",
                &audiences,
                None,
            )
            .is_ok()
        );
    }
}
