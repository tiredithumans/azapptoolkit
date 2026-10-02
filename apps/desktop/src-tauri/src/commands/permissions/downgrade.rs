use tauri::State;

use crate::commands::applications::invalidate_app_detail_state;
use crate::dto::UiError;
use crate::dto::permissions::DowngradeOutcome;
use crate::state::AppState;

use super::manifest::swap_declared_role;

/// Replaces a broad application permission with a documented narrower
/// alternative (the least-privilege "Downgrade…" action; pairs come from
/// `azapptoolkit_core::audit::downgrade_alternatives` and the request is
/// re-validated against that table). NOT safe by construction — the narrower
/// permission only suffices if the app never uses the broader capability — so
/// the UI presents it as an admin-judged choice; this command just makes the
/// chosen swap atomic-ish and non-stranding:
///
/// 1. Grant the narrower appRoleAssignment **before** revoking the broad one
///    (grant-before-strip, as the Exchange/SharePoint scoping cores do), so a
///    mid-flight failure leaves the app with extra access, never none.
/// 2. Swap the `requiredResourceAccess` declaration in one trailing patch.
///
/// Idempotent: a broad permission already gone (re-run, stale UI) is a no-op
/// success with every outcome flag `false`.
#[tauri::command]
pub async fn downgrade_application_permission(
    state: State<'_, AppState>,
    tenant_id: String,
    object_id: String,
    resource_app_id: String,
    broad_value: String,
    narrow_value: String,
) -> Result<DowngradeOutcome, UiError> {
    let client = state.graph_for(&tenant_id);
    let (outcome, error) = downgrade_application_permission_core(
        &client,
        &object_id,
        &resource_app_id,
        &broad_value,
        &narrow_value,
    )
    .await?;

    if outcome.narrow_granted || outcome.broad_revoked || outcome.declaration_swapped {
        invalidate_app_detail_state(&state.cache, &tenant_id);
    }
    if let Some(e) = error {
        return Err(e);
    }
    Ok(outcome)
}

/// True when `narrow_value` is a documented narrower alternative of
/// `broad_value`.
///
/// The request arrives from the UI, so it is re-validated here rather than
/// trusted: the pair table is the only thing that makes this action a
/// *downgrade* rather than an arbitrary permission swap.
fn is_documented_downgrade(broad_value: &str, narrow_value: &str) -> bool {
    azapptoolkit_core::audit::downgrade_alternatives(broad_value).contains(&narrow_value)
}

/// Shared core of [`downgrade_application_permission`]: grant-before-strip, then
/// the declaration swap. No `State`, no cache side effects.
///
/// Returns `(outcome, error)` rather than `Result<outcome>` because a failure
/// *after* the first mutation still has real writes to report — the caller must
/// invalidate on the partial success before surfacing the error, which is
/// exactly the ordering the command layer used to inline.
pub(crate) async fn downgrade_application_permission_core(
    client: &azapptoolkit_graph::GraphClient,
    object_id: &str,
    resource_app_id: &str,
    broad_value: &str,
    narrow_value: &str,
) -> Result<(DowngradeOutcome, Option<UiError>), UiError> {
    if !is_documented_downgrade(broad_value, narrow_value) {
        return Err(UiError::validation(
            "not_a_downgrade",
            format!("{narrow_value} is not a documented narrower alternative of {broad_value}"),
        ));
    }

    let app = client.get_application(object_id).await?;
    let resource_sp = client
        .resolve_resource_sp(resource_app_id)
        .await?
        .ok_or_else(|| {
            UiError::not_found(
                "resource",
                format!("resource app id {resource_app_id} not found"),
            )
        })?;
    let role_id = |value: &str| {
        resource_sp
            .app_roles
            .iter()
            .find(|r| r.value == value && r.is_enabled != Some(false))
            .map(|r| r.id.clone())
    };
    let Some(broad_id) = role_id(broad_value) else {
        return Err(UiError::validation(
            "unknown_permission",
            format!("{broad_value} is not an app role on this resource"),
        ));
    };
    let Some(narrow_id) = role_id(narrow_value) else {
        return Err(UiError::validation(
            "unknown_permission",
            format!("this resource does not expose {narrow_value}, so it cannot be swapped in"),
        ));
    };

    let mut outcome = DowngradeOutcome::default();
    let mut error: Option<UiError> = None;

    // Live grants first. Failures before the first mutation return early via
    // `?`; once anything has landed, errors are collected so the cache bust
    // below still runs (partial success = real write).
    let sp = client.get_service_principal_by_app_id(&app.app_id).await?;
    if let Some(sp) = &sp {
        let assignments = client.list_app_role_assignments(&sp.id).await?;
        let broad_assignment = assignments
            .iter()
            .find(|a| a.resource_id == resource_sp.id && a.app_role_id == broad_id);
        if let Some(broad_assignment) = broad_assignment {
            let narrow_already = assignments
                .iter()
                .any(|a| a.resource_id == resource_sp.id && a.app_role_id == narrow_id);
            if !narrow_already {
                client
                    .grant_app_role(&sp.id, &resource_sp.id, &narrow_id)
                    .await?;
                outcome.narrow_granted = true;
            }
            match client
                .remove_app_role_assignment(&sp.id, &broad_assignment.id)
                .await
            {
                Ok(()) => outcome.broad_revoked = true,
                Err(e) => error = Some(e.into()),
            }
        }
    }

    // Declaration swap in one PATCH — skipped when the revoke failed, so the
    // manifest keeps matching the live grants (both still present).
    if error.is_none() {
        let mut next = app.required_resource_access.clone();
        if swap_declared_role(&mut next, resource_app_id, &broad_id, &narrow_id) {
            let patch = azapptoolkit_graph::client::AppPatch {
                required_resource_access: Some(next),
                ..Default::default()
            };
            match client.update_application(object_id, &patch).await {
                Ok(_) => outcome.declaration_swapped = true,
                Err(e) => error = Some(e.into()),
            }
        }
    }

    Ok((outcome, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_downgrade_is_only_a_downgrade_if_the_table_says_so() {
        // The request comes from the UI, so the pair is re-validated here. Without
        // this the action would swap any permission for any other while still
        // being presented to the operator as "downgrade to least privilege".
        let broad = "Mail.ReadWrite";
        let narrower = azapptoolkit_core::audit::downgrade_alternatives(broad);
        assert!(
            !narrower.is_empty(),
            "fixture assumes {broad} has documented alternatives"
        );
        for n in narrower {
            assert!(is_documented_downgrade(broad, n));
        }
        // Not a documented pair, and not the reverse direction either.
        assert!(!is_documented_downgrade(broad, "Directory.ReadWrite.All"));
        assert!(!is_documented_downgrade(broad, broad));
        for n in azapptoolkit_core::audit::downgrade_alternatives(broad) {
            assert!(
                !is_documented_downgrade(n, broad),
                "{n} -> {broad} widens access and must never validate as a downgrade"
            );
        }
    }
}
