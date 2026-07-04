//! The three thin, self-contained enterprise-app tabs: SCIM Provisioning
//! status, the directory Activity change-log, and Conditional Access policies.
//! Grouped in one file — each is a small wrapper over a binding / shared panel.

use super::*;

#[component]
pub(super) fn ProvisioningContent(
    signal: Signal<Arc<EnterpriseApplicationDetail>>,
) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let sp_id = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));

    let jobs = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = sp_id.get();
        async move {
            match tenant {
                Some(t) => {
                    enterprise_application::get_enterprise_app_provisioning(&t.tenant_id, &id).await
                }
                None => Ok(Vec::new()),
            }
        }
    });

    view! {
        <Suspense fallback=move || {
            view! {
                <div class="centered-pad">
                    <Spinner
                        size=Signal::derive(|| SpinnerSize::Tiny)
                        label="Loading provisioning…"
                    />
                </div>
            }
        }>
            {move || Suspend::new(async move {
                match jobs.await {
                    Err(_) => {
                        view! {
                            <div class="alert alert--warn">
                                "Provisioning status is unavailable. It needs admin consent to Synchronization.Read.All and an Entra ID P1/P2 license."
                            </div>
                        }
                            .into_any()
                    }
                    Ok(list) if list.is_empty() => {
                        view! {
                            <Body1>"This application has no SCIM provisioning configured."</Body1>
                        }
                            .into_any()
                    }
                    Ok(list) => {
                        view! {
                            <div>
                                {list
                                    .into_iter()
                                    .map(|j| {
                                        let (label, cls) = match j.status_code.as_deref() {
                                            Some("Active") => ("Active".to_string(), "badge badge--ok"),
                                            Some("Quarantine") => {
                                                ("Quarantine".to_string(), "badge badge--danger")
                                            }
                                            Some(other) => (other.to_string(), "badge badge--warning"),
                                            None => ("Unknown".to_string(), "badge"),
                                        };
                                        let last = match (j.last_state.clone(), j.last_run.clone()) {
                                            (Some(s), Some(t)) => format!("{s} — {t}"),
                                            (Some(s), None) => s,
                                            _ => "—".to_string(),
                                        };
                                        let title = j
                                            .template_id
                                            .clone()
                                            .unwrap_or_else(|| j.id.clone());
                                        view! {
                                            <div class="prov-job">
                                                <div class="row-between">
                                                    <strong>{title}</strong>
                                                    <span class=cls>{label}</span>
                                                </div>
                                                <dl class="read-field">
                                                    <dt>"Last run"</dt>
                                                    <dd>{last}</dd>
                                                    {j.quarantine_reason
                                                        .clone()
                                                        .map(|r| {
                                                            view! {
                                                                <dt>"Quarantine reason"</dt>
                                                                <dd>{r}</dd>
                                                            }
                                                        })}
                                                </dl>
                                            </div>
                                        }
                                    })
                                    .collect_view()}
                            </div>
                        }
                            .into_any()
                    }
                }
            })}
        </Suspense>
    }
}

/// Activity / change-log for the enterprise app — directory audit entries
/// targeting the service principal and its paired app registration (if any).
#[component]
pub(super) fn ActivityContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let app_id = Signal::derive(move || signal.with(|d| d.service_principal.app_id.clone()));
    let primary = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));
    let secondary = Signal::derive(move || {
        signal.with(|d| d.service_principal.paired_app_registration_id.clone())
    });
    view! { <ActivityPanel app_id=app_id primary_id=primary secondary_id=secondary /> }
}

/// Conditional Access for the enterprise app — policies that target its appId.
#[component]
pub(super) fn CaContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
    let app_id = Signal::derive(move || signal.with(|d| d.service_principal.app_id.clone()));
    view! { <ConditionalAccessPanel app_id=app_id /> }
}
