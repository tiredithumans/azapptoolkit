use super::*;

#[component]
pub(super) fn CredentialsContent(
    signal: Signal<Arc<EnterpriseApplicationDetail>>,
) -> impl IntoView {
    let secrets = signal.with(|d| d.service_principal.password_credentials.clone());
    let certs = signal.with(|d| d.service_principal.key_credentials.clone());

    let secrets_view = view! {
        <DataTable
            headers=vec!["Description", "Expires", "Status"]
            rows=secrets
            empty_message="No client secrets."
            row=|s: azapptoolkit_core::models::PasswordCredential| {
                let (label, cls) = cred_status(s.end_date_time);
                view! {
                    <tr>
                        <td>{s.display_name.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{fmt_date(s.end_date_time)}</td>
                        <td>
                            <span class=cls>{label}</span>
                        </td>
                    </tr>
                }
                    .into_any()
            }
        />
    };

    let certs_view = view! {
        <DataTable
            headers=vec!["Name", "Usage", "Expires", "Status"]
            rows=certs
            empty_message="No certificates."
            row=|c: azapptoolkit_core::models::KeyCredential| {
                let (label, cls) = cred_status(c.end_date_time);
                view! {
                    <tr>
                        <td>{c.display_name.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{c.usage.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{fmt_date(c.end_date_time)}</td>
                        <td>
                            <span class=cls>{label}</span>
                        </td>
                    </tr>
                }
                    .into_any()
            }
        />
    };

    view! {
        <section class="ent-creds">
            <h4>"Client secrets"</h4>
            {secrets_view}
            <h4>"Certificates"</h4>
            <Body1 class="mi-view__intro">
                "For SAML single sign-on apps these are the token-signing certificates — watch the expiry to avoid SSO outages."
            </Body1>
            {certs_view}
        </section>
    }
    .into_any()
}
