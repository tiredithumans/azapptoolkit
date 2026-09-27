use chrono::{DateTime, Utc};

use super::*;
use crate::util::{expiry_label, expiry_tone, floored_days_until};

/// Expiry badge for an enterprise credential (incl. SAML signing certs). Days
/// are FLOORED, so one that lapsed hours ago reads "Expired", never "0d left".
/// This tab is display-only (no removal path), so it need not follow the
/// audit's whole-day `is_expired` rule the removal sweeps count by.
fn expiry_badge(end: Option<DateTime<Utc>>, now: DateTime<Utc>) -> AnyView {
    match end.map(|e| floored_days_until(e, now)) {
        None => view! { <Badge label="No expiry" /> }.into_any(),
        Some(d) => view! { <Badge label=expiry_label(d) tone=expiry_tone(d) /> }.into_any(),
    }
}

#[component]
pub(super) fn CredentialsContent(
    signal: Signal<Arc<EnterpriseApplicationDetail>>,
) -> impl IntoView {
    let secrets = signal.with(|d| d.service_principal.password_credentials.clone());
    let certs = signal.with(|d| d.service_principal.key_credentials.clone());
    let now = Utc::now();

    let secrets_view = view! {
        <DataTable
            headers=vec!["Description", "Expires", "Status"]
            rows=secrets
            empty_message="No client secrets."
            row=move |s: azapptoolkit_core::models::PasswordCredential| {
                view! {
                    <tr>
                        <td>{s.display_name.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{fmt_date(s.end_date_time)}</td>
                        <td>{expiry_badge(s.end_date_time, now)}</td>
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
            row=move |c: azapptoolkit_core::models::KeyCredential| {
                view! {
                    <tr>
                        <td>{c.display_name.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{c.usage.clone().unwrap_or_else(|| "—".into())}</td>
                        <td>{fmt_date(c.end_date_time)}</td>
                        <td>{expiry_badge(c.end_date_time, now)}</td>
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
