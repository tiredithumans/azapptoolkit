//! App-owner output summaries for an SSO integration. Renders the values an
//! application owner needs to complete their side of the SAML / OIDC setup, each
//! with a copy-to-clipboard control. Used by both the wizard's final step and
//! the enterprise-app detail "SSO" tab.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};
use wasm_bindgen_futures::JsFuture;

use crate::bindings::sso::{OidcSsoSummary, SamlSsoSummary};
use crate::components::icon::IconName;
use crate::components::ui::IconButton;
use crate::util::copy_text;

/// A labelled, monospace, copy-to-clipboard read-only field. Empty values render
/// an em-dash and no copy button.
#[component]
pub fn CopyField(#[prop(into)] label: String, #[prop(into)] value: String) -> impl IntoView {
    let has_value = !value.trim().is_empty();
    let copy_value = value.clone();
    let aria = format!("Copy {label}");
    view! {
        <div class="sso-field">
            <span class="sso-field__label">{label}</span>
            <span class="sso-field__value mono">
                {if has_value { value.clone() } else { "—".to_string() }}
                {has_value
                    .then(|| {
                        view! {
                            <IconButton
                                icon=IconName::Copy
                                aria_label=aria.clone()
                                title="Copy".to_string()
                                on_click=Callback::new(move |_| copy_text(copy_value.clone()))
                            />
                        }
                    })}
            </span>
        </div>
    }
}

/// A large monospace block (certificate / secret) with a copy button.
#[component]
fn CopyBlock(
    #[prop(into)] label: String,
    #[prop(into)] value: String,
    #[prop(into)] hint: String,
) -> impl IntoView {
    let copied = RwSignal::new(false);
    let copy_value = value.clone();
    let copy = move |_| {
        let v = copy_value.clone();
        copied.set(false);
        leptos::task::spawn_local(async move {
            if let Some(win) = web_sys::window() {
                let promise = win.navigator().clipboard().write_text(&v);
                let _ = JsFuture::from(promise).await;
                copied.set(true);
            }
        });
    };
    view! {
        <div class="sso-block">
            <span class="sso-field__label">{label}</span>
            {(!hint.is_empty()).then(|| view! { <Body1 class="hint">{hint}</Body1> })}
            <pre class="secret-reveal">{value}</pre>
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(copy)
            >
                {move || if copied.get() { "Copied" } else { "Copy" }}
            </Button>
        </div>
    }
}

/// SAML app-owner summary. `signing_cert_base64` is only present right after
/// creation / certificate rotation (the public certificate is returned once).
#[component]
pub fn SamlSummaryView(summary: SamlSsoSummary) -> impl IntoView {
    let cert = summary.signing_cert_base64.clone();
    view! {
        <div class="sso-summary">
            <Body1 class="hint">
                "Share these values with the application owner to finish the SAML integration."
            </Body1>
            <CopyField label="Microsoft Entra Identifier (Issuer)" value=summary.entity_id_issuer />
            <CopyField label="Login URL" value=summary.login_url />
            <CopyField label="Logout URL" value=summary.logout_url />
            <CopyField label="App Federation Metadata URL" value=summary.federation_metadata_url />
            <CopyField label="Identifier (Entity ID)" value=summary.sp_entity_id />
            <CopyField label="Reply URL (ACS)" value=summary.reply_url />
            <CopyField
                label="Signing certificate thumbprint"
                value=summary.signing_cert_thumbprint.unwrap_or_default()
            />
            <CopyField
                label="Signing certificate expires"
                value=summary.signing_cert_expiry.unwrap_or_default()
            />
            {cert
                .map(|c| {
                    view! {
                        <CopyBlock
                            label="SAML signing certificate (Base64)"
                            value=c
                            hint="The public certificate the application owner uploads to validate Entra's SAML assertions."
                        />
                    }
                })}
        </div>
    }
}

/// OIDC app-owner summary. `client_secret` is only present right after creation
/// (show-once); it renders as a copy-block when set.
#[component]
pub fn OidcSummaryView(summary: OidcSsoSummary) -> impl IntoView {
    let secret = summary.client_secret.clone();
    let redirects = summary.redirect_uris.join("\n");
    let spa = summary.spa_redirect_uris.join("\n");
    view! {
        <div class="sso-summary">
            <Body1 class="hint">
                "Share these values with the application owner to finish the OIDC integration."
            </Body1>
            <CopyField label="Application (client) ID" value=summary.client_id />
            <CopyField label="Directory (tenant) ID" value=summary.tenant_id />
            <CopyField label="Authority" value=summary.authority />
            <CopyField label="OIDC discovery document" value=summary.discovery_url />
            <CopyField label="Redirect URIs (web)" value=redirects />
            <CopyField label="Redirect URIs (SPA)" value=spa />
            {secret
                .map(|s| {
                    view! {
                        <CopyBlock
                            label="Client secret"
                            value=s
                            hint="Copy now — the secret value can never be retrieved again after you leave this screen."
                        />
                    }
                })}
            {summary
                .client_secret_expiry
                .map(|e| view! { <CopyField label="Client secret expires" value=e /> })}
        </div>
    }
}
