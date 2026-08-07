//! App-owner output summaries for an SSO integration. Renders the values an
//! application owner needs to complete their side of the SAML / OIDC setup, each
//! with a copy-to-clipboard control, plus one "Copy all details" button that
//! produces the whole set as labelled plain text to paste into mail or chat.
//! Used by both the wizard's final step and the enterprise-app detail "SSO" tab.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance};
use wasm_bindgen_futures::JsFuture;

use crate::bindings::sso::{OidcSsoSummary, SamlSsoSummary};
use crate::components::ui::CopyIconButton;

/// One labelled value in an app-owner summary.
///
/// Built ONCE per summary and used for both the rendered fields and the
/// "Copy all details" payload, so the two cannot drift — a field added to the
/// view is in the paste-able text automatically.
pub struct OwnerField {
    pub label: &'static str,
    pub value: String,
}

fn f(label: &'static str, value: impl Into<String>) -> OwnerField {
    OwnerField {
        label,
        value: value.into(),
    }
}

/// Renders `fields` as labelled plain text for pasting to an application owner.
///
/// Empty values are dropped rather than pasted as an em-dash — the recipient
/// should see the values that exist, not placeholders for the ones that don't.
/// A value spanning several lines (the redirect-URI lists, a certificate) goes
/// under its label indented, so a mail client's line wrapping cannot merge two
/// URIs into one unusable string.
pub fn owner_summary_text(heading: &str, fields: &[OwnerField], note: Option<&str>) -> String {
    let mut out = String::new();
    out.push_str(heading);
    out.push('\n');
    out.push_str(&"=".repeat(heading.chars().count()));
    out.push('\n');
    for field in fields.iter().filter(|f| !f.value.trim().is_empty()) {
        let value = field.value.trim();
        out.push('\n');
        if value.contains('\n') {
            out.push_str(field.label);
            out.push_str(":\n");
            for line in value.lines() {
                out.push_str("  ");
                out.push_str(line);
                out.push('\n');
            }
        } else {
            out.push_str(field.label);
            out.push_str(": ");
            out.push_str(value);
            out.push('\n');
        }
    }
    if let Some(note) = note {
        out.push('\n');
        out.push_str(note);
        out.push('\n');
    }
    out
}

/// The "Copy all details" control. Separate from [`CopyIconButton`] because
/// this one is a labelled button with a persistent confirmation, not a
/// per-field icon.
#[component]
fn CopyAllButton(#[prop(into)] text: String) -> impl IntoView {
    let copied = RwSignal::new(false);
    let copy = move |_| {
        crate::util::copy_text(text.clone());
        copied.set(true);
    };
    view! {
        <div class="sso-summary__actions">
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                on_click=Box::new(copy)
            >
                {move || if copied.get() { "Copied all details" } else { "Copy all details" }}
            </Button>
        </div>
    }
}

/// A labelled, monospace, copy-to-clipboard read-only field. Empty values render
/// an em-dash and no copy button.
#[component]
pub fn CopyField(#[prop(into)] label: String, #[prop(into)] value: String) -> impl IntoView {
    let has_value = !value.trim().is_empty();
    let copy_value: Signal<String> = RwSignal::new(value.clone()).into();
    let aria = format!("Copy {label}");
    view! {
        <div class="sso-field">
            <span class="sso-field__label">{label}</span>
            <span class="sso-field__value mono">
                {if has_value { value.clone() } else { "—".to_string() }}
                {has_value
                    .then(|| {
                        view! { <CopyIconButton value=copy_value aria_label=aria.clone() /> }
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
    let fields = vec![
        f(
            "Microsoft Entra Identifier (Issuer)",
            summary.entity_id_issuer,
        ),
        f("Login URL", summary.login_url),
        f("Logout URL", summary.logout_url),
        f(
            "App Federation Metadata URL",
            summary.federation_metadata_url,
        ),
        f("Identifier (Entity ID)", summary.sp_entity_id),
        f("Reply URL (ACS)", summary.reply_url),
        f(
            "Signing certificate thumbprint",
            summary.signing_cert_thumbprint.unwrap_or_default(),
        ),
        f(
            "Signing certificate expires",
            summary.signing_cert_expiry.unwrap_or_default(),
        ),
    ];
    // The signing certificate is PUBLIC — it is what the owner uploads to
    // validate Entra's assertions — so it belongs in the paste-able block.
    let mut text_fields = fields
        .iter()
        .map(|x| f(x.label, x.value.clone()))
        .collect::<Vec<_>>();
    if let Some(c) = cert.clone() {
        text_fields.push(f("SAML signing certificate (Base64)", c));
    }
    let all_text = owner_summary_text("SAML single sign-on details", &text_fields, None);
    view! {
        <div class="sso-summary">
            <Body1 class="hint">
                "Share these values with the application owner to finish the SAML integration."
            </Body1>
            <CopyAllButton text=all_text />
            {fields
                .into_iter()
                .map(|x| view! { <CopyField label=x.label value=x.value /> })
                .collect_view()}
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
    let mut fields = vec![
        f("Application (client) ID", summary.client_id),
        f("Directory (tenant) ID", summary.tenant_id),
        f("Authority", summary.authority),
        f("OIDC discovery document", summary.discovery_url),
        f("Redirect URIs (web)", redirects),
        f("Redirect URIs (SPA)", spa),
    ];
    if let Some(e) = summary.client_secret_expiry.clone() {
        fields.push(f("Client secret expires", e));
    }
    // The client secret is deliberately NOT in the bulk copy. This button
    // exists to produce a block for pasting into mail or chat, and a credential
    // that grants the application's identity does not belong in that channel —
    // it has its own explicit copy button below, to be sent separately.
    let note = secret.is_some().then_some(
        "The client secret is NOT included above. Send it separately over a secure channel \
         (password manager, secrets vault) — it grants this application's identity.",
    );
    let all_text = owner_summary_text("OpenID Connect single sign-on details", &fields, note);
    view! {
        <div class="sso-summary">
            <Body1 class="hint">
                "Share these values with the application owner to finish the OIDC integration."
            </Body1>
            <CopyAllButton text=all_text />
            {fields
                .into_iter()
                .map(|x| view! { <CopyField label=x.label value=x.value /> })
                .collect_view()}
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
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labelled_text_is_paste_ready_and_skips_empty_values() {
        let text = owner_summary_text(
            "SAML single sign-on details",
            &[
                f("Login URL", "https://login.example/x"),
                // An unset optional field: the recipient should not receive a
                // line telling them a value is missing.
                f("Signing certificate thumbprint", "   "),
                f("Reply URL (ACS)", "https://app.example/acs"),
            ],
            None,
        );
        assert!(text.starts_with("SAML single sign-on details\n===="));
        assert!(text.contains("Login URL: https://login.example/x\n"));
        assert!(text.contains("Reply URL (ACS): https://app.example/acs\n"));
        assert!(
            !text.contains("thumbprint"),
            "empty fields must not be pasted at all:\n{text}"
        );
    }

    #[test]
    fn a_multi_line_value_is_indented_under_its_label() {
        // Redirect-URI lists and certificates arrive newline-joined. Inline
        // after the label, a mail client's wrapping can run two URIs together
        // into one string the owner then pastes verbatim.
        let text = owner_summary_text(
            "OpenID Connect single sign-on details",
            &[f(
                "Redirect URIs (web)",
                "https://a.example/cb\nhttps://b.example/cb",
            )],
            None,
        );
        assert!(
            text.contains("Redirect URIs (web):\n  https://a.example/cb\n  https://b.example/cb\n")
        );
    }

    #[test]
    fn the_note_is_appended_last_when_present() {
        let text = owner_summary_text(
            "OpenID Connect single sign-on details",
            &[f("Application (client) ID", "abc")],
            Some("The client secret is NOT included above."),
        );
        assert!(
            text.trim_end()
                .ends_with("The client secret is NOT included above.")
        );
        // ...and the secret itself never appears in a block destined for mail.
        assert!(!text.contains("s3cret"));
    }
}
