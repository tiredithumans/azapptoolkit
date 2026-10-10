//! "New SSO application" wizard. A multi-step modal that creates an Entra
//! Enterprise Application configured for SAML or OIDC single sign-on and, on
//! success, shows the app-owner output summary.
//!
//! Steps: 0 = protocol + display name, 1 = protocol-specific config, 2 = review
//! + create, 3 = output summary. Step state is a plain `RwSignal<u8>` matched in
//!   the view (the codebase has no Thaw stepper). Mirrors `create_app_dialog.rs`
//!   for the modal shell and `secret_reveal_dialog.rs` for show-once output.
//!
//! Mounted in the shell only while its open flag is set, so each open is a
//! fresh component — no manual state reset needed.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Select, Spinner, SpinnerSize, Textarea};

use crate::bindings::auth;
use crate::bindings::sso::{
    self, OidcSsoConfigInput, OidcSsoSummary, SamlSsoConfigInput, SamlSsoSummary,
};
use crate::components::claims_editor::{ClaimsEditor, ClaimsEditorState};
use crate::components::sso_summary::{OidcSummaryView, SamlSummaryView};
use crate::components::ui::{Callout, FormError};
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;

/// Splits a textarea (one URL per line) into a trimmed, non-empty Vec.
fn lines_to_vec(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Lifetime bounds mirrored from the backend (`commands/sso/mod.rs`:
/// `MAX_CERT_LIFETIME_DAYS`/`DEFAULT_CERT_LIFETIME_DAYS` and the secret pair).
/// The frontend gate exists to stop the old silent fallback, where a mistyped
/// "3650" or "abc" fell through `parse().ok()` to `None` and quietly created
/// the app with the default lifetime the operator did not type.
const CERT_MAX_DAYS: u32 = 1095;
const CERT_DEFAULT_DAYS: u32 = 365;
const SECRET_MAX_DAYS: u32 = 730;
const SECRET_DEFAULT_DAYS: u32 = 180;

/// `None` when the typed lifetime may be sent: blank (an explicit "use the
/// default", which the field hint states) or a number inside `1..=max`.
/// Pure so the ladder is table-testable; only consulted while the field is
/// on screen (Step 2) and again in `run_create` for the retry path.
fn lifetime_problem(days: &str, max: u32, default: u32) -> Option<String> {
    let trimmed = days.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<u32>() {
        Ok(n) if (1..=max).contains(&n) => None,
        Ok(n) => Some(format!(
            "'{trimmed}' ({n} days) is out of range — use 1-{max} days (blank = the {default}-day \
             default)."
        )),
        Err(_) => Some(format!(
            "'{trimmed}' is not a number of days — use 1-{max} days (blank = the {default}-day \
             default)."
        )),
    }
}

#[component]
pub fn SsoWizardDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_created: Callback<()>,
) -> impl IntoView {
    let session = use_session();

    let step = RwSignal::new(0u8);
    let protocol = RwSignal::new("saml".to_string());
    let display_name = RwSignal::new(String::new());

    // SAML fields.
    let entity_id = RwSignal::new(String::new());
    let reply_url = RwSignal::new(String::new());
    let logout_url = RwSignal::new(String::new());
    let cert_subject = RwSignal::new(String::new());
    let cert_days = RwSignal::new("365".to_string());
    let notification_emails = RwSignal::new(String::new());
    let claims_state = ClaimsEditorState::empty();

    // OIDC fields.
    let redirect_uris = RwSignal::new(String::new());
    let spa_uris = RwSignal::new(String::new());
    let secret_name = RwSignal::new(String::new());
    let secret_days = RwSignal::new("180".to_string());

    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    // Set when the backend reports a missing consent for the claims write scope.
    let needs_consent = RwSignal::new(false);
    // Created summaries (one is set depending on protocol).
    let saml_result: RwSignal<Option<SamlSsoSummary>> = RwSignal::new(None);
    let oidc_result: RwSignal<Option<OidcSsoSummary>> = RwSignal::new(None);

    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<leptos::html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    // Seed the SAML notification emails from the tenant default. One-shot at
    // construction: the shell mounts this dialog only while it is open, so each
    // open is a fresh component with an empty field.
    if let Some(t) = session.active_tenant.get_untracked() {
        leptos::task::spawn_local(async move {
            let d = crate::bindings::defaults::get_tenant_defaults(&t.tenant_id).await;
            // The dialog can close before this local read returns, and reading
            // a disposed signal panics the window; another tenant's default is
            // not this one's.
            if notification_emails.is_disposed() || !session.is_active_tenant(&t.tenant_id) {
                return;
            }
            let emails = d.enterprise_application.default_notification_emails;
            if !emails.is_empty()
                && notification_emails
                    .try_get_untracked()
                    .is_some_and(|v| v.trim().is_empty())
            {
                notification_emails.set(emails.join("\n"));
            }
        });
    }

    let close = move || on_close.run(());

    // Runs the create command for the chosen protocol. Reused by the Create
    // button and by the retry-after-consent button.
    let run_create = move || {
        // Reached after an await on the consent-retry path, when the dialog
        // may be disposed: reading a disposed signal panics, so check first.
        if busy.is_disposed() || busy.get_untracked() {
            return;
        }
        let Some(t) = session.active_tenant.get_untracked() else {
            return;
        };
        busy.set(true);
        error.set(None);
        needs_consent.set(false);
        let is_saml = protocol.get_untracked() == "saml";
        // Belt and braces behind the Step 2 Next gate: also refuse at Create
        // time so the retry-after-consent path can't resend a bad lifetime.
        let lifetime = if is_saml {
            lifetime_problem(&cert_days.get_untracked(), CERT_MAX_DAYS, CERT_DEFAULT_DAYS)
        } else {
            lifetime_problem(
                &secret_days.get_untracked(),
                SECRET_MAX_DAYS,
                SECRET_DEFAULT_DAYS,
            )
        };
        if let Some(problem) = lifetime {
            error.set(Some(problem));
            busy.set(false);
            return;
        }
        let tenant_id = t.tenant_id.clone();

        if is_saml {
            // Validate notification emails up front (same rule as the backend's
            // `set_notification_emails`) so the create flow — where the step is
            // best-effort and reports a failure as a warning — gives the user
            // feedback before anything is created.
            let emails = lines_to_vec(&notification_emails.get_untracked());
            if emails.len() > 5 {
                error.set(Some(
                    "Entra allows at most 5 notification email addresses.".to_string(),
                ));
                busy.set(false);
                return;
            }
            if let Some(bad) = emails.iter().find(|e| !e.contains('@')) {
                error.set(Some(format!("\"{bad}\" is not a valid email address.")));
                busy.set(false);
                return;
            }
            let policy = claims_state.to_dto();
            let input = SamlSsoConfigInput {
                display_name: display_name.get_untracked().trim().to_string(),
                entity_id: entity_id.get_untracked().trim().to_string(),
                reply_url: reply_url.get_untracked().trim().to_string(),
                logout_url: {
                    let l = logout_url.get_untracked().trim().to_string();
                    (!l.is_empty()).then_some(l)
                },
                cert_subject: {
                    let s = cert_subject.get_untracked().trim().to_string();
                    (!s.is_empty()).then_some(s)
                },
                cert_lifetime_days: cert_days.get_untracked().trim().parse().ok(),
                claims_policy: (!policy.is_empty()).then_some(policy),
                notification_emails: emails,
            };
            leptos::task::spawn_local(async move {
                match sso::create_saml_sso_application(&tenant_id, &input).await {
                    Ok(summary) => {
                        saml_result.set(Some(summary));
                        step.set(3);
                        on_created.try_run(());
                    }
                    Err(e) => {
                        if e.is_consent_required() {
                            needs_consent.set(true);
                        }
                        error.set(Some(e.message));
                    }
                }
                busy.set(false);
            });
        } else {
            let input = OidcSsoConfigInput {
                display_name: display_name.get_untracked().trim().to_string(),
                redirect_uris: lines_to_vec(&redirect_uris.get_untracked()),
                spa_redirect_uris: lines_to_vec(&spa_uris.get_untracked()),
                secret_display_name: {
                    let n = secret_name.get_untracked().trim().to_string();
                    (!n.is_empty()).then_some(n)
                },
                secret_lifetime_days: secret_days.get_untracked().trim().parse().ok(),
            };
            leptos::task::spawn_local(async move {
                match sso::create_oidc_sso_application(&tenant_id, &input).await {
                    Ok(summary) => {
                        oidc_result.set(Some(summary));
                        step.set(3);
                        on_created.try_run(());
                    }
                    Err(e) => error.set(Some(e.message)),
                }
                busy.set(false);
            });
        }
    };

    // Grant the claims-write consent, then retry the create.
    let grant_and_retry = move |_| {
        if busy.get_untracked() {
            return;
        }
        let Some(t) = session.active_tenant.get_untracked() else {
            return;
        };
        busy.set(true);
        error.set(None);
        let tenant_id = t.tenant_id.clone();
        leptos::task::spawn_local(async move {
            let consent = auth::request_scope_consent(&tenant_id, "policy_write").await;
            // Land nothing on a switched or signed-out tenant: the task outlives
            // the dialog (`frontend-workspace.md`), and the retried create here
            // would surface — or write — in whatever tenant is active now.
            if !session.is_active_tenant(&tenant_id) {
                busy.set(false);
                return;
            }
            match consent {
                Ok(()) => {
                    needs_consent.set(false);
                    busy.set(false);
                    run_create();
                }
                Err(e) => {
                    error.set(Some(e.message));
                    busy.set(false);
                }
            }
        });
    };

    // Step 3's "Open application": the new enterprise app, on the tab where its
    // setup continues. SAML lands on SSO (where a warned-about claims or email
    // step is retried); OIDC on Overview, since `configure_oidc` never sets
    // `preferredSingleSignOnMode` and the SSO tab would read "not configured".
    let open_created = move |_| {
        let target = saml_result
            .get_untracked()
            .map(|s| (s.service_principal_id, "sso"))
            .or_else(|| {
                oidc_result
                    .get_untracked()
                    .map(|s| (s.service_principal_id, "overview"))
            });
        if let Some((sp, tab)) = target {
            session.open_enterprise_on_tab(sp, tab);
        }
        close();
    };

    // Step-1 "Next" is allowed when the protocol-specific required fields are
    // set AND the lifetime field is valid (or deliberately blank) — an invalid
    // lifetime must never silently reach the create call as the default.
    let step1_ready = move || {
        if protocol.get() == "saml" {
            !entity_id.with(|s| s.trim().is_empty())
                && !reply_url.with(|s| s.trim().is_empty())
                && lifetime_problem(&cert_days.get(), CERT_MAX_DAYS, CERT_DEFAULT_DAYS).is_none()
        } else {
            (!redirect_uris.with(|s| s.trim().is_empty())
                || !spa_uris.with(|s| s.trim().is_empty()))
                && lifetime_problem(&secret_days.get(), SECRET_MAX_DAYS, SECRET_DEFAULT_DAYS)
                    .is_none()
        }
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby="sso-wizard-dialog-title"
            >
                <div class="modal modal--wide" node_ref=modal_ref>
                    <h3 id="sso-wizard-dialog-title">"New application"</h3>
                    <div class="sso-wizard__steps">
                        <Body1 class="hint">
                            {move || match step.get() {
                                0 => "Step 1 of 3 — Protocol & name",
                                1 => "Step 2 of 3 — Configuration",
                                2 => "Step 3 of 3 — Review & create",
                                _ => "Done — configuration summary",
                            }}
                        </Body1>
                    </div>

                    // ---- Step 0: protocol + display name ----
                    <Show when=move || step.get() == 0 fallback=|| ()>
                        <Field label="Single sign-on protocol">
                            <Select value=protocol>
                                <option value="saml">"SAML"</option>
                                <option value="oidc">"OpenID Connect (OIDC)"</option>
                            </Select>
                        </Field>
                        <Field label="Display name">
                            <Input value=display_name />
                        </Field>
                    </Show>

                    // ---- Step 1: protocol-specific config ----
                    <Show when=move || step.get() == 1 && protocol.get() == "saml" fallback=|| ()>
                        <Field label="Identifier (Entity ID)">
                            <Input value=entity_id />
                        </Field>
                        <Field label="Reply URL (Assertion Consumer Service URL)">
                            <Input value=reply_url />
                        </Field>
                        <Field label="Logout URL (optional)">
                            <Input value=logout_url />
                        </Field>
                        <Field label="Signing certificate subject (optional)">
                            <Input value=cert_subject />
                        </Field>
                        <Field label="Certificate lifetime (days)">
                            <Input value=cert_days />
                            {move || {
                                let hint = lifetime_problem(
                                    &cert_days.get(),
                                    CERT_MAX_DAYS,
                                    CERT_DEFAULT_DAYS,
                                )
                                .unwrap_or_else(|| {
                                    format!(
                                        "1-{CERT_MAX_DAYS} days; blank = the \
                                         {CERT_DEFAULT_DAYS}-day default."
                                    )
                                });
                                view! { <Body1 class="hint">{hint}</Body1> }
                            }}
                        </Field>
                        <Field label="Notification emails (one per line, max 5 — optional)">
                            <Textarea value=notification_emails />
                        </Field>
                        <div class="sso-claims">
                            <span class="sso-field__label">"Attributes & claims (optional)"</span>
                            <Body1 class="hint">
                                "Custom claims require admin consent for Policy.ReadWrite.ApplicationConfiguration and Application.ReadWrite.All. Leave empty to use Entra's default claim set."
                            </Body1>
                            <ClaimsEditor state=claims_state />
                        </div>
                    </Show>
                    <Show when=move || step.get() == 1 && protocol.get() == "oidc" fallback=|| ()>
                        <Field label="Redirect URIs (web — one per line)">
                            <Textarea value=redirect_uris />
                        </Field>
                        <Field label="Redirect URIs (single-page app — one per line)">
                            <Textarea value=spa_uris />
                        </Field>
                        <Field label="Client secret name (optional — creates a secret)">
                            <Input value=secret_name />
                        </Field>
                        <Field label="Secret lifetime (days)">
                            <Input value=secret_days />
                            {move || {
                                let hint = lifetime_problem(
                                    &secret_days.get(),
                                    SECRET_MAX_DAYS,
                                    SECRET_DEFAULT_DAYS,
                                )
                                .unwrap_or_else(|| {
                                    format!(
                                        "1-{SECRET_MAX_DAYS} days; blank = the \
                                         {SECRET_DEFAULT_DAYS}-day default."
                                    )
                                });
                                view! { <Body1 class="hint">{hint}</Body1> }
                            }}
                        </Field>
                    </Show>

                    // ---- Step 2: review ----
                    <Show when=move || step.get() == 2 fallback=|| ()>
                        <dl class="read-field">
                            <dt>"Protocol"</dt>
                            <dd>{move || protocol.get().to_uppercase()}</dd>
                            <dt>"Display name"</dt>
                            <dd>{move || display_name.get()}</dd>
                            {move || {
                                (protocol.get() == "saml")
                                    .then(|| {
                                        view! {
                                            <>
                                                <dt>"Entity ID"</dt>
                                                <dd class="mono">{move || entity_id.get()}</dd>
                                                <dt>"Reply URL"</dt>
                                                <dd class="mono">{move || reply_url.get()}</dd>
                                            </>
                                        }
                                    })
                            }}
                        </dl>
                        {move || {
                            needs_consent
                                .get()
                                .then(|| {
                                    view! {
                                        <Callout tone="warn">
                                            "Custom claims need admin consent for Policy.ReadWrite.ApplicationConfiguration and Application.ReadWrite.All."
                                            <Button
                                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                on_click=Box::new(grant_and_retry)
                                                disabled=Signal::derive(move || busy.get())
                                            >
                                                "Grant admin consent & retry"
                                            </Button>
                                        </Callout>
                                    }
                                })
                        }}
                    </Show>

                    // ---- Step 3: output summary ----
                    <Show when=move || step.get() == 3 fallback=|| ()>
                        {move || saml_result.get().map(|s| view! { <SamlSummaryView summary=s /> })}
                        {move || oidc_result.get().map(|s| view! { <OidcSummaryView summary=s /> })}
                    </Show>

                    {move || error.get().map(|e| view! { <FormError>{e}</FormError> })}

                    // ---- Footer actions ----
                    <div class="actions-row">
                        <Show when=move || step.get() == 3 fallback=move || {
                            view! {
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(move |_| {
                                        if step.get() == 0 { close() } else { step.update(|s| *s -= 1) }
                                    })
                                    disabled=Signal::derive(move || busy.get())
                                >
                                    {move || if step.get() == 0 { "Cancel" } else { "Back" }}
                                </Button>
                                <Show when=move || step.get() < 2 fallback=move || {
                                    view! {
                                        <Button
                                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                                            on_click=Box::new(move |_| run_create())
                                            disabled=Signal::derive(move || busy.get())
                                        >
                                            {move || {
                                                if busy.get() {
                                                    view! {
                                                        <Spinner size=Signal::derive(|| {
                                                            SpinnerSize::Tiny
                                                        }) />
                                                    }
                                                        .into_any()
                                                } else {
                                                    view! { "Create" }.into_any()
                                                }
                                            }}
                                        </Button>
                                    }
                                }>
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(move |_| step.update(|s| *s += 1))
                                        disabled=Signal::derive(move || {
                                            (step.get() == 0
                                                && display_name.with(|d| d.trim().is_empty()))
                                                || (step.get() == 1 && !step1_ready())
                                        })
                                    >
                                        "Next"
                                    </Button>
                                </Show>
                            }
                        }>
                            <Button
                                class="sso-wizard-open"
                                appearance=Signal::derive(|| ButtonAppearance::Primary)
                                on_click=Box::new(open_created)
                            >
                                "Open application"
                            </Button>
                            <Button
                                appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                on_click=Box::new(move |_| close())
                            >
                                "Done"
                            </Button>
                        </Show>
                    </div>
                </div>
            </div>
        </Show>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_and_blank_cert_lifetimes_pass_the_gate() {
        // In-range numbers, surrounding whitespace, and the deliberate blank
        // ("use the default") are all sendable.
        for ok in ["365", "1", "1095", " 180 "] {
            assert!(
                lifetime_problem(ok, CERT_MAX_DAYS, CERT_DEFAULT_DAYS).is_none(),
                "{ok}"
            );
        }
        assert!(lifetime_problem("", CERT_MAX_DAYS, CERT_DEFAULT_DAYS).is_none());
    }

    #[test]
    fn a_mistyped_lifetime_names_the_problem_instead_of_defaulting() {
        // The pre-F382 code sent every one of these as the DEFAULT lifetime.
        for bad in ["0", "1096", "abc", "365 days", "-5", "4294967296"] {
            let problem = lifetime_problem(bad, CERT_MAX_DAYS, CERT_DEFAULT_DAYS)
                .unwrap_or_else(|| panic!("`{bad}` must not pass the gate"));
            assert!(
                problem.contains(bad.trim()),
                "message should quote `{bad}`: {problem}"
            );
        }
    }

    #[test]
    fn the_secret_gate_uses_the_secret_bounds() {
        assert!(lifetime_problem("730", SECRET_MAX_DAYS, SECRET_DEFAULT_DAYS).is_none());
        assert!(lifetime_problem("731", SECRET_MAX_DAYS, SECRET_DEFAULT_DAYS).is_some());
    }
}
