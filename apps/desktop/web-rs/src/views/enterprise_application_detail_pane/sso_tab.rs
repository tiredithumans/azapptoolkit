use super::*;

/// SSO configuration for the enterprise app — view/edit the SAML or OIDC setup
/// and surface the app-owner output summary. Reads `get_sso_config`; edits go
/// through the per-field SSO commands and bump a local `reload`.
#[component]
pub(super) fn SsoContent(signal: Signal<EnterpriseApplicationDetail>) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let sp_id = Signal::derive(move || signal.with(|d| d.service_principal.id.clone()));
    let reload = RwSignal::new(0u32);

    let config = LocalResource::new(move || {
        let tenant = tenant.get();
        let id = sp_id.get();
        let _ = reload.get();
        async move {
            match tenant {
                Some(t) => sso::get_sso_config(&t.tenant_id, &id).await,
                None => Ok(SsoConfigDto::default()),
            }
        }
    });

    view! {
        <Suspense fallback=move || {
            view! {
                <div class="centered-pad">
                    <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading SSO…" />
                </div>
            }
        }>
            {move || Suspend::new(async move {
                match config.await {
                    Err(e) => {
                        view! { <div class="alert alert--warn">{e.message}</div> }.into_any()
                    }
                    Ok(cfg) => view! { <SsoEditor cfg=cfg reload=reload /> }.into_any(),
                }
            })}
        </Suspense>
    }
}

/// Inner SSO editor, seeded from the loaded [`SsoConfigDto`]. Branches on
/// `sso_mode` (OIDC vs SAML/default) for the editable fields, and renders the
/// app-owner summary fetched via `get_sso_summary`.
#[component]
fn SsoEditor(cfg: SsoConfigDto, reload: RwSignal<u32>) -> impl IntoView {
    let session = use_session();
    let tenant_id = session
        .active_tenant
        .get_untracked()
        .map(|t| t.tenant_id)
        .unwrap_or_default();

    let is_oidc = cfg.sso_mode.as_deref() == Some("oidc");
    let protocol = if is_oidc { "oidc" } else { "saml" };
    // Held in `StoredValue` (Copy) so the on_click handlers below capture only
    // Copy state and stay `Fn` — Leptos `<Show>` children must be re-callable.
    let tenant_id = StoredValue::new(tenant_id);
    let object_id = StoredValue::new(cfg.object_id.clone());
    let sp_id = StoredValue::new(cfg.service_principal_id.clone());

    // SAML editable fields.
    let entity_id = RwSignal::new(cfg.entity_id.clone().unwrap_or_default());
    let reply_url = RwSignal::new(cfg.reply_urls.first().cloned().unwrap_or_default());
    let logout_url = RwSignal::new(cfg.logout_url.clone().unwrap_or_default());
    // SAML signing-cert expiry notification recipients (one per line).
    let notification_emails = RwSignal::new(cfg.notification_emails.join("\n"));
    // OIDC editable fields (one URI per line).
    let redirect_uris = RwSignal::new(cfg.redirect_uris.join("\n"));
    let spa_uris = RwSignal::new(cfg.spa_redirect_uris.join("\n"));
    // Cert rotation.
    let cert_subject = RwSignal::new(String::new());
    let rotated_cert: RwSignal<Option<String>> = RwSignal::new(None);
    // Attributes & claims editor state, seeded from the assigned policy.
    let claims_state = ClaimsEditorState::from_dto(&cfg.claims_policy.clone().unwrap_or_default());

    let busy = RwSignal::new(false);
    let needs_consent = RwSignal::new(false);

    // App-owner summary (read-only), recomputed on reload.
    let summary = LocalResource::new(move || {
        let tenant_id = tenant_id.get_value();
        let sp_id = sp_id.get_value();
        let _ = reload.get();
        async move { sso::get_sso_summary(&tenant_id, &sp_id, protocol).await }
    });

    // ---- save handlers (capture only Copy state → stay `Fn`) ----
    let save_saml_urls = move |_| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let tenant_id = tenant_id.get_value();
        let object_id = object_id.get_value();
        let logout = {
            let l = logout_url.get_untracked().trim().to_string();
            (!l.is_empty()).then_some(l)
        };
        let entity = entity_id.get_untracked().trim().to_string();
        let reply = reply_url.get_untracked().trim().to_string();
        leptos::task::spawn_local(async move {
            match sso::set_saml_urls(&tenant_id, &object_id, &entity, &reply, logout.as_deref())
                .await
            {
                Ok(()) => {
                    session.toast_success("SAML URLs saved.");
                    reload.update(|n| *n = n.wrapping_add(1));
                }
                Err(e) => {
                    session.toast_error(e.message, None);
                }
            }
            busy.set(false);
        });
    };

    let save_oidc_uris = move |_| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let tenant_id = tenant_id.get_value();
        let object_id = object_id.get_value();
        let web = split_lines(&redirect_uris.get_untracked());
        let spa = split_lines(&spa_uris.get_untracked());
        leptos::task::spawn_local(async move {
            match sso::set_oidc_redirect_uris(&tenant_id, &object_id, &web, &spa).await {
                Ok(()) => {
                    session.toast_success("Redirect URIs saved.");
                    reload.update(|n| *n = n.wrapping_add(1));
                }
                Err(e) => {
                    session.toast_error(e.message, None);
                }
            }
            busy.set(false);
        });
    };

    let rotate_cert = move |_| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let tenant_id = tenant_id.get_value();
        let sp_id = sp_id.get_value();
        let subject = cert_subject.get_untracked().trim().to_string();
        leptos::task::spawn_local(async move {
            match sso::rotate_saml_signing_certificate(&tenant_id, &sp_id, &subject, None).await {
                Ok(cert) => {
                    session.toast_success(format!("New signing certificate: {}", cert.thumbprint));
                    rotated_cert.set(cert.base64);
                    reload.update(|n| *n = n.wrapping_add(1));
                }
                Err(e) => {
                    session.toast_error(e.message, None);
                }
            }
            busy.set(false);
        });
    };

    // Save the SAML cert-expiry notification recipients (separate SP write — no
    // claims-write consent needed).
    let save_notification_emails = move |_| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let tenant_id = tenant_id.get_value();
        let sp_id = sp_id.get_value();
        let emails = split_lines(&notification_emails.get_untracked());
        leptos::task::spawn_local(async move {
            match sso::set_notification_emails(&tenant_id, &sp_id, &emails).await {
                Ok(()) => {
                    // Deliberately do NOT bump `reload` here: the textarea
                    // already shows the saved value, and reloading would tear
                    // down the Suspense subtree and discard any in-progress edits
                    // in the sibling claims editor.
                    session.toast_success("Notification emails saved.");
                }
                Err(e) => {
                    session.toast_error(e.message, None);
                }
            }
            busy.set(false);
        });
    };
    let save_claims = move || {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        needs_consent.set(false);
        let tenant_id = tenant_id.get_value();
        let sp_id = sp_id.get_value();
        let policy = claims_state.to_dto();
        leptos::task::spawn_local(async move {
            match sso::set_claims_mapping(&tenant_id, &sp_id, "Custom claims", &policy).await {
                Ok(_) => {
                    session.toast_success("Attributes & claims saved.");
                    reload.update(|n| *n = n.wrapping_add(1));
                }
                Err(e) => {
                    if e.code == "consent_required" {
                        needs_consent.set(true);
                    }
                    session.toast_error(e.message, None);
                }
            }
            busy.set(false);
        });
    };
    let grant_consent = move |_| {
        let tenant_id = tenant_id.get_value();
        busy.set(true);
        leptos::task::spawn_local(async move {
            match crate::bindings::auth::request_scope_consent(&tenant_id, "policy_write").await {
                Ok(()) => {
                    needs_consent.set(false);
                    session.toast_success("Consent granted. Save again to apply your claims.");
                }
                Err(e) => {
                    session.toast_error(e.message, None);
                }
            }
            busy.set(false);
        });
    };

    let mode_label = cfg
        .sso_mode
        .clone()
        .unwrap_or_else(|| "not configured".to_string());

    view! {
        <div class="sso-tab">
            <dl class="read-field">
                <dt>"SSO mode"</dt>
                <dd>{mode_label}</dd>
            </dl>

            // ---- editable config ----
            <Show when=move || !is_oidc fallback=|| ()>
                <h4>"SAML configuration"</h4>
                <Field label="Identifier (Entity ID)">
                    <Input value=entity_id />
                </Field>
                <Field label="Reply URL (ACS)">
                    <Input value=reply_url />
                </Field>
                <Field label="Logout URL">
                    <Input value=logout_url />
                </Field>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(save_saml_urls)
                    disabled=Signal::derive(move || busy.get())
                >
                    "Save URLs"
                </Button>

                <h4>"Signing certificate"</h4>
                <Field label="Certificate subject (e.g. CN=Contoso)">
                    <Input value=cert_subject />
                </Field>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(rotate_cert)
                    disabled=Signal::derive(move || busy.get())
                >
                    "Generate new signing certificate"
                </Button>
                {move || {
                    rotated_cert
                        .get()
                        .map(|c| {
                            view! {
                                <pre class="secret-reveal">{c}</pre>
                            }
                        })
                }}

                <h4>"Signing-certificate notification emails"</h4>
                <Field label="Notification emails (one per line, max 5)">
                    <Textarea value=notification_emails />
                </Field>
                <Body1 class="hint">
                    "Entra emails these addresses 60/30/7 days before the SAML signing certificate expires. After saving, open the app's SSO blade in the Entra admin center once so Entra enables the notifications."
                </Body1>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(save_notification_emails)
                    disabled=Signal::derive(move || busy.get())
                >
                    "Save notification emails"
                </Button>

                <h4>"Attributes & claims"</h4>
                <ClaimsEditor state=claims_state />
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| save_claims())
                    disabled=Signal::derive(move || busy.get())
                >
                    "Save claims"
                </Button>
                {move || {
                    needs_consent
                        .get()
                        .then(|| {
                            view! {
                                <div class="alert alert--warn">
                                    "Custom claims need admin consent for Policy.ReadWrite.ApplicationConfiguration."
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(grant_consent)
                                        disabled=Signal::derive(move || busy.get())
                                    >
                                        "Grant admin consent"
                                    </Button>
                                </div>
                            }
                        })
                }}
            </Show>
            <Show when=move || is_oidc fallback=|| ()>
                <h4>"OIDC configuration"</h4>
                <Field label="Redirect URIs (web — one per line)">
                    <Textarea value=redirect_uris />
                </Field>
                <Field label="Redirect URIs (SPA — one per line)">
                    <Textarea value=spa_uris />
                </Field>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(save_oidc_uris)
                    disabled=Signal::derive(move || busy.get())
                >
                    "Save redirect URIs"
                </Button>
            </Show>

            // ---- app-owner summary ----
            <h4>"Details for the application owner"</h4>
            <Suspense fallback=move || {
                view! {
                    <div class="centered-pad">
                        <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                    </div>
                }
            }>
                {move || Suspend::new(async move {
                    match summary.await {
                        Err(e) => {
                            view! { <div class="alert alert--warn">{e.message}</div> }.into_any()
                        }
                        Ok(value) => {
                            if is_oidc {
                                match serde_json::from_value::<OidcSsoSummary>(value) {
                                    Ok(s) => view! { <OidcSummaryView summary=s /> }.into_any(),
                                    Err(_) => view! { <Body1>"Summary unavailable."</Body1> }.into_any(),
                                }
                            } else {
                                match serde_json::from_value::<SamlSsoSummary>(value) {
                                    Ok(s) => view! { <SamlSummaryView summary=s /> }.into_any(),
                                    Err(_) => view! { <Body1>"Summary unavailable."</Body1> }.into_any(),
                                }
                            }
                        }
                    }
                })}
            </Suspense>
        </div>
    }
}

/// Splits a textarea (one entry per line) into a trimmed, non-empty Vec.
fn split_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}
