use super::*;

use crate::hooks::use_command::use_command;

/// SSO configuration for the enterprise app — view/edit the SAML or OIDC setup
/// and surface the app-owner output summary. Reads `get_sso_config`; edits go
/// through the per-field SSO commands and bump a local `reload`.
#[component]
pub(super) fn SsoContent(signal: Signal<Arc<EnterpriseApplicationDetail>>) -> impl IntoView {
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
                <DetailSkeleton />
            }
        }>
            {move || Suspend::new(async move {
                match config.await {
                    Err(e) => {
                        view! {
                            <DetailLoadError
                                error=e
                                on_retry=Callback::new(move |_| reload.update(|n| *n += 1))
                            />
                        }
                            .into_any()
                    }
                    Ok(cfg) => view! { <SsoEditor cfg=cfg reload=reload /> }.into_any(),
                }
            })}
        </Suspense>
    }
}

/// Inner SSO editor, seeded from the loaded [`SsoConfigDto`]. A method selector
/// sets `preferredSingleSignOnMode`; the editable fields then branch on the
/// *saved* mode (SAML / OIDC / not-configured). Renders the app-owner summary
/// fetched via `get_sso_summary`.
#[component]
fn SsoEditor(cfg: SsoConfigDto, reload: RwSignal<u32>) -> impl IntoView {
    let session = use_session();
    let tenant_id = session
        .active_tenant
        .get_untracked()
        .map(|t| t.tenant_id)
        .unwrap_or_default();

    let is_oidc = cfg.sso_mode.as_deref() == Some("oidc");
    let is_saml = cfg.sso_mode.as_deref() == Some("saml");
    let configured = is_saml || is_oidc;
    let protocol = if is_oidc { "oidc" } else { "saml" };
    let saved_mode_label = cfg
        .sso_mode
        .clone()
        .unwrap_or_else(|| "not configured".to_string());
    // Held in `StoredValue` (Copy) so the on_click handlers below capture only
    // Copy state and stay `Fn` — Leptos `<Show>` children must be re-callable.
    let tenant_id = StoredValue::new(tenant_id);
    let object_id = StoredValue::new(cfg.object_id.clone());
    let sp_id = StoredValue::new(cfg.service_principal_id.clone());

    // Method selector — seeded to the saved mode; "disabled" clears SSO.
    let selected_mode = RwSignal::new(match cfg.sso_mode.as_deref() {
        Some("saml") => "saml".to_string(),
        Some("oidc") => "oidc".to_string(),
        _ => "disabled".to_string(),
    });
    let mode_cmd = use_command();

    // SAML editable fields — one row per entry (`components::uri_list_editor`),
    // the same editor the App Registration Authentication tab uses.
    // Identifiers get NO validator: a SAML Entity ID is routinely a bare
    // `urn:`, which the redirect rules reject on purpose. Reply URLs are
    // genuine redirect URIs and do take them.
    let identifiers = UriListState::new(&cfg.identifier_uris);
    let reply_urls = UriListState::validated(&cfg.reply_urls, redirect_uri_reason);
    let logout_url = RwSignal::new(cfg.logout_url.clone().unwrap_or_default());
    // SAML signing-cert expiry notification recipients (one per line).
    let notification_emails = UriListState::new(&cfg.notification_emails);
    // OIDC editable fields (one URI per line).
    let redirect_uris = UriListState::validated(&cfg.redirect_uris, redirect_uri_reason);
    let spa_uris = UriListState::validated(&cfg.spa_redirect_uris, redirect_uri_reason);
    // Cert rotation.
    let cert_subject = RwSignal::new(String::new());
    let rotated_cert: RwSignal<Option<String>> = RwSignal::new(None);
    // Attributes & claims editor state, seeded from the assigned policy.
    let claims_state = ClaimsEditorState::from_dto(&cfg.claims_policy.clone().unwrap_or_default());

    let cmd = use_command();
    let needs_consent = RwSignal::new(false);

    // App-owner summary (read-only), recomputed on reload. Only fetched once SSO
    // is actually configured for SAML/OIDC (no point otherwise).
    let summary = LocalResource::new(move || {
        let tenant_id = tenant_id.get_value();
        let sp_id = sp_id.get_value();
        let _ = reload.get();
        async move {
            if configured {
                sso::get_sso_summary(&tenant_id, &sp_id, protocol).await
            } else {
                Ok(serde_json::Value::Null)
            }
        }
    });

    // Apply a new SSO method, then reload so the editor switches to it.
    let apply_mode = move |_| {
        mode_cmd.run_toast_err(
            move |()| {
                session.toast_success("Single sign-on method updated.");
                reload.update(|n| *n = n.wrapping_add(1));
            },
            move |tenant_id| {
                let sp_id = sp_id.get_value();
                let mode = selected_mode.get_untracked();
                async move { sso::set_sso_mode(&tenant_id, &sp_id, &mode).await }
            },
        );
    };

    // ---- save handlers (capture only Copy state → stay `Fn`). Errors surface
    // as toasts (no inline error signal), so these use `run_toast_err`; the
    // claims write branches on `consent_required`, so it uses `run_with`. ----
    let save_saml_urls = move |_| {
        cmd.run_toast_err(
            move |()| {
                session.toast_success("SAML configuration saved.");
                reload.update(|n| *n = n.wrapping_add(1));
            },
            move |tenant_id| {
                let object_id = object_id.get_value();
                let logout = {
                    let l = logout_url.get_untracked().trim().to_string();
                    (!l.is_empty()).then_some(l)
                };
                let ids = identifiers.to_uris();
                let replies = reply_urls.to_uris();
                async move {
                    sso::set_saml_urls(&tenant_id, &object_id, &ids, &replies, logout.as_deref())
                        .await
                }
            },
        );
    };

    let save_oidc_uris = move |_| {
        cmd.run_toast_err(
            move |()| {
                session.toast_success("Redirect URIs saved.");
                reload.update(|n| *n = n.wrapping_add(1));
            },
            move |tenant_id| {
                let object_id = object_id.get_value();
                let web = redirect_uris.to_uris();
                let spa = spa_uris.to_uris();
                async move { sso::set_oidc_redirect_uris(&tenant_id, &object_id, &web, &spa).await }
            },
        );
    };

    let rotate_cert = move |_| {
        cmd.run_toast_err(
            move |cert: sso::SsoCertResult| {
                session.toast_success(format!("New signing certificate: {}", cert.thumbprint));
                rotated_cert.set(cert.base64);
                reload.update(|n| *n = n.wrapping_add(1));
            },
            move |tenant_id| {
                let sp_id = sp_id.get_value();
                let subject = cert_subject.get_untracked().trim().to_string();
                async move {
                    sso::rotate_saml_signing_certificate(&tenant_id, &sp_id, &subject, None).await
                }
            },
        );
    };

    // Save the SAML cert-expiry notification recipients (separate SP write — no
    // claims-write consent needed).
    let save_notification_emails = move |_| {
        cmd.run_toast_err(
            move |()| {
                // Deliberately do NOT bump `reload` here: the textarea already
                // shows the saved value, and reloading would tear down the
                // Suspense subtree and discard any in-progress edits in the
                // sibling claims editor.
                session.toast_success("Notification emails saved.");
            },
            move |tenant_id| {
                let sp_id = sp_id.get_value();
                let emails = notification_emails.to_uris();
                async move { sso::set_notification_emails(&tenant_id, &sp_id, &emails).await }
            },
        );
    };
    let save_claims = move || {
        needs_consent.set(false);
        let policy = claims_state.to_dto();
        cmd.run_with(
            move |_saved: Option<String>| {
                session.toast_success("Attributes & claims saved.");
                reload.update(|n| *n = n.wrapping_add(1));
            },
            move |e| {
                if e.code == "consent_required" {
                    needs_consent.set(true);
                }
                session.report_command_error(&e);
            },
            move |tenant_id| {
                let sp_id = sp_id.get_value();
                async move {
                    sso::set_claims_mapping(&tenant_id, &sp_id, "Custom claims", &policy).await
                }
            },
        );
    };
    let grant_consent = move |_| {
        cmd.run_toast_err(
            move |()| {
                needs_consent.set(false);
                session.toast_success("Consent granted. Save again to apply your claims.");
            },
            move |tenant_id| async move {
                crate::bindings::auth::request_scope_consent(&tenant_id, "policy_write").await
            },
        );
    };

    view! {
        <div class="sso-tab">
            <h4>"Single sign-on method"</h4>
            <dl class="read-field">
                <dt>"Current method"</dt>
                <dd>{saved_mode_label}</dd>
            </dl>
            <Field label="Set sign-on method">
                <select
                    class="ui-select"
                    on:change=move |ev| selected_mode.set(event_target_value(&ev))
                >
                    <option value="saml" selected=is_saml>
                        "SAML"
                    </option>
                    <option value="oidc" selected=is_oidc>
                        "OIDC / OpenID Connect"
                    </option>
                    <option value="disabled" selected=!configured>
                        "Disabled"
                    </option>
                </select>
            </Field>
            <Button
                appearance=Signal::derive(|| ButtonAppearance::Primary)
                on_click=Box::new(apply_mode)
                disabled=Signal::derive(move || mode_cmd.busy.get())
            >
                "Apply method"
            </Button>
            <Body1 class="hint">
                "Password-based and linked single sign-on are configured in the Microsoft Entra admin center, not here."
            </Body1>

            // ---- editable config (branches on the SAVED mode) ----
            <Show when=move || is_saml fallback=|| ()>
                <h4>"SAML configuration"</h4>
                <UriListEditor
                    state=identifiers
                    class="uri-list--saml-identifiers"
                    label="Identifiers (Entity IDs)"
                    noun="identifier"
                    placeholder="https://saml.contoso.com/sp"
                />
                <UriListEditor
                    state=reply_urls
                    class="uri-list--saml-reply"
                    label="Reply URLs (ACS)"
                    noun="reply URL"
                    placeholder="https://saml.contoso.com/acs"
                />
                <Field label="Logout URL">
                    <Input value=logout_url />
                </Field>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(save_saml_urls)
                    disabled=Signal::derive(move || cmd.busy.get())
                >
                    "Save SAML URLs"
                </Button>

                <h4>"Signing certificate"</h4>
                <Field label="Certificate subject (e.g. CN=Contoso)">
                    <Input value=cert_subject />
                </Field>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                    on_click=Box::new(rotate_cert)
                    disabled=Signal::derive(move || cmd.busy.get())
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
                <UriListEditor
                    state=notification_emails
                    class="uri-list--notification-emails"
                    label="Notification emails (max 5)"
                    noun="notification email"
                    placeholder="identity-team@contoso.com"
                />
                <Body1 class="hint">
                    "Entra emails these addresses 60/30/7 days before the SAML signing certificate expires. After saving, open the app's SSO blade in the Entra admin center once so Entra enables the notifications."
                </Body1>
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(save_notification_emails)
                    disabled=Signal::derive(move || cmd.busy.get())
                >
                    "Save notification emails"
                </Button>

                <h4>"Attributes & claims"</h4>
                <ClaimsEditor state=claims_state />
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| save_claims())
                    disabled=Signal::derive(move || cmd.busy.get())
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
                                        disabled=Signal::derive(move || cmd.busy.get())
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
                <UriListEditor
                    state=redirect_uris
                    class="uri-list--oidc-web"
                    label="Redirect URIs (web)"
                    noun="web redirect URI"
                    placeholder="https://contoso.com/signin-oidc"
                />
                <UriListEditor
                    state=spa_uris
                    class="uri-list--oidc-spa"
                    label="Redirect URIs (SPA)"
                    noun="SPA redirect URI"
                    placeholder="https://contoso.com/"
                />
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(save_oidc_uris)
                    disabled=Signal::derive(move || cmd.busy.get())
                >
                    "Save redirect URIs"
                </Button>
            </Show>

            // Nothing editable here for unconfigured / password / linked SSO.
            {(!configured)
                .then(|| {
                    view! {
                        <div class="alert alert--warn">
                            "Single sign-on isn't set to SAML or OIDC for this application. Choose a method above and select \"Apply method\" to configure it here."
                        </div>
                    }
                })}

            // ---- app-owner summary (only once SSO is configured) ----
            {configured
                .then(|| {
                    view! {
                        <h4>"Details for the application owner"</h4>
                        <Suspense fallback=move || {
                            view! { <SkeletonList rows=3 /> }
                        }>
                            {move || Suspend::new(async move {
                                match summary.await {
                                    Err(e) => {
                                        view! { <div class="alert alert--warn">{e.message}</div> }
                                            .into_any()
                                    }
                                    Ok(value) => {
                                        if is_oidc {
                                            match serde_json::from_value::<OidcSsoSummary>(value) {
                                                Ok(s) => view! { <OidcSummaryView summary=s /> }.into_any(),
                                                Err(_) => {
                                                    view! { <Body1>"Summary unavailable."</Body1> }.into_any()
                                                }
                                            }
                                        } else {
                                            match serde_json::from_value::<SamlSsoSummary>(value) {
                                                Ok(s) => view! { <SamlSummaryView summary=s /> }.into_any(),
                                                Err(_) => {
                                                    view! { <Body1>"Summary unavailable."</Body1> }.into_any()
                                                }
                                            }
                                        }
                                    }
                                }
                            })}
                        </Suspense>
                    }
                })}
        </div>
    }
}
