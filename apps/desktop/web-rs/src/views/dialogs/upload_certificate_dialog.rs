//! Upload a certificate (file picker or pasted PEM / base64-DER) onto an
//! application.

use leptos::html;
use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize, Textarea};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;

use crate::bindings::applications::{self, AddCertificateInput};
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_focus_trap::use_focus_trap;
use crate::state::use_session;
use crate::util::cert_payload_from_bytes;

#[component]
pub fn UploadCertificateDialog(
    #[prop(into)] open: Signal<bool>,
    #[prop(into)] object_id: Signal<String>,
    #[prop(into)] on_close: Callback<()>,
    #[prop(into)] on_uploaded: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let display_name = RwSignal::new(String::new());
    let pem = RwSignal::new(String::new());
    let file_name: RwSignal<Option<String>> = RwSignal::new(None);
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    use_escape(
        move || open.get_untracked() && !busy.get_untracked(),
        move || on_close.run(()),
    );
    let modal_ref: NodeRef<html::Div> = NodeRef::new();
    use_focus_trap(modal_ref, open);

    // Reads the chosen file (binary-safe: .cer/.crt may be raw DER) and fills
    // the paste box with the normalized payload, prefilling an empty display
    // name from the file stem.
    let on_file_change = move |ev: leptos::ev::Event| {
        let Some(input) = ev
            .target()
            .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        else {
            return;
        };
        let Some(file) = input.files().and_then(|files| files.get(0)) else {
            return;
        };
        let name = file.name();
        leptos::task::spawn_local(async move {
            match JsFuture::from(file.array_buffer()).await {
                Ok(buf) => {
                    let bytes = js_sys::Uint8Array::new(&buf).to_vec();
                    pem.set(cert_payload_from_bytes(&bytes));
                    if display_name.get_untracked().trim().is_empty() {
                        let stem = name.rsplit_once('.').map_or(name.as_str(), |(s, _)| s);
                        display_name.set(stem.to_string());
                    }
                    file_name.set(Some(name));
                    error.set(None);
                }
                Err(_) => error.set(Some("Could not read the selected file.".to_string())),
            }
        });
    };

    let upload = move |_| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let tenant = session.active_tenant.get();
        let id = object_id.get();
        let dn = display_name.get();
        let body = pem.get();
        let on_close_cb = on_close;
        let on_uploaded_cb = on_uploaded;
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                busy.set(false);
                return;
            };
            let input = AddCertificateInput {
                display_name: dn.trim().to_string(),
                pem_or_base64: body,
                end_date_time: None,
            };
            match applications::add_certificate_credential(&t.tenant_id, &id, &input).await {
                Ok(()) => {
                    display_name.set(String::new());
                    pem.set(String::new());
                    file_name.set(None);
                    on_uploaded_cb.run(());
                    on_close_cb.run(());
                }
                Err(e) => error.set(Some(e.message)),
            }
            busy.set(false);
        });
    };

    view! {
        <Show when=move || open.get() fallback=|| view! { <></> }>
            <div
                class="modal-backdrop"
                role="dialog"
                aria-modal="true"
                aria-labelledby="upload-cert-dialog-title"
            >
                <div class="modal modal--wide" node_ref=modal_ref>
                    <h3 id="upload-cert-dialog-title">"Upload certificate"</h3>
                    <Body1>
                        "Choose a .cer, .pem, or .crt file — or paste a PEM block / base64-encoded DER. Graph derives the expiry from the certificate."
                    </Body1>
                    <Field label="Certificate file">
                        <input
                            type="file"
                            accept=".cer,.pem,.crt"
                            class="file-input"
                            on:change=on_file_change
                        />
                    </Field>
                    {move || {
                        file_name
                            .get()
                            .map(|n| view! { <Body1 class="hint mono">{format!("Loaded: {n}")}</Body1> })
                    }}
                    <Field label="Display name">
                        <Input value=display_name />
                    </Field>
                    <Field label="…or paste PEM / base64">
                        <Textarea value=pem />
                    </Field>
                    {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| on_close.run(()))
                            disabled=Signal::derive(move || busy.get())
                        >
                            "Cancel"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(upload)
                            disabled=Signal::derive(move || busy.get())
                        >
                            {move || {
                                if busy.get() {
                                    view! {
                                        <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                    }
                                        .into_any()
                                } else {
                                    view! { "Upload" }.into_any()
                                }
                            }}
                        </Button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
