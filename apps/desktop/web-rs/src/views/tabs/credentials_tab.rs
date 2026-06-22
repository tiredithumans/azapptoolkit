//! Credentials tab. Lists secrets + certificates for an app, lets you add /
//! remove / sweep expired.

use chrono::NaiveDate;
use leptos::prelude::*;
use thaw::{
    Body1, Button, ButtonAppearance, DatePicker, Field, Input, Select, Spinner, SpinnerSize,
};

use wasm_bindgen_futures::JsFuture;

use crate::bindings::applications::{
    self, AddPasswordInput, ApplicationDetail, GenerateCertificateInput,
    GeneratedCertificateResult, RemoveExpiredResult,
};
use crate::bindings::keyvault::{self, RotateCredentialInput, RotateCredentialResult};
use crate::components::modal_shell::ModalShell;
use crate::components::ui::CopyableId;
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;
use crate::views::dialogs::secret_reveal_dialog::SecretRevealDialog;
use crate::views::dialogs::upload_certificate_dialog::UploadCertificateDialog;
use crate::views::tabs::federated_tab::FederatedTab;

const WARN_DAYS: i64 = 30;
const CRITICAL_DAYS: i64 = 7;

fn days_until(end: Option<chrono::DateTime<chrono::Utc>>) -> Option<i64> {
    let end = end?;
    let now = chrono::Utc::now();
    Some((end - now).num_days())
}

fn status_label(days: Option<i64>) -> (&'static str, &'static str) {
    match days {
        None => ("Unknown", "badge--unknown"),
        Some(d) if d < 0 => ("Expired", "badge--danger"),
        Some(d) if d <= CRITICAL_DAYS => ("Critical", "badge--danger"),
        Some(d) if d <= WARN_DAYS => ("Warning", "badge--warning"),
        Some(_) => ("OK", "badge--ok"),
    }
}

/// The days-until-expiry status badge, shared by the secrets and certificates
/// tables (the days-remaining text and the urgency class come from the same
/// `status_label` thresholds).
fn status_badge(days: Option<i64>) -> impl IntoView {
    let (status, badge_class) = status_label(days);
    view! {
        <span class=format!("badge {badge_class}")>
            {match days {
                None => status.to_string(),
                Some(d) if d < 0 => "Expired".into(),
                Some(d) => format!("{d}d left"),
            }}
        </span>
    }
}

/// A credential Remove button shared by the secrets and certificates tables:
/// shows a spinner while *this* key is being removed (the in-flight `removing`
/// signal) and stages `key_id` into `pending` for the confirm dialog.
fn remove_button(
    removing: RwSignal<Option<String>>,
    pending: RwSignal<Option<String>>,
    key_id: String,
) -> impl IntoView {
    let key_disabled = key_id.clone();
    let key_click = key_id.clone();
    let key_label = key_id;
    view! {
        <Button
            class="button--danger"
            appearance=Signal::derive(|| ButtonAppearance::Subtle)
            disabled=Signal::derive(move || {
                removing.with(|r| r.as_deref() == Some(key_disabled.as_str()))
            })
            on_click=Box::new(move |_| pending.set(Some(key_click.clone())))
        >
            {move || {
                if removing.with(|r| r.as_deref() == Some(key_label.as_str())) {
                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }.into_any()
                } else {
                    view! { "Remove" }.into_any()
                }
            }}
        </Button>
    }
}

/// `localStorage` key for the last Key Vault a rotation wrote to, scoped per
/// tenant so a remembered vault never leaks across tenants (the same
/// scoping `SavedViews` uses).
fn last_vault_key(tenant_id: &str) -> String {
    format!("azapptoolkit:lastvault:{tenant_id}")
}

fn ls_get(key: &str) -> Option<String> {
    web_sys::window()?
        .local_storage()
        .ok()
        .flatten()?
        .get_item(key)
        .ok()
        .flatten()
}

fn ls_set(key: &str, value: &str) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.set_item(key, value);
    }
}

/// The portal's "Expires" presets for a new client secret: label + lifetime in
/// days, with "Custom" (start/end pickers) as the escape hatch. 180 days is
/// the portal's recommended default; 730 (24 months) is the hard cap.
const EXPIRES_PRESETS: &[(&str, &str)] = &[
    ("180", "Recommended: 180 days (6 months)"),
    ("90", "90 days (3 months)"),
    ("365", "365 days (12 months)"),
    ("545", "545 days (18 months)"),
    ("730", "730 days (24 months)"),
    ("custom", "Custom"),
];

const CUSTOM_PRESET: &str = "custom";
const MAX_SECRET_LIFETIME_DAYS: i64 = 730;

/// `AddPasswordInput`'s `(lifetime_days, start_date_time, end_date_time)`.
type ExpiryFields = (
    Option<u32>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
);

/// Resolves the Expires controls into `AddPasswordInput`'s
/// `(lifetime_days, start_date_time, end_date_time)`. Mirrors the backend's
/// validation (end after start, 24-month cap) for friendlier, pre-submit
/// errors; dates resolve to midnight UTC, like the portal.
fn resolve_expiry_fields(
    preset: &str,
    start: Option<NaiveDate>,
    end: Option<NaiveDate>,
    today: NaiveDate,
) -> Result<ExpiryFields, String> {
    if preset != CUSTOM_PRESET {
        let days = preset
            .parse::<u32>()
            .map_err(|_| "Choose an expiry option.".to_string())?;
        return Ok((Some(days), None, None));
    }
    let end = end.ok_or_else(|| "Choose an end date.".to_string())?;
    let effective_start = start.unwrap_or(today);
    if end <= effective_start {
        return Err("End date must be after the start date.".to_string());
    }
    if (end - effective_start).num_days() > MAX_SECRET_LIFETIME_DAYS {
        return Err("Secret lifetime cannot exceed 24 months.".to_string());
    }
    // Midnight construction never fails on a valid NaiveDate, so to_utc is
    // total in practice.
    let to_utc = |d: NaiveDate| d.and_hms_opt(0, 0, 0).map(|dt| dt.and_utc());
    Ok((None, start.and_then(to_utc), to_utc(end)))
}

/// Derives a valid Key Vault secret name from an app's display name. Vault
/// secret names allow only `[0-9a-zA-Z-]`, so the raw display name (spaces,
/// punctuation) can't be used directly; everything else is stripped, falling
/// back to a safe default when nothing usable remains.
fn sanitize_secret_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    if cleaned.is_empty() {
        "client-secret".to_string()
    } else {
        cleaned
    }
}

#[component]
pub fn CredentialsTab(
    #[prop(into)] detail: Signal<ApplicationDetail>,
    #[prop(into)] on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let object_id = Signal::derive(move || detail.with(|d| d.application.id.clone()));
    let secrets =
        Signal::derive(move || detail.with(|d| d.application.password_credentials.clone()));
    let certs = Signal::derive(move || detail.with(|d| d.application.key_credentials.clone()));

    let add_open = RwSignal::new(false);
    let display_name = RwSignal::new("client-secret".to_string());
    let expires_preset = RwSignal::new("180".to_string());
    let today = chrono::Utc::now().date_naive();
    let custom_start: RwSignal<Option<NaiveDate>> = RwSignal::new(Some(today));
    let custom_end: RwSignal<Option<NaiveDate>> =
        RwSignal::new(Some(today + chrono::Duration::days(180)));
    // One inline `error` signal shared by every credential mutation (rendered
    // once below). Each command keeps its own `bool` busy guard, so it gets a
    // dedicated `use_command` handle whose errors route into this shared signal
    // via `run_with`. The per-row `removing`/`removing_cert` handlers track an
    // in-flight key id (`Option<String>`), which doesn't fit `CommandState`'s
    // `bool` busy, so they stay hand-rolled.
    let cmd_create = use_command();
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let revealed: RwSignal<Option<String>> = RwSignal::new(None);
    let removing: RwSignal<Option<String>> = RwSignal::new(None);
    let cert_open = RwSignal::new(false);
    let removing_cert: RwSignal<Option<String>> = RwSignal::new(None);
    let cmd_expire = use_command();
    let expired_result: RwSignal<Option<RemoveExpiredResult>> = RwSignal::new(None);
    let pending_secret: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_cert: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_expired = RwSignal::new(false);

    let rotate_open = RwSignal::new(false);
    let rotate_vault = RwSignal::new(String::new());
    let rotate_secret_name = RwSignal::new(String::new());
    let rotate_lifetime = RwSignal::new("180".to_string());
    let cmd_rotate = use_command();
    let rotate_result: RwSignal<Option<RotateCredentialResult>> = RwSignal::new(None);

    let app_name = Signal::derive(move || detail.with(|d| d.application.display_name.clone()));
    // Opens the rotate dialog with smart prefills: the vault remembered from the
    // last rotation in this tenant, and a Key-Vault-safe secret name derived from
    // the app name. Only fills empty fields so an in-progress edit is preserved.
    // Shared by the section header button and the per-row "Rotate" shortcut.
    let open_rotate = move || {
        let tid = session
            .active_tenant
            .get()
            .map(|t| t.tenant_id)
            .unwrap_or_default();
        if rotate_vault.get_untracked().trim().is_empty() {
            if let Some(last) = ls_get(&last_vault_key(&tid)) {
                rotate_vault.set(last);
            }
        }
        if rotate_secret_name.get_untracked().trim().is_empty() {
            rotate_secret_name.set(sanitize_secret_name(&app_name.get_untracked()));
        }
        rotate_open.set(true);
    };

    let gencert_open = RwSignal::new(false);
    let gencert_subject = RwSignal::new(detail.with(|d| d.application.display_name.clone()));
    let gencert_validity = RwSignal::new("365".to_string());
    let cmd_gencert = use_command();
    let gencert_result: RwSignal<Option<GeneratedCertificateResult>> = RwSignal::new(None);

    let expired_count = Signal::derive(move || {
        secrets.with(|list| {
            list.iter()
                .filter(|s| matches!(days_until(s.end_date_time), Some(d) if d < 0))
                .count()
        })
    });

    let create_secret = move |_| {
        // Pre-submit validation mirrors the backend; on failure surface the
        // message in the shared `error` signal and don't dispatch the command.
        error.set(None);
        let id = object_id.get();
        let dn = display_name.get();
        let (lifetime_days, start_date_time, end_date_time) = match resolve_expiry_fields(
            &expires_preset.get(),
            custom_start.get(),
            custom_end.get(),
            chrono::Utc::now().date_naive(),
        ) {
            Ok(fields) => fields,
            Err(msg) => {
                error.set(Some(msg));
                return;
            }
        };
        let on_changed_cb = on_changed;
        cmd_create.run_with(
            move |cred: azapptoolkit_core::models::PasswordCredential| {
                add_open.set(false);
                // Defer the detail reload until the reveal dialog is dismissed: the
                // reload re-runs the resource this whole subtree (incl. our local
                // `revealed` signal) is built from, which would tear the dialog down
                // before the user can copy the one-time secret value.
                match cred.secret_text {
                    Some(text) => revealed.set(Some(text)),
                    None => on_changed_cb.run(()),
                }
            },
            move |e| error.set(Some(e.message)),
            move |tenant_id| {
                let input = AddPasswordInput {
                    display_name: dn.trim().to_string(),
                    lifetime_days,
                    start_date_time,
                    end_date_time,
                };
                async move { applications::add_password(&tenant_id, &id, &input).await }
            },
        );
    };

    let remove_secret = move |key_id: String| {
        if removing.get().is_some() {
            return;
        }
        removing.set(Some(key_id.clone()));
        error.set(None);
        let tenant = session.active_tenant.get();
        let id = object_id.get();
        let on_changed_cb = on_changed;
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                removing.set(None);
                return;
            };
            match applications::remove_password(&t.tenant_id, &id, &key_id).await {
                Ok(()) => {
                    session.toast_success("Secret removed.");
                    on_changed_cb.run(());
                }
                Err(e) => error.set(Some(e.message)),
            }
            removing.set(None);
        });
    };

    let remove_cert = move |key_id: String| {
        if removing_cert.get().is_some() {
            return;
        }
        removing_cert.set(Some(key_id.clone()));
        error.set(None);
        let tenant = session.active_tenant.get();
        let id = object_id.get();
        let on_changed_cb = on_changed;
        leptos::task::spawn_local(async move {
            let Some(t) = tenant else {
                removing_cert.set(None);
                return;
            };
            match applications::remove_certificate_credential(&t.tenant_id, &id, &key_id).await {
                Ok(()) => {
                    session.toast_success("Certificate removed.");
                    on_changed_cb.run(());
                }
                Err(e) => error.set(Some(e.message)),
            }
            removing_cert.set(None);
        });
    };

    let remove_expired = move |_| {
        error.set(None);
        let id = object_id.get();
        let on_changed_cb = on_changed;
        cmd_expire.run_with(
            move |r| {
                expired_result.set(Some(r));
                on_changed_cb.run(());
            },
            move |e| error.set(Some(e.message)),
            move |tenant_id| async move {
                applications::remove_expired_passwords(&tenant_id, &id).await
            },
        );
    };

    let do_rotate = move |remove_existing: bool| {
        error.set(None);
        rotate_result.set(None);
        let id = object_id.get();
        let vault = rotate_vault.get().trim().to_string();
        let secret_name = rotate_secret_name.get().trim().to_string();
        // Required-field validation runs before dispatch (was inside the spawn);
        // surface it in the shared `error` signal and don't dispatch.
        if vault.is_empty() || secret_name.is_empty() {
            error.set(Some("Vault name and secret name are required.".into()));
            return;
        }
        let days = rotate_lifetime
            .get()
            .parse::<u32>()
            .unwrap_or(180)
            .clamp(1, 730);
        let remove_key_ids: Vec<String> = if remove_existing {
            secrets.with(|list| list.iter().map(|s| s.key_id.clone()).collect())
        } else {
            Vec::new()
        };
        let on_changed_cb = on_changed;
        cmd_rotate.run_with(
            move |r: RotateCredentialResult| {
                rotate_open.set(false);
                // Remember the vault (tenant-scoped) so the next rotation in
                // this tenant prefills it.
                if let Some(t) = session.active_tenant.get_untracked() {
                    ls_set(&last_vault_key(&t.tenant_id), &r.vault_name);
                }
                rotate_result.set(Some(r));
                on_changed_cb.run(());
            },
            move |e| error.set(Some(e.message)),
            move |tenant_id| {
                let input = RotateCredentialInput {
                    object_id: id,
                    vault_name: vault,
                    secret_name,
                    lifetime_days: Some(days),
                    remove_key_ids,
                };
                async move { keyvault::rotate_app_credential(&tenant_id, &input).await }
            },
        );
    };

    let do_generate_cert = move |_| {
        error.set(None);
        let id = object_id.get();
        let subject = gencert_subject.get().trim().to_string();
        // Required-field validation runs before dispatch (was inside the spawn);
        // surface it in the shared `error` signal and don't dispatch.
        if subject.is_empty() {
            error.set(Some("Subject (common name) is required.".into()));
            return;
        }
        let days = gencert_validity
            .get()
            .parse::<u32>()
            .unwrap_or(365)
            .clamp(1, 1095);
        let on_changed_cb = on_changed;
        cmd_gencert.run_with(
            move |r| {
                gencert_open.set(false);
                gencert_result.set(Some(r));
                on_changed_cb.run(());
            },
            move |e| error.set(Some(e.message)),
            move |tenant_id| {
                let input = GenerateCertificateInput {
                    object_id: id,
                    subject,
                    validity_days: Some(days),
                };
                async move {
                    applications::generate_self_signed_certificate(&tenant_id, &input).await
                }
            },
        );
    };

    view! {
        <div class="credentials-tab">
            <section>
                <header class="row-between">
                    <strong>{move || format!("Secrets ({})", secrets.with(Vec::len))}</strong>
                    <div class="actions-row">
                        {move || {
                            let count = expired_count.get();
                            (count > 0)
                                .then(|| {
                                    view! {
                                        <Button
                                            class="button--danger"
                                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                            disabled=Signal::derive(move || cmd_expire.busy.get())
                                            on_click=Box::new(move |_| pending_expired.set(true))
                                        >
                                            {move || {
                                                if cmd_expire.busy.get() {
                                                    view! {
                                                        <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                                    }
                                                        .into_any()
                                                } else {
                                                    format!("Remove {count} expired").into_any()
                                                }
                                            }}
                                        </Button>
                                    }
                                })
                        }}
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| open_rotate())
                        >
                            "Rotate into Key Vault…"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(move |_| add_open.set(true))
                        >
                            "+ New secret"
                        </Button>
                    </div>
                </header>
                {move || {
                    let secrets = secrets.get();
                    if secrets.is_empty() {
                        view! { <Body1>"No secrets."</Body1> }.into_any()
                    } else {
                        view! {
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>"Description"</th>
                                        <th>"Hint"</th>
                                        <th>"Secret ID"</th>
                                        <th>"Expires"</th>
                                        <th>"Status"</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {secrets
                                        .into_iter()
                                        .map(|s| {
                                            let days = days_until(s.end_date_time);
                                            // Offer the rotate shortcut on secrets that are
                                            // expiring soon or already expired — where rotation
                                            // is the relevant action.
                                            let near_expiry = matches!(days, Some(d) if d <= WARN_DAYS);
                                            view! {
                                                <tr>
                                                    <td>{s.display_name.clone().unwrap_or_else(|| "—".into())}</td>
                                                    <td class="mono">
                                                        {s.hint
                                                            .clone()
                                                            .map(|h| format!("{h}********"))
                                                            .unwrap_or_else(|| "—".into())}
                                                    </td>
                                                    <td>
                                                        <CopyableId value=s.key_id.clone() label="secret ID" />
                                                    </td>
                                                    <td>
                                                        {s
                                                            .end_date_time
                                                            .map(|d| d.date_naive().to_string())
                                                            .unwrap_or_else(|| "—".into())}
                                                    </td>
                                                    <td>{status_badge(days)}</td>
                                                    <td>
                                                        <div class="actions-row">
                                                            {near_expiry
                                                                .then(|| {
                                                                    view! {
                                                                        <Button
                                                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                            on_click=Box::new(move |_| open_rotate())
                                                                        >
                                                                            "Rotate"
                                                                        </Button>
                                                                    }
                                                                })}
                                                            {remove_button(removing, pending_secret, s.key_id.clone())}
                                                        </div>
                                                    </td>
                                                </tr>
                                            }
                                        })
                                        .collect_view()}
                                </tbody>
                            </table>
                        }
                            .into_any()
                    }
                }}
                {move || {
                    expired_result
                        .get()
                        .map(|r| {
                            let class = if r.failures.is_empty() {
                                "alert alert--ok"
                            } else {
                                "alert alert--warn"
                            };
                            view! {
                                <div class=class>
                                    {format!(
                                        "Removed {} expired secret(s){}",
                                        r.removed_key_ids.len(),
                                        if !r.failures.is_empty() {
                                            format!("; {} failed", r.failures.len())
                                        } else {
                                            String::new()
                                        },
                                    )}
                                </div>
                            }
                        })
                }}
                {move || {
                    rotate_result
                        .get()
                        .map(|r| {
                            let class = if r.warnings.is_empty() {
                                "alert alert--ok"
                            } else {
                                "alert alert--warn"
                            };
                            let msg = format!(
                                "Rotated into Key Vault “{}” as secret “{}”; new credential created, {} old removed{}.",
                                r.vault_name,
                                r.secret_name,
                                r.removed_key_ids.len(),
                                if r.warnings.is_empty() {
                                    String::new()
                                } else {
                                    format!(", {} warning(s)", r.warnings.len())
                                },
                            );
                            view! { <div class=class>{msg}</div> }
                        })
                }}
            </section>
            <section>
                <header class="row-between">
                    <strong>{move || format!("Certificates ({})", certs.with(Vec::len))}</strong>
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| gencert_open.set(true))
                        >
                            "Generate certificate…"
                        </Button>
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Primary)
                            on_click=Box::new(move |_| cert_open.set(true))
                        >
                            "+ Upload certificate"
                        </Button>
                    </div>
                </header>
                {move || {
                    let certs = certs.get();
                    if certs.is_empty() {
                        view! { <Body1>"No certificates."</Body1> }.into_any()
                    } else {
                        view! {
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>"Name"</th>
                                        <th>"Thumbprint"</th>
                                        <th>"Key ID"</th>
                                        <th>"Usage"</th>
                                        <th>"Type"</th>
                                        <th>"Expires"</th>
                                        <th>"Status"</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {certs
                                        .into_iter()
                                        .map(|c| {
                                            let days = days_until(c.end_date_time);
                                            let thumbprint = c
                                                .custom_key_identifier
                                                .as_deref()
                                                .and_then(crate::util::thumbprint_hex);
                                            view! {
                                                <tr>
                                                    <td>{c.display_name.clone().unwrap_or_else(|| "—".into())}</td>
                                                    <td>
                                                        {match thumbprint {
                                                            Some(tp) => view! {
                                                                <CopyableId value=tp label="thumbprint" />
                                                            }
                                                                .into_any(),
                                                            None => view! { "—" }.into_any(),
                                                        }}
                                                    </td>
                                                    <td>
                                                        <CopyableId value=c.key_id.clone() label="key ID" />
                                                    </td>
                                                    <td>{c.usage.clone().unwrap_or_else(|| "—".into())}</td>
                                                    <td>{c.r#type.clone().unwrap_or_else(|| "—".into())}</td>
                                                    <td>
                                                        {c
                                                            .end_date_time
                                                            .map(|d| d.date_naive().to_string())
                                                            .unwrap_or_else(|| "—".into())}
                                                    </td>
                                                    <td>{status_badge(days)}</td>
                                                    <td>
                                                        {remove_button(removing_cert, pending_cert, c.key_id.clone())}
                                                    </td>
                                                </tr>
                                            }
                                        })
                                        .collect_view()}
                                </tbody>
                            </table>
                        }
                            .into_any()
                    }
                }}
            </section>
            // Federated credentials are this app's third credential type
            // (secret-less workload identity federation), so they live alongside
            // secrets and certificates rather than in a separate tab. The section
            // keeps its own fetch/reload — federated creds aren't part of
            // ApplicationDetail.
            <section>
                <FederatedTab detail=detail />
            </section>
            <UploadCertificateDialog
                open=Signal::derive(move || cert_open.get())
                object_id=Signal::derive(move || object_id.get())
                on_close=Callback::new(move |()| cert_open.set(false))
                on_uploaded=on_changed
            />
            {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
            <ModalShell
                open=Signal::derive(move || add_open.get())
                title="New client secret"
                busy=Signal::derive(move || cmd_create.busy.get())
                on_close=Callback::new(move |()| add_open.set(false))
            >
                <Body1 class="hint">
                    "Consider a certificate or federated identity credential instead — \
                     they're more secure than client secrets, which shouldn't be used in production."
                </Body1>
                <Field label="Description">
                    <Input value=display_name />
                </Field>
                <Field label="Expires">
                    <Select value=expires_preset>
                        {EXPIRES_PRESETS
                            .iter()
                            .map(|(value, label)| {
                                view! { <option value=*value>{*label}</option> }
                            })
                            .collect_view()}
                    </Select>
                </Field>
                <Show
                    when=move || expires_preset.get() == CUSTOM_PRESET
                    fallback=|| view! { <></> }
                >
                    <Field label="Start date">
                        <DatePicker value=custom_start />
                    </Field>
                    <Field label="End date">
                        <DatePicker value=custom_end />
                    </Field>
                    <Body1 class="hint">
                        "Maximum 24 months; Microsoft recommends less than 12 months."
                    </Body1>
                </Show>
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| add_open.set(false))
                        disabled=Signal::derive(move || cmd_create.busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(create_secret)
                        disabled=Signal::derive(move || cmd_create.busy.get())
                    >
                        {move || {
                            if cmd_create.busy.get() {
                                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                    .into_any()
                            } else {
                                view! { "Create" }.into_any()
                            }
                        }}
                    </Button>
                </div>
            </ModalShell>
            {move || {
                revealed
                    .get()
                    .map(|secret| {
                        view! {
                            <SecretRevealDialog
                                secret_text=secret
                                on_close=Callback::new(move |()| {
                                    revealed.set(None);
                                    on_changed.run(());
                                })
                            />
                        }
                    })
            }}
            <ModalShell
                open=Signal::derive(move || gencert_open.get())
                title="Generate self-signed certificate"
                busy=Signal::derive(move || cmd_gencert.busy.get())
                on_close=Callback::new(move |()| gencert_open.set(false))
            >
                <Body1>
                    "Creates an RSA-2048 certificate, adds the public part to this app as a verify-only credential, and shows the private key once. Use the private key to authenticate the app (client assertion)."
                </Body1>
                <Field label="Subject (common name)">
                    <Input value=gencert_subject />
                </Field>
                <Field label="Valid for (days)">
                    <Input value=gencert_validity />
                </Field>
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| gencert_open.set(false))
                        disabled=Signal::derive(move || cmd_gencert.busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(do_generate_cert)
                        disabled=Signal::derive(move || cmd_gencert.busy.get())
                    >
                        {move || {
                            if cmd_gencert.busy.get() {
                                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                    .into_any()
                            } else {
                                view! { "Generate" }.into_any()
                            }
                        }}
                    </Button>
                </div>
            </ModalShell>
            <ModalShell
                open=Signal::derive(move || gencert_result.with(|r| r.is_some()))
                title="Certificate generated"
                on_close=Callback::new(move |()| gencert_result.set(None))
                wide=true
            >
            {move || {
                gencert_result
                    .get()
                    .map(|r| {
                        let pk = r.private_key_pem.clone();
                        let copy_pk = move |_| {
                            let value = pk.clone();
                            leptos::task::spawn_local(async move {
                                if let Some(win) = web_sys::window() {
                                    let _ = JsFuture::from(
                                            win.navigator().clipboard().write_text(&value),
                                        )
                                        .await;
                                }
                            });
                        };
                        view! {
                            <Body1>
                                "Copy the private key now — it is never stored and cannot be retrieved again. The public certificate has already been added to the application."
                            </Body1>
                            <Body1 class="mono">{format!("Thumbprint: {}", r.thumbprint)}</Body1>
                            <Body1 class="mono">{format!("Expires: {}", r.expires)}</Body1>
                            <strong>"Private key (PKCS#8 PEM)"</strong>
                            <pre class="secret-reveal">{r.private_key_pem.clone()}</pre>
                            <strong>"Certificate (PEM)"</strong>
                            <pre class="secret-reveal">{r.certificate_pem.clone()}</pre>
                            <div class="actions-row">
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(copy_pk)
                                >
                                    "Copy private key"
                                </Button>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                    on_click=Box::new(move |_| gencert_result.set(None))
                                >
                                    "Done"
                                </Button>
                            </div>
                        }
                    })
            }}
            </ModalShell>
            <ModalShell
                open=Signal::derive(move || rotate_open.get())
                title="Rotate secret into Key Vault"
                busy=Signal::derive(move || cmd_rotate.busy.get())
                on_close=Callback::new(move |()| rotate_open.set(false))
            >
                <Body1>
                    "Mints a new client secret, stores it as a new version of the vault secret below, then optionally removes the existing secret(s). The value is written only to Key Vault — it is never shown here."
                </Body1>
                <Field label="Key Vault name">
                    <Input value=rotate_vault />
                </Field>
                <Field label="Secret name">
                    <Input value=rotate_secret_name />
                </Field>
                <Field label="New secret expires in (days)">
                    <Input value=rotate_lifetime />
                </Field>
                <div class="actions-row">
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| rotate_open.set(false))
                        disabled=Signal::derive(move || cmd_rotate.busy.get())
                    >
                        "Cancel"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Secondary)
                        on_click=Box::new(move |_| do_rotate(false))
                        disabled=Signal::derive(move || cmd_rotate.busy.get())
                    >
                        "Rotate (keep old)"
                    </Button>
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                        on_click=Box::new(move |_| do_rotate(true))
                        disabled=Signal::derive(move || cmd_rotate.busy.get())
                    >
                        {move || {
                            if cmd_rotate.busy.get() {
                                view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                    .into_any()
                            } else {
                                view! { "Rotate & remove existing" }.into_any()
                            }
                        }}
                    </Button>
                </div>
            </ModalShell>
            <ConfirmDialog
                open=Signal::derive(move || pending_secret.with(|p| p.is_some()))
                title="Remove this client secret?"
                body="Any caller still using this secret will start getting 401s immediately. This cannot be undone."
                confirm_label="Remove"
                busy=Signal::derive(move || removing.with(|r| r.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_secret.get() {
                        pending_secret.set(None);
                        remove_secret(id);
                    }
                })
                on_close=Callback::new(move |()| pending_secret.set(None))
            />
            <ConfirmDialog
                open=Signal::derive(move || pending_cert.with(|p| p.is_some()))
                title="Remove this certificate?"
                body="Any caller still using this certificate will fail to authenticate immediately. This cannot be undone."
                confirm_label="Remove"
                busy=Signal::derive(move || removing_cert.with(|r| r.is_some()))
                on_confirm=Callback::new(move |()| {
                    if let Some(id) = pending_cert.get() {
                        pending_cert.set(None);
                        remove_cert(id);
                    }
                })
                on_close=Callback::new(move |()| pending_cert.set(None))
            />
            <ConfirmDialog
                open=Signal::derive(move || pending_expired.get())
                title="Remove all expired secrets?"
                body="Sweeps every expired client secret from this application. Active secrets are not touched."
                confirm_label="Remove expired"
                busy=Signal::derive(move || cmd_expire.busy.get())
                on_confirm=Callback::new(move |()| {
                    pending_expired.set(false);
                    remove_expired(());
                })
                on_close=Callback::new(move |()| pending_expired.set(false))
            />
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }

    const TODAY: &str = "2026-01-01";

    #[test]
    fn presets_map_to_lifetime_days() {
        for (preset, _) in EXPIRES_PRESETS.iter().filter(|(p, _)| *p != CUSTOM_PRESET) {
            let (days, start, end) = resolve_expiry_fields(preset, None, None, d(TODAY)).unwrap();
            assert_eq!(days, Some(preset.parse::<u32>().unwrap()));
            assert!(start.is_none() && end.is_none());
        }
    }

    #[test]
    fn custom_resolves_midnight_utc_window() {
        let (days, start, end) = resolve_expiry_fields(
            CUSTOM_PRESET,
            Some(d("2026-02-01")),
            Some(d("2026-08-01")),
            d(TODAY),
        )
        .unwrap();
        assert!(days.is_none());
        assert_eq!(start.unwrap().to_rfc3339(), "2026-02-01T00:00:00+00:00");
        assert_eq!(end.unwrap().to_rfc3339(), "2026-08-01T00:00:00+00:00");
    }

    #[test]
    fn custom_requires_end_after_start_and_caps_at_24_months() {
        assert!(resolve_expiry_fields(CUSTOM_PRESET, None, None, d(TODAY)).is_err());
        assert!(resolve_expiry_fields(
            CUSTOM_PRESET,
            Some(d("2026-06-01")),
            Some(d("2026-06-01")),
            d(TODAY),
        )
        .is_err());
        // Without an explicit start, "today" anchors the window.
        assert!(
            resolve_expiry_fields(CUSTOM_PRESET, None, Some(d("2025-12-01")), d(TODAY)).is_err()
        );
        assert!(resolve_expiry_fields(
            CUSTOM_PRESET,
            Some(d("2026-01-01")),
            Some(d("2028-06-01")),
            d(TODAY),
        )
        .is_err());
    }
}
