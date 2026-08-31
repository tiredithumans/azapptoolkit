//! Credentials tab. Lists secrets + certificates for an app, lets you add /
//! remove / sweep expired.

use std::sync::Arc;

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
use crate::components::vault_picker::VaultPicker;
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::util::{ls_get, ls_set};
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
    // Disallowed characters become a SEPARATOR, not nothing.
    //
    // They used to be dropped, which silently merged distinct names: "a.b" and
    // "ab" produced the same secret, and a rotate or add-secret then wrote a new
    // VERSION under a name another app already owned — so code trusting "latest
    // version at that name" for app A could receive app B's credential material.
    // Runs are collapsed and the ends trimmed so the result never carries a
    // doubled or leading hyphen Key Vault would reject.
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '-' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let cleaned = out.trim_matches('-');
    if cleaned.is_empty() {
        // A wholly non-Latin display name reduces to nothing, and every such app
        // used to land on the bare literal — so they all collided with each
        // other. Discriminate by a stable digest of the ORIGINAL name, which is
        // the only distinguishing input left at this point.
        if name.trim().is_empty() {
            "client-secret".to_string()
        } else {
            format!("client-secret-{:08x}", stable_digest(name))
        }
    } else {
        cleaned.to_string()
    }
}

/// FNV-1a, written out rather than taken from `DefaultHasher`.
///
/// This digest ends up in a Key Vault secret NAME, so it has to reproduce
/// across processes and across toolchain upgrades — `DefaultHasher`'s algorithm
/// carries no such guarantee, and a name that shifted under the app would
/// orphan every previously written version.
fn stable_digest(s: &str) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for b in s.as_bytes() {
        hash ^= u32::from(*b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

#[component]
pub fn CredentialsTab(
    #[prop(into)] detail: Signal<Arc<ApplicationDetail>>,
    #[prop(into)] on_changed: Callback<()>,
) -> impl IntoView {
    let session = use_session();
    let object_id = Signal::derive(move || detail.with(|d| d.application.id.clone()));
    let app_id = Signal::derive(move || detail.with(|d| d.application.app_id.clone()));
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
    let pending_secret: RwSignal<Option<String>> = RwSignal::new(None);
    let pending_cert: RwSignal<Option<String>> = RwSignal::new(None);
    // Name the exact credential a Remove will destroy. An app with six secrets
    // rendered six identical "Remove this client secret?" dialogs, so the
    // operator had to trust that the button they clicked was the row they meant.
    // Falls back to the key id, which is always present and is what the row
    // shows anyway.
    let pending_secret_label = Signal::derive(move || {
        pending_secret
            .with(|p| {
                p.as_ref().map(|id| {
                    secrets.with(|list| {
                        list.iter()
                            .find(|s| &s.key_id == id)
                            .and_then(|s| s.display_name.clone())
                            .unwrap_or_else(|| id.clone())
                    })
                })
            })
            .unwrap_or_default()
    });
    let pending_cert_label = Signal::derive(move || {
        pending_cert
            .with(|p| {
                p.as_ref().map(|id| {
                    certs.with(|list| {
                        list.iter()
                            .find(|c| &c.key_id == id)
                            .and_then(|c| c.display_name.clone())
                            .unwrap_or_else(|| id.clone())
                    })
                })
            })
            .unwrap_or_default()
    });
    let pending_expired = RwSignal::new(false);

    let rotate_open = RwSignal::new(false);
    let rotate_vault = RwSignal::new(String::new());
    let rotate_secret_name = RwSignal::new(String::new());
    let rotate_lifetime = RwSignal::new("180".to_string());
    let cmd_rotate = use_command();

    let app_name = Signal::derive(move || detail.with(|d| d.application.display_name.clone()));
    // Opens the rotate dialog and prefills empty fields (never clobbering an
    // in-progress edit). Vault precedence: this app's remembered binding → the
    // tenant default vault → the last vault used in this tenant. Secret name:
    // the binding's remembered name → a Key-Vault-safe name from the app name.
    // Shared by the section header button and the per-row "Rotate" shortcut.
    let open_rotate = move || {
        error.set(None);
        rotate_open.set(true);
        let tid = session
            .active_tenant
            .get()
            .map(|t| t.tenant_id)
            .unwrap_or_default();
        let app = app_id.get_untracked();
        let app_name_val = app_name.get_untracked();
        leptos::task::spawn_local(async move {
            let d = if tid.is_empty() {
                None
            } else {
                Some(crate::bindings::defaults::get_tenant_defaults(&tid).await)
            };

            // Vault: this app's remembered binding → tenant default → last-used.
            let mut vault: Option<String> = None;
            let mut secret: Option<String> = None;
            if let Some(d) = &d {
                if !app.is_empty()
                    && let Some(b) = d.app_vaults.get(&app)
                {
                    vault = Some(b.vault_name.clone());
                    secret = b.secret_name.clone();
                } else if let Some(dv) = &d.default_vault {
                    vault = Some(dv.clone());
                }
            }
            if vault.is_none() && !tid.is_empty() {
                vault = ls_get(&last_vault_key(&tid));
            }

            // Secret name: the binding's remembered name → the tenant secret-name
            // pattern (default `secret-<appId>`) → a Key-Vault-safe app name.
            let secret_default = if app.is_empty() {
                sanitize_secret_name(&app_name_val)
            } else {
                let resolved = d
                    .as_ref()
                    .map(|d| d.secret_name_for(&app))
                    .unwrap_or_else(|| {
                        crate::bindings::defaults::TenantDefaults::default().secret_name_for(&app)
                    });
                sanitize_secret_name(&resolved)
            };

            if rotate_vault.get_untracked().trim().is_empty()
                && let Some(v) = vault
            {
                rotate_vault.set(v);
            }
            if rotate_secret_name.get_untracked().trim().is_empty() {
                rotate_secret_name.set(secret.unwrap_or(secret_default));
            }
        });
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
            move |r: RemoveExpiredResult| {
                // The confirmation goes on the session toast stack, like
                // `remove_secret`/`remove_cert` above — NOT into a local signal.
                // `on_changed` re-runs the resource this subtree is built from,
                // so anything held here is unmounted before it can be read; the
                // toast host lives at the shell root and survives. A partial
                // failure rides an error toast, which lingers longer.
                let removed = r.removed_key_ids.len();
                if r.failures.is_empty() {
                    session.toast_success(format!("Removed {removed} expired secret(s)."));
                } else {
                    session.toast_error(
                        format!(
                            "Removed {removed} expired secret(s); {} could not be removed.",
                            r.failures.len(),
                        ),
                        None,
                    );
                }
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
        let id = object_id.get();
        let app = app_id.get();
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
                // Same reason as `remove_expired`: `on_changed` unmounts this
                // subtree, so the confirmation has to outlive it on the session
                // toast stack. Warnings ride an error toast so they linger.
                let msg = format!(
                    "Rotated into Key Vault \u{201c}{}\u{201d} as secret \u{201c}{}\u{201d}; new credential created, {} old removed.",
                    r.vault_name,
                    r.secret_name,
                    r.removed_key_ids.len(),
                );
                if r.warnings.is_empty() {
                    session.toast_success(msg);
                } else {
                    session.toast_error(
                        format!("{msg} {} warning(s) \u{2014} see the log.", r.warnings.len()),
                        None,
                    );
                }
                on_changed_cb.run(());
            },
            move |e| error.set(Some(e.message)),
            move |tenant_id| {
                let input = RotateCredentialInput {
                    object_id: id,
                    app_id: (!app.is_empty()).then_some(app),
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
        cmd_gencert.run_with(
            move |r| {
                gencert_open.set(false);
                // Defer the detail reload until the reveal is dismissed — same
                // reason as `create_secret` above. The reload re-runs the
                // resource this whole subtree (incl. `gencert_result`) is built
                // from, so calling it here tore the modal down before it
                // painted: the operator saw the dialog promise a one-time
                // private key and then never got one.
                gencert_result.set(Some(r));
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

    // Dismissing the reveal is what releases the deferred reload: the public
    // half of the new certificate is already on the app, so the list behind the
    // modal is stale until this runs.
    let dismiss_gencert = Callback::new(move |()| {
        gencert_result.set(None);
        on_changed.run(());
    });

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
                            on_click=Box::new(move |_| {
                                error.set(None);
                                add_open.set(true);
                            })
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
            </section>
            <section>
                <header class="row-between">
                    <strong>{move || format!("Certificates ({})", certs.with(Vec::len))}</strong>
                    <div class="actions-row">
                        <Button
                            appearance=Signal::derive(|| ButtonAppearance::Secondary)
                            on_click=Box::new(move |_| {
                                error.set(None);
                                gencert_open.set(true);
                            })
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
            // The tab-body banner, for failures raised OUTSIDE a modal (inline
            // delete/remove). A modal keeps its own copy: this one renders behind
            // the backdrop, where it is invisible to someone who just watched an
            // action do nothing.
            {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
            <ModalShell
                open=Signal::derive(move || add_open.get())
                title="New client secret"
                busy=Signal::derive(move || cmd_create.busy.get())
                on_close=Callback::new(move |()| add_open.set(false))
            >
                // Failures from this dialog's action land here, not only in the
                // tab body behind the backdrop. Without it a failed generate left
                // the dialog open, no key shown, and the reason hidden — which
                // reads as "the app silently did nothing".
                {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
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
                // Failures from this dialog's action land here, not only in the
                // tab body behind the backdrop. Without it a failed generate left
                // the dialog open, no key shown, and the reason hidden — which
                // reads as "the app silently did nothing".
                {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
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
                on_close=dismiss_gencert
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
                                    on_click=Box::new(move |_| dismiss_gencert.run(()))
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
                // Failures from this dialog's action land here, not only in the
                // tab body behind the backdrop. Without it a failed generate left
                // the dialog open, no key shown, and the reason hidden — which
                // reads as "the app silently did nothing".
                {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}
                <Body1>
                    "Mints a new client secret, stores it as a new version of the vault secret below, then optionally removes the existing secret(s). The value is written only to Key Vault — it is never shown here."
                </Body1>
                <Field label="Key Vault name">
                    <VaultPicker value=rotate_vault />
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
                        class="button--danger"
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
                subject=pending_secret_label
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
                subject=pending_cert_label
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

    /// The Key Vault secret NAME derived from a credential's display name.
    ///
    /// Key Vault accepts `[0-9a-zA-Z-]` only, so everything else has to go — and
    /// the empty result has to become a valid fallback rather than a rejected
    /// request. What matters beyond legality is DISTINCTNESS: this name selects
    /// which secret a rotate writes a new version of, so two apps sharing one
    /// name means one app's rotate lands on the other's credential.
    #[test]
    fn secret_names_are_reduced_to_what_key_vault_accepts() {
        // Already valid: unchanged.
        assert_eq!(sanitize_secret_name("api-prod-2026"), "api-prod-2026");
        // Disallowed characters become a separator rather than vanishing, and
        // runs collapse to a single hyphen with the ends trimmed.
        assert_eq!(
            sanitize_secret_name("My App / prod_v1.2"),
            "My-App-prod-v1-2"
        );
        assert_eq!(sanitize_secret_name("api prod-2026"), "api-prod-2026");
        assert_eq!(sanitize_secret_name("  lead and trail  "), "lead-and-trail");
        // The regression this replaced: these two used to collapse to the same
        // name, so the second write versioned the first instead of creating a
        // sibling.
        assert_ne!(sanitize_secret_name("a.b"), sanitize_secret_name("ab"));
        assert_eq!(sanitize_secret_name("a.b"), "a-b");
        // Non-ASCII is still dropped rather than transliterated, so a wholly
        // non-Latin name reduces to nothing — but it no longer lands on a shared
        // literal. Every such app used to get exactly `client-secret`.
        assert_eq!(sanitize_secret_name("Zurich"), "Zurich");
        let a = sanitize_secret_name("\u{4f60}\u{597d}");
        let b = sanitize_secret_name("\u{3053}\u{3093}\u{306b}\u{3061}\u{306f}");
        assert!(a.starts_with("client-secret-"), "got {a}");
        assert_ne!(a, b, "two non-Latin names must not share a secret name");
        // The digest has to reproduce across processes and toolchains, or a
        // rotate would orphan every version written under the old name.
        assert_eq!(a, sanitize_secret_name("\u{4f60}\u{597d}"));
        // Genuinely empty input keeps the bare fallback — there is nothing to
        // discriminate on, and it is the documented default.
        assert_eq!(sanitize_secret_name(""), "client-secret");
        assert_eq!(sanitize_secret_name("   "), "client-secret");
        // The output is always a legal Key Vault secret name.
        for input in ["", "  ", "a b", "\u{e9}\u{e8}", "ok-1", "!!!", "..a..b.."] {
            let out = sanitize_secret_name(input);
            assert!(!out.is_empty(), "{input:?} produced an empty name");
            assert!(
                out.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "{input:?} produced an illegal name: {out}"
            );
            assert!(
                !out.starts_with('-') && !out.ends_with('-'),
                "{input:?} -> {out}"
            );
            assert!(!out.contains("--"), "{input:?} -> {out}");
        }
    }

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
        assert!(
            resolve_expiry_fields(
                CUSTOM_PRESET,
                Some(d("2026-06-01")),
                Some(d("2026-06-01")),
                d(TODAY),
            )
            .is_err()
        );
        // Without an explicit start, "today" anchors the window.
        assert!(
            resolve_expiry_fields(CUSTOM_PRESET, None, Some(d("2025-12-01")), d(TODAY)).is_err()
        );
        assert!(
            resolve_expiry_fields(
                CUSTOM_PRESET,
                Some(d("2026-01-01")),
                Some(d("2028-06-01")),
                d(TODAY),
            )
            .is_err()
        );
    }
}
