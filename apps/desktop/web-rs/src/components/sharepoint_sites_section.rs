//! Collapsible "SharePoint site access" section rendered under the permissions
//! table (app-registration Permissions tab and enterprise-app Permissions
//! content). Folds in what used to be the standalone SharePoint access tab:
//! grant this app per-site access via the `Sites.Selected` model, list a
//! site's app permissions, and revoke them.
//!
//! Callers render this only when the principal declares/holds a `Sites.*`
//! permission. No `on_changed` callback: site grants live on the SharePoint
//! site (not the Entra grant list), and the `Sites.*` Scope badges above are
//! name-derived — nothing in the permissions table changes, so inline result
//! notes survive.

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::sharepoint::GrantSiteAccessResult;
use crate::bindings::{auth, sharepoint};
use crate::components::requires_role::RequiresRole;
use crate::components::ui::DataTable;
use crate::hooks::use_command::use_command;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;

use crate::util::no_tenant;

#[component]
pub fn SharePointSitesSection(
    /// appId (client id) — keys the site grant's `grantedToIdentities`.
    #[prop(into)]
    app_id: Signal<String>,
    #[prop(into)] app_display_name: Signal<String>,
) -> impl IntoView {
    let session = use_session();
    let open = RwSignal::new(false);

    let site_url = RwSignal::new(String::new());
    // Drives the consent / grant / remove mutations, which share one busy+error.
    let cmd = use_command();
    let result: RwSignal<Option<GrantSiteAccessResult>> = RwSignal::new(None);
    // The site whose permissions are currently listed; set after grant/list.
    let listed_url = RwSignal::new(String::new());
    let reload = RwSignal::new(0_u32);
    let pending_remove: RwSignal<Option<String>> = RwSignal::new(None);
    // The site-permission endpoints require the admin-consent-only
    // `Sites.FullControl.All` scope, acquired on demand. A `consent_required`
    // from any SharePoint call flips this on to offer a "Grant consent" button.
    let needs_consent = RwSignal::new(false);

    let permissions = LocalResource::new(move || {
        let tenant = session.active_tenant.get();
        let url = listed_url.get();
        let _ = reload.get();
        async move {
            if url.trim().is_empty() {
                return Ok(Vec::new());
            }
            let Some(t) = tenant else {
                return Err(no_tenant());
            };
            let r = sharepoint::list_site_permissions(&t.tenant_id, &url).await;
            match &r {
                Ok(_) => needs_consent.set(false),
                Err(e) if e.code == "consent_required" => needs_consent.set(true),
                Err(_) => {}
            }
            r
        }
    });

    // Grants the SharePoint consent, then re-runs the listing (which also
    // clears the prompt on success). Grant/revoke can be re-clicked afterwards.
    let grant_consent = move |_| {
        cmd.run(
            move |()| {
                needs_consent.set(false);
                reload.update(|n| *n += 1);
            },
            move |tenant_id| async move {
                auth::request_scope_consent(&tenant_id, "sharepoint").await
            },
        );
    };

    let do_grant = move |role: &'static str| {
        let url = site_url.get().trim().to_string();
        if url.is_empty() {
            cmd.error.set(Some("Enter a SharePoint site URL.".into()));
            return;
        }
        cmd.error.set(None);
        result.set(None);
        let app_id = app_id.get();
        let app_name = app_display_name.get();
        let listed = url.clone();
        cmd.run_with(
            move |r| {
                needs_consent.set(false);
                result.set(Some(r));
                listed_url.set(listed);
                reload.update(|n| *n += 1);
            },
            move |e| {
                if e.code == "consent_required" {
                    needs_consent.set(true);
                }
                cmd.error.set(Some(e.message));
            },
            move |tenant_id| async move {
                sharepoint::grant_site_access(
                    &tenant_id,
                    &app_id,
                    &app_name,
                    &url,
                    &[role.to_string()],
                )
                .await
            },
        );
    };

    let do_list = move |_| {
        let url = site_url.get().trim().to_string();
        if url.is_empty() {
            cmd.error.set(Some("Enter a SharePoint site URL.".into()));
            return;
        }
        cmd.error.set(None);
        listed_url.set(url);
        reload.update(|n| *n += 1);
    };

    let do_remove = move |perm_id: String| {
        let url = listed_url.get();
        if url.trim().is_empty() {
            return;
        }
        cmd.error.set(None);
        cmd.run_with(
            move |()| {
                needs_consent.set(false);
                reload.update(|n| *n += 1);
            },
            move |e| {
                if e.code == "consent_required" {
                    needs_consent.set(true);
                }
                cmd.error.set(Some(e.message));
            },
            move |tenant_id| async move {
                sharepoint::remove_site_permission(&tenant_id, &url, &perm_id).await
            },
        );
    };

    view! {
        <section class="detail-section">
            <header class="row-between">
                <strong>"SharePoint site access"</strong>
                <span class="detail-section__controls">
                    <RequiresRole capability_key="sharepoint_sites_selected" />
                    <Button
                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                        on_click=Box::new(move |_| open.update(|o| *o = !*o))
                    >
                        {move || if open.get() { "Hide" } else { "Show" }}
                    </Button>
                </span>
            </header>
            {move || {
                open.get()
                    .then(|| {
                        view! {
                            <Body1>
                                "Grant this application access to a specific SharePoint site instead of the whole tenant (the Sites.Selected model). Enter the site URL (e.g. https://contoso.sharepoint.com/sites/Marketing). Requires the app to hold the Sites.Selected permission, and you to be a SharePoint administrator or site owner."
                            </Body1>
                            <Field label="Site URL">
                                <Input
                                    value=site_url
                                    placeholder="https://contoso.sharepoint.com/sites/Marketing"
                                />
                            </Field>
                            <div class="actions-row">
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                    on_click=Box::new(move |_| do_grant("read"))
                                    disabled=Signal::derive(move || cmd.busy.get())
                                >
                                    "Grant read"
                                </Button>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                                    on_click=Box::new(move |_| do_grant("write"))
                                    disabled=Signal::derive(move || cmd.busy.get())
                                >
                                    "Grant write"
                                </Button>
                                <Button
                                    appearance=Signal::derive(|| ButtonAppearance::Secondary)
                                    on_click=Box::new(do_list)
                                    disabled=Signal::derive(move || cmd.busy.get())
                                >
                                    "List site permissions"
                                </Button>
                                {move || {
                                    cmd.busy
                                        .get()
                                        .then(|| {
                                            view! {
                                                <Spinner size=Signal::derive(|| SpinnerSize::Tiny) />
                                            }
                                        })
                                }}
                            </div>

                            {move || {
                                cmd.error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })
                            }}
                            {move || {
                                needs_consent
                                    .get()
                                    .then(|| {
                                        view! {
                                            <div class="alert alert--warn">
                                                "Managing site permissions needs the Sites.FullControl.All admin permission. Grant consent to continue (you must be a SharePoint or Global administrator)."
                                                <div class="actions-row">
                                                    <Button
                                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                                        on_click=Box::new(grant_consent)
                                                        disabled=Signal::derive(move || cmd.busy.get())
                                                    >
                                                        "Grant consent"
                                                    </Button>
                                                </div>
                                            </div>
                                        }
                                    })
                            }}
                            {move || {
                                result
                                    .get()
                                    .map(|r| {
                                        let summary = format!(
                                            "Granted {} on “{}”.",
                                            r.permission.roles.join(", "),
                                            r.site_display_name.unwrap_or(r.site_id),
                                        );
                                        view! { <div class="alert alert--ok">{summary}</div> }
                                    })
                            }}

                            <hr />
                            <strong>"Current site permissions"</strong>
                            <Suspense fallback=move || {
                                view! {
                                    <Spinner size=Signal::derive(|| SpinnerSize::Tiny) label="Loading…" />
                                }
                            }>
                                {move || Suspend::new(async move {
                                    match permissions.await {
                                        Ok(list) => {
                                            view! {
                                                <DataTable
                                                    headers=vec!["Application", "Roles", ""]
                                                    rows=list
                                                    empty_message="No app permissions listed. Grant access or list a site above."
                                                    row=move |p: sharepoint::SitePermissionDto| {
                                                        let id = p.id.clone();
                                                        let app = p
                                                            .app_display_name
                                                            .or(p.app_id)
                                                            .unwrap_or_else(|| "—".into());
                                                        view! {
                                                            <tr>
                                                                <td>{app}</td>
                                                                <td class="mono">{p.roles.join(", ")}</td>
                                                                <td>
                                                                    <Button
                                                                        class="button--danger"
                                                                        appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                                        on_click=Box::new(move |_| pending_remove.set(Some(id.clone())))
                                                                        disabled=Signal::derive(move || cmd.busy.get())
                                                                    >
                                                                        "Remove"
                                                                    </Button>
                                                                </td>
                                                            </tr>
                                                        }
                                                            .into_any()
                                                    }
                                                />
                                            }
                                                .into_any()
                                        }
                                        // Consent is surfaced by the banner above; don't also
                                        // echo the raw 403 body here.
                                        Err(e) if e.code == "consent_required" => ().into_any(),
                                        Err(e) => {
                                            view! { <Body1 class="form-error">{e.message}</Body1> }
                                                .into_any()
                                        }
                                    }
                                })}
                            </Suspense>
                            <ConfirmDialog
                                open=Signal::derive(move || pending_remove.with(|p| p.is_some()))
                                title="Revoke this site permission?"
                                body="This app immediately loses access to the SharePoint site. The grant can be re-added from this section."
                                confirm_label="Revoke"
                                busy=cmd.busy
                                on_confirm=Callback::new(move |()| {
                                    if let Some(id) = pending_remove.get() {
                                        pending_remove.set(None);
                                        do_remove(id);
                                    }
                                })
                                on_close=Callback::new(move |()| pending_remove.set(None))
                            />
                        }
                    })
            }}
        </section>
    }
}
