//! Permission tester — a standalone tool to check whether a chosen identity
//! (app registration, enterprise app, or managed identity) actually has access
//! to a *specific* Exchange mailbox or SharePoint site ("identity → resource").
//! It exercises the authoritative live checks on the backend (`test_mailbox_access`
//! / `test_site_access`) rather than reading the declared manifest, so it reflects
//! effective access (org-wide grant vs scoped vs none). Both checks are keyed on
//! the principal's appId, so they work for any service-principal type.

use std::collections::HashSet;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize, Tab, TabList};
use wasm_bindgen::JsCast;

use crate::bindings::permission_tester::{self, PermissionTestResult};
use crate::bindings::{TenantContext, auth, search};
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::SectionHeader;
use crate::hooks::use_debounced::use_debounced;
use crate::state::use_session;

use crate::util::no_tenant;

/// Maps a verdict string from [`PermissionTestResult`] to (badge class, label).
fn verdict_badge(verdict: &str) -> (&'static str, &'static str) {
    match verdict {
        "org_wide" => ("badge badge--warning", "Has access — organization-wide"),
        "scoped" => ("badge badge--ok", "Has access — scoped"),
        "no_access" => ("badge", "No access"),
        _ => ("badge badge--warning", "Couldn't determine"),
    }
}

#[component]
pub fn PermissionTesterView() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // Selected app (the service principal's appId) + resource inputs.
    let app_id = RwSignal::new(String::new());
    // Typeahead state: `app_query` is the raw text; `app_focused` gates the
    // results dropdown (with a blur delay so a result click registers first).
    let app_query = RwSignal::new(String::new());
    let app_focused = RwSignal::new(false);
    // Keyboard navigation for the typeahead: `sel` is the highlighted row;
    // `rows_now` mirrors the resolved results so the keydown handler (on the
    // input) can read the current rows synchronously to act on Enter.
    let sel = RwSignal::new(0usize);
    let rows_now: RwSignal<Vec<(String, String, AppKind)>> = RwSignal::new(Vec::new());
    let resource_tab = RwSignal::new(String::from("exchange"));
    let mailbox = RwSignal::new(String::new());
    let site_url = RwSignal::new(String::new());

    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let result: RwSignal<Option<PermissionTestResult>> = RwSignal::new(None);
    // The SharePoint site-permission endpoints need the admin-consent-only
    // Sites.FullControl.All scope; a `consent_required` flips this on.
    let needs_consent = RwSignal::new(false);

    // Reset state when the tenant changes.
    Effect::new(move |_| {
        let _ = tenant.get();
        app_id.set(String::new());
        app_query.set(String::new());
        app_focused.set(false);
        result.set(None);
        error.set(None);
        needs_consent.set(false);
    });

    // Server-side identity search (debounced) — reuses the global search so the
    // picker spans app registrations, enterprise apps, and managed identities
    // (all three are service principals testable by appId). Returns
    // `(app_id, display_name, kind)`, deduped by appId (an app registration and
    // its enterprise-app SP share one appId; the test verdict is the same).
    let debounced_query = use_debounced(app_query.into(), 200);
    let app_results = LocalResource::new(move || {
        let t = tenant.get();
        let q = debounced_query.get();
        async move {
            let q = q.trim().to_string();
            if q.is_empty() {
                return Vec::new();
            }
            let Some(t) = t else { return Vec::new() };
            let Ok(r) = search::global_search(&t.tenant_id, &q).await else {
                return Vec::new();
            };
            let mut out: Vec<(String, String, AppKind)> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            // Pushed app-reg first so a shared appId keeps the App-Reg label.
            let groups = [
                (r.app_registrations, AppKind::AppRegistration),
                (r.enterprise_apps, AppKind::EnterpriseApp),
                (r.managed_identities, AppKind::ManagedIdentityUnknown),
            ];
            for (hits, kind) in groups {
                for h in hits {
                    if let Some(app_id) = h.app_id
                        && seen.insert(app_id.clone())
                    {
                        out.push((app_id, h.display_name, kind));
                    }
                }
            }
            out
        }
    });

    // Mirror the resolved results into a plain signal + reset the highlight, so
    // the input's keydown handler can pick the selected row synchronously.
    Effect::new(move |_| {
        if let Some(rows) = app_results.get() {
            rows_now.set(rows.to_vec());
            sel.set(0);
        }
    });

    // Pick the row at index `i`: fill the inputs and close the dropdown.
    let pick = move |i: usize| {
        if let Some((id, name, _)) = rows_now.with(|r| r.get(i).cloned()) {
            app_id.set(id);
            app_query.set(name);
            app_focused.set(false);
        }
    };

    let on_picker_keydown = move |ev: leptos::ev::KeyboardEvent| {
        let len = rows_now.with(Vec::len);
        match ev.key().as_str() {
            "ArrowDown" if len > 0 => {
                ev.prevent_default();
                sel.update(|i| *i = (*i + 1) % len);
            }
            "ArrowUp" if len > 0 => {
                ev.prevent_default();
                sel.update(|i| *i = if *i == 0 { len - 1 } else { *i - 1 });
            }
            "Enter" if len > 0 => {
                ev.prevent_default();
                pick(sel.get_untracked());
            }
            "Escape" => {
                ev.prevent_default();
                app_focused.set(false);
            }
            _ => {}
        }
    };

    // Zero-arg so it can be called both from the button (wrapped) and from the
    // post-consent retry, without the event-arg type leaking in.
    let do_test = move || {
        if busy.get() {
            return;
        }
        let aid = app_id.get();
        if aid.trim().is_empty() {
            error.set(Some("Choose an application to test.".into()));
            return;
        }
        let tab = resource_tab.get();
        let resource = if tab == "exchange" {
            mailbox.get().trim().to_string()
        } else {
            site_url.get().trim().to_string()
        };
        if resource.is_empty() {
            error.set(Some(if tab == "exchange" {
                "Enter a mailbox address.".into()
            } else {
                "Enter a SharePoint site URL.".into()
            }));
            return;
        }
        busy.set(true);
        error.set(None);
        result.set(None);
        let t: Option<TenantContext> = tenant.get();
        leptos::task::spawn_local(async move {
            let Some(t) = t else {
                busy.set(false);
                error.set(Some(no_tenant().message));
                return;
            };
            let r = if tab == "exchange" {
                permission_tester::test_mailbox_access(&t.tenant_id, &aid, &resource).await
            } else {
                permission_tester::test_site_access(&t.tenant_id, &aid, &resource).await
            };
            match r {
                Ok(res) => {
                    needs_consent.set(false);
                    result.set(Some(res));
                }
                Err(e) => {
                    if e.code == "consent_required" {
                        needs_consent.set(true);
                    }
                    error.set(Some(e.message));
                }
            }
            busy.set(false);
        });
    };

    // Grant SharePoint consent, then re-run the test.
    let grant_consent = move |_| {
        if busy.get() {
            return;
        }
        let Some(t) = tenant.get() else { return };
        busy.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            match auth::request_scope_consent(&t.tenant_id, "sharepoint").await {
                Ok(()) => {
                    needs_consent.set(false);
                    // Clear `busy` first — `do_test` early-returns while it's set,
                    // and it re-sets it for the actual run.
                    busy.set(false);
                    do_test();
                }
                Err(e) => {
                    busy.set(false);
                    error.set(Some(e.message));
                }
            }
        });
    };

    view! {
        <main class="permission-tester">
            <SectionHeader
                title="Permission Tester".to_string()
                crumb="Verify effective access".to_string()
            />
            <Body1>
                "Check whether an app registration, enterprise app, or managed identity can actually reach a specific Exchange mailbox or SharePoint site. This runs the live authorization check — it reflects effective access (organization-wide grant, scoped grant, or none), not just what the identity declares."
            </Body1>

            <Field label="Identity">
                <div class="tester-picker">
                    <input
                        type="text"
                        class="input"
                        role="combobox"
                        aria-autocomplete="list"
                        aria-controls="tester-listbox"
                        aria-expanded=move || {
                            (app_focused.get() && !app_query.get().trim().is_empty()).to_string()
                        }
                        aria-activedescendant=move || {
                            if rows_now.with(Vec::is_empty) {
                                String::new()
                            } else {
                                format!("tester-opt-{}", sel.get())
                            }
                        }
                        placeholder="Search app registrations, enterprise apps, or managed identities…"
                        prop:value=move || app_query.get()
                        on:input=move |ev| {
                            app_query.set(event_target_value(&ev));
                            // Typing a new query invalidates the prior selection.
                            app_id.set(String::new());
                            sel.set(0);
                            app_focused.set(true);
                        }
                        on:keydown=on_picker_keydown
                        on:focus=move |_| app_focused.set(true)
                        on:blur=move |_| {
                            // Delay closing so a click on a result registers first
                            // (the click fires after blur). Mirrors GlobalSearch.
                            if let Some(w) = web_sys::window() {
                                let cb = wasm_bindgen::closure::Closure::once_into_js(move || {
                                    app_focused.set(false)
                                });
                                let _ = w
                                    .set_timeout_with_callback_and_timeout_and_arguments_0(
                                        cb.unchecked_ref::<js_sys::Function>(),
                                        150,
                                    );
                            }
                        }
                    />
                    {move || {
                        if !app_focused.get() || app_query.get().trim().is_empty() {
                            return ().into_any();
                        }
                        view! {
                            <div class="tester-picker__results" role="listbox" id="tester-listbox">
                                <Suspense fallback=move || {
                                    view! {
                                        <div class="tester-picker__empty">"Searching…"</div>
                                    }
                                }>
                                    {move || Suspend::new(async move {
                                        let rows = app_results.await;
                                        if rows.is_empty() {
                                            return view! {
                                                <div class="tester-picker__empty">
                                                    "No matching identities."
                                                </div>
                                            }
                                                .into_any();
                                        }
                                        rows.into_iter()
                                            .enumerate()
                                            .map(|(i, (id, name, kind))| {
                                                let row_class = move || {
                                                    let mut c = String::from("tester-picker__item");
                                                    if sel.get() == i {
                                                        c.push_str(" tester-picker__item--active");
                                                    }
                                                    c
                                                };
                                                view! {
                                                    <button
                                                        type="button"
                                                        id=format!("tester-opt-{i}")
                                                        role="option"
                                                        aria-selected=move || (sel.get() == i).to_string()
                                                        class=row_class
                                                        on:mouseenter=move |_| sel.set(i)
                                                        on:click=move |_| pick(i)
                                                    >
                                                        <span class="tester-picker__name">
                                                            <TypeChip kind=kind />
                                                            {name}
                                                        </span>
                                                        <span class="mono muted">{id}</span>
                                                    </button>
                                                }
                                            })
                                            .collect_view()
                                            .into_any()
                                    })}
                                </Suspense>
                            </div>
                        }
                            .into_any()
                    }}
                </div>
            </Field>
            {move || {
                let id = app_id.get();
                (!id.is_empty())
                    .then(|| {
                        view! {
                            <Body1 class="muted">
                                {format!("Selected appId: {id}")}
                            </Body1>
                        }
                    })
            }}

            <TabList selected_value=resource_tab>
                <Tab value="exchange">"Exchange mailbox"</Tab>
                <Tab value="sharepoint">"SharePoint site"</Tab>
            </TabList>

            {move || {
                if resource_tab.get() == "exchange" {
                    view! {
                        <Field label="Mailbox">
                            <Input value=mailbox placeholder="user@contoso.com" />
                        </Field>
                    }
                        .into_any()
                } else {
                    view! {
                        <Field label="Site URL">
                            <Input
                                value=site_url
                                placeholder="https://contoso.sharepoint.com/sites/Marketing"
                            />
                        </Field>
                    }
                        .into_any()
                }
            }}

            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| do_test())
                    disabled=Signal::derive(move || busy.get())
                >
                    "Test access"
                </Button>
                {move || {
                    busy.get()
                        .then(|| view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> })
                }}
            </div>

            {move || error.get().map(|e| view! { <Body1 class="form-error">{e}</Body1> })}

            {move || {
                needs_consent
                    .get()
                    .then(|| {
                        view! {
                            <div class="alert alert--warn">
                                "Testing SharePoint access needs the Sites.FullControl.All admin permission (it's required even to read a site's permissions). Grant consent to continue — you must be a SharePoint or Global administrator."
                                <div class="actions-row">
                                    <Button
                                        appearance=Signal::derive(|| ButtonAppearance::Primary)
                                        on_click=Box::new(grant_consent)
                                        disabled=Signal::derive(move || busy.get())
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
                        let (badge_class, label) = verdict_badge(&r.verdict);
                        let roles = if r.roles.is_empty() {
                            None
                        } else {
                            Some(r.roles.join(", "))
                        };
                        view! {
                            <div class="permission-tester__result">
                                <div class="row-between">
                                    <span class=badge_class>{label}</span>
                                    <span class="muted">{r.resource_label.clone()}</span>
                                </div>
                                {r.detail.clone().map(|d| view! { <Body1>{d}</Body1> })}
                                {roles
                                    .map(|roles| {
                                        view! {
                                            <Body1>
                                                <strong>"Granted via: "</strong>
                                                {roles}
                                            </Body1>
                                        }
                                    })}
                            </div>
                        }
                    })
            }}
        </main>
    }
}
