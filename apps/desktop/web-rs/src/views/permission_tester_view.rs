//! Permission tester — a standalone tool to check whether a chosen identity
//! (app registration, enterprise app, or managed identity) actually has access
//! to a *specific* Exchange mailbox or SharePoint resource ("identity →
//! resource"). The SharePoint side takes any securable a Selected scope can
//! address — a site collection, a list or document library, a folder, or a
//! single file — and the backend walks the inheritance chain, so a file with no
//! entry of its own still reports the access it inherits. After a SharePoint
//! probe the resolved resource's own permission entries are listed underneath
//! the verdict, with a confirm-gated revoke per app grant (F094).
//! It exercises the authoritative live checks on the backend (`test_mailbox_access`
//! / `test_site_access`) rather than reading the declared manifest, so it reflects
//! effective access (org-wide grant vs scoped vs none). Both checks are keyed on
//! the principal's appId, so they work for any service-principal type.

use std::collections::HashSet;

use leptos::prelude::*;
use thaw::{Body1, Button, ButtonAppearance, Field, Input, Spinner, SpinnerSize};

use crate::bindings::permission_tester::{self, AccessVerdict, PermissionTestResult};
use crate::bindings::{TenantContext, auth, search, sharepoint};
use crate::components::permission_principal::principal_label;
use crate::components::type_chip::{AppKind, TypeChip};
use crate::components::ui::{
    Badge, BadgeTone, Callout, DataTable, FormError, SectionHeader, TabBar, TabBarItem,
};
use crate::constants::TYPEAHEAD_DEBOUNCE_MS;
use crate::hooks::use_debounced::use_debounced;
use crate::hooks::use_deferred_blur::use_deferred_blur;
use crate::state::use_session;
use crate::views::dialogs::confirm_dialog::ConfirmDialog;

use crate::util::no_tenant;

/// Maps a [`PermissionTestResult`] verdict to (badge tone, label).
/// Exhaustive on purpose: a new verdict must be given its own badge.
fn verdict_badge(verdict: AccessVerdict) -> (BadgeTone, &'static str) {
    match verdict {
        AccessVerdict::OrgWide => (BadgeTone::Warning, "Has access — organization-wide"),
        AccessVerdict::Scoped => (BadgeTone::Ok, "Has access — scoped"),
        AccessVerdict::NoAccess => (BadgeTone::Neutral, "No access"),
        AccessVerdict::Unknown => (BadgeTone::Warning, "Couldn't determine"),
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

    // The tested SharePoint URL's own permission entries + the revoke dialog.
    // The verdict answers "can this app reach here?"; the table shows what is
    // actually granted ON the resolved resource, so a grant made in the
    // wizard can be undone here (F094). Verify-by-URL: empty means "no grants
    // on this resource", never "no item-level access" — the caveat travels
    // with the table.
    // The tuple carries the tested URL alongside the entries so a revoke
    // targets the resource that was actually inspected, not whatever the field
    // says meanwhile.
    let item_perms: RwSignal<Option<(String, Vec<sharepoint::SelectedItemPermissionDto>)>> =
        RwSignal::new(None);
    let perms_busy = RwSignal::new(false);
    // (grantee label, permission id) of the row whose revoke dialog is open.
    let pending_revoke: RwSignal<Option<(String, String)>> = RwSignal::new(None);

    // Reset state when the tenant changes.
    Effect::new(move |_| {
        let _ = tenant.get();
        app_id.set(String::new());
        app_query.set(String::new());
        app_focused.set(false);
        // Tenant A's mailbox / site URL mean nothing in tenant B; neither does
        // the resource tab left open under it (F436).
        mailbox.set(String::new());
        site_url.set(String::new());
        resource_tab.set(String::from("exchange"));
        result.set(None);
        error.set(None);
        needs_consent.set(false);
        item_perms.set(None);
        perms_busy.set(false);
        pending_revoke.set(None);
    });

    // A "Test access…" affordance beside a scope badge that can't state its own
    // reach seeds `tester_app_id` and navigates here; this consumes it. The
    // picker searches by *name* but tests by appId, so the seed fills both: the
    // appId the checks actually use, and the field text, which would otherwise
    // read empty over a live selection.
    //
    // An Effect rather than a read at mount because this view is keep-alive —
    // after its first visit it never mounts again, and a mount-time read would
    // make the affordance work exactly once per session (the same reason the
    // audit controller consumes `pending_audit_run` this way). Clearing the
    // signal *before* writing is what makes it one-shot: this effect also sees
    // the signals it sets, and every re-run then finds `None` and does nothing,
    // so returning here later can't clobber a manual edit.
    //
    // Declared after the tenant reset above so it wins on a first mount, where
    // both run: a seed that arrived with the navigation must not be erased by
    // the reset that same tick.
    Effect::new(move |_| {
        if let Some(seed) = session.tenant_ui.tester_app_id.get() {
            session.tenant_ui.tester_app_id.set(None);
            app_query.set(seed.clone());
            app_id.set(seed);
            // The seed is an exact appId, not a search: don't drop the operator
            // into a typeahead dropdown they have to dismiss.
            app_focused.set(false);
            result.set(None);
            error.set(None);
        }
    });

    // Server-side identity search (debounced) — reuses the global search so the
    // picker spans app registrations, enterprise apps, and managed identities
    // (all three are service principals testable by appId). Returns
    // `(app_id, display_name, kind)`, deduped by appId (an app registration and
    // its enterprise-app SP share one appId; the test verdict is the same).
    let debounced_query = use_debounced(app_query.into(), TYPEAHEAD_DEBOUNCE_MS);
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
            // A seeded selection leaves the field reading the bare appId; the
            // search for it resolves the name by exact lookup, so show that
            // instead. Guarded on the seeded state (field text == selected
            // appId) so a manual query is never overwritten.
            let seeded = app_id.get_untracked();
            if !seeded.is_empty()
                && app_query.with_untracked(|q| q.trim().eq_ignore_ascii_case(&seeded))
                && let Some((_, name, _)) = rows
                    .iter()
                    .find(|(id, _, _)| id.eq_ignore_ascii_case(&seeded))
            {
                app_query.set(name.clone());
            }
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
    // post-consent retry, without the event-arg type leaking in. A `Callback`
    // rather than a closure because three sites share it (button, post-consent
    // retry, post-revoke re-probe) and `move` closures would each have to own
    // it; a Callback is `Copy`.
    let do_test = Callback::new(move |_: ()| {
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
                "Enter a SharePoint site, library, folder or file URL.".into()
            }));
            return;
        }
        busy.set(true);
        error.set(None);
        result.set(None);
        // The table is always the *new* resource's, fetched as part of this
        // same probe — stale rows from the previous URL must not survive it.
        item_perms.set(None);
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
                    // SharePoint only: the verdict answers "can this app reach
                    // here?"; the entries answer "what is granted ON this
                    // resource?" — one probe renders both (F094). A failed
                    // entry read keeps the table hidden rather than rendering
                    // it empty: "no grants on this resource" is only provable
                    // when the read actually answered.
                    if tab == "sharepoint" {
                        let listed =
                            sharepoint::list_selected_item_permissions(&t.tenant_id, &resource)
                                .await;
                        match listed {
                            Ok(perms) => item_perms.set(Some((resource, perms))),
                            Err(e) => {
                                if e.is_consent_required() {
                                    needs_consent.set(true);
                                }
                                if !session.report_if_session_lost(&e) {
                                    error.set(Some(format!(
                                        "The verdict above is complete, but the permission entries on this resource could not be read: {}",
                                        e.message
                                    )));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if e.is_consent_required() {
                        needs_consent.set(true);
                    }
                    // A dead session gets the Re-authenticate lever, not a
                    // dead-end line; consent keeps this view's own button.
                    if !session.report_if_session_lost(&e) {
                        error.set(Some(e.message));
                    }
                }
            }
            busy.set(false);
        });
    });

    // Grant SharePoint consent, then re-run the test.
    let grant_consent = move |_| {
        if busy.get() {
            return;
        }
        let Some(t) = tenant.get() else { return };
        busy.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            let res = auth::request_scope_consent(&t.tenant_id, "sharepoint").await;
            // The consent prompt is answered minutes later, perhaps after a
            // sign-out: a toast then would surface at the next sign-in.
            if busy.is_disposed() || !session.is_active_tenant(&t.tenant_id) {
                return;
            }
            match res {
                Ok(()) => {
                    needs_consent.set(false);
                    // Clear `busy` first — `do_test` early-returns while it's set,
                    // and it re-sets it for the actual run.
                    busy.set(false);
                    do_test.try_run(());
                }
                Err(e) => {
                    busy.set(false);
                    if !session.report_if_session_lost(&e) {
                        error.set(Some(e.message));
                    }
                }
            }
        });
    };

    // Revoke one Selected entry from the tested resource, then re-probe with
    // the same identity: the fresh probe re-reads verdict and entries together,
    // so the table and the "Granted via" line prove the revoke landed — never
    // an optimistic row removal. The URL is the one the table was fetched for
    // (not whatever the field says meanwhile), read off `item_perms`.
    let do_revoke = move |url: String, perm_id: String| {
        if perms_busy.get() {
            return;
        }
        let Some(t) = tenant.get() else { return };
        perms_busy.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            let r = sharepoint::remove_selected_item_permission(&t.tenant_id, &url, &perm_id).await;
            // The dialog closes either way: a modal pinned over a failed
            // revoke is worse than the same error as a line under the form.
            pending_revoke.set(None);
            perms_busy.set(false);
            match r {
                Ok(()) => {
                    do_test.try_run(());
                }
                Err(e) => {
                    if e.is_consent_required() {
                        needs_consent.set(true);
                    }
                    if !session.report_if_session_lost(&e) {
                        error.set(Some(format!("Revoke failed: {}", e.message)));
                    }
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
                "Check whether an app registration, enterprise app, or managed identity can actually reach a specific Exchange mailbox or SharePoint resource — a site collection, library, folder or file. This runs the live authorization check — it reflects effective access (organization-wide grant, scoped grant, or none), not just what the identity declares."
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
                        // Delay closing so a click on a result registers first.
                        on:blur=use_deferred_blur(app_focused)
                    />
                    {move || {
                        if !app_focused.get() || app_query.get().trim().is_empty() {
                            return ().into_any();
                        }
                        // The listbox holds only options; the loading and empty
                        // text sits in a sibling `role="status"` region so it is
                        // never announced as if it were a result (same shape as
                        // GlobalSearch).
                        view! {
                            <div class="tester-picker__results">
                                <div role="listbox" id="tester-listbox">
                                    <Suspense fallback=|| ()>
                                        {move || Suspend::new(async move {
                                            let rows = app_results.await;
                                            if rows.is_empty() {
                                                return ().into_any();
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
                                <div role="status">
                                    <Suspense fallback=move || {
                                        view! {
                                            <div class="tester-picker__empty">"Searching…"</div>
                                        }
                                    }>
                                        {move || Suspend::new(async move {
                                            app_results
                                                .await
                                                .is_empty()
                                                .then(|| {
                                                    view! {
                                                        <div class="tester-picker__empty">
                                                            "No matching identities."
                                                        </div>
                                                    }
                                                })
                                        })}
                                    </Suspense>
                                </div>
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

            <TabBar
                label="Resource type"
                items=vec![
                    TabBarItem { value: "exchange", label: "Exchange mailbox" },
                    TabBarItem { value: "sharepoint", label: "SharePoint resource" },
                ]
                selected=resource_tab
            />

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
                        <Field label="Site, library, folder or file URL">
                            <Input
                                value=site_url
                                placeholder="https://contoso.sharepoint.com/sites/Finance/Shared Documents/Invoices"
                            />
                        </Field>
                        <Body1 class="hint hint--field">
                            "Any level a Selected scope can address. A permission inherited from the library or site collection counts as access, and a grant that the app can't use — a permission entry with no matching Selected scope in its token — is reported as no access."
                        </Body1>
                    }
                        .into_any()
                }
            }}

            <div class="actions-row">
                <Button
                    appearance=Signal::derive(|| ButtonAppearance::Primary)
                    on_click=Box::new(move |_| do_test.run(()))
                    // A revoke re-probes on success; disabling here keeps the
                    // two probes from racing into one error/result signal.
                    disabled=Signal::derive(move || busy.get() || perms_busy.get())
                >
                    "Test access"
                </Button>
                {move || {
                    busy.get()
                        .then(|| view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> })
                }}
            </div>

            {move || error.get().map(|e| view! { <FormError>{e}</FormError> })}

            {move || {
                needs_consent
                    .get()
                    .then(|| {
                        view! {
                            <Callout tone="warn">
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
                            </Callout>
                        }
                    })
            }}

            {move || {
                result
                    .get()
                    .map(|r| {
                        let (badge_tone, label) = verdict_badge(r.verdict);
                        let roles = if r.roles.is_empty() {
                            None
                        } else {
                            Some(r.roles.join(", "))
                        };
                        view! {
                            <div class="permission-tester__result">
                                <div class="row-between">
                                    <Badge label=label tone=badge_tone />
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

            // The entries live on the *resource*, not in the app's manifest —
            // this is where a per-URL grant made in the wizard gets undone,
            // next to the probe that verified it (F094). Keyed on a
            // *successful* read: `None` covers both "no probe yet" and "the
            // read failed", and neither may render as "no grants".
            {move || {
                if resource_tab.get() != "sharepoint" {
                    return ().into_any();
                }
                let Some((url, perms)) = item_perms.get() else {
                    return ().into_any();
                };
                view! {
                    <div class="permission-tester__grants">
                        <Body1>
                            <strong>"Selected item permissions on this resource"</strong>
                        </Body1>
                        <Body1 class="mono muted">{url}</Body1>
                        <Body1 class="hint hint--field">
                            "The permission entries on the resource the tested URL resolves to — every app grant on it, not just the tested app's. This is a verify-by-URL read: an empty list means no grants on this resource, never that the app has no item-level access elsewhere (a file inherits from its library and its site)."
                        </Body1>
                        <DataTable
                            headers=vec!["Granted to", "Roles", ""]
                            rows=perms
                            empty_message="No app grants on this resource. This is not proof the app has no item-level access: check the library and site above it, and remember a file inherits."
                            row=move |p: sharepoint::SelectedItemPermissionDto| {
                                let perm_id = p.id.clone();
                                let roles = p.roles.join(", ");
                                // Only app grants are revocable here. An entry
                                // without an application is a user, group or
                                // sharing link — revoking it would cut a
                                // person's access, not an app's, and this view
                                // has no business doing that. An entry whose
                                // application fails to resolve has no `app_id`
                                // either (no revoke), so a parse gap never
                                // deletes.
                                let app_grant = p.app_id.clone();
                                let (who, secondary) = principal_label(&p);
                                let label = who.clone();
                                // Precomputed: the `on_click` closure below
                                // moves `label`, so the aria-label can't borrow
                                // it inside the same `view!`.
                                let aria = format!("Revoke {roles} for {label}");
                                view! {
                                    <tr>
                                        <td class="permission-cell">
                                            <div>{who}</div>
                                            {secondary
                                                .map(|s| {
                                                    view! { <div class="mono muted">{s}</div> }
                                                })}
                                        </td>
                                        <td class="cell-mid">{roles.clone()}</td>
                                        <td class="cell-mid">
                                            {app_grant
                                                .map(|_| {
                                                    view! {
                                                        <Button
                                                            class="button--danger"
                                                            appearance=Signal::derive(|| ButtonAppearance::Subtle)
                                                            attr:aria-label=aria
                                                            disabled=Signal::derive(move || perms_busy.get())
                                                            on_click=Box::new(move |_| {
                                                                pending_revoke
                                                                    .set(Some((label.clone(), perm_id.clone())))
                                                            })
                                                        >
                                                            "Revoke"
                                                        </Button>
                                                    }
                                                })}
                                        </td>
                                    </tr>
                                }
                                    .into_any()
                            }
                        />
                    </div>
                }
                    .into_any()
            }}
            <ConfirmDialog
                open=Signal::derive(move || pending_revoke.with(|p| p.is_some()))
                title="Revoke this item permission?"
                body="Removes this permission entry from the resource. Everyone else keeps their own grants, and the app may still reach the item another way (its library, its site, or an org-wide grant) — re-test afterwards to confirm."
                subject=Signal::derive(move || {
                    pending_revoke
                        .with(|p| p.clone())
                        .map(|(who, id)| format!("{who} · {id}"))
                        .unwrap_or_default()
                })
                confirm_label="Revoke"
                busy=perms_busy
                on_confirm=Callback::new(move |()| {
                    let Some((_, perm_id)) = pending_revoke.get() else { return };
                    let Some((url, _)) = item_perms.get() else { return };
                    do_revoke(url, perm_id);
                })
                on_close=Callback::new(move |()| pending_revoke.set(None))
            />
        </main>
    }
}
