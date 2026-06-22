//! Persistent application shell: left navigation rail + top bar + content
//! slot. The shell is mounted once per authenticated session so navigation
//! state (active view, tool-dialog flags) stays alive across view switches.

use leptos::prelude::*;
use thaw::{Spinner, SpinnerSize};

use crate::bindings::applications;
use crate::components::global_search::GlobalSearch;
use crate::components::icon::{Icon, IconName};
use crate::components::toast::ToastHost;
use crate::state::{use_session, ActiveView};
use crate::views::dialogs::{
    cache_diagnostics_dialog::CacheDiagnosticsDialog, create_app_dialog::CreateAppDialog,
    sso_wizard_dialog::SsoWizardDialog,
};

#[component]
pub fn AppShell(children: Children) -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;
    let view = session.view;

    let org = LocalResource::new(move || {
        let tenant = tenant.get();
        async move {
            match tenant {
                Some(t) => applications::get_organization(&t.tenant_id).await.ok(),
                None => None,
            }
        }
    });

    // In-flight flag so the button reads "Signing out…" (and can't be
    // double-clicked) while the backend clears the keyring + caches.
    let signing_out = RwSignal::new(false);
    let on_sign_out = move |_| {
        let session = session;
        if signing_out.get() {
            return;
        }
        if let Some(t) = tenant.get() {
            signing_out.set(true);
            leptos::task::spawn_local(async move {
                let _ = crate::bindings::auth::sign_out(&t).await;
                // Reset before the tenant clears: that unmounts this shell, and
                // writing to a signal after its owner is disposed is an error.
                signing_out.set(false);
                session.set_active_tenant(None);
            });
        } else {
            session.set_active_tenant(None);
        }
    };

    // Re-mints the session's tokens in place (no sign-out) so a role activated
    // after sign-in — e.g. an "Exchange Administrator" PIM role — takes effect.
    // The in-flight guard prevents a double-click from racing two refreshes.
    let refreshing = RwSignal::new(false);
    let on_refresh_token = move |_| {
        let session = session;
        if refreshing.get() {
            return;
        }
        if let Some(t) = tenant.get() {
            refreshing.set(true);
            leptos::task::spawn_local(async move {
                match crate::bindings::auth::refresh_session(&t.tenant_id).await {
                    Ok(()) => {
                        session.toast_success(
                            "Token refreshed — roles activated since sign-in now apply. \
                             Retry the action that failed.",
                        );
                    }
                    Err(e) => {
                        session.toast_error(format!("Couldn't refresh token: {}", e.message), None);
                    }
                }
                refreshing.set(false);
            });
        }
    };

    let nav_row_view = move |label: &'static str, icon: IconName, target: ActiveView| {
        let class = move || {
            let mut c = String::from("nav__item");
            if view.get() == target {
                c.push_str(" nav__item--selected");
            }
            c
        };
        // `aria-current="page"` on the active item; absent otherwise so AT
        // announces the current view. Returning `None` omits the attribute.
        let aria_current = move || (view.get() == target).then_some("page");
        view! {
            <button
                class=class
                type="button"
                title=label
                aria-current=aria_current
                on:click=move |_| session.set_view(target)
            >
                <span class="nav__icon"><Icon name=icon size=18 /></span>
                <span class="nav__label">{label}</span>
            </button>
        }
    };

    let nav_row_action = move |label: &'static str, icon: IconName, flag: RwSignal<bool>| {
        // `aria-expanded` reflects the dialog's open signal so AT knows the
        // button controls a currently-open/closed surface.
        let aria_expanded = move || flag.get();
        view! {
            <button
                class="nav__item"
                type="button"
                title=label
                aria-expanded=aria_expanded
                aria-haspopup="dialog"
                on:click=move |_| flag.set(true)
            >
                <span class="nav__icon"><Icon name=icon size=18 /></span>
                <span class="nav__label">{label}</span>
            </button>
        }
    };

    view! {
        <div class="shell">
            <nav class="shell__nav">
                <div class="shell__brand">
                    <span class="shell__brand-mark">"a"</span>
                    <span class="shell__brand-text">"azapptoolkit"</span>
                </div>
                <div class="shell__nav-list">
                    {nav_row_view("Home", IconName::Home, ActiveView::Home)}
                    {nav_row_view("App Registrations", IconName::AppWindow, ActiveView::Apps)}
                    {nav_row_view("Enterprise Applications", IconName::Building, ActiveView::EnterpriseApps)}
                    {nav_row_view("Managed Identities", IconName::Server, ActiveView::ManagedIdentities)}
                    <div class="shell__nav-section-label">"Tools"</div>
                    {nav_row_view("Security", IconName::ShieldCheck, ActiveView::Security)}
                    {nav_row_view("Permission Tester", IconName::Search, ActiveView::PermissionTester)}
                    {nav_row_view("Resource Access", IconName::Database, ActiveView::ResourceAccess)}
                    {nav_row_view("Bulk Actions", IconName::Wrench, ActiveView::BulkActions)}
                    {nav_row_view("Disaster Recovery", IconName::Download, ActiveView::DisasterRecovery)}
                    {nav_row_view("Key Vault", IconName::Key, ActiveView::KeyVault)}
                    // Logged-in user block — kept inside the scrollable nav list
                    // (directly below Tools) so it stays attached to the nav and
                    // scrolls with it, instead of being pinned to the bottom of a
                    // tall rail where a long content list pushes it out of view.
                    <div class="shell__user">
                        <div class="shell__user-info">
                            {move || Suspend::new(async move {
                                match org.await.as_ref() {
                                    Some(o) => view! { <span class="shell__user-name">{o.display_name.clone()}</span> }.into_any(),
                                    None => view! { <span class="shell__user-name">"—"</span> }.into_any(),
                                }
                            })}
                            <span class="shell__user-email">
                                {move || {
                                    tenant.get().map(|t| t.username.clone()).unwrap_or_default()
                                }}
                            </span>
                        </div>
                        // Live readiness checklist — what the signed-in user holds
                        // (active roles + consented scopes) vs. what each feature
                        // needs. Above Refresh Token because that button is often
                        // the fix for a stale-role "?" this page surfaces.
                        <button
                            class="nav__item shell__user-readiness"
                            type="button"
                            title="Access readiness — check which roles and scopes you currently have for each feature"
                            aria-current=move || (view.get() == ActiveView::Readiness).then_some("page")
                            on:click=move |_| session.set_view(ActiveView::Readiness)
                        >
                            <span class="nav__icon"><Icon name=IconName::ShieldCheck size=18 /></span>
                            <span class="nav__label">"Readiness"</span>
                        </button>
                        // Re-mint tokens without dropping the session, e.g. to pick
                        // up a PIM role activated after sign-in. Styled as a
                        // `nav__item` so it collapses to icon-only on a narrow rail.
                        <button
                            class="nav__item shell__user-refresh"
                            type="button"
                            title="Refresh token — re-applies roles activated since sign-in (e.g. an active PIM role) without signing out"
                            disabled=move || refreshing.get()
                            on:click=on_refresh_token
                        >
                            <span class="nav__icon">
                                {move || {
                                    if refreshing.get() {
                                        view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                            .into_any()
                                    } else {
                                        view! { <Icon name=IconName::Refresh size=18 /> }.into_any()
                                    }
                                }}
                            </span>
                            <span class="nav__label">
                                {move || if refreshing.get() { "Refreshing…" } else { "Refresh Token" }}
                            </span>
                        </button>
                        // Cache diagnostics inspector — sits directly above Sign Out
                        // in the user block. Reuses `nav_row_action` so it renders as
                        // a full-width `nav__item` matching the buttons around it.
                        {nav_row_action("Cache", IconName::Activity, session.cache_open)}
                        // Styled as a `nav__item` so it collapses to an icon-only
                        // button (hiding the label) when the rail narrows — the same
                        // way the nav links do — instead of disappearing.
                        <button
                            class="nav__item shell__user-signout"
                            type="button"
                            title="Sign Out"
                            disabled=move || signing_out.get()
                            on:click=on_sign_out
                        >
                            <span class="nav__icon"><Icon name=IconName::LogOut size=18 /></span>
                            <span class="nav__label">
                                {move || if signing_out.get() { "Signing out…" } else { "Sign Out" }}
                            </span>
                        </button>
                        // App version, baked at compile time. The release bumps the
                        // web-rs crate version in lockstep with the app (tauri.conf +
                        // workspace), so CARGO_PKG_VERSION here is the shipped version.
                        <div class="shell__version">{concat!("v", env!("CARGO_PKG_VERSION"))}</div>
                    </div>
                </div>
            </nav>
            <div class="shell__main">
                <header class="shell__topbar">
                    <div class="shell__topbar-left"></div>
                    <div class="shell__topbar-center">
                        <GlobalSearch />
                    </div>
                    <div class="shell__topbar-right" />
                </header>
                <div class="shell__content">{children()}</div>
            </div>
            <CacheDiagnosticsDialog
                open=Signal::derive(move || session.cache_open.get())
                on_close=Callback::new(move |()| session.cache_open.set(false))
            />
            <ToastHost />
            // Lifted out of ApplicationsView so the dialog state survives view
            // switches (create_open is a signal here, not local to Apps).
            <Show when=move || view.get() == ActiveView::Apps>
                {move || {
                    let open = session.create_open.get();
                    if !open {
                        return ().into_any();
                    }
                    // Capture session by move into each closure so they stay 'static.
                    let on_close = Callback::new({
                        let session = session;
                        move |()| session.create_open.set(false)
                    });
                    let on_created_cb = Callback::new({
                        let session = session;
                        move |()| session.bump_apps_reload()
                    });
                    view! {
                        <CreateAppDialog
                            open=Signal::derive(move || session.create_open.get())
                            on_close=on_close
                            on_created=on_created_cb
                        />
                    }
                    .into_any()
                }}
            </Show>
            // SSO wizard — lifted to the shell (like the create-app dialog) so its
            // multi-step state survives view switches. Mounted under the
            // Enterprise Apps view, where it's launched.
            <Show when=move || view.get() == ActiveView::EnterpriseApps>
                {move || {
                    if !session.sso_wizard_open.get() {
                        return ().into_any();
                    }
                    let on_close = Callback::new({
                        let session = session;
                        move |()| session.sso_wizard_open.set(false)
                    });
                    let on_created_cb = Callback::new({
                        let session = session;
                        move |()| {
                            session.enterprise_apps_reload.update(|n| *n = n.wrapping_add(1))
                        }
                    });
                    view! {
                        <SsoWizardDialog
                            open=Signal::derive(move || session.sso_wizard_open.get())
                            on_close=on_close
                            on_created=on_created_cb
                        />
                    }
                        .into_any()
                }}
            </Show>
        </div>
    }
}
