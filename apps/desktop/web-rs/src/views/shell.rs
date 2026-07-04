//! Persistent application shell: left navigation rail + top bar + content
//! slot. The shell is mounted once per authenticated session so navigation
//! state (active view, tool-dialog flags) stays alive across view switches.

use std::rc::Rc;

use leptos::ev;
use leptos::prelude::*;
use thaw::{Spinner, SpinnerSize};
use wasm_bindgen::JsCast;

use crate::bindings::{applications, updater};
use crate::components::global_search::GlobalSearch;
use crate::components::icon::{Icon, IconName};
use crate::components::open_items_dock::OpenItemsDock;
use crate::components::open_items_workspace::OpenItemsWorkspace;
use crate::components::toast::{ToastHost, ToastKind};
use crate::components::update_splash::UpdateSplash;
use crate::hooks::use_escape::use_escape;
use crate::state::{ActiveView, use_session};
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
    // Tries the silent refresh first; if the session is dead (an expired/revoked
    // or missing refresh token, surfaced as `refresh_missing`/`not_signed_in`),
    // it falls back to one interactive browser round trip — still no sign-out, so
    // the cached lists + audit run survive. The in-flight guard prevents a
    // double-click from racing two refreshes; `reauthing` flips the label while
    // the browser flow is open.
    let refreshing = RwSignal::new(false);
    let reauthing = RwSignal::new(false);
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
                    Err(e) if matches!(e.code.as_str(), "refresh_missing" | "not_signed_in") => {
                        // Silent re-mint can't fix a dead refresh token; re-auth
                        // interactively in place rather than dumping the user to
                        // the sign-in screen.
                        reauthing.set(true);
                        match crate::bindings::auth::reauthenticate(&t).await {
                            Ok(_) => session
                                .toast_success("Re-authenticated — retry the action that failed."),
                            Err(e) => session.toast_error(
                                format!("Couldn't re-authenticate: {}", e.message),
                                None,
                            ),
                        };
                        reauthing.set(false);
                    }
                    Err(e) => {
                        session.toast_error(format!("Couldn't refresh token: {}", e.message), None);
                    }
                }
                refreshing.set(false);
            });
        }
    };

    // Auto-update: the pending update (if any) + the changelog-splash open flag.
    // The launch check (once on mount) toasts a notification whose action opens
    // the splash; the nav "Check for updates" button opens it directly.
    let update_info: RwSignal<Option<updater::UpdateInfo>> = RwSignal::new(None);
    let update_open = RwSignal::new(false);
    Effect::new(move |_| {
        // Runs once (no tracked reads). A check failure — e.g. a dev build with
        // no updater, or GitHub being unreachable — is swallowed silently; the
        // user can still trigger a manual check from the nav.
        leptos::task::spawn_local(async move {
            if let Ok(Some(info)) = updater::check_for_update().await {
                let version = info.version.clone();
                update_info.set(Some(info));
                session.push_toast(
                    ToastKind::Info,
                    format!("Update available: v{version}"),
                    Some("View changelog".to_string()),
                    Some(Rc::new(move || update_open.set(true))),
                );
            }
        });
    });

    // Manual "Check for updates" — opens the splash when one's found, else a
    // reassuring "up to date" toast; a real failure surfaces as an error toast.
    let checking = RwSignal::new(false);
    let on_check_updates = move |_| {
        if checking.get() {
            return;
        }
        checking.set(true);
        leptos::task::spawn_local(async move {
            match updater::check_for_update().await {
                Ok(Some(info)) => {
                    update_info.set(Some(info));
                    update_open.set(true);
                }
                Ok(None) => {
                    session.toast_success("You're on the latest version.");
                }
                Err(e) => {
                    session.toast_error(format!("Update check failed: {}", e.message), None);
                }
            }
            checking.set(false);
        });
    };

    // Overflow "…" popover in the signed-in user block — holds the low-frequency
    // utilities (cache diagnostics, manual update check, version) so the user
    // block itself slims to identity + Sign Out. Local open flag; closed on an
    // outside mousedown and on Escape.
    let menu_open = RwSignal::new(false);
    let overflow_ref = NodeRef::<leptos::html::Div>::new();
    let outside_handle = window_event_listener(ev::mousedown, move |evt| {
        if !menu_open.get_untracked() {
            return;
        }
        let Some(root) = overflow_ref.get() else {
            return;
        };
        let target = evt
            .target()
            .and_then(|t| t.dyn_into::<web_sys::Node>().ok());
        if !root.contains(target.as_ref()) {
            menu_open.set(false);
        }
    });
    on_cleanup(move || outside_handle.remove());
    use_escape(
        move || menu_open.get_untracked(),
        move || menu_open.set(false),
    );

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

    view! {
        <div class="shell">
            <nav class="shell__nav">
                <div class="shell__brand">
                    <span class="shell__brand-mark">"a"</span>
                    <span class="shell__brand-text">"azapptoolkit"</span>
                </div>
                <div class="shell__nav-list">
                    // Nav IA: three labeled groups (Inventory / Security /
                    // Operations) via `shell__nav-section-label`. Readiness is a
                    // real page, so it lives in the Security group — not down in
                    // the user block with the utilities.
                    <div class="shell__nav-section-label">"Inventory"</div>
                    {nav_row_view("Home", IconName::Home, ActiveView::Home)}
                    {nav_row_view("App Registrations", IconName::AppWindow, ActiveView::Apps)}
                    {nav_row_view("Enterprise Applications", IconName::Building, ActiveView::EnterpriseApps)}
                    {nav_row_view("Managed Identities", IconName::Server, ActiveView::ManagedIdentities)}
                    <div class="shell__nav-section-label">"Security"</div>
                    {nav_row_view("Security", IconName::ShieldCheck, ActiveView::Security)}
                    {nav_row_view("Permission Tester", IconName::Search, ActiveView::PermissionTester)}
                    {nav_row_view("Resource Access", IconName::Database, ActiveView::ResourceAccess)}
                    {nav_row_view("Readiness", IconName::CheckCircle, ActiveView::Readiness)}
                    <div class="shell__nav-section-label">"Operations"</div>
                    {nav_row_view("Bulk Actions", IconName::Wrench, ActiveView::BulkActions)}
                    {nav_row_view("Disaster Recovery", IconName::Download, ActiveView::DisasterRecovery)}
                    {nav_row_view("Key Vault", IconName::Key, ActiveView::KeyVault)}
                    // Logged-in user block — kept inside the scrollable nav list
                    // (directly below Operations) so it stays attached to the nav
                    // and scrolls with it, instead of being pinned to the bottom of
                    // a tall rail where a long content list pushes it out of view.
                    // Slimmed to identity + Sign Out + an overflow "…" popover;
                    // Refresh Token moved to the top bar (next to the tenant chip).
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
                        // Overflow "…" popover for the low-frequency utilities:
                        // cache diagnostics, manual update check, version. Opens
                        // upward (the block is at the bottom of the rail); closes on
                        // outside-click / Escape (wired above).
                        <div class="shell__overflow" node_ref=overflow_ref>
                            <button
                                class="nav__item shell__overflow-trigger"
                                type="button"
                                title="More — cache diagnostics, check for updates, version"
                                aria-haspopup="menu"
                                aria-expanded=move || menu_open.get()
                                on:click=move |_| menu_open.update(|o| *o = !*o)
                            >
                                <span class="nav__icon"><Icon name=IconName::More size=18 /></span>
                                <span class="nav__label">"More"</span>
                            </button>
                            <Show when=move || menu_open.get()>
                                <div class="shell__overflow-menu" role="menu">
                                    <button
                                        class="shell__overflow-item"
                                        type="button"
                                        role="menuitem"
                                        aria-haspopup="dialog"
                                        on:click=move |_| {
                                            session.tenant_ui.cache_open.set(true);
                                            menu_open.set(false);
                                        }
                                    >
                                        <span class="nav__icon"><Icon name=IconName::Activity size=16 /></span>
                                        <span>"Cache diagnostics"</span>
                                    </button>
                                    <button
                                        class="shell__overflow-item"
                                        type="button"
                                        role="menuitem"
                                        disabled=move || checking.get()
                                        on:click=move |ev| {
                                            on_check_updates(ev);
                                            menu_open.set(false);
                                        }
                                    >
                                        <span class="nav__icon">
                                            {move || {
                                                if checking.get() {
                                                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                                        .into_any()
                                                } else {
                                                    view! { <Icon name=IconName::Download size=16 /> }.into_any()
                                                }
                                            }}
                                        </span>
                                        <span>
                                            {move || if checking.get() { "Checking…" } else { "Check for updates" }}
                                        </span>
                                    </button>
                                    // App version, baked at compile time. The release
                                    // bumps the web-rs crate version in lockstep with
                                    // the app, so CARGO_PKG_VERSION is the shipped one.
                                    <div class="shell__overflow-version">
                                        {concat!("Version ", env!("CARGO_PKG_VERSION"))}
                                    </div>
                                </div>
                            </Show>
                        </div>
                    </div>
                </div>
            </nav>
            <div class="shell__main">
                {demo_banner()}
                <header class="shell__topbar">
                    // Left: the persistent app-level page identity — the nav
                    // section group as a crumb + the active view's title (mirrors
                    // the page's `SectionHeader` so identity survives content
                    // scroll). Derived from `session.view`, not the page header.
                    <div class="shell__topbar-left">
                        <div class="shell__topbar-title">
                            <span class="shell__topbar-crumb">
                                {move || topbar_labels(view.get()).0}
                            </span>
                            <span class="shell__topbar-view">
                                {move || topbar_labels(view.get()).1}
                            </span>
                        </div>
                    </div>
                    <div class="shell__topbar-center">
                        <GlobalSearch />
                    </div>
                    // Right: the signed-in tenant chip (org display name + primary
                    // verified domain) + the Refresh-token affordance (silent
                    // refresh, then interactive re-auth if the session is dead).
                    <div class="shell__topbar-right">
                        <div class="shell__tenant-chip" title="Signed-in tenant">
                            <span class="shell__tenant-chip-icon">
                                <Icon name=IconName::Building size=14 />
                            </span>
                            <span class="shell__tenant-chip-text">
                                {move || Suspend::new(async move {
                                    match org.await.as_ref() {
                                        Some(o) => {
                                            let domain = o
                                                .verified_domains
                                                .iter()
                                                .find(|d| d.is_default == Some(true))
                                                .or_else(|| o.verified_domains.first())
                                                .map(|d| d.name.clone());
                                            view! {
                                                <span class="shell__tenant-chip-name">
                                                    {o.display_name.clone()}
                                                </span>
                                                {domain
                                                    .map(|d| {
                                                        view! {
                                                            <span class="shell__tenant-chip-domain">{d}</span>
                                                        }
                                                    })}
                                            }
                                                .into_any()
                                        }
                                        None => {
                                            view! {
                                                <span class="shell__tenant-chip-name">
                                                    {tenant
                                                        .get_untracked()
                                                        .and_then(|t| t.username.clone())
                                                        .unwrap_or_else(|| "—".to_string())}
                                                </span>
                                            }
                                                .into_any()
                                        }
                                    }
                                })}
                            </span>
                        </div>
                        <button
                            class="ui-icon-btn shell__topbar-refresh"
                            type="button"
                            aria-label="Refresh token"
                            title=move || {
                                if reauthing.get() {
                                    "Re-authenticating…"
                                } else if refreshing.get() {
                                    "Refreshing token…"
                                } else {
                                    "Refresh token — re-applies roles activated since sign-in \
                                     (e.g. an active PIM role) without signing out; if your \
                                     session has expired, opens a browser to re-authenticate \
                                     in place"
                                }
                            }
                            disabled=move || refreshing.get()
                            on:click=on_refresh_token
                        >
                            {move || {
                                if refreshing.get() {
                                    view! { <Spinner size=Signal::derive(|| SpinnerSize::Tiny) /> }
                                        .into_any()
                                } else {
                                    view! { <Icon name=IconName::Refresh size=16 /> }.into_any()
                                }
                            }}
                        </button>
                    </div>
                </header>
                // The content area + the workspace overlay share one positioned
                // wrapper (the `1fr` grid row); the dock is the row below it.
                <div class="shell__content-wrap">
                    <div class="shell__content">{children()}</div>
                    <OpenItemsWorkspace />
                </div>
                <OpenItemsDock />
            </div>
            <CacheDiagnosticsDialog
                open=Signal::derive(move || session.tenant_ui.cache_open.get())
                on_close=Callback::new(move |()| session.tenant_ui.cache_open.set(false))
            />
            <UpdateSplash open=update_open info=update_info />
            <ToastHost />
            // Lifted out of ApplicationsView so the dialog state survives view
            // switches (create_open is a signal here, not local to Apps).
            <Show when=move || view.get() == ActiveView::Apps>
                {move || {
                    let open = session.tenant_ui.create_open.get();
                    if !open {
                        return ().into_any();
                    }
                    // Capture session by move into each closure so they stay 'static.
                    let on_close = Callback::new({
                        let session = session;
                        move |()| session.tenant_ui.create_open.set(false)
                    });
                    let on_created_cb = Callback::new({
                        let session = session;
                        move |()| session.bump_apps_reload()
                    });
                    view! {
                        <CreateAppDialog
                            open=Signal::derive(move || session.tenant_ui.create_open.get())
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
                    if !session.tenant_ui.sso_wizard_open.get() {
                        return ().into_any();
                    }
                    let on_close = Callback::new({
                        let session = session;
                        move |()| session.tenant_ui.sso_wizard_open.set(false)
                    });
                    let on_created_cb = Callback::new({
                        let session = session;
                        move |()| {
                            session.enterprise_apps_reload.update(|n| *n = n.wrapping_add(1))
                        }
                    });
                    view! {
                        <SsoWizardDialog
                            open=Signal::derive(move || session.tenant_ui.sso_wizard_open.get())
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

/// The persistent top-bar identity for `view`: `(crumb, title)`. The crumb is
/// the nav section group (Inventory / Security / Operations — the P5 IA), giving
/// the app-level "where am I" context; the title mirrors the page's
/// `SectionHeader` so the anchor keeps naming the page once its header scrolls
/// out of view.
fn topbar_labels(view: ActiveView) -> (&'static str, &'static str) {
    match view {
        ActiveView::Home => ("Inventory", "Overview"),
        ActiveView::Apps => ("Inventory", "App Registrations"),
        ActiveView::EnterpriseApps => ("Inventory", "Enterprise Applications"),
        ActiveView::ManagedIdentities => ("Inventory", "Managed Identities"),
        ActiveView::Security => ("Security", "Security"),
        ActiveView::PermissionTester => ("Security", "Permission Tester"),
        ActiveView::ResourceAccess => ("Security", "Resource Access"),
        ActiveView::Readiness => ("Security", "Access readiness"),
        ActiveView::BulkActions => ("Operations", "Bulk Actions"),
        ActiveView::DisasterRecovery => ("Operations", "Disaster Recovery"),
        ActiveView::KeyVault => ("Operations", "Key Vault"),
    }
}

/// A persistent "this is a demo" strip, rendered only in the GitHub Pages `demo`
/// build (compiled out of the desktop bundle). Sits above the top bar, spanning
/// the content column, so it reads as a global notice without disturbing the nav.
fn demo_banner() -> impl IntoView {
    #[cfg(feature = "demo")]
    {
        view! {
            <div class="demo-banner" role="status">
                <span class="demo-banner__text">
                    "Live demo — sample data, no sign-in. Mutations and exports are disabled."
                </span>
                <a
                    class="demo-banner__link"
                    href="https://github.com/tiredithumans/azapptoolkit"
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    "Get the app"
                </a>
            </div>
        }
        .into_any()
    }
    #[cfg(not(feature = "demo"))]
    {
        ().into_any()
    }
}
