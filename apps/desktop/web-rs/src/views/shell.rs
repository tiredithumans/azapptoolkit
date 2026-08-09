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
use crate::components::release_notes::ReleaseNotesDialog;
use crate::components::shortcuts_help::ShortcutsHelp;
use crate::components::toast::{ToastHost, ToastKind};
use crate::components::update_splash::UpdateSplash;
use crate::hooks::use_escape::use_escape;
use crate::hooks::use_shortcuts::use_shortcuts;
use crate::state::{ActiveView, use_session};
use crate::views::dialogs::{
    cache_diagnostics_dialog::CacheDiagnosticsDialog, create_app_dialog::CreateAppDialog,
    gallery_dialog::GalleryDialog, new_app_chooser_dialog::NewAppChooserDialog,
    sso_wizard_dialog::SsoWizardDialog,
};

#[component]
pub fn AppShell(children: Children) -> impl IntoView {
    let session = use_session();
    // The app's global keyboard layer (quick nav, list-filter focus, close item,
    // this sheet). Installed once, here, alongside the shell that owns the
    // surfaces the bindings act on.
    let shortcuts_open = RwSignal::new(false);
    use_shortcuts(session, shortcuts_open);
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
                // A failed sign-out means the backend did NOT clear the OS
                // keyring, so the refresh token is still on disk. Discarding the
                // result and clearing the tenant anyway made "signed out" a
                // claim the app had never verified — and on a shared workstation
                // that claim is the entire point of the button.
                //
                // So the local session is cleared only on success. Staying put
                // is the honest state (the operator IS still signed in) and it
                // is also the only way the error can be seen: `ToastHost` mounts
                // inside this tenant-gated shell, so a toast pushed on the way
                // out would unmount before it rendered.
                let outcome = crate::bindings::auth::sign_out(&t).await;
                // Reset before the tenant clears: that unmounts this shell, and
                // writing to a signal after its owner is disposed is an error.
                signing_out.set(false);
                match outcome {
                    Ok(()) => session.set_active_tenant(None),
                    Err(e) => {
                        session.toast_error(
                            format!(
                                "Sign-out failed, so you are still signed in and the stored \
                                 credentials were not cleared: {}. Try again — if it keeps \
                                 failing, remove the azapptoolkit entry from your OS credential \
                                 store.",
                                e.message
                            ),
                            None,
                        );
                    }
                }
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
                        // Re-applied roles may change access, so re-run a mounted
                        // Access Readiness checklist (this is its only re-check).
                        session.bump_readiness_reload();
                        session.toast_success(
                            "Token refreshed — roles activated since sign-in now apply. \
                             Retry the action that failed.",
                        );
                    }
                    Err(e) if e.is_reauth_fatal() => {
                        // Silent re-mint can't fix a dead refresh token; re-auth
                        // interactively in place rather than dumping the user to
                        // the sign-in screen.
                        reauthing.set(true);
                        match crate::bindings::auth::reauthenticate(&t).await {
                            Ok(_) => {
                                session.bump_readiness_reload();
                                session.toast_success(
                                    "Re-authenticated — retry the action that failed.",
                                )
                            }
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
    // "What's new" for the version already installed — the notes baked into
    // this build, reachable from the account menu after the splash is gone.
    let release_notes_open = RwSignal::new(false);
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

    // Account menu hung off the top-right tenant pill: the operator/tenant
    // cluster (identity, Access Readiness, Settings, cache diagnostics, update
    // check, Sign Out, version) that used to sit at the foot of the left rail.
    // Opens downward from the pill; closes on outside mousedown and on Escape.
    let menu_open = RwSignal::new(false);
    let account_ref = NodeRef::<leptos::html::Div>::new();
    let outside_handle = window_event_listener(ev::mousedown, move |evt| {
        if !menu_open.get_untracked() {
            return;
        }
        let Some(root) = account_ref.get() else {
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

    // A menu row that navigates to `target` and closes the menu. Marks the active
    // view with `aria-current` + a selected class (mirrors `nav_row_view`).
    let account_nav_item = move |label: &'static str, icon: IconName, target: ActiveView| {
        let class = move || {
            let mut c = String::from("shell__account-item");
            if view.get() == target {
                c.push_str(" shell__account-item--selected");
            }
            c
        };
        let aria_current = move || (view.get() == target).then_some("page");
        view! {
            <button
                class=class
                type="button"
                role="menuitem"
                aria-current=aria_current
                on:click=move |_| {
                    session.set_view(target);
                    menu_open.set(false);
                }
            >
                <span class="nav__icon"><Icon name=icon size=16 /></span>
                <span>{label}</span>
            </button>
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

    view! {
        <div class="shell">
            <nav class="shell__nav">
                <div class="shell__brand">
                    <span class="shell__brand-mark">"a"</span>
                    <span class="shell__brand-text">"azapptoolkit"</span>
                </div>
                <div class="shell__nav-list">
                    // Nav IA: three labeled groups (Inventory / Security /
                    // Operations) via `shell__nav-section-label`. Operator/tenant
                    // context (Access Readiness, Settings, cache, updates, Sign Out)
                    // is NOT here — it hangs off the top-bar tenant pill's account
                    // menu, since it's about the signed-in operator, not the org's apps.
                    <div class="shell__nav-section-label">"Inventory"</div>
                    {nav_row_view("Home", IconName::Home, ActiveView::Home)}
                    {nav_row_view("App Registrations", IconName::AppWindow, ActiveView::Apps)}
                    {nav_row_view("Enterprise Applications", IconName::Building, ActiveView::EnterpriseApps)}
                    {nav_row_view("Managed Identities", IconName::Server, ActiveView::ManagedIdentities)}
                    <div class="shell__nav-section-label">"Security"</div>
                    {nav_row_view("Security", IconName::ShieldCheck, ActiveView::Security)}
                    {nav_row_view("Permission Tester", IconName::Search, ActiveView::PermissionTester)}
                    {nav_row_view("Resource Access", IconName::Database, ActiveView::ResourceAccess)}
                    <div class="shell__nav-section-label">"Operations"</div>
                    {nav_row_view("Bulk Actions", IconName::Wrench, ActiveView::BulkActions)}
                    {nav_row_view("Disaster Recovery", IconName::Download, ActiveView::DisasterRecovery)}
                    {nav_row_view("Key Vault", IconName::Key, ActiveView::KeyVault)}
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
                    // Right: the signed-in tenant pill — which doubles as the
                    // account-menu trigger (org identity + chevron → operator/tenant
                    // actions) — plus the Refresh-token affordance (silent refresh,
                    // then interactive re-auth if the session is dead).
                    <div class="shell__topbar-right">
                        <div class="shell__account" node_ref=account_ref>
                            <button
                                class="shell__tenant-chip"
                                type="button"
                                title="Account — access readiness, settings, sign out"
                                aria-haspopup="menu"
                                aria-expanded=move || menu_open.get()
                                on:click=move |_| menu_open.update(|o| *o = !*o)
                            >
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
                                <span class="shell__tenant-chip-caret">
                                    <Icon name=IconName::ChevronDown size=14 />
                                </span>
                            </button>
                            <Show when=move || menu_open.get()>
                                <div class="shell__account-menu" role="menu">
                                    <div class="shell__account-menu-header">
                                        <span class="shell__account-menu-label">"Signed in as"</span>
                                        <span class="shell__account-menu-user">
                                            {move || {
                                                tenant
                                                    .get()
                                                    .and_then(|t| t.username.clone())
                                                    .unwrap_or_else(|| "—".to_string())
                                            }}
                                        </span>
                                    </div>
                                    {account_nav_item(
                                        "Access Readiness",
                                        IconName::CheckCircle,
                                        ActiveView::Readiness,
                                    )}
                                    {account_nav_item("Settings", IconName::Settings, ActiveView::Settings)}
                                    <div class="shell__account-divider" role="separator"></div>
                                    <button
                                        class="shell__account-item"
                                        type="button"
                                        role="menuitem"
                                        on:click=move |_| {
                                            session.tenant_ui.cache_open.set(true);
                                            menu_open.set(false);
                                        }
                                    >
                                        <span class="nav__icon"><Icon name=IconName::Activity size=16 /></span>
                                        <span>"Cache diagnostics"</span>
                                    </button>
                                    <button
                                        class="shell__account-item"
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
                                    <div class="shell__account-divider" role="separator"></div>
                                    <button
                                        class="shell__account-item shell__account-item--signout"
                                        type="button"
                                        role="menuitem"
                                        disabled=move || signing_out.get()
                                        on:click=move |ev| {
                                            on_sign_out(ev);
                                            menu_open.set(false);
                                        }
                                    >
                                        <span class="nav__icon"><Icon name=IconName::LogOut size=16 /></span>
                                        <span>
                                            {move || if signing_out.get() { "Signing out…" } else { "Sign Out" }}
                                        </span>
                                    </button>
                                    // App version, baked at compile time — the release
                                    // bumps web-rs in lockstep, so CARGO_PKG_VERSION is
                                    // the shipped one. "What's new" re-opens this
                                    // version's release notes, which otherwise existed
                                    // only in the update splash the user already
                                    // dismissed.
                                    <div class="shell__account-version">
                                        <span>{concat!("Version ", env!("CARGO_PKG_VERSION"))}</span>
                                        // `role="menuitem"` like its siblings: the
                                        // container is `role="menu"`, where an
                                        // interactive child with no role is invisible
                                        // to a screen reader walking the menu.
                                        <button
                                            class="link-btn"
                                            type="button"
                                            role="menuitem"
                                            on:click=move |_| {
                                                release_notes_open.set(true);
                                                menu_open.set(false);
                                            }
                                        >
                                            "What's new"
                                        </button>
                                    </div>
                                </div>
                            </Show>
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
                    <ShortcutsHelp open=shortcuts_open />
                </div>
                <OpenItemsDock />
            </div>
            <CacheDiagnosticsDialog
                open=Signal::derive(move || session.tenant_ui.cache_open.get())
                on_close=Callback::new(move |()| session.tenant_ui.cache_open.set(false))
            />
            <UpdateSplash open=update_open info=update_info />
            <ReleaseNotesDialog open=release_notes_open />
            <ToastHost />
            <ToolDialogs />
        </div>
    }
}

/// One shell-mounted tool dialog: gated on the active view AND on its own open
/// flag, with the `open` signal and the `on_close` callback both derived from
/// that single flag.
///
/// Four dialogs repeated this ~20-line shape verbatim inside `AppShell`. The
/// only things that genuinely differ are the view a dialog mounts under, the
/// flag that opens it, and the element itself — so those are the only things
/// left at the call site.
fn tool_dialog<V>(
    mount_on: ActiveView,
    flag: RwSignal<bool>,
    render: impl Fn(Signal<bool>, Callback<()>) -> V + Copy + Send + Sync + 'static,
) -> impl IntoView
where
    V: IntoView + 'static,
{
    let view = use_session().view;
    view! {
        <Show when=move || view.get() == mount_on>
            {move || {
                if !flag.get() {
                    return ().into_any();
                }
                render(Signal::derive(move || flag.get()), Callback::new(move |()| flag.set(false)))
                    .into_any()
            }}
        </Show>
    }
}

/// The shell-mounted dialogs, lifted out of the views that launch them so their
/// (often multi-step) state survives a view switch. Mounted exactly once, in
/// [`AppShell`].
#[component]
fn ToolDialogs() -> impl IntoView {
    let session = use_session();
    let ui = session.tenant_ui;
    let bump_enterprise_apps = move || {
        session
            .enterprise_apps_reload
            .update(|n| *n = n.wrapping_add(1))
    };
    view! {
        {tool_dialog(
            ActiveView::Apps,
            ui.create_open,
            move |open, on_close| {
                view! {
                    <CreateAppDialog
                        open=open
                        on_close=on_close
                        on_created=Callback::new(move |()| session.bump_apps_reload())
                    />
                }
            },
        )}
        {tool_dialog(
            ActiveView::EnterpriseApps,
            ui.sso_wizard_open,
            move |open, on_close| {
                view! {
                    <SsoWizardDialog
                        open=open
                        on_close=on_close
                        on_created=Callback::new(move |()| bump_enterprise_apps())
                    />
                }
            },
        )}
        {tool_dialog(
            ActiveView::EnterpriseApps,
            ui.new_app_chooser_open,
            move |open, on_close| view! { <NewAppChooserDialog open=open on_close=on_close /> },
        )}
        {tool_dialog(
            ActiveView::EnterpriseApps,
            ui.gallery_open,
            move |open, on_close| {
                view! {
                    <GalleryDialog
                        open=open
                        on_close=on_close
                        on_created=Callback::new(move |()| bump_enterprise_apps())
                    />
                }
            },
        )}
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
        ActiveView::Readiness => ("Account", "Access Readiness"),
        ActiveView::Settings => ("Account", "Settings"),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `ActiveView` gets a breadcrumb, and every breadcrumb sits under one
    /// of the four nav groups.
    ///
    /// `topbar_labels` is a total match, so a NEW variant fails to compile here
    /// — but a variant added with a placeholder, or moved between nav groups
    /// without the sidebar following, compiles fine and ships a wrong or blank
    /// breadcrumb. shell.rs is 679 lines with no inline tests at all; this is
    /// the pure logic in it.
    #[test]
    fn every_view_has_a_breadcrumb_in_a_known_group() {
        const GROUPS: [&str; 4] = ["Inventory", "Security", "Account", "Operations"];
        let views = [
            ActiveView::Home,
            ActiveView::Apps,
            ActiveView::EnterpriseApps,
            ActiveView::ManagedIdentities,
            ActiveView::Security,
            ActiveView::PermissionTester,
            ActiveView::ResourceAccess,
            ActiveView::Readiness,
            ActiveView::Settings,
            ActiveView::BulkActions,
            ActiveView::DisasterRecovery,
            ActiveView::KeyVault,
        ];
        for view in views {
            let (group, leaf) = topbar_labels(view);
            assert!(
                GROUPS.contains(&group),
                "{view:?} is filed under unknown nav group {group:?}"
            );
            assert!(!leaf.is_empty(), "{view:?} has a blank breadcrumb leaf");
        }
    }

    /// Two destinations sharing a leaf label are indistinguishable in the
    /// breadcrumb. `Security` is the one deliberate self-titled case (the group
    /// and the page are the same thing); everything else must be unique.
    #[test]
    fn breadcrumb_leaves_are_unique() {
        let mut seen: Vec<&str> = Vec::new();
        for view in [
            ActiveView::Home,
            ActiveView::Apps,
            ActiveView::EnterpriseApps,
            ActiveView::ManagedIdentities,
            ActiveView::Security,
            ActiveView::PermissionTester,
            ActiveView::ResourceAccess,
            ActiveView::Readiness,
            ActiveView::Settings,
            ActiveView::BulkActions,
            ActiveView::DisasterRecovery,
            ActiveView::KeyVault,
        ] {
            let (_, leaf) = topbar_labels(view);
            assert!(!seen.contains(&leaf), "duplicate breadcrumb leaf {leaf:?}");
            seen.push(leaf);
        }
    }
}
