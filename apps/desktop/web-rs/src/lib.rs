//! Library crate for the azapptoolkit front-end. The actual entry point is the
//! thin `main.rs` binary, which only calls [`run`]; everything else lives here
//! as a library so the views, components, and helpers are reachable from
//! integration tests (a binary-only crate exposes nothing). The Trunk build
//! still bundles the `main.rs` bin; this split adds no runtime cost.
//!
//! Exposing the view/component modules as `pub` (so integration tests can mount
//! them) makes each `#[component]` fn `pub`, and many take props of crate-
//! internal types — an intentional design (those types are not part of any
//! shipped API; the components are only "public" to be test-mountable). Allow
//! the resulting `private_interfaces` lint crate-wide rather than leaking those
//! prop types into the public surface.
#![allow(private_interfaces)]

use leptos::prelude::*;
use thaw::{ConfigProvider, Theme};

pub mod bindings;
pub mod components;
pub mod constants;
pub mod hooks;
pub mod state;
pub mod util;
pub mod views;

// Shared mock Tauri IPC bridge (installs `window.__TAURI_INTERNALS__` + a route
// registry of canned fixtures). Compiled only for the test harness and the demo
// build — never the shipped desktop bundle.
#[cfg(feature = "mock-ipc")]
pub mod ipc_mock;

// Browser test harness: mounts real views with the Tauri IPC bridge mocked, so
// GUI behaviour is exercised without a live tenant. Behind a feature so it is
// never compiled into the shipped Trunk bundle (`web-build` doesn't enable it).
#[cfg(feature = "test-support")]
pub mod test_support;

// GitHub Pages demo: pre-loads the mock IPC bridge with curated sample data and
// signs into a demo tenant, so the full UI runs in a plain browser. Enabled only
// by `just web-build-pages`.
#[cfg(feature = "demo")]
pub mod demo;

use state::{ActiveView, provide_session, use_session};
use util::keep_alive;
use views::{
    applications_view::ApplicationsView, bulk_actions_view::BulkActionsView,
    config_screen::ConfigScreen, dr::DisasterRecoveryView,
    enterprise_applications_view::EnterpriseApplicationsView, home_dashboard::HomeDashboard,
    key_vault_view::KeyVaultView, managed_identities::ManagedIdentitiesView,
    permission_tester_view::PermissionTesterView, readiness_view::ReadinessView,
    resource_access::ResourceAccessView, security_view::SecurityView, settings_view::SettingsView,
    shell::AppShell, sign_in::SignInScreen,
};

/// Boot the app: install the panic hook and mount the Leptos+Thaw root onto the
/// document body. Called by the `main.rs` binary.
pub fn run() {
    console_error_panic_hook::set_once();
    // Demo build: install the mock IPC bridge + sample data before the app mounts
    // so the first resource fires against fixtures, not a (missing) backend.
    #[cfg(feature = "demo")]
    demo::install();
    mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    provide_session();
    // Demo build: start already signed in to the demo tenant so the config and
    // sign-in gates fall through to the authenticated shell.
    #[cfg(feature = "demo")]
    use_session().set_active_tenant(Some(demo::demo_tenant()));
    let theme = RwSignal::new(initial_theme());

    view! {
        <ConfigProvider theme>
            <Root />
        </ConfigProvider>
    }
}

#[component]
fn Root() -> impl IntoView {
    let session = use_session();
    let tenant = session.active_tenant;

    // One-shot config-status check into a plain signal. Deliberately NOT a
    // <Suspense>/Suspend gate: a reactive `match` keeps the app's Suspense
    // topology unchanged. An app-wide Suspense around the whole shell can
    // surface write-during-render bugs in nested panes (it did — the enterprise
    // detail pane looped). `None` = the fast local-IPC check is still in flight.
    // Demo build short-circuits to "configured" (no first-run config screen); the
    // live build probes the backend.
    let configured = RwSignal::new(if cfg!(feature = "demo") {
        Some(true)
    } else {
        None::<bool>
    });
    #[cfg(not(feature = "demo"))]
    leptos::task::spawn_local(async move {
        configured.set(Some(bindings::config::get_auth_config().await.configured));
    });

    view! {
        <div style="height: 100%; display: flex; flex-direction: column;">
            {move || match configured.get() {
                None => ().into_any(),
                // Freshly-downloaded release with no usable client/tenant IDs:
                // configure them (saved to settings.json) before any sign-in.
                Some(false) => view! { <ConfigScreen /> }.into_any(),
                Some(true) => {
                    view! {
                        {move || match tenant.get() {
                            None => view! { <SignInScreen /> }.into_any(),
                            Some(_) => view! { <AuthedShell /> }.into_any(),
                        }}
                    }
                        .into_any()
                }
            }}
        </div>
    }
}

/// Authenticated content: the persistent shell plus a *keep-alive* set of view
/// panes. Each pane mounts lazily on first visit and then stays mounted; only
/// its CSS `display` toggles on view switch. This avoids unmounting/remounting
/// a view on every nav click — which previously re-ran each view's data
/// resource (a fresh Tauri IPC round trip + deserialize + re-render) and
/// discarded scroll/selection state. With keep-alive, returning to an
/// already-loaded view is instant: its `LocalResource` value is still cached
/// and nothing refetches (its tracked inputs don't change on a switch).
#[component]
fn AuthedShell() -> impl IntoView {
    let session = use_session();
    let view = session.view;

    // Insert-only latch of visited views. Seeded with the current view so the
    // first pane is mounted on the initial render (no empty flash), and grown
    // by the effect below as the user navigates.
    let visited = RwSignal::new(std::collections::HashSet::from([view.get_untracked()]));
    Effect::new(move |_| {
        let v = view.get();
        visited.update(|set| {
            set.insert(v);
        });
    });

    view! {
        <AppShell>
            {keep_alive(view, visited, ActiveView::Home, || view! { <HomeDashboard /> })}
            {keep_alive(view, visited, ActiveView::Apps, || view! { <ApplicationsView /> })}
            {keep_alive(
                view,
                visited,
                ActiveView::EnterpriseApps,
                || view! { <EnterpriseApplicationsView /> },
            )}
            {keep_alive(
                view,
                visited,
                ActiveView::ManagedIdentities,
                || view! { <ManagedIdentitiesView /> },
            )}
            {keep_alive(view, visited, ActiveView::Security, || view! { <SecurityView /> })}
            {keep_alive(
                view,
                visited,
                ActiveView::PermissionTester,
                || view! { <PermissionTesterView /> },
            )}
            {keep_alive(
                view,
                visited,
                ActiveView::ResourceAccess,
                || view! { <ResourceAccessView /> },
            )}
            {keep_alive(view, visited, ActiveView::KeyVault, || view! { <KeyVaultView /> })}
            {keep_alive(view, visited, ActiveView::BulkActions, || view! { <BulkActionsView /> })}
            {keep_alive(
                view,
                visited,
                ActiveView::DisasterRecovery,
                || view! { <DisasterRecoveryView /> },
            )}
            {keep_alive(view, visited, ActiveView::Readiness, || view! { <ReadinessView /> })}
            {keep_alive(view, visited, ActiveView::Settings, || view! { <SettingsView /> })}
        </AppShell>
    }
}

/// Pick light or dark based on `prefers-color-scheme`.
fn initial_theme() -> Theme {
    let dark = web_sys::window()
        .and_then(|w| w.match_media("(prefers-color-scheme: dark)").ok().flatten())
        .map(|m| m.matches())
        .unwrap_or(false);
    if dark { Theme::dark() } else { Theme::light() }
}
