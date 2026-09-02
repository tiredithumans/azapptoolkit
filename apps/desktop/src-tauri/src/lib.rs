mod cert;
mod commands;
mod dto;
mod state;
mod token_adapter;

use tracing_appender::rolling;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

pub fn run() {
    let log_guards = install_tracing();
    install_panic_hook();

    let app_state = state::AppState::new();

    let builder = tauri::Builder::default();
    // macOS only: Windows and Linux get no menu bar at all (Tauri installs a
    // default one only there), and adding one would grow chrome that has never
    // been part of this app.
    #[cfg(target_os = "macos")]
    let builder = builder.menu(macos_menu);

    builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .setup(|_app| {
            // Ensure the config directory exists for the settings/keyring paths.
            // The former silent background auto-install lived here; updates are
            // now interactive — the front-end checks on launch and drives the
            // changelog splash + "Update & restart" via `commands::updater`.
            let config_dir = config_directory();
            let _ = std::fs::create_dir_all(&config_dir);
            Ok(())
        })
        .manage(app_state)
        .manage(log_guards)
        .invoke_handler(tauri::generate_handler![
            commands::config::get_auth_config,
            commands::config::set_auth_config,
            commands::config::restart_app,
            commands::defaults::get_tenant_defaults,
            commands::defaults::set_tenant_defaults,
            commands::updater::check_for_update,
            commands::updater::perform_update,
            commands::auth::sign_in,
            commands::auth::restore_session,
            commands::auth::sign_out,
            commands::auth::refresh_session,
            commands::auth::reauthenticate,
            commands::auth::request_scope_consent,
            commands::backup::backup_tenant,
            commands::backup::save_backup_to_file,
            commands::backup::load_backup_from_file,
            commands::backup::cancel_dr,
            commands::restore::plan_restore,
            commands::restore::restore_tenant,
            commands::restore::save_restore_report_to_file,
            commands::applications::get_organization,
            commands::applications::list_applications_with_pairing,
            commands::applications::get_directory_index_status,
            commands::applications::save_applications_to_file,
            commands::applications::get_application_detail,
            commands::applications::invalidate_application_detail,
            commands::applications::create_application,
            commands::applications::update_application,
            commands::applications::get_application_authentication,
            commands::applications::set_application_authentication,
            commands::expose_api::get_expose_api,
            commands::expose_api::set_identifier_uris,
            commands::expose_api::upsert_api_scope,
            commands::expose_api::delete_api_scope,
            commands::expose_api::set_pre_authorized_app,
            commands::expose_api::remove_pre_authorized_app,
            commands::applications::delete_application,
            commands::applications::add_application_owner,
            commands::applications::remove_application_owner,
            commands::applications::set_application_owners,
            commands::applications::search_users,
            commands::applications::search_groups,
            commands::applications::search_distribution_lists,
            commands::applications::add_password,
            commands::applications::remove_password,
            commands::applications::remove_expired_passwords,
            commands::permissions::list_catalog_resources,
            commands::permissions::list_resource_permissions,
            commands::permissions::list_resource_permission_counts,
            commands::permissions::list_app_role_resources,
            commands::permissions::grant_admin_consent,
            commands::permissions::grant_single_permission,
            commands::permissions::declare_app_permission,
            commands::permissions::downgrade_application_permission,
            commands::permissions::remove_declared_permission,
            commands::permissions::revoke_app_role_assignment,
            commands::permissions::revoke_oauth2_scope,
            commands::applications::add_certificate_credential,
            commands::applications::remove_certificate_credential,
            commands::applications::generate_self_signed_certificate,
            commands::applications::save_generated_certificate_pfx,
            commands::applications::list_federated_credentials,
            commands::applications::add_federated_credential,
            commands::applications::update_federated_credential,
            commands::applications::remove_federated_credential,
            commands::activity::list_directory_audits_for_app,
            commands::activity::get_app_sign_in_activity,
            commands::conditional_access::list_conditional_access_for_app,
            commands::audit::run_audit,
            commands::audit::cancel_audit,
            commands::audit::get_cached_audit,
            commands::audit::save_audit_to_file,
            commands::remediation::remediate_disable_sign_in,
            commands::remediation::remediate_remove_expired_credentials,
            commands::remediation::remediate_remove_redundant_permissions,
            commands::remediation::remediate_scope_mailbox_access,
            commands::remediation::remediate_scope_sharepoint_access,
            commands::bulk::bulk_remove_expired_credentials,
            commands::bulk::bulk_delete_applications,
            commands::bulk::bulk_grant_permissions,
            commands::bulk::bulk_create_applications,
            commands::bulk::bulk_remove_redundant_permissions,
            commands::bulk::bulk_scope_mailbox_access,
            commands::bulk::bulk_scope_sharepoint_access,
            commands::bulk::bulk_add_owner,
            commands::bulk::bulk_disable_sign_in,
            commands::bulk::bulk_stage_sso_certificates,
            commands::bulk::cancel_bulk,
            commands::diagnostics::cache_stats,
            commands::diagnostics::clear_cache,
            commands::diagnostics::invalidate_list_cache,
            commands::diagnostics::set_cache_enabled,
            commands::diagnostics::set_cache_config,
            commands::keyvault::kv_list_secrets,
            commands::keyvault::kv_get_secret,
            commands::keyvault::rotate_app_credential,
            commands::keyvault::list_available_key_vaults,
            commands::exchange::grant_exchange_mailbox_access,
            commands::exchange::list_exchange_role_assignments,
            commands::exchange::get_mail_permission_scopes,
            commands::exchange::get_mail_scopes_for_principal,
            commands::exchange::grant_managed_identity_scoped_exchange_access,
            commands::exchange::remove_exchange_mailbox_access,
            commands::exchange::list_exchange_scope_group,
            commands::exchange::add_exchange_scope_group_members,
            commands::exchange::remove_exchange_scope_group_members,
            commands::exchange::migrate_application_access_policies,
            commands::exchange::move_exchange_scope_to_managed_group,
            commands::exchange::delete_exchange_scope_group,
            commands::managed_identity::list_managed_identities,
            commands::managed_identity::save_managed_identities_to_file,
            commands::managed_identity::grant_managed_identity_permission,
            commands::managed_identity::list_managed_identity_azure_roles,
            commands::managed_identity::assign_managed_identity_azure_role,
            // One held-permissions read for every service-principal type
            // (enterprise app + managed identity).
            commands::graph_roles::list_held_app_role_grants,
            commands::enterprise_application::list_enterprise_applications,
            commands::enterprise_application::save_enterprise_applications_to_file,
            commands::enterprise_application::get_enterprise_application_detail,
            commands::enterprise_application::list_enterprise_app_assignments,
            commands::enterprise_application::assign_enterprise_app_access,
            commands::enterprise_application::remove_enterprise_app_access,
            commands::enterprise_application::list_sp_group_memberships,
            commands::enterprise_application::add_sp_to_group,
            commands::enterprise_application::remove_sp_from_group,
            commands::enterprise_application::get_enterprise_app_provisioning,
            commands::enterprise_application::set_enterprise_app_visibility,
            commands::enterprise_application::set_enterprise_app_account_enabled,
            commands::enterprise_application::set_enterprise_app_assignment_required,
            commands::enterprise_application::set_enterprise_app_notes,
            commands::enterprise_application::add_enterprise_app_owner,
            commands::enterprise_application::remove_enterprise_app_owner,
            commands::enterprise_application::delete_enterprise_application,
            commands::gallery::prefetch_application_gallery,
            commands::gallery::search_application_templates,
            commands::gallery::create_gallery_application,
            commands::app_roles::list_enterprise_app_roles,
            commands::app_roles::upsert_enterprise_app_role,
            commands::app_roles::delete_enterprise_app_role,
            commands::sso::create_saml_sso_application,
            commands::sso::create_oidc_sso_application,
            commands::sso::get_sso_config,
            commands::sso::set_sso_mode,
            commands::sso::set_saml_urls,
            commands::sso::rotate_saml_signing_certificate,
            commands::sso::get_signing_cert_rollover,
            commands::sso::stage_saml_signing_certificate,
            commands::sso::probe_federation_metadata,
            commands::sso::activate_saml_signing_certificate,
            commands::sso::revert_saml_signing_certificate,
            commands::sso::retire_saml_signing_certificate,
            commands::sso::list_sso_certificate_expirations,
            commands::sso::save_sso_certificates_to_file,
            commands::sso::set_claims_mapping,
            commands::sso::set_notification_emails,
            commands::sso::set_oidc_redirect_uris,
            commands::sso::get_sso_summary,
            commands::credentials::list_credential_expirations,
            commands::credentials::save_credentials_to_file,
            commands::consent::list_oauth2_grants_audit,
            commands::consent::save_oauth2_grants_to_file,
            commands::consent::list_app_permission_grants,
            commands::consent::save_app_permission_grants_to_file,
            commands::search::global_search,
            commands::search::prefetch_search_corpus,
            commands::sharepoint::grant_site_access,
            commands::sharepoint::list_site_permissions,
            commands::sharepoint::remove_site_permission,
            commands::sharepoint::convert_site_access_to_selected,
            commands::sharepoint::sweep_site_permissions,
            commands::sharepoint::cancel_resource_sweep,
            commands::sharepoint::get_cached_site_sweep,
            commands::sharepoint::get_app_site_access,
            commands::sharepoint::save_site_access_to_file,
            commands::sharepoint::resolve_sharepoint_resource,
            commands::sharepoint::grant_selected_item_access,
            commands::sharepoint::list_selected_item_permissions,
            commands::sharepoint::remove_selected_item_permission,
            commands::keyvault_rbac::sweep_key_vault_access,
            commands::keyvault_rbac::get_cached_key_vault_access,
            commands::keyvault_rbac::save_key_vault_access_to_file,
            commands::permission_tester::test_mailbox_access,
            commands::permission_tester::find_mailbox_reachers,
            commands::permission_tester::save_mailbox_reachers_to_file,
            commands::usage::get_app_graph_usage,
            commands::permission_tester::test_site_access,
            commands::readiness::check_readiness,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// The macOS menu bar, built explicitly so that **Cmd-W is not a menu key
/// equivalent**.
///
/// With no menu configured, Tauri installs `Menu::default`, whose File and
/// Window submenus both carry Close Window on Cmd-W. AppKit routes a menu key
/// equivalent through NSMenu before the key event ever reaches WKWebView, so
/// the front end's Cmd-W binding — "close the focused open item", not the
/// window — was unreachable on macOS, and one keystroke dropped the whole
/// working set, the audit run and any in-flight dialog. This menu simply has no
/// Close Window item, so the accelerator falls through to the webview and
/// `hooks::use_shortcuts` handles it. (The red traffic light and Cmd-Q are
/// untouched; closing the window was never a keyboard-only route.)
///
/// `enable_macos_default_menu(false)` alone would NOT do: WKWebView takes
/// Cmd-C/V/X/A from the Edit menu's key equivalents, so dropping the menu
/// entirely breaks the clipboard app-wide. The App and Edit submenus are
/// therefore reproduced verbatim from `Menu::default`, and the Window/Help
/// submenus keep Tauri's well-known ids so AppKit still fills in the window
/// list and the Help search field.
#[cfg(target_os = "macos")]
fn macos_menu(app: &tauri::AppHandle) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    use tauri::menu::{
        AboutMetadata, HELP_SUBMENU_ID, Menu, PredefinedMenuItem, Submenu, WINDOW_SUBMENU_ID,
    };

    let pkg = app.package_info();
    let config = app.config();
    let about = AboutMetadata {
        name: Some(pkg.name.clone()),
        version: Some(pkg.version.to_string()),
        copyright: config.bundle.copyright.clone(),
        authors: config.bundle.publisher.clone().map(|p| vec![p]),
        ..Default::default()
    };

    Menu::with_items(
        app,
        &[
            &Submenu::with_items(
                app,
                pkg.name.clone(),
                true,
                &[
                    &PredefinedMenuItem::about(app, None, Some(about))?,
                    &PredefinedMenuItem::separator(app)?,
                    &PredefinedMenuItem::services(app, None)?,
                    &PredefinedMenuItem::separator(app)?,
                    &PredefinedMenuItem::hide(app, None)?,
                    &PredefinedMenuItem::hide_others(app, None)?,
                    &PredefinedMenuItem::separator(app)?,
                    &PredefinedMenuItem::quit(app, None)?,
                ],
            )?,
            // Load-bearing, not decoration — see the doc above: without these
            // key equivalents the webview has no clipboard.
            &Submenu::with_items(
                app,
                "Edit",
                true,
                &[
                    &PredefinedMenuItem::undo(app, None)?,
                    &PredefinedMenuItem::redo(app, None)?,
                    &PredefinedMenuItem::separator(app)?,
                    &PredefinedMenuItem::cut(app, None)?,
                    &PredefinedMenuItem::copy(app, None)?,
                    &PredefinedMenuItem::paste(app, None)?,
                    &PredefinedMenuItem::select_all(app, None)?,
                ],
            )?,
            &Submenu::with_items(
                app,
                "View",
                true,
                &[&PredefinedMenuItem::fullscreen(app, None)?],
            )?,
            // Tauri's default Window submenu minus Close Window; the File
            // submenu held nothing else on macOS, so it is gone entirely.
            &Submenu::with_id_and_items(
                app,
                WINDOW_SUBMENU_ID,
                "Window",
                true,
                &[
                    &PredefinedMenuItem::minimize(app, None)?,
                    &PredefinedMenuItem::maximize(app, None)?,
                ],
            )?,
            &Submenu::with_id_and_items(app, HELP_SUBMENU_ID, "Help", true, &[])?,
        ],
    )
}

/// RAII guards for the rolling file appender — returned so the caller can
/// `manage` them into Tauri state and keep the writer thread alive for the
/// lifetime of the app.
pub struct LogGuards {
    _file: tracing_appender::non_blocking::WorkerGuard,
}

fn install_tracing() -> LogGuards {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,azapptoolkit=debug,desktop=debug"));

    // Rolling daily files under the platform's app-data dir. On Windows this
    // lands in `%APPDATA%\azapptoolkit\logs`; on macOS it's
    // `~/Library/Application Support/azapptoolkit/logs`; on Linux
    // `~/.local/share/azapptoolkit/logs`. We avoid `dirs` as a dependency
    // by computing the path from environment variables the OS provides.
    let log_dir = log_directory();
    let _ = std::fs::create_dir_all(&log_dir);
    // Builder instead of `rolling::daily(dir, "azapptoolkit.log")`: the
    // shorthand appends the date *after* the name (`azapptoolkit.log.2026-06-12`),
    // which breaks file-type association. A suffix yields
    // `azapptoolkit.2026-06-12.log` instead.
    let file_appender = rolling::RollingFileAppender::builder()
        .rotation(rolling::Rotation::DAILY)
        .filename_prefix("azapptoolkit")
        .filename_suffix("log")
        // One file per day forever otherwise — a daily-driver install grows
        // unbounded. Two weeks covers any plausible "what happened last week"
        // support question.
        .max_log_files(14)
        .build(&log_dir)
        .expect("failed to initialize rolling log file appender");
    let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false).compact())
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .with_writer(file_writer),
        )
        .try_init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        log_dir = %log_dir.display(),
        "azapptoolkit starting"
    );
    LogGuards { _file: file_guard }
}

/// Routes panics through `tracing` so the log file captures them. Without
/// this a backend panic goes only to stderr — invisible for a double-clicked
/// GUI app, so a crash report reads "it just closed" and the much-advertised
/// log directory holds nothing. The default hook still runs afterwards
/// (stderr remains useful under `just dev`).
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let backtrace = std::backtrace::Backtrace::force_capture();
        tracing::error!(panic = %info, %backtrace, "backend panic");
        default_hook(info);
    }));
}

fn log_directory() -> std::path::PathBuf {
    config_directory().join("logs")
}

pub(crate) fn config_directory() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            return std::path::PathBuf::from(appdata).join("azapptoolkit");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("azapptoolkit");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("azapptoolkit");
        }
    }
    std::path::PathBuf::from(".")
}

/// `build.rs`'s pure parsers, mounted so their tests run in `cargo test`.
/// A build script belongs to no test target, so this is the only way to cover
/// the `.env` parsing that decides the shipped client/tenant id.
#[cfg(test)]
#[path = "../build_support.rs"]
mod build_support;
