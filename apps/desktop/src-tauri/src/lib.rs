mod cert;
mod commands;
mod dto;
mod state;
mod token_adapter;

use azapptoolkit_core::settings::UserSettings;
use tauri_plugin_updater::UpdaterExt;
use tracing_appender::rolling;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn run() {
    let log_guards = install_tracing();
    install_panic_hook();

    let app_state = state::AppState::new();

    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let config_dir = config_directory();
            let _ = std::fs::create_dir_all(&config_dir);
            let settings = UserSettings::load(&config_dir);
            tracing::info!(auto_update = settings.auto_update, "loaded user settings");

            if settings.auto_update {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    match handle.updater() {
                        Ok(updater) => match updater.check().await {
                            Ok(Some(update)) => {
                                tracing::info!(
                                    version = %update.version,
                                    "update available, downloading"
                                );
                                if let Err(e) = update.download_and_install(|_, _| {}, || {}).await
                                {
                                    tracing::warn!(error = %e, "auto-update failed");
                                }
                            }
                            Ok(None) => tracing::debug!("no update available"),
                            Err(e) => tracing::warn!(error = %e, "update check failed"),
                        },
                        Err(e) => tracing::warn!(error = %e, "updater unavailable"),
                    }
                });
            } else {
                tracing::info!("auto-update disabled by user settings");
            }
            Ok(())
        })
        .manage(app_state)
        .manage(log_guards)
        .invoke_handler(tauri::generate_handler![
            commands::config::get_auth_config,
            commands::config::set_auth_config,
            commands::config::restart_app,
            commands::auth::sign_in,
            commands::auth::sign_out,
            commands::auth::current_tenants,
            commands::auth::refresh_session,
            commands::auth::request_scope_consent,
            commands::backup::backup_tenant,
            commands::backup::save_backup_to_file,
            commands::backup::load_backup_from_file,
            commands::backup::cancel_dr,
            commands::restore::plan_restore,
            commands::restore::restore_tenant,
            commands::restore::save_restore_report_to_file,
            commands::applications::get_organization,
            commands::applications::list_applications,
            commands::applications::list_applications_with_pairing,
            commands::applications::save_applications_to_file,
            commands::applications::get_application_detail,
            commands::applications::invalidate_application_detail,
            commands::applications::resolve_permission,
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
            commands::applications::add_password,
            commands::applications::remove_password,
            commands::applications::remove_expired_passwords,
            commands::permissions::list_catalog_resources,
            commands::permissions::list_resource_permissions,
            commands::permissions::list_resource_permission_counts,
            commands::permissions::update_required_resource_access,
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
            commands::audit::export_audit_csv,
            commands::audit::save_audit_to_file,
            commands::remediation::remediate_remove_expired_credentials,
            commands::remediation::remediate_remove_redundant_permissions,
            commands::remediation::remediate_scope_mailbox_access,
            commands::remediation::remediate_scope_sharepoint_access,
            commands::bulk::bulk_remove_expired_credentials,
            commands::bulk::bulk_delete_applications,
            commands::bulk::bulk_grant_permissions,
            commands::bulk::bulk_create_applications,
            commands::bulk::cancel_bulk,
            commands::diagnostics::cache_stats,
            commands::diagnostics::clear_cache,
            commands::diagnostics::invalidate_list_cache,
            commands::diagnostics::set_cache_enabled,
            commands::diagnostics::set_cache_config,
            commands::keyvault::kv_list_secrets,
            commands::keyvault::kv_get_secret,
            commands::keyvault::kv_set_secret,
            commands::keyvault::rotate_app_credential,
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
            commands::app_roles::list_enterprise_app_roles,
            commands::app_roles::upsert_enterprise_app_role,
            commands::app_roles::delete_enterprise_app_role,
            commands::sso::create_saml_sso_application,
            commands::sso::create_oidc_sso_application,
            commands::sso::get_sso_config,
            commands::sso::set_sso_mode,
            commands::sso::set_saml_urls,
            commands::sso::rotate_saml_signing_certificate,
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
            commands::sharepoint::grant_site_access,
            commands::sharepoint::list_site_permissions,
            commands::sharepoint::remove_site_permission,
            commands::sharepoint::convert_site_access_to_selected,
            commands::sharepoint::sweep_site_permissions,
            commands::sharepoint::cancel_resource_sweep,
            commands::sharepoint::get_cached_site_sweep,
            commands::permission_tester::test_mailbox_access,
            commands::permission_tester::find_mailbox_reachers,
            commands::usage::get_app_graph_usage,
            commands::permission_tester::test_site_access,
            commands::readiness::check_readiness,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
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
