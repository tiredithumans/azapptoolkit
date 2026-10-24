//! In-app auto-update commands.
//!
//! Replaces the former silent background auto-install: the front-end checks on
//! launch ([`check_for_update`]) and, if an update is waiting, shows a changelog
//! splash whose "Update & restart" calls [`perform_update`] — which downloads,
//! installs, and relaunches into the new version. The changelog text rides the
//! updater manifest's `notes` field (populated from `CHANGELOG.md` at release
//! time); download progress streams on the `updater-progress` channel.
//!
//! Both commands consult [`update_gate`] before touching the updater, so the
//! documented opt-out (`AZAPPTOOLKIT_AUTO_UPDATE=0` / `"auto_update": false`)
//! and externally managed installs (MSI, .deb, .rpm) make no updater network
//! call at any point in the session.

use std::time::Duration;

use tauri::utils::config::BundleType;
use tauri::{AppHandle, Emitter};
use tauri_plugin_updater::{UpdaterBuilder, UpdaterExt};

use azapptoolkit_core::http_retry::CONNECT_TIMEOUT;
use azapptoolkit_core::settings::UserSettings;

use crate::dto::UiError;
use crate::dto::updater::{UpdateCheck, UpdateInfo, UpdateProgress, UpdatesDisabled};

/// The longest an update transfer may go without receiving a byte. A READ
/// timeout, not a total one: a slow but moving download of a ~10 MB installer
/// must not be cut off, while a connection that stalls (a proxy holding it
/// open, a dropped Wi-Fi link) fails here instead of leaving the splash on
/// "Updating…" with Later disabled for as long as the OS keeps the socket.
const UPDATE_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// The plugin's HTTP client with this app's transfer budget: the shared
/// connect budget every client sets ([`CONNECT_TIMEOUT`]) plus
/// [`UPDATE_READ_TIMEOUT`]. The plugin sets no timeout of its own, so its
/// check and its download could each hang indefinitely.
fn with_transfer_budget(builder: UpdaterBuilder) -> UpdaterBuilder {
    builder.configure_client(|client| {
        client
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(UPDATE_READ_TIMEOUT)
    })
}

/// How an updater failure is reported: `(code, retryable)`.
///
/// - The update's signature did not verify against the key baked into this
///   build, or it was signed for another version than the one announced:
///   `update_unverified`, never retryable — a retry downloads the same bytes,
///   and installing them is exactly what the signature exists to refuse.
/// - The transfer failed (unreachable, timed out, a non-2xx answer):
///   `network_error`, retryable, the class `core::http_retry` retries.
/// - Anything else (an install that failed, a manifest without this platform,
///   a misconfigured updater): `updater`, not retryable — Update & restart
///   would fail the same way, so the splash points at a manual install.
///
/// The plugin's error enum is `#[non_exhaustive]`, so a new variant lands in
/// `updater` until it is classified here.
fn update_error_class(e: &tauri_plugin_updater::Error) -> (&'static str, bool) {
    use tauri_plugin_updater::Error as E;
    match e {
        E::Minisign(_)
        | E::Base64(_)
        | E::SignatureUtf8(_)
        | E::SignedVersionMismatch { .. }
        | E::MissingSignedVersion => ("update_unverified", false),
        // `ReleaseNotFound` is the check's answer when the endpoint replied
        // without a usable manifest (a 5xx or 404 from the release host).
        E::Reqwest(_) | E::Network(_) | E::ReleaseNotFound => ("network_error", true),
        _ => ("updater", false),
    }
}

/// The `UiError` for a failed update check or install ([`update_error_class`]).
/// The front-end swallows a launch-check failure silently and surfaces a
/// manual-check failure as a dismissable toast; the splash disables Update &
/// restart for a non-retryable one.
fn updater_err(e: tauri_plugin_updater::Error) -> UiError {
    let (code, retryable) = update_error_class(&e);
    let message = match code {
        "update_unverified" => format!(
            "The downloaded update failed its signature check, so it was not installed: {e}"
        ),
        "network_error" => format!("Couldn't reach the update server: {e}"),
        _ => e.to_string(),
    };
    UiError::new(code, message, retryable)
}

/// Building the updater failed (plugin misconfigured / not initialised). The
/// plugin itself logs check failures, but not this one, so log it here.
fn updater_unavailable(e: tauri_plugin_updater::Error) -> UiError {
    tracing::warn!(target: "updater", error = %e, "updater unavailable");
    updater_err(e)
}

/// Who is offered an in-app update — pure, so every combination is unit-tested.
///
/// The install format wins over the opt-out because it is the more specific
/// explanation: an MSI install is managed by the deployment tooling whether or
/// not the operator also turned checks off. Installs the in-app updater does
/// not own are never offered its payload — the manifest only carries the NSIS
/// and AppImage keys, so an MSI install would otherwise get a second, per-user
/// NSIS copy and a .deb install a download that fails as the wrong format.
/// `None` is a dev build or a raw binary and stays updatable.
pub(crate) fn update_policy(
    auto_update: bool,
    bundle: Option<BundleType>,
) -> Option<UpdatesDisabled> {
    // Exhaustive on purpose (no wildcard): a new Tauri bundle type must be
    // classified here before it compiles.
    match bundle {
        Some(BundleType::Msi) => return Some(UpdatesDisabled::Msi),
        Some(BundleType::Deb | BundleType::Rpm) => return Some(UpdatesDisabled::SystemPackage),
        Some(BundleType::Nsis | BundleType::AppImage | BundleType::App | BundleType::Dmg)
        | None => {}
    }
    (!auto_update).then_some(UpdatesDisabled::Policy)
}

/// [`update_policy`] for this process: the opt-out as `UserSettings::load`
/// resolves it (file + env override), read on each call so an edit takes
/// effect without a restart, and the bundle type the bundler baked in.
fn update_gate() -> Option<UpdatesDisabled> {
    let reason = update_policy(
        UserSettings::load(&crate::config_directory()).auto_update,
        tauri::utils::platform::bundle_type(),
    );
    if let Some(r) = reason {
        tracing::info!(target: "updater", reason = ?r, "update check skipped");
    }
    reason
}

/// Checks the configured endpoint for a newer signed release. Returns
/// `Disabled` — without any network call — when [`update_gate`] says the
/// in-app updater is off for this install, `UpToDate` when there is nothing
/// newer, else `Available`.
#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<UpdateCheck, UiError> {
    if let Some(reason) = update_gate() {
        return Ok(UpdateCheck::Disabled { reason });
    }
    let updater = with_transfer_budget(app.updater_builder())
        .build()
        .map_err(updater_unavailable)?;
    // Check failures (network, non-2xx, malformed manifest) are already logged
    // by the plugin; don't log them twice.
    match updater.check().await.map_err(updater_err)? {
        Some(update) => {
            tracing::info!(
                target: "updater",
                current = %update.current_version,
                available = %update.version,
                "update available"
            );
            Ok(UpdateCheck::Available {
                info: UpdateInfo {
                    version: update.version.clone(),
                    current_version: update.current_version.clone(),
                    notes: update.body.clone().unwrap_or_default(),
                    pub_date: update.date.map(|d| d.to_string()),
                },
            })
        }
        None => Ok(UpdateCheck::UpToDate),
    }
}

/// Downloads + installs the pending update (re-checked here so a stale handle
/// can't drive it), streaming byte progress on `updater-progress`, then
/// relaunches into the new version. Never returns on success (`app.restart()`
/// diverges); the awaiting webview is torn down by the relaunch. Refused
/// before any network call when [`update_gate`] says updates are off.
#[tauri::command]
pub async fn perform_update(app: AppHandle) -> Result<(), UiError> {
    if let Some(reason) = update_gate() {
        return Err(UiError::validation(
            "updates_disabled",
            reason.description(),
        ));
    }
    let updater = with_transfer_budget(app.updater_builder())
        .build()
        .map_err(updater_unavailable)?;
    let Some(update) = updater.check().await.map_err(updater_err)? else {
        // Nothing to install (already current) — treat as a no-op success.
        return Ok(());
    };

    let version = update.version.clone();
    let app_progress = app.clone();
    let mut downloaded: u64 = 0;
    update
        .download_and_install(
            move |chunk_len, content_len| {
                downloaded += chunk_len as u64;
                let _ = app_progress.emit(
                    crate::dto::events::UPDATER_PROGRESS,
                    UpdateProgress {
                        downloaded,
                        total: content_len,
                    },
                );
            },
            || {},
        )
        .await
        .map_err(|e| {
            // The plugin logs nothing on a download / signature / install
            // failure; the README promises this lands in the log.
            tracing::warn!(target: "updater", error = %e, version = %version, "update install failed");
            updater_err(e)
        })?;

    // On Windows (NSIS, passive) the installer has run; relaunch applies it.
    app.restart()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signature that does not verify is final (a retry fetches the same
    /// bytes); a transfer failure is the retryable network class; anything
    /// else is not retryable either, so the splash offers the manual install.
    #[test]
    fn update_errors_are_classified_by_what_failed() {
        use tauri_plugin_updater::Error as E;
        let cases: Vec<(E, &str, bool)> = vec![
            (
                E::SignedVersionMismatch {
                    signed: "1.0.0".into(),
                    announced: "2.0.0".into(),
                },
                "update_unverified",
                false,
            ),
            (E::MissingSignedVersion, "update_unverified", false),
            (E::SignatureUtf8("x".into()), "update_unverified", false),
            (
                E::Network("Download request failed with status: 503".into()),
                "network_error",
                true,
            ),
            (E::ReleaseNotFound, "network_error", true),
            (E::TargetNotFound("darwin-aarch64".into()), "updater", false),
            (E::InvalidUpdaterFormat, "updater", false),
            (E::EmptyEndpoints, "updater", false),
            (
                E::Io(std::io::Error::other("the installer could not be written")),
                "updater",
                false,
            ),
        ];
        for (err, code, retryable) in cases {
            let label = err.to_string();
            let ui = updater_err(err);
            assert_eq!(ui.code, code, "{label}");
            assert_eq!(ui.retryable, retryable, "{label}");
            // Consistent with the one retryable-class definition.
            assert_eq!(
                azapptoolkit_core::http_retry::is_retryable_code(&ui.code),
                retryable,
                "{label}"
            );
        }
        // An error from the HTTP client itself (here a URL it refuses, so no
        // socket is needed) is the transfer class too.
        let refused = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .expect("reqwest client builds")
            .get("http://[::1")
            .build()
            .expect_err("an unparseable URL");
        let ui = updater_err(E::Reqwest(refused));
        assert_eq!((ui.code.as_str(), ui.retryable), ("network_error", true));
        assert!(
            ui.message.starts_with("Couldn't reach the update server"),
            "{}",
            ui.message
        );
    }

    #[test]
    fn managed_formats_never_check_and_the_opt_out_stops_everything_else() {
        use UpdatesDisabled::{Msi, Policy, SystemPackage};
        let cases: [(Option<BundleType>, Option<UpdatesDisabled>); 8] = [
            (Some(BundleType::Msi), Some(Msi)),
            (Some(BundleType::Deb), Some(SystemPackage)),
            (Some(BundleType::Rpm), Some(SystemPackage)),
            (Some(BundleType::Nsis), None),
            (Some(BundleType::AppImage), None),
            (Some(BundleType::App), None),
            (Some(BundleType::Dmg), None),
            // A dev build / raw binary has no baked bundle type: it must stay
            // updatable, never be blocked.
            (None, None),
        ];
        for (bundle, when_on) in cases {
            assert_eq!(
                update_policy(true, bundle.clone()),
                when_on,
                "auto_update on, {bundle:?}"
            );
            // The install format wins; everything the updater owns is stopped
            // by the opt-out.
            let when_off = when_on.or(Some(Policy));
            assert_eq!(
                update_policy(false, bundle.clone()),
                when_off,
                "auto_update off, {bundle:?}"
            );
        }
    }
}
