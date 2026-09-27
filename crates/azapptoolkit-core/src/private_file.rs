//! Writing a file only its owner can read.
//!
//! Every file this toolkit puts on disk describes, or contains, tenant
//! credentials: `settings.json` records which Key Vault holds which app's
//! secrets, a backup manifest is the whole app estate, a restore report
//! carries **plaintext show-once client secrets** for redistribution, and a
//! generated certificate's `.pfx` carries a **private key** (encrypted, but
//! under a password shown on the same screen). All of
//! them were written through `std::fs::write`, which leaves the mode to the
//! process umask — commonly `0644`, world-readable, on a shared or
//! multi-account machine.
//!
//! AGENTS.md's first coding rule is "never write secrets to disk or logs". The
//! files above are the sanctioned exceptions: the operator asked for them. That
//! makes *how* they are written the only control left, so it belongs in one
//! place rather than at each call site.

use std::io::Write;
use std::path::Path;

/// Writes `contents` to `path`, readable and writable by the owner only.
///
/// The permission is applied to the **empty** file, before any content exists,
/// so the bytes are never momentarily present at a wider mode. Setting it
/// explicitly (rather than relying on `OpenOptions::mode`, which applies only
/// at creation) also tightens a file that already existed — the common case,
/// since these are all rewritten in place.
///
/// **Windows** has no mode bits and Rust's std exposes no portable ACL API, so
/// there the write is an ordinary one: the file inherits the ACL of the
/// directory the operator chose, and the app's own config directory already
/// sits under the per-user profile.
pub fn write_owner_only(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    // Written to a sibling temp and renamed over the target, never truncated in
    // place. `settings.json` carries the tenant defaults and the Key Vault
    // bindings the rotation flow needs to find a secret again, and truncating
    // first meant any interruption between the truncate and a completed
    // `write_all`/`sync_all` left the file empty or torn. `UserSettings` then
    // failed to parse it, the caller swallowed that behind `unwrap_or_default()`
    // with a `warn!` the user never sees, and the next writer serialized the
    // defaults back over the top — permanently losing both.
    //
    // `rename` is atomic within a filesystem and preserves the temp's mode, so
    // a reader sees either the old file or the new one, never a partial write,
    // and the 0600 permission tests still hold.
    let temp = temp_sibling(path);
    let result = write_then_rename(&temp, path, contents);
    if result.is_err() {
        // Best effort: leaving a 0600 temp behind is untidy but harmless, and
        // the original error is what the caller needs.
        let _ = std::fs::remove_file(&temp);
    }
    result
}

/// Creates `dir` (and any missing ancestors), readable only by its owner.
///
/// The directories this is for hold what the files above do not: the rolling
/// logs carry tenant ids, app display names, correlation ids, Microsoft Graph
/// error bodies and panic backtraces, and `tracing_appender` creates each log
/// file at the process umask (commonly `0644`). A `0700` directory is the only
/// control over who can read them, and the config directory beside them holds
/// `settings.json`.
///
/// On **unix** every directory this call creates is `0700`; ancestors that
/// already existed are left alone, and only the leaf is tightened, so a
/// directory created before this existed does not keep its `0755` forever. A
/// path with no final component (`.`, `/`, `x/..`) is never re-moded: the
/// config directory falls back to `.` when `HOME` is unset, and chmodding the
/// working directory is not this function's business.
///
/// **Windows** has no mode bits and Rust's std exposes no portable ACL API, so
/// there this is `create_dir_all`: the directory inherits the ACL of the
/// per-user profile it sits under, as [`write_owner_only`]'s files do.
pub fn create_owner_only_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        if dir.file_name().is_some() {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// A temp path beside `path`, so the rename stays within one filesystem.
fn temp_sibling(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp{}", std::process::id()));
    path.with_file_name(name)
}

fn write_then_rename(temp: &Path, path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(temp)?;
        // Explicit, not just `OpenOptions::mode`, which applies only at
        // creation — a temp left behind by a crashed run is reused here.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let mut file = file;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = std::fs::File::create(temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
    }
    std::fs::rename(temp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-rolled rather than pulling in `tempfile`: the settings tests next
    /// door do the same, and a dev-dependency is still a dependency.
    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> TempDir {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "azapptoolkit-private-file-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    /// The write must never truncate the target in place.
    ///
    /// `settings.json` carries the tenant defaults and the vault bindings the
    /// rotation flow needs to find a secret again. Truncating first meant an
    /// interruption before `write_all` completed left the file empty or torn,
    /// `UserSettings::from_file` then failed to parse it, the caller swallowed
    /// that behind `unwrap_or_default()`, and the next writer serialized the
    /// defaults back over the top — permanently losing both.
    #[test]
    fn a_rewrite_never_truncates_the_target_in_place() {
        let dir = tempdir();
        let path = dir.0.join("settings.json");
        write_owner_only(&path, b"{\"first\":true}").unwrap();

        write_owner_only(&path, b"{\"second\":true}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"second\":true}");

        // No temp file survives a successful write.
        let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind: {leftovers:?}"
        );
    }

    /// The rename must carry the 0600 mode, or the atomicity fix would quietly
    /// widen the permissions the rest of this module exists to enforce.
    #[cfg(unix)]
    #[test]
    fn the_renamed_file_keeps_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let path = dir.0.join("settings.json");
        write_owner_only(&path, b"a").unwrap();
        write_owner_only(&path, b"b").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
    }

    #[test]
    fn the_file_is_written_and_readable_back() {
        let dir = tempdir();
        let path = dir.0.join("out.json");
        write_owner_only(&path, b"{\"a\":1}").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"a\":1}");
    }

    #[cfg(unix)]
    #[test]
    fn a_new_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let path = dir.0.join("new.json");
        write_owner_only(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_world_readable_file_is_tightened() {
        // The case `OpenOptions::mode` alone does NOT cover, and the common one
        // here: these files are rewritten in place, so one created before this
        // existed would have kept its 0644 forever.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let path = dir.0.join("old.json");
        std::fs::write(&path, b"old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_owner_only(&path, b"new").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode was {:o}", mode & 0o777);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn a_shorter_write_does_not_leave_the_old_tail() {
        let dir = tempdir();
        let path = dir.0.join("trunc.json");
        write_owner_only(&path, b"a-long-previous-secret").unwrap();
        write_owner_only(&path, b"short").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "short");
    }

    #[test]
    fn creates_nested_dirs() {
        let dir = tempdir();
        let nested = dir.0.join("a").join("b");
        create_owner_only_dir(&nested).unwrap();
        assert!(nested.is_dir());
        // Idempotent: the app calls it on every launch.
        create_owner_only_dir(&nested).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_new_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let nested = dir.0.join("a").join("b");
        create_owner_only_dir(&nested).unwrap();
        for d in [dir.0.join("a"), nested] {
            let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} was {mode:o}", d.display());
        }
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_world_readable_dir_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let d = dir.0.join("d");
        std::fs::create_dir(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();

        create_owner_only_dir(&d).unwrap();

        let mode = std::fs::metadata(&d).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "got {mode:o}");
    }

    /// The `.` fallback of the config directory must never chmod the working
    /// directory. Exercised on a private temp dir only: were the guard broken,
    /// running this against a real `.` or `/tmp` would re-mode it.
    #[cfg(unix)]
    #[test]
    fn a_nameless_path_is_never_remoded() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();

        let nameless = dir.0.join("sub").join("..");
        assert!(nameless.file_name().is_none());
        assert!(create_owner_only_dir(&nameless).is_ok());

        let mode = std::fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "the parent was re-moded to {mode:o}");
    }
}
