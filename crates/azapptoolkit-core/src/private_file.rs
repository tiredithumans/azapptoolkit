//! Writing a file only its owner can read.
//!
//! Every file this toolkit puts on disk describes, or contains, tenant
//! credentials: `settings.json` records which Key Vault holds which app's
//! secrets, a backup manifest is the whole app estate, and a restore report
//! carries **plaintext show-once client secrets** for redistribution. All of
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        let mut file = file;
        file.write_all(contents)?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        let mut file = std::fs::File::create(path)?;
        file.write_all(contents)?;
        file.sync_all()
    }
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
}
