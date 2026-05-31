//! Filesystem helpers shared by client and server.
//!
//! Centralizes the `O_NOFOLLOW` open pattern that's used in several
//! places to prevent a planted symlink from redirecting an open to an
//! arbitrary file. All callers should funnel
//! through here so the cfg-unix gating stays in one place.

use std::fs::OpenOptions;
use std::path::Path;

/// Apply `O_NOFOLLOW` on unix, plus a 0o600 create mode when
/// `owner_only`. No-op on other platforms (where symlinks have
/// different semantics and the same attack surface doesn't apply).
///
/// Invariant: `custom_flags` *replaces* the open's custom flag set
/// rather than OR-ing into it, so this helper must be the sole owner
/// of custom flags on `opts`. Do not combine it with a caller-side
/// `custom_flags(..)` (e.g. `O_DIRECT`, `O_CLOEXEC`): whichever call
/// runs last wins and the other's flags — including `O_NOFOLLOW` — are
/// silently dropped. Funnel any new flag through this module instead.
pub fn apply_secure_open(opts: &mut OpenOptions, owner_only: bool) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if owner_only {
            opts.mode(0o600);
        }
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    {
        let _ = owner_only;
    }
    opts
}

/// Apply `O_NOFOLLOW` to an `OpenOptions` on unix. No-op on other
/// platforms (where symlinks have different semantics and the same
/// attack surface doesn't apply).
pub fn apply_no_follow(opts: &mut OpenOptions) -> &mut OpenOptions {
    apply_secure_open(opts, false)
}

/// Apply `O_NOFOLLOW | O_NONBLOCK` on unix. No-op on other platforms.
///
/// Used for the Get open path: if a planted path is a FIFO, a plain
/// blocking `open()` would hang until a writer appears (DoS, #309).
/// `O_NONBLOCK` makes the `open` itself non-blocking so a FIFO with no
/// writer returns immediately instead of stalling the request. On a
/// regular file `O_NONBLOCK` is harmless — the flag is a no-op for
/// regular-file reads, which stay blocking as usual.
///
/// Like [`apply_secure_open`], this *replaces* the custom flag set, so
/// it must own the custom flags on `opts`; don't pair it with another
/// `custom_flags(..)` call.
pub fn apply_no_follow_nonblock(opts: &mut std::fs::OpenOptions) -> &mut std::fs::OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    opts
}

/// Apply `O_NOFOLLOW` and a 0o600 create mode on unix. Used when the
/// file being opened holds material we never want another local user
/// to read -- private keys and in-flight Put temp files. Without an
/// explicit mode the file inherits the daemon umask (typically 0o022
/// -> 0o644 = world-readable) which leaks the content for the duration
/// the file exists.
///
/// Two independent concerns are bundled here, both unix-only:
///   * `O_NOFOLLOW` defends against a planted symlink redirecting the
///     open. No-op off unix because symlink semantics differ there.
///   * the 0o600 create mode is the owner-only secrecy guarantee. This
///     is *not* implemented off unix: `#[cfg(not(unix))]` ignores
///     `owner_only` entirely, so on Windows the file is created with the
///     OS-default ACL and is **not** owner-restricted. Callers writing
///     secrets (private keys, in-flight temps) on a non-unix target must
///     not rely on this for confidentiality; the current production
///     target is unix only.
pub fn apply_owner_only_no_follow(opts: &mut OpenOptions) -> &mut OpenOptions {
    apply_secure_open(opts, true)
}

/// Require that a path's `symlink_metadata` reports a regular file.
/// Used by the Put resume path before reopening an existing temp file
/// for read/append: even with `O_NOFOLLOW` we still want to refuse a
/// directory or other special file.
pub fn require_regular_file(path: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "resume temp is not a regular file (symlink or directory?)",
        ));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::path::PathBuf;

    /// Per-test scratch dir under the system temp root, removed on drop.
    /// qftp-common has no `tempfile` dev-dep, so this stands in for it.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "qftp-fs-safe-{tag}-{}-{nanos}-{seq}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn require_regular_file_accepts_regular() {
        let scratch = Scratch::new("regular");
        let p = scratch.join("file");
        std::fs::write(&p, b"hi").unwrap();
        require_regular_file(&p).expect("a plain regular file should pass");
    }

    #[test]
    fn require_regular_file_rejects_directory() {
        let scratch = Scratch::new("dir");
        let p = scratch.join("subdir");
        std::fs::create_dir(&p).unwrap();
        let err = require_regular_file(&p).expect_err("a directory must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn require_regular_file_rejects_symlink() {
        let scratch = Scratch::new("symlink");
        let target = scratch.join("target");
        std::fs::write(&target, b"secret").unwrap();
        let link = scratch.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // symlink_metadata inspects the link itself, not its target, so
        // is_file() must be false even though `target` is a regular file.
        let err = require_regular_file(&link).expect_err("a symlink must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn require_regular_file_rejects_fifo() {
        let scratch = Scratch::new("fifo");
        let p = scratch.join("pipe");
        let c = std::ffi::CString::new(p.as_os_str().to_str().unwrap()).unwrap();
        let ret = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(ret, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
        let err = require_regular_file(&p).expect_err("a FIFO must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn require_regular_file_rejects_missing() {
        let scratch = Scratch::new("missing");
        let p = scratch.join("nope");
        let err = require_regular_file(&p).expect_err("a missing path must error");
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    #[test]
    fn apply_no_follow_nonblock_open_of_writerless_fifo_does_not_block() {
        let scratch = Scratch::new("nonblock-fifo");
        let p = scratch.join("pipe");
        let c = std::ffi::CString::new(p.as_os_str().to_str().unwrap()).unwrap();
        let ret = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(ret, 0, "mkfifo failed: {}", std::io::Error::last_os_error());
        let mut opts = OpenOptions::new();
        opts.read(true);
        apply_no_follow_nonblock(&mut opts);
        // O_RDONLY|O_NONBLOCK open of a writer-less FIFO returns
        // immediately; without O_NONBLOCK this would hang forever
        // waiting for a writer, so a clean return is the assertion.
        drop(
            opts.open(&p)
                .expect("nonblocking open of a FIFO should succeed"),
        );
    }
}
