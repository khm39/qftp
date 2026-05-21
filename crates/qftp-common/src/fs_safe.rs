//! Filesystem helpers shared by client and server.
//!
//! Centralizes the `O_NOFOLLOW` open pattern that's used in several
//! places to prevent a planted symlink from redirecting an open to an
//! arbitrary file. All callers should funnel
//! through here so the cfg-unix gating stays in one place.

use std::fs::OpenOptions;
use std::path::Path;

/// Apply `O_NOFOLLOW` to an `OpenOptions` on unix. No-op on other
/// platforms (where symlinks have different semantics and the same
/// attack surface doesn't apply).
pub fn apply_no_follow(opts: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts
}

/// Apply `O_NOFOLLOW` and a 0o600 create mode on unix. Used when the
/// file being opened holds material we never want another local user
/// to read -- private keys and in-flight Put temp files
///. Without an explicit mode the file inherits the daemon
/// umask (typically 0o022 -> 0o644 = world-readable) which leaks the
/// content for the duration the file exists.
pub fn apply_owner_only_no_follow(opts: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts
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
