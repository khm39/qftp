//! Filesystem helpers shared by client and server.
//!
//! Centralizes the `O_NOFOLLOW` open pattern that's used in several
//! places to prevent a planted symlink from redirecting an open to an
//! arbitrary file (issues #106/#107/#109). All callers should funnel
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
