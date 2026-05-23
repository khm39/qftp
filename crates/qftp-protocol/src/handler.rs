use std::borrow::Cow;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use qftp_common::protocol::{
    DirEntry, ErrorCode, ErrorResponse, FileStat, Request, Response, MAX_DIR_ENTRIES,
};

use crate::user::{Op, User};

/// Read a file's mode where the OS exposes one (Unix), and synthesize a
/// generous default elsewhere so listings still round-trip.
#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    meta.permissions().mode()
}
#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> u32 {
    0o644
}

/// Apply a Unix mode where the OS supports it; otherwise refuse so callers
/// don't silently lose ACLs they thought they were setting.
#[cfg(unix)]
fn set_mode(target: &Path, mode: u32) -> Response {
    // Re-lstat immediately before the chmod. `walk_safe` lstat'd
    // every component, but a TOCTOU window exists between that check
    // and this syscall: a write-permitted attacker could swap the
    // leaf with a symlink to /etc and chmod the target. Re-checking
    // here closes most of the window. Full closure needs openat2 +
    // fchmodat with AT_SYMLINK_NOFOLLOW (out of scope for this
    // change).
    match fs::symlink_metadata(target) {
        Ok(m) if m.file_type().is_symlink() => {
            return err(
                ErrorCode::PermissionDenied,
                "target became a symlink between resolve and chmod (#106)",
            );
        }
        Ok(_) => {}
        Err(e) => return err(io_code(&e), format!("re-stat failed: {e}")),
    }
    // Strip suid/sgid/sticky from the requested mode. See
    // server::apply_mode for the rationale.
    let masked = mode & 0o0777;
    let perms = fs::Permissions::from_mode(masked);
    match fs::set_permissions(target, perms) {
        Ok(()) => Response::Ok,
        Err(e) => err(ErrorCode::Internal, format!("chmod failed: {e}")),
    }
}
#[cfg(not(unix))]
fn set_mode(_target: &Path, _mode: u32) -> Response {
    err(
        ErrorCode::Unsupported,
        "chmod is not supported on this platform",
    )
}

/// Shorthand for constructing an `Err` response with a code + message.
pub fn err(code: ErrorCode, msg: impl Into<String>) -> Response {
    Response::Err(ErrorResponse::new(code, msg))
}

/// Map a std::io::Error to the closest ErrorCode.
pub fn io_code(e: &std::io::Error) -> ErrorCode {
    use std::io::ErrorKind::*;
    match e.kind() {
        NotFound => ErrorCode::NotFound,
        PermissionDenied => ErrorCode::PermissionDenied,
        AlreadyExists => ErrorCode::AlreadyExists,
        _ => ErrorCode::Internal,
    }
}

/// Walk a user-supplied path from `cwd` (or `root` when absolute) one
/// component at a time, manually handling `.` and `..` and rejecting any
/// component that would either escape `root` or follow a symbolic link.
///
/// See the docs in Phase 1 for the rationale. Returns the resolved path
/// or a structured ErrorResponse with the right code.
fn walk_safe(cwd: &Path, root: &Path, user_path: &str) -> Result<PathBuf, ErrorResponse> {
    let p = Path::new(user_path);
    let mut current = if p.is_absolute() {
        root.to_path_buf()
    } else {
        cwd.to_path_buf()
    };

    for comp in p.components() {
        match comp {
            Component::RootDir => {
                current = root.to_path_buf();
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if current == *root {
                    return Err(ErrorResponse::new(
                        ErrorCode::PermissionDenied,
                        "path outside root",
                    ));
                }
                if !current.pop() {
                    return Err(ErrorResponse::new(
                        ErrorCode::PermissionDenied,
                        "path outside root",
                    ));
                }
                if !current.starts_with(root) {
                    return Err(ErrorResponse::new(
                        ErrorCode::PermissionDenied,
                        "path outside root",
                    ));
                }
            }
            Component::Normal(name) => {
                current.push(name);
                match std::fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err(ErrorResponse::new(
                                ErrorCode::PermissionDenied,
                                format!("symlink not allowed in path ({})", current.display()),
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // OK: the leaf may not exist yet.
                    }
                    Err(e) => {
                        return Err(ErrorResponse::new(
                            ErrorCode::Internal,
                            format!("Failed to stat path component: {e}"),
                        ));
                    }
                }
            }
            Component::Prefix(_) => {
                return Err(ErrorResponse::new(
                    ErrorCode::Malformed,
                    "invalid path prefix",
                ));
            }
        }
    }

    if !current.starts_with(root) {
        return Err(ErrorResponse::new(
            ErrorCode::PermissionDenied,
            "path outside root",
        ));
    }

    Ok(current)
}

/// Resolve a user-supplied path that must already exist.
pub fn resolve(cwd: &Path, root: &Path, user_path: &str) -> Result<PathBuf, ErrorResponse> {
    let path = walk_safe(cwd, root, user_path)?;
    if !path.exists() {
        return Err(ErrorResponse::new(
            ErrorCode::NotFound,
            format!("No such file or directory: {}", path.display()),
        ));
    }
    Ok(path)
}

/// Resolve a path whose final component may not exist yet.
pub fn resolve_parent(cwd: &Path, root: &Path, user_path: &str) -> Result<PathBuf, ErrorResponse> {
    let path = walk_safe(cwd, root, user_path)?;
    let parent = path
        .parent()
        .ok_or_else(|| ErrorResponse::new(ErrorCode::Malformed, "invalid path: no parent"))?;
    // `Path::is_dir` follows a final symlink: a parent swapped to a
    // symlink-to-directory between `walk_safe` (which lstat'd every
    // component and rejected symlinks) and this check would slip
    // through. `symlink_metadata` does NOT traverse a final symlink, so
    // a symlinked parent reports `is_dir() == false` and is rejected --
    // matching the crate's "never follow a symlink" posture.
    let parent_is_dir = std::fs::symlink_metadata(parent)
        .map(|m| m.is_dir())
        .unwrap_or(false);
    if !parent_is_dir {
        return Err(ErrorResponse::new(
            ErrorCode::NotFound,
            format!("Parent directory not found: {}", parent.display()),
        ));
    }
    Ok(path)
}

/// Re-walk the ancestors of `target` between `root` (exclusive)
/// and `target` itself (exclusive) and assert every component lstat's
/// as a non-symlink. Used as a defense-in-depth re-check just before
/// `fs::create_dir / remove_dir / remove_file / rename` so a parent
/// component that was swapped to a symlink between `resolve_parent`
/// and the syscall can be detected and refused, rather than having
/// the operation silently target the symlink's destination.
///
/// This is the same TOCTOU pattern that handler::set_mode and the
/// `Stat` arm already guard but applied to mutating
/// operations whose parents (not just the leaf) need to stay rooted.
/// True closure would require openat2(RESOLVE_BENEATH); this re-lstat
/// only narrows the window.
pub fn recheck_ancestors_no_symlinks(target: &Path, root: &Path) -> Result<(), ErrorResponse> {
    // Collect ancestors strictly between `target` (exclusive) and
    // `root` (inclusive), then walk them root-first so a swap at any
    // depth is caught.
    let mut ancestors: Vec<&Path> = Vec::new();
    let mut cur = target.parent();
    while let Some(p) = cur {
        if p == root {
            ancestors.push(p);
            break;
        }
        if !p.starts_with(root) {
            return Err(ErrorResponse::new(
                ErrorCode::PermissionDenied,
                "path outside root",
            ));
        }
        ancestors.push(p);
        cur = p.parent();
    }
    for ancestor in ancestors.iter().rev() {
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                // `root` itself is allowed to be the canonical
                // directory the operator pointed us at. Any ancestor
                // below root must not be a symlink.
                if meta.file_type().is_symlink() && *ancestor != root {
                    return Err(ErrorResponse::new(
                        ErrorCode::PermissionDenied,
                        format!(
                            "parent became a symlink between resolve and op ({}, #137)",
                            ancestor.display()
                        ),
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ErrorResponse::new(
                    ErrorCode::NotFound,
                    format!(
                        "parent disappeared between resolve and op: {}",
                        ancestor.display()
                    ),
                ));
            }
            Err(e) => {
                return Err(ErrorResponse::new(
                    ErrorCode::Internal,
                    format!("failed to re-stat parent {}: {e}", ancestor.display()),
                ));
            }
        }
    }
    Ok(())
}

/// Like [`recheck_ancestors_no_symlinks`] but also verifies the leaf
/// `target` itself is not a symlink.
///
/// The O_NOFOLLOW open paths (Get / Put) only need the ancestor check
/// because the kernel guards their leaf. `Ls` and `Cd`, however, hand
/// the resolved path straight to `fs::read_dir` / store it as the new
/// `cwd`, both of which follow a leaf symlink. A component (or the
/// leaf) swapped to a symlink after `walk_safe` validated it would
/// then escape the root. This re-check narrows that TOCTOU window for
/// those two operations.
///
/// A `target` equal to `root` is accepted: the operator-supplied root
/// may itself be reached via a symlink, and `walk_safe` never lets a
/// path resolve above it. Only paths strictly below `root` are checked.
pub fn recheck_path_no_symlinks(target: &Path, root: &Path) -> Result<(), ErrorResponse> {
    if target == root {
        return Ok(());
    }
    recheck_ancestors_no_symlinks(target, root)?;
    match std::fs::symlink_metadata(target) {
        Ok(meta) if meta.file_type().is_symlink() => Err(ErrorResponse::new(
            ErrorCode::PermissionDenied,
            format!(
                "path became a symlink between resolve and op ({}, #137)",
                target.display()
            ),
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ErrorResponse::new(
            ErrorCode::NotFound,
            format!(
                "path disappeared between resolve and op: {}",
                target.display()
            ),
        )),
        Err(e) => Err(ErrorResponse::new(
            ErrorCode::Internal,
            format!("failed to re-stat {}: {e}", target.display()),
        )),
    }
}

/// Required permission for a given request.
fn required_op(req: &Request) -> Option<Op> {
    match req {
        Request::Pwd | Request::Cd { .. } | Request::Quit | Request::Quota => None,
        Request::Ls { .. } | Request::Stat { .. } | Request::Get { .. } => Some(Op::Read),
        Request::Put { .. } => Some(Op::Write),
        Request::Mkdir { .. } => Some(Op::Mkdir),
        Request::Rmdir { .. } => Some(Op::Rmdir),
        Request::Rm { .. } => Some(Op::Delete),
        Request::Rename { .. } => Some(Op::Rename),
        Request::Chmod { .. } => Some(Op::Chmod),
        _ => Some(Op::Read),
    }
}

pub fn acl_reject(user: &User, req: &Request) -> Option<Response> {
    let op = required_op(req)?;
    if user.permissions.allows(op) {
        None
    } else {
        Some(err(
            ErrorCode::PermissionDenied,
            format!("user '{}' is not allowed to {:?}", user.name, op),
        ))
    }
}

/// Handle a single FTP request, returning the appropriate response.
/// True when `path`'s final component is a server-internal upload temp
/// (`*.qftp.partial`). These files are created, resumed, and swept by
/// the server; a client must not rename or delete one out from under an
/// in-flight upload, and they are hidden from `Ls`.
pub fn is_upload_temp(path: &str) -> bool {
    // `temp_path_for` builds the temp name as `<final-filename>.qftp.partial`
    // -- a leaf that ENDS in `.qftp.partial`. A substring match would
    // wrongly classify legitimate files like `archive.qftp.partial.tar`
    // as server temps, hiding them from `Ls` and refusing `Rm`/`Rename`.
    // Match only the exact suffix the server actually produces.
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(".qftp.partial"))
        .unwrap_or(false)
}

pub fn handle_request(req: &Request, cwd: &mut PathBuf, root: &Path) -> Response {
    match req {
        Request::Pwd => {
            let rel = cwd.strip_prefix(root).unwrap_or(Path::new(""));
            let display = format!("/{}", rel.display());
            Response::Path(display)
        }

        Request::Cd { path } => match resolve(cwd, root, path) {
            Ok(target) => {
                // Re-check ancestors + leaf for a TOCTOU symlink swap
                // before adopting `target` as the new cwd: a poisoned
                // cwd would otherwise let later operations escape root.
                if let Err(e) = recheck_path_no_symlinks(&target, root) {
                    Response::Err(e)
                } else if !target.is_dir() {
                    err(ErrorCode::NotADirectory, format!("Not a directory: {path}"))
                } else {
                    *cwd = target;
                    Response::Ok
                }
            }
            Err(e) => Response::Err(e),
        },

        Request::Ls { path } => {
            let dir: Result<Cow<Path>, ErrorResponse> = if path.is_empty() {
                Ok(Cow::Borrowed(cwd.as_path()))
            } else {
                resolve(cwd, root, path).map(Cow::Owned)
            };
            // `fs::read_dir` follows a symlink at any path component,
            // so an intermediate dir (or the listed dir itself)
            // swapped to a symlink after `walk_safe` would escape the
            // root. The O_NOFOLLOW open paths re-check ancestors; Ls
            // reads the directory directly, so it must re-check here.
            let dir = dir.and_then(|d| {
                recheck_path_no_symlinks(&d, root)?;
                Ok(d)
            });

            match dir {
                Ok(dir) => match fs::read_dir(&*dir) {
                    Ok(entries) => {
                        let mut listing: Vec<DirEntry> = Vec::with_capacity(64);
                        for entry in entries {
                            // Cap the in-memory listing: a directory with
                            // millions of (e.g. 0-byte) files would
                            // otherwise drive an unbounded allocation in
                            // the worker thread. The client enforces the
                            // same MAX_DIR_ENTRIES in `validate_response`.
                            if listing.len() >= MAX_DIR_ENTRIES {
                                return err(
                                    ErrorCode::Internal,
                                    format!("directory listing exceeds {MAX_DIR_ENTRIES} entries"),
                                );
                            }
                            let entry = match entry {
                                Ok(e) => e,
                                Err(e) => return err(io_code(&e), format!("Read dir error: {e}")),
                            };
                            // into_string() is a zero-copy OsString -> String
                            // move for the UTF-8 common case; fall back to
                            // lossy only for non-UTF-8.
                            let name = entry
                                .file_name()
                                .into_string()
                                .unwrap_or_else(|os| os.to_string_lossy().into_owned());
                            // Hide in-flight / aborted upload temp files
                            // (`<name>.qftp.partial`): they are server
                            // bookkeeping, not listable content, and would
                            // otherwise be pulled down by `mget` / `get -r`.
                            // Match the exact suffix `temp_path_for`
                            // produces, not a substring, so a legitimate
                            // file merely containing `.qftp.partial` isn't
                            // hidden (mirrors `is_upload_temp`).
                            if name.ends_with(".qftp.partial") {
                                continue;
                            }
                            let meta = match entry.metadata() {
                                Ok(m) => m,
                                Err(e) => return err(io_code(&e), format!("Metadata error: {e}")),
                            };
                            let modified = meta
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            listing.push(DirEntry {
                                name,
                                is_dir: meta.is_dir(),
                                size: meta.len(),
                                modified,
                                mode: mode_of(&meta),
                            });
                        }
                        listing.sort_by(|a, b| a.name.cmp(&b.name));
                        Response::DirListing(listing)
                    }
                    Err(e) => err(io_code(&e), format!("Cannot list directory: {e}")),
                },
                Err(e) => Response::Err(e),
            }
        }

        Request::Mkdir { path } => match resolve_parent(cwd, root, path) {
            Ok(target) => {
                if let Err(e) = recheck_ancestors_no_symlinks(&target, root) {
                    return Response::Err(e);
                }
                match fs::create_dir(&target) {
                    Ok(()) => Response::Ok,
                    Err(e) => err(io_code(&e), format!("mkdir failed: {e}")),
                }
            }
            Err(e) => Response::Err(e),
        },

        Request::Rmdir { path } => match resolve(cwd, root, path) {
            Ok(target) => {
                if let Err(e) = recheck_ancestors_no_symlinks(&target, root) {
                    return Response::Err(e);
                }
                match fs::remove_dir(&target) {
                    Ok(()) => Response::Ok,
                    Err(e) => err(io_code(&e), format!("rmdir failed: {e}")),
                }
            }
            Err(e) => Response::Err(e),
        },

        Request::Rm { path } => {
            if is_upload_temp(path) {
                return err(
                    ErrorCode::PermissionDenied,
                    "cannot remove a server-internal upload temp file",
                );
            }
            match resolve(cwd, root, path) {
                Ok(target) => {
                    if let Err(e) = recheck_ancestors_no_symlinks(&target, root) {
                        return Response::Err(e);
                    }
                    match fs::remove_file(&target) {
                        Ok(()) => Response::Ok,
                        Err(e) => err(io_code(&e), format!("rm failed: {e}")),
                    }
                }
                Err(e) => Response::Err(e),
            }
        }

        Request::Rename { from, to } => {
            if is_upload_temp(from) || is_upload_temp(to) {
                return err(
                    ErrorCode::PermissionDenied,
                    "cannot rename a server-internal upload temp file",
                );
            }
            let src = match resolve(cwd, root, from) {
                Ok(p) => p,
                Err(e) => return Response::Err(e),
            };
            let dst = match resolve_parent(cwd, root, to) {
                Ok(p) => p,
                Err(e) => return Response::Err(e),
            };
            if let Err(e) = recheck_ancestors_no_symlinks(&src, root) {
                return Response::Err(e);
            }
            if let Err(e) = recheck_ancestors_no_symlinks(&dst, root) {
                return Response::Err(e);
            }
            match fs::rename(&src, &dst) {
                Ok(()) => Response::Ok,
                Err(e) => err(io_code(&e), format!("rename failed: {e}")),
            }
        }

        Request::Chmod { path, mode } => match resolve(cwd, root, path) {
            Ok(target) => {
                // Parent-dir symlink TOCTOU re-check. `set_mode`
                // re-lstats only the leaf, so without this an ancestor
                // component swapped to a symlink after `resolve` would
                // let the chmod follow it and modify a file outside the
                // root. Every other mutating op already does this.
                if let Err(e) = recheck_ancestors_no_symlinks(&target, root) {
                    return Response::Err(e);
                }
                set_mode(&target, *mode)
            }
            Err(e) => Response::Err(e),
        },

        Request::Stat { path } => match resolve(cwd, root, path) {
            // Use symlink_metadata so a TOCTOU-swapped symlink at
            // the leaf doesn't leak information about an external
            // target's size/mode/mtime. If the leaf turned into a
            // symlink between resolve() and here, refuse instead of
            // reporting on the link.
            Ok(target) => match fs::symlink_metadata(&target) {
                Ok(meta) => {
                    if meta.file_type().is_symlink() {
                        return err(
                            ErrorCode::PermissionDenied,
                            "target became a symlink between resolve and stat (#106)",
                        );
                    }
                    let modified = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    Response::FileStat(FileStat {
                        size: meta.len(),
                        is_dir: meta.is_dir(),
                        modified,
                        mode: mode_of(&meta),
                    })
                }
                Err(e) => err(io_code(&e), format!("stat failed: {e}")),
            },
            Err(e) => Response::Err(e),
        },

        Request::Get { .. } | Request::Put { .. } | Request::Quit => err(
            ErrorCode::Malformed,
            "unexpected command on simple-handler path",
        ),
        _ => err(ErrorCode::Unsupported, "request variant not understood"),
    }
}

// The tests below exercise Unix symlink semantics and the unix-only
// PermissionsExt path. Gating the whole module keeps `cargo test`
// compiling on non-Unix targets.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_root() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("file.txt"), b"hello").unwrap();
        fs::write(root.join("sub/inner.txt"), b"world").unwrap();
        (dir, root)
    }

    #[test]
    fn resolve_relative_path_under_cwd() {
        let (_dir, root) = setup_root();
        let resolved = resolve(&root, &root, "file.txt").unwrap();
        assert_eq!(resolved, root.join("file.txt"));
    }

    #[test]
    fn resolve_absolute_path_is_rooted() {
        let (_dir, root) = setup_root();
        let resolved = resolve(&root, &root, "/sub/inner.txt").unwrap();
        assert_eq!(resolved, root.join("sub/inner.txt"));
    }

    #[test]
    fn resolve_rejects_parent_escape() {
        let (_dir, root) = setup_root();
        let e = resolve(&root, &root, "../etc/passwd").unwrap_err();
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert!(e.message.contains("outside root"));
    }

    #[test]
    fn resolve_rejects_existing_path_outside_root() {
        let (_dir, root) = setup_root();
        let e = resolve(&root, &root, "/../../../../../../tmp").unwrap_err();
        assert_eq!(e.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn resolve_missing_file_errors_with_not_found() {
        let (_dir, root) = setup_root();
        let e = resolve(&root, &root, "does-not-exist").unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }

    #[test]
    fn resolve_parent_allows_nonexistent_leaf() {
        let (_dir, root) = setup_root();
        let resolved = resolve_parent(&root, &root, "new-file.txt").unwrap();
        assert_eq!(resolved, root.join("new-file.txt"));
    }

    #[test]
    fn resolve_parent_rejects_missing_parent_dir() {
        let (_dir, root) = setup_root();
        let e = resolve_parent(&root, &root, "no/such/parent/leaf").unwrap_err();
        assert_eq!(e.code, ErrorCode::NotFound);
    }

    #[test]
    fn resolve_rejects_symlink_pointing_outside_root() {
        let (_dir, root) = setup_root();
        std::os::unix::fs::symlink("/tmp", root.join("escape")).unwrap();
        let e = resolve(&root, &root, "escape").unwrap_err();
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert!(e.message.contains("symlink"));
    }

    #[test]
    fn resolve_rejects_symlink_pointing_inside_root() {
        let (_dir, root) = setup_root();
        std::os::unix::fs::symlink(root.join("file.txt"), root.join("link.txt")).unwrap();
        let e = resolve(&root, &root, "link.txt").unwrap_err();
        assert_eq!(e.code, ErrorCode::PermissionDenied);
    }

    #[test]
    fn cd_into_directory_updates_cwd() {
        let (_dir, root) = setup_root();
        let mut cwd = root.clone();
        let resp = handle_request(&Request::Cd { path: "sub".into() }, &mut cwd, &root);
        assert!(matches!(resp, Response::Ok));
        assert_eq!(cwd, root.join("sub"));
    }

    #[test]
    fn cd_into_file_is_rejected_with_not_a_directory() {
        let (_dir, root) = setup_root();
        let mut cwd = root.clone();
        let resp = handle_request(
            &Request::Cd {
                path: "file.txt".into(),
            },
            &mut cwd,
            &root,
        );
        match resp {
            Response::Err(e) => assert_eq!(e.code, ErrorCode::NotADirectory),
            other => panic!("expected NotADirectory error, got {other:?}"),
        }
        assert_eq!(cwd, root);
    }

    /// Simulate the parent-dir TOCTOU. We build `root/sub/leaf`
    /// at resolve time, then swap `sub` for a symlink (the same
    /// primitive an attacker would have if they could win the race
    /// after `walk_safe` returns) and call `recheck_ancestors_no_symlinks`
    /// directly. The re-check must refuse the operation so Mkdir /
    /// Rmdir / Rm / Rename never land in the symlink target.
    #[test]
    fn recheck_ancestors_catches_parent_swap() {
        let (_dir, root) = setup_root();
        let outside = TempDir::new().unwrap();
        // Compose the path "root/sub/something" with `sub` still being
        // the real directory walk_safe verified.
        let target = root.join("sub").join("new-dir");
        // The first check on the unswapped tree passes.
        recheck_ancestors_no_symlinks(&target, &root).expect("clean parent should pass");
        // Now swap `sub` for a symlink to a directory outside the
        // root, the same shape as a TOCTOU exploit.
        fs::remove_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("sub")).unwrap();
        let e = recheck_ancestors_no_symlinks(&target, &root)
            .expect_err("swapped parent must be refused");
        assert_eq!(e.code, ErrorCode::PermissionDenied);
        assert!(
            e.message.contains("#137"),
            "expected error to cite #137, got: {}",
            e.message
        );
    }

    /// End-to-end check against the public handle_request entry
    /// point. Mkdir on a path whose parent is a symlink must be refused
    /// even though walk_safe would have validated the (pre-swap) tree.
    #[test]
    fn mkdir_refuses_when_parent_is_symlink() {
        let (_dir, root) = setup_root();
        let outside = TempDir::new().unwrap();
        // Replace `sub` with a symlink pointing outside the root.
        fs::remove_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("sub")).unwrap();
        let mut cwd = root.clone();
        let resp = handle_request(
            &Request::Mkdir {
                path: "sub/new".into(),
            },
            &mut cwd,
            &root,
        );
        match resp {
            Response::Err(e) => {
                assert_eq!(e.code, ErrorCode::PermissionDenied);
            }
            other => panic!("expected PermissionDenied, got {other:?}"),
        }
        // And the operation must NOT have leaked outside the root.
        assert!(
            !outside.path().join("new").exists(),
            "mkdir leaked into symlink target -- TOCTOU still open"
        );
    }

    /// cwd poisoning: a real directory the connection `Cd`'d into is
    /// swapped for a symlink afterwards. `Ls` with an empty path lists
    /// `cwd` directly via `fs::read_dir`, which follows the symlink and
    /// escapes the root unless the leaf re-check refuses it.
    #[test]
    fn ls_refuses_when_cwd_was_swapped_to_symlink() {
        let (_dir, root) = setup_root();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("secret.txt"), b"leak").unwrap();
        let mut cwd = root.join("sub");
        fs::remove_dir_all(&cwd).unwrap();
        std::os::unix::fs::symlink(outside.path(), &cwd).unwrap();
        let resp = handle_request(
            &Request::Ls {
                path: String::new(),
            },
            &mut cwd,
            &root,
        );
        match resp {
            Response::Err(e) => assert_eq!(e.code, ErrorCode::PermissionDenied),
            other => panic!("expected PermissionDenied (escape via cwd symlink), got {other:?}"),
        }
    }

    /// A normal `Ls` of a clean subdirectory and of the root itself
    /// must still succeed after the symlink re-check was added.
    #[test]
    fn ls_clean_directories_still_work() {
        let (_dir, root) = setup_root();
        let mut cwd = root.clone();
        assert!(matches!(
            handle_request(&Request::Ls { path: "sub".into() }, &mut cwd, &root),
            Response::DirListing(_)
        ));
        match handle_request(
            &Request::Ls {
                path: String::new(),
            },
            &mut cwd,
            &root,
        ) {
            Response::DirListing(entries) => assert!(!entries.is_empty()),
            other => panic!("expected DirListing for root, got {other:?}"),
        }
    }
}
