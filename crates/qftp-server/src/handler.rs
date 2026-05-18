use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

use qftp_common::protocol::{DirEntry, FileStat, Request, Response};

/// Walk a user-supplied path from `cwd` (or `root` when absolute) one
/// component at a time, manually handling `.` and `..` and rejecting any
/// component that would either escape `root` or follow a symbolic link.
///
/// This is a conservative substitute for `openat2(RESOLVE_BENEATH)`: it
/// forecloses both the "symlink under root points outside root" leak and
/// the TOCTOU window where a symlink could be swapped between
/// canonicalize() and the subsequent open(). The trade-off is that
/// legitimate symlinks anywhere in the path are also refused, which is
/// acceptable for Phase 1.
///
/// Returns the absolute, symlink-free path. Nonexistent leaves are not
/// rejected -- callers (`resolve` vs `resolve_parent`) decide whether the
/// final component must already exist.
fn walk_safe(cwd: &Path, root: &Path, user_path: &str) -> Result<PathBuf, String> {
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
                    return Err("Permission denied: path outside root".into());
                }
                if !current.pop() {
                    return Err("Permission denied: path outside root".into());
                }
                if !current.starts_with(root) {
                    return Err("Permission denied: path outside root".into());
                }
            }
            Component::Normal(name) => {
                current.push(name);
                match std::fs::symlink_metadata(&current) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err(format!(
                                "Permission denied: symlink not allowed in path ({})",
                                current.display()
                            ));
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        // OK: the leaf may not exist yet (resolve_parent
                        // relies on this). Keep walking so we still reject
                        // subsequent symlink components above the missing
                        // leaf, if any.
                    }
                    Err(e) => return Err(format!("Failed to stat path component: {e}")),
                }
            }
            Component::Prefix(_) => {
                return Err("Permission denied: invalid path prefix".into());
            }
        }
    }

    if !current.starts_with(root) {
        return Err("Permission denied: path outside root".into());
    }

    Ok(current)
}

/// Resolve a user-supplied path that must already exist. The returned path
/// is absolute, contained in `root`, and free of symlink components.
pub fn resolve(cwd: &Path, root: &Path, user_path: &str) -> Result<PathBuf, String> {
    let path = walk_safe(cwd, root, user_path)?;
    if !path.exists() {
        return Err(format!("No such file or directory: {}", path.display()));
    }
    Ok(path)
}

/// Resolve a path whose final component may not exist yet (mkdir target,
/// rename destination, Put target). The parent directory must exist.
pub fn resolve_parent(cwd: &Path, root: &Path, user_path: &str) -> Result<PathBuf, String> {
    let path = walk_safe(cwd, root, user_path)?;
    let parent = path.parent().ok_or_else(|| "Invalid path".to_string())?;
    if !parent.is_dir() {
        return Err(format!("Parent directory not found: {}", parent.display()));
    }
    Ok(path)
}

/// Handle a single FTP request, returning the appropriate response.
/// Mutates `cwd` when a Cd command succeeds.
pub fn handle_request(req: &Request, cwd: &mut PathBuf, root: &Path) -> Response {
    match req {
        Request::Pwd => {
            let rel = cwd.strip_prefix(root).unwrap_or(Path::new(""));
            let display = format!("/{}", rel.display());
            Response::Path(display)
        }

        Request::Cd { path } => match resolve(cwd, root, path) {
            Ok(target) => {
                if !target.is_dir() {
                    Response::Err(format!("Not a directory: {path}"))
                } else {
                    *cwd = target;
                    Response::Ok
                }
            }
            Err(e) => Response::Err(e),
        },

        Request::Ls { path } => {
            let dir = if path.is_empty() {
                Ok(cwd.clone())
            } else {
                resolve(cwd, root, path)
            };

            match dir {
                Ok(dir) => match fs::read_dir(&dir) {
                    Ok(entries) => {
                        let mut listing: Vec<DirEntry> = Vec::new();
                        for entry in entries {
                            let entry = match entry {
                                Ok(e) => e,
                                Err(e) => return Response::Err(format!("Read dir error: {e}")),
                            };
                            let meta = match entry.metadata() {
                                Ok(m) => m,
                                Err(e) => return Response::Err(format!("Metadata error: {e}")),
                            };
                            let modified = meta
                                .modified()
                                .ok()
                                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            listing.push(DirEntry {
                                name: entry.file_name().to_string_lossy().into_owned(),
                                is_dir: meta.is_dir(),
                                size: meta.len(),
                                modified,
                                mode: meta.permissions().mode(),
                            });
                        }
                        listing.sort_by(|a, b| a.name.cmp(&b.name));
                        Response::DirListing(listing)
                    }
                    Err(e) => Response::Err(format!("Cannot list directory: {e}")),
                },
                Err(e) => Response::Err(e),
            }
        }

        Request::Mkdir { path } => match resolve_parent(cwd, root, path) {
            Ok(target) => match fs::create_dir(&target) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Err(format!("mkdir failed: {e}")),
            },
            Err(e) => Response::Err(e),
        },

        Request::Rmdir { path } => match resolve(cwd, root, path) {
            Ok(target) => match fs::remove_dir(&target) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Err(format!("rmdir failed: {e}")),
            },
            Err(e) => Response::Err(e),
        },

        Request::Rm { path } => match resolve(cwd, root, path) {
            Ok(target) => match fs::remove_file(&target) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Err(format!("rm failed: {e}")),
            },
            Err(e) => Response::Err(e),
        },

        Request::Rename { from, to } => {
            let src = match resolve(cwd, root, from) {
                Ok(p) => p,
                Err(e) => return Response::Err(e),
            };
            let dst = match resolve_parent(cwd, root, to) {
                Ok(p) => p,
                Err(e) => return Response::Err(e),
            };
            match fs::rename(&src, &dst) {
                Ok(()) => Response::Ok,
                Err(e) => Response::Err(format!("rename failed: {e}")),
            }
        }

        Request::Chmod { path, mode } => match resolve(cwd, root, path) {
            Ok(target) => {
                let perms = fs::Permissions::from_mode(*mode);
                match fs::set_permissions(&target, perms) {
                    Ok(()) => Response::Ok,
                    Err(e) => Response::Err(format!("chmod failed: {e}")),
                }
            }
            Err(e) => Response::Err(e),
        },

        Request::Stat { path } => match resolve(cwd, root, path) {
            Ok(target) => match fs::metadata(&target) {
                Ok(meta) => {
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
                        mode: meta.permissions().mode(),
                    })
                }
                Err(e) => Response::Err(format!("stat failed: {e}")),
            },
            Err(e) => Response::Err(e),
        },

        Request::Get { .. } | Request::Put { .. } | Request::Quit => {
            Response::Err("Unexpected command".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Build a temporary root with one regular file and one nested dir.
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
        // walk_safe processes `..` manually -- with cwd == root it refuses
        // to pop above root rather than ever touching the filesystem.
        let err = resolve(&root, &root, "../etc/passwd").unwrap_err();
        assert!(
            err.contains("outside root"),
            "expected outside-root rejection, got: {err}"
        );
    }

    #[test]
    fn resolve_rejects_existing_path_outside_root() {
        let (_dir, root) = setup_root();
        // Absolute path starting with `/` is reinterpreted as relative to
        // root; the first `..` then tries to escape root and is refused.
        let err = resolve(&root, &root, "/../../../../../../tmp").unwrap_err();
        assert!(
            err.contains("outside root"),
            "expected outside-root rejection, got: {err}"
        );
    }

    #[test]
    fn resolve_missing_file_errors() {
        let (_dir, root) = setup_root();
        let err = resolve(&root, &root, "does-not-exist").unwrap_err();
        assert!(err.contains("No such"));
    }

    #[test]
    fn resolve_parent_allows_nonexistent_leaf() {
        let (_dir, root) = setup_root();
        // The parent (root) exists, the leaf does not -- resolve_parent should
        // still succeed because mkdir/put need to create the leaf.
        let resolved = resolve_parent(&root, &root, "new-file.txt").unwrap();
        assert_eq!(resolved, root.join("new-file.txt"));
    }

    #[test]
    fn resolve_parent_rejects_missing_parent_dir() {
        let (_dir, root) = setup_root();
        let err = resolve_parent(&root, &root, "no/such/parent/leaf").unwrap_err();
        assert!(err.contains("Parent directory not found"));
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
    fn resolve_rejects_symlink_pointing_outside_root() {
        let (_dir, root) = setup_root();
        // Create symlink root/escape -> /tmp (outside root)
        std::os::unix::fs::symlink("/tmp", root.join("escape")).unwrap();
        let err = resolve(&root, &root, "escape").unwrap_err();
        // The canonicalize() in resolve() follows the symlink and lands
        // outside root, hitting the explicit outside-root check.
        assert!(
            err.contains("outside root") || err.contains("symlink not allowed"),
            "expected outside-root or symlink rejection, got: {err}"
        );
    }

    #[test]
    fn resolve_rejects_symlink_pointing_inside_root() {
        let (_dir, root) = setup_root();
        // Create a symlink under root that points to another path under
        // root. canonicalize succeeds and stays inside root, but the
        // symlink-component check must still reject it to avoid TOCTOU.
        std::os::unix::fs::symlink(root.join("file.txt"), root.join("link.txt")).unwrap();
        let err = resolve(&root, &root, "link.txt").unwrap_err();
        assert!(
            err.contains("symlink not allowed"),
            "expected symlink rejection, got: {err}"
        );
    }

    #[test]
    fn cd_into_file_is_rejected() {
        let (_dir, root) = setup_root();
        let mut cwd = root.clone();
        let resp = handle_request(
            &Request::Cd {
                path: "file.txt".into(),
            },
            &mut cwd,
            &root,
        );
        assert!(matches!(resp, Response::Err(_)));
        assert_eq!(cwd, root);
    }
}
