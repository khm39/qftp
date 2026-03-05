use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use qftp_common::protocol::{DirEntry, FileStat, Request, Response};

/// Resolve a user-supplied path against the current working directory and root,
/// returning an absolute canonical path that is guaranteed to be within root.
pub fn resolve(cwd: &Path, root: &Path, user_path: &str) -> Result<PathBuf, String> {
    let raw = if user_path.starts_with('/') {
        root.join(user_path.trim_start_matches('/'))
    } else {
        cwd.join(user_path)
    };

    let canonical = raw
        .canonicalize()
        .map_err(|e| format!("No such file or directory: {e}"))?;

    if !canonical.starts_with(root) {
        return Err("Permission denied: path outside root".into());
    }

    Ok(canonical)
}

/// Resolve a path whose final component may not yet exist (e.g. mkdir target,
/// rename destination). The parent directory must exist and be within root.
pub fn resolve_parent(cwd: &Path, root: &Path, user_path: &str) -> Result<PathBuf, String> {
    let raw = if user_path.starts_with('/') {
        root.join(user_path.trim_start_matches('/'))
    } else {
        cwd.join(user_path)
    };

    let file_name = raw
        .file_name()
        .ok_or_else(|| "Invalid path".to_string())?
        .to_os_string();

    let parent = raw
        .parent()
        .ok_or_else(|| "Invalid path".to_string())?
        .canonicalize()
        .map_err(|e| format!("Parent directory not found: {e}"))?;

    if !parent.starts_with(root) {
        return Err("Permission denied: path outside root".into());
    }

    Ok(parent.join(file_name))
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

        Request::Cd { path } => {
            match resolve(cwd, root, path) {
                Ok(target) => {
                    if !target.is_dir() {
                        Response::Err(format!("Not a directory: {path}"))
                    } else {
                        *cwd = target;
                        Response::Ok
                    }
                }
                Err(e) => Response::Err(e),
            }
        }

        Request::Ls { path } => {
            let dir = if path.is_empty() {
                Ok(cwd.clone())
            } else {
                resolve(cwd, root, path)
            };

            match dir {
                Ok(dir) => {
                    match fs::read_dir(&dir) {
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
                    }
                }
                Err(e) => Response::Err(e),
            }
        }

        Request::Mkdir { path } => {
            match resolve_parent(cwd, root, path) {
                Ok(target) => {
                    match fs::create_dir(&target) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Err(format!("mkdir failed: {e}")),
                    }
                }
                Err(e) => Response::Err(e),
            }
        }

        Request::Rmdir { path } => {
            match resolve(cwd, root, path) {
                Ok(target) => {
                    match fs::remove_dir(&target) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Err(format!("rmdir failed: {e}")),
                    }
                }
                Err(e) => Response::Err(e),
            }
        }

        Request::Rm { path } => {
            match resolve(cwd, root, path) {
                Ok(target) => {
                    match fs::remove_file(&target) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Err(format!("rm failed: {e}")),
                    }
                }
                Err(e) => Response::Err(e),
            }
        }

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

        Request::Chmod { path, mode } => {
            match resolve(cwd, root, path) {
                Ok(target) => {
                    let perms = fs::Permissions::from_mode(*mode);
                    match fs::set_permissions(&target, perms) {
                        Ok(()) => Response::Ok,
                        Err(e) => Response::Err(format!("chmod failed: {e}")),
                    }
                }
                Err(e) => Response::Err(e),
            }
        }

        Request::Stat { path } => {
            match resolve(cwd, root, path) {
                Ok(target) => {
                    match fs::metadata(&target) {
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
                    }
                }
                Err(e) => Response::Err(e),
            }
        }

        Request::Get { .. } | Request::Put { .. } | Request::Quit => {
            Response::Err("Unexpected command".into())
        }
    }
}
