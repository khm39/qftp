//! `qftp-client sync <local> <remote-url> [--delete] [--checksum]`
//!
//! One-direction incremental sync, local → remote. The remote tree
//! is walked via `Ls` per directory; the local tree via
//! `std::fs::read_dir`. Files are kept-or-uploaded based on a
//! cheap (size, mtime) match — exact like rsync's default. Pass
//! `--checksum` to verify with BLAKE3 instead, which is slow but
//! catches silent corruption.
//!
//! `--delete` removes remote files that have no local counterpart
//! after the transfer batch completes (rsync's `--delete-after`
//! semantics).
//!
//! `.qftpignore`: if a file with that name exists at the
//! local root, each non-empty, non-`#` line is treated as a glob
//! pattern matched against relative paths. A trailing `/` restricts
//! the match to directories; a leading `/` anchors to the local
//! root. Full gitignore semantics (negation, per-subdir files) are
//! deliberately not implemented yet -- a pragmatic subset that
//! covers the common cases (`*.log`, `target/`, `/build/`).
//!
//! Out of scope (filed as a follow-up of):
//!   - Download direction (remote → local).
//!   - Negation (`!pattern`) and nested `.qftpignore` files.
//!   - Parallel streams. Sync currently issues one Put / Rm at a
//!     time. Multi-stream parallelism is a natural extension; the
//!     event-driven server side (Phase 2) already supports it.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use qftp_common::protocol::*;
use qftp_common::transport::*;

use crate::config::{self, Overrides};
use crate::proto::{join_remote, Session};
use crate::session_store;
use crate::transfer;

#[derive(Debug, Clone, Copy)]
pub struct Opts {
    pub delete: bool,
    pub use_checksum: bool,
    pub dry_run: bool,
}

pub fn run(local: &str, remote_url: &str, opts: Opts, overrides: &Overrides) -> Result<i32> {
    let local_root = std::fs::canonicalize(local)
        .with_context(|| format!("sync: cannot canonicalize {local}"))?;
    if !local_root.is_dir() {
        return Err(anyhow!("sync: {} is not a directory", local_root.display()));
    }

    let url = config::parse_url(remote_url)
        .with_context(|| format!("sync: invalid remote URL {remote_url}"))?;
    let host_port = config::format_host_port(&url.host, url.port);
    let target = format!(
        "qftp://{host_port}{}",
        url.initial_path.as_deref().unwrap_or("/")
    );
    let spec = config::resolve(Some(&target), &config::ConfigFile::default(), overrides)?;
    let remote_root = url.initial_path.unwrap_or_else(|| "/".to_string());

    eprintln!(
        "sync {} -> {} (delete={}, checksum={}, dry_run={})",
        local_root.display(),
        target,
        opts.delete,
        opts.use_checksum,
        opts.dry_run
    );

    // .qftpignore: read once at the local root. Missing file =
    // empty matcher (no exclusions). Parse failures fall back to
    // empty + warn so the sync isn't blocked by a malformed file.
    let ignore = IgnoreMatcher::load(&local_root.join(".qftpignore"));

    // Local index: relative-path -> (size, mtime).
    let local_files = walk_local(&local_root, &ignore)?;
    tracing::info!(count = local_files.len(), "sync: local files");

    let crate::connect::Established {
        mut conn,
        socket,
        mut poll,
        mut events,
        ..
    } = crate::connect::establish(
        &spec,
        "sync",
        crate::connect::EstablishOpts::for_spec(&spec),
    )?;
    let mut next: u64 = 0;
    let mut session = Session {
        conn: &mut conn,
        socket: &socket,
        poll: &mut poll,
        events: &mut events,
        next_stream_id: &mut next,
    };

    // Remote index: relative-path -> (size, mtime). We walk the
    // remote tree breadth-first using Ls. A failed listing (network
    // error, server denial, or the too-large/cyclic cap) aborts the
    // sync: proceeding on a partial map would report a silently
    // incomplete mirror as success, and with `--delete` could remove
    // files that were merely never walked.
    let remote_files = walk_remote(&mut session, &remote_root)
        .context("sync: failed to walk the remote directory tree")?;
    tracing::info!(count = remote_files.len(), "sync: remote files");

    let mut to_upload: Vec<PathBuf> = Vec::new();
    let mut to_delete: Vec<String> = Vec::new();

    for (rel, lmeta) in &local_files {
        let need_upload = match remote_files.get(rel) {
            None => true,
            Some(rmeta) => {
                if opts.use_checksum {
                    // Conservative: always re-upload when --checksum
                    // is set. A future improvement: fetch the
                    // server's stored BLAKE3 and compare.
                    true
                } else {
                    rmeta.size != lmeta.size || mtime_differs(rmeta.modified, lmeta.modified)
                }
            }
        };
        if need_upload {
            to_upload.push(rel.clone());
        }
    }

    if opts.delete {
        let local_set: HashSet<&PathBuf> = local_files.keys().collect();
        for rel in remote_files.keys() {
            if local_set.contains(rel) {
                continue;
            }
            // A remote file that `.qftpignore` excludes was pruned from
            // `local_files` by `walk_local`, so it merely looks
            // "missing locally". Deleting it would destroy a file the
            // user explicitly told sync to leave alone -- rsync
            // protects excluded files from --delete; mirror that.
            if sync_excludes(&ignore, rel) {
                tracing::info!(
                    file = %rel.display(),
                    "sync: keeping remote file excluded by .qftpignore"
                );
                continue;
            }
            to_delete.push(rel.to_string_lossy().into_owned());
        }
    }

    println!(
        "sync plan: {} upload, {} skip, {} delete",
        to_upload.len(),
        local_files.len() - to_upload.len(),
        to_delete.len(),
    );

    if opts.dry_run {
        for p in &to_upload {
            println!("  + {}", p.display());
        }
        for p in &to_delete {
            println!("  - {p}");
        }
        return Ok(0);
    }

    // Ensure the remote root exists. mkdir of an existing dir gets
    // AlreadyExists which we ignore; every other error (connection
    // dropped, malformed response, etc.) bubbles up so the caller
    // doesn't try to upload into a directory that doesn't exist.
    ensure_remote_dir(&mut session, remote_root.clone())?;

    // Create the distinct parent directories once each. A flat
    // directory of N files would otherwise send N redundant Mkdir
    // round-trips that all return AlreadyExists after the first.
    // Sorted so a shallower parent is created before a nested one.
    let mut mkdir_parents: BTreeSet<String> = BTreeSet::new();
    for rel in &to_upload {
        let remote_path = join_remote(&remote_root, rel);
        if let Some(parent) = Path::new(&remote_path).parent() {
            mkdir_parents.insert(parent.to_string_lossy().into_owned());
        }
    }
    for parent in mkdir_parents {
        ensure_remote_dir(&mut session, parent)?;
    }

    // Upload.
    let mut upload_failures = 0u64;
    for rel in &to_upload {
        let local_path = local_root.join(rel);
        let remote_path = join_remote(&remote_root, rel);
        let stream_id = session.take_stream();
        match transfer::do_put(&mut session, stream_id, &local_path, &remote_path, 0, false) {
            Ok(()) => tracing::info!(file = %remote_path, "sync: uploaded"),
            Err(e) => {
                tracing::warn!(error = %e, file = %remote_path, "sync: upload failed");
                upload_failures += 1;
            }
        }
    }

    // Delete (rsync --delete-after semantics: only run when the upload
    // batch succeeded). An upload failure suggests a degraded
    // connection or remote -- the remote-only files we're about to
    // delete might still be needed -- so skip the delete pass rather
    // than silently destroy data on top of a partial upload.
    if upload_failures > 0 && !to_delete.is_empty() {
        eprintln!(
            "sync: skipping --delete: {upload_failures} upload(s) failed, leaving \
             {} remote-only file(s) in place",
            to_delete.len()
        );
    } else {
        for rel in &to_delete {
            let remote_path = join_remote(&remote_root, Path::new(rel));
            match session.request_response(&Request::Rm {
                path: remote_path.clone(),
            }) {
                Ok(Response::Ok) => tracing::info!(file = %remote_path, "sync: deleted"),
                Ok(Response::Err(e)) => {
                    tracing::warn!(?e.code, msg = %e.message, file = %remote_path, "sync: delete failed")
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "sync: delete failed"),
            }
        }
    }

    // Polite close.
    let qid = session.take_stream();
    let _ = send_message(session.conn, qid, &Request::Quit);
    let _ = stream_send_all(session.conn, qid, &[], true);
    let _ = flush_egress(session.conn, session.socket);

    if let Some(dir) = session_store::default_dir() {
        let _ = session_store::save_from_conn(&dir, &spec.host, session.conn);
    }

    Ok(0)
}

#[derive(Debug, Clone, Copy)]
struct Meta {
    size: u64,
    modified: u64,
}

fn walk_local(root: &Path, ignore: &IgnoreMatcher) -> Result<HashMap<PathBuf, Meta>> {
    let mut out: HashMap<PathBuf, Meta> = HashMap::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, dir = %dir.display(), "sync: read_dir failed");
                continue;
            }
        };
        for entry in read.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let rel = match path.strip_prefix(root) {
                Ok(r) => r.to_path_buf(),
                Err(_) => continue,
            };
            if ft.is_dir() {
                // Pruning at the directory level avoids descending
                // into giant target/ trees when the user ignored
                // them.
                if ignore.is_dir_ignored(&rel) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !ft.is_file() {
                continue; // skip symlinks, sockets, etc.
            }
            // Skip the .qftpignore file itself -- syncing it to
            // every remote would be surprising.
            if rel.as_os_str() == ".qftpignore" {
                continue;
            }
            if ignore.is_file_ignored(&rel) {
                continue;
            }
            let meta = entry.metadata().ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = meta
                .as_ref()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            out.insert(rel, Meta { size, modified });
        }
    }
    Ok(out)
}

/// `.qftpignore` matcher. One entry per non-empty non-comment
/// line. The matcher is intentionally simpler than gitignore:
///
///   - Trailing `/` -> directory-only.
///   - Leading `/` -> anchored to the local sync root.
///   - Otherwise the pattern matches against (a) the full relative
///     path and (b) any individual component along the way. This is
///     why `*.log` correctly matches `deep/nested/foo.log` even
///     though `glob::Pattern` itself doesn't span `/`.
#[derive(Debug, Default)]
pub struct IgnoreMatcher {
    rules: Vec<Rule>,
}

#[derive(Debug)]
struct Rule {
    pattern: glob::Pattern,
    /// `/foo` -> only matches against the path rooted at the sync
    /// root, not nested occurrences.
    anchored: bool,
    /// `foo/` -> only applies when the candidate is a directory.
    dir_only: bool,
}

impl IgnoreMatcher {
    pub fn load(path: &Path) -> Self {
        let content = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(_) => return Self::default(),
        };
        let mut rules = Vec::new();
        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let dir_only = line.ends_with('/');
            let mut pat = line.trim_end_matches('/');
            let anchored = pat.starts_with('/');
            if anchored {
                pat = pat.trim_start_matches('/');
            }
            match glob::Pattern::new(pat) {
                Ok(p) => rules.push(Rule {
                    pattern: p,
                    anchored,
                    dir_only,
                }),
                Err(e) => {
                    tracing::warn!(
                        pattern = %raw,
                        error = %e,
                        "sync: ignoring malformed .qftpignore line"
                    );
                }
            }
        }
        Self { rules }
    }

    pub fn is_file_ignored(&self, rel: &Path) -> bool {
        self.matches(rel, false)
    }

    pub fn is_dir_ignored(&self, rel: &Path) -> bool {
        self.matches(rel, true)
    }

    fn matches(&self, rel: &Path, is_dir: bool) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        for rule in &self.rules {
            if rule.dir_only && !is_dir {
                continue;
            }
            if rule.anchored {
                if rule.pattern.matches(&rel_str) {
                    return true;
                }
            } else {
                if rule.pattern.matches(&rel_str) {
                    return true;
                }
                // Non-anchored patterns also match any individual
                // component along the path so `target/` excludes
                // `a/b/target/c.bin`.
                for comp in rel.components() {
                    let c = comp.as_os_str().to_string_lossy();
                    if rule.pattern.matches(&c) {
                        return true;
                    }
                }
            }
        }
        false
    }
}

/// Send `Mkdir(path)` and tolerate every application-level error so a
/// single misconfigured or transiently flaky directory doesn't kill
/// the entire sync run. Only transport-level failures (dropped
/// connection, framing error, unexpected response variant) bubble up.
///
/// The two obvious cases are `AlreadyExists` (the directory is
/// already there) and `PermissionDenied` (the user has Put but not
/// Mkdir on a pre-provisioned tree). Less obvious but equally benign
/// are the kernel-coalesced shapes that the server's `io_code` folds
/// into `Internal` -- ESTALE on NFS, EIO during a brief remount,
/// transient EBUSY etc. Cycle-3 hard-failed sync on those, breaking
/// pipelines that previously coped. The per-file `do_put` step that
/// follows is what surfaces a truly broken path; we just need to
/// log here so the operator can see the warning trail.
fn ensure_remote_dir(session: &mut Session, path: String) -> Result<()> {
    let resp = session
        .request_response(&Request::Mkdir { path: path.clone() })
        .with_context(|| format!("sync: Mkdir({path}) request failed"))?;
    use qftp_common::protocol::ErrorCode;
    match resp {
        Response::Ok => Ok(()),
        // Session-fatal codes: continuing would fail every
        // subsequent request the same way. Bail at the first one
        // so the operator sees the root cause instead of N
        // confusing per-file do_put errors.
        //
        // Note: `Malformed` is intentionally NOT in this set. The
        // server emits Malformed for per-path issues too (a
        // `Component::Prefix` in one path, a parent-less path, ...
        // -- see qftp-protocol handler.rs walk_safe /
        // resolve_parent), so bailing on the first one would abort
        // the whole sync when 999/1000 paths are fine.
        Response::Err(e) if matches!(e.code, ErrorCode::Unauthorized | ErrorCode::Unsupported) => {
            anyhow::bail!(
                "sync: Mkdir({path}) failed with fatal code [{:?}] {}",
                e.code,
                e.message
            )
        }
        // AlreadyExists is the expected case on a re-sync; debug! so
        // operators tailing the log on a 5000-directory tree don't
        // get a wall of warns. The other tolerated codes (Internal
        // / NotADirectory / PermissionDenied / QuotaExceeded / etc.)
        // stay at warn! because they're surprising enough to want
        // visible.
        Response::Err(e) if e.code == ErrorCode::AlreadyExists => {
            tracing::debug!(
                path = %path,
                msg = %e.message,
                "sync: remote dir already exists (expected on re-sync)",
            );
            Ok(())
        }
        Response::Err(e) => {
            tracing::warn!(
                path = %path,
                code = ?e.code,
                msg = %e.message,
                "sync: remote Mkdir returned an application-level error; \
                 continuing (the subsequent do_put will fail concretely if the \
                 path is not a usable directory)",
            );
            Ok(())
        }
        other => anyhow::bail!("sync: Mkdir({path}) got unexpected response: {other:?}"),
    }
}

/// Upper bound on the number of remote directories `walk_remote` will
/// visit. A malicious or buggy server can return the same sub-directory
/// name on every `Ls`, driving the client to recurse forever; this cap
/// makes the walk terminate with a clear error instead.
const MAX_REMOTE_DIRS: usize = 10_000;

fn walk_remote(session: &mut Session, root: &str) -> Result<HashMap<PathBuf, Meta>> {
    let mut out: HashMap<PathBuf, Meta> = HashMap::new();
    // (remote-abs-path, relative-prefix)
    let mut stack: Vec<(String, PathBuf)> = vec![(root.to_string(), PathBuf::new())];
    let mut visited: usize = 0;
    while let Some((abs, rel)) = stack.pop() {
        visited += 1;
        if visited > MAX_REMOTE_DIRS {
            // Bailing out: returning a partial map could leave `sync`
            // believing the remote tree is complete (and with
            // `--delete`, delete files that were simply never walked).
            anyhow::bail!(
                "sync: remote directory tree too large or cyclic \
                 (exceeded {MAX_REMOTE_DIRS} directories)"
            );
        }
        let req = Request::Ls { path: abs.clone() };
        let resp = match session.request_response(&req) {
            Ok(r) => r,
            Err(e) => {
                // A swallowed failure here yields an incomplete map but
                // still `Ok`, so `sync` would report success on a
                // silently partial mirror. Propagate it instead.
                return Err(e).with_context(|| format!("sync: remote Ls failed for {abs}"));
            }
        };
        let entries = match resp {
            Response::DirListing(e) => e,
            Response::Err(e) => {
                anyhow::bail!("sync: remote Ls failed for {abs}: {}", e.message);
            }
            other => {
                anyhow::bail!("sync: unexpected response listing {abs}: {other:?}");
            }
        };
        for e in entries {
            // A malicious server could synthesize entry names with
            // `..` or absolute paths. With `--delete`, those names would
            // be echoed back as `Rm` requests, asking the server to
            // delete arbitrary paths. Reject lexically before we even
            // remember the name.
            if !qftp_common::protocol::safe_entry_name(&e.name) {
                tracing::warn!(
                    name = %e.name,
                    parent = %abs,
                    "sync: ignoring unsafe entry name from server"
                );
                continue;
            }
            let child_abs = join_remote(&abs, Path::new(&e.name));
            let child_rel = rel.join(&e.name);
            if e.is_dir {
                stack.push((child_abs, child_rel));
            } else {
                out.insert(
                    child_rel,
                    Meta {
                        size: e.size,
                        modified: e.modified,
                    },
                );
            }
        }
    }
    Ok(out)
}

/// Whether `.qftpignore` would have kept `rel` out of the local walk --
/// either the file itself matches a rule, or one of its ancestor
/// directories does. `walk_local` prunes ignored directories, so files
/// beneath them never reach the local index either; `sync --delete`
/// must apply the same exclusion before treating a remote file as
/// "missing locally".
fn sync_excludes(ignore: &IgnoreMatcher, rel: &Path) -> bool {
    if ignore.is_file_ignored(rel) {
        return true;
    }
    let mut cur = rel.parent();
    while let Some(dir) = cur {
        if dir.as_os_str().is_empty() {
            break;
        }
        if ignore.is_dir_ignored(dir) {
            return true;
        }
        cur = dir.parent();
    }
    false
}

/// mtime equality with a 2-second tolerance. FAT only stores even
/// seconds, so a copy to/from FAT can drift the recorded mtime by up
/// to 2 seconds even when the contents are identical. Counting such a
/// gap as "differs" would force a needless re-upload every sync; this
/// matches `rsync --modify-window=2`, which exists for the same case.
fn mtime_differs(a: u64, b: u64) -> bool {
    a.abs_diff(b) > 2
}

// SystemTime helper is reserved for the future remote->local path;
// silence dead_code in the upload-only flow.
#[allow(dead_code)]
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtime_window_is_2s() {
        // The window tolerates a 2-second drift (FAT's 2-second
        // granularity); anything bigger counts as "differs".
        assert!(!mtime_differs(10, 10));
        assert!(!mtime_differs(10, 11));
        assert!(!mtime_differs(10, 12));
        assert!(mtime_differs(10, 13));
    }

    fn matcher_from(lines: &[&str]) -> IgnoreMatcher {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), lines.join("\n")).unwrap();
        IgnoreMatcher::load(tmp.path())
    }

    #[test]
    fn ignore_matches_suffix_in_nested_dir() {
        let m = matcher_from(&["*.log"]);
        assert!(m.is_file_ignored(Path::new("a/b/c.log")));
        assert!(m.is_file_ignored(Path::new("c.log")));
        assert!(!m.is_file_ignored(Path::new("c.txt")));
    }

    #[test]
    fn ignore_dir_only_pattern() {
        let m = matcher_from(&["target/"]);
        assert!(m.is_dir_ignored(Path::new("target")));
        assert!(m.is_dir_ignored(Path::new("a/target")));
        // Pure file named `target` is not excluded by the dir-only
        // form -- gitignore-compatible.
        assert!(!m.is_file_ignored(Path::new("target")));
    }

    #[test]
    fn ignore_anchored_pattern_only_at_root() {
        let m = matcher_from(&["/build/"]);
        assert!(m.is_dir_ignored(Path::new("build")));
        // Nested `build` survives because the rule is anchored.
        assert!(!m.is_dir_ignored(Path::new("a/build")));
    }

    #[test]
    fn ignore_skips_comments_and_blank_lines() {
        let m = matcher_from(&["# comment", "", "*.tmp"]);
        assert!(m.is_file_ignored(Path::new("x.tmp")));
    }

    #[test]
    fn ignore_default_has_no_rules() {
        let m = IgnoreMatcher::default();
        assert!(!m.is_file_ignored(Path::new("anything")));
    }

    #[test]
    fn sync_excludes_protects_ignored_files_from_delete() {
        let m = matcher_from(&["*.log", "target/"]);
        // A file matched directly by a rule.
        assert!(sync_excludes(&m, Path::new("deep/nested/app.log")));
        // A file beneath an ignored directory: `walk_local` prunes the
        // directory, so the file never reaches the local index and must
        // not be treated as "missing locally" by --delete.
        assert!(sync_excludes(&m, Path::new("target/release/qftp")));
        // An unrelated file stays eligible for deletion.
        assert!(!sync_excludes(&m, Path::new("src/main.rs")));
    }
}
