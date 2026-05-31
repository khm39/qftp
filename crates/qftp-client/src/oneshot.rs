//! One-shot subcommand handlers. Each maps a `qftp <verb> URL …`
//! invocation to a single protocol round, sets up a connection,
//! performs the operation, and exits with a sysexits-style code.
//!
//! The dispatch point is [`run`], which the `main` function calls
//! when `Args::command` is `Some(_)`. REPL mode and one-shot mode
//! share the same connection setup so they behave identically with
//! respect to TLS, config-file aliases, and CLI overrides.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use qftp_common::protocol::*;
use qftp_common::transport::*;

use crate::config::{self, ConfigFile, ConnectionSpec, Overrides};
use crate::proto::{take_stream, Session};
use crate::repl::sanitize_for_terminal;
use crate::session_store;
use crate::transfer;
use crate::OneShot;

/// sysexits.h-style exit codes. We return them via
/// `std::process::exit` so a script driver can branch on them.
pub mod exit {
    pub const OK: i32 = 0;
    pub const USAGE: i32 = 64;
    pub const DATA: i32 = 65;
    pub const NOPERM: i32 = 77;
}

/// Parsed one-shot remote reference: either a `qftp://host[:port]/path`
/// URL (host/port split out for connection setup) or a config-file host
/// alias (`<alias>[:/path]`). The `path` is retained for the operation
/// itself; `target` carries the host selector (`qftp://…` URL or bare
/// alias name) that `spec_from_url` feeds back through `config::resolve`.
#[derive(Debug, Clone)]
struct RemoteRef {
    /// Host selector handed to `config::resolve`: a `qftp://…` URL
    /// (without the path component) for URL inputs, or the bare alias
    /// name for non-URL inputs.
    target: String,
    path: String,
}

fn parse_remote(input: &str) -> Result<RemoteRef> {
    if config::looks_like_url(input) {
        let url =
            config::parse_url(input).with_context(|| format!("invalid remote URL: {input}"))?;
        let path = url.initial_path.unwrap_or_else(|| "/".to_string());
        let host_port = config::format_host_port(&url.host, url.port);
        let target = match &url.user {
            Some(u) => format!("qftp://{u}@{host_port}"),
            None => format!("qftp://{host_port}"),
        };
        return Ok(RemoteRef { target, path });
    }
    // Non-URL input is a config-file host alias, optionally suffixed
    // with `:/path` (scp-style `alias:remote/path`). Everything before
    // the first ':' is the alias; the rest (if any) is the remote path.
    let (alias, path) = match input.split_once(':') {
        Some((a, p)) => (a.to_string(), p.to_string()),
        None => (input.to_string(), "/".to_string()),
    };
    if alias.is_empty() {
        return Err(anyhow!("invalid remote '{input}': empty host alias"));
    }
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };
    Ok(RemoteRef {
        target: alias,
        path,
    })
}

/// Resolve a `ConnectionSpec` from a one-shot remote ref + the loaded
/// config file + CLI overrides. URL host/port wins for URL targets;
/// alias targets are resolved against `[host.<alias>]`. CLI flags
/// override on top, mirroring the REPL flow.
fn spec_from_url(
    remote: &RemoteRef,
    cfg_file: &ConfigFile,
    overrides: &Overrides,
) -> Result<ConnectionSpec> {
    config::resolve(Some(&remote.target), cfg_file, overrides)
}

/// Open a connection and run a callback against the established
/// `quiche::Connection`. Returns the callback's exit code.
fn with_connection<F>(spec: &ConnectionSpec, body: F) -> Result<i32>
where
    F: FnOnce(&mut Session) -> Result<i32>,
{
    let crate::connect::Established {
        mut conn,
        socket,
        mut poll,
        mut events,
        ..
    } = crate::connect::establish(
        spec,
        "one-shot",
        crate::connect::EstablishOpts::for_spec(spec),
    )?;
    let ticket_dir = session_store::default_dir();

    let mut next_stream_id: u64 = 0;
    let code = {
        let mut session = Session {
            conn: &mut conn,
            socket: &socket,
            poll: &mut poll,
            events: &mut events,
            next_stream_id: &mut next_stream_id,
        };
        body(&mut session)?
    };

    // Polite close.
    let qid = take_stream(&mut next_stream_id);
    let _ = send_message(&mut conn, qid, &Request::Quit);
    let _ = stream_send_all(&mut conn, qid, &[], true);
    let _ = flush_egress(&mut conn, &socket);

    // Save the latest session ticket so the *next* one-shot can
    // 0-RTT-resume. Best-effort: a write failure means the next
    // invocation pays the 1-RTT cost, nothing worse.
    if let Some(dir) = &ticket_dir {
        if let Err(e) = session_store::save_from_conn(dir, &spec.host, &conn) {
            tracing::warn!(error = ?e, "failed to persist session ticket");
        }
    }

    Ok(code)
}

/// Map a `Response::Err` ErrorCode to a sysexits-style exit code so a
/// shell script can branch on the failure reason.
fn err_to_exit(code: &ErrorCode) -> i32 {
    use ErrorCode::*;
    match code {
        Unauthorized | PermissionDenied => exit::NOPERM,
        Malformed => exit::USAGE,
        _ => exit::DATA,
    }
}

fn report_response_for_status(resp: &Response) -> i32 {
    match resp {
        Response::Ok => exit::OK,
        Response::Err(e) => {
            // `e.message` is server-supplied; strip terminal escapes
            // before printing (same threat model as the REPL path).
            eprintln!(
                "Error [{:?}]: {}",
                e.code,
                sanitize_for_terminal(&e.message)
            );
            err_to_exit(&e.code)
        }
        other => {
            eprintln!("Unexpected response: {other:?}");
            exit::DATA
        }
    }
}

/// How an existing destination is handled by a Put / Get. Captures
/// the `--no-clobber` / `--force` / `--interactive` flag interaction
/// in one place so the policy lives next to the dispatch (rather than
/// being re-derived inside each transfer helper). `interactive` is the
/// rsync default on a TTY; non-TTY defaults to `force` (silent
/// overwrite) so scripted batches keep their previous behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClobberPolicy {
    /// `-f` / `--force`: overwrite the destination silently.
    Force,
    /// `-n` / `--no-clobber`: refuse to overwrite. Wire-enforced via
    /// `Request::Put { no_clobber: true }`; local Gets compare the
    /// destination path before opening the network stream.
    NoClobber,
    /// `-i` / `--interactive`: prompt y/N before overwriting.
    Interactive,
}

/// The action a clobber policy dictates for a given destination
/// existence state. Centralizes the policy×exists matrix that `run_put`
/// and `run_get` both branch on; each call site still emits its own
/// messages and performs its own side effects (prompt I/O, `remove_file`,
/// the wire `no_clobber` flag, run_get's deferred remote-size probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClobberDecision {
    /// Refuse: the destination exists and the policy forbids overwrite.
    Skip,
    /// Overwrite the existing destination without asking.
    Overwrite,
    /// Ask the user before overwriting the existing destination.
    Prompt,
    /// Nothing in the way (or `--force`): proceed with the transfer.
    Proceed,
}

/// Map a clobber policy + destination-exists flag to the action to take.
/// `--force` always proceeds (overwriting if needed); the other policies
/// only matter when the destination already exists.
fn decide_clobber(policy: ClobberPolicy, exists: bool) -> ClobberDecision {
    match policy {
        ClobberPolicy::Force => {
            if exists {
                ClobberDecision::Overwrite
            } else {
                ClobberDecision::Proceed
            }
        }
        _ if !exists => ClobberDecision::Proceed,
        ClobberPolicy::NoClobber => ClobberDecision::Skip,
        ClobberPolicy::Interactive => ClobberDecision::Prompt,
    }
}

fn resolve_clobber(no_clobber: bool, force: bool, interactive: bool) -> ClobberPolicy {
    if no_clobber {
        ClobberPolicy::NoClobber
    } else if force {
        ClobberPolicy::Force
    } else if interactive || std::io::stdin().is_terminal() {
        // Explicit `-i` and TTY default both land in the same arm:
        // ask before overwriting. rsync uses the same heuristic.
        ClobberPolicy::Interactive
    } else {
        ClobberPolicy::Force
    }
}

/// Dispatch entry point called from `main`. Returns the process
/// exit code; `main` calls `std::process::exit` with it.
pub fn run(cmd: OneShot, cfg_file: &ConfigFile, overrides: Overrides) -> Result<i32> {
    match cmd {
        OneShot::Put {
            local,
            remote,
            recursive,
            no_clobber,
            force,
            interactive,
            dry_run,
        } => run_put(
            &local,
            &remote,
            recursive,
            resolve_clobber(no_clobber, force, interactive),
            dry_run,
            cfg_file,
            &overrides,
        ),
        OneShot::Get {
            remote,
            local,
            recursive,
            no_clobber,
            force,
            interactive,
            dry_run,
        } => run_get(
            &remote,
            local.as_deref(),
            recursive,
            resolve_clobber(no_clobber, force, interactive),
            dry_run,
            cfg_file,
            &overrides,
        ),
        OneShot::Ls { remote } => {
            run_remote_oneshot(&remote, cfg_file, &overrides, |path| Request::Ls {
                path: path.into(),
                cursor: None,
            })
        }
        OneShot::Rm { remote } => run_remote_oneshot(&remote, cfg_file, &overrides, |path| {
            Request::Rm { path: path.into() }
        }),
        OneShot::Mkdir { remote } => run_remote_oneshot(&remote, cfg_file, &overrides, |path| {
            Request::Mkdir { path: path.into() }
        }),
        OneShot::Rmdir { remote } => run_remote_oneshot(&remote, cfg_file, &overrides, |path| {
            Request::Rmdir { path: path.into() }
        }),
        OneShot::Rename { from, to } => run_rename(&from, &to, cfg_file, &overrides),
        OneShot::Stat { remote } => run_stat(&remote, cfg_file, &overrides),
        OneShot::Watch {
            local,
            remote,
            debounce_ms,
        } => crate::watch::run(&local, &remote, debounce_ms, &overrides),
        OneShot::Sync {
            local,
            remote,
            delete,
            checksum,
            dry_run,
        } => crate::sync::run(
            &local,
            &remote,
            crate::sync::Opts {
                delete,
                use_checksum: checksum,
                dry_run,
            },
            &overrides,
        ),
        OneShot::PutMulti {
            local,
            remote_path,
            to,
            strict,
        } => crate::fanout::run(&local, &remote_path, &to, strict, &overrides),
    }
}

/// Generic "URL -> single request -> single response -> exit code".
fn run_remote_oneshot(
    url: &str,
    cfg_file: &ConfigFile,
    overrides: &Overrides,
    build: impl FnOnce(&str) -> Request,
) -> Result<i32> {
    let r = parse_remote(url)?;
    let spec = spec_from_url(&r, cfg_file, overrides)?;
    let req = build(&r.path);
    with_connection(&spec, |session| {
        let resp = session.request_response(&req)?;
        // Special-case Response::Path for Pwd / Stat-like reads:
        // print the value so the user actually sees something.
        // Both the path and the directory entry names are
        // server-supplied; strip terminal escapes before printing.
        if let Response::Path(p) = &resp {
            println!("{}", sanitize_for_terminal(p));
        } else if let Response::DirListing { entries, .. } = &resp {
            for e in entries {
                println!(
                    "{} {} {}",
                    if e.is_dir() { 'd' } else { '-' },
                    e.size,
                    sanitize_for_terminal(&e.name)
                );
            }
        }
        Ok(report_response_for_status(&resp))
    })
}

fn run_stat(url: &str, cfg_file: &ConfigFile, overrides: &Overrides) -> Result<i32> {
    let r = parse_remote(url)?;
    let spec = spec_from_url(&r, cfg_file, overrides)?;
    let req = Request::Stat {
        path: r.path.clone(),
    };
    with_connection(&spec, |session| {
        let resp = session.request_response(&req)?;
        match &resp {
            Response::FileStat(s) => {
                println!("size  {}", s.size);
                println!("kind  {}", if s.is_dir() { "directory" } else { "file" });
                println!("mode  {:o}", s.mode & 0o777);
                println!("mtime {}", s.modified);
                Ok(exit::OK)
            }
            _ => Ok(report_response_for_status(&resp)),
        }
    })
}

fn run_rename(
    from_url: &str,
    to_url: &str,
    cfg_file: &ConfigFile,
    overrides: &Overrides,
) -> Result<i32> {
    let from = parse_remote(from_url)?;
    let to = parse_remote(to_url)?;
    if from.target != to.target {
        return Err(anyhow!(
            "rename across hosts is not supported ({} vs {})",
            from.target,
            to.target
        ));
    }
    let spec = spec_from_url(&from, cfg_file, overrides)?;
    let req = Request::Rename {
        from: from.path.clone(),
        to: to.path.clone(),
    };
    with_connection(&spec, |session| {
        let resp = session.request_response(&req)?;
        Ok(report_response_for_status(&resp))
    })
}

fn run_get(
    remote_url: &str,
    local: Option<&str>,
    recursive: bool,
    clobber: ClobberPolicy,
    dry_run: bool,
    cfg_file: &ConfigFile,
    overrides: &Overrides,
) -> Result<i32> {
    if recursive {
        // For now, surface a clear message rather than partially
        // implementing recursive walking in one-shot. The REPL form
        // (`get -r`) covers this case; follow-up can wire it up
        // here once the REPL/BFS helper is extracted.
        return Err(anyhow!(
            "one-shot `get -r` is not yet implemented (use the REPL: \
             qftp-client qftp://host -e 'get -r remote local')"
        ));
    }
    let r = parse_remote(remote_url)?;
    let spec = spec_from_url(&r, cfg_file, overrides)?;
    let local_path = match local {
        Some(p) => PathBuf::from(p),
        None => {
            // Mirror REPL behaviour: take the remote basename.
            let name = Path::new(&r.path)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "download".to_string());
            PathBuf::from(name)
        }
    };
    // --dry-run / --no-clobber / --interactive policy on Get
    // operates purely on the *local* side. transfer::do_get itself
    // already resumes a pre-existing partial download by appending
    // to it; the override here turns that into "skip" or "redownload
    // from scratch" depending on the flag.
    let local_exists = local_path.exists();
    if dry_run {
        match decide_clobber(clobber, local_exists) {
            ClobberDecision::Skip => {
                println!(
                    "would skip (exists, --no-clobber): {}",
                    local_path.display()
                );
            }
            ClobberDecision::Overwrite => {
                println!(
                    "would overwrite (exists, --force): {}",
                    local_path.display()
                );
            }
            ClobberDecision::Prompt => {
                println!("would prompt (exists): {}", local_path.display());
            }
            ClobberDecision::Proceed => {
                println!("would download: {} -> {}", r.path, local_path.display());
            }
        }
        return Ok(exit::OK);
    }
    if local_exists {
        match clobber {
            ClobberPolicy::NoClobber => {
                // A pre-existing local file under --no-clobber may be
                // either a *complete* download (which we must not
                // overwrite) or a *partial* left by an interrupted
                // earlier `get` (which do_get is designed to resume).
                // The "refuse only if complete" decision needs the
                // remote size, so it is deferred into the connection
                // body below where a `Stat` can be issued.
            }
            ClobberPolicy::Interactive => {
                if !prompt_overwrite(&local_path.display().to_string())? {
                    eprintln!("skipped: {}", local_path.display());
                    return Ok(exit::OK);
                }
                // User said yes -- treat as force (start over).
                let _ = std::fs::remove_file(&local_path);
            }
            ClobberPolicy::Force => {
                // do_get's default behaviour is to *resume* from any
                // existing local file. --force means the user wants
                // a fresh download instead.
                let _ = std::fs::remove_file(&local_path);
            }
        }
    }
    let no_clobber_check = local_exists && matches!(clobber, ClobberPolicy::NoClobber);
    with_connection(&spec, |session| {
        if no_clobber_check {
            // Probe the remote size: --no-clobber should only refuse
            // overwriting an *already complete* file, not block
            // resuming an incomplete partial. Mirrors run_put's Stat
            // probe.
            match stat_remote(session, &r.path)? {
                Some(s) => {
                    let local_len = std::fs::metadata(&local_path).map(|m| m.len()).unwrap_or(0);
                    if local_len >= s.size {
                        eprintln!("skipping (exists, --no-clobber): {}", local_path.display());
                        return Ok(exit::OK);
                    }
                    // Local is a shorter partial -- fall through and
                    // let do_get resume it.
                }
                None => {
                    // Couldn't learn the remote size (NotFound, server
                    // error, or unexpected response). Be conservative
                    // and keep the no-clobber refusal rather than
                    // overwriting. A missing remote is also handled here:
                    // there is nothing complete to protect, so a skip is
                    // the same outcome as the old `Some(0)` comparison.
                    eprintln!("skipping (exists, --no-clobber): {}", local_path.display());
                    return Ok(exit::OK);
                }
            }
        }
        match transfer::do_get(session, &r.path, &local_path) {
            Ok(()) => Ok(exit::OK),
            Err(e) => {
                eprintln!("get failed: {e}");
                Ok(exit::DATA)
            }
        }
    })
}

fn run_put(
    locals: &[String],
    remote_url: &str,
    recursive: bool,
    clobber: ClobberPolicy,
    dry_run: bool,
    cfg_file: &ConfigFile,
    overrides: &Overrides,
) -> Result<i32> {
    if locals.is_empty() {
        return Err(anyhow!("put requires at least one local file"));
    }
    if recursive {
        return Err(anyhow!(
            "one-shot `put -r` is not yet implemented (use the REPL: \
             qftp-client qftp://host -e 'put -r src/ dst/')"
        ));
    }
    let r = parse_remote(remote_url)?;
    let spec = spec_from_url(&r, cfg_file, overrides)?;

    // The remote URL path can be either a directory (every local
    // file lands under it with its original basename) or a single
    // file name (only valid for a single local). We treat a
    // trailing '/' or multiple locals as the "directory target"
    // case.
    let multiple = locals.len() > 1;
    let target_is_dir = r.path.ends_with('/') || multiple;

    // For dry-run we still open the connection so the user sees auth
    // failures and remote-existence checks; the actual transfer is
    // gated on `!dry_run`.
    with_connection(&spec, |session| {
        let mut worst = exit::OK;
        for local in locals {
            let local_path = PathBuf::from(local);
            let dest = if target_is_dir {
                let base = Path::new(local)
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "uploaded".to_string());
                if r.path.ends_with('/') {
                    format!("{}{}", r.path, base)
                } else if r.path.is_empty() {
                    base
                } else {
                    format!("{}/{}", r.path, base)
                }
            } else {
                r.path.clone()
            };

            // Pre-check existence on remote when the policy needs to
            // know (so we can skip the body upload for --no-clobber
            // and prompt for --interactive). --force skips the probe
            // and pays no extra round-trip.
            let mut effective_no_clobber = false;
            if !matches!(clobber, ClobberPolicy::Force) {
                let exists = stat_remote(session, &dest)?.is_some();
                match decide_clobber(clobber, exists) {
                    ClobberDecision::Skip => {
                        if dry_run {
                            println!("would skip (exists, --no-clobber): {local} -> {dest}");
                        } else {
                            eprintln!("skipping (exists, --no-clobber): {local} -> {dest}");
                        }
                        continue;
                    }
                    ClobberDecision::Prompt => {
                        if dry_run {
                            println!("would prompt (exists): {local} -> {dest}");
                            continue;
                        }
                        if !prompt_overwrite(&dest)? {
                            eprintln!("skipped: {dest}");
                            continue;
                        }
                    }
                    // No remote destination in the way. For --no-clobber
                    // wire the flag on regardless so a race between the
                    // probe and the upload still gets refused.
                    ClobberDecision::Proceed => {
                        if matches!(clobber, ClobberPolicy::NoClobber) {
                            effective_no_clobber = true;
                        }
                    }
                    // Unreachable here: --force skips this whole block.
                    ClobberDecision::Overwrite => {}
                }
            }
            if dry_run {
                println!("would upload: {local} -> {dest}");
                continue;
            }
            // Auto-resume an interrupted upload unless --force asked
            // for a clean re-send. Mirrors `get`'s resume behaviour.
            let local_size = std::fs::metadata(&local_path).map(|m| m.len()).unwrap_or(0);
            let offset = if matches!(clobber, ClobberPolicy::Force) {
                0
            } else {
                transfer::probe_put_resume_offset(session, &dest, local_size)
            };
            let stream_id = session.take_stream();
            match transfer::do_put(
                session,
                stream_id,
                &local_path,
                &dest,
                offset,
                effective_no_clobber,
            ) {
                Ok(()) => {}
                Err(e) if offset > 0 && e.downcast_ref::<transfer::StalePartial>().is_some() => {
                    eprintln!("put {local} -> {dest}: server partial is stale, re-uploading");
                    let sid = session.take_stream();
                    if let Err(e2) =
                        transfer::do_put(session, sid, &local_path, &dest, 0, effective_no_clobber)
                    {
                        eprintln!("put {local} -> {dest} failed: {e2}");
                        worst = exit::DATA;
                    }
                }
                Err(e) => {
                    eprintln!("put {local} -> {dest} failed: {e}");
                    worst = exit::DATA;
                }
            }
        }
        Ok(worst)
    })
}

/// Probe `path` on the remote via `Stat`. Returns `Some(stat)` for an
/// existing path, and `None` both for a definite `NotFound` and for any
/// other error/response we couldn't interpret. Used by `run_put` and
/// `run_get` to decide `--no-clobber` / `--interactive` handling
/// without sending body bytes.
///
/// Folding `NotFound` and "unparseable response" into the same `None`
/// is deliberate and matches the callers: `run_put` treats both as
/// "don't skip" (a missing destination is uploaded; an indecipherable
/// answer errs toward attempting the upload), and `run_get`'s
/// no-clobber probe treats both as "keep the refusal" (a missing remote
/// is `Some(0)`-equivalent, which the `local_len >= remote_size` check
/// already short-circuits to a skip).
fn stat_remote(session: &mut Session, path: &str) -> Result<Option<FileStat>> {
    let resp = session.request_response(&Request::Stat {
        path: path.to_string(),
    })?;
    Ok(match resp {
        Response::FileStat(s) => Some(s),
        _ => None,
    })
}

/// Read a y/N answer from stdin. Returns `true` only for an explicit
/// 'y'/'yes' (case-insensitive). EOF / read error / anything else
/// counts as no.
fn prompt_overwrite(target: &str) -> Result<bool> {
    use std::io::BufRead;
    eprint!("Overwrite '{target}'? [y/N] ");
    flush_stdout();
    let _ = std::io::stderr().flush();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let mut line = String::new();
    match handle.read_line(&mut line) {
        Ok(0) | Err(_) => Ok(false),
        Ok(_) => {
            let t = line.trim().to_ascii_lowercase();
            Ok(t == "y" || t == "yes")
        }
    }
}

fn flush_stdout() {
    let _ = std::io::stdout().flush();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConfigFile, Overrides};

    #[test]
    fn parse_remote_url_splits_target_and_path() {
        let r = parse_remote("qftp://files.example:9000/data/x").unwrap();
        assert_eq!(r.target, "qftp://files.example:9000");
        assert_eq!(r.path, "/data/x");
    }

    #[test]
    fn parse_remote_url_with_user_preserves_user_in_target() {
        let r = parse_remote("qftp://alice@h:4433/p").unwrap();
        assert_eq!(r.target, "qftp://alice@h:4433");
        assert_eq!(r.path, "/p");
    }

    #[test]
    fn parse_remote_url_without_path_defaults_to_root() {
        let r = parse_remote("qftp://h:4433").unwrap();
        assert_eq!(r.target, "qftp://h:4433");
        assert_eq!(r.path, "/");
    }

    #[test]
    fn parse_remote_alias_with_path() {
        let r = parse_remote("work:/dst/file").unwrap();
        assert_eq!(r.target, "work");
        assert_eq!(r.path, "/dst/file");
    }

    #[test]
    fn parse_remote_bare_alias_defaults_to_root() {
        let r = parse_remote("work").unwrap();
        assert_eq!(r.target, "work");
        assert_eq!(r.path, "/");
    }

    #[test]
    fn parse_remote_empty_alias_is_error() {
        assert!(parse_remote(":/dst").is_err());
    }

    /// #307: a one-shot alias target must resolve against the loaded
    /// config file (endpoint / ca / server_name), not an empty default.
    #[test]
    fn spec_from_url_resolves_alias_from_config() {
        let cfg: ConfigFile = toml::from_str(
            r#"
                [host.work]
                endpoint = "qftps://files.work.example:9000"
                ca = "/etc/qftp/ca.pem"
                server_name = "custom-sni.example"
            "#,
        )
        .unwrap();
        let r = parse_remote("work:/data").unwrap();
        let spec = spec_from_url(&r, &cfg, &Overrides::default()).unwrap();
        assert_eq!(spec.host, "files.work.example:9000");
        assert_eq!(spec.server_name, "custom-sni.example");
        assert_eq!(spec.ca.as_deref(), Some("/etc/qftp/ca.pem"));
        // The remote operation path comes from the alias suffix.
        assert_eq!(r.path, "/data");
    }

    /// #306/#307: CLI overrides still win over an alias's config fields.
    #[test]
    fn spec_from_url_overrides_beat_alias() {
        let cfg: ConfigFile = toml::from_str(
            r#"
                [host.work]
                endpoint = "qftps://files.work.example:9000"
            "#,
        )
        .unwrap();
        let overrides = Overrides {
            ca: Some("/tmp/override-ca.pem".to_string()),
            insecure: Some(true),
            ..Overrides::default()
        };
        let r = parse_remote("work").unwrap();
        let spec = spec_from_url(&r, &cfg, &overrides).unwrap();
        assert_eq!(spec.ca.as_deref(), Some("/tmp/override-ca.pem"));
        assert!(spec.insecure);
    }

    /// A URL one-shot target ignores the config-file aliases and uses
    /// the URL host directly.
    #[test]
    fn spec_from_url_url_target_uses_url_host() {
        let cfg = ConfigFile::default();
        let r = parse_remote("qftp://example.com:5555/data").unwrap();
        let spec = spec_from_url(&r, &cfg, &Overrides::default()).unwrap();
        assert_eq!(spec.host, "example.com:5555");
        assert_eq!(spec.server_name, "example.com");
    }

    /// #308: server-supplied error messages are stripped of terminal
    /// escapes when reported by the one-shot status path.
    #[test]
    fn report_response_sanitizes_error_message() {
        use qftp_common::protocol::{ErrorCode, ErrorResponse};
        // We can't capture stderr easily here, but we can at least
        // assert the sanitizer the path uses neutralizes escapes.
        let raw = "boom\x1b]0;pwned\x07\x1b[2J";
        let cleaned = sanitize_for_terminal(raw);
        assert!(!cleaned.contains('\x1b'));
        assert!(!cleaned.contains('\x07'));
        // And the status code mapping is unaffected by the message.
        let resp = Response::Err(ErrorResponse::new(ErrorCode::PermissionDenied, raw));
        assert_eq!(report_response_for_status(&resp), exit::NOPERM);
    }
}
