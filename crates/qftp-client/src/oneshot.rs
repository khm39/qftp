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
use mio::{Events, Poll};
use qftp_common::protocol::*;
use qftp_common::transport::*;

use crate::config::{self, ConnectionSpec, Overrides};
use crate::proto::{request_response, take_stream};
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

/// Parsed `qftp://host[:port]/path` URL with the host/port split out
/// for connection setup and the path retained for the operation
/// itself.
#[derive(Debug, Clone)]
struct RemoteRef {
    host_port: String,
    /// SNI / cert CN expected on the server. Currently unused —
    /// `spec_from_url` rebuilds it via `config::resolve` — but kept
    /// in the struct for clarity and for future per-URL overrides.
    #[allow(dead_code)]
    server_name: String,
    user: Option<String>,
    path: String,
}

fn parse_remote(input: &str) -> Result<RemoteRef> {
    let url = config::parse_url(input).with_context(|| format!("invalid remote URL: {input}"))?;
    let path = url.initial_path.unwrap_or_else(|| "/".to_string());
    Ok(RemoteRef {
        host_port: config::format_host_port(&url.host, url.port),
        server_name: url.host.clone(),
        user: url.user,
        path,
    })
}

/// Resolve a `ConnectionSpec` from a one-shot URL + overrides. The
/// URL host/port wins; CLI flags still override on top, mirroring
/// the REPL flow.
fn spec_from_url(remote: &RemoteRef, overrides: &Overrides) -> Result<ConnectionSpec> {
    // We feed the URL through the resolver so CLI overrides
    // (--host, --ca, …) follow identical precedence as REPL mode.
    let target = if let Some(u) = &remote.user {
        format!("qftp://{u}@{}{}", remote.host_port, remote.path)
    } else {
        format!("qftp://{}{}", remote.host_port, remote.path)
    };
    config::resolve(Some(&target), &config::ConfigFile::default(), overrides)
}

/// Open a connection and run a callback against the established
/// `quiche::Connection`. Returns the callback's exit code.
fn with_connection<F>(spec: &ConnectionSpec, body: F) -> Result<i32>
where
    F: FnOnce(
        &mut quiche::Connection,
        &mio::net::UdpSocket,
        &mut Poll,
        &mut Events,
        &mut u64,
    ) -> Result<i32>,
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
    let code = body(
        &mut conn,
        &socket,
        &mut poll,
        &mut events,
        &mut next_stream_id,
    )?;

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
            eprintln!("Error [{:?}]: {}", e.code, e.message);
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
pub fn run(cmd: OneShot, overrides: Overrides) -> Result<i32> {
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
            &overrides,
        ),
        OneShot::Ls { remote } => run_remote_oneshot(&remote, &overrides, |path| Request::Ls {
            path: path.into(),
        }),
        OneShot::Rm { remote } => run_remote_oneshot(&remote, &overrides, |path| Request::Rm {
            path: path.into(),
        }),
        OneShot::Mkdir { remote } => run_remote_oneshot(&remote, &overrides, |path| {
            Request::Mkdir { path: path.into() }
        }),
        OneShot::Rmdir { remote } => run_remote_oneshot(&remote, &overrides, |path| {
            Request::Rmdir { path: path.into() }
        }),
        OneShot::Rename { from, to } => run_rename(&from, &to, &overrides),
        OneShot::Stat { remote } => run_stat(&remote, &overrides),
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
    overrides: &Overrides,
    build: impl FnOnce(&str) -> Request,
) -> Result<i32> {
    let r = parse_remote(url)?;
    let spec = spec_from_url(&r, overrides)?;
    let req = build(&r.path);
    with_connection(&spec, |conn, socket, poll, events, next| {
        let resp = request_response(conn, socket, poll, events, next, &req)?;
        // Special-case Response::Path for Pwd / Stat-like reads:
        // print the value so the user actually sees something.
        if let Response::Path(p) = &resp {
            println!("{p}");
        } else if let Response::DirListing(entries) = &resp {
            for e in entries {
                println!("{} {} {}", if e.is_dir { 'd' } else { '-' }, e.size, e.name);
            }
        }
        Ok(report_response_for_status(&resp))
    })
}

fn run_stat(url: &str, overrides: &Overrides) -> Result<i32> {
    let r = parse_remote(url)?;
    let spec = spec_from_url(&r, overrides)?;
    let req = Request::Stat {
        path: r.path.clone(),
    };
    with_connection(&spec, |conn, socket, poll, events, next| {
        let resp = request_response(conn, socket, poll, events, next, &req)?;
        match &resp {
            Response::FileStat(s) => {
                println!("size  {}", s.size);
                println!("kind  {}", if s.is_dir { "directory" } else { "file" });
                println!("mode  {:o}", s.mode & 0o777);
                println!("mtime {}", s.modified);
                Ok(exit::OK)
            }
            _ => Ok(report_response_for_status(&resp)),
        }
    })
}

fn run_rename(from_url: &str, to_url: &str, overrides: &Overrides) -> Result<i32> {
    let from = parse_remote(from_url)?;
    let to = parse_remote(to_url)?;
    if from.host_port != to.host_port {
        return Err(anyhow!(
            "rename across hosts is not supported ({} vs {})",
            from.host_port,
            to.host_port
        ));
    }
    let spec = spec_from_url(&from, overrides)?;
    let req = Request::Rename {
        from: from.path.clone(),
        to: to.path.clone(),
    };
    with_connection(&spec, |conn, socket, poll, events, next| {
        let resp = request_response(conn, socket, poll, events, next, &req)?;
        Ok(report_response_for_status(&resp))
    })
}

fn run_get(
    remote_url: &str,
    local: Option<&str>,
    recursive: bool,
    clobber: ClobberPolicy,
    dry_run: bool,
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
    let spec = spec_from_url(&r, overrides)?;
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
        if local_exists {
            match clobber {
                ClobberPolicy::NoClobber => {
                    println!(
                        "would skip (exists, --no-clobber): {}",
                        local_path.display()
                    );
                }
                ClobberPolicy::Force => {
                    println!(
                        "would overwrite (exists, --force): {}",
                        local_path.display()
                    );
                }
                ClobberPolicy::Interactive => {
                    println!("would prompt (exists): {}", local_path.display());
                }
            }
        } else {
            println!("would download: {} -> {}", r.path, local_path.display());
        }
        return Ok(exit::OK);
    }
    if local_exists {
        match clobber {
            ClobberPolicy::NoClobber => {
                eprintln!("skipping (exists, --no-clobber): {}", local_path.display());
                return Ok(exit::OK);
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
    with_connection(&spec, |conn, socket, poll, events, next| {
        let stream_id = take_stream(next);
        match transfer::do_get(conn, socket, poll, events, stream_id, &r.path, &local_path) {
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
    let spec = spec_from_url(&r, overrides)?;

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
    with_connection(&spec, |conn, socket, poll, events, next| {
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
                let exists =
                    remote_exists(conn, socket, poll, events, next, &dest)?.unwrap_or(false);
                match clobber {
                    ClobberPolicy::Force => {}
                    ClobberPolicy::NoClobber => {
                        if exists {
                            if dry_run {
                                println!("would skip (exists, --no-clobber): {local} -> {dest}");
                            } else {
                                eprintln!("skipping (exists, --no-clobber): {local} -> {dest}");
                            }
                            continue;
                        }
                        // Wire it on regardless so a race between the
                        // probe and the upload still gets refused.
                        effective_no_clobber = true;
                    }
                    ClobberPolicy::Interactive => {
                        if exists {
                            if dry_run {
                                println!("would prompt (exists): {local} -> {dest}");
                                continue;
                            }
                            if !prompt_overwrite(&dest)? {
                                eprintln!("skipped: {dest}");
                                continue;
                            }
                        }
                    }
                }
            }
            if dry_run {
                println!("would upload: {local} -> {dest}");
                continue;
            }
            // Auto-resume an interrupted upload unless --force asked
            // for a clean re-send. Mirrors `get`'s resume behaviour.
            let local_size = std::fs::metadata(&local_path)
                .map(|m| m.len())
                .unwrap_or(0);
            let offset = if matches!(clobber, ClobberPolicy::Force) {
                0
            } else {
                transfer::probe_put_resume_offset(
                    conn, socket, poll, events, next, &dest, local_size,
                )
            };
            let stream_id = take_stream(next);
            match transfer::do_put(
                conn,
                socket,
                poll,
                events,
                stream_id,
                &local_path,
                &dest,
                offset,
                effective_no_clobber,
            ) {
                Ok(()) => {}
                Err(e)
                    if offset > 0 && e.downcast_ref::<transfer::StalePartial>().is_some() =>
                {
                    eprintln!("put {local} -> {dest}: server partial is stale, re-uploading");
                    let sid = take_stream(next);
                    if let Err(e2) = transfer::do_put(
                        conn,
                        socket,
                        poll,
                        events,
                        sid,
                        &local_path,
                        &dest,
                        0,
                        effective_no_clobber,
                    ) {
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

/// Probe whether `path` exists on the remote via `Stat`. Returns
/// `Some(bool)` for a definitive yes/no, `None` if the server
/// answered with an error we couldn't interpret (treated as "unknown
/// — don't skip the upload"). Used by `run_put` to short-circuit
/// `--no-clobber` and `--interactive` without sending body bytes.
fn remote_exists(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next: &mut u64,
    path: &str,
) -> Result<Option<bool>> {
    let resp = request_response(
        conn,
        socket,
        poll,
        events,
        next,
        &Request::Stat {
            path: path.to_string(),
        },
    )?;
    Ok(match resp {
        Response::FileStat(_) => Some(true),
        Response::Err(e) if matches!(e.code, ErrorCode::NotFound) => Some(false),
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
