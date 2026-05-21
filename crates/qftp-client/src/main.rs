use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use mio::{Events, Poll};
use qftp_common::protocol::*;
use qftp_common::transport::*;

mod completer;
mod config;
mod connect;
mod fanout;
mod known_hosts;
mod oneshot;
mod proto;
mod repl;
mod session_store;
mod stats;
mod sync;
mod transfer;
mod watch;

use proto::{join_remote, request_response, take_stream};

/// Long-form `--version` body. Built from the package version plus
/// the build-time facts injected by `build.rs`.
const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\n  build:  ",
    env!("QFTP_BUILD_DATE"),
    "\n  commit: ",
    env!("QFTP_GIT_REV"),
    "\n  target: ",
    env!("TARGET_TRIPLE"),
);

#[derive(Parser)]
#[command(
    name = "qftp-client",
    about = "QUIC File Transfer Protocol Client",
    version = env!("CARGO_PKG_VERSION"),
    long_version = LONG_VERSION,
    long_about = "Connect to a qftp server. The positional TARGET is either a \
        qftp:// URL (e.g. qftp://user@host:4433/path) or the name of a host \
        alias defined in ~/.qftp/config.toml. Flag overrides have the highest \
        precedence; URL fields beat alias fields; builtin defaults are last.\n\n\
        With no subcommand, qftp opens an interactive REPL. With a subcommand \
        (put / get / ls / rm / mkdir / rmdir / rename / stat), it performs the \
        single operation and exits."
)]
#[command(args_conflicts_with_subcommands = true)]
struct Args {
    #[command(subcommand)]
    command: Option<OneShot>,

    /// `qftp://[user@]host[:port][/path]`, `qftps://...`, or a host
    /// alias defined in the config file. When omitted, falls back to
    /// the legacy `--host` / `--server-name` flags and defaults.
    target: Option<String>,
    /// Path to the client config file. Defaults to
    /// `~/.qftp/config.toml`.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Override host (and optionally port) as `ip:port`. Beats URL /
    /// alias.
    #[arg(long)]
    host: Option<String>,
    /// Override SNI / certificate name expected on the server cert.
    #[arg(long)]
    server_name: Option<String>,
    #[arg(long)]
    ca: Option<String>,
    /// Skip server certificate verification. Development only.
    #[arg(long)]
    insecure: bool,
    /// Pin the server's TLS leaf certificate on first connect
    /// (SSH-style known_hosts). Subsequent connects refuse to
    /// continue if the fingerprint changes. Use this instead of
    /// `--insecure` when there is no CA infrastructure.
    #[arg(long = "trust-on-first-use", short = 'T')]
    trust_on_first_use: bool,
    /// Override the known_hosts file location.
    /// Defaults to `~/.qftp/known_hosts`.
    #[arg(long)]
    known_hosts: Option<PathBuf>,
    /// Disable 0-RTT session resumption. The client will still
    /// receive new tickets but won't replay them. Useful for
    /// debugging and when you need to ensure a fresh handshake.
    #[arg(long, default_value_t = false)]
    no_zero_rtt: bool,
    /// Override the session-ticket directory.
    /// Defaults to `~/.qftp/session-tickets/`.
    #[arg(long)]
    session_ticket_dir: Option<PathBuf>,
    #[arg(long, requires = "client_key")]
    client_cert: Option<String>,
    #[arg(long, requires = "client_cert")]
    client_key: Option<String>,
    /// Run a single command non-interactively and exit. Repeatable.
    #[arg(long = "execute", short = 'e')]
    execute: Vec<String>,
    /// Read commands from stdin (one per line) instead of opening an
    /// interactive REPL. Useful for scripted batch transfers.
    #[arg(long, default_value_t = false)]
    batch: bool,
    /// Path to the command history file. Defaults to
    /// `~/.qftp_history`.
    #[arg(long)]
    history: Option<PathBuf>,
    /// Quiet mode: hide progress bars, print errors only.
    #[arg(long, short = 'q', default_value_t = false)]
    quiet: bool,
    /// Increase log verbosity. `-v` info, `-vv` debug, `-vvv` trace.
    /// Beats `RUST_LOG`.
    #[arg(long, short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,
    /// Throttle uploads to this byte rate. Accepts K/M/G (SI) or
    /// Ki/Mi/Gi (binary) suffixes; `0` (default) is unlimited.
    /// Examples: `--bwlimit 5M` = 5 MB/s, `--bwlimit 100Ki`.
    #[arg(long, default_value = "0")]
    bwlimit: String,
    /// Print a shell-completion script to stdout and exit.
    /// Pipe it into the right place for your shell, e.g.
    ///   `qftp-client --generate-completions bash | sudo tee \
    ///   /etc/bash_completion.d/qftp-client`.
    #[arg(long, value_name = "SHELL")]
    generate_completions: Option<Shell>,
}

/// One-shot subcommands modelled on scp / sftp's single-shot UX.
/// Each takes one or two `qftp://[user@]host[:port]/path` URLs;
/// path arguments without a scheme are treated as local files.
///
/// Exit codes follow sysexits.h:
///   * 0 = success
///   * 64 = usage error (bad URL, missing argument)
///   * 65 = data / transfer error (network, ACL, checksum)
///   * 77 = auth failure (mTLS / TOFU mismatch)
#[derive(Subcommand)]
enum OneShot {
    /// Upload one or more local files to a remote URL.
    Put {
        /// Local path(s). Globs are expanded by the shell or, when
        /// quoted, by qftp itself.
        local: Vec<String>,
        /// Destination `qftp://host[:port]/path`. The last argument.
        remote: String,
        /// Recurse into directories.
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Skip uploads whose destination already exists. Server-side
        /// enforced (returns AlreadyExists for races).
        #[arg(short = 'n', long, conflicts_with_all = ["force", "interactive"])]
        no_clobber: bool,
        /// Overwrite existing destinations without asking. Default on
        /// non-TTY stdin; on a TTY, the default is `--interactive`.
        #[arg(short = 'f', long, conflicts_with = "interactive")]
        force: bool,
        /// On a TTY, prompt before overwriting an existing destination.
        /// Defaults on when stdin is a TTY.
        #[arg(short = 'i', long)]
        interactive: bool,
        /// Print the upload plan without transferring anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Download a remote path to a local file.
    Get {
        /// Source `qftp://host[:port]/path`.
        remote: String,
        /// Local destination. Defaults to the basename of the remote
        /// path.
        local: Option<String>,
        /// Recurse into directories.
        #[arg(short = 'r', long)]
        recursive: bool,
        /// Skip the download if the local destination already exists.
        #[arg(short = 'n', long, conflicts_with_all = ["force", "interactive"])]
        no_clobber: bool,
        /// Overwrite a pre-existing local file (delete + re-download).
        /// On a non-TTY stdin this is the default.
        #[arg(short = 'f', long, conflicts_with = "interactive")]
        force: bool,
        /// On a TTY, prompt before overwriting an existing local file.
        /// Defaults on when stdin is a TTY.
        #[arg(short = 'i', long)]
        interactive: bool,
        /// Print the download plan without transferring anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// List a remote directory.
    Ls {
        /// `qftp://host[:port]/path`.
        remote: String,
    },
    /// Remove a remote file.
    Rm { remote: String },
    /// Create a remote directory.
    Mkdir { remote: String },
    /// Remove an empty remote directory.
    Rmdir { remote: String },
    /// Rename / move a remote path. Both URLs must point to the same
    /// host.
    Rename { from: String, to: String },
    /// Show metadata for a remote path.
    Stat { remote: String },
    /// Watch a local directory and mirror create / modify / delete
    /// events to a remote prefix. Runs until Ctrl-C.
    Watch {
        local: String,
        remote: String,
        #[arg(long, default_value_t = 200)]
        debounce_ms: u64,
    },
    /// One-way upload sync (local → remote). Skips files whose size
    /// and mtime already match. Pass `--checksum` to use BLAKE3
    /// comparison instead. Pass `--delete` to remove remote files
    /// that no longer exist locally.
    Sync {
        local: String,
        remote: String,
        #[arg(long)]
        delete: bool,
        #[arg(long)]
        checksum: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Fan-out: upload one local file to multiple servers in
    /// parallel. Each `--to` is a `qftp://host[:port]` (the path
    /// comes from the second positional argument, applied to every
    /// host). The BLAKE3 checksum is computed once and reused.
    PutMulti {
        /// Local file to upload.
        local: String,
        /// Remote path component (applied to every target).
        remote_path: String,
        /// Target hosts. Repeat the flag or pass a
        /// comma-separated list.
        #[arg(long, required = true, value_delimiter = ',')]
        to: Vec<String>,
        /// `--strict` aborts the whole batch on any failure;
        /// `--best-effort` (default) carries on with the survivors
        /// and reports at the end.
        #[arg(long, default_value_t = false)]
        strict: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    stats::init();

    // Tracing init: `-v` family wins over RUST_LOG. `-q` falls to
    // warn so the user only sees errors (progress bars are silenced
    // separately by the transfer module).
    let cli_level: Option<&str> = match (args.quiet, args.verbose) {
        (true, _) => Some("warn"),
        (false, 0) => None,
        (false, 1) => Some("info"),
        (false, 2) => Some("debug"),
        (false, _) => Some("trace"),
    };
    let filter = match cli_level {
        Some(l) => tracing_subscriber::EnvFilter::new(l),
        None => tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    transfer::set_quiet(args.quiet);
    let bw = transfer::parse_bw_limit(&args.bwlimit)
        .with_context(|| format!("--bwlimit '{}'", args.bwlimit))?;
    transfer::set_bw_limit_bps(bw);
    if bw > 0 {
        tracing::info!(bytes_per_sec = bw, "upload throttled by --bwlimit");
    }

    if let Some(shell) = args.generate_completions {
        let mut cmd = Args::command();
        let bin = cmd.get_name().to_string();
        clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
        return Ok(());
    }

    let config_path = args
        .config
        .as_ref()
        .map(|p| PathBuf::from(config::expand_tilde(&p.to_string_lossy())))
        .or_else(config::default_config_path);
    let cfg_file = match &config_path {
        Some(p) => config::ConfigFile::load(p)?,
        None => config::ConfigFile::default(),
    };

    let overrides = config::Overrides {
        host: args.host.clone(),
        server_name: args.server_name.clone(),
        insecure: if args.insecure { Some(true) } else { None },
        ca: args.ca.clone(),
        client_cert: args.client_cert.clone(),
        client_key: args.client_key.clone(),
    };

    // One-shot subcommand path. Bypasses the REPL entirely and exits
    // with a sysexits-style code so shell scripts can branch.
    if let Some(cmd) = args.command {
        let code = oneshot::run(cmd, overrides)?;
        std::process::exit(code);
    }

    let spec = config::resolve(args.target.as_deref(), &cfg_file, &overrides)?;

    // TOFU is only meaningful when the user has *not* supplied a CA
    // bundle. A `--ca` overrides it (we trust the PKI chain). When
    // TOFU is active we ask quiche to skip its own peer verification
    // and run the fingerprint check ourselves after the handshake.
    let tofu_active = args.trust_on_first_use && spec.ca.is_none() && !spec.insecure;
    let effective_verify_peer = !spec.insecure && !tofu_active;

    // --insecure drops the only authentication we have over the
    // wire. Surface that explicitly so it never lands in a script
    // unnoticed.
    if spec.insecure {
        eprintln!(
            "warning: --insecure disables TLS peer verification; \
             traffic is authenticated only by mTLS (if any). \
             Prefer --trust-on-first-use or --ca for production use."
        );
    }

    // Needed both to drive 0-RTT resumption inside `establish` and to
    // persist the freshest ticket on a clean exit.
    let ticket_dir = args
        .session_ticket_dir
        .clone()
        .or_else(session_store::default_dir);

    // Load known_hosts up front when TOFU is active: the pinned
    // fingerprint binds the 0-RTT session ticket inside `establish`
    // (a stored ticket is only resumed against the same server
    // identity it was saved for), and the same view drives the
    // post-handshake pin check.
    let tofu = if tofu_active {
        let kh_path = args
            .known_hosts
            .clone()
            .or_else(known_hosts::default_path)
            .context("$HOME is not set; --known-hosts must be provided for TOFU")?;
        let kh = known_hosts::KnownHosts::load(&kh_path)?;
        Some((kh_path, kh))
    } else {
        None
    };
    let expected_cert_fingerprint = tofu
        .as_ref()
        .and_then(|(_, kh)| kh.pinned_fingerprint(&spec.host));

    let connect::Established {
        mut conn,
        socket,
        mut poll,
        mut events,
        resumed,
    } = connect::establish(
        &spec,
        "connect",
        connect::EstablishOpts {
            verify_peer: effective_verify_peer,
            zero_rtt: !args.no_zero_rtt,
            ticket_dir: ticket_dir.clone(),
            expected_cert_fingerprint,
        },
    )?;

    if let Some((kh_path, kh)) = &tofu {
        let der = conn
            .peer_cert()
            .context("server presented no certificate; cannot pin")?;
        let seen = known_hosts::fingerprint_hex(der);
        match kh.lookup(&spec.host, &seen) {
            known_hosts::Verdict::Match => {
                tracing::info!(
                    host = %spec.host,
                    fingerprint = %format!("sha256:{seen}"),
                    "TOFU: pinned, matched"
                );
            }
            known_hosts::Verdict::New => {
                known_hosts::KnownHosts::append_to_file(kh_path, &spec.host, &seen)?;
                eprintln!(
                    "The authenticity of host '{}' can't be established.",
                    spec.host
                );
                eprintln!("Server cert fingerprint is sha256:{seen}");
                eprintln!("Pinned in {}.", kh_path.display());
            }
            known_hosts::Verdict::Mismatch { pinned } => {
                conn.close(true, 0x0, b"server cert pin mismatch").ok();
                let _ = flush_egress(&mut conn, &socket);
                return Err(known_hosts::mismatch_error(&spec.host, &pinned, &seen));
            }
        }
    }

    if resumed && conn.is_resumed() {
        eprintln!("Connected to {} (0-RTT resumed)", spec.host);
    } else {
        eprintln!("Connected to {}", spec.host);
    }

    // Determine the source of commands: --execute > --batch/stdin
    // pipeline > interactive TTY.
    let mut next_stream_id: u64 = 0;
    let mut quit_requested = false;
    let mut local_cwd: PathBuf = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    if let Some(path) = &spec.initial_path {
        let req = Request::Cd { path: path.clone() };
        match request_response(
            &mut conn,
            &socket,
            &mut poll,
            &mut events,
            &mut next_stream_id,
            &req,
        )? {
            Response::Ok => {}
            Response::Err(e) => {
                eprintln!("initial cd {} failed: [{:?}] {}", path, e.code, e.message);
            }
            other => {
                eprintln!("initial cd: unexpected response {other:?}");
            }
        }
    }

    if !args.execute.is_empty() {
        for line in &args.execute {
            if quit_requested {
                break;
            }
            run_one_line(
                line,
                &mut conn,
                &socket,
                &mut poll,
                &mut events,
                &mut next_stream_id,
                &mut quit_requested,
                &mut local_cwd,
            )?;
        }
    } else if args.batch || !std::io::stdin().is_terminal() {
        let stdin = std::io::stdin();
        let handle = stdin.lock();
        for line in handle.lines() {
            if quit_requested {
                break;
            }
            let line = line.context("reading stdin")?;
            run_one_line(
                &line,
                &mut conn,
                &socket,
                &mut poll,
                &mut events,
                &mut next_stream_id,
                &mut quit_requested,
                &mut local_cwd,
            )?;
        }
    } else {
        run_interactive(
            &args,
            &mut conn,
            &socket,
            &mut poll,
            &mut events,
            &mut next_stream_id,
            &mut local_cwd,
        )?;
    }

    if !quit_requested {
        // Try a polite Quit so the server logs a clean close.
        let stream_id = take_stream(&mut next_stream_id);
        let _ = send_message(&mut conn, stream_id, &Request::Quit);
        let _ = stream_send_all(&mut conn, stream_id, &[], true);
        let _ = flush_egress(&mut conn, &socket);
    }

    // Persist the latest session ticket so the next connect can
    // 0-RTT-resume. `conn.session()` returns the freshest ticket
    // received during this connection; saving on every clean exit
    // means we keep the post-handshake-rotated ticket too.
    if !args.no_zero_rtt {
        if let Some(dir) = &ticket_dir {
            if let Err(e) = session_store::save_from_conn(dir, &spec.host, &conn) {
                tracing::warn!(error = ?e, "failed to persist session ticket");
            }
        }
    }

    eprintln!("Goodbye.");
    Ok(())
}

fn run_interactive(
    args: &Args,
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    local_cwd: &mut PathBuf,
) -> Result<()> {
    // Tab completion wired through `ReplHelper`. Without an
    // explicit helper rustyline emits a beep on TAB; with it we get
    // first-word command completion + local-path completion for the
    // `put`/`lcd`/`lls`/`lmkdir`/`!` family.
    let mut rl: rustyline::Editor<completer::ReplHelper, _> = rustyline::Editor::new()?;
    rl.set_helper(Some(completer::ReplHelper::new()));
    let hist_path = history_path(args);
    if let Some(p) = &hist_path {
        let _ = rl.load_history(p);
    }
    let mut quit = false;
    loop {
        if quit {
            break;
        }
        let line = match rl.readline("qftp> ") {
            Ok(l) => l,
            Err(
                rustyline::error::ReadlineError::Interrupted | rustyline::error::ReadlineError::Eof,
            ) => break,
            Err(e) => {
                println!("readline error: {e}");
                break;
            }
        };
        let _ = rl.add_history_entry(&line);
        run_one_line(
            &line,
            conn,
            socket,
            poll,
            events,
            next_stream_id,
            &mut quit,
            local_cwd,
        )?;
    }
    if let Some(p) = hist_path {
        let _ = rl.save_history(&p);
    }
    Ok(())
}

fn history_path(args: &Args) -> Option<PathBuf> {
    if let Some(p) = &args.history {
        return Some(p.clone());
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".qftp_history"))
}

#[allow(clippy::too_many_arguments)]
fn run_one_line(
    line: &str,
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    quit_out: &mut bool,
    local_cwd: &mut PathBuf,
) -> Result<()> {
    let cmd = match repl::parse_command(line) {
        Some(c) => c,
        None => return Ok(()),
    };

    match cmd {
        repl::Command::Lcd(target) => {
            let dest = match target.as_deref() {
                Some(p) => {
                    let p = config::expand_tilde(p);
                    let pb = PathBuf::from(p);
                    if pb.is_absolute() {
                        pb
                    } else {
                        local_cwd.join(pb)
                    }
                }
                None => std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/")),
            };
            match std::fs::canonicalize(&dest) {
                Ok(c) if c.is_dir() => {
                    *local_cwd = c;
                    println!("local cwd: {}", local_cwd.display());
                }
                Ok(_) => println!("lcd: not a directory: {}", dest.display()),
                Err(e) => println!("lcd: {}: {e}", dest.display()),
            }
            return Ok(());
        }
        repl::Command::Lpwd => {
            println!("{}", local_cwd.display());
            return Ok(());
        }
        repl::Command::Lls(path) => {
            let target = match path {
                Some(p) => resolve_local(local_cwd, &p),
                None => local_cwd.clone(),
            };
            match std::fs::read_dir(&target) {
                Ok(entries) => {
                    let mut names: Vec<String> = entries
                        .filter_map(|e| e.ok())
                        .map(|e| {
                            let p = e.path();
                            let suffix = if p.is_dir() { "/" } else { "" };
                            format!("{}{suffix}", e.file_name().to_string_lossy())
                        })
                        .collect();
                    names.sort_unstable();
                    for n in names {
                        println!("{n}");
                    }
                }
                Err(e) => println!("lls {}: {e}", target.display()),
            }
            return Ok(());
        }
        repl::Command::Lmkdir(path) => {
            let target = resolve_local(local_cwd, &path);
            if let Err(e) = std::fs::create_dir_all(&target) {
                println!("lmkdir {}: {e}", target.display());
            }
            return Ok(());
        }
        repl::Command::Stats => {
            stats::print(&stats::snapshot());
            return Ok(());
        }
        repl::Command::Shell(rest) => {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
            let mut cmd_proc = std::process::Command::new(&shell);
            cmd_proc.current_dir(local_cwd.clone());
            if rest.is_empty() {
                // Interactive shell.
                let _ = cmd_proc.status();
            } else {
                cmd_proc.arg("-c").arg(&rest);
                let _ = cmd_proc.status();
            }
            return Ok(());
        }
        repl::Command::Remote(req) => {
            let is_quit = matches!(req, Request::Quit);
            let resp = request_response(conn, socket, poll, events, next_stream_id, &req)?;
            repl::display_response(&resp);
            if is_quit {
                *quit_out = true;
            }
        }
        repl::Command::Get {
            remote,
            local,
            recursive,
        } => {
            if recursive {
                let local_root = local.map(|s| resolve_local(local_cwd, &s));
                do_recursive_get(
                    conn,
                    socket,
                    poll,
                    events,
                    next_stream_id,
                    &remote,
                    local_root.map(|p| p.to_string_lossy().into_owned()),
                )?;
            } else {
                let stream_id = take_stream(next_stream_id);
                let local_path = match local {
                    Some(s) => resolve_local(local_cwd, &s),
                    None => {
                        let name = Path::new(&remote)
                            .file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| remote.clone());
                        local_cwd.join(name)
                    }
                };
                if let Err(e) =
                    transfer::do_get(conn, socket, poll, events, stream_id, &remote, &local_path)
                {
                    println!("get failed: {e}");
                }
            }
        }
        repl::Command::Put {
            local,
            remote,
            recursive,
        } => {
            // Expand glob, resolving relative entries against the
            // REPL's local cwd.
            let pattern = resolve_local(local_cwd, &local)
                .to_string_lossy()
                .into_owned();
            let locals = expand_glob(&pattern);
            if locals.is_empty() {
                println!("no local files match {local}");
                return Ok(());
            }
            if recursive {
                for path in locals {
                    let remote_root = remote.clone().unwrap_or_else(|| {
                        path.file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| ".".to_string())
                    });
                    if let Err(e) = do_recursive_put(
                        conn,
                        socket,
                        poll,
                        events,
                        next_stream_id,
                        &path,
                        &remote_root,
                    ) {
                        println!("put -r {} failed: {e}", path.display());
                    }
                }
            } else {
                for path in locals {
                    let stream_id = take_stream(next_stream_id);
                    let target = remote.clone().unwrap_or_else(|| {
                        path.file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "uploaded".to_string())
                    });
                    if let Err(e) = transfer::do_put(
                        conn, socket, poll, events, stream_id, &path, &target, 0, false,
                    ) {
                        println!("put {} failed: {e}", path.display());
                    }
                }
            }
        }
    }
    Ok(())
}

/// Resolve a user-supplied local path against the REPL's local cwd.
/// Absolute paths and paths starting with `~/` pass through; relative
/// paths are joined onto `local_cwd`.
fn resolve_local(local_cwd: &Path, p: &str) -> PathBuf {
    let expanded = config::expand_tilde(p);
    let pb = PathBuf::from(expanded);
    if pb.is_absolute() {
        pb
    } else {
        local_cwd.join(pb)
    }
}

fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    match glob::glob(pattern) {
        Ok(paths) => paths.filter_map(|p| p.ok()).collect(),
        Err(_) => vec![PathBuf::from(pattern)],
    }
}

/// Walk the remote directory tree, downloading every file under `remote`
/// into `local_root`. The remote layout is preserved relative to
/// `remote`.
fn do_recursive_get(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    remote: &str,
    local_root: Option<String>,
) -> Result<()> {
    let local_root = local_root.map(PathBuf::from).unwrap_or_else(|| {
        Path::new(remote)
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(remote))
    });
    std::fs::create_dir_all(&local_root).ok();

    // BFS via Ls.
    let mut queue: Vec<(String, PathBuf)> = vec![(remote.to_string(), local_root.clone())];
    while let Some((rdir, ldir)) = queue.pop() {
        let req = Request::Ls { path: rdir.clone() };
        let resp = request_response(conn, socket, poll, events, next_stream_id, &req)?;
        let entries = match resp {
            Response::DirListing(e) => e,
            Response::Err(e) => {
                repl::display_error(&e);
                continue;
            }
            other => {
                println!("unexpected response listing {rdir}: {other:?}");
                continue;
            }
        };
        std::fs::create_dir_all(&ldir).ok();
        for entry in entries {
            // A malicious server can return entry names containing
            // `..` or absolute paths; `PathBuf::join` would silently
            // escape `ldir`. Reject lexically before we touch the
            // filesystem.
            if !qftp_common::protocol::safe_entry_name(&entry.name) {
                tracing::warn!(
                    name = %entry.name,
                    "recursive get: server returned unsafe entry name; skipping"
                );
                continue;
            }
            let remote_child = join_remote(&rdir, Path::new(&entry.name));
            let local_child = ldir.join(&entry.name);
            if entry.is_dir {
                queue.push((remote_child, local_child));
            } else {
                let stream_id = take_stream(next_stream_id);
                if let Err(e) = transfer::do_get(
                    conn,
                    socket,
                    poll,
                    events,
                    stream_id,
                    &remote_child,
                    &local_child,
                ) {
                    println!("get {} failed: {e}", remote_child);
                }
            }
        }
    }
    Ok(())
}

/// Walk a local directory and upload every regular file under it,
/// mirroring its structure under `remote_root`.
fn do_recursive_put(
    conn: &mut quiche::Connection,
    socket: &mio::net::UdpSocket,
    poll: &mut Poll,
    events: &mut Events,
    next_stream_id: &mut u64,
    local: &Path,
    remote_root: &str,
) -> Result<()> {
    if !local.is_dir() {
        // -r on a file degrades to a normal put.
        let stream_id = take_stream(next_stream_id);
        return transfer::do_put(
            conn,
            socket,
            poll,
            events,
            stream_id,
            local,
            remote_root,
            0,
            false,
        );
    }
    // Ensure top-level mkdir.
    let _ = request_response(
        conn,
        socket,
        poll,
        events,
        next_stream_id,
        &Request::Mkdir {
            path: remote_root.to_string(),
        },
    )?;

    // BFS local.
    let mut queue: Vec<(PathBuf, String)> = vec![(local.to_path_buf(), remote_root.to_string())];
    while let Some((dir, rremote)) = queue.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => {
                println!("read_dir {} failed: {e}", dir.display());
                continue;
            }
        };
        for entry in read.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name_str = name.to_string_lossy().into_owned();
            let remote_child = join_remote(&rremote, Path::new(&name_str));
            if path.is_dir() {
                let _ = request_response(
                    conn,
                    socket,
                    poll,
                    events,
                    next_stream_id,
                    &Request::Mkdir {
                        path: remote_child.clone(),
                    },
                )?;
                queue.push((path, remote_child));
            } else {
                let stream_id = take_stream(next_stream_id);
                if let Err(e) = transfer::do_put(
                    conn,
                    socket,
                    poll,
                    events,
                    stream_id,
                    &path,
                    &remote_child,
                    0,
                    false,
                ) {
                    println!("put {} failed: {e}", path.display());
                }
            }
        }
    }
    Ok(())
}
