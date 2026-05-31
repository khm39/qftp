use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
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

use proto::{join_remote, Session};

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

#[derive(Parser, Debug)]
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
struct Args {
    #[command(subcommand)]
    command: Option<OneShot>,

    /// `qftp://[user@]host[:port][/path]`, `qftps://...`, or a host
    /// alias defined in the config file. When omitted, falls back to
    /// the legacy `--host` / `--server-name` flags and defaults.
    target: Option<String>,
    /// Path to the client config file. Defaults to
    /// `~/.qftp/config.toml`.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Override host (and optionally port) as `ip:port`. Beats URL /
    /// alias.
    #[arg(long, global = true)]
    host: Option<String>,
    /// Override SNI / certificate name expected on the server cert.
    #[arg(long, global = true)]
    server_name: Option<String>,
    #[arg(long, global = true)]
    ca: Option<String>,
    /// Skip server certificate verification. Development only.
    #[arg(long, global = true)]
    insecure: bool,
    /// Pin the server's TLS leaf certificate on first connect
    /// (SSH-style known_hosts). Subsequent connects refuse to
    /// continue if the fingerprint changes. Use this instead of
    /// `--insecure` when there is no CA infrastructure.
    #[arg(long = "trust-on-first-use", short = 'T', global = true)]
    trust_on_first_use: bool,
    /// Override the known_hosts file location.
    /// Defaults to `~/.qftp/known_hosts`.
    #[arg(long, global = true)]
    known_hosts: Option<PathBuf>,
    /// Disable 0-RTT session resumption. The client will still
    /// receive new tickets but won't replay them. Useful for
    /// debugging and when you need to ensure a fresh handshake.
    #[arg(long, default_value_t = false, global = true)]
    no_zero_rtt: bool,
    /// Override the session-ticket directory.
    /// Defaults to `~/.qftp/session-tickets/`.
    #[arg(long, global = true)]
    session_ticket_dir: Option<PathBuf>,
    #[arg(long, requires = "client_key", global = true)]
    client_cert: Option<String>,
    #[arg(long, requires = "client_cert", global = true)]
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
    #[arg(long, short = 'q', default_value_t = false, global = true)]
    quiet: bool,
    /// Increase log verbosity. `-v` info, `-vv` debug, `-vvv` trace.
    /// Beats `RUST_LOG`.
    #[arg(long, short = 'v', action = clap::ArgAction::Count, global = true)]
    verbose: u8,
    /// Throttle uploads to this byte rate. Accepts K/M/G (SI) or
    /// Ki/Mi/Gi (binary) suffixes; `0` (default) is unlimited.
    /// Examples: `--bwlimit 5M` = 5 MB/s, `--bwlimit 100Ki`.
    #[arg(long, default_value = "0", global = true)]
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
#[derive(Subcommand, Debug)]
enum OneShot {
    /// Upload one or more local files to a remote URL.
    Put {
        /// Destination `qftp://host[:port]/path`.
        remote: String,
        /// Local path(s). Globs are expanded by the shell or, when
        /// quoted, by qftp itself. Trailing positional (clap requires a
        /// variadic `Vec` to come after any required positionals).
        local: Vec<String>,
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
        // TOFU / known_hosts / session-ticket controls are honored only
        // by the REPL/connect path, not by one-shot's `with_connection`.
        // They now *parse* alongside a subcommand (global flags), so warn
        // loudly rather than silently dropping a `-T` the user expected
        // to pin a fingerprint.
        if args.trust_on_first_use || args.known_hosts.is_some() {
            eprintln!(
                "warning: --trust-on-first-use / --known-hosts are not honored \
                 in one-shot mode; use --ca, --insecure, or the interactive REPL"
            );
        }
        let code = oneshot::run(cmd, &cfg_file, overrides)?;
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

    let mut session = Session {
        conn: &mut conn,
        socket: &socket,
        poll: &mut poll,
        events: &mut events,
        next_stream_id: &mut next_stream_id,
    };

    if let Some(path) = &spec.initial_path {
        let req = Request::Cd { path: path.clone() };
        match session.request_response(&req)? {
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
            run_one_line(line, &mut session, &mut quit_requested, &mut local_cwd)?;
        }
    } else if args.batch || !std::io::stdin().is_terminal() {
        let stdin = std::io::stdin();
        let handle = stdin.lock();
        for line in handle.lines() {
            if quit_requested {
                break;
            }
            let line = line.context("reading stdin")?;
            run_one_line(&line, &mut session, &mut quit_requested, &mut local_cwd)?;
        }
    } else {
        run_interactive(&args, &mut session, &mut quit_requested, &mut local_cwd)?;
    }

    if !quit_requested {
        // Try a polite Quit so the server logs a clean close.
        let stream_id = session.take_stream();
        let _ = send_message(session.conn, stream_id, &Request::Quit);
        let _ = stream_send_all(session.conn, stream_id, &[], true);
        let _ = flush_egress(session.conn, session.socket);
    }

    // Persist the latest session ticket so the next connect can
    // 0-RTT-resume. `conn.session()` returns the freshest ticket
    // received during this connection; saving on every clean exit
    // means we keep the post-handshake-rotated ticket too.
    if !args.no_zero_rtt {
        if let Some(dir) = &ticket_dir {
            if let Err(e) = session_store::save_from_conn(dir, &spec.host, session.conn) {
                tracing::warn!(error = ?e, "failed to persist session ticket");
            }
        }
    }

    eprintln!("Goodbye.");
    Ok(())
}

fn run_interactive(
    args: &Args,
    session: &mut Session,
    quit_out: &mut bool,
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
    // Propagate the quit state into `main`'s `quit_requested` so a
    // `quit`/`exit` typed in the REPL (which already sent Request::Quit)
    // is not followed by a second polite Quit on shutdown.
    loop {
        if *quit_out {
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
        run_one_line(&line, session, quit_out, local_cwd)?;
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

fn run_one_line(
    line: &str,
    session: &mut Session,
    quit_out: &mut bool,
    local_cwd: &mut PathBuf,
) -> Result<()> {
    let cmd = match repl::parse_command(line) {
        Some(c) => c,
        None => return Ok(()),
    };

    match cmd {
        repl::Command::Lcd(_)
        | repl::Command::Lpwd
        | repl::Command::Lls(_)
        | repl::Command::Lmkdir(_)
        | repl::Command::Stats
        | repl::Command::Shell(_) => run_local_command(cmd, local_cwd),
        repl::Command::Remote(req) => run_remote_command(session, req, quit_out),
        repl::Command::Get { .. } | repl::Command::Put { .. } | repl::Command::Mget { .. } => {
            run_transfer_command(session, cmd, local_cwd)
        }
    }
}

/// Local-only REPL commands: no protocol round-trip. Mutates the REPL's
/// `local_cwd` for `lcd`. The caller routes only the local `Command`
/// variants here.
fn run_local_command(cmd: repl::Command, local_cwd: &mut PathBuf) -> Result<()> {
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
                Ok(_) => eprintln!("lcd: not a directory: {}", dest.display()),
                Err(e) => eprintln!("lcd: {}: {e}", dest.display()),
            }
        }
        repl::Command::Lpwd => {
            println!("{}", local_cwd.display());
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
                Err(e) => eprintln!("lls {}: {e}", target.display()),
            }
        }
        repl::Command::Lmkdir(path) => {
            let target = resolve_local(local_cwd, &path);
            if let Err(e) = std::fs::create_dir_all(&target) {
                eprintln!("lmkdir {}: {e}", target.display());
            }
        }
        repl::Command::Stats => {
            stats::print(&stats::snapshot());
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
        }
        _ => unreachable!("run_local_command received a non-local command"),
    }
    Ok(())
}

/// A single remote protocol round-trip (the `repl::Command::Remote`
/// variant). Sets `*quit_out` when the request was `Quit`.
fn run_remote_command(session: &mut Session, req: Request, quit_out: &mut bool) -> Result<()> {
    let is_quit = matches!(req, Request::Quit);
    let resp = session.request_response(&req)?;
    repl::display_response(&resp);
    if is_quit {
        *quit_out = true;
    }
    Ok(())
}

/// Bulk-transfer REPL commands: `get` / `put` / `mget`. The caller
/// routes only those `Command` variants here.
fn run_transfer_command(session: &mut Session, cmd: repl::Command, local_cwd: &Path) -> Result<()> {
    match cmd {
        repl::Command::Get {
            remote,
            local,
            recursive,
        } => {
            if recursive {
                let local_root = local.map(|s| resolve_local(local_cwd, &s));
                do_recursive_get(
                    session,
                    &remote,
                    local_root.map(|p| p.to_string_lossy().into_owned()),
                )?;
            } else {
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
                if let Err(e) = transfer::do_get(session, &remote, &local_path) {
                    eprintln!("get failed: {e}");
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
                eprintln!("no local files match {local}");
                return Ok(());
            }
            if recursive {
                for path in locals {
                    let remote_root = remote.clone().unwrap_or_else(|| {
                        path.file_name()
                            .map(|s| s.to_string_lossy().into_owned())
                            .unwrap_or_else(|| ".".to_string())
                    });
                    if let Err(e) = do_recursive_put(session, &path, &remote_root) {
                        eprintln!("put -r {} failed: {e}", path.display());
                    }
                }
            } else {
                for (path, target) in prepare_puts(locals, remote.as_deref()) {
                    // Auto-resume an interrupted upload, mirroring the
                    // way `get` resumes from a partial local file. The
                    // probe stays interleaved with the upload (not
                    // batched up front): when a glob maps several locals
                    // onto one explicit remote target, each file's resume
                    // probe must observe the prior file's just-completed
                    // upload, so probing all of them ahead of time would
                    // change the offset each sees.
                    let local_size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                    let offset = transfer::probe_put_resume_offset(session, &target, local_size);
                    let stream_id = session.take_stream();
                    match transfer::do_put(session, stream_id, &path, &target, offset, false) {
                        Ok(()) => {}
                        Err(e)
                            if offset > 0
                                && e.downcast_ref::<transfer::StalePartial>().is_some() =>
                        {
                            eprintln!(
                                "put {target}: server partial is stale, re-uploading from scratch"
                            );
                            let sid = session.take_stream();
                            if let Err(e2) =
                                transfer::do_put(session, sid, &path, &target, 0, false)
                            {
                                eprintln!("put {} failed: {e2}", path.display());
                            }
                        }
                        Err(e) => eprintln!("put {} failed: {e}", path.display()),
                    }
                }
            }
        }
        repl::Command::Mget { pattern, local_dir } => {
            do_mget(session, &pattern, local_dir.as_deref(), local_cwd)?;
        }
        _ => unreachable!("run_transfer_command received a non-transfer command"),
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

/// Pair each local upload path with its derived remote target. When an
/// explicit `remote` is given every local maps onto it; otherwise each
/// local uploads under its own basename (falling back to `"uploaded"`
/// for a path with no file name). Pure (no network / no filesystem
/// probe): the per-file resume probe and `do_put` stay in the caller's
/// execution loop so each upload still observes the prior one.
fn prepare_puts(locals: Vec<PathBuf>, remote: Option<&str>) -> Vec<(PathBuf, String)> {
    locals
        .into_iter()
        .map(|path| {
            let target = match remote {
                Some(r) => r.to_string(),
                None => path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "uploaded".to_string()),
            };
            (path, target)
        })
        .collect()
}

fn expand_glob(pattern: &str) -> Vec<PathBuf> {
    match glob::glob(pattern) {
        Ok(paths) => {
            let matches: Vec<PathBuf> = paths.filter_map(|p| p.ok()).collect();
            if matches.is_empty() {
                // A real local file whose name literally contains glob
                // metacharacters (`[`, `]`, `?`, `*`) is interpreted as
                // a pattern and matches nothing. Fall back to the
                // literal path when it actually exists on disk so e.g.
                // `put 'report[2024].txt'` uploads that file.
                let literal = PathBuf::from(pattern);
                if std::fs::symlink_metadata(&literal).is_ok() {
                    return vec![literal];
                }
            }
            matches
        }
        Err(_) => vec![PathBuf::from(pattern)],
    }
}

/// Download every file in one remote directory whose name matches a
/// glob (`mget`). Unlike `put`'s local glob, the wildcard is expanded
/// against a server `Ls`, so only the final path component may carry
/// glob metacharacters; the directory part is taken verbatim.
fn do_mget(
    session: &mut Session,
    pattern: &str,
    local_dir: Option<&str>,
    local_cwd: &Path,
) -> Result<()> {
    let (rdir, fileglob) = match pattern.rfind('/') {
        // A leading-root pattern like `/*.txt` puts the only `/` at
        // index 0, so `&pattern[..0]` is "". That empty string makes
        // `Request::Ls` list the remote cwd, not the server root the
        // `/` asked for -- so list `/` explicitly in that case.
        Some(0) => ("/", &pattern[1..]),
        Some(i) => (&pattern[..i], &pattern[i + 1..]),
        None => ("", pattern),
    };
    let matcher = match glob::Pattern::new(fileglob) {
        Ok(p) => p,
        Err(e) => {
            println!("mget: invalid pattern '{fileglob}': {e}");
            return Ok(());
        }
    };
    // Match like a shell glob: `*` must not pick up leading-dot files,
    // matching the filesystem-walker behaviour of `put`'s local glob.
    let glob_opts = glob::MatchOptions {
        require_literal_leading_dot: true,
        ..glob::MatchOptions::new()
    };
    let local_root = match local_dir {
        Some(d) => resolve_local(local_cwd, d),
        None => local_cwd.to_path_buf(),
    };
    if let Err(e) = std::fs::create_dir_all(&local_root) {
        println!("mget: cannot use {}: {e}", local_root.display());
        return Ok(());
    }

    let resp = session.request_response(&Request::Ls {
        path: rdir.to_string(),
        cursor: None,
    })?;
    let entries = match resp {
        Response::DirListing { entries, .. } => entries,
        Response::Err(e) => {
            repl::display_error(&e);
            return Ok(());
        }
        other => {
            println!("mget: unexpected response listing '{rdir}': {other:?}");
            return Ok(());
        }
    };

    let mut matched = 0usize;
    let mut ok = 0usize;
    let mut skipped = 0usize;
    let mut unsafe_rejected = 0usize;
    for entry in entries {
        if entry.is_dir() || !matcher.matches_with(&entry.name, glob_opts) {
            continue;
        }
        // A malicious server can return entry names containing `..` or
        // separators; reject them lexically before they reach a path.
        // Surface the rejection on stderr (not just `tracing`) and
        // count it, so a server that returns *only* unsafe names does
        // not get reported as a misleading "no remote files match".
        // The raw name is deliberately not echoed -- it could carry
        // terminal escape sequences -- only the count is shown.
        if !proto::entry_name_safe(&entry.name, "mget: skipping unsafe entry name") {
            unsafe_rejected += 1;
            continue;
        }
        matched += 1;
        let local_child = local_root.join(&entry.name);
        // Skip an existing local destination rather than auto-resuming
        // onto it: `do_get` would append to whatever bytes are there,
        // and a checksum mismatch would then delete the file -- so a
        // same-named but unrelated local file would be destroyed.
        //
        // Use `symlink_metadata` rather than `Path::exists()`: the
        // latter follows symlinks, so a symlink named like a matched
        // entry would report its *target's* presence (a TOCTOU that
        // either skips a real download or, for a dangling link, slips
        // past here only to fail the `O_NOFOLLOW` open). The skip
        // decision must be about the local *name*, which a symlink
        // itself occupies.
        if std::fs::symlink_metadata(&local_child).is_ok() {
            println!("mget: skipping {} (local file exists)", entry.name);
            skipped += 1;
            continue;
        }
        let remote_child = if rdir.is_empty() {
            entry.name.clone()
        } else if rdir == "/" {
            // Root directory: avoid emitting a doubled `//` separator.
            format!("/{}", entry.name)
        } else {
            format!("{rdir}/{}", entry.name)
        };
        match transfer::do_get(session, &remote_child, &local_child) {
            Ok(()) => ok += 1,
            Err(e) => println!("mget: {remote_child} failed: {e}"),
        }
    }
    if unsafe_rejected > 0 {
        eprintln!(
            "mget: warning: server returned {unsafe_rejected} entry/entries \
             with unsafe name(s) (contained '..', '/', or other rejected \
             characters); they were skipped"
        );
    }
    if matched == 0 {
        if unsafe_rejected > 0 {
            println!(
                "mget: no safe remote files match '{pattern}' \
                 ({unsafe_rejected} unsafe entry/entries rejected -- see warning above)"
            );
        } else {
            println!("mget: no remote files match '{pattern}'");
        }
    } else {
        println!(
            "mget: downloaded {ok}/{matched} file(s) to {} ({skipped} skipped)",
            local_root.display()
        );
    }
    Ok(())
}

/// Walk the remote directory tree, downloading every file under `remote`
/// into `local_root`. The remote layout is preserved relative to
/// `remote`.
fn do_recursive_get(session: &mut Session, remote: &str, local_root: Option<String>) -> Result<()> {
    let local_root = local_root.map(PathBuf::from).unwrap_or_else(|| {
        Path::new(remote)
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(remote))
    });
    std::fs::create_dir_all(&local_root).ok();

    // BFS via Ls. A malicious or buggy server can return the same
    // sub-directory name on every listing, driving the client to
    // recurse without bound; cap the number of directories visited so
    // the walk terminates with a clear error instead.
    let mut queue: Vec<(String, PathBuf)> = vec![(remote.to_string(), local_root.clone())];
    let mut visited: usize = 0;
    while let Some((rdir, ldir)) = queue.pop() {
        visited += 1;
        if visited > proto::MAX_DIRS {
            anyhow::bail!(
                "recursive get aborted: remote directory tree too large \
                 or cyclic (exceeded {} directories)",
                proto::MAX_DIRS
            );
        }
        let req = Request::Ls {
            path: rdir.clone(),
            cursor: None,
        };
        let resp = session.request_response(&req)?;
        let entries = match resp {
            Response::DirListing { entries, .. } => entries,
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
            if !proto::entry_name_safe(
                &entry.name,
                "recursive get: server returned unsafe entry name; skipping",
            ) {
                continue;
            }
            let remote_child = join_remote(&rdir, Path::new(&entry.name));
            let local_child = ldir.join(&entry.name);
            if entry.is_dir() {
                queue.push((remote_child, local_child));
            } else {
                // Same existing-destination guard as `do_mget`: never
                // resume/append onto an already-present local name.
                // `do_get` appends to whatever bytes are there and
                // deletes the file on a trailer mismatch, so a same-named
                // but unrelated local file would be destroyed. Use
                // `symlink_metadata` so the decision is about the local
                // *name* (a symlink occupies it too) rather than its
                // target.
                if std::fs::symlink_metadata(&local_child).is_ok() {
                    println!("get: skipping {remote_child} (local file exists)");
                    continue;
                }
                if let Err(e) = transfer::do_get(session, &remote_child, &local_child) {
                    println!("get {} failed: {e}", remote_child);
                }
            }
        }
    }
    Ok(())
}

/// A single planned operation in a recursive upload, in the order it
/// must be issued so that a directory always exists before its
/// children are uploaded into it.
#[derive(Debug, PartialEq, Eq)]
enum PutOp {
    Mkdir(String),
    PutFile { local: PathBuf, remote: String },
}

/// Walk `local` and produce the ordered upload plan for `remote_root`,
/// skipping symlinks and bounding the number of directories visited.
///
/// Pure (no network): the side effects of `do_recursive_put` are the
/// `Mkdir`/`Put` requests it issues, and those map one-to-one onto the
/// returned `Vec`, so the cycle-termination and symlink-exclusion
/// behaviour is testable against a real on-disk tree.
fn plan_recursive_put(local: &Path, remote_root: &str) -> Result<Vec<PutOp>> {
    let mut ops = vec![PutOp::Mkdir(remote_root.to_string())];
    let mut queue: Vec<(PathBuf, String)> = vec![(local.to_path_buf(), remote_root.to_string())];
    let mut visited: usize = 0;
    while let Some((dir, rremote)) = queue.pop() {
        visited += 1;
        if visited > proto::MAX_DIRS {
            anyhow::bail!(
                "recursive put aborted: local directory tree too large \
                 or cyclic (exceeded {} directories)",
                proto::MAX_DIRS
            );
        }
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
            // Use the entry's own file type (a no-follow lstat) rather
            // than `path.is_dir()`, which follows symlinks: a symlink
            // pointing at a directory (or an ancestor, forming a cycle)
            // would otherwise be descended into. Skip symlinks entirely
            // so the walk stays within the real on-disk tree.
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(e) => {
                    println!("stat {} failed: {e}", path.display());
                    continue;
                }
            };
            if file_type.is_symlink() {
                println!("put: skipping symlink {}", path.display());
                continue;
            }
            if file_type.is_dir() {
                ops.push(PutOp::Mkdir(remote_child.clone()));
                queue.push((path, remote_child));
            } else {
                ops.push(PutOp::PutFile {
                    local: path,
                    remote: remote_child,
                });
            }
        }
    }
    Ok(ops)
}

/// Walk a local directory and upload every regular file under it,
/// mirroring its structure under `remote_root`.
fn do_recursive_put(session: &mut Session, local: &Path, remote_root: &str) -> Result<()> {
    if !local.is_dir() {
        // -r on a file degrades to a normal put.
        let stream_id = session.take_stream();
        return transfer::do_put(session, stream_id, local, remote_root, 0, false);
    }

    for op in plan_recursive_put(local, remote_root)? {
        match op {
            PutOp::Mkdir(path) => {
                let _ = session.request_response(&Request::Mkdir { path })?;
            }
            PutOp::PutFile { local, remote } => {
                let stream_id = session.take_stream();
                if let Err(e) = transfer::do_put(session, stream_id, &local, &remote, 0, false) {
                    println!("put {} failed: {e}", local.display());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod cli_tests {
    use super::{Args, OneShot};
    use clap::{CommandFactory, Parser};

    /// clap's own structural self-check. Catches, among other things,
    /// a non-required variadic positional placed before a required one
    /// (the #305 regression that made `put` panic in debug builds).
    #[test]
    fn command_definition_is_valid() {
        Args::command().debug_assert();
    }

    /// `put REMOTE LOCAL...`: the remote is the first positional, the
    /// variadic locals trail it. Regression guard for #305.
    #[test]
    fn put_parses_remote_then_locals() {
        let args = Args::try_parse_from(["qftp-client", "put", "qftp://h/b", "/tmp/a"])
            .expect("put REMOTE LOCAL must parse");
        match args.command {
            Some(OneShot::Put { remote, local, .. }) => {
                assert_eq!(remote, "qftp://h/b");
                assert_eq!(local, vec!["/tmp/a".to_string()]);
            }
            other => panic!("expected Put, got {other:?}"),
        }
    }

    #[test]
    fn put_parses_multiple_locals() {
        let args =
            Args::try_parse_from(["qftp-client", "put", "qftp://h/dir/", "/tmp/a", "/tmp/b"])
                .expect("put REMOTE LOCAL... must parse");
        match args.command {
            Some(OneShot::Put { remote, local, .. }) => {
                assert_eq!(remote, "qftp://h/dir/");
                assert_eq!(local, vec!["/tmp/a".to_string(), "/tmp/b".to_string()]);
            }
            other => panic!("expected Put, got {other:?}"),
        }
    }

    /// `put --help` must render without panicking. Before #305 the
    /// debug_assert fired during arg construction, so even `--help`
    /// crashed in debug builds.
    #[test]
    fn put_help_does_not_panic() {
        let err = Args::try_parse_from(["qftp-client", "put", "--help"])
            .expect_err("--help short-circuits to an Err(DisplayHelp)");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    /// #306: connection flags are `global = true`, so they may appear
    /// *before* a one-shot subcommand without a usage error.
    #[test]
    fn global_flag_before_subcommand() {
        let args = Args::try_parse_from(["qftp-client", "--insecure", "get", "qftp://h/b"])
            .expect("--insecure before subcommand must parse");
        assert!(args.insecure);
        assert!(matches!(args.command, Some(OneShot::Get { .. })));
    }

    /// #306: the same global flags may also appear *after* the
    /// subcommand and its positionals.
    #[test]
    fn global_flags_after_subcommand() {
        let args = Args::try_parse_from([
            "qftp-client",
            "get",
            "qftp://h/b",
            "--ca",
            "/tmp/ca.pem",
            "--client-cert",
            "/tmp/c.pem",
            "--client-key",
            "/tmp/k.pem",
        ])
        .expect("--ca/--client-cert/--client-key after subcommand must parse");
        assert_eq!(args.ca.as_deref(), Some("/tmp/ca.pem"));
        assert_eq!(args.client_cert.as_deref(), Some("/tmp/c.pem"));
        assert_eq!(args.client_key.as_deref(), Some("/tmp/k.pem"));
    }

    /// The bare-target REPL form (no subcommand) still parses; making
    /// the connection flags global must not break the legacy path.
    #[test]
    fn bare_target_without_subcommand_still_parses() {
        let args = Args::try_parse_from(["qftp-client", "--insecure", "qftp://h/b"])
            .expect("bare target with global flag must parse");
        assert!(args.command.is_none());
        assert_eq!(args.target.as_deref(), Some("qftp://h/b"));
        assert!(args.insecure);
    }
}

#[cfg(test)]
mod tests {
    use super::{plan_recursive_put, PutOp};
    use std::fs;

    #[cfg(unix)]
    #[test]
    fn recursive_put_terminates_on_symlink_cycle() {
        // #267: a self-referential symlink (`dir/loop -> .`) used to make
        // the BFS recurse without bound because `path.is_dir()` follows
        // the link. The walk must now skip the symlink and finish.
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("data");
        fs::create_dir_all(&root).expect("mkdir root");
        fs::write(root.join("file.txt"), b"hello").expect("write file");
        std::os::unix::fs::symlink(&root, root.join("loop")).expect("symlink");

        let ops = plan_recursive_put(&root, "/remote").expect("plan must terminate");

        // The symlink is never descended into and never uploaded.
        assert!(
            !ops.iter().any(|op| matches!(
                op,
                PutOp::PutFile { remote, .. } if remote.contains("loop")
            )),
            "symlink should be skipped: {ops:?}"
        );
        // The single real file is planned exactly once.
        let file_puts = ops
            .iter()
            .filter(
                |op| matches!(op, PutOp::PutFile { remote, .. } if remote.ends_with("file.txt")),
            )
            .count();
        assert_eq!(file_puts, 1, "real file uploaded exactly once: {ops:?}");
    }

    #[test]
    fn recursive_put_plans_dirs_before_their_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().join("data");
        let sub = root.join("sub");
        fs::create_dir_all(&sub).expect("mkdir sub");
        fs::write(sub.join("nested.txt"), b"x").expect("write nested");

        let ops = plan_recursive_put(&root, "/remote").expect("plan");

        let mkdir_sub = ops
            .iter()
            .position(|op| matches!(op, PutOp::Mkdir(p) if p == "/remote/sub"));
        let put_nested = ops.iter().position(
            |op| matches!(op, PutOp::PutFile { remote, .. } if remote == "/remote/sub/nested.txt"),
        );
        let (m, p) = (
            mkdir_sub.expect("mkdir for sub planned"),
            put_nested.expect("put for nested file planned"),
        );
        assert!(m < p, "mkdir must precede the put into it: {ops:?}");
        assert_eq!(ops.first(), Some(&PutOp::Mkdir("/remote".to_string())));
    }
}
