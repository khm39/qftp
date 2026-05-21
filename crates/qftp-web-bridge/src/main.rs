//! qftp WebTransport bridge.
//!
//! A standalone server that lets browsers speak qftp over WebTransport
//! (HTTP/3). It terminates WebTransport with the quinn-based
//! `wtransport` stack and drives the transport-independent
//! `qftp-protocol` core, so the native `qftp-server` and `qftp-client`
//! stay on `quiche` (see ADR 0001). Run it alongside `qftp-server` --
//! they share the same `--root` and `users.toml`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use qftp_protocol::user::{UserConfig, UserDirectory};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use wtransport::endpoint::IncomingSession;
use wtransport::{Endpoint, Identity, ServerConfig};

mod auth;
mod http;
mod transfer;

use auth::TokenDirectory;

#[derive(Parser, Debug)]
#[command(
    name = "qftp-web-bridge",
    about = "WebTransport bridge that serves qftp to browser clients."
)]
struct Args {
    /// PEM-encoded TLS certificate chain. WebTransport requires a
    /// browser-trusted certificate (or one pinned via
    /// `serverCertificateHashes`); self-signed certs are otherwise
    /// refused by browsers.
    #[arg(long)]
    cert: PathBuf,

    /// PEM-encoded TLS private key.
    #[arg(long)]
    key: PathBuf,

    /// UDP address for the WebTransport (HTTP/3) listener.
    #[arg(long, default_value = "0.0.0.0:4433")]
    bind: SocketAddr,

    /// Directory served as the global root; per-user homes resolve
    /// under it (same semantics as `qftp-server --root`).
    #[arg(long)]
    root: PathBuf,

    /// Optional users TOML, identical in format to `qftp-server
    /// --users`. Without it every session is the anonymous user.
    #[arg(long)]
    users: Option<PathBuf>,

    /// Optional bearer-token TOML mapping opaque tokens to user names.
    /// Without it token auth is disabled and every session is served
    /// as the anonymous (read-only) user.
    #[arg(long)]
    users_tokens: Option<PathBuf>,

    /// TCP address for the bundled single-page-app HTTP listener.
    /// WebTransport cannot deliver the initial page, so the bridge
    /// serves it here. Front it with a TLS-terminating reverse proxy
    /// in production.
    #[arg(long, default_value = "127.0.0.1:8080")]
    http_bind: SocketAddr,
}

/// Process-wide state shared by every accepted session.
struct Shared {
    users: UserDirectory,
    tokens: TokenDirectory,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let root = std::fs::canonicalize(&args.root)
        .with_context(|| format!("failed to canonicalize root {}", args.root.display()))?;

    let users = match &args.users {
        Some(path) => {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read users file {}", path.display()))?;
            let cfg: UserConfig = toml::from_str(&text)
                .with_context(|| format!("failed to parse users file {}", path.display()))?;
            UserDirectory::from_config(&root, cfg)?
        }
        None => UserDirectory::default_anonymous(&root),
    };

    let tokens = match &args.users_tokens {
        Some(path) => TokenDirectory::load(path, &users)?,
        None => TokenDirectory::anonymous(),
    };
    if !tokens.auth_enabled() {
        warn!(
            "no --users-tokens file: every WebTransport session is served as \
             the anonymous (read-only) user"
        );
    }

    let identity = Identity::load_pemfiles(&args.cert, &args.key)
        .await
        .context("failed to load TLS certificate/key")?;

    let config = ServerConfig::builder()
        .with_bind_address(args.bind)
        .with_identity(identity)
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .build();

    let endpoint = Endpoint::server(config).context("failed to start WebTransport endpoint")?;
    let shared = Arc::new(Shared { users, tokens });

    // Serve the bundled SPA over plain HTTP on a separate task.
    let http_bind = args.http_bind;
    tokio::spawn(async move {
        if let Err(e) = http::serve(http_bind).await {
            warn!(error = %e, "SPA HTTP listener stopped");
        }
    });

    info!(
        bind = %args.bind,
        http_bind = %args.http_bind,
        root = %root.display(),
        "qftp web bridge listening"
    );

    loop {
        let incoming = endpoint.accept().await;
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Err(e) = handle_session(incoming, shared).await {
                warn!(error = %e, "session ended with error");
            }
        });
    }
}

/// Authenticate one incoming WebTransport session, then dispatch each
/// of its bidirectional streams as an independent qftp request.
async fn handle_session(incoming: IncomingSession, shared: Arc<Shared>) -> Result<()> {
    let request = incoming.await.context("incoming session failed")?;

    let user = match shared.tokens.resolve(request.path(), &shared.users) {
        Some(u) => u,
        None => {
            // Deliberately not logging the path: it carries the token.
            info!(remote = %request.remote_address(),
                "rejecting unauthenticated WebTransport session");
            request.forbidden().await;
            return Ok(());
        }
    };

    let connection = request.accept().await.context("failed to accept session")?;
    info!(user = %user.name, remote = %connection.remote_address(),
        "WebTransport session established");

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(transfer::handle_stream(send, recv, Arc::clone(&user)));
            }
            Err(e) => {
                info!(user = %user.name, reason = %e, "WebTransport session closed");
                return Ok(());
            }
        }
    }
}
