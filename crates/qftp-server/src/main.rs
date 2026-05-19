use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, Result};
use clap::Parser;
use qftp_common::transport::{create_server_config, ServerTlsConfig};
use tracing::{info, warn};

mod connection;
mod handler;
mod limits;
mod metrics;
mod retry;
mod server;
mod user;

#[derive(Parser)]
#[command(name = "qftp-server", about = "QUIC File Transfer Protocol Server")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    bind: String,
    #[arg(long, default_value = ".")]
    root: String,

    // --- TLS ---
    #[arg(long, required_unless_present = "self_signed")]
    cert: Option<String>,
    #[arg(long, required_unless_present = "self_signed")]
    key: Option<String>,
    /// Generate a fresh self-signed certificate at startup. Development only.
    #[arg(long, default_value_t = false)]
    self_signed: bool,
    /// Keep the self-signed certificate across restarts. Stored under
    /// `--self-signed-state-dir` (default
    /// `${XDG_STATE_HOME}/qftp/self-signed/` or
    /// `~/.local/state/qftp/self-signed/`). Use this together with a
    /// TOFU client (`qftp-client --trust-on-first-use`) so the
    /// fingerprint stays stable across server restarts.
    #[arg(long, default_value_t = false, requires = "self_signed")]
    self_signed_persistent: bool,
    /// Override the directory used by `--self-signed-persistent`.
    #[arg(long, requires = "self_signed_persistent")]
    self_signed_state_dir: Option<PathBuf>,
    /// Path to a PEM CA bundle. When set, clients must present a certificate
    /// signed by this CA (mTLS).
    #[arg(long)]
    client_ca: Option<String>,

    // --- Users / ACL ---
    /// Path to a TOML file defining user homes and permissions. When omitted,
    /// every connection is mapped to a single full-permission anonymous user.
    #[arg(long)]
    users: Option<PathBuf>,

    // --- Caps & rate limiting ---
    #[arg(long, default_value_t = 64)]
    max_connections: usize,
    #[arg(long, default_value_t = 8)]
    max_connections_per_ip: usize,
    /// Require stateless retry (anti-amplification address validation)
    /// before any connection state is allocated. Recommended for any
    /// internet-facing deployment.
    #[arg(long, default_value_t = false)]
    require_retry: bool,

    // --- Observability ---
    /// Bind address for the Prometheus / healthz HTTP endpoint. Disabled
    /// when omitted.
    #[arg(long)]
    metrics_bind: Option<String>,
    #[arg(long, default_value = "text")]
    log_format: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(&args.log_format)?;

    let root = fs::canonicalize(&args.root).context("failed to canonicalize root directory")?;

    let tls = load_or_make_tls(&args)?;
    let quiche_config = create_server_config(&tls)?;

    let users = match &args.users {
        Some(path) => {
            let text = fs::read_to_string(path)
                .with_context(|| format!("failed to read users file: {}", path.display()))?;
            let cfg: user::UserConfig = toml::from_str(&text)
                .with_context(|| format!("failed to parse users file: {}", path.display()))?;
            Arc::new(user::UserDirectory::from_config(&root, cfg)?)
        }
        None => Arc::new(user::UserDirectory::default_anonymous(&root)),
    };

    let addr: std::net::SocketAddr = args.bind.parse().context("invalid bind address")?;
    let std_socket = std::net::UdpSocket::bind(addr).context("failed to bind UDP socket")?;
    std_socket
        .set_nonblocking(true)
        .context("failed to set nonblocking")?;
    let socket = mio::net::UdpSocket::from_std(std_socket);

    info!(
        %addr,
        root = %root.display(),
        mtls = args.client_ca.is_some(),
        require_retry = args.require_retry,
        users_file = ?args.users,
        "QFTP server starting"
    );

    let shutdown = install_signal_handler()?;
    let metrics = Arc::new(metrics::Metrics::default());

    if let Some(bind) = &args.metrics_bind {
        metrics::spawn(Arc::clone(&metrics), bind, Arc::clone(&shutdown))
            .context("failed to start metrics endpoint")?;
    }

    let server_config = server::ServerConfig {
        caps: limits::Caps {
            max_total_connections: args.max_connections,
            max_per_ip_connections: args.max_connections_per_ip,
        },
        require_retry: args.require_retry,
    };

    server::run(
        quiche_config,
        socket,
        server_config,
        users,
        metrics,
        shutdown,
    )?;

    info!("QFTP server stopped");
    Ok(())
}

fn init_tracing(format: &str) -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match format {
        "json" => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init(),
        "text" => tracing_subscriber::fmt().with_env_filter(filter).init(),
        other => anyhow::bail!("unknown log format: {other} (expected 'text' or 'json')"),
    }
    Ok(())
}

fn load_or_make_tls(args: &Args) -> Result<ServerTlsConfig> {
    if args.self_signed && args.self_signed_persistent {
        return load_or_make_persistent_self_signed(args);
    }
    if args.self_signed {
        warn!("Generating ephemeral self-signed certificate (--self-signed). Do not use in production.");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("failed to generate self-signed certificate")?;
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let cert_path =
            std::env::temp_dir().join(format!("qftp-server-cert-{}.pem", std::process::id()));
        let key_path =
            std::env::temp_dir().join(format!("qftp-server-key-{}.pem", std::process::id()));
        fs::write(&cert_path, &cert_pem).context("failed to write cert PEM")?;
        fs::write(&key_path, &key_pem).context("failed to write key PEM")?;
        #[cfg(unix)]
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .context("failed to set key file permissions")?;

        log_fingerprint(&cert_pem, "ephemeral");

        Ok(ServerTlsConfig {
            cert_pem: cert_path.to_string_lossy().to_string(),
            key_pem: key_path.to_string_lossy().to_string(),
            client_ca_pem: args.client_ca.clone(),
        })
    } else {
        let cert = args
            .cert
            .as_ref()
            .context("--cert is required (or pass --self-signed for dev)")?;
        let key = args
            .key
            .as_ref()
            .context("--key is required (or pass --self-signed for dev)")?;
        check_key_permissions(key)?;
        Ok(ServerTlsConfig {
            cert_pem: cert.clone(),
            key_pem: key.clone(),
            client_ca_pem: args.client_ca.clone(),
        })
    }
}

/// Load or create a self-signed cert at a stable on-disk path. The
/// fingerprint stays the same across restarts, which is what TOFU
/// clients (`qftp-client -T`) need to avoid "host key changed"
/// warnings every reboot.
fn load_or_make_persistent_self_signed(args: &Args) -> Result<ServerTlsConfig> {
    let dir = persistent_state_dir(args)?;
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create state dir {}", dir.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to set 0700 on {}", dir.display()))?;

    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    let need_regen = match (cert_path.exists(), key_path.exists()) {
        (true, true) => match cert_is_valid(&cert_path) {
            Ok(true) => false,
            Ok(false) => {
                warn!(
                    cert = %cert_path.display(),
                    "persistent self-signed cert is expired or unreadable; regenerating"
                );
                true
            }
            Err(e) => {
                warn!(
                    error = ?e,
                    cert = %cert_path.display(),
                    "failed to parse persistent self-signed cert; regenerating"
                );
                true
            }
        },
        _ => true,
    };

    if need_regen {
        // 10-year validity. Long lives match the TOFU pattern: pin
        // once, keep working. rcgen 0.13 generate_simple_self_signed
        // produces a default that's already 5+ years; we let that
        // stand to avoid pulling in extra cert-customisation
        // machinery for a Phase 0.5 feature.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .context("failed to generate self-signed certificate")?;
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        fs::write(&cert_path, &cert_pem)
            .with_context(|| format!("failed to write {}", cert_path.display()))?;
        fs::write(&key_path, &key_pem)
            .with_context(|| format!("failed to write {}", key_path.display()))?;
        #[cfg(unix)]
        {
            fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644))
                .with_context(|| format!("failed to chmod {}", cert_path.display()))?;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("failed to chmod {}", key_path.display()))?;
        }
        info!(dir = %dir.display(), "wrote new persistent self-signed cert");
    } else {
        info!(dir = %dir.display(), "loaded existing persistent self-signed cert");
    }

    let cert_pem_str = fs::read_to_string(&cert_path)
        .with_context(|| format!("failed to read {}", cert_path.display()))?;
    log_fingerprint(&cert_pem_str, "persistent");

    Ok(ServerTlsConfig {
        cert_pem: cert_path.to_string_lossy().to_string(),
        key_pem: key_path.to_string_lossy().to_string(),
        client_ca_pem: args.client_ca.clone(),
    })
}

fn persistent_state_dir(args: &Args) -> Result<PathBuf> {
    if let Some(p) = &args.self_signed_state_dir {
        return Ok(p.clone());
    }
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(xdg).join("qftp/self-signed"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".local/state/qftp/self-signed"));
    }
    anyhow::bail!(
        "cannot derive state dir: neither $XDG_STATE_HOME nor $HOME is set. \
         Pass --self-signed-state-dir explicitly."
    )
}

/// Walk the PEM cert and report whether `Not After` is still in the
/// future. A `false` return means the caller should regenerate.
fn cert_is_valid(path: &Path) -> Result<bool> {
    use x509_parser::pem::parse_x509_pem;
    use x509_parser::prelude::FromDer;
    let pem_bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let (_, pem) = parse_x509_pem(&pem_bytes).context("failed to parse PEM block")?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&pem.contents)
        .context("failed to parse DER")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before epoch?")?
        .as_secs() as i64;
    Ok(cert.validity().not_after.timestamp() > now)
}

/// Compute and log the SHA-256 fingerprint of the leaf cert so an
/// operator setting up TOFU has it visible at startup time.
fn log_fingerprint(cert_pem: &str, source: &str) {
    use x509_parser::pem::parse_x509_pem;
    let bytes = cert_pem.as_bytes();
    match parse_x509_pem(bytes) {
        Ok((_, pem)) => {
            use sha2::Digest;
            let digest = sha2::Sha256::digest(&pem.contents);
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            info!(
                source,
                fingerprint = %format!("sha256:{hex}"),
                "self-signed leaf cert fingerprint"
            );
        }
        Err(e) => {
            warn!(error = ?e, "could not compute self-signed cert fingerprint");
        }
    }
}

#[cfg(unix)]
fn check_key_permissions(path: &str) -> Result<()> {
    let meta = fs::metadata(path).context("failed to stat key file")?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        anyhow::bail!(
            "key file {} has permissions {:o}; expected owner-only (e.g. 0600)",
            path,
            mode & 0o777
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_key_permissions(_path: &str) -> Result<()> {
    Ok(())
}

fn install_signal_handler() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, shutdown.clone())
        .context("failed to register SIGINT handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, shutdown.clone())
        .context("failed to register SIGTERM handler")?;
    Ok(shutdown)
}
