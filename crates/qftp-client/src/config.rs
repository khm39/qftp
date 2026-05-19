//! Client-side connection configuration: URL parsing and TOML config
//! file loading.
//!
//! Two layers of input feed into a single `ConnectionSpec`:
//!
//! 1. A positional `target` argument that is either a `qftp://` /
//!    `qftps://` URL or the name of a host alias defined in the config
//!    file.
//! 2. An optional `~/.qftp/config.toml` (overridable with `--config`).
//!
//! CLI flags then override anything they specify. This is the
//! `ConnectionSpec` the rest of the client uses.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

/// Fully resolved connection parameters used by `main` after merging
/// URL, config-file alias, and CLI overrides.
#[derive(Debug, Clone)]
pub struct ConnectionSpec {
    /// Address the UDP socket will `connect()` to.
    pub host: String,
    /// SNI / certificate name expected on the server cert.
    pub server_name: String,
    /// Optional user component parsed from `qftp://user@host`.
    /// Reserved for #77 (SSH-style password / pubkey auth); the
    /// current mTLS-only protocol ignores it.
    #[allow(dead_code)]
    pub user: Option<String>,
    /// Optional `cd <path>` to run immediately after handshake.
    pub initial_path: Option<String>,
    pub insecure: bool,
    pub ca: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

/// Result of parsing a `qftp://` or `qftps://` URL. Just the URL
/// fields, before config-file or CLI merging happens.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UrlTarget {
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub initial_path: Option<String>,
}

pub const DEFAULT_PORT: u16 = 4433;

/// Recognise a positional target that looks like a URL.
pub fn looks_like_url(target: &str) -> bool {
    target.starts_with("qftp://") || target.starts_with("qftps://")
}

/// Parse a `qftp://[user@]host[:port][/path]` (or `qftps://...`) URL
/// into its components. Both schemes are accepted; transport is QUIC +
/// TLS 1.3 either way, so `qftps://` is just an alias preserved for
/// users who expect the "secure" suffix.
pub fn parse_url(input: &str) -> Result<UrlTarget> {
    let parsed = url::Url::parse(input).with_context(|| format!("invalid URL: {input}"))?;
    let scheme = parsed.scheme();
    if scheme != "qftp" && scheme != "qftps" {
        return Err(anyhow!(
            "unsupported scheme: {scheme} (expected qftp or qftps)"
        ));
    }
    // qftp authenticates with mTLS or (later) #77 pubkey/passphrase;
    // there is no protocol-level password. Silently ignoring a `:pw`
    // in the URL would let users believe they had auth set up. Reject
    // it explicitly so secrets cannot leak into shell history.
    if parsed.password().is_some() {
        return Err(anyhow!(
            "URL contains a password component; qftp does not support password-in-URL \
             (use --client-cert / --client-key, or wait for #77 pubkey auth)"
        ));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("URL is missing a host component"))?
        .to_string();
    let port = parsed.port().unwrap_or(DEFAULT_PORT);
    let user = if parsed.username().is_empty() {
        None
    } else {
        Some(
            percent_decode(parsed.username())
                .ok_or_else(|| anyhow!("invalid percent-encoding in user"))?,
        )
    };
    let initial_path = match parsed.path() {
        "" | "/" => None,
        p => Some(p.to_string()),
    };
    Ok(UrlTarget {
        host,
        port,
        user,
        initial_path,
    })
}

fn percent_decode(s: &str) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hi = (bytes[i + 1] as char).to_digit(16)?;
            let lo = (bytes[i + 2] as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Mirrors the TOML `[host.<alias>]` shape. All fields optional;
/// `endpoint` is the URL form that everything else can layer onto.
#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct HostConfig {
    pub endpoint: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub server_name: Option<String>,
    pub user: Option<String>,
    pub insecure: Option<bool>,
    pub ca: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
    pub initial_path: Option<String>,
}

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigFile {
    pub host: HashMap<String, HostConfig>,
}

impl ConfigFile {
    /// Read `path` as TOML. A missing file is not an error; an empty
    /// config is returned. Parse errors are surfaced verbatim so the
    /// user can fix syntax.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                toml::from_str(&s).with_context(|| format!("failed to parse {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }
}

/// Default config-file location: `~/.qftp/config.toml`. Returns `None`
/// when `$HOME` is unset (most CI matrices) so callers can fall back to
/// "no config file".
pub fn default_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".qftp/config.toml"))
}

/// Expand a leading `~/` against `$HOME`. Anything else passes through
/// unchanged.
pub fn expand_tilde(p: &str) -> String {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return Path::new(&home).join(rest).to_string_lossy().into_owned();
        }
    }
    p.to_string()
}

/// CLI-level overrides; `None` means "leave whatever was resolved
/// from URL/config alone".
#[derive(Debug, Default)]
pub struct Overrides {
    pub host: Option<String>,
    pub server_name: Option<String>,
    pub insecure: Option<bool>,
    pub ca: Option<String>,
    pub client_cert: Option<String>,
    pub client_key: Option<String>,
}

/// Build a `ConnectionSpec` from the user's inputs.
///
/// Precedence (highest wins): CLI flag > URL > config-file alias >
/// builtin default. The positional target string is treated as a URL
/// when it starts with `qftp://` / `qftps://`, otherwise as the name
/// of a `[host.<alias>]` section in `config`.
pub fn resolve(
    target: Option<&str>,
    config: &ConfigFile,
    overrides: &Overrides,
) -> Result<ConnectionSpec> {
    let mut url_part: Option<UrlTarget> = None;
    let mut alias_part: Option<HostConfig> = None;

    if let Some(t) = target {
        if looks_like_url(t) {
            url_part = Some(parse_url(t)?);
        } else {
            let cfg = config.host.get(t).cloned().ok_or_else(|| {
                let mut available: Vec<&str> = config.host.keys().map(|s| s.as_str()).collect();
                available.sort_unstable();
                if available.is_empty() {
                    anyhow!(
                        "no host alias '{t}' defined (the config file has no [host.*] sections)"
                    )
                } else {
                    anyhow!(
                        "no host alias '{t}'. Defined aliases: {}",
                        available.join(", ")
                    )
                }
            })?;
            alias_part = Some(cfg);
        }
    }

    // Layering, lowest precedence first:
    //   1. builtin defaults
    //   2. alias.endpoint (a URL parsed into host/port/sni/user/path)
    //   3. alias's explicit fields (host/port/server_name/...): these
    //      override the endpoint so an operator can pin a different
    //      SNI than the cert's hostname, etc.
    //   4. URL given on the command line (it's the user's explicit
    //      intent at invocation time)
    //   5. CLI flag overrides (--host etc., the highest)
    //
    // The merge intentionally goes endpoint -> alias overrides ->
    // command-line URL so users get the "alias is a defaults bundle"
    // mental model.

    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = DEFAULT_PORT;
    let mut server_name = "localhost".to_string();
    let mut user: Option<String> = None;
    let mut initial_path: Option<String> = None;
    let mut insecure = false;
    let mut ca: Option<String> = None;
    let mut client_cert: Option<String> = None;
    let mut client_key: Option<String> = None;

    // Step 2: alias.endpoint.
    if let Some(alias) = &alias_part {
        if let Some(endpoint) = &alias.endpoint {
            let u = parse_url(endpoint)?;
            host.clone_from(&u.host);
            port = u.port;
            server_name.clone_from(&u.host);
            if let Some(uu) = &u.user {
                user = Some(uu.clone());
            }
            if let Some(p) = &u.initial_path {
                initial_path = Some(p.clone());
            }
        }
    }

    // Step 3: alias explicit fields override the endpoint.
    if let Some(alias) = &alias_part {
        if let Some(h) = &alias.host {
            host.clone_from(h);
        }
        if let Some(p) = alias.port {
            port = p;
        }
        if let Some(s) = &alias.server_name {
            server_name.clone_from(s);
        }
        if let Some(u) = &alias.user {
            user = Some(u.clone());
        }
        if let Some(b) = alias.insecure {
            insecure = b;
        }
        if let Some(p) = &alias.initial_path {
            initial_path = Some(p.clone());
        }
        if let Some(s) = &alias.ca {
            ca = Some(expand_tilde(s));
        }
        if let Some(s) = &alias.client_cert {
            client_cert = Some(expand_tilde(s));
        }
        if let Some(s) = &alias.client_key {
            client_key = Some(expand_tilde(s));
        }
    }

    // Step 4: URL given on the command line.
    if let Some(u) = &url_part {
        host.clone_from(&u.host);
        port = u.port;
        // SNI follows the URL host unless explicitly overridden by a
        // flag later.
        server_name.clone_from(&u.host);
        if let Some(uu) = &u.user {
            user = Some(uu.clone());
        }
        if let Some(p) = &u.initial_path {
            initial_path = Some(p.clone());
        }
    }

    // Step 5: CLI flags win.
    if let Some(h) = &overrides.host {
        let (h_only, p_opt) = split_host_port(h);
        host = h_only;
        if let Some(p) = p_opt {
            port = p;
        }
    }
    if let Some(s) = &overrides.server_name {
        server_name.clone_from(s);
    }
    if let Some(b) = overrides.insecure {
        insecure = b;
    }
    if overrides.ca.is_some() {
        ca = overrides.ca.clone();
    }
    if overrides.client_cert.is_some() {
        client_cert = overrides.client_cert.clone();
    }
    if overrides.client_key.is_some() {
        client_key = overrides.client_key.clone();
    }

    Ok(ConnectionSpec {
        host: format_host_port(&host, port),
        server_name,
        user,
        initial_path,
        insecure,
        ca,
        client_cert,
        client_key,
    })
}

/// Format a host + port for the `SocketAddr` parser. IPv6 literals
/// must be wrapped in brackets so `[::1]:4433` parses; IPv4 and
/// hostnames pass through plain.
pub(crate) fn format_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Split a `--host` value into `(host, Some(port))`, accepting:
///   - `127.0.0.1:4433`
///   - `example.com:4433`
///   - `[::1]:4433`            (bracketed IPv6 with port)
///   - `[::1]`                 (bracketed IPv6, no port)
///   - `2001:db8::1`           (bare IPv6, no port)
///   - `127.0.0.1`             (no port)
///
/// Bare IPv6 literals are unambiguous when they contain more than one
/// `:`, so we only treat the last colon as a port separator for hosts
/// with at most one `:`.
fn split_host_port(input: &str) -> (String, Option<u16>) {
    if let Some(rest) = input.strip_prefix('[') {
        // Bracketed IPv6.
        if let Some((host, after)) = rest.split_once(']') {
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host.to_string(), port);
        }
        return (input.to_string(), None);
    }
    let colon_count = input.bytes().filter(|b| *b == b':').count();
    match colon_count {
        0 => (input.to_string(), None),
        1 => match input.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => (h.to_string(), Some(port)),
                Err(_) => (input.to_string(), None),
            },
            None => (input.to_string(), None),
        },
        // 2+ colons: bare IPv6 address. There's no port unless the
        // user used the bracket form, which we handled above.
        _ => (input.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_url() {
        let u = parse_url("qftp://localhost:4433").unwrap();
        assert_eq!(u.host, "localhost");
        assert_eq!(u.port, 4433);
        assert!(u.user.is_none());
        assert!(u.initial_path.is_none());
    }

    #[test]
    fn parse_url_default_port() {
        let u = parse_url("qftp://example.com").unwrap();
        assert_eq!(u.port, DEFAULT_PORT);
    }

    #[test]
    fn parse_url_with_user_and_path() {
        let u = parse_url("qftps://alice@files.example:9000/data").unwrap();
        assert_eq!(u.host, "files.example");
        assert_eq!(u.port, 9000);
        assert_eq!(u.user.as_deref(), Some("alice"));
        assert_eq!(u.initial_path.as_deref(), Some("/data"));
    }

    #[test]
    fn parse_url_rejects_unknown_scheme() {
        assert!(parse_url("http://example.com").is_err());
        assert!(parse_url("sftp://example.com").is_err());
    }

    #[test]
    fn parse_url_decodes_percent_user() {
        let u = parse_url("qftp://a%40b@host").unwrap();
        assert_eq!(u.user.as_deref(), Some("a@b"));
    }

    #[test]
    fn looks_like_url_detects_both_schemes() {
        assert!(looks_like_url("qftp://x"));
        assert!(looks_like_url("qftps://x"));
        assert!(!looks_like_url("work"));
        assert!(!looks_like_url("http://x"));
    }

    #[test]
    fn config_parse_basic() {
        let toml = r#"
            [host.work]
            endpoint = "qftps://files.work.example:4433"
            ca = "~/.qftp/work-ca.pem"
            client_cert = "~/.qftp/work-cert.pem"
            client_key = "~/.qftp/work-key.pem"

            [host.home]
            endpoint = "qftp://home.lan:4433"
            insecure = true
        "#;
        let cfg: ConfigFile = toml::from_str(toml).unwrap();
        assert_eq!(cfg.host.len(), 2);
        assert_eq!(
            cfg.host["work"].endpoint.as_deref(),
            Some("qftps://files.work.example:4433")
        );
        assert_eq!(cfg.host["home"].insecure, Some(true));
    }

    #[test]
    fn config_rejects_unknown_field() {
        let toml = r#"
            [host.work]
            endpoint = "qftps://x:4433"
            typo = "oops"
        "#;
        assert!(toml::from_str::<ConfigFile>(toml).is_err());
    }

    #[test]
    fn resolve_pure_url() {
        let cfg = ConfigFile::default();
        let spec = resolve(
            Some("qftp://example.com:5555/data"),
            &cfg,
            &Overrides::default(),
        )
        .unwrap();
        assert_eq!(spec.host, "example.com:5555");
        assert_eq!(spec.server_name, "example.com");
        assert_eq!(spec.initial_path.as_deref(), Some("/data"));
    }

    #[test]
    fn resolve_alias_endpoint() {
        let cfg: ConfigFile = toml::from_str(
            r#"
                [host.work]
                endpoint = "qftps://files.work.example:9000"
                ca = "/etc/qftp/ca.pem"
            "#,
        )
        .unwrap();
        let spec = resolve(Some("work"), &cfg, &Overrides::default()).unwrap();
        assert_eq!(spec.host, "files.work.example:9000");
        assert_eq!(spec.server_name, "files.work.example");
        assert_eq!(spec.ca.as_deref(), Some("/etc/qftp/ca.pem"));
    }

    #[test]
    fn resolve_alias_explicit_fields_override_endpoint() {
        let cfg: ConfigFile = toml::from_str(
            r#"
                [host.work]
                endpoint = "qftps://files.work.example:9000"
                server_name = "custom-sni.example"
                port = 7000
            "#,
        )
        .unwrap();
        let spec = resolve(Some("work"), &cfg, &Overrides::default()).unwrap();
        // Endpoint primes the defaults, then the alias's explicit
        // server_name / port override them. Host stays at the
        // endpoint's value because no explicit `host =` was set.
        assert_eq!(spec.server_name, "custom-sni.example");
        assert_eq!(spec.host, "files.work.example:7000");
    }

    #[test]
    fn parse_url_rejects_password() {
        let err = parse_url("qftp://alice:secret@host:4433").unwrap_err();
        assert!(err.to_string().contains("password"));
    }

    #[test]
    fn resolve_unknown_alias_lists_aliases_sorted() {
        let cfg: ConfigFile = toml::from_str(
            r#"
                [host.zzz]
                endpoint = "qftp://x:4433"
                [host.aaa]
                endpoint = "qftp://x:4433"
                [host.mmm]
                endpoint = "qftp://x:4433"
            "#,
        )
        .unwrap();
        let err = resolve(Some("nope"), &cfg, &Overrides::default()).unwrap_err();
        let msg = err.to_string();
        // Aliases must appear in sorted order.
        let aaa_pos = msg.find("aaa").unwrap();
        let mmm_pos = msg.find("mmm").unwrap();
        let zzz_pos = msg.find("zzz").unwrap();
        assert!(aaa_pos < mmm_pos);
        assert!(mmm_pos < zzz_pos);
    }

    #[test]
    fn split_host_port_handles_ipv4_hostname_and_ipv6() {
        assert_eq!(
            split_host_port("127.0.0.1:4433"),
            ("127.0.0.1".to_string(), Some(4433))
        );
        assert_eq!(
            split_host_port("example.com:4433"),
            ("example.com".to_string(), Some(4433))
        );
        assert_eq!(
            split_host_port("example.com"),
            ("example.com".to_string(), None)
        );
        // Bare IPv6 (no port): not split.
        assert_eq!(
            split_host_port("2001:db8::1"),
            ("2001:db8::1".to_string(), None)
        );
        // Bracketed IPv6 with port.
        assert_eq!(
            split_host_port("[::1]:4433"),
            ("::1".to_string(), Some(4433))
        );
        assert_eq!(split_host_port("[::1]"), ("::1".to_string(), None));
    }

    #[test]
    fn format_host_port_brackets_ipv6() {
        assert_eq!(format_host_port("127.0.0.1", 4433), "127.0.0.1:4433");
        assert_eq!(format_host_port("example.com", 4433), "example.com:4433");
        assert_eq!(format_host_port("::1", 4433), "[::1]:4433");
        assert_eq!(format_host_port("2001:db8::1", 9000), "[2001:db8::1]:9000");
        // Already bracketed -> left alone.
        assert_eq!(format_host_port("[::1]", 4433), "[::1]:4433");
    }

    #[test]
    fn resolve_ipv6_url_brackets_socket_string() {
        let cfg = ConfigFile::default();
        let spec = resolve(Some("qftp://[::1]:4433"), &cfg, &Overrides::default()).unwrap();
        assert_eq!(spec.host, "[::1]:4433");
        // SocketAddr should be parseable.
        let _: std::net::SocketAddr = spec.host.parse().unwrap();
    }

    #[test]
    fn resolve_flag_overrides_url() {
        let cfg = ConfigFile::default();
        let overrides = Overrides {
            host: Some("10.0.0.1:7777".to_string()),
            insecure: Some(true),
            ..Overrides::default()
        };
        let spec = resolve(Some("qftp://example.com:5555"), &cfg, &overrides).unwrap();
        assert_eq!(spec.host, "10.0.0.1:7777");
        assert!(spec.insecure);
    }

    #[test]
    fn resolve_unknown_alias_lists_available() {
        let cfg: ConfigFile = toml::from_str(
            r#"
                [host.work]
                endpoint = "qftp://x:4433"
            "#,
        )
        .unwrap();
        let err = resolve(Some("nope"), &cfg, &Overrides::default()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("nope"));
        assert!(msg.contains("work"));
    }

    #[test]
    fn resolve_flag_host_accepts_bracketed_ipv6() {
        let cfg = ConfigFile::default();
        let overrides = Overrides {
            host: Some("[2001:db8::1]:5555".to_string()),
            ..Overrides::default()
        };
        let spec = resolve(None, &cfg, &overrides).unwrap();
        assert_eq!(spec.host, "[2001:db8::1]:5555");
        let _: std::net::SocketAddr = spec.host.parse().unwrap();
    }

    #[test]
    fn resolve_default_when_no_target() {
        let cfg = ConfigFile::default();
        let spec = resolve(None, &cfg, &Overrides::default()).unwrap();
        assert_eq!(spec.host, "127.0.0.1:4433");
        assert_eq!(spec.server_name, "localhost");
    }

    #[test]
    fn config_load_missing_file_is_empty() {
        let cfg = ConfigFile::load(Path::new("/nonexistent/qftp/config.toml")).unwrap();
        assert!(cfg.host.is_empty());
    }
}
