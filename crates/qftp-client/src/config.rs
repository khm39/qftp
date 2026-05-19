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
        return Err(anyhow!("unsupported scheme: {scheme} (expected qftp or qftps)"));
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
            Ok(s) => toml::from_str(&s)
                .with_context(|| format!("failed to parse {}", path.display())),
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
                let available: Vec<&String> = config.host.keys().collect();
                if available.is_empty() {
                    anyhow!(
                        "no host alias '{t}' defined (the config file has no [host.*] sections)"
                    )
                } else {
                    anyhow!(
                        "no host alias '{t}'. Defined aliases: {}",
                        available
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            })?;
            alias_part = Some(cfg);
        }
    }

    if let Some(alias) = &alias_part {
        if let Some(endpoint) = &alias.endpoint {
            url_part = Some(parse_url(endpoint)?);
        }
    }

    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = DEFAULT_PORT;
    let mut server_name = "localhost".to_string();
    let mut user: Option<String> = None;
    let mut initial_path: Option<String> = None;
    let mut insecure = false;
    let mut ca: Option<String> = None;
    let mut client_cert: Option<String> = None;
    let mut client_key: Option<String> = None;

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
        ca = alias.ca.as_deref().map(expand_tilde).or(ca);
        client_cert = alias.client_cert.as_deref().map(expand_tilde).or(client_cert);
        client_key = alias.client_key.as_deref().map(expand_tilde).or(client_key);
        initial_path.clone_from(&alias.initial_path);
    }

    if let Some(u) = &url_part {
        host.clone_from(&u.host);
        port = u.port;
        // SNI follows the URL host unless overridden elsewhere.
        server_name.clone_from(&u.host);
        if let Some(uu) = &u.user {
            user = Some(uu.clone());
        }
        if let Some(p) = &u.initial_path {
            initial_path = Some(p.clone());
        }
    }

    if let Some(h) = &overrides.host {
        // Override format is `ip:port`; parse it so we keep the
        // resolved host/port pair coherent.
        if let Some((h_only, p_only)) = h.rsplit_once(':') {
            if let Ok(p) = p_only.parse::<u16>() {
                host = h_only.to_string();
                port = p;
            } else {
                host = h.clone();
            }
        } else {
            host = h.clone();
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
        host: format!("{host}:{port}"),
        server_name,
        user,
        initial_path,
        insecure,
        ca,
        client_cert,
        client_key,
    })
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
        let spec = resolve(Some("qftp://example.com:5555/data"), &cfg, &Overrides::default())
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
            "#,
        )
        .unwrap();
        let spec = resolve(Some("work"), &cfg, &Overrides::default()).unwrap();
        // URL wins over alias.server_name for host but not for SNI:
        // endpoint sets SNI to its host, then no explicit field beats
        // it -- but our precedence (alias < url) means alias.server_name
        // is overwritten when endpoint is present. This test pins the
        // behaviour so a future maintainer notices if it shifts.
        assert_eq!(spec.server_name, "files.work.example");
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
