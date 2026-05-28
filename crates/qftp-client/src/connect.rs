//! Shared client-side QUIC connection setup.
//!
//! Every client path — the REPL, the one-shot subcommands, the sync
//! and watch uploaders, and the fanout helper — needs the same
//! sequence: build a `quiche::Config` from a `ConnectionSpec`, resolve
//! the host, bind a UDP socket, mint a SCID, call `quiche::connect`,
//! optionally hand it a 0-RTT session ticket, then pump the handshake
//! until established or closed. This module is the single implementation.
//!
//! [`EstablishOpts`] carries the few knobs that differ between paths:
//! the non-interactive callers use [`EstablishOpts::for_spec`], while
//! the REPL builds it explicitly so it can route `--no-zero-rtt`, a
//! custom ticket directory, and TOFU's verify-peer override through.
//! TOFU pinning itself runs in `main.rs` on the returned connection.

use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use mio::{Events, Interest, Poll, Token};
use qftp_common::transport::{
    create_client_config, flush_egress, handle_ingress, ClientCert, ClientTlsConfig,
};

use crate::config::ConnectionSpec;
use crate::session_store;

const CLIENT: Token = Token(0);

/// Per-attempt handshake budget for every resolved address but the
/// last. A reachable peer completes its handshake in well under a
/// second; this only bounds how long an *unreachable* address — e.g.
/// an IPv6 record for an IPv4-only server — is waited on before
/// falling back to the next address.
const FALLBACK_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);

/// Convert a `ConnectionSpec`'s `client_cert` / `client_key` pair into
/// the `ClientCert` struct expected by `create_client_config`. Returns
/// `None` if either half is missing.
pub fn client_cert_from_spec(spec: &ConnectionSpec) -> Option<ClientCert> {
    match (&spec.client_cert, &spec.client_key) {
        (Some(c), Some(k)) => Some(ClientCert {
            cert_pem: c.clone(),
            key_pem: k.clone(),
        }),
        _ => None,
    }
}

/// Knobs for [`establish`] that vary between client paths.
pub struct EstablishOpts {
    /// Verify the server cert in the TLS stack. False for `--insecure`
    /// or while TOFU runs its own pin check after the handshake.
    pub verify_peer: bool,
    /// Attempt 0-RTT resumption from a stored session ticket.
    pub zero_rtt: bool,
    /// Session-ticket directory override. `None` uses the default.
    pub ticket_dir: Option<PathBuf>,
    /// Server-cert fingerprint a stored 0-RTT ticket must be bound to.
    /// In TOFU mode this is the pinned known_hosts value, so a ticket
    /// is only resumed against the same server identity it was saved
    /// for (defends against DNS-repoint / cert-rotation replay). `None`
    /// in CA mode, where the TLS layer's chain validation covers it.
    pub expected_cert_fingerprint: Option<[u8; 32]>,
}

impl EstablishOpts {
    /// Defaults for the non-interactive paths: TLS verification follows
    /// `spec.insecure`, 0-RTT on, and the default ticket directory.
    /// These paths use CA-mode verification (no TOFU), so the ticket
    /// fingerprint binding is left to the TLS layer.
    pub fn for_spec(spec: &ConnectionSpec) -> Self {
        Self {
            verify_peer: !spec.insecure,
            zero_rtt: true,
            ticket_dir: None,
            expected_cert_fingerprint: None,
        }
    }
}

/// A connection driven through its handshake, ready for requests.
pub struct Established {
    pub conn: quiche::Connection,
    pub socket: mio::net::UdpSocket,
    pub poll: Poll,
    pub events: Events,
    /// True when quiche accepted a 0-RTT session ticket.
    pub resumed: bool,
}

/// Open a connection to `spec.host` and drive the handshake to
/// completion. `context_label` is woven into error messages so a
/// failure still points at the calling path.
///
/// `spec.host` is resolved through the system resolver, which can
/// return several addresses — commonly an IPv6 and an IPv4 address for
/// a dual-stack name. Each is tried in the resolver's own order (so an
/// IPv6 address is used when the host publishes a reachable one), and
/// the first that completes a handshake wins. Every attempt but the
/// last is bounded by [`FALLBACK_HANDSHAKE_TIMEOUT`] so an unreachable
/// address falls back quickly; the final address keeps the unbounded
/// wait that a single-address host has always had.
pub fn establish(
    spec: &ConnectionSpec,
    context_label: &str,
    opts: EstablishOpts,
) -> Result<Established> {
    let mut config = create_client_config(ClientTlsConfig {
        verify_peer: opts.verify_peer,
        ca_path: spec.ca.clone(),
        client_cert: client_cert_from_spec(spec),
    })?;

    // Resolve `host:port` through the system resolver. `ToSocketAddrs`
    // handles both numeric literals (`127.0.0.1:4433`, `[::1]:4433`)
    // and DNS names; a plain `str::parse::<SocketAddr>()` would only
    // accept numeric literals and reject every hostname.
    let resolved: Vec<SocketAddr> = spec
        .host
        .to_socket_addrs()
        .with_context(|| format!("{context_label}: cannot resolve host {}", spec.host))?
        .collect();
    if resolved.is_empty() {
        return Err(anyhow!(
            "{context_label}: host {} resolved to no addresses",
            spec.host
        ));
    }

    let mut last_err: Option<anyhow::Error> = None;
    for (i, &peer_addr) in resolved.iter().enumerate() {
        let is_last = i + 1 == resolved.len();
        let budget = if is_last {
            None
        } else {
            Some(FALLBACK_HANDSHAKE_TIMEOUT)
        };
        match try_connect(spec, &mut config, peer_addr, &opts, budget, context_label) {
            Ok(est) => return Ok(est),
            Err(e) => {
                if !is_last {
                    tracing::warn!(
                        addr = %peer_addr,
                        error = %e,
                        "connect attempt failed; trying next address"
                    );
                }
                last_err = Some(e);
            }
        }
    }
    // `resolved` is non-empty, so the loop ran at least once and set
    // `last_err` on the failing final attempt.
    Err(last_err.expect("at least one resolved address was attempted"))
}

/// One connection attempt against a single resolved `peer_addr`: bind a
/// local socket of the matching family, run `quiche::connect`, hand it
/// a 0-RTT ticket when one is available, and pump the handshake.
///
/// `handshake_budget` caps how long to wait for `is_established` before
/// giving up so the caller can fall back to another address; `None`
/// waits until the connection is either established or closed.
fn try_connect(
    spec: &ConnectionSpec,
    config: &mut quiche::Config,
    peer_addr: SocketAddr,
    opts: &EstablishOpts,
    handshake_budget: Option<Duration>,
    context_label: &str,
) -> Result<Established> {
    // Bind the local socket in the same address family as the peer; a
    // hardcoded IPv4 bind cannot reach a host that resolved to IPv6.
    let bind_addr = if peer_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let std_socket =
        UdpSocket::bind(bind_addr).with_context(|| format!("{context_label}: UDP bind"))?;
    std_socket.set_nonblocking(true)?;
    std_socket.connect(peer_addr)?;
    qftp_common::transport::tune_udp_buffers(&std_socket);
    let local_addr = std_socket.local_addr()?;
    let mut socket = mio::net::UdpSocket::from_std(std_socket);

    let rng = ring::rand::SystemRandom::new();
    let mut scid_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    use ring::rand::SecureRandom;
    rng.fill(&mut scid_bytes)
        .map_err(|e| anyhow::anyhow!("{context_label}: system RNG failed to seed SCID: {e}"))?;
    let scid = quiche::ConnectionId::from_vec(scid_bytes.to_vec());
    let mut conn = quiche::connect(
        Some(&spec.server_name),
        &scid,
        local_addr,
        peer_addr,
        config,
    )?;

    // 0-RTT resume: hand quiche a stored ticket before any I/O so the
    // first Initial can carry early data. A rejected ticket falls back
    // to 1-RTT; the stale blob is forgotten so it isn't replayed.
    let mut resumed = false;
    if opts.zero_rtt {
        let dir = opts.ticket_dir.clone().or_else(session_store::default_dir);
        if let Some(dir) = &dir {
            if let Some(ticket) =
                session_store::load(dir, &spec.host, opts.expected_cert_fingerprint.as_ref())
            {
                match conn.set_session(&ticket) {
                    Ok(()) => {
                        resumed = true;
                        tracing::info!(host = %spec.host, "0-RTT: resuming session");
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = ?e,
                            "stale session ticket; falling back to 1-RTT"
                        );
                        let _ = session_store::forget(dir, &spec.host);
                    }
                }
            }
        }
    }

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(1024);
    poll.registry()
        .register(&mut socket, CLIENT, Interest::READABLE)?;

    flush_egress(&mut conn, &socket)?;
    let mut buf = [0u8; 65535];
    let deadline = handshake_budget.map(|d| Instant::now() + d);
    loop {
        poll.poll(
            &mut events,
            conn.timeout().or(Some(Duration::from_millis(100))),
        )?;
        conn.on_timeout();
        handle_ingress(&mut conn, &socket, &mut buf)?;
        flush_egress(&mut conn, &socket)?;
        if conn.is_established() {
            break;
        }
        if conn.is_closed() {
            return Err(anyhow!(
                "{context_label}: connection to {peer_addr} closed during handshake"
            ));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(anyhow!(
                "{context_label}: handshake to {peer_addr} timed out"
            ));
        }
    }

    // CA-mode hostname binding. quiche's `verify_peer(true)` makes
    // BoringSSL validate the certificate *chain*, but it never checks
    // that the leaf identifies the host we meant to reach -- the
    // `server_name` passed to `quiche::connect` only sets the SNI, not
    // a verification target. Without this any certificate that chains
    // to a trusted CA, issued for *any* host, would be accepted, so a
    // DNS-spoof / path-hijack peer could impersonate the server
    // (CWE-295). TOFU and `--insecure` set `verify_peer = false` and do
    // their own (or no) checks, so only enforce here when the TLS layer
    // actually authenticated the chain.
    if opts.verify_peer {
        let der = conn.peer_cert().ok_or_else(|| {
            anyhow!("{context_label}: server presented no certificate to verify hostname against")
        })?;
        if !cert_matches_hostname(der, &spec.server_name) {
            conn.close(true, 0x0, b"server cert hostname mismatch").ok();
            let _ = flush_egress(&mut conn, &socket);
            return Err(anyhow!(
                "{context_label}: server certificate does not match hostname '{}'",
                spec.server_name
            ));
        }
    }

    Ok(Established {
        conn,
        socket,
        poll,
        events,
        resumed,
    })
}

/// Check whether the DER-encoded leaf certificate identifies `host`.
///
/// Follows RFC 6125 / 9525: a literal IP target is matched only against
/// SAN iPAddress entries; a DNS target is matched against SAN dNSName
/// entries (with a single left-most wildcard label), and the Subject CN
/// is consulted only as a legacy fallback when the certificate carries
/// no dNSName SANs at all.
fn cert_matches_hostname(der: &[u8], host: &str) -> bool {
    use x509_parser::prelude::*;

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return false;
    };

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for gn in &san.value.general_names {
                if let GeneralName::IPAddress(bytes) = gn {
                    if ip_san_matches(bytes, &ip) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    let mut had_dns_san = false;
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::DNSName(pat) = gn {
                had_dns_san = true;
                if dns_name_matches(pat, host) {
                    return true;
                }
            }
        }
    }

    // Legacy CN fallback only when no dNSName SAN constrains the cert.
    if !had_dns_san {
        for attr in cert.subject().iter_common_name() {
            if let Ok(cn) = attr.as_str() {
                if dns_name_matches(cn, host) {
                    return true;
                }
            }
        }
    }

    false
}

/// Match a SAN iPAddress octet string against a parsed IP literal.
fn ip_san_matches(san: &[u8], ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => san == v4.octets(),
        std::net::IpAddr::V6(v6) => san == v6.octets(),
    }
}

/// Match a certificate DNS name (possibly a `*.example.com` wildcard)
/// against the requested host. Comparison is ASCII case-insensitive;
/// a wildcard matches exactly one left-most label and never the bare
/// parent domain.
fn dns_name_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let host = host.trim_end_matches('.');
    if pattern.is_empty() || host.is_empty() {
        return false;
    }

    if let Some(rest) = pattern.strip_prefix("*.") {
        // A wildcard label may not match a host that has fewer labels
        // than the pattern, and the wildcard only covers the single
        // left-most label of `host`.
        let Some((host_label, host_rest)) = host.split_once('.') else {
            return false;
        };
        if host_label.is_empty() {
            return false;
        }
        return !rest.is_empty() && rest.eq_ignore_ascii_case(host_rest);
    }

    pattern.eq_ignore_ascii_case(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair, SanType};

    fn cert_with_dns(names: &[&str]) -> Vec<u8> {
        let params =
            CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("rcgen new");
        let key = KeyPair::generate().expect("rcgen keypair");
        params
            .self_signed(&key)
            .expect("self_signed")
            .der()
            .to_vec()
    }

    fn cert_with_sans(sans: Vec<SanType>) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("rcgen new");
        params.subject_alt_names = sans;
        let key = KeyPair::generate().expect("rcgen keypair");
        params
            .self_signed(&key)
            .expect("self_signed")
            .der()
            .to_vec()
    }

    #[test]
    fn exact_dns_san_matches_and_other_host_rejected() {
        let der = cert_with_dns(&["files.example.com"]);
        assert!(cert_matches_hostname(&der, "files.example.com"));
        assert!(cert_matches_hostname(&der, "FILES.EXAMPLE.COM"));
        // CWE-295 regression: a cert for one host must not authenticate
        // a connection meant for a different host.
        assert!(!cert_matches_hostname(&der, "evil.example.com"));
        assert!(!cert_matches_hostname(&der, "example.com"));
    }

    #[test]
    fn wildcard_san_matches_one_label_only() {
        let der = cert_with_dns(&["*.example.com"]);
        assert!(cert_matches_hostname(&der, "a.example.com"));
        assert!(cert_matches_hostname(&der, "files.example.com"));
        // Wildcard never matches the bare parent or a multi-label child.
        assert!(!cert_matches_hostname(&der, "example.com"));
        assert!(!cert_matches_hostname(&der, "a.b.example.com"));
    }

    #[test]
    fn dns_san_present_disables_cn_fallback() {
        // A cert with a dNSName SAN that does not name the host must be
        // rejected even if its CN happens to match -- SAN wins.
        let mut params =
            CertificateParams::new(vec!["other.example.com".to_string()]).expect("rcgen new");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "target.example.com");
        params.distinguished_name = dn;
        let key = KeyPair::generate().expect("rcgen keypair");
        let der = params
            .self_signed(&key)
            .expect("self_signed")
            .der()
            .to_vec();
        assert!(!cert_matches_hostname(&der, "target.example.com"));
        assert!(cert_matches_hostname(&der, "other.example.com"));
    }

    #[test]
    fn cn_fallback_only_without_dns_san() {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("rcgen new");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "legacy.example.com");
        params.distinguished_name = dn;
        let key = KeyPair::generate().expect("rcgen keypair");
        let der = params
            .self_signed(&key)
            .expect("self_signed")
            .der()
            .to_vec();
        assert!(cert_matches_hostname(&der, "legacy.example.com"));
        assert!(!cert_matches_hostname(&der, "elsewhere.example.com"));
    }

    #[test]
    fn ip_target_matches_ip_san_only() {
        let der = cert_with_sans(vec![SanType::IpAddress("192.0.2.1".parse().unwrap())]);
        assert!(cert_matches_hostname(&der, "192.0.2.1"));
        assert!(!cert_matches_hostname(&der, "192.0.2.2"));
    }

    #[test]
    fn ip_target_does_not_match_dns_san() {
        // RFC 9525: an IP literal target is matched against iPAddress
        // SANs only, never against dNSName entries. Force a dNSName
        // carrying an IP-shaped string (rcgen would otherwise classify
        // a bare IP literal as an iPAddress SAN).
        let der = cert_with_sans(vec![SanType::DnsName("192.0.2.1".try_into().unwrap())]);
        assert!(!cert_matches_hostname(&der, "192.0.2.1"));
    }

    #[test]
    fn garbage_cert_never_matches() {
        assert!(!cert_matches_hostname(b"not a cert", "example.com"));
        assert!(!cert_matches_hostname(&[], "example.com"));
    }
}
