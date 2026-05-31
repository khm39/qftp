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
    if let Some((dir, ticket)) = resume_ticket(opts, &spec.host) {
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
                let _ = session_store::forget(&dir, &spec.host);
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
        // Bind to `server_name` (intended identity / SNI, config-overridable), not `spec.host` (dial target).
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

/// Decide whether — and which — stored 0-RTT ticket to offer for `host`.
///
/// Returns `Some((ticket_dir, ticket_bytes))` only when 0-RTT is enabled
/// and a fresh ticket is found; the dir is returned so the caller can
/// `forget` it if quiche later rejects the blob in `set_session`.
///
/// This is the security-critical resumption seam: in TOFU mode
/// `opts.expected_cert_fingerprint` is the pinned known_hosts value and
/// is threaded straight into `session_store::load`, so a ticket is only
/// resumed against the same server identity it was saved for. Dropping
/// that argument here would let a repointed host replay a stolen ticket;
/// keeping the load behind `opts.zero_rtt` lets `--no-zero-rtt` disable
/// resumption entirely.
fn resume_ticket(opts: &EstablishOpts, host: &str) -> Option<(PathBuf, Vec<u8>)> {
    if !opts.zero_rtt {
        return None;
    }
    let dir = opts
        .ticket_dir
        .clone()
        .or_else(session_store::default_dir)?;
    let ticket = session_store::load(&dir, host, opts.expected_cert_fingerprint.as_ref())?;
    Some((dir, ticket))
}

/// Check whether the DER-encoded leaf certificate identifies `host`.
///
/// Follows RFC 6125 / 9525: a literal IP target is matched only against
/// SAN iPAddress entries; a DNS target is matched against SAN dNSName
/// entries (with a single left-most wildcard label), and the Subject CN
/// is consulted only as a legacy fallback when the certificate carries
/// no SAN extension at all. A SAN extension that lists only non-dNSName
/// entries still disables the CN fallback.
fn cert_matches_hostname(der: &[u8], host: &str) -> bool {
    use x509_parser::prelude::*;

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return false;
    };

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match_ip_san(&cert, &ip);
    }

    match match_dns_san(&cert, host) {
        DnsSanVerdict::Matched => true,
        // A SAN extension we cannot parse may carry a dNSName that would
        // forbid the CN fallback; fail closed rather than fall through.
        DnsSanVerdict::FailClosed => false,
        DnsSanVerdict::DnsSanPresentNoMatch => false,
        // Legacy CN fallback only when no SAN extension constrains the cert.
        DnsSanVerdict::NoDnsSan => match_cn_fallback(&cert, host),
    }
}

/// Match a literal IP target against the cert's SAN iPAddress entries
/// only (RFC 9525): a DNS target is never considered here, and any
/// missing / unparseable SAN extension yields no match.
fn match_ip_san(cert: &x509_parser::certificate::X509Certificate, ip: &std::net::IpAddr) -> bool {
    use x509_parser::prelude::*;
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for gn in &san.value.general_names {
            if let GeneralName::IPAddress(bytes) = gn {
                if ip_san_matches(bytes, ip) {
                    return true;
                }
            }
        }
    }
    false
}

/// Outcome of matching a DNS host against the cert's dNSName SANs.
enum DnsSanVerdict {
    /// A dNSName SAN matched the host.
    Matched,
    /// A SAN extension was present (with or without dNSName entries) but
    /// none matched the host. The CN fallback must NOT run -- once a SAN
    /// extension exists it is authoritative for identity (RFC 6125 /
    /// 9525), so a cert whose SAN lists only unrelated entries (e.g.
    /// iPAddress / rfc822Name and no dNSName) must not be authenticated
    /// for a DNS host via a matching legacy CN.
    DnsSanPresentNoMatch,
    /// No SAN extension present at all. The CN fallback may run.
    NoDnsSan,
    /// The SAN extension could not be parsed; fail closed (an
    /// unparseable SAN may carry a dNSName that would forbid the CN
    /// fallback).
    FailClosed,
}

/// Match a DNS host against the cert's dNSName SANs (single left-most
/// wildcard label supported), reporting enough state for the caller to
/// gate the legacy CN fallback and fail closed on a parse error.
fn match_dns_san(cert: &x509_parser::certificate::X509Certificate, host: &str) -> DnsSanVerdict {
    use x509_parser::prelude::*;
    let mut san_present = false;
    match cert.subject_alternative_name() {
        Ok(Some(san)) => {
            // The extension itself is present: this alone disables the CN
            // fallback, regardless of whether it carries any dNSName.
            san_present = true;
            for gn in &san.value.general_names {
                if let GeneralName::DNSName(pat) = gn {
                    if dns_name_matches(pat, host) {
                        return DnsSanVerdict::Matched;
                    }
                }
            }
        }
        Ok(None) => {}
        Err(_) => return DnsSanVerdict::FailClosed,
    }
    if san_present {
        DnsSanVerdict::DnsSanPresentNoMatch
    } else {
        DnsSanVerdict::NoDnsSan
    }
}

/// Legacy Subject CN fallback. Only consulted when the cert carries no
/// SAN extension at all (see `match_dns_san`).
fn match_cn_fallback(cert: &x509_parser::certificate::X509Certificate, host: &str) -> bool {
    for attr in cert.subject().iter_common_name() {
        if let Ok(cn) = attr.as_str() {
            if dns_name_matches(cn, host) {
                return true;
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
    fn ip_only_san_disables_cn_fallback_for_dns_host() {
        // CWE-295 / RFC 6125 §6.4.4: a SAN extension that is present but
        // carries no dNSName (here only an iPAddress) is still
        // authoritative for identity. A DNS-host connection must NOT be
        // authenticated by a matching legacy CN when any SAN extension
        // exists. Before the fix the empty-dNSName case fell through to
        // the CN.
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("rcgen new");
        params.subject_alt_names = vec![SanType::IpAddress("192.0.2.1".parse().unwrap())];
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "target.example.com");
        params.distinguished_name = dn;
        let key = KeyPair::generate().expect("rcgen keypair");
        let der = params
            .self_signed(&key)
            .expect("self_signed")
            .der()
            .to_vec();
        // SAN present (iPAddress only) -> CN must not rescue the DNS host.
        assert!(!cert_matches_hostname(&der, "target.example.com"));
        // The iPAddress SAN itself still authenticates the IP target.
        assert!(cert_matches_hostname(&der, "192.0.2.1"));
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
    fn unparseable_san_does_not_fall_back_to_cn() {
        use x509_parser::prelude::*;

        // Emit a normal dNSName SAN plus a duplicate SAN extension (same
        // OID 2.5.29.17) via a custom extension. x509-parser then fails
        // to resolve `subject_alternative_name()` (DuplicateExtensions),
        // and the host must NOT be authenticated by the matching CN.
        let mut params =
            CertificateParams::new(vec!["other.example.com".to_string()]).expect("rcgen new");
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "legacy.example.com");
        params.distinguished_name = dn;
        // A second, syntactically valid SAN extension: SEQUENCE { dNSName }.
        let dup_san = rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 17],
            vec![0x30, 0x14, 0x82, 0x12]
                .into_iter()
                .chain(b"legacy.example.com".iter().copied())
                .collect(),
        );
        params.custom_extensions.push(dup_san);
        let key = KeyPair::generate().expect("rcgen keypair");
        let der = params
            .self_signed(&key)
            .expect("self_signed")
            .der()
            .to_vec();

        let (_, cert) = X509Certificate::from_der(&der).expect("cert must still parse");
        assert!(
            cert.subject_alternative_name().is_err(),
            "test precondition: SAN getter must return Err"
        );
        // Fail closed: CN matches but the unparseable SAN must block it.
        assert!(!cert_matches_hostname(&der, "legacy.example.com"));
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

    // ---- 0-RTT resume wiring (try_connect's resume_ticket seam) ----

    fn opts_with(zero_rtt: bool, dir: &std::path::Path, fp: Option<[u8; 32]>) -> EstablishOpts {
        EstablishOpts {
            verify_peer: true,
            zero_rtt,
            ticket_dir: Some(dir.to_path_buf()),
            expected_cert_fingerprint: fp,
        }
    }

    #[test]
    fn resume_ticket_skipped_when_zero_rtt_disabled() {
        // --no-zero-rtt: even with a fresh ticket on disk, none is
        // offered, so set_session is never reached.
        let tmp = tempfile::TempDir::new().unwrap();
        session_store::save(tmp.path(), "host:4433", Some(b"opaque"), &[0u8; 32]).unwrap();
        assert!(resume_ticket(&opts_with(false, tmp.path(), None), "host:4433").is_none());
    }

    #[test]
    fn resume_ticket_returns_dir_and_bytes_when_present() {
        let tmp = tempfile::TempDir::new().unwrap();
        session_store::save(tmp.path(), "host:4433", Some(b"opaque"), &[0u8; 32]).unwrap();
        let got = resume_ticket(&opts_with(true, tmp.path(), None), "host:4433");
        let (dir, ticket) = got.expect("ticket should be offered");
        // The returned dir is the one forget() will target on a
        // set_session error.
        assert_eq!(dir, tmp.path());
        assert_eq!(ticket, b"opaque");
    }

    #[test]
    fn resume_ticket_threads_matching_fingerprint() {
        // A TOFU caller's pinned fingerprint that matches the stored
        // binding still resumes.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut fp = [0u8; 32];
        fp[0] = 0xab;
        session_store::save(tmp.path(), "host:4433", Some(b"opaque"), &fp).unwrap();
        let got = resume_ticket(&opts_with(true, tmp.path(), Some(fp)), "host:4433");
        assert_eq!(got.map(|(_, t)| t), Some(b"opaque".to_vec()));
    }

    #[test]
    fn resume_ticket_drops_on_fingerprint_mismatch() {
        // The security-critical seam: a pinned fingerprint that does NOT
        // match the stored binding (DNS repoint / cert rotation) yields
        // no ticket, so a stolen ticket is never replayed against a
        // repointed host. A regression that dropped
        // expected_cert_fingerprint would resume here and fail this.
        let tmp = tempfile::TempDir::new().unwrap();
        let mut saved_fp = [0u8; 32];
        saved_fp[0] = 0xab;
        session_store::save(tmp.path(), "host:4433", Some(b"opaque"), &saved_fp).unwrap();
        let mut wrong = [0u8; 32];
        wrong[0] = 0xcd;
        assert!(
            resume_ticket(&opts_with(true, tmp.path(), Some(wrong)), "host:4433").is_none(),
            "mismatched pin must not offer a ticket"
        );
        // And the bad ticket was purged so it isn't re-offered.
        assert!(!session_store::ticket_path(tmp.path(), "host:4433").exists());
    }

    #[test]
    fn resume_ticket_none_when_no_ticket_on_disk() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(resume_ticket(&opts_with(true, tmp.path(), None), "host:4433").is_none());
    }

    #[test]
    fn forget_clears_ticket_on_set_session_error_path() {
        // Mirrors the do-on-set_session-error branch: when quiche rejects
        // the ticket, the stored blob is forgotten so the next connect
        // doesn't replay it. We can't drive quiche's set_session to fail
        // in a unit test, so assert the forget() the error arm calls
        // actually removes the ticket the resume_ticket seam returned.
        let tmp = tempfile::TempDir::new().unwrap();
        session_store::save(tmp.path(), "host:4433", Some(b"opaque"), &[0u8; 32]).unwrap();
        let (dir, _ticket) =
            resume_ticket(&opts_with(true, tmp.path(), None), "host:4433").unwrap();
        session_store::forget(&dir, "host:4433").unwrap();
        assert!(!session_store::ticket_path(tmp.path(), "host:4433").exists());
        assert!(resume_ticket(&opts_with(true, tmp.path(), None), "host:4433").is_none());
    }
}
