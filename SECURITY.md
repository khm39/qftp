# Security policy

## Supported versions

Until qftp ships a 1.0 release, only the latest tagged release on the
default branch receives security fixes. After 1.0, the policy in this
file will be updated to reflect a real support window.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

Instead, use one of the following channels:

1. **GitHub private vulnerability reporting.** Navigate to the
   repository's Security tab and click "Report a vulnerability". This
   creates a private advisory that only the maintainers can see.
2. **Email.** Mail the maintainer (see the `authors =` line of the
   workspace `Cargo.toml`) and put `[qftp security]` in the subject.
   Encrypt with our PGP key if it's posted on the project page; if it
   isn't yet, an unencrypted heads-up is still better than a public
   issue.

We will acknowledge receipt within five working days and aim to ship a
fix or mitigation within 30 days for any issue rated medium or higher.

## Threat model

qftp is designed for a workload where:

- The QUIC + TLS 1.3 transport is trusted; mTLS is the authentication
  primitive when configured. We rely on the TLS implementation in
  `quiche` (BoringSSL).
- The server may be exposed to the public internet. It must withstand
  source-address spoofing (mitigated by `--require-retry`), connection
  flooding (mitigated by `--max-connections{,-per-ip}` and the
  per-IP rate limiter), and protocol fuzzing (covered by the
  `request_deser` / `response_deser` fuzz targets).
- Path traversal is structurally impossible: the server walks the
  user-supplied path component by component, refuses `..` past the
  user's home, and refuses symbolic links anywhere in the path. This
  is a conservative substitute for `openat2(RESOLVE_BENEATH)`; legitimate
  symlinks under the user's home are also refused.
- The server is not a userland sandbox. It runs as whichever Unix user
  the operator starts it as, and a misconfigured `--users` file can
  grant a peer access to everything that user can read. Run it as an
  unprivileged user dedicated to qftp.

### Trust on first use (TOFU)

`qftp-client --trust-on-first-use` adopts the SSH `known_hosts` trust
model when neither a `--ca` bundle nor an enterprise PKI is available
(self-signed dev servers, home LAN). On first connect, the client
pins the server's leaf-cert SHA-256 fingerprint to
`~/.qftp/known_hosts`; subsequent connects refuse to continue if the
fingerprint changes. The trust assumption is identical to SSH's: the
**first** connection must not be intercepted. The fingerprint check
runs after the TLS handshake completes, so a determined MitM could
complete the handshake; the connection is then closed with the SSH-
style banner. Use `--ca` whenever a real CA chain is available.

### WebTransport bridge (`qftp-web-bridge`)

The optional `qftp-web-bridge` exposes qftp to browsers over
WebTransport. It is a **separate trust boundary** from the native
server:

- Browsers cannot present client certificates to a WebTransport
  endpoint, so the bridge does **not** use mTLS. It authenticates
  with bearer tokens (`--users-tokens`): an opaque token in the
  connection URL's query string is mapped to a `users.toml` user.
  Tokens are the only secret gating web access -- generate them with
  high entropy and treat the tokens file like a password file.
- **Bearer tokens travel in the URL query string, where intermediaries
  log them.** The token is inside the TLS-encrypted HTTP/3 handshake
  on the wire, but any component that terminates or inspects TLS and
  then logs the request URL -- a reverse proxy, load balancer, WAF, or
  CDN with access logging -- captures the secret in cleartext logs.
  Prefer mTLS (the native server) for anything that can present a
  client certificate; use the WebTransport bridge only for true
  browser clients. Where the bridge is required, disable URL/query
  logging on every TLS-terminating intermediary in front of it, treat
  any log store that may have seen a token as compromised, and rotate
  tokens routinely. Per-user, revocable tokens limit the blast radius
  of a leaked log.
- WebTransport requires a browser-trusted TLS certificate; the bridge
  has no `--insecure` equivalent. The token travels inside the
  TLS-encrypted HTTP/3 handshake.
- Without `--users-tokens`, every browser session is the anonymous
  read-only user. Never run a writable deployment without it.
- The bundled SPA is served over plain HTTP on `--http-bind`; bind it
  to loopback and front it with a TLS-terminating reverse proxy.
- Safari has no WebTransport support and cannot use the bridge.

### Integrity is not authenticity

The BLAKE3 checksums on `Get`/`Put` (header field or streamed trailer)
detect **accidental corruption** of the transferred bytes -- truncation,
bit-rot, a buggy resume. They are an unkeyed hash: they are **not** a
message-authentication code and do **not** prove who produced the bytes.
Authenticity and confidentiality on the wire come entirely from the
QUIC + TLS 1.3 channel (and, when configured, mTLS peer
authentication). An attacker who could rewrite both the body and its
trailer would pass the BLAKE3 check; only TLS prevents that on the
wire. Do not treat a matching BLAKE3 digest as a signature.
Message-layer authenticity (a per-message MAC or signed manifest) is a
[qftp/2 direction](PROTOCOL-CHANGELOG.md), not a `qftp/1` guarantee.

## Out of scope

- Side channels in the BLAKE3 / HMAC implementations (we rely on the
  crates' constant-time properties).
- Resource exhaustion attacks that succeed at limits *configured by
  the operator* (e.g., setting `--max-connections-per-ip 10000` and
  then complaining about RAM use). Tune for your environment.
- Anything that requires write access to the server's filesystem
  *outside* qftp's `--root` (we don't escape that, and we can't
  defend against it).

## Hardening checklist for production

- Run with `--require-retry`. The stateless-retry token is HMAC-signed
  over the peer's address and connection ID; the HMAC tag **SHOULD** be
  at least 20 bytes (160 bits) of the SHA-256 output. A shorter
  truncation weakens the forgery resistance of the only thing gating
  connection-state allocation before address validation; this is the
  recommended minimum for new deployments and configurations.
- Set `--max-connections` and `--max-connections-per-ip` for your
  capacity.
- Configure mTLS via `--client-ca` and a per-user `--users` TOML;
  never rely on the anonymous-user fallback in production.
- Run the server as a dedicated unprivileged Unix user. The provided
  `examples/systemd/qftp-server.service` does this with `DynamicUser=`.
- Restrict `--root` to its own directory. Don't point it at `/`.
- Scrape `--metrics-bind` on a private interface; the endpoint serves
  Prometheus text and is not authenticated. Recommended bind is
  `127.0.0.1:<port>` (or `[::1]:<port>`); for cluster scrapers, bind to
  a management VLAN or a UNIX-domain-socket fronted proxy. The server
  logs a loud warning if it sees a non-loopback bind (#143).
- Set `--log-format json` and forward to your central log pipeline.
