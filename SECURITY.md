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

### OS user isolation

By default the server runs every transfer as the one OS user that
launched it (see the threat-model bullet above). The optional
`--user-isolation` mode (Linux only; ADR
[0002](docs/adr/0002-process-isolation.md)) instead serves each
connection from a dedicated process running as the **authenticated
user's real UID**, so the kernel's discretionary access control backs
up the userspace ACL and uploaded files are owned by the real user.

Its trust properties:

- **The dispatcher is root-equivalent.** To `setuid` to any configured
  user it needs root, or `CAP_SETUID` + `CAP_SETGID`. Treat the
  dispatcher as a high-value target and apply the systemd hardening in
  `examples/systemd/qftp-server-isolation.service`. `DynamicUser=` is
  incompatible with this mode and must not be set.
- **The dispatcher never sees plaintext file data.** It runs only the
  QUIC + mTLS handshake; once a connection is handed to a worker, the
  worker holds the TLS keys and the dispatcher is out of the data
  path.
- **Workers are unprivileged and confined.** A worker `setgroups` +
  `setgid` + `setuid`s to the target user and verifies the drop is
  irreversible (it must not be able to `seteuid(0)`) *before* serving
  any byte. A bug in one worker is contained to one connection's UID.
- **Validate before enabling.** `qftp-server --check-isolation --users
  <file>` resolves every configured user to an OS account and checks
  the process can switch credentials — run it in CI / at deploy time.

This mode does not change the wire protocol and is independent of
mTLS configuration; without `--user-isolation` the server behaves
exactly as before.

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

- Run with `--require-retry`.
- Set `--max-connections` and `--max-connections-per-ip` for your
  capacity.
- Configure mTLS via `--client-ca` and a per-user `--users` TOML;
  never rely on the anonymous-user fallback in production.
- Run the server as a dedicated unprivileged Unix user. The provided
  `examples/systemd/qftp-server.service` does this with `DynamicUser=`.
- For a multi-user host where transfers should run as real OS users,
  consider `--user-isolation` (Linux; see "OS user isolation" above and
  `examples/systemd/qftp-server-isolation.service`). Validate the
  `users.toml` -> OS account mapping with `--check-isolation` first.
- Restrict `--root` to its own directory. Don't point it at `/`.
- Scrape `--metrics-bind` on a private interface; the endpoint serves
  Prometheus text and is not authenticated. Recommended bind is
  `127.0.0.1:<port>` (or `[::1]:<port>`); for cluster scrapers, bind to
  a management VLAN or a UNIX-domain-socket fronted proxy. The server
  logs a loud warning if it sees a non-loopback bind (#143).
- Set `--log-format json` and forward to your central log pipeline.
