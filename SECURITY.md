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
- Restrict `--root` to its own directory. Don't point it at `/`.
- Scrape `--metrics-bind` on a private interface; the endpoint serves
  Prometheus text and is not authenticated.
- Set `--log-format json` and forward to your central log pipeline.
