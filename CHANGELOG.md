# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
qftp's public API surface is the wire protocol (see
[docs/protocol.md](docs/protocol.md)); the ALPN major version (`qftp/<n>`)
is what we will bump to signal an intentional wire break.

## [Unreleased]

### Added

- **`mget` — remote wildcard download.** `mget <glob> [local-dir]`
  lists a remote directory and downloads every file whose name matches
  the glob, the download counterpart to `put`'s existing client-side
  glob expansion. `mput` is added as an alias of `put` so FTP-familiar
  muscle memory works. (#175)
- **End-to-end integrity for the browser client.** The web SPA now
  computes BLAKE3 in-browser (a small pure-JS implementation,
  `web/blake3.js`): downloads verify the server's trailer and reject a
  corrupt file, and uploads append a BLAKE3 trailer the bridge verifies
  before committing. Previously browser transfers had no end-to-end
  integrity check while native transfers did.
- **Working upload resume.** An interrupted `put` now leaves a
  deterministically named `<name>.qftp.partial` on the server; the
  next `put` of the same file probes that temp with `Stat` and resumes
  from where it stopped, mirroring `get`'s download resume. Previously
  the random temp-file suffix made the server-side resume path
  unreachable, so `offset > 0` was rejected outright. The bytes in an
  aborted upload's partial are charged to the user's quota until the
  partial is resumed or replaced, so an abort loop can't bypass the
  limit.

- **WebTransport bridge (`qftp-web-bridge`).** A new standalone binary
  that serves qftp to browsers over WebTransport (HTTP/3). It runs
  alongside `qftp-server` (same `--root` and `users.toml`), carries
  bearer-token auth (`--users-tokens`), and streams Get / Put with the
  same BLAKE3-trailer wire format as the native protocol. It also
  ships a single-page web app -- browse, drag-and-drop upload,
  download, delete, rename, with progress bars -- served over a
  built-in HTTP listener (`--http-bind`). Self-signed certificates
  work via WebTransport `serverCertificateHashes` pinning: the bridge
  publishes its leaf-cert hash at `/config.json` and the SPA pins it.
  The transport-independent
  request handling, ACLs, and user directory were extracted into a new
  `qftp-protocol` library crate shared by the server and the bridge.
  The bridge uses `wtransport` (quinn); `qftp-server` / `qftp-client`
  stay on `quiche` (see ADR 0001 and `docs/web-client.md`).
- **Protocol versioning.** ALPN is now `qftp/1` (was `qftp`). New
  binaries refuse to negotiate with peers that don't offer the new
  ALPN; the QUIC handshake fails cleanly with no fallback.
  Request / Response enums and DirEntry / FileStat carry
  `#[non_exhaustive]` + `#[serde(default)]` so future minor additions
  don't break older binaries.
- **Structured error codes.** `Response::Err` now carries
  `ErrorResponse { code: ErrorCode, message: String }` with codes
  including `NotFound`, `PermissionDenied`, `ChecksumMismatch`,
  `RateLimited`, `InvalidRange`, etc. Clients display them as
  `Error [<Code>]: <message>`; scripts can match on the code.
- **Resumable downloads.** `Request::Get { path, offset, length }`
  lets clients resume an interrupted Get from the local file's
  current length. The server seeks to `offset` and clamps the
  response at `length` (or EOF, when `None`).
- **Resumable uploads.** `Request::Put { ..., offset, checksum }` lets
  the client continue appending to an existing `.qftp.partial` temp.
  The server validates the existing length matches `offset` before
  accepting more bytes.
- **BLAKE3 integrity.** Every Get streams a 32-byte BLAKE3 trailer
  after the body; the client verifies and deletes the local file on
  mismatch. Every Put declares a BLAKE3 checksum in the request and
  the server refuses the rename if the received bytes don't match.
- **Recursive `get -r` / `put -r`.** Walk the directory tree on both
  sides, mirroring it on the other.
- **Progress bars** for Get and Put (indicatif). Auto-disabled on
  non-TTY stderr.
- **Glob expansion on local `put` arguments.** `put *.log` expands on
  the client side.
- **Client REPL enhancements.** History persists to `~/.qftp_history`
  (or `--history <path>`). `--execute "<cmd>"` runs one command and
  exits. Piping commands on stdin runs them in batch.
- **Documentation.** Top-level README, [docs/protocol.md](docs/protocol.md),
  [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md), and dual
  MIT/Apache-2.0 licensing.
- **Packaging.** Multi-stage Dockerfile, systemd unit example,
  cargo-dist release workflow, and `repository`/`license`/`rust-version`
  metadata on every crate.

### Changed

- Connection slot keying is now deterministic
  (`HMAC-SHA256(seed, dcid)` truncated to `MAX_CONN_ID_LEN`), so
  retransmitted Initials during the handshake collapse onto the same
  slot rather than opening parallel connections. (Pre-existing in
  the Phase 2 PR; documented for completeness.)
- The metrics endpoint exposes `qftp_connections_open` as a Prometheus
  *gauge*, not a counter. (Pre-existing fix; calling out so
  dashboards know what to expect.)

### Security

- Stateless retry (`--require-retry`) prevents source-address spoofing
  amplification.
- Per-request token-bucket rate limiting kicks in after handshake, so
  an accepted peer can't drown the server with command floods.
- **mTLS is now enforced, not optional.** quiche's `verify_peer(true)`
  sets `SSL_VERIFY_PEER` only, so a client presenting *no* certificate
  still completed the TLS handshake and was served as the anonymous
  user -- which, with `--users`, can read the entire `--root`. A
  server started with `--client-ca` now closes any established
  connection that presents no peer certificate.
- **Client-certificate identity confusion closed.** A certificate is
  matched against `users.toml` over its SAN dNSName / rfc822Name / URI
  entries and the Subject CN. Matching now refuses any certificate
  that resolves to more than one distinct configured user, instead of
  silently picking the first -- a cert carrying an extra SAN entry can
  no longer select a higher-privileged account.
- **Symlink TOCTOU re-check extended to `Ls` and `Cd`.** Both followed
  a path component swapped to a symlink after validation (`Ls` via
  `fs::read_dir`, `Cd` by adopting a poisoned `cwd`); they now run the
  same ancestor + leaf re-check the mutating operations already used.
- **Quota enforcement no longer races.** `Put` reserved its byte count
  *after* checking the quota, so two concurrent uploads could both
  pass and overshoot the limit. The reservation is now made before the
  check, in both the native server and the WebTransport bridge.
- **WebTransport bridge bounds concurrent sessions.** The bridge
  accepted sessions without limit; each can hold many buffering
  streams. A semaphore now caps concurrent sessions.

## [0.1.0] - placeholder

Pre-history. Repository was a 2-binary proof-of-concept with a single
connection, no auth, and no tests. See the Phase 0 - 2 PR series for
the staged work that brought it to this point.
