# Changelog

All notable changes to this project will be documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
qftp's public API surface is the wire protocol (specified in
[spec/](spec/)); the ALPN major version (`qftp/<n>`) is what we will
bump to signal an intentional wire break. Wire-protocol changes are
tracked separately in [PROTOCOL-CHANGELOG.md](PROTOCOL-CHANGELOG.md);
this file tracks the reference implementation.

## [Unreleased]

### Added

- **zstd transfer compression (opt-out).** File bodies are compressed in
  transit with zstd by default: downloads request it (`accept_encoding`),
  fresh and resumed uploads send a self-contained zstd frame, and the
  BLAKE3 trailer / `offset` / on-disk `.partial` stay in the **plaintext**
  domain so integrity and resume are unchanged. Already-compressed files
  (media/archives, by extension) and tiny transfers fall back to identity
  automatically; `--no-compress` disables it. Decompression is bounded by
  the declared plaintext size / `MAX_FILE_SIZE` and a frozen 8 MiB window
  (`window_log = 23`) as a decompression-bomb defense. The web bridge
  serves and accepts identity only. (#300)
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
- **Documentation.** Top-level README, the protocol specification in
  [spec/](spec/), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md),
  and MIT licensing.
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

### Fixed

- **Resumed downloads no longer fail integrity verification.** On a
  resumed `get` the client hashed the *whole* local file while the
  server's trailer covers only the streamed `[offset..]` suffix (as
  [spec/qftp-protocol.md](spec/qftp-protocol.md) specifies), so the
  BLAKE3 check always mismatched
  and the partial file was deleted -- resume was completely broken. The
  client now hashes only the bytes it receives. (#178)
- **The client can connect to hostnames again.** Connection setup fed
  `host:port` straight to `str::parse::<SocketAddr>()`, which only
  accepts numeric IP literals, so every DNS name was rejected. The host
  is now resolved via `ToSocketAddrs`, and the local socket is bound in
  the resolved address family. (#179)
- **Resumed uploads now commit when the whole body arrives at once.**
  After the server finished re-hashing a resumed upload's prefix it
  returned early; if the entire post-offset body had arrived in the
  initial request burst the stream had no more readable data, so the
  upload never reached the commit phase and stalled until the
  connection timed out. The re-hash completion path now falls through
  into the body phase. (#180)
- **A stale server-side partial now triggers a clean retry.** A resumed
  `put` whose partial had vanished or changed length was refused with
  `InvalidRange`, but the client only treated `ChecksumMismatch` as a
  stale partial, so the upload hard-failed instead of restarting from
  scratch. Both codes now trigger the retry-from-zero path. (#181)
- **Recursive `get` and `sync` bound their server-driven walk.** A
  malicious server returning the same sub-directory name on every `Ls`
  drove the client to recurse without limit; both walks now stop with
  a clear error after 10,000 directories. (#182)
- **The Put commit re-checks for symlinked parents.** The final
  `rename` of an uploaded temp into place ran with no ancestor symlink
  re-check, so a parent directory swapped to a symlink during a long
  upload could redirect the file outside the user's home. (#183)
- **Server-supplied strings are sanitized before terminal display.**
  Directory names, paths, and error messages from the server are
  stripped of control characters, closing an ANSI/OSC terminal-escape
  injection vector. (#184)
- **Browser auth tokens are percent-decoded.** The SPA form-encodes the
  token into the URL, but the bridge compared the raw encoded slice, so
  any token with `+`, `/` or `=` failed every web login. (#185)
- **`sync` fails loudly on an incomplete remote walk.** A per-directory
  `Ls` failure was swallowed and `sync` reported success on a silently
  partial mirror; such a failure now aborts with a non-zero exit. (#186)
- **`--bwlimit` no longer stalls the QUIC connection.** The pacer's
  blocking sleep left the connection unserviced long enough for the
  idle timer to fire; the throttle wait is now spent in short slices
  that keep servicing the connection. (#187)
- **Resumed uploads require an integrity checksum.** A resumed `put`
  with neither a BLAKE3 trailer nor a header checksum committed its
  on-disk prefix unverified; such a resume is now refused up front.
  (#188)
- **Browser downloads always verify the integrity trailer.** The SPA
  skipped verification when the server cleared `checksum_follows`; it
  now requires the trailer it always asks for. (#189)
- **CI runs the in-browser BLAKE3 test.** `web/blake3.test.js`, which
  pins the hand-written `web/blake3.js` against the Rust crate, is now
  executed by CI so a regression cannot ship green. (#190)
- **`Put` / `Get` reject `*.qftp.partial` paths.** A client could
  `Put` to a server-internal upload temp name, producing a file hidden
  from `Ls`, un-deletable, and swept after 24h; both ops now reject
  such paths. (#191)
- **The `connections_open` metrics gauge no longer leaks.** A
  duplicate accept (a retransmitted Initial deriving the same SCID)
  incremented the gauge without a matching decrement; the counters are
  now bumped only for a connection that is actually retained. (#192)
- **`--no-clobber` `get` resumes an interrupted download.** It refused
  any pre-existing local file; it now probes the remote size and only
  refuses a file that is already complete, letting a shorter partial
  resume. (#193)
- **`mget /<glob>` lists the server root.** A leading-slash pattern
  collapsed the directory part to `""`, which lists the remote cwd; it
  now lists `/`. (#194)
- **A failed resume re-hash no longer leaks quota.** When the server's
  re-hash of a resumed upload's prefix failed it left the partial on
  disk with its bytes still charged; the failure path now deletes the
  temp and refunds the prefix, matching the checksum-mismatch path.
  (#195)
- **`resolve_parent` no longer follows a symlinked parent.** It checked
  the parent with `is_dir()`, which traverses a final symlink; it now
  uses `symlink_metadata`. (#196)
- **REPL `put` uploads filenames containing glob metacharacters.** A
  literal file such as `report[2024].txt` was treated as a glob and
  matched nothing; `expand_glob` now falls back to the literal path
  when it exists. (#197)
- **`stream_send_all` always delivers the FIN.** It derived "last
  chunk" from a buffer constant, so a write larger than `STREAM_BUF_SIZE`
  could leave the stream half-open; the FIN is now always sent as a
  dedicated empty frame. (#198)
- **The WebTransport bridge cannot be spun by a zero-length read.**
  `read_request` looped without progress on `Ok(Some(0))`; it now
  fails fast. (#199)
- **`is_upload_temp` matches the exact temp suffix.** It used a
  substring test, so a legitimate file like `archive.qftp.partial.tar`
  was hidden and un-deletable; it now matches `ends_with`. (#200)
- **A stale-partial retry is not counted as a transfer failure.** A
  resumed `put` that restarts from scratch no longer records a
  spurious failure in `stats`. (#201)
- **`mget`'s skip-existing check does not follow symlinks.** It used
  `Path::exists()`; it now uses `symlink_metadata` so the decision is
  about the local name itself. (#202)
- **`mget` surfaces server entries rejected for unsafe names.** They
  were dropped with only a `tracing` line, so a server returning only
  unsafe names looked like an empty match; the count is now reported
  to the user. (#203)
- **The web bridge names upload temps like the native server.** It
  used a random suffix, so its partials were unresumable and
  non-interoperable; it now uses the deterministic
  `<name>.qftp.partial` (truncating a stale partial, keeping the
  `O_NOFOLLOW` open). (#204)
- **A Put to a path with no file name is rejected.** Such a path made
  `temp_path_for` collapse to a bare `.qftp.partial`; `start_put` now
  refuses it. (#205)

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
- **A single client can no longer crash the whole server.** A
  per-stream / per-connection QUIC send error (e.g. a peer that resets
  a stream right after sending a request, or queues another action
  behind a `Quit`) propagated out of `process_readable_streams`
  through `run()`, terminating the process and dropping every other
  client's connection. The per-connection work in the event loop now
  catches such errors and closes only the offending connection. (#177)

## [0.1.0] - placeholder

Pre-history. Repository was a 2-binary proof-of-concept with a single
connection, no auth, and no tests. See the Phase 0 - 2 PR series for
the staged work that brought it to this point.
