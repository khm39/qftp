# qftp wire protocol

This document is the source of truth for the `qftp/1` wire protocol.

## Transport

- **UDP + QUIC.** Both endpoints speak QUIC version 1 (RFC 9000).
- **ALPN: `qftp/1`.** The major version is part of ALPN so neither end can talk to a peer it can't understand.
- **Mandatory TLS 1.3.** mTLS is optional but, when configured, the server enforces it via `--client-ca`.

## Streams

- Every command runs on its own client-initiated bidirectional QUIC stream (stream IDs `0, 4, 8, …`). Sub-issue [#36](https://github.com/khm39/qftp/issues/36) per-connection state machine multiplexes them.
- The first frame on a stream is always a bincode-serialized `Request`. The server replies with a `Response` (or several, in the case of `Get`).
- `Get` and `Put` carry file body bytes on the same stream as the request.

## Frame format

Every protocol message is sent as a 4-byte big-endian length prefix followed by a bincode-serialized payload:

```
+--------+--------+--------+--------+--------+...+--------+
|             u32 BE length            |     payload      |
+--------+--------+--------+--------+--------+...+--------+
```

Frames larger than 16 MiB are refused by both sides (`qftp_common::transport::MAX_MESSAGE_SIZE`).

## Request / Response semantics

The full enums live in [`crates/qftp-common/src/protocol.rs`](../crates/qftp-common/src/protocol.rs); below is the per-operation behaviour.

### Ls / Cd / Pwd / Stat / Mkdir / Rmdir / Rm / Rename / Chmod / Quit

These are all single Request → single Response operations. The server's `Response` carries a structured `ErrorResponse { code: ErrorCode, message: String }` on failure; the `ErrorCode` is the machine-readable handle for scripts.

`Quit` is replied to with `Response::Ok`, after which the server initiates a graceful CONNECTION_CLOSE.

### Get

```
client -> server : Request::Get { path, offset, length }
server -> client : Response::FileReady { size, total_size, checksum_follows }
server -> client : <size bytes of file body>
server -> client : <32 bytes BLAKE3 trailer, if checksum_follows>
                   <FIN on the last byte>
```

- `offset` lets the client resume an interrupted download. The server seeks to it before reading.
- `length` clips the response to at most that many body bytes. `None` means "to EOF".
- `total_size` is the file's full on-disk size, regardless of how much we're sending this round.
- When `checksum_follows` is true, the body is immediately followed by a 32-byte BLAKE3 trailer covering exactly the streamed body (post-offset, post-length). The client compares it to its own running hash and deletes the local file on mismatch.

If anything goes wrong (path traversal, ACL denial, file too large, range past EOF, …) the server sends a single `Response::Err` with the right `ErrorCode` and the stream ends.

### Put

```
client -> server : Request::Put { path, size, mode, offset, checksum, no_clobber, checksum_trailer }
client -> server : <size bytes of body, FIN on the last byte>
                   <32 bytes BLAKE3 trailer, if checksum_trailer>
server -> client : Response::Ok | Response::Err(...)
```

- `size` is the number of body bytes the client is about to send (post-offset).
- `offset` enables append-style resume. The interrupted upload's partial lives next to the eventual destination as `<final-filename>.qftp.partial` (so the final `rename` stays atomic) and is kept on disk across a disconnect. The name is deterministic — derived only from the destination — so a later session can find it: a client `Stat`s that path to learn how many bytes already landed and sends that count as `offset` (the native client does this automatically). When `offset > 0` the server opens the existing partial, requires it to be exactly `offset` bytes long (`ErrorCode::InvalidRange` otherwise), re-hashes that prefix into the running BLAKE3, and appends. A fresh Put (`offset == 0`) truncates and reuses any stale partial at that path.
- `no_clobber`: when true, the server refuses the upload with `ErrorCode::AlreadyExists` if `path` already exists. Defaults to `false` (silent overwrite) for older clients.
- Checksum verification has two paths. `checksum` is the legacy header field: the BLAKE3 of the full file, populated by a pre-send pass. `checksum_trailer` lets the client hash as it streams and append a 32-byte BLAKE3 trailer on the same stream right after the `size` body bytes. When the trailer is present and full it takes precedence over the header `checksum` (`resolve_put_checksum` in `crates/qftp-protocol/src/stream.rs`, shared by both transports since #269); the native client always uses the trailer path (`checksum_trailer: true`, `checksum: None`). The chosen checksum (BLAKE3 of the full file, not just the bytes sent this round) is verified after the last byte. On mismatch the temp is removed — a corrupt partial would only fail the same check on every resume — and the response carries `ErrorCode::ChecksumMismatch`. With neither field set, the upload is accepted unverified (pre-existing behavior).

Upon success, the server `rename`s the temp into place atomically and applies `mode` (Unix only).

## Error codes

`ErrorCode` is `#[non_exhaustive]`; clients should treat unknown values as `Internal`. Current variants:

```
NotFound          PermissionDenied  AlreadyExists
NotADirectory     IsADirectory      FileTooLarge
UploadOverflow    UploadTruncated   ChecksumMismatch
RateLimited       Malformed         Internal
Unauthorized      InvalidRange      Unsupported
QuotaExceeded
```

## Versioning policy

- **Major version** is part of ALPN (`qftp/<major>`). Bumping it is a hard break; old peers will fail the QUIC handshake.
- **Minor changes** are made non-breaking by the use of `#[non_exhaustive]` enums and `#[serde(default)]` fields. New variants and fields are silently ignored by older binaries.
- The wire format is bincode; field reordering is *not* a minor change.

## 0-RTT session resumption

The server enables QUIC 0-RTT (`Config::enable_early_data`). A client
that has a fresh session ticket from a previous connect can send
application data with its first flight, skipping the 1-RTT TLS
handshake. The client stores tickets at
`~/.qftp/session-tickets/<host>:<port>.ticket` (mode 0600, 24h TTL)
and silently falls back to a 1-RTT handshake on rejection.

### Replay protection

A 0-RTT flight is replayable: an attacker who captures the Initial
packets can resend them to the same server. We therefore split the
request set:

| Request | 0-RTT? |
|---|---|
| `Ls`, `Cd`, `Pwd`, `Stat`, `Quit` | Allowed -- read-only / idempotent, small fixed-size reply |
| `Get`, `Quota`, `Put`, `Rm`, `Mkdir`, `Rmdir`, `Rename`, `Chmod` | Refused with `ErrorCode::Unsupported` ("Operation requires 1-RTT data") |

`Get` is refused even though its reply is idempotent and side-effect-free:
it can return up to `MAX_FILE_SIZE` bytes, so a replayed 0-RTT flight is a
bandwidth amplification primitive (reflected downloads against a spoofed
source IP). `Quota` is likewise refused — a captured 0-RTT `Quota` can be
re-fired indefinitely as an amplification "ping" against the user record.
The allow list therefore keeps only small fixed-size replies. The latency
cost is one extra round trip on the first request of a session; subsequent
requests run at 1-RTT either way.

The check is `request_is_replay_safe` against `conn.is_in_early_data()` at request-decode time. `request_is_replay_safe` only classifies whether a request type is safe to replay; the request-dispatch loop in `server.rs` is what tests `conn.is_in_early_data()` and applies that classification solely to requests arriving as 0-RTT early data. After
the handshake completes, every request is allowed; the client's retry
of a refused mutation transparently goes through under 1-RTT.

The server publishes `qftp_zero_rtt_accepted_total` and
`qftp_zero_rtt_rejected_total` for visibility.

## Stateless retry

When the server is started with `--require-retry`, the very first Initial packet from any peer triggers a QUIC RETRY containing an HMAC-signed token committing to `(peer_addr, original_dcid)`. The client transparently resends the Initial with the token attached; the server verifies the HMAC, recovers the original DCID, and only then commits any connection state. The token format is documented inline in [`crates/qftp-server/src/retry.rs`](../crates/qftp-server/src/retry.rs).

## Rate limiting

Two layers:

1. **Per-IP connection rate limit** (`limits::RateLimiter`), checked on every Initial. Initials that fail it are dropped silently.
2. **Per-request rate limit** on established connections, checked when a `Request` frame is decoded. A denied request gets `ErrorCode::RateLimited` and the stream ends.

Both layers share the same token bucket sized 50 rps, burst 100. (`server::run` literals.)

## Connection ID derivation

The server SCID is derived deterministically as `HMAC-SHA256(seed, client_dcid)` truncated to `quiche::MAX_CONN_ID_LEN`. The seed is a process-lifetime random value. This makes handshake-retransmitted Initials collapse onto the same connection slot instead of opening duplicates.

## Tests

Round-trip tests for every payload-bearing variant live next to their definition in `qftp-common::protocol::tests`. Fuzz targets in [`fuzz/`](../fuzz) feed arbitrary bytes into `bincode::deserialize::<Request>` and `::<Response>`; the assertion is "never panic". Soak workflow in [`.github/workflows/soak.yml`](../.github/workflows/soak.yml) loops put/get/cmp against a live server while sampling RSS / FD / thread count.
