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
client -> server : Request::Put { path, size, mode, offset, checksum }
client -> server : <size bytes of body, FIN on the last byte>
server -> client : Response::Ok | Response::Err(...)
```

- `size` is the number of body bytes the client is about to send (post-offset).
- `offset` enables append-style resume. When `offset > 0` the server validates that an existing temp file already has exactly that many bytes; if not, it returns `ErrorCode::InvalidRange`. The temp lives next to the eventual destination so the final `rename` is atomic, and is named `<final-filename>.qftp.partial.<server-pid>.<stream-id>` (e.g. uploading `dump.bin` from stream 4 of server pid 17654 lands at `dump.bin.qftp.partial.17654.4` first).
- `checksum` (BLAKE3 of the full file, not just the bytes being sent this round) is verified after the last byte. On mismatch the temp is left for the Drop cleanup and the response carries `ErrorCode::ChecksumMismatch`.

Upon success, the server `rename`s the temp into place atomically and applies `mode` (Unix only).

## Error codes

`ErrorCode` is `#[non_exhaustive]`; clients should treat unknown values as `Internal`. Current variants:

```
NotFound          PermissionDenied  AlreadyExists
NotADirectory     IsADirectory      FileTooLarge
UploadOverflow    UploadTruncated   ChecksumMismatch
RateLimited       Malformed         Internal
Unauthorized      InvalidRange      Unsupported
```

## Versioning policy

- **Major version** is part of ALPN (`qftp/<major>`). Bumping it is a hard break; old peers will fail the QUIC handshake.
- **Minor changes** are made non-breaking by the use of `#[non_exhaustive]` enums and `#[serde(default)]` fields. New variants and fields are silently ignored by older binaries.
- The wire format is bincode; field reordering is *not* a minor change.

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
