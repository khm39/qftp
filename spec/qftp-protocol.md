# qftp/1 protocol

The **source of truth** for the `qftp/1` protocol. This is the entry
point of the [specification](README.md): it covers transport, streams,
and the semantics of every operation. The byte-for-byte encoding of
each message is in [wire-format.md](wire-format.md); error codes are in
[error-codes.md](error-codes.md); version negotiation and extension
rules are in [versioning.md](versioning.md).

The key words **MUST**, **MUST NOT**, **SHOULD**, **MAY**, etc. are to
be interpreted as described in RFC 2119. Values described as
**implementation-defined** are choices the reference implementation
makes that another conforming implementation need not match.

## Transport

- **UDP + QUIC.** Both endpoints speak QUIC version 1 (RFC 9000).
- **ALPN: `qftp/1`.** The major version is part of the ALPN identifier
  so neither end can talk to a peer it cannot understand; see
  [versioning.md](versioning.md).
- **Mandatory TLS 1.3.** mTLS is optional but, when configured, the
  server enforces that clients present a certificate chained to a
  trusted CA.

## Streams

- Every command runs on its own client-initiated bidirectional QUIC
  stream (stream IDs `0, 4, 8, …`).
- The first frame on a stream is always a `Request`; the server replies
  with a `Response` (or several, in the case of `Get`). Frame encoding
  is defined in [wire-format.md](wire-format.md).
- `Get` and `Put` carry file body bytes on the same stream as the
  request, after the framed control messages; see
  [wire-format.md § Body streaming](wire-format.md#body-streaming).

## Frame format

Each message is a length-prefixed frame (a 4-byte big-endian length
followed by the payload), capped at 16 MiB. The complete framing and
payload encoding are specified in [wire-format.md](wire-format.md).

## Request / Response semantics

The byte layout of every message is in
[wire-format.md](wire-format.md); this section is the per-operation
behaviour.

### Ls / Cd / Pwd / Stat / Mkdir / Rmdir / Rm / Rename / Chmod / Quota / Quit

These are all single `Request` → single `Response` operations. On
failure the server's `Response::Err` carries an `ErrorResponse { code,
message }`; the `code` is the machine-readable handle for scripts (see
[error-codes.md](error-codes.md)).

- `Ls` returns `Response::DirListing`; `Pwd` and a successful `Cd`
  return `Response::Path`; `Stat` returns `Response::FileStat`;
  `Quota` returns `Response::QuotaInfo`; `Mkdir` / `Rmdir` / `Rm` /
  `Rename` / `Chmod` return `Response::Ok`.
- `Quit` is replied to with `Response::Ok`, after which the server
  initiates a graceful QUIC `CONNECTION_CLOSE`.

### Get

```
client -> server : Request::Get { path, offset, length }
server -> client : Response::FileReady { size, total_size, checksum_follows }
server -> client : <size bytes of file body>
server -> client : <32-byte BLAKE3 trailer, if checksum_follows>
                   <FIN on the last byte>
```

- `offset` lets the client resume an interrupted download; the server
  seeks to it before reading.
- `length` clips the response to at most that many body bytes; `None`
  means "to EOF".
- `size` is the number of body bytes the server is about to stream
  (post-`offset`, post-`length`); `total_size` is the file's full
  on-disk size, so the client can detect truncation across resumed
  sessions.
- When `checksum_follows` is true, the body is immediately followed by
  a 32-byte BLAKE3 trailer covering exactly the streamed body
  (post-offset, post-length). The client **MUST** compare it to its own
  running hash and discard the local file on mismatch.

If anything goes wrong (path traversal, ACL denial, file too large,
range past EOF, …) the server sends a single `Response::Err` with the
appropriate `ErrorCode` and ends the stream.

### Put

```
client -> server : Request::Put { path, size, mode, offset, checksum, no_clobber, checksum_trailer }
client -> server : <size bytes of body, FIN on the last byte>
                   <32-byte BLAKE3 trailer, if checksum_trailer>
server -> client : Response::Ok | Response::Err(...)
```

- `size` is the number of body bytes the client is about to send
  (post-`offset`).
- `offset` enables append-style resume. The interrupted upload's
  partial is kept on the server next to the eventual destination under
  a deterministic name derived only from the destination (the reference
  implementation uses `<final-filename>.qftp.partial`, so the final
  rename stays atomic). A later session can find it: the client `Stat`s
  that path to learn how many bytes already landed and sends that count
  as `offset`. When `offset > 0` the server **MUST** verify the
  existing partial is exactly `offset` bytes (`ErrorCode::InvalidRange`
  otherwise), continue the running BLAKE3 over that prefix, and append.
  A fresh `Put` (`offset == 0`) truncates and reuses any stale partial
  at that path.
- `no_clobber`: when true, the server refuses the upload with
  `ErrorCode::AlreadyExists` if `path` already exists. When false
  (the wire default), a pre-existing file is silently overwritten.
- **Checksum resolution.** There are two checksum paths.
  `checksum` is the header field: the BLAKE3 of the full file,
  populated by a pre-send pass. `checksum_trailer` lets the client hash
  as it streams and append a 32-byte BLAKE3 trailer on the same stream
  right after the `size` body bytes. When the trailer is present and
  complete it **takes precedence** over the header `checksum`. The
  chosen checksum (BLAKE3 of the full file, not just the bytes sent
  this round) is verified after the last byte; on mismatch the server
  removes the temp and replies `ErrorCode::ChecksumMismatch`. With
  neither field set, the upload is accepted unverified.

On success the server renames the temp into place atomically and
applies `mode` (POSIX permission bits; ignored on platforms without
them).

## Error codes

`Response::Err` carries an `ErrorResponse { code, message }`. The full
registry of `ErrorCode` values, their meaning, and the rule for codes
an older peer does not recognise are in
[error-codes.md](error-codes.md).

## Versioning policy

The major version is carried in the ALPN identifier (`qftp/<major>`);
incompatible peers fail the QUIC handshake. The wire-level rules for
forward- and backward-compatible extension within a major version are
in [versioning.md](versioning.md).

## 0-RTT session resumption

The server enables QUIC 0-RTT. A client that holds a fresh session
ticket from a previous connect can send application data in its first
flight, skipping the 1-RTT TLS handshake. The reference client stores
tickets per host (mode 0600, 24h TTL) and silently falls back to a
1-RTT handshake on rejection.

### Replay protection

A 0-RTT flight is replayable: an attacker who captures the Initial
packets can resend them to the same server. The request set is
therefore split by whether a request is safe to replay as 0-RTT early
data:

| Request | 0-RTT? |
|---|---|
| `Ls`, `Cd`, `Pwd`, `Stat`, `Quit` | Allowed — read-only / idempotent, small fixed-size reply |
| `Get`, `Quota`, `Put`, `Rm`, `Mkdir`, `Rmdir`, `Rename`, `Chmod` | Refused with `ErrorCode::Unsupported` ("operation requires 1-RTT data") |

`Get` is refused even though its reply is idempotent: it can return a
large body, so a replayed 0-RTT flight is a bandwidth-amplification
primitive (reflected downloads against a spoofed source IP). `Quota` is
refused for the same amplification reason. The allow list therefore
keeps only small fixed-size replies. The cost is one extra round trip
on the first request of a session; subsequent requests run at 1-RTT
either way. A request refused this way **MUST** be retried by the
client after the handshake completes (the reference client does so
transparently).

## Stateless retry

A server **MAY** require QUIC stateless retry on the first Initial
packet from any peer (the reference server does so under
`--require-retry`). The retry carries a token that commits to the
peer's address and original destination connection ID; the client
resends its Initial with the token attached, and the server verifies it
before committing any connection state. The token is **opaque to the
client** — it echoes it back unchanged — and its internal format is
**implementation-defined** (the reference server uses an HMAC-signed
encoding).

## Rate limiting

Two layers, both **implementation-defined** in their exact limits:

1. **Per-IP connection rate limit**, checked on every Initial. Initials
   that fail it are dropped silently.
2. **Per-request rate limit** on established connections, checked when a
   `Request` frame is decoded. A denied request gets
   `ErrorCode::RateLimited` and the stream ends.

(The reference server defaults both to a token bucket of 50 requests/s
with a burst of 100.)

## Connection ID derivation

The server's source connection ID **SHOULD** be derived
deterministically from the client's destination connection ID so that
handshake-retransmitted Initials collapse onto the same connection slot
instead of opening duplicates. The derivation is
**implementation-defined** (the reference server uses
`HMAC-SHA256(process-lifetime seed, client_dcid)` truncated to the
QUIC connection-ID length). Clients treat the server's connection ID as
opaque, per QUIC.

## Conformance

The byte-level behaviour of this protocol is pinned by the golden
vectors in [`test-vectors/`](../test-vectors/); see
[test-vectors/README.md](../test-vectors/README.md). A second
implementation validates its encoder and decoder against those vectors
without depending on the reference implementation. The reference
implementation re-derives and checks them on every CI run
(`crates/qftp-conformance`).
