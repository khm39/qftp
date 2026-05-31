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

#### Ls pagination

A directory listing is paginated so that one huge directory cannot force
an unbounded `DirListing` frame:

- `Request::Ls` carries an opaque `cursor: Option<string>`. `None`
  requests the first page; to fetch the next page the client echoes back
  verbatim the `next_cursor` it received.
- `Response::DirListing` carries `entries` plus `next_cursor:
  Option<string>`. `next_cursor = Some(..)` means more pages follow;
  `None` means this was the last page. A correct client loops until it
  sees `None`.
- The cursor is **server-defined and opaque**: the server encodes its
  own scan position into it, and the client **MUST** treat it as an
  opaque token — neither parsing nor constructing it. A server **MAY**
  reject a cursor it did not issue.
- Per-page size is **implementation-defined**: the 100000-entry cap
  applies per page, and a server **SHOULD** also split a page that would
  exceed a soft byte budget (~1 MiB in the reference server).

**Reference implementation status (qftp/1.0): pagination is reserved but
not yet implemented.** The `cursor` and `next_cursor` fields are part of
the frozen wire format and the protocol contract above is normative for
future servers, but the reference server in this repository does **not**
split listings: it always replies with `next_cursor = None` and ignores
any `cursor` a client sends. Its single-page cap is therefore an absolute
limit — a directory with more than 100000 listable entries is **refused**
with an `Internal` error (`ErrorCode::Internal`) rather than silently
truncated, and is currently unlistable until a client/server that
implements the loop above is shipped. Clients should still implement the
`next_cursor` loop for forward compatibility; against this server the loop
simply terminates after the first page.

#### Directory and file metadata

`DirEntry` (in `DirListing`) and `FileStat` (from `Stat`) carry the same
metadata, byte layout in [wire-format.md](wire-format.md):

- `file_type` classifies the entry — `Regular`, `Directory`, `Symlink`,
  `Other`, or an unknown future value (see
  [`FileType`](wire-format.md#filetype)). The pre-1.0 `is_dir` boolean
  is gone; `is_dir` is now the derived predicate
  `file_type == Directory`, and an unknown `file_type` is treated as
  "not a directory".
- `modified` is whole seconds since the Unix epoch; `mtime_nanos` is its
  nanosecond part (`0..1_000_000_000`).
- `uid`/`gid` are the POSIX owner ids, reported as `0` where the
  platform does not provide them (e.g. Windows).

### Get

```
client -> server : Request::Get { path, offset, length, accept_encoding }
server -> client : Response::FileReady { size, total_size, checksum_follows, hash_algorithm, encoding, plaintext_size }
server -> client : <size bytes of file body>
server -> client : <digest-length trailer, if checksum_follows>
                   <FIN on the last byte>
```

- `offset` lets the client resume an interrupted download; the server
  seeks to it before reading.
- `length` clips the response to at most that many body bytes; `None`
  means "to EOF".
- `size` is the number of body bytes the server is about to stream:
  plaintext bytes for `encoding == Identity`, encoded wire bytes for a
  compressed response. `total_size` is the file's full on-disk
  plaintext size, so the client can detect truncation across resumed
  sessions. A shrink mid-resume (`total_size` below the client's
  `offset`) is `ErrorCode::InvalidRange`. When `size == 0` the body
  phase is skipped entirely (a trailer, if any, still follows).
- `hash_algorithm` names the digest the trailer uses; it is BLAKE3 in
  `qftp/1` (see [`HashAlgorithm`](wire-format.md#hashalgorithm)).
- When `checksum_follows` is true, the body is immediately followed by a
  trailer of the `hash_algorithm` digest length (BLAKE3 → 32 bytes)
  covering exactly the streamed suffix (post-offset, post-length), not
  the whole file. The client **MUST** compare it to its own running hash
  and discard the local file on mismatch. A resumed Get (`offset > 0`)
  **MUST NOT** be answered with `checksum_follows = false`: the client
  needs the suffix digest to validate the resumed tail.

#### Transfer compression

Compression is opt-in per transfer. A client advertises the codecs it
can decode in `Request::Get.accept_encoding`, ordered by preference.
The server chooses one supported codec and echoes the actual choice in
`Response::FileReady.encoding`; it MAY choose `Identity` even when the
client advertised compression (for example for tiny or already
compressed files). `Identity` is the default and preserves the
uncompressed qftp/1 body bytes.

The transfer domain is always plaintext: `Get.offset`, `Put.offset`,
the server-side `.partial` file, quota accounting, and the BLAKE3
trailer all refer to decoded plaintext bytes. When `encoding ==
Identity`, `plaintext_size` is ignored and receivers use `size`. When
compressed, `size` is the encoded byte count on the QUIC stream and
`plaintext_size` is the decoded byte count.

Receivers MUST defend against decompression bombs by bounding decoded
output to `plaintext_size` and `MAX_FILE_SIZE`; exceeding that bound is
`UploadOverflow` for Put. Storage quota is measured on plaintext, not
encoded bytes. Malformed compressed frames, including zstd frames whose
window exceeds `window_log = 23` (8 MiB), are `DecodeError` (`431`).

If anything goes wrong (path traversal, ACL denial, file too large,
range past EOF, …) the server sends a single `Response::Err` with the
appropriate `ErrorCode` and ends the stream.

### Put

```
client -> server : Request::Put { path, size, mode, offset, hash_algorithm, checksum, no_clobber, checksum_trailer, encoding, plaintext_size }
client -> server : <size bytes of body>
client -> server : <digest-length trailer, if checksum_trailer>
                   <FIN on the last byte>
server -> client : Response::Ok | Response::Err(...)
```

- `size` is the number of body bytes the client is about to send
  (post-`offset`): plaintext bytes for `encoding == Identity`, encoded
  wire bytes for a compressed upload. When compressed,
  `plaintext_size` is the decoded byte count. When `size == 0` the
  body phase is skipped.
- `hash_algorithm` names the digest used for both `checksum` and the
  trailer; it is BLAKE3 in `qftp/1`
  (see [`HashAlgorithm`](wire-format.md#hashalgorithm)). A server that
  cannot compute the requested algorithm **SHOULD** refuse with
  `ErrorCode::Unsupported`.
- `offset` enables append-style resume. The interrupted upload's
  partial is kept on the server next to the eventual destination under
  a deterministic name derived only from the destination (the reference
  implementation uses `<final-filename>.qftp.partial`, so the final
  rename stays atomic). A later session can find it: the client `Stat`s
  that path to learn how many bytes already landed and sends that count
  as `offset`. When `offset > 0` the server **MUST** verify the
  existing partial is exactly `offset` bytes (`ErrorCode::InvalidRange`
  otherwise), continue the running hash over that prefix, and append.
  A fresh `Put` (`offset == 0`) truncates and reuses any stale partial
  at that path.
- `no_clobber`: when true, the server refuses the upload with
  `ErrorCode::AlreadyExists` if `path` already exists. When false
  (the wire default), a pre-existing file is silently overwritten.
- **Checksum resolution.** There are two checksum paths, both carrying
  the digest of the **full file** (including any re-hashed resume prefix,
  not just the bytes sent this round), sized by `hash_algorithm`.
  `checksum` is the header field (`Option<seq<u8>>`), populated by a
  pre-send pass. `checksum_trailer` lets the client hash as it streams
  and append a trailer of the `hash_algorithm` digest length on the same
  stream right after the `size` body bytes. When the trailer is present
  and complete it **takes precedence** over the header `checksum`. A
  trailer that is cut short by the stream FIN before the full digest
  length arrives is **not** a silent fallback to the header `checksum`:
  the server **MUST** reply `ErrorCode::UploadTruncated`. The chosen
  checksum is verified after the last byte; on mismatch the server
  removes the temp and replies `ErrorCode::ChecksumMismatch`. With
  neither field set, the upload is accepted unverified.
- **Structured details.** A `Response::Err` **MAY** attach
  [`ErrorDetails`](wire-format.md#errordetails) for machine handling:
  `Range { offset, file_size }` with `InvalidRange`,
  `Upload { received, declared }` with `UploadOverflow`/`UploadTruncated`,
  and `RetryAfter { millis }` with `RateLimited`.

On success the server renames the temp into place atomically and
applies `mode` (POSIX permission bits; ignored on platforms without
them).

## Error codes

`Response::Err` carries an `ErrorResponse { code, message, details }`.
`code` is the numeric machine-readable status, `message` is
non-localized operator-facing English (never parsed by machine logic),
and `details` is an optional structured supplement
([`ErrorDetails`](wire-format.md#errordetails)). The full registry of
`ErrorCode` values, their classes, the retryability rules, and the rule
for codes an older peer does not recognise are in
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
client **immediately** after the handshake completes — with no backoff,
since the refusal is solely about 0-RTT, not the operation itself (the
reference client does so transparently; see the retryability table in
[error-codes.md](error-codes.md)).

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

## Implementation-defined parameters

Several values are **implementation-defined**: the wire neither carries
nor constrains them, and a conforming peer need not match the reference
implementation. They are collected here so an alternate implementation
knows which knobs are local policy. (The rate limits, the
stateless-retry token format, and the server connection-ID derivation
are also implementation-defined; they are described in their own
sections above.)

### Transport parameters

These are the QUIC transport parameters the **reference native server
and client** apply (`qftp-common`'s `apply_common_config`). They are
not negotiated by qftp beyond the QUIC handshake itself, and another
implementation **MAY** choose different values.

| Parameter | Reference value | Notes |
|---|---|---|
| `initial_max_streams_bidi` | `4` | Max concurrent client-initiated bidi streams. The reference client opens one at a time. |
| `max_idle_timeout` | `30 s` | Connection is closed if idle this long. |
| `initial_max_stream_data` (bidi local/remote) | `16 MiB` | Per-stream QUIC flow-control window; sized for gigabit-BDP, not user buffering (the user-space chunk is 64 KiB). |
| `initial_max_data` | `64 MiB` | Per-connection flow-control window (`4 × 16 MiB`). |
| Pacing | **off** | The reference disables quiche's pacer; back-pressure is via the flow-control window and the congestion controller. |
| Keepalive | **none** | The native endpoints send no keepalive; an idle connection times out at `max_idle_timeout`.¹ |
| Active migration | disabled | `disable_active_migration(true)`. |

¹ The `qftp-web-bridge` is a **separate transport** (browser-facing
WebTransport, see [SECURITY.md](../SECURITY.md)) and *does* set a
keepalive (15 s) to satisfy browser/proxy idle behaviour. The "none"
row above describes the native `qftp/1` transport only.

### Endianness

A reminder that the framing length prefix is **big-endian** while all
payload integers are **little-endian** — an asymmetry that is easy to
get wrong. The normative byte-level definition (and the dedicated
endianness section) is in [wire-format.md](wire-format.md); this is a
pointer, not a redefinition.

### Path encoding

- Paths are exchanged as length-prefixed strings and are assumed to be
  **UTF-8**. Bytes that are not valid UTF-8 are handled in an
  implementation-defined way (the reference implementation converts
  lossily rather than aborting).
- **Case sensitivity and Unicode normalization** (NFC/NFD) are
  **implementation-defined**: they follow the server's underlying
  filesystem. Clients **MUST NOT** assume a path compares or normalizes
  the same way on a different server.
- The **maximum path depth** (number of components) is
  implementation-defined, in addition to any limit the server's OS
  imposes on path/component length.

### File size limit

The maximum file size accepted by `Get`/`Put` is
**implementation-defined**; it is not a wire field. The reference
implementation caps a single transfer at **1 GiB** and replies
`ErrorCode::FileTooLarge` ([error-codes.md](error-codes.md)) beyond it.

## Conformance

The byte-level behaviour of this protocol is pinned by the golden
vectors in [`test-vectors/`](../test-vectors/); see
[test-vectors/README.md](../test-vectors/README.md). A second
implementation validates its encoder and decoder against those vectors
without depending on the reference implementation. The reference
implementation re-derives and checks them on every CI run
(`crates/qftp-conformance`).
