# Protocol changelog

Changes to the **qftp wire protocol** — the bytes on the wire and their
meaning. This is separate from [CHANGELOG.md](CHANGELOG.md), which
tracks the Rust reference implementation (features, bug fixes, internal
refactors). The protocol is the project's stable public surface;
implementation releases may come and go without a protocol change.

The protocol is versioned by its QUIC **ALPN major** (`qftp/<n>`). A
change that an existing peer of the same major cannot decode requires a
new major; see [spec/versioning.md](spec/versioning.md). Any change to
the bytes on the wire MUST update [`test-vectors/`](test-vectors/) and
appear here.

## qftp/1

The first published wire version. The full specification is in
[`spec/`](spec/) and is pinned by the golden vectors in
[`test-vectors/`](test-vectors/). Summary of what `qftp/1` defines:

- **Framing.** Every control message is a 4-byte big-endian
  length-prefixed frame, payload capped at 16 MiB
  ([spec/wire-format.md](spec/wire-format.md)).
- **Encoding.** A positional, little-endian, fixed-width encoding:
  `u32` enum discriminants, `u64` length prefixes for strings and
  sequences, raw fixed arrays, structs in declaration order
  ([spec/wire-format.md](spec/wire-format.md)).
- **Messages.** `Request` (13 variants: `Ls`, `Cd`, `Pwd`, `Get`,
  `Put`, `Mkdir`, `Rmdir`, `Rm`, `Rename`, `Chmod`, `Stat`, `Quota`,
  `Quit`) and `Response` (7 variants: `Ok`, `Err`, `DirListing`,
  `Path`, `FileStat`, `FileReady`, `QuotaInfo`).
- **Error codes.** A 17-entry `ErrorCode` registry
  ([spec/error-codes.md](spec/error-codes.md)).
- **Body streaming.** `Get`/`Put` carry file body bytes on the request
  stream, with an optional 32-byte BLAKE3 trailer
  ([spec/wire-format.md](spec/wire-format.md#body-streaming)).
- **Resume and integrity.** Ranged/resumed `Get`, append-style `Put`
  resume, and BLAKE3 verification (header checksum or streamed
  trailer).
- **Transport behaviour.** 0-RTT replay protection, optional stateless
  retry, rate limiting, deterministic connection-ID derivation
  ([spec/qftp-protocol.md](spec/qftp-protocol.md)).

`qftp/1` was previously documented in `docs/protocol.md`; the
specification now lives in [`spec/`](spec/) as the source of truth.

### 1.0 wire freeze

Before tagging 1.0, every *now-or-never* breaking change was batched
into one coordinated revision so that post-1.0 additions can be made
within `qftp/1` by the append-only rule
([spec/versioning.md](spec/versioning.md)) instead of each forcing an
ALPN major bump. qftp is pre-1.0 and nothing is deployed against the
earlier shape, so these breaks are acceptable. The batch **supersedes**
the corresponding bullets in the `qftp/1` summary above (the 16-entry
`ErrorCode` registry, the fixed 32-byte BLAKE3 trailer, and the
`DirEntry`/`FileStat` field shape); the entries below are the frozen
shape, and [`spec/`](spec/) plus [`test-vectors/`](test-vectors/) are
authoritative.

- **Status codes are numeric `u32`.** `ErrorResponse.code` is a `u32`
  little-endian status (HTTP-like classes: `4xx` caller-caused, `5xx`
  server-caused), no longer a positional enum index. A decoder that
  receives an unrecognised value now decodes it as `Unknown(n)`
  classified by range, rather than rejecting the frame — this replaces
  the earlier "unknown `ErrorCode` = `Malformed`" rule. See
  [spec/error-codes.md](spec/error-codes.md).
- **Structured error details.** `ErrorResponse` gains an optional
  `details: Option<ErrorDetails>`, a `u32`-tagged, non-exhaustive enum
  carrying machine-readable context: `Range { offset, file_size }`
  (InvalidRange), `Upload { received, declared }`
  (UploadOverflow/UploadTruncated), and `RetryAfter { millis }`
  (RateLimited). `message` stays operator/developer-facing English
  diagnostics, not for end-user display.
- **Richer `DirEntry` / `FileStat`.** `is_dir: bool` is **removed** and
  replaced by an explicit `file_type` (`u32`: `Regular=0`,
  `Directory=1`, `Symlink=2`, `Other=3`). Both structures gain
  sub-second time (`mtime_nanos`, the nanosecond part of `modified`,
  `0..1_000_000_000`) and ownership (`uid`, `gid`, `0` where
  unavailable). See [spec/wire-format.md](spec/wire-format.md).
- **Directory pagination.** `Request::Ls` gains `cursor:
  Option<string>` and `Response::DirListing` changes from a bare
  `seq<DirEntry>` to `{ entries, next_cursor: Option<string> }`. The
  cursor is **opaque and server-defined**; clients echo it back
  verbatim. `next_cursor = Some(..)` means more pages follow. Per-page
  limits are implementation-defined.
- **Hash-algorithm agility.** A `HashAlgorithm` enum (`u32`,
  `Blake3=0`) is carried in `Request::Put` and `Response::FileReady`.
  The header `checksum` and the streamed trailer become a variable
  `seq<u8>` whose length is the algorithm's digest length (BLAKE3 →
  32), replacing the fixed `[u8; 32]`. A future algorithm is added as a
  new `HashAlgorithm` value and the trailer length follows from it.
- **Transfer-compression schema.** An `Encoding` enum (`u32`,
  `Identity=0`, `Zstd=1`) is added for opt-in body compression.
  `Request::Get` appends `accept_encoding: seq<Encoding>`, and both
  `Request::Put` and `Response::FileReady` append `encoding: Encoding`
  plus `plaintext_size: u64`. `Identity` is the default; compressed
  transfers use `size` for encoded wire bytes and `plaintext_size` for
  decoded plaintext bytes. The BLAKE3 trailer and resume `offset`
  remain plaintext-domain. `ErrorCode::DecodeError` is assigned `431`
  for malformed compressed frames or zstd windows exceeding
  `window_log = 23` (8 MiB).

Compatible refinements landed in the same revision (not new breaks):
the `Put` FIN/trailer framing was clarified (FIN on the last trailer
byte when a trailer follows, else on the last body byte; `size == 0`
skips the body phase; a short trailer is `UploadTruncated`, never a
silent fall-back to the header checksum); resume checksum/`total_size`
semantics were tightened (a shrink mid-resume is `InvalidRange`;
`checksum_follows = false` is forbidden on a resumed `Get`); and a
conformance test now asserts every variant's on-wire discriminant
against [`test-vectors/`](test-vectors/).

The `qftp/1` major version is **not** bumped: all of the above is folded
into `qftp/1` while it is still pre-release.

### Future directions (deferred to qftp/2)

Recorded here so they are not relitigated as `qftp/1` minor revisions.
Each is wire-breaking in a way the append-only rule cannot absorb, so
each is reserved for the next ALPN major:

- **Self-describing encoding.** Move off the positional, fixed-width
  encoding toward a tagged wire format (CBOR / Protobuf-style) so
  unknown fields and variants survive a round trip.
- **Varint integers.** Replace the fixed-width `u32`/`u64` payload
  integers with variable-length encodings.
- **In-band capability negotiation.** A capability/feature exchange
  beyond the ALPN major, so peers can advertise optional features
  without an ALPN bump.
- **Per-control-message MAC / signed manifests.** Authenticity at the
  message layer (TLS already provides channel integrity; BLAKE3 is
  integrity only — see [SECURITY.md](SECURITY.md)).
- **New operations.** `Copy`, `Symlink`, and `Transaction`
  (multi-operation atomicity).
