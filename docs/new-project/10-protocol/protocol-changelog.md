# Protocol changelog

Changes to the **qftp wire protocol** — the bytes on the wire and their
meaning. This is separate from the reference implementation's own changelog, which
tracks the Rust reference implementation (features, bug fixes, internal
refactors). The protocol is the project's stable public surface;
implementation releases may come and go without a protocol change.

The protocol is versioned by its QUIC **ALPN major** (`qftp/<n>`). A
change that an existing peer of the same major cannot decode requires a
new major; see [versioning.md](versioning.md). Any change to
the bytes on the wire MUST update [`test-vectors/`](test-vectors/) and
appear here.

## qftp/1

The first published wire version. The full specification is in
this directory and is pinned by the golden vectors in
[`test-vectors/`](test-vectors/). Summary of what `qftp/1` defines:

- **Framing.** Every control message is a 4-byte big-endian
  length-prefixed frame, payload capped at 16 MiB
  ([wire-format.md](wire-format.md)).
- **Encoding.** A positional, little-endian, fixed-width encoding:
  `u32` enum discriminants, `u64` length prefixes for strings and
  sequences, raw fixed arrays, structs in declaration order
  ([wire-format.md](wire-format.md)).
- **Messages.** `Request` (13 variants: `Ls`, `Cd`, `Pwd`, `Get`,
  `Put`, `Mkdir`, `Rmdir`, `Rm`, `Rename`, `Chmod`, `Stat`, `Quota`,
  `Quit`) and `Response` (7 variants: `Ok`, `Err`, `DirListing`,
  `Path`, `FileStat`, `FileReady`, `QuotaInfo`).
- **Error codes.** A 16-entry `ErrorCode` registry (the 1.0 wire
  freeze below adds `DecodeError = 431`, bringing the current registry
  to 17; see [error-codes.md](error-codes.md)).
- **Body streaming.** `Get`/`Put` carry file body bytes on the request
  stream, with an optional 32-byte BLAKE3 trailer
  ([wire-format.md](wire-format.md#body-streaming)).
- **Resume and integrity.** Ranged/resumed `Get`, append-style `Put`
  resume, and BLAKE3 verification (header checksum or streamed
  trailer).
- **Transport behaviour.** 0-RTT replay protection, optional stateless
  retry, rate limiting, deterministic connection-ID derivation
  ([qftp-protocol.md](qftp-protocol.md)).

The specification lives in this directory as the source of truth.

### 1.0 wire freeze

Before tagging 1.0, every *now-or-never* breaking change was batched
into one coordinated revision so that post-1.0 additions can be made
within `qftp/1` by the append-only rule
([versioning.md](versioning.md)) instead of each forcing an
ALPN major bump. qftp is pre-1.0 and nothing is deployed against the
earlier shape, so these breaks are acceptable. The batch **supersedes**
the corresponding bullets in the `qftp/1` summary above (the 16-entry
`ErrorCode` registry, the fixed 32-byte BLAKE3 trailer, and the
`DirEntry`/`FileStat` field shape); the entries below are the frozen
shape, and this directory plus [`test-vectors/`](test-vectors/) are
authoritative.

- **Status codes are numeric `u32`.** `ErrorResponse.code` is a `u32`
  little-endian status (HTTP-like classes: `4xx` caller-caused, `5xx`
  server-caused), no longer a positional enum index. A decoder that
  receives an unrecognised value now decodes it as `Unknown(n)`
  classified by range, rather than rejecting the frame — this replaces
  the earlier "unknown `ErrorCode` = `Malformed`" rule. See
  [error-codes.md](error-codes.md).
- **Structured error details.** `ErrorResponse` gains an optional
  `details: Option<ErrorDetails>`, a positional `u32`-discriminant enum (adding a variant is a major-version change, see [versioning.md](versioning.md))
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
  unavailable). See [wire-format.md](wire-format.md).
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
  plus `plaintext_size: u64`. `Identity` is the default; for
  compressed transfers `size` equals `plaintext_size` (both count
  plaintext bytes) and the codec frame, not `size`, delimits the wire
  body. The BLAKE3 trailer and resume `offset`
  remain plaintext-domain. `ErrorCode::DecodeError` is assigned `431`
  for malformed compressed frames or zstd windows exceeding
  `window_log = 23` (8 MiB).

Compatible refinements landed in the same revision (not new breaks):
the `Put` FIN/trailer framing was clarified (FIN on the last trailer
byte when a trailer follows, else on the last body byte; `Identity` with `size == 0`
skips the body phase; a short trailer is `UploadTruncated`, never a
silent fall-back to the header checksum); resume checksum/`total_size`
semantics were tightened (a shrink mid-resume is `InvalidRange`;
`checksum_follows = false` is forbidden on a resumed `Get`); and a
conformance test now asserts every variant's on-wire discriminant
against [`test-vectors/`](test-vectors/).

The `qftp/1` major version is **not** bumped: all of the above is folded
into `qftp/1` while it is still pre-release.

### Post-freeze specification revisions (no wire change)

Behavioural rules tightened after the 1.0 wire freeze. None of these
change the bytes on the wire or the golden vectors; they change what a
conforming endpoint does with already-frozen messages.

- **0-RTT allow list narrowed, identity gate added.** `Ls` moved from
  the 0-RTT allow list to the refused set: a single `DirListing` page
  can be a multi-MiB frame, the same amplification reasoning that
  already excluded `Get` and `Quota`. Additionally, a server that can
  resolve named identities (mTLS enforced, or named users configured)
  **MUST** refuse *every* request arriving as 0-RTT early data, since
  early data can only execute as the anonymous user and would leak the
  anonymous view across the identity boundary. Both refusals reuse
  `ErrorCode::Unsupported` and the existing immediate-retry rule. See
  [qftp-protocol.md](qftp-protocol.md#0-rtt-session-resumption).
- **Path resolution specified.** A new normative section defines what
  a `path` means: the per-user root is `/`, the per-connection cwd
  (changed only by `Cd`), leading-`/` vs cwd-relative resolution,
  `.`/`..` handling (`..` past the root is `PermissionDenied`, never
  clamped), the no-escape-including-symlinks guarantee, the virtual
  `Response::Path` representation, and the cross-stream ordering rule
  for `Cd` (the new cwd is guaranteed only for requests issued after
  the `Cd` response is received). Previously all of this was
  implementation lore; independent implementations could not have
  agreed on it. See
  [qftp-protocol.md](qftp-protocol.md#path-resolution).
- **`Cd` response corrected to `Response::Ok`.** The spec said a
  successful `Cd` returns `Response::Path`; the reference
  implementation has always returned `Response::Ok` (the cwd is
  observable via `Pwd`). The spec now documents `Ok`.
- **Get trailer coverage corrected — the trailer binds a resume to
  the file version.** The spec described the Get trailer as covering
  "exactly the streamed suffix"; all three reference endpoints
  (server, client, web bridge) have always computed the **cumulative
  digest over `[0, offset + body length)`**, folding the `[0..offset)`
  prefix in on both sides. The spec now documents the cumulative
  digest, which is also what protects a resumed Get against the
  server-side file changing between sessions (a same-size content
  change defeats the `total_size` check but not the prefix digest). A
  suffix-only independent implementation would have failed every
  resumed transfer against the reference stack.
- **Upload verification made mandatory for risky `Put` shapes.** A
  resumed `Put` (`offset > 0`) and a compressed `Put`
  (`encoding != Identity`) **MUST** carry `checksum` and/or
  `checksum_trailer`; the server refuses them with
  `ErrorCode::Unsupported` otherwise. A compressed `Put` **MUST**
  carry `size == plaintext_size` (violation: `Malformed`). The
  reference server already enforced all three; the spec now says so.
- **Append-only extension rule clarified as one-directional.** A newer
  decoder reading an older sender's frame rejects it as `Malformed`
  unless it explicitly accepts both shapes; revisions that append
  fields and need mixed-version interop must define the decode
  default. See [versioning.md](versioning.md).

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
  integrity only — see [security-model.md](security-model.md)).
- **New operations.** `Copy`, `Symlink`, and `Transaction`
  (multi-operation atomicity).
