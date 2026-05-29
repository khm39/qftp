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
- **Error codes.** A 16-entry `ErrorCode` registry
  ([spec/error-codes.md](spec/error-codes.md)).
- **Body streaming.** `Get`/`Put` carry raw file bytes on the request
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
