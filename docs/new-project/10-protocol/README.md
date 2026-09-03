# qftp protocol specification (`qftp/1`)

This directory is the **source of truth** for the qftp wire protocol and
is self-contained: everything needed to implement a conforming qftp/1
endpoint in any language is in these files plus the golden vectors in
[`test-vectors/`](test-vectors/). No source code needs to be consulted.

qftp is a language-independent protocol — an FTP replacement built on
QUIC + TLS 1.3. The current wire version is **`qftp/1`** (the major
version is carried in the QUIC ALPN identifier; see
[versioning.md](versioning.md)).

> **`qftp/1.0` wire freeze — 2026-05-30.** The `qftp/1` wire is frozen
> as of this date. Within `qftp/1`, only **backward-compatible,
> append-only** changes are permitted, under the rules in
> [versioning.md](versioning.md); any change an existing `qftp/1`
> decoder cannot accept **MUST** be made in a new ALPN major (`qftp/2`).
> Transfer compression (zstd) was folded into `qftp/1` before any
> release as a backward-compatible append-only extension; see
> [protocol-changelog.md](protocol-changelog.md).

The key words **MUST**, **MUST NOT**, **SHOULD**, **MAY**, etc. in
these documents are to be interpreted as described in RFC 2119.

## Documents

| Document | Contents |
|---|---|
| [qftp-protocol.md](qftp-protocol.md) | Transport, streams, path resolution, and the semantics of every operation (Get/Put resume, checksums, compression, 0-RTT, retry, rate limiting). The entry point. |
| [wire-format.md](wire-format.md) | Byte-for-byte encoding of every control message: framing, primitive encodings, and per-message field layouts. |
| [error-codes.md](error-codes.md) | The `ErrorCode` registry: the on-wire value and meaning of each code, the retryability rules, and the rule for unknown codes. |
| [versioning.md](versioning.md) | Version negotiation (ALPN) and the wire-level rules for forward- and backward-compatible extension. |
| [security-model.md](security-model.md) | The threat model the protocol and its reference deployment are designed against, and the hardening rules an implementation is expected to follow. |
| [protocol-changelog.md](protocol-changelog.md) | History of every change to the bytes on the wire, and the directions deferred to `qftp/2`. |
| [test-vectors/](test-vectors/) | Golden encodings of every message; format described in [test-vectors/README.md](test-vectors/README.md). |

## Conformance

A conforming implementation **MUST** pass both directions (decode and
encode) for every vector in [`test-vectors/`](test-vectors/). Any change
that alters the bytes on the wire **MUST** be reflected in the vectors
and noted in [protocol-changelog.md](protocol-changelog.md).

## Relationship to implementations

Where these documents describe behaviour the wire cannot express on its
own (for example, the precedence between a header checksum and a
streamed trailer), the specification text is normative. Where a
document points at a concrete value a particular implementation
happens to use but other implementations need not match (for example,
a default rate limit), it is called out as **implementation-defined**.
Byte layouts are never defined by reference to a programming-language
type or to any serialization library; they are defined directly in
[wire-format.md](wire-format.md).
