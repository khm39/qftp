# qftp protocol specification

This directory is the **source of truth** for the qftp wire protocol.
qftp is a language-independent protocol — an FTP replacement built on
QUIC + TLS 1.3. The Rust crates under [`crates/`](../crates/) are the
**reference implementation**; they conform to this specification, not
the other way round. A second implementation in any language can be
written from this directory and [`test-vectors/`](../test-vectors/)
without reading Rust.

The current wire version is **`qftp/1`** (the major version is carried
in the QUIC ALPN identifier; see [versioning.md](versioning.md)).

> **`qftp/1.0` wire freeze — 2026-05-30.** The `qftp/1` wire is frozen
> as of this date. The coordinated pre-1.0 break that produced this
> shape (numeric `u32` status codes, structured `ErrorDetails`, richer
> `DirEntry`/`FileStat`, directory pagination, and hash-algorithm
> agility) is recorded in
> [PROTOCOL-CHANGELOG.md](../PROTOCOL-CHANGELOG.md). From here on:
> within `qftp/1`, only **backward-compatible, append-only** changes
> are permitted, under the rules in [versioning.md](versioning.md);
> any change an existing `qftp/1` decoder cannot accept **MUST** be
> made in a new ALPN major (`qftp/2`). Deferred directions for that
> next major are listed in the protocol changelog.

The key words **MUST**, **MUST NOT**, **SHOULD**, **MAY**, etc. in
these documents are to be interpreted as described in RFC 2119.

## Documents

| Document | Contents |
|---|---|
| [qftp-protocol.md](qftp-protocol.md) | Transport, streams, and the semantics of every operation (Get/Put resume, checksums, 0-RTT, retry, rate limiting). The entry point. |
| [wire-format.md](wire-format.md) | Byte-for-byte encoding of every control message: framing, primitive encodings, and per-message field layouts. |
| [error-codes.md](error-codes.md) | The `ErrorCode` registry: the on-wire value and meaning of each code, and the rule for unknown codes. |
| [versioning.md](versioning.md) | Version negotiation (ALPN) and the wire-level rules for forward- and backward-compatible extension. |

Conformance vectors live in [`test-vectors/`](../test-vectors/), with a
format description in
[test-vectors/README.md](../test-vectors/README.md). The reference
implementation re-derives and validates them on every CI run
(`crates/qftp-conformance`).

## Changes

Wire-protocol changes are tracked separately from implementation
changes: see [PROTOCOL-CHANGELOG.md](../PROTOCOL-CHANGELOG.md) for the
former and [CHANGELOG.md](../CHANGELOG.md) for the latter. Any change
that alters the bytes on the wire **MUST** be reflected in
[`test-vectors/`](../test-vectors/) and noted in the protocol
changelog.

## Relationship to the reference implementation

Where these documents describe behaviour the wire cannot express on its
own (for example, the precedence between a header checksum and a
streamed trailer), the specification text is normative. Where a
document points at a concrete value the reference implementation
happens to use but other implementations need not match (for example, a
default rate limit), it is called out as **implementation-defined**.
Byte layouts are never defined by reference to a Rust type or to any
serialization library; they are defined directly in
[wire-format.md](wire-format.md).
