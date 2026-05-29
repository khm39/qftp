# qftp/1 versioning and extensibility

Part of the **qftp/1 specification** ([spec/](README.md)).

This document defines how qftp versions are negotiated and the
wire-level rules for extending the protocol without breaking existing
peers. The key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to
be interpreted as described in RFC 2119.

## Major versions and ALPN

The major version is carried in the QUIC **ALPN** identifier:
`qftp/<major>`. The current value is **`qftp/1`**.

- Each ALPN value denotes one wire-compatible major version.
- Version negotiation is the QUIC/TLS ALPN handshake itself: a client
  offers the ALPN values it supports and the server selects one. If
  there is no common value, the QUIC handshake **fails cleanly** and no
  connection is established. This achieves the effect of a
  Hello/Welcome exchange with zero protocol round-trips.
- Bumping the major version (e.g. to `qftp/2`) is a hard break: peers
  that only speak `qftp/1` will fail to negotiate. Any change to the
  bytes on the wire that an existing `qftp/1` decoder cannot accept
  (see below) **MUST** bump the major version.

## The wire encoding is positional

The encoding ([wire-format.md](wire-format.md)) is **positional and not
self-describing**: there are no field names, field tags, or optional-
field markers on the wire. A decoder reads exactly the fields and
variant it was built to know, in order. Two consequences govern what a
minor revision may change:

1. **An unknown enum discriminant cannot be decoded.** Request,
   Response, and ErrorCode variants are identified by a numeric
   discriminant ([wire-format.md](wire-format.md#primitive-encodings)).
   A decoder that receives a discriminant it does not know **MUST**
   reject the message — for a `Request`/`Response` frame, as
   `ErrorCode::Malformed`; for an `ErrorCode`, per
   [error-codes.md](error-codes.md#unknown-codes).
2. **A truncated message is an error.** A decoder that reaches the end
   of a frame's payload before it has read every field of the value it
   is decoding **MUST** reject the frame as `Malformed`.

## What a minor revision may change

Within a major version, the only backward-compatible structural change
the wire supports is **appending fields to the end of an existing
message's payload**:

- A new field added at the **end** of a message is tolerated by a
  decoder built for the older shape: after reading the fields it knows,
  it ignores the trailing bytes. (The reference implementation decodes
  with trailing bytes allowed.)
- A decoder built for the **newer** shape, reading a frame produced by
  an older sender, will not find the appended field. New fields are
  therefore safe to add only when a receiver that does not understand a
  field can proceed without it; senders **MUST NOT** assume a peer that
  negotiated `qftp/1` populates fields introduced after the original
  `qftp/1`.

Changes that are **NOT** backward compatible within a major version and
therefore **MUST** bump the major version include: reordering or
removing fields, changing a field's type or width, changing the
big-endian frame length prefix or the little-endian payload integer
order, and renumbering any discriminant.

Adding a new `Request`/`Response` variant or a new `ErrorCode` is a
change older peers cannot decode (consequence 1 above). Such additions
are wire changes: each **MUST** be recorded in
[PROTOCOL-CHANGELOG.md](../PROTOCOL-CHANGELOG.md) with new golden
vectors in [`test-vectors/`](../test-vectors/), and an implementation
**MUST NOT** emit a variant or code to a peer that may not understand
it. A revision that needs older peers to keep interoperating after such
an addition bumps the major version.

## Recording changes

Every change to the bytes on the wire **MUST** be reflected in
[`test-vectors/`](../test-vectors/) (so the conformance suite covers
it) and recorded in
[PROTOCOL-CHANGELOG.md](../PROTOCOL-CHANGELOG.md), separately from
implementation-only changes tracked in
[CHANGELOG.md](../CHANGELOG.md).
