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
variant it was built to know, in order. Enums come in two flavours with
different unknown-value behaviour, and three consequences govern what a
minor revision may change:

1. **An unknown *positional* enum discriminant cannot be decoded.**
   `Request`, `Response`, and `ErrorDetails` are positional enums: their
   `u32` discriminant is a declaration-order index, and the fields that
   follow depend on which variant it selects
   ([wire-format.md](wire-format.md#primitive-encodings)). A decoder
   that receives a discriminant it does not know cannot know what
   follows, so it **MUST** reject the message — a `Request`/`Response`
   frame as `ErrorCode::Malformed` (`400`), an unknown `ErrorDetails`
   discriminant likewise.
2. **An unknown *numeric* enum value decodes.** `ErrorCode`,
   `FileType`, `HashAlgorithm`, and `Encoding` are numeric enums: each is a single
   self-contained `u32` *value* with no variant-dependent payload
   ([wire-format.md](wire-format.md#primitive-encodings)). A value a
   decoder has no named variant for is preserved as `Unknown(n)` rather
   than rejected, so the surrounding message still decodes. (For
   `ErrorCode` the decoder additionally classifies by leading digit; see
   [error-codes.md](error-codes.md#unknown-codes). This is the change
   from earlier `qftp/1`, which treated an unknown `ErrorCode` as
   `Malformed`.)
3. **A truncated message is an error.** A decoder that reaches the end
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
  an older sender, will not find the appended field — and because a
  truncated message is `Malformed` (consequence 3 above), a naïve
  newer decoder **rejects** the older frame outright. The append-only
  rule is therefore **one-directional**: it lets *older decoders*
  tolerate *newer senders*, not the reverse. A revision that appends a
  field and needs to keep interoperating with unupgraded senders
  **MUST** have its decoder explicitly accept both shapes (decode the
  shorter, pre-revision layout and substitute a defined default for
  the missing field), and **MUST** document that default here and in
  the message's specification. Senders likewise **MUST NOT** assume a
  peer that negotiated `qftp/1` populates fields introduced after the
  original `qftp/1`.

Changes that are **NOT** backward compatible within a major version and
therefore **MUST** bump the major version include: reordering or
removing fields, changing a field's type or width, changing the
big-endian frame length prefix or the little-endian payload integer
order, and renumbering any discriminant.

Adding a new `Request`/`Response` (or `ErrorDetails`) **variant** is a
change older peers cannot decode (consequence 1 above): an
implementation **MUST NOT** emit such a variant to a peer that may not
understand it, and a revision that needs older peers to keep
interoperating after introducing one bumps the major version.

Adding a new **numeric value** to `ErrorCode`, `FileType`,
`HashAlgorithm`, or `Encoding` is different (consequence 2): an older
peer decodes the unknown value as `Unknown(n)` and keeps going, so the
addition is **forward-compatible** and does **not** require a
major-version bump. A peer still **SHOULD NOT** emit a value it knows
the receiver cannot act on (e.g. a `HashAlgorithm` the peer cannot
compute or an `Encoding` it cannot decode), but doing so fails
gracefully (`Unsupported`) rather than breaking the frame.

The qftp/1 pre-release compression schema is an example of an
append-only, forward-compatible addition within the major version:
`Request::Get` appends `accept_encoding`, `Request::Put` and
`Response::FileReady` append `encoding` and `plaintext_size`, and the
numeric enums gain `Encoding::{Identity=0,Zstd=1}` plus
`ErrorCode::DecodeError = 431`. Existing fields keep their order, type,
and byte width.

Either kind of addition is a documented wire change: each **MUST** be
recorded in [PROTOCOL-CHANGELOG.md](../PROTOCOL-CHANGELOG.md) with new
golden vectors in [`test-vectors/`](../test-vectors/).

## Recording changes

Every change to the bytes on the wire **MUST** be reflected in
[`test-vectors/`](../test-vectors/) (so the conformance suite covers
it) and recorded in
[PROTOCOL-CHANGELOG.md](../PROTOCOL-CHANGELOG.md), separately from
implementation-only changes tracked in
[CHANGELOG.md](../CHANGELOG.md).
