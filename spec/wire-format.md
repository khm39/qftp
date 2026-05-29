# qftp/1 wire format

Part of the **qftp/1 specification** ([spec/](README.md)). The
specification is the source of truth for the bytes on the wire; the
Rust reference implementation conforms to it, not the other way round.

This document defines, byte for byte, how every control message of the
`qftp/1` protocol is encoded. A correct implementation in any language
can encode and decode `qftp/1` messages from this document and the
golden vectors in [`test-vectors/`](../test-vectors/) alone, without
reading the reference implementation.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**,
**SHOULD**, **MAY** are to be interpreted as described in RFC 2119.

## Conventions

- All byte values are written in hexadecimal.
- "u8 / u16 / u32 / u64" denote unsigned integers of 8 / 16 / 32 / 64
  bits. "Octet" and "byte" are used interchangeably.
- Field layouts are listed **in wire order**, top to bottom.

## Endianness

`qftp/1` mixes two byte orders, and getting this wrong is the most
common interop bug, so it is called out up front:

- The **frame length prefix is big-endian** (`u32`). It is the *only*
  big-endian integer in the entire protocol.
- **Every integer inside the payload is little-endian** — enum
  discriminants, enum tag values, `string`/`seq` length prefixes, and
  all `u8`/`u16`/`u32`/`u64` fields. Raw body bytes and digest trailers
  ([§ Body streaming](#body-streaming)) carry no integers and are sent
  verbatim.

## Framing

Every control message is sent as a **length-prefixed frame**: a 4-byte
length followed by the encoded payload.

```
+--------+--------+--------+--------+--------+ ... +--------+
|        length (u32, big-endian)   |       payload         |
+--------+--------+--------+--------+--------+ ... +--------+
```

- The length prefix is a **u32 in big-endian** byte order (note: this
  is the *only* big-endian integer in the protocol; payload integers
  are little-endian, see below). Its value is the number of payload
  bytes that follow, not counting the 4 prefix bytes.
- An implementation **MUST** refuse a frame whose length prefix
  exceeds **16 MiB** (`16 * 1024 * 1024` = `0x0100_0000` = 16777216
  bytes) without reading the payload, and **MUST NOT** allocate a
  payload buffer larger than the declared length.
- After decoding, an implementation **SHOULD** apply the per-field
  sanity caps in [§ Field caps](#field-caps); the frame cap alone does
  not bound an individual `string`/`seq` field.
- The receiver consumes exactly `4 + length` bytes per message. Any
  bytes beyond the declared payload length belong to the next frame or
  to the body-streaming layer ([§ Body streaming](#body-streaming)).

## Primitive encodings

The payload is a concatenation of primitively-encoded fields with **no
padding, alignment, field tags, or separators**. The primitives are:

| Type | Encoding |
|---|---|
| `u8` | 1 byte. |
| `u16` | 2 bytes, **little-endian**. |
| `u32` | 4 bytes, **little-endian**. |
| `u64` | 8 bytes, **little-endian**. |
| `bool` | 1 byte: `0x00` = false, `0x01` = true. A decoder **MUST** reject any other value. |
| `Option<T>` | 1 tag byte: `0x00` = none (nothing follows), `0x01` = some, followed by the encoding of `T`. A decoder **MUST** reject any other tag value. |
| `string` | a `u64` little-endian **byte** length `n`, then exactly `n` bytes of **UTF-8**. |
| `seq<T>` (variable array) | a `u64` little-endian element count `n`, then `n` encodings of `T`. |
| `[u8; N]` (fixed array) | exactly `N` raw bytes, with **no** length prefix. |
| struct | the encodings of its fields concatenated in declaration order. |
| positional enum value | the variant discriminant (`u32` LE), then the encodings of that variant's fields (if any) in declaration order. Discriminants are numbered from `0` in declaration order. Used by [`Request`](#request), [`Response`](#response), and [`ErrorDetails`](#errordetails). |
| numeric enum value | a single `u32` LE **value** (not a positional index). Used by [`ErrorCode`](#errorresponse), [`FileType`](#filetype), and [`HashAlgorithm`](#hashalgorithm); each carries an explicitly assigned numeric code, and a value a decoder does not recognise is preserved rather than rejected (see those sections and [versioning.md](versioning.md)). |

The rules **compose recursively**, with no extra tag, separator, or
padding between or around a nested value: a field that is itself a
struct, an `Option<T>`, or a `seq<T>` is encoded by applying the
matching rule to it. In particular, each struct element inside a
`seq<T>` (for example each `DirEntry` in a `DirListing`) is encoded
with its fields in declaration order, exactly as a standalone struct.

These rules are complete: every message type below is built from them.

> **Implementation note (non-normative).** The reference implementation
> obtains exactly this encoding from `bincode` 1.x configured with
> fixed-int encoding and little-endian byte order. The specification,
> not bincode, is normative: a future reference implementation MAY use
> any encoder that produces these bytes.

## Messages

A stream's first frame carries a [`Request`](#request); the server
answers with one or more [`Response`](#response) frames. `string`
fields are UTF-8 with no NUL terminator. Integer fields are little-endian
per the table above.

### Request

`Request` is an enum; the frame payload begins with its `u32`
little-endian discriminant.

| Discriminant | Variant | Fields (wire order) |
|---|---|---|
| `0` | `Ls` | `path: string`, `cursor: Option<string>` |
| `1` | `Cd` | `path: string` |
| `2` | `Pwd` | *(none)* |
| `3` | `Get` | `path: string`, `offset: u64`, `length: Option<u64>` |
| `4` | `Put` | `path: string`, `size: u64`, `mode: u32`, `offset: u64`, `hash_algorithm: HashAlgorithm` (`u32`), `checksum: Option<seq<u8>>`, `no_clobber: bool`, `checksum_trailer: bool` |
| `5` | `Mkdir` | `path: string` |
| `6` | `Rmdir` | `path: string` |
| `7` | `Rm` | `path: string` |
| `8` | `Rename` | `from: string`, `to: string` |
| `9` | `Chmod` | `path: string`, `mode: u32` |
| `10` | `Stat` | `path: string` |
| `11` | `Quota` | *(none)* |
| `12` | `Quit` | *(none)* |

Field meanings are defined in [qftp-protocol.md](qftp-protocol.md).
New discriminants MAY be added in later minor revisions; see
[versioning.md](versioning.md) for how a decoder treats an unknown
discriminant.

### Response

| Discriminant | Variant | Fields (wire order) |
|---|---|---|
| `0` | `Ok` | *(none)* |
| `1` | `Err` | one [`ErrorResponse`](#errorresponse) |
| `2` | `DirListing` | `entries: seq<DirEntry>` (see [`DirEntry`](#direntry)), `next_cursor: Option<string>` |
| `3` | `Path` | `string` |
| `4` | `FileStat` | one [`FileStat`](#filestat) |
| `5` | `FileReady` | `size: u64`, `total_size: u64`, `checksum_follows: bool`, `hash_algorithm: HashAlgorithm` (`u32`) |
| `6` | `QuotaInfo` | `used_bytes: u64`, `file_count: u64`, `limit_bytes: Option<u64>` |

### ErrorResponse

A struct, used only inside `Response::Err`.

| Field (wire order) | Type |
|---|---|
| `code` | `ErrorCode` (a numeric enum: one `u32` LE value; see [error-codes.md](error-codes.md)) |
| `message` | `string` (operator/developer-facing diagnostics; **SHOULD** be ≤ 1 KiB, see [§ Field caps](#field-caps)) |
| `details` | `Option<ErrorDetails>` (structured supplement; see [`ErrorDetails`](#errordetails)) |

`message` is an English, **non-localized** diagnostic string for
operators and developers; it is **not** intended for end-user display.
Machine logic **MUST** branch on `code` (and, where present, `details`),
not on `message`.

### FileType

A numeric enum carried in [`DirEntry`](#direntry) and
[`FileStat`](#filestat), encoded as a single `u32` LE **value**:

| Value | Variant |
|---|---|
| `0` | `Regular` |
| `1` | `Directory` |
| `2` | `Symlink` |
| `3` | `Other` |

A value not listed here is preserved as an unknown classification and
**MUST NOT** be rejected (see [versioning.md](versioning.md)); a decoder
treats it as "not a directory" for the purpose of the `is_dir` helper.

### HashAlgorithm

A numeric enum naming the content-hash algorithm of a transfer,
encoded as a single `u32` LE **value**:

| Value | Variant | Digest length |
|---|---|---|
| `0` | `Blake3` | 32 bytes |

`Blake3` is the only algorithm defined in `qftp/1`. The field exists so
a future algorithm can be negotiated without a major-version bump; the
header `checksum` and the streamed trailer are exactly the algorithm's
digest length ([§ Body streaming](#body-streaming)). A value a decoder
does not recognise is preserved rather than rejected
([versioning.md](versioning.md)); a peer that receives an algorithm it
cannot compute **SHOULD** refuse the transfer with
[`Unsupported`](error-codes.md).

### ErrorDetails

A positional enum (its `u32` LE discriminant is a declaration-order
index, **not** an assigned value), carried inside
`ErrorResponse.details` when present. Each variant supplies
machine-readable context for a specific [`ErrorCode`](error-codes.md).

| Discriminant | Variant | Fields (wire order) |
|---|---|---|
| `0` | `Range` | `offset: u64`, `file_size: u64` |
| `1` | `Upload` | `received: u64`, `declared: u64` |
| `2` | `RetryAfter` | `millis: u32` |

`Range` accompanies `InvalidRange`; `Upload` accompanies
`UploadOverflow` / `UploadTruncated`; `RetryAfter` accompanies
`RateLimited`. As a positional enum, an unknown `ErrorDetails`
discriminant cannot be decoded — a frame carrying one is rejected as
`Malformed` ([versioning.md](versioning.md)). For example,
`Some(ErrorDetails::Range { offset: 10, file_size: 5 })` encodes as the
`Option` tag `01`, the discriminant `00 00 00 00`, then
`0a 00 00 00 00 00 00 00` (`offset`) and `05 00 00 00 00 00 00 00`
(`file_size`).

### DirEntry

A struct, carried in `Response::DirListing`.

| Field (wire order) | Type |
|---|---|
| `name` | `string` (a single path component; **MUST NOT** contain `/`, `\`, or NUL, and **MUST NOT** be `.` or `..`) |
| `file_type` | `FileType` (a `u32` LE value; see [`FileType`](#filetype)) |
| `size` | `u64` |
| `modified` | `u64` (seconds since the Unix epoch) |
| `mtime_nanos` | `u32` (nanosecond part of `modified`, `0..1_000_000_000`) |
| `uid` | `u32` (owner uid; `0` where unavailable, e.g. Windows) |
| `gid` | `u32` (owner gid; `0` where unavailable) |
| `mode` | `u32` (POSIX permission bits; synthesized on platforms without them) |

### FileStat

A struct, carried in `Response::FileStat`. It is exactly a `DirEntry`
without the leading `name`: the remaining fields appear in the same
order.

| Field (wire order) | Type |
|---|---|
| `file_type` | `FileType` (a `u32` LE value; see [`FileType`](#filetype)) |
| `size` | `u64` |
| `modified` | `u64` (seconds since the Unix epoch) |
| `mtime_nanos` | `u32` (nanosecond part of `modified`, `0..1_000_000_000`) |
| `uid` | `u32` (owner uid; `0` where unavailable) |
| `gid` | `u32` (owner gid; `0` where unavailable) |
| `mode` | `u32` |

## Field caps

A frame is bounded at 16 MiB, but a single variable-length field is
not. To bound memory against a hostile peer, an implementation
**SHOULD** reject a decoded message that violates these caps:

| Field | Cap |
|---|---|
| any `path` / `from` / `to`, and each `DirEntry.name` | 4096 bytes (`0x1000`) |
| `ErrorResponse.message` | 1024 bytes (`0x0400`) |
| `Response::DirListing` element count (its `seq<DirEntry>`) | 100000 entries **per page** |

With pagination ([qftp-protocol.md](qftp-protocol.md)), the 100000-entry
cap applies to a single `DirListing` page, not to the whole listing; a
server **SHOULD** additionally split a page that would otherwise exceed
a soft byte budget (the reference server uses ~1 MiB).

## Body streaming

`Get` and `Put` carry raw file bytes on the **same** QUIC stream as
the control messages, immediately after the relevant framed message.
These body bytes are **not** length-prefixed or otherwise framed — the
byte count is carried in the control message, and the QUIC stream FIN
marks the end.

The trailer, when present, is exactly **the negotiated
[`HashAlgorithm`](#hashalgorithm)'s digest length** (BLAKE3 → 32 bytes).
It is raw digest bytes — **not** a framed message — and carries no
length prefix.

### Get

```
client -> server : frame( Request::Get { path, offset, length } )
server -> client : frame( Response::FileReady { size, total_size, checksum_follows, hash_algorithm } )
server -> client : <size> raw body bytes
server -> client : <digest-length trailer>       (only if checksum_follows == true)
                   QUIC stream FIN on the last byte
```

- The server streams exactly `size` body bytes (the post-`offset`,
  post-`length` slice).
- When `size == 0` the body phase is skipped: no body bytes are sent.
  A trailer (if `checksum_follows`) still follows, covering the empty
  body.
- When `checksum_follows` is `true`, a trailer of the
  `hash_algorithm` digest length follows the body: the hash of those
  `size` body bytes (not the whole file). The client **MUST** verify it
  and discard the data on mismatch.
- The QUIC stream **FIN** is set on the last trailer byte when a
  trailer follows, otherwise on the last body byte (or, for `size == 0`
  with no trailer, on the empty stream).
- On error the server sends a single `Response::Err` instead of
  `FileReady` and ends the stream.

### Put

```
client -> server : frame( Request::Put { path, size, mode, offset, hash_algorithm, checksum, no_clobber, checksum_trailer } )
client -> server : <size> raw body bytes
client -> server : <digest-length trailer>       (only if checksum_trailer == true)
                   QUIC stream FIN on the last byte
server -> client : frame( Response::Ok ) | frame( Response::Err( ErrorResponse ) )
```

- The client streams exactly `size` body bytes. When `size == 0` the
  body phase is skipped.
- The QUIC stream **FIN** is set on the last trailer byte when a
  trailer follows, otherwise on the last body byte.
- When `checksum_trailer` is `true`, a trailer of the `hash_algorithm`
  digest length (the hash of the full file) follows the body. The
  server **MUST** treat the trailer as complete only when it receives
  the full digest length; a trailer cut short by FIN is **not** a
  silent fallback to the header `checksum` but an error,
  [`UploadTruncated`](error-codes.md). When present and complete, the
  trailer takes precedence over the header `checksum` field.
  Checksum-resolution semantics are in
  [qftp-protocol.md](qftp-protocol.md).

## Worked example

`Request::Ls { path: "docs", cursor: None }` — vector `ls` in
[`test-vectors/requests.json`](../test-vectors/requests.json):

```
00 00 00 11                                  frame length  = u32 BE 17
00 00 00 00                                  Request discriminant = 0 (Ls)
04 00 00 00 00 00 00 00                      path length    = u64 LE 4
64 6f 63 73                                  path           = "docs"
00                                           cursor         = Option tag 0 (None)
```

Total on the wire: `4 + 17 = 21` bytes;
`wire_hex = "00000011000000000400000000000000646f637300"`.

Every `Request`, `Response`, and `ErrorCode` variant has a
corresponding entry in [`test-vectors/`](../test-vectors/) with both
`wire_hex` (the full frame) and `payload_hex` (the payload without the
4-byte prefix). A second implementation validates against those; see
[test-vectors/README.md](../test-vectors/README.md).
