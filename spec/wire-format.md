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
| enum discriminant | `u32` little-endian. Variants are numbered from `0` in declaration order (see each enum's table). |
| `Option<T>` | 1 tag byte: `0x00` = none (nothing follows), `0x01` = some, followed by the encoding of `T`. A decoder **MUST** reject any other tag value. |
| `string` | a `u64` little-endian **byte** length `n`, then exactly `n` bytes of **UTF-8**. |
| `seq<T>` (variable array) | a `u64` little-endian element count `n`, then `n` encodings of `T`. |
| `[u8; N]` (fixed array) | exactly `N` raw bytes, with **no** length prefix. |
| struct | the encodings of its fields concatenated in declaration order. |
| enum value | the variant discriminant (`u32` LE), then the encodings of that variant's fields (if any) in declaration order. |

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
| `0` | `Ls` | `path: string` |
| `1` | `Cd` | `path: string` |
| `2` | `Pwd` | *(none)* |
| `3` | `Get` | `path: string`, `offset: u64`, `length: Option<u64>` |
| `4` | `Put` | `path: string`, `size: u64`, `mode: u32`, `offset: u64`, `checksum: Option<[u8; 32]>`, `no_clobber: bool`, `checksum_trailer: bool` |
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
| `2` | `DirListing` | `seq<DirEntry>` (see [`DirEntry`](#direntry)) |
| `3` | `Path` | `string` |
| `4` | `FileStat` | one [`FileStat`](#filestat) |
| `5` | `FileReady` | `size: u64`, `total_size: u64`, `checksum_follows: bool` |
| `6` | `QuotaInfo` | `used_bytes: u64`, `file_count: u64`, `limit_bytes: Option<u64>` |

### ErrorResponse

A struct, used only inside `Response::Err`.

| Field (wire order) | Type |
|---|---|
| `code` | `ErrorCode` (a `u32` little-endian discriminant; see [error-codes.md](error-codes.md)) |
| `message` | `string` (human-readable; **SHOULD** be ≤ 1 KiB, see [§ Field caps](#field-caps)) |

### DirEntry

A struct, carried in `Response::DirListing`.

| Field (wire order) | Type |
|---|---|
| `name` | `string` (a single path component; **MUST NOT** contain `/`, `\`, or NUL, and **MUST NOT** be `.` or `..`) |
| `is_dir` | `bool` |
| `size` | `u64` |
| `modified` | `u64` (seconds since the Unix epoch) |
| `mode` | `u32` (POSIX permission bits; synthesized on platforms without them) |

### FileStat

A struct, carried in `Response::FileStat`. **Note the field order
differs from `DirEntry`**: `is_dir` follows `size` here.

| Field (wire order) | Type |
|---|---|
| `size` | `u64` |
| `is_dir` | `bool` |
| `modified` | `u64` (seconds since the Unix epoch) |
| `mode` | `u32` |

## Field caps

A frame is bounded at 16 MiB, but a single variable-length field is
not. To bound memory against a hostile peer, an implementation
**SHOULD** reject a decoded message that violates these caps:

| Field | Cap |
|---|---|
| any `path` / `from` / `to`, and each `DirEntry.name` | 4096 bytes (`0x1000`) |
| `ErrorResponse.message` | 1024 bytes (`0x0400`) |
| `Response::DirListing` element count (its `seq<DirEntry>`) | 100000 entries |

## Body streaming

`Get` and `Put` carry raw file bytes on the **same** QUIC stream as
the control messages, immediately after the relevant framed message.
These body bytes are **not** length-prefixed or otherwise framed — the
byte count is carried in the control message, and the QUIC stream FIN
marks the end.

### Get

```
client -> server : frame( Request::Get { path, offset, length } )
server -> client : frame( Response::FileReady { size, total_size, checksum_follows } )
server -> client : <size> raw body bytes
server -> client : <32-byte BLAKE3 trailer>      (only if checksum_follows == true)
                   QUIC stream FIN on the last byte
```

- The server streams exactly `size` body bytes (the post-`offset`,
  post-`length` slice).
- When `checksum_follows` is `true`, exactly **32 raw bytes** follow
  the body: the BLAKE3 hash of those `size` body bytes (not the whole
  file). The client **MUST** verify it and discard the data on
  mismatch.
- On error the server sends a single `Response::Err` instead of
  `FileReady` and ends the stream.

### Put

```
client -> server : frame( Request::Put { path, size, mode, offset, checksum, no_clobber, checksum_trailer } )
client -> server : <size> raw body bytes
                   QUIC stream FIN on the last byte
client -> server : <32-byte BLAKE3 trailer>      (only if checksum_trailer == true)
server -> client : frame( Response::Ok ) | frame( Response::Err( ErrorResponse ) )
```

- The client streams exactly `size` body bytes.
- When `checksum_trailer` is `true`, exactly **32 raw bytes** (the
  BLAKE3 hash of the full file) follow the body. When present and
  complete, the trailer takes precedence over the header `checksum`
  field. Checksum-resolution semantics are in
  [qftp-protocol.md](qftp-protocol.md).

The 32-byte trailers are raw hash bytes — they are **not** a framed
message and carry no length prefix.

## Worked example

`Request::Ls { path: "docs" }` — vector `ls` in
[`test-vectors/requests.json`](../test-vectors/requests.json):

```
00 00 00 10                                  frame length  = u32 BE 16
00 00 00 00                                  Request discriminant = 0 (Ls)
04 00 00 00 00 00 00 00                      path length    = u64 LE 4
64 6f 63 73                                  path           = "docs"
```

Total on the wire: `4 + 16 = 20` bytes;
`wire_hex = "00000010000000000400000000000000646f6373"`.

Every `Request`, `Response`, and `ErrorCode` variant has a
corresponding entry in [`test-vectors/`](../test-vectors/) with both
`wire_hex` (the full frame) and `payload_hex` (the payload without the
4-byte prefix). A second implementation validates against those; see
[test-vectors/README.md](../test-vectors/README.md).
