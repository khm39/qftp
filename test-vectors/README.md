# qftp/1 conformance test vectors

Golden encodings of every `qftp/1` control message. They let any
implementation check its encoder and decoder against the reference
implementation **without depending on Rust or bincode**. The byte
layout these vectors exercise is specified in
[`spec/wire-format.md`](../spec/wire-format.md).

## Files

| File | Contents |
|---|---|
| `requests.json` | One vector per `Request` variant (plus a few field-presence variations for the optional `Get`/`Put` fields). |
| `responses.json` | One vector per `Response` variant (plus empty/default edge cases). |
| `error-codes.json` | One `Response::Err` per `ErrorCode`, with an empty message, so the on-wire discriminant of every code is pinned. |

Each file is a JSON object:

```json
{
  "protocol": "qftp/1",
  "kind": "Request",
  "note": "...",
  "vectors": [ { ...vector... }, ... ]
}
```

## Vector schema

Each entry in `vectors` has:

| Field | Meaning |
|---|---|
| `name` | Stable identifier, referenced from the spec. |
| `description` | Human-readable summary. |
| `value` | The decoded message as JSON (see [Value representation](#value-representation)). |
| `payload_hex` | The encoded payload, lowercase hex, **without** the 4-byte frame prefix. |
| `wire_hex` | The full frame: 4-byte big-endian length prefix followed by the payload, lowercase hex. `wire_hex` always equals the prefix plus `payload_hex`. |

## How to use them

A conforming implementation **MUST** pass both directions for every
vector:

1. **Decode:** hex-decode `wire_hex`, decode it as a frame per
   [`wire-format.md`](../spec/wire-format.md), and confirm the result
   equals `value`.
2. **Encode:** encode `value` and confirm the bytes equal `wire_hex`.

The reference implementation runs exactly these two checks in
`crates/qftp-conformance/tests/conformance.rs`.

## Value representation

`value` is a JSON rendering of the message, chosen to be readable and
unambiguous. It is a *decoding aid*; the bytes (`wire_hex`) are
authoritative.

- **Enums are externally tagged.** A variant with fields is
  `{"VariantName": { ...fields... }}` (e.g.
  `{"Ls": {"path": "docs"}}`); a variant with a single unnamed payload
  is `{"VariantName": payload}` (e.g. `{"Path": "/srv"}`); a fieldless
  variant is the bare string `"VariantName"` (e.g. `"Pwd"`).
- **JSON object key order is not significant.** The wire field order is
  fixed by [`wire-format.md`](../spec/wire-format.md) and may differ
  from the (alphabetical) key order a JSON serializer emits. For
  example `Get`'s wire order is `path, offset, length`, but the JSON
  object may list them alphabetically.
- **`Option<T>`** is the value when present and JSON `null` when absent.
- **`[u8; 32]`** (the `Put` header checksum) is a JSON array of 32
  integers in `0..=255`.
- **Integers** are JSON numbers; all fit in a 64-bit unsigned range.

## Regenerating

The vectors are generated from the reference implementation:

```sh
cargo run -p qftp-conformance --bin gen-vectors
```

CI regenerates them and fails if the working tree changes, so any
unintended change to the bytes on the wire is caught. **Do not edit
these files by hand.**
