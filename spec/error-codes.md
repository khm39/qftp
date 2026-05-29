# qftp/1 error codes

Part of the **qftp/1 specification** ([spec/](README.md)).

`Response::Err` carries an [`ErrorResponse`](wire-format.md#errorresponse)
whose `code` field is an `ErrorCode`: a machine-readable category that
scripts and recursive transfers branch on instead of parsing the
human-readable `message`. On the wire, `code` is a **`u32`
little-endian discriminant** (see
[wire-format.md](wire-format.md#primitive-encodings)).

The key words **MUST**, **SHOULD**, **MAY** are to be interpreted as
described in RFC 2119.

## Registry

This is the registry of assigned code points for `qftp/1`. The numeric
value is the on-wire discriminant and is fixed; it **MUST NOT** be
reused or reassigned. Each code is exercised by a golden vector in
[`test-vectors/error-codes.json`](../test-vectors/error-codes.json).

| Code | Name | Meaning |
|---|---|---|
| `0` | `NotFound` | Path resolution found no such file or directory. |
| `1` | `PermissionDenied` | An ACL or filesystem permission check refused the operation. |
| `2` | `AlreadyExists` | The destination exists and the operation requires that it not (e.g. `Put` with `no_clobber`). |
| `3` | `NotADirectory` | A directory was expected but the path is a regular file. |
| `4` | `IsADirectory` | A regular file was expected but the path is a directory. |
| `5` | `FileTooLarge` | The payload exceeds the server's configured maximum file size. |
| `6` | `UploadOverflow` | The peer sent more body bytes than its `Put` declared in `size`. |
| `7` | `UploadTruncated` | The peer sent the stream FIN before delivering its declared `size` body bytes. |
| `8` | `ChecksumMismatch` | BLAKE3 verification of the transferred bytes failed. |
| `9` | `RateLimited` | The per-request rate limit on the connection refused this request. |
| `10` | `Malformed` | The frame or its payload could not be decoded (see [versioning.md](versioning.md)). |
| `11` | `Internal` | A server-side I/O error or an otherwise unexpected internal failure. |
| `12` | `Unauthorized` | Authentication failed or the user is not configured. |
| `13` | `InvalidRange` | A resume `offset` (or `Get` range) is not valid for this file. |
| `14` | `Unsupported` | The operation is not supported in the current context (e.g. a mutation arriving as 0-RTT early data; see [qftp-protocol.md](qftp-protocol.md#0-rtt-session-resumption)). |
| `15` | `QuotaExceeded` | The operation would push the user past their configured storage quota. |

## Unknown codes

The registry is expected to grow in later `qftp/1` minor revisions. New
codes are assigned the next unused value, appended to the end of the
table; assigned values are never changed.

Because the wire encoding is positional and not self-describing
([versioning.md](versioning.md)), a decoder built before a code was
assigned cannot map that discriminant to a known name. Such an
implementation:

- **MUST NOT** crash on an unrecognised `code` value, and
- **SHOULD** present it to the user as a generic failure equivalent to
  `Internal` (code `11`), preserving the accompanying `message`.

Because adding a code is a change an older peer cannot fully decode,
introducing a new `ErrorCode` is a wire change: it **MUST** be recorded
in [PROTOCOL-CHANGELOG.md](../PROTOCOL-CHANGELOG.md) and accompanied by
a new vector in [`test-vectors/`](../test-vectors/).
