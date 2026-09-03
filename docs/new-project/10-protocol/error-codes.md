# qftp/1 error codes

Part of the **qftp/1 specification** ([README.md](README.md)).

`Response::Err` carries an [`ErrorResponse`](wire-format.md#errorresponse)
whose `code` field is an `ErrorCode`: a machine-readable category that
scripts and recursive transfers branch on instead of parsing the
human-readable `message`. On the wire, `code` is a **numeric `u32`
status value**, little-endian — an explicitly assigned code point, not a
positional discriminant index (see
[wire-format.md](wire-format.md#primitive-encodings)).

The key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be
interpreted as described in RFC 2119.

## Status classes

The numeric space mirrors HTTP, so the leading digit carries the
who-caused-it classification with no lookup table:

- **`2xx` — success.** Conveyed by `Response::Ok` (the `200` "success"
  status is *not* carried in an `ErrorResponse.code`; a success is never
  an `Err`).
- **`4xx` — client class.** The caller's request caused the failure;
  the operation will not succeed if retried unchanged.
- **`5xx` — server class.** A server-side or transient condition caused
  the failure; an identical retry may succeed.

The classification a decoder reports for a code is its
class — `class()` in the reference implementation: leading digit `4` →
client, leading digit `5` → server, anything else → server (the
conservative default for an unrecognised range).

## Registry

This is the registry of assigned code points for `qftp/1`. The numeric
value is the on-wire status and is fixed; it **MUST NOT** be reused or
reassigned. Each code is exercised by a golden vector in
[`test-vectors/error-codes.json`](test-vectors/error-codes.json).

| Code | Name | Class | Meaning |
|---|---|---|---|
| `400` | `Malformed` | client | The frame or its payload could not be decoded (see [versioning.md](versioning.md)). |
| `401` | `Unauthorized` | client | Authentication failed or the user is not configured. |
| `403` | `PermissionDenied` | client | An ACL or filesystem permission check refused the operation. |
| `404` | `NotFound` | client | Path resolution found no such file or directory. |
| `405` | `Unsupported` | client | The operation is not supported in the current context (e.g. a mutation arriving as 0-RTT early data; see [qftp-protocol.md](qftp-protocol.md#0-rtt-session-resumption)). |
| `409` | `AlreadyExists` | client | The destination exists and the operation requires that it not (e.g. `Put` with `no_clobber`). |
| `413` | `FileTooLarge` | client | The payload exceeds the server's configured maximum file size. |
| `416` | `InvalidRange` | client | A resume `offset` (or `Get` range) is not valid for this file. |
| `420` | `NotADirectory` | client | A directory was expected but the path is a regular file. |
| `421` | `IsADirectory` | client | A regular file was expected but the path is a directory. |
| `422` | `ChecksumMismatch` | client | Content-hash verification of the transferred bytes failed. |
| `423` | `UploadOverflow` | client | The peer sent more body bytes than its `Put` declared in `size`. |
| `424` | `UploadTruncated` | client | The peer sent the stream FIN before delivering its declared `size` body bytes (or before completing the digest trailer). |
| `429` | `RateLimited` | client | The per-request rate limit on the connection refused this request. |
| `430` | `QuotaExceeded` | client | The operation would push the user past their configured storage quota. |
| `431` | `DecodeError` | client | A compressed body could not be decoded (malformed codec frame or window exceeding the negotiated maximum). |
| `500` | `Internal` | server | A server-side I/O error or an otherwise unexpected internal failure. |

## The `message` field

`ErrorResponse.message` is operator/developer-facing diagnostics: a
fixed, **English**, **non-localized** string, **not** intended for
end-user display and **not** to be parsed by machine logic. Clients
**MUST** branch on `code` (and, where present, on
[`details`](wire-format.md#errordetails)), never on `message` text. An
implementation MAY surface `message` in logs or to operators verbatim.

## Retryability

Whether a failed request should be retried follows from its class, with
two named exceptions. Clients **MUST** observe the following:

| Codes | Disposition | Retry policy |
|---|---|---|
| All `4xx` except `429` and `405`-from-0-RTT | `MUST_NOT_RETRY` | The request is permanently rejected as sent; retrying it unchanged will fail identically. The client **MUST NOT** retry. |
| `429` `RateLimited` | `SHOULD_RETRY` | Retry after a backoff with jitter. When `details` carries [`RetryAfter { millis }`](wire-format.md#errordetails), the client **SHOULD** wait at least that long before the first retry. |
| `500` `Internal` (and any `5xx`) | `SHOULD_RETRY` | Transient; retry after a backoff with jitter. |
| `405` `Unsupported` returned for a request refused as **0-RTT early data** | retry **immediately** | The refusal is purely because the request arrived as 0-RTT; once the 1-RTT handshake completes, the same request is valid. The client **SHOULD** replay it immediately after the handshake, with no backoff (the reference client does this transparently). See [qftp-protocol.md](qftp-protocol.md#0-rtt-session-resumption). |

`405` `Unsupported` returned for any other reason (a genuinely
unsupported operation) is `MUST_NOT_RETRY` like the rest of the `4xx`
class.

## Unknown codes

The registry is expected to grow in later `qftp/1` minor revisions. New
codes are assigned an unused numeric value in the appropriate class
range; assigned values are never changed.

Because `code` is a self-describing numeric value rather than a
positional discriminant, a code a decoder does not have a named variant
for **decodes successfully** as an unknown status `Unknown(n)` — it does
**not** make the `ErrorResponse` undecodable, and a decoder **MUST NOT**
reject the frame on that account (this is the change from earlier
`qftp/1`, which treated an unknown code as `Malformed`). The decoder
**MUST** classify an unknown code by its leading digit (`4xx` → client,
`5xx` → server, otherwise server) and **MUST** preserve the accompanying
`message`, so a client can apply the retryability rule above by class
even for a code it has never seen.

Adding a new `ErrorCode` is therefore **forward-compatible**: an older
peer still decodes the frame and classifies the code by range, so it is
**not** a major-version break (unlike adding a `Request`/`Response`
variant; see [versioning.md](versioning.md)). It remains a documented
wire addition: a new code **MUST** be recorded in
[protocol-changelog.md](protocol-changelog.md) and accompanied by a
new vector in [`test-vectors/`](test-vectors/).
