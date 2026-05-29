# Proposal: qftp/1.0 coordinated wire freeze

**Status: DRAFT for review.** This proposal batches every *now-or-never*
breaking wire change into one coordinated revision before the 1.0
freeze, so that post-1.0 additions don't each require an ALPN major
bump. It builds on the spec-first migration (#298). All changes here
are wire-breaking but acceptable: qftp is pre-1.0 and nothing is
deployed against the current wire.

Decisions already made by the maintainer:

- **Status code width: `u32`** (consistency with every other wire
  integer; the 2-byte saving of `u16` only matters on rare error
  frames and a lone `u16` adds to the endianness/width footgun).
- **Freeze batch: all three breaking extensions** — richer
  `DirEntry`/`FileStat`, directory pagination, hash-algorithm agility —
  plus the compatible improvements.

Open sub-choices flagged inline with **❓CONFIRM**.

---

## 1. Status codes (`ErrorCode` → numeric `u32`)

`ErrorResponse.code` becomes a **`u32` numeric status** (was a
positional bincode enum index). Class structure mirrors HTTP:

- `2xx` success, `4xx` caller-caused, `5xx` server-caused.
- `200` = success, conveyed by `Response::Ok` (not carried in `code`).

Registry (all `u32` LE):

| Code | Name | Class |
|---|---|---|
| 400 | Malformed | client |
| 401 | Unauthorized | client |
| 403 | PermissionDenied | client |
| 404 | NotFound | client |
| 405 | Unsupported | client |
| 409 | AlreadyExists | client |
| 413 | FileTooLarge | client |
| 416 | InvalidRange | client |
| 420 | NotADirectory | client |
| 421 | IsADirectory | client |
| 422 | ChecksumMismatch | client |
| 423 | UploadOverflow | client |
| 424 | UploadTruncated | client |
| 429 | RateLimited | client |
| 430 | QuotaExceeded | client |
| 500 | Internal | server |

- Rust: `ErrorCode` keeps named variants **plus `Unknown(u32)`**;
  custom `Serialize`/`Deserialize` read/write a `u32`; `to_u32`/
  `from_u32`; `class()` → `Client`/`Server` by leading digit.
- **Unknown codes now decode** (→ `Unknown(n)`, classified by range);
  this removes the qftp/1 "unknown ErrorCode = Malformed" rule.
  `versioning.md` and `error-codes.md` updated accordingly.

## 2. Structured error details (`ErrorResponse.details`)

`ErrorResponse { code: u32, message: string, details: Option<ErrorDetails> }`.
`ErrorDetails` is a `u32`-tagged, `#[non_exhaustive]` enum:

| Tag | Variant | Fields | Used by |
|---|---|---|---|
| 0 | `Range` | `offset: u64`, `file_size: u64` | InvalidRange |
| 1 | `Upload` | `received: u64`, `declared: u64` | UploadOverflow / UploadTruncated |
| 2 | `RetryAfter` | `millis: u32` | RateLimited |

`message` is operator/developer-facing diagnostics: English, **not**
localized, **not** for end-user display. A **retryability table** goes
in `error-codes.md` (MUST_NOT_RETRY for permanent 4xx; SHOULD_RETRY
with backoff+jitter for 429/500; `Unsupported` from a 0-RTT refusal is
retried *immediately* after the handshake).

## 3. Richer `DirEntry` / `FileStat`

Replace `is_dir: bool` with an explicit `file_type`, and add
sub-second time + ownership:

`FileType` enum (`u32`): `Regular=0`, `Directory=1`, `Symlink=2`, `Other=3`.

```
DirEntry { name: string, file_type: u32, size: u64,
           modified: u64, mtime_nanos: u32, uid: u32, gid: u32, mode: u32 }
FileStat { file_type: u32, size: u64,
           modified: u64, mtime_nanos: u32, uid: u32, gid: u32, mode: u32 }
```

- `mtime_nanos` ∈ `0..1_000_000_000` (nanosecond part of `modified`).
- `uid`/`gid` are `0` where unavailable (e.g. Windows).
- A helper `is_dir()` = `file_type == Directory` keeps call sites tidy.
- **❓CONFIRM:** remove `is_dir` entirely (vs keep it alongside
  `file_type`). Proposal: remove — `file_type` subsumes it and pre-1.0
  is the moment to drop redundancy.

## 4. Directory pagination

```
Request::Ls    { path: string, cursor: Option<string> }
Response::DirListing { entries: seq<DirEntry>, next_cursor: Option<string> }
```

- `cursor` is **opaque, server-defined** (the server encodes its scan
  position; clients echo it back verbatim). `None` = first page.
- `next_cursor = Some(..)` → more pages follow; `None` → last page.
- Per-page limits are implementation-defined (the 100000-entry cap
  becomes per-page); servers SHOULD also apply a ~1 MiB soft byte cap
  per page.
- `Response::DirListing` changes from a bare `seq<DirEntry>` to a
  struct with `entries` + `next_cursor`.

## 5. Hash-algorithm agility

`HashAlgorithm` enum (`u32`): `Blake3=0` (the only algorithm in 1.0).

```
Request::Put       { ..., hash_algorithm: u32, checksum: Option<seq<u8>>, ... }
Response::FileReady { size: u64, total_size: u64, checksum_follows: bool, hash_algorithm: u32 }
```

- The header `checksum` and the streamed trailer are **digest bytes
  whose length is the algorithm's digest length** (BLAKE3 → 32). The
  fixed `[u8; 32]` becomes a variable `seq<u8>` sized by the algorithm.
- A future algorithm is added as a new `HashAlgorithm` value; the
  trailer length follows from it. (Adding a value is still a wire
  concern, but the negotiation field now exists.)
- **❓CONFIRM:** `checksum: Option<seq<u8>>` (variable, agile) vs keep
  `Option<[u8; 32]>` (BLAKE3-locked). Proposal: variable, to make the
  agility real.

## 6. Compatible improvements (no new break, included in the freeze)

- **Framing/FIN:** Put diagram fixed (FIN on the last *trailer* byte
  when a trailer follows; on the last body byte otherwise); `size = 0`
  skips the body phase; a trailer is complete only at full digest
  length, else `UploadTruncated` (never silently fall back to the
  header checksum).
- **Checksum/resume:** Get-trailer hashes the post-offset suffix; Put
  hashes the full file (incl. the re-hashed prefix on resume); add an
  `offset > 0` golden vector. `total_size` is the true full size; a
  shrink mid-resume → `InvalidRange`. Forbid `checksum_follows = false`
  on a resumed Get.
- **Discriminant locking:** a conformance test asserts every variant's
  on-wire bytes against `test-vectors/` (serde rename does *not* bind
  bincode discriminants).
- **Endianness section** in `wire-format.md` (frame length BE, all
  payload ints LE — called out prominently).
- **Security/DoS:** release in-flight quota + delete partial on
  abort/timeout; per-stream upload timeout; enforce peer cert at the
  TLS layer; raise retry-token HMAC to ≥20 bytes; document the
  WebTransport bearer-token query-string logging risk in `SECURITY.md`.
- **Docs:** one "implementation-defined transport parameters" table
  (max-streams=4, idle=30s, flow windows, pacing, no keepalive,
  stream-ID correlation); path encoding (UTF-8 only, lossy otherwise),
  case/normalization implementation-defined, max path depth; the 1 GiB
  file-size limit documented as implementation-defined; 1.0 freeze
  stamp + date in `spec/README.md`.

## Final discriminants (all `u32` LE, locked by conformance test)

`Request`: `Ls=0, Cd=1, Pwd=2, Get=3, Put=4, Mkdir=5, Rmdir=6, Rm=7,
Rename=8, Chmod=9, Stat=10, Quota=11, Quit=12`.

`Response`: `Ok=0, Err=1, DirListing=2, Path=3, FileStat=4,
FileReady=5, QuotaInfo=6`.

## Out of scope (deferred to qftp/2)

Self-describing encoding (CBOR/Protobuf), varint integers, in-band
capability negotiation, per-control-message MAC / signed manifests,
`Copy`/`Symlink`/`Transaction` operations. Recorded in
`PROTOCOL-CHANGELOG.md` as future directions.

---

## Implementation plan (on sign-off)

A Workflow in this order (core types first — they're the coupling
point — then parallel dependents, then review):

1. **Core (`crates/qftp-common/src/protocol.rs`):** the new enums,
   `ErrorCode`/`HashAlgorithm`/`FileType`/`ErrorDetails`, custom serde,
   updated `Request`/`Response`/`DirEntry`/`FileStat`, `validate_*`.
2. **Dependents (parallel by crate):** handler/server/client/web-bridge
   call sites; spec docs (`wire-format.md`, `error-codes.md`,
   `versioning.md`, `qftp-protocol.md`); `gen-vectors` sample updates.
3. **Regenerate `test-vectors/` + conformance + build/clippy/fmt.**
4. **Review** (multi-lens: byte-accuracy vs vectors, spec/impl
   consistency, compile/call-site correctness, DoD).
5. `PROTOCOL-CHANGELOG.md` entry; bump nothing (still `qftp/1`,
   pre-release).
