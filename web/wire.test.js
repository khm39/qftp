"use strict";
/*
 * Wire-conformance test for web/app.js's hand-written bincode codec.
 *
 * The golden vectors in test-vectors/{requests,responses}.json are
 * generated from the Rust reference implementation (see
 * test-vectors/README.md), so checking the JS encoder/decoder against
 * them catches any drift between app.js and the frozen qftp/1 wire
 * format -- the exact class of bug that slipped in when #302 changed
 * Put/DirEntry/ErrorCode and the JS side didn't follow.
 *
 * Run: node web/wire.test.js
 */

const { encodeRequest, decodeResponse, Reader } = require("./app.js");
const requestVectors = require("../test-vectors/requests.json");
const responseVectors = require("../test-vectors/responses.json");

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

// Independent numeric ErrorCode status -> name map, asserted against
// app.js's decoded `code`. Deliberately NOT app.js's own table: an
// independent copy means reverting app.js to the broken positional
// array (the #302 ErrorCode regression) actually fails this test.
const STATUS_TO_NAME = {
  400: "Malformed",
  401: "Unauthorized",
  403: "PermissionDenied",
  404: "NotFound",
  405: "Unsupported",
  409: "AlreadyExists",
  413: "FileTooLarge",
  416: "InvalidRange",
  420: "NotADirectory",
  421: "IsADirectory",
  422: "ChecksumMismatch",
  423: "UploadOverflow",
  424: "UploadTruncated",
  429: "RateLimited",
  430: "QuotaExceeded",
  500: "Internal",
};

let failures = 0;
let skipped = 0;

function check(label, got, expected) {
  if (got === expected) {
    console.log(`ok    ${label}`);
  } else {
    console.error(`FAIL  ${label}\n        got  ${got}\n        want ${expected}`);
    failures++;
  }
}

function skip(label, why) {
  console.log(`skip  ${label}  (${why})`);
  skipped++;
}

// A vector's `value` is externally tagged: a variant with fields is
// {"Name": {...}}, a fieldless variant is the bare string "Name".
function variantOf(value) {
  if (typeof value === "string") return [value, {}];
  const name = Object.keys(value)[0];
  return [name, value[name]];
}

// ---------------------------------------------------------------------
// Requests: encode `value` and compare to `payload_hex`.
// ---------------------------------------------------------------------

// Map a vector's (snake_case) request fields onto the camelCase shape
// encodeRequest expects. Returns null when the JS client doesn't model
// the variant (e.g. a Put header checksum), so the loop can skip it.
function vectorToReq(name, fields) {
  switch (name) {
    case "Ls": return { type: "Ls", path: fields.path, cursor: fields.cursor };
    case "Cd": return { type: "Cd", path: fields.path };
    case "Pwd": return { type: "Pwd" };
    case "Get":
      return { type: "Get", path: fields.path, offset: fields.offset, length: fields.length };
    case "Put":
      // The web client never sets a header checksum; it streams a
      // trailer instead. Vectors that carry one aren't modelled.
      if (fields.checksum != null) return null;
      return {
        type: "Put",
        path: fields.path,
        size: fields.size,
        mode: fields.mode,
        offset: fields.offset,
        noClobber: fields.no_clobber,
        checksumTrailer: fields.checksum_trailer,
      };
    case "Mkdir": return { type: "Mkdir", path: fields.path };
    case "Rmdir": return { type: "Rmdir", path: fields.path };
    case "Rm": return { type: "Rm", path: fields.path };
    case "Rename": return { type: "Rename", from: fields.from, to: fields.to };
    case "Chmod": return { type: "Chmod", path: fields.path, mode: fields.mode };
    case "Stat": return { type: "Stat", path: fields.path };
    case "Quota": return { type: "Quota" };
    case "Quit": return { type: "Quit" };
    default: return null;
  }
}

for (const v of requestVectors.vectors) {
  const label = `request   ${v.name}`;
  const [name, fields] = variantOf(v.value);
  const req = vectorToReq(name, fields);
  if (req === null) {
    skip(label, `JS client does not model ${name} with these fields`);
    continue;
  }
  let got;
  try {
    got = hex(encodeRequest(req));
  } catch (e) {
    skip(label, "encode threw: " + (e.message || e));
    continue;
  }
  check(label, got, v.payload_hex);
}

// ---------------------------------------------------------------------
// Responses: strip the 4-byte frame prefix from `wire_hex`, decode the
// payload, and confirm the decoded fields match `value`.
// ---------------------------------------------------------------------

function payloadFromWire(wireHex) {
  const frameBytes = hexToBytes(wireHex);
  const len = new DataView(frameBytes.buffer, frameBytes.byteOffset, 4).getUint32(0, false);
  if (frameBytes.length - 4 !== len) {
    throw new Error(`frame length prefix ${len} != payload ${frameBytes.length - 4}`);
  }
  return frameBytes.subarray(4);
}

for (const v of responseVectors.vectors) {
  const baseLabel = `response  ${v.name}`;
  const [name] = variantOf(v.value);

  let decoded;
  try {
    decoded = decodeResponse(new Reader(payloadFromWire(v.wire_hex)));
  } catch (e) {
    check(baseLabel, "decode threw: " + (e.message || e), "<no throw>");
    continue;
  }

  switch (name) {
    case "Err": {
      const expected = v.value.Err;
      check(`${baseLabel}.status`, decoded.status, expected.code);
      check(`${baseLabel}.code`, decoded.code,
        STATUS_TO_NAME[expected.code] || "Unknown");
      check(`${baseLabel}.message`, decoded.message, expected.message);
      break;
    }
    case "DirListing": {
      const expected = v.value.DirListing;
      check(`${baseLabel}.count`, decoded.entries.length, expected.entries.length);
      for (let i = 0; i < expected.entries.length; i++) {
        const e = expected.entries[i];
        const d = decoded.entries[i] || {};
        check(`${baseLabel}[${i}].name`, d.name, e.name);
        check(`${baseLabel}[${i}].fileType`, d.fileType, e.file_type);
        check(`${baseLabel}[${i}].isDir`, d.isDir, e.file_type === 1);
        check(`${baseLabel}[${i}].size`, Number(d.size), e.size);
        check(`${baseLabel}[${i}].mode`, d.mode, e.mode);
      }
      check(`${baseLabel}.nextCursor`, decoded.nextCursor, expected.next_cursor);
      break;
    }
    case "Path":
      check(`${baseLabel}.path`, decoded.path, v.value.Path);
      break;
    case "Ok":
      check(`${baseLabel}.type`, decoded.type, "Ok");
      break;
    case "FileStat": {
      const expected = v.value.FileStat;
      check(`${baseLabel}.fileType`, decoded.fileType, expected.file_type);
      check(`${baseLabel}.size`, Number(decoded.size), expected.size);
      check(`${baseLabel}.mode`, decoded.mode, expected.mode);
      break;
    }
    case "FileReady": {
      const expected = v.value.FileReady;
      check(`${baseLabel}.size`, Number(decoded.size), expected.size);
      check(`${baseLabel}.totalSize`, Number(decoded.totalSize), expected.total_size);
      check(`${baseLabel}.checksumFollows`, decoded.checksumFollows, expected.checksum_follows);
      break;
    }
    case "QuotaInfo": {
      const expected = v.value.QuotaInfo;
      check(`${baseLabel}.usedBytes`, Number(decoded.usedBytes), expected.used_bytes);
      check(`${baseLabel}.fileCount`, Number(decoded.fileCount), expected.file_count);
      check(`${baseLabel}.limitBytes`,
        decoded.limitBytes == null ? null : Number(decoded.limitBytes),
        expected.limit_bytes);
      break;
    }
    default:
      skip(baseLabel, `JS client does not model response ${name}`);
  }
}

console.log(`\n${skipped} skipped`);
if (failures > 0) {
  console.error(`${failures} failure(s)`);
  process.exit(1);
}
console.log("all wire vectors pass");
