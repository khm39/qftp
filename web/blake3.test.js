"use strict";
/*
 * Regression test for web/blake3.js -- the SPA's pure-JavaScript
 * BLAKE3. The expected digests were produced by the Rust `blake3`
 * crate, i.e. the exact implementation the qftp server and web bridge
 * verify uploads against, over the standard BLAKE3 test-vector input
 * (byte i = i % 251).
 *
 * Run: node web/blake3.test.js
 */

const { Blake3, blake3 } = require("./blake3.js");

/** The standard BLAKE3 test-vector input: byte i is `i % 251`. */
function patternInput(len) {
  const a = new Uint8Array(len);
  for (let i = 0; i < len; i++) a[i] = i % 251;
  return a;
}

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// length -> expected unkeyed BLAKE3-256 hex digest.
const VECTORS = {
  0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
  1: "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
  63: "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
  64: "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
  65: "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
  1023: "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
  1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
  1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
  2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
  3000: "5fade288bf27444bee55ba2babb98c3c922c1e84c2e445e7d1f6da24756f5060",
  70000: "5a8ef06db0fc4e6c27f6e4a44e333916934b860d747d8d65f56df4597f0421bf",
};

// Irregular chunk sizes for the streaming test -- straddle block
// (64-byte) and chunk (1024-byte) boundaries so the incremental path
// is exercised, not just whole-buffer hashing.
const CHUNK_SIZES = [1, 7, 63, 64, 65, 200, 511, 1000];

let failures = 0;
function check(label, got, expected) {
  if (got === expected) {
    console.log(`ok    ${label}`);
  } else {
    console.error(`FAIL  ${label}\n        got  ${got}\n        want ${expected}`);
    failures++;
  }
}

for (const [lenStr, expected] of Object.entries(VECTORS)) {
  const len = Number(lenStr);
  const input = patternInput(len);

  check(`one-shot   len=${len}`, hex(blake3(input)), expected);

  const h = new Blake3();
  for (let off = 0, si = 0; off < len; si++) {
    const take = Math.min(CHUNK_SIZES[si % CHUNK_SIZES.length], len - off);
    h.update(input.subarray(off, off + take));
    off += take;
  }
  check(`streaming  len=${len}`, hex(h.digest()), expected);
}

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall blake3.js vectors pass");
