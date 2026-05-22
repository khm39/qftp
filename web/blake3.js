"use strict";
/*
 * Minimal pure-JavaScript BLAKE3 -- hash mode, 256-bit output.
 *
 * A faithful port of the official BLAKE3 reference implementation
 * (reference_impl.py from the BLAKE3 repository): one chunk is 1024
 * bytes = 16 compressed 64-byte blocks, and chunks form the leaves of a
 * binary Merkle tree. Only the unkeyed `hash` mode is implemented --
 * that is all the qftp wire protocol needs (a 32-byte integrity
 * trailer after a Get/Put body).
 *
 * The compression function uses only 32-bit add / xor / rotate, so it
 * is exact in JavaScript: every value is kept in a Uint32Array (stores
 * are reduced mod 2^32 automatically) and intermediate sums stay well
 * inside Number's 2^53 safe-integer range.
 *
 * Correctness is pinned against the Rust `blake3` crate's output in
 * web/blake3.test.js.
 */

const OUT_LEN = 32;
const BLOCK_LEN = 64;
const CHUNK_LEN = 1024;

const CHUNK_START = 1 << 0;
const CHUNK_END = 1 << 1;
const PARENT = 1 << 2;
const ROOT = 1 << 3;

const IV = Uint32Array.of(
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
);

const MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/** Rotate a 32-bit word right by `n` bits. */
function rotr(x, n) {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

/** The BLAKE3 quarter-round mixing function, applied in place. */
function g(state, a, b, c, d, mx, my) {
  state[a] = (state[a] + state[b] + mx) >>> 0;
  state[d] = rotr(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b] + my) >>> 0;
  state[d] = rotr(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotr(state[b] ^ state[c], 7);
}

/** One round: four column mixes then four diagonal mixes. */
function roundFn(state, m) {
  g(state, 0, 4, 8, 12, m[0], m[1]);
  g(state, 1, 5, 9, 13, m[2], m[3]);
  g(state, 2, 6, 10, 14, m[4], m[5]);
  g(state, 3, 7, 11, 15, m[6], m[7]);
  g(state, 0, 5, 10, 15, m[8], m[9]);
  g(state, 1, 6, 11, 12, m[10], m[11]);
  g(state, 2, 7, 8, 13, m[12], m[13]);
  g(state, 3, 4, 9, 14, m[14], m[15]);
}

/** Apply the fixed message permutation, returning a fresh word array. */
function permute(m) {
  const out = new Uint32Array(16);
  for (let i = 0; i < 16; i++) out[i] = m[MSG_PERMUTATION[i]];
  return out;
}

/** Compress one block; returns the 16-word output state. */
function compress(cv, blockWords, counter, blockLen, flags) {
  const state = Uint32Array.of(
    cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
    IV[0], IV[1], IV[2], IV[3],
    counter >>> 0, Math.floor(counter / 0x100000000) >>> 0, blockLen, flags,
  );
  let m = blockWords;
  for (let r = 0; r < 7; r++) {
    roundFn(state, m);
    if (r < 6) m = permute(m);
  }
  for (let i = 0; i < 8; i++) {
    state[i] ^= state[i + 8];
    state[i + 8] ^= cv[i];
  }
  return state;
}

/** Read a 64-byte block (zero-padded) as 16 little-endian u32 words. */
function wordsFromBlock(block) {
  const words = new Uint32Array(16);
  const dv = new DataView(block.buffer, block.byteOffset, block.byteLength);
  for (let i = 0; i < 16; i++) words[i] = dv.getUint32(i * 4, true);
  return words;
}

/** The 8-word chaining value of an Output node. */
function outputChainingValue(o) {
  return compress(o.icv, o.blockWords, o.counter, o.blockLen, o.flags).slice(0, 8);
}

/** Build the parent Output node combining two child chaining values. */
function parentOutput(leftCv, rightCv) {
  const blockWords = new Uint32Array(16);
  blockWords.set(leftCv, 0);
  blockWords.set(rightCv, 8);
  return { icv: IV.slice(), blockWords, counter: 0, blockLen: BLOCK_LEN, flags: PARENT };
}

/** Accumulates the 16 blocks of one 1024-byte chunk. */
class ChunkState {
  constructor(chunkCounter) {
    this.cv = IV.slice();
    this.chunkCounter = chunkCounter;
    this.block = new Uint8Array(BLOCK_LEN);
    this.blockLen = 0;
    this.blocksCompressed = 0;
  }

  len() {
    return BLOCK_LEN * this.blocksCompressed + this.blockLen;
  }

  startFlag() {
    return this.blocksCompressed === 0 ? CHUNK_START : 0;
  }

  update(input) {
    let off = 0;
    while (off < input.length) {
      if (this.blockLen === BLOCK_LEN) {
        this.cv = compress(
          this.cv, wordsFromBlock(this.block), this.chunkCounter,
          BLOCK_LEN, this.startFlag(),
        ).slice(0, 8);
        this.blocksCompressed++;
        this.block = new Uint8Array(BLOCK_LEN);
        this.blockLen = 0;
      }
      const take = Math.min(BLOCK_LEN - this.blockLen, input.length - off);
      this.block.set(input.subarray(off, off + take), this.blockLen);
      this.blockLen += take;
      off += take;
    }
  }

  output() {
    return {
      icv: this.cv,
      blockWords: wordsFromBlock(this.block),
      counter: this.chunkCounter,
      blockLen: this.blockLen,
      flags: this.startFlag() | CHUNK_END,
    };
  }
}

/**
 * Incremental BLAKE3 hasher. `update()` accepts any number of byte
 * chunks; `digest()` returns the final 32-byte hash. The instance is
 * single-use -- call `digest()` exactly once.
 */
class Blake3 {
  constructor() {
    this.chunkState = new ChunkState(0);
    this.cvStack = [];
  }

  _addChunkChainingValue(newCv, totalChunks) {
    let cv = newCv;
    let t = totalChunks;
    // Merge with stacked subtrees whenever the chunk count is even,
    // so the stack only ever holds the left edge of the tree.
    while ((t & 1) === 0) {
      cv = outputChainingValue(parentOutput(this.cvStack.pop(), cv));
      t = Math.floor(t / 2);
    }
    this.cvStack.push(cv);
  }

  update(input) {
    let off = 0;
    while (off < input.length) {
      if (this.chunkState.len() === CHUNK_LEN) {
        const chunkCv = outputChainingValue(this.chunkState.output());
        const totalChunks = this.chunkState.chunkCounter + 1;
        this._addChunkChainingValue(chunkCv, totalChunks);
        this.chunkState = new ChunkState(totalChunks);
      }
      const take = Math.min(CHUNK_LEN - this.chunkState.len(), input.length - off);
      this.chunkState.update(input.subarray(off, off + take));
      off += take;
    }
    return this;
  }

  digest() {
    // Fold the chunk stack from the right edge inward to the root.
    let output = this.chunkState.output();
    for (let i = this.cvStack.length - 1; i >= 0; i--) {
      output = parentOutput(this.cvStack[i], outputChainingValue(output));
    }
    // The root node is re-compressed with the ROOT flag.
    const words = compress(
      output.icv, output.blockWords, 0, output.blockLen, output.flags | ROOT,
    );
    const out = new Uint8Array(OUT_LEN);
    const dv = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) dv.setUint32(i * 4, words[i], true);
    return out;
  }
}

/** One-shot convenience: BLAKE3 of a single Uint8Array. */
function blake3(bytes) {
  return new Blake3().update(bytes).digest();
}

// CommonJS export for the node test harness (web/blake3.test.js).
// `module` is undefined when this file is loaded as a browser <script>,
// so the SPA just gets `Blake3` / `blake3` as globals.
if (typeof module !== "undefined" && module.exports) {
  module.exports = { Blake3, blake3 };
}
