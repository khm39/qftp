"use strict";
/*
 * qftp web client.
 *
 * Speaks the qftp wire protocol directly over WebTransport: each
 * request opens one bidirectional stream carrying a length-prefixed
 * bincode frame (4-byte big-endian length, then the bincode payload).
 * The bincode payload itself is little-endian, fixed-int encoded --
 * see crates/qftp-common/src/protocol.rs for the message definitions.
 *
 * Note: the bridge always appends a 32-byte BLAKE3 trailer after a Get
 * body. This client reads and discards it; in-browser BLAKE3
 * verification is a planned follow-up (needs a WASM/JS BLAKE3).
 */

// ---------------------------------------------------------------------
// bincode codec (little-endian, fixed-int).
// ---------------------------------------------------------------------

class Writer {
  constructor() { this.parts = []; this.len = 0; }
  _push(arr) { this.parts.push(arr); this.len += arr.length; }
  u8(v) { this._push(new Uint8Array([v & 0xff])); }
  bool(v) { this.u8(v ? 1 : 0); }
  u32(v) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, v >>> 0, true);
    this._push(b);
  }
  u64(v) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(v), true);
    this._push(b);
  }
  str(s) {
    const enc = new TextEncoder().encode(s);
    this.u64(enc.length);
    this._push(enc);
  }
  finish() {
    const out = new Uint8Array(this.len);
    let off = 0;
    for (const p of this.parts) { out.set(p, off); off += p.length; }
    return out;
  }
}

class Reader {
  constructor(u8) {
    this.u8 = u8;
    this.view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
    this.pos = 0;
  }
  _need(n) {
    if (this.pos + n > this.u8.length) throw new Error("truncated response frame");
  }
  u8v() { this._need(1); return this.u8[this.pos++]; }
  bool() { return this.u8v() !== 0; }
  u32() { this._need(4); const v = this.view.getUint32(this.pos, true); this.pos += 4; return v; }
  u64() { this._need(8); const v = this.view.getBigUint64(this.pos, true); this.pos += 8; return v; }
  bytes(n) { this._need(n); const b = this.u8.subarray(this.pos, this.pos + n); this.pos += n; return b; }
  str() { return new TextDecoder().decode(this.bytes(Number(this.u64()))); }
}

// ---------------------------------------------------------------------
// qftp protocol encode / decode.
// ---------------------------------------------------------------------

const ERROR_CODES = [
  "NotFound", "PermissionDenied", "AlreadyExists", "NotADirectory",
  "IsADirectory", "FileTooLarge", "UploadOverflow", "UploadTruncated",
  "ChecksumMismatch", "RateLimited", "Malformed", "Internal",
  "Unauthorized", "InvalidRange", "Unsupported", "QuotaExceeded",
];

function encodeRequest(req) {
  const w = new Writer();
  switch (req.type) {
    case "Ls": w.u32(0); w.str(req.path); break;
    case "Cd": w.u32(1); w.str(req.path); break;
    case "Pwd": w.u32(2); break;
    case "Get":
      w.u32(3); w.str(req.path); w.u64(req.offset || 0);
      if (req.length == null) { w.u8(0); } else { w.u8(1); w.u64(req.length); }
      break;
    case "Put":
      w.u32(4); w.str(req.path); w.u64(req.size); w.u32(req.mode);
      w.u64(req.offset || 0);
      w.u8(0); // checksum: None (header-checksum path unused by the web client)
      w.bool(req.noClobber || false);
      w.bool(false); // checksum_trailer: off
      break;
    case "Mkdir": w.u32(5); w.str(req.path); break;
    case "Rmdir": w.u32(6); w.str(req.path); break;
    case "Rm": w.u32(7); w.str(req.path); break;
    case "Rename": w.u32(8); w.str(req.from); w.str(req.to); break;
    case "Chmod": w.u32(9); w.str(req.path); w.u32(req.mode); break;
    case "Stat": w.u32(10); w.str(req.path); break;
    case "Quota": w.u32(11); break;
    case "Quit": w.u32(12); break;
    default: throw new Error("unknown request type " + req.type);
  }
  return w.finish();
}

function decodeResponse(r) {
  const tag = r.u32();
  switch (tag) {
    case 0:
      return { type: "Ok" };
    case 1:
      return { type: "Err", code: ERROR_CODES[r.u32()] || "Unknown", message: r.str() };
    case 2: {
      const n = Number(r.u64());
      const entries = [];
      for (let i = 0; i < n; i++) {
        entries.push({
          name: r.str(), isDir: r.bool(),
          size: r.u64(), modified: r.u64(), mode: r.u32(),
        });
      }
      return { type: "DirListing", entries };
    }
    case 3:
      return { type: "Path", path: r.str() };
    case 4:
      return { type: "FileStat", size: r.u64(), isDir: r.bool(), modified: r.u64(), mode: r.u32() };
    case 5:
      return { type: "FileReady", size: r.u64(), totalSize: r.u64(), checksumFollows: r.bool() };
    case 6: {
      const usedBytes = r.u64();
      const fileCount = r.u64();
      const limitBytes = r.u8v() ? r.u64() : null;
      return { type: "QuotaInfo", usedBytes, fileCount, limitBytes };
    }
    default:
      throw new Error("unknown response tag " + tag);
  }
}

class QftpError extends Error {
  constructor(resp) {
    super("[" + resp.code + "] " + resp.message);
    this.code = resp.code;
  }
}

// ---------------------------------------------------------------------
// Stream framing helpers.
// ---------------------------------------------------------------------

/** Prepend the 4-byte big-endian length prefix to a bincode payload. */
function frame(payload) {
  const out = new Uint8Array(4 + payload.length);
  new DataView(out.buffer).setUint32(0, payload.length, false); // big-endian
  out.set(payload, 4);
  return out;
}

/** Buffered reader over a WebTransport ReadableStream of byte chunks. */
class ByteStream {
  constructor(readable) {
    this.reader = readable.getReader();
    this.buf = new Uint8Array(0);
    this.done = false;
  }
  async _pull() {
    if (this.done) return false;
    const { value, done } = await this.reader.read();
    if (done) { this.done = true; return false; }
    const merged = new Uint8Array(this.buf.length + value.length);
    merged.set(this.buf);
    merged.set(value, this.buf.length);
    this.buf = merged;
    return true;
  }
  async readExact(n) {
    while (this.buf.length < n) {
      if (!(await this._pull())) throw new Error("stream ended before " + n + " bytes");
    }
    const out = this.buf.slice(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }
  async readFrame() {
    const lenBytes = await this.readExact(4);
    const len = new DataView(lenBytes.buffer).getUint32(0, false); // big-endian
    return await this.readExact(len);
  }
  /** Return up to `max` buffered bytes (pulling once if empty), or null at EOF. */
  async readSome(max) {
    if (this.buf.length === 0 && !(await this._pull())) return null;
    const n = Math.min(max, this.buf.length);
    const out = this.buf.slice(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }
}

const CHUNK = 256 * 1024;

// ---------------------------------------------------------------------
// qftp connection over WebTransport.
// ---------------------------------------------------------------------

class Qftp {
  constructor(wt) { this.wt = wt; }

  static async connect(url, certHash) {
    try {
      // A browser-trusted certificate connects without pinning.
      return await Qftp._dial(url, null);
    } catch (e) {
      // Failing with an untrusted (self-signed) certificate is exactly
      // when serverCertificateHashes pinning is needed. Retry with it.
      if (certHash) return await Qftp._dial(url, certHash);
      throw e;
    }
  }

  static async _dial(url, certHash) {
    const options = certHash
      ? { serverCertificateHashes: [{ algorithm: "sha-256", value: certHash }] }
      : undefined;
    const wt = new WebTransport(url, options);
    await wt.ready;
    return new Qftp(wt);
  }

  close() {
    try { this.wt.close(); } catch (_) { /* already closed */ }
  }

  async _open() {
    return await this.wt.createBidirectionalStream();
  }

  /** One-shot request/response (Ls, Cd, Mkdir, Rm, Rename, ...). */
  async request(req) {
    const stream = await this._open();
    const writer = stream.writable.getWriter();
    await writer.write(frame(encodeRequest(req)));
    await writer.close();
    const bs = new ByteStream(stream.readable);
    return decodeResponse(new Reader(await bs.readFrame()));
  }

  async list(path) {
    const resp = await this.request({ type: "Ls", path });
    if (resp.type === "Err") throw new QftpError(resp);
    if (resp.type !== "DirListing") throw new Error("unexpected reply to Ls");
    return resp.entries;
  }

  async download(path, onProgress) {
    const stream = await this._open();
    const writer = stream.writable.getWriter();
    await writer.write(frame(encodeRequest({ type: "Get", path, offset: 0, length: null })));
    await writer.close();

    const bs = new ByteStream(stream.readable);
    const resp = decodeResponse(new Reader(await bs.readFrame()));
    if (resp.type === "Err") throw new QftpError(resp);
    if (resp.type !== "FileReady") throw new Error("unexpected reply to Get");

    const total = Number(resp.size);
    const chunks = [];
    let got = 0;
    while (got < total) {
      const chunk = await bs.readSome(Math.min(CHUNK, total - got));
      if (!chunk) throw new Error("stream ended before the file body completed");
      chunks.push(chunk);
      got += chunk.length;
      onProgress(got, total);
    }
    if (resp.checksumFollows) {
      await bs.readExact(32); // BLAKE3 trailer; verification is a follow-up
    }
    return new Blob(chunks);
  }

  async upload(path, file, onProgress) {
    const stream = await this._open();
    const writer = stream.writable.getWriter();
    const size = file.size;
    await writer.write(frame(encodeRequest({
      type: "Put", path, size, mode: 0o644, offset: 0, noClobber: false,
    })));

    const reader = file.stream().getReader();
    let sent = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      await writer.write(value);
      sent += value.length;
      onProgress(sent, size);
    }
    await writer.close();

    const bs = new ByteStream(stream.readable);
    const resp = decodeResponse(new Reader(await bs.readFrame()));
    if (resp.type === "Err") throw new QftpError(resp);
  }
}

// ---------------------------------------------------------------------
// Path helpers.
// ---------------------------------------------------------------------

function joinPath(base, name) {
  return base === "/" ? "/" + name : base + "/" + name;
}

function parentPath(p) {
  if (p === "/" || p === "") return "/";
  const idx = p.lastIndexOf("/");
  return idx <= 0 ? "/" : p.slice(0, idx);
}

function formatSize(n) {
  n = Number(n);
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
}

function formatDate(secs) {
  const s = Number(secs);
  return s === 0 ? "-" : new Date(s * 1000).toLocaleString();
}

// ---------------------------------------------------------------------
// UI.
// ---------------------------------------------------------------------

const el = {};
let qftp = null;
let currentPath = "/";
let connected = false;

// Filled from the bridge's /config.json: the WebTransport port and,
// for self-signed deployments, the leaf certificate hash to pin.
let appConfig = { certHash: null, webtransportPort: 4433 };

function $(id) { return document.getElementById(id); }

/** Decode a lowercase hex string into a Uint8Array, or null if invalid. */
function hexToBytes(hex) {
  if (typeof hex !== "string" || hex.length === 0 || hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

/** Load /config.json from the bridge; falls back to defaults on error. */
async function loadConfig() {
  try {
    const resp = await fetch("/config.json", { cache: "no-store" });
    if (!resp.ok) return;
    const cfg = await resp.json();
    if (typeof cfg.webtransportPort === "number") {
      appConfig.webtransportPort = cfg.webtransportPort;
    }
    appConfig.certHash = hexToBytes(cfg.certHash);
  } catch (_) {
    // SPA served without the bridge (e.g. behind a CDN): use defaults.
  }
}

function log(msg, kind) {
  const li = document.createElement("li");
  li.textContent = new Date().toLocaleTimeString() + "  " + msg;
  if (kind) li.className = kind;
  el.log.appendChild(li);
  while (el.log.childElementCount > 200) el.log.removeChild(el.log.firstChild);
  el.log.scrollTop = el.log.scrollHeight;
}

function showLoginError(msg) {
  el.loginError.textContent = msg;
  el.loginError.hidden = false;
}

function setConnected(on) {
  connected = on;
  el.login.hidden = on;
  el.browser.hidden = !on;
  el.connStatus.textContent = on ? "connected" : "disconnected";
  el.connStatus.className = "status " + (on ? "status-on" : "status-off");
}

function onConnected() {
  el.loginError.hidden = true;
  setConnected(true);
  currentPath = "/";
  log("connected", "ok");
  // A dropped session (e.g. the bridge restarting) returns the UI to
  // the login screen so the user can reconnect by clicking Connect.
  qftp.wt.closed
    .then(() => onDisconnected("session closed"))
    .catch(() => onDisconnected("session lost"));
  refresh();
}

function onDisconnected(reason) {
  if (!connected) return;
  setConnected(false);
  qftp = null;
  log("disconnected: " + reason, "err");
  showLoginError("Disconnected (" + reason + "). Reconnect below.");
}

async function doConnect() {
  let target;
  try {
    const u = new URL(el.url.value.trim());
    const token = el.token.value;
    if (token) u.searchParams.set("token", token);
    target = u.toString();
  } catch (_) {
    showLoginError("Invalid server URL.");
    return;
  }
  el.connect.disabled = true;
  el.loginError.hidden = true;
  try {
    qftp = await Qftp.connect(target, appConfig.certHash);
    onConnected();
  } catch (e) {
    showLoginError("Connection failed. Check the URL, token, and that the "
      + "server certificate is trusted by this browser.");
    log("connect error: " + (e && e.message ? e.message : e), "err");
  } finally {
    el.connect.disabled = false;
  }
}

function disconnect() {
  if (qftp) qftp.close();
  onDisconnected("by user");
}

async function refresh() {
  if (!qftp) return;
  el.path.textContent = currentPath;
  el.rows.innerHTML = "";
  try {
    const entries = await qftp.list(currentPath);
    entries.sort((a, b) => (b.isDir - a.isDir) || a.name.localeCompare(b.name));
    el.emptyDir.hidden = entries.length !== 0;
    for (const entry of entries) el.rows.appendChild(renderRow(entry));
  } catch (e) {
    log("ls failed: " + (e.message || e), "err");
  }
}

function renderRow(entry) {
  const tr = document.createElement("tr");

  const nameTd = document.createElement("td");
  const cell = document.createElement("div");
  cell.className = "name-cell";
  const icon = document.createElement("span");
  icon.textContent = entry.isDir ? "[dir]" : "[file]";
  icon.className = "muted";
  const link = document.createElement("span");
  link.className = "name-link";
  link.textContent = entry.name;
  link.addEventListener("click", () => {
    if (entry.isDir) {
      currentPath = joinPath(currentPath, entry.name);
      refresh();
    } else {
      doDownload(entry.name);
    }
  });
  cell.appendChild(icon);
  cell.appendChild(link);
  nameTd.appendChild(cell);

  const sizeTd = document.createElement("td");
  sizeTd.className = "num";
  sizeTd.textContent = entry.isDir ? "-" : formatSize(entry.size);

  const dateTd = document.createElement("td");
  dateTd.textContent = formatDate(entry.modified);

  const actionsTd = document.createElement("td");
  actionsTd.className = "row-actions";
  const renameBtn = document.createElement("button");
  renameBtn.textContent = "Rename";
  renameBtn.addEventListener("click", () => doRename(entry.name));
  const deleteBtn = document.createElement("button");
  deleteBtn.textContent = "Delete";
  deleteBtn.addEventListener("click", () => doDelete(entry));
  actionsTd.appendChild(renameBtn);
  actionsTd.appendChild(deleteBtn);

  tr.appendChild(nameTd);
  tr.appendChild(sizeTd);
  tr.appendChild(dateTd);
  tr.appendChild(actionsTd);
  return tr;
}

/** Create a labelled progress widget; returns {update, done, fail}. */
function newTransfer(label) {
  const box = document.createElement("div");
  box.className = "transfer";
  const text = document.createElement("div");
  text.textContent = label;
  const bar = document.createElement("div");
  bar.className = "bar";
  const fill = document.createElement("div");
  bar.appendChild(fill);
  box.appendChild(text);
  box.appendChild(bar);
  el.transfers.appendChild(box);

  return {
    update(done, total) {
      const pct = total > 0 ? Math.round((done / total) * 100) : 0;
      fill.style.width = pct + "%";
      text.textContent = label + "  " + pct + "%";
    },
    done(msg) {
      box.classList.add("done");
      fill.style.width = "100%";
      text.textContent = label + "  " + (msg || "done");
      setTimeout(() => box.remove(), 4000);
    },
    fail(msg) {
      box.classList.add("failed");
      text.textContent = label + "  failed: " + msg;
    },
  };
}

async function doDownload(name) {
  const path = joinPath(currentPath, name);
  const t = newTransfer("Download " + name);
  try {
    const blob = await qftp.download(path, (done, total) => t.update(done, total));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    t.done(formatSize(blob.size));
    log("downloaded " + name, "ok");
  } catch (e) {
    t.fail(e.message || String(e));
    log("download " + name + " failed: " + (e.message || e), "err");
  }
}

async function uploadFile(file) {
  const path = joinPath(currentPath, file.name);
  const t = newTransfer("Upload " + file.name);
  try {
    await qftp.upload(path, file, (done, total) => t.update(done, total));
    t.done(formatSize(file.size));
    log("uploaded " + file.name, "ok");
  } catch (e) {
    t.fail(e.message || String(e));
    log("upload " + file.name + " failed: " + (e.message || e), "err");
  }
}

async function uploadFiles(files) {
  for (const file of files) {
    await uploadFile(file);
  }
  refresh();
}

async function doDelete(entry) {
  if (!confirm("Delete " + entry.name + "?")) return;
  const path = joinPath(currentPath, entry.name);
  try {
    const resp = await qftp.request({ type: entry.isDir ? "Rmdir" : "Rm", path });
    if (resp.type === "Err") throw new QftpError(resp);
    log("deleted " + entry.name, "ok");
    refresh();
  } catch (e) {
    log("delete " + entry.name + " failed: " + (e.message || e), "err");
  }
}

async function doRename(name) {
  const next = prompt("Rename '" + name + "' to:", name);
  if (!next || next === name) return;
  try {
    const resp = await qftp.request({
      type: "Rename",
      from: joinPath(currentPath, name),
      to: joinPath(currentPath, next),
    });
    if (resp.type === "Err") throw new QftpError(resp);
    log("renamed " + name + " to " + next, "ok");
    refresh();
  } catch (e) {
    log("rename failed: " + (e.message || e), "err");
  }
}

async function doMkdir() {
  const name = prompt("New folder name:");
  if (!name) return;
  try {
    const resp = await qftp.request({ type: "Mkdir", path: joinPath(currentPath, name) });
    if (resp.type === "Err") throw new QftpError(resp);
    log("created folder " + name, "ok");
    refresh();
  } catch (e) {
    log("mkdir failed: " + (e.message || e), "err");
  }
}

function wireUp() {
  el.connect.addEventListener("click", doConnect);
  el.token.addEventListener("keydown", (e) => { if (e.key === "Enter") doConnect(); });
  el.disconnect.addEventListener("click", disconnect);
  el.refresh.addEventListener("click", refresh);
  el.mkdir.addEventListener("click", doMkdir);
  el.up.addEventListener("click", () => {
    if (currentPath !== "/") { currentPath = parentPath(currentPath); refresh(); }
  });

  el.filepick.addEventListener("change", () => {
    if (el.filepick.files.length) uploadFiles(Array.from(el.filepick.files));
    el.filepick.value = "";
  });

  el.dropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    el.dropzone.classList.add("drag");
  });
  el.dropzone.addEventListener("dragleave", () => el.dropzone.classList.remove("drag"));
  el.dropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    el.dropzone.classList.remove("drag");
    if (e.dataTransfer && e.dataTransfer.files.length) {
      uploadFiles(Array.from(e.dataTransfer.files));
    }
  });
}

document.addEventListener("DOMContentLoaded", async () => {
  for (const id of ["unsupported", "login", "browser", "conn-status", "url",
    "token", "connect", "login-error", "up", "path", "mkdir", "refresh",
    "disconnect", "dropzone", "filepick", "transfers", "rows", "empty-dir", "log"]) {
    el[id.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = $(id);
  }

  if (typeof WebTransport === "undefined") {
    el.unsupported.hidden = false;
    return;
  }

  el.login.hidden = false;
  await loadConfig();
  el.url.value = "https://" + (location.hostname || "localhost")
    + ":" + appConfig.webtransportPort + "/";
  wireUp();
});
