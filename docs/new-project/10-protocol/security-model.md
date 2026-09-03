# qftp security model

Part of the **qftp/1 specification** ([README.md](README.md)). This
document records the threat model that the protocol and its reference
deployment shape are designed against. Items marked **(protocol)** are
properties of `qftp/1` itself; items marked **(deployment)** describe
what a server or client implementation is expected to provide and what
an operator is expected to configure.

## Threat model

- **(protocol)** The QUIC + TLS 1.3 transport is the trust anchor.
  Confidentiality, integrity, and peer authenticity on the wire come
  entirely from TLS 1.3; mTLS is the authentication primitive when
  configured.
- **(deployment)** A server may be exposed to the public internet. It
  must withstand source-address spoofing (mitigated by QUIC stateless
  retry, see [qftp-protocol.md](qftp-protocol.md#stateless-retry)),
  connection flooding (mitigated by global / per-IP connection caps and
  a per-IP Initial rate limiter), and protocol fuzzing (every decoder
  must be total: no input may crash the process).
- **(protocol)** Path traversal must be structurally impossible: a
  server walks the user-supplied path component by component, refuses
  `..` past the user's root, and either refuses symbolic links anywhere
  in the path or resolves them with a primitive that cannot escape the
  root (see [qftp-protocol.md](qftp-protocol.md#path-resolution)).
- **(deployment)** The server is not a userland sandbox. It runs as
  whichever OS user the operator starts it as, and a misconfigured user
  file can grant a peer access to everything that user can read. Run it
  as an unprivileged user dedicated to qftp. Per-user homes and ACLs are
  enforced in userspace, the same model as FTP "virtual users"; OS-level
  per-user isolation is deliberately **not** part of the design.

## Trust on first use (TOFU)

A client MAY adopt the SSH `known_hosts` trust model when neither a CA
bundle nor an enterprise PKI is available (self-signed development
servers, home LANs): on first connect it pins the server's leaf
certificate fingerprint (SHA-256 of the DER) and refuses to continue on
later connects if the fingerprint changes. The trust assumption is
identical to SSH's: the **first** connection must not be intercepted.
A client SHOULD perform the pin check before sending any application
data. A CA bundle SHOULD be used whenever a real CA chain is available.

## Browser bridge (WebTransport)

A bridge that exposes qftp to browsers over WebTransport is a
**separate trust boundary** from the native server:

- Browsers cannot present client certificates to a WebTransport
  endpoint, so the bridge authenticates with bearer tokens instead of
  mTLS. Tokens are the only secret gating web access: generate them
  with high entropy, store them hashed, and treat the token file like
  a password file.
- A token carried in the connection URL's query string is visible to
  every component that terminates or inspects TLS and logs the request
  URL (reverse proxies, load balancers, WAFs, CDNs). Disable URL/query
  logging on every such intermediary, treat any log store that may have
  seen a token as compromised, and rotate tokens routinely.
- WebTransport requires a browser-trusted TLS certificate; there is no
  "insecure" mode for browsers.
- Without token authentication every browser session is the anonymous
  read-only user. Never run a writable deployment without it.
- **WebTransport is not protected by CORS or the same-origin policy**:
  any web page a user's browser renders can attempt a WebTransport
  session against any bridge that user's machine can reach. The bridge
  MUST check the CONNECT request's `origin` header against an operator
  allowlist; when no allowlist is configured, browser sessions MUST be
  refused in anonymous mode.
- The single-page application is served over plain HTTP by the bridge
  only for development; in production it is served behind a
  TLS-terminating reverse proxy or as static files.

## Integrity is not authenticity

The BLAKE3 checksums on `Get` / `Put` (header field or streamed trailer)
detect **accidental corruption** of the transferred bytes: truncation,
bit-rot, a buggy resume. They are an unkeyed hash: they are **not** a
message-authentication code and do **not** prove who produced the
bytes. An attacker who could rewrite both the body and its trailer would
pass the BLAKE3 check; only TLS prevents that on the wire. Do not treat
a matching BLAKE3 digest as a signature. Message-layer authenticity (a
per-message MAC or signed manifest) is a `qftp/2` direction (see
[protocol-changelog.md](protocol-changelog.md)), not a `qftp/1`
guarantee.

## Transfer compression

qftp transfer compression is a body-only, per-file transform. CRIME and
BREACH-style chosen-plaintext attacks are structurally non-applicable:
control frames, credentials, bearer tokens, and other secrets are not
mixed into the compressed body, and each transfer is an independent
frame. Compress-then-encrypt leaks the encoded length of a file; qftp
accepts that for file transfer, where size disclosure is already part of
the protocol surface.

The main compression risk is decompression bombs. Receivers MUST bound
decoded output by `plaintext_size` and the implementation's maximum
file size, refuse output that exceeds the plaintext declaration, and
charge storage quota on plaintext bytes rather than encoded bytes.
Malformed compressed frames or zstd windows above the `qftp/1` limit
(`window_log = 23`, 8 MiB) are `DecodeError` (`431`). The declared
`plaintext_size` MUST NOT be used to pre-allocate memory; it is a cheap
early rejection only, and the running plaintext output counter is the
defence.

## 0-RTT

Early data is replayable and arrives before any client-certificate
identity is known. The request allow list and the identity gate in
[qftp-protocol.md](qftp-protocol.md#0-rtt-session-resumption) are
security rules, not optimisations: a server MUST NOT execute a
mutating, large-reply, or identity-dependent request from early data.

## Out of scope

- Side channels in the BLAKE3 / HMAC implementations (constant-time
  properties of the underlying libraries are relied upon).
- Resource exhaustion that succeeds only at limits *configured by the
  operator*.
- Anything that requires write access to the server's filesystem
  *outside* the configured root.

## Hardening checklist for production deployments

- Require stateless retry on internet-facing servers. The retry token
  is HMAC-signed over the peer's address and connection ID; the HMAC
  tag SHOULD be at least 20 bytes (160 bits).
- Set global and per-IP connection caps for the deployment's capacity.
- Configure mTLS with a client CA and a per-user file; never rely on
  the anonymous-user fallback in production.
- Run the server as a dedicated unprivileged OS user.
- Restrict the storage root to its own directory. Don't point it at `/`.
- Bind the metrics endpoint to a loopback or management interface; it
  serves Prometheus text and is not authenticated.
- Emit structured (JSON) logs and forward them to a central pipeline.
