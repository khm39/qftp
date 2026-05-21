# qftp web client

`qftp-web-bridge` lets browsers transfer files with a qftp server. It
is a standalone binary that terminates **WebTransport** (HTTP/3) with
the quinn-based `wtransport` stack and drives the same
`qftp-protocol` core the native server uses. The native `qftp-server`
and `qftp-client` are unchanged and stay on `quiche` (see
[ADR 0001](adr/0001-quic-runtime.md)).

```
[ Browser SPA ]                     [ qftp-web-bridge ]
      |  HTTP/1.1  GET / , /app.js  ----->  static SPA listener (--http-bind)
      |  WebTransport (HTTP/3)      ----->  WebTransport listener (--bind)
      |    one bidi stream = one qftp Request
      |                                       |
      |                                  qftp-protocol  ->  filesystem / users.toml
```

## Running it

```
qftp-web-bridge \
  --cert server.pem --key server.key \
  --bind 0.0.0.0:4433 \
  --http-bind 127.0.0.1:8080 \
  --root /srv/qftp \
  --users users.toml \
  --users-tokens tokens.toml
```

- `--bind` is the WebTransport (UDP / HTTP/3) listener.
- `--http-bind` serves the bundled single-page app over plain HTTP.
  WebTransport cannot deliver the initial page, so the bridge serves
  it itself. In production, put a TLS-terminating reverse proxy
  (nginx) in front of this port.
- `--root` and `--users` have the same meaning as on `qftp-server`;
  point the bridge and the server at the same directory and
  `users.toml` to expose one filesystem through both.

Open `http://<http-bind>/` in the browser, fill in the WebTransport
URL (`https://<host>:4433/`) and an access token, and connect.

## Browser requirements

WebTransport is required: Chrome / Edge 97+ and Firefox 124+. **Safari
does not support WebTransport** and the SPA shows an explanatory
message there.

WebTransport also requires the server certificate to be trusted by the
browser. Use a publicly trusted certificate (or one trusted by your
organisation's PKI). Pinning a self-signed certificate via
`serverCertificateHashes` is a planned follow-up.

## Authentication

A browser cannot attach custom request headers to a WebTransport
connection, so qftp's mTLS identity is not reachable from the web. The
bridge uses **bearer tokens** instead.

`--users-tokens` is a TOML file mapping opaque tokens to user names
that must already exist in the `--users` file:

```toml
[[tokens]]
token = "long-random-url-safe-string"
user  = "alice"

[[tokens]]
token = "another-random-string"
user  = "bob"
```

The SPA carries the token in the WebTransport URL's query string
(`https://host:4433/?token=...`); the bridge reads it when the session
is established and refuses the session if the token is missing or
unknown. Without `--users-tokens` token auth is disabled and every
session is served as the anonymous (read-only) user, mirroring
`qftp-server`'s behaviour when no `--users` file is configured.

Tokens must be URL-safe and high-entropy -- they are the only secret
gating access over this transport.

## Limitations

- **Upload resume is not supported** by the bridge; the SPA uploads
  whole files (`offset = 0`).
- **In-browser BLAKE3 verification is not implemented yet.** The
  bridge still streams the 32-byte BLAKE3 trailer after every download
  (identical wire format to the native protocol); the SPA currently
  reads and discards it. Verifying it in the browser needs a
  WASM/JS BLAKE3 and is a planned follow-up.
