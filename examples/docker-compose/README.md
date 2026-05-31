# Docker Compose: qftp + web bridge + nginx

A reference deployment that runs the native qftp server, the
WebTransport bridge, and an nginx TLS front-end for the browser SPA
side by side, all sharing one filesystem.

See [`docs/web-client.md`](../../docs/web-client.md) for how the bridge
works.

## Layout

| Service           | Protocol                     | Port (host) |
|-------------------|------------------------------|-------------|
| `qftp-server`     | native qftp/1 over QUIC      | UDP 4434    |
| `qftp-web-bridge` | WebTransport (HTTP/3)        | UDP 4433    |
| `nginx`           | HTTPS for the SPA page       | TCP 8443    |

nginx terminates TLS for the **web page** only. WebTransport traffic
is HTTP/3 over UDP and is **not** proxied -- the browser reaches
`qftp-web-bridge` on UDP 4433 directly.

## Setup

Run these from this directory.

1. **Tokens (required first).** No `tokens.toml` ships with the repo --
   the bridge will not start without one, by design. Copy the example
   and replace **every** placeholder with a fresh random value (a token
   is the only secret gating that user's web access):

   ```sh
   cp tokens.toml.example tokens.toml
   # then edit tokens.toml; for each token use a high-entropy value:
   openssl rand -hex 32
   ```

2. **TLS certificate.** For a real deployment use a browser-trusted
   certificate. For a LAN / dev box, a self-signed one works if the
   SPA pins it (WebTransport `serverCertificateHashes`), which needs an
   ECDSA P-256 key and a short validity:

   ```sh
   mkdir -p certs
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
     -keyout certs/key.pem -out certs/cert.pem -days 13 -nodes \
     -subj "/CN=localhost" \
     -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
   ```

3. **Data directory.** The containers run as the distroless `nonroot`
   user (uid 65532), so the served filesystem must be writable by it:

   ```sh
   mkdir -p data && sudo chown 65532:65532 data
   ```

4. **Start:**

   ```sh
   docker compose up --build
   ```

## Using it

Open `https://localhost:8443/` in Chrome, Edge, or Firefox 124+. With a
self-signed certificate the browser warns on the page -- accept it for
the dev host. In the SPA, connect to `https://localhost:4433/` with one
of the tokens from `tokens.toml`.

## Notes

- A self-signed certificate must stay short-lived (the `-days 13`
  above) for `serverCertificateHashes` pinning; regenerate it when it
  expires, or use a real CA certificate (no pinning, no expiry churn).
- `qftp-server` here has no `--client-ca`, so its native-protocol
  peers are anonymous; add mTLS for production (see the main README).
- All three services can share one certificate, as shown, or use
  separate ones.
