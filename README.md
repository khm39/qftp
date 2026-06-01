# qftp -- QUIC File Transfer Protocol

A small, modern replacement for FTP built on QUIC + TLS 1.3. Single
connection carries every command and every byte of file body, all
multiplexed over independent streams. Resumable transfers, BLAKE3
integrity, mTLS authentication, per-user ACLs.

**This repository is both the qftp protocol specification and its
reference implementation.** The [`spec/`](spec/) directory is the
source of truth for the wire protocol; the Rust crates under
[`crates/`](crates/) are the reference implementation that conforms to
it. A second implementation in another language can be built from
[`spec/`](spec/) and [`test-vectors/`](test-vectors/) alone.

## Why QUIC?

The classic FTP design has the wrong shape today: two TCP connections
(control + data), no native crypto, no head-of-line independence, and a
NAT-hostile passive/active port dance. QUIC fixes all of that in a
single transport: one socket, mandatory TLS, independent streams,
0-RTT-capable handshakes, and connection migration. qftp is what FTP
would have looked like had it been designed in 2025.

## Status

Pre-1.0, but functionally complete for the supported feature set:

- Multi-connection server (graceful shutdown, per-IP / global caps,
  stateless retry, in-connection rate limiting).
- mTLS authentication with per-user homes and ACLs (read / write /
  delete / mkdir / rmdir / rename / chmod).
- Streaming upload and download (BufReader / BufWriter; the server's
  peak RAM use does not scale with file size).
- Resume for both directions. Get auto-resumes from the local file's
  current length; Put auto-resumes by probing the server's
  `<name>.qftp.partial` temp and continuing from where it stopped.
- BLAKE3 integrity. The server emits a 32-byte trailer after Get
  bodies; the client computes the matching hash and refuses to keep a
  corrupted local file. For Put, the client commits to a BLAKE3 in the
  request and the server verifies it before renaming the temp into
  place.
- Recursive `get -r` / `put -r`, glob expansion on local arguments,
  history persistence (`~/.qftp_history`), progress bars, and a
  `--execute` / piped-stdin batch mode.
- Prometheus metrics endpoint and `/healthz`.
- Optional structured JSON logging.
- 0-RTT session resumption: the second `qftp` connect to the same host
  skips the TLS handshake. Writes are still gated to 1-RTT to defeat
  replay; reads (Get / Ls / Stat / Pwd / Cd) go at 0-RTT.

## Quick start

```sh
# Server (development cert; do not use --self-signed in production)
qftp-server --self-signed --bind 127.0.0.1:4433 --root ./srv

# Client. Two ways to handle the server identity:
#   --insecure         skip all verification (dev only, MitM-prone)
#   --trust-on-first-use   SSH-style: pin the cert on first connect
#   --ca <file>        full PKI verification against a CA bundle
qftp-client --trust-on-first-use qftp://localhost:4433
qftp> ls
qftp> get -r remote-dir local-dir
qftp> put -r local-dir remote-dir
qftp> mget '*.log' ./logs
qftp> quit
```

### One-shot subcommands

For scp-style scripted use, the client accepts subcommands and exits
after the single operation (sysexits-style codes: 0 ok, 64 usage,
65 transfer, 77 auth):

```sh
qftp-client put ./dump.tar.gz qftp://files.example/backups/
qftp-client get qftp://files.example/foo.bin ./foo.bin
qftp-client ls qftp://files.example/dir
qftp-client stat qftp://files.example/dir/file
qftp-client rm qftp://files.example/old.log
qftp-client mkdir qftp://files.example/new-dir
qftp-client rmdir qftp://files.example/empty-dir
qftp-client rename qftp://files.example/a qftp://files.example/b
```

A subcommand-less invocation drops into the REPL as before.

### Saved hosts

The client reads `~/.qftp/config.toml` (override with `--config`). Define
host aliases and point the CLI at the alias name:

```toml
[host.work]
endpoint = "qftps://files.work.example:4433"
ca = "~/.qftp/work-ca.pem"
client_cert = "~/.qftp/work-cert.pem"
client_key = "~/.qftp/work-key.pem"

[host.home]
endpoint = "qftp://home.lan:4433"
tofu = false      # set true for SSH-style pinning at the alias level
```

```sh
qftp-client work          # uses the [host.work] alias
qftp-client qftp://server.example:4433/data  # raw URL + initial cd
```

Precedence (highest wins): CLI flag > URL fields > alias fields.

## Production deployment

```sh
# 1. Generate a CA, server cert, and per-user client cert.
./scripts/gen-test-mtls.sh tls

# 2. Define users in TOML.
cat > users.toml <<'EOF'
[[users]]
name = "alice"
permissions = { read = true, write = true, mkdir = true, rmdir = true, rename = true, delete = true, chmod = true }

[[users]]
name = "bob"
home = "/srv/qftp/bob-read-only"
permissions = { read = true }
EOF

# 3. Run the server with mTLS, rate limiting, retry, and metrics.
qftp-server \
    --cert tls/server.crt --key tls/server.key \
    --client-ca tls/ca.crt \
    --users users.toml \
    --root /srv/qftp \
    --bind 0.0.0.0:4433 \
    --require-retry \
    --max-connections 256 \
    --max-connections-per-ip 16 \
    --metrics-bind 127.0.0.1:9090 \
    --log-format json

# 4. Connect as a user.
qftp-client \
    --ca tls/ca.crt \
    --client-cert tls/client.crt --client-key tls/client.key \
    --host server.example:4433 --server-name server.example
```

## CLI flag reference

### qftp-server

| Flag | Purpose |
|---|---|
| `--bind <ip:port>` | UDP bind address. Default `127.0.0.1:4433`. |
| `--root <path>` | Storage root. Per-user homes are created under it unless they're absolute paths. |
| `--cert <pem>` / `--key <pem>` | Server certificate and key. Required unless `--self-signed`. The key file must be owner-readable only. |
| `--self-signed` | Generate an ephemeral cert at startup. Development only. |
| `--self-signed-persistent` | Keep the self-signed cert across restarts (stored under `$XDG_STATE_HOME/qftp/self-signed/`). Pairs with `qftp-client --trust-on-first-use` for stable fingerprint pinning on home LANs. |
| `--self-signed-state-dir <path>` | Override the persistent self-signed state directory. |
| `--client-ca <pem>` | When set, clients must present an mTLS cert chained to this CA. |
| `--users <toml>` | TOML file defining users, homes, and permissions. Without it, every connection is an anonymous user with full perms on `--root`. |
| `--max-connections <n>` | Hard cap on concurrent connections. Default 64. |
| `--max-connections-per-ip <n>` | Hard cap per source IP. Default 8. |
| `--require-retry` | Demand QUIC stateless retry on every Initial. Recommended for any internet-facing deployment. |
| `--metrics-bind <ip:port>` | Bind address for the Prometheus / healthz HTTP endpoint. Disabled when omitted. |
| `--log-format text\|json` | Default `text`. Use `json` for ingest by Loki / Datadog / etc. |

### qftp-client

```
qftp-client [OPTIONS] [TARGET]
```

`TARGET` is either a `qftp://[user@]host[:port][/initial-path]` URL
(`qftps://` is accepted as a synonym) or the name of a host alias
defined in the config file. Omitted, the client falls back to the
legacy flags / defaults.

| Flag | Purpose |
|---|---|
| `--config <path>` | Override the default `~/.qftp/config.toml`. |
| `--host <ip:port>` | Override host. Beats URL / alias. |
| `--server-name <name>` | Override SNI / cert CN expected. |
| `--ca <pem>` | PEM CA bundle to verify the server cert. Falls back to system trust store. |
| `--insecure` | Skip server cert verification. Dev only. |
| `--trust-on-first-use` (`-T`) | SSH-style cert pinning. First connect saves the SHA-256 fingerprint to `~/.qftp/known_hosts`; later connects verify against it. Ignored when `--ca` is set. |
| `--known-hosts <path>` | Override the default `~/.qftp/known_hosts`. |
| `--no-zero-rtt` | Skip 0-RTT session resumption (every connect is a fresh handshake). |
| `--session-ticket-dir <path>` | Override the default `~/.qftp/session-tickets/`. |
| `--client-cert <pem>` / `--client-key <pem>` | mTLS client certificate. |
| `--execute "<cmd>"` (`-e`) | Run a single command and exit. Repeatable. |
| `--batch` | Read commands from stdin, one per line, instead of opening a REPL. Also implicit when stdin is not a TTY. |
| `--history <path>` | Override the default `~/.qftp_history`. |
| `--no-compress` | Disable zstd transfer compression. By default fresh uploads are compressed and downloads request compression; already-compressed files (media/archives) are auto-skipped. |

## Web client (browser)

`qftp-web-bridge` serves qftp to browsers over WebTransport (HTTP/3).
It is a separate binary that runs alongside `qftp-server`, shares the
same `--root` and `users.toml`, and ships a single-page app: directory
browsing, drag-and-drop upload, download, delete, and rename, all with
progress bars and end-to-end BLAKE3 integrity checks.

```
qftp-web-bridge \
    --cert server.pem --key server.key \
    --bind 0.0.0.0:4433 --http-bind 127.0.0.1:8080 \
    --root /srv/qftp \
    --users users.toml --users-tokens tokens.toml
```

Then open `http://127.0.0.1:8080/` (or front it with HTTPS for any
non-localhost use). Browsers need WebTransport: Chrome / Edge, or
Firefox 124+; Safari is not supported.

### qftp-web-bridge

| Flag | Purpose |
|---|---|
| `--cert <pem>` / `--key <pem>` | TLS certificate and key for the WebTransport endpoint. |
| `--bind <ip:port>` | UDP bind address for WebTransport (HTTP/3). Default `0.0.0.0:4433`. |
| `--http-bind <ip:port>` | TCP bind address for the bundled SPA's plain-HTTP listener. Default `127.0.0.1:8080`. |
| `--root <path>` | Storage root; same meaning as `qftp-server --root`. |
| `--users <toml>` | Users, homes, and permissions (the same file `qftp-server` uses). |
| `--users-tokens <toml>` | Maps bearer tokens to user names. Without it, every session is the anonymous read-only user. |

A ready-to-run Docker Compose deployment (bridge + server + nginx) is
in [examples/docker-compose/](examples/docker-compose/). The setup
steps, bearer-token auth model, and certificate handling are in
[docs/web-client.md](docs/web-client.md).

## Documentation

- [spec/](spec/) -- the protocol specification, the source of truth for
  the wire format: [protocol](spec/qftp-protocol.md),
  [wire format](spec/wire-format.md), [error codes](spec/error-codes.md),
  [versioning](spec/versioning.md).
- [test-vectors/](test-vectors/) -- language-independent conformance
  vectors for the wire format.
- [docs/web-client.md](docs/web-client.md) -- the browser client and
  the WebTransport bridge.
- [docs/adr/](docs/adr/) -- architectural decision records (the
  `quiche` vs `quinn` choice is [0001](docs/adr/0001-quic-runtime.md)).
- [SECURITY.md](SECURITY.md) -- vulnerability reporting and supported
  versions.
- [CHANGELOG.md](CHANGELOG.md) -- per-release implementation notes.
- [PROTOCOL-CHANGELOG.md](PROTOCOL-CHANGELOG.md) -- wire-protocol
  changes (versioned by ALPN major).

## Platform support

| OS | Status |
|---|---|
| Linux x86_64 | Primary target, CI runs here. |
| Linux aarch64 | Built by cargo-dist. |
| macOS x86_64 / aarch64 | Built by cargo-dist. |
| Windows | Best-effort. The `mode` field of file metadata is synthesized; `chmod` returns `Unsupported`. |

## License

Licensed under the MIT license ([LICENSE.md](LICENSE.md)).
