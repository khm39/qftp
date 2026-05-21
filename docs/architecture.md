# qftp architecture

This document describes how the qftp server is put together at runtime.
For the *why* behind the big decisions, see the ADRs in
[docs/adr/](adr/): [0001](adr/0001-quic-runtime.md) (the `quiche` + `mio`
runtime) and [0002](adr/0002-process-isolation.md) (OS user isolation).

## Crates

| Crate | Role |
|---|---|
| `qftp-common` | Wire protocol, framing, QUIC transport helpers shared by both ends. |
| `qftp-server` | The server: event loop, ACLs, user directory, metrics. |
| `qftp-client` | The CLI: REPL, one-shot subcommands, sync / watch / fan-out. |
| `qftp-admin` | `users.toml` editor. |
| `qftp-bench` | Loopback throughput harness. |

## The QUIC event loop

The server is built on `quiche` (QUIC) and `mio` (readiness). It is
**not** an `async` runtime — see ADR 0001. One thread owns one UDP
socket and a `HashMap<ConnectionId, ConnectionContext>`. Each loop tick:

1. Poll the socket (timeout = the shortest QUIC timer across all
   connections).
2. Drain inbound datagrams; route each to its connection by Connection
   ID, or to the accept path for a new `Initial`.
3. Run `on_timeout` for every connection.
4. Process readable streams: decode requests, drive `Put` receive.
5. Drive sending streams: stream `Get` bodies a chunk per tick so one
   big transfer can't starve the others.
6. Flush egress (Linux coalesces with `sendmsg(UDP_SEGMENT)` / GSO).
7. Reap closed connections.

Blocking filesystem requests (`Ls`, `Stat`, `Mkdir`, ...) are offloaded
to a small worker-thread pool so a slow directory walk on one
connection cannot stall the loop; `Get` / `Put` streaming and all QUIC
packet I/O stay on the loop thread.

## Process models

The server runs in one of two process models.

### Standard (default)

A single process serves every connection. All file I/O runs as
whatever OS user launched `qftp-server`. This is the model behind
`server::run(.., RunRole::Standalone)` and is what every deployment
without `--user-isolation` uses. Run it as a dedicated unprivileged
user (see `examples/systemd/qftp-server.service`).

### OS user isolation (`--user-isolation`, Linux only)

Opt-in via `--user-isolation`. Each connection is served by its own
process running as the **authenticated user's real UID**, so uploads
land owned by that user and the kernel's discretionary access control
backs up the userspace ACL. See ADR 0002 for the full rationale.

```
              ┌───────────────────────────── dispatcher (privileged) ─────────┐
   client ───►│ UDP :4433 (wildcard, SO_REUSEPORT)                            │
              │   accept Initial → QUIC + mTLS handshake → fork() at "ready"   │
              └───────────────────────────────────────────────────────────────┘
                                 │ fork() (copy-on-write)
                                 ▼
              ┌───────────────────────────── worker (setuid alice) ───────────┐
   client ◄──►│ UDP :4433 (connect()ed to this peer, SO_REUSEPORT)            │
              │   inherits the established quiche::Connection, drops to        │
              │   alice's uid/gid, serves this one connection, then exits      │
              └───────────────────────────────────────────────────────────────┘
```

Key points:

- **The dispatcher is single-threaded.** It accepts connections and
  runs the full QUIC + mTLS handshake but never serves a request and
  never spawns a thread — which is what makes `fork()` safe. It reaps
  exited workers each tick so they don't linger as zombies.
- **The handoff is `fork()` without `exec()`.** The established
  `quiche::Connection` — BoringSSL TLS state and all — is inherited by
  the child through copy-on-write. TLS state is never serialised,
  moved, or replayed; this is the central trick of ADR 0002.
- **Packet routing needs no IPC.** The worker binds the same server
  port with `SO_REUSEPORT` but `connect()`s the socket to its one
  peer. Linux delivers that peer's datagrams to the connected socket
  in preference to the dispatcher's wildcard socket, so each worker
  receives exactly its own connection's traffic.
- **Privilege drop is irreversible.** Before serving any byte the
  worker runs `setgroups` + `setgid` + `setuid` and verifies it can no
  longer `seteuid(0)` (`privdrop::drop_to`).
- **Crash isolation is per connection.** A worker is one OS process;
  `kill -9` on it cannot affect the dispatcher or any other worker.

Validate a deployment before enabling it with the preflight:

```sh
qftp-server --check-isolation --users users.toml
```

It resolves every `users.toml` entry to an OS account and reports
whether the process holds the capabilities needed to switch
credentials — the isolation equivalent of `sshd -t`.

One operational prerequisite the preflight cannot check for you: each
user's home directory under `--root` must be owned by (or writable by)
that user's UID. The worker creates files as the setuid'd user, not as
root, so a root-owned home would make every upload fail with
`PermissionDenied`. `scripts/isolation-test.sh` exercises the whole
path end to end on a throwaway tree.

#### systemd

`DynamicUser=` is **incompatible** with `--user-isolation`: the
dispatcher must be able to `setuid` to arbitrary configured users, and
a dynamic user cannot. Run the dispatcher as root, or as a fixed user
granted `AmbientCapabilities=CAP_SETUID CAP_SETGID` (plus
`CAP_NET_BIND_SERVICE` for ports below 1024). See
`examples/systemd/qftp-server-isolation.service`.

#### Current limitations

The first cut of `--user-isolation` does not yet:

- preserve QUIC **connection migration** (the worker's socket is
  pinned to the peer's address at handoff time);
- preserve the **0-RTT latency** benefit across the handoff (early
  data is not lost — it rides the copy-on-write `Connection` — but the
  request is served at 1-RTT);
- expose **per-worker metrics** — `--metrics-bind` is ignored in this
  mode, because aggregating counters across processes needs a
  child→dispatcher IPC channel that is not built yet.
