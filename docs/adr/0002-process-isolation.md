# 0002 - OS user isolation: privileged dispatcher + per-connection setuid workers

- **Status**: Proposed
- **Date**: 2026-05-21
- **Deciders**: maintainers
- **Phase**: 5
- **Tracking issue**: [#62](https://github.com/khm39/qftp/issues/62)

## Context

qftp today runs as a single unprivileged process. Every file
operation is performed by whatever OS user launched `qftp-server`,
so a `Put` from `CN=alice` and a `Put` from `CN=bob` both land on
disk owned by that one launching user. Access control is enforced
entirely in userspace (`handler.rs` ACL checks, `user.rs` home
confinement); the kernel's discretionary access control (DAC) plays
no part.

The Phase 5 goal is **true OS user integration**: each transfer runs
under the real UID of the authenticated user, so `ls -l` on the
server shows `-rw-r--r-- 1 alice qftp ...`, quota/permission bits are
enforced by the kernel, and a bug in the userspace ACL is backed up
by ordinary filesystem permissions. This is the property `sshd` +
SFTP have and qftp does not.

Issue #62 framed four options (PAM-only, `setfsuid` worker pool,
`SO_REUSEPORT` process split, fork-exec per connection) and tentatively
picked the process-split direction. This ADR makes the binding
architectural decision.

### The hard constraint

A privileged process cannot simply "hand a connection to the right
user's worker" because of QUIC + mTLS ordering:

1. With mTLS the client identity is the peer certificate, which is
   not available until the TLS handshake **completes**
   (`conn.is_established()` then `conn.peer_cert()` — see
   `server.rs:670`).
2. The handshake state lives inside a `quiche::Connection`, whose TLS
   half is a BoringSSL context. **BoringSSL state is not
   serialisable and cannot be moved across a process boundary.**

So the kernel cannot route a connection to a per-user process up
front (it doesn't know the user yet), and a finished connection
cannot be marshalled and shipped to another process afterwards
(BoringSSL won't move). Any design has to resolve this tension.

The single insight this ADR turns on: `fork()` **without** a
following `exec()` copies the entire address space — including the
live BoringSSL/quiche state — via copy-on-write. The TLS context
does not need to be *moved*; it needs to be *inherited*.

## Decision

Adopt a **privileged dispatcher + per-connection setuid worker**
model, Linux-only, opt-in behind a `--user-isolation` flag.

### D1 — Per-connection workers, not a per-user pool

Each accepted connection is served by its own dedicated child
process. The child is `setuid`'d to the connection's authenticated
user and lives exactly as long as that one connection.

This is chosen over the issue's tentatively-preferred per-user pool
because the pool model is **incompatible with the BoringSSL
constraint**: the fork-COW trick (D2) only transfers TLS state at the
*moment a child is created*. A long-lived per-user worker that is
already running cannot have a second connection's freshly-finished
TLS state injected into it — that would require either moving the
BoringSSL context (impossible) or replaying the handshake (fragile,
see Alternatives). Per-connection workers make the handoff trivially
correct: the child is born holding exactly the connection it will
serve.

Per-connection workers also give strictly stronger isolation (one
connection crashing never disturbs another connection of the *same*
user) and need no connection-id-to-worker matching logic.

The cost — one process per live connection — is acceptable for a
file-transfer workload (long-lived, modest connection counts) and is
already bounded: the existing `ConnectionCounter` in `limits.rs`
(`--max-connections`, `--max-connections-per-ip`) now doubles as the
ceiling on child-process count. No new knob is required to bound it.

### D2 — A single privileged dispatcher owns the UDP socket and runs every handshake

One long-lived dispatcher process:

- Binds the UDP socket and runs the existing `quiche` + `mio` event
  loop (this is **not** a runtime change — see ADR 0001).
- Performs QUIC accept, Retry/anti-amplification, and the **full
  mTLS handshake** for every new connection, exactly as `server.rs`
  does today.
- At handshake completion, extracts the certificate identity
  (`user::extract_identity_candidates`, already implemented) and
  resolves it to a target UID/GID.
- `fork()`s a child **without exec**. The child inherits the live,
  post-handshake `quiche::Connection` — TLS keys and all — through
  copy-on-write. It then `setgroups()` + `setgid()` + `setuid()` to
  the target user, drops all capabilities, and continues serving that
  connection with the unchanged `handler.rs` / transfer state machine.
- After forking, the dispatcher **drops its own copy** of that
  connection's state. From that point the dispatcher only ever sees
  the connection's *ciphertext*, never plaintext file bytes.

A connection whose certificate maps to no OS account is rejected with
`CONNECTION_CLOSE` and no child is forked. The anonymous user maps to
a dedicated low-privilege account (configured `qftp` user); its child
is `setuid`'d there like any other.

`SO_REUSEPORT` — the mechanism in the issue title — is deliberately
**not** used for user routing. It cannot route by user (the kernel's
4-tuple hash is identity-blind) and the "land randomly, reject on
mismatch" variant has a 1-in-N hit rate. `SO_REUSEPORT` remains
available as a *future* knob to scale the dispatcher itself across
cores (several dispatchers, each forking its own children); that is
orthogonal to user isolation and out of scope here.

### D3 — Ingress is forwarded by the dispatcher; egress is written directly by the child

The UDP socket stays solely owned by the dispatcher (a shared reader
would split datagrams randomly between dispatcher and child).

- **Ingress**: the dispatcher demultiplexes every datagram by its
  QUIC Connection ID — the routing table it already maintains — and
  forwards datagrams for an established connection to the owning
  child over a `SOCK_SEQPACKET` `socketpair` created before the fork.
  Message: `Datagram { recv_addr, data }`. `SEQPACKET` preserves
  message boundaries, so no length framing is needed. Connection
  migration (client 4-tuple changes, DCID stays) is handled for free
  because routing is by DCID.
- **Egress**: the child writes packets **directly** to the shared UDP
  socket fd it inherited at fork. UDP send from a shared fd is safe
  and needs no IPC. Keeping egress off the IPC path matters because
  egress is the throughput-critical direction (#150/#151).

A per-connection optimisation — the child opening its own
`connect()`-ed UDP socket so the kernel delivers that client's
packets straight to it, bypassing the dispatcher's forwarding hop —
is promising but has kernel-version and connection-migration sharp
edges. It is left for the C.2 PoC to validate and is **not** part of
the baseline.

### D4 — Shared state stays in the dispatcher; only metrics are aggregated

Because the dispatcher is the *only* process that accepts connections
and runs handshakes, most state the issue worried about sharing is
naturally already centralised:

- **Retry / anti-amplification key**: only the dispatcher does Retry,
  so the key never leaves it. *Not* shared.
- **`RateLimiter` and `ConnectionCounter`**: all acceptance happens
  in the dispatcher, so per-IP rate limiting and connection caps work
  unchanged with no cross-process aggregation. *Not* shared.
- **Metrics**: each child holds local counters. Children send counter
  deltas to the dispatcher over the existing `socketpair` (on a timer
  and at connection close); the dispatcher aggregates and continues
  to own the `/metrics` HTTP endpoint. The per-worker breakdown is
  keyed by **user** (`qftp_worker_connections_open{user="alice"}`),
  not by PID, to keep cardinality bounded.
- **`users.toml` hot reload (SIGHUP)**: the dispatcher reloads;
  new connections use the new config; in-flight children keep the
  snapshot they were forked with.

### D5 — Privilege model

- The dispatcher needs `CAP_SETUID` + `CAP_SETGID` (to become any
  configured user) and `CAP_NET_BIND_SERVICE` if bound below port
  1024. Granting it the ability to `setuid` to arbitrary users makes
  it root-equivalent in practice; `SECURITY.md` must say so plainly.
- Children drop **all** capabilities immediately after
  `setgroups()` / `setgid()` / `setuid()` and before touching any
  client data.
- Graceful shutdown drains via an IPC `Drain` message, not signals,
  so the dispatcher does **not** need `CAP_KILL` to signal its
  now-foreign-UID children.
- Each child sets `PR_SET_PDEATHSIG = SIGKILL` so a dispatcher crash
  cannot orphan workers.
- The systemd unit runs the dispatcher with `AmbientCapabilities=`
  rather than full `User=root` where possible; `DynamicUser=` is
  incompatible with this model and must not be set.

### D6 — Linux-only, opt-in, default off

The feature is gated behind `--user-isolation` and compiled under
`#[cfg(target_os = "linux")]`. With the flag absent (the default) or
on non-Linux platforms, `qftp-server` keeps today's single-process
behaviour byte-for-byte. There is **no wire-protocol change**;
existing clients are unaffected. `users.toml` gains an optional `uid`
field (when omitted, the UID is resolved by `getpwnam(name)`).

## Consequences

### Positive

- **Kernel-enforced DAC.** Files land owned by the real user; a
  userspace ACL bug is backstopped by ordinary filesystem
  permissions. This is the headline Phase 5 goal.
- **The BoringSSL constraint is dissolved, not fought.** Fork-COW
  inheritance means the TLS state is never serialised, moved, or
  replayed. The handoff is a `fork()` call.
- **Crash isolation per connection.** `kill -9` on one worker cannot
  touch any other connection — same user or not.
- **The dispatcher never sees plaintext file data.** After fork it
  handles only ciphertext datagrams; the plaintext transfer happens
  entirely inside the unprivileged, user-confined child.
- **Minimal shared-state surface.** Rate limiter, connection counter
  and retry key stay single-process; only metrics need aggregation.
- **No runtime change.** Each process is still `quiche` + `mio`;
  ADR 0001 stands. ADR 0001's own "when to revisit" note already
  anticipated "run multiple server processes" as the scaling answer.

### Negative

- **A process per live connection.** Bounded by `--max-connections`,
  but heavier than one shared process. Acceptable for file transfer;
  would be wrong for a high-connection-rate workload.
- **The dispatcher is on the data path.** Every ciphertext datagram
  takes one extra `socketpair` hop. Expected to be measurable on
  loopback (the D3 connected-socket optimisation is the escape hatch
  if benchmarks demand it).
- **The dispatcher is root-equivalent.** `setuid`-to-anyone is a
  powerful capability; it is a new, security-critical trust anchor.
- **Linux-only.** Other platforms keep the single-process model with
  no OS user integration.
- **Test harness rework.** The Phase 2 soak harness assumes a single
  process and needs multi-process awareness (C.3).

### Mitigations

- Connection-count bound reuses an existing, already-tested knob.
- The connected-socket fast path (D3) is scoped into the C.2 PoC so
  the forwarding-hop cost has a known remedy before it becomes a
  production problem.
- The dispatcher's blast radius is narrowed by D2 (no plaintext after
  fork) and D5 (children drop all caps); `SECURITY.md` documents the
  trust model explicitly.
- Integration tests run under a Linux user namespace so UID switching
  is exercised in CI without needing real privileged accounts (C.3).

## Alternatives considered

### Per-user worker pool (issue's tentative pick)

One long-lived process per configured user, connections fanned in.
Rejected: a running per-user worker cannot receive a second
connection's finished BoringSSL state (D1). Making it work needs
`setfsuid`-per-request inside the worker (= the rejected option
below) or a handshake replay (below). Per-connection workers avoid
both.

### `setfsuid` / `setresuid` thread pool (issue's option B)

A single process flips its filesystem UID per request. Linux-only,
and crucially **not crash-isolated**: a panic or memory-safety bug in
one request's handling can corrupt another user's in-flight work in
the same address space. The whole point of Phase 5 is a kernel-strength
boundary; an in-process boundary is not one.

### `SO_REUSEPORT` random distribution + reject-on-mismatch (issue's option c)

Per-user workers each listen on the shared port; the kernel
distributes connections randomly; a worker that gets a connection for
the wrong user sends `CONNECTION_CLOSE` and the client retries.
Rejected: a 1-in-N success rate per attempt is unacceptable UX, and
it still requires a pre-spawned per-user pool with the D1 problem.

### Dispatcher completes handshake, replays ClientHello to a worker (issue's option a)

The dispatcher finishes the handshake, then re-drives a fresh
handshake against the chosen worker by replaying records. Rejected as
needlessly complex: it reaches the same end state the fork-COW handoff
reaches in one `fork()` call, but with a bespoke, fragile TLS-record
shuffling layer.

### Client declares the target user via SNI (issue's option b)

The client puts the username in the TLS SNI so the kernel/dispatcher
can route before the handshake. Rejected: it abuses SNI semantics,
leaks the username in cleartext, and is trivially spoofable — routing
must follow the *authenticated* certificate, not a client hint.

## Rollout

Three PRs, matching the issue's C.1 / C.2 / C.3 split:

- **C.1** — this ADR, plus a minimal two-process PoC (dispatcher +
  one forked child, anonymous user, single connection) that
  empirically confirms fork-COW preserves a live `quiche::Connection`
  and that DCID-based ingress forwarding works. The PoC also
  measures the D3 forwarding-hop cost and probes the connected-socket
  fast path.
- **C.2** — the full implementation: `process/dispatcher.rs`,
  `process/worker.rs`, an `ipc/` module for the `socketpair`
  protocol, the `uid` field in `users.toml`, the `--user-isolation`
  flag, capability handling, and graceful drain.
- **C.3** — multi-process soak/integration tests under a user
  namespace, crash-isolation tests, per-worker metrics breakdown,
  and the `docs/architecture.md` / `SECURITY.md` / systemd updates.

## When to revisit

- If connection rates ever make one-process-per-connection too heavy,
  revisit D1 — but the right move would likely be capping/queuing
  connections, not a per-user pool.
- If the D3 forwarding hop dominates a real benchmark, promote the
  connected-socket fast path from optimisation to baseline.
- If the dispatcher's single-threaded handshake throughput becomes
  the bottleneck, add `SO_REUSEPORT` across multiple dispatchers
  (each forking its own children) — a horizontal-scale knob, not a
  redesign.
- If a non-Linux platform ever needs OS user integration, this ADR
  does not cover it; a new ADR would be required.

Until then: privileged dispatcher, per-connection setuid workers,
fork-COW handoff, Linux-only, opt-in.
