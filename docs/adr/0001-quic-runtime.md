# 0001 - QUIC runtime: stay on `quiche` + `mio`

- **Status**: Accepted
- **Date**: 2026-05-19
- **Deciders**: maintainers
- **Phase**: 0.5
- **Tracking issue**: [#25](https://github.com/khm39/qftp/issues/25)

## Context

The Phase 0 server was a single-connection proof of concept built on
`cloudflare/quiche` (the QUIC implementation) with `mio` (the
event-loop primitive). Every subsequent phase needed to extend this:
Phase 1 added streaming I/O and structured logging, Phase 2 added
multi-connection dispatch, ACLs, rate limits, and metrics, Phase 3
added resume, integrity, recursive transfers, and a proper protocol
versioning scheme.

Before committing to Phase 1+ on the existing runtime, this ADR
captures the decision of whether to:

1. **(A) Stay on `quiche` + `mio`.** Continue with the synchronous /
   manually-multiplexed event loop pattern that already works.
2. **(B) Migrate to `quinn` + `tokio`.** A fully `async` QUIC stack
   that handles multi-connection dispatch, per-stream futures, and
   timer scheduling natively.
3. **(C) Migrate to `s2n-quic` + `tokio`.** AWS's `async` QUIC stack
   with similar properties to quinn.

## Decision

**Continue with `quiche` + `mio`** for the foreseeable future. The
decision was made implicitly during Phase 1; this ADR documents it
after the fact so a future maintainer doesn't have to reverse-engineer
the rationale from commit messages.

## Consequences

### Positive

- **No rewrite cost.** Phase 0 / Phase 1 code keeps working as-is.
  Roughly 2000 lines of server code never had to be touched purely
  for runtime reasons.
- **Smaller dependency footprint.** Avoiding `tokio` keeps the
  release binary slim (no full async runtime); we only pull in what
  we actually use (`mio` for socket events, `signal-hook` for SIGINT
  / SIGTERM).
- **Predictable scheduling.** The single-threaded event loop makes
  the connection-state lifecycle (accept -> negotiate -> serve ->
  drain -> reap) easy to reason about. Every `ConnectionContext` is
  touched by exactly one thread, which keeps the borrow-checker
  story trivial and removes a whole class of synchronization bugs.
- **Cloudflare's production exposure.** `quiche` powers Cloudflare's
  edge; the QUIC implementation has been stress-tested at internet
  scale. `quinn` and `s2n-quic` are good libraries, but `quiche`'s
  battle-testing has more zeroes in its packet count.

### Negative

- **Manual multi-connection plumbing.** Every Phase that grew the
  server (Phase 2 especially) had to do its own dispatch:
  `HashMap<ConnectionId, ConnectionContext>` keyed by an
  `HMAC-SHA256(seed, dcid)` alias, manual `try_accept` /
  `try_consume` / `flush_egress` for each connection per loop tick.
  See `crates/qftp-server/src/server.rs` for what that looks like.
  An `async` stack would have given us most of this for free.
- **Synchronous I/O within a transfer.** The Phase 1 Get
  implementation blocked the entire event loop during a big
  transfer (`std::thread::sleep` between chunks). Phase 2 fixed
  this by making Get event-driven (`SendingFileData` state +
  `drive_sending_streams` chunk-per-tick), but it required ~150
  lines of state machine that an `async fn` would have collapsed.
- **No native HTTP/3.** If qftp ever wants to expose an HTTP/3
  control plane (e.g. for the metrics endpoint), `quinn` /
  `s2n-quic` would have a lower bar; with `quiche` we'd be
  hand-rolling it or pulling in `quiche-h3`.

### Mitigations

- The manual multi-connection plumbing is now done and well-tested
  (Phase 2 unit tests cover the limit / retry / counter pieces; the
  end-to-end soak harness covers the loop). Future contributors
  don't have to rewrite it.
- The synchronous-Get problem is solved; the same `drive_*`
  iteration pattern would extend cleanly to streaming Put with
  parallel-stream slicing if Phase 3 #55 ever comes back as a
  priority.
- HTTP/3 is out of scope; the metrics endpoint is plain HTTP/1.1
  over its own TCP port, which is fine for the Prometheus scrape
  pattern.

## Alternatives considered

### B. Migrate to `quinn` + `tokio`

- **Cost**: estimated ~1500 lines of server diff (every Cargo.toml,
  every `mod`, every `Result<...>` return). The handler /
  walk_safe / metrics / TLS-config code would carry over largely
  unchanged, but `server.rs` would need a near-complete rewrite.
- **Risk**: introducing `tokio` means inheriting a much larger
  dependency graph and a different mental model for failure
  injection during tests. soak / fuzz wiring would need to be
  re-validated.
- **Reward**: per-stream `async fn` collapses `drive_put` /
  `drive_sending_streams` into ~30 lines each; multi-connection
  dispatch becomes `tokio::spawn`. Cleaner code, but the existing
  code already works.

### C. Migrate to `s2n-quic` + `tokio`

- Same trade-offs as (B) plus a smaller ecosystem and less existing
  community knowledge to lean on when something misbehaves.

## When to revisit

This decision is correct **as of Phase 3**. Re-open it if any of
the following are true:

- We need to scale the server to many CPUs and the single-threaded
  event loop becomes the bottleneck. (At which point the right move
  may be running multiple server processes behind a UDP load
  balancer, which doesn't require a runtime change.)
- A serious vulnerability in `quiche` or `boringssl` (its TLS
  backend) makes maintenance untenable.
- We want first-class HTTP/3 inside the same process (e.g. for an
  admin control plane).
- A genuine production deployment runs into a behavioural mismatch
  between `quiche`'s implementation choices and what we need.

Until then: stay on `quiche` + `mio`. Reopen this ADR if you
disagree.
