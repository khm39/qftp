# CLAUDE.md

## Project Overview

QFTP (QUIC File Transfer Protocol) — a Rust file transfer system built on QUIC, providing secure file operations over UDP with TLS encryption. Uses the `quiche` library for QUIC transport and `bincode` for binary protocol serialization.

## Repository Structure

```
crates/
├── qftp-common/       # Shared protocol definitions & QUIC transport layer
│   └── src/
│       ├── lib.rs         # Re-exports protocol and transport modules
│       ├── protocol.rs    # Request/Response enums, DirEntry, FileStat types
│       └── transport.rs   # Length-prefixed messaging, QUIC config helpers
├── qftp-server/       # File server (single-connection, mio event loop)
│   └── src/
│       ├── main.rs        # Server startup, QUIC connection handling, event loop
│       └── handler.rs     # Per-command request handlers (ls, get, put, etc.)
└── qftp-client/       # Interactive client with REPL
    └── src/
        ├── main.rs        # Client startup, QUIC connection, stream management
        └── repl.rs        # Command parsing, output formatting
```

## Build & Run

```sh
# Build all crates
cargo build

# Build in release mode
cargo build --release

# Run the server (serves files from a root directory)
cargo run -p qftp-server -- --root /path/to/serve

# Run the client
cargo run -p qftp-client -- --host 127.0.0.1

# Check code compiles without building
cargo check

# Run clippy lints
cargo clippy --all-targets
```

## Testing

No automated tests exist yet. Testing is done manually by running the server and client.

## Architecture & Key Conventions

### Protocol (`qftp-common/src/protocol.rs`)
- Enum-based `Request`/`Response` with serde + bincode serialization
- Supported commands: Ls, Cd, Pwd, Get, Put, Mkdir, Rmdir, Rm, Rename, Chmod, Stat, Quit
- Structured types: `DirEntry` (directory listing), `FileStat` (file metadata)

### Transport (`qftp-common/src/transport.rs`)
- Length-prefixed framing: 4-byte big-endian u32 header + payload
- Max message size: 16 MB
- Stream buffer: 64 KB chunks (`STREAM_BUF_SIZE`)
- QUIC connection limits: 10 MB total, 1 MB per stream
- ALPN protocol identifier: `"qftp"`
- 30-second idle timeout

### Server (`qftp-server/`)
- Single connection at a time (rejects concurrent connections)
- Per-stream state machine: `ReadingRequest` → `ReadingFileData` → `Done`
- Root directory sandboxing via path canonicalization — all paths are resolved and verified against the root
- Max upload size: 1 GB
- Self-signed TLS certificates generated at startup via `rcgen`

### Client (`qftp-client/`)
- Interactive REPL using `rustyline` with history support
- Client-initiated bidirectional QUIC streams (IDs: 0, 4, 8, ...)
- Pretty-printed output with human-readable file sizes and Unix permissions

## Code Style

- **Rust edition 2021**
- Error handling: `anyhow::Result` for application errors, `thiserror` for typed errors in common crate
- Logging: `log` macros (`info!`, `warn!`, `error!`) with `env_logger`
- CLI arguments: `clap` with derive macros
- Idiomatic Rust: pattern matching, `?` error propagation, enum-based state machines
- Commit messages: imperative mood, descriptive (e.g., "Extract config into shared function", "Fix ls to default to current directory")

## Key Constants

| Constant | Value | Location |
|---|---|---|
| `MAX_MESSAGE_SIZE` | 16 MB | `transport.rs` |
| `STREAM_BUF_SIZE` | 64 KB | `transport.rs` |
| `MAX_UPLOAD_SIZE` | 1 GB | `handler.rs` |
| QUIC max data | 10 MB | `transport.rs` |
| QUIC max stream data | 1 MB | `transport.rs` |
| Idle timeout | 30 s | `transport.rs` |

## Dependencies

Core: `quiche` (QUIC), `serde`+`bincode` (serialization), `mio` (async I/O), `clap` (CLI), `ring` (crypto), `anyhow`/`thiserror` (errors), `rcgen` (certs), `rustyline` (REPL)
