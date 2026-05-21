//! OS user isolation: per-connection worker bootstrap (ADR 0002).
//!
//! After `server::run_dispatcher` `fork`s, the child process lands
//! here. It opens a connection-private UDP socket, drops OS privileges
//! to the authenticated user, and then serves exactly that one
//! connection via `server::run`.
//!
//! Packet routing needs no IPC: the worker's socket is bound to the
//! same server port with `SO_REUSEPORT` but `connect()`ed to the one
//! peer, and the Linux UDP demux delivers that peer's datagrams to the
//! connected socket in preference to the dispatcher's wildcard socket.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

use crate::connection::ConnectionContext;
use crate::metrics::Metrics;
use crate::server::{run, RunRole, ServerConfig};
use crate::user::UserDirectory;

/// Create a UDP socket with `SO_REUSEPORT` set, bound to `local`. The
/// dispatcher binds its listening socket this way so its forked
/// workers can later co-bind the same port.
pub fn bind_reuseport(local: SocketAddr) -> Result<std::net::UdpSocket> {
    build_socket(local, None)
}

/// The child half of a `fork` in `run_dispatcher`: become the worker
/// for `ctx`. Opens a connection-private socket, drops to the target
/// user, serves the connection, and exits the process. Never returns.
#[allow(clippy::too_many_arguments)]
pub fn become_worker(
    ctx: ConnectionContext,
    local: SocketAddr,
    ids: crate::privdrop::ResolvedIds,
    quiche_config: quiche::Config,
    server_config: ServerConfig,
    users: Arc<UserDirectory>,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
) -> ! {
    match worker_main(
        ctx,
        local,
        ids,
        quiche_config,
        server_config,
        users,
        metrics,
        shutdown,
    ) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            tracing::error!(error = %e, "isolation worker failed");
            std::process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn worker_main(
    ctx: ConnectionContext,
    local: SocketAddr,
    ids: crate::privdrop::ResolvedIds,
    quiche_config: quiche::Config,
    server_config: ServerConfig,
    users: Arc<UserDirectory>,
    metrics: Arc<Metrics>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let peer = ctx.peer_addr;

    // Connection-private socket: same server port (SO_REUSEPORT) but
    // connect()ed to this one peer. Must be created while still
    // privileged -- co-binding a SO_REUSEPORT port requires the same
    // uid as the dispatcher that first bound it.
    let std_sock =
        build_socket(local, Some(peer)).context("creating the connection-private worker socket")?;
    qftp_common::transport::tune_udp_buffers(&std_sock);
    let socket = mio::net::UdpSocket::from_std(std_sock);

    // Drop OS privileges to the authenticated user before serving any
    // of its bytes.
    crate::privdrop::drop_to(&ids)
        .with_context(|| format!("dropping privileges to uid {} gid {}", ids.uid, ids.gid))?;
    info!(
        peer = %peer,
        user = %ctx.user.name,
        uid = ids.uid,
        gid = ids.gid,
        "isolation worker serving connection"
    );

    run(
        quiche_config,
        socket,
        server_config,
        users,
        metrics,
        shutdown,
        RunRole::Worker(Box::new(ctx)),
    )
}

/// Build a UDP socket: `socket()` + `SO_REUSEPORT`, `bind(local)`, and
/// optionally `connect(peer)`, set non-blocking. The descriptor is
/// owned by the returned `UdpSocket` from creation onward, so an error
/// on any later step closes it cleanly via `Drop`.
fn build_socket(local: SocketAddr, connect_to: Option<SocketAddr>) -> Result<std::net::UdpSocket> {
    use std::os::unix::io::FromRawFd;

    let domain = if local.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("socket() failed");
    }
    // SAFETY: `fd` is a fresh, valid, owned UDP socket descriptor;
    // wrapping it now gives RAII cleanup for every error path below.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("setsockopt(SO_REUSEPORT) failed");
    }

    let (sa, sa_len) = sockaddr(local);
    let rc = unsafe { libc::bind(fd, &sa as *const _ as *const libc::sockaddr, sa_len) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("bind({local}) failed"));
    }

    if let Some(peer) = connect_to {
        let (pa, pa_len) = sockaddr(peer);
        let rc = unsafe { libc::connect(fd, &pa as *const _ as *const libc::sockaddr, pa_len) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("connect({peer}) failed"));
        }
    }

    sock.set_nonblocking(true)
        .context("set_nonblocking on worker socket failed")?;
    Ok(sock)
}

/// Marshal a `SocketAddr` into a `sockaddr_storage` plus its length.
fn sockaddr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(v4) => {
            // SAFETY: sockaddr_storage is large enough for sockaddr_in.
            let sa = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_port = v4.port().to_be();
            sa.sin_addr = libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            };
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            // SAFETY: sockaddr_storage is large enough for sockaddr_in6.
            let sa = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_port = v6.port().to_be();
            sa.sin6_flowinfo = v6.flowinfo();
            sa.sin6_scope_id = v6.scope_id();
            sa.sin6_addr.s6_addr = v6.ip().octets();
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len as libc::socklen_t)
}
