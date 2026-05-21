//! OS user-id resolution and privilege-change capability checks for
//! the `--user-isolation` mode (ADR 0002).
//!
//! This module maps a `users.toml` entry to a concrete `(uid, gid)`
//! ([`resolve`]), reports whether the running process is allowed to
//! switch credentials ([`can_change_credentials`]), and performs the
//! actual irreversible credential drop ([`drop_to`]). The
//! `--check-isolation` preflight is built on the first two; the
//! per-connection worker that calls [`drop_to`] lands with the
//! dispatcher implementation.

use std::ffi::CString;

use anyhow::{Context, Result};

/// CAP_SETGID / CAP_SETUID bit positions in the Linux capability set
/// (`linux/capability.h`).
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;

/// A `users.toml` entry resolved to concrete OS ids.
#[derive(Debug, Clone)]
pub struct ResolvedIds {
    pub uid: u32,
    pub gid: u32,
    /// True when `uid` came from an explicit `uid =` in users.toml
    /// rather than a `getpwnam` lookup of the user name.
    pub uid_explicit: bool,
    /// True when `gid` came from an explicit `gid =` rather than the
    /// resolved account's primary group.
    pub gid_explicit: bool,
}

/// Resolve a `users.toml` user to `(uid, gid)`.
///
/// * `explicit_uid = Some` pins the uid directly; `name` need not
///   correspond to a real OS account. The gid is taken from
///   `explicit_gid`, falling back to the uid's passwd primary group.
/// * `explicit_uid = None` requires `name` to be a real OS account;
///   the uid and (unless overridden by `explicit_gid`) the primary gid
///   are read from it.
pub fn resolve(
    name: &str,
    explicit_uid: Option<u32>,
    explicit_gid: Option<u32>,
) -> Result<ResolvedIds> {
    match explicit_uid {
        Some(uid) => {
            let gid = match explicit_gid {
                Some(gid) => gid,
                None => {
                    let (_, pw_gid) = getpwuid(uid)?.with_context(|| {
                        format!(
                            "user '{name}': uid {uid} has no passwd entry, so its \
                             primary group can't be resolved; set an explicit \
                             `gid =` in users.toml"
                        )
                    })?;
                    pw_gid
                }
            };
            Ok(ResolvedIds {
                uid,
                gid,
                uid_explicit: true,
                gid_explicit: explicit_gid.is_some(),
            })
        }
        None => {
            let (pw_uid, pw_gid) = getpwnam(name)?.with_context(|| {
                format!(
                    "user '{name}': no OS account with this name; create the \
                     account or pin an explicit `uid =` in users.toml"
                )
            })?;
            Ok(ResolvedIds {
                uid: pw_uid,
                gid: explicit_gid.unwrap_or(pw_gid),
                uid_explicit: false,
                gid_explicit: explicit_gid.is_some(),
            })
        }
    }
}

/// Whether this process can switch to another user's credentials —
/// i.e. whether `--user-isolation` can work at all. True when running
/// as root, or when the effective capability set holds both
/// CAP_SETUID and CAP_SETGID (granted e.g. via systemd
/// `AmbientCapabilities=`).
pub fn can_change_credentials() -> bool {
    if unsafe { libc::geteuid() } == 0 {
        return true;
    }
    match caps_effective() {
        Some(caps) => has_cap(caps, CAP_SETUID) && has_cap(caps, CAP_SETGID),
        None => false,
    }
}

fn has_cap(caps: u64, bit: u32) -> bool {
    caps & (1u64 << bit) != 0
}

fn caps_effective() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    caps_effective_from_status(&status)
}

/// Parse the `CapEff:` hex bitmask out of `/proc/<pid>/status` text.
/// Split out from [`caps_effective`] as a pure function so it can be
/// unit-tested without a real `/proc`.
fn caps_effective_from_status(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// `getpwnam_r` wrapper. `Ok(None)` means "no such account".
fn getpwnam(name: &str) -> Result<Option<(u32, u32)>> {
    let cname = CString::new(name)
        .with_context(|| format!("user name '{name}' contains an interior NUL byte"))?;
    let mut buf = vec![0u8; 4096];
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < (1usize << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc)).context("getpwnam_r failed");
        }
        if result.is_null() {
            return Ok(None);
        }
        return Ok(Some((pwd.pw_uid, pwd.pw_gid)));
    }
}

/// `getpwuid_r` wrapper. `Ok(None)` means "uid has no passwd entry".
fn getpwuid(uid: u32) -> Result<Option<(u32, u32)>> {
    let mut buf = vec![0u8; 4096];
    loop {
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                &mut pwd,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < (1usize << 20) {
            buf.resize(buf.len() * 2, 0);
            continue;
        }
        if rc != 0 {
            return Err(std::io::Error::from_raw_os_error(rc)).context("getpwuid_r failed");
        }
        if result.is_null() {
            return Ok(None);
        }
        return Ok(Some((pwd.pw_uid, pwd.pw_gid)));
    }
}

/// Permanently drop this process's credentials to `ids`.
///
/// On success the process runs as `(uid, gid)` with no path back: a
/// `setuid` issued while still privileged sets the real, effective
/// **and** saved uid, so the privilege cannot be regained. The
/// supplementary group list is reset to exactly `[gid]`.
///
/// Order matters — `setgroups` and `setgid` must run while still
/// privileged, before `setuid` drops the privilege that permits them.
/// The drop is verified before returning; if any check fails the
/// caller must treat it as fatal and must not continue serving, since
/// a partially-dropped worker could climb back to root.
///
/// Wired into the per-connection worker by the dispatcher increment
/// of #62; kept separate so it can be unit-tested in isolation.
#[allow(dead_code)]
pub fn drop_to(ids: &ResolvedIds) -> Result<()> {
    // 1. Supplementary groups: reset to exactly [gid].
    let groups = [ids.gid];
    if unsafe { libc::setgroups(1, groups.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setgroups failed");
    }
    // 2. setgid before setuid: after setuid the gid can no longer be
    //    changed. Called with euid 0 it sets real/effective/saved gid.
    if unsafe { libc::setgid(ids.gid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setgid failed");
    }
    // 3. setuid drops the user privilege. Called with euid 0 it sets
    //    real/effective/saved uid, so the drop is irreversible.
    if unsafe { libc::setuid(ids.uid) } != 0 {
        return Err(std::io::Error::last_os_error()).context("setuid failed");
    }
    // 4. Verify. A worker that is still able to seteuid(0) must never
    //    be allowed to serve traffic.
    let (uid, euid) = unsafe { (libc::getuid(), libc::geteuid()) };
    let (gid, egid) = unsafe { (libc::getgid(), libc::getegid()) };
    if uid != ids.uid || euid != ids.uid {
        anyhow::bail!(
            "setuid verification failed: wanted uid {}, got real={uid} effective={euid}",
            ids.uid
        );
    }
    if gid != ids.gid || egid != ids.gid {
        anyhow::bail!(
            "setgid verification failed: wanted gid {}, got real={gid} effective={egid}",
            ids.gid
        );
    }
    if ids.uid != 0 && unsafe { libc::seteuid(0) } == 0 {
        anyhow::bail!("privilege drop is reversible: seteuid(0) succeeded after setuid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_root_by_name() {
        // root (uid 0) exists on every Unix system the tests run on.
        let ids = resolve("root", None, None).expect("root must resolve");
        assert_eq!(ids.uid, 0);
        assert!(!ids.uid_explicit);
        assert!(!ids.gid_explicit);
    }

    #[test]
    fn unknown_user_name_is_an_error() {
        let err = resolve("qftp-no-such-user-xyzzy", None, None)
            .expect_err("a nonexistent account must fail to resolve");
        assert!(
            err.to_string().contains("no OS account"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn explicit_uid_bypasses_name_lookup() {
        // The name need not be a real account when the uid is pinned.
        let ids = resolve("not-an-os-user", Some(4242), Some(4343))
            .expect("explicit uid+gid should resolve without an OS account");
        assert_eq!(ids.uid, 4242);
        assert_eq!(ids.gid, 4343);
        assert!(ids.uid_explicit);
        assert!(ids.gid_explicit);
    }

    #[test]
    fn explicit_gid_overrides_primary_group() {
        let ids = resolve("root", None, Some(9999)).expect("root resolves");
        assert_eq!(ids.uid, 0);
        assert_eq!(ids.gid, 9999);
        assert!(ids.gid_explicit);
    }

    #[test]
    fn caps_effective_parses_capeff_line() {
        let status =
            "Name:\tqftp-server\nUid:\t0\t0\t0\t0\nCapEff:\t00000000a80425fb\nSeccomp:\t0\n";
        let caps = caps_effective_from_status(status).expect("CapEff present");
        assert_eq!(caps, 0xa80425fb);
    }

    #[test]
    fn caps_effective_absent_is_none() {
        assert!(caps_effective_from_status("Name:\tx\nUid:\t0\n").is_none());
    }

    #[test]
    fn has_cap_checks_the_right_bit() {
        let caps = (1u64 << CAP_SETUID) | (1u64 << CAP_SETGID);
        assert!(has_cap(caps, CAP_SETUID));
        assert!(has_cap(caps, CAP_SETGID));
        assert!(!has_cap(caps, 0));
        assert!(!has_cap(0, CAP_SETUID));
    }

    #[test]
    fn can_change_credentials_does_not_panic() {
        // The result depends on how the test runner is privileged;
        // just assert the call completes and yields a bool.
        let _: bool = can_change_credentials();
    }

    /// The #62 headline guarantee: after `drop_to`, files the process
    /// creates are owned by the target OS user. Forks a child, drops
    /// it to the `daemon` account, has it create a file, and verifies
    /// the file's owner from the still-root parent.
    ///
    /// Needs root to setuid at all, and a `daemon` account to drop to;
    /// both hold in this repo's CI container. Skipped otherwise.
    #[test]
    fn drop_to_makes_created_files_owned_by_target_user() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipping drop_to test: not running as root");
            return;
        }
        let target = match resolve("daemon", None, None) {
            Ok(ids) => ids,
            Err(_) => {
                eprintln!("skipping drop_to test: no 'daemon' OS account");
                return;
            }
        };

        let dir = tempfile::tempdir().unwrap();
        // The dropped child needs to create a file inside the dir.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let file = dir.path().join("dropped.txt");
        let cpath = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // CHILD: drop privileges and create the file with raw
            // syscalls only, then `_exit`. No Rust-level exit, no
            // allocation past the drop -- this is post-fork code in a
            // (test-runner) multithreaded process.
            if drop_to(&target).is_err() {
                unsafe { libc::_exit(3) };
            }
            let fd = unsafe {
                libc::open(
                    cpath.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    0o644 as libc::c_int,
                )
            };
            if fd < 0 {
                unsafe { libc::_exit(4) };
            }
            let buf = b"ok";
            unsafe {
                libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len());
                libc::close(fd);
                libc::_exit(0);
            }
        }

        // PARENT: reap the child and inspect the file it created.
        let mut status: libc::c_int = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed");
        let exited = libc::WIFEXITED(status);
        let code = libc::WEXITSTATUS(status);
        assert!(
            exited && code == 0,
            "child failed to drop+create (exited={exited}, code={code})"
        );

        let meta = std::fs::metadata(&file).expect("dropped file must exist");
        assert_eq!(meta.uid(), target.uid, "file not owned by the target uid");
        assert_eq!(meta.gid(), target.gid, "file not owned by the target gid");
    }
}
