//! OS user-id resolution and privilege-change capability checks for
//! the `--user-isolation` mode (ADR 0002).
//!
//! This module is the *resolution* half of process isolation: it maps a
//! `users.toml` entry to a concrete `(uid, gid)` and reports whether the
//! running process is even allowed to switch credentials. The actual
//! `setuid`/`setgid` drop performed by a per-connection worker lands
//! with the dispatcher implementation; this module is what the
//! `--check-isolation` preflight is built on.

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
}
