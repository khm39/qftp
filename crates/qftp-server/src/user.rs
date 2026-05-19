//! User identity, home directories, and per-user ACLs.
//!
//! Users are looked up by the Common Name (CN) of the TLS client
//! certificate they presented during the mTLS handshake. The anonymous
//! user is used when mTLS is not configured or the peer did not present a
//! cert; it shares the global root and is **read-only by default** (#104).
//! A peer that presents a cert whose CN is not in the directory is
//! rejected with `Unauthorized` rather than silently downgraded to
//! anonymous (#105).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Operations gated by ACL. Each variant maps to a Request::* that can
/// modify or read state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Read,
    Write,
    Delete,
    Mkdir,
    Rmdir,
    Rename,
    Chmod,
}

/// Per-user permission set. Missing fields default to false on a custom
/// user; the implicit anonymous fallback (no `--users` file) defaults to
/// read-only.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default)]
    pub delete: bool,
    #[serde(default)]
    pub mkdir: bool,
    #[serde(default)]
    pub rmdir: bool,
    #[serde(default)]
    pub rename: bool,
    #[serde(default)]
    pub chmod: bool,
}

impl Permissions {
    /// All-true permission set; used by tests and by callers that want
    /// to express "no ACL" explicitly. Not the default for anonymous —
    /// see [`UserDirectory::default_anonymous`].
    #[allow(dead_code)]
    pub const fn full() -> Self {
        Self {
            read: true,
            write: true,
            delete: true,
            mkdir: true,
            rmdir: true,
            rename: true,
            chmod: true,
        }
    }

    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            delete: false,
            mkdir: false,
            rmdir: false,
            rename: false,
            chmod: false,
        }
    }

    pub fn allows(&self, op: Op) -> bool {
        match op {
            Op::Read => self.read,
            Op::Write => self.write,
            Op::Delete => self.delete,
            Op::Mkdir => self.mkdir,
            Op::Rmdir => self.rmdir,
            Op::Rename => self.rename,
            Op::Chmod => self.chmod,
        }
    }
}

/// A single user entry in the config file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    pub name: String,
    /// Home directory. If relative, it's resolved against the global root.
    /// If absent, defaults to `<global_root>/<name>`.
    pub home: Option<PathBuf>,
    #[serde(default)]
    pub permissions: Permissions,
    /// Optional storage quota in bytes. `Put` requests that would
    /// push the user's home past this value are refused with
    /// `ErrorCode::QuotaExceeded` *before* the body is accepted.
    /// `None` (the default) is unlimited.
    #[serde(default)]
    pub quota_bytes: Option<u64>,
}

/// Resolved user record handed to per-connection contexts. The
/// quota counters (`used_bytes`, `in_flight_bytes`) are mutated
/// concurrently from every connection that runs as this user, so the
/// directory is intentionally an `Arc<User>` rather than `Arc<RwLock<User>>`
/// — only the AtomicU64 fields mutate.
#[derive(Debug)]
pub struct User {
    pub name: String,
    pub home: PathBuf,
    pub permissions: Permissions,
    pub quota_bytes: Option<u64>,
    /// Cached `walk_size(home).0` plus successful Put accruals minus
    /// successful Rm decrements. Initialized once at startup
    /// (avoids the per-Put `walk_size` DoS, #111).
    pub used_bytes: AtomicU64,
    /// Bytes reserved by accepted-but-not-yet-completed Put streams.
    /// `start_put` adds the declared remaining bytes here; the Put
    /// completion path subtracts them (and adds to `used_bytes` on
    /// success). This closes the parallel-Put bypass (#111).
    pub in_flight_bytes: AtomicU64,
}

impl User {
    /// `used + in_flight`, the budget-aware "current usage" figure that
    /// quota checks and the `Quota` response should both report.
    pub fn current_usage(&self) -> u64 {
        self.used_bytes
            .load(Ordering::Relaxed)
            .saturating_add(self.in_flight_bytes.load(Ordering::Relaxed))
    }
}

/// Walk `root` and return `(total_bytes, file_count)`. Used to
/// initialize a user's cached `used_bytes` at startup, and (until
/// the cache lands) for `Request::Quota` replies. We deliberately
/// skip non-regular files so the number matches `du -b --apparent-size`.
pub fn walk_size(root: &Path) -> (u64, u64) {
    let mut bytes = 0u64;
    let mut count = 0u64;
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in read.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                bytes = bytes.saturating_add(meta.len());
                count = count.saturating_add(1);
            }
        }
    }
    (bytes, count)
}

/// Top-level user config, loaded from a TOML file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    #[serde(default)]
    pub anonymous: Option<UserSpec>,
    #[serde(default)]
    pub users: Vec<UserSpec>,
}

/// Compiled user directory. Created once at startup; held in an Arc so
/// each connection can cheaply look up its user without cloning.
pub struct UserDirectory {
    by_name: HashMap<String, Arc<User>>,
    anonymous: Arc<User>,
}

impl UserDirectory {
    /// Build a directory where the anonymous user gets the global root.
    /// Used when no `--users` file is configured. The anonymous user is
    /// **read-only** by default; operators wanting writable anonymous
    /// access must declare it explicitly via `users.toml` (#104).
    pub fn default_anonymous(global_root: &Path) -> Self {
        let anon = Arc::new(User {
            name: "anonymous".to_string(),
            home: global_root.to_path_buf(),
            permissions: Permissions::read_only(),
            quota_bytes: None,
            used_bytes: AtomicU64::new(0),
            in_flight_bytes: AtomicU64::new(0),
        });
        Self {
            by_name: HashMap::new(),
            anonymous: anon,
        }
    }

    /// Read a TOML config and resolve all home paths against `global_root`.
    pub fn from_config(global_root: &Path, cfg: UserConfig) -> Result<Self> {
        let canonical_root = global_root.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize global root {}",
                global_root.display()
            )
        })?;

        // #126: `quota_bytes = 0` is ambiguous. Operators familiar
        // with traditional disk-quota systems often expect 0 to mean
        // "unlimited"; the natural reading of this field is "zero
        // bytes allowed" (every Put fails with QuotaExceeded).
        // Refuse the value at parse time and direct the operator to
        // omit the key for unlimited, or use `permissions.write =
        // false` to forbid writes.
        for spec in cfg.users.iter().chain(cfg.anonymous.iter()) {
            if spec.quota_bytes == Some(0) {
                anyhow::bail!(
                    "user {}: quota_bytes = 0 is ambiguous (#126); \
                     omit the field for unlimited, or set \
                     `permissions.write = false` to forbid writes",
                    spec.name
                );
            }
        }

        let resolve_home = |spec: &UserSpec| -> Result<PathBuf> {
            let raw = match &spec.home {
                Some(h) if h.is_absolute() => h.clone(),
                Some(h) => {
                    if h.components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        anyhow::bail!(
                            "user {}: relative home {} contains `..` (#112)",
                            spec.name,
                            h.display()
                        );
                    }
                    global_root.join(h)
                }
                None => global_root.join(&spec.name),
            };
            std::fs::create_dir_all(&raw).with_context(|| {
                format!(
                    "failed to create home directory {} for user {}",
                    raw.display(),
                    spec.name
                )
            })?;
            let canonical = raw.canonicalize().with_context(|| {
                format!(
                    "failed to canonicalize home {} for user {}",
                    raw.display(),
                    spec.name
                )
            })?;
            if !canonical.starts_with(&canonical_root) {
                anyhow::bail!(
                    "user {} home {} escapes global root {} (#112)",
                    spec.name,
                    canonical.display(),
                    canonical_root.display()
                );
            }
            Ok(canonical)
        };

        let build_user = |spec: &UserSpec, home: PathBuf| -> Arc<User> {
            // #111: prime the used-bytes cache once at startup so the
            // hot path (Put) doesn't re-walk the user's home.
            let (used, _) = walk_size(&home);
            Arc::new(User {
                name: spec.name.clone(),
                home,
                permissions: spec.permissions.clone(),
                quota_bytes: spec.quota_bytes,
                used_bytes: AtomicU64::new(used),
                in_flight_bytes: AtomicU64::new(0),
            })
        };

        let mut by_name = HashMap::new();
        for spec in &cfg.users {
            let home = resolve_home(spec)?;
            let user = build_user(spec, home);
            if by_name.insert(spec.name.clone(), user).is_some() {
                anyhow::bail!("duplicate user name in config: {}", spec.name);
            }
        }

        let anonymous = match &cfg.anonymous {
            Some(spec) => {
                let home = resolve_home(spec)?;
                build_user(spec, home)
            }
            None => {
                let (used, _) = walk_size(&canonical_root);
                Arc::new(User {
                    name: "anonymous".to_string(),
                    home: canonical_root,
                    permissions: Permissions::read_only(),
                    quota_bytes: None,
                    used_bytes: AtomicU64::new(used),
                    in_flight_bytes: AtomicU64::new(0),
                })
            }
        };

        Ok(Self { by_name, anonymous })
    }

    /// Look up a user by CN. `None` selects the anonymous user (used when
    /// no peer certificate is presented). A `Some(cn)` that does not match
    /// any configured user **also** returns anonymous; callers that have a
    /// peer cert should prefer [`lookup_strict`](Self::lookup_strict),
    /// which surfaces the miss so the connection can be rejected (#105).
    #[allow(dead_code)]
    pub fn lookup(&self, cn: Option<&str>) -> Arc<User> {
        match cn.and_then(|n| self.by_name.get(n.trim())) {
            Some(u) => Arc::clone(u),
            None => Arc::clone(&self.anonymous),
        }
    }

    /// Strict CN lookup used after mTLS upgrade. Returns `None` for an
    /// unknown CN so the caller can close the connection with
    /// `Unauthorized` rather than silently falling back to anonymous
    /// (#105). The CN is trimmed of surrounding whitespace before lookup.
    pub fn lookup_strict(&self, cn: &str) -> Option<Arc<User>> {
        self.by_name.get(cn.trim()).map(Arc::clone)
    }

    pub fn anonymous(&self) -> Arc<User> {
        Arc::clone(&self.anonymous)
    }
}

/// Pull the X.509 Common Name out of a DER-encoded leaf certificate. We
/// use the CN as the user identifier in mTLS. Returns None if the cert
/// fails to parse or has no CN, which means the caller will fall back to
/// the anonymous user.
pub fn extract_cn(der: &[u8]) -> Option<String> {
    use x509_parser::prelude::*;
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    for attr in cert.subject().iter_common_name() {
        if let Ok(s) = attr.as_str() {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_all_true_full() {
        let p = Permissions::full();
        for op in [
            Op::Read,
            Op::Write,
            Op::Delete,
            Op::Mkdir,
            Op::Rmdir,
            Op::Rename,
            Op::Chmod,
        ] {
            assert!(p.allows(op), "{op:?} should be allowed in full");
        }
    }

    #[test]
    fn read_only_blocks_writes() {
        let p = Permissions::read_only();
        assert!(p.allows(Op::Read));
        assert!(!p.allows(Op::Write));
        assert!(!p.allows(Op::Delete));
        assert!(!p.allows(Op::Mkdir));
        assert!(!p.allows(Op::Chmod));
    }

    #[test]
    fn parses_users_toml() {
        let toml = r#"
            [[users]]
            name = "alice"
            permissions = { read = true, write = true, mkdir = true }

            [[users]]
            name = "bob"
            home = "/srv/qftp/bob"
            permissions = { read = true }
        "#;
        let cfg: UserConfig = toml::from_str(toml).unwrap();
        assert_eq!(cfg.users.len(), 2);
        assert_eq!(cfg.users[0].name, "alice");
        assert!(cfg.users[0].permissions.write);
        assert!(!cfg.users[1].permissions.write);
    }

    #[test]
    fn lookup_falls_back_to_anonymous() {
        let dir = UserDirectory::default_anonymous(Path::new("/tmp"));
        let user = dir.lookup(Some("does-not-exist"));
        assert_eq!(user.name, "anonymous");
        assert!(user.permissions.allows(Op::Read));
    }

    #[test]
    fn default_anonymous_is_read_only() {
        // #104: without `--users`, the implicit anonymous user must not
        // grant writes, deletes, or chmod.
        let dir = UserDirectory::default_anonymous(Path::new("/tmp"));
        let anon = dir.anonymous();
        assert!(anon.permissions.allows(Op::Read));
        assert!(!anon.permissions.allows(Op::Write));
        assert!(!anon.permissions.allows(Op::Delete));
        assert!(!anon.permissions.allows(Op::Mkdir));
        assert!(!anon.permissions.allows(Op::Rmdir));
        assert!(!anon.permissions.allows(Op::Rename));
        assert!(!anon.permissions.allows(Op::Chmod));
    }

    #[test]
    fn lookup_strict_misses_unknown_cn() {
        // #105: a peer cert with an unknown CN must NOT silently
        // downgrade to anonymous; lookup_strict returns None so the
        // caller can close the connection.
        let dir = UserDirectory::default_anonymous(Path::new("/tmp"));
        assert!(dir.lookup_strict("does-not-exist").is_none());
    }

    #[test]
    fn lookup_strict_trims_whitespace() {
        // #105: trailing/leading whitespace on the CN should not
        // produce a different user than the configured name.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = UserConfig {
            anonymous: None,
            users: vec![UserSpec {
                name: "alice".to_string(),
                home: None,
                permissions: Permissions::read_only(),
                quota_bytes: None,
            }],
        };
        let dir = UserDirectory::from_config(tmp.path(), cfg).unwrap();
        assert!(dir.lookup_strict("alice").is_some());
        assert!(dir.lookup_strict(" alice ").is_some());
        assert!(dir.lookup_strict("alice\t").is_some());
        // Case mismatch is intentional: still a miss.
        assert!(dir.lookup_strict("Alice").is_none());
    }

    #[test]
    fn from_config_rejects_parent_dir_in_relative_home() {
        // #112: a relative `home = "../../etc"` in users.toml must not
        // escape the global root.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = UserConfig {
            anonymous: None,
            users: vec![UserSpec {
                name: "evil".to_string(),
                home: Some(PathBuf::from("../../etc")),
                permissions: Permissions::full(),
                quota_bytes: None,
            }],
        };
        let err = UserDirectory::from_config(tmp.path(), cfg)
            .err()
            .expect("expected from_config to reject this spec");
        assert!(
            err.to_string().contains("..") || err.to_string().contains("#112"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn config_rejects_typoed_field_name() {
        // #113: with deny_unknown_fields, a misspelled key like
        // `quota` (instead of `quota_bytes`) must produce an error
        // rather than silently disabling the quota.
        let toml = r#"
            [[users]]
            name = "alice"
            permissions = { read = true, write = true }
            quota = 1000
        "#;
        let err = toml::from_str::<UserConfig>(toml).expect_err("expected parse to fail on typo");
        assert!(
            err.to_string().contains("unknown field") || err.to_string().contains("quota"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn config_rejects_typoed_permissions_field() {
        // #113: a misspelled `permision` (singular) inside a per-user
        // table must be flagged at parse time.
        let toml = r#"
            [[users]]
            name = "alice"
            permision = { read = true, write = true }
        "#;
        let err = toml::from_str::<UserConfig>(toml).expect_err("expected parse to fail on typo");
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn from_config_rejects_zero_quota() {
        // #126: explicit 0 is ambiguous; require omission for unlimited.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = UserConfig {
            anonymous: None,
            users: vec![UserSpec {
                name: "alice".to_string(),
                home: None,
                permissions: Permissions::read_only(),
                quota_bytes: Some(0),
            }],
        };
        let err = UserDirectory::from_config(tmp.path(), cfg)
            .err()
            .expect("expected quota_bytes = 0 to be refused");
        assert!(err.to_string().contains("#126"));
    }

    #[test]
    fn from_config_initializes_used_bytes_from_walk_size() {
        // #111: a freshly built UserDirectory should reflect any
        // pre-existing files under each user's home, not start at 0.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("alice");
        std::fs::create_dir(&home).unwrap();
        std::fs::write(home.join("a.bin"), [0u8; 100]).unwrap();
        std::fs::write(home.join("b.bin"), [0u8; 250]).unwrap();
        std::fs::create_dir(home.join("sub")).unwrap();
        std::fs::write(home.join("sub/c.bin"), [0u8; 50]).unwrap();

        let cfg = UserConfig {
            anonymous: None,
            users: vec![UserSpec {
                name: "alice".to_string(),
                home: Some(PathBuf::from("alice")),
                permissions: Permissions::read_only(),
                quota_bytes: Some(10_000),
            }],
        };
        let dir = UserDirectory::from_config(tmp.path(), cfg).unwrap();
        let alice = dir.lookup_strict("alice").unwrap();
        assert_eq!(alice.used_bytes.load(Ordering::Relaxed), 400);
        assert_eq!(alice.in_flight_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(alice.current_usage(), 400);
    }

    #[test]
    fn current_usage_tracks_in_flight_plus_used() {
        // #111: parallel-Put bypass guard. The quota check must see
        // committed + reserved, never just committed.
        let user = User {
            name: "u".to_string(),
            home: PathBuf::from("/"),
            permissions: Permissions::read_only(),
            quota_bytes: Some(100),
            used_bytes: AtomicU64::new(40),
            in_flight_bytes: AtomicU64::new(0),
        };
        assert_eq!(user.current_usage(), 40);

        // Two parallel Puts of 30 each would each see used=40, and
        // before the fix both would project 40 + 30 = 70 <= 100 and
        // commit, ending at 100. With the in_flight counter, the
        // second see used=40, in_flight=30, projects 70+30 = 100,
        // OK. A third would see 100+30 = 130 > 100 and be refused.
        user.in_flight_bytes.fetch_add(30, Ordering::Relaxed);
        assert_eq!(user.current_usage(), 70);
        user.in_flight_bytes.fetch_add(30, Ordering::Relaxed);
        assert_eq!(user.current_usage(), 100);
    }

    #[test]
    fn from_config_rejects_absolute_home_outside_root() {
        // #112: even an absolute home must canonicalize to inside the
        // global root.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = UserConfig {
            anonymous: None,
            users: vec![UserSpec {
                name: "escapee".to_string(),
                home: Some(PathBuf::from("/etc")),
                permissions: Permissions::read_only(),
                quota_bytes: None,
            }],
        };
        let err = UserDirectory::from_config(tmp.path(), cfg)
            .err()
            .expect("expected from_config to reject this spec");
        assert!(
            err.to_string().contains("escapes") || err.to_string().contains("#112"),
            "unexpected error: {err}"
        );
    }
}
