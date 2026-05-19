//! User identity, home directories, and per-user ACLs.
//!
//! Users are looked up by the Common Name (CN) of the TLS client
//! certificate they presented during the mTLS handshake. The anonymous
//! user is used when mTLS is not configured or the peer did not present a
//! cert; it shares the global root and (by default) full permissions.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
/// user; the anonymous fallback defaults to all-true.
#[derive(Debug, Clone, Default, Deserialize)]
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
pub struct UserSpec {
    pub name: String,
    /// Home directory. If relative, it's resolved against the global root.
    /// If absent, defaults to `<global_root>/<name>`.
    pub home: Option<PathBuf>,
    #[serde(default)]
    pub permissions: Permissions,
}

/// Resolved, immutable user record handed to per-connection contexts.
#[derive(Debug)]
pub struct User {
    pub name: String,
    pub home: PathBuf,
    pub permissions: Permissions,
}

/// Top-level user config, loaded from a TOML file.
#[derive(Debug, Default, Deserialize)]
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
    /// Build a directory where the anonymous user gets the global root and
    /// full permissions. Used when no `--users` file is configured.
    pub fn default_anonymous(global_root: &Path) -> Self {
        let anon = Arc::new(User {
            name: "anonymous".to_string(),
            home: global_root.to_path_buf(),
            permissions: Permissions::full(),
        });
        Self {
            by_name: HashMap::new(),
            anonymous: anon,
        }
    }

    /// Read a TOML config and resolve all home paths against `global_root`.
    pub fn from_config(global_root: &Path, cfg: UserConfig) -> Result<Self> {
        let resolve_home = |spec: &UserSpec| -> PathBuf {
            match &spec.home {
                Some(h) if h.is_absolute() => h.clone(),
                Some(h) => global_root.join(h),
                None => global_root.join(&spec.name),
            }
        };

        let mut by_name = HashMap::new();
        for spec in &cfg.users {
            let home = resolve_home(spec);
            std::fs::create_dir_all(&home).with_context(|| {
                format!(
                    "failed to create home directory {} for user {}",
                    home.display(),
                    spec.name
                )
            })?;
            let user = Arc::new(User {
                name: spec.name.clone(),
                home,
                permissions: spec.permissions.clone(),
            });
            if by_name.insert(spec.name.clone(), user).is_some() {
                anyhow::bail!("duplicate user name in config: {}", spec.name);
            }
        }

        let anonymous = match &cfg.anonymous {
            Some(spec) => {
                let home = resolve_home(spec);
                std::fs::create_dir_all(&home).ok();
                Arc::new(User {
                    name: spec.name.clone(),
                    home,
                    permissions: spec.permissions.clone(),
                })
            }
            None => Arc::new(User {
                name: "anonymous".to_string(),
                home: global_root.to_path_buf(),
                permissions: Permissions::read_only(),
            }),
        };

        Ok(Self { by_name, anonymous })
    }

    pub fn lookup(&self, cn: Option<&str>) -> Arc<User> {
        match cn.and_then(|n| self.by_name.get(n)) {
            Some(u) => Arc::clone(u),
            None => Arc::clone(&self.anonymous),
        }
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
}
