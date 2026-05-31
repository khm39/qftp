//! `qftp-admin` — ops-side CLI for editing the server's `users.toml`.
//!
//! The qftp server consumes `users.toml` at startup. Editing it by
//! hand is error-prone (missing field, wrong permission spelling),
//! so this binary does the CRUD with schema validation and an atomic
//! write through `toml_edit` so existing comments are preserved.
//!
//! ## Subcommands
//!
//! ```text
//! qftp-admin init-users    <path>
//! qftp-admin add-user      <name> [--home PATH] [--read/--write/...]
//! qftp-admin remove-user   <name>
//! qftp-admin list-users
//! qftp-admin set-permissions <name> [--read/--write/...]
//! qftp-admin set-quota       <name> (--bytes N | --unlimited)
//! qftp-admin generate-completions <SHELL>
//! ```
//!
//! All commands accept `--users <path>` to point at a non-default
//! file (default `/etc/qftp/users.toml`).
//!
//! Runtime ops (kick / show-connections / reload) require a server
//! admin socket and are deferred to a follow-up.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
// The permission-flag key set is owned by `qftp-protocol` so this CLI
// (the only writer of users.toml) can't drift from the server's
// `Permissions` schema, which is `#[serde(deny_unknown_fields)]` (#269).
use qftp_protocol::user::PERM_KEYS;

const DEFAULT_USERS_PATH: &str = "/etc/qftp/users.toml";

#[derive(Parser)]
#[command(
    name = "qftp-admin",
    about = "Edit qftp-server's users.toml from the command line.",
    long_about = "qftp-admin manages the users.toml file consumed by qftp-server. \
        It reads, edits, and writes the file atomically while preserving comments \
        through toml_edit. Server-runtime operations (kick, show-connections, \
        reload) need a UNIX-socket admin RPC on the server side; that is filed as \
        a follow-up of #79."
)]
struct Args {
    /// Path to users.toml. Defaults to /etc/qftp/users.toml.
    #[arg(long, global = true, default_value = DEFAULT_USERS_PATH)]
    users: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new users.toml with a header comment and no entries.
    InitUsers,
    /// Add a user. ACL flags default to read-only; pass --write etc.
    /// to widen them.
    AddUser {
        name: String,
        /// Per-user home, relative to the server's --root or absolute.
        #[arg(long)]
        home: Option<PathBuf>,
        #[arg(long, default_value_t = true)]
        read: bool,
        #[arg(long, default_value_t = false)]
        write: bool,
        #[arg(long, default_value_t = false)]
        delete: bool,
        #[arg(long, default_value_t = false)]
        mkdir: bool,
        #[arg(long, default_value_t = false)]
        rmdir: bool,
        #[arg(long, default_value_t = false)]
        rename: bool,
        #[arg(long, default_value_t = false)]
        chmod: bool,
    },
    /// Remove a user by name.
    RemoveUser { name: String },
    /// List all users with their home and permissions.
    ListUsers,
    /// Update a user's permission flags. Only the flags you pass are
    /// modified; the rest stay as they were.
    SetPermissions {
        name: String,
        #[arg(long)]
        read: Option<bool>,
        #[arg(long)]
        write: Option<bool>,
        #[arg(long)]
        delete: Option<bool>,
        #[arg(long)]
        mkdir: Option<bool>,
        #[arg(long)]
        rmdir: Option<bool>,
        #[arg(long)]
        rename: Option<bool>,
        #[arg(long)]
        chmod: Option<bool>,
    },
    /// Set or clear a user's storage quota (bytes). Pass `--bytes N`
    /// to set a limit, or `--unlimited` to remove the quota key.
    SetQuota {
        name: String,
        /// Quota in bytes. Mutually exclusive with --unlimited.
        #[arg(
            long,
            conflicts_with = "unlimited",
            required_unless_present = "unlimited"
        )]
        bytes: Option<u64>,
        /// Remove the quota entirely (unlimited).
        #[arg(long, default_value_t = false)]
        unlimited: bool,
    },
    /// Print a shell-completion script and exit.
    GenerateCompletions { shell: Shell },
}

fn main() -> Result<()> {
    let args = Args::parse();
    execute_command(&args.users, args.command)
}

fn execute_command(users_path: &Path, command: Command) -> Result<()> {
    match command {
        Command::GenerateCompletions { shell } => {
            let mut cmd = Args::command();
            let bin = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
            Ok(())
        }
        Command::InitUsers => init_users(users_path),
        Command::AddUser {
            name,
            home,
            read,
            write,
            delete,
            mkdir,
            rmdir,
            rename,
            chmod,
        } => add_user(
            users_path,
            &name,
            home.as_deref(),
            Perms {
                read,
                write,
                delete,
                mkdir,
                rmdir,
                rename,
                chmod,
            },
        ),
        Command::RemoveUser { name } => remove_user(users_path, &name),
        Command::ListUsers => list_users(users_path),
        Command::SetPermissions {
            name,
            read,
            write,
            delete,
            mkdir,
            rmdir,
            rename,
            chmod,
        } => set_permissions(
            users_path,
            &name,
            PartialPerms {
                read,
                write,
                delete,
                mkdir,
                rmdir,
                rename,
                chmod,
            },
        ),
        Command::SetQuota {
            name,
            bytes,
            unlimited,
        } => set_quota(users_path, &name, if unlimited { None } else { bytes }),
    }
}

#[derive(Debug, Clone, Copy)]
struct Perms {
    read: bool,
    write: bool,
    delete: bool,
    mkdir: bool,
    rmdir: bool,
    rename: bool,
    chmod: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct PartialPerms {
    read: Option<bool>,
    write: Option<bool>,
    delete: Option<bool>,
    mkdir: Option<bool>,
    rmdir: Option<bool>,
    rename: Option<bool>,
    chmod: Option<bool>,
}

// Inserts in PERM_KEYS declaration order so the serialized inline table
// matches the server's `Permissions` field order and stays byte-stable.
fn build_perms_table(perms: Perms) -> toml_edit::InlineTable {
    let mut it = toml_edit::InlineTable::new();
    it.insert("read", perms.read.into());
    it.insert("write", perms.write.into());
    it.insert("delete", perms.delete.into());
    it.insert("mkdir", perms.mkdir.into());
    it.insert("rmdir", perms.rmdir.into());
    it.insert("rename", perms.rename.into());
    it.insert("chmod", perms.chmod.into());
    it
}

fn apply_partial_perms(it: &mut toml_edit::InlineTable, partial: PartialPerms) {
    let apply = |it: &mut toml_edit::InlineTable, k: &str, v: Option<bool>| {
        if let Some(b) = v {
            it.insert(k, b.into());
        }
    };
    apply(it, "read", partial.read);
    apply(it, "write", partial.write);
    apply(it, "delete", partial.delete);
    apply(it, "mkdir", partial.mkdir);
    apply(it, "rmdir", partial.rmdir);
    apply(it, "rename", partial.rename);
    apply(it, "chmod", partial.chmod);
}

fn get_bool_from_perm_item(item: Option<&toml_edit::Item>, key: &str) -> bool {
    match item {
        Some(toml_edit::Item::Value(toml_edit::Value::InlineTable(it))) => {
            it.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
        }
        Some(toml_edit::Item::Table(tt)) => tt.get(key).and_then(|v| v.as_bool()).unwrap_or(false),
        _ => false,
    }
}

fn init_users(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("{} already exists; refusing to overwrite", path.display());
    }
    let body = "# qftp-server user database -- managed by `qftp-admin`.\n\
                # Run `qftp-admin add-user NAME --read --write ...` to add an entry.\n\n";
    write_atomic(path, body)
}

fn add_user(path: &Path, name: &str, home: Option<&Path>, perms: Perms) -> Result<()> {
    // Validate before any file I/O so bad input fails fast.
    // The server keys `by_name` on the raw spec name but resolves
    // connections via `cn.trim()` (qftp-protocol/src/user.rs), so a
    // name with surrounding whitespace would be stored un-trimmed yet
    // looked up trimmed and never match; an empty name is unusable too.
    if name.is_empty() || name != name.trim() {
        bail!("user name must be non-empty and contain no leading/trailing whitespace");
    }
    // `anonymous` is the server's reserved fallback identity (the
    // top-level `[anonymous]` key); a `[[users]]` entry by that name is
    // never resolvable as that user, so reject it.
    if name == "anonymous" {
        bail!("user name 'anonymous' is reserved");
    }

    // Reject non-UTF-8 homes instead of lossily coercing them: the
    // server reads `home` as a string, so writing a U+FFFD-mangled path
    // would silently denote a different (or invalid) location.
    let home = match home {
        Some(h) => Some(
            h.to_str()
                .ok_or_else(|| anyhow!("--home is not valid UTF-8"))?,
        ),
        None => None,
    };

    let mut doc = load_or_default(path)?;
    let users = ensure_users_array(&mut doc)?;

    if find_user_index(users, name).is_some() {
        bail!("user '{name}' already exists; use `set-permissions` to modify");
    }

    let mut table = toml_edit::Table::new();
    table.insert("name", toml_edit::value(name));
    if let Some(h) = home {
        table.insert("home", toml_edit::value(h));
    }
    table.insert(
        "permissions",
        toml_edit::Item::Value(toml_edit::Value::InlineTable(build_perms_table(perms))),
    );

    users.push(table);
    write_atomic(path, &doc.to_string())?;
    println!("Added user '{name}' to {}.", path.display());
    Ok(())
}

fn remove_user(path: &Path, name: &str) -> Result<()> {
    let mut doc = load_existing(path)?;
    let users = ensure_users_array(&mut doc)?;
    let idx = validate_user_exists(users, name)?;
    users.remove(idx);
    write_atomic(path, &doc.to_string())?;
    println!("Removed user '{name}' from {}.", path.display());
    Ok(())
}

fn list_users(path: &Path) -> Result<()> {
    let doc = load_existing(path)?;
    let users = doc
        .get("users")
        .and_then(|i| i.as_array_of_tables())
        .map(|a| a.iter().collect::<Vec<_>>())
        .unwrap_or_default();
    if users.is_empty() {
        println!("(no users defined in {})", path.display());
        return Ok(());
    }
    println!("{:<24} {:<32} PERMS", "NAME", "HOME");
    println!("{}", "-".repeat(78));
    for t in users {
        let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let home = t
            .get("home")
            .and_then(|v| v.as_str())
            .unwrap_or("<default>");
        let perms = format_perms(t);
        println!("{name:<24} {home:<32} {perms}");
    }
    Ok(())
}

fn format_perms(t: &toml_edit::Table) -> String {
    let p = t.get("permissions");
    let mut on: Vec<&str> = Vec::new();
    for k in PERM_KEYS {
        if get_bool_from_perm_item(p, k) {
            on.push(k);
        }
    }
    if on.is_empty() {
        "(none)".to_string()
    } else {
        on.join(",")
    }
}

fn set_permissions(path: &Path, name: &str, partial: PartialPerms) -> Result<()> {
    let mut doc = load_existing(path)?;
    let users = ensure_users_array(&mut doc)?;
    let idx = validate_user_exists(users, name)?;

    let entry = users.get_mut(idx).expect("idx in bounds");
    // Lift the existing permissions table into an inline table we can
    // patch in place; if absent, start fresh with all-false.
    let mut perms_tbl = match entry.get("permissions") {
        Some(toml_edit::Item::Value(toml_edit::Value::InlineTable(it))) => it.clone(),
        Some(toml_edit::Item::Table(t)) => {
            let mut it = toml_edit::InlineTable::new();
            for k in PERM_KEYS {
                if let Some(v) = t.get(k).and_then(|i| i.as_bool()) {
                    it.insert(k.to_string(), v.into());
                }
            }
            it
        }
        _ => toml_edit::InlineTable::new(),
    };
    apply_partial_perms(&mut perms_tbl, partial);

    entry.insert(
        "permissions",
        toml_edit::Item::Value(toml_edit::Value::InlineTable(perms_tbl)),
    );
    write_atomic(path, &doc.to_string())?;
    println!("Updated permissions for '{name}' in {}.", path.display());
    Ok(())
}

fn set_quota(path: &Path, name: &str, bytes: Option<u64>) -> Result<()> {
    // Validate before any file I/O so bad input fails fast.
    if let Some(n) = bytes {
        // The server treats `quota_bytes = 0` as ambiguous and bails at
        // startup (#126); reject it here and point at the right flag.
        if n == 0 {
            bail!(
                "quota of 0 is ambiguous; use `--unlimited` to remove the quota, \
                 or pass a positive byte count"
            );
        }
        // TOML integers are i64-range (toml_edit only exposes `From<i64>`),
        // so a u64 above i64::MAX would serialize as a negative integer and
        // the server's u64 deserialization would reject the file (#269).
        if n > i64::MAX as u64 {
            bail!(
                "quota {n} exceeds the maximum representable TOML integer \
                 ({}); pass a smaller value",
                i64::MAX
            );
        }
    }

    let mut doc = load_existing(path)?;
    let users = ensure_users_array(&mut doc)?;
    let idx = validate_user_exists(users, name)?;
    let entry = users.get_mut(idx).expect("idx in bounds");
    match bytes {
        // `quota_bytes` is the schema key on `UserSpec` (Option<u64>,
        // #[serde(default)]); writing/removing it keeps the file valid
        // under the server's deny_unknown_fields (#269).
        Some(n) => {
            entry.insert("quota_bytes", toml_edit::value(n as i64));
            write_atomic(path, &doc.to_string())?;
            println!("Set quota for '{name}' to {n} bytes in {}.", path.display());
        }
        None => {
            entry.remove("quota_bytes");
            write_atomic(path, &doc.to_string())?;
            println!(
                "Cleared quota for '{name}' (now unlimited) in {}.",
                path.display()
            );
        }
    }
    Ok(())
}

fn load_existing(path: &Path) -> Result<toml_edit::DocumentMut> {
    let s = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    s.parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("failed to parse {}", path.display()))
}

fn load_or_default(path: &Path) -> Result<toml_edit::DocumentMut> {
    if path.exists() {
        load_existing(path)
    } else {
        Ok(toml_edit::DocumentMut::new())
    }
}

fn ensure_users_array(doc: &mut toml_edit::DocumentMut) -> Result<&mut toml_edit::ArrayOfTables> {
    if doc.get("users").is_none() {
        doc.insert("users", toml_edit::Item::ArrayOfTables(Default::default()));
    }
    // If the file pre-existed with a `users` key of the wrong shape
    // (e.g. a hand-edited `[users]` table or `users = "..."`), the
    // insert above is skipped and `as_array_of_tables_mut` returns
    // None. Surface that as a clean parse-style error instead of
    // panicking with a misleading "just inserted" message.
    doc["users"].as_array_of_tables_mut().ok_or_else(|| {
        anyhow!(
            "`users` key in users.toml is not an array-of-tables; \
             expected `[[users]]` entries"
        )
    })
}

fn find_user_index(users: &toml_edit::ArrayOfTables, name: &str) -> Option<usize> {
    users
        .iter()
        .position(|t| t.get("name").and_then(|v| v.as_str()) == Some(name))
}

fn validate_user_exists(users: &toml_edit::ArrayOfTables, name: &str) -> Result<usize> {
    find_user_index(users, name).ok_or_else(|| anyhow!("user '{name}' not found"))
}

fn write_atomic(path: &Path, body: &str) -> Result<()> {
    // Previously this used a deterministic `users.toml.tmp`
    // name, which raced under concurrent admin invocations and
    // could leave the temp at relaxed permissions if it already
    // existed (`OpenOptionsExt::mode` is only honored at create).
    // tempfile::NamedTempFile gives us a random suffix, 0o600 by
    // default on Unix, and atomic `persist` over the destination.
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    std::fs::create_dir_all(&parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let mut tf = tempfile::NamedTempFile::new_in(&parent)
        .with_context(|| format!("failed to create temp file in {}", parent.display()))?;
    set_temp_file_permissions(&tf)?;
    tf.as_file_mut()
        .write_all(body.as_bytes())
        .with_context(|| format!("failed to write temp file under {}", parent.display()))?;
    tf.as_file().sync_all().ok();
    tf.persist(path)
        .with_context(|| format!("failed to persist tmp to {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn set_temp_file_permissions(tf: &tempfile::NamedTempFile) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = tf.as_file().metadata()?.permissions();
    perms.set_mode(0o600);
    tf.as_file().set_permissions(perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_temp_file_permissions(_tf: &tempfile::NamedTempFile) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Round-trip through the server's real config types now that
    // qftp-protocol is a dependency, so a schema drift (a renamed
    // permission key, a quota field change) fails these tests at the
    // exact deny_unknown_fields boundary the server enforces (#269).
    use qftp_protocol::user::UserConfig;

    fn tmp() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    #[test]
    fn add_then_list_then_remove() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        add_user(
            &p,
            "alice",
            None,
            Perms {
                read: true,
                write: true,
                delete: false,
                mkdir: true,
                rmdir: false,
                rename: false,
                chmod: false,
            },
        )
        .unwrap();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(body.contains("alice"));
        assert!(body.contains("write = true"));
        // Round-trip parse with the server's UserConfig to make sure
        // the file is consumable as-is.
        let cfg: UserConfig = toml::from_str(&body).unwrap();
        assert_eq!(cfg.users.len(), 1);
        assert_eq!(cfg.users[0].name, "alice");
        assert!(cfg.users[0].permissions.write);

        remove_user(&p, "alice").unwrap();
        let cfg: UserConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(cfg.users.is_empty());
    }

    #[test]
    fn add_duplicate_fails() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        let perms = Perms {
            read: true,
            write: false,
            delete: false,
            mkdir: false,
            rmdir: false,
            rename: false,
            chmod: false,
        };
        add_user(&p, "alice", None, perms).unwrap();
        let err = add_user(&p, "alice", None, perms).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn set_permissions_partial() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        add_user(
            &p,
            "alice",
            None,
            Perms {
                read: true,
                write: false,
                delete: false,
                mkdir: false,
                rmdir: false,
                rename: false,
                chmod: false,
            },
        )
        .unwrap();
        set_permissions(
            &p,
            "alice",
            PartialPerms {
                write: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        let cfg: UserConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(cfg.users[0].permissions.read);
        assert!(cfg.users[0].permissions.write);
    }

    #[test]
    fn remove_missing_user_errors() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        let err = remove_user(&p, "ghost").unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn set_quota_round_trips_and_clears() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        add_user(
            &p,
            "alice",
            None,
            Perms {
                read: true,
                write: true,
                delete: false,
                mkdir: false,
                rmdir: false,
                rename: false,
                chmod: false,
            },
        )
        .unwrap();
        set_quota(&p, "alice", Some(4096)).unwrap();
        let cfg: UserConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(cfg.users[0].quota_bytes, Some(4096));
        // Clearing removes the key -> unlimited (None).
        set_quota(&p, "alice", None).unwrap();
        let cfg: UserConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(cfg.users[0].quota_bytes, None);
    }

    #[test]
    fn set_quota_missing_user_errors() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        let err = set_quota(&p, "ghost", Some(10)).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn set_quota_rejects_zero() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        // Rejected before the user lookup, so a missing user is irrelevant.
        let err = set_quota(&p, "anyone", Some(0)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ambiguous"), "got: {msg}");
        assert!(msg.contains("--unlimited"), "got: {msg}");
    }

    #[test]
    fn perms_field_count_matches_perm_keys() {
        // Destructure without `..` so adding/removing a permission field
        // fails to compile here, forcing PERM_KEYS to be updated in lock
        // step (#40, guards the drift described in #269).
        let Perms {
            read,
            write,
            delete,
            mkdir,
            rmdir,
            rename,
            chmod,
        } = Perms {
            read: false,
            write: false,
            delete: false,
            mkdir: false,
            rmdir: false,
            rename: false,
            chmod: false,
        };
        let perms_fields = [read, write, delete, mkdir, rmdir, rename, chmod];
        assert_eq!(perms_fields.len(), PERM_KEYS.len());

        let PartialPerms {
            read,
            write,
            delete,
            mkdir,
            rmdir,
            rename,
            chmod,
        } = PartialPerms::default();
        let partial_fields = [read, write, delete, mkdir, rmdir, rename, chmod];
        assert_eq!(partial_fields.len(), PERM_KEYS.len());
    }

    #[test]
    fn build_perms_table_preserves_perm_keys_order() {
        // Locks the serialized inline-table key order to PERM_KEYS so a
        // refactor can't silently reorder users.toml output (#19/#40).
        let it = build_perms_table(Perms {
            read: true,
            write: true,
            delete: true,
            mkdir: true,
            rmdir: true,
            rename: true,
            chmod: true,
        });
        let keys: Vec<&str> = it.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, PERM_KEYS);
    }

    #[test]
    fn set_quota_rejects_overflow() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        let err = set_quota(&p, "anyone", Some(i64::MAX as u64 + 1)).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "got: {err}");
    }

    fn ro_perms() -> Perms {
        Perms {
            read: true,
            write: false,
            delete: false,
            mkdir: false,
            rmdir: false,
            rename: false,
            chmod: false,
        }
    }

    #[test]
    fn add_user_rejects_empty_name() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        let err = add_user(&p, "", None, ro_perms()).unwrap_err();
        assert!(err.to_string().contains("non-empty"), "got: {err}");
        // Nothing should have been written for the rejected name.
        let cfg: UserConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(cfg.users.is_empty());
    }

    #[test]
    fn add_user_rejects_padded_name() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        let err = add_user(&p, " alice", None, ro_perms()).unwrap_err();
        assert!(err.to_string().contains("whitespace"), "got: {err}");
        let err = add_user(&p, "alice\t", None, ro_perms()).unwrap_err();
        assert!(err.to_string().contains("whitespace"), "got: {err}");
        let cfg: UserConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(cfg.users.is_empty());
    }

    #[test]
    fn add_user_rejects_reserved_anonymous() {
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        let err = add_user(&p, "anonymous", None, ro_perms()).unwrap_err();
        assert!(err.to_string().contains("reserved"), "got: {err}");
        let cfg: UserConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(cfg.users.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn add_user_rejects_non_utf8_home() {
        use std::os::unix::ffi::OsStrExt;
        let d = tmp();
        let p = d.path().join("users.toml");
        init_users(&p).unwrap();
        let bad = Path::new(std::ffi::OsStr::from_bytes(&[0xff, 0xfe]));
        let err = add_user(&p, "alice", Some(bad), ro_perms()).unwrap_err();
        assert!(err.to_string().contains("valid UTF-8"), "got: {err}");
        // The user must not have been added with a mangled home.
        let cfg: UserConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(cfg.users.is_empty());
    }

    #[test]
    fn set_permissions_preserves_subtable_form() {
        // A hand-edited standard sub-table (`[users.permissions]`) must be
        // lifted into an inline table without dropping pre-existing flags
        // (exercises the `Item::Table` arm in set_permissions, which
        // add_user's inline-table output never reaches).
        let d = tmp();
        let p = d.path().join("users.toml");
        let body = "\
[[users]]
name = \"alice\"

[users.permissions]
read = true
";
        std::fs::write(&p, body).unwrap();
        set_permissions(
            &p,
            "alice",
            PartialPerms {
                write: Some(true),
                ..Default::default()
            },
        )
        .unwrap();
        let cfg: UserConfig = toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        // Pre-existing read survives the lift; the new write is applied.
        assert!(cfg.users[0].permissions.read);
        assert!(cfg.users[0].permissions.write);
        assert!(!cfg.users[0].permissions.delete);
    }
}
