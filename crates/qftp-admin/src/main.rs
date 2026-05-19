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
//! qftp-admin generate-completions <SHELL>
//! ```
//!
//! All commands accept `--users <path>` to point at a non-default
//! file (default `/etc/qftp/users.toml`).
//!
//! Runtime ops (kick / show-connections / reload) require a server
//! admin socket and are deferred to a follow-up of #79.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

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
    /// Print a shell-completion script and exit.
    GenerateCompletions { shell: Shell },
}

fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::GenerateCompletions { shell } => {
            let mut cmd = Args::command();
            let bin = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, bin, &mut std::io::stdout());
            Ok(())
        }
        Command::InitUsers => init_users(&args.users),
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
            &args.users,
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
        Command::RemoveUser { name } => remove_user(&args.users, &name),
        Command::ListUsers => list_users(&args.users),
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
            &args.users,
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

const PERM_KEYS: &[&str] = &[
    "read", "write", "delete", "mkdir", "rmdir", "rename", "chmod",
];

fn init_users(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("{} already exists; refusing to overwrite", path.display());
    }
    let body = "# qftp-server user database -- managed by `qftp-admin`.\n\
                # Run `qftp-admin add-user NAME --read --write ...` to add an entry.\n\n";
    write_atomic(path, body)
}

fn add_user(path: &Path, name: &str, home: Option<&Path>, perms: Perms) -> Result<()> {
    let mut doc = load_or_default(path)?;
    let users = ensure_users_array(&mut doc);

    if find_user_index(users, name).is_some() {
        bail!("user '{name}' already exists; use `set-permissions` to modify");
    }

    let mut table = toml_edit::Table::new();
    table.insert("name", toml_edit::value(name));
    if let Some(h) = home {
        table.insert("home", toml_edit::value(h.to_string_lossy().to_string()));
    }
    let mut perms_tbl = toml_edit::InlineTable::new();
    perms_tbl.insert("read", perms.read.into());
    perms_tbl.insert("write", perms.write.into());
    perms_tbl.insert("delete", perms.delete.into());
    perms_tbl.insert("mkdir", perms.mkdir.into());
    perms_tbl.insert("rmdir", perms.rmdir.into());
    perms_tbl.insert("rename", perms.rename.into());
    perms_tbl.insert("chmod", perms.chmod.into());
    table.insert(
        "permissions",
        toml_edit::Item::Value(toml_edit::Value::InlineTable(perms_tbl)),
    );

    users.push(table);
    write_atomic(path, &doc.to_string())?;
    println!("Added user '{name}' to {}.", path.display());
    Ok(())
}

fn remove_user(path: &Path, name: &str) -> Result<()> {
    let mut doc = load_existing(path)?;
    let users = ensure_users_array(&mut doc);
    let idx = find_user_index(users, name).ok_or_else(|| anyhow!("user '{name}' not found"))?;
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
    let inline_get = |k: &str| -> bool {
        match p {
            Some(toml_edit::Item::Value(toml_edit::Value::InlineTable(it))) => {
                it.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
            }
            Some(toml_edit::Item::Table(tt)) => {
                tt.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
            }
            _ => false,
        }
    };
    for k in PERM_KEYS {
        if inline_get(k) {
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
    let users = ensure_users_array(&mut doc);
    let idx = find_user_index(users, name).ok_or_else(|| anyhow!("user '{name}' not found"))?;

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
    let apply = |it: &mut toml_edit::InlineTable, k: &str, v: Option<bool>| {
        if let Some(b) = v {
            it.insert(k, b.into());
        }
    };
    apply(&mut perms_tbl, "read", partial.read);
    apply(&mut perms_tbl, "write", partial.write);
    apply(&mut perms_tbl, "delete", partial.delete);
    apply(&mut perms_tbl, "mkdir", partial.mkdir);
    apply(&mut perms_tbl, "rmdir", partial.rmdir);
    apply(&mut perms_tbl, "rename", partial.rename);
    apply(&mut perms_tbl, "chmod", partial.chmod);

    entry.insert(
        "permissions",
        toml_edit::Item::Value(toml_edit::Value::InlineTable(perms_tbl)),
    );
    write_atomic(path, &doc.to_string())?;
    println!("Updated permissions for '{name}' in {}.", path.display());
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

fn ensure_users_array(doc: &mut toml_edit::DocumentMut) -> &mut toml_edit::ArrayOfTables {
    if doc.get("users").is_none() {
        doc.insert("users", toml_edit::Item::ArrayOfTables(Default::default()));
    }
    doc["users"]
        .as_array_of_tables_mut()
        .expect("just inserted")
}

fn find_user_index(users: &toml_edit::ArrayOfTables, name: &str) -> Option<usize> {
    users
        .iter()
        .position(|t| t.get("name").and_then(|v| v.as_str()) == Some(name))
}

fn write_atomic(path: &Path, body: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    let tmp = path.with_extension("toml.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("failed to open {}", tmp.display()))?;
    f.write_all(body.as_bytes())
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    f.sync_all().ok();
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let cfg: ServerCompatConfig = toml::from_str(&body).unwrap();
        assert_eq!(cfg.users.len(), 1);
        assert_eq!(cfg.users[0].name, "alice");
        assert!(cfg.users[0].permissions.write);

        remove_user(&p, "alice").unwrap();
        let cfg: ServerCompatConfig =
            toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
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
        let cfg: ServerCompatConfig =
            toml::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
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

    // Minimal mirror of qftp-server::user::UserConfig so the round-
    // trip assertion above compiles without a workspace dependency
    // that would create a cycle. If the server schema changes, this
    // mirror must follow.
    #[derive(serde::Deserialize, Default)]
    struct ServerCompatConfig {
        #[serde(default)]
        users: Vec<ServerCompatUser>,
    }
    #[derive(serde::Deserialize)]
    struct ServerCompatUser {
        name: String,
        #[serde(default)]
        permissions: ServerCompatPerms,
    }
    #[derive(serde::Deserialize, Default)]
    struct ServerCompatPerms {
        #[serde(default)]
        read: bool,
        #[serde(default)]
        write: bool,
    }
}
