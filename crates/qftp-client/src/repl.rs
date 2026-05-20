use qftp_common::protocol::{ErrorResponse, Request, Response};

use crate::stats::format_size;

#[derive(Debug)]
pub enum Command {
    Remote(Request),
    Get {
        remote: String,
        local: Option<String>,
        recursive: bool,
    },
    Put {
        local: String,
        remote: Option<String>,
        recursive: bool,
    },
    /// `lcd <path>` — change the REPL's local working directory used
    /// when a `put` or `get` argument is a relative path. Does not
    /// chdir() the process, so background helpers stay where they
    /// were.
    Lcd(Option<String>),
    /// `lpwd` — show the REPL local cwd.
    Lpwd,
    /// `lls [path]` — list a local directory.
    Lls(Option<String>),
    /// `lmkdir <path>` — make a local directory (and parents).
    Lmkdir(String),
    /// `!cmd …` — pass the rest of the line to `$SHELL -c`. The
    /// empty `!` form spawns an interactive `$SHELL`.
    Shell(String),
    /// `stats` — print process-wide transfer counters
    /// (uptime, bytes up/down, success rate). Local; no protocol
    /// round-trip.
    Stats,
}

/// Pull `-r` / `--recursive` out of a token slice. Returns the flag and
/// the remaining positional arguments.
fn take_recursive_flag<'a>(parts: &'a [&'a str]) -> (bool, Vec<&'a str>) {
    let mut recursive = false;
    let mut rest = Vec::with_capacity(parts.len());
    for p in parts {
        if *p == "-r" || *p == "--recursive" {
            recursive = true;
        } else {
            rest.push(*p);
        }
    }
    (recursive, rest)
}

pub fn parse_command(line: &str) -> Option<Command> {
    // `!` is parsed before whitespace-split so the user can pass
    // pipes, quotes, redirection unmodified.
    if let Some(rest) = line.strip_prefix('!') {
        return Some(Command::Shell(rest.trim().to_string()));
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let cmd = parts[0].to_lowercase();
    let args = &parts[1..];
    match cmd.as_str() {
        "ls" | "dir" => {
            let path = args.first().unwrap_or(&"").to_string();
            Some(Command::Remote(Request::Ls { path }))
        }
        "cd" => {
            let path = args.first().unwrap_or(&"/").to_string();
            Some(Command::Remote(Request::Cd { path }))
        }
        "pwd" => Some(Command::Remote(Request::Pwd)),
        "get" => {
            let (recursive, args) = take_recursive_flag(args);
            if args.is_empty() {
                println!("Usage: get [-r] <remote> [local]");
                return None;
            }
            Some(Command::Get {
                remote: args[0].to_string(),
                local: args.get(1).map(|s| s.to_string()),
                recursive,
            })
        }
        "put" => {
            let (recursive, args) = take_recursive_flag(args);
            if args.is_empty() {
                println!("Usage: put [-r] <local> [remote]");
                return None;
            }
            Some(Command::Put {
                local: args[0].to_string(),
                remote: args.get(1).map(|s| s.to_string()),
                recursive,
            })
        }
        "mkdir" => {
            if args.is_empty() {
                println!("Usage: mkdir <path>");
                return None;
            }
            Some(Command::Remote(Request::Mkdir {
                path: args[0].to_string(),
            }))
        }
        "rmdir" => {
            if args.is_empty() {
                println!("Usage: rmdir <path>");
                return None;
            }
            Some(Command::Remote(Request::Rmdir {
                path: args[0].to_string(),
            }))
        }
        "rm" | "delete" => {
            if args.is_empty() {
                println!("Usage: rm <path>");
                return None;
            }
            Some(Command::Remote(Request::Rm {
                path: args[0].to_string(),
            }))
        }
        "rename" | "mv" => {
            if args.len() < 2 {
                println!("Usage: rename <from> <to>");
                return None;
            }
            Some(Command::Remote(Request::Rename {
                from: args[0].to_string(),
                to: args[1].to_string(),
            }))
        }
        "chmod" => {
            if args.len() < 2 {
                println!("Usage: chmod <mode_octal> <path>");
                return None;
            }
            let mode = match u32::from_str_radix(args[0], 8) {
                Ok(m) => m,
                Err(_) => {
                    println!("Invalid octal mode: {}", args[0]);
                    return None;
                }
            };
            Some(Command::Remote(Request::Chmod {
                path: args[1].to_string(),
                mode,
            }))
        }
        "stat" => {
            if args.is_empty() {
                println!("Usage: stat <path>");
                return None;
            }
            Some(Command::Remote(Request::Stat {
                path: args[0].to_string(),
            }))
        }
        "quota" => Some(Command::Remote(Request::Quota)),
        "lcd" => Some(Command::Lcd(args.first().map(|s| s.to_string()))),
        "lpwd" => Some(Command::Lpwd),
        "lls" => Some(Command::Lls(args.first().map(|s| s.to_string()))),
        "lmkdir" => {
            if args.is_empty() {
                println!("Usage: lmkdir <path>");
                return None;
            }
            Some(Command::Lmkdir(args[0].to_string()))
        }
        "stats" => Some(Command::Stats),
        "quit" | "exit" => Some(Command::Remote(Request::Quit)),
        "help" | "?" => {
            print_help();
            None
        }
        _ => {
            println!("Unknown command: {}", parts[0]);
            None
        }
    }
}

pub fn display_response(resp: &Response) {
    match resp {
        Response::Ok => println!("OK"),
        Response::Err(e) => display_error(e),
        Response::Path(p) => println!("{p}"),
        Response::DirListing(entries) => {
            println!("{:<12} {:>10}  {:<4}  NAME", "MODE", "SIZE", "TYPE");
            println!("{}", "-".repeat(50));
            for entry in entries {
                let type_str = if entry.is_dir { "DIR" } else { "file" };
                println!(
                    "{:<12} {:>10}  {:<4}  {}",
                    format_mode(entry.mode),
                    format_size(entry.size),
                    type_str,
                    entry.name,
                );
            }
        }
        Response::FileStat(s) => {
            let type_str = if s.is_dir { "directory" } else { "file" };
            println!("  Size: {}", format_size(s.size));
            println!("  Type: {type_str}");
            println!("  Mode: {:o}", s.mode & 0o777);
            println!("  Modified: {}", s.modified);
        }
        Response::QuotaInfo {
            used_bytes,
            file_count,
            limit_bytes,
        } => {
            println!("Used:  {} ({file_count} files)", format_size(*used_bytes));
            match limit_bytes {
                Some(lim) => {
                    let pct = if *lim > 0 {
                        (*used_bytes as f64 / *lim as f64) * 100.0
                    } else {
                        0.0
                    };
                    println!("Quota: {} ({pct:.1}% used)", format_size(*lim));
                }
                None => println!("Quota: unlimited"),
            }
        }
        Response::FileReady {
            size,
            total_size,
            checksum_follows,
        } => {
            println!(
                "File ready: {size} bytes (total {total_size}{})",
                if *checksum_follows {
                    ", checksum follows"
                } else {
                    ""
                }
            );
        }
        _ => println!("Response: {resp:?}"),
    }
}

pub fn display_error(e: &ErrorResponse) {
    println!("Error [{:?}]: {}", e.code, e.message);
    if let Some(hint) = error_hint(&e.code) {
        println!("  hint: {hint}");
    }
}

/// Short, actionable suggestion to show after an `ErrorCode`. None
/// for codes that already speak for themselves (`AlreadyExists`,
/// `NotADirectory`, ...).
pub fn error_hint(code: &qftp_common::protocol::ErrorCode) -> Option<&'static str> {
    use qftp_common::protocol::ErrorCode::*;
    Some(match code {
        NotFound => "use `ls` to see what's actually there.",
        PermissionDenied => {
            "check the user's permissions in users.toml \
            (run `qftp-admin set-permissions ...`)."
        }
        Unauthorized => {
            "did you pass `--client-cert` / `--client-key`? \
            If the server uses TOFU, did the host fingerprint change?"
        }
        ChecksumMismatch => {
            "the bytes arrived but didn't hash correctly. \
            Network corruption or a storage fault; retry the transfer."
        }
        InvalidRange => {
            "the resume offset doesn't match the server's \
            partial-file length. Remove the local file (or the server's \
            `.qftp.partial.*`) and retry."
        }
        RateLimited => {
            "the server's per-IP token bucket refused this \
            request. Back off, or raise `--max-connections-per-ip` on the server."
        }
        FileTooLarge => {
            "the file exceeds the server's MAX_FILE_SIZE. \
            See docs/protocol.md and consider splitting or compressing."
        }
        Unsupported => {
            "the server doesn't support this operation in the \
            current context. If you got this on a write while resuming, \
            it likely arrived in 0-RTT (#76); retry after the handshake \
            completes (the client does so automatically)."
        }
        Malformed => {
            "the server rejected the framing as malformed. \
            Are the client and server the same major version (qftp/1)?"
        }
        QuotaExceeded => {
            "you've hit your per-user storage limit. Free some space (`rm`), \
            or ask the operator to raise `quota_bytes` in users.toml."
        }
        _ => return None,
    })
}

fn format_mode(mode: u32) -> String {
    let mode = mode & 0o777;
    let mut s = String::with_capacity(9);
    let flags = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (bit, ch) in flags {
        if mode & bit != 0 {
            s.push(ch);
        } else {
            s.push('-');
        }
    }
    s
}

fn print_help() {
    println!("Available commands:");
    println!("  ls [path]                    List directory contents");
    println!("  cd [path]                    Change remote directory");
    println!("  pwd                          Print remote working directory");
    println!("  get [-r] <remote> [local]    Download (auto-resumes if local exists)");
    println!("  put [-r] <local> [remote]    Upload (BLAKE3 checksum verified)");
    println!("  mkdir <path>                 Create a directory");
    println!("  rmdir <path>                 Remove a directory");
    println!("  rm <path>                    Delete a file");
    println!("  rename <from> <to>           Rename/move a file");
    println!("  chmod <mode> <path>          Change file permissions (octal)");
    println!("  stat <path>                  Show file information");
    println!("  quota                        Show your storage usage and limit");
    println!("  lcd [path]                   Change the REPL's local cwd (no $HOME → /)");
    println!("  lpwd                         Print the REPL's local cwd");
    println!("  lls [path]                   List a local directory");
    println!("  lmkdir <path>                Create a local directory");
    println!("  !cmd ...                     Run `cmd` via $SHELL -c");
    println!("  !                            Spawn an interactive $SHELL");
    println!("  stats                        Show session transfer counters");
    println!("  help                         Show this help message");
    println!("  quit                         Disconnect and exit");
    println!();
    println!("Tips:");
    println!("  - Local glob: `put *.log` expands on the client side.");
    println!("  - Use `-r` to walk directories on get/put.");
    println!("  - `lcd` is REPL-scoped; the client process never chdir()'s.");
}
