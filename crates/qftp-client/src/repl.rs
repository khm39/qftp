use qftp_common::protocol::{ErrorResponse, Request, Response};

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
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
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
    println!("  help                         Show this help message");
    println!("  quit                         Disconnect and exit");
    println!();
    println!("Tips:");
    println!("  - Local glob: `put *.log` expands on the client side.");
    println!("  - Use `-r` to walk directories on get/put.");
}
