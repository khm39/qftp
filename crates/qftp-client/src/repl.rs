use qftp_common::protocol::{Request, Response};

#[derive(Debug)]
pub enum Command {
    Remote(Request),
    Get { remote: String, local: Option<String> },
    Put { local: String, remote: Option<String> },
}

pub fn parse_command(line: &str) -> Option<Command> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let cmd = parts[0].to_lowercase();
    match cmd.as_str() {
        "ls" | "dir" => {
            let path = parts.get(1).unwrap_or(&".").to_string();
            Some(Command::Remote(Request::Ls { path }))
        }
        "cd" => {
            let path = parts.get(1).unwrap_or(&"/").to_string();
            Some(Command::Remote(Request::Cd { path }))
        }
        "pwd" => Some(Command::Remote(Request::Pwd)),
        "get" => {
            if parts.len() < 2 {
                println!("Usage: get <remote> [local]");
                return None;
            }
            let remote = parts[1].to_string();
            let local = parts.get(2).map(|s| s.to_string());
            Some(Command::Get { remote, local })
        }
        "put" => {
            if parts.len() < 2 {
                println!("Usage: put <local> [remote]");
                return None;
            }
            let local = parts[1].to_string();
            let remote = parts.get(2).map(|s| s.to_string());
            Some(Command::Put { local, remote })
        }
        "mkdir" => {
            if parts.len() < 2 {
                println!("Usage: mkdir <path>");
                return None;
            }
            Some(Command::Remote(Request::Mkdir {
                path: parts[1].to_string(),
            }))
        }
        "rmdir" => {
            if parts.len() < 2 {
                println!("Usage: rmdir <path>");
                return None;
            }
            Some(Command::Remote(Request::Rmdir {
                path: parts[1].to_string(),
            }))
        }
        "rm" | "delete" => {
            if parts.len() < 2 {
                println!("Usage: rm <path>");
                return None;
            }
            Some(Command::Remote(Request::Rm {
                path: parts[1].to_string(),
            }))
        }
        "rename" | "mv" => {
            if parts.len() < 3 {
                println!("Usage: rename <from> <to>");
                return None;
            }
            Some(Command::Remote(Request::Rename {
                from: parts[1].to_string(),
                to: parts[2].to_string(),
            }))
        }
        "chmod" => {
            if parts.len() < 3 {
                println!("Usage: chmod <mode_octal> <path>");
                return None;
            }
            let mode = match u32::from_str_radix(parts[1], 8) {
                Ok(m) => m,
                Err(_) => {
                    println!("Invalid octal mode: {}", parts[1]);
                    return None;
                }
            };
            Some(Command::Remote(Request::Chmod {
                path: parts[2].to_string(),
                mode,
            }))
        }
        "stat" => {
            if parts.len() < 2 {
                println!("Usage: stat <path>");
                return None;
            }
            Some(Command::Remote(Request::Stat {
                path: parts[1].to_string(),
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
        Response::Err(e) => println!("Error: {e}"),
        Response::Path(p) => println!("{p}"),
        Response::DirListing(entries) => {
            println!(
                "{:<12} {:>10}  {:<4}  {}",
                "MODE", "SIZE", "TYPE", "NAME"
            );
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
        Response::FileReady { size } => {
            println!("File ready: {size} bytes");
        }
    }
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
    println!("  ls [path]              List directory contents");
    println!("  dir [path]             Alias for ls");
    println!("  cd [path]              Change remote directory");
    println!("  pwd                    Print remote working directory");
    println!("  get <remote> [local]   Download a file");
    println!("  put <local> [remote]   Upload a file");
    println!("  mkdir <path>           Create a directory");
    println!("  rmdir <path>           Remove a directory");
    println!("  rm <path>              Delete a file");
    println!("  delete <path>          Alias for rm");
    println!("  rename <from> <to>     Rename/move a file");
    println!("  mv <from> <to>         Alias for rename");
    println!("  chmod <mode> <path>    Change file permissions (octal mode)");
    println!("  stat <path>            Show file information");
    println!("  help                   Show this help message");
    println!("  quit                   Disconnect and exit");
    println!("  exit                   Alias for quit");
}
