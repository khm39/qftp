//! rustyline tab-completion helper for the REPL (#64).
//!
//! Two completion sources:
//!
//!   1. Command names at the start of the line. `qftp` has a fixed
//!      vocabulary (`ls`, `cd`, `put`, …), so we just prefix-match
//!      against a static list.
//!
//!   2. Local filesystem paths for the local-side argument of
//!      `put`, `lcd`, `lls`, `lmkdir`, and `!`-shell commands.
//!      Reuses `rustyline::completion::FilenameCompleter`, which
//!      already knows how to expand `~` and quote spaces.
//!
//! Remote-side completion (`cd <TAB>`, `get <TAB>`, …) would need a
//! synchronous `Ls` on the live QUIC connection -- which the editor
//! doesn't have a handle to from inside `complete()`. That's left
//! for a follow-up: a channel between the editor and the REPL loop
//! would let us cache remote directory listings and complete from
//! the cache.

use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};

/// All built-in command names. Kept in sync with `repl::parse_command`.
/// First-word prefix-completed by `complete_command`.
const COMMANDS: &[&str] = &[
    "ls", "dir", "cd", "pwd", "get", "put", "mkdir", "rmdir", "rm", "delete", "rename", "mv",
    "chmod", "stat", "quota", "lcd", "lpwd", "lls", "lmkdir", "stats", "quit", "exit", "help",
];

/// Commands whose first positional argument is a local path.
/// Completion falls through to `FilenameCompleter` for these.
const LOCAL_PATH_COMMANDS: &[&str] = &["put", "lcd", "lls", "lmkdir"];

pub struct ReplHelper {
    filenames: FilenameCompleter,
}

impl ReplHelper {
    pub fn new() -> Self {
        Self {
            filenames: FilenameCompleter::new(),
        }
    }
}

impl Default for ReplHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl Helper for ReplHelper {}

impl Hinter for ReplHelper {
    type Hint = String;
}

impl Highlighter for ReplHelper {}

impl Validator for ReplHelper {}

impl Completer for ReplHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        // `!cmd …` -> defer to shell-side completion. The cheapest
        // thing we can do is hand off to `FilenameCompleter` on the
        // tail of the line so `!ls /usr/<TAB>` still expands paths.
        if line.starts_with('!') {
            return self.filenames.complete(line, pos, ctx);
        }

        let upto_cursor = &line[..pos];
        let parts: Vec<&str> = upto_cursor.split_whitespace().collect();
        let trailing_space = upto_cursor.ends_with(char::is_whitespace);

        // No tokens yet, or we're still typing the first word -> command completion.
        if parts.is_empty() || (parts.len() == 1 && !trailing_space) {
            let prefix = parts.first().copied().unwrap_or("");
            let start = pos - prefix.len();
            let cands = complete_command(prefix);
            return Ok((start, cands));
        }

        let cmd = parts[0].to_lowercase();
        if LOCAL_PATH_COMMANDS.contains(&cmd.as_str()) {
            return self.filenames.complete(line, pos, ctx);
        }

        // Unknown / remote commands: no completion candidates.
        // Returning an empty list keeps the cursor put rather than
        // beeping awkwardly.
        Ok((pos, Vec::new()))
    }
}

fn complete_command(prefix: &str) -> Vec<Pair> {
    let prefix_lower = prefix.to_lowercase();
    COMMANDS
        .iter()
        .filter(|name| name.starts_with(&prefix_lower))
        .map(|name| Pair {
            display: (*name).to_string(),
            replacement: (*name).to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_lists_every_command() {
        let cands = complete_command("");
        // Surface a stable count rather than a fragile equality so
        // adding a future command doesn't break the test.
        assert!(cands.len() >= 20);
    }

    #[test]
    fn prefix_filters_candidates() {
        let cands = complete_command("rm");
        let names: Vec<&str> = cands.iter().map(|p| p.replacement.as_str()).collect();
        assert!(names.contains(&"rm"));
        assert!(names.contains(&"rmdir"));
        assert!(!names.contains(&"cd"));
    }

    #[test]
    fn unknown_prefix_returns_empty() {
        assert!(complete_command("xyzzy").is_empty());
    }

    #[test]
    fn lowercase_match_is_case_insensitive() {
        let cands = complete_command("LS");
        assert!(cands.iter().any(|p| p.replacement == "ls"));
    }
}
