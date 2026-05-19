//! Embed a few build-time facts into the binary for `--version`.
//! Run on every build; cheap because we only invoke `git` / read
//! env vars.

use std::process::Command;

fn main() {
    // Git short SHA + "+dirty" suffix when there are uncommitted
    // changes. Falls back to "unknown" when the build is not in a
    // git checkout (release tarballs).
    let git = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    let git_full = if dirty { format!("{git}+dirty") } else { git };
    println!("cargo:rustc-env=QFTP_GIT_REV={git_full}");

    // ISO-8601 UTC at build time.
    let date = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=QFTP_BUILD_DATE={date}");

    // Target triple is exposed to build scripts by cargo as TARGET.
    let triple = std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    println!("cargo:rustc-env=TARGET_TRIPLE={triple}");

    // Re-run when the working tree's git state changes.
    println!("cargo:rerun-if-changed=.git/HEAD");
}
