#![no_main]
//! Fuzz the server-side path resolver. `handler::resolve` /
//! `resolve_parent` wrap the private `walk_safe`, which is what turns a
//! user-supplied path string from the wire into an on-disk path. A
//! malicious client controls that string completely, so the resolver
//! must never panic and must never return a path that escapes `root`.
//!
//! We feed arbitrary UTF-8 (lossily decoded from the fuzz bytes) as the
//! user path and assert the two invariants:
//!   * no panic (libfuzzer catches it),
//!   * every `Ok(path)` stays within `root` (the anti-traversal goal).
use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use qftp_protocol::handler::{resolve, resolve_parent};

struct Roots {
    root: PathBuf,
    cwd: PathBuf,
    _dir: tempfile::TempDir,
}

fn roots() -> &'static Roots {
    static ROOTS: OnceLock<Roots> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let dir = tempfile::tempdir().expect("fuzz tempdir");
        let root = dir.path().to_path_buf();
        let cwd = root.join("sub");
        std::fs::create_dir_all(&cwd).expect("fuzz cwd");
        // Populate the tree so fuzz inputs can reach branches that
        // need an existing on-disk component: a regular file (the
        // `Normal` -> existing-non-symlink `Ok(_)` path) and symlinks
        // pointing inside and outside `root` (the symlink-rejection
        // branch). Without these, those arms are unreachable.
        std::fs::File::create(cwd.join("file")).expect("fuzz file");
        std::os::unix::fs::symlink("sub", root.join("link_in")).expect("fuzz link_in");
        std::os::unix::fs::symlink("/tmp", root.join("link_out")).expect("fuzz link_out");
        Roots {
            root,
            cwd,
            _dir: dir,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let user_path = String::from_utf8_lossy(data);
    let r = roots();

    if let Ok(p) = resolve(&r.cwd, &r.root, &user_path) {
        assert!(
            p.starts_with(&r.root),
            "resolve escaped root: {p:?} not under {:?} (input {user_path:?})",
            r.root
        );
    }
    if let Ok(p) = resolve_parent(&r.cwd, &r.root, &user_path) {
        // `resolve_parent` returns the path whose parent must exist; the
        // resolved path itself must still be rooted.
        assert!(
            p.starts_with(&r.root),
            "resolve_parent escaped root: {p:?} not under {:?} (input {user_path:?})",
            r.root
        );
    }
});
