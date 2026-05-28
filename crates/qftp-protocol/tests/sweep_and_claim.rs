//! Regression coverage for two server-side invariants flagged in #274:
//!
//!   * `sweep_stale_partials` only removes *old* `*.qftp.partial`
//!     uploads, never fresh ones, never a bare `.qftp.partial`, and it
//!     recurses into nested directories.
//!   * `UploadClaim::try_claim` refuses a second concurrent Put to the
//!     same path, releases the claim on drop, and treats distinct
//!     paths independently.

use std::collections::HashSet;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use qftp_protocol::stream::UploadClaim;
use qftp_protocol::user::{sweep_stale_partials, Permissions, User};

fn test_user(home: &Path) -> Arc<User> {
    Arc::new(User {
        name: "t".to_string(),
        home: home.to_path_buf(),
        permissions: Permissions::full(),
        quota_bytes: Some(1_000_000),
        used_bytes: AtomicU64::new(0),
        in_flight_bytes: AtomicU64::new(0),
        active_uploads: Mutex::new(HashSet::new()),
    })
}

/// Write `path` and back-date its mtime by `age`. `set_modified` is
/// stable std, so this stays dependency-free.
fn write_aged(path: &Path, age: Duration) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let f = File::create(path).unwrap();
    f.set_modified(SystemTime::now() - age).unwrap();
}

const STALE: Duration = Duration::from_secs(48 * 60 * 60);
const FRESH: Duration = Duration::from_secs(60);

#[test]
fn sweep_removes_old_partials_keeps_fresh_and_bare() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    let old_partial = root.join("a.bin.qftp.partial");
    let fresh_partial = root.join("b.bin.qftp.partial");
    let bare_partial = root.join(".qftp.partial");
    let regular = root.join("c.bin");
    let nested_old = root.join("sub").join("deep").join("d.bin.qftp.partial");
    let nested_fresh = root.join("sub").join("e.bin.qftp.partial");

    write_aged(&old_partial, STALE);
    write_aged(&fresh_partial, FRESH);
    write_aged(&bare_partial, STALE);
    write_aged(&regular, STALE);
    write_aged(&nested_old, STALE);
    write_aged(&nested_fresh, FRESH);

    sweep_stale_partials(root);

    assert!(!old_partial.exists(), "old partial should be swept");
    assert!(fresh_partial.exists(), "fresh partial must be kept");
    assert!(
        bare_partial.exists(),
        "bare .qftp.partial (no prefix) must be kept"
    );
    assert!(regular.exists(), "non-partial files must be kept");
    assert!(
        !nested_old.exists(),
        "old partial in nested dir should be swept (recursion)"
    );
    assert!(
        nested_fresh.exists(),
        "fresh partial in nested dir must be kept"
    );
}

#[test]
fn sweep_on_missing_root_is_a_noop() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    sweep_stale_partials(&missing);
}

#[test]
fn try_claim_refuses_second_put_to_same_path() {
    let dir = tempfile::tempdir().unwrap();
    let user = test_user(dir.path());
    let path = PathBuf::from("upload.bin.qftp.partial");

    let first = UploadClaim::try_claim(Arc::clone(&user), path.clone());
    assert!(first.is_some(), "first claim must succeed");

    let second = UploadClaim::try_claim(Arc::clone(&user), path.clone());
    assert!(
        second.is_none(),
        "second claim to same path must be refused"
    );
}

#[test]
fn dropping_claim_allows_reclaim() {
    let dir = tempfile::tempdir().unwrap();
    let user = test_user(dir.path());
    let path = PathBuf::from("upload.bin.qftp.partial");

    let first = UploadClaim::try_claim(Arc::clone(&user), path.clone());
    assert!(first.is_some());
    drop(first);

    let again = UploadClaim::try_claim(Arc::clone(&user), path.clone());
    assert!(again.is_some(), "claim must be re-acquirable after drop");
}

#[test]
fn distinct_paths_claim_independently() {
    let dir = tempfile::tempdir().unwrap();
    let user = test_user(dir.path());

    let a = UploadClaim::try_claim(Arc::clone(&user), PathBuf::from("a.qftp.partial"));
    let b = UploadClaim::try_claim(Arc::clone(&user), PathBuf::from("b.qftp.partial"));
    assert!(
        a.is_some() && b.is_some(),
        "distinct paths must claim independently"
    );
}
