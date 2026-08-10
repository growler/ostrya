//! The process-wide staging reap.
//!
//! [`ostrya::reap_process_staging`] removes the staging directory of every live
//! transaction in the process, so it holds this test binary to itself: a test
//! sharing the process would lose the staging directory of its own transaction.

mod common;

use std::path::{Path, PathBuf};

use common::TmpDir;
use ostrya::{CreateOptions, Repo, RepoMode};
use ostrya_rt::block_on;

/// The staging directory names present under `<repo>/tmp`.
fn staging_dirs(repo: &Path) -> Vec<String> {
    let tmp = repo.join("tmp");
    let mut dirs = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir && name.starts_with("staging-") && !name.ends_with("-lock") {
                dirs.push(name);
            }
        }
    }
    dirs
}

fn new_repo(tag: &str) -> (TmpDir, PathBuf) {
    let dir = TmpDir::new(tag);
    let repo_path = dir.path().join("repo");
    block_on(Repo::create(&repo_path, CreateOptions::new(RepoMode::Bare))).expect("create repo");
    (dir, repo_path)
}

/// The reap removes the staging directory of a transaction that is still live,
/// which is what a process ending without running destructors needs. Two live
/// transactions lose both directories and both sibling lock files, and the
/// transactions still abort cleanly afterward.
#[test]
fn reap_process_staging_removes_the_directories_of_live_transactions() {
    let (_dir, repo_path) = new_repo("txn-reap-process");
    block_on(async {
        let repo = Repo::open(&repo_path).await.unwrap();
        let t1 = repo.transaction().await.unwrap();
        let t2 = repo.transaction().await.unwrap();
        let names = staging_dirs(&repo_path);
        assert_eq!(names.len(), 2, "two live transactions, two staging dirs");

        ostrya::reap_process_staging();

        assert!(
            staging_dirs(&repo_path).is_empty(),
            "the reap removed every staging dir this process owns"
        );
        for name in names {
            let lock = repo_path.join("tmp").join(format!("{name}-lock"));
            assert!(!lock.exists(), "the reap removed the sibling lock {name}");
        }
        t1.abort().await.unwrap();
        t2.abort().await.unwrap();
    });
}
