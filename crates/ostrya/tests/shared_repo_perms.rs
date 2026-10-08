//! The permission bits that a `bare-user-shared` repository forces on the
//! entries that ostrya creates inside it.
//!
//! These tests stand for one guarantee: a second member of the repository
//! group can write where the first member wrote. A test of that case needs two
//! uids, and these tests run under one uid. The mode assertions stand in for
//! the case.
//!
//! - The second uid needs a directory at `02770` and a lock file at `0660`.
//! - The forced modes replace the masked results, which deny the second uid.
//!   The masked results are `0755` at a mask of `022`, and a fixed `0600` for
//!   the staging sibling lock.
//!
//! The file-creation mask is global to the process and these tests run on
//! parallel threads, so no test here sets the mask. The test suite of
//! `ostrya-cli` proves the independence from `umask`: it runs the binary as a
//! child process.

mod common;

use std::fs::Permissions;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use common::TmpDir;
use ostrya::{CreateOptions, FileMeta, Repo, RepoMode};
use ostrya_core::{ObjectType, loose_path};
use ostrya_rt::block_on;

/// The directories a repository holds, in the order `init` creates them.
const LAYOUT_DIRS: &[&str] = &[
    "objects",
    "tmp",
    "tmp/cache",
    "refs",
    "refs/heads",
    "refs/remotes",
    "refs/mirrors",
    "state",
    "extensions",
];

/// The permission bits of `path`, the setuid, setgid, and sticky bits included.
fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

/// The `tmp/` entries of a live transaction: the staging directory and its
/// sibling lock file.
fn staging_entries(repo_path: &Path) -> (PathBuf, PathBuf) {
    let tmp = repo_path.join("tmp");
    let mut names: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(&tmp).expect("read tmp/").flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir && name.starts_with("staging-") {
            names.push(name);
        }
    }
    assert_eq!(names.len(), 1, "one staging dir during the transaction");
    let dir = tmp.join(&names[0]);
    let lock = tmp.join(format!("{}-lock", names[0]));
    (dir, lock)
}

/// Returns the mode that a directory gets under the mask of this process, if
/// the create requests `0775`. The layout directories request the same bits,
/// so a repository that forces no mode gets this mode.
fn masked_dir_mode(base: &Path, tag: &str) -> u32 {
    let probe = base.join(format!("probe-dir-{tag}"));
    std::fs::DirBuilder::new()
        .mode(0o775)
        .create(&probe)
        .expect("create the probe directory");
    mode_of(&probe)
}

/// Returns the mode that a file gets under the mask of this process, if the
/// create requests `0660`. `.lock` requests the same bits.
fn masked_lock_mode(base: &Path, tag: &str) -> u32 {
    let probe = base.join(format!("probe-file-{tag}"));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o660)
        .open(&probe)
        .expect("create the probe file");
    mode_of(&probe)
}

/// A fresh `bare-user-shared` repository: the root, every layout directory, and
/// `.lock`.
#[test]
fn shared_repo_forces_the_layout_and_lock_modes() {
    let dir = TmpDir::new("shared-layout");
    let repo_path = dir.path().join("repo");
    block_on(async {
        let repo = Repo::create(&repo_path, CreateOptions::new(RepoMode::BareUserShared))
            .await
            .expect("create the repository");
        // The first transaction creates `.lock`.
        let txn = repo.transaction().await.expect("begin a transaction");
        txn.abort().await.expect("abort the transaction");
    });

    assert_eq!(mode_of(&repo_path), 0o2770, "the repository root");
    for sub in LAYOUT_DIRS {
        assert_eq!(mode_of(&repo_path.join(sub)), 0o2770, "the {sub} directory");
    }
    assert_eq!(mode_of(&repo_path.join(".lock")), 0o660, ".lock");
}

/// One file object committed into a `bare-user-shared` repository: the staging
/// directory and its sibling lock while the transaction is live, then the
/// object fanout and the object itself.
#[test]
fn shared_repo_forces_the_staging_fanout_and_object_modes() {
    let dir = TmpDir::new("shared-commit");
    let repo_path = dir.path().join("repo");
    block_on(async {
        let repo = Repo::create(&repo_path, CreateOptions::new(RepoMode::BareUserShared))
            .await
            .expect("create the repository");
        let txn = repo.transaction().await.expect("begin a transaction");

        let checksum = txn
            .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o600), b"hello ostree\n")
            .await
            .expect("write the file object");

        let (staging_dir, staging_lock) = staging_entries(&repo_path);
        assert_eq!(mode_of(&staging_dir), 0o2770, "the staging directory");
        assert_eq!(mode_of(&staging_lock), 0o660, "the staging sibling lock");

        txn.commit().await.expect("commit the transaction");

        let loose = loose_path(&checksum, ObjectType::File, RepoMode::BareUserShared);
        let object = repo_path.join("objects").join(&loose);
        assert_eq!(
            mode_of(object.parent().expect("the fanout directory")),
            0o2770,
            "the objects fanout directory"
        );
        assert_eq!(mode_of(&object), 0o644, "the object file");
    });
}

/// A ref write and a detached-metadata write outside a transaction in a
/// `bare-user-shared` repository with no `tmp/`: the write creates `tmp/` at
/// the forced directory mode, and the ref file and the `.commitmeta` take
/// `0644`.
#[test]
fn shared_repo_forces_the_mode_of_a_tmp_a_ref_write_creates() {
    let dir = TmpDir::new("shared-ref-tmp");
    let repo_path = dir.path().join("repo");
    let tmp = repo_path.join("tmp");
    let checksum = ostrya::Checksum::from_bytes([7; 32]);
    block_on(async {
        let repo = Repo::create(&repo_path, CreateOptions::new(RepoMode::BareUserShared))
            .await
            .expect("create the repository");
        std::fs::remove_dir_all(&tmp).expect("remove tmp/");
        repo.set_ref_immediate("dir/one", Some(&checksum))
            .await
            .expect("write the ref");
        assert_eq!(mode_of(&tmp), 0o2770, "the tmp directory");
        assert_eq!(
            mode_of(&repo_path.join("refs/heads/dir/one")),
            0o644,
            "the ref file"
        );

        repo.write_commit_detached_metadata(&checksum, None)
            .await
            .expect("write the detached metadata");
        let loose = loose_path(&checksum, ObjectType::CommitMeta, RepoMode::BareUserShared);
        assert_eq!(
            mode_of(&repo_path.join("objects").join(&loose)),
            0o644,
            "the .commitmeta file"
        );
    });
}

/// The control: a `bare-user` repository keeps the masked modes. This test
/// shows that the forcing applies to the one repository mode.
#[test]
fn bare_user_repo_keeps_the_masked_modes() {
    let dir = TmpDir::new("bare-user-control");
    let repo_path = dir.path().join("repo");
    let expected_dir = masked_dir_mode(dir.path(), "bu");
    let expected_lock = masked_lock_mode(dir.path(), "bu");

    block_on(async {
        let repo = Repo::create(&repo_path, CreateOptions::new(RepoMode::BareUser))
            .await
            .expect("create the repository");
        let txn = repo.transaction().await.expect("begin a transaction");
        txn.abort().await.expect("abort the transaction");
    });

    assert_eq!(mode_of(&repo_path), expected_dir, "the repository root");
    for sub in LAYOUT_DIRS {
        assert_eq!(
            mode_of(&repo_path.join(sub)),
            expected_dir,
            "the {sub} directory"
        );
    }
    assert_eq!(mode_of(&repo_path.join(".lock")), expected_lock, ".lock");
}

/// The next transaction reaps a staging tree that a dead transaction left
/// behind, with the modes that a `bare-user-shared` repository gives it.
#[test]
fn shared_repo_reaps_a_stale_staging_dir() {
    let dir = TmpDir::new("shared-reap");
    let repo_path = dir.path().join("repo");
    block_on(Repo::create(
        &repo_path,
        CreateOptions::new(RepoMode::BareUserShared),
    ))
    .expect("create the repository");

    // Make a leftover staging directory with an unheld sibling lock. A crashed
    // transaction of another group member leaves this state behind.
    let tmp = repo_path.join("tmp");
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let stale = format!("staging-{}-STALE1", boot.trim());
    let stale_dir = tmp.join(&stale);
    std::fs::create_dir_all(stale_dir.join("aa")).unwrap();
    std::fs::write(stale_dir.join("aa").join("leftover"), b"x").unwrap();
    std::fs::set_permissions(&stale_dir, Permissions::from_mode(0o2770)).unwrap();
    let stale_lock = tmp.join(format!("{stale}-lock"));
    std::fs::write(&stale_lock, b"").unwrap();
    std::fs::set_permissions(&stale_lock, Permissions::from_mode(0o660)).unwrap();

    block_on(async {
        let repo = Repo::open(&repo_path).await.expect("open the repository");
        let txn = repo.transaction().await.expect("begin a transaction");
        assert!(
            !stale_dir.exists(),
            "the stale staging dir is reaped at transaction start"
        );
        assert!(!stale_lock.exists(), "the stale staging lock is reaped too");
        txn.abort().await.expect("abort the transaction");
    });
}
