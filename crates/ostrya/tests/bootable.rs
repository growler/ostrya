#![forbid(unsafe_code)]

//! Integration tests of the kernel version of a tree.
//!
//! Each tree shape goes through the two entry points:
//!
//! - [`Transaction::kernel_version`] reads the tree while it is staged.
//! - [`RepoTree::kernel_version`] reads the same tree after the commit that
//!   holds it is published.
//!
//! The two must give the same answer for each shape, because one walk serves
//! both.
//!
//! Two more tests check the boundary between the two forms. The staged form
//! reads a kernel directory that exists only in the open transaction. The
//! published form reads a kernel directory from `objects/` with no open
//! transaction.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use ostrya::{
    BootableRefusal, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions,
    MutableTree, Repo, RepoMode, RepoTree, Transaction,
};
use ostrya_rt::block_on;

/// Builds one tree shape under `base/src` and returns the directory that holds
/// it. `kernels` names the directories under `/usr/lib/modules` that get a
/// `vmlinuz` entry.
fn build_tree(base: &Path, kernels: &[&str]) -> std::path::PathBuf {
    let src = base.join("src");
    let modules = src.join("usr/lib/modules");
    std::fs::create_dir_all(&modules).unwrap();
    for version in kernels {
        let dir = modules.join(version);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("vmlinuz"), b"k\n").unwrap();
    }
    src
}

/// Ingests `src` into a new root tree with canonical permissions, so that only
/// the shape of the tree decides the answer.
async fn ingest(txn: &Transaction, src: &Path) -> RepoTree {
    let mut modifier = CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    );
    let mut mtree = MutableTree::new();
    let parent = std::fs::File::open(src.parent().unwrap()).unwrap();
    let name = Path::new(src.file_name().unwrap());
    txn.write_dfd_to_mtree(parent.as_fd(), name, &mut mtree, Some(&mut modifier))
        .await
        .unwrap();
    txn.write_mtree(&mut mtree).await.unwrap()
}

/// The answer of one entry point: a kernel version or a refusal.
type Answer = std::result::Result<String, BootableRefusal>;

/// Runs `src` through the two entry points and returns the two answers: the
/// staged answer, then the published answer.
async fn both_answers(repo_dir: &Path, src: &Path) -> (Answer, Answer) {
    let repo = Repo::create(repo_dir, CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let txn = repo.transaction().await.unwrap();
    let root = ingest(&txn, src).await;
    let staged = txn.kernel_version(&root).await.unwrap();
    let checksum = txn
        .write_commit(CommitOptions::default(), &root)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    let (tree, _) = repo.read_commit(&checksum.to_hex()).await.unwrap();
    let published = tree.kernel_version().await.unwrap();
    (staged, published)
}

/// Builds `src`, runs it through the two entry points, and checks that both
/// answers are `expected`.
fn assert_both(tag: &str, expected: Answer, build: impl FnOnce(&Path) -> std::path::PathBuf) {
    let tmp = TmpDir::new(tag);
    let src = build(tmp.path());
    let repo_dir = tmp.path().join("repo");
    let (staged, published) = block_on(both_answers(&repo_dir, &src));
    assert_eq!(staged, expected, "{tag}: the staged answer");
    assert_eq!(published, expected, "{tag}: the published answer");
}

/// The one kernel directory names the version.
#[test]
fn one_kernel_names_the_version() {
    assert_both("bootable-one", Ok("6.1.0-test".to_owned()), |base| {
        build_tree(base, &["6.1.0-test"])
    });
}

/// Two kernel directories do not name one version.
#[test]
fn two_kernels_are_refused() {
    assert_both(
        "bootable-two",
        Err(BootableRefusal::MultipleKernels),
        |base| build_tree(base, &["1.0", "2.0"]),
    );
}

/// A `/usr/lib/modules` that holds directories, but no kernel, is refused.
#[test]
fn no_kernel_directory_is_refused() {
    assert_both("bootable-none", Err(BootableRefusal::NoKernel), |base| {
        let src = build_tree(base, &[]);
        std::fs::create_dir_all(src.join("usr/lib/modules/6.1.0")).unwrap();
        std::fs::write(src.join("usr/lib/modules/6.1.0/initramfs.img"), b"x\n").unwrap();
        src
    });
}

/// A tree with no `/usr` names the first component that it does not hold.
#[test]
fn a_missing_usr_names_that_component() {
    assert_both(
        "bootable-no-usr",
        Err(BootableRefusal::MissingComponent {
            path: "/usr".to_owned(),
        }),
        |base| {
            let src = base.join("src");
            std::fs::create_dir_all(&src).unwrap();
            std::fs::write(src.join("f"), b"x\n").unwrap();
            src
        },
    );
}

/// A tree that holds `/usr`, but not `/usr/lib`, names the deeper component.
#[test]
fn a_missing_lib_names_that_component() {
    assert_both(
        "bootable-no-lib",
        Err(BootableRefusal::MissingComponent {
            path: "/usr/lib".to_owned(),
        }),
        |base| {
            let src = base.join("src");
            std::fs::create_dir_all(src.join("usr/bin")).unwrap();
            std::fs::write(src.join("usr/bin/f"), b"x\n").unwrap();
            src
        },
    );
}

/// A tree that holds `/usr/lib`, but not `/usr/lib/modules`, names the last
/// component of the path. This is the third of the three components that the
/// walk can report as absent.
#[test]
fn a_missing_modules_names_that_component() {
    assert_both(
        "bootable-no-modules",
        Err(BootableRefusal::MissingComponent {
            path: "/usr/lib/modules".to_owned(),
        }),
        |base| {
            let src = base.join("src");
            std::fs::create_dir_all(src.join("usr/lib/systemd")).unwrap();
            std::fs::write(src.join("usr/lib/systemd/f"), b"x\n").unwrap();
            src
        },
    );
}

/// A file at `/usr/lib/modules` is not a directory, and the walk does not
/// descend into it.
#[test]
fn a_file_at_modules_is_not_a_directory() {
    assert_both(
        "bootable-modules-file",
        Err(BootableRefusal::NotADirectory {
            path: "/usr/lib/modules".to_owned(),
        }),
        |base| {
            let src = base.join("src");
            std::fs::create_dir_all(src.join("usr/lib")).unwrap();
            std::fs::write(src.join("usr/lib/modules"), b"x\n").unwrap();
            src
        },
    );
}

/// The staged form reads the objects of the open transaction. Before the
/// transaction commits, the published form cannot read the root dirtree of
/// the same tree. A caller that derives commit metadata needs the staged form for
/// this reason.
#[test]
fn the_staged_form_reads_an_uncommitted_tree() {
    let tmp = TmpDir::new("bootable-staged");
    let src = build_tree(tmp.path(), &["6.1.0-test"]);
    let repo_dir = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root = ingest(&txn, &src).await;
        assert_eq!(
            txn.kernel_version(&root).await.unwrap(),
            Ok("6.1.0-test".to_owned())
        );
        assert!(
            root.kernel_version().await.is_err(),
            "the published form read a tree that is still staged"
        );
        txn.abort().await.unwrap();
    });
}

/// The published form reads a commit with no transaction open.
#[test]
fn the_published_form_reads_a_committed_tree() {
    let tmp = TmpDir::new("bootable-published");
    let src = build_tree(tmp.path(), &["6.1.0-test"]);
    let repo_dir = tmp.path().join("repo");
    block_on(async {
        let repo = Repo::create(&repo_dir, CreateOptions::new(RepoMode::Archive))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        let root = ingest(&txn, &src).await;
        let checksum = txn
            .write_commit(CommitOptions::default(), &root)
            .await
            .unwrap();
        txn.set_ref("kernel", Some(&checksum));
        txn.commit().await.unwrap();

        let reopened = Repo::open(&repo_dir).await.unwrap();
        let (tree, _) = reopened.read_commit("kernel").await.unwrap();
        assert_eq!(
            tree.kernel_version().await.unwrap(),
            Ok("6.1.0-test".to_owned())
        );
    });
}
