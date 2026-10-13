//! Tests of the ref-name rule on the write and resolution paths of the
//! library.
//!
//! A component of a ref name is not empty, does not start with `-` or `.`, and
//! holds only ASCII alphanumerics, `-`, `.`, `_`, and non-ASCII characters for
//! which `char::is_alphanumeric` is true, less the ones that the `ostree` tool
//! refuses. The remote of a refspec follows the same rule. Each test gives each path a name that only this rule refuses, and
//! checks that the refusal is `Error::InvalidRefspec` and that no ref file
//! stands afterward.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use ostrya::{
    Checksum, CollectionRef, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions,
    Error, MutableTree, Repo, RepoMode,
};
use ostrya_rt::block_on;

/// Names that only the ref-name rule refuses. `a:b:c` is a refspec with a `:`
/// in its name part. The others hold a no-break space, a zero-width space, an
/// emoji, and a combining mark, in place of a letter.
const REFUSED: [&str; 9] = [
    "a b",
    "a*",
    "-a",
    "a/.b",
    "a:b:c",
    "a\u{a0}b",
    "a\u{200b}b",
    "a\u{1f600}b",
    "a\u{301}b",
];

/// The collection id of the collection refs of the tests.
const COLLECTION: &str = "org.example.Rule";

/// Creates a repository and commits one file, without a ref. Returns the
/// repository and the commit.
async fn repo_with_commit(base: &Path) -> (Repo, Checksum) {
    let repo = Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap();
    let tree = base.join("src");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), "body\n").unwrap();
    let txn = repo.transaction().await.unwrap();
    let dfd = std::fs::File::open(&tree).unwrap();
    let mut modifier = Some(CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    ));
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, modifier.as_mut())
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                subject: Some("body".to_owned()),
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref("main", Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

/// Returns the paths of the regular files and links below `refs/` that the
/// test did not create, sorted.
fn ref_files(repo_dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = format!("{prefix}{}", entry.file_name().to_string_lossy());
            if entry.file_type().unwrap().is_dir() {
                walk(&entry.path(), &format!("{name}/"), out);
            } else {
                out.push(name);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo_dir.join("refs"), "", &mut out);
    out.sort();
    out
}

fn assert_refused<T: std::fmt::Debug>(result: Result<T, Error>, name: &str) {
    match result {
        Err(Error::InvalidRefspec(got)) => {
            assert!(got.contains(name), "{name:?}: the error names {got:?}")
        }
        other => panic!("{name:?}: {other:?}"),
    }
}

#[test]
fn a_ref_write_refuses_a_name_outside_the_rule() {
    block_on(async {
        let tmp = TmpDir::new("rule-write");
        let (repo, commit) = repo_with_commit(tmp.path()).await;
        let repo_dir = tmp.path().join("repo");
        let before = ref_files(&repo_dir);
        for name in REFUSED {
            assert_refused(repo.set_ref_immediate(name, Some(&commit)).await, name);

            let cref = CollectionRef::new(COLLECTION, name);
            assert_refused(
                repo.set_collection_ref_immediate(&cref, Some(&commit))
                    .await,
                name,
            );

            // The transaction checks the refspec at the commit, before it
            // publishes an object.
            let txn = repo.transaction().await.unwrap();
            txn.set_ref(name, Some(&commit));
            assert_refused(txn.commit().await, name);
            let txn = repo.transaction().await.unwrap();
            txn.set_collection_ref(&cref, Some(&commit));
            assert_refused(txn.commit().await, name);

            // The name fails as the alias and as the target of the alias.
            assert_refused(repo.set_ref_alias_immediate(name, "main").await, name);
            assert_refused(repo.set_ref_alias_immediate("al", name).await, name);

            assert_eq!(ref_files(&repo_dir), before, "{name:?} wrote a ref");
        }
        // A remote ref takes the rule for its name part and for its remote.
        for name in ["origin:a b", "o r:main", "o*:main", "-o:main", ".o:main"] {
            assert_refused(repo.set_ref_immediate(name, Some(&commit)).await, name);
        }
        assert_eq!(ref_files(&repo_dir), before);
    });
}

#[test]
fn a_ref_write_takes_a_name_inside_the_rule() {
    block_on(async {
        let tmp = TmpDir::new("rule-write-valid");
        let (repo, commit) = repo_with_commit(tmp.path()).await;
        for name in [
            "a.",
            "a..b",
            "_a",
            "a_b",
            "1a",
            "A",
            "é",
            "a/éb",
            "origin:é/a",
            "é:main",
            "o.:main",
            "a\u{4e2d}b",
            "a\u{b5}b",
        ] {
            repo.set_ref_immediate(name, Some(&commit)).await.unwrap();
            assert_eq!(
                repo.resolve_ref_tip(name).await.unwrap(),
                Some(commit),
                "{name}"
            );
        }
    });
}

#[test]
fn a_resolution_refuses_a_name_outside_the_rule() {
    block_on(async {
        let tmp = TmpDir::new("rule-resolve");
        let (repo, _) = repo_with_commit(tmp.path()).await;
        for name in REFUSED {
            assert_refused(repo.resolve_rev(name, true).await, name);
            assert_refused(repo.resolve_rev(name, false).await, name);
            assert_refused(repo.resolve_ref_tip(name).await, name);
        }
    });
}
