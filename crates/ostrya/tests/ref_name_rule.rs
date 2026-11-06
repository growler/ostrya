//! Tests of the ref-name rule on the write and resolution paths of the
//! library.
//!
//! A component of a ref name is not empty, does not start with `-` or `.`, and
//! holds only ASCII alphanumerics, `-`, `.`, `_`, and non-ASCII characters for
//! which `char::is_alphanumeric` is true, less the ones that the `ostree` tool
//! refuses. The remote of a refspec follows the same rule. Each test gives each path a name that only this rule refuses, and
//! checks that the refusal is `Error::InvalidRefspec` and that no ref file
//! stands afterward. The id of a collection ref follows the collection-id
//! rule.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error,
    MutableTree, ObjectType, Ref, RefSelector, Repo, RepoMode,
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

/// Reads `refspec` as a ref with no check: `REMOTE:NAME`, split at the first
/// `:`, is a remote ref, and other text is a local ref.
fn refspec(refspec: &str) -> Ref {
    match refspec.split_once(':') {
        Some((remote, name)) => Ref::remote(remote, name),
        None => Ref::local(refspec),
    }
}

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
    txn.set_ref(&Ref::local("main"), Some(&commit));
    txn.commit().await.unwrap();
    (repo, commit)
}

/// Returns the paths of the regular files and links below `refs/` that the
/// test did not create, sorted.
fn ref_files(repo_dir: &Path) -> Vec<String> {
    files_below(&repo_dir.join("refs"))
}

/// Returns the paths of the regular files and links below `root`, sorted.
fn files_below(root: &Path) -> Vec<String> {
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
    walk(root, "", &mut out);
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
            assert_refused(
                repo.set_ref_immediate(&refspec(name), Some(&commit)).await,
                name,
            );

            let cref = Ref::collection(COLLECTION, name);
            assert_refused(repo.set_ref_immediate(&cref, Some(&commit)).await, name);

            // The transaction checks the refspec at the commit, before it
            // publishes an object.
            let txn = repo.transaction().await.unwrap();
            txn.set_ref(&refspec(name), Some(&commit));
            assert_refused(txn.commit().await, name);
            let txn = repo.transaction().await.unwrap();
            txn.set_ref(&cref, Some(&commit));
            assert_refused(txn.commit().await, name);

            // The name fails as the alias and as the target of the alias.
            assert_refused(repo.set_ref_alias_immediate(name, "main").await, name);
            assert_refused(repo.set_ref_alias_immediate("al", name).await, name);

            assert_eq!(ref_files(&repo_dir), before, "{name:?} wrote a ref");
        }
        // A remote ref takes the rule for its name part and for its remote.
        for name in ["origin:a b", "o r:main", "o*:main", "-o:main", ".o:main"] {
            assert_refused(
                repo.set_ref_immediate(&refspec(name), Some(&commit)).await,
                name,
            );
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
            repo.set_ref_immediate(&refspec(name), Some(&commit))
                .await
                .unwrap();
            assert_eq!(
                repo.resolve_ref_tip(&refspec(name)).await.unwrap(),
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
            assert_refused(repo.resolve_ref_tip(&refspec(name)).await, name);
            for r in [Ref::collection(COLLECTION, name), Ref::local(name)] {
                assert_refused(repo.resolve_ref_tip(&r).await, name);
            }
        }
    });
}

/// Collection ids that the collection-id rule refuses: one element, an empty
/// element, an element that starts with a digit, and an id of 256 bytes.
fn refused_ids() -> [String; 4] {
    [
        "a".to_owned(),
        "org..x".to_owned(),
        "1org.x".to_owned(),
        format!("a.{}", "b".repeat(254)),
    ]
}

/// Collection ids that the collection-id rule accepts. The last one is 255
/// bytes, the longest id that the ref store takes.
fn accepted_ids() -> [String; 4] {
    [
        COLLECTION.to_owned(),
        "_a.b".to_owned(),
        "A.b1".to_owned(),
        format!("a.{}", "b".repeat(253)),
    ]
}

/// Stages a commit of one new file in `txn` and returns it. `body` makes the
/// commit new to the repository.
async fn stage_commit(txn: &ostrya::Transaction, base: &Path, body: &str) -> Checksum {
    let tree = base.join(format!("src-{body}"));
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("b.txt"), format!("{body}\n")).unwrap();
    let dfd = std::fs::File::open(&tree).unwrap();
    let mut modifier = Some(CommitModifier::new(
        CommitModifierFlags::CANONICAL_PERMISSIONS | CommitModifierFlags::SKIP_XATTRS,
    ));
    let mut mtree = MutableTree::new();
    txn.write_dfd_to_mtree(dfd.as_fd(), Path::new("."), &mut mtree, modifier.as_mut())
        .await
        .unwrap();
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    txn.write_commit(
        CommitOptions {
            subject: Some(body.to_owned()),
            timestamp: Some(1_700_000_000),
            ..CommitOptions::default()
        },
        &root,
    )
    .await
    .unwrap()
}

#[test]
fn a_collection_ref_write_refuses_an_id_outside_the_rule() {
    block_on(async {
        let tmp = TmpDir::new("rule-collection-id");
        let (repo, commit) = repo_with_commit(tmp.path()).await;
        let repo_dir = tmp.path().join("repo");
        for (index, id) in refused_ids().iter().enumerate() {
            let cref = Ref::collection(id.as_str(), "main");
            let refs_before = ref_files(&repo_dir);
            let objects_before = files_below(&repo_dir.join("objects"));

            assert_refused(repo.set_ref_immediate(&cref, Some(&commit)).await, id);
            assert_eq!(ref_files(&repo_dir), refs_before, "{id:?} wrote a ref");

            // The transaction checks the id at the commit, before it
            // publishes an object.
            let txn = repo.transaction().await.unwrap();
            let staged = stage_commit(&txn, tmp.path(), &format!("staged-{index}")).await;
            txn.set_ref(&cref, Some(&staged));
            assert_refused(txn.commit().await, id);
            assert!(
                !repo.has_object(ObjectType::Commit, &staged).await.unwrap(),
                "{id:?}: the commit published the staged commit"
            );
            assert_eq!(ref_files(&repo_dir), refs_before, "{id:?} wrote a ref");
            assert_eq!(
                files_below(&repo_dir.join("objects")),
                objects_before,
                "{id:?} published an object"
            );
        }
    });
}

#[test]
fn an_update_guard_refuses_an_id_outside_the_rule() {
    block_on(async {
        let tmp = TmpDir::new("rule-collection-id-guard");
        let (repo, commit) = repo_with_commit(tmp.path()).await;
        let repo_dir = tmp.path().join("repo");
        let before = ref_files(&repo_dir);
        let guard = repo.begin_update().await.unwrap();
        for id in refused_ids() {
            let cref = Ref::collection(id.as_str(), "main");
            assert_refused(guard.set_ref(&cref, Some(&commit)).await, &id);
            assert_refused(guard.read_ref(&cref).await, &id);
        }
        guard.finish().await.unwrap();
        assert_eq!(ref_files(&repo_dir), before);
    });
}

/// Each case of `Ref` that fails the rule fails the transaction commit
/// before it publishes an object. The error holds the text of the ref.
#[test]
fn a_transaction_refuses_each_case_outside_the_rule_before_it_publishes() {
    block_on(async {
        let tmp = TmpDir::new("rule-each-case");
        let (repo, _) = repo_with_commit(tmp.path()).await;
        let repo_dir = tmp.path().join("repo");
        for (index, r) in [
            Ref::local("a b"),
            Ref::local("origin:main"),
            Ref::remote("o r", "main"),
            Ref::remote("origin", "-a"),
            Ref::collection("a", "main"),
            Ref::collection(COLLECTION, "-a"),
            Ref::collection(COLLECTION, "a:b"),
        ]
        .into_iter()
        .enumerate()
        {
            let refs_before = ref_files(&repo_dir);
            let objects_before = files_below(&repo_dir.join("objects"));
            let txn = repo.transaction().await.unwrap();
            let staged = stage_commit(&txn, tmp.path(), &format!("case-{index}")).await;
            txn.set_ref(&r, Some(&staged));
            match txn.commit().await {
                Err(Error::InvalidRefspec(got)) => assert_eq!(got, r.to_string()),
                other => panic!("{r}: {other:?}"),
            }
            assert!(
                !repo.has_object(ObjectType::Commit, &staged).await.unwrap(),
                "{r}: the commit published the staged commit"
            );
            assert_eq!(ref_files(&repo_dir), refs_before, "{r} wrote a ref");
            assert_eq!(
                files_below(&repo_dir.join("objects")),
                objects_before,
                "{r} published an object"
            );
        }
    });
}

#[test]
fn a_collection_ref_resolution_refuses_an_id_outside_the_rule() {
    block_on(async {
        let tmp = TmpDir::new("rule-collection-id-resolve");
        let (repo, _) = repo_with_commit(tmp.path()).await;
        for id in refused_ids() {
            let cref = Ref::collection(id.as_str(), "main");
            assert_refused(repo.resolve_ref_tip(&cref).await, &id);
        }
    });
}

#[test]
fn a_collection_listing_refuses_an_id_outside_the_rule() {
    block_on(async {
        let tmp = TmpDir::new("rule-collection-id-list");
        let (repo, _) = repo_with_commit(tmp.path()).await;
        let all = RefSelector::parse([]).unwrap();
        for id in refused_ids() {
            assert_refused(repo.list_collection_refs_in(&id, &all).await, &id);
        }
    });
}

#[test]
fn a_collection_ref_write_takes_an_id_inside_the_rule() {
    block_on(async {
        let tmp = TmpDir::new("rule-collection-id-valid");
        let (repo, commit) = repo_with_commit(tmp.path()).await;
        let repo_dir = tmp.path().join("repo");
        for id in accepted_ids() {
            let immediate = Ref::collection(id.as_str(), "immediate");
            repo.set_ref_immediate(&immediate, Some(&commit))
                .await
                .unwrap();

            let queued = Ref::collection(id.as_str(), "queued");
            let txn = repo.transaction().await.unwrap();
            txn.set_ref(&queued, Some(&commit));
            txn.commit().await.unwrap();

            let guarded = Ref::collection(id.as_str(), "guarded");
            let guard = repo.begin_update().await.unwrap();
            guard.set_ref(&guarded, Some(&commit)).await.unwrap();
            assert_eq!(
                guard.read_ref(&guarded).await.unwrap(),
                Some(commit),
                "{id}"
            );
            guard.finish().await.unwrap();

            for name in ["immediate", "queued", "guarded"] {
                let path = repo_dir.join(format!("refs/mirrors/{id}/{name}"));
                assert!(path.is_file(), "{id}: no ref file {name}");
            }
        }
    });
}

/// A directory under `refs/mirrors/` whose name fails the rule comes from an
/// out-of-band write alone. The ref store does not remove a ref under it.
#[test]
fn a_ref_under_an_invalid_collection_directory_stays() {
    block_on(async {
        let tmp = TmpDir::new("rule-collection-id-stays");
        let (repo, commit) = repo_with_commit(tmp.path()).await;
        let path = tmp.path().join("repo/refs/mirrors/fresh/x");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, format!("{commit}\n")).unwrap();
        assert_refused(
            repo.set_ref_immediate(&Ref::collection("fresh", "x"), None)
                .await,
            "@fresh:x",
        );
        assert_refused(
            repo.resolve_ref_tip(&Ref::collection("fresh", "x")).await,
            "@fresh:x",
        );
        assert_refused(
            repo.list_collection_refs_in("fresh", &RefSelector::parse([]).unwrap())
                .await,
            "fresh",
        );
        assert!(path.is_file(), "the ref store removed the ref");
    });
}
