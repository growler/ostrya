//! Abbreviated-checksum resolution (Phase 17f, item X1).
//!
//! A revision shorter than a full checksum names the one commit object whose
//! checksum starts with it. These tests pin the rule at the library boundary:
//! which objects the match set holds, what a prefix more than one commit carries
//! reports, and where the scan stands against the ref store. The behavior was
//! recovered from the `ostree` tool as a black box and is stated in
//! `docs/format-reference.md`, "Revision syntax"; the invocation-level comparison
//! against the tool is in `crates/ostrya-cli/tests/cli.rs`.

mod common;

use std::os::fd::AsFd;
use std::path::Path;

use common::TmpDir;
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, Error,
    MutableTree, ObjectType, Repo, RepoMode,
};
use ostrya_rt::block_on;

/// Commit a one-file tree whose content is `body`, on `branch`, parented on
/// `parent`. The timestamp varies with the body so each commit is a distinct
/// object, and the walk uses canonical permissions so the objects do not depend
/// on the test environment.
async fn commit_body(
    repo: &Repo,
    base: &Path,
    branch: &str,
    body: &str,
    parent: Option<Checksum>,
) -> Checksum {
    let tree = base.join("src");
    std::fs::create_dir_all(&tree).unwrap();
    std::fs::write(tree.join("a.txt"), body).unwrap();
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
                parent,
                subject: Some(body.to_owned()),
                timestamp: Some(1_700_000_000 + body.len() as u64),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.set_ref(branch, Some(&commit));
    txn.commit().await.unwrap();
    commit
}

/// Commit bodies until two commits share their first hex character, returning
/// that character. The checksums are content-addressed, so the collision is
/// found by committing rather than chosen.
async fn ambiguous_prefix(repo: &Repo, base: &Path) -> String {
    let mut seen: Vec<Checksum> = Vec::new();
    for n in 0..400 {
        let body = format!("body {n}");
        let commit = commit_body(repo, base, &format!("probe-{n}"), &body, None).await;
        let head = commit.to_hex()[..1].to_owned();
        if seen.iter().any(|c| c.to_hex().starts_with(&head)) {
            return head;
        }
        seen.push(commit);
    }
    panic!("no two commits shared a first character in 400 tries");
}

#[test]
fn an_abbreviated_checksum_resolves_at_every_length() {
    block_on(async {
        let tmp = TmpDir::new("abbrev-lengths");
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit = commit_body(&repo, tmp.path(), "only", "one\n", None).await;
        let hex = commit.to_hex();

        // Every prefix of the one commit resolves to it, from a single
        // character up to the character before a full checksum.
        for len in [1usize, 2, 3, 4, 8, 32, 63] {
            assert_eq!(
                repo.resolve_rev(&hex[..len], false).await.unwrap(),
                Some(commit),
                "prefix of {len} characters"
            );
        }
        // The full checksum keeps resolving to itself, and one character more
        // is a ref name that names nothing.
        assert_eq!(repo.resolve_rev(&hex, false).await.unwrap(), Some(commit));
        assert!(matches!(
            repo.resolve_rev(&format!("{hex}a"), false).await,
            Err(Error::RefNotFound(_))
        ));
        // An uppercase rendering is a ref name, as it is at a full checksum.
        assert!(matches!(
            repo.resolve_rev(&hex[..8].to_uppercase(), false).await,
            Err(Error::RefNotFound(_))
        ));
        // The ancestry suffix applies to what the prefix resolved to: the one
        // commit here is a root commit.
        assert!(matches!(
            repo.resolve_rev(&format!("{}^", &hex[..6]), false).await,
            Err(Error::NoParentCommit(_))
        ));
    });
}

#[test]
fn the_match_set_holds_commit_objects_alone() {
    block_on(async {
        let tmp = TmpDir::new("abbrev-commits-only");
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit = commit_body(&repo, tmp.path(), "only", "one\n", None).await;

        // Every other object in the store is unreachable by prefix, whatever
        // its type, and a prefix no object carries is a ref name.
        let objects = repo.list_objects().await.unwrap();
        let mut others = 0;
        for name in &objects {
            if name.ty == ObjectType::Commit {
                continue;
            }
            others += 1;
            let hex = name.checksum.to_hex();
            assert!(
                matches!(
                    repo.resolve_rev(&hex[..8], false).await,
                    Err(Error::RefNotFound(_))
                ),
                "a {:?} object must not resolve by prefix",
                name.ty
            );
        }
        assert!(others > 0, "the store must hold non-commit objects");
        assert_eq!(
            repo.resolve_rev(&commit.to_hex()[..8], false)
                .await
                .unwrap(),
            Some(commit)
        );
    });
}

#[test]
fn a_prefix_more_than_one_commit_carries_is_ambiguous() {
    block_on(async {
        let tmp = TmpDir::new("abbrev-ambiguous");
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let prefix = ambiguous_prefix(&repo, tmp.path()).await;

        // Ambiguity is an error whatever `allow_noent` says: the name is not an
        // absent one.
        for allow_noent in [false, true] {
            let err = repo.resolve_rev(&prefix, allow_noent).await.unwrap_err();
            assert!(
                matches!(&err, Error::AmbiguousRefspec(rev) if *rev == prefix),
                "allow_noent = {allow_noent}: {err}"
            );
        }
        // The ancestry suffix reports the same failure: nothing was resolved to
        // walk back from.
        assert!(matches!(
            repo.resolve_rev(&format!("{prefix}^"), true).await,
            Err(Error::AmbiguousRefspec(_))
        ));
    });
}

#[test]
fn a_prefix_stands_ahead_of_a_ref_of_the_same_name() {
    block_on(async {
        let tmp = TmpDir::new("abbrev-versus-ref");
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let first = commit_body(&repo, tmp.path(), "base", "one\n", None).await;
        let prefix = first.to_hex()[..4].to_owned();

        // A hex name no commit begins with is a ref name, so the store carries
        // one under that name.
        let free = "dddd";
        assert!(matches!(
            repo.resolve_rev(free, false).await,
            Err(Error::RefNotFound(_))
        ));
        repo.set_ref_immediate(free, Some(&first)).await.unwrap();
        assert_eq!(repo.resolve_rev(free, false).await.unwrap(), Some(first));

        // A ref whose name is a prefix of a commit resolves to that commit and
        // not to the ref's own target, so the branch's tip is reached through
        // the ref listing and not through its name.
        let second = commit_body(&repo, tmp.path(), &prefix, "two\n", Some(first)).await;
        assert_ne!(first, second);
        assert_eq!(repo.resolve_rev(&prefix, false).await.unwrap(), Some(first));
        assert_eq!(
            repo.list_refs(Some(&prefix)).await.unwrap(),
            vec![(prefix.clone(), second)]
        );
    });
}

#[test]
fn a_ref_read_takes_no_prefix() {
    block_on(async {
        let tmp = TmpDir::new("abbrev-ref-read");
        let repo = Repo::create(
            &tmp.path().join("repo"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let commit = commit_body(&repo, tmp.path(), "base", "one\n", None).await;

        // `list_refs` reports the ref store, so the branch keeps its own tip
        // whatever a name would resolve to as a revision.
        assert_eq!(
            repo.list_refs(None).await.unwrap(),
            vec![("base".to_owned(), commit)]
        );
    });
}
