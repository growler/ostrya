//! Tests of the ref store with a `Ref`. They cover the ref path that each
//! case and each collection id reads and writes, the read of
//! `refs/heads/NAME` under the collection id of the repository, aliases,
//! absent refs, the read errors, the read while another handle holds the
//! update lock, and the revisions `@ID:NAME` and `@ID:NAME^`.

mod common;

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use common::TmpDir;
use ostrya::{
    Checksum, CommitOptions, CreateOptions, DirMeta, Error, MutableTree, Ref, Repo, RepoMode,
    Xattrs,
};
use ostrya_rt::block_on;

/// The `[core] collection-id` of the repositories of the tests.
const OWN: &str = "org.example.Own";

/// A collection id that is not the id of the repository.
const OTHER: &str = "org.example.Other";

/// Creates a repository at `<tmp>/repo` with the collection id `collection_id`
/// and returns its path.
fn create(tmp: &TmpDir, collection_id: Option<&str>) -> PathBuf {
    let path = tmp.path().join("repo");
    let mut opts = CreateOptions::new(RepoMode::BareUser);
    if let Some(id) = collection_id {
        opts = opts.collection_id(id);
    }
    block_on(Repo::create(&path, opts)).unwrap();
    path
}

fn open(path: &Path) -> Repo {
    block_on(Repo::open(path)).unwrap()
}

fn checksum(byte: u8) -> Checksum {
    Checksum::from_bytes([byte; 32])
}

/// Writes `checksum` to the collection ref `@id:name`.
async fn put(repo: &Repo, id: &str, name: &str, checksum: &Checksum) {
    repo.set_ref_immediate(&Ref::collection(id, name), Some(checksum))
        .await
        .unwrap();
}

/// Writes `checksum` to `refs/mirrors/OWN/name` of the repository at `path`
/// by hand, as a source outside the port does.
fn put_own_mirror(path: &Path, name: &str, checksum: &Checksum) {
    let file = path.join("refs/mirrors").join(OWN).join(name);
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, format!("{}\n", checksum.to_hex())).unwrap();
}

/// Writes `checksum` to the local ref `name`.
async fn put_local(repo: &Repo, name: &str, checksum: &Checksum) {
    repo.set_ref_immediate(&Ref::local(name), Some(checksum))
        .await
        .unwrap();
}

async fn resolve(repo: &Repo, r: &Ref) -> Option<Checksum> {
    repo.resolve_ref_tip(r).await.unwrap()
}

/// Returns the commit of `r`, or `Error::RefNotFound` with the text of `r`
/// if the ref is absent.
async fn resolve_or_not_found(repo: &Repo, r: &Ref) -> ostrya::Result<Option<Checksum>> {
    repo.resolve_ref_tip(r)
        .await?
        .map(Some)
        .ok_or_else(|| Error::RefNotFound(r.to_string()))
}

/// Asserts that `result` is `Error::RefNotFound` that holds `label`.
fn assert_not_found(result: ostrya::Result<Option<Checksum>>, label: &str) {
    match result {
        Err(Error::RefNotFound(got)) => assert_eq!(got, label),
        other => panic!("{label}: {other:?}"),
    }
}

/// Asserts that `result` is `Error::Io` of `kind`.
fn assert_io(result: ostrya::Result<Option<Checksum>>, kind: ErrorKind) {
    match result {
        Err(Error::Io(e)) => assert_eq!(e.kind(), kind, "{e}"),
        other => panic!("{kind:?}: {other:?}"),
    }
}

#[test]
fn a_mirror_ref_of_another_collection_resolves() {
    let tmp = TmpDir::new("ref-store-mirror");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put(&repo, OTHER, "main", &checksum(1)).await;
        put_local(&repo, "main", &checksum(2)).await;
        let cref = Ref::collection(OTHER, "main");
        assert_eq!(resolve(&repo, &cref).await, Some(checksum(1)));
        assert_eq!(
            repo.resolve_ref_tip(&cref).await.unwrap(),
            Some(checksum(1))
        );
    });
}

#[test]
fn another_collection_does_not_read_a_local_ref() {
    let tmp = TmpDir::new("ref-store-other-local");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put_local(&repo, "x", &checksum(1)).await;
        assert_eq!(resolve(&repo, &Ref::collection(OTHER, "x")).await, None);
    });
}

#[test]
fn the_own_collection_reads_a_local_ref() {
    let tmp = TmpDir::new("ref-store-own-local");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        let cref = Ref::collection(OWN, "main");
        assert_eq!(resolve(&repo, &cref).await, Some(checksum(1)));
        assert_eq!(
            repo.resolve_ref_tip(&cref).await.unwrap(),
            Some(checksum(1))
        );
    });
}

#[test]
fn the_own_collection_ignores_its_mirror_refs() {
    let tmp = TmpDir::new("ref-store-own-mirror");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    put_own_mirror(&path, "main", &checksum(1));
    put_own_mirror(&path, "only", &checksum(1));
    block_on(async {
        put_local(&repo, "main", &checksum(2)).await;
        assert_eq!(
            resolve(&repo, &Ref::collection(OWN, "main")).await,
            Some(checksum(2))
        );
        let only = Ref::collection(OWN, "only");
        assert_eq!(resolve(&repo, &only).await, None);
        assert_not_found(
            resolve_or_not_found(&repo, &only).await,
            &format!("@{OWN}:only"),
        );
    });
}

#[test]
fn a_local_ref_reads_refs_heads_alone() {
    let tmp = TmpDir::new("ref-store-local");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    put_own_mirror(&path, "main", &checksum(1));
    put_own_mirror(&path, "only-mirror", &checksum(1));
    block_on(async {
        put_local(&repo, "main", &checksum(2)).await;
        assert_eq!(resolve(&repo, &Ref::local("main")).await, Some(checksum(2)));
        assert_eq!(resolve(&repo, &Ref::local("only-mirror")).await, None);
    });
}

#[test]
fn a_repository_with_no_collection_id_reads_the_mirror_ref_alone() {
    let tmp = TmpDir::new("ref-store-no-id");
    let repo = open(&create(&tmp, None));
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        let cref = Ref::collection(OWN, "main");
        assert_eq!(resolve(&repo, &cref).await, None);
        assert_not_found(
            resolve_or_not_found(&repo, &cref).await,
            &format!("@{OWN}:main"),
        );
        put(&repo, OWN, "main", &checksum(2)).await;
        assert_eq!(resolve(&repo, &cref).await, Some(checksum(2)));
    });
}

#[test]
fn an_alias_resolves_to_its_target() {
    let tmp = TmpDir::new("ref-store-alias");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        repo.set_ref_alias_immediate("current", "main")
            .await
            .unwrap();
        assert_eq!(
            resolve(&repo, &Ref::local("current")).await,
            Some(checksum(1))
        );
        assert_eq!(
            resolve(&repo, &Ref::collection(OWN, "current")).await,
            Some(checksum(1))
        );

        put(&repo, OTHER, "stable", &checksum(2)).await;
        let mirror = path.join("refs/mirrors").join(OTHER);
        std::os::unix::fs::symlink("stable", mirror.join("current")).unwrap();
        assert_eq!(
            resolve(&repo, &Ref::collection(OTHER, "current")).await,
            Some(checksum(2))
        );
    });
}

#[test]
fn an_alias_with_an_absent_target_reads_as_an_absent_ref() {
    let tmp = TmpDir::new("ref-store-dangling");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put_local(&repo, "gone", &checksum(1)).await;
        let own = path.join("refs/mirrors").join(OWN);
        std::fs::create_dir_all(&own).unwrap();
        std::os::unix::fs::symlink("missing", own.join("gone")).unwrap();
        assert_eq!(
            resolve(&repo, &Ref::collection(OWN, "gone")).await,
            Some(checksum(1))
        );

        let other = path.join("refs/mirrors").join(OTHER);
        std::fs::create_dir_all(&other).unwrap();
        std::os::unix::fs::symlink("missing", other.join("gone")).unwrap();
        assert_eq!(resolve(&repo, &Ref::collection(OTHER, "gone")).await, None);
    });
}

#[test]
fn an_absent_ref_reads_as_none() {
    let tmp = TmpDir::new("ref-store-absent");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        for (cref, label) in [
            (Ref::collection(OTHER, "absent"), format!("@{OTHER}:absent")),
            (Ref::collection(OWN, "absent"), format!("@{OWN}:absent")),
            (Ref::local("absent"), "absent".to_owned()),
        ] {
            assert_eq!(repo.resolve_ref_tip(&cref).await.unwrap(), None, "{label}");
            assert_not_found(resolve_or_not_found(&repo, &cref).await, &label);
        }
    });
}

#[test]
fn the_own_collection_reads_a_local_ref_beside_a_mirror_directory_or_file() {
    let tmp = TmpDir::new("ref-store-own-not-a-ref");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        // `refs/mirrors/OWN/a` is a directory.
        put_own_mirror(&path, "a/b", &checksum(2));
        put_local(&repo, "a", &checksum(1)).await;
        let cref = Ref::collection(OWN, "a");
        assert_eq!(
            repo.resolve_ref_tip(&cref).await.unwrap(),
            Some(checksum(1))
        );

        // `refs/mirrors/OWN/f` is a file, so `refs/mirrors/OWN/f/g` goes
        // through a file.
        put_own_mirror(&path, "f", &checksum(2));
        put_local(&repo, "f/g", &checksum(1)).await;
        let cref = Ref::collection(OWN, "f/g");
        assert_eq!(
            repo.resolve_ref_tip(&cref).await.unwrap(),
            Some(checksum(1))
        );
    });
}

#[test]
fn the_own_collection_reads_a_local_ref_whose_mirror_path_is_too_long() {
    let tmp = TmpDir::new("ref-store-own-too-long");
    let repo = open(&create(&tmp, Some(OWN)));
    // A name of 4079 bytes, in components of at most 200 bytes. The path
    // `refs/heads/NAME` is 4090 bytes, and the path `refs/mirrors/OWN/NAME`
    // is 4108 bytes, longer than the 4095 bytes that Linux accepts.
    let mut parts = vec!["a".repeat(200); 20];
    parts.push("b".repeat(59));
    let name = parts.join("/");
    assert_eq!(name.len(), 4079);
    block_on(async {
        put_local(&repo, &name, &checksum(1)).await;
        assert_eq!(
            repo.resolve_ref_tip(&Ref::collection(OWN, name.as_str()))
                .await
                .unwrap(),
            Some(checksum(1))
        );
        assert_io(
            repo.resolve_ref_tip(&Ref::collection(OTHER, name.as_str()))
                .await,
            ErrorKind::InvalidFilename,
        );
    });
}

#[test]
fn the_own_collection_reads_a_local_ref_beside_a_mirror_ref_that_fails() {
    let tmp = TmpDir::new("ref-store-own-fails");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    let own = path.join("refs/mirrors").join(OWN);
    std::fs::create_dir_all(&own).unwrap();
    // `l` is a symlink to itself.
    std::os::unix::fs::symlink("l", own.join("l")).unwrap();
    std::fs::write(own.join("g"), "garbage\n").unwrap();
    std::fs::write(own.join("u"), b"\xff\xfe\n").unwrap();
    block_on(async {
        for name in ["l", "g", "u"] {
            put_local(&repo, name, &checksum(1)).await;
            let cref = Ref::collection(OWN, name);
            assert_eq!(
                repo.resolve_ref_tip(&cref).await.unwrap(),
                Some(checksum(1)),
                "{name}"
            );
        }
    });
}

#[test]
fn another_collection_fails_on_a_directory_or_a_file() {
    let tmp = TmpDir::new("ref-store-other-not-a-ref");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put(&repo, OTHER, "a/b", &checksum(2)).await;
        put_local(&repo, "a", &checksum(1)).await;
        assert_io(
            repo.resolve_ref_tip(&Ref::collection(OTHER, "a")).await,
            ErrorKind::IsADirectory,
        );

        put(&repo, OTHER, "f", &checksum(2)).await;
        put_local(&repo, "f/g", &checksum(1)).await;
        assert_io(
            repo.resolve_ref_tip(&Ref::collection(OTHER, "f/g")).await,
            ErrorKind::NotADirectory,
        );

        // A local ref keeps the error of `resolve_rev`.
        put_local(&repo, "d/e", &checksum(1)).await;
        assert_io(
            repo.resolve_ref_tip(&Ref::local("d")).await,
            ErrorKind::IsADirectory,
        );
    });
}

#[test]
fn a_resolve_takes_no_update_lock() {
    let tmp = TmpDir::new("ref-store-no-lock");
    let path = create(&tmp, Some(OWN));
    // With `lock-timeout-secs=0`, a call that waits for the update lock fails
    // at once with `Error::LockTimeout`.
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("lock-timeout-secs=0\n");
    std::fs::write(&config, text).unwrap();

    let holder = open(&path);
    let reader = open(&path);
    block_on(async {
        put(&holder, OTHER, "a", &checksum(1)).await;
        put_local(&holder, "b", &checksum(2)).await;
        put_local(&holder, "c", &checksum(3)).await;
        let crefs = [
            (Ref::collection(OTHER, "a"), checksum(1)),
            (Ref::collection(OWN, "b"), checksum(2)),
            (Ref::local("c"), checksum(3)),
        ];

        let guard = holder.begin_update().await.unwrap();
        for repo in [&holder, &reader] {
            for (cref, want) in &crefs {
                assert_eq!(
                    repo.resolve_ref_tip(cref).await.unwrap(),
                    Some(*want),
                    "{cref:?}"
                );
            }
        }
        let tasks: Vec<_> = crefs
            .iter()
            .cloned()
            .flat_map(|(cref, want)| {
                [holder.clone(), reader.clone()].map(|repo| {
                    let cref = cref.clone();
                    ostrya_rt::spawn(async move { (repo.resolve_ref_tip(&cref).await, want, cref) })
                })
            })
            .collect();
        for task in tasks {
            let (result, want, cref) = task.await;
            assert_eq!(result.unwrap(), Some(want), "{cref:?}");
        }
        guard.finish().await.unwrap();
    });
}

/// Writes a commit of an empty tree with the parent `parent` and the subject
/// `subject`, and returns its checksum.
async fn write_commit(repo: &Repo, subject: &str, parent: Option<Checksum>) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let meta = DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: Xattrs::empty(),
    };
    let mut mtree = MutableTree::new();
    mtree.set_metadata_checksum(txn.write_dirmeta(&meta).await.unwrap());
    let root = txn.write_mtree(&mut mtree).await.unwrap();
    let commit = txn
        .write_commit(
            CommitOptions {
                parent,
                subject: Some(subject.to_owned()),
                timestamp: Some(1_700_000_000),
                ..CommitOptions::default()
            },
            &root,
        )
        .await
        .unwrap();
    txn.commit().await.unwrap();
    commit
}

#[test]
fn a_revision_reads_a_collection_ref_and_its_ancestry() {
    let tmp = TmpDir::new("ref-store-rev");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        let first = write_commit(&repo, "first", None).await;
        let second = write_commit(&repo, "second", Some(first)).await;
        put(&repo, OTHER, "os/x86_64", &second).await;
        let rev = format!("@{OTHER}:os/x86_64");
        assert_eq!(repo.resolve_rev(&rev, false).await.unwrap(), Some(second));
        assert_eq!(
            repo.resolve_rev(&format!("{rev}^"), false).await.unwrap(),
            Some(first)
        );
        assert!(matches!(
            repo.resolve_rev(&format!("{rev}^^"), false).await,
            Err(Error::NoParentCommit(c)) if c == first
        ));
    });
}

#[test]
fn a_revision_of_the_own_collection_reads_the_local_ref() {
    let tmp = TmpDir::new("ref-store-rev-own");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    put_own_mirror(&path, "main", &checksum(1));
    block_on(async {
        put_local(&repo, "main", &checksum(2)).await;
        assert_eq!(
            repo.resolve_rev(&format!("@{OWN}:main"), false)
                .await
                .unwrap(),
            Some(checksum(2))
        );
    });
}

#[test]
fn a_revision_of_an_absent_collection_ref_names_the_ref() {
    let tmp = TmpDir::new("ref-store-rev-absent");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        let rev = format!("@{OTHER}:x");
        assert_not_found(repo.resolve_rev(&rev, false).await, &rev);
        assert_eq!(repo.resolve_rev(&rev, true).await.unwrap(), None);
        for rev in ["@bad:x", "@bad-id.x:y", "@", "@org.example.A:"] {
            match repo.resolve_rev(rev, true).await {
                Err(Error::InvalidRefspec(got)) => assert_eq!(got, rev),
                other => panic!("{rev}: {other:?}"),
            }
        }
    });
}

/// Returns the commit in the ref file at `rel` under `path`, or `None` if
/// the file is absent.
fn ref_file(path: &Path, rel: &str) -> Option<Checksum> {
    match std::fs::read_to_string(path.join(rel)) {
        Ok(text) => Some(Checksum::from_hex(text.trim_end()).unwrap()),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => panic!("{rel}: {e}"),
    }
}

/// The refs of the write tests, each with the file that holds it.
fn cases() -> [(Ref, &'static str); 4] {
    [
        (Ref::local("a/b"), "refs/heads/a/b"),
        (Ref::remote("origin", "a/b"), "refs/remotes/origin/a/b"),
        (
            Ref::collection(OTHER, "a/b"),
            "refs/mirrors/org.example.Other/a/b",
        ),
        (Ref::collection(OWN, "c"), "refs/heads/c"),
    ]
}

#[test]
fn each_writer_puts_each_case_at_its_path() {
    let tmp = TmpDir::new("ref-store-writers");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        for (r, rel) in cases() {
            repo.set_ref_immediate(&r, Some(&checksum(1)))
                .await
                .unwrap();
            assert_eq!(ref_file(&path, rel), Some(checksum(1)), "{r}");
            assert_eq!(resolve(&repo, &r).await, Some(checksum(1)), "{r}");

            let txn = repo.transaction().await.unwrap();
            txn.set_ref(&r, Some(&checksum(2)));
            txn.commit().await.unwrap();
            assert_eq!(ref_file(&path, rel), Some(checksum(2)), "{r}");
            assert_eq!(resolve(&repo, &r).await, Some(checksum(2)), "{r}");

            let guard = repo.begin_update().await.unwrap();
            guard.set_ref(&r, Some(&checksum(3))).await.unwrap();
            assert_eq!(guard.read_ref(&r).await.unwrap(), Some(checksum(3)), "{r}");
            guard.finish().await.unwrap();
            assert_eq!(ref_file(&path, rel), Some(checksum(3)), "{r}");

            let guard = repo.begin_update().await.unwrap();
            guard.set_ref(&r, None).await.unwrap();
            assert_eq!(guard.read_ref(&r).await.unwrap(), None, "{r}");
            guard.finish().await.unwrap();
            assert_eq!(ref_file(&path, rel), None, "{r}");
        }
        assert!(!path.join("refs/mirrors").join(OWN).exists());
    });
}

#[test]
fn a_parsed_ref_of_the_own_collection_writes_the_local_ref() {
    let tmp = TmpDir::new("ref-store-parsed-own");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        let r: Ref = format!("@{OWN}:a").parse().unwrap();
        assert_eq!(r, Ref::collection(OWN, "a"));
        repo.set_ref_immediate(&r, Some(&checksum(1)))
            .await
            .unwrap();
        assert_eq!(ref_file(&path, "refs/heads/a"), Some(checksum(1)));
        assert_eq!(resolve(&repo, &Ref::local("a")).await, Some(checksum(1)));
        assert!(!path.join("refs/mirrors").join(OWN).exists());
    });
}
