//! Tests of `Repo::resolve_collection_ref`. They cover the ref path that each
//! collection id reads, the read of `refs/heads/NAME` under the collection id
//! of the repository, aliases, absent refs, the read errors, and the read
//! while another handle holds the update lock.

mod common;

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use common::TmpDir;
use ostrya::{Checksum, CollectionRef, CreateOptions, Error, Repo, RepoMode};
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

/// Writes `checksum` to the collection ref `id:name`.
async fn put(repo: &Repo, id: &str, name: &str, checksum: &Checksum) {
    repo.set_collection_ref_immediate(&CollectionRef::new(id, name), Some(checksum))
        .await
        .unwrap();
}

/// Writes `checksum` to the local ref `name`.
async fn put_local(repo: &Repo, name: &str, checksum: &Checksum) {
    repo.set_ref_immediate(name, Some(checksum)).await.unwrap();
}

async fn resolve(repo: &Repo, cref: &CollectionRef) -> Option<Checksum> {
    repo.resolve_collection_ref(cref, true).await.unwrap()
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
    let tmp = TmpDir::new("resolve-cref-mirror");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put(&repo, OTHER, "main", &checksum(1)).await;
        put_local(&repo, "main", &checksum(2)).await;
        let cref = CollectionRef::new(OTHER, "main");
        assert_eq!(resolve(&repo, &cref).await, Some(checksum(1)));
        assert_eq!(
            repo.resolve_collection_ref(&cref, false).await.unwrap(),
            Some(checksum(1))
        );
    });
}

#[test]
fn another_collection_does_not_read_a_local_ref() {
    let tmp = TmpDir::new("resolve-cref-other-local");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put_local(&repo, "x", &checksum(1)).await;
        assert_eq!(resolve(&repo, &CollectionRef::new(OTHER, "x")).await, None);
    });
}

#[test]
fn the_own_collection_reads_a_local_ref() {
    let tmp = TmpDir::new("resolve-cref-own-local");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        let cref = CollectionRef::new(OWN, "main");
        assert_eq!(resolve(&repo, &cref).await, Some(checksum(1)));
        assert_eq!(
            repo.resolve_collection_ref(&cref, false).await.unwrap(),
            Some(checksum(1))
        );
    });
}

#[test]
fn the_mirror_ref_of_the_own_collection_wins() {
    let tmp = TmpDir::new("resolve-cref-own-wins");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put(&repo, OWN, "main", &checksum(1)).await;
        put_local(&repo, "main", &checksum(2)).await;
        assert_eq!(
            resolve(&repo, &CollectionRef::new(OWN, "main")).await,
            Some(checksum(1))
        );
    });
}

#[test]
fn a_local_ref_reads_refs_heads_alone() {
    let tmp = TmpDir::new("resolve-cref-local");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put(&repo, OWN, "main", &checksum(1)).await;
        put(&repo, OWN, "only-mirror", &checksum(1)).await;
        put_local(&repo, "main", &checksum(2)).await;
        assert_eq!(
            resolve(&repo, &CollectionRef::local("main")).await,
            Some(checksum(2))
        );
        assert_eq!(
            resolve(&repo, &CollectionRef::local("only-mirror")).await,
            None
        );
    });
}

#[test]
fn a_repository_with_no_collection_id_reads_the_mirror_ref_alone() {
    let tmp = TmpDir::new("resolve-cref-no-id");
    let repo = open(&create(&tmp, None));
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        let cref = CollectionRef::new(OWN, "main");
        assert_eq!(resolve(&repo, &cref).await, None);
        assert_not_found(
            repo.resolve_collection_ref(&cref, false).await,
            &format!("{OWN}:main"),
        );
        put(&repo, OWN, "main", &checksum(2)).await;
        assert_eq!(resolve(&repo, &cref).await, Some(checksum(2)));
    });
}

#[test]
fn an_alias_resolves_to_its_target() {
    let tmp = TmpDir::new("resolve-cref-alias");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        repo.set_ref_alias_immediate("current", "main")
            .await
            .unwrap();
        assert_eq!(
            resolve(&repo, &CollectionRef::local("current")).await,
            Some(checksum(1))
        );
        assert_eq!(
            resolve(&repo, &CollectionRef::new(OWN, "current")).await,
            Some(checksum(1))
        );

        put(&repo, OTHER, "stable", &checksum(2)).await;
        let mirror = path.join("refs/mirrors").join(OTHER);
        std::os::unix::fs::symlink("stable", mirror.join("current")).unwrap();
        assert_eq!(
            resolve(&repo, &CollectionRef::new(OTHER, "current")).await,
            Some(checksum(2))
        );
    });
}

#[test]
fn an_alias_with_an_absent_target_reads_as_an_absent_ref() {
    let tmp = TmpDir::new("resolve-cref-dangling");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put_local(&repo, "gone", &checksum(1)).await;
        let own = path.join("refs/mirrors").join(OWN);
        std::fs::create_dir_all(&own).unwrap();
        std::os::unix::fs::symlink("missing", own.join("gone")).unwrap();
        assert_eq!(
            resolve(&repo, &CollectionRef::new(OWN, "gone")).await,
            Some(checksum(1))
        );

        let other = path.join("refs/mirrors").join(OTHER);
        std::fs::create_dir_all(&other).unwrap();
        std::os::unix::fs::symlink("missing", other.join("gone")).unwrap();
        assert_eq!(
            resolve(&repo, &CollectionRef::new(OTHER, "gone")).await,
            None
        );
    });
}

#[test]
fn an_absent_ref_follows_allow_noent() {
    let tmp = TmpDir::new("resolve-cref-absent");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        for (cref, label) in [
            (
                CollectionRef::new(OTHER, "absent"),
                format!("{OTHER}:absent"),
            ),
            (CollectionRef::new(OWN, "absent"), format!("{OWN}:absent")),
            (CollectionRef::local("absent"), "absent".to_owned()),
        ] {
            assert_eq!(
                repo.resolve_collection_ref(&cref, true).await.unwrap(),
                None,
                "{label}"
            );
            assert_not_found(repo.resolve_collection_ref(&cref, false).await, &label);
        }
    });
}

#[test]
fn the_own_collection_reads_a_local_ref_past_a_directory_or_a_file() {
    let tmp = TmpDir::new("resolve-cref-own-not-a-ref");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        // `refs/mirrors/OWN/a` is a directory.
        put(&repo, OWN, "a/b", &checksum(2)).await;
        put_local(&repo, "a", &checksum(1)).await;
        let cref = CollectionRef::new(OWN, "a");
        assert_eq!(
            repo.resolve_collection_ref(&cref, false).await.unwrap(),
            Some(checksum(1))
        );

        // `refs/mirrors/OWN/f` is a file, so `refs/mirrors/OWN/f/g` goes
        // through a file.
        put(&repo, OWN, "f", &checksum(2)).await;
        put_local(&repo, "f/g", &checksum(1)).await;
        let cref = CollectionRef::new(OWN, "f/g");
        assert_eq!(
            repo.resolve_collection_ref(&cref, false).await.unwrap(),
            Some(checksum(1))
        );
    });
}

#[test]
fn the_own_collection_reads_a_local_ref_past_a_mirror_path_that_is_too_long() {
    let tmp = TmpDir::new("resolve-cref-own-too-long");
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
            repo.resolve_collection_ref(&CollectionRef::new(OWN, name.as_str()), false)
                .await
                .unwrap(),
            Some(checksum(1))
        );
        for allow_noent in [true, false] {
            assert_io(
                repo.resolve_collection_ref(&CollectionRef::new(OTHER, name.as_str()), allow_noent)
                    .await,
                ErrorKind::InvalidFilename,
            );
        }
    });
}

#[test]
fn the_own_collection_does_not_read_a_local_ref_past_a_mirror_ref_that_fails() {
    let tmp = TmpDir::new("resolve-cref-own-fails");
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
        }
        for allow_noent in [true, false] {
            let l = CollectionRef::new(OWN, "l");
            // `ErrorKind::FilesystemLoop` is not stable, so the test reads the
            // OS error.
            let eloop = rustix::io::Errno::LOOP.raw_os_error();
            match repo.resolve_collection_ref(&l, allow_noent).await {
                Err(Error::Io(e)) if e.raw_os_error() == Some(eloop) => {}
                other => panic!("l: {other:?}"),
            }
            let g = CollectionRef::new(OWN, "g");
            match repo.resolve_collection_ref(&g, allow_noent).await {
                Err(Error::Core(_)) => {}
                other => panic!("g: {other:?}"),
            }
            let u = CollectionRef::new(OWN, "u");
            match repo.resolve_collection_ref(&u, allow_noent).await {
                Err(Error::InvalidFormat(_)) => {}
                other => panic!("u: {other:?}"),
            }
        }
    });
}

#[test]
fn another_collection_fails_on_a_directory_or_a_file() {
    let tmp = TmpDir::new("resolve-cref-other-not-a-ref");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        put(&repo, OTHER, "a/b", &checksum(2)).await;
        put_local(&repo, "a", &checksum(1)).await;
        for allow_noent in [true, false] {
            assert_io(
                repo.resolve_collection_ref(&CollectionRef::new(OTHER, "a"), allow_noent)
                    .await,
                ErrorKind::IsADirectory,
            );
        }

        put(&repo, OTHER, "f", &checksum(2)).await;
        put_local(&repo, "f/g", &checksum(1)).await;
        assert_io(
            repo.resolve_collection_ref(&CollectionRef::new(OTHER, "f/g"), true)
                .await,
            ErrorKind::NotADirectory,
        );

        // A local ref keeps the error of `resolve_rev`.
        put_local(&repo, "d/e", &checksum(1)).await;
        assert_io(
            repo.resolve_collection_ref(&CollectionRef::local("d"), true)
                .await,
            ErrorKind::IsADirectory,
        );
    });
}

#[test]
fn a_resolve_takes_no_update_lock() {
    let tmp = TmpDir::new("resolve-cref-no-lock");
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
            (CollectionRef::new(OTHER, "a"), checksum(1)),
            (CollectionRef::new(OWN, "b"), checksum(2)),
            (CollectionRef::local("c"), checksum(3)),
        ];

        let guard = holder.begin_update().await.unwrap();
        for repo in [&holder, &reader] {
            for (cref, want) in &crefs {
                assert_eq!(
                    repo.resolve_collection_ref(cref, false).await.unwrap(),
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
                    ostrya_rt::spawn(async move {
                        (repo.resolve_collection_ref(&cref, false).await, want, cref)
                    })
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
