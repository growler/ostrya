//! Tests of `Repo::list_collection_refs_in`. They cover the selection of the
//! refs of one collection, the order of the result, the directories that a
//! listing reads, the rule of the collection id of the repository, aliases,
//! absent collections, and the listing while another handle holds the update
//! lock.

mod common;

use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::TmpDir;
use ostrya::{Checksum, CreateOptions, Error, Ref, RefSelector, Repo, RepoMode};
use ostrya_rt::block_on;

/// The `[core] collection-id` of the repositories of the tests.
const OWN: &str = "org.example.Own";

/// A collection id that is not the id of the repository.
const OTHER: &str = "org.example.Other";

/// A third collection id, which the listings of the tests do not name.
const THIRD: &str = "org.example.Third";

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

fn selector(entries: &[&str]) -> RefSelector {
    RefSelector::parse(entries.iter().copied()).unwrap()
}

/// Lists the refs of the collection `id` that the selector of `entries`
/// selects.
async fn list(repo: &Repo, id: &str, entries: &[&str]) -> Vec<(String, Checksum)> {
    repo.list_collection_refs_in(id, &selector(entries))
        .await
        .unwrap()
}

/// Returns the names of the listing of [`list`].
async fn names(repo: &Repo, id: &str, entries: &[&str]) -> Vec<String> {
    list(repo, id, entries)
        .await
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// Returns `(name, commit)` pairs from string slices and checksum bytes.
fn pairs(want: &[(&str, u8)]) -> Vec<(String, Checksum)> {
    want.iter()
        .map(|(name, byte)| ((*name).to_owned(), checksum(*byte)))
        .collect()
}

/// Sets mode 0 on each directory of `dirs`. Returns `false`, with mode 0755
/// set again, when the process still reads one of them: a user that ignores
/// the mode cannot run the test.
fn lock(dirs: &[PathBuf]) -> bool {
    for dir in dirs {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    if dirs.iter().any(|dir| std::fs::read_dir(dir).is_ok()) {
        unlock(dirs);
        return false;
    }
    true
}

/// Sets mode 0755 on each directory of `dirs`.
fn unlock(dirs: &[PathBuf]) {
    for dir in dirs {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

/// Asserts that `result` is `Error::Io` of `PermissionDenied`.
fn assert_denied(result: ostrya::Result<Vec<(String, Checksum)>>, what: &str) {
    match result {
        Err(Error::Io(e)) => assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{what}: {e}"),
        other => panic!("{what}: {other:?}"),
    }
}

/// A positive pattern reads only the directories that it can match, and a
/// negative pattern with a final `**` keeps the walk out of the directory
/// that it covers. A directory with mode 0 fails a listing that reads it. The
/// test returns at once for a user that ignores the mode.
#[test]
fn a_listing_of_another_collection_reads_only_the_selected_directories() {
    let tmp = TmpDir::new("list-cref-in-other-dirs");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put(&repo, OTHER, "pool/a", &checksum(1)).await;
        put(&repo, OTHER, "pool/b/c", &checksum(2)).await;
        put(&repo, OTHER, "builds/x", &checksum(3)).await;
        put(&repo, OTHER, "builds/locked/y", &checksum(4)).await;
        let locked = [path.join("refs/mirrors").join(OTHER).join("builds/locked")];
        if !lock(&locked) {
            return;
        }
        assert_eq!(
            list(&repo, OTHER, &["pool/**"]).await,
            pairs(&[("pool/a", 1), ("pool/b/c", 2)])
        );
        assert_eq!(
            list(&repo, OTHER, &["!builds/locked/**"]).await,
            pairs(&[("builds/x", 3), ("pool/a", 1), ("pool/b/c", 2)])
        );
        for entries in [&[][..], &["**"][..]] {
            assert_denied(
                repo.list_collection_refs_in(OTHER, &selector(entries))
                    .await,
                &format!("{entries:?}"),
            );
        }
        unlock(&locked);
    });
}

/// Under the collection id of the repository, the listing walks
/// `refs/heads/` by the same rules, and it never opens `refs/mirrors/ID/`.
/// The test returns at once for a user that ignores the mode.
#[test]
fn a_listing_of_the_own_collection_reads_only_the_selected_directories() {
    let tmp = TmpDir::new("list-cref-in-own-dirs");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    put_own_mirror(&path, "pool/m", &checksum(6));
    block_on(async {
        put(&repo, OWN, "pool/a", &checksum(1)).await;
        put_local(&repo, "pool/b/c", &checksum(2)).await;
        put_local(&repo, "builds/x", &checksum(3)).await;
        put_local(&repo, "builds/locked/z", &checksum(5)).await;
        let locked = [
            path.join("refs/mirrors").join(OWN),
            path.join("refs/heads/builds/locked"),
        ];
        if !lock(&locked) {
            return;
        }
        assert_eq!(
            list(&repo, OWN, &["pool/**"]).await,
            pairs(&[("pool/a", 1), ("pool/b/c", 2)])
        );
        assert_eq!(
            list(&repo, OWN, &["!builds/locked/**"]).await,
            pairs(&[("builds/x", 3), ("pool/a", 1), ("pool/b/c", 2)])
        );
        for entries in [&[][..], &["**"][..]] {
            assert_denied(
                repo.list_collection_refs_in(OWN, &selector(entries)).await,
                &format!("{entries:?}"),
            );
        }
        unlock(&locked);
    });
}

/// A listing of another collection opens no directory of a third
/// collection, not the directory of the collection id of the repository,
/// and not `refs/heads`. The test returns at once for a user that ignores
/// the mode.
#[test]
fn a_listing_of_another_collection_reads_no_other_collection_and_no_local_ref() {
    let tmp = TmpDir::new("list-cref-in-other-only");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put(&repo, OTHER, "main", &checksum(1)).await;
        put(&repo, OTHER, "x/y", &checksum(2)).await;
        put(&repo, THIRD, "main", &checksum(3)).await;
        put_own_mirror(&path, "main", &checksum(4));
        put_local(&repo, "main", &checksum(5)).await;
        let mirrors = path.join("refs/mirrors");
        let locked = [
            mirrors.join(THIRD),
            mirrors.join(OWN),
            path.join("refs/heads"),
        ];
        if !lock(&locked) {
            return;
        }
        assert_eq!(
            list(&repo, OTHER, &[]).await,
            pairs(&[("main", 1), ("x/y", 2)])
        );
        assert_eq!(list(&repo, OTHER, &["!x/**"]).await, pairs(&[("main", 1)]));
        assert_eq!(list(&repo, OTHER, &["main"]).await, pairs(&[("main", 1)]));
        assert_denied(
            repo.list_collection_refs_in(THIRD, &selector(&[])).await,
            THIRD,
        );
        unlock(&locked);
    });
}

/// A selector with the negative pattern `**` selects no ref, and the listing
/// opens no directory: it succeeds with `refs/mirrors` and `refs/heads`
/// unreadable, for the own collection and for another collection. The test
/// returns at once for a user that ignores the mode.
#[test]
fn a_negative_pattern_of_each_name_opens_no_directory() {
    let tmp = TmpDir::new("list-cref-in-no-name");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put(&repo, OTHER, "main", &checksum(1)).await;
        put(&repo, OWN, "main", &checksum(2)).await;
        put_local(&repo, "local", &checksum(3)).await;
        let locked = [path.join("refs/mirrors"), path.join("refs/heads")];
        if !lock(&locked) {
            return;
        }
        for id in [OWN, OTHER] {
            for entries in [&["!**"][..], &["main", "!**"][..]] {
                assert!(
                    list(&repo, id, entries).await.is_empty(),
                    "{id} {entries:?}"
                );
            }
        }
        assert_denied(
            repo.list_collection_refs_in(OTHER, &selector(&[])).await,
            OTHER,
        );
        unlock(&locked);
    });
}

/// An empty selector selects each ref of the collection, in byte order of
/// the names, and no ref of another collection and no local ref. In byte
/// order, `a.b` comes before `a/x`, and `a/x` comes before `a0`.
#[test]
fn an_empty_selector_selects_each_ref_of_the_collection_in_byte_order() {
    let tmp = TmpDir::new("list-cref-in-empty");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        for (name, byte) in [("b/c/d", 4), ("a0", 3), ("a/x", 2), ("a.b", 1)] {
            put(&repo, OTHER, name, &checksum(byte)).await;
        }
        put(&repo, THIRD, "a", &checksum(5)).await;
        put(&repo, THIRD, "c", &checksum(5)).await;
        put(&repo, OWN, "a", &checksum(6)).await;
        put(&repo, OWN, "q", &checksum(6)).await;
        put_local(&repo, "a", &checksum(7)).await;
        put_local(&repo, "z", &checksum(7)).await;
        assert_eq!(
            list(&repo, OTHER, &[]).await,
            pairs(&[("a.b", 1), ("a/x", 2), ("a0", 3), ("b/c/d", 4)])
        );
    });
}

/// A negative pattern drops the refs that it matches, with or without a
/// positive pattern, for another collection and for the collection id of the
/// repository.
#[test]
fn a_negative_pattern_drops_the_refs_that_it_matches() {
    let tmp = TmpDir::new("list-cref-in-negative");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        for id in [OTHER, OWN] {
            for name in ["main", "pool/x/a", "pool/x/b", "pool/y"] {
                put(&repo, id, name, &checksum(1)).await;
            }
        }
        let cases: [(&[&str], &[&str]); 4] = [
            (&["**", "!pool/x/**"], &["main", "pool/y"]),
            (&["!pool/x/**"], &["main", "pool/y"]),
            (&["!pool/x/a"], &["main", "pool/x/b", "pool/y"]),
            (&["!**"], &[]),
        ];
        for id in [OTHER, OWN] {
            for (entries, want) in cases {
                assert_eq!(names(&repo, id, entries).await, want, "{id} {entries:?}");
            }
        }
    });
}

/// A pattern selects the same names in the collection as it selects in a
/// ref list: `*` is one part, `**` is one or more parts, and a literal is
/// one name.
#[test]
fn a_pattern_keeps_its_meaning_in_the_collection() {
    let tmp = TmpDir::new("list-cref-in-meaning");
    let repo = open(&create(&tmp, Some(OWN)));
    block_on(async {
        let all = ["a", "c", "p/b/c", "p/d/e/c", "p/q", "x/c", "x/y/c"];
        for id in [OTHER, OWN] {
            for name in all {
                put(&repo, id, name, &checksum(1)).await;
            }
        }
        let cases: [(&[&str], &[&str]); 6] = [
            (&["*"], &["a", "c"]),
            (&["**/c"], &["p/b/c", "p/d/e/c", "x/c", "x/y/c"]),
            (&["p/*/c"], &["p/b/c"]),
            (&["p/q"], &["p/q"]),
            (&["p/**"], &["p/b/c", "p/d/e/c", "p/q"]),
            (&["**"], &all),
        ];
        for id in [OTHER, OWN] {
            for (entries, want) in cases {
                assert_eq!(names(&repo, id, entries).await, want, "{id} {entries:?}");
            }
        }
    });
}

/// Under the collection id of the repository, the listing holds the refs of
/// `refs/heads/` alone, and it does not open `refs/mirrors/ID/`. The last
/// part of the test returns at once for a user that ignores the mode.
#[test]
fn the_own_collection_ignores_its_mirror_refs() {
    let tmp = TmpDir::new("list-cref-in-own-mirror");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    put_own_mirror(&path, "main", &checksum(2));
    put_own_mirror(&path, "only-mirror", &checksum(4));
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        put_local(&repo, "only-local", &checksum(3)).await;
        let want = pairs(&[("main", 1), ("only-local", 3)]);
        assert_eq!(list(&repo, OWN, &[]).await, want);

        let locked = [path.join("refs/mirrors").join(OWN)];
        if !lock(&locked) {
            return;
        }
        assert_eq!(list(&repo, OWN, &[]).await, want);
        assert_eq!(list(&repo, OWN, &["main"]).await, pairs(&[("main", 1)]));
        unlock(&locked);
    });
}

/// Under the collection id of the repository with no mirror directory, the
/// listing holds the refs of `refs/heads/`.
#[test]
fn the_own_collection_with_no_mirror_directory_lists_the_local_refs() {
    let tmp = TmpDir::new("list-cref-in-own-local");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        put_local(&repo, "x/y", &checksum(2)).await;
        put(&repo, OTHER, "main", &checksum(3)).await;
        assert!(!path.join("refs/mirrors").join(OWN).exists());
        assert_eq!(
            list(&repo, OWN, &[]).await,
            pairs(&[("main", 1), ("x/y", 2)])
        );
    });
}

/// In a repository with no collection id, each collection id lists its
/// mirror refs alone.
#[test]
fn a_repository_with_no_collection_id_lists_the_mirror_refs_alone() {
    let tmp = TmpDir::new("list-cref-in-no-id");
    let repo = open(&create(&tmp, None));
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        put_local(&repo, "only-local", &checksum(1)).await;
        put(&repo, OWN, "main", &checksum(2)).await;
        put(&repo, OWN, "other", &checksum(3)).await;
        assert_eq!(
            list(&repo, OWN, &[]).await,
            pairs(&[("main", 2), ("other", 3)])
        );
    });
}

/// A collection with no directory gives an empty listing. An entry of the
/// collection id that is a regular file or a symlink is no directory.
#[test]
fn an_absent_collection_gives_an_empty_listing() {
    let tmp = TmpDir::new("list-cref-in-absent");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        assert!(list(&repo, OTHER, &[]).await.is_empty());
        assert!(list(&repo, OTHER, &["main"]).await.is_empty());

        put(&repo, THIRD, "main", &checksum(2)).await;
        assert!(list(&repo, OTHER, &[]).await.is_empty());

        let entry = path.join("refs/mirrors").join(OTHER);
        std::os::unix::fs::symlink(THIRD, &entry).unwrap();
        assert!(list(&repo, OTHER, &[]).await.is_empty());
        std::fs::remove_file(&entry).unwrap();
        std::fs::write(&entry, format!("{}\n", checksum(3))).unwrap();
        assert!(list(&repo, OTHER, &[]).await.is_empty());
        std::fs::remove_file(&entry).unwrap();

        std::fs::remove_dir_all(path.join("refs/mirrors")).unwrap();
        assert!(list(&repo, OTHER, &[]).await.is_empty());
        assert!(list(&repo, THIRD, &[]).await.is_empty());
        assert_eq!(list(&repo, OWN, &[]).await, pairs(&[("main", 1)]));
    });

    let tmp = TmpDir::new("list-cref-in-absent-no-id");
    let repo = open(&create(&tmp, None));
    block_on(async {
        assert!(list(&repo, OWN, &[]).await.is_empty());
    });
}

/// A `refs/mirrors` that is a regular file fails a listing of another
/// collection, which opens it. A listing of the own collection does not open
/// it. A selector with the negative pattern `**` opens no directory and
/// gives an empty listing.
#[test]
fn a_mirror_directory_that_is_a_file_fails_the_listing() {
    let tmp = TmpDir::new("list-cref-in-mirrors-file");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put_local(&repo, "main", &checksum(1)).await;
        let mirrors = path.join("refs/mirrors");
        std::fs::remove_dir(&mirrors).unwrap();
        std::fs::write(&mirrors, "").unwrap();
        match repo.list_collection_refs_in(OTHER, &selector(&[])).await {
            Err(Error::Io(e)) => assert_eq!(e.kind(), ErrorKind::NotADirectory, "{e}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(list(&repo, OWN, &[]).await, pairs(&[("main", 1)]));
        for id in [OWN, OTHER] {
            assert!(list(&repo, id, &["!**"]).await.is_empty(), "{id}");
        }
    });
}

/// An alias to a ref of the collection is in the listing with the commit of
/// its target. An alias with no target and an alias to a remote ref are not
/// in it. Under the collection id of the repository, such a mirror alias
/// does not hide the local ref of its name.
#[test]
fn an_alias_lists_the_commit_of_its_target() {
    let tmp = TmpDir::new("list-cref-in-alias");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put(&repo, OTHER, "stable", &checksum(1)).await;
        repo.set_ref_immediate(&Ref::remote("origin", "main"), Some(&checksum(2)))
            .await
            .unwrap();
        let mirror = path.join("refs/mirrors").join(OTHER);
        std::os::unix::fs::symlink("stable", mirror.join("current")).unwrap();
        std::os::unix::fs::symlink("missing", mirror.join("gone")).unwrap();
        std::os::unix::fs::symlink("../../remotes/origin/main", mirror.join("remote")).unwrap();
        assert!(path.join("refs/remotes/origin/main").is_file());
        assert_eq!(
            list(&repo, OTHER, &[]).await,
            pairs(&[("current", 1), ("stable", 1)])
        );

        put_local(&repo, "main", &checksum(3)).await;
        repo.set_ref_alias_immediate("latest", "main")
            .await
            .unwrap();
        put_local(&repo, "gone", &checksum(4)).await;
        let own = path.join("refs/mirrors").join(OWN);
        std::fs::create_dir_all(&own).unwrap();
        std::os::unix::fs::symlink("missing", own.join("gone")).unwrap();
        std::os::unix::fs::symlink("../../remotes/origin/main", own.join("remote")).unwrap();
        assert_eq!(
            list(&repo, OWN, &[]).await,
            pairs(&[("gone", 4), ("latest", 3), ("main", 3)])
        );
    });
}

/// An alias to a ref under a mirror directory whose name fails the
/// collection-id rule is not in the listing, in the listing of another
/// collection and in the listing of the collection id of the repository. An
/// alias to a ref of a valid collection is in it.
#[test]
fn an_alias_to_a_mirror_ref_of_an_invalid_collection_id_is_not_listed() {
    let tmp = TmpDir::new("list-cref-in-alias-invalid");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put(&repo, OTHER, "stable", &checksum(1)).await;
        put(&repo, THIRD, "main", &checksum(2)).await;
        let mirrors = path.join("refs/mirrors");
        let invalid = mirrors.join("invalid");
        std::fs::create_dir(&invalid).unwrap();
        std::fs::write(invalid.join("main"), format!("{}\n", checksum(3))).unwrap();
        let mirror = mirrors.join(OTHER);
        std::os::unix::fs::symlink("../invalid/main", mirror.join("bad")).unwrap();
        std::os::unix::fs::symlink(format!("../{THIRD}/main"), mirror.join("good")).unwrap();
        assert_eq!(
            list(&repo, OTHER, &[]).await,
            pairs(&[("good", 2), ("stable", 1)])
        );

        put_local(&repo, "main", &checksum(4)).await;
        let heads = path.join("refs/heads");
        std::os::unix::fs::symlink("../mirrors/invalid/main", heads.join("bad")).unwrap();
        std::os::unix::fs::symlink(format!("../mirrors/{THIRD}/main"), heads.join("good")).unwrap();
        assert_eq!(
            list(&repo, OWN, &[]).await,
            pairs(&[("good", 2), ("main", 4)])
        );
    });
}

/// The listing does not check a name that it finds against the ref-name
/// rule. A wildcard selects such a name.
#[test]
fn a_listing_holds_a_name_outside_the_ref_name_rule() {
    let tmp = TmpDir::new("list-cref-in-name-rule");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    block_on(async {
        put(&repo, OTHER, "main", &checksum(1)).await;
        let mirror = path.join("refs/mirrors").join(OTHER);
        std::fs::write(mirror.join("a b"), format!("{}\n", checksum(2))).unwrap();
        assert_eq!(
            list(&repo, OTHER, &["*"]).await,
            pairs(&[("a b", 2), ("main", 1)])
        );
    });
}

/// An invalid collection id fails with `Error::InvalidRefspec` that holds
/// the id, and the call reads no file: a valid id fails on the unreadable
/// `refs/mirrors`. The last part of the test returns at once for a user that
/// ignores the mode.
#[test]
fn an_invalid_collection_id_reads_no_file() {
    let tmp = TmpDir::new("list-cref-in-invalid");
    let path = create(&tmp, Some(OWN));
    let repo = open(&path);
    let ids = [
        "a".to_owned(),
        "org..x".to_owned(),
        "1org.x".to_owned(),
        "org/x".to_owned(),
        format!("a.{}", "b".repeat(254)),
    ];
    block_on(async {
        put(&repo, OTHER, "main", &checksum(1)).await;
        let locked = [path.join("refs/mirrors")];
        if !lock(&locked) {
            return;
        }
        for id in &ids {
            match repo.list_collection_refs_in(id, &selector(&[])).await {
                Err(Error::InvalidRefspec(got)) => assert_eq!(&got, id),
                other => panic!("{id}: {other:?}"),
            }
        }
        assert_denied(
            repo.list_collection_refs_in(OTHER, &selector(&[])).await,
            OTHER,
        );
        unlock(&locked);
    });
}

/// The client groups of the config do not limit the listing.
#[test]
fn a_listing_takes_no_client_group() {
    let tmp = TmpDir::new("list-cref-in-groups");
    let path = create(&tmp, Some(OWN));
    let config = path.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    text.push_str("[ex-ostrya client \"c\"]\nauth=anonymous\nallow=r:pub/**\n");
    text.push_str("[ex-ostrya client \"d\"]\nauth=anonymous\ncollection=*\nallow=r:pub/**\n");
    std::fs::write(&config, text).unwrap();
    let repo = open(&path);
    block_on(async {
        put(&repo, OTHER, "pub/a", &checksum(1)).await;
        put(&repo, OTHER, "secret", &checksum(2)).await;
        put_local(&repo, "pub/b", &checksum(3)).await;
        put_local(&repo, "secret", &checksum(4)).await;
        assert_eq!(
            list(&repo, OTHER, &[]).await,
            pairs(&[("pub/a", 1), ("secret", 2)])
        );
        assert_eq!(
            list(&repo, OWN, &[]).await,
            pairs(&[("pub/b", 3), ("secret", 4)])
        );
    });
}

/// The listing takes no lock: it runs while another handle and the same
/// handle hold the update lock.
#[test]
fn a_listing_takes_no_update_lock() {
    let tmp = TmpDir::new("list-cref-in-no-lock");
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
        let guard = holder.begin_update().await.unwrap();
        for repo in [&holder, &reader] {
            assert_eq!(list(repo, OTHER, &[]).await, pairs(&[("a", 1)]));
            assert_eq!(list(repo, OWN, &[]).await, pairs(&[("b", 2)]));
        }
        guard.finish().await.unwrap();
    });
}
