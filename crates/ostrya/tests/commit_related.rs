//! Integration tests of the related commits of a commit.
//!
//! `Transaction::write_commit` writes `CommitOptions::related` into field 2
//! of the commit object, sorted by name, and refuses dependencies that are
//! defective, not complete, or nested. `Transaction::check_related` runs the
//! same checks before a tree is built. `Repo::commit_add_composefs_metadata`
//! keeps field 2 and applies the same check. `Repo::read_commit_related`
//! reads field 2 and the detached key `ostrya.related`. The `ostree` command
//! has no counterpart, so the tests use ostrya alone.

mod common;

use std::path::Path;

use common::{TmpDir, file_inventory};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CommitRelated, CreateOptions,
    DictBuilder, Error, MutableTree, ObjectType, RelatedField, Repo, RepoMode, RepoTree,
    Transaction, Type, Value,
};
use ostrya_rt::block_on;

/// A fixed timestamp, so the commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// The detached metadata key of the build sources.
const RELATED_KEY: &str = "ostrya.related";

/// Writes a tree with one file at `base/<name>`. The content of the file names
/// the tree.
fn write_tree(base: &Path, name: &str) {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
}

/// Writes the trees `base/<name>` and creates an archive repository under
/// `base/repo`.
async fn repo_with_trees(base: &Path, names: &[&str]) -> Repo {
    for name in names {
        write_tree(base, name);
    }
    Repo::create(&base.join("repo"), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// Stages the tree `base/<name>` in `txn` and returns its root.
async fn stage_tree(txn: &Transaction, base: &Path, name: &str) -> RepoTree {
    use std::os::fd::AsFd;
    let mut mtree = MutableTree::new();
    let mut modifier = CommitModifier::new(CommitModifierFlags::SKIP_XATTRS);
    let dfd = std::fs::File::open(base).unwrap();
    txn.write_dfd_to_mtree(
        dfd.as_fd(),
        Path::new(name),
        &mut mtree,
        Some(&mut modifier),
    )
    .await
    .unwrap();
    txn.write_mtree(&mut mtree).await.unwrap()
}

/// Returns the commit options of these tests, with `related`.
fn options(name: &str, related: &[(&str, Checksum)]) -> CommitOptions {
    CommitOptions {
        subject: Some(name.to_owned()),
        timestamp: Some(FIXED_TS),
        related: related
            .iter()
            .map(|(entry, checksum)| ((*entry).to_owned(), *checksum))
            .collect(),
        ..CommitOptions::default()
    }
}

/// Commits the tree `base/<name>` into `repo` with the dependencies
/// `related`, and returns the commit.
async fn commit(repo: &Repo, base: &Path, name: &str, related: &[(&str, Checksum)]) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let root = stage_tree(&txn, base, name).await;
    let commit = txn
        .write_commit(options(name, related), &root)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    commit
}

/// One entry of field 2 as stored: a name and the bytes of a checksum.
type Field2Entry<'a> = (&'a str, &'a [u8]);

/// Stores a copy of the commit `source` with field 2 set to `related`, with
/// no check of the entries, and returns its checksum.
async fn store_with_field2(
    repo: &Repo,
    source: &Checksum,
    related: &[Field2Entry<'_>],
) -> Checksum {
    let (mut commit, _) = repo.load_commit(source).await.unwrap();
    commit.related = related
        .iter()
        .map(|(name, bytes)| ((*name).to_owned(), bytes.to_vec()))
        .collect();
    let bytes = commit.serialize().unwrap();
    let txn = repo.transaction().await.unwrap();
    let written = txn
        .write_metadata(ObjectType::Commit, None, &bytes)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    written
}

/// Returns the entries `entries` as field 2 stores them: names and checksum
/// bytes.
fn field2(entries: &[(&str, Checksum)]) -> Vec<(String, Vec<u8>)> {
    entries
        .iter()
        .map(|(name, checksum)| ((*name).to_owned(), checksum.as_bytes().to_vec()))
        .collect()
}

/// Returns the related entries `entries` as owned pairs.
fn owned(entries: &[(&str, Checksum)]) -> Vec<(String, Checksum)> {
    entries
        .iter()
        .map(|(name, checksum)| ((*name).to_owned(), *checksum))
        .collect()
}

/// Returns an `a(say)` variant of the build sources `entries`.
fn sources(entries: &[(&str, &[u8])]) -> (Type, Value) {
    let elements = entries
        .iter()
        .map(|(name, bytes)| {
            Value::Tuple(vec![
                Value::Str((*name).to_owned()),
                Value::Bytes(bytes.to_vec()),
            ])
        })
        .collect();
    (Type::parse("a(say)").unwrap(), Value::Array(elements))
}

/// Returns an `a{sv}` with one entry for each `(key, (type, value))`, in the
/// order of `entries`.
fn dict(entries: Vec<(&str, (Type, Value))>) -> Value {
    let mut builder = DictBuilder::new();
    for (key, (ty, value)) in entries {
        builder.insert(key, ty, value);
    }
    builder.build()
}

/// Returns the commit, the field, and the reason of an
/// [`Error::InvalidRelated`].
fn related_error(err: Error) -> (Option<Checksum>, RelatedField, String) {
    match err {
        Error::InvalidRelated {
            commit,
            field,
            reason,
        } => (commit, field, reason),
        other => panic!("expected InvalidRelated, got {other:?}"),
    }
}

/// Returns the regular files and symlinks under `objects/` of `repo`.
fn objects(repo: &Repo) -> Vec<(String, Vec<u8>)> {
    file_inventory(repo.path(), "objects")
}

/// Returns the regular files and symlinks under `tmp/` of `repo`, where the
/// staging directory of a transaction is.
fn staged(repo: &Repo) -> Vec<(String, Vec<u8>)> {
    file_inventory(repo.path(), "tmp")
}

/// Returns the regular files and symlinks under `refs/` of `repo`.
fn refs(repo: &Repo) -> Vec<(String, Vec<u8>)> {
    file_inventory(repo.path(), "refs")
}

#[test]
fn write_commit_sorts_the_dependencies() {
    let tmp = TmpDir::new("related-sort");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["fe", "uki", "head"]).await;
        let fe = commit(&repo, tmp.path(), "fe", &[]).await;
        let uki = commit(&repo, tmp.path(), "uki", &[]).await;
        let head = commit(
            &repo,
            tmp.path(),
            "head",
            &[("container/fe", fe), ("boot/uki", uki), ("Boot/x", fe)],
        )
        .await;
        let sorted = [("Boot/x", fe), ("boot/uki", uki), ("container/fe", fe)];
        let (stored, _) = repo.load_commit(&head).await.unwrap();
        assert_eq!(stored.related, field2(&sorted));
        assert_eq!(
            repo.read_commit_related(&head).await.unwrap(),
            CommitRelated {
                dependencies: owned(&sorted),
                build_sources: Vec::new(),
            }
        );
    });
}

#[test]
fn one_set_of_dependencies_gives_one_checksum() {
    let tmp = TmpDir::new("related-stable");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["fe", "uki", "head"]).await;
        let fe = commit(&repo, tmp.path(), "fe", &[]).await;
        let uki = commit(&repo, tmp.path(), "uki", &[]).await;
        let first = commit(
            &repo,
            tmp.path(),
            "head",
            &[("container/fe", fe), ("boot/uki", uki)],
        )
        .await;
        let second = commit(
            &repo,
            tmp.path(),
            "head",
            &[("boot/uki", uki), ("container/fe", fe)],
        )
        .await;
        assert_eq!(first, second);
        let plain = commit(&repo, tmp.path(), "head", &[]).await;
        assert_ne!(first, plain, "field 2 is in the commit checksum");
    });
}

#[test]
fn write_commit_refuses_defective_or_incomplete_dependencies() {
    let tmp = TmpDir::new("related-refuse");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["dep", "partial", "head"]).await;
        let dep = commit(&repo, tmp.path(), "dep", &[]).await;
        let partial = commit(&repo, tmp.path(), "partial", &[]).await;
        let state = repo.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join(format!("{partial}.commitpartial")), b"").unwrap();
        let absent = Checksum::from_ay(&[0x22; 32]).unwrap();

        let cases = [
            (
                vec![("a/x", dep), ("", dep)],
                "entry 1 has an empty name".to_owned(),
            ),
            (
                vec![("b/x", dep), ("a/x", dep), ("b/x", absent)],
                "two entries have the name b/x".to_owned(),
            ),
            (
                vec![("a/x", dep), ("b/x", absent)],
                format!(
                    "dependency b/x names commit {absent}, which is in neither the repository \
                     nor the transaction"
                ),
            ),
            (
                vec![("a/x", partial)],
                format!("dependency a/x names commit {partial}, which is partial"),
            ),
        ];
        for (related, expected) in cases {
            let objects_before = objects(&repo);
            let refs_before = refs(&repo);
            let txn = repo.transaction().await.unwrap();
            let root = stage_tree(&txn, tmp.path(), "head").await;
            let staged_before = staged(&repo);
            let err = txn
                .write_commit(options("head", &related), &root)
                .await
                .unwrap_err();
            assert_eq!(
                staged(&repo),
                staged_before,
                "the refused call stages nothing"
            );
            assert_eq!(
                err.to_string(),
                format!("related commits in field 2: {expected}")
            );
            assert_eq!(
                related_error(err),
                (None, RelatedField::Dependencies, expected)
            );
            // The transaction stays open.
            let written = txn
                .write_commit(options("head", &[("a/x", dep)]), &root)
                .await
                .unwrap();
            txn.set_ref("main", Some(&written));
            txn.abort().await.unwrap();
            assert_eq!(objects(&repo), objects_before, "no new object");
            assert_eq!(refs(&repo), refs_before, "no new ref");
        }
    });
}

#[test]
fn check_related_runs_the_checks_of_write_commit() {
    let tmp = TmpDir::new("related-check");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["dep", "partial", "c", "nested"]).await;
        let dep = commit(&repo, tmp.path(), "dep", &[]).await;
        let partial = commit(&repo, tmp.path(), "partial", &[]).await;
        let c = commit(&repo, tmp.path(), "c", &[]).await;
        let nested = commit(&repo, tmp.path(), "nested", &[("lib/c", c)]).await;
        let state = repo.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join(format!("{partial}.commitpartial")), b"").unwrap();
        let absent = Checksum::from_ay(&[0x22; 32]).unwrap();

        let txn = repo.transaction().await.unwrap();
        let cases = [
            (vec![("", dep)], "entry 0 has an empty name".to_owned()),
            (
                vec![("a/x", dep), ("a/x", dep)],
                "two entries have the name a/x".to_owned(),
            ),
            (
                vec![("a/x", absent)],
                format!(
                    "dependency a/x names commit {absent}, which is in neither the repository \
                     nor the transaction"
                ),
            ),
            (
                vec![("a/x", partial)],
                format!("dependency a/x names commit {partial}, which is partial"),
            ),
            (
                vec![("a/x", nested)],
                format!("dependency a/x names commit {nested}, which has dependencies of its own"),
            ),
        ];
        for (related, expected) in cases {
            let staged_before = staged(&repo);
            let err = txn.check_related(&owned(&related)).await.unwrap_err();
            assert_eq!(
                related_error(err),
                (None, RelatedField::Dependencies, expected)
            );
            assert_eq!(staged(&repo), staged_before, "the call stages nothing");
        }
        // The checks run in the byte order of the names: the absent `a/x`
        // comes before the nested `b/x`.
        let err = txn
            .check_related(&owned(&[("b/x", nested), ("a/x", absent)]))
            .await
            .unwrap_err();
        assert!(
            related_error(err).2.starts_with("dependency a/x "),
            "the first name in byte order"
        );
        // An accepted list stays in the order of the caller.
        let accepted = owned(&[("b/x", dep), ("a/x", c)]);
        txn.check_related(&accepted).await.unwrap();
        assert_eq!(accepted, owned(&[("b/x", dep), ("a/x", c)]));
        txn.check_related(&[]).await.unwrap();
        txn.abort().await.unwrap();
    });
}

#[test]
fn write_commit_refuses_a_nested_dependency() {
    let tmp = TmpDir::new("related-nested");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["c", "b", "a"]).await;
        let c = commit(&repo, tmp.path(), "c", &[]).await;
        let b = commit(&repo, tmp.path(), "b", &[("lib/c", c)]).await;
        let txn = repo.transaction().await.unwrap();
        let root = stage_tree(&txn, tmp.path(), "a").await;
        let err = txn
            .write_commit(options("a", &[("lib/b", b)]), &root)
            .await
            .unwrap_err();
        assert_eq!(
            related_error(err),
            (
                None,
                RelatedField::Dependencies,
                format!("dependency lib/b names commit {b}, which has dependencies of its own")
            )
        );
        txn.abort().await.unwrap();
    });
}

#[test]
fn write_commit_accepts_a_dependency_of_the_same_transaction() {
    let tmp = TmpDir::new("related-same-txn");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["dep", "head", "nested"]).await;
        let txn = repo.transaction().await.unwrap();
        let dep_root = stage_tree(&txn, tmp.path(), "dep").await;
        let dep = txn
            .write_commit(options("dep", &[]), &dep_root)
            .await
            .unwrap();
        let root = stage_tree(&txn, tmp.path(), "head").await;
        let head = txn
            .write_commit(options("head", &[("a/dep", dep)]), &root)
            .await
            .unwrap();
        // A staged dependency with a dependency of its own is nested.
        let nested_root = stage_tree(&txn, tmp.path(), "nested").await;
        let err = txn
            .write_commit(options("nested", &[("a/head", head)]), &nested_root)
            .await
            .unwrap_err();
        assert_eq!(
            related_error(err).2,
            format!("dependency a/head names commit {head}, which has dependencies of its own")
        );
        txn.commit().await.unwrap();
        assert_eq!(
            repo.read_commit_related(&head).await.unwrap().dependencies,
            owned(&[("a/dep", dep)])
        );
    });
}

#[test]
fn composefs_metadata_keeps_the_dependencies() {
    let tmp = TmpDir::new("related-composefs-keep");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["dep", "head"]).await;
        let dep = commit(&repo, tmp.path(), "dep", &[]).await;
        let head = commit(&repo, tmp.path(), "head", &[("a/dep", dep)]).await;
        let txn = repo.transaction().await.unwrap();
        let rewritten = repo
            .commit_add_composefs_metadata(&txn, &head)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        let (stored, _) = repo.load_commit(&rewritten).await.unwrap();
        assert_eq!(stored.related, field2(&[("a/dep", dep)]));
    });
}

#[test]
fn composefs_metadata_refuses_a_defective_source_field() {
    let tmp = TmpDir::new("related-composefs-refuse");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["c", "b", "head"]).await;
        let c = commit(&repo, tmp.path(), "c", &[]).await;
        let b = commit(&repo, tmp.path(), "b", &[("lib/c", c)]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        let (c_bytes, b_bytes) = (c.as_bytes().as_slice(), b.as_bytes().as_slice());
        let cases: [(&[Field2Entry], String); 5] = [
            (
                &[("lib/b", b_bytes)],
                format!("dependency lib/b names commit {b}, which has dependencies of its own"),
            ),
            (
                &[("lib/y", c_bytes), ("lib/x", c_bytes)],
                "entries are not sorted by name: lib/x follows lib/y".to_owned(),
            ),
            (
                &[("lib/x", c_bytes), ("lib/x", c_bytes)],
                "two entries have the name lib/x".to_owned(),
            ),
            (
                &[("lib/x", &c_bytes[..31])],
                "entry 0 (lib/x) has a checksum of 31 bytes, not 32".to_owned(),
            ),
            (
                &[("lib/x", &[0x33; 32])],
                format!(
                    "dependency lib/x names commit {}, which is in neither the repository nor \
                     the transaction",
                    Checksum::from_ay(&[0x33; 32]).unwrap()
                ),
            ),
        ];
        for (related, expected) in cases {
            let source = store_with_field2(&repo, &head, related).await;
            let objects_before = objects(&repo);
            let txn = repo.transaction().await.unwrap();
            let err = repo
                .commit_add_composefs_metadata(&txn, &source)
                .await
                .unwrap_err();
            assert_eq!(
                related_error(err),
                (Some(source), RelatedField::Dependencies, expected)
            );
            txn.abort().await.unwrap();
            assert_eq!(objects(&repo), objects_before, "no new object");
        }
    });
}

#[test]
fn read_commit_related_gives_both_fields() {
    let tmp = TmpDir::new("related-read-both");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["dep", "src", "head"]).await;
        let dep = commit(&repo, tmp.path(), "dep", &[]).await;
        let src = commit(&repo, tmp.path(), "src", &[]).await;
        let head = commit(&repo, tmp.path(), "head", &[("a/dep", dep)]).await;
        let absent = [0x44; 32];
        let meta = dict(vec![(
            RELATED_KEY,
            sources(&[("source/src", src.as_bytes()), ("source/gone", &absent)]),
        )]);
        repo.write_commit_detached_metadata(&head, Some(&meta))
            .await
            .unwrap();
        assert_eq!(
            repo.read_commit_related(&head).await.unwrap(),
            CommitRelated {
                dependencies: owned(&[("a/dep", dep)]),
                build_sources: owned(&[
                    ("source/src", src),
                    ("source/gone", Checksum::from_ay(&absent).unwrap()),
                ]),
            }
        );
        // With no detached metadata, the build sources are empty.
        assert_eq!(
            repo.read_commit_related(&dep).await.unwrap(),
            CommitRelated::default()
        );
    });
}

#[test]
fn read_commit_related_takes_the_first_build_source_key() {
    let tmp = TmpDir::new("related-read-first-key");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src", "head"]).await;
        let src = commit(&repo, tmp.path(), "src", &[]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        let meta = dict(vec![
            (RELATED_KEY, sources(&[("source/first", src.as_bytes())])),
            (RELATED_KEY, sources(&[("source/second", src.as_bytes())])),
        ]);
        repo.write_commit_detached_metadata(&head, Some(&meta))
            .await
            .unwrap();
        assert_eq!(
            repo.read_commit_related(&head).await.unwrap().build_sources,
            owned(&[("source/first", src)])
        );
    });
}

#[test]
fn read_commit_related_refuses_a_defective_build_source_value() {
    let tmp = TmpDir::new("related-read-bad-sources");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        let strings = (
            Type::parse("as").unwrap(),
            Value::Array(vec![Value::Str("source/x".into())]),
        );
        let cases = [
            (strings, "type is `as`, not `a(say)`"),
            (
                sources(&[("source/x", &[0x55; 20])]),
                "entry 0 (source/x) has a checksum of 20 bytes, not 32",
            ),
            (sources(&[("", &[0x55; 32])]), "entry 0 has an empty name"),
        ];
        for (value, expected) in cases {
            let meta = dict(vec![(RELATED_KEY, value)]);
            repo.write_commit_detached_metadata(&head, Some(&meta))
                .await
                .unwrap();
            let err = repo.read_commit_related(&head).await.unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("related commits in ostrya.related of commit {head}: {expected}")
            );
            assert_eq!(
                related_error(err),
                (Some(head), RelatedField::BuildSources, expected.to_owned())
            );
        }
    });
}

#[test]
fn read_commit_related_checks_the_format_of_field2() {
    let tmp = TmpDir::new("related-read-field2");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["dep", "head"]).await;
        let dep = commit(&repo, tmp.path(), "dep", &[]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        let bytes = dep.as_bytes().as_slice();

        let short = store_with_field2(&repo, &head, &[("a/x", &bytes[..31])]).await;
        assert_eq!(
            related_error(repo.read_commit_related(&short).await.unwrap_err()),
            (
                Some(short),
                RelatedField::Dependencies,
                "entry 0 (a/x) has a checksum of 31 bytes, not 32".to_owned()
            )
        );
        let unnamed = store_with_field2(&repo, &head, &[("a/x", bytes), ("", bytes)]).await;
        assert_eq!(
            related_error(repo.read_commit_related(&unnamed).await.unwrap_err()),
            (
                Some(unnamed),
                RelatedField::Dependencies,
                "entry 1 has an empty name".to_owned()
            )
        );

        // The read keeps an unsorted field and a name two times.
        let absent = [0x66; 32];
        let unsorted = store_with_field2(
            &repo,
            &head,
            &[("b/x", bytes), ("a/x", &absent), ("b/x", bytes)],
        )
        .await;
        let absent = Checksum::from_ay(&absent).unwrap();
        assert_eq!(
            repo.read_commit_related(&unsorted)
                .await
                .unwrap()
                .dependencies,
            owned(&[("b/x", dep), ("a/x", absent), ("b/x", dep)])
        );
    });
}

#[test]
fn read_commit_related_of_an_absent_commit() {
    let tmp = TmpDir::new("related-read-absent");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &[]).await;
        let absent = Checksum::from_ay(&[0x77; 32]).unwrap();
        let err = repo.read_commit_related(&absent).await.unwrap_err();
        assert!(matches!(err, Error::ObjectNotFound { .. }), "got {err:?}");
    });
}
