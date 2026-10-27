//! Integration tests of the related commits of a commit.
//!
//! `Transaction::write_commit` writes `CommitOptions::related` into field 2
//! of the commit object, sorted by name, and refuses dependencies that are
//! defective, not complete, or nested. `Transaction::check_related` runs the
//! same checks before a tree is built. `Repo::commit_add_composefs_metadata`
//! keeps field 2 and applies the same check. `Repo::read_commit_related`
//! reads field 2 and the detached key `ostrya.related`.
//! `Repo::add_detached_related` and `Transaction::add_detached_related` add
//! a build source, and the detached metadata writes check the value of
//! `ostrya.related`. The `ostree` command has no counterpart, so the tests
//! use ostrya alone.

mod common;

use std::path::Path;

use common::{Field2Entry, TmpDir, file_inventory, store_with_field2};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CommitRelated, CreateOptions,
    DictBuilder, DummySigner, Error, LockKind, MutableTree, ObjectType, PullOptions, RelatedField,
    Repo, RepoMode, RepoTree, Transaction, Type, Value,
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

/// Writes `meta` as the `.commitmeta` of `commit` with no check, as a write
/// out of band does.
fn write_raw_detached(repo: &Repo, commit: &Checksum, meta: &Value) {
    let bytes = ostrya_core::to_bytes(&Type::parse("a{sv}").unwrap(), meta).unwrap();
    let path = repo.path().join("objects").join(ostrya::loose_path(
        commit,
        ObjectType::CommitMeta,
        repo.mode(),
    ));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Returns the keys of the detached metadata of `commit`, in stored order.
async fn detached_keys(repo: &Repo, commit: &Checksum) -> Vec<String> {
    let dict = repo
        .read_commit_detached_metadata(commit)
        .await
        .unwrap()
        .expect("the commit has detached metadata");
    dict.as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_tuple().unwrap()[0].as_str().unwrap().to_owned())
        .collect()
}

/// Returns an `s` value.
fn string(text: &str) -> (Type, Value) {
    (Type::parse("s").unwrap(), Value::Str(text.to_owned()))
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
            // The detached metadata writes refuse the value, so the test
            // writes the file out of band.
            let meta = dict(vec![(RELATED_KEY, value)]);
            write_raw_detached(&repo, &head, &meta);
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

#[test]
fn add_detached_related_replaces_by_name_and_keeps_the_sort() {
    let tmp = TmpDir::new("related-add-sort");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["x", "y", "head"]).await;
        let x = commit(&repo, tmp.path(), "x", &[]).await;
        let y = commit(&repo, tmp.path(), "y", &[]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        repo.write_commit_detached_metadata(&head, Some(&dict(vec![("test.note", string("n"))])))
            .await
            .unwrap();

        repo.add_detached_related(&head, "z/x", &x).await.unwrap();
        repo.add_detached_related(&head, "a/y", &y).await.unwrap();
        assert_eq!(
            repo.read_commit_related(&head).await.unwrap().build_sources,
            owned(&[("a/y", y), ("z/x", x)])
        );
        // An add with a stored name replaces the entry.
        repo.add_detached_related(&head, "z/x", &y).await.unwrap();
        assert_eq!(
            repo.read_commit_related(&head).await.unwrap().build_sources,
            owned(&[("a/y", y), ("z/x", y)])
        );
        // The new key comes after the stored keys, and the other key stays.
        assert_eq!(
            detached_keys(&repo, &head).await,
            ["test.note", RELATED_KEY]
        );

        // A commit with no detached metadata gets a dict with the one key. A
        // checksum that the repository does not hold is accepted.
        let absent = Checksum::from_ay(&[0x31; 32]).unwrap();
        repo.add_detached_related(&x, "layer/gone", &absent)
            .await
            .unwrap();
        assert_eq!(
            repo.read_commit_related(&x).await.unwrap().build_sources,
            owned(&[("layer/gone", absent)])
        );
        assert_eq!(detached_keys(&repo, &x).await, [RELATED_KEY]);
    });
}

#[test]
fn add_detached_related_edits_the_first_key() {
    let tmp = TmpDir::new("related-add-first-key");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src", "head"]).await;
        let src = commit(&repo, tmp.path(), "src", &[]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        let second = sources(&[("source/second", src.as_bytes())]);
        let meta = dict(vec![
            (RELATED_KEY, sources(&[("source/first", src.as_bytes())])),
            (RELATED_KEY, second.clone()),
        ]);
        repo.write_commit_detached_metadata(&head, Some(&meta))
            .await
            .unwrap();
        repo.add_detached_related(&head, "source/added", &src)
            .await
            .unwrap();
        let expected = dict(vec![
            (
                RELATED_KEY,
                sources(&[
                    ("source/added", src.as_bytes()),
                    ("source/first", src.as_bytes()),
                ]),
            ),
            (RELATED_KEY, second),
        ]);
        assert_eq!(
            repo.read_commit_detached_metadata(&head).await.unwrap(),
            Some(expected)
        );
    });
}

#[test]
fn add_detached_related_refuses_an_empty_name() {
    let tmp = TmpDir::new("related-add-empty-name");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src", "head"]).await;
        let src = commit(&repo, tmp.path(), "src", &[]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        repo.add_detached_related(&head, "source/src", &src)
            .await
            .unwrap();
        let before = objects(&repo);
        let expected = (
            Some(head),
            RelatedField::BuildSources,
            "the new entry has an empty name".to_owned(),
        );
        let err = repo
            .add_detached_related(&head, "", &src)
            .await
            .unwrap_err();
        assert_eq!(related_error(err), expected);
        assert_eq!(objects(&repo), before, "the refused add writes nothing");

        let txn = repo.transaction().await.unwrap();
        let err = txn.add_detached_related(&head, "", &src).unwrap_err();
        assert_eq!(related_error(err), expected);
        txn.commit().await.unwrap();
        assert_eq!(objects(&repo), before, "the refused add queues nothing");
    });
}

#[test]
fn add_detached_related_of_an_absent_commit() {
    let tmp = TmpDir::new("related-add-absent");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src"]).await;
        let src = commit(&repo, tmp.path(), "src", &[]).await;
        let absent = Checksum::from_ay(&[0x77; 32]).unwrap();
        let before = objects(&repo);
        let err = repo
            .add_detached_related(&absent, "source/src", &src)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::ObjectNotFound { checksum, ty: ObjectType::Commit } if checksum == absent),
            "got {err:?}"
        );
        assert_eq!(objects(&repo), before);
    });
}

#[test]
fn add_detached_related_refuses_a_defective_stored_value() {
    let tmp = TmpDir::new("related-add-defective");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src", "head"]).await;
        let src = commit(&repo, tmp.path(), "src", &[]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        let meta = dict(vec![(
            RELATED_KEY,
            sources(&[("source/short", &[0x55; 31])]),
        )]);
        write_raw_detached(&repo, &head, &meta);
        let before = objects(&repo);
        let expected = (
            Some(head),
            RelatedField::BuildSources,
            "entry 0 (source/short) has a checksum of 31 bytes, not 32".to_owned(),
        );

        let err = repo
            .add_detached_related(&head, "source/src", &src)
            .await
            .unwrap_err();
        assert_eq!(related_error(err), expected);
        assert_eq!(objects(&repo), before, "the refused add writes nothing");

        // The queued add fails at the commit of the transaction. The commit
        // writes no ref, and the file stays as it was.
        let refs_before = refs(&repo);
        let txn = repo.transaction().await.unwrap();
        txn.add_detached_related(&head, "source/src", &src).unwrap();
        txn.set_ref("main", Some(&head));
        let err = txn.commit().await.unwrap_err();
        assert_eq!(related_error(err), expected);
        assert_eq!(objects(&repo), before);
        assert_eq!(refs(&repo), refs_before, "the failed commit writes no ref");
    });
}

#[test]
fn transaction_add_detached_related_gives_the_result_of_the_repo_add() {
    let tmp = TmpDir::new("related-add-txn");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["x", "y", "one", "two"]).await;
        let x = commit(&repo, tmp.path(), "x", &[]).await;
        let y = commit(&repo, tmp.path(), "y", &[]).await;
        let one = commit(&repo, tmp.path(), "one", &[]).await;
        let two = commit(&repo, tmp.path(), "two", &[]).await;
        let adds = [("z/x", x), ("a/y", y), ("z/x", y)];

        for (name, source) in adds {
            repo.add_detached_related(&one, name, &source)
                .await
                .unwrap();
        }
        let txn = repo.transaction().await.unwrap();
        for (name, source) in adds {
            txn.add_detached_related(&two, name, &source).unwrap();
        }
        txn.commit().await.unwrap();
        assert_eq!(
            repo.read_commit_detached_metadata(&two).await.unwrap(),
            repo.read_commit_detached_metadata(&one).await.unwrap()
        );
        assert_eq!(
            repo.read_commit_related(&two).await.unwrap().build_sources,
            owned(&[("a/y", y), ("z/x", y)])
        );
    });
}

#[test]
fn transaction_adds_apply_after_the_queued_dict_and_before_the_signatures() {
    let tmp = TmpDir::new("related-add-txn-order");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src", "head"]).await;
        let src = commit(&repo, tmp.path(), "src", &[]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;

        let txn = repo.transaction().await.unwrap();
        txn.set_commit_detached_metadata(&head, dict(vec![("test.note", string("n"))]));
        txn.add_detached_related(&head, "source/src", &src).unwrap();
        txn.sign_commit(&head, &DummySigner::new("key"))
            .await
            .unwrap();
        txn.commit().await.unwrap();
        let keys = detached_keys(&repo, &head).await;
        assert_eq!(keys.len(), 3, "got {keys:?}");
        assert_eq!(keys[..2], ["test.note", RELATED_KEY]);
        assert_eq!(
            repo.read_commit_related(&head).await.unwrap().build_sources,
            owned(&[("source/src", src)])
        );

        // A queued dict after an add drops the add.
        let txn = repo.transaction().await.unwrap();
        txn.add_detached_related(&head, "source/other", &src)
            .unwrap();
        txn.set_commit_detached_metadata(&head, dict(vec![("test.note", string("m"))]));
        txn.commit().await.unwrap();
        assert_eq!(detached_keys(&repo, &head).await, ["test.note"]);
        assert!(
            repo.read_commit_related(&head)
                .await
                .unwrap()
                .build_sources
                .is_empty()
        );
    });
}

/// A local write ignores `[ex-ostrya] keep-detached-related`. Under `false`,
/// each write API and a signature after it keep `ostrya.related`.
#[test]
fn a_local_write_keeps_the_related_key_under_the_switch() {
    let tmp = TmpDir::new("related-local-write-switch");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["src", "one", "two", "three", "four"]).await;
        let config = repo.path().join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("\n[ex-ostrya]\nkeep-detached-related=false\n");
        std::fs::write(&config, text).unwrap();
        let repo = Repo::open(repo.path()).await.unwrap();
        assert!(!repo.config().keep_detached_related().unwrap());
        let src = commit(&repo, tmp.path(), "src", &[]).await;
        let [one, two, three, four] = [
            commit(&repo, tmp.path(), "one", &[]).await,
            commit(&repo, tmp.path(), "two", &[]).await,
            commit(&repo, tmp.path(), "three", &[]).await,
            commit(&repo, tmp.path(), "four", &[]).await,
        ];
        let meta = dict(vec![
            ("test.note", string("n")),
            (RELATED_KEY, sources(&[("source/src", src.as_bytes())])),
        ]);

        repo.write_commit_detached_metadata(&one, Some(&meta))
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        txn.set_commit_detached_metadata(&two, meta.clone());
        txn.commit().await.unwrap();
        repo.add_detached_related(&three, "source/src", &src)
            .await
            .unwrap();
        let txn = repo.transaction().await.unwrap();
        txn.add_detached_related(&four, "source/src", &src).unwrap();
        txn.commit().await.unwrap();

        for head in [one, two, three, four] {
            repo.sign_commit(&head, &DummySigner::new("key"))
                .await
                .unwrap();
            assert!(
                detached_keys(&repo, &head)
                    .await
                    .iter()
                    .any(|k| k == RELATED_KEY),
                "{head}"
            );
            assert_eq!(
                repo.read_commit_related(&head).await.unwrap().build_sources,
                owned(&[("source/src", src)]),
                "{head}"
            );
        }
    });
}

/// Returns the defective `ostrya.related` values of the write checks, each
/// with the reason of its refusal.
fn defective_values() -> Vec<((Type, Value), &'static str)> {
    let strings = (
        Type::parse("as").unwrap(),
        Value::Array(vec![Value::Str("source/x".into())]),
    );
    vec![
        (strings, "type is `as`, not `a(say)`"),
        (
            sources(&[("source/ok", &[0x55; 32]), ("source/x", &[0x55; 31])]),
            "entry 1 (source/x) has a checksum of 31 bytes, not 32",
        ),
        (sources(&[("", &[0x55; 32])]), "entry 0 has an empty name"),
    ]
}

#[test]
fn write_commit_detached_metadata_checks_each_build_source_key() {
    let tmp = TmpDir::new("related-write-check");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        let stored = dict(vec![("test.note", string("n"))]);
        repo.write_commit_detached_metadata(&head, Some(&stored))
            .await
            .unwrap();
        let before = objects(&repo);
        let valid = sources(&[("source/ok", &[0x55; 32])]);
        for (value, reason) in defective_values() {
            // The defect is in the first key, and then in a later key.
            for meta in [
                dict(vec![(RELATED_KEY, value.clone())]),
                dict(vec![
                    (RELATED_KEY, valid.clone()),
                    (RELATED_KEY, value.clone()),
                ]),
            ] {
                let err = repo
                    .write_commit_detached_metadata(&head, Some(&meta))
                    .await
                    .unwrap_err();
                assert_eq!(
                    err.to_string(),
                    format!("related commits in ostrya.related of commit {head}: {reason}")
                );
                assert_eq!(
                    related_error(err),
                    (Some(head), RelatedField::BuildSources, reason.to_owned())
                );
                assert_eq!(objects(&repo), before, "the refused write writes nothing");
            }
        }

        // Entries that are not sorted, a name two times, and a checksum that
        // the repository does not hold are accepted.
        let accepted = dict(vec![(
            RELATED_KEY,
            sources(&[
                ("source/b", &[0x55; 32]),
                ("source/a", &[0x56; 32]),
                ("source/b", &[0x57; 32]),
            ]),
        )]);
        repo.write_commit_detached_metadata(&head, Some(&accepted))
            .await
            .unwrap();
    });
}

#[test]
fn write_commit_detached_metadata_checks_before_the_lock() {
    let tmp = TmpDir::new("related-write-before-lock");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        // The config of a new repository ends in its `[core]` group, so the
        // appended key goes into that group.
        let config = repo.path().join("config");
        let mut text = std::fs::read_to_string(&config).unwrap();
        text.push_str("lock-timeout-secs=0\n");
        std::fs::write(&config, text).unwrap();
        let writing = Repo::open(repo.path()).await.unwrap();

        let held = repo
            .transaction_with_lock(LockKind::Exclusive)
            .await
            .expect("take the exclusive hold");
        // The hold excludes the handle that writes.
        let valid = dict(vec![(RELATED_KEY, sources(&[("source/ok", &[0x55; 32])]))]);
        let err = writing
            .write_commit_detached_metadata(&head, Some(&valid))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::LockTimeout { secs: 0 }),
            "the hold is live: {err:?}"
        );

        let before = objects(&repo);
        let defective = dict(vec![(RELATED_KEY, sources(&[("", &[0x55; 32])]))]);
        let err = writing
            .write_commit_detached_metadata(&head, Some(&defective))
            .await
            .unwrap_err();
        assert_eq!(
            related_error(err),
            (
                Some(head),
                RelatedField::BuildSources,
                "entry 0 has an empty name".to_owned()
            ),
            "the check comes before the lock"
        );
        held.abort().await.unwrap();
        assert_eq!(objects(&repo), before, "the refused write writes nothing");
        assert_eq!(
            writing.read_commit_detached_metadata(&head).await.unwrap(),
            None
        );
    });
}

#[test]
fn a_queued_defective_dict_fails_the_commit() {
    let tmp = TmpDir::new("related-queued-check");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        for (value, reason) in defective_values() {
            let before = objects(&repo);
            let refs_before = refs(&repo);
            let txn = repo.transaction().await.unwrap();
            let root = stage_tree(&txn, tmp.path(), "head").await;
            let head = txn.write_commit(options("head", &[]), &root).await.unwrap();
            txn.set_commit_detached_metadata(&head, dict(vec![(RELATED_KEY, value)]));
            txn.set_ref("main", Some(&head));
            let err = txn.commit().await.unwrap_err();
            assert_eq!(
                related_error(err),
                (Some(head), RelatedField::BuildSources, reason.to_owned())
            );
            assert_eq!(
                objects(&repo),
                before,
                "the refused commit publishes nothing"
            );
            assert_eq!(refs(&repo), refs_before, "the refused commit writes no ref");
            assert!(staged(&repo).is_empty(), "the staging directory is removed");
        }
    });
}

#[test]
fn a_signature_over_a_defective_value_takes_no_check() {
    let tmp = TmpDir::new("related-sign-no-check");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), &["head"]).await;
        let head = commit(&repo, tmp.path(), "head", &[]).await;
        let meta = dict(vec![(
            RELATED_KEY,
            sources(&[("source/short", &[0x55; 31])]),
        )]);
        write_raw_detached(&repo, &head, &meta);
        repo.sign_commit(&head, &DummySigner::new("key"))
            .await
            .unwrap();
        assert_eq!(detached_keys(&repo, &head).await.len(), 2);
    });
}

#[test]
fn a_local_pull_stores_a_defective_value() {
    let tmp = TmpDir::new("related-pull-no-check");
    block_on(async {
        let src = repo_with_trees(tmp.path(), &["head"]).await;
        let txn = src.transaction().await.unwrap();
        let root = stage_tree(&txn, tmp.path(), "head").await;
        let head = txn.write_commit(options("head", &[]), &root).await.unwrap();
        txn.set_ref("main", Some(&head));
        txn.commit().await.unwrap();
        let meta = dict(vec![(
            RELATED_KEY,
            sources(&[("source/short", &[0x55; 31])]),
        )]);
        write_raw_detached(&src, &head, &meta);

        let dst = Repo::create(
            &tmp.path().join("dst"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        dst.pull_local(
            &src,
            PullOptions {
                refs: vec!["main".to_owned()],
                ..PullOptions::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(dst.resolve_rev("main", false).await.unwrap(), Some(head));
        assert_eq!(
            dst.read_commit_detached_metadata(&head).await.unwrap(),
            Some(meta)
        );
    });
}
