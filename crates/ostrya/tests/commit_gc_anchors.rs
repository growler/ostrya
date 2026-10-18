//! Integration tests of the check of GC anchor keys at a commit write.
//!
//! `Transaction::write_commit`, `Transaction::commit`,
//! `Repo::write_commit_detached_metadata`, and
//! `Repo::commit_add_composefs_metadata` refuse a dict that gives a key of
//! `[ex-ostrya] gc-root-metadata-keys` a value that a prune refuses. The
//! anchor commit of a summary takes no check. The `ostree` command has no
//! counterpart, so the tests use ostrya alone.

mod common;

use std::path::Path;

use common::{TmpDir, file_inventory};
use ostrya::{
    Checksum, CommitModifier, CommitModifierFlags, CommitOptions, CreateOptions, DictBuilder,
    DummySigner, Error, LockKind, MutableTree, PruneOptions, PullOptions, Repo, RepoMode, RepoTree,
    SummaryOptions, Transaction, Type, Value,
};
use ostrya_rt::block_on;

/// A fixed timestamp, so the commits are reproducible.
const FIXED_TS: u64 = 1_700_000_000;

/// The metadata key that these tests name in `[ex-ostrya]
/// gc-root-metadata-keys`.
const ANCHORS: &str = "test.anchors";

/// A metadata key that the config does not name.
const OTHER: &str = "test.other";

/// The reason that the decoder gives for an `s` value.
const STRING_REASON: &str = "type is `s`, not `aay`, `a(say)`, or `a{s(say)}`";

/// The reason that the decoder gives for a first checksum of 20 bytes.
const SHORT_REASON: &str = "element 0 is 20 bytes, not 32";

/// Writes a tree with one file at `base/<name>`. The content of the file names
/// the tree.
fn write_tree(base: &Path, name: &str) {
    let dir = base.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("payload.txt"), format!("{name}\n")).unwrap();
}

/// Writes the trees `base/<name>` and creates an archive repository under
/// `base/<repo>`.
async fn repo_with_trees(base: &Path, repo: &str, names: &[&str]) -> Repo {
    for name in names {
        write_tree(base, name);
    }
    Repo::create(&base.join(repo), CreateOptions::new(RepoMode::Archive))
        .await
        .unwrap()
}

/// Appends `text` to the config of `repo` and returns a new handle, which
/// reads the changed config.
///
/// The config of a new repository ends in its `[core]` group, so a `[core]`
/// key in `text` goes before the first group header of `text`.
async fn reconfigure(repo: &Repo, text: &str) -> Repo {
    let config = repo.path().join("config");
    let mut current = std::fs::read_to_string(&config).unwrap();
    current.push_str(text);
    std::fs::write(&config, current).unwrap();
    Repo::open(repo.path()).await.unwrap()
}

/// Sets `[ex-ostrya] gc-root-metadata-keys` to `value` in `repo` and returns
/// a new handle.
async fn configure_keys(repo: &Repo, value: &str) -> Repo {
    reconfigure(
        repo,
        &format!("\n[ex-ostrya]\ngc-root-metadata-keys={value}\n"),
    )
    .await
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

/// Returns the commit options of these tests, with `metadata`.
fn options(name: &str, metadata: Option<Value>) -> CommitOptions {
    CommitOptions {
        subject: Some(name.to_owned()),
        timestamp: Some(FIXED_TS),
        metadata,
        ..CommitOptions::default()
    }
}

/// Commits the tree `base/<name>` into `repo` with `metadata`, sets the ref
/// `branch` to it if one is given, and returns the commit.
async fn commit(
    repo: &Repo,
    base: &Path,
    name: &str,
    metadata: Option<Value>,
    branch: Option<&str>,
) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let root = stage_tree(&txn, base, name).await;
    let commit = txn
        .write_commit(options(name, metadata), &root)
        .await
        .unwrap();
    if let Some(branch) = branch {
        txn.set_ref(branch, Some(&commit));
    }
    txn.commit().await.unwrap();
    commit
}

/// Returns an `aay` value of checksum bytes, with its type.
fn checksums(checksums: &[&[u8]]) -> (Type, Value) {
    let elements = checksums.iter().map(|c| Value::Bytes(c.to_vec())).collect();
    (Type::parse("aay").unwrap(), Value::Array(elements))
}

/// Returns an `(say)` pair of a canonical ref and checksum bytes.
fn pair(canonical_ref: &str, checksum: &[u8]) -> Value {
    Value::Tuple(vec![
        Value::Str(canonical_ref.to_owned()),
        Value::Bytes(checksum.to_vec()),
    ])
}

/// Returns an `a(say)` value of `(canonical ref, checksum)` pairs, with its
/// type.
fn pairs(pairs: &[(&str, &[u8])]) -> (Type, Value) {
    let elements = pairs.iter().map(|(r, c)| pair(r, c)).collect();
    (Type::parse("a(say)").unwrap(), Value::Array(elements))
}

/// Returns an `a{s(say)}` value of `name -> (canonical ref, checksum)`
/// entries, with its type.
fn named_pairs(entries: &[(&str, &str, &[u8])]) -> (Type, Value) {
    let elements = entries
        .iter()
        .map(|(name, r, c)| Value::Tuple(vec![Value::Str((*name).to_owned()), pair(r, c)]))
        .collect();
    (Type::parse("a{s(say)}").unwrap(), Value::Array(elements))
}

/// Returns an `s` value, with its type.
fn string(text: &str) -> (Type, Value) {
    (Type::parse("s").unwrap(), Value::Str(text.to_owned()))
}

/// Returns an `a{sv}` with one entry for each `(key, (type, value))`, in the
/// order of `entries`. A key can occur more than one time.
fn entries(entries: Vec<(&str, (Type, Value))>) -> Value {
    let mut builder = DictBuilder::new();
    for (key, (ty, value)) in entries {
        builder.insert(key, ty, value);
    }
    builder.build()
}

/// Returns an empty `a{sv}`.
fn empty_dict() -> Value {
    Value::Array(Vec::new())
}

/// Returns the dicts that each write method refuses, each with the reason of
/// the refusal. `anchor` is a commit of the store.
fn defective_dicts(anchor: &Checksum) -> Vec<(Value, &'static str)> {
    let valid = anchor.as_bytes();
    let short: &[u8] = &[0x11; 20];
    vec![
        (entries(vec![(ANCHORS, string("main"))]), STRING_REASON),
        (entries(vec![(ANCHORS, checksums(&[short]))]), SHORT_REASON),
        (
            entries(vec![(ANCHORS, pairs(&[("main", short)]))]),
            SHORT_REASON,
        ),
        (
            entries(vec![(ANCHORS, named_pairs(&[("app", "main", short)]))]),
            SHORT_REASON,
        ),
        // The first entry is valid, and the check reads the second too.
        (
            entries(vec![
                (OTHER, string("x")),
                (ANCHORS, checksums(&[valid])),
                (ANCHORS, string("main")),
            ]),
            STRING_REASON,
        ),
    ]
}

/// Returns the reason of an [`Error::InvalidGcAnchor`] for [`ANCHORS`].
fn anchor_reason(err: Error) -> String {
    match err {
        Error::InvalidGcAnchor {
            metadata_key,
            reason,
        } => {
            assert_eq!(metadata_key, ANCHORS, "the error names the key");
            reason
        }
        other => panic!("expected InvalidGcAnchor, got {other:?}"),
    }
}

/// Returns the regular files and symlinks under `objects/` of `repo`, with
/// their bytes.
fn objects(repo: &Repo) -> Vec<(String, Vec<u8>)> {
    file_inventory(repo.path(), "objects")
}

/// Returns the regular files and symlinks under `refs/` of `repo`, with their
/// bytes.
fn refs(repo: &Repo) -> Vec<(String, Vec<u8>)> {
    file_inventory(repo.path(), "refs")
}

#[test]
fn write_commit_accepts_each_anchor_shape() {
    let tmp = TmpDir::new("gc-anchors-write-accepts");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["anchor", "head"]).await;
        let anchor = commit(&repo, tmp.path(), "anchor", None, None).await;
        let repo = configure_keys(&repo, ANCHORS).await;
        let valid = anchor.as_bytes();
        // A checksum that names no commit in the store passes.
        let absent: &[u8] = &[0x22; 32];
        let cases = [
            entries(vec![(ANCHORS, checksums(&[valid, absent]))]),
            entries(vec![(ANCHORS, pairs(&[("main", valid), ("", absent)]))]),
            entries(vec![(
                ANCHORS,
                named_pairs(&[("app", "main", valid), ("app", "", absent)]),
            )]),
            entries(vec![(ANCHORS, checksums(&[]))]),
            entries(vec![(ANCHORS, pairs(&[]))]),
            entries(vec![(ANCHORS, named_pairs(&[]))]),
            entries(vec![
                (ANCHORS, checksums(&[valid])),
                (ANCHORS, pairs(&[("main", absent)])),
                (ANCHORS, named_pairs(&[("app", "", valid)])),
            ]),
        ];
        for metadata in cases {
            let written = commit(&repo, tmp.path(), "head", Some(metadata.clone()), None).await;
            let (stored, _) = repo.load_commit(&written).await.unwrap();
            assert_eq!(stored.metadata, metadata, "the commit holds the dict");
        }
    });
}

#[test]
fn write_commit_refuses_a_defective_anchor_value() {
    let tmp = TmpDir::new("gc-anchors-write-refuses");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["anchor", "head"]).await;
        let anchor = commit(&repo, tmp.path(), "anchor", None, Some("main")).await;
        let repo = configure_keys(&repo, ANCHORS).await;
        for (metadata, expected) in defective_dicts(&anchor) {
            let before = objects(&repo);
            let txn = repo.transaction().await.unwrap();
            let root = stage_tree(&txn, tmp.path(), "head").await;
            let err = txn
                .write_commit(options("head", Some(metadata)), &root)
                .await
                .unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(
                    "metadata key {ANCHORS} is in [ex-ostrya] gc-root-metadata-keys: {expected}"
                )
            );
            assert_eq!(anchor_reason(err), expected);
            // The transaction stays open. Its commit publishes the staged
            // tree objects, and a commit object staged before the refusal.
            txn.commit().await.unwrap();
            let new: Vec<String> = objects(&repo)
                .into_iter()
                .filter(|object| !before.contains(object))
                .map(|(path, _)| path)
                .collect();
            assert!(
                new.iter().all(|path| !path.ends_with(".commit")),
                "the store holds no new commit object: {new:?}"
            );
        }
    });
}

#[test]
fn a_refused_write_commit_leaves_the_transaction_open() {
    let tmp = TmpDir::new("gc-anchors-write-open");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["head"]).await;
        let repo = configure_keys(&repo, ANCHORS).await;
        let txn = repo.transaction().await.unwrap();
        let root = stage_tree(&txn, tmp.path(), "head").await;
        let defective = entries(vec![(ANCHORS, string("main"))]);
        let err = txn
            .write_commit(options("head", Some(defective)), &root)
            .await
            .unwrap_err();
        assert_eq!(anchor_reason(err), STRING_REASON);
        let written = txn
            .write_commit(options("head", None), &root)
            .await
            .unwrap();
        txn.set_ref("main", Some(&written));
        txn.commit().await.unwrap();
        assert_eq!(
            repo.resolve_rev("main", false).await.unwrap(),
            Some(written)
        );
    });
}

#[test]
fn write_commit_does_not_check_the_sizes_entry_it_adds() {
    let tmp = TmpDir::new("gc-anchors-write-sizes");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["head"]).await;
        // The `ostree.sizes` value is an `aay` whose elements are not 32
        // bytes, so the check of the walk refuses it.
        let repo = configure_keys(&repo, "ostree.sizes").await;
        let mut txn = repo.transaction().await.unwrap();
        txn.set_generate_sizes(true);
        let root = stage_tree(&txn, tmp.path(), "head").await;
        let metadata = entries(vec![(OTHER, string("x"))]);
        let written = txn
            .write_commit(options("head", Some(metadata)), &root)
            .await
            .unwrap();
        txn.set_ref("main", Some(&written));
        txn.commit().await.unwrap();
        let (stored, _) = repo.load_commit(&written).await.unwrap();
        assert!(
            stored.metadata.dict_get("ostree.sizes").is_some(),
            "the commit holds the sizes entry"
        );
        // A prune that reaches the commit refuses the sizes value.
        let opts = PruneOptions {
            refs_only: true,
            ..PruneOptions::new()
        };
        let err = repo.prune(&opts).await.unwrap_err();
        assert!(
            matches!(&err, Error::InvalidGcRoot { metadata_key, .. } if metadata_key == "ostree.sizes"),
            "got {err:?}"
        );
    });
}

#[test]
fn write_commit_detached_metadata_refuses_a_defective_anchor_value() {
    let tmp = TmpDir::new("gc-anchors-detached-refuses");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["anchor", "head"]).await;
        let anchor = commit(&repo, tmp.path(), "anchor", None, None).await;
        let with_meta = commit(&repo, tmp.path(), "head", None, None).await;
        let stored = entries(vec![(OTHER, string("stays"))]);
        repo.write_commit_detached_metadata(&with_meta, Some(&stored))
            .await
            .unwrap();
        let repo = configure_keys(&repo, ANCHORS).await;
        for target in [with_meta, anchor] {
            for (meta, expected) in defective_dicts(&anchor) {
                let before = objects(&repo);
                let err = repo
                    .write_commit_detached_metadata(&target, Some(&meta))
                    .await
                    .unwrap_err();
                assert_eq!(anchor_reason(err), expected);
                assert_eq!(
                    objects(&repo),
                    before,
                    "the .commitmeta file stays as it was"
                );
            }
        }
        assert_eq!(
            repo.read_commit_detached_metadata(&with_meta)
                .await
                .unwrap(),
            Some(stored),
            "the stored dict stays"
        );
        assert_eq!(
            repo.read_commit_detached_metadata(&anchor).await.unwrap(),
            None,
            "a commit with no detached metadata keeps none"
        );
    });
}

#[test]
fn write_commit_detached_metadata_checks_before_the_lock() {
    let tmp = TmpDir::new("gc-anchors-detached-before-lock");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["head"]).await;
        let head = commit(&repo, tmp.path(), "head", None, None).await;
        let writing = reconfigure(
            &repo,
            &format!("lock-timeout-secs=0\n\n[ex-ostrya]\ngc-root-metadata-keys={ANCHORS}\n"),
        )
        .await;

        let held = repo
            .transaction_with_lock(LockKind::Exclusive)
            .await
            .expect("take the exclusive hold");
        // The hold excludes the handle that writes.
        let valid = entries(vec![(OTHER, string("x"))]);
        let err = writing
            .write_commit_detached_metadata(&head, Some(&valid))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::LockTimeout { secs: 0 }),
            "the hold is live: {err:?}"
        );

        let defective = entries(vec![(ANCHORS, string("main"))]);
        let err = writing
            .write_commit_detached_metadata(&head, Some(&defective))
            .await
            .unwrap_err();
        assert_eq!(
            anchor_reason(err),
            STRING_REASON,
            "the check comes before the lock"
        );
        held.abort().await.unwrap();
        assert_eq!(
            writing.read_commit_detached_metadata(&head).await.unwrap(),
            None
        );
    });
}

#[test]
fn commit_refuses_a_queued_detached_dict_with_a_defective_anchor_value() {
    let tmp = TmpDir::new("gc-anchors-commit-refuses");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["anchor", "head"]).await;
        let anchor = commit(&repo, tmp.path(), "anchor", None, Some("main")).await;
        let stored = entries(vec![(OTHER, string("stays"))]);
        repo.write_commit_detached_metadata(&anchor, Some(&stored))
            .await
            .unwrap();
        let repo = configure_keys(&repo, ANCHORS).await;
        for (meta, expected) in defective_dicts(&anchor) {
            let objects_before = objects(&repo);
            let refs_before = refs(&repo);
            let txn = repo.transaction().await.unwrap();
            let root = stage_tree(&txn, tmp.path(), "head").await;
            let written = txn
                .write_commit(options("head", None), &root)
                .await
                .unwrap();
            // A valid dict for one commit and a defective dict for another.
            txn.set_commit_detached_metadata(&anchor, entries(vec![(OTHER, string("new"))]));
            txn.set_commit_detached_metadata(&written, meta);
            txn.set_ref("main", Some(&written));
            txn.set_ref("other", Some(&written));
            let err = txn.commit().await.unwrap_err();
            assert_eq!(anchor_reason(err), expected);
            assert_eq!(
                objects(&repo),
                objects_before,
                "the store holds no new object and the same .commitmeta files"
            );
            assert_eq!(refs(&repo), refs_before, "the store holds no new ref");
        }
        assert_eq!(
            repo.read_commit_detached_metadata(&anchor).await.unwrap(),
            Some(stored)
        );
    });
}

#[test]
fn signing_keeps_a_stored_defective_anchor_value() {
    let tmp = TmpDir::new("gc-anchors-sign");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["head"]).await;
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        // The dict goes in before the config names the key.
        let stored = entries(vec![(ANCHORS, string("main"))]);
        repo.write_commit_detached_metadata(&head, Some(&stored))
            .await
            .unwrap();
        let repo = configure_keys(&repo, ANCHORS).await;
        let signer = DummySigner::new(b"sig".to_vec());

        let txn = repo.transaction().await.unwrap();
        txn.sign_commit(&head, &signer).await.unwrap();
        txn.commit().await.unwrap();
        repo.sign_commit(&head, &signer).await.unwrap();

        let detached = repo
            .read_commit_detached_metadata(&head)
            .await
            .unwrap()
            .unwrap();
        let anchor_value = detached.dict_get(ANCHORS).unwrap();
        assert_eq!(
            anchor_value.as_variant().unwrap().1.as_str(),
            Some("main"),
            "the defective value stays"
        );
        let signatures = detached.dict_get("ostree.sign.dummy").unwrap();
        assert_eq!(
            signatures.as_variant().unwrap().1.as_array().unwrap().len(),
            2,
            "both signatures are stored"
        );
    });
}

#[test]
fn a_key_not_in_the_list_takes_a_value_of_each_type() {
    let tmp = TmpDir::new("gc-anchors-other-key");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["head"]).await;
        let repo = configure_keys(&repo, ANCHORS).await;
        let short: &[u8] = &[0x11; 20];
        let any = entries(vec![
            (OTHER, string("main")),
            (OTHER, (Type::parse("u").unwrap(), Value::U32(7))),
            (OTHER, checksums(&[short])),
            (OTHER, pairs(&[("main", short)])),
        ]);

        let txn = repo.transaction().await.unwrap();
        let root = stage_tree(&txn, tmp.path(), "head").await;
        let written = txn
            .write_commit(options("head", Some(any.clone())), &root)
            .await
            .unwrap();
        txn.set_commit_detached_metadata(&written, any.clone());
        txn.commit().await.unwrap();
        assert_eq!(
            repo.read_commit_detached_metadata(&written).await.unwrap(),
            Some(any.clone())
        );

        repo.write_commit_detached_metadata(&written, Some(&any))
            .await
            .unwrap();
    });
}

#[test]
fn a_config_value_that_does_not_parse_fails_a_write_with_entries() {
    let tmp = TmpDir::new("gc-anchors-config-malformed");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["head"]).await;
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        // A trailing backslash is a malformed escape sequence.
        let repo = configure_keys(&repo, "test.anchors\\").await;
        let one_entry = entries(vec![(OTHER, string("x"))]);

        // `write_commit` with an entry fails.
        let txn = repo.transaction().await.unwrap();
        let root = stage_tree(&txn, tmp.path(), "head").await;
        let err = txn
            .write_commit(options("head", Some(one_entry.clone())), &root)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Core(_)), "got {err:?}");
        // `write_commit` with no dict or an empty dict does not read the key.
        txn.write_commit(options("head", None), &root)
            .await
            .unwrap();
        txn.write_commit(options("head", Some(empty_dict())), &root)
            .await
            .unwrap();
        txn.abort().await.unwrap();

        // `write_commit_detached_metadata` with an entry fails.
        let err = repo
            .write_commit_detached_metadata(&head, Some(&one_entry))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Core(_)), "got {err:?}");
        repo.write_commit_detached_metadata(&head, None)
            .await
            .unwrap();
        repo.write_commit_detached_metadata(&head, Some(&empty_dict()))
            .await
            .unwrap();

        // `commit` with a queued dict that holds an entry fails.
        let refs_before = refs(&repo);
        let txn = repo.transaction().await.unwrap();
        txn.set_commit_detached_metadata(&head, one_entry);
        txn.set_ref("other", Some(&head));
        let err = txn.commit().await.unwrap_err();
        assert!(matches!(err, Error::Core(_)), "got {err:?}");
        assert_eq!(refs(&repo), refs_before, "the refused commit writes no ref");
        // `commit` with an empty queued dict does not read the key.
        let txn = repo.transaction().await.unwrap();
        txn.set_commit_detached_metadata(&head, empty_dict());
        txn.commit().await.unwrap();
    });
}

#[test]
fn a_local_pull_stores_defective_anchor_values() {
    let tmp = TmpDir::new("gc-anchors-pull-local");
    block_on(async {
        let src = repo_with_trees(tmp.path(), "src", &["head"]).await;
        let metadata = entries(vec![(ANCHORS, string("main"))]);
        let head = commit(&src, tmp.path(), "head", Some(metadata), Some("main")).await;
        let short: &[u8] = &[0x11; 20];
        let detached = entries(vec![(ANCHORS, checksums(&[short]))]);
        src.write_commit_detached_metadata(&head, Some(&detached))
            .await
            .unwrap();

        let dst = Repo::create(
            &tmp.path().join("dst"),
            CreateOptions::new(RepoMode::Archive),
        )
        .await
        .unwrap();
        let dst = configure_keys(&dst, ANCHORS).await;
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
            Some(detached)
        );
    });
}

#[test]
fn a_summary_anchor_commit_takes_no_check() {
    let tmp = TmpDir::new("gc-anchors-summary");
    block_on(async {
        // The list names a binding key of the anchor commit, and then holds a
        // malformed escape sequence.
        for (i, keys) in ["ostree.ref-binding", "ostree.ref-binding\\"]
            .into_iter()
            .enumerate()
        {
            let repo = repo_with_trees(tmp.path(), &format!("repo{i}"), &[]).await;
            let repo = reconfigure(
                &repo,
                &format!(
                    "collection-id=org.example.Anchors\n\n\
                     [ex-ostrya]\ngc-root-metadata-keys={keys}\n"
                ),
            )
            .await;
            repo.regenerate_summary(&SummaryOptions::default())
                .await
                .unwrap();
            let anchor = repo
                .resolve_rev("ostree-metadata", false)
                .await
                .unwrap()
                .expect("the anchor ref is written");
            let (stored, _) = repo.load_commit(&anchor).await.unwrap();
            assert!(
                stored.metadata.dict_get("ostree.ref-binding").is_some(),
                "the anchor commit holds the ref binding"
            );
            assert!(
                repo.path().join("summary").exists(),
                "the summary is written"
            );
        }
    });
}

/// The metadata key that holds the composefs digest of a commit.
const COMPOSEFS_DIGEST: &str = "ostree.composefs.digest.v0";

#[test]
fn composefs_metadata_refuses_a_copied_defective_anchor_value() {
    let tmp = TmpDir::new("gc-anchors-composefs-copy");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["head"]).await;
        // The dict goes in before the config names the key.
        let metadata = entries(vec![(ANCHORS, string("main"))]);
        let head = commit(&repo, tmp.path(), "head", Some(metadata), Some("main")).await;
        let repo = configure_keys(&repo, ANCHORS).await;
        let objects_before = objects(&repo);
        let refs_before = refs(&repo);

        let txn = repo.transaction().await.unwrap();
        let err = repo
            .commit_add_composefs_metadata(&txn, &head)
            .await
            .unwrap_err();
        assert_eq!(anchor_reason(err), STRING_REASON);
        txn.abort().await.unwrap();
        assert_eq!(
            objects(&repo),
            objects_before,
            "the store holds no new object"
        );
        assert_eq!(refs(&repo), refs_before, "the store holds no new ref");
    });
}

#[test]
fn composefs_metadata_refuses_the_digest_key_as_an_anchor_key() {
    let tmp = TmpDir::new("gc-anchors-composefs-digest-key");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["head"]).await;
        let head = commit(&repo, tmp.path(), "head", None, Some("main")).await;
        let repo = configure_keys(&repo, COMPOSEFS_DIGEST).await;
        let objects_before = objects(&repo);

        let txn = repo.transaction().await.unwrap();
        let err = repo
            .commit_add_composefs_metadata(&txn, &head)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::InvalidGcAnchor { metadata_key, .. } if metadata_key == COMPOSEFS_DIGEST),
            "got {err:?}"
        );
        txn.abort().await.unwrap();
        assert_eq!(
            objects(&repo),
            objects_before,
            "the store holds no new object"
        );
    });
}

#[test]
fn composefs_metadata_keeps_a_valid_anchor_value() {
    let tmp = TmpDir::new("gc-anchors-composefs-valid");
    block_on(async {
        let repo = repo_with_trees(tmp.path(), "repo", &["anchor", "head"]).await;
        let anchor = commit(&repo, tmp.path(), "anchor", None, None).await;
        let repo = configure_keys(&repo, ANCHORS).await;
        let metadata = entries(vec![(ANCHORS, checksums(&[anchor.as_bytes()]))]);
        let head = commit(&repo, tmp.path(), "head", Some(metadata.clone()), None).await;

        let txn = repo.transaction().await.unwrap();
        let written = repo
            .commit_add_composefs_metadata(&txn, &head)
            .await
            .unwrap();
        txn.commit().await.unwrap();
        let (stored, _) = repo.load_commit(&written).await.unwrap();
        assert_eq!(
            stored.metadata.dict_get(ANCHORS),
            metadata.dict_get(ANCHORS),
            "the commit keeps the anchor value"
        );
        assert!(
            stored.metadata.dict_get(COMPOSEFS_DIGEST).is_some(),
            "the commit holds the composefs digest"
        );
    });
}
