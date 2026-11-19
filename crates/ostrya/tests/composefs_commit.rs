#![forbid(unsafe_code)]

//! Tests of the composefs image commit and of its lookup.
//!
//! The tests check these facts:
//!
//! - The image commit has the fixed shape: the subject, the timestamp 0, no
//!   parent, no metadata key, no related entry, and no detached metadata. Its
//!   root directory is `0:0 040755` with no xattrs and holds `root.cfs`
//!   alone, a regular file `0:0 0100400`. The file is the image of an export
//!   with `ComposefsOptions::RECORDED`, and the call returns its digest.
//! - Two writes of one image give one image commit. One tree gives one image
//!   commit in the `bare-user-only`, `bare-user`, and `archive` modes.
//! - The lookup finds the attachment, else the supplement, and gives `None`
//!   for a commit with neither. The attachment wins over the supplement.
//! - The lookup refuses each defect of the image commit of the attachment
//!   and of the supplement, and a bad attachment stops the lookup when a
//!   valid supplement exists. Two entries of the name in one field, and a
//!   defective entry of field 2 or of `ostrya.related`, fail the lookup.
//!   With a valid attachment, the lookup reads no `.commitmeta`.
//! - The lookup reads the key only if the commit names an image commit.
//! - A complete image commit with a missing dirtree or image object fails
//!   the lookup with `ObjectNotFound`.
//! - The lookup refuses an `archive` repository before any read. The write
//!   of the image commit works in `archive` mode and writes no
//!   `ostree.sizes`.
//! - With no key, the lookup gives the file with no check.
//! - In a sealing repository, the returned descriptor is sealed and its
//!   kernel digest is the key, and a wrong key gives `DigestMismatch`. These
//!   tests skip if the file system has no fs-verity.

mod common;

use std::io::Read;
use std::os::fd::AsFd;

use ostrya::{
    COMPOSEFS_RELATION, Checksum, Commit, ComposefsImageDefect, ComposefsImageSource,
    ComposefsOptions, DirMeta, DirTree, Error, FileMeta, ObjectType, RelationField, Repo, RepoMode,
    RepoTree, Transaction, Value, Xattrs, loose_path,
};
use ostrya_rt::block_on;

use common::composefs::{
    DIGEST_KEY, build_owned_source, commit_owned, dict, key_dict, new_repo, verity_supported,
};
use common::{TmpDir, mark_partial};

/// The subject of each image commit.
const IMAGE_SUBJECT: &str = "composefs image";

/// Makes the owned source tree under `scratch/tree`, a repository of `mode`
/// with `config` at `scratch/repo`, and a commit of the tree. Returns the
/// repository and the commit of the tree.
async fn setup(scratch: &TmpDir, mode: RepoMode, config: &str) -> (Repo, Checksum) {
    let base = scratch.path().join("tree");
    build_owned_source(&base);
    let repo = new_repo(&scratch.path().join("repo"), mode, config).await;
    let tree = commit_owned(&repo, &base).await;
    (repo, tree)
}

/// Returns the root of the tree of `commit`.
async fn root_of(repo: &Repo, commit: &Checksum) -> RepoTree {
    repo.read_commit(&commit.to_string()).await.unwrap().0
}

/// Writes the image commit of the tree of `tree` in its own transaction, and
/// returns the image commit and the digest of the image.
async fn write_image_commit(repo: &Repo, tree: &Checksum) -> (Checksum, [u8; 32]) {
    let root = root_of(repo, tree).await;
    let txn = repo.transaction().await.unwrap();
    let written = txn.write_composefs_commit(&root).await.unwrap();
    txn.commit().await.unwrap();
    written
}

/// Stages `bytes` as a commit object in a transaction of its own, with no
/// check of field 2, and returns its checksum.
async fn store_commit_bytes(repo: &Repo, bytes: &[u8]) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let written = txn
        .write_metadata(ObjectType::Commit, None, bytes)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    written
}

/// Stores a copy of the commit `tree` with the subject `subject`, the key
/// `key` if given, and field 2 set to `attachments`, with no check of the
/// entries. Returns the checksum of the copy.
async fn store_named(
    repo: &Repo,
    tree: &Checksum,
    subject: &str,
    key: Option<&[u8; 32]>,
    attachments: &[(&str, &[u8])],
) -> Checksum {
    let metadata = key.map_or_else(|| Value::Array(Vec::new()), key_dict);
    store_with_metadata(repo, tree, subject, metadata, attachments).await
}

/// Stores a copy of the commit `tree` with the subject `subject`, the
/// metadata dict `metadata`, and field 2 set to `attachments`, with no check
/// of the entries or of the dict. Returns the checksum of the copy.
async fn store_with_metadata(
    repo: &Repo,
    tree: &Checksum,
    subject: &str,
    metadata: Value,
    attachments: &[(&str, &[u8])],
) -> Checksum {
    let (mut commit, _) = repo.load_commit(tree).await.unwrap();
    commit.subject = subject.to_owned();
    commit.metadata = metadata;
    commit.related = attachments
        .iter()
        .map(|(name, bytes)| ((*name).to_owned(), bytes.to_vec()))
        .collect();
    store_commit_bytes(repo, &commit.serialize().unwrap()).await
}

/// Stages an image commit with the root directory `files` and `dirs` in
/// `txn`, and returns its checksum. The other fields are those of an image
/// commit.
async fn stage_image_commit(
    txn: &Transaction,
    files: Vec<(String, Checksum)>,
    dirs: Vec<(String, Checksum, Checksum)>,
) -> Checksum {
    let root_dirmeta = txn.write_dirmeta(&root_dirmeta()).await.unwrap();
    let tree = DirTree { files, dirs };
    let root_dirtree = txn
        .write_metadata(ObjectType::DirTree, None, &tree.serialize().unwrap())
        .await
        .unwrap();
    let commit = Commit {
        metadata: Value::Array(Vec::new()),
        parent: None,
        related: Vec::new(),
        subject: IMAGE_SUBJECT.to_owned(),
        body: String::new(),
        timestamp: 0,
        root_dirtree,
        root_dirmeta,
    };
    txn.write_metadata(ObjectType::Commit, None, &commit.serialize().unwrap())
        .await
        .unwrap()
}

/// The root dirmeta of an image commit.
fn root_dirmeta() -> DirMeta {
    DirMeta {
        uid: 0,
        gid: 0,
        mode: 0o040755,
        xattrs: Xattrs::empty(),
    }
}

/// Returns the checksum of the file object of `root.cfs` in the image
/// commit `image`.
async fn image_object(repo: &Repo, image: &Checksum) -> Checksum {
    let (commit, _) = repo.load_commit(image).await.unwrap();
    let tree = repo.load_dirtree(&commit.root_dirtree).await.unwrap();
    assert_eq!(tree.files.len(), 1);
    tree.files[0].1
}

/// Returns the bytes of the loose object of the file `object` in the
/// repository `repo` of a mode other than `archive`.
fn raw_object(repo: &Repo, object: &Checksum) -> Vec<u8> {
    let path = loose_path(object, ObjectType::File, repo.mode());
    std::fs::read(repo.path().join("objects").join(path)).unwrap()
}

/// Returns the bytes of the RECORDED export of the commit `tree`.
async fn recorded_export(repo: &Repo, tree: &Checksum) -> ostrya::Image {
    repo.export_composefs(tree, &ComposefsOptions::RECORDED)
        .await
        .unwrap()
}

/// Reads the whole file `file` from its current offset.
fn read_all(mut file: &std::fs::File) -> Vec<u8> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

/// Returns the parts of an [`Error::InvalidComposefsImage`].
fn invalid_image(
    err: Error,
) -> (
    Checksum,
    ComposefsImageSource,
    Checksum,
    ComposefsImageDefect,
) {
    match err {
        Error::InvalidComposefsImage {
            commit,
            relation,
            image,
            defect,
        } => (commit, relation, image, *defect),
        other => panic!("expected InvalidComposefsImage, got {other:?}"),
    }
}

/// Returns the detached metadata dict that holds `entries` as the
/// supplements, with no check.
fn supplement_dict(entries: &[(&str, &Checksum)]) -> Value {
    let raw: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(name, checksum)| (*name, checksum.as_bytes().as_slice()))
        .collect();
    raw_supplement_dict(&raw)
}

/// Returns the detached metadata dict that holds `entries`, names and raw
/// checksum bytes, as the supplements, with no check.
fn raw_supplement_dict(entries: &[(&str, &[u8])]) -> Value {
    dict(
        "ostrya.related",
        "a(say)",
        Value::Array(
            entries
                .iter()
                .map(|(name, bytes)| {
                    Value::Tuple(vec![
                        Value::Str((*name).to_owned()),
                        Value::Bytes(bytes.to_vec()),
                    ])
                })
                .collect(),
        ),
    )
}

/// Writes `meta` as the `.commitmeta` of `commit` with no check, as a write
/// out of band does. The write calls of the library refuse a defective
/// `ostrya.related` value.
fn write_raw_detached(repo: &Repo, commit: &Checksum, meta: &Value) {
    let bytes = ostrya_core::to_bytes(&ostrya_core::Type::parse("a{sv}").unwrap(), meta).unwrap();
    let path =
        repo.path()
            .join("objects")
            .join(loose_path(commit, ObjectType::CommitMeta, repo.mode()));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}

/// Writes a commit of a tree with the one file `a`, `0:0 0100644`, in
/// `repo`, with explicit objects, so that each repository mode stores the
/// same tree. Returns the commit.
async fn plain_tree_commit(repo: &Repo) -> Checksum {
    let txn = repo.transaction().await.unwrap();
    let file = txn
        .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o644), b"payload\n")
        .await
        .unwrap();
    let root_dirmeta = txn.write_dirmeta(&root_dirmeta()).await.unwrap();
    let tree = DirTree {
        files: vec![("a".to_owned(), file)],
        dirs: Vec::new(),
    };
    let root_dirtree = txn
        .write_metadata(ObjectType::DirTree, None, &tree.serialize().unwrap())
        .await
        .unwrap();
    let commit = Commit {
        metadata: Value::Array(Vec::new()),
        parent: None,
        related: Vec::new(),
        subject: "plain tree".to_owned(),
        body: String::new(),
        timestamp: 0,
        root_dirtree,
        root_dirmeta,
    };
    let checksum = txn
        .write_metadata(ObjectType::Commit, None, &commit.serialize().unwrap())
        .await
        .unwrap();
    txn.commit().await.unwrap();
    checksum
}

/// The image commit has the fixed shape, its image file holds the RECORDED
/// export of the tree, and the call returns the digest of that image.
#[test]
fn the_image_commit_has_the_fixed_shape() {
    let scratch = TmpDir::new("cfs-commit-shape");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;

        let (commit, _) = repo.load_commit(&image).await.unwrap();
        assert_eq!(commit.subject, IMAGE_SUBJECT);
        assert_eq!(commit.body, "");
        assert_eq!(commit.timestamp, 0);
        assert_eq!(commit.parent, None);
        assert_eq!(commit.metadata, Value::Array(Vec::new()));
        assert!(commit.related.is_empty());
        assert_eq!(
            repo.read_commit_detached_metadata(&image).await.unwrap(),
            None
        );

        let dirmeta = repo.load_dirmeta(&commit.root_dirmeta).await.unwrap();
        assert_eq!(dirmeta, root_dirmeta());
        let dirtree = repo.load_dirtree(&commit.root_dirtree).await.unwrap();
        assert!(dirtree.dirs.is_empty());
        assert_eq!(dirtree.files.len(), 1);
        assert_eq!(dirtree.files[0].0, "root.cfs");

        let object = dirtree.files[0].1;
        let file = repo.load_file(&object).await.unwrap();
        assert_eq!((file.uid, file.gid, file.mode), (0, 0, 0o100400));
        assert!(file.xattrs.is_empty());

        let export = recorded_export(&repo, &tree).await;
        assert_eq!(raw_object(&repo, &object), export.bytes);
        assert_eq!(digest, export.fs_verity);
    });
}

/// Two transactions that write the image commit of one tree give the same
/// image commit and the same digest.
#[test]
fn two_writes_of_one_image_give_one_image_commit() {
    let scratch = TmpDir::new("cfs-commit-twice");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let first = write_image_commit(&repo, &tree).await;
        let second = write_image_commit(&repo, &tree).await;
        assert_eq!(first, second);
    });
}

/// A commit that a transaction writes with the key and the attachment of an
/// image commit of the same transaction gives that image. The file is at
/// offset 0 and holds the image.
#[test]
fn the_lookup_gives_the_image_of_an_attachment() {
    let scratch = TmpDir::new("cfs-commit-attachment");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let root = root_of(&repo, &tree).await;
        let txn = repo.transaction().await.unwrap();
        let (image, digest) = txn.write_composefs_commit(&root).await.unwrap();
        let commit = txn
            .write_commit(
                ostrya::CommitOptions {
                    subject: Some("with image".to_owned()),
                    timestamp: Some(0),
                    metadata: Some(key_dict(&digest)),
                    attachments: vec![(COMPOSEFS_RELATION.to_owned(), image)],
                    ..ostrya::CommitOptions::default()
                },
                &root,
            )
            .await
            .unwrap();
        txn.commit().await.unwrap();

        let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
        assert_eq!(found.source, ComposefsImageSource::Attachment);
        assert_eq!(found.commit, image);
        let export = recorded_export(&repo, &tree).await;
        assert_eq!(found.size, export.bytes.len() as u64);
        assert_eq!(read_all(&found.file), export.bytes);
    });
}

/// A commit with the supplement of an image commit gives that image.
#[test]
fn the_lookup_gives_the_image_of_a_supplement() {
    let scratch = TmpDir::new("cfs-commit-supplement");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let commit = store_named(&repo, &tree, "supplement", Some(&digest), &[]).await;
        repo.add_supplement(&commit, COMPOSEFS_RELATION, &image)
            .await
            .unwrap();

        let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
        assert_eq!(found.source, ComposefsImageSource::Supplement);
        assert_eq!(found.commit, image);
        let export = recorded_export(&repo, &tree).await;
        assert_eq!(found.size, export.bytes.len() as u64);
        assert_eq!(read_all(&found.file), export.bytes);
    });
}

/// With an attachment and a supplement, the lookup gives the image commit of
/// the attachment.
#[test]
fn the_attachment_wins_over_the_supplement() {
    let scratch = TmpDir::new("cfs-commit-both");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        // The supplement names an image commit of another tree.
        let txn = repo.transaction().await.unwrap();
        let other = txn
            .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o400), b"other")
            .await
            .unwrap();
        let other = stage_image_commit(&txn, vec![("root.cfs".to_owned(), other)], vec![]).await;
        txn.commit().await.unwrap();
        let commit = store_named(
            &repo,
            &tree,
            "both",
            Some(&digest),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        repo.add_supplement(&commit, COMPOSEFS_RELATION, &other)
            .await
            .unwrap();

        let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
        assert_eq!(found.source, ComposefsImageSource::Attachment);
        assert_eq!(found.commit, image);
    });
}

/// A commit with no attachment and no supplement of the name gives `None`,
/// also if it has the key and other related entries.
#[test]
fn a_commit_with_no_image_commit_gives_none() {
    let scratch = TmpDir::new("cfs-commit-none");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        assert!(repo.open_composefs_image(&tree).await.unwrap().is_none());
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let commit = store_named(
            &repo,
            &tree,
            "other names",
            Some(&digest),
            &[("layer/composefs", image.as_bytes())],
        )
        .await;
        repo.add_supplement(&commit, "layer/other", &image)
            .await
            .unwrap();
        assert!(repo.open_composefs_image(&commit).await.unwrap().is_none());
    });
}

/// A defect of the image commit that the lookup checks.
#[derive(Debug, Clone, Copy)]
enum Fault {
    /// The repository does not hold the image commit.
    Absent,
    /// The repository marks the image commit partial.
    Partial,
    /// The root directory holds another file and no `root.cfs`.
    NoImageFile,
    /// `root.cfs` is a symlink object.
    SymlinkImage,
    /// `root.cfs` is a directory.
    DirImage,
    /// The root directory holds `root.cfs` and another file.
    ExtraEntry,
    /// The key of the commit is not the digest of the image.
    WrongKey,
}

/// The lookup refuses each defect of the image commit, for the attachment
/// and for the supplement, with the commit, the source, the image commit,
/// and the defect.
#[test]
fn each_defect_of_the_image_commit_is_refused() {
    let scratch = TmpDir::new("cfs-commit-defects");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (valid, digest) = write_image_commit(&repo, &tree).await;
        let image_file = image_object(&repo, &valid).await;

        let txn = repo.transaction().await.unwrap();
        let other = txn
            .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o400), b"other")
            .await
            .unwrap();
        let link = txn
            .write_symlink("target", &FileMeta::regular(0, 0, 0o777), None)
            .await
            .unwrap();
        let empty_dir = txn
            .write_metadata(
                ObjectType::DirTree,
                None,
                &DirTree::default().serialize().unwrap(),
            )
            .await
            .unwrap();
        let dir_meta = txn.write_dirmeta(&root_dirmeta()).await.unwrap();
        let no_image =
            stage_image_commit(&txn, vec![("other".to_owned(), other)], Vec::new()).await;
        let symlink =
            stage_image_commit(&txn, vec![("root.cfs".to_owned(), link)], Vec::new()).await;
        let dir = stage_image_commit(
            &txn,
            Vec::new(),
            vec![("root.cfs".to_owned(), empty_dir, dir_meta)],
        )
        .await;
        let extra = stage_image_commit(
            &txn,
            vec![
                ("extra".to_owned(), other),
                ("root.cfs".to_owned(), image_file),
            ],
            Vec::new(),
        )
        .await;
        txn.commit().await.unwrap();

        let wrong = [0x11u8; 32];
        let cases = [
            (
                Fault::Absent,
                Checksum::from_bytes([0x5a; 32]),
                digest,
                ComposefsImageDefect::Absent,
            ),
            (Fault::Partial, valid, digest, ComposefsImageDefect::Partial),
            (
                Fault::NoImageFile,
                no_image,
                digest,
                ComposefsImageDefect::NoImageFile,
            ),
            (
                Fault::SymlinkImage,
                symlink,
                digest,
                ComposefsImageDefect::NotRegular,
            ),
            (
                Fault::DirImage,
                dir,
                digest,
                ComposefsImageDefect::NotRegular,
            ),
            (
                Fault::ExtraEntry,
                extra,
                digest,
                ComposefsImageDefect::ExtraEntry("extra".to_owned()),
            ),
            (
                Fault::WrongKey,
                valid,
                wrong,
                ComposefsImageDefect::DigestMismatch {
                    expected: wrong,
                    actual: digest,
                },
            ),
        ];
        for source in [
            ComposefsImageSource::Attachment,
            ComposefsImageSource::Supplement,
        ] {
            for (fault, image, key, expected) in &cases {
                let subject = format!("{fault:?} {source}");
                let commit = match source {
                    ComposefsImageSource::Attachment => {
                        store_named(
                            &repo,
                            &tree,
                            &subject,
                            Some(key),
                            &[(COMPOSEFS_RELATION, image.as_bytes())],
                        )
                        .await
                    }
                    ComposefsImageSource::Supplement => {
                        let commit = store_named(&repo, &tree, &subject, Some(key), &[]).await;
                        repo.add_supplement(&commit, COMPOSEFS_RELATION, image)
                            .await
                            .unwrap();
                        commit
                    }
                };
                if let Fault::Partial = fault {
                    mark_partial(&repo, image);
                }
                let err = repo.open_composefs_image(&commit).await.unwrap_err();
                let text = err.to_string();
                let (at, relation, named, defect) = invalid_image(err);
                assert_eq!(
                    (at, relation, named, &defect),
                    (commit, source, *image, expected),
                    "{fault:?} {source}"
                );
                assert_eq!(
                    text,
                    format!(
                        "composefs image of commit {commit}: {source} composefs names commit \
                         {image}, {expected}"
                    )
                );
                if let Fault::Partial = fault {
                    std::fs::remove_file(repo.path().join(format!("state/{image}.commitpartial")))
                        .unwrap();
                }
            }
        }
    });
}

/// The text of each defect.
#[test]
fn each_defect_has_its_text() {
    let cases = [
        (
            ComposefsImageDefect::Absent,
            "which the repository does not hold",
        ),
        (ComposefsImageDefect::Partial, "which is partial"),
        (
            ComposefsImageDefect::NoImageFile,
            "whose tree holds no /root.cfs",
        ),
        (
            ComposefsImageDefect::NotRegular,
            "whose /root.cfs is not a regular file",
        ),
        (
            ComposefsImageDefect::ExtraEntry("etc".to_owned()),
            "whose tree holds the entry etc next to /root.cfs",
        ),
    ];
    for (defect, text) in cases {
        assert_eq!(defect.to_string(), text);
    }
    let mismatch = ComposefsImageDefect::DigestMismatch {
        expected: [0x11; 32],
        actual: [0x22; 32],
    };
    assert_eq!(
        mismatch.to_string(),
        format!(
            "whose /root.cfs has the fs-verity digest {}, and the commit records {}",
            "22".repeat(32),
            "11".repeat(32)
        )
    );
}

/// A bad attachment stops the lookup, also when a valid supplement exists.
#[test]
fn a_bad_attachment_stops_the_lookup_next_to_a_valid_supplement() {
    let scratch = TmpDir::new("cfs-commit-bad-attachment");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (valid, digest) = write_image_commit(&repo, &tree).await;
        let absent = Checksum::from_bytes([0x5a; 32]);
        let commit = store_named(
            &repo,
            &tree,
            "bad attachment",
            Some(&digest),
            &[(COMPOSEFS_RELATION, absent.as_bytes())],
        )
        .await;
        repo.add_supplement(&commit, COMPOSEFS_RELATION, &valid)
            .await
            .unwrap();
        let err = repo.open_composefs_image(&commit).await.unwrap_err();
        assert_eq!(
            invalid_image(err),
            (
                commit,
                ComposefsImageSource::Attachment,
                absent,
                ComposefsImageDefect::Absent
            )
        );
    });
}

/// Two entries of the name in field 2 or in `ostrya.related`, and a
/// defective entry of another name in field 2, fail the lookup with
/// `InvalidRelations`.
#[test]
fn duplicate_and_defective_entries_are_refused() {
    let scratch = TmpDir::new("cfs-commit-duplicates");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;

        let twice = store_named(
            &repo,
            &tree,
            "two attachments",
            Some(&digest),
            &[
                (COMPOSEFS_RELATION, image.as_bytes()),
                (COMPOSEFS_RELATION, image.as_bytes()),
            ],
        )
        .await;
        match repo.open_composefs_image(&twice).await.unwrap_err() {
            Error::InvalidRelations {
                commit,
                field,
                reason,
            } => {
                assert_eq!(commit, Some(twice));
                assert_eq!(field, RelationField::Attachments);
                assert_eq!(reason, "two or more entries have the name composefs");
            }
            other => panic!("expected InvalidRelations, got {other:?}"),
        }

        let defective = store_named(
            &repo,
            &tree,
            "defective attachment",
            Some(&digest),
            &[
                (COMPOSEFS_RELATION, image.as_bytes()),
                ("layer/short", &[1, 2, 3]),
            ],
        )
        .await;
        match repo.open_composefs_image(&defective).await.unwrap_err() {
            Error::InvalidRelations { commit, field, .. } => {
                assert_eq!(commit, Some(defective));
                assert_eq!(field, RelationField::Attachments);
            }
            other => panic!("expected InvalidRelations, got {other:?}"),
        }

        let supplements = store_named(&repo, &tree, "two supplements", Some(&digest), &[]).await;
        repo.write_commit_detached_metadata(
            &supplements,
            Some(&supplement_dict(&[
                (COMPOSEFS_RELATION, &image),
                (COMPOSEFS_RELATION, &image),
            ])),
        )
        .await
        .unwrap();
        match repo.open_composefs_image(&supplements).await.unwrap_err() {
            Error::InvalidRelations { commit, field, .. } => {
                assert_eq!(commit, Some(supplements));
                assert_eq!(field, RelationField::Supplements);
            }
            other => panic!("expected InvalidRelations, got {other:?}"),
        }
    });
}

/// The lookup refuses an `archive` repository with `Unsupported`.
#[test]
fn the_lookup_refuses_an_archive_repository() {
    let scratch = TmpDir::new("cfs-commit-archive-lookup");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::Archive, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let commit = store_named(
            &repo,
            &tree,
            "archive",
            Some(&digest),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        match repo.open_composefs_image(&commit).await.unwrap_err() {
            Error::Unsupported(message) => assert!(message.contains("archive"), "{message}"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    });
}

/// In an `archive` repository, the image file is a `.filez` object whose
/// inflated payload is the image. A transaction that generates sizes writes
/// no `ostree.sizes` into the image commit.
#[test]
fn the_image_commit_is_written_in_an_archive_repository() {
    use futures_lite::AsyncReadExt;

    let scratch = TmpDir::new("cfs-commit-archive-write");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::Archive, "").await;
        let root = root_of(&repo, &tree).await;
        let mut txn = repo.transaction().await.unwrap();
        txn.set_generate_sizes(true);
        let (image, digest) = txn.write_composefs_commit(&root).await.unwrap();
        txn.commit().await.unwrap();

        let (commit, _) = repo.load_commit(&image).await.unwrap();
        assert_eq!(commit.metadata, Value::Array(Vec::new()));
        let object = image_object(&repo, &image).await;
        let filez = loose_path(&object, ObjectType::File, RepoMode::Archive);
        assert!(filez.ends_with(".filez"), "{filez}");
        assert!(repo.path().join("objects").join(&filez).is_file());

        let file = repo.load_file(&object).await.unwrap();
        let mut payload = Vec::new();
        file.reader()
            .await
            .unwrap()
            .read_to_end(&mut payload)
            .await
            .unwrap();
        let export = recorded_export(&repo, &tree).await;
        assert_eq!(payload, export.bytes);
        assert_eq!(digest, export.fs_verity);
    });
}

/// A commit with no key gives the file of its image commit with no check of
/// the content, also if the image is the image of another tree.
#[test]
fn a_commit_with_no_key_gives_the_image_with_no_check() {
    let scratch = TmpDir::new("cfs-commit-no-key");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        // The image commit holds an image file whose content is not the image
        // of the tree.
        let txn = repo.transaction().await.unwrap();
        let other = txn
            .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o400), b"not an image")
            .await
            .unwrap();
        let image = stage_image_commit(&txn, vec![("root.cfs".to_owned(), other)], vec![]).await;
        txn.commit().await.unwrap();
        let commit = store_named(
            &repo,
            &tree,
            "no key",
            None,
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;

        let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
        assert_eq!(found.source, ComposefsImageSource::Attachment);
        assert_eq!(found.commit, image);
        assert_eq!(found.size, 12);
        assert_eq!(read_all(&found.file), b"not an image");
    });
}

/// In a `bare-user` repository with `[ex-integrity] fsverity=yes`, the image
/// file is sealed, and the lookup returns the sealed descriptor whose kernel
/// digest is the key.
#[test]
fn the_lookup_returns_the_sealed_image() {
    let scratch = TmpDir::new("cfs-commit-sealed");
    if !verity_supported(scratch.path()) {
        eprintln!("skipping: the file system has no fs-verity");
        return;
    }
    block_on(async {
        let (repo, tree) = setup(
            &scratch,
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=yes\n",
        )
        .await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let commit = store_named(
            &repo,
            &tree,
            "sealed",
            Some(&digest),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;

        let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
        let stat = rustix::fs::statx(
            &found.file,
            "",
            rustix::fs::AtFlags::EMPTY_PATH,
            rustix::fs::StatxFlags::SIZE,
        )
        .unwrap();
        assert!(
            stat.stx_attributes
                .contains(rustix::fs::StatxAttributes::VERITY)
        );
        assert_eq!(
            ostrya_sys::measure_verity(found.file.as_fd()).unwrap(),
            digest
        );
        assert_eq!(found.size, stat.stx_size);
    });
}

/// With a valid attachment, the lookup does not read the `.commitmeta`: a
/// defective supplement entry or two supplements of the name do not fail it.
#[test]
fn a_valid_attachment_does_not_read_the_supplements() {
    let scratch = TmpDir::new("cfs-commit-attachment-only");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let detached = [
            raw_supplement_dict(&[("layer/short", &[1, 2, 3])]),
            supplement_dict(&[(COMPOSEFS_RELATION, &image), (COMPOSEFS_RELATION, &image)]),
        ];
        for (n, dict) in detached.iter().enumerate() {
            let commit = store_named(
                &repo,
                &tree,
                &format!("attachment {n}"),
                Some(&digest),
                &[(COMPOSEFS_RELATION, image.as_bytes())],
            )
            .await;
            write_raw_detached(&repo, &commit, dict);
            let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
            assert_eq!(found.source, ComposefsImageSource::Attachment, "{n}");
            assert_eq!(found.commit, image, "{n}");
        }
    });
}

/// The lookup reads the key only if the commit names an image commit: a key
/// of 31 bytes gives `None` with no entry, and `InvalidFormat` with one.
#[test]
fn a_malformed_key_fails_only_a_commit_that_names_an_image() {
    let scratch = TmpDir::new("cfs-commit-bad-key");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, _) = write_image_commit(&repo, &tree).await;
        let short = || dict(DIGEST_KEY, "ay", Value::Bytes(vec![0x11; 31]));

        let unnamed = store_with_metadata(&repo, &tree, "no entry", short(), &[]).await;
        assert!(repo.open_composefs_image(&unnamed).await.unwrap().is_none());

        let named = store_with_metadata(
            &repo,
            &tree,
            "with entry",
            short(),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        match repo.open_composefs_image(&named).await.unwrap_err() {
            Error::InvalidFormat(_) => {}
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
    });
}

/// In an `archive` repository, the lookup refuses an absent commit with
/// `Unsupported`, so the refusal comes before any read.
#[test]
fn the_archive_refusal_comes_before_any_read() {
    let scratch = TmpDir::new("cfs-commit-archive-absent");
    block_on(async {
        let repo = new_repo(&scratch.path().join("repo"), RepoMode::Archive, "").await;
        let absent = Checksum::from_bytes([0x5a; 32]);
        match repo.open_composefs_image(&absent).await.unwrap_err() {
            Error::Unsupported(message) => assert!(message.contains("archive"), "{message}"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    });
}

/// A defective supplement entry of another name fails the lookup of a commit
/// with no attachment of the name.
#[test]
fn a_defective_supplement_of_another_name_is_refused() {
    let scratch = TmpDir::new("cfs-commit-bad-supplement");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let commit = store_named(&repo, &tree, "bad supplement", Some(&digest), &[]).await;
        write_raw_detached(
            &repo,
            &commit,
            &raw_supplement_dict(&[
                (COMPOSEFS_RELATION, image.as_bytes()),
                ("layer/short", &[1, 2, 3]),
            ]),
        );
        match repo.open_composefs_image(&commit).await.unwrap_err() {
            Error::InvalidRelations {
                commit: at, field, ..
            } => {
                assert_eq!(at, Some(commit));
                assert_eq!(field, RelationField::Supplements);
            }
            other => panic!("expected InvalidRelations, got {other:?}"),
        }
    });
}

/// In a sealing repository, a key that is not the kernel digest of the
/// sealed image gives `DigestMismatch` with the actual digest.
#[test]
fn a_wrong_key_of_a_sealed_image_is_refused() {
    let scratch = TmpDir::new("cfs-commit-sealed-wrong");
    if !verity_supported(scratch.path()) {
        eprintln!("skipping: the file system has no fs-verity");
        return;
    }
    block_on(async {
        let (repo, tree) = setup(
            &scratch,
            RepoMode::BareUser,
            "[ex-integrity]\nfsverity=yes\n",
        )
        .await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let wrong = [0x11u8; 32];
        let commit = store_named(
            &repo,
            &tree,
            "sealed wrong key",
            Some(&wrong),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        let err = repo.open_composefs_image(&commit).await.unwrap_err();
        assert_eq!(
            invalid_image(err),
            (
                commit,
                ComposefsImageSource::Attachment,
                image,
                ComposefsImageDefect::DigestMismatch {
                    expected: wrong,
                    actual: digest,
                }
            )
        );
    });
}

/// A complete image commit whose file object of `root.cfs` or whose root
/// dirtree is missing fails the lookup with `ObjectNotFound`.
#[test]
fn a_missing_object_of_a_complete_image_commit_is_not_found() {
    let scratch = TmpDir::new("cfs-commit-missing-object");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let commit = store_named(
            &repo,
            &tree,
            "missing objects",
            Some(&digest),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        let (image_commit, _) = repo.load_commit(&image).await.unwrap();
        let file = image_object(&repo, &image).await;
        let dirtree = image_commit.root_dirtree;
        let remove = |checksum: &Checksum, ty: ObjectType| {
            let path = loose_path(checksum, ty, repo.mode());
            std::fs::remove_file(repo.path().join("objects").join(path)).unwrap();
        };

        for (checksum, ty) in [(file, ObjectType::File), (dirtree, ObjectType::DirTree)] {
            remove(&checksum, ty);
            match repo.open_composefs_image(&commit).await.unwrap_err() {
                Error::ObjectNotFound {
                    checksum: missing,
                    ty: missing_ty,
                } => assert_eq!((missing, missing_ty), (checksum, ty)),
                other => panic!("expected ObjectNotFound for {ty:?}, got {other:?}"),
            }
        }
    });
}

/// A `bare-user-only` repository writes the image commit in the fixed
/// shape, and the image commit of one tree has the same checksum in the
/// `bare-user-only`, `bare-user`, and `archive` modes.
#[test]
fn the_image_commit_is_the_same_in_each_mode() {
    let scratch = TmpDir::new("cfs-commit-modes");
    block_on(async {
        let mut images = Vec::new();
        for (n, mode) in [
            RepoMode::BareUserOnly,
            RepoMode::BareUser,
            RepoMode::Archive,
        ]
        .into_iter()
        .enumerate()
        {
            let repo = new_repo(&scratch.path().join(format!("repo{n}")), mode, "").await;
            let tree = plain_tree_commit(&repo).await;
            let (image, digest) = write_image_commit(&repo, &tree).await;
            let export = recorded_export(&repo, &tree).await;
            assert_eq!(digest, export.fs_verity, "{mode:?}");
            if mode == RepoMode::BareUserOnly {
                let (commit, _) = repo.load_commit(&image).await.unwrap();
                assert_eq!(commit.subject, IMAGE_SUBJECT);
                assert_eq!(commit.timestamp, 0);
                assert_eq!(commit.metadata, Value::Array(Vec::new()));
                let dirmeta = repo.load_dirmeta(&commit.root_dirmeta).await.unwrap();
                assert_eq!(dirmeta, root_dirmeta());
                let object = image_object(&repo, &image).await;
                let file = repo.load_file(&object).await.unwrap();
                assert_eq!((file.uid, file.gid, file.mode), (0, 0, 0o100400));
                assert!(file.xattrs.is_empty());
                assert_eq!(raw_object(&repo, &object), export.bytes);
                let found = store_named(
                    &repo,
                    &tree,
                    "bare-user-only",
                    Some(&digest),
                    &[(COMPOSEFS_RELATION, image.as_bytes())],
                )
                .await;
                let found = repo.open_composefs_image(&found).await.unwrap().unwrap();
                assert_eq!(read_all(&found.file), export.bytes);
            }
            images.push((image, digest));
        }
        assert_eq!(images[0], images[1]);
        assert_eq!(images[0], images[2]);
    });
}
