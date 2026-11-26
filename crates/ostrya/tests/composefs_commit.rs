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
//! - The lookup reads and compares the key for a supplement alone. A
//!   supplement of a commit with no key gives `NoKey` before any read of the
//!   image commit, and a wrong key gives `DigestMismatch`. An attachment
//!   with a wrong key, a malformed key, or no key gives its image.
//! - A complete image commit with a missing dirtree or image object fails
//!   the lookup with `ObjectNotFound`.
//! - The lookup refuses an `archive` repository before any read. The write
//!   of the image commit works in `archive` mode and writes no
//!   `ostree.sizes`.
//! - With `[ex-integrity] fsverity=yes`, a `/root.cfs` with no seal gives
//!   `NotSealed` for the attachment and for the supplement.
//! - In a sealing repository, the returned descriptor is sealed and its
//!   kernel digest is the key, and a wrong key of a supplement gives
//!   `DigestMismatch`. These tests skip if the file system has no fs-verity.
//! - `Repo::add_composefs_supplement` writes the image commit and the
//!   supplement, writes nothing for a valid supplement, replaces a bad
//!   supplement, completes a partial image commit, refuses a commit with the
//!   attachment, a commit with no key, and a key that is not the digest of
//!   the image, and works in an `archive` repository. In `archive` mode, it
//!   replaces a supplement that names another image commit. With
//!   `fsverity=yes`, it refuses a supplement with no seal and writes
//!   nothing, except in `archive` mode.
//! - `CheckedAttachments::add` checks the new entry alone: an entry of the
//!   first check that the repository marks partial after that check fails
//!   neither the add nor the write of the commit. The add keeps the entries
//!   sorted.
//! - With a hook, the image file is the image that
//!   `Repo::export_composefs_to` writes for the tree with the same hook, and
//!   the call returns its digest. A commit that names the image commit as
//!   the attachment and carries the digest of the image with no hook as the
//!   key, or no key, gives the image. The same image commit as a supplement
//!   gives `DigestMismatch`.

mod common;

use std::io::Read;
use std::os::fd::AsFd;
use std::path::Path;

use ostrya::{
    COMPOSEFS_RELATION, Checksum, Commit, ComposefsEntryFn, ComposefsImageDefect,
    ComposefsImageSource, ComposefsOptions, ComposefsSupplementAdd, DirMeta, DirTree, EntryKind,
    Error, FileMeta, Metadata, ObjectType, RelationField, Repo, RepoMode, RepoTree, Transaction,
    Value, Xattrs, loose_path,
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
    let written = txn.write_composefs_commit(&root, None).await.unwrap();
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
    repo.export_composefs(tree, &ComposefsOptions::RECORDED, None)
        .await
        .unwrap()
}

/// Returns the SELinux label that [`label_entry`] gives the node at `path`,
/// with a NUL at its end.
fn label_of(path: &Path) -> Vec<u8> {
    let mut label = format!("system_u:object_r:image_t:s0:{}", path.display()).into_bytes();
    label.push(0);
    label
}

/// A hook that adds to each node the label of its path.
fn label_entry(path: &Path, _: EntryKind, meta: &mut Metadata) -> Result<(), Error> {
    meta.xattrs
        .push((b"security.selinux".to_vec(), label_of(path)));
    Ok(())
}

/// Writes the RECORDED export of the commit `tree` with the hook `filter` to
/// the file `path`. Returns the bytes of the file and the returned digest.
async fn hooked_export(
    repo: &Repo,
    tree: &Checksum,
    filter: ComposefsEntryFn<'_>,
    path: &Path,
) -> (Vec<u8>, [u8; 32]) {
    let file = std::fs::File::create(path).unwrap();
    let digest = repo
        .export_composefs_to(
            tree,
            &ComposefsOptions::RECORDED,
            Some(filter),
            file.as_fd(),
        )
        .await
        .unwrap();
    drop(file);
    (std::fs::read(path).unwrap(), digest)
}

/// Returns `true` if `haystack` holds `needle`.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
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

/// Sets `[ex-integrity] fsverity=yes` in the `config` of `repo`, and opens
/// the repository again. The objects that `repo` wrote before keep the seal
/// state that they had.
async fn require_verity(repo: Repo) -> Repo {
    set_fsverity(repo, "yes").await
}

/// Sets `[ex-integrity] fsverity` to `value` in the `config` of `repo`, with
/// no check of the value, and opens the repository again.
async fn set_fsverity(repo: Repo, value: &str) -> Repo {
    let root = repo.path().to_path_buf();
    drop(repo);
    let config = root.join("config");
    let mut text = std::fs::read_to_string(&config).unwrap();
    assert!(!text.contains("fsverity"), "{text}");
    text.push_str(&format!("[ex-integrity]\nfsverity={value}\n"));
    std::fs::write(&config, text).unwrap();
    Repo::open(&root).await.unwrap()
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
        let (image, digest) = txn.write_composefs_commit(&root, None).await.unwrap();
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

/// With a hook, the image file holds the export of the tree with the same
/// hook, and the call returns the digest of that export. The image holds the
/// label of each path, and differs from the image with no hook.
#[test]
fn the_image_commit_holds_the_image_of_the_hook() {
    let scratch = TmpDir::new("cfs-commit-hook");
    let hook: ComposefsEntryFn<'_> = &label_entry;
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let root = root_of(&repo, &tree).await;
        let txn = repo.transaction().await.unwrap();
        let (image, digest) = txn.write_composefs_commit(&root, Some(hook)).await.unwrap();
        txn.commit().await.unwrap();

        let object = image_object(&repo, &image).await;
        let stored = raw_object(&repo, &object);
        let (export, export_digest) =
            hooked_export(&repo, &tree, hook, &scratch.path().join("hooked.cfs")).await;
        assert_eq!(stored, export);
        assert_eq!(digest, export_digest);
        for path in [
            "/",
            "/hello.txt",
            "/sub",
            "/sub/nested.txt",
            "/link",
            "/usr",
        ] {
            assert!(holds(&stored, &label_of(Path::new(path))), "{path}");
        }

        let plain = recorded_export(&repo, &tree).await;
        assert_ne!(stored, plain.bytes);
        assert_ne!(digest, plain.fs_verity);
    });
}

/// A transaction writes the image commit with a hook, and a commit of the
/// same tree that names the image commit as the attachment and carries the
/// digest of the image with no hook as the key. The lookup gives the image
/// of the hook. A commit with no key gives it too. A commit that names the
/// labeled image commit as a supplement with the same key fails the lookup
/// with `DigestMismatch`.
#[test]
fn the_lookup_gives_a_labeled_attachment_of_a_commit_with_the_rebuilt_key() {
    let scratch = TmpDir::new("cfs-commit-hook-lookup");
    let hook: ComposefsEntryFn<'_> = &label_entry;
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let root = root_of(&repo, &tree).await;
        let txn = repo.transaction().await.unwrap();
        let (image, labeled) = txn.write_composefs_commit(&root, Some(hook)).await.unwrap();
        let rebuilt = txn.composefs_digest(&root).await.unwrap();
        let commit = txn
            .write_commit(
                ostrya::CommitOptions {
                    subject: Some("with labeled image".to_owned()),
                    timestamp: Some(0),
                    metadata: Some(key_dict(&rebuilt)),
                    attachments: vec![(COMPOSEFS_RELATION.to_owned(), image)],
                    ..ostrya::CommitOptions::default()
                },
                &root,
            )
            .await
            .unwrap();
        txn.commit().await.unwrap();
        assert_eq!(rebuilt, recorded_export(&repo, &tree).await.fs_verity);
        assert_ne!(rebuilt, labeled);

        let stored = raw_object(&repo, &image_object(&repo, &image).await);
        let no_key = store_named(
            &repo,
            &tree,
            "labeled image with no key",
            None,
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        for named in [commit, no_key] {
            let found = repo.open_composefs_image(&named).await.unwrap().unwrap();
            assert_eq!(found.source, ComposefsImageSource::Attachment);
            assert_eq!(found.commit, image);
            assert_eq!(found.size, stored.len() as u64);
            assert_eq!(read_all(&found.file), stored);
        }

        let supplement = store_named(&repo, &tree, "labeled supplement", Some(&rebuilt), &[]).await;
        repo.add_supplement(&supplement, COMPOSEFS_RELATION, &image)
            .await
            .unwrap();
        let err = repo.open_composefs_image(&supplement).await.unwrap_err();
        assert_eq!(
            invalid_image(err),
            (
                supplement,
                ComposefsImageSource::Supplement,
                image,
                ComposefsImageDefect::DigestMismatch {
                    expected: rebuilt,
                    actual: labeled,
                }
            )
        );
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
    /// The commit carries no key.
    NoKey,
}

/// The lookup refuses each defect of the image commit, for the attachment
/// and for the supplement, with the commit, the source, the image commit,
/// and the defect. A wrong key and no key fail a supplement alone. With no
/// key, the lookup refuses a supplement that names an absent image commit
/// with `NoKey`, so it reads no part of the image commit.
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
        let absent = Checksum::from_bytes([0x5a; 32]);
        let both = [
            ComposefsImageSource::Attachment,
            ComposefsImageSource::Supplement,
        ];
        let supplement = [ComposefsImageSource::Supplement];
        let cases = [
            (
                Fault::Absent,
                absent,
                Some(digest),
                ComposefsImageDefect::Absent,
                &both[..],
            ),
            (
                Fault::Partial,
                valid,
                Some(digest),
                ComposefsImageDefect::Partial,
                &both[..],
            ),
            (
                Fault::NoImageFile,
                no_image,
                Some(digest),
                ComposefsImageDefect::NoImageFile,
                &both[..],
            ),
            (
                Fault::SymlinkImage,
                symlink,
                Some(digest),
                ComposefsImageDefect::NotRegular,
                &both[..],
            ),
            (
                Fault::DirImage,
                dir,
                Some(digest),
                ComposefsImageDefect::NotRegular,
                &both[..],
            ),
            (
                Fault::ExtraEntry,
                extra,
                Some(digest),
                ComposefsImageDefect::ExtraEntry("extra".to_owned()),
                &both[..],
            ),
            (
                Fault::WrongKey,
                valid,
                Some(wrong),
                ComposefsImageDefect::DigestMismatch {
                    expected: wrong,
                    actual: digest,
                },
                &supplement[..],
            ),
            (
                Fault::NoKey,
                absent,
                None,
                ComposefsImageDefect::NoKey,
                &supplement[..],
            ),
        ];
        for (fault, image, key, expected, sources) in &cases {
            for &source in *sources {
                let subject = format!("{fault:?} {source}");
                let commit = match source {
                    ComposefsImageSource::Attachment => {
                        store_named(
                            &repo,
                            &tree,
                            &subject,
                            key.as_ref(),
                            &[(COMPOSEFS_RELATION, image.as_bytes())],
                        )
                        .await
                    }
                    ComposefsImageSource::Supplement => {
                        let commit = store_named(&repo, &tree, &subject, key.as_ref(), &[]).await;
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
        (
            ComposefsImageDefect::NoKey,
            "and the commit carries no ostree.composefs.digest.v0",
        ),
        (
            ComposefsImageDefect::NotSealed,
            "whose /root.cfs has no fs-verity seal with SHA-256, 4096-byte blocks, no salt, \
             and its full size",
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
        let (image, digest) = txn.write_composefs_commit(&root, None).await.unwrap();
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

/// A commit with no key gives the file of the image commit of its attachment
/// with no check of the content, also if the image is the image of another
/// tree.
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

/// The lookup reads the key only if the commit names a supplement: a key of
/// 31 bytes gives `None` with no entry, the image with an attachment, and
/// `InvalidFormat` with a supplement.
#[test]
fn a_malformed_key_fails_only_a_commit_that_names_a_supplement() {
    let scratch = TmpDir::new("cfs-commit-bad-key");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, _) = write_image_commit(&repo, &tree).await;
        let short = || dict(DIGEST_KEY, "ay", Value::Bytes(vec![0x11; 31]));

        let unnamed = store_with_metadata(&repo, &tree, "no entry", short(), &[]).await;
        assert!(repo.open_composefs_image(&unnamed).await.unwrap().is_none());

        let attached = store_with_metadata(
            &repo,
            &tree,
            "with attachment",
            short(),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        let found = repo.open_composefs_image(&attached).await.unwrap().unwrap();
        assert_eq!(found.source, ComposefsImageSource::Attachment);
        assert_eq!(found.commit, image);

        let supplied = store_with_metadata(&repo, &tree, "with supplement", short(), &[]).await;
        repo.add_supplement(&supplied, COMPOSEFS_RELATION, &image)
            .await
            .unwrap();
        match repo.open_composefs_image(&supplied).await.unwrap_err() {
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

/// In a sealing repository, a supplement of a commit whose key is the kernel
/// digest of the sealed image gives the image. A key that is not the kernel
/// digest gives `DigestMismatch` with the actual digest.
#[test]
fn a_wrong_key_of_a_sealed_supplement_is_refused() {
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
        let right = store_named(&repo, &tree, "sealed right key", Some(&digest), &[]).await;
        repo.add_supplement(&right, COMPOSEFS_RELATION, &image)
            .await
            .unwrap();
        let found = repo.open_composefs_image(&right).await.unwrap().unwrap();
        assert_eq!(found.source, ComposefsImageSource::Supplement);
        assert_eq!(found.commit, image);
        assert_eq!(
            ostrya_sys::measure_verity(found.file.as_fd()).unwrap(),
            digest
        );

        let wrong = [0x11u8; 32];
        let commit = store_named(&repo, &tree, "sealed wrong key", Some(&wrong), &[]).await;
        repo.add_supplement(&commit, COMPOSEFS_RELATION, &image)
            .await
            .unwrap();
        let err = repo.open_composefs_image(&commit).await.unwrap_err();
        assert_eq!(
            invalid_image(err),
            (
                commit,
                ComposefsImageSource::Supplement,
                image,
                ComposefsImageDefect::DigestMismatch {
                    expected: wrong,
                    actual: digest,
                }
            )
        );
    });
}

/// A repository writes the image commit under `fsverity=no`, so `/root.cfs`
/// has no seal, and the lookup gives the image of the attachment and of the
/// supplement. After the repository sets `[ex-integrity] fsverity=yes`, the
/// lookup refuses each source with `NotSealed`.
#[test]
fn an_unsealed_image_is_refused_under_fsverity_yes() {
    let scratch = TmpDir::new("cfs-commit-not-sealed");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let attached = store_named(
            &repo,
            &tree,
            "unsealed attachment",
            Some(&digest),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        let supplied = store_named(&repo, &tree, "unsealed supplement", Some(&digest), &[]).await;
        repo.add_supplement(&supplied, COMPOSEFS_RELATION, &image)
            .await
            .unwrap();
        let cases = [
            (attached, ComposefsImageSource::Attachment),
            (supplied, ComposefsImageSource::Supplement),
        ];
        for (commit, source) in cases {
            let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
            assert_eq!((found.source, found.commit), (source, image));
        }

        let repo = require_verity(repo).await;
        for (commit, source) in cases {
            let err = repo.open_composefs_image(&commit).await.unwrap_err();
            let text = err.to_string();
            assert_eq!(
                invalid_image(err),
                (commit, source, image, ComposefsImageDefect::NotSealed),
                "{source}"
            );
            assert_eq!(
                text,
                format!(
                    "composefs image of commit {commit}: {source} composefs names commit \
                     {image}, whose /root.cfs has no fs-verity seal with SHA-256, 4096-byte \
                     blocks, no salt, and its full size"
                )
            );
        }
    });
}

/// With a malformed `[ex-integrity] fsverity` value, the lookup of a commit
/// that names no image commit gives `None`, because the lookup reads the
/// value only for an image commit. The lookup of a commit that names an
/// image commit fails with `InvalidFormat`.
#[test]
fn a_malformed_fsverity_fails_only_a_commit_that_names_an_image() {
    let scratch = TmpDir::new("cfs-commit-bad-fsverity");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let attached = store_named(
            &repo,
            &tree,
            "attachment",
            Some(&digest),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;

        let repo = set_fsverity(repo, "bogus").await;
        assert!(repo.open_composefs_image(&tree).await.unwrap().is_none());
        match repo.open_composefs_image(&attached).await.unwrap_err() {
            Error::InvalidFormat(message) => assert!(message.contains("fsverity"), "{message}"),
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
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
/// `bare-user-only`, `bare-user`, `archive`, and `bare-user-private` modes.
#[test]
fn the_image_commit_is_the_same_in_each_mode() {
    let scratch = TmpDir::new("cfs-commit-modes");
    block_on(async {
        let mut images = Vec::new();
        for (n, mode) in [
            RepoMode::BareUserOnly,
            RepoMode::BareUser,
            RepoMode::Archive,
            RepoMode::BareUserPrivate,
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
        assert_eq!(images[0], images[3]);
    });
}

/// Returns the sorted paths of the files below `objects/` of `repo`.
fn object_files(repo: &Repo) -> Vec<std::path::PathBuf> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(&repo.path().join("objects"), &mut out);
    out.sort();
    out
}

/// Returns the bytes of the `.commitmeta` of `commit`, or `None` if the
/// repository holds none.
fn commitmeta_bytes(repo: &Repo, commit: &Checksum) -> Option<Vec<u8>> {
    let path = loose_path(commit, ObjectType::CommitMeta, repo.mode());
    std::fs::read(repo.path().join("objects").join(path)).ok()
}

/// Returns the supplements of `commit`.
async fn supplements(repo: &Repo, commit: &Checksum) -> Vec<(String, Checksum)> {
    repo.read_commit_relations(commit)
        .await
        .unwrap()
        .supplements
}

/// A commit with the key and no image commit gets the image commit of its
/// tree as the supplement. The lookup then gives it. A second call finds the
/// valid supplement and writes nothing.
#[test]
fn the_add_writes_the_supplement_of_a_commit_with_the_key() {
    let scratch = TmpDir::new("cfs-add-key");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let digest = recorded_export(&repo, &tree).await.fs_verity;
        let commit = store_named(&repo, &tree, "add", Some(&digest), &[]).await;

        let added = repo.add_composefs_supplement(&commit).await.unwrap();
        let ComposefsSupplementAdd::Written { image, replaced } = added else {
            panic!("expected Written, got {added:?}");
        };
        assert_eq!(replaced, None);
        assert_eq!(
            supplements(&repo, &commit).await,
            vec![(COMPOSEFS_RELATION.to_owned(), image)]
        );
        let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
        assert_eq!(found.source, ComposefsImageSource::Supplement);
        assert_eq!(found.commit, image);
        assert_eq!(
            read_all(&found.file),
            recorded_export(&repo, &tree).await.bytes
        );

        let objects = object_files(&repo);
        let meta = commitmeta_bytes(&repo, &commit);
        assert_eq!(
            repo.add_composefs_supplement(&commit).await.unwrap(),
            ComposefsSupplementAdd::Valid { image }
        );
        assert_eq!(object_files(&repo), objects);
        assert_eq!(commitmeta_bytes(&repo, &commit), meta);
    });
}

/// A commit with no key is refused with `InvalidInput`, also if it has a
/// supplement, and the call writes no object and no supplement.
#[test]
fn the_add_refuses_a_commit_with_no_key() {
    let scratch = TmpDir::new("cfs-add-no-key");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let bare = store_named(&repo, &tree, "no key", None, &[]).await;
        let (image, _) = write_image_commit(&repo, &tree).await;
        let supplied = store_named(&repo, &tree, "no key, supplement", None, &[]).await;
        repo.add_supplement(&supplied, COMPOSEFS_RELATION, &image)
            .await
            .unwrap();

        for commit in [bare, supplied] {
            let objects = object_files(&repo);
            let meta = commitmeta_bytes(&repo, &commit);
            match repo.add_composefs_supplement(&commit).await.unwrap_err() {
                Error::InvalidInput(message) => assert_eq!(
                    message,
                    format!(
                        "commit {commit} carries no ostree.composefs.digest.v0; a supplement \
                         is not written (Repo::commit_add_composefs_metadata stages a commit \
                         that carries the key)"
                    )
                ),
                other => panic!("expected InvalidInput, got {other:?}"),
            }
            assert_eq!(object_files(&repo), objects);
            assert_eq!(commitmeta_bytes(&repo, &commit), meta);
        }
        assert!(commitmeta_bytes(&repo, &bare).is_none());
    });
}

/// A key that is not the digest of the built image refuses the commit with
/// both digests, and the call writes no object and no supplement.
#[test]
fn the_add_refuses_a_key_that_is_not_the_digest() {
    let scratch = TmpDir::new("cfs-add-mismatch");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let digest = recorded_export(&repo, &tree).await.fs_verity;
        let wrong = [0x11u8; 32];
        let commit = store_named(&repo, &tree, "wrong key", Some(&wrong), &[]).await;
        let objects = object_files(&repo);

        match repo.add_composefs_supplement(&commit).await.unwrap_err() {
            Error::ComposefsDigestMismatch {
                commit: refused,
                expected,
                actual,
            } => {
                assert_eq!(refused, commit);
                assert_eq!(expected, wrong);
                assert_eq!(actual, digest);
            }
            other => panic!("expected ComposefsDigestMismatch, got {other:?}"),
        }
        assert_eq!(object_files(&repo), objects);
        assert!(commitmeta_bytes(&repo, &commit).is_none());
        assert!(repo.open_composefs_image(&commit).await.unwrap().is_none());
    });
}

/// A commit that names an image commit as the attachment is refused, and
/// the call writes nothing.
#[test]
fn the_add_refuses_a_commit_with_the_attachment() {
    let scratch = TmpDir::new("cfs-add-attachment");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let commit = store_named(
            &repo,
            &tree,
            "attached",
            Some(&digest),
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        let objects = object_files(&repo);
        match repo.add_composefs_supplement(&commit).await.unwrap_err() {
            Error::InvalidInput(message) => assert_eq!(
                message,
                format!(
                    "commit {commit} names its composefs image commit {image} as an \
                     attachment; a supplement is not written"
                )
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert_eq!(object_files(&repo), objects);
        assert!(commitmeta_bytes(&repo, &commit).is_none());
    });
}

/// A commit with the attachment and no key gets the refusal of the
/// attachment. A commit with neither gets the refusal of the key before the
/// add reads the `.commitmeta`. A directory at the path of the `.commitmeta`
/// fails the add of a commit with the key with `InvalidFormat`, and does not
/// change the refusal of a commit with no key. The add writes nothing.
#[test]
fn the_add_refuses_the_attachment_then_the_missing_key_before_the_supplements() {
    let scratch = TmpDir::new("cfs-add-order");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let attached = store_named(
            &repo,
            &tree,
            "attachment, no key",
            None,
            &[(COMPOSEFS_RELATION, image.as_bytes())],
        )
        .await;
        let keyed = store_named(&repo, &tree, "key, damaged", Some(&digest), &[]).await;
        let bare = store_named(&repo, &tree, "no key, damaged", None, &[]).await;
        for commit in [keyed, bare] {
            let path = repo.path().join("objects").join(loose_path(
                &commit,
                ObjectType::CommitMeta,
                repo.mode(),
            ));
            std::fs::create_dir_all(path).unwrap();
        }
        let objects = object_files(&repo);

        match repo.add_composefs_supplement(&attached).await.unwrap_err() {
            Error::InvalidInput(message) => assert_eq!(
                message,
                format!(
                    "commit {attached} names its composefs image commit {image} as an \
                     attachment; a supplement is not written"
                )
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        match repo.add_composefs_supplement(&keyed).await.unwrap_err() {
            Error::InvalidFormat(message) => {
                assert!(
                    message.ends_with(".commitmeta is not a regular file"),
                    "{message}"
                )
            }
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
        match repo.add_composefs_supplement(&bare).await.unwrap_err() {
            Error::InvalidInput(message) => assert_eq!(
                message,
                format!(
                    "commit {bare} carries no ostree.composefs.digest.v0; a supplement \
                     is not written (Repo::commit_add_composefs_metadata stages a commit \
                     that carries the key)"
                )
            ),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
        assert_eq!(object_files(&repo), objects);
    });
}

/// The add writes the supplement of a commit under `fsverity=no`, so its
/// `/root.cfs` has no seal. After the repository sets `[ex-integrity]
/// fsverity=yes`, the add hashes the file, finds the digest of the key, and
/// refuses the commit with `NotSealed`. It writes no object and no
/// supplement. In an `archive` repository, the add applies no seal rule and
/// finds the supplement valid.
#[test]
fn the_add_refuses_an_unsealed_supplement_under_fsverity_yes() {
    let scratch = TmpDir::new("cfs-add-not-sealed");
    block_on(async {
        for mode in [RepoMode::BareUser, RepoMode::Archive] {
            let base = scratch.path().join(format!("{mode:?}"));
            std::fs::create_dir(&base).unwrap();
            build_owned_source(&base.join("tree"));
            let repo = new_repo(&base.join("repo"), mode, "").await;
            let tree = commit_owned(&repo, &base.join("tree")).await;
            let digest = recorded_export(&repo, &tree).await.fs_verity;
            let commit = store_named(&repo, &tree, "unsealed", Some(&digest), &[]).await;
            let added = repo.add_composefs_supplement(&commit).await.unwrap();
            let ComposefsSupplementAdd::Written { image, .. } = added else {
                panic!("expected Written, got {added:?}");
            };

            let repo = require_verity(repo).await;
            let objects = object_files(&repo);
            let meta = commitmeta_bytes(&repo, &commit);
            let result = repo.add_composefs_supplement(&commit).await;
            if mode == RepoMode::Archive {
                assert_eq!(result.unwrap(), ComposefsSupplementAdd::Valid { image });
            } else {
                assert_eq!(
                    invalid_image(result.unwrap_err()),
                    (
                        commit,
                        ComposefsImageSource::Supplement,
                        image,
                        ComposefsImageDefect::NotSealed
                    )
                );
            }
            assert_eq!(object_files(&repo), objects, "{mode:?}");
            assert_eq!(commitmeta_bytes(&repo, &commit), meta, "{mode:?}");
        }
    });
}

/// Under `[ex-integrity] fsverity=yes`, the add writes a sealed image
/// commit, and a second call finds the supplement valid and writes nothing.
#[test]
fn the_add_finds_a_sealed_supplement_valid_under_fsverity_yes() {
    let scratch = TmpDir::new("cfs-add-sealed");
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
        let digest = recorded_export(&repo, &tree).await.fs_verity;
        let commit = store_named(&repo, &tree, "sealed add", Some(&digest), &[]).await;
        let added = repo.add_composefs_supplement(&commit).await.unwrap();
        let ComposefsSupplementAdd::Written { image, replaced } = added else {
            panic!("expected Written, got {added:?}");
        };
        assert_eq!(replaced, None);

        let objects = object_files(&repo);
        let meta = commitmeta_bytes(&repo, &commit);
        assert_eq!(
            repo.add_composefs_supplement(&commit).await.unwrap(),
            ComposefsSupplementAdd::Valid { image }
        );
        assert_eq!(object_files(&repo), objects);
        assert_eq!(commitmeta_bytes(&repo, &commit), meta);
    });
}

/// A supplement names the image commit of another tree, written under
/// `fsverity=no`, so its `/root.cfs` has no seal. After the repository sets
/// `[ex-integrity] fsverity=yes`, the add hashes the file, finds a digest
/// other than the key, and replaces the entry with the sealed image commit
/// of the tree. The lookup then gives the new image.
#[test]
fn the_add_replaces_an_unsealed_supplement_of_another_image_under_fsverity_yes() {
    let scratch = TmpDir::new("cfs-add-unsealed-other");
    if !verity_supported(scratch.path()) {
        eprintln!("skipping: the file system has no fs-verity");
        return;
    }
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let digest = recorded_export(&repo, &tree).await.fs_verity;
        let plain = plain_tree_commit(&repo).await;
        let (wrong, _) = write_image_commit(&repo, &plain).await;
        let commit = store_named(&repo, &tree, "unsealed other", Some(&digest), &[]).await;
        repo.add_supplement(&commit, COMPOSEFS_RELATION, &wrong)
            .await
            .unwrap();

        let repo = require_verity(repo).await;
        let added = repo.add_composefs_supplement(&commit).await.unwrap();
        let ComposefsSupplementAdd::Written { image, replaced } = added else {
            panic!("expected Written, got {added:?}");
        };
        assert_eq!(replaced, Some(wrong));
        assert_ne!(image, wrong);
        assert_eq!(
            supplements(&repo, &commit).await,
            vec![(COMPOSEFS_RELATION.to_owned(), image)]
        );
        let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
        assert_eq!(
            (found.source, found.commit),
            (ComposefsImageSource::Supplement, image)
        );
        assert_eq!(
            ostrya_sys::measure_verity(found.file.as_fd()).unwrap(),
            digest
        );
    });
}

/// The add writes the image commit of a tree under `fsverity=no`, so its
/// `/root.cfs` has no seal. After the repository sets `[ex-integrity]
/// fsverity=yes`, the add of a second commit of the same tree builds the
/// same image commit. The transaction does not write the held object again,
/// so the add refuses the built image commit with `NotSealed` and writes no
/// object and no supplement.
#[test]
fn the_add_refuses_a_built_image_with_no_seal_under_fsverity_yes() {
    let scratch = TmpDir::new("cfs-add-built-not-sealed");
    if !verity_supported(scratch.path()) {
        eprintln!("skipping: the file system has no fs-verity");
        return;
    }
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let digest = recorded_export(&repo, &tree).await.fs_verity;
        let first = store_named(&repo, &tree, "first", Some(&digest), &[]).await;
        let added = repo.add_composefs_supplement(&first).await.unwrap();
        let ComposefsSupplementAdd::Written { image, .. } = added else {
            panic!("expected Written, got {added:?}");
        };

        let repo = require_verity(repo).await;
        let second = store_named(&repo, &tree, "second", Some(&digest), &[]).await;
        let objects = object_files(&repo);
        let err = repo.add_composefs_supplement(&second).await.unwrap_err();
        assert_eq!(
            invalid_image(err),
            (
                second,
                ComposefsImageSource::Supplement,
                image,
                ComposefsImageDefect::NotSealed
            )
        );
        assert_eq!(object_files(&repo), objects);
        assert!(commitmeta_bytes(&repo, &second).is_none());
        assert!(repo.open_composefs_image(&second).await.unwrap().is_none());
    });
}

/// A supplement whose image commit fails a check is replaced: an absent
/// image commit, and an image commit whose digest is not the key.
#[test]
fn the_add_replaces_a_bad_supplement() {
    let scratch = TmpDir::new("cfs-add-replace");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let digest = recorded_export(&repo, &tree).await.fs_verity;
        let txn = repo.transaction().await.unwrap();
        let other = txn
            .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o400), b"other")
            .await
            .unwrap();
        let other = stage_image_commit(&txn, vec![("root.cfs".to_owned(), other)], vec![]).await;
        txn.commit().await.unwrap();
        let absent = Checksum::from_bytes([0x5a; 32]);

        for (subject, bad) in [("absent", absent), ("other", other)] {
            let commit = store_named(&repo, &tree, subject, Some(&digest), &[]).await;
            repo.add_supplement(&commit, COMPOSEFS_RELATION, &bad)
                .await
                .unwrap();
            let added = repo.add_composefs_supplement(&commit).await.unwrap();
            let ComposefsSupplementAdd::Written { image, replaced } = added else {
                panic!("expected Written, got {added:?}");
            };
            assert_eq!(replaced, Some(bad), "{subject}");
            assert_eq!(
                supplements(&repo, &commit).await,
                vec![(COMPOSEFS_RELATION.to_owned(), image)]
            );
            let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
            assert_eq!(found.commit, image);
        }
    });
}

/// A supplement that names a partial image commit is replaced by the same
/// image commit, and the call removes the partial marker.
#[test]
fn the_add_completes_a_partial_image_commit() {
    let scratch = TmpDir::new("cfs-add-partial");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (image, digest) = write_image_commit(&repo, &tree).await;
        let commit = store_named(&repo, &tree, "partial", Some(&digest), &[]).await;
        repo.add_supplement(&commit, COMPOSEFS_RELATION, &image)
            .await
            .unwrap();
        mark_partial(&repo, &image);
        // The object of the image is absent, as after a pull that stopped.
        let object = image_object(&repo, &image).await;
        let path = loose_path(&object, ObjectType::File, repo.mode());
        std::fs::remove_file(repo.path().join("objects").join(path)).unwrap();

        let added = repo.add_composefs_supplement(&commit).await.unwrap();
        assert_eq!(
            added,
            ComposefsSupplementAdd::Written {
                image,
                replaced: Some(image),
            }
        );
        assert_eq!(
            repo.commit_state(&image).await.unwrap(),
            ostrya::CommitState::Normal
        );
        let found = repo.open_composefs_image(&commit).await.unwrap().unwrap();
        assert_eq!(found.commit, image);
    });
}

/// In an `archive` repository, the add writes the image commit, and a
/// second call checks the inflated image and writes nothing. A supplement
/// that names another image commit fails the check of the inflated image
/// and is replaced. A supplement whose image is not the key of a commit
/// fails the check, and the key refuses the built image.
#[test]
fn the_add_works_in_an_archive_repository() {
    let scratch = TmpDir::new("cfs-add-archive");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::Archive, "").await;
        let digest = recorded_export(&repo, &tree).await.fs_verity;
        let commit = store_named(&repo, &tree, "archive", Some(&digest), &[]).await;
        let added = repo.add_composefs_supplement(&commit).await.unwrap();
        let ComposefsSupplementAdd::Written { image, replaced } = added else {
            panic!("expected Written, got {added:?}");
        };
        assert_eq!(replaced, None);
        let objects = object_files(&repo);
        assert_eq!(
            repo.add_composefs_supplement(&commit).await.unwrap(),
            ComposefsSupplementAdd::Valid { image }
        );
        assert_eq!(object_files(&repo), objects);

        // The supplement of a commit with the right key names the valid
        // image commit of another tree: the digest of its inflated image is
        // not the key, so the add builds the image and replaces the entry.
        let plain = plain_tree_commit(&repo).await;
        let (another, _) = write_image_commit(&repo, &plain).await;
        let renamed = store_named(&repo, &tree, "archive another", Some(&digest), &[]).await;
        repo.add_supplement(&renamed, COMPOSEFS_RELATION, &another)
            .await
            .unwrap();
        assert_eq!(
            repo.add_composefs_supplement(&renamed).await.unwrap(),
            ComposefsSupplementAdd::Written {
                image,
                replaced: Some(another),
            }
        );
        assert_eq!(
            supplements(&repo, &renamed).await,
            vec![(COMPOSEFS_RELATION.to_owned(), image)]
        );

        // The supplement of another commit with another key names the same
        // image commit: its inflated digest is not that key, so the add
        // builds the image, and the key refuses it.
        let wrong = [0x11u8; 32];
        let other = store_named(&repo, &tree, "archive wrong", Some(&wrong), &[]).await;
        repo.add_supplement(&other, COMPOSEFS_RELATION, &image)
            .await
            .unwrap();
        match repo.add_composefs_supplement(&other).await.unwrap_err() {
            Error::ComposefsDigestMismatch {
                expected, actual, ..
            } => {
                assert_eq!(expected, wrong);
                assert_eq!(actual, digest);
            }
            other => panic!("expected ComposefsDigestMismatch, got {other:?}"),
        }
        assert_eq!(
            supplements(&repo, &other).await,
            vec![(COMPOSEFS_RELATION.to_owned(), image)]
        );
    });
}

/// `CheckedAttachments::add` checks the new entry alone: after the first
/// check, the repository marks the commit of the other entries partial, and
/// the add and the write of the commit pass. The add takes an image commit
/// that the transaction stages, keeps the entries sorted, and refuses an
/// empty name, a name that the entries hold, and a partial commit with no
/// change to the entries.
#[test]
fn checked_attachments_add_checks_the_new_entry() {
    let scratch = TmpDir::new("cfs-checked-add");
    block_on(async {
        let (repo, tree) = setup(&scratch, RepoMode::BareUser, "").await;
        let (partial, _) = write_image_commit(&repo, &tree).await;
        let other = plain_tree_commit(&repo).await;
        let root = root_of(&repo, &tree).await;
        let txn = repo.transaction().await.unwrap();
        let mut checked = txn
            .check_attachments(&[("z/last".to_owned(), other), ("a/first".to_owned(), other)])
            .await
            .unwrap();
        // The repository holds the image commit `partial` and marks it
        // partial. It also marks the checked attachment `other` partial, so
        // a check of an entry of the first check fails.
        mark_partial(&repo, &partial);
        mark_partial(&repo, &other);
        let refusal = |err: Error| match err {
            Error::InvalidRelations {
                commit: None,
                field: RelationField::Attachments,
                reason,
            } => reason,
            other => panic!("expected InvalidRelations, got {other:?}"),
        };
        assert_eq!(
            refusal(checked.add("", &other).await.unwrap_err()),
            "the new entry has an empty name"
        );
        assert_eq!(
            refusal(checked.add("a/first", &other).await.unwrap_err()),
            "two entries have the name a/first"
        );
        let reason = refusal(checked.add(COMPOSEFS_RELATION, &partial).await.unwrap_err());
        assert!(reason.contains("partial"), "{reason}");
        assert!(reason.contains(&partial.to_string()), "{reason}");
        assert!(!reason.contains(&other.to_string()), "{reason}");
        std::fs::remove_file(repo.path().join(format!("state/{partial}.commitpartial"))).unwrap();

        let staged = txn
            .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o400), b"staged")
            .await
            .unwrap();
        let staged = stage_image_commit(&txn, vec![("root.cfs".to_owned(), staged)], vec![]).await;
        checked.add(COMPOSEFS_RELATION, &staged).await.unwrap();
        let commit = txn
            .write_commit_checked(
                ostrya::CommitOptions {
                    subject: Some("checked".to_owned()),
                    timestamp: Some(0),
                    ..ostrya::CommitOptions::default()
                },
                checked,
                &root,
            )
            .await
            .unwrap();
        txn.commit().await.unwrap();
        let relations = repo.read_commit_relations(&commit).await.unwrap();
        assert_eq!(
            relations.attachments,
            vec![
                ("a/first".to_owned(), other),
                (COMPOSEFS_RELATION.to_owned(), staged),
                ("z/last".to_owned(), other),
            ]
        );
    });
}
