//! The composefs image commit.
//!
//! The image commit holds the composefs image of the tree of another commit.
//! Its tree holds one regular file, `/root.cfs`, which is the EROFS image.
//! A commit names its image commit by the name [`COMPOSEFS_RELATION`], as an
//! attachment (field 2 of the commit object) or as a supplement (the key
//! `ostrya.related` of the detached metadata).
//!
//! - [`Transaction::write_composefs_commit`] stages the image commit of a
//!   tree.
//! - [`Repo::open_composefs_image`] finds the image commit that a commit
//!   names, checks it, and opens its `/root.cfs`.
//! - [`Repo::add_composefs_supplement`] writes the image commit of a commit
//!   and names it as the supplement [`COMPOSEFS_RELATION`] of the commit.
//!
//! The shape of the image commit is fixed:
//!
//! - The root directory is `0:0` with the mode `040755` and no xattrs.
//! - The root directory holds the file `root.cfs` alone. The file is `0:0`
//!   with the mode `0100400` and no xattrs. Its content is the image that an
//!   export with [`ComposefsOptions::RECORDED`] writes for the tree.
//! - The commit has the subject `composefs image`, an empty body, the
//!   timestamp 0, no parent, no metadata key, and no related entry.
//!
//! The same image therefore gives the same image commit.

use ostrya_core::{Checksum, Commit, DirMeta, DirTree, ObjectType, Value, Xattrs};

use async_compression::futures::bufread::DeflateDecoder;

use crate::composefs::{
    ComposefsOptions, DIGEST_CHUNK, digest_hex, image_file_digest, recorded_digest,
};
use crate::error::{Error, Result};
use crate::file::{FileKind, FileObject, Payload};
use crate::inflate::BufSource;
use crate::read::CommitState;
use crate::related::{self, RelationField};
use crate::repo::Repo;
use crate::transaction::Transaction;
use crate::tree::RepoTree;
use crate::write::FileMeta;

/// The name of the attachment and of the supplement that names the
/// composefs image commit of a commit.
pub const COMPOSEFS_RELATION: &str = "composefs";

/// The name of the image file in the root directory of the image commit.
const IMAGE_FILE: &str = "root.cfs";

/// The subject of the image commit.
const IMAGE_SUBJECT: &str = "composefs image";

/// The permission bits of the image file.
const IMAGE_PERM: u32 = 0o400;

/// The mode of the root directory of the image commit.
const ROOT_DIR_MODE: u32 = 0o040755;

/// The field of a commit that names the image commit that
/// [`Repo::open_composefs_image`] opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposefsImageSource {
    /// The attachment [`COMPOSEFS_RELATION`]: an entry of field 2 of the
    /// commit object.
    Attachment,
    /// The supplement [`COMPOSEFS_RELATION`]: an entry of the key
    /// `ostrya.related` of the detached metadata.
    Supplement,
}

impl std::fmt::Display for ComposefsImageSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ComposefsImageSource::Attachment => "attachment",
            ComposefsImageSource::Supplement => "supplement",
        })
    }
}

/// The open composefs image of a commit, from
/// [`Repo::open_composefs_image`].
#[derive(Debug)]
pub struct ComposefsImage {
    /// The loose object of `/root.cfs` in the image commit, open read-only at
    /// offset 0.
    pub file: std::fs::File,
    /// The size of the image in bytes.
    pub size: u64,
    /// The field of the commit that names the image commit.
    pub source: ComposefsImageSource,
    /// The checksum of the image commit.
    pub commit: Checksum,
}

/// The result of [`Repo::add_composefs_supplement`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComposefsSupplementAdd {
    /// The commit has the supplement [`COMPOSEFS_RELATION`], and its image
    /// commit passes the checks of [`Repo::open_composefs_image`]. The call
    /// writes nothing.
    Valid {
        /// The checksum of the image commit.
        image: Checksum,
    },
    /// The call wrote the image commit and set the supplement
    /// [`COMPOSEFS_RELATION`] of the commit to it.
    Written {
        /// The checksum of the image commit.
        image: Checksum,
        /// The image commit that the supplement named before the call, if
        /// the commit had the supplement and its image commit failed a
        /// check. It can be equal to `image`: for example, a partial image
        /// commit that the call completes.
        replaced: Option<Checksum>,
    },
}

/// The defect of an image commit that [`Repo::open_composefs_image`] refuses
/// with [`Error::InvalidComposefsImage`].
///
/// The text of each defect is a clause that follows the checksum of the image
/// commit in the text of the error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComposefsImageDefect {
    /// The repository does not hold the image commit.
    Absent,
    /// The repository marks the image commit partial.
    Partial,
    /// The root directory of the image commit holds no entry `root.cfs`.
    NoImageFile,
    /// The entry `root.cfs` is a directory or a symlink.
    NotRegular,
    /// The root directory of the image commit holds an entry other than
    /// `root.cfs`. The value is the name of the entry.
    ExtraEntry(String),
    /// The fs-verity digest of `/root.cfs` is not the value of the key
    /// `ostree.composefs.digest.v0` of the commit.
    DigestMismatch {
        /// The digest that the commit records.
        expected: [u8; 32],
        /// The fs-verity digest of `/root.cfs`.
        actual: [u8; 32],
    },
}

impl std::fmt::Display for ComposefsImageDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComposefsImageDefect::Absent => f.write_str(related::ABSENT_REASON),
            ComposefsImageDefect::Partial => f.write_str(related::PARTIAL_REASON),
            ComposefsImageDefect::NoImageFile => write!(f, "whose tree holds no /{IMAGE_FILE}"),
            ComposefsImageDefect::NotRegular => {
                write!(f, "whose /{IMAGE_FILE} is not a regular file")
            }
            ComposefsImageDefect::ExtraEntry(name) => {
                write!(f, "whose tree holds the entry {name} next to /{IMAGE_FILE}")
            }
            ComposefsImageDefect::DigestMismatch { expected, actual } => write!(
                f,
                "whose /{IMAGE_FILE} has the fs-verity digest {}, and the commit records {}",
                digest_hex(actual),
                digest_hex(expected)
            ),
        }
    }
}

/// Methods that write the composefs image commit.
impl Transaction {
    /// Stages the composefs image commit of a tree that this transaction
    /// staged.
    ///
    /// The call returns the checksum of the image commit and the fs-verity
    /// digest of the image. The image is the image that an export with
    /// [`ComposefsOptions::RECORDED`] writes for the tree, so the digest is
    /// the value that [`composefs_digest`](Transaction::composefs_digest)
    /// gives.
    ///
    /// The image commit has a fixed shape:
    ///
    /// - The root directory is `0:0` with the mode `040755` and no xattrs.
    /// - The root directory holds the file `root.cfs` alone. The file is the
    ///   image, `0:0` with the mode `0100400` and no xattrs.
    /// - The commit has the subject `composefs image`, an empty body, the
    ///   timestamp 0, no parent, no metadata key, and no related entry.
    ///
    /// So the same image gives the same image commit.
    ///
    /// The call writes the image file with
    /// [`write_composefs_content`](Transaction::write_composefs_content). It
    /// then stages the root dirmeta, the root dirtree, and the commit object
    /// with no `ostree.sizes` key. The image commit
    /// does not name the commit of the tree. The caller names the image commit
    /// from that commit as the attachment or the supplement
    /// [`COMPOSEFS_RELATION`].
    ///
    /// In an `archive` repository, the image file is a `.filez` object.
    /// [`Repo::open_composefs_image`] refuses an `archive` repository.
    ///
    /// If the repository already holds the image commit and marks it partial,
    /// the call does not remove the partial marker. The image commit then
    /// stays partial, and [`Repo::open_composefs_image`] refuses it.
    ///
    /// # Errors
    ///
    /// - The errors of
    ///   [`write_composefs_content`](Transaction::write_composefs_content).
    /// - The errors of [`write_dirmeta`](Transaction::write_dirmeta) and of
    ///   [`write_metadata`](Transaction::write_metadata).
    pub async fn write_composefs_commit(&self, root: &RepoTree) -> Result<(Checksum, [u8; 32])> {
        let meta = FileMeta::regular(0, 0, IMAGE_PERM);
        let (image, digest) = self
            .write_composefs_content(root, &ComposefsOptions::RECORDED, &meta)
            .await?;
        let root_dirmeta = self
            .write_dirmeta(&DirMeta {
                uid: 0,
                gid: 0,
                mode: ROOT_DIR_MODE,
                xattrs: Xattrs::empty(),
            })
            .await?;
        let tree = DirTree {
            files: vec![(IMAGE_FILE.to_owned(), image)],
            dirs: Vec::new(),
        };
        let root_dirtree = self
            .write_metadata(ObjectType::DirTree, None, &tree.serialize()?)
            .await?;
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
        let checksum = self
            .write_metadata(ObjectType::Commit, None, &commit.serialize()?)
            .await?;
        Ok((checksum, digest))
    }
}

/// Methods that find and open the composefs image of a commit.
impl Repo {
    /// Opens the composefs image of the image commit that `commit` names.
    ///
    /// The call returns `None` if `commit` names no image commit.
    ///
    /// # Lookup
    ///
    /// The call reads the commit object and finds the image commit in this
    /// order:
    ///
    /// 1. The attachment [`COMPOSEFS_RELATION`] of field 2. If the commit has
    ///    it, the call does not read the detached metadata.
    /// 2. Else the supplement [`COMPOSEFS_RELATION`] of the key
    ///    `ostrya.related` of the detached metadata.
    ///
    /// The call checks each entry of field 2, and each entry of
    /// `ostrya.related` if it reads that key. A
    /// defective entry fails the call, also if its name is not
    /// [`COMPOSEFS_RELATION`]. Two entries of the name in one field fail the
    /// call. If the image commit of the selected entry has a defect, the call
    /// fails and does not try the other field.
    ///
    /// The call does not check the state of `commit`. A partial commit gives
    /// its image as a complete commit does.
    ///
    /// # Checks
    ///
    /// The call checks the image commit in this order:
    ///
    /// 1. The repository holds the image commit.
    /// 2. The repository does not mark the image commit partial.
    /// 3. The root directory holds the entry `root.cfs`.
    /// 4. The entry `root.cfs` is not a directory.
    /// 5. The root directory holds no other entry.
    /// 6. The file object of `root.cfs` is not a symlink.
    /// 7. If `commit` carries the key `ostree.composefs.digest.v0`, the
    ///    fs-verity digest of `/root.cfs` is the value of the key.
    ///
    /// The call does not check the owners, the modes, or the xattrs of the
    /// image commit. If `commit` has no key, the call gives the file with no
    /// check of its content.
    ///
    /// If the file object is sealed with fs-verity with SHA-256, 4096-byte
    /// blocks, no salt, and its full size, the call reads the digest from the
    /// kernel. Otherwise it streams the file through the fs-verity hasher in
    /// chunks of 128 KiB. The call measures the digest through the descriptor
    /// that it returns. A process that can write the unsealed file can change
    /// it after the call returns, so the check holds only for the bytes that
    /// the call read.
    ///
    /// The key records the digest of the image that the commit mounts with.
    /// The call trusts the key and builds no image to check it.
    ///
    /// # Errors
    ///
    /// - [`Error::Unsupported`] if the repository is in `archive` mode. The
    ///   call refuses this mode before it reads a file.
    /// - [`Error::ObjectNotFound`] if the repository does not hold the commit
    ///   object of `commit`.
    /// - [`Error::Core`] if the commit tuple does not frame, if field 2 does
    ///   not decode, if the detached metadata does not parse, or if a commit
    ///   object or the root dirtree of the image commit does not parse.
    /// - [`Error::InvalidRelations`] with `commit` and the field, if an entry
    ///   of field 2 or of `ostrya.related` has an empty name or a checksum
    ///   that is not 32 bytes, if the value of `ostrya.related` is not a
    ///   variant of type `a(say)`, or if two entries of one field have the
    ///   name [`COMPOSEFS_RELATION`].
    /// - [`Error::InvalidFormat`] if the first entry of
    ///   `ostree.composefs.digest.v0` is not a variant of type `ay` with 32
    ///   bytes.
    /// - [`Error::InvalidComposefsImage`] with `commit`, the source, the
    ///   image commit, and the [`ComposefsImageDefect`], if a check of the
    ///   image commit fails.
    /// - [`Error::ObjectNotFound`] if the repository holds the image commit
    ///   complete and does not hold its root dirtree or the file object of
    ///   `root.cfs`.
    /// - [`Error::InvalidFormat`] if a metadata object is larger than
    ///   [`MAX_METADATA_SIZE`](crate::MAX_METADATA_SIZE) or is not a regular
    ///   file, if a symlink is on its path, or if the file object does not
    ///   have the form of the repository mode. [`Repo::load_file`] lists the
    ///   cases.
    /// - [`Error::Io`] if a read of the image or another file system
    ///   operation fails.
    pub async fn open_composefs_image(&self, commit: &Checksum) -> Result<Option<ComposefsImage>> {
        if self.mode().is_archive() {
            return Err(archive_refusal());
        }
        let repo = self.clone();
        let key = *commit;
        ostrya_rt::unblock(move || {
            let Some(named) = repo.named_image_blocking(&key)? else {
                return Ok(None);
            };
            let (file, size) =
                repo.check_raw_image_blocking(&key, named.source, &named.image, named.key)?;
            Ok(Some(ComposefsImage {
                file,
                size,
                source: named.source,
                commit: named.image,
            }))
        })
        .await
    }

    /// Writes the composefs image commit of `commit` and names it as the
    /// supplement [`COMPOSEFS_RELATION`] of `commit`, if the commit has no
    /// valid image commit.
    ///
    /// The call begins a transaction before it reads the commit, so a prune
    /// cannot remove the commit or its objects during the build. It then
    /// makes these steps in this order:
    ///
    /// 1. If field 2 of the commit has the attachment
    ///    [`COMPOSEFS_RELATION`], the call refuses the commit. It does not
    ///    check the attachment.
    /// 2. If the commit has the supplement [`COMPOSEFS_RELATION`], the call
    ///    checks its image commit with the checks of
    ///    [`open_composefs_image`](Repo::open_composefs_image). If the image
    ///    commit passes, the call writes nothing and gives
    ///    [`ComposefsSupplementAdd::Valid`]. If a check fails with
    ///    [`Error::InvalidComposefsImage`], the call writes the entry again in
    ///    step 5. Thus the call replaces an entry that names another image
    ///    commit, an image commit that the repository does not hold or holds
    ///    partial, or an image commit whose tree has a defect.
    /// 3. The call builds the image of the tree of the commit with
    ///    [`ComposefsOptions::RECORDED`] and stages the image commit with
    ///    [`Transaction::write_composefs_commit`].
    /// 4. If the commit carries `ostree.composefs.digest.v0` and the
    ///    fs-verity digest of the image is not the value of the key, the call
    ///    refuses the commit. A commit whose key records the digest of an
    ///    image with labels that the port does not write is refused. If the
    ///    commit has no key, the call makes no check of the image.
    /// 5. The call sets the supplement [`COMPOSEFS_RELATION`] of the commit
    ///    to the image commit, as [`Transaction::add_supplement`] does, and
    ///    commits the transaction.
    /// 6. If the repository marked the image commit partial before the call,
    ///    the call removes the partial marker. After the commit of the
    ///    transaction, the repository holds each object of the image commit.
    ///
    /// The transaction does not write an object that the repository already
    /// holds. If the entry names the image commit that the build gives, and
    /// the file object of its `/root.cfs` is changed on disk, the check of
    /// step 2 fails and the build gives the same image commit. The call then
    /// gives [`ComposefsSupplementAdd::Written`] with this image commit as
    /// `replaced`, and the changed object stays. A changed object is a defect
    /// that [`Repo::fsck`] reports.
    ///
    /// The checks of step 2 work in each repository mode. In `archive` mode,
    /// the call inflates the image and streams it through the fs-verity
    /// hasher. The call writes the image commit in each mode. In `archive`
    /// mode, the image file is a `.filez` object, and
    /// [`open_composefs_image`](Repo::open_composefs_image) refuses the
    /// repository.
    ///
    /// The call does not check the state of `commit`. If an object of its
    /// tree is absent, the build fails.
    ///
    /// On a refusal or an error before the commit of the transaction, the
    /// call writes nothing.
    ///
    /// # Errors
    ///
    /// - The errors of [`Repo::transaction`].
    /// - The errors of [`Repo::load_object_bytes`] for the commit object.
    /// - [`Error::Core`] if the commit object does not parse.
    /// - [`Error::InvalidFormat`] if the first entry of
    ///   `ostree.composefs.digest.v0` is not a variant of type `ay` with 32
    ///   bytes.
    /// - [`Error::InvalidRelations`] with `commit` and the field, if an entry
    ///   of field 2 or of `ostrya.related` is defective, or if two entries of
    ///   one field have the name [`COMPOSEFS_RELATION`].
    /// - [`Error::InvalidInput`] if field 2 of the commit has the attachment
    ///   [`COMPOSEFS_RELATION`].
    /// - The errors of the checks of step 2 other than
    ///   [`Error::InvalidComposefsImage`], as
    ///   [`open_composefs_image`](Repo::open_composefs_image) lists them.
    /// - The errors of [`Transaction::write_composefs_commit`]. The build
    ///   fails with [`Error::ObjectNotFound`] if an object of the tree is
    ///   absent.
    /// - [`Error::ComposefsDigestMismatch`] if the commit carries the key and
    ///   the digest of the image is not its value.
    /// - The errors of [`Transaction::commit`].
    /// - The error of the removal of the partial marker.
    pub async fn add_composefs_supplement(
        &self,
        commit: &Checksum,
    ) -> Result<ComposefsSupplementAdd> {
        let txn = self.transaction().await?;
        let (result, was_partial) = match self.stage_composefs_supplement(&txn, commit).await {
            Ok(staged) => staged,
            Err(e) => {
                txn.abort().await?;
                return Err(e);
            }
        };
        let ComposefsSupplementAdd::Written { image, .. } = result else {
            txn.abort().await?;
            return Ok(result);
        };
        let fsync = txn.fsync_flags()?.0;
        txn.commit().await?;
        if was_partial {
            let failed = self.remove_partial_markers(vec![image], fsync).await?;
            if let Some((_, e)) = failed.into_iter().next() {
                return Err(e);
            }
        }
        Ok(result)
    }

    /// Runs the steps of
    /// [`add_composefs_supplement`](Repo::add_composefs_supplement) up to the
    /// commit of `txn`.
    ///
    /// For [`ComposefsSupplementAdd::Written`], the call stages the image
    /// commit and queues the supplement in `txn`. The second value is `true`
    /// if the repository marked the image commit partial before the call.
    /// For [`ComposefsSupplementAdd::Valid`], the call stages nothing.
    async fn stage_composefs_supplement(
        &self,
        txn: &Transaction,
        commit: &Checksum,
    ) -> Result<(ComposefsSupplementAdd, bool)> {
        let repo = self.clone();
        let read_commit = *commit;
        let read = ostrya_rt::unblock(move || repo.supplement_state_blocking(&read_commit)).await?;
        let replaced = match read.state {
            SupplementState::Valid(image) => {
                return Ok((ComposefsSupplementAdd::Valid { image }, false));
            }
            SupplementState::Build { replaced } => replaced,
        };
        let root = RepoTree::from_parts(self.clone(), read.root_dirtree, read.root_dirmeta);
        let (image, digest) = txn.write_composefs_commit(&root).await?;
        if let Some(expected) = read.key
            && expected != digest
        {
            return Err(Error::ComposefsDigestMismatch {
                commit: *commit,
                expected,
                actual: digest,
            });
        }
        let was_partial = self.commit_state(&image).await? == CommitState::Partial;
        txn.add_supplement(commit, COMPOSEFS_RELATION, &image)?;
        Ok((
            ComposefsSupplementAdd::Written { image, replaced },
            was_partial,
        ))
    }

    /// Reads the commit object of `commit` one time and gives the parts of it
    /// that [`add_composefs_supplement`](Repo::add_composefs_supplement) uses:
    /// the root of its tree, the value of the key
    /// `ostree.composefs.digest.v0`, and the state of its supplement
    /// [`COMPOSEFS_RELATION`].
    ///
    /// The call refuses a commit whose field 2 has the attachment
    /// [`COMPOSEFS_RELATION`]. If the commit has the supplement, the call
    /// checks its image commit with
    /// [`check_composefs_commit_blocking`](Repo::check_composefs_commit_blocking).
    /// The reads block the thread, so an async caller runs this call on the
    /// blocking pool.
    fn supplement_state_blocking(&self, commit: &Checksum) -> Result<SupplementRead> {
        let bytes = self.load_object_bytes_blocking(ObjectType::Commit, commit)?;
        let parsed = Commit::parse(&bytes)?;
        let key = recorded_digest(&parsed)?;
        let mut replaced = None;
        if let Some((source, image)) = self.named_entry_blocking(commit, &bytes)? {
            if source == ComposefsImageSource::Attachment {
                return Err(Error::InvalidInput(format!(
                    "commit {commit} names its composefs image commit {image} as an \
                     attachment; a supplement is not written"
                )));
            }
            match self.check_composefs_commit_blocking(commit, source, &image, key) {
                Ok(_) => {
                    return Ok(SupplementRead {
                        root_dirtree: parsed.root_dirtree,
                        root_dirmeta: parsed.root_dirmeta,
                        key,
                        state: SupplementState::Valid(image),
                    });
                }
                Err(Error::InvalidComposefsImage { .. }) => replaced = Some(image),
                Err(e) => return Err(e),
            }
        }
        Ok(SupplementRead {
            root_dirtree: parsed.root_dirtree,
            root_dirmeta: parsed.root_dirmeta,
            key,
            state: SupplementState::Build { replaced },
        })
    }

    /// Reads the commit `commit` and returns the image commit that it names,
    /// as [`open_composefs_image`](Repo::open_composefs_image) selects it,
    /// with the value of the key `ostree.composefs.digest.v0` of `commit`.
    ///
    /// The call parses the key only if `commit` names an image commit. The
    /// reads and the parse block the thread, so an async caller runs this
    /// call on the blocking pool.
    fn named_image_blocking(&self, commit: &Checksum) -> Result<Option<NamedImage>> {
        let bytes = self.load_object_bytes_blocking(ObjectType::Commit, commit)?;
        let Some((source, image)) = self.named_entry_blocking(commit, &bytes)? else {
            return Ok(None);
        };
        let key = recorded_digest(&Commit::parse(&bytes)?)?;
        Ok(Some(NamedImage { source, image, key }))
    }

    /// Returns the field and the checksum of the image commit that the commit
    /// `commit` names, as
    /// [`open_composefs_image`](Repo::open_composefs_image) selects it.
    /// `bytes` are the bytes of the commit object of `commit`.
    ///
    /// The call reads the detached metadata only if field 2 has no entry
    /// [`COMPOSEFS_RELATION`]. The read blocks the thread, so an async caller
    /// runs this call on the blocking pool.
    fn named_entry_blocking(
        &self,
        commit: &Checksum,
        bytes: &[u8],
    ) -> Result<Option<(ComposefsImageSource, Checksum)>> {
        let attachments = related::checked_entries(
            RelationField::Attachments,
            Some(*commit),
            related::parse_attachments(bytes)?,
        )?;
        if let Some(image) = composefs_entry(commit, RelationField::Attachments, &attachments)? {
            return Ok(Some((ComposefsImageSource::Attachment, image)));
        }
        let detached = self.read_supplement_dict_blocking(commit)?;
        let supplements = related::supplements(detached.as_ref())
            .map_err(|reason| Error::InvalidRelations {
                commit: Some(*commit),
                field: RelationField::Supplements,
                reason,
            })?
            .map(|entries| {
                related::checked_entries(RelationField::Supplements, Some(*commit), entries)
            })
            .transpose()?
            .unwrap_or_default();
        Ok(
            composefs_entry(commit, RelationField::Supplements, &supplements)?
                .map(|image| (ComposefsImageSource::Supplement, image)),
        )
    }

    /// Checks the image commit `image`, which `commit` names in the field
    /// `relation`, by the checks of
    /// [`open_composefs_image`](Repo::open_composefs_image). `key` is the
    /// value of the key `ostree.composefs.digest.v0` of `commit`, or `None`
    /// for no check of the digest.
    ///
    /// The call works in each repository mode. In a mode other than
    /// `archive`, it returns the file object of `root.cfs`, open read-only at
    /// offset 0, and its size. In `archive` mode, it returns `None`. If `key`
    /// is set, it first streams the inflated payload through the fs-verity
    /// hasher in chunks of 128 KiB. If `key` is `None`, it reads no byte of
    /// the payload. The reads block the thread, so an async caller runs this
    /// call on the blocking pool.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidComposefsImage`] with `commit`, `relation`, `image`,
    /// and the defect, and the errors of the reads that
    /// [`open_composefs_image`](Repo::open_composefs_image) lists.
    fn check_composefs_commit_blocking(
        &self,
        commit: &Checksum,
        relation: ComposefsImageSource,
        image: &Checksum,
        key: Option<[u8; 32]>,
    ) -> Result<Option<(std::fs::File, u64)>> {
        if !self.mode().is_archive() {
            return self
                .check_raw_image_blocking(commit, relation, image, key)
                .map(Some);
        }
        let (object, payload) = self.image_file_blocking(commit, relation, image, false)?;
        let Some(expected) = key else {
            return Ok(None);
        };
        let Some((file, len)) = payload else {
            return Err(no_payload(&object));
        };
        let actual = inflated_digest_blocking(file, len)?;
        check_digest(&expected, &actual)
            .map_err(|defect| invalid_image(commit, relation, image, defect))?;
        Ok(None)
    }

    /// Checks the image commit `image` as
    /// [`check_composefs_commit_blocking`](Repo::check_composefs_commit_blocking) does in a mode
    /// other than `archive`, and returns the file object of `root.cfs`, open
    /// read-only at offset 0, and its size.
    ///
    /// If `key` is set, the digest of the file comes from the kernel when the
    /// load of the object gives one. Else the call streams the file through
    /// the fs-verity hasher in chunks of 128 KiB and seeks back to offset 0.
    /// The reads block the thread, so an async caller runs this call on the
    /// blocking pool.
    fn check_raw_image_blocking(
        &self,
        commit: &Checksum,
        relation: ComposefsImageSource,
        image: &Checksum,
        key: Option<[u8; 32]>,
    ) -> Result<(std::fs::File, u64)> {
        use std::io::{Seek, SeekFrom};

        let (object, payload) = self.image_file_blocking(commit, relation, image, key.is_some())?;
        let Some((mut file, size)) = payload else {
            return Err(no_payload(&object));
        };
        let Some(expected) = key else {
            return Ok((file, size));
        };
        let actual = match object.kernel_fs_verity() {
            Some(digest) => digest,
            None => {
                let digest = image_file_digest(&mut file)?;
                file.seek(SeekFrom::Start(0))?;
                digest
            }
        };
        check_digest(&expected, &actual)
            .map_err(|defect| invalid_image(commit, relation, image, defect))?;
        Ok((file, size))
    }

    /// Runs the checks of the image commit `image` up to the type of the file
    /// object of `root.cfs`, and returns that object with its object file,
    /// open at the start of its payload.
    ///
    /// If `measure` is set, the load of the object also reads the fs-verity
    /// digest that the kernel holds for it. The reads block the thread, so an
    /// async caller runs this call on the blocking pool.
    fn image_file_blocking(
        &self,
        commit: &Checksum,
        relation: ComposefsImageSource,
        image: &Checksum,
        measure: bool,
    ) -> Result<(FileObject, Option<Payload>)> {
        let invalid = |defect| invalid_image(commit, relation, image, defect);
        let Some(bytes) = self.held_object_bytes_blocking(ObjectType::Commit, image)? else {
            return Err(invalid(ComposefsImageDefect::Absent));
        };
        if self.commit_state_blocking(image)? == CommitState::Partial {
            return Err(invalid(ComposefsImageDefect::Partial));
        }
        let root = Commit::parse(&bytes)?.root_dirtree;
        let tree = DirTree::parse(&self.load_object_bytes_blocking(ObjectType::DirTree, &root)?)?;
        let file = image_entry(&tree).map_err(invalid)?;
        let (object, payload) = self.open_file_blocking(&file, measure)?;
        if !matches!(object.kind, FileKind::Regular { .. }) {
            return Err(invalid(ComposefsImageDefect::NotRegular));
        }
        Ok((object, payload))
    }
}

/// The parts of a commit that [`Repo::add_composefs_supplement`] uses, from
/// [`Repo::supplement_state_blocking`].
struct SupplementRead {
    /// The checksum of the root dirtree of the commit.
    root_dirtree: Checksum,
    /// The checksum of the root dirmeta of the commit.
    root_dirmeta: Checksum,
    /// The value of the key `ostree.composefs.digest.v0` of the commit, or
    /// `None` if the commit does not carry the key.
    key: Option<[u8; 32]>,
    /// The state of the supplement [`COMPOSEFS_RELATION`] of the commit.
    state: SupplementState,
}

/// The state of the supplement [`COMPOSEFS_RELATION`] of a commit, from
/// [`Repo::supplement_state_blocking`].
enum SupplementState {
    /// The supplement names this image commit, and the image commit passes
    /// the checks.
    Valid(Checksum),
    /// The call builds the image commit. `replaced` is the image commit that
    /// the supplement names and that fails a check, or `None` if the commit
    /// has no supplement.
    Build { replaced: Option<Checksum> },
}

/// The image commit that a commit names, from
/// [`Repo::named_image_blocking`].
struct NamedImage {
    /// The field of the commit that names the image commit.
    source: ComposefsImageSource,
    /// The checksum of the image commit.
    image: Checksum,
    /// The value of the key `ostree.composefs.digest.v0` of the commit, or
    /// `None` if the commit does not carry the key.
    key: Option<[u8; 32]>,
}

/// Returns the error of the defect `defect` of the image commit `image`,
/// which `commit` names in the field `relation`.
fn invalid_image(
    commit: &Checksum,
    relation: ComposefsImageSource,
    image: &Checksum,
    defect: ComposefsImageDefect,
) -> Error {
    Error::InvalidComposefsImage {
        commit: *commit,
        relation,
        image: *image,
        defect: Box::new(defect),
    }
}

/// Returns the error of the file object `object` of `/root.cfs` that the load
/// gives with no payload.
fn no_payload(object: &FileObject) -> Error {
    Error::InvalidFormat(format!(
        "the file object {} of /{IMAGE_FILE} has no payload",
        object.checksum()
    ))
}

/// Returns the error of a lookup of the composefs image in an `archive`
/// repository.
fn archive_refusal() -> Error {
    Error::Unsupported(
        "the lookup of a composefs image refuses an archive repository: it stores \
         /root.cfs compressed, and a mount needs the raw image"
            .into(),
    )
}

/// Returns the checksum of the entry [`COMPOSEFS_RELATION`] of `entries`, the
/// checked entries of the field `field` of `commit`, or `None` if no entry
/// has the name.
///
/// # Errors
///
/// [`Error::InvalidRelations`] with `commit` and `field` if two or more
/// entries have the name.
fn composefs_entry(
    commit: &Checksum,
    field: RelationField,
    entries: &[(String, Checksum)],
) -> Result<Option<Checksum>> {
    let mut named = entries
        .iter()
        .filter(|(name, _)| name == COMPOSEFS_RELATION);
    let first = named.next().map(|(_, checksum)| *checksum);
    if named.next().is_some() {
        return Err(Error::InvalidRelations {
            commit: Some(*commit),
            field,
            reason: format!("two or more entries have the name {COMPOSEFS_RELATION}"),
        });
    }
    Ok(first)
}

/// Returns the checksum of the file object of `root.cfs` in `tree`, the root
/// dirtree of an image commit, or the structural defect of the tree.
///
/// A tree with no entry `root.cfs` gives [`ComposefsImageDefect::NoImageFile`],
/// a directory `root.cfs` gives [`ComposefsImageDefect::NotRegular`], and
/// each other entry gives [`ComposefsImageDefect::ExtraEntry`], in this order.
fn image_entry(tree: &DirTree) -> std::result::Result<Checksum, ComposefsImageDefect> {
    let file = tree
        .files
        .iter()
        .find(|(name, _)| name == IMAGE_FILE)
        .map(|(_, checksum)| *checksum);
    let dir = tree.dirs.iter().any(|(name, _, _)| name == IMAGE_FILE);
    if file.is_none() && !dir {
        return Err(ComposefsImageDefect::NoImageFile);
    }
    if dir {
        return Err(ComposefsImageDefect::NotRegular);
    }
    let extra = tree
        .files
        .iter()
        .map(|(name, _)| name)
        .chain(tree.dirs.iter().map(|(name, _, _)| name))
        .find(|name| *name != IMAGE_FILE);
    if let Some(name) = extra {
        return Err(ComposefsImageDefect::ExtraEntry(name.clone()));
    }
    Ok(file.expect("the tree holds the file root.cfs"))
}

/// Refuses `actual`, the fs-verity digest of `/root.cfs`, with
/// [`ComposefsImageDefect::DigestMismatch`] if it is not `expected`.
fn check_digest(
    expected: &[u8; 32],
    actual: &[u8; 32],
) -> std::result::Result<(), ComposefsImageDefect> {
    if actual == expected {
        return Ok(());
    }
    Err(ComposefsImageDefect::DigestMismatch {
        expected: *expected,
        actual: *actual,
    })
}

/// Returns the fs-verity digest of the inflated payload of an `archive`
/// object. `file` is open at the start of the raw-DEFLATE stream, and `len`
/// is the number of bytes from there to the end of the file.
///
/// The call reads the stream in bounded chunks and hashes the inflated bytes
/// in chunks of 128 KiB. The reads block the thread, so an async caller runs
/// this call on the blocking pool.
fn inflated_digest_blocking(file: std::fs::File, len: u64) -> Result<[u8; 32]> {
    use futures_lite::AsyncReadExt;

    let source = BufSource::with_len_hint(futures_lite::io::AssertAsync::new(file), len);
    let mut decoder = DeflateDecoder::new(source);
    let mut hasher = ostrya_composefs::FsVerityHasher::new();
    let mut buf = vec![0u8; DIGEST_CHUNK];
    // The reader over a blocking file never returns `Pending`, so `block_on`
    // drives it on this thread with no executor.
    futures_lite::future::block_on(async {
        loop {
            let n = decoder.read(&mut buf).await.map_err(Error::Io)?;
            if n == 0 {
                return Ok::<(), Error>(());
            }
            hasher.update(&buf[..n]);
        }
    })?;
    Ok(hasher.finalize())
}

/// Compile-time checks that [`ComposefsImage`] is `Send + Sync` and that the
/// futures of the calls of this module are `Send`.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>(_: &T) {}
    assert_send_sync::<ComposefsImage>();
    assert_send_sync::<ComposefsImageDefect>();
    let _ = |repo: &Repo, commit: &Checksum| assert_send(&repo.open_composefs_image(commit));
    let _ = |repo: &Repo, commit: &Checksum| assert_send(&repo.add_composefs_supplement(commit));
    let _ = |txn: &Transaction, root: &RepoTree| assert_send(&txn.write_composefs_commit(root));
    let _ = |txn: &Transaction, root: &RepoTree, meta: &FileMeta| {
        assert_send(&txn.write_composefs_content(root, &ComposefsOptions::RECORDED, meta));
    };
};

#[cfg(test)]
mod tests {
    use ostrya_core::{Checksum, DirMeta, DirTree, ObjectType, RepoMode, Xattrs};
    use ostrya_rt::block_on;

    use super::{ComposefsImageDefect, ComposefsImageSource, ROOT_DIR_MODE};
    use crate::tree::RepoTree;
    use crate::{CreateOptions, Error, FileMeta, Repo};

    /// In an `archive` repository, the check of an image commit hashes the
    /// inflated payload of `root.cfs`, refuses a key that is not its digest,
    /// and gives no descriptor.
    #[test]
    fn the_check_hashes_the_inflated_image_in_archive_mode() {
        let path = std::env::temp_dir().join(format!(
            "ostrya-image-commit-archive-{}-{}",
            std::process::id(),
            crate::write::unique()
        ));
        let _ = std::fs::remove_dir_all(&path);
        block_on(async {
            let repo = Repo::create(&path, CreateOptions::new(RepoMode::Archive))
                .await
                .unwrap();
            let txn = repo.transaction().await.unwrap();
            let file = txn
                .write_regfile_inline(None, &FileMeta::regular(0, 0, 0o644), b"payload\n")
                .await
                .unwrap();
            let dirmeta = txn
                .write_dirmeta(&DirMeta {
                    uid: 0,
                    gid: 0,
                    mode: ROOT_DIR_MODE,
                    xattrs: Xattrs::empty(),
                })
                .await
                .unwrap();
            let tree = DirTree {
                files: vec![("a".to_owned(), file)],
                dirs: Vec::new(),
            };
            let dirtree = txn
                .write_metadata(ObjectType::DirTree, None, &tree.serialize().unwrap())
                .await
                .unwrap();
            let root = RepoTree::from_parts(repo.clone(), dirtree, dirmeta);
            let (image, digest) = txn.write_composefs_commit(&root).await.unwrap();
            txn.commit().await.unwrap();

            let commit = Checksum::from_bytes([1; 32]);
            let source = ComposefsImageSource::Supplement;
            for key in [Some(&digest), None] {
                let checked = repo
                    .check_composefs_commit_blocking(&commit, source, &image, key.copied())
                    .unwrap();
                assert!(checked.is_none());
            }
            let wrong = [0x11; 32];
            match repo
                .check_composefs_commit_blocking(&commit, source, &image, Some(wrong))
                .unwrap_err()
            {
                Error::InvalidComposefsImage { defect, .. } => assert_eq!(
                    *defect,
                    ComposefsImageDefect::DigestMismatch {
                        expected: wrong,
                        actual: digest,
                    }
                ),
                other => panic!("expected InvalidComposefsImage, got {other:?}"),
            }
        });
        let _ = std::fs::remove_dir_all(&path);
    }
}
